#!/usr/bin/env node
/**
 * bin/mcpaudit.js — the CLI entrypoint (Node ≥ 20, zero runtime deps).
 *
 * All the impure stuff lives here (arg parsing, picking a PackageSource,
 * stdout, exit code). The analysis itself is the pure core in src/.
 *
 * Behaviour contract (so it is safe in CI):
 *   - exit 0  : scan completed, gate not tripped
 *   - exit 1  : scan completed, a finding met/exceeded --fail-on
 *   - exit 2  : usage error (bad/missing args) — printed before any scan
 *   - INTERNAL errors (a bug in mcpaudit, an unreadable tree, etc.) are
 *     CAUGHT, printed as a diagnostic, and we exit 0. A security linter must
 *     never crash the host pipeline; a broken scanner failing open is
 *     surfaced loudly but does not block the build. (Use --fail-on with a
 *     separate required check if you want hard enforcement.)
 *   - This file performs NO network I/O. A bare package name uses a
 *     PackageSource; the shipped default is an honest stub that tells you to
 *     pass a path. The path scan is fully offline.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { analyzeProject } from "../src/analyze.js";
import { gate } from "../src/rules.js";
import { formatHuman, formatJson, formatSarif } from "../src/format.js";
import {
  buildBaseline,
  diffAgainstBaseline,
  monitoringRecord,
} from "../src/baseline.js";
import {
  LocalDirSource,
  StubRegistrySource,
  resolveTarget,
} from "../src/source.js";

const VERSION = "0.1.0";
const VALID_GATES = ["critical", "high", "medium", "low", "none"];

const HELP = `mcpaudit ${VERSION} — static security scanner for MCP servers

USAGE
  npx mcpaudit <path|package> [options]

ARGUMENTS
  <path>      a local directory: an MCP server's source tree (fully offline)
  <package>   a package name: requires an operator-wired registry source;
              the shipped build asks you to pass a path instead (no network)

OPTIONS
  --json                 machine-readable JSON instead of the human report
  --sarif                SARIF v2.1.0 (GitHub code-scanning upload format)
  --include-tests        also scan *.test.* / *.spec.* files and __tests__/
                         __mocks__ directories (skipped by default: they are
                         fixtures, not code the agent runs)
  --fail-on <severity>   exit non-zero if any finding is >= severity
                         (${VALID_GATES.join(" | ")}; default: high)
  --baseline <file>      diff against a committed baseline; only NEW findings
                         (regressions) are gated. FIXED/unchanged are shown
                         but never fail the build.
  --baseline-write <f>   run the scan and WRITE a baseline file (commit it),
                         then exit 0. Use this to (re)accept current state.
  --monitor-json         with --baseline: emit the structured monitoring
                         record (the machine contract for a hosted tier)
  --quiet                print only findings (suppress the header/summary)
  --no-color             disable ANSI color (color is off by default in CI)
  --color                force ANSI color
  -h, --help             this help
  -v, --version          print version

EXIT CODES
  0  scan done, gate not tripped (also: internal error — fails OPEN, loudly)
  1  scan done, a finding met/exceeded --fail-on
  2  usage error

WHAT IT DETECTS (static, conservative — see README "Limitations")
  MCP001 command injection   MCP002 env/credential exfiltration to the LLM
  MCP003 broad fs scope      MCP004 unrestricted tool glob
  MCP005 dangerous eval      MCP006 unpinned remote code execution
  MCP007 prototype pollution MCP008 SSRF-able fetch (attacker URL)
  MCP009 hardcoded secret    MCP010 path traversal in a file tool
  MCP011 unsafe deserialize  MCP012 dangerous npm lifecycle script
  MCP013 secret in manifest  MCP014 risky declared dependency

This is static analysis. It cannot catch obfuscated, indirected or
runtime-only vulnerabilities. A clean result is NOT a security guarantee —
review the server's tools and scope yourself before wiring it into an agent.`;

function parseArgs(argv) {
  const opts = {
    target: null,
    json: false,
    sarif: false,
    failOn: "high",
    baseline: null,
    baselineWrite: null,
    monitorJson: false,
    quiet: false,
    color: undefined,
    help: false,
    version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") opts.help = true;
    else if (a === "-v" || a === "--version") opts.version = true;
    else if (a === "--json") opts.json = true;
    else if (a === "--sarif") opts.sarif = true;
    else if (a === "--monitor-json") opts.monitorJson = true;
    else if (a === "--include-tests") opts.includeTests = true;
    else if (a === "--quiet") opts.quiet = true;
    else if (a === "--no-color") opts.color = false;
    else if (a === "--color") opts.color = true;
    else if (a === "--fail-on") {
      opts.failOn = (argv[++i] || "").toLowerCase();
    } else if (a.startsWith("--fail-on=")) {
      opts.failOn = a.slice("--fail-on=".length).toLowerCase();
    } else if (a === "--baseline") {
      opts.baseline = argv[++i] ?? "";
    } else if (a.startsWith("--baseline=")) {
      opts.baseline = a.slice("--baseline=".length);
    } else if (a === "--baseline-write") {
      opts.baselineWrite = argv[++i] ?? "";
    } else if (a.startsWith("--baseline-write=")) {
      opts.baselineWrite = a.slice("--baseline-write=".length);
    } else if (a.startsWith("-")) {
      return { error: `unknown option: ${a}` };
    } else if (opts.target === null) {
      opts.target = a;
    } else {
      return { error: `unexpected extra argument: ${a}` };
    }
  }
  return { opts };
}

async function run(argv, out, err) {
  const { opts, error } = parseArgs(argv);
  if (error) {
    err(error + "\n\n" + HELP);
    return 2;
  }
  if (opts.help) {
    out(HELP);
    return 0;
  }
  if (opts.version) {
    out(VERSION);
    return 0;
  }
  if (!opts.target) {
    err("error: a <path> or <package> argument is required.\n\n" + HELP);
    return 2;
  }
  if (!VALID_GATES.includes(opts.failOn)) {
    err(
      `error: --fail-on must be one of ${VALID_GATES.join(", ")} (got "${opts.failOn}")\n`,
    );
    return 2;
  }

  // --- everything below must never crash the host CI ---
  try {
    const t = resolveTarget(opts.target);
    let dir;
    if (t.kind === "path") {
      dir = await new LocalDirSource().materialize(t.value).catch((e) => {
        throw new Error(e.message);
      });
    } else {
      // Named package: the shipped default source is an honest stub. It
      // throws a clear, actionable message (no silent no-op, no network).
      dir = await new StubRegistrySource().materialize(t.value);
    }

    const report = analyzeProject(dir, { includeTests: opts.includeTests });

    // --- baseline WRITE: persist current state, exit 0 (accept). ----------
    if (opts.baselineWrite !== null) {
      if (!opts.baselineWrite) {
        err("error: --baseline-write needs a file path.");
        return 2;
      }
      const doc = buildBaseline(report);
      try {
        writeFileSync(opts.baselineWrite, JSON.stringify(doc, null, 2) + "\n");
      } catch (e) {
        // writing the baseline is the user's explicit intent — a failure here
        // IS a usage/operational error worth signalling (not a scan gate).
        err(`mcpaudit: could not write baseline ${opts.baselineWrite}: ${e.message}`);
        return 2;
      }
      err(
        `mcpaudit: wrote baseline (${doc.summary.total} finding(s)) to ${opts.baselineWrite}. Commit it; future runs with --baseline gate only on NEW findings.`,
      );
      return 0;
    }

    // --- baseline DIFF: report new/fixed; gate only on NEW. ---------------
    let diff = null;
    if (opts.baseline !== null) {
      if (!opts.baseline) {
        err("error: --baseline needs a file path.");
        return 2;
      }
      let baselineDoc = null;
      try {
        baselineDoc = JSON.parse(readFileSync(opts.baseline, "utf8"));
      } catch {
        baselineDoc = null; // diffAgainstBaseline reports all-as-NEW + a note
      }
      diff = diffAgainstBaseline(report, baselineDoc);
    }

    if (opts.sarif) {
      out(formatSarif(report, VERSION).replace(/\n$/, ""));
    } else if (opts.monitorJson && diff) {
      out(JSON.stringify(monitoringRecord(report, diff), null, 2));
    } else if (opts.json) {
      const base = JSON.parse(formatJson(report));
      if (diff) {
        base.baseline = {
          schemaOk: diff.schemaOk,
          note: diff.note,
          counts: diff.counts,
          newFindingIds: diff.newFindings.map((f) => f.id),
          fixedFindingIds: diff.fixedFindings.map((f) => f.id),
        };
      }
      out(JSON.stringify(base, null, 2));
    } else {
      const useColor =
        opts.color === undefined
          ? Boolean(process.stdout.isTTY) && !process.env.CI
          : opts.color;
      let text = formatHuman(report, { color: useColor });
      if (opts.quiet && report.findings.length === 0) text = "";
      if (text) out(text);
      if (diff) {
        const dl = [];
        dl.push("");
        dl.push("baseline diff:");
        if (diff.note) dl.push(`  note: ${diff.note}`);
        dl.push(
          `  NEW: ${diff.counts.new} · FIXED: ${diff.counts.fixed} · unchanged: ${diff.counts.unchanged}`,
        );
        for (const f of diff.newFindings) {
          dl.push(
            `  + NEW ${f.ruleId} [${f.severity}] ${f.file}:${f.line}:${f.column}`,
          );
        }
        for (const f of diff.fixedFindings) {
          dl.push(`  - FIXED ${f.ruleId || ""} ${f.file || ""}`.trimEnd());
        }
        out(dl.join("\n"));
      }
    }

    // Gate. Default: gate on ALL findings >= fail-on. With --baseline: gate
    // ONLY on NEW findings (a triaged/accepted finding does not re-break the
    // build; a freshly-introduced regression does).
    const gateSet = diff ? diff.newFindings : report.findings;
    if (gate(gateSet, opts.failOn)) {
      if (!opts.json && !opts.sarif && !opts.monitorJson) {
        err(
          diff
            ? `\nmcpaudit: gate FAILED — NEW finding(s) at or above "${opts.failOn}" since the baseline. (exit 1)`
            : `\nmcpaudit: gate FAILED — found finding(s) at or above "${opts.failOn}". (exit 1)`,
        );
      }
      return 1;
    }
    return 0;
  } catch (e) {
    // Internal/operational failure: fail OPEN but LOUD. We exit 0 so a
    // scanner bug does not block every PR; the message makes it impossible
    // to miss, and `--fail-on` as a *required* check is the way to enforce.
    err(
      `mcpaudit: could not complete the scan (${e && e.message ? e.message : e}). ` +
        `Treating as NO RESULT and exiting 0 so your pipeline is not blocked ` +
        `by a scanner failure. Re-run with a local path, or open an issue ` +
        `with the 'mcpaudit-feedback' label.`,
    );
    return 0;
  }
}

// Only auto-run as a CLI (keeps run() unit-testable without spawning).
const isMain =
  process.argv[1] &&
  (process.argv[1].endsWith("mcpaudit.js") ||
    process.argv[1].endsWith("mcpaudit"));
if (isMain) {
  run(
    process.argv.slice(2),
    (s) => process.stdout.write(s + "\n"),
    (s) => process.stderr.write(s + "\n"),
  ).then((code) => {
    process.exitCode = code;
  });
}

export { run, parseArgs };
