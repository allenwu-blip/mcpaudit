import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { analyzeProject } from "../src/analyze.js";
import { gate, SEVERITY_ORDER } from "../src/rules.js";
import { formatHuman, formatJson } from "../src/format.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (n) => join(here, "fixtures", n);

describe("analyzeProject on fixtures (offline, no network)", () => {
  it("clean-server produces ZERO findings", () => {
    const r = analyzeProject(fx("clean-server"));
    expect(r.errors).toEqual([]);
    expect(r.findings, JSON.stringify(r.findings, null, 2)).toHaveLength(0);
    expect(r.scannedFiles.length).toBeGreaterThan(0);
  });

  it("vulnerable-server fires every rule with correct severity", () => {
    const r = analyzeProject(fx("vulnerable-server"));
    const rules = new Set(r.findings.map((f) => f.ruleId));
    for (const id of [
      "MCP001",
      "MCP002",
      "MCP003",
      "MCP004",
      "MCP005",
      "MCP006",
    ]) {
      expect(rules.has(id), `expected ${id} to fire`).toBe(true);
    }
    const sev = (id) =>
      r.findings.find((f) => f.ruleId === id).severity;
    expect(sev("MCP001")).toBe("critical");
    expect(sev("MCP002")).toBe("high");
    expect(sev("MCP003")).toBe("high");
    expect(sev("MCP005")).toBe("high");
    expect(sev("MCP004")).toBe("medium");
    expect(sev("MCP006")).toBe("medium");

    // file:line must point into the right file.
    const inj = r.findings.find((f) => f.ruleId === "MCP001");
    expect(inj.file).toMatch(/index\.js$/);
    expect(inj.line).toBeGreaterThan(0);
  });

  it("borderline-server produces ZERO findings (false-positive guard)", () => {
    const r = analyzeProject(fx("borderline-server"));
    expect(
      r.findings,
      "borderline must not false-positive:\n" +
        JSON.stringify(r.findings, null, 2),
    ).toHaveLength(0);
  });

  it("returns a diagnostic (not a throw) for a missing directory", () => {
    const r = analyzeProject(fx("does-not-exist"));
    expect(r.errors.length).toBeGreaterThan(0);
    expect(Array.isArray(r.findings)).toBe(true);
  });
});

describe("gate()", () => {
  const mk = (sev) => ({ severity: sev });
  it("orders severities", () => {
    expect(SEVERITY_ORDER.critical).toBeGreaterThan(SEVERITY_ORDER.high);
    expect(SEVERITY_ORDER.high).toBeGreaterThan(SEVERITY_ORDER.medium);
    expect(SEVERITY_ORDER.medium).toBeGreaterThan(SEVERITY_ORDER.low);
  });
  it("fails when a finding meets/exceeds the gate", () => {
    expect(gate([mk("high")], "high")).toBe(true);
    expect(gate([mk("critical")], "high")).toBe(true);
  });
  it("passes when below the gate", () => {
    expect(gate([mk("medium"), mk("low")], "high")).toBe(false);
  });
  it("'none' never gates", () => {
    expect(gate([mk("critical")], "none")).toBe(false);
  });
  it("empty findings never gate", () => {
    expect(gate([], "low")).toBe(false);
  });
});

describe("formatters", () => {
  const report = {
    root: "/tmp/x",
    findings: [
      {
        id: "MCP001-1",
        ruleId: "MCP001",
        severity: "critical",
        file: "src/i.js",
        line: 3,
        column: 5,
        message: "command injection via exec()",
        remediation: "use execFile with an argv array",
        snippet: "exec(`ping ${host}`)",
      },
    ],
    scannedFiles: ["src/i.js"],
    errors: [],
  };

  it("formatJson is valid parseable JSON with a schema version + summary", () => {
    const obj = JSON.parse(formatJson(report));
    expect(obj.schema).toBeTypeOf("string");
    expect(obj.summary.total).toBe(1);
    expect(obj.summary.bySeverity.critical).toBe(1);
    expect(obj.findings[0].ruleId).toBe("MCP001");
  });

  it("formatHuman includes severity, location, message and remediation", () => {
    const s = formatHuman(report);
    expect(s).toMatch(/MCP001/);
    expect(s).toMatch(/critical/i);
    expect(s).toMatch(/src\/i\.js:3/);
    expect(s).toMatch(/execFile/);
  });

  it("formatHuman reports a clean bill of health on zero findings", () => {
    const s = formatHuman({ ...report, findings: [] });
    expect(s).toMatch(/no findings|clean/i);
  });
});

// A repo that generates the same library into several integration directories
// gets its finding count multiplied by the number of copies. Found scanning
// ooples/token-optimizer-mcp, where `hooks-core/` is the source of truth and
// ten copies are generated under `integrations/*/hooks/lib/` — 47% of that
// scan's findings were nine files counted ten times.
describe("generated/vendored duplicate accounting", () => {
  let dir;
  const VULN =
    "import { execSync } from 'child_process';\n" +
    "export function run(p) { return execSync(`ls ${p}`); }\n";

  const mk = (rel, body) => {
    const full = join(dir, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, body, "utf8");
  };

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "mcpaudit-dupes-"));
    mk("package.json", JSON.stringify({ name: "d", version: "1.0.0" }));
    mk("hooks-core/lib.js", VULN);
    for (const agent of ["cursor", "codex", "gemini"])
      mk(`integrations/${agent}/hooks/lib.js`, VULN);
    // A file with the same finding but DIFFERENT bytes is not a copy.
    mk("src/other.js", VULN + "// unrelated module\n");
  });

  it("groups byte-identical files and states the deduplicated count", () => {
    const r = analyzeProject(dir);
    expect(r.duplicateGroups).toHaveLength(1);
    expect(r.duplicateGroups[0].copies).toBe(4);
    expect(r.duplicateGroups[0].perCopy).toBe(1);
    // 4 copies + 1 unique file = 5 findings, 2 distinct.
    expect(r.findings).toHaveLength(5);
    const note = r.errors.find((e) => /leading comment banner/.test(e));
    expect(note).toBeTruthy();
    expect(note).toMatch(/gives 2 distinct/);
  });

  it("does not name a source when every file in the group is identical", () => {
    // Nothing here carries a banner, so there is no odd one out. Guessing
    // which of four identical files is "the original" would be a coin flip.
    const r = analyzeProject(dir);
    expect(r.duplicateGroups[0].source).toBeNull();
    expect(r.errors.find((e) => /Edit the un-stamped original/.test(e))).toBeUndefined();
  });

  it("still REPORTS every copy — dedup is accounting, not suppression", () => {
    const r = analyzeProject(dir);
    const files = r.findings.map((f) => f.file.replace(/\\/g, "/"));
    expect(files).toContain("hooks-core/lib.js");
    expect(files).toContain("integrations/cursor/hooks/lib.js");
    expect(files).toContain("integrations/codex/hooks/lib.js");
    expect(files).toContain("integrations/gemini/hooks/lib.js");
  });

  it("says nothing when identical files are clean", () => {
    const clean = mkdtempSync(join(tmpdir(), "mcpaudit-clean-dupes-"));
    for (const p of ["a/x.js", "b/x.js"]) {
      mkdirSync(join(clean, dirname(p)), { recursive: true });
      writeFileSync(join(clean, p), "export const N = 1;\n", "utf8");
    }
    const r = analyzeProject(clean);
    expect(r.duplicateGroups).toHaveLength(0);
    expect(r.errors.some((e) => /leading comment banner/.test(e))).toBe(false);
    rmSync(clean, { recursive: true, force: true });
  });
});

// Reported by @ooples on ooples/token-optimizer-mcp#343: every generated copy
// there carries a two-line "GENERATED FILE -- do not edit" banner, so a
// raw-bytes grouper leaves the source of truth outside the group it is the
// source of — "the file your report tells a maintainer to edit is the one file
// your grouper won't group."
describe("generated copies carrying a banner", () => {
  let dir;
  const VULN = 'import { execSync } from "child_process";\nexport const r = (c) => execSync(`ls ${c}`);\n';
  const BANNER =
    "// GENERATED FILE -- do not edit.\n" +
    "// Source of truth: hooks-core/lib.js. Regenerate with `npm run sync:hooks`.\n";

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "mcpaudit-banner-"));
    const mk = (rel, body) => {
      const full = join(dir, rel);
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, body, "utf8");
    };
    mk("package.json", JSON.stringify({ name: "b", version: "1.0.0" }));
    mk("hooks-core/lib.js", VULN);
    for (const agent of ["cursor", "codex", "gemini"])
      mk(`integrations/${agent}/hooks/lib.js`, BANNER + VULN);
  });

  it("groups the un-stamped source together with its stamped copies", () => {
    const r = analyzeProject(dir);
    expect(r.duplicateGroups).toHaveLength(1);
    expect(r.duplicateGroups[0].copies).toBe(4);
  });

  it("names the source as the file to edit", () => {
    const r = analyzeProject(dir);
    expect(r.duplicateGroups[0].source.replace(/\\/g, "/")).toBe("hooks-core/lib.js");
    const note = r.errors.find((e) => /Edit the un-stamped original/.test(e));
    expect(note).toBeTruthy();
    expect(note).toMatch(/hooks-core[\\/]lib\.js/);
  });

  it("still reports the finding in every copy", () => {
    const r = analyzeProject(dir);
    const files = r.findings.map((f) => f.file.replace(/\\/g, "/"));
    expect(files).toContain("hooks-core/lib.js");
    expect(files).toContain("integrations/cursor/hooks/lib.js");
    expect(files).toContain("integrations/codex/hooks/lib.js");
    expect(files).toContain("integrations/gemini/hooks/lib.js");
  });

  it("does not group two modules that merely share a banner", () => {
    // The banner is stripped for comparison, not ignored wholesale — files
    // with different bodies must stay apart however similar their headers.
    const two = mkdtempSync(join(tmpdir(), "mcpaudit-banner2-"));
    mkdirSync(join(two, "a"), { recursive: true });
    mkdirSync(join(two, "b"), { recursive: true });
    writeFileSync(join(two, "package.json"), JSON.stringify({ name: "t", version: "1.0.0" }), "utf8");
    writeFileSync(join(two, "a/x.js"), BANNER + VULN, "utf8");
    writeFileSync(join(two, "b/x.js"), BANNER + VULN.replace("ls", "cat"), "utf8");
    const r = analyzeProject(two);
    expect(r.duplicateGroups).toHaveLength(0);
    rmSync(two, { recursive: true, force: true });
  });
});

describe("dot-directories are scanned unless named", () => {
  // `.github/` held one of eleven generated copies in token-optimizer-mcp, and
  // `.cursor/mcp.json` / `.vscode/mcp.json` are manifests MCP003/4/6 exist to
  // read. A blanket dot-prefix skip made all of them invisible.
  let dir;
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "mcpaudit-dotdirs-"));
    const mk = (rel, body) => {
      const full = join(dir, rel);
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, body, "utf8");
    };
    mk("package.json", JSON.stringify({ name: "d", version: "1.0.0" }));
    mk(
      ".github/hooks/lib.js",
      'import { execSync } from "child_process";\nexport const r = (c) => execSync(`ls ${c}`);\n',
    );
    mk(".git/objects/evil.js", 'import { execSync } from "child_process";\nexport const r = (c) => execSync(`ls ${c}`);\n');
    mk(".venv/lib/pkg.js", 'import { execSync } from "child_process";\nexport const r = (c) => execSync(`ls ${c}`);\n');
  });

  it("scans .github", () => {
    const r = analyzeProject(dir);
    const files = r.findings.map((f) => f.file.replace(/\\/g, "/"));
    expect(files).toContain(".github/hooks/lib.js");
  });

  it("still skips VCS metadata and virtualenvs", () => {
    const r = analyzeProject(dir);
    const files = r.findings.map((f) => f.file.replace(/\\/g, "/"));
    expect(files.some((f) => f.startsWith(".git/"))).toBe(false);
    expect(files.some((f) => f.startsWith(".venv/"))).toBe(false);
  });
});
