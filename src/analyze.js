/**
 * analyze.js — the only place that touches the filesystem.
 *
 * Walks a local MCP-server directory, reads source + manifest files, and
 * dispatches the pure rules in rules.js. It NEVER executes the scanned
 * project and NEVER does network I/O. Any error reading the tree is
 * collected into `errors` and returned — analyzeProject does not throw, so a
 * CI wrapper can catch nothing and still exit cleanly.
 */

import {
  readFileSync,
  readdirSync,
  statSync,
  lstatSync,
  existsSync,
  realpathSync,
} from "node:fs";
import { join, relative, sep, resolve } from "node:path";
import { createHash } from "node:crypto";
import { analyzeSource, analyzeManifest } from "./rules.js";
import { loadConfig, CONFIG_NAME } from "./config.js";

const SOURCE_EXT = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts"]);
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".next",
  ".cache",
  "out",
  "vendor",
]);
const MANIFEST_NAMES = new Set(["package.json", "mcp.json", "server.json"]);

// Test and mock files are developer-authored fixtures, not code an agent will
// execute at runtime. Scanning them is almost pure noise: on the official
// modelcontextprotocol/servers repo, 19 of 47 findings came from `__tests__/`
// alone. Skipped by default; `--include-tests` scans them anyway.
const TEST_FILE_RE = /\.(test|spec)\.[cm]?[jt]sx?$/i;
// Matched against the path RELATIVE to the scan root, so pointing the scanner
// straight at `test/fixtures/some-server` still scans it normally — only a
// `test/` directory *inside* the audited tree is skipped.
const TEST_DIR_RE = /(^|[\\/])(__tests__|__mocks__|tests?|specs?|e2e)([\\/])/i;
function looksLikeTest(rel) {
  return TEST_FILE_RE.test(rel) || TEST_DIR_RE.test(rel);
}

const MAX_FILE_BYTES = 2 * 1024 * 1024; // skip absurdly large/minified blobs
const MAX_FILES = 5000;
const MAX_DEPTH = 40; // pathological deep trees / symlink-ish loops guard

/**
 * A line is "minified/obfuscated" if it is extremely long. Running the
 * lexical rules on a 200 KB single-line bundle is pointless (no real
 * line/col, and it's a build artifact, not the audited source) and is a DoS
 * vector — we skip the file and surface it as a diagnostic instead of
 * grinding (or worse, mis-reporting a finding at col 90000).
 */
function looksMinified(txt) {
  if (txt.length < 50000) return false;
  let longest = 0;
  let cur = 0;
  for (let i = 0; i < txt.length; i++) {
    if (txt.charCodeAt(i) === 10) {
      if (cur > longest) longest = cur;
      cur = 0;
    } else cur++;
  }
  if (cur > longest) longest = cur;
  return longest > 5000;
}

// Cheap binary sniff: a NUL in the first 4 KB ⇒ not source we should lex.
function looksBinary(txt) {
  const n = Math.min(txt.length, 4096);
  for (let i = 0; i < n; i++) if (txt.charCodeAt(i) === 0) return true;
  return false;
}

function isManifest(name) {
  return MANIFEST_NAMES.has(name) || name.endsWith(".mcp.json");
}

/**
 * Walk the tree WITHOUT following symlinks out of (or anywhere via) the
 * target. We use the entry's own `Dirent` type (lstat semantics from
 * `readdirSync(..., {withFileTypes:true})`) and explicitly skip symlinks —
 * a malicious server could otherwise point a symlink at `/etc` or create a
 * loop. The scanned root is canonicalised once and every descended dir is
 * asserted to stay within it (defence in depth against TOCTOU/junctions).
 */
function* walk(root, errors) {
  let canonRoot;
  try {
    canonRoot = realpathSync(root);
  } catch {
    canonRoot = resolve(root);
  }
  const stack = [{ dir: root, depth: 0 }];
  let count = 0;
  while (stack.length) {
    const { dir, depth } = stack.pop();
    if (depth > MAX_DEPTH) {
      errors.push(`max directory depth (${MAX_DEPTH}) reached at ${dir}; subtree skipped`);
      continue;
    }
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      errors.push(`cannot read directory ${dir}: ${e.message}`);
      continue;
    }
    for (const ent of entries) {
      const full = join(dir, ent.name);
      // Never traverse OR read through a symlink. This is the single most
      // important hardening: the scanner must not be steerable out of the
      // target tree (read /root/.ssh, follow a loop, etc.).
      if (ent.isSymbolicLink()) {
        errors.push(`skipped symlink (not followed): ${relative(root, full) || ent.name}`);
        continue;
      }
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name) || ent.name.startsWith(".")) continue;
        // Defence in depth: confirm the real path is still inside the root.
        let realFull;
        try {
          realFull = realpathSync(full);
        } catch {
          realFull = resolve(full);
        }
        if (
          realFull !== canonRoot &&
          !realFull.startsWith(canonRoot + sep)
        ) {
          errors.push(`skipped path outside scan root: ${relative(root, full) || ent.name}`);
          continue;
        }
        stack.push({ dir: full, depth: depth + 1 });
      } else if (ent.isFile()) {
        if (++count > MAX_FILES) {
          errors.push(`file cap (${MAX_FILES}) reached; scan truncated`);
          return;
        }
        yield full;
      }
      // sockets/FIFOs/block devices: ignored (not isFile/isDirectory).
    }
  }
}

function safeRead(file, errors, { allowLarge = false } = {}) {
  try {
    // lstat (not stat) so a symlinked FILE that slipped through is sized as
    // the link, and we still never readFileSync-follow it below.
    const st = lstatSync(file);
    if (st.isSymbolicLink()) {
      errors.push(`skipped symlink file (not followed): ${file}`);
      return null;
    }
    if (!allowLarge && st.size > MAX_FILE_BYTES) {
      errors.push(
        `skipped large file (> ${MAX_FILE_BYTES} bytes): ${file} (likely a bundle/minified artifact)`,
      );
      return null;
    }
    // Read as bytes then decode: invalid UTF-8 becomes U+FFFD instead of
    // throwing, so a non-UTF8 file degrades the scan, never aborts it.
    const buf = readFileSync(file);
    const txt = buf.toString("utf8");
    if (looksBinary(txt)) {
      errors.push(`skipped binary/non-text file: ${file}`);
      return null;
    }
    return txt;
  } catch (e) {
    errors.push(`cannot read file ${file}: ${e.message}`);
    return null;
  }
}

/**
 * @param {string} rootDir absolute or relative path to an MCP server tree
 * @param {{ followManifestOnly?: boolean, includeTests?: boolean }} [opts]
 * @returns {{ root:string, findings:Finding[], scannedFiles:string[], errors:string[] }}
 */
export function analyzeProject(rootDir, opts = {}) {
  const errors = [];
  const findings = [];
  const scannedFiles = [];
  // rel path → sha256 of contents, used to spot generated/vendored duplicates.
  const contentHash = new Map();

  if (!existsSync(rootDir)) {
    return {
      root: rootDir,
      findings,
      scannedFiles,
      errors: [`path does not exist: ${rootDir}`],
    };
  }
  let rootStat;
  try {
    rootStat = statSync(rootDir);
  } catch (e) {
    return {
      root: rootDir,
      findings,
      scannedFiles,
      errors: [`cannot stat ${rootDir}: ${e.message}`],
    };
  }
  if (!rootStat.isDirectory()) {
    return {
      root: rootDir,
      findings,
      scannedFiles,
      errors: [`not a directory: ${rootDir} (point mcpaudit at the server's source folder)`],
    };
  }

  const cfg = loadConfig(rootDir, errors);
  const stats = { suppressedByConfig: 0 };

  // A few rules are version-sensitive: js-yaml 4 made `load` the safe one, so
  // flagging it in a project that declares ^4 reports a bug the dependency
  // fixed years ago. Read the root manifest once and hand the ranges down.
  let deps;
  try {
    const pkg = JSON.parse(readFileSync(join(rootDir, "package.json"), "utf8"));
    deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  } catch {
    deps = undefined; // no manifest, or unreadable: rules fall back to strict
  }

  for (const file of walk(rootDir, errors)) {
    const base = file.split(sep).pop();
    const rel = relative(rootDir, file) || base;
    const dot = file.slice(file.lastIndexOf("."));

    if (isManifest(base)) {
      const txt = safeRead(file, errors);
      if (txt == null) continue;
      scannedFiles.push(rel);
      let json;
      try {
        json = JSON.parse(txt);
      } catch (e) {
        errors.push(`invalid JSON in ${rel}: ${e.message}`);
        continue;
      }
      for (const f of analyzeManifest(json, rel)) findings.push(f);
      continue;
    }

    if (opts.followManifestOnly) continue;
    if (!SOURCE_EXT.has(dot)) continue;
    if (/\.min\.js$/.test(base) || /\.d\.ts$/.test(base) || /\.bundle\.js$/.test(base))
      continue;
    if (!opts.includeTests && looksLikeTest(rel)) continue;
    const txt = safeRead(file, errors);
    if (txt == null) continue;
    if (looksMinified(txt)) {
      errors.push(
        `skipped minified/obfuscated source (very long lines): ${rel} — audit the original, not the bundle`,
      );
      continue;
    }
    scannedFiles.push(rel);
    contentHash.set(rel, createHash("sha256").update(txt).digest("hex"));
    for (const f of analyzeSource(txt, rel, cfg, stats, deps)) findings.push(f);
  }

  // GENERATED / VENDORED COPIES.
  // A repo that ships the same library into several integration directories
  // gets its finding count multiplied by the number of copies, which reads as
  // a much bigger problem than it is. ooples/token-optimizer-mcp keeps one
  // source of truth in `hooks-core/` and generates ten copies under
  // `integrations/*/hooks/lib/` (each stamped "GENERATED FILE -- do not edit",
  // regenerated by `npm run sync:hooks`); 47% of that scan's 247 findings were
  // the same nine files counted ten times. Every copy is still reported —
  // suppressing a real finding because it appears twice would be worse — but
  // the count that matters is stated alongside the raw one.
  const byHash = new Map();
  for (const [rel, h] of contentHash) {
    if (!byHash.has(h)) byHash.set(h, []);
    byHash.get(h).push(rel);
  }
  const findingsPerFile = new Map();
  for (const f of findings)
    findingsPerFile.set(f.file, (findingsPerFile.get(f.file) ?? 0) + 1);

  const duplicateGroups = [];
  for (const files of byHash.values()) {
    if (files.length < 2) continue;
    files.sort();
    const perCopy = findingsPerFile.get(files[0]) ?? 0;
    if (perCopy === 0) continue; // identical clean files are not worth saying
    duplicateGroups.push({ canonical: files[0], copies: files.length, perCopy });
  }
  if (duplicateGroups.length) {
    const raw = duplicateGroups.reduce((n, g) => n + g.perCopy * g.copies, 0);
    const once = duplicateGroups.reduce((n, g) => n + g.perCopy, 0);
    errors.push(
      `${raw} of ${findings.length} finding(s) are in ${duplicateGroups.length} group(s) of ` +
        `byte-identical files (generated or vendored copies). Counting each group once ` +
        `gives ${findings.length - raw + once} distinct finding(s). Fixing the original ` +
        `fixes every copy.`,
    );
  }

  // Config-driven suppression is a human assertion, not an analysis result, so
  // it is always surfaced. A scanner that silently drops findings because of a
  // file in the repo it just scanned is worse than one that over-reports.
  if (stats.suppressedByConfig > 0) {
    errors.push(
      `${stats.suppressedByConfig} finding(s) suppressed by ${CONFIG_NAME} ` +
        `(pathValidators / trustedPathVars). Delete or rename that file to see them.`,
    );
  }

  // A hostile tree could otherwise emit a multi-MB `errors` array; cap it so
  // the scanner's own output stays bounded (it still never throws).
  if (errors.length > 200) {
    const extra = errors.length - 200;
    errors.length = 200;
    errors.push(`(+${extra} more diagnostics suppressed)`);
  }

  // Stable, useful ordering: severity desc, then file, then line.
  const order = { critical: 4, high: 3, medium: 2, low: 1 };
  findings.sort(
    (a, b) =>
      (order[b.severity] ?? 0) - (order[a.severity] ?? 0) ||
      a.file.localeCompare(b.file) ||
      a.line - b.line ||
      a.ruleId.localeCompare(b.ruleId),
  );

  return { root: rootDir, findings, scannedFiles, errors, duplicateGroups };
}
