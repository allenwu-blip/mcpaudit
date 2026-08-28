import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { analyzeProject } from "../src/analyze.js";
import { loadConfig, CONFIG_NAME } from "../src/config.js";

// A server whose fs paths arrive the two ways the analyzer cannot resolve on
// its own: out of a project-local validator, and as a bare function parameter.
const SERVER = `
import fs from "node:fs/promises";
import { validatePath } from "./guard.js";

export async function listing(requested) {
  const validPath = await validatePath(requested);
  return await fs.readdir(validPath, { withFileTypes: true });
}

export async function readOne(filePath) {
  return await fs.readFile(filePath, "utf-8");
}
`;

let dir;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "mcpaudit-cfg-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "src", "index.js"), SERVER, "utf8");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const cfg = (obj) =>
  writeFileSync(join(dir, CONFIG_NAME), JSON.stringify(obj), "utf8");

describe("loadConfig", () => {
  it("returns empty defaults when no config file exists", () => {
    const c = loadConfig(dir, []);
    expect(c.present).toBe(false);
    expect(c.pathValidators).toEqual([]);
    expect(c.trustedPathVars).toEqual([]);
  });

  it("never throws on malformed JSON; reports and falls back", () => {
    writeFileSync(join(dir, CONFIG_NAME), "{ not json", "utf8");
    const errors = [];
    const c = loadConfig(dir, errors);
    expect(c.present).toBe(false);
    expect(errors.join(" ")).toMatch(/invalid JSON/);
  });

  it("ignores unknown keys and non-identifier entries, and says so", () => {
    cfg({ pathValidators: ["validatePath", "../evil", 7], bogusKey: 1 });
    const errors = [];
    const c = loadConfig(dir, errors);
    expect(c.pathValidators).toEqual(["validatePath"]);
    expect(errors.join(" ")).toMatch(/unknown key/);
  });
});

describe("config-driven suppression of MCP010", () => {
  it("without a config, both path sinks are reported", () => {
    const r = analyzeProject(dir);
    const m010 = r.findings.filter((f) => f.ruleId === "MCP010");
    expect(m010).toHaveLength(2);
  });

  it("a declared validator suppresses instead of downgrading", () => {
    cfg({ pathValidators: ["validatePath"] });
    const r = analyzeProject(dir);
    const m010 = r.findings.filter((f) => f.ruleId === "MCP010");
    expect(m010).toHaveLength(1); // only the bare-parameter one survives
    expect(m010[0].snippet).toMatch(/readFile/);
  });

  it("a declared trusted variable suppresses the bare-parameter sink", () => {
    cfg({ trustedPathVars: ["filePath"] });
    const r = analyzeProject(dir);
    const m010 = r.findings.filter((f) => f.ruleId === "MCP010");
    expect(m010).toHaveLength(1);
    expect(m010[0].snippet).toMatch(/readdir/);
  });

  it("suppression is never silent: the count is always reported", () => {
    cfg({ pathValidators: ["validatePath"], trustedPathVars: ["filePath"] });
    const r = analyzeProject(dir);
    expect(r.findings.filter((f) => f.ruleId === "MCP010")).toHaveLength(0);
    expect(r.errors.join(" ")).toMatch(/2 finding\(s\) suppressed/);
    expect(r.errors.join(" ")).toContain(CONFIG_NAME);
  });

  it("an undeclared validator still only downgrades, never suppresses", () => {
    // No config at all: the naming-convention heuristic must keep the finding
    // visible at `low` rather than dropping it.
    const r = analyzeProject(dir);
    const viaValidator = r.findings.find(
      (f) => f.ruleId === "MCP010" && /readdir/.test(f.snippet),
    );
    expect(viaValidator).toBeDefined();
    expect(viaValidator.severity).toBe("low");
  });
});
