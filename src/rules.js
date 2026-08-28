/**
 * rules.js — the pure, deterministic static-analysis core of `mcpaudit`.
 *
 * NO file I/O, NO network, NO code execution. Everything here is a pure
 * function from (source string | parsed manifest) to Finding[]. This is what
 * makes the scanner fully unit-testable and safe to run before an untrusted
 * MCP server is ever executed.
 *
 * Design stance: a security scanner that cries wolf gets uninstalled. Every
 * rule is deliberately CONSERVATIVE and every Finding explains *why* it
 * fired. Pattern-based static analysis cannot be complete (see README
 * "Limitations") — we accept some false negatives to keep false positives
 * low on the obvious-newbie-safe patterns (literal `exec`, literal `eval`,
 * env read into a non-returned constant, scoped relative dirs).
 */

export const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

/**
 * Lexically blank the parts of the source a rule must NOT match on — line
 * and block comments, and the *static text* of string / template literals —
 * while PRESERVING, as live code, the `${ ... }` interpolation expressions
 * inside template literals. Removed regions are replaced with spaces so
 * 1-based line/column offsets are preserved exactly.
 *
 * This is the correct lexical model for these rules: a commented-out
 * `exec(...)` or a `process.env` mentioned in prose is not a finding, but
 * `exec(`ping ${userInput}`)` IS — the danger is the interpolated *code*,
 * which we keep visible. A plain quoted string ("ls -la") is fully blanked.
 * Not a full JS parser, but predictable and the single biggest
 * false-positive reducer.
 *
 * @param {string} src
 * @returns {{ code: string, strings: Array<{line:number,raw:string,quote:string,hasInterp:boolean}> }}
 *   `code` is the blanked source (template `${}` exprs preserved);
 *   `strings` records each literal (raw text incl. `${}`, start line, quote,
 *   whether it had any interpolation).
 */
export function maskNonCode(src) {
  let out = "";
  const strings = [];
  let i = 0;
  const n = src.length;
  let line = 1;
  // template-literal stack so nested templates inside ${} work
  /** @type {Array<{startLine:number, buf:string, hasInterp:boolean}>} */
  let cur = null; // { quote, startLine, buf, hasInterp }
  const blank = (ch) => (ch === "\n" ? "\n" : " ");

  while (i < n) {
    const ch = src[i];
    const two = src.slice(i, i + 2);

    if (cur) {
      // inside a string / template literal
      if (ch === "\\") {
        cur.buf += two;
        out += blank(ch) + blank(src[i + 1] ?? " ");
        if (src[i + 1] === "\n") line++;
        i += 2;
        continue;
      }
      // Template-literal interpolation: keep `${ ... }` as live code so
      // rules see process.env / variables inside it. We copy the whole
      // balanced ${...} (including nested braces/strings) verbatim to `out`.
      if (cur.quote === "`" && two === "${") {
        cur.hasInterp = true;
        cur.buf += "${";
        out += "${";
        i += 2;
        let depth = 1;
        while (i < n && depth > 0) {
          const cc = src[i];
          if (cc === "{") depth++;
          else if (cc === "}") depth--;
          if (depth === 0) {
            cur.buf += "}";
            out += "}";
            i++;
            break;
          }
          cur.buf += cc;
          out += cc; // preserved as code
          if (cc === "\n") line++;
          i++;
        }
        continue;
      }
      if (
        (cur.quote === "`" && ch === "`") ||
        (cur.quote !== "`" && ch === cur.quote)
      ) {
        strings.push({
          line: cur.startLine,
          raw: cur.buf,
          quote: cur.quote,
          hasInterp: cur.hasInterp,
        });
        out += blank(ch);
        cur = null;
        i++;
        continue;
      }
      cur.buf += ch;
      out += blank(ch);
      if (ch === "\n") line++;
      i++;
      continue;
    }

    if (two === "//") {
      while (i < n && src[i] !== "\n") {
        out += " ";
        i++;
      }
      continue;
    }
    if (two === "/*") {
      out += "  ";
      i += 2;
      while (i < n && src.slice(i, i + 2) !== "*/") {
        out += blank(src[i]);
        if (src[i] === "\n") line++;
        i++;
      }
      if (i < n) {
        out += "  ";
        i += 2;
      }
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      cur = { quote: ch, startLine: line, buf: "", hasInterp: false };
      out += blank(ch);
      i++;
      continue;
    }
    out += ch;
    if (ch === "\n") line++;
    i++;
  }
  return { code: out, strings };
}

function lineColAt(text, index) {
  let line = 1;
  let col = 1;
  for (let k = 0; k < index && k < text.length; k++) {
    if (text[k] === "\n") {
      line++;
      col = 1;
    } else col++;
  }
  return { line, col };
}

function snippetAt(src, line) {
  const lines = src.split("\n");
  return (lines[line - 1] ?? "").trim().slice(0, 200);
}

// Small, dependency-free stable hash (FNV-1a). The finding `id` is
// DETERMINISTIC — same vuln at the same location always yields the same id
// across runs/machines — so CI baselines / suppression lists are stable.
//
// `disc` is a stable discriminator (the finding's own message). Two DIFFERENT
// findings at the same file:line:col — e.g. a manifest can legitimately raise
// MCP014 "git source" AND MCP014 "typosquat" both at 1:1 — must get DISTINCT
// ids or baseline-diff / SARIF de-dup would silently collapse them. Folding
// the (deterministic) message in keeps ids unique without breaking
// stability: the same rule+location+message always hashes the same.
function stableId(ruleId, file, line, column, disc = "") {
  const s = `${ruleId}|${file}|${line}|${column}|${disc}`;
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return `${ruleId}-${h.toString(16).padStart(8, "0")}`;
}

function mkFinding(ruleId, severity, file, line, column, message, remediation, src) {
  return {
    id: stableId(ruleId, file, line, column, message),
    ruleId,
    severity,
    file,
    line,
    column,
    message,
    remediation,
    snippet: snippetAt(src, line),
  };
}

// ---------------------------------------------------------------------------
// Source rules
// ---------------------------------------------------------------------------

const EXEC_FNS = ["exec", "execSync", "spawn", "spawnSync", "fork"];

function scanCallArgs(code, openParenIdx) {
  let depth = 0;
  let i = openParenIdx;
  for (; i < code.length; i++) {
    const c = code[i];
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) break;
    }
  }
  const inner = code.slice(openParenIdx + 1, i);
  // first top-level argument
  let d = 0;
  let firstEnd = inner.length;
  for (let k = 0; k < inner.length; k++) {
    const c = inner[k];
    if (c === "(" || c === "[" || c === "{") d++;
    else if (c === ")" || c === "]" || c === "}") d--;
    else if (c === "," && d === 0) {
      firstEnd = k;
      break;
    }
  }
  return { firstArg: inner.slice(0, firstEnd), fullArgs: inner, end: i };
}

/**
 * In masked code, a string literal's static text is blank but template
 * `${...}` interpolation is preserved. So a non-literal first argument is
 * one that, after masking, still contains an identifier, a `${`, a `+`
 * concat, or other code tokens. A pure literal masks to whitespace.
 */
function argIsNonLiteral(maskedArg) {
  const t = maskedArg.trim();
  if (t === "") return false; // pure string/number/template-without-interp
  if (/^\[[\s\S]*\]$/.test(t)) return "array"; // argv array
  return true; // identifier, ${}, concat, call, etc.
}

/**
 * Learn which identifiers actually refer to node:child_process in this file.
 * Without this, a bare `.exec(` on ANY object (e.g. `regex.exec(str)`,
 * `db.spawn(...)`) would false-positive. We only flag calls that are either
 * qualified on a child_process binding (`cp.exec`, `child_process.exec`) or
 * use a name destructured/required from child_process. This is the single
 * biggest real-world false-positive guard for MCP001.
 *
 * @param {string} code masked code
 * @returns {{ cpNamespaces:Set<string>, cpFns:Set<string> }}
 */
function childProcessBindings(code) {
  const cpNamespaces = new Set(); // e.g. `cp` in `import cp from 'child_process'`
  const cpFns = new Set(); // e.g. `exec` in `import { exec } from ...`
  const CP = /['"]node:child_process['"]|['"]child_process['"]/;

  // import ... from 'child_process'
  const importRe =
    /import\s+(?:(\*\s+as\s+([\w$]+))|([\w$]+)|(?:[\w$]+\s*,\s*)?\{([^}]*)\}|([\w$]+))\s+from\s+(['"][^'"]+['"])/g;
  let im;
  while ((im = importRe.exec(code))) {
    if (!CP.test(im[6])) continue;
    if (im[2]) cpNamespaces.add(im[2]); // * as cp
    if (im[3]) cpNamespaces.add(im[3]); // default import
    if (im[5]) cpNamespaces.add(im[5]); // bare default (alt branch)
    if (im[4]) {
      for (const part of im[4].split(",")) {
        const name = part.split(/\s+as\s+/).pop().trim();
        if (name) cpFns.add(name);
      }
    }
  }
  // const cp = require('child_process')  /  const { exec } = require(...)
  const reqRe =
    /(?:const|let|var)\s+(?:([\w$]+)|\{([^}]*)\})\s*=\s*require\(\s*(['"][^'"]+['"])\s*\)/g;
  let rq;
  while ((rq = reqRe.exec(code))) {
    if (!CP.test(rq[3])) continue;
    if (rq[1]) cpNamespaces.add(rq[1]);
    if (rq[2]) {
      for (const part of rq[2].split(",")) {
        const name = part.split(":").pop().split(/\s+as\s+/).pop().trim();
        if (name) cpFns.add(name);
      }
    }
  }
  return { cpNamespaces, cpFns };
}

function ruleCommandInjection(orig, masked, file, findings) {
  const { code } = masked;
  // Detect bindings from the ORIGINAL source: the module specifier string
  // (e.g. "child_process") is blanked in masked code, so binding detection
  // must read orig. Call SITES are still matched in masked code below, so a
  // commented-out call never fires regardless.
  const { cpNamespaces, cpFns } = childProcessBindings(orig);
  if (cpNamespaces.size === 0 && cpFns.size === 0) return; // no CP usage

  const nsAlt = [...cpNamespaces].map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  // A call is in scope iff it is `<cpNamespace>.<fn>(` OR a bare `<fn>(`
  // where <fn> was imported/required from child_process.
  const fnList = EXEC_FNS.concat(["execFile", "execFileSync"]);
  const qualified = nsAlt.length
    ? new RegExp(`\\b(?:${nsAlt.join("|")})\\.(${fnList.join("|")})\\s*\\(`, "g")
    : null;
  const bareNames = fnList.filter((f) => cpFns.has(f));
  const bare = bareNames.length
    ? new RegExp(`(?<![.\\w$])(${bareNames.join("|")})\\s*\\(`, "g")
    : null;

  const sites = [];
  for (const re of [qualified, bare]) {
    if (!re) continue;
    let mm;
    while ((mm = re.exec(code))) sites.push({ fn: mm[1], at: mm.index });
  }
  sites.sort((a, b) => a.at - b.at);

  for (const site of sites) {
    const fn = site.fn;
    const openIdx = code.indexOf("(", site.at);
    if (openIdx < 0) continue;
    const { firstArg, fullArgs } = scanCallArgs(code, openIdx);
    const firstKind = argIsNonLiteral(firstArg);
    const shellTrue = /shell\s*:\s*true/.test(fullArgs);

    // ARGV FORM vs SHELL FORM.
    // `execFile`, and also `spawn`/`spawnSync`/`fork` when `shell: true` is
    // NOT set, do not go through a shell: arg1 is the program path and every
    // dynamic value travels in the argv array. That is the exact mitigation
    // security guidance tells people to use instead of `exec()`, so reporting
    // it as "command injection / would run arbitrary shell" is both wrong and
    // insulting to a codebase that did the right thing. Only `exec`/`execSync`
    // always parse arg1 as a shell command line.
    const isArgvForm =
      (/execFile/.test(fn) || /^(?:spawn|spawnSync|fork)$/.test(fn)) && !shellTrue;

    let severity = "critical";
    let message;
    let remediation;

    if (isArgvForm) {
      // Args are safe by construction here; the only remaining question is
      // who decides WHICH program runs.
      if (firstKind !== true) continue;
      // A zero-argument resolver (`getAdbPath()`, `resolveBinary()`) is the
      // idiomatic way to locate a platform tool and is a far cry from a bare
      // variable that might carry tool input. Report it, but not as critical.
      const isResolverCall = /^[\w$]+(?:\s*\.\s*[\w$]+)*\s*\(\s*\)$/.test(firstArg.trim());
      severity = isResolverCall ? "medium" : "high";
      message =
        `\`${fn}()\` runs a program whose PATH is non-literal. Arguments here go through the argv array, so there is no shell and no argument injection — ` +
        (isResolverCall
          ? "and the path comes from a resolver call, which is the normal way to locate a platform tool. Reported so you can confirm that resolver cannot be steered (PATH lookup, env var, or config an attacker can write), because whoever controls it controls which binary the agent executes."
          : "but whoever controls this value controls which binary the agent executes. If it can be reached from MCP tool input, that is arbitrary program execution.");
      remediation =
        "Resolve the program from a fixed absolute path or an allowlist of known binaries; do not let tool input, `PATH`, or user-writable config decide which executable runs.";
    } else {
      // exec/execSync (always a shell), or anything with shell:true.
      const cmdDanger = firstKind === true;
      const shellDanger = shellTrue && argIsNonLiteral(fullArgs) === true;
      if (!cmdDanger && !shellDanger) continue;
      message = `\`${fn}()\` is invoked with a non-literal command${shellTrue ? " (shell:true)" : ""}. If any interpolated/variable part can reach this from an MCP tool argument it is a command-injection sink — a tool the LLM calls would run arbitrary shell.`;
      remediation =
        "Use `execFile(cmd, [args])` with a fixed command string and an argv array (no shell). Strictly validate/allowlist any input; never interpolate tool input into a shell command.";
    }

    const at = lineColAt(code, openIdx);
    findings.push(
      mkFinding("MCP001", severity, file, at.line, at.col, message, remediation, orig),
    );
  }
}

function ruleEnvExfiltration(orig, masked, file, findings) {
  const { code } = masked;
  // Masked code blanks comment/static-string text but PRESERVES template
  // `${...}` interpolation as code. So `process.env` surviving on a masked
  // line means it is real code (a value), not prose. We flag it only when it
  // lands somewhere the model sees:
  //  (a) a `text:` field of a returned content item,
  //  (b) a tool/handler description argument (e.g. interpolated into the
  //      description string of server.tool(...) — visible via the preserved
  //      `${process.env...}`),
  //  (c) a `return` of a value containing process.env.
  // `const X = process.env.Y` used only for outbound auth is NOT flagged.
  const codeLines = code.split("\n");
  for (let li = 0; li < codeLines.length; li++) {
    const cLine = codeLines[li];
    if (!/process\.env\b/.test(cLine)) continue; // comment/static-string only

    const inText = /\btext\s*:/.test(cLine);

    // `inReturn` used to be "this line contains the word return", which is not
    // the same thing as "the returned value contains process.env":
    //     if (process.env.MODE === 'off') return 'off:mode';   // returns a literal
    //     return process.env.NODE_ENV === 'development';        // returns a boolean
    //     return !!process.env.OPENAI_API_KEY;                  // returns a boolean
    // The first leaks nothing (env is in the *condition*); the other two leak
    // only whether a variable is set, not its value. Across seven real MCP
    // servers this shape was the single largest MCP002 false-positive source.
    const retIdx = cLine.search(/\breturn\b/);
    const returned = retIdx >= 0 ? cLine.slice(retIdx + 6) : "";
    const envIsReturned = /process\.env\b/.test(returned);
    // A comparison or coercion yields a boolean, not the secret itself.
    const returnsBoolean =
      /(?:[=!]==?|\bin\b)\s*[^=]|^\s*!!|\bBoolean\s*\(/.test(returned) &&
      !/\btext\s*:/.test(returned);
    const inReturn = envIsReturned && !returnsBoolean;
    const inToolCall =
      /\.(tool|registerTool|setRequestHandler|prompt|resource)\s*\(/.test(
        cLine,
      );
    // A bare assignment to a local (read for outbound auth) is the safe case.
    const looksLikeAssignmentOnly =
      /^\s*(?:const|let|var)\s+[\w$]+\s*=\s*process\.env\b/.test(cLine) &&
      !inReturn &&
      !inText;

    if (looksLikeAssignmentOnly) continue;
    if (!(inText || inReturn || inToolCall)) continue;

    const col = cLine.indexOf("process.env") + 1;
    const where = inText
      ? "a tool result `text` field"
      : inToolCall
        ? "a tool/handler declaration (e.g. its description)"
        : "a returned value";
    // `text:` and a tool declaration are unambiguously model-visible. A plain
    // `return process.env.X` is not: lexically, a config getter
    // (`return process.env.LOG_DIR`) and a tool handler that hands the value
    // to the model are the same shape, and the former is far more common.
    // Report it, but do not let it dominate a `--fail-on high` gate.
    const bareReturn = !inText && !inToolCall;
    findings.push(
      mkFinding(
        "MCP002",
        bareReturn ? "medium" : "high",
        file,
        li + 1,
        col,
        `\`process.env\` is placed into ${where}, which is visible to the LLM. Environment variables routinely hold API keys, tokens and DB URLs; exposing them to the model leaks credentials into its context (and any logs/telemetry of the conversation).` +
          (bareReturn
            ? " Reported at MEDIUM: this is a bare `return`, and a config getter looks identical to a tool handler at this level of analysis. If this function only feeds internal configuration, ignore it."
            : ""),
        "Never return `process.env` (or whole config objects) to the model. Return only the specific, non-secret fields the tool needs; read secrets into local variables used solely for outbound auth.",
        orig,
      ),
    );
  }
}

/**
 * Is the identifier vm provably bound, in this file, to something that is
 * NOT the Node vm builtin? The vm-specific methods we match
 * (runInThisContext / runInNewContext / runInContext / compileFunction) are
 * essentially never used on a non-vm object -- unlike the child-process
 * generic dot-exec / dot-spawn (which regex.exec / db.spawn collide with and
 * so need a POSITIVE binding in MCP001). So the conservative default here is
 * the inverse: a vm.<thatMethod>( call is a real sink UNLESS vm is
 * contradicted by a local declaration assigning it to a non-require-of-vm
 * value (e.g. const vm = makeSandboxShim()), a destructure, or a function
 * parameter. That keeps the long-standing true positive (vm.runInThisContext
 * with no import is how vm is conventionally used) while killing the
 * userland-vm false positive. Reads ORIGINAL (the require/import specifier is
 * blanked in masked code). NOTE: regex/comment chars here are kept quote- and
 * backtick-free on purpose so the lexical masker stays in sync (see the
 * dogfood invariant) -- mirrors the rest of this file.
 *
 * @param {string} code original source
 * @returns {boolean} true if vm is shadowed by a non-builtin local binding
 */
// Matches one quote character: code point 39 (single), 34 (double), 96
// (backtick). Built via String.fromCharCode so the SOURCE carries ZERO
// literal quote characters on purpose: the lexical masker (maskNonCode) is
// regex-naive, so a literal quote inside a regex literal shifts its string
// state and can desync masking for the rest of the file (the dogfood-clean
// invariant the whole file already respects; this rule must too).
const QUOTE_CHAR = new RegExp(
  "[" + String.fromCharCode(39, 34, 96) + "]",
  "g",
);

function vmShadowedByNonBuiltin(code) {
  // const/let/var vm = <expr> where <expr> is NOT a require of vm / node:vm.
  const decl = /\b(?:const|let|var)\s+vm\s*=\s*([^;\n]+)/g;
  let d;
  while ((d = decl.exec(code))) {
    const rhs = d[1].trim().replace(QUOTE_CHAR, "");
    // After stripping quotes a genuine vm import RHS reads exactly
    // require(node:vm) or require(vm) (whitespace-tolerant). Anything else
    // (a sandbox shim, a factory call, etc.) means vm is NOT the builtin.
    if (!/^require\(\s*(?:node:)?vm\s*\)$/.test(rhs)) return true;
  }
  // destructured  const { vm } = ... ,  function f(vm) ,  (vm) => ,  param.
  if (/\b(?:const|let|var)\s*\{[^}]*\bvm\b[^}]*\}\s*=/.test(code)) return true;
  if (/\bfunction\b[^(]*\([^)]*\bvm\b[^)]*\)/.test(code)) return true;
  if (/\(\s*[^)]*\bvm\b[^)]*\)\s*=>/.test(code)) return true;
  return false;
}

function ruleDangerousEval(orig, masked, file, findings) {
  const { code } = masked;
  // QUALIFIER GUARD (the moat): MCP001/MCP010 gate on provenance; MCP005 did
  // not. A dot-eval / dot-compile etc. that is a METHOD on some object (math
  // lib, parser, ORM, template engine) is legitimate code. The negative
  // lookbehind before eval rejects member access (x.eval, x?.eval) and
  // identifier tails (myeval) -- only a BARE global eval( fires. new Function(
  // is already a bare global constructor (a dot-Function( is not new Function).
  // For the vm.* family: the matched method names are vm-builtin-specific
  // (negligible benign collision), so we keep firing on the namespace pattern
  // but SUPPRESS when vm is provably a userland binding -- provenance,
  // conservative direction (favor a false negative over cry-wolf).
  const patterns = [
    { re: /(?<![.?\w$])eval\s*\(/g, what: "eval()" },
    { re: /\bnew\s+Function\s*\(/g, what: "new Function()" },
  ];
  if (!vmShadowedByNonBuiltin(orig)) {
    patterns.push({
      re: /\bvm\s*\.\s*(?:runInThisContext|runInNewContext|runInContext|compileFunction)\s*\(/g,
      what: "vm code execution",
    });
  }
  for (const { re, what } of patterns) {
    let m;
    while ((m = re.exec(code))) {
      const openIdx = code.indexOf("(", m.index);
      if (openIdx < 0) continue;
      const { firstArg } = scanCallArgs(code, openIdx);
      // In masked code a string literal's text is blank and template
      // interpolation is preserved → a literal-only arg is empty/whitespace.
      const isLiteralOnly = firstArg.trim() === "";
      if (isLiteralOnly) continue; // eval("1+1") etc. — not flagged
      const at = lineColAt(code, m.index);
      findings.push(
        mkFinding(
          "MCP005",
          "high",
          file,
          at.line,
          at.col,
          `${what} is invoked with a non-literal argument. In an MCP server reachable from tool input this is arbitrary code execution driven by the model/attacker.`,
          "Remove dynamic code execution. Parse data with a real parser (e.g. a math/JSON grammar), or dispatch over an explicit allowlist of operations.",
          orig,
        ),
      );
    }
  }
}

const REMOTE_EXEC_RE =
  /\b(curl|wget)\b[^\n|]*\|\s*(sh|bash|zsh)\b|\bnpx\s+[^\n]*@latest|\buvx\s+|\bpip\s+install\b[^\n]*&&|\bcurl\b[^\n]*\|\s*python\b/;

/**
 * Does this string LOOK LIKE an actual shell command line (vs. English
 * prose that merely mentions one)? We require the *trimmed* content to BEGIN
 * with a shell command token (optionally after a `cd …/env-var/&&` prefix).
 * A remediation sentence like "...(e.g. `curl … | sh`)..." starts with
 * letters/words, not a command, so it does NOT match — killing the
 * documentation false positive while still catching `exec("curl … | sh")`.
 */
function looksLikeCommandLine(raw) {
  const t = raw.trim();
  // strip a leading `cd path &&` / `VAR=val ` / `sudo ` style prefix
  const stripped = t.replace(
    /^(?:sudo\s+|[A-Z_][A-Z0-9_]*=\S+\s+|cd\s+\S+\s*&&\s*|\(\s*)+/,
    "",
  );
  return /^(curl|wget|npx|uvx|bunx|pnpm|npm|yarn|pip|pip3|python|python3|sh|bash|zsh|node|deno|bun)\b/.test(
    stripped,
  );
}

function ruleUnpinnedRemoteExecSource(orig, masked, file, findings) {
  // A `curl … | sh` / `npx …@latest` is only a finding when it is an actual
  // command the program runs — NOT a comment, and NOT prose that merely
  // mentions one (e.g. our own remediation text). `masked.strings` records
  // every real string/template literal (raw content + start line); comments
  // are never recorded there. We additionally require the string to LOOK
  // LIKE a command line (begins with a shell token), which removes the
  // documentation-string false positive.
  const seenLines = new Set();
  for (const s of masked.strings) {
    if (!REMOTE_EXEC_RE.test(s.raw)) continue;
    if (!looksLikeCommandLine(s.raw)) continue;
    if (seenLines.has(s.line)) continue;
    seenLines.add(s.line);
    findings.push(
      mkFinding(
        "MCP006",
        "medium",
        file,
        s.line,
        1,
        "Unpinned remote code is fetched and executed (e.g. `curl … | sh`, `npx …@latest`, `uvx`). The code that runs can change after you audit it (supply-chain / TOCTOU).",
        "Pin to an exact version or vendored artifact and verify a checksum/signature before executing. Avoid `| sh` install pipes inside an MCP server.",
        orig,
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// MCP007 — prototype-pollution sinks
//
// Conservative: we flag only the well-known, mechanically-recognisable
// pollution sinks reachable from non-literal input:
//   (a) a *computed* assignment whose key chain visibly involves a
//       `__proto__` / `constructor` / `prototype` token AND a non-literal,
//       e.g. `obj[req][k] = v` where one of the segments is a variable;
//   (b) an unsafe recursive-merge / deep-assign call (`merge`, `deepmerge`,
//       `defaultsDeep`, `set`, `setWith`, `assignIn`, `extend`, `mixin`)
//       invoked with a non-literal source AND NOT guarded — heuristic: the
//       call passes a variable as the merge source.
// We require a literal `__proto__`/`prototype`/`constructor` token to be
// present in the file's masked code (so prose/strings never trip it) for the
// computed-assignment form; the merge form requires a recognised sink name
// AND a non-literal argument. A pure literal merge target does not fire.
// ---------------------------------------------------------------------------

// Capture an optional receiver so we can tell `_.set(o, path, v)` (a lodash
// deep-set — a real pollution sink) from `map.set(k, v)` (a Map write, which
// cannot reach Object.prototype at all).
// The receiver group must also match `)` and `]`, because `getClients().set(k,v)`
// and `arr[i].set(k,v)` are method calls too — capturing only bare identifiers
// let those through as if they were free-standing `set(...)` calls.
const POLLUTION_MERGE_FNS =
  /(?:([A-Za-z_$][\w$]*|\)|\])\s*\.\s*)?\b(merge|mergeWith|defaultsDeep|set|setWith|assignIn|assignInWith|extend|extendWith|mixin|deepmerge|deepMerge|deepAssign|defaults)\s*\(/g;

// These names are also ordinary methods on Map/Set/WeakMap/TypedArray/URL-
// SearchParams/Headers and on countless library objects. Matching them on any
// receiver made this rule fire on `transports.set(sessionId, t)` and
// `buffer.set(chunk, offset)` — the single largest false-positive source in
// the ruleset. For these names we require either a bare call (an imported
// `set`/`merge`) or an explicit lodash-style receiver.
const AMBIGUOUS_SINK_NAMES = new Set([
  "set",
  "setWith",
  "extend",
  "extendWith",
  "defaults",
  "mixin",
  "assignIn",
  "assignInWith",
]);
const LODASH_RECEIVERS = new Set(["_", "lodash", "ld"]);

const PROTO_TOKEN = /\b(__proto__|prototype|constructor)\b/;

function ruleProtoPollution(orig, masked, file, findings) {
  const { code } = masked;
  const lines = code.split("\n");

  // (a) computed assignment whose lvalue is a dynamic property chain. We
  // require: a bracket-access lvalue with a non-literal (identifier) index,
  // immediately assigned, on a line that ALSO references a proto token, OR a
  // bracket-access lvalue whose index expression literally contains a proto
  // token via masked code (computed `o[k]=v` where `k` is attacker-derived
  // is the canonical recursive sink). We keep this tight: the line must have
  // BOTH a `]=`/`] =` computed-assign shape AND a proto token somewhere in
  // the (masked) file is required for the assignment to be reported, so
  // generic `arr[i]=x` never fires.
  const fileHasProtoToken = PROTO_TOKEN.test(code);
  for (let li = 0; li < lines.length; li++) {
    const L = lines[li];
    // Computed-assignment lvalue: `<expr>[ key ] = value` (not `==`).
    // The leading `[\w$)\]]` matters: without it this also matched ARRAY
    // DESTRUCTURING, which is everywhere in modern JS and has nothing to do
    // with prototype pollution —
    //     const [a, b] = ipv4Parts.map(Number);
    //     const [clientId, clientSecret] = credentials.split(':');
    //     const [, existing] = await Promise.all([...]);
    // — as well as TypeScript tuple annotations like `): [string, T] =>`.
    // A real computed assignment always has an object expression immediately
    // before the bracket: an identifier, a `)`, or a `]`.
    const m = /[\w$)\]]\s*\[[^\]\n]+\]\s*=(?![=>])/.exec(L);
    if (!m) continue;
    // `[\w$)\]]` alone is not enough: the `t` of `const` is a word character,
    // so `const [a, b] = x` still matched. Reject when the token immediately
    // before the bracket is a keyword that introduces a binding or an
    // expression rather than an object being indexed.
    const lead = /([A-Za-z_$][\w$]*)\s*\[[^\]\n]+\]\s*=(?![=>])/.exec(L);
    if (
      lead &&
      /^(?:const|let|var|return|of|in|await|typeof|case|yield|new|delete|void|do|else)$/.test(
        lead[1],
      )
    ) {
      continue;
    }
    const idx = L.slice(L.indexOf("[", m.index === 0 ? 0 : 0));
    // crude: the bracket segment just before `=`
    const seg = /\[([^\]\n]+)\]\s*=(?![=>])/.exec(L);
    const keyExpr = seg ? seg[1].trim() : "";
    const keyIsLiteral = keyExpr === ""; // masked: string literal → blank
    const keyIsNumber = /^\d+$/.test(keyExpr);
    const lineHasProto = PROTO_TOKEN.test(L);
    // Fire only if: the assigned key is a non-literal (variable/expr) AND
    // either this line names a proto token, or the file does (a recursive
    // assignment helper in the same module). Numeric indices (arrays) and
    // pure-literal keys never fire.
    if (keyIsLiteral || keyIsNumber) {
      if (!lineHasProto) continue;
    }
    if (!(lineHasProto || (fileHasProtoToken && !keyIsLiteral && !keyIsNumber)))
      continue;
    // ALLOWLIST-GUARDED KEY. The idiomatic safe form of a computed assignment
    // is to check the key against a fixed set first:
    //     if (FORWARDABLE_REQUEST_HEADERS.has(name.toLowerCase())) {
    //       forwardedHeaders[name] = value;
    //     }
    // `__proto__` cannot reach the assignment unless somebody put it in the
    // allowlist. An explicit `key === '__proto__'` rejection counts too.
    // Downgrade rather than suppress: we can see a guard, not what is in it.
    const keyId = /^[\w$]+/.exec(keyExpr || "")?.[0];
    let guarded = null;
    if (keyId) {
      const win = lines.slice(Math.max(0, li - 25), li).join("\n");
      const allow = new RegExp(
        `([\\w$.]+)\\s*\\.\\s*(?:has|includes|hasOwnProperty)\\s*\\(\\s*${keyId}\\b`,
      ).exec(win);
      if (allow) guarded = allow[1];
      else if (
        new RegExp(`${keyId}\\s*[!=]==?\\s*["'\`]?__proto__`).test(win) ||
        new RegExp(`__proto__[\\s\\S]{0,40}${keyId}\\b`).test(win)
      ) {
        guarded = "an explicit __proto__ check";
      }
    }

    const col = L.indexOf("[", m.index >= 0 ? 0 : 0) + 1;
    findings.push(
      mkFinding(
        "MCP007",
        guarded ? "low" : "high",
        file,
        li + 1,
        col > 0 ? col : 1,
        "Computed property assignment with an attacker-influenceable key (a recursive/dynamic `obj[key] = value` reachable from tool input where `key` can be `__proto__`/`constructor`/`prototype`). This is a prototype-pollution sink: poisoning `Object.prototype` can corrupt every object in the process and is a common RCE/auth-bypass primitive." +
          (guarded
            ? ` Reported at LOW: the key looks allowlist-guarded by \`${guarded}\` just above this assignment, which is the correct defence. mcpaudit cannot see what that set contains, so confirm \`__proto__\`, \`constructor\` and \`prototype\` are not in it.`
            : ""),
        "Reject keys equal to `__proto__`, `prototype`, or `constructor`; use a `Map`, `Object.create(null)`, or `Object.defineProperty` with `Object.hasOwn` guards. Validate tool input against a strict schema before using it as an object key.",
        orig,
      ),
    );
  }

  // (b) unsafe recursive merge / deep-set with a non-literal source.
  let mm;
  POLLUTION_MERGE_FNS.lastIndex = 0;
  while ((mm = POLLUTION_MERGE_FNS.exec(code))) {
    const receiver = mm[1]; // undefined for a bare `merge(a, b)` call
    const fnName = mm[2];
    // `map.set(k, v)` / `buf.set(chunk, off)` are not deep merges. Only a bare
    // call or a lodash-style receiver can be the deep-set we care about.
    if (
      AMBIGUOUS_SINK_NAMES.has(fnName) &&
      receiver !== undefined &&
      !LODASH_RECEIVERS.has(receiver)
    ) {
      continue;
    }
    const openIdx = code.indexOf("(", mm.index);
    if (openIdx < 0) continue;
    const { fullArgs } = scanCallArgs(code, openIdx);
    // A literal-only merge (e.g. `_.merge(a, { fixed: 1 })`) masks the object
    // text away but keeps `{}` / identifiers. Require a bare identifier
    // source argument (the classic `merge(target, untrustedInput)` shape):
    // at least two top-level args and a non-literal that is NOT an object
    // literal `{...}` (an inline object literal is developer-authored shape,
    // not attacker data).
    const argParts = splitTopLevel(fullArgs);
    if (argParts.length < 2) continue;
    const src2 = argParts[argParts.length - 1].trim();
    const isObjLiteral = /^\{[\s\S]*\}$/.test(src2);
    const isArrLiteral = /^\[[\s\S]*\]$/.test(src2);
    const isLiteralBlank = src2 === ""; // masked string/number literal
    if (isObjLiteral || isArrLiteral || isLiteralBlank) continue;
    const at = lineColAt(code, mm.index);
    findings.push(
      mkFinding(
        "MCP007",
        "high",
        file,
        at.line,
        at.col,
        `\`${fnName}()\` performs a recursive/deep merge or deep property set from a non-literal source. If that source is (or is derived from) MCP tool input, an attacker-supplied \`__proto__\` key walks into \`Object.prototype\` — prototype pollution.`,
        "Use a pollution-safe merge (guard `__proto__`/`constructor`/`prototype`, or a maintained version that does), parse into `Object.create(null)`, or copy only an explicit allowlist of known keys from the input.",
        orig,
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// MCP008 — SSRF-able outbound fetch with an attacker-influenced URL
//
// MCP servers frequently expose a "fetch this URL" / "call this webhook"
// style tool. If the URL argument to `fetch`/`axios`/`got`/`request`/
// `http(s).get|request` is built from a non-literal (a variable, a `${}`, or
// `+` concat) and is reachable from tool input, the model (or a prompt
// injector upstream) can point it at cloud metadata (169.254.169.254),
// localhost admin ports, or internal services. Conservative: a fully literal
// URL never fires; a URL that is `new URL(x, FIXED_LITERAL_BASE)` where the
// base is a literal does not fire (path-only is far lower risk and is the
// common safe pattern).
// ---------------------------------------------------------------------------

const HTTP_SINKS = [
  "fetch",
  "axios",
  "got",
  "request",
  "superagent",
  "undici",
  "ky",
];

/**
 * Is the URL expression an SSRF risk? We are deliberately conservative: the
 * dangerous case is when the **origin (scheme://host)** is attacker-
 * influenceable. The extremely common SAFE pattern — a hardcoded absolute
 * base with only the path/query varying (`"https://api.x/v1?q=" + enc(q)` or
 * `` `https://api.x/v1/${id}` ``) — must NOT fire (that was the clean-server
 * dogfood false positive).
 *
 * @param {string} expr the URL expression, ORIGINAL source text (literals
 *   intact so we can see whether the leading literal pins the origin)
 * @returns {"safe"|"risk"}
 */
function classifyUrlExpr(expr) {
  let e = expr.trim();
  // unwrap `new URL( … )` → its first arg is the URL/path; a second literal
  // base arg pins the origin (safe). `new URL(x)` alone → judge x.
  const mu = /^new\s+URL\s*\(([\s\S]*)\)$/.exec(e);
  if (mu) {
    const parts = splitTopLevel(mu[1]);
    const base = (parts[1] || "").trim();
    if (base && /^["'`]/.test(base)) return "safe"; // fixed base origin
    e = (parts[0] || "").trim();
  }
  if (e === "") return "safe";
  // Template literal: safe iff it BEGINS with `scheme://host` BEFORE the
  // first `${}` (origin is fixed; only path/query interpolated).
  if (e.startsWith("`")) {
    const body = e.slice(1, e.endsWith("`") ? -1 : undefined);
    const firstInterp = body.indexOf("${");
    const head = firstInterp < 0 ? body : body.slice(0, firstInterp);
    if (/^[a-z][a-z0-9+.-]*:\/\/[^/${\s]+/i.test(head)) return "safe";
    return "risk"; // `${base}/x` or `https://${host}` → host attacker-set
  }
  // Concatenation chain: split on top-level `+`. Safe iff the FIRST operand
  // is a string literal that already contains `scheme://host` (origin fixed,
  // we only append path/query). Anything else (leading variable, or first
  // literal lacks an absolute origin) → risk.
  const firstPlus = (() => {
    let d = 0;
    for (let i = 0; i < e.length; i++) {
      const c = e[i];
      if (c === "(" || c === "[" || c === "{") d++;
      else if (c === ")" || c === "]" || c === "}") d--;
      else if (c === "`" || c === '"' || c === "'") {
        // skip a literal
        const q = c;
        i++;
        while (i < e.length && e[i] !== q) {
          if (e[i] === "\\") i++;
          i++;
        }
      } else if (c === "+" && d === 0) return i;
    }
    return -1;
  })();
  if (firstPlus >= 0) {
    const first = e.slice(0, firstPlus).trim();
    const lit = /^["'`]([\s\S]*?)["'`]$/.exec(first);
    if (lit && /^[a-z][a-z0-9+.-]*:\/\/[^/\s]+/i.test(lit[1])) return "safe";
    return "risk";
  }
  // A lone string literal is fully fixed (caller already handled, but be
  // safe). A lone identifier / call / member expression is the classic
  // `fetch(userProvidedUrl)` → risk.
  if (/^["'`][\s\S]*["'`]$/.test(e)) return "safe";
  return "risk";
}

function ruleSsrfFetch(orig, masked, file, findings) {
  const { code } = masked;
  // direct fetch( / axios( / got( / axios.get( / http.get( / https.request(
  const callRe =
    /(?<![.\w$])(fetch|axios|got|request|ky|undici|superagent)\s*(?:\.\s*(get|post|put|patch|delete|request|head)\s*)?\(|(?<![.\w$])https?\s*\.\s*(get|request)\s*\(/g;
  let m;
  while ((m = callRe.exec(code))) {
    const openIdx = code.indexOf("(", m.index);
    if (openIdx < 0) continue;
    // Match call args in MASKED code (so a commented-out / string-embedded
    // fetch never fires — provenance), but read the URL expression from the
    // ORIGINAL source at the same offsets so literal text is visible to
    // classifyUrlExpr (origin-fixed detection needs the literal contents).
    const { end } = scanCallArgs(code, openIdx);

    // NOT A CALL: `async fetch(request) { ... }` is a METHOD DEFINITION. It is
    // the standard server entry point for Bun, Deno and Cloudflare Workers —
    //     const server = Bun.serve({ port, async fetch(req) { ... } });
    // — so flagging it as an outbound SSRF sink is backwards: that handler
    // *receives* requests. A definition is followed by its body `{`; a real
    // call is followed by `;`, `.`, `,`, `)` or an operator.
    const after = code.slice(end).match(/^\s*(.)/);
    if (after && after[1] === "{") continue;
    const before = code.slice(Math.max(0, m.index - 24), m.index);
    if (/\b(?:async|function)\s+$/.test(before)) continue;

    const origInner = orig.slice(openIdx + 1, end);
    const oParts = splitTopLevel(origInner);
    const arg1 = (oParts[0] || "").trim();
    const urlField = /\b(?:url|baseURL|uri)\s*:\s*([^,}\n]+)/.exec(origInner);
    const urlExpr = arg1 !== "" ? arg1 : urlField ? urlField[1].trim() : "";
    if (urlExpr === "") continue;
    if (classifyUrlExpr(urlExpr) === "safe") continue;

    // HOISTED-LITERAL GUARD, mirroring MCP010's hoisted containment. Pulling a
    // fixed endpoint out into a named constant is the *tidier* way to write it:
    //     const LATEST_SOURCE = "https://example.dev/latest.ts";
    //     await fetch(LATEST_SOURCE, { headers: { accept: "text/plain" } });
    // Judging the identifier alone calls that an attacker-controlled origin.
    // If the nearest assignment before this call is a plain string literal, the
    // origin is as fixed as an inline literal.
    if (/^[\w$]+$/.test(urlExpr)) {
      const beforeSrc = orig.slice(0, m.index);
      const assignRe = new RegExp(
        `(?:\\b(?:const|let|var)\\s+${urlExpr}\\s*=|(?<![.\\w$])${urlExpr}\\s*=(?!=))([^;\\n]+)`,
        "g",
      );
      let a;
      let lastRhs = null;
      while ((a = assignRe.exec(beforeSrc))) lastRhs = a[1];
      if (lastRhs && classifyUrlExpr(lastRhs.trim()) === "safe") continue;
    }
    const at = lineColAt(code, m.index);
    const sink = m[1] || `https.${m[3] || ""}`;
    findings.push(
      mkFinding(
        "MCP008",
        "high",
        file,
        at.line,
        at.col,
        `\`${sink}\` is called with a non-literal URL. In an MCP server this is typically reachable from tool input, so the model (or an upstream prompt injection) can redirect the request to cloud metadata (169.254.169.254), \`localhost\` admin ports, or internal services — server-side request forgery (SSRF) and credential theft.`,
        "Validate the URL against a strict allowlist of hosts/schemes before fetching; reject private/loopback/link-local IPs and `file:`/`gopher:` schemes; if only a path varies, hardcode the origin and use `new URL(path, FIXED_BASE)`.",
        orig,
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// MCP009 — hardcoded secret in a tool schema / description / manifest
//
// A literal that LOOKS like a real credential (long hex/base64 token, an
// AWS/GitHub/Slack/OpenAI/Anthropic-style key, a private-key PEM header)
// embedded directly in source — especially in a tool description/schema the
// model sees, but anywhere is bad. Conservative: high-signal prefixes and a
// generic high-entropy long-token check with an allow-list of obvious
// placeholders (XXXX, your-, example, changeme, <...>, dummy, sk-...REDACTED).
// ---------------------------------------------------------------------------

const SECRET_PATTERNS = [
  { re: /\bAKIA[0-9A-Z]{16}\b/, what: "an AWS access key id" },
  { re: /\bASIA[0-9A-Z]{16}\b/, what: "an AWS temporary access key id" },
  {
    re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/,
    what: "a GitHub token",
  },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, what: "a Slack token" },
  {
    re: /\b(sk|rk)-(?:proj-)?[A-Za-z0-9_-]{20,}\b/,
    what: "an OpenAI-style secret key",
  },
  {
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
    what: "an Anthropic API key",
  },
  {
    re: /\bAIza[0-9A-Za-z_-]{35}\b/,
    what: "a Google API key",
  },
  {
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
    what: "a private key (PEM)",
  },
  {
    re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
    what: "a JWT (possibly a long-lived credential)",
  },
];
const SECRET_PLACEHOLDER =
  /\b(x{4,}|your[-_]|example|changeme|placeholder|dummy|redacted|sample|test[-_]?key|fake|<[^>]+>|\.\.\.|insert[-_]|todo)\b/i;

function ruleHardcodedSecret(orig, masked, file, findings) {
  // Secrets live in *string literals*. `masked.strings` records each literal
  // (raw text, start line) and excludes comments — so a key only mentioned in
  // a comment never fires; a key pasted into a tool description (a real
  // string) does.
  const seen = new Set();
  for (const s of masked.strings) {
    const raw = s.raw;
    for (const { re, what } of SECRET_PATTERNS) {
      const mt = re.exec(raw);
      if (!mt) continue;
      const tok = mt[0];
      if (SECRET_PLACEHOLDER.test(raw) && !/PRIVATE KEY/.test(tok)) continue;
      const key = `${s.line}|${tok.slice(0, 12)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(
        mkFinding(
          "MCP009",
          "critical",
          file,
          s.line,
          1,
          `A string literal contains what looks like ${what}. A real credential committed into an MCP server's source (and especially into a tool description/schema the model can read back) is an immediate secret leak and is in your git history forever.`,
          "Remove the secret, rotate it immediately (assume it is compromised once committed), and load it from an environment variable / secret manager at runtime. Never place credentials in tool descriptions or schemas.",
          orig,
        ),
      );
    }
  }
}

// ---------------------------------------------------------------------------
// MCP010 — path traversal in a file-system tool
//
// The HIGH-SIGNAL sink (kept deliberately tight to avoid cry-wolf): an
// `fs.*` path that is either
//   (a) a bare identifier / member expression (`fs.readFile(userPath)`), or
//   (b) a string CONCATENATION (`"./data/" + name`, template `` `./d/${x}` ``)
//       with NO path containment call anywhere in the expression.
// We do NOT fire when the path is wrapped in `path.join(...)` /
// `path.resolve(...)` / `path.normalize(...)` / reduced via
// `path.basename(...)` — those are the standard containment idioms, and
// flagging every `path.join("./dir", x)` is precisely the false-positive
// pattern that gets a scanner uninstalled. (A `path.join` whose joined
// segment still escapes via `..` is a deeper taint problem, explicitly
// out of scope for a conservative lexical scanner — see README Limitations.)
// A pure literal path never fires.
// ---------------------------------------------------------------------------

const FS_PATH_SINKS =
  /\bfs(?:\s*\.\s*promises)?\s*\.\s*(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|readdir|readdirSync|createReadStream|createWriteStream|open|openSync|copyFile|copyFileSync)\s*\(|\b(readFile|writeFile|appendFile|unlink|rm|readdir|copyFile)\s*\(/g;

const PATH_HELPERS = ["join", "resolve", "normalize", "basename"];

/**
 * Containment idioms are written two ways, and only recognising one of them
 * was a false-positive source: `path.join(dir, name)` and, just as commonly,
 * `import { join } from "node:path"` followed by a bare `join(dir, name)`.
 *
 * The bare form is only honoured when the file actually destructures that
 * name out of node:path — same provenance discipline MCP001 uses for
 * child_process, so a random `resolve()` from a promise helper is not
 * mistaken for path containment.
 *
 * @param {string} orig unmasked source (imports live here)
 * @returns {RegExp} matches a containment call in an expression
 */
function pathContainmentRe(orig) {
  const names = new Set();
  const importRe =
    /(?:import\s*\{([^}]*)\}\s*from\s*['"](?:node:)?path['"]|(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['"](?:node:)?path['"]\s*\))/g;
  let m;
  while ((m = importRe.exec(orig))) {
    for (const raw of (m[1] || m[2] || "").split(",")) {
      // handles `join`, `join as pathJoin`, `join: pathJoin`
      const local = raw.split(/\s+as\s+|:/).pop().trim();
      const orig_ = raw.split(/\s+as\s+|:/)[0].trim();
      if (PATH_HELPERS.includes(orig_) && /^[\w$]+$/.test(local)) names.add(local);
    }
  }
  const qualified = `\\bpath\\s*\\.\\s*(?:${PATH_HELPERS.join("|")})\\s*\\(`;
  if (!names.size) return new RegExp(qualified);
  const bare = `(?<![.\\w$])(?:${[...names].join("|")})\\s*\\(`;
  return new RegExp(`${qualified}|${bare}`);
}

// A project-local path validator, by naming convention: `validatePath`,
// `ensureInsideRoot`, `sanitizePath`, `assertSafePath`, `checkPath`, … We
// cannot verify what these enforce (no taint tracking), so a hit here
// DOWNGRADES the finding rather than suppressing it.
const VALIDATOR_CALL_RE =
  /\b(?:await\s+)?(?:[\w$]+\s*\.\s*)?((?:validate|sanitiz|assert|ensure|check|guard|verif|secure|safe)[\w$]*)\s*\(/i;

function rulefsPathTraversal(orig, masked, file, findings, cfg, stats) {
  const { code } = masked;
  // Project-declared assertions (see src/config.js). These SUPPRESS rather
  // than downgrade, because a human explicitly took responsibility for them —
  // but every suppression is counted and reported, so this can never quietly
  // hide a finding.
  const declaredValidators = new Set(cfg?.pathValidators ?? []);
  const trustedVars = new Set(cfg?.trustedPathVars ?? []);
  const suppress = () => {
    if (stats) stats.suppressedByConfig = (stats.suppressedByConfig ?? 0) + 1;
  };
  // require an fs binding so a random `readFile(` helper on another object is
  // not a finding (provenance), mirroring MCP001's discipline.
  const usesFs =
    /\bfrom\s+['"]node:fs['"]|\brequire\(\s*['"]node:fs['"]|\bfrom\s+['"]fs['"]|\brequire\(\s*['"]fs['"]|\bimport\s+fs\b|\bfs\s*\.\s*promises\b/.test(
      orig,
    );
  const containmentRe = pathContainmentRe(orig);
  let m;
  FS_PATH_SINKS.lastIndex = 0;
  while ((m = FS_PATH_SINKS.exec(code))) {
    const qualified = Boolean(m[1]); // fs.readFile form
    const bare = m[2]; // destructured readFile form
    if (!qualified && !usesFs) continue; // bare form needs fs provenance
    if (qualified && !usesFs) continue;
    const fn = m[1] || bare;
    const openIdx = code.indexOf("(", m.index);
    if (openIdx < 0) continue;
    const { firstArg } = scanCallArgs(code, openIdx);
    const p = firstArg.trim();
    if (p === "") continue; // pure literal path
    // `fs.readFileSync(0, "utf8")` reads FILE DESCRIPTOR 0 — stdin. A numeric
    // literal is not a path and cannot be traversed; only string paths can.
    if (/^\d+$/.test(p)) continue;
    // Any path-module containment idiom anywhere in the path expression →
    // treat as handled (low-FP stance; see header).
    if (containmentRe.test(p)) continue;
    // Now: fire only if p is a bare ident/member, OR a concat/template with a
    // dynamic part. A masked pure-literal is already `""` (skipped above).
    const isConcat = /\+/.test(p) || /\$\{/.test(p) || /^`/.test(p);
    const isBareRef = /^[\w$][\w$.[\]'"]*$/.test(p); // userPath, req.body.f
    if (!isConcat && !isBareRef) continue; // e.g. a fn() result — unknown, skip
    // The project declared this parameter/variable pre-validated.
    if (trustedVars.size && /^[\w$]+$/.test(p) && trustedVars.has(p)) {
      suppress();
      continue;
    }
    // HOISTED-CONTAINMENT GUARD (the moat): extract-to-named-variable is
    // idiomatic SAFE code, e.g.
    //   const safe = path.resolve(BASE, path.basename(n)); readFileSync(safe)
    // The containment idiom lives on the ASSIGNMENT, not inside the fs-call
    // arg. If p is a bare single identifier, look BACK at its nearest
    // declaration/assignment before this call; if that RHS itself contains a
    // path.join / resolve / normalize / basename call, treat it as contained
    // and do NOT fire. (A reassignment from raw input with no path.* still
    // fires; see the MCP010 STILL-fires-on-a-hoisted-variable test.) This
    // mirrors the in-arg containment skip above; favor a false negative over
    // cry-wolf, consistent with the project ethos + README Limitations.
    let viaValidator = null;
    if (!isConcat && /^[\w$]+$/.test(p)) {
      const before = code.slice(0, m.index);
      const assignRe = new RegExp(
        `(?:\\b(?:const|let|var)\\s+${p}\\s*=|(?<![.\\w$])${p}\\s*=(?!=))([^;\\n]+)`,
        "g",
      );
      let a;
      let lastRhs = null;
      while ((a = assignRe.exec(before))) lastRhs = a[1]; // nearest wins
      if (lastRhs && containmentRe.test(lastRhs)) {
        continue; // hoisted containment — handled, do not fire
      }
      // SOFT containment: the value came out of a project-local validator
      // (`validatePath`, `ensureInsideRoot`, `sanitizePath`, …). Without taint
      // tracking we cannot prove what that function enforces, so we must NOT
      // suppress — silently dropping a path-traversal finding is exactly the
      // failure mode a security scanner cannot afford. We downgrade instead:
      // the finding stays visible but drops out of `--fail-on high` and stops
      // crowding out real signal. (The official MCP `filesystem` server hits
      // this: 13 findings, all `validatePath()` output, all noise at `high`.)
      // VALIDATE-THEN-USE. The assignment form (`const p = validatePath(x)`) is
      // only half of it; the other half is far more common in MCP tool
      // handlers, where the path arrives destructured straight out of the
      // schema and is checked in place:
      //     async ({ saveTo }) => {
      //       validateFileExtension(saveTo, ALLOWED, "save_screenshot");
      //       validateOutputPath(saveTo);
      //       fs.writeFileSync(saveTo, screenshot);
      //     }
      // Nothing is ever assigned, so looking only at assignments missed it.
      // Bounded look-back approximates "earlier in this function".
      if (!viaValidator) {
        const win = before.slice(-2000);
        const guardRe = new RegExp(
          `\\b((?:validate|sanitiz|assert|ensure|check|guard|verif|secure|safe)[\\w$]*)\\s*\\(\\s*${p}\\b`,
          "i",
        );
        const g = guardRe.exec(win);
        if (g) viaValidator = g[1];
      }
      // SAME-FILE PATH HELPER. Naming conventions only get you so far:
      //     function getTokenFilePath() {
      //       return path.join(getConfigDir(), 'tokens.json');
      //     }
      //     const tokenPath = getTokenFilePath();
      //     await fs.writeFile(tokenPath, ...);
      // `getTokenFilePath` matches no validator pattern, but its body is right
      // there in the same file and visibly contains the containment idiom. That
      // is stronger evidence than a name, so read it instead of guessing.
      if (!viaValidator && lastRhs) {
        const call = /(?:await\s+)?(?:[\w$]+\s*\.\s*)?([\w$]+)\s*\(/.exec(lastRhs);
        if (call) {
          const fn = call[1];
          // Function declaration, assigned arrow/function, or a class method
          // (`private resolvePath(p: string) { ... }` is just as common as a
          // free function, and `this.resolvePath(x)` reaches it the same way).
          const defRe = new RegExp(
            `function\\s+${fn}\\s*\\(` +
              `|(?:const|let|var)\\s+${fn}\\s*=` +
              `|[\\n;{]\\s*(?:(?:private|public|protected|static|async|readonly)\\s+)*${fn}\\s*\\(`,
          );
          const d = defRe.exec(orig);
          // Bounded window approximates the function body without parsing.
          if (d && containmentRe.test(orig.slice(d.index, d.index + 600))) {
            viaValidator = fn;
          }
        }
      }
      if (lastRhs) {
        const v = VALIDATOR_CALL_RE.exec(lastRhs);
        if (v) viaValidator = v[1];
        // A validator the project explicitly declared is an assertion by a
        // human, not a guess from a naming convention: suppress, don't
        // downgrade. Still counted and reported.
        if (declaredValidators.size) {
          const d = /(?:await\s+)?(?:[\w$]+\s*\.\s*)?([\w$]+)\s*\(/.exec(lastRhs);
          if (d && declaredValidators.has(d[1])) {
            suppress();
            continue;
          }
        }
      }
    }
    const at = lineColAt(code, m.index);
    findings.push(
      mkFinding(
        "MCP010",
        viaValidator ? "low" : "high",
        file,
        at.line,
        at.col,
        `\`${typeof fn === "string" ? fn : "fs call"}\` uses a non-literal path. In an MCP file tool reachable from tool input, an attacker can supply \`../../../etc/passwd\` (or an absolute path) and read or overwrite files outside the intended directory — path traversal / arbitrary file access.` +
          (viaValidator
            ? ` Reported at LOW: this path is guarded by \`${viaValidator}()\` — either assigned from it, or passed to it earlier in this function — which looks like a project-local path validator. mcpaudit does no taint tracking and cannot verify what that function actually enforces; confirm it resolves symlinks and asserts containment against an allowlist before treating this as handled.`
            : ""),
        "Resolve the path and assert it stays inside an allowed base dir (`const full = path.resolve(BASE, p); if (!full.startsWith(BASE + path.sep)) throw`), or reduce to `path.basename(p)` when only a filename is expected.",
        orig,
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// MCP011 — unsafe deserialization of non-literal data
//
// `JSON.parse` is fine. The dangerous deserializers are: the `node-serialize`
// / `serialize-javascript` `unserialize`, `js-yaml` `load` (the unsafe full
// schema, not `safeLoad`/`load(x,{schema:JSON_SCHEMA})`), and any
// `*.unserialize(`/`deserialize(` on attacker data, plus `vm`-backed YAML.
// Conservative: requires a recognised unsafe deserializer name AND a
// non-literal argument; `JSON.parse`, `yaml.safeLoad`, and `load(x, {schema:
// ...JSON_SCHEMA})` never fire.
// ---------------------------------------------------------------------------

const UNSAFE_DESERIALIZE =
  /(?<![.\w$])(unserialize|deserialize)\s*\(|\b(yaml|jsyaml|YAML|jsYaml)\s*\.\s*load\s*\(|(?<![.\w$])load\s*\(/g;

/**
 * js-yaml 4 removed `safeLoad` and made `load` itself safe: it defaults to the
 * DEFAULT_SCHEMA, which cannot instantiate arbitrary JS types. The dangerous
 * full-schema behaviour this rule was written for belongs to js-yaml 3.x and
 * earlier. Flagging `yaml.load` in a project that depends on ^4 is reporting a
 * vulnerability that the dependency fixed years ago.
 *
 * @param {Record<string,string>|undefined} deps dependency ranges from package.json
 * @returns {boolean} true when js-yaml is pinned to 4 or newer
 */
function yamlLoadIsSafe(deps) {
  const range = deps?.["js-yaml"];
  if (typeof range !== "string") return false;
  const major = /(\d+)/.exec(range);
  return Boolean(major) && Number(major[1]) >= 4;
}

function ruleUnsafeDeserialize(orig, masked, file, findings, deps) {
  const { code } = masked;
  const yamlSafe = yamlLoadIsSafe(deps);
  // provenance for the bare `load(` form: only consider it if js-yaml (or a
  // serialize lib) is imported, else `load(` is too generic.
  const yamlImported =
    /['"]js-yaml['"]|['"]yaml['"]|['"]node-serialize['"]|['"]serialize-javascript['"]|['"]funcster['"]|['"]cryo['"]/.test(
      orig,
    );
  let m;
  UNSAFE_DESERIALIZE.lastIndex = 0;
  while ((m = UNSAFE_DESERIALIZE.exec(code))) {
    const isUnser = Boolean(m[1]); // unserialize|deserialize
    const isYamlQualified = Boolean(m[2]); // yaml.load
    const isBareLoad = !isUnser && !isYamlQualified; // load(
    if (isBareLoad && !yamlImported) continue;
    if ((isUnser || isYamlQualified) && !yamlImported && isUnser) {
      // unserialize/deserialize without a known lib import — still high
      // signal (these names are almost never benign) but require it to look
      // like a call on data; keep it, do not gate on import for unserialize.
    }
    const fn =
      m[1] || (m[2] ? `${m[2]}.load` : "load");
    const openIdx = code.indexOf("(", m.index);
    if (openIdx < 0) continue;
    const { firstArg, fullArgs } = scanCallArgs(code, openIdx);
    if (firstArg.trim() === "") continue; // literal payload — not attacker data
    // js-yaml safe usage: `load(x, { schema: JSON_SCHEMA })` or core/failsafe.
    if (
      (isYamlQualified || isBareLoad) &&
      /\bschema\s*:\s*[\w.$]*(JSON_SCHEMA|CORE_SCHEMA|FAILSAFE_SCHEMA)/.test(
        fullArgs,
      )
    )
      continue;
    // Declared js-yaml >= 4: `load` is the safe one. Only the yaml forms are
    // cleared; `unserialize`/`deserialize` are unaffected by that version.
    if (yamlSafe && !isUnser) continue;
    const at = lineColAt(code, m.index);
    const sevText = isUnser
      ? "Functions/`node-serialize`-style unserialize can construct and immediately invoke attacker-defined functions — direct remote code execution."
      : "`js-yaml`'s default/legacy full-schema `load` can instantiate arbitrary JS types from YAML tags — code execution / object injection.";
    findings.push(
      mkFinding(
        "MCP011",
        isUnser ? "critical" : "high",
        file,
        at.line,
        at.col,
        `\`${fn}()\` deserializes a non-literal value. In an MCP server this is typically tool input. ${sevText}`,
        isUnser
          ? "Do not use `node-serialize`/`serialize-javascript` unserialize on untrusted data. Use `JSON.parse` (data only) and reconstruct behaviour from an explicit, validated schema."
          : "Use `yaml.load(x, { schema: yaml.JSON_SCHEMA })` (or `CORE_SCHEMA`/`FAILSAFE_SCHEMA`), or a safe parser; never deserialize untrusted YAML with the default schema.",
        orig,
      ),
    );
  }
}

/** Split a top-level argument string on commas not nested in (), [], {}. */
function splitTopLevel(s) {
  const parts = [];
  let d = 0;
  let buf = "";
  for (let k = 0; k < s.length; k++) {
    const c = s[k];
    if (c === "(" || c === "[" || c === "{") d++;
    else if (c === ")" || c === "]" || c === "}") d--;
    if (c === "," && d === 0) {
      parts.push(buf);
      buf = "";
      continue;
    }
    buf += c;
  }
  if (buf.trim() !== "" || parts.length) parts.push(buf);
  return parts;
}

/**
 * Run every source rule on one file's text.
 * @param {string} src - file contents
 * @param {string} relPath - path label used in findings
 * @returns {Finding[]}
 */
export function analyzeSource(src, relPath, cfg, stats, deps) {
  const findings = [];
  if (typeof src !== "string" || src === "") return findings;
  const masked = maskNonCode(src);
  ruleCommandInjection(src, masked, relPath, findings);
  ruleEnvExfiltration(src, masked, relPath, findings);
  ruleDangerousEval(src, masked, relPath, findings);
  ruleUnpinnedRemoteExecSource(src, masked, relPath, findings);
  ruleProtoPollution(src, masked, relPath, findings);
  ruleSsrfFetch(src, masked, relPath, findings);
  ruleHardcodedSecret(src, masked, relPath, findings);
  rulefsPathTraversal(src, masked, relPath, findings, cfg, stats);
  ruleUnsafeDeserialize(src, masked, relPath, findings, deps);
  return findings;
}

// ---------------------------------------------------------------------------
// Manifest rules
// ---------------------------------------------------------------------------

function collectDirEntries(obj, acc = []) {
  if (!obj || typeof obj !== "object") return acc;
  for (const [k, v] of Object.entries(obj)) {
    const key = k.toLowerCase();
    if (
      /(alloweddirectories|allowedpaths|roots|directories|allowdir|fsroot|rootdir|workspace)/.test(
        key,
      )
    ) {
      if (Array.isArray(v)) for (const e of v) if (typeof e === "string") acc.push(e);
      else if (typeof v === "string") acc.push(v);
    }
    if (v && typeof v === "object") collectDirEntries(v, acc);
  }
  return acc;
}

function isBroadRoot(p) {
  const s = String(p).trim();
  if (s === "" ) return false;
  if (s === "/" || s === "\\") return true;
  if (s === "~" || s.startsWith("~/") || s === "~\\") return true;
  if (/^[A-Za-z]:[\\/]?$/.test(s)) return true; // C:\ , D:/
  if (s === "." && false) return false;
  if (/(^|\/)\.\.(\/|$)/.test(s)) return true; // path traversal
  if (s === "*" || s === "**" || s === "/*" || s === "/**") return true;
  if (s === "$HOME" || s === "${HOME}" || s === "%USERPROFILE%") return true;
  return false;
}

function ruleBroadFsScope(json, file, findings) {
  for (const dir of collectDirEntries(json)) {
    if (isBroadRoot(dir)) {
      findings.push(
        mkFinding(
          "MCP003",
          "high",
          file,
          1,
          1,
          `MCP manifest grants an over-broad filesystem root: "${dir}". A filesystem-capable server with root/home/traversal scope lets the model read or write anything the process can (SSH keys, .env, source).`,
          'Restrict allowed directories to the narrowest project-relative subtree the server actually needs (e.g. "./workspace"). Never grant "/", "~", a drive root, "*", or a "../"-escaping path.',
          "",
        ),
      );
    }
  }
}

// A key whose VALUE is the tool allowlist itself (an array or a "*" string).
const ALLOWLIST_KEY = /^(allow|allowedtools|toolallowlist|tools|permissions)$/;
const WILDCARD = new Set(["*", "**", ".*", "*.*"]);

function ruleUnrestrictedToolGlob(json, file, findings) {
  const hits = [];
  const walk = (o) => {
    if (!o || typeof o !== "object") return;
    for (const [k, v] of Object.entries(o)) {
      const key = k.toLowerCase();
      if (key === "allowalltools" && v === true) {
        hits.push("allowAllTools: true");
      } else if (ALLOWLIST_KEY.test(key)) {
        // Only treat this key as an allowlist if its value is directly an
        // array or a string wildcard. If it's a container object (e.g.
        // `tools: { allow: [...] }`) we DON'T match here — we let the walk
        // descend so only the inner `allow` array is evaluated once. This
        // prevents the same wildcard being reported twice.
        if (Array.isArray(v)) {
          if (v.some((e) => WILDCARD.has(e))) {
            hits.push(`${k}: ${JSON.stringify(v)}`);
          }
        } else if (typeof v === "string" && WILDCARD.has(v)) {
          hits.push(`${k}: ${JSON.stringify(v)}`);
        }
      }
      if (v && typeof v === "object") walk(v);
    }
  };
  walk(json);
  for (const h of [...new Set(hits)]) {
    findings.push(
      mkFinding(
        "MCP004",
        "medium",
        file,
        1,
        1,
        `Unrestricted tool/permission scope declared (${h}). A wildcard tool allowlist means every current and future tool — including dangerous ones — is exposed to the model with no review gate.`,
        "Declare an explicit allowlist of the specific tool names the integration needs; drop the wildcard.",
        "",
      ),
    );
  }
}

const PINNED_RE = /@(\d|v\d|[0-9a-f]{7,40}$|sha256)/i;
function ruleUnpinnedRemoteExecManifest(json, file, findings) {
  const cmd = typeof json?.command === "string" ? json.command : "";
  const args = Array.isArray(json?.args) ? json.args.map(String) : [];
  const joined = [cmd, ...args].join(" ");
  const remoteRunner = /\b(npx|uvx|bunx|pnpm dlx|dlx)\b/.test(joined);
  const curlPipe = /\b(curl|wget)\b.*\|\s*(sh|bash|python)\b/.test(joined);
  if (curlPipe) {
    findings.push(
      mkFinding(
        "MCP006",
        "medium",
        file,
        1,
        1,
        `Manifest start command pipes remote content into a shell: "${joined}". The executed code can change after audit (supply-chain).`,
        "Install/vendor a pinned, checksum-verified artifact and start it directly (e.g. `node dist/index.js`).",
        "",
      ),
    );
    return;
  }
  if (!remoteRunner) return;
  // npx/uvx is acceptable IF a package spec is pinned to an exact version or
  // a commit. `pkg@latest`, `-y pkg`, or `pkg` (no version) is unpinned.
  const pkgSpecs = args.filter((a) => !a.startsWith("-"));
  const anyUnpinned =
    /@latest\b/.test(joined) ||
    pkgSpecs.length === 0 ||
    pkgSpecs.some((s) => !PINNED_RE.test(s));
  if (anyUnpinned) {
    findings.push(
      mkFinding(
        "MCP006",
        "medium",
        file,
        1,
        1,
        `Manifest starts the server via an unpinned remote runner: "${joined}". \`npx\`/\`uvx\` resolves and executes the latest published code at run time, so what you audited is not necessarily what runs.`,
        "Pin the package to an exact version (e.g. `pkg@1.2.3`) or vendor it; prefer starting from a local, lockfile-resolved install.",
        "",
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// MCP012 — dangerous npm lifecycle script (package.json)
//
// `preinstall`/`install`/`postinstall`/`prepare`/`prepublish` scripts run
// automatically on `npm install` — BEFORE you ever import the server. A
// lifecycle script that pipes a remote download into a shell, curls a script,
// or execs an env-driven command is a classic supply-chain install hook.
// Conservative: a normal build hook (`tsc`, `node build.js`, `prebuild`,
// `husky install`) does NOT fire — only network-fetch-into-shell, curl|sh,
// base64-decode-pipe, or an obvious obfuscated one-liner does.
// ---------------------------------------------------------------------------

const LIFECYCLE_HOOKS = new Set([
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "prepublish",
  "prepublishOnly",
  "preuninstall",
  "postuninstall",
]);
const DANGEROUS_SCRIPT =
  /\b(curl|wget)\b[^\n]*\|\s*(sh|bash|zsh|node|python3?)\b|\bcurl\b[^\n]*-o\b[^\n]*&&[^\n]*\b(sh|bash|node)\b|\bbase64\s+(?:-d|--decode)\b[^\n]*\|\s*(sh|bash|node)\b|\beval\s+["'$]|\bnode\s+-e\b|\bpython3?\s+-c\b|[A-Za-z0-9+/]{120,}={0,2}/;

function ruleDangerousLifecycle(json, file, findings) {
  // Only meaningful for an npm package manifest. mcp.json has no `scripts`.
  const scripts = json && typeof json.scripts === "object" ? json.scripts : null;
  if (!scripts) return;
  for (const [name, body] of Object.entries(scripts)) {
    if (!LIFECYCLE_HOOKS.has(name)) continue;
    if (typeof body !== "string") continue;
    if (!DANGEROUS_SCRIPT.test(body)) continue;
    findings.push(
      mkFinding(
        "MCP012",
        "critical",
        file,
        1,
        1,
        `npm lifecycle hook "${name}" runs a network-fetch-into-shell / obfuscated command: ${JSON.stringify(body).slice(0, 160)}. Lifecycle scripts execute automatically on \`npm install\`, before you import or audit the server — a textbook supply-chain install hook.`,
        "Remove network and shell side-effects from install/postinstall/prepare scripts. Build steps should be deterministic and offline (e.g. `tsc -p .`). If a binary must be fetched, pin and checksum it in code, not in a lifecycle script.",
        "",
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// MCP013 — secret committed in a manifest
//
// Reuses the MCP009 credential patterns but scans the *stringified manifest*
// (env blocks, custom config) — e.g. an `env: { GITHUB_TOKEN: "ghp_..." }`
// baked into mcp.json. Placeholders are still excluded.
// ---------------------------------------------------------------------------

function ruleManifestSecret(json, file, findings) {
  let text;
  try {
    text = JSON.stringify(json);
  } catch {
    return;
  }
  if (typeof text !== "string") return;
  const seen = new Set();
  for (const { re, what } of SECRET_PATTERNS) {
    const mt = re.exec(text);
    if (!mt) continue;
    const tok = mt[0];
    // Placeholder check on a window around the match, not the whole blob.
    const win = text.slice(
      Math.max(0, mt.index - 40),
      mt.index + tok.length + 40,
    );
    if (SECRET_PLACEHOLDER.test(win) && !/PRIVATE KEY/.test(tok)) continue;
    if (seen.has(tok.slice(0, 12))) continue;
    seen.add(tok.slice(0, 12));
    findings.push(
      mkFinding(
        "MCP013",
        "critical",
        file,
        1,
        1,
        `The manifest contains what looks like ${what}. Credentials committed into an MCP manifest (e.g. an \`env\` block) are leaked to anyone with the repo and live in git history.`,
        "Remove and rotate the credential. Reference secrets by environment-variable NAME in the manifest and inject the value at runtime; never store the value itself.",
        "",
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// MCP014 — declared dependency on an install-time-dangerous / typosquat-shaped
//           or git/url/tarball package (package.json dependencies)
//
// Static and offline (NO registry lookup — that stays an interface/stub).
// Two checks:
//   (1) a dependency pinned to a `git+`, `http(s):` tarball, or `github:`
//       spec — code resolved outside the registry/lockfile, mutable, not
//       audited (medium);
//   (2) a dependency whose NAME matches a small built-in list of packages
//       historically used as RCE/exfil install hooks or known
//       confusable/typosquat shapes of popular MCP/AI deps (low — advisory,
//       "verify this is the package you meant", never a hard claim).
// We deliberately do NOT claim "this version is a known CVE" — there is no
// bundled vuln DB and we make no such assertion (see README Limitations).
// ---------------------------------------------------------------------------

const DEP_FIELDS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
];
// Confusable shapes of widely-used MCP/agent ecosystem packages. This is an
// ADVISORY nudge ("did you mean X?"), explicitly not a CVE/malware claim.
const KNOWN_GOOD = [
  "@modelcontextprotocol/sdk",
  "zod",
  "express",
  "axios",
  "dotenv",
  "openai",
  "@anthropic-ai/sdk",
];
function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  if (Math.abs(m - n) > 2) return 3;
  const dp = Array.from({ length: m + 1 }, (_, i) => i);
  for (let j = 1; j <= n; j++) {
    let prev = dp[0];
    dp[0] = j;
    for (let i = 1; i <= m; i++) {
      const tmp = dp[i];
      dp[i] = Math.min(
        dp[i] + 1,
        dp[i - 1] + 1,
        prev + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
      prev = tmp;
    }
  }
  return dp[m];
}

function ruleRiskyDependency(json, file, findings) {
  const isPkgJson = json && (json.dependencies || json.devDependencies || json.name);
  if (!isPkgJson) return;
  const reportedNames = new Set();
  for (const field of DEP_FIELDS) {
    const deps = json[field];
    if (!deps || typeof deps !== "object") continue;
    for (const [name, spec] of Object.entries(deps)) {
      const s = String(spec);
      // (1) non-registry source spec
      if (
        /^(git\+|git:|github:|gitlab:|bitbucket:|https?:\/\/|file:)/.test(s) ||
        /\.(tgz|tar\.gz)(\?|#|$)/.test(s)
      ) {
        if (!reportedNames.has(`url:${name}`)) {
          reportedNames.add(`url:${name}`);
          findings.push(
            mkFinding(
              "MCP014",
              "medium",
              file,
              1,
              1,
              `Dependency "${name}" is installed from a non-registry source ("${s}"). git/url/tarball deps are not lockfile-pinned to an immutable registry artifact: the code can change after you audit it, and it bypasses registry-side checks (supply-chain / TOCTOU).`,
              'Depend on an exact published version from the registry (e.g. "name": "1.2.3") and commit a lockfile. If a fork is required, vendor it and pin to a commit + checksum you reviewed.',
              "",
            ),
          );
        }
      }
      // (2) typosquat-shape advisory (only for unscoped, lowercase-ish names)
      if (/^[a-z0-9._-]+$/.test(name) && !KNOWN_GOOD.includes(name)) {
        for (const good of KNOWN_GOOD) {
          if (good.includes("/")) continue; // skip scoped for distance
          const d = levenshtein(name, good);
          if (d > 0 && d <= 1 && Math.abs(name.length - good.length) <= 1) {
            if (!reportedNames.has(`typo:${name}`)) {
              reportedNames.add(`typo:${name}`);
              findings.push(
                mkFinding(
                  "MCP014",
                  "low",
                  file,
                  1,
                  1,
                  `Dependency "${name}" is one character from the popular package "${good}". This is an ADVISORY check (not a malware/CVE claim and no registry was contacted): confusable names are a common typosquat vector — confirm "${name}" is the package you intended.`,
                  `Verify the exact package name and publisher. If you meant "${good}", correct the dependency. mcpaudit makes no assertion about this specific package — it only flags the name-similarity.`,
                  "",
                ),
              );
            }
          }
        }
      }
    }
  }
}

/**
 * Run every manifest rule on one parsed JSON manifest (package.json /
 * mcp.json / server.json / *.mcp.json). Pure. Each rule is shape-aware so a
 * package.json rule never double-fires on mcp.json and vice-versa.
 * @param {object} json
 * @param {string} relPath
 * @returns {Finding[]}
 */
export function analyzeManifest(json, relPath) {
  const findings = [];
  if (!json || typeof json !== "object") return findings;
  ruleBroadFsScope(json, relPath, findings);
  ruleUnrestrictedToolGlob(json, relPath, findings);
  ruleUnpinnedRemoteExecManifest(json, relPath, findings);
  ruleDangerousLifecycle(json, relPath, findings);
  ruleManifestSecret(json, relPath, findings);
  ruleRiskyDependency(json, relPath, findings);
  return findings;
}

/**
 * CI gate: true (=> caller should exit non-zero) iff any finding's severity
 * is >= `failOn`. `failOn: "none"` never gates.
 * @param {Finding[]} findings
 * @param {"critical"|"high"|"medium"|"low"|"none"} failOn
 * @returns {boolean}
 */
export function gate(findings, failOn) {
  if (failOn === "none") return false;
  const threshold = SEVERITY_ORDER[failOn] ?? SEVERITY_ORDER.high;
  return findings.some(
    (f) => (SEVERITY_ORDER[f.severity] ?? 0) >= threshold,
  );
}
