# mcpaudit

**A quick security X-ray for AI agent plugins, to run before you plug one in.**

An MCP server (MCP = Model Context Protocol, the standard way to give an AI
assistant new tools) is code you download and let an AI agent run. mcpaudit
reads that code *before* you trust it and points out the dangerous bits — the
quick safety check that doesn't really exist for these plugins yet.

```bash
npx allenwu-blip/mcpaudit#0040ed63d9bae5b0fbe0323928178455253034e9 ./path-to-an-mcp-server
```

No install, no setup, no API key, no internet needed. It reads the plugin's
source code and its settings file and flags risky patterns, ranked by how bad
they are, each with a concrete fix. It **never runs** the code it is checking —
it only reads it.

---

## Track record

This has been run against real servers, and every finding was read by hand
before it was reported to anyone.

- **12 MCP servers audited** — the four official TypeScript reference
  implementations plus eight third-party ones. Public reports filed on MongoDB,
  Softeria, mobile-mcp, mcpvault, mcp-server-neon, freee, ssh-mcp and
  token-optimizer.
- **A maintainer independently checked the triage.** From
  [ms-365-mcp-server#651](https://github.com/Softeria/ms-365-mcp-server/issues/651),
  which they then closed as completed: *"I spot-checked the `src/` ones and your
  triage matches what I see."*
- **MongoDB routed the report into internal tracking** —
  [issue #1470](https://github.com/mongodb-js/mongodb-mcp-server/issues/1470),
  Jira MCP-637.
- **A user found a false negative and it got fixed.** That same maintainer
  pointed out a `spawn` this scanner had missed, because they inject it as a
  class field so the call site reads `spawnCommand` rather than an imported
  name. Aliases are now resolved; seven regression tests cover it.

Triaging that corpus turned up **22 precision bugs in this tool**, which is the
more useful number. Findings across the twelve repositories went 652 → 436 and
criticals 105 → 9 — that is the raw hit count moving, not a false-positive rate.

Four of the 22 were the same mistake: a *defence* reported as the vulnerability
— an allowlist guard, a reserved-key set containing `__proto__`, a file named
`safe-exec.ts` documenting the CWE-78 mitigation it enforces, and a Google API
key one line under a comment saying it is public. Defensive code and vulnerable
code look alike at the token level; the difference is the direction of the
logic. A scanner that cannot tell them apart punishes the teams that did the
work. Avoiding that is most of what the rules above are for.

Write-ups: [scanning 12 MCP servers](https://gist.github.com/allenwu-blip/d20a110207dd36cd3b4d86f3960ec215)
· [what 396 repos actually install](https://gist.github.com/allenwu-blip/817f4a181ec9ef050b6a25e992cdad4e)

---

## Why

These plugins run with real power *inside* the AI agent's loop — they can get a
shell, your files, and the network on your machine, and whatever a plugin's
tools output flows straight back into the AI's context where it can steer what
the AI does next. Published MCP servers get inconsistent security review before people wire
them in — the 2026 surveys from
[dev.to](https://dev.to/ecap0/the-state-of-mcp-server-security-in-2026-118-findings-across-68-packages-4fkd)
and
[The Register](https://www.theregister.com/security/2026/04/16/mcp-design-flaw-puts-200k-servers-at-risk-researcher/5222022)
give differing pictures of how widespread the risk is — but the failure
modes are concrete: command injection, environment/credential leakage into
LLM-visible context, and over-broad filesystem/tool scope.

> `mcpaudit` exists so you can run a concrete check for those patterns
> yourself, in seconds, offline, before letting someone else's plugin run
> inside your agent.

## Install / run

It's zero-install via `npx`. A local path is scanned fully offline:

```bash
# Pin to a commit. Read it first if you like — that is the point of a pin.
MCPAUDIT='allenwu-blip/mcpaudit#0040ed63d9bae5b0fbe0323928178455253034e9'

# scan a server you cloned / vendored
npx "$MCPAUDIT" ./vendor/some-mcp-server

# machine-readable output for CI / tooling
npx "$MCPAUDIT" ./server --json

# SARIF v2.1.0 (a standard scan-results format GitHub understands) —
# upload it so findings show in GitHub's Code scanning tab
npx "$MCPAUDIT" ./server --sarif > mcpaudit.sarif

# stricter gate: any high or critical fails the command
npx "$MCPAUDIT" ./server --fail-on high

# continuous monitoring: accept current state, then gate only on NEW
# regressions (offline, no accounts) — see "Continuous monitoring" below
npx "$MCPAUDIT" ./server --baseline-write .mcpaudit-baseline.json
npx "$MCPAUDIT" ./server --baseline .mcpaudit-baseline.json
```

> **Why the commit hash.** `npx allenwu-blip/mcpaudit` — no hash — runs
> whatever is on `main` at the moment you type it, which is a stranger's
> code that can change between your two runs. A security tool asking you to
> do that is a tool that has not read its own MCP006 rule. The pin above is
> the commit these docs were written against; `git log` it, diff it, or
> replace it with a later one you have looked at. This suggestion came from
> [@ooples](https://github.com/ooples), who declined to run the unpinned
> form and audited by hand instead. He was right.

> Scanning by **bare package name** (`npx mcpaudit some-mcp-pkg`) needs a
> registry/tarball fetch wired up; the published build asks you to pass a
> path instead (it does not silently do nothing and does not hit the
> network). The path scan is the fully-functional path today.

### Exit codes (so you can wire it into CI)

CI ("continuous integration" — the automated checks that run on every code
push) reads these exit codes:

| code | meaning |
|------|---------|
| `0`  | scan completed, gate not tripped. **Also** internal error — see below. |
| `1`  | scan completed and a finding met/exceeded `--fail-on` (default `high`). |
| `2`  | usage error (bad arguments). |

**Fails open on purpose:** if `mcpaudit` itself breaks (a bug, a folder it
can't read), it prints a loud error and exits `0`. A security checker that is
itself broken should not block every build in your project. If you want it to
be a *hard* stop, make it a **required** check with `--fail-on` set, so a
missing or zero result is visible rather than silently passing.

## What it detects

This is the detailed reference for developers. The rules are fixed and give
the same answer every time (no AI, no guessing). Each finding has a stable id,
a severity (how serious), the exact `file:line:col` location, a plain
explanation of **why it fired**, and how to fix it.

| id | severity | what it flags |
|----|----------|---------------|
| `MCP001` | critical | **Command injection** — `child_process` `exec`/`execSync`/`spawn`/`fork` (or `execFile` with `shell:true`) built from a non-literal command (template interpolation, `+` concat, or a variable). A pure string literal does not fire. |
| `MCP002` | high | **Credential / env exfiltration to the LLM** — `process.env` flowing into a tool result `text`, a returned value, or a tool/handler description. Env read into a local used only for outbound auth does not fire. |
| `MCP003` | high | **Over-broad filesystem scope** — an MCP manifest granting `/`, `~`, a drive root, `*`, or a `../`-escaping path as an allowed directory. |
| `MCP004` | medium | **Unrestricted tool scope** — a wildcard tool allowlist (`"*"`, `["*"]`, `allowAllTools: true`). |
| `MCP005` | high | **Dangerous dynamic eval** — a *bare global* `eval()` / `new Function()`, or the `vm` builtin's `runInThisContext`/`runInNewContext`/`runInContext`/`compileFunction`, with a non-literal argument. `eval("1+1")` does not fire; a *method* of the same name on another object (`mathExpr.compile(x)`, `parser.eval(x)`) does not fire; a userland-bound `vm` does not fire (provenance). |
| `MCP006` | medium | **Unpinned remote code execution** — `curl … \| sh`, `npx …@latest`, `uvx`, etc. in source strings or the manifest start command. A pinned `pkg@1.2.3` does not fire. |
| `MCP007` | high | **Prototype pollution** — a recursive/deep merge or deep-set (`_.merge`, `defaultsDeep`, `setWith`, `deepmerge`, …) from a non-literal source, or a computed `obj[key]=v` assignment where `key` can be `__proto__`/`constructor`. An inline-object-literal merge source and numeric array indices do not fire. |
| `MCP008` | high | **SSRF-able outbound request** — `fetch`/`axios`/`got`/`https.request` with an attacker-influenceable URL **origin** (a bare variable, `${host}` in the authority, or a leading-variable concat). A hardcoded origin with only the path/query varying (`"https://api.x/v1?q=" + enc(q)`, `` `https://api.x/${id}` ``) does **not** fire. |
| `MCP009` | critical | **Hardcoded secret in source** — a string literal that looks like a real credential (AWS/GitHub/Slack/Google key, an OpenAI- or Anthropic-style key, a PEM private key, a JWT). Obvious placeholders (`your-…`, `XXXX`, `<…>`, `example`) and comment-only mentions do not fire. |
| `MCP010` | high | **Path traversal in a file tool** — an `fs.*` call whose path is a bare variable or a concat/template with no `path.join`/`resolve`/`normalize`/`basename` containment. Requires an `fs` binding (provenance). A pure literal path does not fire; a bare path variable whose *nearest prior assignment* is a `path.join`/`resolve`/`normalize`/`basename` expression (hoisted containment) does not fire. |
| `MCP011` | critical / high | **Unsafe deserialization** — `node-serialize`/`serialize-javascript` `unserialize`/`deserialize` of non-literal data (critical, RCE), or `js-yaml` `load()` with the default schema (high). `JSON.parse` and `yaml.load(x, { schema: yaml.JSON_SCHEMA })` do not fire. |
| `MCP012` | critical | **Dangerous npm lifecycle script** — a `preinstall`/`install`/`postinstall`/`prepare` script that pipes a network download into a shell, base64-decodes into a shell, or is an obvious obfuscated one-liner. A normal build hook (`tsc`, `node build.js`, `husky install`) does not fire; a curl in a non-lifecycle script does not fire. |
| `MCP013` | critical | **Secret committed in a manifest** — a credential pattern (as MCP009) embedded in `package.json`/`mcp.json` (e.g. an `env` block). Placeholders and `${VAR}` references do not fire. |
| `MCP014` | medium / low | **Risky declared dependency** — a `git+`/url/tarball dependency source that bypasses the registry/lockfile (medium); or, as a **low advisory only**, a dependency name one edit away from a popular package (typosquat *shape*). **Static and offline — no registry/network and no CVE/malware claim is ever made.** |

The rules are intentionally **conservative** — they aim to avoid the obvious
false-positive patterns (literal `exec`/`eval`, env used only for auth,
scoped relative directories, fixed-origin URLs, `path.join`-contained file
access, safe-schema YAML, placeholder secrets, normal build hooks, and scary
tokens that are only in comments). The bundled `borderline` fixture is a
legit MCP server full of code that *looks* dangerous and must produce **zero
findings**; it is part of CI.

### Output formats

| flag | format | use |
|------|--------|-----|
| *(default)* | human | a developer reading the terminal before `npx`-ing a server |
| `--json` | JSON | CI/tooling (stable schema, summary counts); includes a `baseline` block when `--baseline` is used |
| `--sarif` | SARIF v2.1.0 | upload with `github/codeql-action/upload-sarif@v3` to populate the **Code scanning** tab; each result carries the stable finding id as a `partialFingerprint` so GitHub de-dupes across runs |
| `--monitor-json` | JSON | (with `--baseline`) the structured monitoring record — the machine contract a hosted tier would consume; this build only prints it locally |

### Project config (`mcpaudit.config.json`) — for what the analyzer can't know

There is exactly one thing a lexical scanner cannot resolve on its own: a path
that reaches an `fs.*` call as a **function parameter**. There is no assignment
to look back at, and without taint tracking there is no way to know whether the
caller validated it. The official MCP `filesystem` server is the canonical
case — its `lib.ts` exports functions taking a path, and every real caller runs
`validatePath()` first, but the scanner can only see the callee.

Drop a `mcpaudit.config.json` at the scan root to tell it what you know:

```json
{
  "pathValidators":  ["validatePath", "assertInsideRoot"],
  "trustedPathVars": ["filePath", "tempPath", "currentPath"]
}
```

| key | meaning |
|-----|---------|
| `pathValidators` | a value assigned from one of these calls is treated as **contained**, instead of merely downgraded to `low` |
| `trustedPathVars` | variable/parameter names you assert are validated before reaching a filesystem call |

Both are assertions by a human who took responsibility, so they suppress rather
than downgrade. Unknown keys and non-identifier entries are ignored and
reported; a malformed file never aborts the scan.

**Suppression is never silent.** Every run prints how many findings the config
removed, in the human report and in `--json`:

```
diagnostics (scan was degraded, not aborted):
  - 13 finding(s) suppressed by mcpaudit.config.json (pathValidators /
    trustedPathVars). Delete or rename that file to see them.
```

A scanner that quietly drops findings because of a file in the repo it just
scanned is worse than one that over-reports. If you inherit a repo with this
file in it, you can see at a glance that it is there and what it cost you.

### Continuous monitoring (baseline diff — free, offline, no accounts)

A one-shot scan tells you today's state. A team usually wants *"did anything
get **worse** since we last reviewed this server?"* That is a diff against a
committed baseline — pure, deterministic, offline, no sign-up:

```bash
# 1. accept the current state into a baseline and commit it
npx allenwu-blip/mcpaudit#0040ed63d9bae5b0fbe0323928178455253034e9 ./server --baseline-write .mcpaudit-baseline.json
git add .mcpaudit-baseline.json && git commit -m "mcpaudit baseline"

# 2. in CI: re-scan and gate ONLY on NEW findings (regressions). An
#    already-triaged finding no longer re-breaks every build; a freshly
#    introduced one does.
npx allenwu-blip/mcpaudit#0040ed63d9bae5b0fbe0323928178455253034e9 ./server --baseline .mcpaudit-baseline.json --fail-on high
```

The baseline file is intentionally **timestamp/host/user-free** so re-writing
an unchanged repo is byte-identical (clean, reviewable PR diffs); *when* a
finding appeared is git's job, not the file's.

> **Note (honest scope):** the hosted/continuous-monitoring *product* — a
> service that watches a server over time, alerts on a new critical, or shows
> a fleet view — is **not in this repo**. This OSS CLI ships only the
> baseline-diff mechanic and emits the machine record a hosted tier would
> consume (`--monitor-json`). There is **no network call, no upload, no
> account, no billing** anywhere in this codebase, by design.

## GitHub Action

A thin wrapper around the same scan. Copy
[`examples/mcpaudit.yml`](examples/mcpaudit.yml) into
`.github/workflows/`:

```yaml
- uses: allenwu-blip/mcpaudit@v0
  with:
    path: "."
    fail-on: "high"
    sarif: "true"          # optional: write mcpaudit.sarif
    # baseline: ".mcpaudit-baseline.json"  # optional: gate on NEW only
```

It posts a GitHub annotation per finding and sets outputs (`total`,
`critical`, `high`, `medium`, `low`, `gate`, plus `new`/`fixed` with a
baseline and `sarif-file` with `sarif: true`). With `sarif: true` it writes
a SARIF v2.1.0 file you upload via `github/codeql-action/upload-sarif@v3`
(see [`examples/mcpaudit.yml`](examples/mcpaudit.yml) for the
`security-events: write` permission and upload step). No token or secret is
needed for the scan itself; the Action does **no network I/O** and never
runs the scanned code. It fails open on internal error — make the job a
**required** check for hard enforcement.

## Limitations (read this)

`mcpaudit` reads code and matches known-dangerous patterns. It does **not**
run the code in a locked box (a "sandbox") and it does **not** trace exactly
how a value flows from input to a dangerous spot ("taint analysis"). Be
clear-eyed about what that means:

- **It will miss things (false negatives).** Obfuscated code, vulnerability
  reached through indirection/aliasing, dynamic `require`, behaviour that
  only manifests at runtime, or a malicious dependency several layers deep
  are largely **out of scope**. A clean result is **not** a security
  guarantee or an audit — review the server's tools and scope yourself.
- **It does not do taint tracking.** It cannot prove a sink is *reachable
  from tool input*; it flags the dangerous shape and tells you to verify
  reachability. Conversely it deliberately under-reports to stay quiet:
  e.g. **MCP010 does not flag `path.join("./dir", x)`** even though a `..`
  in `x` can still escape — full path-containment analysis is beyond a
  lexical scanner, so that is a *known, accepted false negative*, not a
  guarantee the call is safe. Treat every `path.*`/merge/`fetch` on tool
  input as worth a human look regardless of whether a rule fired.
- **Provenance-gated, conservative by design (favor a false negative over
  cry-wolf).** A few rules deliberately stay quiet on idiomatic-safe shapes:
  - **MCP005** fires only on a *bare global* `eval(` / `new Function(`, and
    on the `vm` builtin's `runInThisContext`/`runInNewContext`/`runInContext`/
    `compileFunction`. A *method* call that merely shares those names —
    `mathExpr.compile(x)`, `parser.eval(x)`, `engine.compile(tmpl)`, an ORM
    `.run()` — does **not** fire (it is not the global / `vm`). The `vm.*`
    sink is suppressed when `vm` is provably a userland binding (e.g.
    `const vm = makeSandboxShim()`). Bare `eval(userInput)` still fires by
    design — that *is* the sink.
  - **MCP010** also treats *hoisted containment* as safe: when the `fs.*`
    path is a bare variable whose nearest prior assignment is built from
    `path.join`/`resolve`/`normalize`/`basename(...)` (e.g.
    `const safe = path.resolve(BASE, path.basename(name)); fs.readFileSync(safe)`),
    it does **not** fire. This look-back is the *nearest* declaration/
    assignment of that identifier and is intentionally single-hop — a
    containment value passed through *additional* indirection (further
    aliasing, a helper return) is a *known, accepted false negative* (same
    stance as the `path.join` note above), not a safety guarantee.
- **It will sometimes be wrong (false positives).** The rules use a lexical
  model (comments and static string text are excluded; template
  interpolation is treated as code). Unusual code can still trip a rule.
  Please [report misfires](FEEDBACK.md) — that is how it improves.
- **No accuracy/benchmark numbers are claimed.** There is no published
  labeled corpus behind this tool, so it ships with **no precision/recall or
  detection-rate figures**, and it makes no claim about how it compares to
  any external survey of the MCP ecosystem.
- **The dependency layer is static and offline — and makes no CVE claim.**
  `MCP014` flags non-registry dependency *sources* and, as a *low advisory
  only*, names that are one edit from a popular package. It contacts **no
  registry**, bundles **no vulnerability database**, and asserts **nothing**
  about whether a given package/version is malicious or has a known CVE.
  Pair it with a real SCA/advisory tool (`npm audit`, OSV, Dependabot).
  Registry/tarball fetching for `mcpaudit <name>` remains an unimplemented,
  honest interface — the published build asks you to pass a path.
- **Scope is the documented MCP/Node patterns.** JS/TS source + JSON
  manifests. Servers written in other languages, or that hide configuration
  outside the manifest, are not fully covered. Minified/bundled,
  binary/non-UTF8, and symlinked files are deliberately **skipped** (and
  surfaced as diagnostics) — audit the original source, not build artifacts.
- It is one layer. Use it alongside dependency scanning, least-privilege
  configuration, and human review — not instead of them.

## How it works

- `src/rules.js` — the pure, deterministic analyzer (no I/O, no network, no
  code execution): 14 source/manifest rules. Fully unit-tested.
- `src/analyze.js` — the only filesystem touch: walks the tree, **never
  follows symlinks** (cannot be steered out of the target), skips
  minified/binary/non-UTF8 blobs and pathological depth, never throws
  (errors are collected and returned), and never runs the project.
- `src/format.js` — pure presentation: human, `--json`, and SARIF v2.1.0.
- `src/baseline.js` — pure baseline build + diff for continuous monitoring;
  contains the documented `// PAID TIER` seam (no network/account code).
- `bin/mcpaudit.js` / `src/action.js` — thin CLI / Action glue.

Finding ids are a deterministic hash of `rule|file|line|col|message`, so two
distinct findings at the same location stay distinct **and** the id is
stable across runs and machines — CI baselines, SARIF de-dup, and
suppression lists are reproducible.

## Development

```bash
npm ci
npm test          # vitest — no network, no API key required
node bin/mcpaudit.js test/fixtures/vulnerable-server   # try it
node bin/mcpaudit.js test/fixtures/vulnerable-server --sarif | head
```

Tests run against three fixture MCP servers — a clean one (zero findings), a
vulnerable one (**every one of the 14 rules fires** with the right severity
and location), and a borderline one (legit code that looks scary across all
14 rules and must stay at **zero findings**) — plus dedicated suites for
SARIF schema correctness, baseline-diff behaviour, and adversarial
hardening (symlink escape, minified/binary/non-UTF8, deep trees,
never-throws).

## Feedback

False positives and missed vulns are the most valuable input. See
[FEEDBACK.md](FEEDBACK.md): add the `mcpaudit-feedback` label to an issue, or
use the issue template. Reports are captured **verbatim** — read exactly as
written, never paraphrased.

## License

MIT — see [LICENSE](LICENSE).
