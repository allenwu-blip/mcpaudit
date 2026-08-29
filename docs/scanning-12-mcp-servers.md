# I Scanned 12 MCP Servers and Found 22 Bugs in My Own Scanner

I built [`mcpaudit`](https://github.com/allenwu-blip/mcpaudit), a static security scanner for Model Context Protocol servers. Fifteen deterministic rules, pure lexical analysis, no code execution, no network access. Its job is to find dangerous patterns before you install someone else's plugin into your agent.

To check whether it worked, I scanned 12 real repositories — the four official TypeScript servers from `modelcontextprotocol/servers` plus eight third-party ones (`ssh-mcp`, `mcpvault`, `ms-365-mcp-server`, `mongodb-mcp-server`, `mcp-server-neon`, `mobile-mcp`, `freee-mcp`, `token-optimizer-mcp`).

Then I read the source behind every single hit.

Across all twelve, **two findings were worth a maintainer's attention.** Everything else was either my tool being wrong, or a real pattern sitting outside the threat model. Triaging it turned up **22 precision bugs in mcpaudit itself**, which is the more useful number and the reason for this post.

## Hit counts are a vanity metric

Total findings across the twelve repositories went from **652 to 436**. A 33% reduction.

If you were selling this as a product update you'd be embarrassed. It suggests the tool is still noisy.

But criticals went **105 → 9**. A 91% drop.

Why is the total drop modest while the critical drop is enormous? Because one repository, `token-optimizer-mcp`, generates its hook library into eleven directories from a single source of truth in `hooks-core/`. My scanner counted the same thirteen findings once per copy. The rule was right. The repository was repetitive.

So "we reduced alerts by 33%" would be a lie by omission. **The real change is categorical.** Entire classes of logically impossible judgement disappeared:

- `Map.set` is no longer prototype pollution — `Map` keys never traverse `Object.prototype`.
- `execFile` with an argv array is no longer shell injection — it doesn't invoke a shell.
- Array destructuring is no longer computed property assignment.

The scanner is quieter not because it suppresses noise, but because it stopped making category errors.

## The four that matter most: I reported people's defences as their vulnerabilities

Of the 22, four were the same mistake, and it is the one I would most want another scanner author to avoid.

| What I flagged | What it actually was |
|---|---|
| `mongodb-mcp-server` header handling | an **allowlist guard** on forwarded headers |
| `freee-mcp` prototype pollution | a `RESERVED_KEYS` set — whose own `'__proto__'` literal was the evidence that tripped my rule |
| `token-optimizer-mcp` command injection | a file named **`safe-exec.ts`** whose header documents the CWE-78 mitigation it enforces |
| `chrome-devtools-mcp` hardcoded secret | a Google CrUX key, one line under a comment reading *"Yes, we're aware this API key is public"* |

Defensive code and vulnerable code are nearly identical at the token level. The difference is the *direction of the logic*, and a lexical rule reads tokens, not direction.

This failure mode is worse than ordinary noise. It systematically punishes the teams who did the work and rewards the ones who never thought about `__proto__` at all — because they never mentioned it, so they never tripped the rule. If you ship a scanner that cannot tell a guard from a sink, that is the incentive you are creating.

## A post-mortem on the rest

### `execFile` is not `exec`

The single biggest contributor to the critical drop.

```javascript
// Safe: first arg is a binary path, rest is an argv array. No shell.
execFileSync(getAdbPath(), ["-s", this.deviceId, ...args], {...});
```

`execFile`, `spawn` and `fork` without `shell: true` do not invoke a shell. This is *exactly* what every security guide tells you to replace `exec()` with. I was flagging the recommended fix as Critical.

- `mobile-mcp`: 12 criticals → 0
- `token-optimizer-mcp`: 86 criticals → 4

### `return` doesn't mean `process.env` is returned

`MCP002` checked whether `process.env` appeared on the same line as `return`.

```javascript
if (process.env.MODE === 'off') return 'off:mode';  // env in the condition, literal returned
return process.env.NODE_ENV === 'development';       // returns a boolean, not the value
```

125 false positives across 7 repositories.

### Method definitions are not calls

```javascript
const server = Bun.serve({ port, async fetch(request) { ... } });
```

That's the standard entry point for Bun/Deno/Workers. This `fetch` *receives* requests; it doesn't send them. My SSRF rule had the direction backwards.

### My fix wasn't clean

I fixed the array-destructuring false positive by requiring a leading `[\w$)\]]` before the bracket, assuming it would exclude declarations. `const` ends in `t`, which is a word character, so `const [` still matched. I didn't notice until I scanned `mcp-server-neon` and it was still wrong.

*You cannot fix a regex bug by guessing. You need real code to break your fix.*

### Function names are not semantics

`MCP010` assumed a function named `validate*` was a validator. It missed the inverse:

```javascript
function getTokenFilePath() {
  return path.join(getConfigDir(), 'tokens.json');
}
fs.writeFileSync(getTokenFilePath(), data);
```

The name matched no validator pattern, but the body was right there in the same file. The scanner now reads the function body when it's in scope. `mcpvault` high-severity hits went 18 → 2.

The rest — `Map.set`, destructured `import { join }`, file descriptors mistaken for paths, constants treated as attacker-controlled, scanning `__tests__/` as production code — are all the same shape: a pattern that looks dangerous in isolation and is provably safe in context.

## The two true positives

1. **`sequentialthinking/lib.ts:64`**
   ```javascript
   this.branches[input.branchId] = [];
   ```
   `input.branchId` arrives directly as MCP tool input. Textbook prototype-pollution sink.

2. **`everything/tools/get-env.ts:34`**
   ```javascript
   text: JSON.stringify(process.env, null, 2)
   ```
   Dumps the entire environment into an LLM-visible tool result. It's a demo server and the behaviour is intentional, but it's still an anti-pattern worth naming.

An uncomfortable footnote on the first one: it was firing **by accident**. My prototype-pollution rule required a file to show "awareness of the prototype chain" before it would report, and the token I used for that was `constructor` — which every JavaScript class contains. The gate was satisfied by every class in existence. The corpus's only true positive of that kind was being found for a reason that had nothing to do with why it was true.

## The parts other people found

Two maintainers reviewed this work and each found something I could not have found alone.

**A false negative.** The maintainer of `ms-365-mcp-server` spot-checked my triage, agreed with it, and then pointed out a `spawn` I had missed — they inject it as a class field, so the call site reads `spawnCommand` rather than an imported name. My provenance gate only matched imported identifiers. Aliases are now resolved; seven regression tests cover it.

**A blind spot I'd explained away.** The maintainer of `token-optimizer-mcp` noticed my copy count was one short and guessed why, without running my tool:

> `copilot` is under `.github/`, which most scanners skip by default — I suspect that's exactly why your group size came out one short.

He was right. My directory walker had `if (SKIP_DIRS.has(name) || name.startsWith("."))` — a blanket skip of every dot-directory. For an **MCP** scanner that is an embarrassing default, because `.cursor/mcp.json`, `.vscode/mcp.json` and `.claude/settings.json` are the exact manifests three of my rules exist to read. I was skipping the files I claim to check. Fixing it took that repository from 938 scanned files to 996.

He also caught an arithmetic contradiction: my report claimed both "130 distinct findings" and "closes 143 of the 247," which cannot both be true. The cause was that every generated copy carries a two-line `// GENERATED FILE -- do not edit.` banner that the source does not — so a byte-hash deduplicator puts `hooks-core/` **outside** the group it is the source of. In his words: *the file your report tells a maintainer to edit is the one file your grouper won't group.* Grouping now ignores a leading comment banner, and names the un-stamped original as the file to fix.

The pattern worth naming: every `file:line` citation in that report was exact, because the tool produced them. The paths and the counts were wrong, because I typed them by hand. **Everything I wrote rather than generated is the part that failed.**

## The ceiling: cross-function taint analysis

The official `filesystem` server still reports 10 high-severity hits, and they are *correct*.

```typescript
return await fs.readFile(filePath, encoding as BufferEncoding);   // lib.ts:158
await fs.writeFile(tempPath, content, 'utf-8');                   // lib.ts:173
```

The validation lives in the caller. `index.ts` runs everything through `validatePath()` — normalises, checks an allowlist, re-checks after resolving symlinks, validates the parent directory for files that don't exist yet. It even has a TOCTOU race test.

My scanner is lexical and single-file. It sees a bare parameter reaching `fs.readFile` with no validator call in that scope, because the validation happened one stack frame up. Fixing that needs cross-function taint analysis, which I have not built.

But the honest position is that **reporting those 10 is defensible.** `lib.ts` exports functions accepting arbitrary paths. Whether they're safe depends on every caller validating first. A library that assumes its callers are careful is a security risk, and the scanner is right to be suspicious.

Since I can't do the analysis, there's an escape hatch — a `mcpaudit.config.json` where you assert which functions are validators. It's a **suppression, not a downgrade**, and it is never silent:

```text
diagnostics (scan was degraded, not aborted):
  - 13 finding(s) suppressed by mcpaudit.config.json ...
```

A scanner that quietly drops findings because of a config file is worse than one that over-reports.

## What I'd tell anyone building one of these

**Scan real code, not fixtures.** Every one of the 22 bugs came from a real repository. None came from my test suite, which passed the whole time.

**Your defence-detection matters as much as your detection.** Four of 22 were me reporting a mitigation as the vulnerability. If you can't tell a guard from a sink, you are punishing the teams that did the work.

**Write down the file you couldn't parse.** I reported one file as "skipped: minified" rather than dropping it silently. It wasn't minified — its newlines had been stripped and its entire body sat behind a `//`. That note is the only reason the maintainer looked, and it led to eight dead files being deleted from the package. A minified file has no `//` comments, because they'd swallow everything after them; so "huge line that starts with `//`" is collapsed source and deserves its own message.

**Hit-count deltas are marketing.** 652 → 436 says nothing. `Map.set` is no longer prototype pollution — that says something.

The scanner now has 15 rules and 199 tests. Run it against something you're about to install:

```bash
npx allenwu-blip/mcpaudit#0040ed63d9bae5b0fbe0323928178455253034e9 ./some-mcp-server
```

That hash is there on purpose. An unpinned `npx <github-repo>` runs whatever is on `main` at the moment you type it — a stranger's code that can change between your two runs. A security tool asking you to do that hasn't read its own rules. That criticism came from the same maintainer above, who declined to run it and audited by hand instead.
