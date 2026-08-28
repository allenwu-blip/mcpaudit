import { defineConfig } from "vitest/config";

// `bin/mcpaudit.js` opens with `#!/usr/bin/env node`. Node strips a shebang
// before parsing, so running the CLI works and `import()`ing it from plain node
// works; esbuild, which Vite uses to transform imported modules, does not strip
// it and fails with `SyntaxError: Invalid or unexpected token` — reported
// against the IMPORT SPECIFIER in the importing file, which is why this looked
// like a problem in the tests rather than in the CLI.
// Cost of not noticing: test/cli.test.js and test/baseline.test.js failed to
// load, so neither had ever run. Comment the line out rather than deleting it,
// to keep every subsequent line and column offset identical.
const stripShebang = {
  name: "strip-shebang",
  enforce: "pre",
  transform(code, id) {
    if (!id.endsWith(".js") || !code.startsWith("#!")) return null;
    return { code: `//${code.slice(2)}`, map: null };
  },
};

export default defineConfig({
  plugins: [stripShebang],
  test: {
    environment: "node",
    include: ["test/**/*.test.js"],
    // Hard guarantee: no network, no real API key required in CI. The scan
    // core is pure; the only I/O is reading the local fixture directories.
    env: {},
  },
});
