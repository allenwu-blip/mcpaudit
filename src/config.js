/**
 * Optional per-project configuration: `mcpaudit.config.json` at the scan root.
 *
 * This exists for exactly one situation the analyzer cannot resolve on its own.
 * mcpaudit does no taint tracking, so when a path reaches an `fs.*` call as a
 * function parameter there is no assignment to look back at and no way to know
 * whether the caller validated it. The official MCP `filesystem` server is the
 * canonical case: ten `high` findings in `lib.ts`, every one of them a path
 * parameter that every real caller does validate first.
 *
 * The project owner knows that. This file lets them say so.
 *
 * {
 *   "pathValidators":  ["validatePath", "assertInsideRoot"],
 *   "trustedPathVars": ["filePath", "tempPath", "currentPath"]
 * }
 *
 * `pathValidators`  - a value assigned from one of these calls is treated as
 *                     contained, instead of merely downgraded to `low`.
 * `trustedPathVars` - variable/parameter names the project asserts are
 *                     validated before they reach a filesystem call.
 *
 * Both are assertions by a human who took responsibility, so they suppress
 * rather than downgrade. Suppression is NEVER silent: every scan reports how
 * many findings this file removed, and `--json` carries the same count. A
 * security tool that quietly drops findings is worse than one that shouts.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

export const CONFIG_NAME = "mcpaudit.config.json";

const EMPTY = Object.freeze({
  pathValidators: [],
  trustedPathVars: [],
  present: false,
});

function names(v) {
  if (!Array.isArray(v)) return [];
  return v.filter((s) => typeof s === "string" && /^[\w$]+$/.test(s));
}

/**
 * Read and validate the project config. Never throws: a broken config must not
 * take the scan down, it just reports the problem and scans with defaults.
 *
 * @param {string} rootDir scan root
 * @param {string[]} errors diagnostics sink
 * @returns {{pathValidators:string[], trustedPathVars:string[], present:boolean}}
 */
export function loadConfig(rootDir, errors = []) {
  let txt;
  try {
    txt = readFileSync(join(rootDir, CONFIG_NAME), "utf8");
  } catch {
    return EMPTY; // absent is the normal case
  }

  let json;
  try {
    json = JSON.parse(txt);
  } catch (e) {
    errors.push(`${CONFIG_NAME}: invalid JSON (${e.message}); scanning with defaults`);
    return EMPTY;
  }
  if (!json || typeof json !== "object" || Array.isArray(json)) {
    errors.push(`${CONFIG_NAME}: expected a JSON object; scanning with defaults`);
    return EMPTY;
  }

  const cfg = {
    pathValidators: names(json.pathValidators),
    trustedPathVars: names(json.trustedPathVars),
    present: true,
  };

  for (const k of Object.keys(json)) {
    if (k !== "pathValidators" && k !== "trustedPathVars") {
      errors.push(`${CONFIG_NAME}: unknown key "${k}" ignored`);
    }
  }
  return cfg;
}
