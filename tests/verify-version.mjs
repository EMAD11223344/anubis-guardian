#!/usr/bin/env node
/**
 * Version-consistency gate (W4): the version surfaced to users must agree
 * everywhere it is hardcoded. Guards against the drift class found during the
 * W4 audit (docs/comments circulated v1.5.2/v1.5.3 labels while npm stayed at
 * the last published version).
 *
 * Asserts (all must equal):
 *   1. package.json "version"
 *   2. src/engine.ts VERSION constant (via dist/engine.js)
 *   3. the README version badge (badge/version-X.Y.Z)
 *   4. the docs/site landing page version badge, when present
 * Historical references (CHANGELOG Unreleased sections, corpus provenance
 * strings, fix-commit round labels) are deliberately NOT asserted — they are
 * commit-history, not release labels.
 */
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const v = pkg.version;

let PASS = 0;
const FAILS = [];
const check = (name, cond, extra = "") => {
  if (cond) PASS++;
  else FAILS.push(`${name}${extra ? " — " + extra : ""}`);
};

check(`package.json version parses as semver (${v})`, /^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(v));

const dist = readFileSync(join(ROOT, "dist", "engine.js"), "utf8");
const m = dist.match(/VERSION = "([^"]+)"/);
check(`dist/engine.js VERSION === ${v}`, Boolean(m) && m[1] === v, m ? `dist says ${m[1]}` : "VERSION constant not found");

const readme = readFileSync(join(ROOT, "README.md"), "utf8");
const badge = readme.match(/badge\/version-([\w.-]+)-/);
check(`README version badge === ${v}`, Boolean(badge) && badge[1] === v, badge ? `badge says ${badge[1]}` : "badge not found");

const site = join(ROOT, "docs", "site", "index.html");
try {
  const html = readFileSync(site, "utf8");
  const sv = html.match(/version-([\w.-]+)-/);
  if (sv) check(`docs/site version badge === ${v}`, sv[1] === v, `site says ${sv[1]}`);
} catch { /* no site page — not asserted */ }

console.error(`VERSION CONSISTENCY: ${PASS} passed, ${FAILS.length} failed (v${v})`);
if (FAILS.length) {
  for (const f of FAILS) console.error(`  FAILED: ${f}`);
  process.exit(1);
}
