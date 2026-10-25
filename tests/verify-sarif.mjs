#!/usr/bin/env node
/**
 * SARIF verification (Plan v1.3 decision — SARIF lands in the Security tab):
 * schema sanity, level mapping, masking contract, deterministic shape.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const file = process.argv[2] ?? "/tmp/anubis-test.sarif";
let failures = 0;
const check = (ok, label) => {
  if (ok) console.log(`PASS  ${label}`);
  else { console.error(`FAIL  ${label}`); failures++; }
};

const sarif = JSON.parse(readFileSync(file, "utf8"));
check(sarif.version === "2.1.0", "SARIF version is 2.1.0");
check(sarif.runs?.length === 1, "single run");
const run = sarif.runs[0];
check(run.tool?.driver?.name === "anubis-guardian", "tool.driver.name");
check(Array.isArray(run.tool.driver.rules) && run.tool.driver.rules.length > 0, "rules registry present");
check(Array.isArray(run.results) && run.results.length > 0, "results present");

const levels = new Set(run.results.map((r) => r.level));
check([...levels].every((l) => ["error", "warning", "note"].includes(l)), `levels valid (${[...levels].join(",")})`);

const errCount = run.results.filter((r) => r.level === "error").length;
check(errCount > 0, `high/critical findings map to SARIF level="error" (${errCount} SARIF results — findings, not verification errors)`);

check(run.results.every((r) => r.locations?.[0]?.physicalLocation?.artifactLocation?.uri), "every result has a location");
check(run.results.every((r) => r.partialFingerprints?.anubisFingerprint), "every result carries the anubis fingerprint");

// masking: no JWT-looking full token may appear
const raw = JSON.stringify(sarif);
check(!/eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/.test(raw), "no full JWT-shaped values in SARIF");

// no timestamps (determinism)
check(!/"(utcTimestamp|endTimeUtc|startTimeUtc)"/.test(raw), "no timestamps (deterministic)");

if (failures) { console.error(`\nSARIF VERIFICATION: ${failures} failure(s)`); process.exit(1); }
console.log("\nSARIF VERIFICATION: PASS — Security-tab ready");
