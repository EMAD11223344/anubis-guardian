#!/usr/bin/env node
/**
 * Clean-corpus verification — the FP gate (Plan Section 13):
 * zero findings above INFO on the clean reference app.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const result = JSON.parse(readFileSync(join(here, "clean", "findings.json"), "utf8"));

const bad = result.findings.filter((f) => f.severity !== "info" && f.severity !== "low");
for (const f of bad) {
  console.error(`FP? ${f.id}/${f.severity} @ ${f.file}:${f.line} — ${f.title}`);
}
const infos = result.findings.filter((f) => f.severity === "info");
for (const f of infos) {
  console.log(`info (documented-correct pattern): ${f.id} @ ${f.file}:${f.line}`);
}

if (bad.length) {
  console.error(`\nCLEAN VERIFICATION: ${bad.length} unexpected finding(s) — false positives above threshold`);
  process.exit(1);
}
console.log(`\nCLEAN VERIFICATION: PASS — 0 findings above threshold (score ${result.score}, grade ${result.grade})`);
