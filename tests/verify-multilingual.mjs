#!/usr/bin/env node
/**
 * Multilingual regression gate (W3) — asserts the REAL CLI scan of
 * tests/multilingual/app matches the committed manifest exactly:
 *   1. every expected detection (rule, file, exact absolute line, severity floor),
 *   2. the exact total finding count (no unexpected extras),
 *   3. zero findings above LOW on the safe counterpart files,
 *   4. zero findings AT ALL on the documented out-of-scope files
 *      (the boundary is locked silent),
 *   5. the masking contract — no raw secret literal anywhere in the report,
 *   6. byte-identical determinism across a second scan,
 *   7. the performance budget.
 * Run by the `multilingual:verify` npm script (setup → CLI scan → this gate).
 */
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url)); // tests/
const ML = join(here, "multilingual");
const ROOT = join(here, "..");
const CLI = join(ROOT, "dist", "cli.js");
const manifest = JSON.parse(readFileSync(join(ML, "manifest.json"), "utf8"));

let PASS = 0;
const FAILS = [];
const check = (name, cond, extra = "") => {
  if (cond) PASS++;
  else { FAILS.push(name); console.log(`  FAILED: ${name}${extra ? " — " + extra : ""}`); }
};

const outPath = join(ML, "findings.json");
const result = JSON.parse(readFileSync(outPath, "utf8"));
const findings = result.findings ?? [];

const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// 1. every expected detection, exact rule + file + line + severity floor
for (const exp of manifest.expected_detections) {
  const hit = findings.find((f) => f.id === exp.id && f.file === exp.file && f.line === exp.line);
  check(`expected ${exp.id} @ ${exp.file}:${exp.line}`,
    Boolean(hit) && RANK[hit.severity] <= RANK[exp.severity_floor],
    hit ? `got severity ${hit.severity}` : "MISSING");
}

// 2. exact total count — no unexpected extras
check(`total finding count is exactly ${manifest.expected_count}`,
  findings.length === manifest.expected_count,
  `got ${findings.length}: ${findings.map((f) => `${f.id}@${f.file}:${f.line}`).join(", ")}`);

// 3. safe files: zero findings above LOW
for (const sf of manifest.safe_files_zero_above_low) {
  const bad = findings.filter((f) => f.file === sf && RANK[f.severity] < RANK.low);
  check(`safe file stays clean: ${sf}`, bad.length === 0,
    bad.map((f) => `${f.id}/${f.severity}:${f.line}`).join(", "));
}

// 4. out-of-scope files: zero findings at any severity (locked silent)
for (const oos of manifest.out_of_scope_locked_silent) {
  const any = findings.filter((f) => f.file === oos.file);
  check(`out-of-scope boundary locked silent: ${oos.file}`, any.length === 0,
    any.map((f) => `${f.id}/${f.severity}:${f.line}`).join(", "));
}

// 5. masking contract — the raw secret literals must appear NOWHERE in the report text
const SECRET_LITERALS = [
  "Pr0d-Secret-2026!xYz9",
  "x7Kp9mQw2vB4nZ8hJ3fL6dRs5tYgUe1C",
  "sk_live_51Dem0KeyN0tRealZ9xQ2vB",
  "AKIA4YKJ7RQ3XMP2LE9T",
  "postgres://ci_user:Sk9-Live-Pass-77@db.prod.internal:5432/appdb",
  "sk-proj-4x9K2mL8pQ7vN3bR6tY1wE5uI0oS8aD3fG7hJ2kL4mN9",
];
const raw = readFileSync(outPath, "utf8");
for (const lit of SECRET_LITERALS) {
  check(`masking: raw secret never written to the report (${lit.slice(0, 4)}…)`, !raw.includes(lit));
}

// 6. determinism — a second CLI scan is byte-identical
const tmpDir = mkdtempSync(join(tmpdir(), "anubis-ml-"));
const second = join(tmpDir, "second.json");
const t0 = Date.now();
execFileSync("node", [CLI, "scan", join(ML, "app"), "--format", "json", "--output", second], { stdio: "pipe" });
const elapsedMs = Date.now() - t0;
check("determinism: two CLI scans are byte-identical",
  readFileSync(second, "utf8") === readFileSync(outPath, "utf8"));
rmSync(tmpDir, { recursive: true, force: true });

// 7. performance budget (fixture scan; generous local-machine bound)
check(`scan wall time within budget (${elapsedMs}ms < 15000ms)`, elapsedMs < 15000);

console.log(`multilingual fixture: ${findings.length} findings · ${elapsedMs}ms scan`);
console.error(`\nMULTILINGUAL VERIFICATION: ${PASS} passed, ${FAILS.length} failed`);
if (FAILS.length) {
  for (const f of FAILS) console.error(`  FAILED: ${f}`);
  process.exit(1);
}
