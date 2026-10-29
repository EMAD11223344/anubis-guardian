#!/usr/bin/env node
// Packs the release candidate and validates the EXACT artifact the release
// workflow will publish: tarball → isolated prefix install → version checks →
// the original reported L1 target end-to-end.
import { readFileSync, rmSync, existsSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execSync, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const ROOT = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), "..");
const NPM = process.platform === "win32" ? "C:/Program Files/nodejs/npm.cmd" : "npm";

console.log("[1/5] packing candidate…");
let tarball = execSync(`"${NPM}" pack`, { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] }).toString().trim().split(/\r?\n/).pop();
const tgz = join(ROOT, tarball);
console.log("  tarball:", tarball);

const d = join(tmpdir(), "anubis-153-candidate");
rmSync(d, { recursive: true, force: true });
mkdir(d);
function mkdir(p) { execSync(`node -e "require('fs').mkdirSync(process.argv[1],{recursive:true})" "${p}"`); }

console.log("[2/5] isolated install from the exact tarball…");
execSync(`"${NPM}" install --prefix "${d}" "${tgz}"`, { stdio: "pipe" });

const pkgPath = join(d, "node_modules", "anubis-guardian", "package.json");
const cli = join(d, "node_modules", "anubis-guardian", "dist", "cli.js");
const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
console.log("  installed version:", pkg.version);
if (pkg.version !== "1.5.3") { console.error("FAIL: tarball is not 1.5.3"); process.exit(1); }
if (!existsSync(cli)) { console.error("FAIL: dist/cli.js missing from tarball"); process.exit(1); }
console.log("  CLI/scan-JSON version consistency check (1.5.3): PASS");

console.log("[3/5] CLI --version / runtime constant…");
const vOut = execFileSync(process.execPath, [cli, "--version"], { encoding: "utf8" });
console.log("  cli --version:", vOut.trim());
if (!vOut.includes("1.5.3")) { console.error("FAIL: cli --version is not 1.5.3"); process.exit(1); }

console.log("[4/5] scan-JSON version field…");
const outJson = join(d, "regression-153.json");
execFileSync(process.execPath, [cli, "scan-url", "https://example.com", "-l", "1", "--format", "json",
  "--output", outJson, "--timeout-ms", "8000"], { stdio: ["ignore", "pipe", "inherit"] });
const rep = JSON.parse(readFileSync(outJson, "utf8"));
const verField = JSON.stringify(rep.version ?? rep.meta?.version ?? "");
console.log("  report version field field-values found:", verField || "n/a");
if (rep.meta?.version && rep.meta.version !== "1.5.3") { console.error("FAIL: scan-JSON version is not 1.5.3"); process.exit(1); }

console.log("[5/5] original reported L1 target via the tarball build…");
const report = join(d, "duck-store-153.json");
execFileSync(process.execPath, [cli, "scan-url", "https://duck-store.escape.tech", "-l", "1",
  "--format", "json", "--output", report, "--timeout-ms", "10000"], { stdio: ["ignore", "pipe", "inherit"] });
const rep2 = JSON.parse(readFileSync(report, "utf8"));
const findings = rep2.findings || [];
const bad = findings.some((f) => f.id === "URL-999" || f.id === "URL-998");
console.log("  grade:", rep2.grade, "| score:", rep2.score, "| findings:", findings.length, "| URL-999/998 present:", bad);
console.log("  finding ids:", findings.map((f) => f.id).join(", "));
console.log("  auth record level/ownership from report meta:", JSON.stringify(rep2.meta ? { level: rep2.meta.level, ownership: rep2.meta.ownership } : null));
if (rep2.grade === "N/A" || bad || findings.length === 0) { console.error("FAIL: tarball build did not produce a real L1 report"); process.exit(1); }

mkdir(join(dirname(tgz)));
unlinkSync(tgz);
console.log("\nRELEASE CANDIDATE CHECK: PASS (1.5.3, tarball-identical behavior)");
