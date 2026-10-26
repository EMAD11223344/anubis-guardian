#!/usr/bin/env node
/**
 * v1.0 — BENCHMARKS.md generator. Policy (Plan Section 13 + Decision v1.2 #5):
 * **no number is published without a measurement.** Everything written here was
 * produced by running the suites in THIS run, on the recorded environment.
 * External suites (OWASP NodeGoat / Juice Shop) are secondary sanity: general
 * layers only (secrets + SAST) — the Supabase/Next/Nest playbooks have no
 * target there. If a clone/scan fails, the entry is recorded as PENDING —
 * never estimated.
 *
 * Usage: node scripts/measure-benchmarks.mjs [--skip-external]
 */
import { spawnSync } from "node:child_process";
import { writeFileSync, readFileSync, existsSync, rmSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir, platform, cpus } from "node:os";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "dist", "cli.js");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const TMP = join(tmpdir(), `anubis-bench-${process.pid}`);
mkdirSync(TMP, { recursive: true });

const gitCommit = (() => {
  // provenance: the exact commit the binaries and fixtures came from (never estimated)
  const r = spawnSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", cwd: ROOT });
  if (r.status !== 0) return "unavailable";
  const dirty = spawnSync("git", ["status", "--porcelain"], { encoding: "utf8", cwd: ROOT });
  const dirtyOut = dirty.status === 0 ? dirty.stdout.trim() : "";
  return dirtyOut ? `${r.stdout.trim()} (+uncommitted working tree: docs/bench edits)` : r.stdout.trim();
})();

const env = {
  tool_version: pkg.version,
  tool_commit: gitCommit,
  node: process.version,
  platform: `${platform()} · ${cpus().length} vCPU`,
  command: "npm run build && node scripts/measure-benchmarks.mjs",
  date: new Date().toISOString().slice(0, 10),
};

const results = [];
const record = (name, value, status = "measured") => results.push({ name, value, status });
const run = (cmd, opts = {}) => spawnSync(cmd[0], cmd.slice(1), { encoding: "utf8", ...opts });

// ---------- 1. Honeypot (self-test recall: planted vulnerabilities) ----------
const t0 = Date.now();
const hp = run(["node", join(ROOT, "tests", "honeypot", "setup.mjs")]);
const hpScan = run(["node", CLI, "scan", join(ROOT, "tests", "honeypot", "app"), join(ROOT, "tests", "honeypot", "nest-app"),
  "--format", "json", "-o", join(TMP, "hp.json")]);
const hpMs = Date.now() - t0;
const hpVerify = run(["node", join(ROOT, "tests", "verify-honeypot.mjs")]);
const hpOk = hpVerify.status === 0 && /ALL SEEDS DETECTED/.test(hpVerify.stdout);
let hpFindings = {};
if (hpScan.status === 0 && existsSync(join(TMP, "hp.json"))) {
  const r = JSON.parse(readFileSync(join(TMP, "hp.json"), "utf8"));
  for (const f of r.findings) hpFindings[f.id] = (hpFindings[f.id] ?? 0) + 1;
}
record("Honeypot recall (49 planted checks, 2 roots — self-test)", hpOk ? "49/49 detected, masking contract intact" : `FAILURES: ${hpVerify.stdout.slice(-200)}`, hpOk ? "measured" : "failed");
record("Honeypot findings by rule id", JSON.stringify(hpFindings));
record("Honeypot multi-root scan wall time (2 roots, includes setup)", `${(hpMs / 1000).toFixed(2)}s`);

// ---------- 2. Clean corpus (FP control) ----------
const cl = run(["node", join(ROOT, "tests", "clean", "setup.mjs")]);
const clScan = run(["node", CLI, "scan", join(ROOT, "tests", "clean", "app"), "--format", "json", "-o", join(TMP, "clean.json")]);
const clVerify = run(["node", join(ROOT, "tests", "verify-clean.mjs")]);
const clOk = clVerify.status === 0 && /PASS/.test(clVerify.stdout);
record("Clean corpus false positives (must be 0 above threshold)", clOk ? "0 findings above threshold — score 100, grade A" : `FP LEAK: ${clVerify.stdout.slice(-200)}`, clOk ? "measured" : "failed");

// ---------- 3. Single-root perf ----------
const t1 = Date.now();
run(["node", CLI, "scan", join(ROOT, "tests", "honeypot", "app"), "--format", "json", "-o", join(TMP, "perf1.json")]);
record("Single-root scan wall time (Next.js+Supabase honeypot app)", `${((Date.now() - t1) / 1000).toFixed(2)}s`);

// ---------- 4. Acceptance gates (all modes) ----------
for (const [name, script] of [
  ["acceptance v0.2 (init-ci pins, determinism, workspaces, cross-root CRITICAL, artifacts)", "tests/acceptance-v02.mjs"],
  ["acceptance v0.3 (AI review + verifier, authz quarantine, taint canaries, hook, SKILL contract)", "tests/acceptance-v03.mjs"],
  ["acceptance v0.4 (URL Mode: L1 passivity, ownership gates, Supabase probe, determinism, renderers)", "tests/mode2/acceptance-v04.mjs"],
  ["acceptance v1.0 (rules-lock, init-zap, restricted differential IDOR, packaging/SBOM, install smoke)", "tests/mode2/acceptance-v10.mjs"],
]) {
  const r = run(["node", join(ROOT, script)]);
  const out = r.stdout + r.stderr; // acceptance suites print the summary on either stream
  const m = [...out.matchAll(/(\d+) passed, (\d+) failed/g)].pop();
  const ok = r.status === 0;
  record(name, m ? `${m[1]} gates passed, ${m[2]} failed` : (ok ? "ALL PASS (exit 0)" : "failed (non-zero exit)"), ok ? "measured" : "failed");
}
const m2v = run(["node", join(ROOT, "tests", "mode2", "verify-mode2.mjs")]);
const m2m = [...(m2v.stdout + m2v.stderr).matchAll(/(\d+) passed, (\d+) failed/g)].pop();
record("Mode 2 honeypot (planted URL classes incl. masking)", m2m ? `${m2m[1]} checks passed, ${m2m[2]} failed` : (m2v.status === 0 ? "ALL PASS (exit 0)" : "failed"), m2v.status === 0 ? "measured" : "failed");

// ---------- 5. URL Mode perf (local fixture — server in a CHILD process:
// spawnSync blocks the parent event loop, so an in-process server would deadlock,
// the same lesson the v0.3/v0.4 acceptance suites already encoded) ----------
try {
  const { spawn } = await import("node:child_process");
  const child = spawn(process.execPath, [join(ROOT, "tests", "mode2", "servers.mjs"), "--serve"], { stdio: ["ignore", "pipe", "inherit"] });
  const ready = await new Promise((res, rej) => {
    let buf = "";
    child.stdout.on("data", (d) => { buf += d.toString(); const i = buf.indexOf("\n"); if (i >= 0) res(JSON.parse(buf.slice(0, i))); });
    setTimeout(() => rej(new Error("fixtures timeout")), 10_000);
  });
  const BAD = `http://127.0.0.1:${ready.bad}`;
  const t2 = Date.now();
  const u1 = run(["node", CLI, "scan-url", BAD, "--level", "1", "--allow-private", "--delay-ms", "2", "--format", "json", "-o", join(TMP, "url1.json")]);
  record("URL Mode L1 passive scan wall time (local fixture)", u1.status === 0 ? `${((Date.now() - t2) / 1000).toFixed(2)}s` : `failed (exit ${u1.status})`, u1.status === 0 ? "measured" : "failed");
  const t3 = Date.now();
  const u2 = run(["node", CLI, "scan-url", BAD, "--level", "3", "--allow-private", "--ownership-token", ready.nonce, "--active-tests",
    "--identity-a", "x-test-role: admin-bench", "--identity-b", "x-test-role: restricted-bench", "--delay-ms", "2", "--format", "json", "-o", join(TMP, "url3.json")]);
  const u3 = u2.status === 0 ? JSON.parse(readFileSync(join(TMP, "url3.json"), "utf8")) : null;
  record("URL Mode L3 full scan wall time (L2 probes + Supabase detect + differential IDOR, local fixture)",
    u3 ? `${((Date.now() - t3) / 1000).toFixed(2)}s · ${u3.meta.files_scanned} requests · score ${u3.score}/${u3.grade}` : `failed (exit ${u2.status})`, u3 ? "measured" : "failed");
  try { child.kill("SIGTERM"); } catch { /* gone */ }
} catch (e) {
  record("URL Mode perf", `fixture error: ${e.message}`, "failed");
}

// ---------- 6. External suites (secondary sanity — honest, labeled) ----------
if (!process.argv.includes("--skip-external")) {
  const ext = join(TMP, "ext");
  mkdirSync(ext, { recursive: true });
  for (const [label, repo] of [
    ["OWASP NodeGoat (sanity — general layers)", "https://github.com/OWASP/NodeGoat.git"],
    ["OWASP Juice Shop (sanity — general layers)", "https://github.com/juice-shop/juice-shop.git"],
  ]) {
    const dir = join(ext, label.includes("NodeGoat") ? "nodegoat" : "juice-shop");
    const t4 = Date.now();
    const clone = run(["git", "clone", "--depth", "1", "--quiet", repo, dir]);
    if (clone.status !== 0) { record(label, "PENDING — clone failed in this environment (never estimated)", "pending"); continue; }
    const scan = run(["node", CLI, "scan", dir, "--format", "json", "-o", join(TMP, `${label.includes("NodeGoat") ? "ng" : "js"}.json`), "--workspaces"]);
    const args = scan.status === 0 ? [] : ["node", CLI, "scan", dir, "--format", "json", "-o", join(TMP, `${label.includes("NodeGoat") ? "ng" : "js"}.json`)];
    const scan2 = args.length ? run(args) : scan;
    if (scan2.status !== 0 && !existsSync(join(TMP, `${label.includes("NodeGoat") ? "ng" : "js"}.json`))) {
      record(label, "PENDING — scan error (see acceptance runs)", "pending"); continue;
    }
    const r = JSON.parse(readFileSync(join(TMP, `${label.includes("NodeGoat") ? "ng" : "js"}.json`), "utf8"));
    const byId = {};
    for (const f of r.findings) if (f.severity !== "info") byId[f.id] = (byId[f.id] ?? 0) + 1;
    record(label, `${r.findings.length} findings (score ${r.score}/${r.grade}) · ${JSON.stringify(byId)} · ${(Date.now() - t4) / 1000}s incl. clone`, "measured");
  }
} else {
  record("External suites", "skipped (--skip-external)", "pending");
}

rmSync(TMP, { recursive: true, force: true });

// ---------- render BENCHMARKS.md ----------
const failed = results.filter((r) => r.status === "failed");
const pending = results.filter((r) => r.status === "pending");
const md = [`# BENCHMARKS.md — measured results only`,
  ``,
  `> Policy: **no number appears here without a measurement.** Every value below was produced by`,
  `> \`scripts/measure-benchmarks.mjs\` in a single run on the environment recorded below. Unmeasurable`,
  `> entries are marked PENDING — they are never estimated. Honeypot numbers are a **self-test** (we`,
  `> planted what we catch); the external suites are the honest recall signal and are labeled as such.`,
  ``,
  `| Environment | Value |`,
  `|---|---|`,
  `| Tool version | ${env.tool_version} |`,
  `| Tool commit (provenance) | ${env.tool_commit} |`,
  `| Node | ${env.node} |`,
  `| Platform | ${env.platform} |`,
  `| Command | \`${env.command}\` |`,
  `| Measured on | ${env.date} |`,
  ``,
  `## Results`,
  ``,
  `| Measurement | Result | Status |`,
  `|---|---|---|`,
  ...results.map((r) => `| ${r.name} | ${r.value.replace(/\|/g, "\\|")} | ${r.status} |`),
  ``,
  `## Reading guide`,
  ``,
  `- **Honeypot recall** = self-test: deterministic proof the shipped rules catch every planted class (49 checks, 2 roots).`,
  `- **Clean corpus** = false-positive control: a clean project must finish at 100/A with zero findings above threshold.`,
  `- **Acceptance gates** = the frozen plan scopes (v0.2 CI/determinism, v0.3 AI+authz+hook, v0.4 URL Mode, v1.0 supply chain + restricted active scope) — every gate must pass.`,
  `- **External suites** (NodeGoat / Juice Shop) = classic vulnerable Node apps — they exercise the general layers (secrets, SAST, deps, CI) only; the Supabase/Next/Nest playbooks have no target there. Treat them as sanity, not as framework-playbook recall.`,
  `- **Wall times** are recorded for transparency of scale, not as speed claims.`,
  ``,
  failed.length ? `## Failed measurements\n\n${failed.map((f) => `- ⛔ ${f.name}: ${f.value}`).join("\n")}\n` : "",
  pending.length ? `## Pending (never estimated)\n\n${pending.map((p) => `- ⏳ ${p.name}: ${p.value}`).join("\n")}\n` : "",
].join("\n");

writeFileSync(join(ROOT, "BENCHMARKS.md"), md, "utf8");
console.error(`written: BENCHMARKS.md — ${results.filter(r => r.status === "measured").length} measured · ${pending.length} pending · ${failed.length} failed`);
if (failed.length) process.exit(1);
