#!/usr/bin/env node
/**
 * v1.0 acceptance — Public Release gates:
 *   K  rules registry signing (rules-lock): pin → verify → tamper-refuse → bypass quarantine
 *   L  init-zap: passive baseline default; --active gated by verified ownership on public domains
 *   M  restricted differential IDOR (--active-tests): L3-scope gate, identities required,
 *      verified-only, GET-only, planted suspect fires / held boundary stays quiet,
 *      identity values never stored, cap, from-capture byte-identical
 *   N  packaging & supply chain: npm pack contents, install→first-report smoke,
 *      SBOM (CycloneDX), release workflow (provenance + pinned SHAs)
 *   P  release docs present (methodology / contribution guide / site / benchmarks tooling)
 */
import { spawn, spawnSync } from "node:child_process";
import { writeFileSync, readFileSync, mkdirSync, rmSync, existsSync, mkdirSync as mkd, readdirSync, copyFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const PKG_VERSION = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;
const CLI = join(ROOT, "dist", "cli.js");
const TMP = join(HERE, ".tmp-acc10");
rmSync(TMP, { recursive: true, force: true });
mkdirSync(TMP, { recursive: true });

let PASS = 0;
const FAILS = [];
function check(name, cond, extra = "") {
  if (cond) { PASS++; console.log(`PASS  ${name}`); }
  else { FAILS.push(name); console.error(`FAIL  ${name}${extra ? ` — ${extra}` : ""}`); }
}
function run(args, opts = {}) {
  const r = spawnSync("node", [CLI, ...args], { encoding: "utf8", ...opts });
  return { code: r.status, out: r.stdout ?? "", err: r.stderr ?? "" };
}

// ---- fixture servers in a child process ----
const child = spawn(process.execPath, [join(HERE, "servers.mjs"), "--serve"], { stdio: ["ignore", "pipe", "inherit"] });
const ready = await new Promise((res, rej) => {
  let buf = "";
  child.stdout.on("data", (d) => { buf += d.toString(); const i = buf.indexOf("\n"); if (i >= 0) res(JSON.parse(buf.slice(0, i))); });
  setTimeout(() => rej(new Error("fixtures timeout")), 10_000);
});
const BAD = `http://127.0.0.1:${ready.bad}`;
const NONCE = ready.nonce;
const cleanup = () => { try { child.kill("SIGTERM"); } catch { /* gone */ } };
process.on("exit", cleanup);
process.on("SIGINT", cleanup);
const requestLog = async () => {
  // Undici pools keep-alive sockets; after >5s idle (Node server keepAliveTimeout)
  // the fixture may have closed the pooled socket, and the stale write can crash
  // fetch with ECONNRESET. Retry on a fresh connection — test-process resilience only.
  let lastErr;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return (await (await fetch(`${BAD}/__requestlog`)).json()).requests;
    } catch (e) {
      lastErr = e;
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  throw lastErr;
};

// org-rule fixture (shared by K gates)
const RULES = join(TMP, "org-rules");
mkd(RULES, { recursive: true });
const PROJ = join(TMP, "proj");
mkd(join(PROJ, "src"), { recursive: true });
writeFileSync(join(RULES, "no-debug.json"), JSON.stringify({
  id: "TESTORG-1", severity: "low", title: "Test org rule: console.log",
  owasp: "A05", files: ["*.js"], regex: "console\\.log\\(",
  fix: "Remove debug logging.", clean_cases: "files without console.log",
}, null, 2));
writeFileSync(join(PROJ, "src", "app.js"), "console.log('debug');\nconst x = 1;\n");

try {
  // ================= K — rules registry signing =================
  const k1 = run(["rules-lock", RULES]);
  const lockPath = join(RULES, "rules-lock.json");
  check("K1: rules-lock pins the directory (exit 0 + lock file written)", k1.code === 0 && existsSync(lockPath), `exit=${k1.code}`);
  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  check("K1b: lock is sha256 + one entry per rule file (deterministic shape)",
    lock.algorithm === "sha256" && Array.isArray(lock.files) && lock.files.length === 1 && /^[0-9a-f]{64}$/.test(lock.files[0].sha256));

  const k2 = run(["scan", PROJ, "--rules-dir", RULES, "--format", "json", "-o", join(TMP, "k2.json")]);
  const k2r = k2.code === 0 ? JSON.parse(readFileSync(join(TMP, "k2.json"), "utf8")) : null;
  check("K2: untouched lock → scan exits 0 with meta.rules_lock=verified", k2.code === 0 && k2r?.meta?.rules_lock === "verified", `exit=${k2.code} lock=${k2r?.meta?.rules_lock}`);
  check("K2b: verified lock → community_rules flag NOT set", k2r?.meta?.community_rules === undefined);

  // tamper: modify the rule file after pinning
  writeFileSync(join(RULES, "no-debug.json"), JSON.stringify({
    id: "TESTORG-1", severity: "critical", title: "TAMPERED — severity escalated after pinning",
    owasp: "A05", files: ["*.js"], regex: "const\\s+", fix: "malicious rule", clean_cases: "none",
  }, null, 2));
  const k3 = run(["scan", PROJ, "--rules-dir", RULES, "--format", "json", "-o", join(TMP, "k3.json")]);
  check("K3: tampered rules → exit 2 (supply-chain refusal BEFORE scanning)", k3.code === 2 && /supply-chain guard/.test(k3.err), `exit=${k3.code}`);
  check("K3b: refusal names the modified file", /modified rule file/.test(k3.err));
  check("K3c: refusal did NOT produce a report", !existsSync(join(TMP, "k3.json")));

  const k4 = run(["scan", PROJ, "--rules-dir", RULES, "--allow-community-rules", "--format", "json", "-o", join(TMP, "k4.json")]);
  const k4r = k4.code === 0 ? JSON.parse(readFileSync(join(TMP, "k4.json"), "utf8")) : null;
  check("K4: --allow-community-rules bypasses (exit 0) with meta.rules_lock=bypassed", k4.code === 0 && k4r?.meta?.rules_lock === "bypassed", `exit=${k4.code}`);
  check("K4b: bypassed run is quarantined-labeled (meta.community_rules=true)", k4r?.meta?.community_rules === true);

  // unpinned (no lock at all) — v0.2 behavior preserved with warning + quarantine label
  const RULES2 = join(TMP, "org-rules-nolock");
  mkd(RULES2, { recursive: true });
  writeFileSync(join(RULES2, "no-debug.json"), JSON.stringify({
    id: "TESTORG-1", severity: "low", title: "Test org rule: console.log",
    owasp: "A05", files: ["*.js"], regex: "console\\.log\\(",
    fix: "Remove debug logging.", clean_cases: "files without console.log",
  }, null, 2));
  const k5 = run(["scan", PROJ, "--rules-dir", RULES2, "--format", "json", "-o", join(TMP, "k5.json")]);
  const k5r = k5.code === 0 ? JSON.parse(readFileSync(join(TMP, "k5.json"), "utf8")) : null;
  check("K5: no lock → scan still works (v0.2 compat) with meta.rules_lock=off", k5.code === 0 && k5r?.meta?.rules_lock === "off", `exit=${k5.code}`);
  check("K5b: no-lock run warned + quarantined-labeled", /no rules-lock\.json/.test(k5.err) && k5r?.meta?.community_rules === true);

  const k6 = run(["rules-lock", join(TMP, "does-not-exist")]);
  check("K6: rules-lock on missing dir → exit 2", k6.code === 2);

  // ================= L — init-zap (the L3 decision: delegate, don't embed) =================
  const zapPassive = join(TMP, "zap-passive.yaml");
  const l1 = run(["init-zap", BAD, "--out", zapPassive]);
  check("L1: init-zap passive baseline for local target → exit 0 + file", l1.code === 0 && existsSync(zapPassive), `exit=${l1.code}`);
  const zapPassiveYml = readFileSync(zapPassive, "utf8");
  check("L1b: passive config has active_scan disabled + safety rails",
    /active_scan:/.test(zapPassiveYml) && /enabled: false/.test(zapPassiveYml) && /rate_limit_ms: 250/.test(zapPassiveYml) && /max_requests: 150/.test(zapPassiveYml));
  check("L1c: config carries the review + no-DAST-engine notice", /REVIEW BEFORE RUNNING/.test(zapPassiveYml) && /embeds NO DAST engine/.test(zapPassiveYml));

  const l2 = run(["init-zap", "http://example.invalid", "--active", "--out", join(TMP, "zap-a.yaml")]);
  check("L2: --active on a PUBLIC domain without verified ownership → exit 2", l2.code === 2, `exit=${l2.code}`);
  check("L2b: refusal is the ownership gate (nonce instructions present)", /anubis-guardian-challenge=/.test(l2.err));
  const l3 = run(["init-zap", "http://example.invalid", "--active", "--ownership-token", "wrong-nonce", "--out", join(TMP, "zap-b.yaml")]);
  check("L3: --active + WRONG nonce on public domain → exit 2", l3.code === 2);
  const zapActive = join(TMP, "zap-active.yaml");
  const l4 = run(["init-zap", BAD, "--active", "--out", zapActive]);
  const zapActiveYml = existsSync(zapActive) ? readFileSync(zapActive, "utf8") : "";
  check("L4: --active on LOCAL staging → exit 0 + active_scan enabled (owner-run delegation)", l4.code === 0 && /enabled: true/.test(zapActiveYml), `exit=${l4.code}`);
  const l5 = run(["init-zap", BAD, "--out", zapPassive]);
  check("L5: existing config left untouched (idempotent)", l5.code === 0 && /exists/.test(l5.err));

  // ================= M — restricted differential IDOR (--active-tests) =================
  const IDENT_A = "x-test-role: admin-secret-777";
  const IDENT_B = "x-test-role: restricted-secret-888";

  const m1 = run(["scan-url", BAD, "--level", "2", "--active-tests", "--identity-a", IDENT_A, "--identity-b", IDENT_B, "--delay-ms", "5"]);
  check("M1: --active-tests at L2 → exit 2 (active scope is L3 by design)", m1.code === 2 && /L3 scope/.test(m1.err), `exit=${m1.code}`);
  const m2 = run(["scan-url", BAD, "--level", "3", "--ownership-token", NONCE, "--active-tests", "--delay-ms", "5"]);
  check("M2: --active-tests without BOTH identities → exit 2", m2.code === 2 && /BOTH testing identities/.test(m2.err), `exit=${m2.code}`);
  const m3 = run(["scan-url", BAD, "--level", "3", "--i-own-this-domain", "--active-tests", "--identity-a", IDENT_A, "--identity-b", IDENT_B, "--delay-ms", "5"]);
  check("M3: --active-tests with self-attestation (even local) → exit 2 (verified-only)", m3.code === 2, `exit=${m3.code}`);

  const logBefore = (await requestLog()).length;
  const cap = join(TMP, "idor-capture.json");
  const m4 = run(["scan-url", BAD, "--level", "3", "--ownership-token", NONCE, "--active-tests", "--allow-private",
    "--identity-a", IDENT_A, "--identity-b", IDENT_B,
    "--idor-path", "/api/admin-panel", "--idor-path", "/api/orders", "--idor-path", "/api/stats",
    "--delay-ms", "5", "--capture", cap, "--format", "json", "-o", join(TMP, "m4.json")]);
  check("M4: verified ownership + both identities → exit 0", m4.code === 0, `exit=${m4.code} ${m4.err.slice(0, 200)}`);
  const m4r = m4.code === 0 ? JSON.parse(readFileSync(join(TMP, "m4.json"), "utf8")) : null;

  check("M5: planted differential access fires URL-061 HIGH + needs_confirmation on /api/admin-panel",
    !!m4r && m4r.findings.some((f) => f.id === "URL-061" && f.severity === "high" && f.needs_confirmation === true && f.file.endsWith("/api/admin-panel")),
    JSON.stringify(m4r?.findings.filter((f) => f.id === "URL-061") ?? []));
  check("M6: held boundaries stay quiet — no URL-061 on /api/orders or /api/stats",
    !!m4r && !m4r.findings.some((f) => f.id === "URL-061" && (f.file.endsWith("/api/orders") || f.file.endsWith("/api/stats"))));
  check("M7: URL-909 summary present + meta.active_tests + levels_run carries L3-active-tests",
    !!m4r && m4r.findings.some((f) => f.id === "URL-909") && m4r.meta.active_tests === true && m4r.url_meta.levels_run.includes("L3-active-tests"));

  const afterLog = await requestLog();
  const newReqs = afterLog.slice(logBefore);
  check("M8: active phase was GET-only (no POST/PUT/DELETE/PATCH ever sent)",
    !afterLog.some((r) => ["POST", "PUT", "DELETE", "PATCH"].includes(r.method)),
    JSON.stringify(afterLog.filter((r) => ["POST", "PUT", "DELETE", "PATCH"].includes(r.method))));
  const apiReqs = newReqs.filter((r) => ["/api/admin-panel", "/api/orders", "/api/stats"].includes(r.url));
  check("M9: exactly 3 endpoints × 2 identities = 6 GETs on the idor endpoints (discovered JSON candidates add none)",
    apiReqs.length === 6 && apiReqs.every((r) => r.method === "GET"), `api=${apiReqs.length} → ${apiReqs.map((r) => r.url).join(", ")}`);

  const capture = JSON.parse(readFileSync(cap, "utf8"));
  check("M10: capture carries the idor record with header NAMES only",
    !!capture.idor && JSON.stringify(capture.idor.identities) === JSON.stringify(["x-test-role"]) && capture.idor.requests.length === 6);
  check("M11: identity VALUES never stored (capture + findings free of the secrets)",
    !JSON.stringify(capture).includes("admin-secret-777") && !JSON.stringify(capture).includes("restricted-secret-888")
    && !JSON.stringify(m4r).includes("admin-secret-777") && !JSON.stringify(m4r).includes("restricted-secret-888"));

  // cap
  const paths30 = [];
  for (let i = 0; i < 30; i++) paths30.push("--idor-path", `/api/p${i}`);
  const m12 = run(["scan-url", BAD, "--level", "3", "--ownership-token", NONCE, "--active-tests", "--allow-private",
    "--identity-a", IDENT_A, "--identity-b", IDENT_B, ...paths30, "--delay-ms", "2", "--format", "json", "-o", join(TMP, "m12.json")]);
  const m12r = m12.code === 0 ? JSON.parse(readFileSync(join(TMP, "m12.json"), "utf8")) : null;
  check("M12: hard cap ≤24 endpoints enforced", m12.code === 0 && !!m12r, `exit=${m12.code}`);

  // from-capture determinism + zero network
  const logPreReplay = (await requestLog()).length;
  const e1 = run(["scan-url", BAD, "--from-capture", cap, "--format", "json", "-o", join(TMP, "replay1.json")]);
  const e2 = run(["scan-url", BAD, "--from-capture", cap, "--format", "json", "-o", join(TMP, "replay2.json")]);
  const logPostReplay = (await requestLog()).length;
  check("M13: from-capture replays byte-identical findings (capture-then-analyze holds for active tests)",
    e1.code === 0 && e2.code === 0 && readFileSync(join(TMP, "replay1.json"), "utf8") === readFileSync(join(TMP, "replay2.json"), "utf8"));
  check("M14: from-capture made ZERO network requests", logPreReplay === logPostReplay, `${logPreReplay} → ${logPostReplay}`);

  // ================= N — packaging & supply chain =================
  const packDir = join(TMP, "pack");
  mkd(packDir, { recursive: true });
  const npmShell = process.platform === "win32" ? { shell: true } : {};
  const n1 = spawnSync("npm", ["pack", "--pack-destination", packDir], { encoding: "utf8", cwd: ROOT, ...npmShell });
  const tgzName = existsSync(packDir) ? readdirSync(packDir).filter((f) => f.endsWith(".tgz")).sort()[0] : undefined;
  const tgz = tgzName ? join(packDir, tgzName) : "";
  check("N1: npm pack produces the tarball", n1.status === 0 && !!tgz, n1.stderr?.slice(0, 200));
  if (tgz) {
    const contents = spawnSync("tar", ["-tzf", tgz], { encoding: "utf8" }).stdout ?? "";
    check("N2: tarball carries dist + skill + README + LICENSE (npm files contract)",
      contents.includes("package/dist/cli.js") && contents.includes("package/skill/SKILL.md") && contents.includes("package/README.md") && contents.includes("package/LICENSE"));
    check("N3: tarball does NOT leak tests/src/node_modules",
      !contents.includes("/tests/") && !contents.includes("/src/") && !contents.includes("node_modules"));

    // install → first report smoke (the v1.0 acceptance: new user install → report)
    // NOTE: the install dir MUST live OUTSIDE the repo (npm walks up to the nearest
    // package.json — installing inside the repo would pollute it with a self-dep)
    const instDir = join(tmpdir(), `anubis-n4-install-${process.pid}`);
    rmSync(instDir, { recursive: true, force: true });
    mkd(instDir, { recursive: true });
    copyFileSync(tgz, join(instDir, "pkg.tgz"));
    const t0 = Date.now();
    const n2i = spawnSync("npm", ["install", "--prefix", instDir, "--no-audit", "--no-fund", "--loglevel", "error", "./pkg.tgz"], { encoding: "utf8", cwd: instDir, ...npmShell });
    const report = join(instDir, "first-report.json");
    const n2r = n2i.status === 0
      ? spawnSync("node", [join(instDir, "node_modules", "anubis-guardian", "dist", "cli.js"), "scan", join(ROOT, "tests", "clean", "app"), "--format", "json", "-o", report], { encoding: "utf8" })
      : { status: 1, stderr: n2i.stderr ?? "" };
    const elapsed = Date.now() - t0;
    check("N4: install → first report works from the packed tarball (exit 0, < 2 min)",
      n2i.status === 0 && n2r.status === 0 && existsSync(report) && elapsed < 120_000,
      `install=${n2i.status} scan=${n2r.status} ${elapsed}ms err=${(n2r.stderr ?? "").slice(0, 300)}`);
    check("N4b: the installed copy reports the package.json version",
      n2r.status === 0 && JSON.parse(readFileSync(report, "utf8")).version === PKG_VERSION);
    rmSync(instDir, { recursive: true, force: true });
  }

  const sbomPath = join(TMP, "sbom.json");
  const n3 = spawnSync("node", [join(ROOT, "scripts", "generate-sbom.mjs"), sbomPath], { encoding: "utf8" });
  let sbomOk = false; let sbomCount = 0;
  try {
    const sbom = JSON.parse(readFileSync(sbomPath, "utf8"));
    sbomCount = sbom.components.length;
    sbomOk = sbom.bomFormat === "CycloneDX" && sbom.specVersion === "1.5" && sbomCount >= 1
      && sbom.metadata.components[0].version === PKG_VERSION
      && sbom.components.some((c) => c.name === "commander");
  } catch { /* parse fail */ }
  check("N5: SBOM generated — CycloneDX 1.5, root = package.json version, commander present", n3.status === 0 && sbomOk, `components=${sbomCount}`);

  const relYml = existsSync(join(ROOT, ".github", "workflows", "release.yml")) ? readFileSync(join(ROOT, ".github", "workflows", "release.yml"), "utf8") : "";
  check("N6: release workflow: provenance + id-token + REAL pinned SHAs",
    /--provenance/.test(relYml) && /id-token: write/.test(relYml) && /actions\/checkout@[0-9a-f]{40}/.test(relYml) && /actions\/setup-node@[0-9a-f]{40}/.test(relYml));

  // ================= P — release docs present =================
  check("P1: METHODOLOGY.md exists", existsSync(join(ROOT, "METHODOLOGY.md")));
  check("P2: CONTRIBUTING-RULES.md (playbook contribution guide) exists", existsSync(join(ROOT, "CONTRIBUTING-RULES.md")));
  check("P3: benchmarks tooling wired (scripts + package.json)", existsSync(join(ROOT, "scripts", "measure-benchmarks.mjs")) && /"benchmarks"/.test(readFileSync(join(ROOT, "package.json"), "utf8")));
  check("P4: docs site landing exists (GitHub Pages ready)", existsSync(join(ROOT, "docs", "site", "index.html")));
} finally {
  cleanup();
}

console.error(`\nACCEPTANCE v1.0: ${PASS} passed, ${FAILS.length} failed`);
if (FAILS.length) {
  for (const f of FAILS) console.error(`  FAILED: ${f}`);
  process.exit(1);
}
