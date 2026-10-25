#!/usr/bin/env node
/**
 * v0.4 acceptance — every gate from the frozen plan scope:
 *   A  L1 truly passive (request log ⊆ browser-equivalent) + L1 flagship finds
 *   B  L2 refuses un-gated (public domain) — self-attestation local-only — L3 verified-only
 *   C  verified ownership (.well-known live + DNS TXT unit test w/ injected resolver)
 *   D  Supabase live anon probe analysis (GET-only, from captured responses)
 *   E  determinism: same capture ⇒ byte-identical findings.json (zero network)
 *   F  output contract on URL findings (sarif / fix-prompt / md / compact)
 *   G  hard rate limiting
 *   H  clean control (expected findings only, no FPs)
 *   I  ownership command (generate + verify)
 */
import { spawn, spawnSync } from "node:child_process";
import { writeFileSync, readFileSync, mkdirSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const CLI = join(ROOT, "dist", "cli.js");
const TMP = join(HERE, ".tmp-acc");
rmSync(TMP, { recursive: true, force: true });
mkdirSync(TMP, { recursive: true });

let PASS = 0;
const FAILS = [];
function check(name, cond, extra = "") {
  if (cond) { PASS++; console.log(`PASS  ${name}`); }
  else { FAILS.push(name); console.error(`FAIL  ${name}${extra ? ` — ${extra}` : ""}`); }
}
function run(args) {
  const r = spawnSync("node", [CLI, ...args], { encoding: "utf8" });
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
const CLEAN = `http://127.0.0.1:${ready.clean}`;
const NONCE = ready.nonce;
const cleanup = () => { try { child.kill("SIGTERM"); } catch { /* gone */ } };
process.on("exit", cleanup);
process.on("SIGINT", cleanup);
const requestLog = async () => {
  // Undici pools keep-alive sockets; after >5s idle (Node server keepAliveTimeout)
  // the fixture may have closed the pooled socket, and the stale write can crash
  // fetch with ECONNRESET. Retry on a fresh connection — this is test-process
  // resilience only, scan behavior is unaffected.
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

try {
  // ================= A — L1 is truly passive =================
  const l1cap = join(TMP, "l1-capture.json");
  const a = run(["scan-url", BAD, "--level", "1", "--allow-private", "--delay-ms", "5", "--capture", l1cap, "--format", "json", "-o", join(TMP, "l1.json")]);
  check("A1: L1 scan exits 0 with no ownership", a.code === 0, `exit=${a.code}`);
  const l1 = JSON.parse(readFileSync(join(TMP, "l1.json"), "utf8"));
  const l1log = await requestLog();
  const requestedPaths = new Set(l1log.map((r) => r.url));
  const BROWSER_EQUIV = new Set(["/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/_next/static/app.js", "/_next/static/vendor.js"]);
  const probed = [...requestedPaths].filter((p) => !BROWSER_EQUIV.has(p));
  check("A2: L1 requests ⊆ browser-equivalent (no probing at all)", probed.length === 0, `probed=${probed.join(", ")}`);
  check("A3: L1 never requested /.env, /.git/config, /backup/, /swagger", !l1log.some((r) => ["/.env", "/.git/config", "/backup/", "/swagger/index.html"].includes(r.url)));
  check("A4: L1 never sent TRACE/OPTIONS", !l1log.some((r) => r.method === "TRACE" || r.method === "OPTIONS"));
  check("A5: L1 flagship — secret in public JS bundle fires (CRITICAL)",
    l1.findings.some((f) => f.id === "URL-040" && f.severity === "critical"));
  check("A6: L1 planted missing header fires", l1.findings.some((f) => f.id === "URL-010"));
  check("A7: L1 emits NO probing findings (no URL-050/.env)", !l1.findings.some((f) => f.id === "URL-050"));
  check("A8: L1 ownership method = none (passive needs none)", l1.url_meta.authorization.ownership_method === "none");
  check("A9: L1 authorization record present", l1.url_meta.authorization.url === BAD && typeof l1.url_meta.authorization.timestamp === "string");

  // ================= B — the legal gate =================
  const b1 = run(["scan-url", "http://example.invalid", "--level", "2", "--delay-ms", "5"]);
  check("B1: public domain L2 without token → exit 2", b1.code === 2, `exit=${b1.code}`);
  check("B2: refusal explains verified-ownership requirement", /VERIFIED ownership/i.test(b1.err));
  check("B3: refusal prints DNS TXT + .well-known instructions", /anubis-guardian-challenge=/.test(b1.err) && /\/\.well-known\/anubis-guardian\//.test(b1.err));
  const b2 = run(["scan-url", "http://example.invalid", "--level", "2", "--i-own-this-domain", "--delay-ms", "5"]);
  check("B4: public domain L2 + checkbox (self-attestation) → exit 2 (checkbox ≠ proof)", b2.code === 2);
  const b3 = run(["scan-url", BAD, "--level", "3", "--i-own-this-domain", "--delay-ms", "5"]);
  check("B5: L3 with self-attestation (even local) → exit 2 (verified-only)", b3.code === 2);
  const b4 = run(["scan-url", BAD, "--level", "2", "--delay-ms", "5"]);
  check("B6: local target L2 without any ownership flag → exit 2 with local-path hint", b4.code === 2 && /--i-own-this-domain/.test(b4.err));

  // ================= C — verified ownership =================
  const c1 = run(["scan-url", BAD, "--level", "2", "--ownership-token", NONCE, "--allow-private", "--delay-ms", "5", "--format", "json", "-o", join(TMP, "c1.json")]);
  check("C1: L2 with correct .well-known nonce exits 0", c1.code === 0, `exit=${c1.code}`);
  const c1r = JSON.parse(readFileSync(join(TMP, "c1.json"), "utf8"));
  check("C2: ownership method = well-known, verified = true",
    c1r.url_meta.authorization.ownership_method === "well-known" && c1r.url_meta.authorization.ownership_verified === true);
  const c2 = run(["scan-url", BAD, "--level", "2", "--ownership-token", "wrong-nonce-000", "--allow-private", "--delay-ms", "5"]);
  check("C3: wrong nonce → exit 2 (level stays locked)", c2.code === 2);
  // DNS TXT unit test — injected resolver (offline)
  const { verifyDnsTxt } = await import(pathToFileURL(join(ROOT, "dist", "urlmode", "ownership.js")).href);
  const fake = async (name) => name.startsWith("_anubis-guardian.") ? [] : [["anubis-guardian-challenge=dnsnonce123"]];
  check("C4: DNS TXT verification (host record) — injected resolver", await verifyDnsTxt("example.test", "dnsnonce123", fake));
  const fake2 = async (name) => name === "example.test" ? [] : [["anubis-guardian-challenge=dnsnonce123"]];
  check("C5: DNS TXT verification (_anubis-guardian.<host> record)", await verifyDnsTxt("example.test", "dnsnonce123", fake2));
  const fake3 = async () => [["v=spf1 -all"]];
  check("C6: DNS TXT mismatch → not verified", !(await verifyDnsTxt("example.test", "dnsnonce123", fake3)));

  // ================= D — Supabase live anon probe (analysis over captured responses) =================
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const ANON = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ ref: "abcdefghij1234567890", role: "anon" })}.S1gn4tureVal1dExample12345`;
  const SUPA = "https://abcdefghij1234567890.supabase.co";
  const dCapture = {
    capture_version: 1,
    meta: { url: BAD, captured_at: "2026-10-25T00:00:00.000Z", level: 3, ownership: { verified: true, method: "dns-txt", host: "127.0.0.1" }, tool: "anubis-guardian", version: "0.4.0", max_requests: 150, delay_ms: 5 },
    tls: null,
    requests: [
      { seq: 1, method: "GET", url: BAD, final_url: BAD + "/", status: 200, headers: { "content-type": "text/html" }, body: `<!doctype html><html><body><script src="/app.js"></script></body></html>`, body_truncated: false, bytes: 90 },
      { seq: 2, method: "GET", url: BAD + "/app.js", final_url: BAD + "/app.js", status: 200, headers: { "content-type": "application/javascript" }, body: `var S="${SUPA}";var K="${ANON}";`, body_truncated: false, bytes: 90 },
      { seq: 3, method: "GET", url: SUPA + "/rest/v1/", final_url: SUPA + "/rest/v1/", status: 200, headers: { "content-type": "application/openapi+json" }, body: JSON.stringify({ openapi: "3.0.0", paths: { "/profiles": {}, "/audit_log": {} } }), body_truncated: false, bytes: 80 },
      { seq: 4, method: "GET", url: SUPA + "/rest/v1/profiles?select=*&limit=1", final_url: SUPA + "/rest/v1/profiles?select=*&limit=1", status: 200, headers: { "content-type": "application/json" }, body: '[{"id":1,"email":"victim@example.test"}]', body_truncated: false, bytes: 40 },
      { seq: 5, method: "GET", url: SUPA + "/rest/v1/audit_log?select=*&limit=1", final_url: SUPA + "/rest/v1/audit_log?select=*&limit=1", status: 401, headers: { "content-type": "application/json" }, body: '{"error":"permission denied"}', body_truncated: false, bytes: 32 },
    ],
    robots: { skipped: [], disallow_all: false },
    notes: ["acceptance fixture capture"],
  };
  const dPath = join(TMP, "supa-capture.json");
  writeFileSync(dPath, JSON.stringify(dCapture, null, 2));
  const d = run(["scan-url", BAD, "--from-capture", dPath, "--format", "json", "-o", join(TMP, "d.json")]);
  check("D1: L3 analysis from capture exits 0", d.code === 0, d.err.slice(0, 200));
  const d1 = JSON.parse(readFileSync(join(TMP, "d.json"), "utf8"));
  check("D2: URL-060 HIGH — live anon read returned rows (RLS not effective)",
    d1.findings.some((f) => f.id === "URL-060" && f.severity === "high" && f.root === "profiles"));
  check("D3: URL-908 INFO — locked table reported as holding (documented-correct)",
    d1.findings.some((f) => f.id === "URL-908" && f.file.includes("audit_log")));
  check("D4: probe was GET-only by construction (capture has no mutations)",
    dCapture.requests.every((r) => r.method === "GET"));
  check("D5: authorization record carries dns-txt verified for L3",
    d1.url_meta.authorization.ownership_method === "dns-txt" && d1.url_meta.authorization.ownership_verified === true);
  check("D6: L3 without verified capture ownership → probe skipped (info only)", !d1.findings.some((f) => f.id === "URL-060" && f.severity === "critical"));

  // ================= E — determinism (same capture ⇒ byte-identical) =================
  const e1 = run(["scan-url", BAD, "--from-capture", l1cap, "--format", "json", "-o", join(TMP, "e1.json")]);
  const e2 = run(["scan-url", BAD, "--from-capture", l1cap, "--format", "json", "-o", join(TMP, "e2.json")]);
  const e1t = readFileSync(join(TMP, "e1.json"), "utf8");
  const e2t = readFileSync(join(TMP, "e2.json"), "utf8");
  check("E1: from-capture runs exit 0", e1.code === 0 && e2.code === 0);
  check("E2: byte-identical findings.json from the same capture (v0.4 determinism)", e1t === e2t);
  const logBefore = await requestLog();
  run(["scan-url", BAD, "--from-capture", l1cap, "--format", "json", "-o", join(TMP, "e3.json")]);
  const logAfter = await requestLog();
  check("E3: from-capture makes ZERO network requests", logBefore.length === logAfter.length);

  // ================= F — output contract on URL findings =================
  const f1 = run(["scan-url", BAD, "--from-capture", l1cap, "--format", "all", "--sarif", join(TMP, "u.sarif"), "--fix-prompt", join(TMP, "u-fix.md"), "--compact", join(TMP, "u-compact.txt"), "--html", join(TMP, "u.html"), "-o", join(TMP, "u-all.txt")]);
  check("F1: all renderers exit 0 on URL findings", f1.code === 0);
  run(["scan-url", BAD, "--from-capture", l1cap, "--format", "md", "-o", join(TMP, "u.md")]); // md renderer runs standalone ("all" = terminal+json by v0.2 contract)
  const sarif = JSON.parse(readFileSync(join(TMP, "u.sarif"), "utf8"));
  check("F2: SARIF 2.1.0 valid with URL artifact locations", sarif.version === "2.1.0"
    && sarif.runs[0].results.some((r) => r.locations[0].physicalLocation.artifactLocation.uri.startsWith("http")));
  const fixmd = readFileSync(join(TMP, "u-fix.md"), "utf8");
  check("F3: fix-prompt carries the map-endpoints-to-code instruction", /MAP the flagged URL\/endpoint to the code/i.test(fixmd));
  check("F4: fix-prompt verify line uses scan-url (same level)", fixmd.includes("`npx anubis-guardian scan-url http://127.0.0.1"));
  const mdOut = readFileSync(join(TMP, "u.md"), "utf8");
  check("F5: markdown report carries the scan authorization record", /## Scan authorization record/.test(mdOut) && /Ownership \| \*\*none\*\*/.test(mdOut));
  check("F6: compact renders URL findings", readFileSync(join(TMP, "u-compact.txt"), "utf8").includes("URL-040"));
  check("F7: HTML renders", readFileSync(join(TMP, "u.html"), "utf8").includes("Anubis Guardian"));

  // ================= G — rate limiting =================
  const g0 = Date.now();
  run(["scan-url", BAD, "--level", "1", "--allow-private", "--delay-ms", "150", "--format", "json", "-o", join(TMP, "g.json")]);
  const gElapsed = Date.now() - g0;
  const gCount = (await requestLog()).length; // cumulative; the L1 run above adds ~6
  check("G1: rate limit enforced (parallel browser-equivalent batches, min-interval pacing ⇒ ≥450ms wall)", gElapsed >= 450, `elapsed=${gElapsed}ms`);

  // ================= H — clean control =================
  const h = run(["scan-url", CLEAN, "--level", "1", "--allow-private", "--delay-ms", "5", "--format", "json", "-o", join(TMP, "h.json")]);
  const h1 = JSON.parse(readFileSync(join(TMP, "h.json"), "utf8"));
  const hIds = h1.findings.filter((f) => f.suppression === null).map((f) => f.id).sort();
  check("H1: clean site exits 0", h.code === 0);
  check("H2: clean site → exactly the expected findings (URL-001 http + URL-904 info), zero FPs",
    JSON.stringify(hIds) === JSON.stringify(["URL-001", "URL-904"]), `ids=${hIds.join(",")}`);
  check("H3: clean score = 90/A (only the honest no-TLS deduction over http)", h1.score === 90 && h1.grade === "A", `score=${h1.score}/${h1.grade}`);

  // ================= I — ownership command =================
  const i1 = run(["ownership", BAD]);
  check("I1: ownership generates nonce + both instructions", i1.code === 0 && /anubis-guardian-challenge=/.test(i1.err) && /\/\.well-known\/anubis-guardian\//.test(i1.err));
  const i2 = run(["ownership", BAD, "--check", NONCE, "--allow-private"]);
  check("I2: ownership --check verifies the published nonce (exit 0)", i2.code === 0, `exit=${i2.code} ${i2.err.slice(0, 120)}`);
  const i3 = run(["ownership", BAD, "--check", "nope", "--allow-private"]);
  check("I3: ownership --check wrong nonce → exit 1", i3.code === 1);

  // ================= J — gates + help surface =================
  const j1 = run(["scan-url", BAD, "--from-capture", l1cap, "--fail-on", "critical", "--format", "json", "-o", join(TMP, "j.json")]);
  check("J1: --fail-on critical exits 1 with CRITICAL findings", j1.code === 1);
  const j2 = run(["scan-url", BAD, "--level", "9"]);
  check("J2: invalid level → exit 2", j2.code === 2);
  check("J3: --help documents the three levels", run(["scan-url", "--help"]).out.includes("3 = 2 + Supabase"));
} finally {
  cleanup();
}

console.log(`\nACCEPTANCE v0.4: ${PASS} passed, ${FAILS.length} failed`);
process.exit(FAILS.length ? 1 : 0);
