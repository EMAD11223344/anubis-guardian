#!/usr/bin/env node
/**
 * v0.4 URL Mode — planted-findings verification (the Mode 2 "honeypot"):
 * a local server plants every class the scanner must catch; every planted
 * finding must fire, decoys must not, secrets must stay masked, and the
 * authorization record must carry the ownership method.
 */
import { spawn, spawnSync } from "node:child_process";
import { writeFileSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const CLI = join(ROOT, "dist", "cli.js");
const TMP = join(HERE, ".tmp");
import { mkdirSync } from "node:fs";
mkdirSync(TMP, { recursive: true });

let PASS = 0;
const FAILS = [];
function check(name, cond, extra = "") {
  if (cond) { PASS++; console.log(`PASS  ${name}`); }
  else { FAILS.push(name); console.error(`FAIL  ${name}${extra ? ` — ${extra}` : ""}`); }
}

// ---- start fixture servers in a child process (spawnSync would deadlock them) ----
const child = spawn(process.execPath, [join(HERE, "servers.mjs"), "--serve"], { stdio: ["ignore", "pipe", "inherit"] });
const ready = await new Promise((resolve, reject) => {
  let buf = "";
  child.stdout.on("data", (d) => {
    buf += d.toString();
    const nl = buf.indexOf("\n");
    if (nl >= 0) { try { resolve(JSON.parse(buf.slice(0, nl))); } catch (e) { reject(e); } }
  });
  child.on("exit", (c) => reject(new Error(`fixture servers exited early (${c})`)));
  setTimeout(() => reject(new Error("fixture servers timeout")), 10_000);
});
const BASE = `http://127.0.0.1:${ready.bad}`;
const NONCE = ready.nonce;
const cleanup = () => { try { child.kill("SIGTERM"); } catch { /* already gone */ } };
process.on("exit", cleanup);
process.on("SIGINT", cleanup);

try {
  // ---- L2 self-attested scan (localhost → self-attestation honored + labeled) ----
  const findingsPath = join(TMP, "findings-l2.json");
  const r = spawnSync("node", [CLI, "scan-url", BASE, "--level", "2", "--i-own-this-domain", "--allow-private",
    "--delay-ms", "5", "--format", "json", "--output", findingsPath], { encoding: "utf8" });
  check("L2 self-attested scan exits 0", r.status === 0, `exit=${r.status} stderr=${r.stderr?.slice(0, 400)}`);

  const result = JSON.parse(readFileSync(findingsPath, "utf8"));
  const ids = (id) => result.findings.filter((f) => f.id === id && f.suppression === null);
  const has = (id, sev) => ids(id).some((f) => !sev || f.severity === sev);

  // authorization record + ownership label (Plan: reports carry ownership method)
  check("authorization record present (url, timestamp, level, ownership)", !!result.url_meta?.authorization
    && result.url_meta.authorization.url === BASE && result.url_meta.authorization.level === 2);
  check("ownership labeled self-attested (local only), not verified",
    result.url_meta.authorization.ownership_method === "self-attested (local only)"
    && result.url_meta.authorization.ownership_verified === false);

  // planted L2 holes
  check("URL-050 CRITICAL — .env with secrets publicly served", has("URL-050", "critical"));
  check("URL-051 HIGH — .git/config exposed", has("URL-051", "high"));
  check("URL-052 CRITICAL — SQL dump exposed", has("URL-052", "critical"));
  check("URL-054 MEDIUM — directory listing /backup/", has("URL-054", "medium"));
  check("URL-055 HIGH — TRACE enabled (XST)", has("URL-055", "high"));
  check("URL-056 MEDIUM — risky methods in Allow (PUT/DELETE)", has("URL-056", "medium"));
  check("URL-057 MEDIUM — Swagger UI exposed", has("URL-057", "medium"));
  check("URL-042 HIGH — source map ships original sources w/ secret-shaped content", has("URL-042", "high"));

  // decoy: SPA catch-all shell at /.env.local must NOT be flagged as env
  check("decoy SPA catch-all /.env.local NOT flagged", !has("URL-050") || ids("URL-050").every((f) => !f.file.endsWith("/.env.local")));

  // planted L1 holes (also present in L2 output)
  check("URL-040 CRITICAL — service_role JWT in public bundle", has("URL-040", "critical"));
  check("URL-040 CRITICAL — Stripe live key in public bundle", ids("URL-040").filter((f) => f.severity === "critical").length >= 2);
  check("URL-010 MEDIUM — CSP missing", has("URL-010", "medium"));
  check("URL-011 skipped (http target — HSTS only over https)", !has("URL-011"));
  check("URL-012 MEDIUM — clickjacking protection missing", has("URL-012", "medium"));
  check("URL-013/014/015 LOW — nosniff/referrer/permissions missing", has("URL-013", "low") && has("URL-014", "low") && has("URL-015", "low"));
  check("URL-020 MEDIUM — cookie without Secure", has("URL-020", "medium"));
  check("URL-021 HIGH — session cookie without HttpOnly", has("URL-021", "high"));
  check("URL-022 LOW — cookie without SameSite", has("URL-022", "low"));
  check("URL-030 LOW — Server version disclosure", has("URL-030", "low"));
  check("URL-031 LOW — X-Powered-By disclosure", has("URL-031", "low"));
  check("URL-041 LOW — internal endpoint in public bundle", has("URL-041", "low"));
  check("URL-043 INFO — sourceMappingURL referenced (advice)", has("URL-043", "info"));
  check("URL-905 LOW — security.txt absent", has("URL-905", "low"));

  // robots awareness: /admin disallowed → skipped + not requested
  check("robots.txt Disallow honored — /admin skipped", result.url_meta.robots.skipped_paths.includes("/admin"));
  const log = await (await fetch(`${BASE}/__requestlog`)).json();
  check("no request to /admin was actually sent", !log.requests.some((x) => x.url === "/admin"));

  // masking contract — raw values never appear anywhere
  const raw = readFileSync(findingsPath, "utf8");
  for (const secret of ["sk_live_51H8xYq2eZvKYlo2C", "CorrectHorse9x!", "SiGn4tureP4rtW1thM0reTh4nTenCh4r4cters"]) {
    check(`MUST_BE_MASKED: "${secret.slice(0, 12)}…" absent from findings.json`, !raw.includes(secret));
  }

  // score is computed from the same findings (root-cause caps apply)
  check("score/grade consistent with findings", typeof result.score === "number" && result.score < 40 && result.grade === "F");

  // ---- CI gate ----
  const gate = spawnSync("node", [CLI, "scan-url", BASE, "--level", "1", "--allow-private", "--delay-ms", "5", "--fail-on", "high"], { encoding: "utf8" });
  check("--fail-on high exits 1 on planted findings", gate.status === 1, `exit=${gate.status}`);
} finally {
  cleanup();
}

console.log(`\nVERIFY MODE2: ${PASS} passed, ${FAILS.length} failed`);
process.exit(FAILS.length ? 1 : 0);
