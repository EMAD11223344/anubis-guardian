#!/usr/bin/env node
/**
 * v1.5.2-p1 — lookup-contract regression gate (root-cause fix for the
 * Node ≥20 autoSelectFamily "Invalid IP address: undefined" bug).
 *
 * Covers:
 *  1. E2E on the REAL CLI: scan-url of a local loopback fixture through the
 *     exact dial path that used to throw ERR_INVALID_IP_ADDRESS(undefined)
 *     before any byte left the process (Node ≥20 autoSelectFamily → dnsopts
 *     all:true). Expected after the fix: homepage captured (HTTP 200), exit 0.
 *  2. Policy refusal intact: same target WITHOUT --allow-private must be
 *     SSRF-REFUSED (exit 2) and the report must NOT claim "target
 *     unreachable" — it must carry the URL-998 policy finding.
 *  3. Unit contract of pinnedIpLookup(): answers BOTH callback shapes —
 *     classic (err, address, family) and array ({all:true} →
 *     [{address, family}]) — and always pins the guard-validated address
 *     while ignoring the hostname the socket layer hands it.
 *  4. classifySocketError taxonomy: node errno → network; ERR_INVALID_* →
 *     internal; message timeouts → timeout.
 *  5. True network failure (closed port) stays URL-999 "Target unreachable",
 *     also fail-closed (grade N/A, exit 2) — and is classified network, not
 *     internal or policy.
 *
 * Fixture note: like tests/mode2, the server runs in a CHILD process —
 * spawnSync in this process would block its event loop and starve it.
 */
import { spawn, spawnSync } from "node:child_process";
import { readFileSync, mkdirSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const CLI = join(ROOT, "dist", "cli.js");
const TMP = join(HERE, ".tmp");
rmSync(TMP, { recursive: true, force: true });
mkdirSync(TMP, { recursive: true });

let PASS = 0;
const FAILS = [];
function check(name, cond, extra = "") {
  if (cond) { PASS++; console.log(`PASS  ${name}`); }
  else { FAILS.push(name); console.error(`FAIL  ${name}${extra ? ` — ${extra}` : ""}`); }
}
function runCli(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (d) => { stderr += d.toString(); });
    child.on("exit", (code) => resolve({ code, stderr }));
  });
}

// ---- start the fixture in a child process (must not share our event loop) ----
const FIXTURE = join(HERE, "lookup-fixture.mjs");
const fixture = spawn(process.execPath, [FIXTURE], { stdio: ["ignore", "pipe", "inherit"] });
const ready = await new Promise((resolve, reject) => {
  let buf = "";
  fixture.stdout.on("data", (d) => {
    buf += d.toString();
    const nl = buf.indexOf("\n");
    if (nl >= 0) { try { resolve(JSON.parse(buf.slice(0, nl))); } catch (e) { reject(e); } }
  });
  fixture.on("exit", (c) => reject(new Error(`lookup fixture exited early (${c})`)));
  setTimeout(() => reject(new Error("lookup fixture timeout")), 10_000);
});
const TARGET = `http://127.0.0.1:${ready.port}/`;

// ---- 1) E2E: the former crash path now produces a real capture ----
const cap1 = join(TMP, "lookup-good.capture.json");
const rep1 = join(TMP, "lookup-good.json");
const good = await runCli(["scan-url", TARGET, "--level", "1", "--allow-private",
  "--format", "json", "--output", rep1, "--capture", cap1, "--delay-ms", "10", "--timeout-ms", "8000"]);
check("E2E: [--allow-private] exit 0 (was exit 2 / Invalid IP address: undefined)", good.code === 0,
  `status=${good.code} stderr=${good.stderr.slice(-200).replace(/\n/g, " ")}`);
try {
  const cap = JSON.parse(readFileSync(cap1, "utf8"));
  const home = (cap.requests || []).find((r) => r.url === TARGET && r.status === 200);
  check("E2E: homepage captured (status 200, body present)", Boolean(home) && /alive/.test(home.body || ""));
  check("E2E: dial record carries no error (clean capture)", !home || home.error === undefined);
  const rep = JSON.parse(readFileSync(rep1, "utf8"));
  check("E2E: no URL-999 in report", !(rep.findings || []).some((f) => f.id === "URL-999"));
  check("E2E: no URL-998 in report", !(rep.findings || []).some((f) => f.id === "URL-998"));
  check("E2E: grade computed (not N/A)", rep.grade !== "N/A" && rep.score !== null);
} catch (e) {
  check("E2E: artifacts readable", false, String(e));
}

// ---- 2) policy refusal: no --allow-private → SSRF refusal, NOT "unreachable" ----
const cap2 = join(TMP, "lookup-policy.capture.json");
const rep2 = join(TMP, "lookup-policy.json");
const policy = await runCli(["scan-url", TARGET, "--level", "1",
  "--format", "json", "--output", rep2, "--capture", cap2, "--delay-ms", "10", "--timeout-ms", "8000"]);
check("POLICY: exit 2 (fail-closed refusal preserved)", policy.code === 2, `status=${policy.code}`);
try {
  const rep = JSON.parse(readFileSync(rep2, "utf8"));
  const u998 = (rep.findings || []).find((f) => f.id === "URL-998");
  check("POLICY: URL-998 policy finding present", Boolean(u998));
  check("POLICY: NOT labeled 'Target unreachable'", !(rep.findings || []).some((f) => f.id === "URL-999"));
  check("POLICY: evidence carries the SSRF-REFUSED reason", Boolean(u998 && /SSRF-REFUSED/.test(u998.evidence?.masked || "")));
  check("POLICY: fail-closed — grade N/A, score null", rep.grade === "N/A" && rep.score === null);
  const cap = JSON.parse(readFileSync(cap2, "utf8"));
  check("POLICY: request record errorKind=policy", (cap.requests || [])[0]?.errorKind === "policy",
    JSON.stringify((cap.requests || [])[0]));
} catch (e) {
  check("POLICY: artifacts readable", false, String(e));
}

// ---- 3) unit: pinnedIpLookup answers BOTH callback contracts ----
const { pinnedIpLookup, classifySocketError } = await import(
  pathToFileURL(join(ROOT, "dist", "urlmode", "fetcher.js")).href
);
const lookup = pinnedIpLookup({ ip: "203.0.113.7", family: 4 });

await new Promise((resolve) => {
  lookup("attacker-controlled.example", {}, (err, addr, fam) => {
    check("UNIT: classic contract → (err, pinnedIp, 4)", err === null && addr === "203.0.113.7" && fam === 4);
    resolve();
  });
});
await new Promise((resolve) => {
  lookup("attacker-controlled.example", { all: true }, (err, addresses) => {
    const ok = err === null && Array.isArray(addresses) && addresses.length === 1 &&
      addresses[0].address === "203.0.113.7" && addresses[0].family === 4;
    check("UNIT: array contract (all:true, autoSelectFamily) → [{address, family}]", ok, JSON.stringify(addresses));
    resolve();
  });
});
lookup("203.0.113.7", {}, (err, addr) => {
  check("UNIT: ignores hostname argument entirely (no rebinding window)", err === null && addr === "203.0.113.7");
});

// ---- 4) taxonomy ----
check("TAX: ENOTFOUND → network", classifySocketError({ code: "ENOTFOUND" }) === "network");
check("TAX: ECONNREFUSED → network", classifySocketError({ code: "ECONNREFUSED" }) === "network");
check("TAX: ERR_INVALID_IP_ADDRESS → internal", classifySocketError({ code: "ERR_INVALID_IP_ADDRESS", message: "Invalid IP address: undefined" }) === "internal");
check("TAX: plain 'connect timeout' message → timeout", classifySocketError({ code: undefined, message: "connect timeout" }) === "timeout");

// ---- 5) true network failure keeps URL-999 + honest kind ----
const cap5 = join(TMP, "lookup-dead.capture.json");
const rep5 = join(TMP, "lookup-dead.json");
const deadUrl = `http://127.0.0.1:${ready.deadPort}/`;
const dead = await runCli(["scan-url", deadUrl, "--level", "1", "--allow-private",
  "--format", "json", "--output", rep5, "--capture", cap5, "--delay-ms", "10", "--timeout-ms", "5000"]);
try {
  const rep = JSON.parse(readFileSync(rep5, "utf8"));
  const u999 = (rep.findings || []).find((f) => f.id === "URL-999");
  const u998 = (rep.findings || []).find((f) => f.id === "URL-998");
  check("NET: closed port → URL-999 'Target unreachable' (true network failure)", Boolean(u999) && !u998,
    JSON.stringify((rep.findings || []).map((f) => f.id)));
  check("NET: fail-closed — grade N/A, score null", rep.grade === "N/A" && rep.score === null);
  const cap = JSON.parse(readFileSync(cap5, "utf8"));
  const k = (cap.requests || [])[0]?.errorKind;
  check("NET: dial error classified network/timeout (not internal/policy)", k === "network" || k === "timeout", `kind=${k}`);
  check("NET: exit 2 preserved for unreachable", dead.code === 2 || dead.code === 1, `exit=${dead.code}`);
} catch (e) {
  check("NET: artifacts readable", false, String(e));
}

fixture.kill();
serverCleanup: try { rmSync(TMP, { recursive: true, force: true }); } catch { /* best effort */ }

console.log(`\n=== verify-lookup-contract: ${PASS} pass, ${FAILS.length} fail (node ${process.versions.node}) ===`);
if (FAILS.length) { FAILS.forEach((f) => console.error(`  failed: ${f}`)); process.exit(1); }
