#!/usr/bin/env node
/**
 * Phase-1 fixture-level regression suite (v1.2 — independent-review fixes).
 * Every task gets at least one POSITIVE (must detect / must refuse) and one
 * CLEAN (must stay silent) case, exercised through the real CLI on real
 * fixtures — the units cover the helpers, THIS covers the wiring end-to-end.
 *
 *   T1  fail-closed CLI:       bad path / bad --format / 0 files → exit 2 · --allow-empty → 0 ·
 *                              scan-url unreachable → exit 2 + grade N/A · reachable local URL → exit 0
 *   T2  ENV-001 value-based:   committed .env with service_role JWT → CRITICAL · public-only .env → none
 *   T3  history triage:        Sk_live in src history → HIST-003 · same in docs/tests + anon JWT → silent
 *   T4  DEP-003 calibration:   "expres" → HIGH · exact popular name → silent
 *   T5  DEP-004 aggregated:    no lockfile → exactly ONE DEP-004 · pnpm lockfile → none
 *   T6  hygiene:               raw __html → SAST-002 · DOMPurify → silent ·
 *                              unguarded fetch → TAINT-001 MEDIUM · allowlisted → LOW-only
 *   T7  walk accounting:       oversize/binary fixture → meta.files_skipped · clean repo → absent
 *   T0  adapters fail-closed:  unknown --tools entry → exit 2 · no --tools → exit 0
 * Exit discipline: any failure → process.exit(1).
 */
import { spawnSync, spawn } from "node:child_process";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..");
const CLI = join(ROOT, "dist", "cli.js");
// v1.2 lesson (hit during development): fixtures MUST live OUTSIDE any git repo.
// Under tests/regression/, a fixture's `git add -A` climbs into an ancestor repo
// and stages/commits tool-repo files — the exact accident class the U12
// containment tests exist for. os.tmpdir() has no ancestor repo.
const TMP = join(tmpdir(), "anubis-regression");
rmSync(TMP, { recursive: true, force: true });
mkdirSync(TMP, { recursive: true });

/**
 * Reachable-target helper: the HTTP server runs in a SEPARATE PROCESS on
 * purpose — spawnSync blocks this process's event loop, so an in-process
 * server never accepts a connection while the CLI child waits (the requests
 * all die with "timeout"). The child prints its port once listening.
 */
function startServer() {
  const child = spawn(process.execPath, ["-e", `
    const { createServer } = require("node:http");
    const s = createServer((q, r) => {
      r.setHeader("content-type", "text/html");
      r.end("<html><body>ok</body></html>");
    });
    s.listen(0, "127.0.0.1", () => process.stdout.write(String(s.address().port)));
  `], { stdio: ["ignore", "pipe", "ignore"] });
  return new Promise((res, rej) => {
    let out = "";
    child.stdout.on("data", (c) => {
      out += c;
      if (out.trim()) res({ child, port: Number(out.trim()) });
    });
    child.on("exit", (c) => rej(new Error(`server child exited ${c}`)));
    setTimeout(() => rej(new Error(`server child did not listen (got '${out.slice(0, 20)}')`)), 10_000).unref();
  });
}

let PASS = 0;
const FAILS = [];
const check = (name, cond, extra = "") => {
  if (cond) { PASS++; console.log(`PASS  ${name}`); }
  else { FAILS.push(name); console.error(`FAIL  ${name}${extra ? ` — ${extra}` : ""}`); }
};

const git = (args, cwd) => spawnSync("git", ["-c", "user.email=t@t.local", "-c", "user.name=t", ...args], { cwd, stdio: "pipe" });

/** run the CLI; returns { code, stdout, stderr, json } (json = parsed stdout only when --format json printed to stdout) */
function run(args) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", cwd: ROOT, maxBuffer: 64 << 20 });
  let json = null;
  try { json = JSON.parse(r.stdout ?? ""); } catch { /* not a json run */ }
  return { code: r.status ?? -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "", json };
}

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const SERVICE_ROLE_JWT = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "https://abcdefghij1234567890.supabase.co/auth/v1", ref: "abcdefghij1234567890", role: "service_role" })}.SiGn4tureP4rtW1thM0reTh4nTenCh4r4cters`;
const ANON_JWT = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "https://abcdefghij1234567890.supabase.co/auth/v1", ref: "abcdefghij1234567890", role: "anon" })}.An0nS1gn4tureP4rtW1thM0reTh4nTenCh4rs`;
const sk_live = "sk_live_Fq9vN2xK7mT4wZbY8cR1dH6";

// ---------------------------------------------------------------- git fixture helper
function makeRepo(name, { commit }) {
  const dir = join(TMP, name);
  mkdirSync(dir, { recursive: true });
  if (commit) {
    const r = git(["init", "-q"], dir);
    if (r.status !== 0) throw new Error(`git init failed in ${dir}: ${r.stderr}`);
  }
  return dir;
}
const commitAll = (dir, msg = "fixture") => git(["add", "-A"], dir).status === 0 && git(["commit", "-q", "-m", msg], dir).status === 0;

// ================================================================ T1 — fail-closed CLI
{
  // positive: bad path → exit 2
  check("T1+ scan nonexistent path exits 2", run(["scan", join(TMP, "definitely-not-there")]).code === 2);
  // positive: unknown --format → exit 2 (was: silent no-op, exit 0)
  check("T1+ unknown --format exits 2", run(["scan", ".", "--format", "credsformat"]).code === 2);
  // positive: zero scannable files → exit 2
  const emptyDir = join(TMP, "empty-dir");
  mkdirSync(emptyDir, { recursive: true });
  check("T1+ zero-file scan exits 2 (no fake 100/A)", run(["scan", emptyDir]).code === 2);
  // clean(+escape hatch): --allow-empty accepts and emits a report
  const allowEmpty = run(["scan", emptyDir, "--allow-empty", "--format", "json"]);
  check("T1= --allow-empty produces a report and exits 0",
    allowEmpty.code === 0 && allowEmpty.json && (allowEmpty.json.meta.files_scanned === 0), allowEmpty.stderr.slice(0, 140));
  // clean: a real scan still exits 0
  check("T1= normal scan of tests/clean/app exits 0", run(["scan", join(ROOT, "tests", "clean", "app")]).code === 0);
  // v1.2 audit: a path that EXISTS but is a FILE (not a directory) is refused —
  // never mis-scanned, never a misleading clean report
  const fileRoot = join(TMP, "not-a-dir.txt");
  writeFileSync(fileRoot, "just a file, not a project directory\n");
  check("T1+ scan of a FILE path exits 2 ('not a project directory')",
    run(["scan", fileRoot]).code === 2 && /not a project directory/.test(run(["scan", fileRoot]).stderr), `code=${run(["scan", fileRoot]).code}`);

  // positive: unreachable scan-url → exit 2, grade N/A, score null
  const un = run(["scan-url", "http://127.0.0.1:1", "--allow-private", "--level", "1", "--format", "json"]);
  check("T1+ unreachable scan-url exits 2", un.code === 2, `code=${un.code}`);
  check("T1+ unreachable scan-url: grade N/A + score null in JSON", un.json?.grade === "N/A" && un.json?.score === null,
    `grade=${un.json?.grade} score=${un.json?.score} (${un.stderr.slice(0, 120)})`);

  // clean: reachable local target grades normally (server in a SEPARATE
  // process — see startServer() for why an in-process server cannot work here)
  const reachable = await startServer();
  try {
    const ok = run(["scan-url", `http://127.0.0.1:${reachable.port}/`, "--allow-private", "--level", "1", "--format", "json"]);
    check("T1= reachable scan-url exits 0 with a real grade", ok.code === 0 && ok.json?.score !== null && ok.json?.grade !== "N/A",
      `code=${ok.code} grade=${ok.json?.grade} score=${ok.json?.score}`);
  } finally { reachable.child.kill(); }
}

// ================================================================ T2 — ENV-001 VALUE-based
{
  const b64env = (body) => `NEXT_PUBLIC_SUPABASE_URL=https://abcdefghij.supabase.co\nNEXT_PUBLIC_SUPABASE_ANON_KEY=${ANON_JWT}\n${body}`;
  // positive: committed .env with a service_role JWT stays CRITICAL (value-based still catches it)
  const dir1 = makeRepo("t2-sr", { commit: true });
  mkdirSync(join(dir1, "src"), { recursive: true });
  writeFileSync(join(dir1, "src", "index.ts"), "export const x = 1;\n");
  writeFileSync(join(dir1, ".env"), b64env(`NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${SERVICE_ROLE_JWT}`));
  commitAll(dir1, "committed env");
  const r1 = run(["scan", dir1, "--format", "json"]);
  const env1 = r1.json?.findings.filter((f) => f.id === "ENV-001");
  check("T2+ committed .env with service_role JWT → ENV-001 CRITICAL",
    r1.code === 0 && env1?.some((f) => f.severity === "critical"), JSON.stringify(env1?.map((f) => f.severity)));

  // clean: public-only .env (Lovable-style) committed → NO ENV-001 at all, zero criticals
  const dir2 = makeRepo("t2-public", { commit: true });
  mkdirSync(join(dir2, "src"), { recursive: true });
  writeFileSync(join(dir2, "src", "index.ts"), "export const x = 1;\n");
  writeFileSync(join(dir2, ".env"), b64env("NEXT_PUBLIC_SITE_URL=https://abcdefghij.example.com"));
  commitAll(dir2, "public env");
  const r2 = run(["scan", dir2, "--format", "json"]);
  const env2 = (r2.json?.findings ?? []).filter((f) => f.id === "ENV-001");
  check("T2= public-only committed .env → ZERO critical/high ENV-001; ONE low 'public values only' note",
    r2.code === 0
    && env2.every((f) => f.severity === "low" && f.confidence === "low")
    && env2.length === 1 && /public values only/.test(env2[0].title)
    && r2.json?.summary.critical === 0 && r2.json?.summary.high === 0,
    JSON.stringify(r2.json?.findings.map((f) => `${f.id}/${f.severity}`)));
}

// ================================================================ T3 — history triage
{
  // positive: sk_live key committed in src history → HIST-003 detected
  const dirP = makeRepo("t3-pos", { commit: true });
  mkdirSync(join(dirP, "src"), { recursive: true });
  mkdirSync(join(dirP, "lib"), { recursive: true });
  // a persistent benign file keeps the worktree non-empty after the key is
  // removed (a 0-file tree now trips the new fail-closed empty-scan refusal)
  writeFileSync(join(dirP, "lib", "util.ts"), "export const util = 1;\n");
  writeFileSync(join(dirP, ".gitignore"), ".env\n.env.*\n*.pem\n*.tfstate\nnode_modules/\n");
  writeFileSync(join(dirP, "src", "config.ts"), `export const KEY = "${sk_live}";\n`);
  commitAll(dirP);
  rmSync(join(dirP, "src", "config.ts"), { force: true });
  commitAll(dirP, "remove leaked key");
  const rp = run(["scan", dirP, "--format", "json"]);
  check("T3+ real secret in src history → HIST-003 detected",
    rp.json?.findings.some((f) => f.id === "HIST-003" && f.file.includes("config.ts")), rp.stderr.slice(0, 140));

  // clean: the same leak under tests/ and docs/ and an anon JWT in src stay silent
  const dirC = makeRepo("t3-clean", { commit: true });
  mkdirSync(join(dirC, "tests"), { recursive: true });
  mkdirSync(join(dirC, "docs"), { recursive: true });
  mkdirSync(join(dirC, "src"), { recursive: true });
  // a real .gitignore keeps the LOW-level HIST-010/011 hygiene notes out of the
  // way — this block asserts on HISTORY leaks, not gitignore completeness
  writeFileSync(join(dirC, ".gitignore"), ".env\n.env.*\n*.pem\n*.tfstate\nnode_modules/\n");
  writeFileSync(join(dirC, "tests", "aws-client.ts"), `// integration key: ${sk_live}\n`);
  writeFileSync(join(dirC, "docs", "guide.md"), `key: ${sk_live}\n`);
  writeFileSync(join(dirC, "src", "api.ts"), `export const ANON = "${ANON_JWT}";\n`);
  commitAll(dirC);
  const rc = run(["scan", dirC, "--format", "json"]);
  const histHits = (rc.json?.findings ?? []).filter(
    (f) => /^HIST-0/.test(f.id) && (f.severity === "critical" || f.severity === "high")
  );
  check("T3= test/docs-path leaks + anon JWT in history stay silent",
    rc.code === 0 && histHits.length === 0, JSON.stringify(histHits.map((f) => `${f.id}/${f.file}`)));
}

// ================================================================ T4 — DEP-003 calibration
{
  const dir = join(TMP, "t4");
  mkdirSync(dir, { recursive: true });
  // positive: offline edit-distance evidence must NEVER be HIGH (v1.2 T4 spec);
  // "expres" (distance 1 from express) is still flagged — as a LOW review note
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "t4a", private: true, dependencies: { expres: "4.18.0", nitro: "2.0.0", qs: "6.13.0" } }));
  const rp = run(["scan", dir, "--format", "json"]);
  const d3 = (rp.json?.findings ?? []).filter((f) => f.id === "DEP-003");
  check("T4+ typosquat (expres) flagged LOW via CLI; nitro/qs (extended popular list) NEVER flagged",
    d3.length === 1 && d3[0].evidence.masked === "expres" && d3[0].severity === "low" && d3[0].confidence === "low"
    && !rp.json?.findings.some((f) => f.id === "DEP-003" && f.severity === "high"),
    JSON.stringify(rp.json?.findings.filter((f) => f.id === "DEP-003")));
  // clean: the exact popular name is never flagged
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "t4b", private: true, dependencies: { express: "4.18.0" } }));
  const rc = run(["scan", dir, "--format", "json"]);
  check("T4= exact popular name (express) → no DEP-003",
    rc.code === 0 && !rc.json?.findings.some((f) => f.id === "DEP-003"));
}

// ================================================================ T5 — DEP-004 aggregated + lockfiles
{
  const dir = join(TMP, "t5");
  mkdirSync(dir, { recursive: true });
  // positive: no lockfile, unknown dep → exactly ONE aggregated DEP-004 (the old code emitted one per dep)
  // NOTE: the package name must NOT match the directory basename ("demo-app" ≠
  // "t5") — isWorkspaceMember treats a matching basename as a workspace member
  // and would silently suppress DEP-004.
  writeFileSync(join(dir, "package.json"),
    JSON.stringify({ name: "demo-app", private: true, dependencies: { "some-madeup-util": "^1.0.0", "another-unknown-thing": "^2.0.0" } }));
  const rp = run(["scan", dir, "--format", "json"]);
  check("T5+ no lockfile → exactly ONE aggregated DEP-004 (medium)", (() => {
    const d = (rp.json?.findings ?? []).filter((f) => f.id === "DEP-004");
    return d.length === 1 && d[0].severity === "medium" && /some-madeup-util/.test(d[0].evidence.masked) && /another-unknown-thing/.test(d[0].evidence.masked);
  })(), JSON.stringify((rp.json?.findings ?? []).filter((f) => f.id === "DEP-004")));
  // clean: pnpm lockfile suppresses the false storm
  writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
  const rc = run(["scan", dir, "--format", "json"]);
  check("T5= pnpm-lock.yaml present → no DEP-004",
    rc.code === 0 && !rc.json?.findings.some((f) => f.id === "DEP-004"));
}

// ================================================================ T6 — hygiene (SAST-002 / TAINT-001)
{
  const dir = join(TMP, "t6");
  mkdirSync(join(dir, "app", "api", "fetch-url"), { recursive: true });
  mkdirSync(join(dir, "app", "components"), { recursive: true });
  // positive: raw __html + unguarded fetch → findings (MEDIUM taint)
  writeFileSync(join(dir, "app", "components", "Raw.tsx"), `export default (p: any) => <div dangerouslySetInnerHTML={{ __html: p.body }} />;\n`);
  writeFileSync(join(dir, "app", "api", "fetch-url", "route.ts"), `export async function GET(req: Request) {\n  const t = new URL(req.url).searchParams.get("t") ?? "";\n  const r = await fetch(t);\n  return new Response(await r.text());\n}\n`);
  const rp = run(["scan", dir, "--format", "json"]);
  check("T6+ raw __html → SAST-002; unguarded fetch → TAINT-001 MEDIUM",
    rp.json?.findings.some((f) => f.id === "SAST-002") && rp.json?.findings.some((f) => f.id === "TAINT-001" && f.severity === "medium"),
    JSON.stringify(rp.json?.findings.map((f) => `${f.id}/${f.severity}`)));

  // clean: DOMPurify flow + allowlisted fetch → NO medium findings from these rules
  // (the positive Raw.tsx fixture is removed first — it is deliberately dirty)
  rmSync(join(dir, "app", "components", "Raw.tsx"), { force: true });
  writeFileSync(join(dir, "app", "components", "Safe.tsx"), `import DOMPurify from "dompurify";\nexport default (p: any) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(p.body) }} />;\n`);
  writeFileSync(join(dir, "app", "api", "fetch-url", "route.ts"),
    `const ALLOWED_HOSTS = ["api.github.com"];\nexport async function GET(req: Request) {\n  const t = new URL(req.url).searchParams.get("t") ?? "";\n  const h = new URL(t).host;\n  if (!ALLOWED_HOSTS.includes(h)) return new Response("no", { status: 400 });\n  const r = await fetch(t);\n  return new Response(await r.text());\n}\n`);
  const rc = run(["scan", dir, "--format", "json"]);
  check("T6= DOMPurify flow → no SAST-002", !rc.json?.findings.some((f) => f.id === "SAST-002"));
  check("T6= allowlisted fetch → TAINT-001 at LOW only (visible, never medium)",
    !(rc.json?.findings ?? []).some((f) => f.id === "TAINT-001" && f.severity !== "low")
    && rc.json?.findings.some((f) => f.id === "TAINT-001" && f.severity === "low"),
    JSON.stringify((rc.json?.findings ?? []).filter((f) => f.id === "TAINT-001")));
}

// ================================================================ T7 — walk skip accounting (v1.4 contract)
// v1.4 (capability E): the oversize skip moved 512KB → 4MB; a 512KB file is
// now analyzed in windows and disclosed via meta.files_windowed. Only >4MB
// still counts as oversize.
{
  const dir = makeRepo("t7-skip", { commit: false });
  writeFileSync(join(dir, "ok.ts"), "export const a = 1;\n");
  writeFileSync(join(dir, "big.txt"), "x".repeat(512 * 1024 + 1));            // windowed — still analyzed
  writeFileSync(join(dir, "huge.txt"), "y".repeat(4 * 1024 * 1024 + 1));      // >4MB — oversize-skipped
  writeFileSync(join(dir, "blob.bin"), Buffer.concat([Buffer.from("PNG"), Buffer.alloc(8, 0)]));
  const r = run(["scan", dir, "--format", "json"]);
  check("T7+ oversize(>4MB)/binary files appear in meta.files_skipped; the 512KB file is WINDOWED (meta.files_windowed), not skipped",
    r.json?.meta?.files_skipped?.oversize === 1 && r.json?.meta?.files_skipped?.binary === 1
    && r.json?.meta?.files_windowed?.length === 1,
    JSON.stringify({ skipped: r.json?.meta?.files_skipped, windowed: r.json?.meta?.files_windowed }));
  // clean: no oversized/binary files → no skip notice
  const dir2 = makeRepo("t7-clean", { commit: false });
  writeFileSync(join(dir2, "ok.ts"), "export const a = 1;\n");
  const r2 = run(["scan", dir2, "--format", "json"]);
  check("T7= clean tree → meta.files_skipped absent", r2.code === 0 && r2.json?.meta?.files_skipped === undefined,
    JSON.stringify(r2.json?.meta?.files_skipped));
}

// ================================================================ T0 — adapters fail-closed
{
  // positive: a requested adapter that cannot run must REFUSE, not fake-clean
  check("T0+ unknown --tools name exits 2", run(["scan", join(ROOT, "tests", "clean", "app"), "--tools", "made-up-scanner"]).code === 2);
  check("T0+ missing binary (gitleaks not installed) exits 2", run(["scan", join(ROOT, "tests", "clean", "app"), "--tools", "gitleaks"]).code === 2,
    "environment-specific: gitleaks assumed absent on the dev image");
  // clean: without --tools nothing adapter-related runs or appears
  const rc = run(["scan", join(ROOT, "tests", "clean", "app"), "--format", "json"]);
  check("T0= default run: no adapter meta, exit 0", rc.code === 0
    && rc.json?.meta?.adapters_used === undefined && rc.json?.meta?.adapters_requested === undefined);
}

// ---- report ----
console.error(`\nPHASE-1 REGRESSION: ${PASS} passed, ${FAILS.length} failed`);
if (FAILS.length) {
  for (const f of FAILS) console.error(`  FAILED: ${f}`);
  process.exit(1);
}
