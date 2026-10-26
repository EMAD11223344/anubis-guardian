#!/usr/bin/env node
/**
 * Phase-2 fixture-level regression suite (v1.2 — detection gaps).
 * Positive + clean cases per task, exercised through the real CLI:
 *
 *   T8  SQL injection:       6 unsafe dynamic-SQL variants → SAST-001 (HIGH when req-traced) ·
 *                            $1 placeholder + $queryRaw tagged template → SILENT
 *   T9  code execution:      eval(req.body.code) → TAINT-006 · literal eval → silent
 *   T10 signing secrets:     jwt.sign 'secret123' → JWT-003 · process.env → silent
 *   T11 seed paths:          seeds/001-users.js + scripts/create-admin.ts → SEED-001 ·
 *                            placeholder passwords + *.test.* → silent
 *   T12 header value-flow:   x-pg-secret → new Pool({connectionString}) → HDR-001 CRITICAL ·
 *                            x-request-id/Authorization/forwarded → silent
 *   T13 redirect sinks:      redirect(<query value>) → TAINT-002 · literal/guarded → silent
 *   T14 dependency recall:   transitive handlebars@4.5.0 via lockfile → DEP-001 ·
 *                            patched moment@2.31.0 → silent
 * Fixtures live under os.tmpdir() (outside any git repo — see phase-1 lesson).
 * Exit discipline: any failure → process.exit(1).
 */
import { spawnSync } from "node:child_process";
import { writeFileSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..");
const CLI = join(ROOT, "dist", "cli.js");
const TMP = join(tmpdir(), "anubis-regression-p2");
rmSync(TMP, { recursive: true, force: true });
mkdirSync(TMP, { recursive: true });

let PASS = 0;
const FAILS = [];
const check = (name, cond, extra = "") => {
  if (cond) { PASS++; console.log(`PASS  ${name}`); }
  else { FAILS.push(name); console.error(`FAIL  ${name}${extra ? ` — ${extra}` : ""}`); }
};

/** run the CLI on a fixture dir; returns { code, json } (json only when --output file read) */
function scan(dir, extraArgs = []) {
  const out = join(TMP, "findings.json");
  rmSync(out, { force: true });
  const r = spawnSync(process.execPath, [CLI, "scan", dir, "--format", "json", "--output", out, ...extraArgs],
    { encoding: "utf8", cwd: ROOT, maxBuffer: 64 << 20 });
  let json = null;
  try { json = JSON.parse(readFileSync(out, "utf8")); } catch { /* refusal — no report */ }
  return { code: r.status ?? -1, json, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

const ids = (r, id) => (r.json?.findings ?? []).filter((f) => f.id === id);
const rel = (dir) => dir.slice(TMP.length + 1);

// ---- T8: unsafe dynamic SQL — 6 variants + 2 safe forms --------------------
const t8 = join(TMP, "t8"); mkdirSync(join(t8, "app", "api"), { recursive: true });
writeFileSync(join(t8, "package.json"), JSON.stringify({ name: "t8", version: "1.0.0", dependencies: { "@prisma/client": "*", "pg": "*" } }));
writeFileSync(join(t8, "app", "api", "db.ts"), `
import { PrismaClient } from "@/generated/prisma";
import { Pool } from "pg";
import knexFactory from "knex";
import { sequelize } from "../../lib/db";
const prisma = new PrismaClient();
const pool = new Pool();
const knex = knexFactory({});
export async function v1(req: Request) { return prisma.$queryRawUnsafe(\`SELECT * FROM users WHERE id=\${req.query.id}\`); }
export async function v2(req: Request) { return prisma.$executeRawUnsafe('DELETE FROM users WHERE id=' + req.query.id); }
export async function v3(req: Request) { return pool.query(\`SELECT * FROM users WHERE name='\${req.query.name}'\`); }
export async function v4(req: Request) { return db.query("SELECT * FROM users WHERE name='" + req.query.name + "'"); }
export async function v5(req: Request) { return knex.raw(\`SELECT * FROM users WHERE id=\${req.query.id}\`); }
export async function v6(req: Request) { return sequelize.query(\`SELECT * FROM users WHERE id=\${req.query.id}\`); }
export async function s1(req: Request) { return pool.query('SELECT * FROM users WHERE id=$1', [req.query.id]); }
export async function s2(req: Request) { return prisma.$queryRaw\`SELECT * FROM users WHERE id=\${req.query.id}\`; }
export {}\n`);
let r = scan(t8);
check("T8+ scan exits 0 with findings", r.code === 0 && ids(r, "SAST-001").length > 0);
check("T8+: all 6 unsafe variants detected, req-traced variants HIGH",
  ids(r, "SAST-001").length === 6
  && ids(r, "SAST-001").every((f) => f.severity === "high")
  && new Set(ids(r, "SAST-001").map((f) => f.line)).size === 6,
  JSON.stringify(ids(r, "SAST-001").map((f) => `L${f.line}:${f.severity}`)));
check("T8= safe forms ($1 placeholder + tagged $queryRaw) NOT detected",
  ids(r, "SAST-001").every((f) => ![15, 16].includes(f.line)),
  JSON.stringify(ids(r, "SAST-001").map((f) => `L${f.line}`)));

// ---- T9: code execution ----------------------------------------------------
const t9 = join(TMP, "t9"); mkdirSync(join(t9, "app", "api"), { recursive: true });
writeFileSync(join(t9, "app", "api", "run.ts"), `
export async function POST(req: Request) { return eval(req.body.code); }
export {}\n`);
writeFileSync(join(t9, "app", "api", "ok.ts"), `
export const safe = eval('1 + 1');         // literal constant
// upgrade note: stop using eval(raw) here someday
const msg = "never eval(userInput) in messages";
export {}\n`);
r = scan(t9);
check("T9+: eval(req.body.code) → TAINT-006 detected", ids(r, "TAINT-006").length === 1,
  JSON.stringify(ids(r, "TAINT-006").map((f) => f.file)));
check("T9= literal eval / comment / string mentions stay silent",
  ids(r, "TAINT-006").every((f) => !/ok\.ts$/.test(f.file)) && ids(r, "SAST-003").every((f) => !/ok\.ts$/.test(f.file)));

// ---- T10: hardcoded signing secrets ----------------------------------------
const t10 = join(TMP, "t10"); mkdirSync(join(t10, "lib"), { recursive: true });
writeFileSync(join(t10, "lib", "auth.ts"), `
import jwt from "jsonwebtoken";
const token = jwt.sign({ sub: "1" }, "secret123");
export {}\n`);
writeFileSync(join(t10, "lib", "ok.ts"), `
import jwt from "jsonwebtoken";
const token2 = jwt.verify(served, process.env.JWT_SECRET as string);
export {}\n`);
r = scan(t10);
check("T10+: jwt.sign(_, 'secret123') → JWT-003 high", ids(r, "JWT-003").some((f) => f.severity === "high"));
check("T10= process.env signing secret silent", ids(r, "JWT-003").every((f) => !/ok\.ts$/.test(f.file)));

// ---- T11: SEED-001 path expansion -------------------------------------------
const t11 = join(TMP, "t11"); mkdirSync(join(t11, "seeds"), { recursive: true }); mkdirSync(join(t11, "scripts"), { recursive: true }); mkdirSync(join(t11, "prisma"), { recursive: true });
writeFileSync(join(t11, "seeds", "001-users.js"), "create({ email: 'a@b.io', password: 'Sup3r-Secret-Prod' });\n");
writeFileSync(join(t11, "scripts", "create-admin.ts"), "const password = 'Admin-Default-2024';\n");
writeFileSync(join(t11, "prisma", "seed-admin.ts"), "password: 'Provision-Secret-9',\n");
writeFileSync(join(t11, "seeds", "placeholders.js"), "create({ password: 'changeme-change-me-now' });\n");
writeFileSync(join(t11, "seeds", "001-users.test.ts"), "test('x', () => expect(make({ password: 'Sup3r-Secret-Prod' })).toBe(true));\n");
r = scan(t11);
check("T11+: seeds/001-users.js + scripts/create-admin.ts + prisma/seed-admin.ts → SEED-001",
  ids(r, "SEED-001").some((f) => /001-users\.js$/.test(f.file))
  && ids(r, "SEED-001").some((f) => /create-admin\.ts$/.test(f.file))
  && ids(r, "SEED-001").some((f) => /seed-admin\.ts$/.test(f.file)));
check("T11= placeholder seeds + *.test.* seeds silent",
  ids(r, "SEED-001").every((f) => !/placeholders\.js$/.test(f.file) && !/001-users\.test\.ts$/.test(f.file)),
  JSON.stringify(ids(r, "SEED-001").map((f) => f.file)));

// ---- T12: header value-flow -------------------------------------------------
const t12 = join(TMP, "t12"); mkdirSync(join(t12, "app", "api"), { recursive: true });
writeFileSync(join(t12, "app", "api", "pool.ts"), `
import { Pool } from "pg";
import { headers } from "next/headers";
export async function GET() {
  const h = await headers();
  const secret = h.get("x-pg-secret");
  const pool = new Pool({ connectionString: secret });
  return Response.json(await pool.query("SELECT 1"));
}
export {}\n`);
writeFileSync(join(t12, "app", "api", "ok.ts"), `
import { headers } from "next/headers";
export async function GET() {
  const h = await headers();
  console.log("request id", h.get("x-request-id"));
  const auth = h.get("authorization");
  verifyToken(auth);
  return fetch("https://up.internal/api", { headers: { "x-forwarded-for": h.get("x-forwarded-for") } });
}
export {}\n`);
r = scan(t12);
check("T12+: x-pg-secret → Pool(connectionString) → HDR-001 CRITICAL",
  ids(r, "HDR-001").some((f) => f.severity === "critical" && /pool\.ts$/.test(f.file)),
  JSON.stringify(ids(r, "HDR-001").map((f) => `${f.file}:${f.severity}`)));
check("T12= x-request-id / Authorization / forwarding stays silent",
  ids(r, "HDR-001").every((f) => !/ok\.ts$/.test(f.file)));

// ---- T13: redirect sinks ------------------------------------------------------
const t13 = join(TMP, "t13"); mkdirSync(join(t13, "app", "api", "go"), { recursive: true }); mkdirSync(join(t13, "app", "api", "home"), { recursive: true });
writeFileSync(join(t13, "app", "api", "go", "route.ts"), `
import { redirect } from "next/navigation";
export async function GET(req: Request) {
  const to = new URL(req.url).searchParams.get("next") as string;
  redirect(to);
}
export {}\n`);
writeFileSync(join(t13, "app", "api", "home", "route.ts"), `
import { redirect } from "next/navigation";
export async function GET(req: Request) {
  const to = new URL(req.url).searchParams.get("next") ?? "/home";
  if (!to.startsWith("/") || to.startsWith("//")) redirect("/home");
  redirect(to);
}
export {}\n`);
r = scan(t13);
check("T13+: redirect(<searchParams>) → TAINT-002", ids(r, "TAINT-002").some((f) => /go[\\/]route\.ts$/.test(f.file)));
check("T13= guarded redirect silent", ids(r, "TAINT-002").every((f) => !/home[\\/]route\.ts$/.test(f.file)),
  JSON.stringify(ids(r, "TAINT-002").map((f) => f.file)));

// ---- T14: transitive dependency recall ---------------------------------------
const t14 = join(TMP, "t14"); mkdirSync(t14, { recursive: true });
writeFileSync(join(t14, "package.json"), JSON.stringify({ name: "t14", version: "1.0.0", dependencies: { express: "^4.17.1" } }));
rmSync(join(t14, ".git"), { recursive: true, force: true });
writeFileSync(join(t14, "package-lock.json"), JSON.stringify({
  name: "t14", version: "1.0.0", lockfileVersion: 1, requires: true,
  dependencies: { express: { version: "4.17.1", resolved: "https://example.com/x", dependencies: {
    handlebars: { version: "4.5.0", resolved: "https://example.com/y" },
    qs: { version: "6.5.2", resolved: "https://example.com/z" },
    moment: { version: "2.29.1", resolved: "https://example.com/m" },
    "serialize-javascript": { version: "3.0.0", resolved: "https://example.com/sj" },
  } } },
}));
writeFileSync(join(t14, "index.js"), "const app = require('express')();\napp.listen(3000);\n");
r = scan(t14);
check("T14+: TRANSITIVE handlebars@4.5.0 / qs@6.5.2 / moment@2.29.1 / serialize-javascript@3.0.0 → DEP-001 from the lockfile",
  ["handlebars@4.5.0", "qs@6.5.2", "moment@2.29.1", "serialize-javascript@3.0.0"]
    .every((v) => ids(r, "DEP-001").some((f) => f.evidence.masked.startsWith(v) && f.file === "package-lock.json")),
  JSON.stringify(ids(r, "DEP-001").map((f) => `${f.evidence.masked}@${f.file}`)));
check("T14= patched comparator silent", (() => {
  const clean = join(TMP, "t14clean");
  mkdirSync(clean, { recursive: true });
  writeFileSync(join(clean, "package.json"), JSON.stringify({ name: "t14c", version: "1.0.0", dependencies: { express: "^4.21.0" } }));
  writeFileSync(join(clean, "package-lock.json"), JSON.stringify({
    name: "t14c", version: "1.0.0", lockfileVersion: 1, requires: true,
    dependencies: { express: { version: "4.21.2", dependencies: { moment: { version: "2.31.0" } } } },
  }));
  writeFileSync(join(clean, "index.js"), "const app = require('express')();\napp.listen(3000);\n");
  const cr = scan(clean);
  return ids(cr, "DEP-001").every((f) => f.file !== "package-lock.json");
})());
// snapshot provenance + staleness meta (T14)
check("T14 meta: advisory_snapshot_date present + NOT stale", r.json?.meta?.advisory_snapshot_date === "2026-10" && r.json?.meta?.advisory_snapshot_stale === undefined);

// ---------------------------------------------------------------------------
console.error(`\nPHASE-2 REGRESSION: ${PASS} passed, ${FAILS.length} failed`);
if (FAILS.length) {
  for (const f of FAILS) console.error(`  FAILED: ${f}`);
  process.exit(1);
}
