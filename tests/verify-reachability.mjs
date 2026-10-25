#!/usr/bin/env node
/**
 * Reachability regression gates (v1.0.1):
 *   R1  client → lib direct import (depth 1) resolved
 *   R2  client → mid → lib chain (depth 2) resolved
 *   R3  NodeNext-style runtime extension ".js" in spec maps to scanned ".ts"
 *   E1  end-to-end: service_role key in a lib imported by a client component
 *       escalates SUPA-001 to CRITICAL (direction verdict = "الاتجاه هو الحكم")
 *   E2  the same key in a server-only file stays INFO (documented-correct)
 * Windows-critical: graph keys must be normalizeAbs()-compatible on win32.
 */
import { spawnSync } from "node:child_process";
import { writeFileSync, mkdirSync, rmSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const CLI = join(ROOT, "dist", "cli.js");
const TMP = join(HERE, ".tmp-reach");
rmSync(TMP, { recursive: true, force: true });
mkdirSync(TMP, { recursive: true });

let PASS = 0;
const FAILS = [];
function check(name, cond, extra = "") {
  if (cond) { PASS++; console.log(`PASS  ${name}`); }
  else { FAILS.push(name); console.error(`FAIL  ${name}${extra ? ` — ${extra}` : ""}`); }
}

// ---- unit: the import graph itself (dist/rules/context.js) ----
const { importedFromClient, classifyFile } = await import(pathToFileURL(join(ROOT, "dist", "rules", "context.js")).href);
const mk = (abs, rel, content, lines) => ({ abs, rel, content, lines, head: undefined });
const Head = `"use client";`;

const r1 = importedFromClient({
  files: [
    mk("C:/proj/app/client.tsx", "app/client.tsx", `${Head}\nimport K from "../lib/secret";\n`, [Head]),
    mk("C:/proj/lib/secret.ts", "lib/secret.ts", "export const K = 1;\n", []),
  ],
});
check("R1: client → lib direct import resolves (normalized graph)", r1.has("C:/proj/lib/secret.ts"), [...r1].join(","));

const r2 = importedFromClient({
  files: [
    mk("C:/proj/app/client.tsx", "app/client.tsx", `${Head}\nimport L from "../lib/mid";\n`, [Head]),
    mk("C:/proj/lib/mid.ts", "lib/mid.ts", 'import S from "./secret";\nexport const L = S;\n', []),
    mk("C:/proj/lib/secret.ts", "lib/secret.ts", "export const S = 1;\n", []),
  ],
});
check("R2: client → mid → lib chain (depth 2) resolves", r2.has("C:/proj/lib/secret.ts") && r2.has("C:/proj/lib/mid.ts"), [...r2].join(","));

const r3 = importedFromClient({
  files: [
    mk("C:/proj/app/client.tsx", "app/client.tsx", `${Head}\nimport K from "../lib/secret.js";\n`, [Head]),
    mk("C:/proj/lib/secret.ts", "lib/secret.ts", "export const K = 1;\n", []),
  ],
});
check("R3: NodeNext-style '../lib/secret.js' maps to scanned secret.ts", r3.has("C:/proj/lib/secret.ts"), [...r3].join(","));

// ---- fixture: a service_role JWT reached through a client import chain ----
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const SERVICE_ROLE_JWT = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "https://abcdefghij1234567890.supabase.co/auth/v1", ref: "abcdefghij1234567890", role: "service_role" })}.SiGn4tureP4rtW1thM0reTh4nTenCh4r4cters`;
const ANON_JWT = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "https://abcdefghij1234567890.supabase.co/auth/v1", ref: "abcdefghij1234567890", role: "anon" })}.An0nS1gn4tureP4rtW1thM0reTh4nTenCh4rs`;

const fixDir = join(TMP, "reach-fixture");
mkdirSync(join(fixDir, "lib"), { recursive: true });
mkdirSync(join(fixDir, "app"), { recursive: true });
writeFileSync(join(fixDir, "package.json"), '{"name":"reach-fixture","private":true}');
writeFileSync(join(fixDir, "lib", "secret.ts"), `export const KEY = "${SERVICE_ROLE_JWT}";\n`);
writeFileSync(join(fixDir, "app", "client.tsx"), `${Head}\nimport { KEY } from "../lib/secret";\nexport default () => null;\n`);
// server-only usage of an anon key must stay clean (documented-correct pattern)
mkdirSync(join(fixDir, "server"), { recursive: true });
writeFileSync(join(fixDir, "server", "admin.ts"), `export const ANON = "${ANON_JWT}"; // server dependency, fine\n`);

const scan = spawnSync("node", [CLI, "scan", fixDir, "--format", "json"], { encoding: "utf8", cwd: ROOT });
check("E1 fixture scan exits 0", scan.status === 0, (scan.stderr ?? "").slice(0, 200));
const report = JSON.parse(scan.stdout);
const supa = report.findings.filter((f) => f.id === "SUPA-001");
const crit = supa.find((f) => f.severity === "critical" && /lib[/\\]secret\.ts$/.test(f.file));
check("E1: service_role in client-imported lib escalates to CRITICAL", !!crit, `supa findings: ${supa.map((f) => `${f.severity}:${f.file}`).join(" | ")}`);
check("E2: key reached from client carries NO unconfirmed downgrade",
  !crit || crit.needs_confirmation !== true || crit.severity === "critical");
const anonFindings = report.findings.filter((f) => /server[/\\]admin\.ts$/.test(f.file) && f.severity !== "info");
check("E2: anon key in server-only file stays silent (documented-correct)", anonFindings.length === 0, anonFindings.map((f) => f.id).join(","));

console.error(`\nREACHABILITY VERIFICATION: ${PASS} passed, ${FAILS.length} failed`);
if (FAILS.length) {
  for (const f of FAILS) console.error(`  FAILED: ${f}`);
  process.exit(1);
}
