#!/usr/bin/env node
/**
 * Honeypot verification — the regression gate (Plan Section 13):
 * every seeded critical/high MUST be detected; full secret values must NEVER
 * appear anywhere in findings.json (masking contract, Section 9.2).
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const result = JSON.parse(readFileSync(join(here, "honeypot", "findings.json"), "utf8"));

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// [ruleId, minSeverity, fileHint, description]
const SEEDS = [
  ["SUPA-001", "critical", ".env", "service_role key in NEXT_PUBLIC env (seed 1)"],
  ["SUPA-001", "critical", "AdminPanel.tsx", "service_role key hardcoded in client component (seed 2)"],
  ["HDR-001", "high", "lib/api-client.ts", "client sends DB password in header (seed 3)"],
  ["HDR-001", "critical", "app/api/connect/route.ts", "server reads DB creds from headers + sink (seed 4)"],
  ["SEED-001", "critical", "prisma/seed.ts", "default admin password, no env guard (seed 5)"],
  ["SEED-001", "high", "supabase/seed.sql", "SQL INSERT with password column literal (seed 6)"],
  ["FILE-006", "high", ".env.production", "production env file committed (seed 7)"],
  ["SUPA-R01", "high", "0001_init.sql", "missing RLS on public.profiles (seed 8)"],
  ["SUPA-R02", "high", "0002_policies.sql", "USING (true) policy on sensitive table (seed 9)"],
  ["NEXT-002", "high", "TokenStore.tsx", "auth token in localStorage (seed 10)"],
  ["FILE-002", "high", ".npmrc", "npm auth token committed (seed 11)"],
  ["HIST-ENV", "high", ".env.local", "env file committed then deleted (seed 12)"],
  ["ENV-001", "critical", ".env", "committed .env with live values (bonus seed)"],
  // ---- v0.2 seeds (Step 0 data priority: CI pack first) ----
  ["CI-001", "medium", "deploy.yml", "unpinned GitHub Actions (seed 13 — top Step 0 pattern)"],
  ["CI-002", "high", "deploy.yml", "pull_request_target trigger (seed 14)"],
  ["CI-003", "high", "deploy.yml", "script injection via event data (seed 15)"],
  ["CI-004", "high", "deploy.yml", "permissions write-all (seed 16)"],
  ["DOCKER-001", "medium", "Dockerfile", "container runs as root (seed 17)"],
  ["DOCKER-002", "medium", "Dockerfile", "FROM :latest (seed 18)"],
  ["DOCKER-003", "high", "Dockerfile", "secret via ARG (seed 19)"],
  ["CRYPTO-001", "high", "lib/auth.ts", "Math.random security material (seed 20 — promoted by Step 0)"],
  ["DEP-002", "high", "package.json", "known-malicious dependency (seed 21)"],
  ["DEP-003", "high", "package.json", "typosquat candidate (seed 22)"],
  ["DEP-004", "medium", "package.json", "unresolved + no lockfile (seed 23)"],
  ["SUPA-R06", "medium", "0003_depth2.sql", "unscoped policy on sensitive table (seed 24)"],
  ["SUPA-R07", "medium", "0003_depth2.sql", "storage bucket without object RLS (seed 25)"],
  ["SUPA-R08", "high", "config.toml", "edge function verify_jwt=false (seed 26)"],
  ["NEST-001", "high", "app.controller.ts", "unguarded NestJS controller (seed 27)"],
  ["NEST-002", "medium", "main.ts", "CORS wildcard (seed 28)"],
  ["NEST-003", "medium", "main.ts", "helmet missing (seed 29)"],
  ["NEST-004", "medium", "main.ts", "no rate limiting (seed 30)"],
  // ---- v0.3 seeds (rule packs II + taint-lite + agent environment) ----
  ["LOGS-001", "high", "lib/logline.ts", "JWT literal written to logs (seed 31)"],
  ["AUTH-001", "high", "app/api/admin/stats/route.ts", "middleware matcher gap — mutating route uncovered (seed 32)"],
  ["SUPA-002", "high", "0004_usermeta.sql", "user_metadata in RLS policy (seed 33)"],
  ["SUPA-003", "high", "admin-export/index.ts", "edge function service_role without caller auth (seed 34)"],
  ["WEBHOOK-001", "high", "webhooks/checkout", "webhook without signature verification (seed 35)"],
  ["MASS-001", "high", "app/api/profile/route.ts", "request body into DB write without whitelist (seed 36)"],
  ["JWT-001", "high", "lib/tokencheck.ts", "jwt.decode feeding a role decision (seed 37)"],
  ["JWT-002", "high", "lib/tokencheck.ts", "algorithms none + ignoreExpiration (seed 38)"],
  ["SWAGGER-001", "medium", "main.ts", "Swagger served without production guard (seed 39)"],
  ["WS-001", "high", "events.gateway.ts", "Socket.IO gateway without auth (seed 40)"],
  ["TAINT-001", "medium", "app/api/fetch-url/route.ts", "SSRF via user URL (seed 41)"],
  ["TAINT-002", "medium", "app/api/go/route.ts", "open redirect (seed 42)"],
  ["TAINT-003", "medium", "files.controller.ts", "path traversal via @Param (seed 43)"],
  ["TAINT-004", "medium", "app/api/convert/route.ts", "command injection (seed 44)"],
  ["TAINT-005", "medium", "files.controller.ts", "reflected XSS in server-rendered HTML (seed 45)"],
  ["AGENT-001", "medium", ".mcp.json", "unpinned MCP server package (seed 46)"],
  ["AGENT-002", "high", ".mcp.json", "literal secret in agent config (seed 47)"],
  ["AGENT-003", "high", ".claude/settings.json", "Bash(*) permission wildcard (seed 48)"],
  ["AGENT-004", "medium", ".claude/settings.json", "hook running npx @latest (seed 49)"],
];

// planted secret values — must NOT appear in any output.
// Values are derived from the fixtures themselves (deterministic, no /tmp dependency).
function serviceRoleFromFixture() {
  const env = readFileSync(join(here, "honeypot", "app", ".env"), "utf8");
  const m = env.match(/^NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=(.+)$/m);
  return m ? m[1].trim() : "";
}
function jwtLiteralsFrom(rel) {
  const content = readFileSync(join(here, "honeypot", "app", rel), "utf8");
  return [...content.matchAll(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g)].map((m) => m[0]);
}

const MUST_BE_MASKED = [
  serviceRoleFromFixture(),
  ...jwtLiteralsFrom("app/components/AdminPanel.tsx"),
  "Pr0dDBP@ssw0rd!",
  "admin123",
  "Sup3rSeed!",
  "Hunter2Prod!",
  "npm_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsT",
  "OldPassw0rd!",
  "sbp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV",
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzZWVkLTMxIn0.Z0VF8xK2mQ0zqLw2vNfHk1YtP5jR9sUuB3oX7eCdA6w",
].filter(Boolean);

const raw = JSON.stringify(result);
let failures = 0;

for (const secret of MUST_BE_MASKED) {
  if (raw.includes(secret)) {
    console.error(`MASKING VIOLATION: full secret value present in findings.json (${secret.slice(0, 6)}…)`);
    failures++;
  }
}

for (const [ruleId, minSeverity, fileHint, desc] of SEEDS) {
  const hit = result.findings.find(
    (f) => f.id === ruleId && f.file.includes(fileHint) && SEVERITY_RANK[f.severity] <= SEVERITY_RANK[minSeverity]
  );
  if (hit) {
    console.log(`PASS  ${desc} → ${hit.id}/${hit.severity} @ ${hit.file}:${hit.line}`);
  } else {
    console.error(`FAIL  ${desc} — expected ${ruleId}>=${minSeverity} in ${fileHint}`);
    failures++;
  }
}

// score sanity
console.log(`\nscore: ${result.score}/100 (${result.grade}) · summary: ${JSON.stringify(result.summary)}`);
if (result.summary.critical < 4) { console.error("FAIL  expected >=4 critical findings"); failures++; }
if (result.coverage.classes_not_covered.length < 5) { console.error("FAIL  classes_not_covered missing"); failures++; }
if (result.meta.no_exec !== true) { console.error("FAIL  no_exec contract violated"); failures++; }

// ---- v0.2 contracts ----
if (!result.target.paths || result.target.paths.length !== 2) {
  console.error("FAIL  multi-root: expected 2 roots in target.paths");
  failures++;
}
if (!result.portfolio || result.portfolio.length !== 2) {
  console.error("FAIL  multi-root: expected per-root portfolio");
  failures++;
} else {
  console.log(`portfolio: ${result.portfolio.map((p) => `${p.path} → ${p.score}/${p.grade}`).join(" · ")}`);
}
if (!result.inventory || !result.inventory.routes?.length) {
  console.error("FAIL  inventory: missing routes");
  failures++;
} else {
  console.log(`inventory: ${result.inventory.routes.length} routes · ${result.inventory.controllers.length} controllers · ${result.inventory.supabase.tables.length} tables · ${result.inventory.supabase.edge_functions.length} edge functions`);
}

if (failures) {
  console.error(`\nHONEYPOT VERIFICATION: ${failures} failure(s)`);
  process.exit(1);
}
console.log("\nHONEYPOT VERIFICATION: ALL SEEDS DETECTED — masking contract intact");
