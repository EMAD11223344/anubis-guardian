/**
 * Coverage registry — single source of truth for `checks_run / checks_applicable`
 * and `classes_covered / classes_not_covered` (Plan Sections 1.1 + 8, v1.6).
 * classes_not_covered is REQUIRED in every report — honesty about the grade.
 */

export interface CheckDef {
  id: string;
  layer: string;
  applicable: (fw: Record<string, boolean>, git: boolean) => boolean;
}

export const CHECKS: CheckDef[] = [
  { id: "recon", layer: "Phase 0", applicable: () => true },
  { id: "SEC-001..009", layer: "L1 secrets", applicable: () => true },
  { id: "SUPA-001", layer: "L1 secrets", applicable: () => true },
  { id: "ENV-001", layer: "L1/L2", applicable: () => true },
  { id: "HDR-001", layer: "L1 secrets", applicable: () => true },
  { id: "SEED-001", layer: "L1 secrets", applicable: () => true },
  { id: "FILE-001..006", layer: "L2 sensitive files", applicable: () => true },
  { id: "HIST-001..011", layer: "L2 git history", applicable: (_fw, git) => git },
  { id: "SUPA-R01..R08", layer: "L5 supabase playbook", applicable: (fw) => Boolean(fw.supabaseMigrations || fw.supabase) },
  { id: "NEXT-001..004", layer: "L5 nextjs playbook", applicable: (fw) => Boolean(fw.nextjs) },
  { id: "NEST-001..004", layer: "L5 nestjs playbook", applicable: (fw) => Boolean(fw.nestjs) },
  { id: "SAST-001..004", layer: "L4 sast-light", applicable: () => true },
  { id: "CRYPTO-001", layer: "L5 rule pack (Step 0: 11% of sample)", applicable: () => true },
  { id: "TAINT-001..006", layer: "L4 taint-lite (v0.3 — MEDIUM cap, generated canary confirmation)", applicable: () => true },
  { id: "LOGS-001", layer: "L5 rule packs II (v0.3)", applicable: () => true },
  { id: "SUPA-002/003", layer: "L5 supabase depth III (v0.3)", applicable: (fw) => Boolean(fw.supabaseMigrations || fw.supabase) },
  { id: "AUTH-001", layer: "L5 nextjs depth II (v0.3)", applicable: (fw) => Boolean(fw.nextjs) },
  { id: "NEXT-005", layer: "L5 nextjs CSRF heuristic (v0.3)", applicable: (fw) => Boolean(fw.nextjs) },
  { id: "PRISMA-001", layer: "L5 multi-tenancy hint (v0.3, low-confidence)", applicable: () => true },
  { id: "MASS-001", layer: "L5 rule packs II (v0.3)", applicable: () => true },
  { id: "WS-001", layer: "L5 rule packs II (v0.3)", applicable: () => true },
  { id: "WEBHOOK-001", layer: "L5 rule packs II (v0.3)", applicable: () => true },
  { id: "JWT-001..003", layer: "L5 rule packs II (v0.3) + hardcoded signing secrets (v1.2 T10)", applicable: () => true },
  { id: "SWAGGER-001", layer: "L5 rule packs II (v0.3)", applicable: () => true },
  { id: "AGENT-001..004", layer: "L5 agent-environment checks (v0.3, ECC-inspired)", applicable: () => true },
  { id: "DEP-001..005", layer: "L3 dependency audit", applicable: () => true },
  { id: "CI-001..004", layer: "L5 ci/supply-chain pack (Step 0: 22% of sample)", applicable: () => true },
  { id: "DOCKER-001..003", layer: "L5 docker pack", applicable: () => true },
  { id: "inventory", layer: "Phase 0 recon inventory", applicable: () => true },
];

/** Declared in Plan Section 1.1 — every report must carry the not-covered list. */
export const CLASSES_COVERED = [
  "secrets (hardcoded keys, service_role by value, DB creds in headers, seeder credentials)",
  "git-history secrets + committed env files",
  "sensitive files (dumps/backups/.npmrc/service-account/tfstate/SSH keys)",
  "supabase RLS (missing RLS, USING(true), views, SECURITY DEFINER, policy scoping, storage.objects, verify_jwt, dashboard drift via --schema)",
  "next.js auth basics (tokens in web storage, cookie flags, NEXT_PUBLIC secrets, mutating endpoints without in-file auth)",
  "nestjs playbook (APP_GUARD-aware unguarded controllers, CORS, helmet, throttler)",
  "sast-light (SQLi concat, XSS dangerous HTML, eval/exec, weak hashing)",
  "crypto (Math.random for tokens/OTPs — CRYPTO-001)",
  "dependencies (CVEs vs bundled advisory snapshot, known-malicious, typosquat, unresolved-no-lockfile, slopsquat via --online)",
  "ci/supply-chain (GitHub Actions SHA pinning, pull_request_target, script injection, permissions; Dockerfile root/:latest/ARG secrets)",
  "recon inventory (routes, server actions, controllers w/ guards, supabase tables/RPC/edge functions, socket events, webhooks)",
  "taint-lite (SSRF, open redirect, path traversal, command injection, reflected XSS — single-file scope, MEDIUM cap, generated canary tests)",
  "rule packs II (LOGS-001, SUPA-002/003, AUTH-001 middleware-matcher gaps, NEXT-005 CSRF heuristic, MASS-001, WS-001, WEBHOOK-001, JWT-001/002, SWAGGER-001, PRISMA-001 hint)",
  "agent environment (unpinned MCP servers, secrets in agent configs, permission wildcards/bypass, unpinned hook commands)",
  "AI review layer with independent verifier (opt-in --ai-review; redaction-before-LLM; verifier-gated; AI findings cap at HIGH)",
  "authz matrix + generated Supertest/Playwright quarantine tests (test-authz — the tool never executes them)",
  "agent guard hook (init-hook — PreToolUse prevention of service_role-in-client, RLS-killing SQL, secrets into .env)",
];

export const CLASSES_NOT_COVERED = [
  "deep multi-file taint flows (taint-lite is single-file + one-level import by design)",
  "IDOR differential testing / authz matrix execution (v1.0 — restricted; the generated tests are run by the owner, never the tool)",
  "URL Mode L1–L3: security headers, exposed files, live probing (v0.4 — after Mode 1 completes)",
  "cookie HttpOnly deep verification beyond the flag-level check + full CSRF semantics (heuristic only)",
  "business & payment logic (human review by design)",
  "DAST / wide fuzzing (non-goal by design)",
  "compliance SOC2/PCI/HIPAA (non-goal by design)",
  "non-JS/TS languages (non-goal — use the Semgrep adapter)",
];
