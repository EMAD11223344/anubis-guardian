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
  { id: "SEC-010", layer: "L1 secrets — credential assignment in configuration formats (properties/ini/toml/tf/yaml/json/python/go/shell; dev round)", applicable: () => true },
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
  { id: "AUTHZ-001/002", layer: "L5 capability A — RBAC/authz pack (v1.4)", applicable: () => true },
  { id: "TEN-001/002", layer: "L5 capability B — multi-tenant isolation pack (v1.4/1.5: by-ID mutations AND reads)", applicable: () => true },
  { id: "LEAK-001..003", layer: "L5 capability C — data-leakage pack (v1.4/1.5: whole-object query-result flows)", applicable: () => true },
  { id: "RES-001..003", layer: "L5 capability D — resource-exhaustion pack (v1.4/1.5: outbound timeout absence)", applicable: () => true },
  { id: "UPLOAD-001..003", layer: "L5 capability F — upload-security pack (v1.4)", applicable: () => true },
  { id: "DEP-001..005", layer: "L3 dependency audit", applicable: () => true },
  { id: "CI-001..004", layer: "L5 ci/supply-chain pack (Step 0: 22% of sample)", applicable: () => true },
  { id: "DOCKER-001..003", layer: "L5 docker pack", applicable: () => true },
  { id: "FB-001", layer: "L5 infra/config pack — Firebase security rules public write (dev round)", applicable: () => true },
  { id: "TF-001", layer: "L5 infra/config pack — Terraform public-read storage ACL (dev round)", applicable: () => true },
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
  "RBAC/authz review pack (AUTHZ-001 missing-evidence tier + AUTHZ-002 client-decided authorization, handler-body scoped, v1.4)",
  "multi-tenant isolation hints (TEN-001/002 — fires only where the repo declares tenant entities; every finding names the invisible enforcement layers it cannot see, v1.4)",
  "data-leakage review pack (LEAK-001 credential fields in responses, LEAK-002 PII in logs, LEAK-003 whole-object query-result serialization — masked/cleanup/projection shapes stay silent, v1.4/1.5)",
  "resource-exhaustion review pack (RES-001 request-built regexes via bounded flow, RES-002 pagination-less collection reads in handlers, RES-003 outbound requests without visible timeout/cancellation in handlers, v1.4/1.5)",
  "upload-security pack (UPLOAD-001 request-derived writes into served dirs, UPLOAD-002 limit-less upload parsers, UPLOAD-003 guard-less archive extraction, v1.4)",
  "large-file windowed scanning (files >512KB analyzed in line-boundary windows to 4MB with overlap; v1.5 adds a mandatory-progress guarantee for giant-line files — every supported byte is covered or the window disclosed via meta.files_windowed)",
  "configuration-format credential assignment (SEC-010 — tokenized credential names with quoted or bare values in properties/ini/toml/tf/yaml/json/python/go/shell files; env reads, ${...} interpolation and var references stay clean)",
  "infra/config-as-policy (FB-001 Firebase security rules granting write verbs with `if true` — read-only public stays a LOW review note; TF-001 Terraform public-read storage ACL)",
];

export const CLASSES_NOT_COVERED = [
  "deep multi-file taint flows (single-file + bounded import chase by design — v1.4 adds cross-file imported-helper SQL-build checks, not a full call graph)",
  "IDOR differential testing / authz matrix execution (v1.0 — restricted; the generated tests are run by the owner, never the tool)",
  "URL Mode L1–L3: security headers, exposed files, live probing (v0.4 — after Mode 1 completes)",
  "cookie HttpOnly deep verification beyond the flag-level check + full CSRF semantics (heuristic only)",
  "business & payment logic (human review by design)",
  "DAST / wide fuzzing (non-goal by design)",
  "compliance SOC2/PCI/HIPAA (non-goal by design)",
  "non-JS/TS SAST (non-goal — Python/Go/Java/other code-level injection, debug-mode and randomness patterns are NOT analyzed; the config-file layers SEC-010/FB-001/TF-001 and the Semgrep adapter cover configuration surfaces and opt-in code depth)",
  "non-npm dependency auditing (bundled advisory snapshot + lockfile parsing are npm-ecosystem-only — requirements.txt / pyproject / go.mod / cargo manifests are inventoried but not version-audited)",
  "§A honesty: policy-level RBAC (role/permission MODELS) and middleware/RLS enforcement are invisible — AUTHZ gives call-shape evidence only, never a confirmed enforcement gap",
  "§B honesty: tenant isolation enforcement (RLS policies, ORM global scopes, service-layer guards) is invisible — TEN findings are review prompts gated on repo-declared tenant entities only",
  "§C honesty: runtime VALUES are unobservable — LEAK cannot distinguish a real secret from a hash/expiring token. Whole-object flows are tracked only when the response argument resolves through a bounded chase to a wide-query shape (LEAK-003, v1.5): re-shaped/nested objects and non-identifier arguments remain invisible",
  "§D honesty: unbounded loops over request-controlled arrays are NOT detected; RES-003 timeout evidence is call-site only (shared clients/wrappers are invisible). Scanner self-resilience is validated separately (adversarial battery gates)",
  "§F honesty: serving-layer behavior (content-type/delivery of stored uploads) and helpers hiding archive/limit configuration are invisible — UPLOAD findings are review prompts",
];
