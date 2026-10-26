# BENCHMARKS.md — measured results only

> Policy: **no number appears here without a measurement.** Every value below was produced by
> `scripts/measure-benchmarks.mjs` in a single run on the environment recorded below. Unmeasurable
> entries are marked PENDING — they are never estimated. Honeypot numbers are a **self-test** (we
> planted what we catch); the external suites are the honest recall signal and are labeled as such.

| Environment | Value |
|---|---|
| Tool version | 1.2.0 |
| Tool commit (provenance) | 5d1ad3224c211173d4149633f00ebd63ee5a86e6 (+uncommitted working tree: docs/bench edits) |
| Node | v22.13.0 |
| Platform | win32 · 4 vCPU |
| Command | `npm run build && node scripts/measure-benchmarks.mjs` |
| Measured on | 2026-10-26 |

## Results

| Measurement | Result | Status |
|---|---|---|
| Honeypot recall (49 planted checks, 2 roots — self-test) | 49/49 detected, masking contract intact | measured |
| Honeypot findings by rule id | {"ENV-001":2,"SUPA-001":2,"SEC-002":1,"HDR-001":7,"SEED-001":2,"AGENT-003":1,"HIST-001":2,"NEXT-001":1,"HIST-ENV":1,"HIST-007":2,"FILE-006":1,"HIST-003":1,"SEC-008":1,"CI-002":1,"CI-004":1,"CI-003":1,"AGENT-002":1,"FILE-002":1,"AUTH-001":4,"SAST-003":1,"MASS-001":1,"WEBHOOK-001":1,"NEXT-002":2,"DOCKER-003":1,"CRYPTO-001":2,"LOGS-001":1,"JWT-001":1,"JWT-002":4,"DEP-002":1,"SUPA-003":1,"SUPA-R08":1,"SUPA-R01":2,"SUPA-R02":3,"SUPA-002":1,"NEST-001":2,"WS-001":1,"AGENT-001":4,"AGENT-004":3,"CI-001":2,"NEXT-004":4,"TAINT-004":1,"TAINT-001":1,"TAINT-002":1,"DOCKER-001":1,"DOCKER-002":1,"DEP-004":2,"SUPA-R06":3,"SUPA-R07":1,"NEST-002":2,"TAINT-003":1,"TAINT-005":1,"NEST-003":1,"NEST-004":1,"SWAGGER-001":1,"HIST-011":2,"DEP-003":1} | measured |
| Honeypot multi-root scan wall time (2 roots, includes setup) | 2.26s | measured |
| Clean corpus false positives (must be 0 above threshold) | 0 findings above threshold — score 100, grade A | measured |
| Single-root scan wall time (Next.js+Supabase honeypot app) | 0.64s | measured |
| acceptance v0.2 (init-ci pins, determinism, workspaces, cross-root CRITICAL, artifacts) | ALL PASS (exit 0) | measured |
| acceptance v0.3 (AI review + verifier, authz quarantine, taint canaries, hook, SKILL contract) | ALL PASS (exit 0) | measured |
| acceptance v0.4 (URL Mode: L1 passivity, ownership gates, Supabase probe, determinism, renderers) | 47 gates passed, 0 failed | measured |
| acceptance v1.0 (rules-lock, init-zap, restricted differential IDOR, packaging/SBOM, install smoke) | 45 gates passed, 0 failed | measured |
| Mode 2 honeypot (planted URL classes incl. masking) | 33 checks passed, 0 failed | measured |
| URL Mode L1 passive scan wall time (local fixture) | 0.28s | measured |
| URL Mode L3 full scan wall time (L2 probes + Supabase detect + differential IDOR, local fixture) | 2.42s · 47 requests · score 0/F | measured |
| OWASP NodeGoat (sanity — general layers) | 28 findings (score 0/F) · {"SEC-007":1,"DEP-001":9,"MASS-001":1,"HIST-005":1,"DEP-002":2,"CI-004":2,"CI-001":6,"TAINT-006":3,"TAINT-002":1,"HIST-011":1,"DEP-003":1} · 3.824s incl. clone | measured |
| OWASP Juice Shop (sanity — general layers) | 120 findings (score 0/F) · {"SEC-007":3,"CI-002":1,"CRYPTO-001":2,"SAST-001":13,"SEC-009":37,"JWT-001":2,"MASS-001":1,"SAST-003":8,"CI-004":13,"CI-001":7,"SWAGGER-001":10,"DOCKER-002":3,"FILE-001":2,"JWT-002":8,"WS-001":1,"TAINT-001":1,"TAINT-003":5,"DOCKER-001":1,"HIST-011":1,"DEP-003":1} · 14.685s incl. clone | measured |

## Reading guide

- **Honeypot recall** = self-test: deterministic proof the shipped rules catch every planted class (49 checks, 2 roots).
- **Clean corpus** = false-positive control: a clean project must finish at 100/A with zero findings above threshold.
- **Acceptance gates** = the frozen plan scopes (v0.2 CI/determinism, v0.3 AI+authz+hook, v0.4 URL Mode, v1.0 supply chain + restricted active scope) — every gate must pass.
- **External suites** (NodeGoat / Juice Shop) = classic vulnerable Node apps — they exercise the general layers (secrets, SAST, deps, CI) only; the Supabase/Next/Nest playbooks have no target there. Treat them as sanity, not as framework-playbook recall.
- **Wall times** are recorded for transparency of scale, not as speed claims.


