# BENCHMARKS.md — measured results only

> Policy: **no number appears here without a measurement.** Every value below was produced by
> `scripts/measure-benchmarks.mjs` in a single run on the environment recorded below. Unmeasurable
> entries are marked PENDING — they are never estimated. Honeypot numbers are a **self-test** (we
> planted what we catch); the external OWASP suites report raw finding counts on unlabelled projects
> — **observations, not recall** — and every labelled precision/recall number below is judged against
> the pinned manifest in `benchmarks/corpus/cases.json`, which is self-curated (see reading guide).

| Environment | Value |
|---|---|
| Tool version | 1.5.1 |
| Tool commit (provenance) | a7bf36af21b7375aeb2585eaf89fab8db4c2e1b5 |
| Node | v22.13.0 |
| Platform | win32 · x64 · Windows_NT 10.0.26100 |
| CPU | Intel(R) Core(TM) i5-4690 CPU @ 3.50GHz · 4 cores |
| RAM | 11.9 GB total |
| Command | `npm run build && node scripts/measure-benchmarks.mjs` |
| Trials | single run per measurement (deterministic scan output — reruns are byte-identical); wall times are LOCAL-machine records for scale transparency, never performance guarantees |
| Measured on | 2026-10-28 |

## Results

| Measurement | Result | Status |
|---|---|---|
| Honeypot recall (49 planted checks, 2 roots — self-test) | 49/49 detected, masking contract intact | measured |
| Honeypot findings by rule id | {"ENV-001":2,"SUPA-001":2,"SEC-002":1,"HDR-001":7,"SEED-001":2,"AGENT-003":1,"HIST-001":2,"NEXT-001":1,"HIST-ENV":1,"HIST-007":2,"FILE-006":1,"HIST-003":1,"SEC-008":1,"CI-002":1,"CI-004":1,"CI-003":1,"AGENT-002":1,"FILE-002":1,"AUTH-001":4,"AUTHZ-002":1,"SAST-003":1,"MASS-001":1,"WEBHOOK-001":1,"NEXT-002":2,"DOCKER-003":1,"CRYPTO-001":2,"LOGS-001":2,"JWT-001":1,"JWT-002":1,"DEP-002":1,"SUPA-003":1,"SUPA-R08":1,"SUPA-R01":2,"SUPA-R02":3,"SUPA-002":1,"NEST-001":2,"WS-001":1,"AGENT-001":4,"AGENT-004":3,"CI-001":2,"NEXT-004":4,"TAINT-004":1,"TAINT-001":1,"TAINT-002":1,"AUTHZ-001":1,"DOCKER-001":1,"DOCKER-002":1,"DEP-004":2,"SUPA-R06":3,"SUPA-R07":1,"NEST-002":2,"TAINT-003":1,"TAINT-005":1,"NEST-003":1,"NEST-004":1,"SWAGGER-001":1,"HIST-011":2,"RES-003":2,"DEP-003":1} | measured |
| Honeypot multi-root scan wall time (2 roots, includes setup) | 2.28s | measured |
| Clean corpus false positives (must be 0 above threshold) | 0 findings above threshold — score 100, grade A | measured |
| Labelled corpus recall (self-curated, vulnerable cases) | 17/17 detected at exact expected rule+line+severity | measured |
| Labelled corpus false positives (safe cases, findings above LOW) | 0 — precision 1.00, recall 1.00 | measured |
| Labelled corpus scan (fixture size / duration) | 35 files · 378 lines · 0.82s wall | measured |
| Labelled corpus tolerated LOW advisories on safe files (no score) | 3 (documented LOW no-score review notes adjudicated via manifest "allowed" entries — calibration, not FPs) | measured |
| Single-root scan wall time (Next.js+Supabase honeypot app) | 0.64s | measured |
| acceptance v0.2 (init-ci pins, determinism, workspaces, cross-root CRITICAL, artifacts) | ALL PASS (exit 0) | measured |
| acceptance v0.3 (AI review + verifier, authz quarantine, taint canaries, hook, SKILL contract) | ALL PASS (exit 0) | measured |
| acceptance v0.4 (URL Mode: L1 passivity, ownership gates, Supabase probe, determinism, renderers) | 47 gates passed, 0 failed | measured |
| acceptance v1.0 (rules-lock, init-zap, restricted differential IDOR, packaging/SBOM, install smoke) | 45 gates passed, 0 failed | measured |
| Mode 2 honeypot (planted URL classes incl. masking) | 33 checks passed, 0 failed | measured |
| URL Mode L1 passive scan wall time (local fixture) | 0.28s | measured |
| URL Mode L3 full scan wall time (L2 probes + Supabase detect + differential IDOR, local fixture) | 2.36s · 47 requests · score 0/F | measured |
| OWASP NodeGoat (sanity — general layers) | pin c5cb68a7084e4ae7dcc60e6a98768720a81841e8 · 28 findings (score 0/F) · {"SEC-007":1,"DEP-001":9,"MASS-001":1,"HIST-005":1,"DEP-002":2,"CI-004":2,"CI-001":6,"TAINT-006":3,"TAINT-002":1,"HIST-011":1,"DEP-003":1} · 3.295s incl. clone | measured |
| OWASP Juice Shop (sanity — general layers) | pin 717f5efa886b0417eeecb52378b03cf10567b7e2 · 142 findings (score 0/F) · {"SEC-007":3,"CI-002":1,"CRYPTO-001":2,"SAST-001":26,"SEC-009":37,"JWT-001":2,"UPLOAD-001":1,"MASS-001":1,"CI-004":13,"CI-001":7,"SWAGGER-001":10,"AUTHZ-001":6,"DOCKER-002":3,"FILE-001":3,"JWT-002":2,"WS-001":1,"SAST-003":8,"UPLOAD-003":4,"TAINT-003":7,"TAINT-001":1,"TAINT-006":1,"DOCKER-001":1,"HIST-011":1,"DEP-003":1} · 14.965s incl. clone | measured |
| gitleaks FP-accounting calibration (planted finding on a labelled-safe file is counted) | 1 planted finding(s) on the labelled-safe file counted as FP (expected ≥ 1) | measured |
| gitleaks path normalization (abs vs rel --source equivalence) | identical normalized sets (abs vs rel --source) | measured |
| External tool comparison status | semgrep: executable not runnable on this host — run the adapter command under WSL/Linux/Docker | pending |

## Labelled corpus — per-category precision / recall (self-curated)

Ground truth: `benchmarks/corpus/cases.json` (17 vulnerable + 12 safe cases, each an adjudicated fixture pair; provenance and matching rules are pinned in the manifest itself).

| Category | vulnerable | safe | TP | FN | FP | precision | recall |
|---|---|---|---|---|---|---|---|
| authz-001-missing-authz-evidence | 3 | 2 | 3 | 0 | 0 | 1.00 | 1.00 |
| authz-002-client-controlled-decision | 3 | 2 | 3 | 0 | 0 | 1.00 | 1.00 |
| ssrf-request-json-to-fetch | 3 | 2 | 3 | 0 | 0 | 1.00 | 1.00 |
| tenant-isolation-unscoped-query | 1 | 1 | 1 | 0 | 0 | 1.00 | 1.00 |
| secrets-committed | 3 | 3 | 3 | 0 | 0 | 1.00 | 1.00 |
| ssrf-request-body-to-fetch | 1 | 0 | 1 | 0 | 0 | 1.00 | 1.00 |
| regex-from-request-input | 1 | 0 | 1 | 0 | 0 | 1.00 | 1.00 |
| ssrf-destination-validation | 1 | 1 | 1 | 0 | 0 | 1.00 | 1.00 |
| webhook-signature-verification | 1 | 1 | 1 | 0 | 0 | 1.00 | 1.00 |

### Case-level verdicts

| Case | Kind | Expected | Verdict |
|---|---|---|---|
| authz-001-destructured-params | vulnerable | AUTHZ-001/≥medium@1 | TP |
| authz-001-arrow-route-handler | vulnerable | AUTHZ-001/≥medium@1 | TP |
| authz-002-client-is-admin-decision | vulnerable | AUTHZ-002/≥high@4 | TP |
| authz-002-destructured-role-decision | vulnerable | AUTHZ-002/≥high@3 | TP |
| ssrf-json-to-fetch | vulnerable | TAINT-001/≥medium@3 | TP |
| ssrf-json-alias-to-fetch | vulnerable | TAINT-001/≥medium@4 | TP |
| ssrf-json-destructure-to-fetch | vulnerable | TAINT-001/≥medium@3 | TP |
| tenant-unscoped-destructive-read | vulnerable | TEN-002/≥medium@3 | TP |
| supabase-service-role-key-in-committed-env | vulnerable | SUPA-001/≥critical@3 | TP |
| supabase-service-role-key-in-client-component | vulnerable | SUPA-001/≥critical@6 | TP |
| authz-001-alias-export-handler | vulnerable | AUTHZ-001/≥medium@3 | TP |
| authz-002-property-alias-decision | vulnerable | AUTHZ-002/≥high@4 | TP |
| ssrf-formdata-to-fetch | vulnerable | TAINT-001/≥medium@4 | TP |
| res-001-regex-from-json-body | vulnerable | RES-001/≥medium@3 | TP |
| ssrf-allowlist-name-not-applied | vulnerable | TAINT-001/≥medium@7 | TP |
| webhook-endpoint-unsigned | vulnerable | WEBHOOK-001/≥high@0 | TP |
| supabase-service-role-reachable-via-path-alias | vulnerable | SUPA-001/≥critical@3 | TP |
| safe-authz-001-authz-call-present | safe | no findings above LOW | clean |
| safe-authz-002-ordinary-body-fields | safe | no findings above LOW | clean |
| safe-authz-002-server-state-decision | safe | no findings above LOW | clean |
| safe-ssrf-static-url | safe | no findings above LOW | clean |
| safe-ssrf-host-allowlist | safe | no findings above LOW | clean |
| safe-tenant-scoped-destructive-read | safe | no findings above LOW | clean |
| safe-secrets-placeholder-env | safe | no findings above LOW | clean |
| safe-secrets-server-env-access | safe | no findings above LOW | clean |
| safe-webhook-signature-verified | safe | no findings above LOW | clean |
| safe-secrets-server-only-via-alias | safe | no findings above LOW | clean |
| safe-authz-001-alias-reexport-no-local-handler | safe | no findings above LOW | clean |
| safe-ssrf-set-has-hostname-operation | safe | no findings above LOW | clean |

> What this table supports: fixture lineage, detection behavior at exact lines, and the LOW-allowlist calibration policy. It does **not** support a general-purpose recall claim — the corpus is authored in-repo.

## External tool comparison — identical working-tree snapshots

| Tool | Pin / configuration | Result on identical trees | Status |
|---|---|---|---|
| gitleaks | pinned 8.30.1, default rules (no config), --no-git | corpus: 4 findings · matched labelled secret cases: 3/3 · FP on safe files: 0 · clean-corpus hits: 2 (reviewed: jwt@.env:2, jwt@.env:3) · 0.75s + 0.67s | measured |
| semgrep | version unavailable; config p/owasp-top-ten (community, OSS edition — no paid rules required); adapter contract: `semgrep scan --json --quiet --config p/owasp-top-ten <root>` | probe FAILED (exit null, non-JSON output (empty)) | PENDING — not runnable on this host (observed blocker recorded); maintainer reproduction: WSL/Linux or Docker + the adapter command |

### Comparison scope matrix (what is fairly comparable, and what is pending)

| Vulnerability category | Anubis Guardian | gitleaks | semgrep (p/owasp-top-ten) |
|---|---|---|---|
| Committed secrets | in scope — measured | in scope — measured (matched 3/3; binary pinned 8.30.1) | supported by ruleset — PENDING (not runnable on this host) |
| Authorization: missing evidence / client-controlled decisions (AUTHZ-001/002) | in scope — measured | out of scope (secrets-only tool) | ruleset likely covers A01 — PENDING (not runnable) |
| SSRF / request-data → outbound fetch (TAINT-001) | in scope — measured | out of scope (secrets-only tool) | ruleset likely covers A10 — PENDING (not runnable) |
| Tenant isolation (multi-tenant schema predicates, TEN-001/002) | in scope — measured | out of scope | PENDING (no community-rule equivalent confirmed) |
| Git-history secret leak detection | in scope by design (Layer 2 HIST rules — bounded by repo-containment; environment-dependent, not part of the numeric table) | in scope by default — excluded here (`--no-git` keeps the numeric table on working trees) | n/a |
| Dependency/CVE posture | separate OSV adapter (out of this section's scope) | out of scope | out of scope for this ruleset |

Numerical comparison is complete only where a row says "measured" for BOTH tools; every PENDING cell names the blocker and the maintainer command. No overall winner is claimed from partial scope.
Comparison scope: gitleaks runs with `--no-git`, so the numeric table compares WORKING-TREE secret detection on identical snapshots. Anubis also ships a bounded git-history layer (HIST rules, `git log` confined to the tracked scope of the scanned directory); history findings depend on repository history, which the fixture dirs deliberately do not exercise, so history behavior on BOTH tools is out of the numeric comparison.
Secret-class matching counts a case as matched only when the tool flags the same file at/near the planted line; safe-file and clean-corpus hits count as reviewed false positives.
The two reviewed gitleaks hits on the clean corpus are both JWT blobs in `tests/clean/app/.env`: the anon key (public by design) and a server-side service-role key used as an env-hygiene fixture (Anubis reports that one as a LOW/info advisory, keeping the project at 100/A — a severity/context difference, disclosed as an observation).
Semgrep numbers (when runnable) are classified counts on labelled files only — raw totals across unrelated rulesets are never used as quality measures.

## Reading guide

- **Honeypot recall** = self-test: deterministic proof the shipped rules catch every planted class (49 checks, 2 roots).
- **Labelled corpus P/R** = self-curated fixture pairs with an adjudicated, commit-pinned manifest: precision/recall arithmetic is reproducible, but the labels are ours — treat as a documented self-baseline, not external validation.
- **Clean corpus** = false-positive control: a clean project must finish at 100/A with zero findings above threshold.
- **Acceptance gates** = the frozen plan scopes (v0.2 CI/determinism, v0.3 AI+authz+hook, v0.4 URL Mode, v1.0 supply chain + restricted active scope) — every gate must pass.
- **External suites** (NodeGoat / Juice Shop) = classic vulnerable Node apps — raw finding counts on UNLABELLED projects; useful as sanity observations, never as recall.
- **External tool comparison** = same-tree, pinned-configuration measurement with disclosed scope; PENDING entries name the exact command a maintainer can run to finish the measurement.
- **Wall times** are recorded for transparency of scale, not as speed claims (see the Trials row above).


## Pending (never estimated)

- ⏳ External tool comparison status: semgrep: executable not runnable on this host — run the adapter command under WSL/Linux/Docker
