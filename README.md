<div align="center">

<img src="https://raw.githubusercontent.com/EMAD11223344/anubis-guardian/main/docs/assets/hero.svg" alt="Anubis Guardian — deterministic security auditor for AI-built projects: offline static-only scanner" width="100%">

# ⚱ Anubis Guardian

**Deterministic security auditor for JavaScript/TypeScript projects — especially those built with AI coding agents**

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.5.1-8b5cf6.svg)](package.json)
[![Node](https://img.shields.io/badge/node-%E2%89%A518-blue.svg)](package.json)
[![npm](https://img.shields.io/badge/npm-install%20--global-cb3837.svg)](https://www.npmjs.com/package/anubis-guardian)

**Offline static analysis · Consent-gated URL mode · Secrets · SAST · Taint · Dependencies · CI/supply-chain · SARIF · Authorization review prompts**

</div>

---

## What it detects

Anubis Guardian scans your codebase for real security defects and produces a **deterministic, reproducible report** — masked secrets, scored severity, coverage manifest, and generated (never-executed) test scaffolds:

- **Committed secrets & exposure** — service-role keys (value-decoded JWTs), provider tokens, DB URLs with passwords, `.env` leaks, git-history traces `HIST-*` · `SUPA-*` · `SEC-*` · `ENV-*`
- **SAST & taint-lite** — dynamic SQL, unsafe framework configuration, SSRF/open-redirect/path-traversal/injection/XSS flows to recognized sinks `SAST-*` · `TAINT-001..006` · `JWT-*` · `NEXT-*`
- **Authorization & access control** — request handlers with a privileged operation and no recognizable authorization check (`AUTHZ-001`), and authorization **decisions taken from client-controlled input** — including decisions read from parsed request bodies (`AUTHZ-002`) `AUTHZ-*` · `TEN-001/002` (tenant isolation)
- **Data leakage, resource exhaustion, uploads** — credential-shaped responses, pagination-less reads, timeouts, upload/archive guards `LEAK-*` · `RES-*` · `UPLOAD-*`
- **Supply chain & CI** — unpinned CI actions, script injection, root Docker images, dependency CVEs `CI-*` · `DOCKER-*` · `DEP-*`
- Everything boundary-sensitive carries **`needs_confirmation`** — a review prompt naming the invisible layer (middleware, DB RLS, runtime values), never a fabricated verdict.

## Why AI-built applications

The rules are seeded from a pattern-frequency study of 100 AI-generated projects — the failure shapes of "vibe-coded" code: **service keys shipped to the client, `Math.random()` tokens, unpinned CI actions, client-visible credentials, Next.js App Router handlers whose security state was copy-pasted away**. Agent-built apps change fast and nobody re-reads them; this is a fast, offline, deterministic gate for that workflow. It remains a general tool for any ES/TS codebase, with optional deep playbooks (Supabase, Next.js, NestJS).

## How it differs from a secret scanner or a general SAST engine

| | Anubis Guardian | Secret scanners (e.g. gitleaks) | General SAST engines (e.g. Semgrep) |
|---|---|---|---|
| **Detection focus** | framework & application logic: authz evidence, tenant isolation, taint to sinks, NEXT/Supabase/Nest playbooks | secret patterns in files and git history | whatever rules/ruleset the operator curates — arbitrary breadth |
| **Zero-config value** | opinionated battery that runs out of the box with masking + scoring + coverage manifest | strong on the one class it targets | depends entirely on the ruleset you pick; no scoring contract |
| **Evidence discipline** | two-tier contract: evidence-backed vs `needs_confirmation` review prompts, root-cause caps, no-CRITICAL-without-confirmation | matched/unmatched secrets | finding confidence/calibration depends on the selected ruleset — no built-in evidence-tier contract |
| **Measured overlap** | committed-secret classes on identical trees: **both tools matched all labelled cases (3/3), 0 false positives on safe files, FP-accounting calibration fixture measured** — scope and detail in [BENCHMARKS.md](BENCHMARKS.md) | | |

There is no "winner" to claim — the tool classes overlap on secrets and diverge everywhere else, and the [comparison section of BENCHMARKS.md](BENCHMARKS.md) pins versions, configuration, matching rules, and every pending scope instead of fabricating superiority.

## Measured performance & detection (highlights)

Every number below reproduces from [`scripts/measure-benchmarks.mjs`](scripts/measure-benchmarks.mjs) on the environment recorded in [BENCHMARKS.md](BENCHMARKS.md) — no number appears there without a measurement, and unmeasurable entries are marked PENDING:

| Measured on the candidate (commit-pinned) | Result |
|---|---|
| Curated honeypot self-test (49 planted checks, 2 roots) | **49/49 detected**, masking contract intact |
| Clean-project false-positive control | **0 findings above threshold — score 100, grade A** |
| Labelled precision/recall corpus (17 vulnerable + 12 safe adjudicated cases) | **17/17 TP, 0 FP** — self-curated manifest [benchmarks/corpus](benchmarks/corpus/cases.json), not an external-recall claim |
| Skilled-tool comparison (gitleaks, pinned 8.30.1, identical trees) | **3/3** labelled secret cases matched, 0 FP on safe files; Semgrep numerical comparison **PENDING** with a full scope matrix |
| Scale on the benchmark hardware | single-root fixture scan ≈ sub-second (0.66 s for the ~30-file Next.js+Supabase honeypot tree) — per-measurement wall times, environment, and the adversarial worst case are all recorded in [BENCHMARKS.md](BENCHMARKS.md) |

> Wall times are local-machine records for scale transparency — **not universal performance guarantees**. The documented worst case (an adversarial ~4 MB pathological file) and its regression gates are disclosed in the limitations below.

> 🛡️ **Different from after-the-fact scanners:** beyond detection, an optional pinned agent hook (`init-hook`) blocks service-role keys, RLS-killing SQL, and secret literals **at write time**, before they enter your codebase.

## Any database, any ORM — what the scanner actually recognizes

The core rules run on **plain JavaScript/TypeScript with no framework assumptions** at the call site. Whatever database or ORM you use — the rules recognize the **common query patterns** your code actually writes: raw SQL strings built by hand or by a query builder, Prisma / Drizzle / TypeORM-style client calls, chained `.from(...)` builders, and committed `.env` files:

| Your stack | What still fires |
|---|---|
| **Prisma / Drizzle / TypeORM / knex / pg / mysql2 / mongoose / plain SQL** | `SAST-001` dynamic-SQL analysis · `TAINT-003` path traversal · `SEED-001` seeder credentials · `LEAK-003` whole-object response exposure · `TEN-001/002` tenant isolation hints · committed `.env` secrets |
| **Express / Fastify / Koa / plain Node HTTP** | `TAINT-001..006` (SSRF, redirect, traversal, injection, XSS, code exec) · `JWT-003` hardcoded secrets · `RES-001..003` resource-exhaustion review · `WEBHOOK-001` · `LOGS-001` |
| **Any CI + Docker** | `CI-001..004` unpinned actions / script injection / permissions · `DOCKER-001..003` root image / `:latest` / ARG secrets |
| **Any git hosting** | git-history secret recovery · committed-then-deleted env files · sensitive-file inventory |

**What "recognizes common patterns" means — and doesn't:** the universal layers match well-known shapes (string-concatenated SQL, `findMany`/`findFirst` calls, `fetch` sinks, migration files). They are not an exhaustive SQL/ORM parser: an exotic query style, a query builder assembled through several abstractions, or a database accessed behind a home-grown proxy layer can be missed. What the scan did and did not reach is disclosed in the report's coverage manifest — treat the result as evidence about executed checks, not as a statement that your database layer is fully covered.

**Optional battery-included playbooks** (not requirements) add host-aware depth when the repo uses them:

| Framework | Extra depth |
|---|---|
| **Supabase** | missing Row-Level Security, `USING (true)` policies, service-role exposure, Storage/Edge/policies — `SUPA-001..003`, `SUPA-R01..R08` |
| **Next.js** | client/server boundary, public env leaks, cookie flags, middleware gaps, CSRF heuristic — `NEXT-002`, `AUTH-001` |
| **NestJS** | unguarded controllers (global-`APP_GUARD`-aware), CORS, helmet, throttler, Socket.IO gateways — `NEST-001..004` |

If none of these apply to your project, the scanner simply runs the universal layers and reports that in the coverage manifest.

## Six capability groups (v1.4 + v1.5)

Framework-agnostic **review prompts** — because static analysis cannot see middleware, database RLS, or runtime values, findings that depend on an invisible layer carry `needs_confirmation` and explicitly name what could not be inspected:

| Group | Rules | What fires (and severity) | Honest boundary |
|---|---|---|---|
| **A. RBAC / authorization** | `AUTHZ-001/002` | mutating request handler with a privileged operation and no authorization call in its **own handler body** (MEDIUM, review) · authorization decided from client input like `req.body.isAdmin` or a parsed `request.json()` body (`if (body.isAdmin)`) (HIGH) | middleware, global guards, and DB RLS are invisible — a guard elsewhere is assumed, never claimed |
| **B. Multi-tenant isolation** | `TEN-001/002` | by-ID mutation **or read** of a declared tenant entity keyed only on request input (MEDIUM review) · unscoped tenant-table SQL | fires **only** where the repo declares tenant entities (schema.prisma / SQL migrations); enforcement layers invisible |
| **C. Data leakage** | `LEAK-001..003` | credential-shaped fields in responses (MEDIUM review) · PII in logs (LOW) · **whole-object serialization of a wide query result** — escalates to MEDIUM when the queried model declares credential columns (v1.5) | runtime values unobservable (hash vs live secret); nested/derived shapes beyond one chase hop remain invisible |
| **D. Resource exhaustion** | `RES-001..003` | regex built from request input (HIGH direct / MEDIUM flow-traced) · pagination-less reads in handlers (MEDIUM review) · **outbound requests without visible timeout/cancellation** in handlers (LOW note, v1.5) | shared clients/wrappers may apply limits invisibly; unbounded loops over request arrays remain undetected |
| **E. Large-file coverage** | windowed scanning | files >512 KB analyzed in overlapping line-boundary windows to 4 MB; giant single lines never stall the window advance (v1.5) — every supported byte is analyzed, lines >4 MB disclosed | assignment→sink chains that cross a window seam beyond the overlap stay non-detections (never false positives) |
| **F. Upload security** | `UPLOAD-001..003` | request-derived writes into served directories (HIGH) · limit-less upload parsers (MEDIUM review) · guard-less archive extraction (MEDIUM review) | serving-layer behavior (content-type, delivery) is invisible |

## Installation

```bash
npm install -g anubis-guardian
```

Or use it in a project:

```bash
npm install --save-dev anubis-guardian
npx anubis-guardian scan . --format json
```

From source (for development):

```bash
git clone https://github.com/EMAD11223344/anubis-guardian.git
cd anubis-guardian
npm install && npm run build
node dist/cli.js scan ./path/to/project
```

**Requirements:** Node ≥ 18. Only runtime dependency: `commander`.

## Getting started

```bash
# codebase audit — offline, no configuration needed
anubis-guardian scan .

# JSON / SARIF / HTML / compact outputs
anubis-guardian scan . --format json -o findings.json
anubis-guardian scan . --sarif results.sarif            # GitHub Security tab
anubis-guardian scan . --html report.html
anubis-guardian scan . --compact out.txt                # token-saving summary for agents

# CI gate
anubis-guardian scan . --fail-on critical               # exit 1 on CRITICAL

# frontend + backend in one run (cross-root data-flow linkage)
anubis-guardian scan ./web ./api

# monorepos
anubis-guardian scan . --workspaces
```

### URL mode (consent-gated)

For a **deployed site you own** — passive-first, with a verified ownership gate before any active check:

```bash
anubis-guardian scan-url https://example.com            # L1 passive (browser-equivalent)
anubis-guardian ownership https://example.com           # generate a verification nonce
anubis-guardian scan-url https://example.com --level 2 --ownership-token <nonce>
```

L1 is always passive (headers, cookies, secrets in public bundles). L2 discovery and L3 probing require verified ownership — a DNS TXT record or `/.well-known` file — and private targets additionally need `--allow-private`. Cloud metadata endpoints are refused unconditionally. **Scanning systems you do not own is illegal; the tool enforces the gate rather than relying on your promise.**

<p align="center">
  <img src="https://raw.githubusercontent.com/EMAD11223344/anubis-guardian/main/docs/assets/modes.svg" alt="Anubis Guardian modes — Mode 1: offline codebase audit (secrets and history, SAST/taint-lite, dependencies, six capability groups, optional framework playbooks); Mode 2: consent-gated URL audit (L1 passive, L2 discovery, L3 probe — verified ownership required)" width="100%">
</p>

## Output formats & exit codes

Full output contract: `terminal` (default) · `json` · `md` · `sarif` · `html` · `compact`, plus `--fix-prompt fix.md` (a deterministic repair prompt for any AI agent) and `--inventory inventory.json` (static attack-surface map).

| Exit | Meaning |
|---|---|
| `0` | scan completed; findings (if any) below the gate |
| `1` | gate threshold breached (`--fail-on` / `--fail-on-cve`) |
| `2` | fail-closed: no trustworthy report (bad path, unknown options, size cap, unreachable URL target, external-tool failure) |

No partial reports: a fail-closed run writes nothing and prints no score.

## Scoring, severity, confidence — and what "incomplete" means honestly

```
score = 100 − (25 × CRITICAL + 10 × HIGH + 4 × MEDIUM + 1 × LOW)      grades A–F
```

- A **CRITICAL** requires independent confirmation (e.g. reachability analysis proving a service key is client-imported); everything merely suspicious is MEDIUM/HIGH + `needs_confirmation`
- Root-cause caps: repeated findings of the same root cause deduct at most 2× the first
- `needs_confirmation: true` = *review prompt, not verdict* — the finding names the invisible layer (middleware, RLS, runtime values) that must be checked by a human
- Repeated **identical** findings deduplicate by fingerprint; `score_breakdown` in the JSON explains every deduction
- The report's coverage manifest lists what ran, and `classes_not_covered` states what the tool does **not** attempt — an A grade means nothing was found by the executed checks, never that the code is secure

## AI-agent integration

The repo ships [`skill/SKILL.md`](skill/SKILL.md) (Agent Skills format) that teaches Claude Code / Cursor / opencode to run the scan, read findings honestly, and propose **suggested diffs only** — applying nothing without approval. The optional `init-hook` guard hook additionally blocks secrets and RLS-killing SQL **at write time**. See [docs/AGENT-INTEGRATION.md](docs/AGENT-INTEGRATION.md).

## CI/CD

`anubis-guardian init-ci` generates a hardened GitHub Actions workflow (SHA-pinned actions, SARIF upload, `--fail-on critical`):

```yaml
- run: npx anubis-guardian scan . --fail-on critical --sarif results.sarif
- uses: github/codeql-action/upload-sarif@<pinned-sha>
  with: { sarif_file: results.sarif }
```

More flags: `--exclude` globs, `--max-files` (fail-closed size cap), `--schema dump.sql` (Supabase dashboard-drift check), `--tools gitleaks,osv-scanner,semgrep` (opt-in adapters), `--online` (slopsquat registry check), `--quarantine` (generated authorization/canary test suites — written, **never executed** by the tool), `test-authz`, `rules-lock`, `init-zap`.

## What Anubis Guardian does NOT prove

- **A finding is evidence, never proof.** Authorization/tenant findings follow a two-tier contract: a missing *visible* check (`AUTHZ-001`, MEDIUM) is a review prompt — middleware, framework guards, and database RLS are legitimately invisible to static analysis and always win.
- **The analysis is bounded, by design.** Rules are structured regex/heuristics over a shared bounded data-flow chase (≤4 assignment hops, same function scope, cycle-safe, one imported-local-helper level) — **no AST parser, no call graph, no cross-function/cross-file data flow**, and deliberately so: determinism, masking, no-exec, zero runtime cost. Deeper aliasing, helper-mediated field flows, and whole-body taint granularity are tracked only to the documented bounds; what a scan did not chase is in the coverage manifest.
- **Recall claims stay local.** The labelled corpus in [benchmarks/corpus](benchmarks/corpus/cases.json) is self-curated (17 vulnerable + 12 safe adjudicated pairs, commit-pinned) — its precision/recall is a documented self-baseline, **not** external validation; raw counts on unlabelled projects (NodeGoat, Juice Shop) are observations, not recall.
- **Known performance boundary.** Files >512 KB are analyzed in windows to 4 MB; above 4 MB is disclosed and skipped. Worst case is honest: an adversarial ~4 MB file of ~2M single-character rows scans in ~70 s on the benchmark hardware (padded absolute-line windows multiply per-rule row visits); realistic density is far faster. Locked by regression gates U26.1–U26.5.
- **No DAST engine** — URL mode is consent-gated, bounded, and passive-first; deep dynamic testing belongs to your own tooling (a ZAP baseline config can be generated)
- Full list with rationale: [METHODOLOGY.md §8](METHODOLOGY.md)

## Documentation

| Document | Contents |
|---|---|
| [METHODOLOGY.md](METHODOLOGY.md) | determinism contract, scoring, false-positive control, known limitations |
| [BENCHMARKS.md](BENCHMARKS.md) | measured results only — honeypot recall, labelled corpus P/R, clean corpus, tool comparison with pinned versions & configs, wall-time scale |
| [ROADMAP.md](ROADMAP.md) | capability-calibrated prioritized roadmap (P1–P3 items with prereqs, fixtures, risks) |
| [docs/TRUST-AUDIT.md](docs/TRUST-AUDIT.md) | release-pipeline trust review — verified controls, ranked tasks, explicit non-claims |
| [benchmarks/corpus](benchmarks/corpus/cases.json) | the adjudicated labelled corpus manifest + reproducible vulnerable/safe fixture pairs |
| [CONTRIBUTING-RULES.md](CONTRIBUTING-RULES.md) | how to contribute rule packs (clean cases mandatory, CRITICAL gating) |
| [docs/AGENT-INTEGRATION.md](docs/AGENT-INTEGRATION.md) | AI-agent wiring recipes and the exit-code contract |
| [studies/RESULTS.md](studies/step0-pattern-study/RESULTS.md) | the pattern-frequency study (100 AI-built projects) that seeded the rules |
| [docs/site](docs/site/index.html) | GitHub Pages landing page |

## Contributing

Contributions are welcome — bug reports, new universal rules, new framework playbooks, clean-case fixtures. Rule contributions follow a strict evidence format (every detection ships with its false-positive control); see [CONTRIBUTING-RULES.md](CONTRIBUTING-RULES.md). General issues and pull requests go through the normal GitHub flow.

## Security vulnerabilities in this tool

Found a security issue in Anubis Guardian itself (not in your scanned code)? Report it privately via [GitHub Security Advisories](https://github.com/EMAD11223344/anubis-guardian/security/advisories/new) rather than a public issue. Scanned-code findings are not tool vulnerabilities — run the scanner on your own repo and read the report.

## Roadmap

Detailed, calibrated roadmap with per-item value/prereqs/fixtures/risks: [ROADMAP.md](ROADMAP.md).

| Stage | Status |
|---|---|
| v1.4 — six capability groups + adversarial ReDoS battery + windowed large-file scanning | ✅ shipped |
| v1.5 — window-progress guarantee, whole-object LEAK-003, RES-003 timeouts, TEN-002 reads, SSRF severity accuracy | ✅ shipped |
| v1.5.2 candidate — Next.js App Router AUTHZ/TAINT fixes, labelled benchmark corpus, pinned gitleaks/semgrep comparison | 🚧 candidate built — release pending owner review |
| reported-defect fix round (6 P0 detection defects reproduced + fixed + regression-locked; benchmark-integrity repairs: pinned external SHAs, gitleaks path calibration, corpus expanded to 29 cases) | 🚧 candidate built — release pending owner review |
| Bounded interprocedural parameter-flow analysis | 🔜 unscheduled (contract change — see ROADMAP.md R7) |

## License

MIT — see [LICENSE](LICENSE).

---

## العربية (Quick Guide)

**أنوبس جارديان** — ماسح أمني حتمي (Deterministic) للمشاريع المكتوبة بجافاسكربت/تايبسكربت، سريع التركيز على مشاريع الذكاء الاصطناعي (vibe coding). ثابت وغير متصل بالإنترنت، لا يُنفّذ الكود المفحوص، ويقنّع الأسرار في كل المخرجات.

**يعمل مع أي قاعدة بيانات وأي إطار عمل** (Prisma / Drizzle / TypeORM / Express / Fastify...) — القواعد تتعرّف على أنماط الاستعلام الشائعة (SQL مُبنى يدويًا، استدعاءات ORM المعروفة)؛ والملحقات الخاصة بـ Supabase وNext.js وNestJS اختيارية لإضافة عمق إضافي عند استخدامها فقط.

```bash
npm install -g anubis-guardian

anubis-guardian scan ./my-project                   # فحص الكود — بدون إنترنت
anubis-guardian scan-url https://example.com        # فحص موقع منشور — L1 سلبي
anubis-guardian ownership https://example.com       # إثبات الملكية للـ L2+
```
