<div align="center">

<img src="https://raw.githubusercontent.com/EMAD11223344/anubis-guardian/main/docs/assets/hero.svg" alt="Anubis Guardian — deterministic security auditor for AI-built projects: offline static-only scanner" width="100%">

# ⚱ Anubis Guardian

**Deterministic security auditor for JavaScript/TypeScript projects — especially those built with AI coding agents**

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.5.0-8b5cf6.svg)](package.json)
[![Node](https://img.shields.io/badge/node-%E2%89%A518-blue.svg)](package.json)
[![npm](https://img.shields.io/badge/npm-install%20--global-cb3837.svg)](https://www.npmjs.com/package/anubis-guardian)

**Offline static analysis · Consent-gated URL mode · Secrets · SAST · Taint · Dependencies · CI/supply-chain · SARIF · Authorization review prompts**

</div>

---

## What is it?

Anubis Guardian scans your codebase for real security defects — hardcoded secrets, dynamic SQL, unsafe framework configuration, missing authorization evidence, tenant-isolation hints, data-exposure risks, and more — and produces a **deterministic, reproducible report** with masking, scoring, and generated (never-executed) test scaffolds.

It is built around the failure patterns of AI-generated ("vibe-coded") applications — service keys shipped to the client, `Math.random()` tokens, unpinned CI actions, client-visible credentials — but it is a **general tool for any ES/TS codebase**, with optional deep playbooks for a few popular frameworks.

**Who it is for:** solo developers, teams adopting AI coding agents, and CI pipelines that want a fast, deterministic, offline security gate. It does not replace human security review; it gives that review a prioritized, honest starting point.

> 🛡️ **Different from after-the-fact scanners:** beyond detection, an optional pinned agent hook (`init-hook`) blocks service-role keys, RLS-killing SQL, and secret literals **at write time**, before they enter your codebase.

## Works everywhere — any database, any ORM

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
| **A. RBAC / authorization** | `AUTHZ-001/002` | mutating request handler with a privileged operation and no authorization call in its **own handler body** (MEDIUM, review) · authorization decided from client input like `req.body.isAdmin` (HIGH) | middleware, global guards, and DB RLS are invisible — a guard elsewhere is assumed, never claimed |
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

## Documentation

| Document | Contents |
|---|---|
| [METHODOLOGY.md](METHODOLOGY.md) | determinism contract, scoring, false-positive control, known limitations |
| [BENCHMARKS.md](BENCHMARKS.md) | measured results only — honeypot recall, clean corpus, wall-time scale |
| [CONTRIBUTING-RULES.md](CONTRIBUTING-RULES.md) | how to contribute rule packs (clean cases mandatory, CRITICAL gating) |
| [docs/AGENT-INTEGRATION.md](docs/AGENT-INTEGRATION.md) | AI-agent wiring recipes and the exit-code contract |
| [studies/RESULTS.md](studies/step0-pattern-study/RESULTS.md) | the pattern-frequency study (100 AI-built projects) that seeded the rules |
| [docs/site](docs/site/index.html) | GitHub Pages landing page |

## Contributing

Contributions are welcome — bug reports, new universal rules, new framework playbooks, clean-case fixtures. Rule contributions follow a strict evidence format (every detection ships with its false-positive control); see [CONTRIBUTING-RULES.md](CONTRIBUTING-RULES.md). General issues and pull requests go through the normal GitHub flow.

## Security vulnerabilities in this tool

Found a security issue in Anubis Guardian itself (not in your scanned code)? Report it privately via [GitHub Security Advisories](https://github.com/EMAD11223344/anubis-guardian/security/advisories/new) rather than a public issue. Scanned-code findings are not tool vulnerabilities — run the scanner on your own repo and read the report.

## Known limitations (stated up front)

- **By design:** regex/structured heuristics rather than a full AST engine; SQL-sink values are tracked through a bounded same-function chase (≤4 hops, cycle-safe, one imported-local-helper level) — **no call-graph, no cross-function dataflow**
- **Single file scope for taint-lite**, capped at MEDIUM, with generated canary tests you run yourself
- **Authorization/tenant/isolation findings are evidence, not proof** — invisible middleware, RLS, or runtime values always win
- **JS/TS only for codebase mode** (non-JS languages: use the supplied Semgrep adapter)
- **Large files:** >512 KB analyzed in windows to 4 MB (exact absolute line numbers); above 4 MB disclosed as skipped; window-seam dataflow chains beyond the overlap stay non-detections
- **No DAST engine** — URL mode is consent-gated, bounded, and passive-first; deep dynamic testing belongs to your own tooling (a ZAP baseline config can be generated)
- Full list with rationale: [METHODOLOGY.md §8](METHODOLOGY.md)

## Roadmap

| Stage | Status |
|---|---|
| v1.4 — six capability groups + adversarial ReDoS battery + windowed large-file scanning | ✅ shipped |
| v1.5 — window-progress guarantee, whole-object LEAK-003, RES-003 timeouts, TEN-002 reads, SSRF severity accuracy | ✅ shipped |
| Bounded interprocedural parameter-flow analysis + measured third-party benchmarks | 🔜 next |

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
