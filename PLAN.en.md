# Anubis Guardian — Project Plan (English)

> **Open-source security audit tool for AI-built (vibe-coded) projects**
>
> Status: `SHIPPED v0.4 — Step 0 ✅ · v0.1 ✅ · v0.2 ✅ · v0.3 ✅ · v0.4 (Mode 2) ✅ — both modes complete · v1.0 next` · Master plan rev: `v2.0` · License: `MIT` · Date: 2026-10
> Modes: **Mode 1 — Codebase** (scan project files, shipped) · **Mode 2 — URL** (scan a live site by its URL, shipped v0.4)
> Implementation: TypeScript / Node ≥ 18 · Distribution: source today; npm (`@anubis-guardian/cli`) at v1.0 + Agent Skill
>
> Same plan in Arabic: [`PLAN.ar.md`](PLAN.ar.md) · Full bilingual design + decision log: [`docs/PLAN.master.md`](docs/PLAN.master.md)

---

## 1. Executive Summary

**Anubis Guardian** is an open-source security audit tool designed for the era of AI-built projects. Developers today ship Next.js apps, NestJS backends, and Supabase-backed systems generated with AI agents in days instead of months — but this speed comes with a consistent pattern of security mistakes: exposed API keys, database credentials sent from the frontend, missing Row-Level Security, JWT tokens stored in `localStorage`, configuration files pushed to GitHub, and unpinned CI actions. Existing scanners (Semgrep, Trivy, Gitleaks) are powerful but generic; they were not designed for this failure pattern, and they are not friendly to developers who are not security specialists.

Anubis Guardian closes this gap. It runs as a **CLI tool** and as an **Agent Skill** (`SKILL.md`) that any AI coding agent — Claude Code, Cursor, Codex, Windsurf — can load and execute. It operates in two modes: scanning a codebase's files (Codebase Mode), or probing a live deployed website by its URL (URL Mode, Levels 1–3 with ownership verification). The output is a single actionable report: a security score out of 100, findings ranked by severity, and a concrete fix for every finding.

The philosophy is **deterministic-first**: the core scanning layers (secrets, git history, framework playbooks, SAST-light) are pure rule-based checks that run offline in seconds with zero API cost. Dependency findings are scored against an **advisory snapshot bundled with each tool release** — so "same code + same tool version = same score" holds exactly. An optional AI Review layer (LLM + independent verifier) sits on top in v0.3 for deep analysis — with a strict redaction + untrusted-data protocol.

**Why TypeScript?** The target projects are Next.js and NestJS — Node already exists in every environment we scan, no second runtime needed. `npx` is the natural UX for the JS/TS audience. TS/JS AST analysis is easiest with `ts-morph`. And agent environments (Claude Code / Cursor) run on Node — the tool and the skill share the same runtime.

## 2. Non-Goals — the scope contract

Any new idea must pass the Decision Log and get an explicit roadmap item — no silent additions to the plan.

| Not covered | By design |
|---|---|
| Business logic & payments | Partially via the optional AI layer + human review — never automated judgment |
| Generic DAST / wide fuzzing | URL Mode L3 is tightly restricted; ZAP config generation is the alternative |
| Compliance (SOC2 / PCI / HIPAA) | Out of scope |
| Non-JS/TS languages | Out of scope for built-in rules — the Semgrep adapter covers them |
| Autonomous fixing | Suggested diffs only — **nothing applies without explicit human approval** |

## 3. Vulnerability coverage

### 3.1 Delivered — v0.2 (current release)

| Area | Checks |
|---|---|
| Secrets | curated key patterns; **SUPA-001** service_role by JWT value-decode + reachability; **HDR-001** DB-creds-in-headers (receiver-first; multi-root cross-root linkage ⇒ confirmed CRITICAL); **SEED-001** seeder credentials (SQL INSERT password-column extraction / docker-compose literals / `.env.example` real values); committed `.env` |
| History & files | git-history secrets (`git log -p`); committed-then-deleted env files; `.gitignore` audit; sensitive-file inventory (dumps / backups / `.npmrc` / service-account / `tfstate` / SSH keys) |
| Dependencies | **DEP-001** CVEs vs bundled OSV.dev snapshot (124 H/C advisories, 16 core packages); **DEP-002** known-malicious (OSV MAL); **DEP-003** typosquat (Damerau ≤ 2 vs ~450 popular names); **DEP-004** unresolved + no lockfile; **DEP-005** slopsquat behind `--online` |
| SAST-light + crypto | **SAST-001** SQLi concat, **SAST-002** dangerous HTML (with local-const tracking), **SAST-003** eval/exec interpolation, **SAST-004** weak hashing; **CRYPTO-001** `Math.random` for tokens/OTPs (promoted from v0.3 by Step 0 data: 11% of sample) |
| Supabase playbook | **SUPA-R01** missing RLS (HIGH + `needs_confirmation` → CRITICAL on schema-export/live-probe confirmation), **R02** `USING (true)`, **R03** views without `security_invoker`, **R04** `SECURITY DEFINER` without `search_path`, **R05** dashboard drift via user-run schema dump, **R06** policies without user-scoping, **R07** `storage.objects` without RLS, **R08** `verify_jwt=false` in Edge Functions |
| Next.js playbook | **NEXT-001** secrets via `NEXT_PUBLIC_*` (with anon-key decode exclusion), **NEXT-002** tokens in web storage, **NEXT-003** session cookie flags, **NEXT-004** mutating endpoints without in-file auth (middleware-aware, file-level) |
| NestJS playbook | **NEST-001** unguarded controllers (APP_GUARD-aware), **NEST-002** CORS wildcard, **NEST-003** helmet missing, **NEST-004** throttler missing |
| CI / supply chain | **CI-001** unpinned actions, **CI-002** `pull_request_target`, **CI-003** script injection (incl. block-scalar), **CI-004** over-broad permissions; **DOCKER-001** root user, **DOCKER-002** `:latest`, **DOCKER-003** ARG secrets — the CI pack is #1 by measured data (22% of the Step 0 sample) |
| Recon | `inventory.json`: routes / server actions / NestJS controllers with guard state / Supabase tables + RLS state / RPC / Edge Functions / Socket.IO events / webhooks — feeds the v0.3 authz matrix |

### 3.2 Delivered — v0.3 (rule packs II + taint-lite + agent environment + AI review)

| Check | Target |
|---|---|
| `LOGS-001` secrets leaked into logs | v0.3 |
| `SUPA-002` `user_metadata` inside RLS policies · `SUPA-003` RPC/Edge with `service_role` and no auth | v0.3 |
| `AUTH-001` auth only in middleware (matcher-dependent) | v0.3 |
| `MASS-001` mass assignment (`data: req.body` without whitelists) | v0.3 |
| `WS-001` Socket.IO gateways without auth (`io.use`) | v0.3 |
| `WEBHOOK-001` webhooks without signature verification | v0.3 |
| `JWT-001/002` `jwt.decode` for decisions / open `algorithms` / `ignoreExpiration` | v0.3 |
| `SWAGGER-001` Swagger/OpenAPI exposed in production | v0.3 |
| Taint-lite (single-file + one-level import scope, MEDIUM cap, mandatory clean-cases): SSRF / open redirect / path traversal / command injection / reflected XSS | v0.3 |
| Next.js cookie-in-fact-not-HttpOnly + CSRF heuristic | v0.3 (heuristic) |
| Authz Matrix (experimental, fed by `inventory.json`) + restricted differential IDOR | v0.3 / v1.0 |
| URL Mode L1–L2 (and restricted L3) | v0.4 |

### 3.3 Delivered — v0.4 (this release: URL Mode / Mode 2)

| Check | Level | Gate |
|---|---|---|
| `URL-001/002/003` plain HTTP · weak TLS protocol · certificate expired/expiring/invalid | L1 | none |
| `URL-010..015` missing CSP / HSTS / clickjacking / nosniff / referrer / permissions headers | L1 | none |
| `URL-020/021/022` cookies without Secure / HttpOnly (session ⇒ HIGH) / SameSite | L1 | none |
| `URL-030/031` Server version + X-Powered-By disclosure | L1 | none |
| `URL-040` **secret shipped in a public JS bundle** (service_role by JWT role-claim decode, Stripe live, AWS, OpenAI, GitHub, Google, Slack, private keys, DB URLs — masked, rotate-first) | L1 | none |
| `URL-041/043` internal endpoints in bundles · sourceMappingURL references (advice) | L1 | none |
| `URL-050/051/052/053` exposed `.env` (secret-shaped ⇒ CRITICAL) / `.git` / SQL dumps & backups / composer | L2 | **verified ownership** |
| `URL-054..057` directory listing · TRACE (XST) · risky `Allow` · exposed Swagger/GraphiQL | L2 | verified ownership |
| `URL-042` source maps shipping original sources (secret-shaped content ⇒ HIGH) | L2 | verified ownership |
| `URL-901` auth/admin surface mapping (info) | L2 | verified ownership |
| `URL-060` **Supabase live anon probe** — `GET /rest/v1/<table>?limit=1` returns rows ⇒ RLS not effective in production (GET-only, verified-only) | L3 | **verified ownership enforced** |

L1 is browser-equivalent by construction (homepage + robots.txt + sitemap.xml + security.txt + the public JS the page loads — **zero probing**, proven by the request-log acceptance gate). L2+ refuses un-gated public domains with exit 2 **before any request**. Every report carries the scan authorization record + ownership label. Same output contract with `Code map:` hints; `--from-capture` re-analysis is byte-identical with zero network.

All v0.3 rule-pack candidates measured ≤ 1% in the public 100-project sample — their value is proven in real dogfooding, which is why they shipped after the data-confirmed priorities.

**Also delivered in v0.3:** the **agent-environment checks** (AGENT-001..004: unpinned MCP servers, secrets in agent configs, permission wildcards/bypass, unpinned hook commands), the **AI review layer with an independent verifier** (`--ai-review`, off by default: redaction-before-LLM + untrusted-data framing + four deterministic verification gates; hallucinated evidence, missing files, and unknown rule ids are rejected; AI findings cap at HIGH), the **authz matrix + quarantine** (`test-authz`: generated failing-by-expectation Supertest/Playwright tests the tool never executes), the **pinned agent guard hook** (`init-hook`: PreToolUse blocking of service_role-into-client, RLS-killing SQL, and secrets-into-`.env` at write time), and the **full Agent Skill** (`skill/SKILL.md`). Acceptance: `npm test` runs 6 gates — build, honeypot **49/49 seeds**, clean corpus **0 FP (100/A)**, SARIF, acceptance v0.2 + v0.3 (AI-review determinism with a canned provider, verifier gates on the wire, hook blocks/allow, authz + canary generation).

## 4. Operating modes

### Mode 1 — Codebase Mode (shipping now)

`anubis-guardian scan <paths...>` — offline, static-only, never executes scanned code. Multi-root (`scan ./frontend ./backend`) links findings across roots. Monorepo support via `--workspaces`. Custom organizational rules via `--rules-dir`. Full flag reference in the [README](README.md).

### Mode 2 — URL Mode (shipped v0.4)

Scanning a deployed site **by its URL**, in three graduated levels:

- **Level 1 — passive external scan (default):** browser-equivalent requests only — security headers, TLS, cookie flags, plus downloading and analyzing public JS bundles (shipped secrets surface here, exactly like a browser sees them).
- **Level 2 — discovery:** sensitive-path probing (exposed `.env`, `.git`, directory listings) — for public domains, **verified ownership is REQUIRED**; self-attestation is confined to localhost/staging and always marked.
- **Level 3 — v0.4 scope = L2 + the Supabase live anon probe** (read-only GET, verified ownership enforced — never the flag alone). Full active testing (reflected-input canaries, differential IDOR) remains the **v1.0 decision point**: minimal active tests OR a generated ZAP baseline config — no DAST engine by design.

**Ownership verification:** DNS TXT record `anubis-guardian-challenge` or a nonce at `/.well-known/anubis-guardian/`. Every URL report carries the ownership method used. Consent banner, rate limiting, robots awareness, and authorization records are part of the layer.

> **Both modes shipped.** Mode 1 completed through v0.3; Mode 2 landed in v0.4 exactly as ordered. URL Mode is competitive parity (v1.5 honesty note); the differentiation is verified ownership + the same output contract (fix-prompt + `Code map:` "where in the code" guidance).

## 5. Architecture

```
anubis-guardian/
├── src/
│   ├── engine.ts / walk.ts / score.ts / types.ts   # engine, scoring, data contract
│   ├── urlmode/       # v0.4 Mode 2: capture fetcher, ownership gate, L1/L2/L3 checks, analyze
│   ├── rules/         # Layer 1/2/3/4/5 rule implementations (one file per domain)
│   ├── report/        # deterministic renderers: terminal, md, sarif, html, compact, fix-prompt
│   ├── inventory.ts   # Phase 0 recon inventory
│   ├── adapters.ts    # gitleaks / osv-scanner / semgrep (opt-in) + update-advisories
│   ├── rulesdir.ts    # --rules-dir org rules DSL (clean_cases required)
│   ├── initci.ts      # init-ci workflow generator (real SHA pins via git ls-remote)
│   └── advisory/      # bundled OSV.dev advisory snapshot + popular-package list
├── skill/SKILL.md     # Agent Skills format for IDE agents
├── studies/step0-pattern-study/   # the 100-project data study (RESULTS.md)
└── tests/             # honeypot (49 seeds) + clean corpus + SARIF + acceptance v0.2/v0.3 + mode2/ (v0.4)
```

Single runtime dependency (`commander`). Node ≥ 18. Determinism is a hard contract: no timestamps in findings, byte-identical `findings.json` and `fix-prompt.md` for identical input + tool version — and in URL Mode, byte-identical findings from the same **capture bundle** (`--from-capture`, zero network), because the live wire itself is not deterministic but the pipeline is.

## 6. Severity & scoring

**Severity model** — severity requires measured impact, not rule count:

- **CRITICAL only with independent confirmation** — a deterministic hint (e.g. missing RLS on a public table) lands as **HIGH + `needs_confirmation`**; CRITICAL arrives only via real confirmation: user-run schema export, live probe, or cross-root linkage.
- Low-confidence findings and INFO never deduct.

**Score:**

```
score = 100 − (25 × CRITICAL + 10 × HIGH + 4 × MEDIUM + 1 × LOW)     grades A–F
```

Root-cause caps: the first finding of a root cause deducts fully, repeats add +10%, and a group is capped at 2× — one leaked `.env` does not become 40 deductions for 40 keys. `score_breakdown` exposes every deduction.

**CI gates:** `--fail-on high|critical` and `--fail-on-cve` (exit 1/0 verified in acceptance). The generated `init-ci` workflow blocks PRs containing CRITICAL findings.

## 7. Output contract

Every renderer is a deterministic view over the same `findings.json`:

| Artifact | Consumer |
|---|---|
| Terminal / `--format md` | the developer, right now |
| `findings.json` | CI, dashboards, future integrations — includes `confidence`, `fingerprint`, `suppression`, `coverage.classes_covered / classes_not_covered` |
| `--sarif` (SARIF 2.1.0) | GitHub Security tab / code scanning |
| `--fix-prompt fix.md` | any AI agent — deterministic fixing prompt with rotate-first guardrails ("never touch tests", "rotate before delete") |
| `--compact` | token-saving summary for agent contexts |
| `--html` | self-contained shareable report |
| `--inventory inventory.json` | the v0.3 authz matrix + org audits |

Masking is mandatory in every output: secret evidence = type + location + first-4 chars + sha256 prefix — the full value is never written anywhere.

## 8. Safety — the tool's own threat model (summary)

- **No execution of scanned code** (plan §9.7): file reads + git plumbing only; generated tests/quarantine folders are run by the owner, never by the tool.
- **The report itself must not leak** (§9.2): mandatory masking everywhere, including CI artifacts and SARIF.
- **AI layer protocol** (§9): redaction-before-LLM, untrusted-data protocol against prompt injection, suggested-diff only — no auto-apply.
- **Organizational rules as supply chain** (§9.4): `--rules-dir` requires clean-cases per rule; org CRITICAL is forced to `needs_confirmation`; the community registry (v1.0) ships signed with checksum pinning + quarantine behind explicit opt-in.
- **URL Mode abuse** (§9.5): graduated levels, verified ownership gates, rate limits, authorization records.
- **Distribution supply chain** (§9.6): at v1.0 — npm provenance attestation + SBOM + signed releases; hook/plugin versions pinned to explicit versions (never `@latest`).
- **Name collision** ("Anubis" is used by other OSS, e.g. TecharoHQ/anubis): always the full name **Anubis Guardian**, npm scope `@anubis-guardian/cli`.

## 9. Data-driven prioritization — the Step 0 study

Before trusting intuition, the tool measured the ecosystem: **100 public AI-built projects** (80 with explicit AI-build signals — Lovable/Bolt/Cursor/Claude/Windsurf/vibe — + 20 AI-default-stack), **3,403 files**, documented repeatable protocol (`studies/step0-pattern-study/RESULTS.md`).

| Pattern | Frequency | Decision |
|---|---|---|
| Unpinned GitHub Actions | **22%** (91 hits) | CI pack → top of v0.2 ✅ |
| `Math.random` for tokens/OTPs | **11%** (136 hits) | CRYPTO-001 promoted v0.3 → **v0.2** ✅ |
| `dangerouslySetInnerHTML` | 7% | already covered (SAST-002) |
| SQL concat / RLS `USING (true)` / service_role / committed `.env` | 3% each | already covered |
| LOGS / SUPA-002/003 / WS / SWAGGER / MASS / WEBHOOK / JWT / AUTH | ≤ 1% each | stay in v0.3 — value proven by dogfooding, not public frequency |

The raw sample (`sweep.json`, `totals.json`, clone list) is preserved for re-analysis and for building the labeled recall corpus at v1.0.

## 10. Roadmap & build progress tracker

> Tracking rule (owner requirement): this registry updates after **every** completed stage — a ✅ requires documented acceptance evidence. Live status mirrors the master plan.

| Stage | Status | Evidence |
|---|---|---|
| Plan v1.8 — 8 review rounds (57 governed design items) | ✅ | Decision Log |
| v0.1 — Codebase core (slices أ→هـ) | ✅ Oct 2026 | Honeypot 13/13 · clean 0 FP (100/A) · byte-identical determinism · scan 0.08s · masking verified |
| Step 0 — instrument (32 candidate patterns) | ✅ within v0.1 | `CANDIDATE_PATTERNS.yaml` + `measure.mjs` |
| Step 0 — the actual sweep (100 projects) | ✅ Oct 2026 | 100 repos / 3,403 files — `RESULTS.md` |
| **v0.2 — Depth + integrations** | ✅ **Oct 2026** | Honeypot 30/30 (2 roots) · clean 0 FP (100/A) · SARIF verifier · full acceptance (incl. byte-identical `findings.json` + `fix-prompt.md`) |
| **v0.3 — Agent Skill + AI Review** (taint-lite · authz matrix · rule packs II · guard hook) | ✅ **Oct 2026** | Honeypot 49/49 · clean 0 FP (100/A) · SARIF + acceptance v0.2/v0.3 green: verifier rejects hallucinated/missing-file/unknown-rule claims, redaction verified on the wire, AI findings capped at HIGH, hook blocks enforced, authz matrix + canaries generated (never executed) |
| **v0.4 — URL Mode / Mode 2** (L1 passive + L2 verified + L3 Supabase probe) | ✅ **Oct 2026** | `npm test` full chain green: mode2 verify **33/33** (planted-hole server: .env CRITICAL, .git HIGH, SQL dump CRITICAL, listing, TRACE, Swagger, sourcemap, bundle secrets ×2 CRITICAL, cookies, headers, robots-skip honored, masking) + acceptance **47 gates**: L1 passivity proven from the request log (no probing at all), public-domain L2 un-gated → exit 2 before any request, checkbox-for-public → exit 2, L3 self-attested → exit 2, .well-known verification live + DNS TXT unit tests, Supabase anon probe (GET-only) from captured responses, byte-identical from-capture determinism + zero-network re-analysis, all renderers (SARIF/fix-prompt/md/compact/html) on URL findings, rate limiting, clean control exactly 90/A, ownership command |
| v1.0 — Public release + BENCHMARKS.md + **field validation on Business-OS** (owner's real project — the first true dogfood, deliberately last) | ⬜ | — |

**Remaining gates:**

| Stage | Exit gate (acceptance) |
|---|---|
| v0.3 | "audit this project" inside an agent IDE runs the tool end-to-end and proposes suggested diffs for top findings — applying nothing without explicit human approval |
| ~~v0.4~~ ✅ | **met:** same output contract on URL findings (fix-prompt carries the map-endpoints-to-code instruction) · L2 refuses un-gated (proven for public domains, checkbox, and L3-self-attested) · ownership method + authorization record in every report · demo deployment acceptance: planted missing headers + exposed `.env` + shipped JS-bundle secret all detected |
| v1.0 | `npx anubis-guardian scan` works from npm; new user: install → first report < 2 minutes; BENCHMARKS.md published with measured numbers only; **L3-active decision point** (minimal active tests OR generated ZAP config) |

## 11. Validation & testing

The Honeypot (30 planted seeds across a Next.js+Supabase app and a NestJS API) is the **permanent regression suite** — every release must catch 100% of its seeds. Its honest limit: it proves nothing about real-world recall, because we planted what we detect. So validation is layered:

| Layer | What it measures | Target |
|---|---|---|
| Honeypot (49 seeds) + Mode 2 planted-hole server | regression: new release broke nothing | 100% of criticals/highs |
| Labeled AI-corpus (from Step 0 sample) | recall on real vulnerabilities we did not plant | measured, published in BENCHMARKS.md — no pre-promised numbers |
| Generic vulnerable apps (Juice Shop / NodeGoat) | sanity for the generic layers only (secrets + SAST) — not the playbooks | measured, published |
| Clean corpus (real AI-built projects) | false-positive rate | < 10% |
| Dogfooding — **Business-OS first** (owner's production projects) | the first real-world signal + launch material | published as a case study |

`npm test` runs the full gate: build + honeypot (49/49) + clean (0 FP, 100/A) + SARIF + acceptance v0.2 + v0.3 + **mode2 verify (33/33)** + **acceptance v0.4 (47 gates)**. Byte-identical determinism (codebase input and URL capture alike) and the masking contract are re-verified on every run.

## 12. Decision principles

1. **Deterministic-first** — the core is offline rule packs; anything non-deterministic is opt-in and flagged in `meta`.
2. **Evidence-only findings** — no finding without evidence; no CRITICAL without independent confirmation.
3. **Severity requires impact** — bound to actual impact, not the number of violated rules (anti alert-fatigue).
4. **Rotate-first** — every secret finding ships provider-specific rotation steps, not "delete the key".
5. **Suggested diffs only** — the tool never modifies a project; even the AI layer proposes, humans apply.
6. **Same language as the audience** — TypeScript/Node because that's where the target projects and agents live.
7. **Universal rules + extensible playbooks** — secrets/history/CI/deps/SAST rules are framework-agnostic; deep playbooks (Supabase/Next.js/NestJS) cover the highest-frequency vibe-coding stacks first, and Step 0 data drives every extension.
8. **Scope is frozen** — new ideas enter via the Decision Log + an explicit roadmap item, never silently.
