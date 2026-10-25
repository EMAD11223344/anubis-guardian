<div align="center">

# ⚱ Anubis Guardian

**Deterministic security auditor for AI-built (vibe-coded) projects**
**مدير أمني حتمي (Deterministic) للمشاريع المبنية بالذكاء الاصطناعي**

Offline · Static-only · Never executes scanned code · MIT

`v1.0.0` (npm: `@anubis-guardian/cli`) · `Node ≥ 18` · `TypeScript` · `License: MIT`

**[English](#-why-anubis-guardian)** · **[العربية](#-الشرح-بالعربية--full-guide-in-arabic)**

</div>

---

## 🔍 Why Anubis Guardian

AI coding agents (Claude Code, Cursor, Bolt, Lovable, Windsurf…) ship full-stack apps in days — but with a **consistent, repeating pattern of security mistakes**: service keys shipped to the client, database passwords in request headers, missing Row-Level Security, JWTs in `localStorage`, `.env` files pushed to GitHub, unpinned CI actions.

Existing scanners (Semgrep, Trivy, Gitleaks) are powerful but generic — they were not designed for this failure pattern. **Anubis Guardian** was: deterministic rule packs for the AI stack (Supabase / Next.js / NestJS), secrets + git-history scanning, dependency analysis against a bundled OSV.dev advisory snapshot, CI/supply-chain checks, taint-lite flows, agent-environment checks, and an optional verifier-gated AI review layer — all with masked output and a single actionable score out of 100.

> **Data-driven priorities:** our [Step 0 study](studies/step0-pattern-study/RESULTS.md) scanned **100 public AI-built projects (3,403 files)**. Top patterns found: unpinned CI actions **22%** · `Math.random` used for tokens **11%** · `dangerouslySetInnerHTML` **7%** · SQL string-concat / RLS `USING (true)` / committed `.env` **3%** each.

## 🧪 What it checks

### Mode 1 — Codebase (offline, static)

| Layer | Checks |
|---|---|
| L1 Secrets | curated key patterns, **SUPA-001** service_role by JWT value-decode + reachability, **HDR-001** DB-creds-in-headers (receiver-first + cross-root linkage), **SEED-001** seeder credentials, committed `.env`, **LOGS-001** secrets leaked into logs |
| L2 History & files | git-history secrets (`git log -p`), committed-then-deleted env files, `.gitignore` audit, sensitive-file inventory (dumps / backups / `.npmrc` / service-account / `tfstate` / SSH keys) |
| L3 Dependencies | **DEP-001** CVEs vs the **bundled OSV.dev advisory snapshot**, **DEP-002** known-malicious (OSV MAL), **DEP-003** typosquat ≤ 2, **DEP-004** unresolved + no lockfile, **DEP-005** slopsquat via `--online` |
| L4 SAST-light + crypto + **taint-lite (new)** | SQLi concat, dangerous HTML, eval/exec, weak hashing, **CRYPTO-001** `Math.random` tokens; **TAINT-001..005** (SSRF / open redirect / path traversal / command injection / reflected XSS — single-file scope, MEDIUM cap, generated canary confirmation) |
| L5 Framework playbooks | **Supabase** SUPA-R01..R08 + **SUPA-002** `user_metadata` policies + **SUPA-003** unauthed service_role edge functions; **Next.js** NEXT-001..004 + **AUTH-001** middleware-matcher gaps + **NEXT-005** CSRF heuristic + **PRISMA-001** multi-tenancy hint; **NestJS** NEST-001..004 + **WS-001** unauth'd Socket.IO gateways |
| L5 Rule packs II (new) | **MASS-001** mass assignment · **WEBHOOK-001** unverified webhooks · **JWT-001** `jwt.decode` authorization · **JWT-002** `algorithms:"none"` / `ignoreExpiration` / unpinned algos · **SWAGGER-001** exposed API docs |
| L5 CI / supply chain | **CI-001..004** (SHA pinning, `pull_request_target`, script injection, permissions), **DOCKER-001..003** (root, `:latest`, ARG secrets) |
| **L5 Agent environment (new)** | **AGENT-001** unpinned MCP servers · **AGENT-002** secrets in agent configs · **AGENT-003** permission wildcards / bypass modes · **AGENT-004** hooks running unpinned remote code |
| **AI review (new — opt-in)** | `--ai-review`: LLM proposes, an **independent deterministic verifier disposes** — evidence must exist in the file, unknown rules and hallucinated snippets are rejected; AI findings cap at HIGH; redaction-before-LLM; flagged in `meta.ai_used` |
| **Authz matrix (new)** | `test-authz`: role × endpoint × guard matrix from the recon inventory + **failing-by-expectation Supertest tests generated into a quarantine folder** — the tool never executes them |
| **Guard hook (new)** | `init-hook`: pinned PreToolUse hook that **blocks** service_role-into-client, RLS-killing SQL, and secrets-into-`.env` *at write time* — prevention, not just detection |
| Phase 0 inventory | `inventory.json`: routes / server actions / controllers with guard state / Supabase tables + RPC + Edge Functions / Socket.IO events / webhooks |

### Mode 2 — URL (v0.4): scan a live deployed site by URL

| Level | Checks | Gate |
|---|---|---|
| **L1 passive** (default, free) | TLS protocol + certificate validity/expiry · security headers (CSP / HSTS / clickjacking / nosniff / referrer / permissions) · cookie flags (Secure / HttpOnly / SameSite) · **secrets shipped in public JS bundles (the #1 vibe-coding hole — since v1.3 in L1)** · server/X-Powered-By disclosure · internal endpoints in bundles · source-map references · tech fingerprint | none — browser-equivalent requests only (page + robots.txt + sitemap.xml + security.txt + the public JS the page loads) |
| **L2 discovery** | exposed `.env` / `.git` / SQL dumps / backups · directory listing · TRACE (XST) + risky `Allow` verbs · exposed Swagger/GraphiQL · source maps shipping original sources · auth/admin surface mapping | **VERIFIED ownership** (DNS TXT `anubis-guardian-challenge=<nonce>` or `/.well-known/anubis-guardian/<nonce>`) — self-attestation is local-only and labeled |
| **L3 (v0.4 scope)** | L2 + **Supabase live anon probe**: `GET /rest/v1/<table>?select=*&limit=1` with the anon key found in the public JS — live proof that RLS is/isn't effective in production | **VERIFIED ownership enforced** (never the flag alone) |

Every URL report carries a **scan authorization record** (URL, timestamp, level, ownership method), hard rate limits, robots.txt awareness, and a `Code map:` hint per finding (“where in the code” — paired with Codebase Mode for exact file:line). Same output contract: `findings.json` + terminal/md/sarif/html/compact + `fix-prompt.md`.

## 📦 Install & Run

```bash
git clone https://github.com/<your-username>/anubis-guardian.git
cd anubis-guardian
npm install && npm run build

# scan any project
node dist/cli.js scan ./path/to/your-project
```

Optional — global command:

```bash
npm link            # then just:
anubis-guardian scan ./my-project
```

> npm (`@anubis-guardian/cli`) is **release-ready in v1.0** — the publish workflow (Trusted Publishing + provenance + SBOM + checksums) ships in `.github/workflows/release.yml`; until the owner runs the actual publish, install from source as above.

## ⌨️ Commands & flags

### `scan` — audit one or more project roots

```bash
node dist/cli.js scan ./my-project                        # terminal report
node dist/cli.js scan ./frontend ./backend                # multi-root + HDR-001 cross-root linkage
node dist/cli.js scan . --workspaces                      # monorepo portfolio (per-app + combined)
node dist/cli.js scan ./my-project --format json --output findings.json
node dist/cli.js scan ./my-project --format compact       # token-saving summary for AI agents
node dist/cli.js scan ./my-project --fail-on high         # CI gate — exit 1 on HIGH or above
node dist/cli.js scan ./my-project --fail-on critical     # CI gate — exit 1 on CRITICAL
node dist/cli.js scan ./my-project --fail-on-cve          # dependency gate (DEP-001)
node dist/cli.js scan ./my-project --sarif results.sarif  # SARIF 2.1.0 → GitHub Security tab
node dist/cli.js scan ./my-project --fix-prompt fix.md    # deterministic fix prompt for any AI agent
node dist/cli.js scan ./my-project --html report.html     # self-contained HTML report
node dist/cli.js scan ./my-project --inventory inventory.json
node dist/cli.js scan ./my-project --schema dump.sql      # user-run Supabase schema export → drift check
node dist/cli.js scan ./my-project --rules-dir .anubis/rules   # custom org rules (JSON DSL)
node dist/cli.js scan ./my-project --tools gitleaks,osv-scanner,semgrep   # adapters (opt-in)
node dist/cli.js scan ./my-project --online               # slopsquat check (non-deterministic, flagged)
node dist/cli.js scan ./my-project --advisories anubis-advisories.json    # local advisory snapshot
node dist/cli.js scan ./my-project --ai-review            # v0.3: optional AI review (verifier-gated)
node dist/cli.js scan ./my-project --quarantine ./anubis-quarantine   # v0.3: generate taint canary tests
```

| Flag | Purpose |
|---|---|
| `<paths...>` | one or more roots — multi-root links findings across roots (sender in frontend + receiver in backend ⇒ confirmed CRITICAL) |
| `-f, --format` | `terminal` (default) \| `json` \| `md` \| `sarif` \| `html` \| `compact` \| `all` |
| `-o, --output` | write the chosen format to a file |
| `--fail-on <high\|critical>` | exit 1 when un-suppressed findings exist at/above this severity (CI gate) |
| `--fail-on-cve` | exit 1 when dependency CVE findings (DEP-001) exist |
| `--schema <file>` | user-run schema export (e.g. `supabase db dump`) for dashboard-drift check |
| `--sarif <file>` | also write a SARIF 2.1.0 report (GitHub Security tab) |
| `--fix-prompt <file>` | also write `fix-prompt.md` — deterministic fixing prompt with rotate-first guardrails |
| `--compact <file>` | also write a token-saving compact summary for agents |
| `--html <file>` | also write a self-contained HTML report |
| `--inventory <file>` | also write `inventory.json` |
| `--workspaces` | monorepo mode: scan every workspace package + a combined portfolio report |
| `--rules-dir <dir>` | load custom organizational rules (JSON DSL; org CRITICAL is forced to `needs_confirmation`) |
| `--tools <list>` | merge external adapters if installed: `gitleaks,osv-scanner,semgrep` (off by default) |
| `--online` | enable registry metadata checks (DEP-005 slopsquat) — non-deterministic, flagged in `meta.online_used` |
| `--advisories <file>` | use a local advisory snapshot instead of the bundled one |
| `--ai-review` | **v0.3** — enable the optional AI review layer; requires `ANUBIS_AI_API_KEY` (OpenAI-compatible endpoint via `ANUBIS_AI_BASE_URL` / `ANUBIS_AI_MODEL`); redaction-before-LLM + independent verifier; flagged in `meta.ai_used` |
| `--quarantine <dir>` | **v0.3** — generate canary tests for taint findings (the tool writes them, never runs them) |

### `scan-url` — Mode 2: audit a live deployed site (v0.4)

```bash
node dist/cli.js scan-url https://example.com                 # L1 passive — free, no ownership needed
node dist/cli.js ownership https://example.com                # prints a nonce + DNS TXT / .well-known instructions
node dist/cli.js ownership https://example.com --check <nonce>  # verify a published nonce
node dist/cli.js scan-url https://example.com --level 2 --ownership-token <nonce>   # L2 discovery (verified)
node dist/cli.js scan-url http://127.0.0.1:3000 --level 2 --i-own-this-domain       # local/staging only (labeled)
node dist/cli.js scan-url https://example.com --level 3 --ownership-token <nonce>   # L3 = L2 + Supabase anon probe (GET-only)
node dist/cli.js scan-url https://example.com --capture capture.json               # save raw capture (evidence)
node dist/cli.js scan-url https://example.com --from-capture capture.json          # re-analyze offline — byte-identical
node dist/cli.js scan-url https://example.com --fail-on high --sarif r.sarif --fix-prompt fix.md
```

| Flag | Purpose |
|---|---|
| `-l, --level <1\|2\|3>` | 1 passive (default) · 2 discovery (ownership-gated) · 3 = 2 + Supabase live anon probe (verified-only) |
| `--ownership-token <nonce>` | verify the nonce you published (DNS TXT or `/.well-known/anubis-guardian/`) |
| `--i-own-this-domain` | self-attestation — honored ONLY for localhost/127.0.0.1/*.local/private staging; labeled `self-attested (local only)` in the report; never enough for L3 |
| `--capture <file>` / `--from-capture <file>` | save the raw capture / re-analyze it offline with zero network (byte-identical determinism) |
| `--timeout-ms` / `--delay-ms` / `--max-requests` / `--max-assets` | pacing + hard caps (default: 250ms between requests, per-level caps 40/120/150) |
| `--fail-on`, `--sarif`, `--fix-prompt`, `--compact`, `--html`, `-f`, `-o` | same output contract as `scan` — fix-prompt includes the map-endpoints-to-code instruction |

**The legal gate:** L2+ on any public domain requires a **verified** nonce — `--i-own-this-domain` is a checkbox, not proof, and is refused for public domains. Nothing is requested before the gate passes. Scanning systems you do not own is illegal in most jurisdictions.

### `test-authz` — authorization matrix + generated tests (v0.3, experimental)

```bash
node dist/cli.js test-authz ./my-project --quarantine anubis-quarantine
node dist/cli.js test-authz ./my-project --fail-on-risk    # CI-usable signal WITHOUT executing tests
```

Builds the authz matrix (endpoint × method × guard state) from the recon inventory and writes:
`authz-matrix.md` + `authz-matrix.json` + a **failing-by-expectation Supertest suite** (every unguarded mutating endpoint must answer 401/403) + a README. **The tool never executes these tests** — you review them, point them at staging, and run them yourself. Not wired into CI by design.

### `init-hook` — install the agent guard hook (v0.3)

```bash
node dist/cli.js init-hook        # in the project root
```

Installs a **pinned** PreToolUse guard hook (`.claude/hooks/anubis-guard-hook.mjs` + settings wiring) that blocks at write time: service_role keys into client-reachable code, SQL that kills RLS, real-looking secrets into `.env`, and `NEXT_PUBLIC_*` secrets. Idempotent, local copy only — never `npx`, never `@latest`. It also prints the snippet to add to `AGENTS.md` / `CLAUDE.md`.

### `init-ci` — hardened GitHub Actions workflow

```bash
node dist/cli.js init-ci                       # in the repo root
node dist/cli.js init-ci --package-manager pnpm
```

Creates `.github/workflows/anubis-guardian.yml`: least-privilege permissions, **real SHA-pinned actions**, scan on every PR/push, SARIF upload to the Security tab, and a `--fail-on critical` gate. Idempotent.

### `update-advisories` — refresh the advisory snapshot

```bash
node dist/cli.js update-advisories
node dist/cli.js scan ./my-project --advisories anubis-advisories.json
```

**Exit codes:** `0` pass · `1` gate threshold breached · `2` usage/scan error.

## 🚦 CI/CD integration

```yaml
# .github/workflows/anubis-guardian.yml — generated by: anubis-guardian init-ci
- run: node dist/cli.js scan . --fail-on critical --sarif results.sarif
- uses: github/codeql-action/upload-sarif@<pinned-sha>
  with: { sarif_file: results.sarif }
```

## 🧮 The score

```
score = 100 − (25 × CRITICAL + 10 × HIGH + 4 × MEDIUM + 1 × LOW)      grades A–F
```

- **Root-cause caps** — first finding of a root cause deducts fully; repeats +10%; group capped at 2×.
- **Low-confidence and INFO findings never deduct** — AI claims rejected by the verifier are logged, never scored.
- `score_breakdown` in `findings.json` shows exactly what deducted and why.

## 🛡️ Guarantees

- **No execution of scanned code** — file reads + git plumbing only. Generated tests land in quarantine; **you** run them. Network calls only behind `--online` / `--ai-review` / `update-advisories` / `--tools`, and flagged in `meta`.
- **Masking everywhere** — full secret values never written to any output (including the AI-review prompt path); evidence = type + location + first-4 chars + sha256 prefix.
- **Determinism by default** — same code + same tool version ⇒ **byte-identical** `findings.json` and `fix-prompt.md`; URL Mode: same **capture** ⇒ byte-identical findings (`--from-capture`, zero network). The optional AI layer is opt-in and flagged (`meta.ai_used`).
- **No CRITICAL without independent confirmation** — deterministic hints are HIGH + `needs_confirmation`; CRITICAL only with real confirmation (schema export, live probe, or cross-root linkage). **AI findings cap at HIGH** even when the verifier confirms them.
- **URL Mode is consent-gated by construction** — L1 passive only; L2+ refuses un-verified public domains (exit 2 before any request); authorization record + ownership label in every report; hard rate limits; no credentialed scanning; GET-only Supabase probe.
- **Rotate-first remediation** — every secret finding ships the rotation steps for its provider.
- **Prevention, not just detection** — the guard hook stops the classic mistakes before they are written.

## 🤖 Agent Skill (for AI coding agents)

The repo ships `skill/SKILL.md` in the Agent Skills format:

```bash
cp skill/SKILL.md ~/.claude/skills/anubis-guardian/SKILL.md   # Claude Code
```

or commit it and reference it from `CLAUDE.md` / `AGENTS.md`. The skill teaches the agent to run the scan, read findings honestly (`needs_confirmation` included), point the human at quarantine tests, and propose **suggested diffs only — applying nothing without explicit human approval**.

## ✅ Tests (regression gates)

```bash
npm test   # build + honeypot + clean + sarif + acceptance v0.2 + v0.3 + mode2 + acceptance v0.4
```

- `tests/honeypot/` — **49 planted seeds** across 2 roots: secrets, headers, seeders, RLS depth-II, CI workflows, Dockerfiles, deps, crypto, rule packs II, all 5 taint flows, agent-environment risks
- `tests/clean/` — per-rule clean-case corpus (allowlisted fetch, pinned MCP servers, scoped allows, guarded redirects…) — score stays **100 / A**
- `tests/verify-sarif.mjs` — SARIF schema/masking/determinism checks
- `tests/acceptance-v02.mjs` — init-ci pins, gates, byte-identical determinism, workspaces, org rules, cross-root CRITICAL
- `tests/acceptance-v03.mjs` — AI review with a mock provider: verifier accepts grounded claims / rejects hallucinated + missing-file + unknown-rule claims, redaction-before-LLM verified on the wire, authz matrix + canary generation, hook enforcement (blocks + allows), SKILL.md contract
- `tests/mode2/` — **v0.4 URL Mode**: planted-hole server (33/33 verify) + acceptance **47 gates**: L1 passivity proven from the request log, gate refusals (public-domain L2 un-gated, checkbox-for-public, L3 self-attested), .well-known + DNS-TXT verification, Supabase anon probe analysis (GET-only), byte-identical from-capture determinism, all renderers, rate limiting, clean control (90/A exactly), ownership command

## 🗺️ Roadmap & build status

| Stage | Status |
|---|---|
| Step 0 — pattern-frequency study (100 public AI-built projects) | ✅ done |
| v0.1 — Codebase core (CLI, secrets, history, score, 2 playbooks) | ✅ done |
| v0.2 — Depth + integrations (SCA, NestJS, CI/Docker, SARIF, init-ci, multi-root) | ✅ done |
| v0.3 — Agent Skill + AI Review + taint-lite + authz matrix + rule packs II + guard hook | ✅ done |
| **v0.4 — URL Mode (Mode 2): L1 passive + L2 verified ownership + L3 Supabase probe (this release)** | ✅ **done** |
| **v1.0 — Public release: rules supply-chain guard + restricted differential IDOR + init-zap + SBOM/provenance + METHODOLOGY.md + BENCHMARKS.md (measured only) + install→report smoke (this release)** | ✅ **done** |
| v1.0 owner actions — `npm publish` to the registry + field validation on Business-OS (the real dogfood) | ⬜ owner |

> **Both modes shipped + release engineering done.** The v1.0 L3-active decision is implemented: the restricted differential access check (`--active-tests`: GET-only, verified ownership, owner identities, ≤24 endpoints, values never stored) + `init-zap` delegates everything deeper to a reviewable ZAP config — the engine still embeds no DAST. Remaining owner actions: the actual `npm publish` (workflow ready: `.github/workflows/release.yml` — Trusted Publishing + provenance + SBOM + checksums) and the Business-OS field validation.

## 📁 Repo layout

```
src/            scan engine (TypeScript, Node ≥ 18, only runtime dep: commander)
  urlmode/      v0.4 Mode 2: capture fetcher, ownership gate, L1/L2/L3 checks, analyze
  advisory/     bundled OSV advisory snapshot + popular-package list (typosquat)
  ai/           v0.3 AI review pipeline: redaction → LLM → independent verifier
  rules/        Layer 1/2/3/4/5 rule implementations (incl. packs2, taint, agentenv)
  report/       deterministic renderers: terminal, md, sarif, html, compact, fix-prompt
  authz.ts      v0.3 authz matrix + quarantine generator
  inithook.ts   v0.3 guard hook (pinned PreToolUse script)
  inventory.ts  Phase 0 recon inventory
  adapters.ts   gitleaks / osv-scanner / semgrep (opt-in) + update-advisories
skill/          SKILL.md — Agent Skills format for IDE agents (both modes)
studies/        Step 0 pattern-frequency study — full 100-project sweep results
tests/          honeypot (49 seeds) + clean corpus + SARIF + acceptance v0.2/v0.3 + mode2/ (v0.4)
docs/           full bilingual design plan (docs/PLAN.master.md)
PLAN.en.md      the project plan — English
PLAN.ar.md      the project plan — Arabic (الخطة بالعربية)
```

## 📄 License

MIT — see [LICENSE](LICENSE). Full design & decision log: [docs/PLAN.master.md](docs/PLAN.master.md).

---

# 🇪🇬 الشرح بالعربية — Full Guide in Arabic

## ليه Anubis Guardian؟

وكلاء البرمجة بالذكاء الاصطناعي بيطلّعوا تطبيقات كاملة في أيام — لكن بنمط أمني متكرر ومعروف: مفاتيح service_role واصلة للـ client، باسوردات قاعدة البيانات في HTTP headers، Row-Level Security ناقصة، JWT في `localStorage`، ملفات `.env` مرفوعة على GitHub، وGitHub Actions بدون SHA pinning.

السكينرات الموجودة أقوياء لكنهم عامين — مش متصممين للنمط ده. **Anubis Guardian** متصمم له بالظبط: قواعد deterministic لستاك الـ AI (Supabase / Next.js / NestJS) + فحص أسرار وتاريخ git + تحليل اعتماديات ضد advisory snapshot مدمج من OSV.dev + فحوص CI وسلسلة التوريد + taint-lite + فحوص بيئة الـ agent + طبقة AI Review اختيارية عليها verifier مستقل — كله بمخرجات مُقنَّعة (masking) ودرجة أمن واحدة من 100.

> **الأولويات مبنية على بيانات:** دراسة [Step 0](studies/step0-pattern-study/RESULTS.md) مسحت **100 مشروع عام مبني بالذكاء الاصطناعي (3,403 ملف)** — أعلى الأنماط: CI actions بدون pinning **22%** · `Math.random` للتوكنات **11%** · `dangerouslySetInnerHTML` **7%**.

## التشغيل خطوة بخطوة

```bash
# 1) انسخ الريبو وادخل عليه
git clone https://github.com/<your-username>/anubis-guardian.git
cd anubis-guardian

# 2) نزّل الاعتماديات وابنِ الأداة (Node >= 18 مطلوب)
npm install && npm run build

# 3) افحص أي مشروع — التقرير بيظهر في التيرمينال
node dist/cli.js scan ./path/to/your-project
```

اختياري — أمر عالمي على جهازك:

```bash
npm link          # بعدها تقدر تكتب مباشرة:
anubis-guardian scan ./my-project
```

> npm (`@anubis-guardian/cli`) **جاهزة للنشر في v1.0** — workflow النشر (Trusted Publishing + provenance + SBOM + checksums) موجود في `.github/workflows/release.yml`؛ ولحد ما المالك ينفّذ publish الفعلي، ثبّت من المصدر زي فوق.

## أهم أوامر الفحص — بالعربي

```bash
node dist/cli.js scan ./my-project                     # التقرير التفاعلي في التيرمينال
node dist/cli.js scan ./frontend ./backend             # multi-root: فحص فرونت وباك مع ربط النتائج بينهم
node dist/cli.js scan . --workspaces                   # مونوريبو: تقرير لكل app + تقرير مجمّع
node dist/cli.js scan ./my-project --format json --output findings.json   # النتائج JSON
node dist/cli.js scan ./my-project --format compact    # ملخص موفّر للتوكِن — مناسب للـ agents
node dist/cli.js scan ./my-project --fail-on critical  # بوابة CI: exit 1 لو في CRITICAL
node dist/cli.js scan ./my-project --fail-on-cve       # بوابة الاعتماديات (DEP-001)
node dist/cli.js scan ./my-project --sarif results.sarif   # SARIF 2.1.0 → تاب Security في GitHub
node dist/cli.js scan ./my-project --fix-prompt fix.md     # برومبت إصلاح جاهز لأي AI agent
node dist/cli.js scan ./my-project --html report.html      # تقرير HTML كامل
node dist/cli.js scan ./my-project --inventory inventory.json   # جرد المسارات والجداول والـ webhooks
node dist/cli.js scan ./my-project --schema dump.sql   # schema export بتشغّله إنت → فحص dashboard drift
node dist/cli.js scan ./my-project --rules-dir .anubis/rules   # قواعد مؤسسية مخصصة (JSON DSL)
node dist/cli.js scan ./my-project --tools gitleaks,osv-scanner,semgrep   # adapters اختيارية
node dist/cli.js scan ./my-project --online            # فحص slopsquat (غير حتمي — معلَّم في meta)

# ——— جديد في v0.3 ———
node dist/cli.js scan ./my-project --ai-review         # طبقة AI Review (تحتاج ANUBIS_AI_API_KEY)
node dist/cli.js scan ./my-project --quarantine ./anubis-quarantine   # توليد اختبارات canary للـ taint
node dist/cli.js test-authz ./my-project --quarantine anubis-quarantine   # مصفوفة الصلاحيات + اختبارات مولّدة
node dist/cli.js init-hook                             # تركيب الـ guard hook (وقاية لحظة الكتابة)

# ——— جديد في v0.4: Mode 2 — فحص موقع منشور بالرابط ———
node dist/cli.js scan-url https://example.com                  # L1 passive — مجاني، من غير أي إثبات ملكية
node dist/cli.js ownership https://example.com                 # بيطبع nonce + تعليمات DNS TXT أو .well-known
node dist/cli.js ownership https://example.com --check <nonce>  # تحقق من الـ nonce اللي نشرته
node dist/cli.js scan-url https://example.com --level 2 --ownership-token <nonce>   # L2 discovery (ملكية متحققة)
node dist/cli.js scan-url http://127.0.0.1:3000 --level 2 --i-own-this-domain       # localhost/staging بس (ومعلَّم في التقرير)
node dist/cli.js scan-url https://example.com --level 3 --ownership-token <nonce>   # L3 = L2 + probe الـ Supabase الحي (GET فقط)
node dist/cli.js scan-url https://example.com --capture capture.json            # حفظ الـ capture الخام (دليل + إعادة إنتاج)
node dist/cli.js scan-url https://example.com --from-capture capture.json       # إعادة تحليل أوفلاين — متطابق بايت-ببايت
node dist/cli.js scan-url https://example.com --fail-on high --sarif r.sarif --fix-prompt fix.md

node dist/cli.js init-ci                               # workflow جاهز بأقل صلاحيات + SHA pins حقيقية
node dist/cli.js update-advisories                     # تحديث محلي لـ snapshot الاعتماديات من OSV.dev
```

**أكواد الخروج:** `0` ناجح · `1` بوابة الأمان اترفض · `2` خطأ استخدام/مسح.

## الجديد في v0.3 — بالعربي

- **Rule packs II:** تسريب أسرار في الـ logs (`LOGS-001`) · سياسات RLS معتمدة على `user_metadata` القابلة للتعديل من المستخدم (`SUPA-002`) · Edge Functions بـ service_role من غير تحقق متصل (`SUPA-003`) · auth في middleware بس مع ثغرات في الـ matcher (`AUTH-001`) · mass assignment (`MASS-001`) · Socket.IO بدون auth (`WS-001`) · webhooks بدون توقيع (`WEBHOOK-001`) · `jwt.decode` لقرارات الأمان (`JWT-001`) · `algorithms:"none"` و`ignoreExpiration` (`JWT-002`) · Swagger مكشوف في production (`SWAGGER-001`)
- **Taint-lite (5 قواعد):** SSRF · open redirect · path traversal · command injection · XSS منعكس — بنطاق ملف واحد، سقف MEDIUM، وتأكيد باختبار canary مولّد تشغّله إنت بنفسك
- **بيئة الـ agent:** MCP بدون تثبيت إصدار · أسرار جوه config الـ agent · صلاحيات wildcard/bypass · hooks بتشغل كود بعيد
- **AI Review (اختياري):** الـ LLM بيقترح و**verifier مستقل بيرفض أو يقبل** — أي snippet مش موجود فعليًا في الملف بيرفض؛ ونتائج الـ AI سقفها HIGH عمرها ما CRITICAL؛ والتقنيع قبل الإرسال للـ LLM إجباري
- **مصفوفة الصلاحيات + quarantine:** الأداة **بتولّد** اختبارات Supertest/Playwright فاشلة-بالتصميم — وهي **عمرها ما بتشغلها**؛ إنت بتراجعها وتشغلها على staging
- **Guard hook:** وقاية لحظة الكتابة — بيمنع service_role في كود الـ client وSQL اللي بيقتل RLS والأسرار في `.env` قبل ما تتسجل أصلًا

## الجديد في v0.4 — بالعربي (Mode 2: الفحص بالرابط)

- **L1 passive (الافتراضي المجاني):** TLS والشهادة · الـ security headers (CSP/HSTS/clickjacking/nosniff/referrer/permissions) · flags الكوكيز (Secure/HttpOnly/SameSite) · **الأسرار المتشحّنة جوه ملفات الـ JS العامة — أشهر ثغرة في مشاريع الـ AI، وموجودة في L1 نفسه من v1.3** · كشف إصدار السيرفر · endpoints داخلية في الـ bundles · بصمة التقنية — **طلبات مطابقة للمتصفح حرفيًا** (الصفحة + robots.txt + sitemap.xml + security.txt + ملفات الـ JS اللي الصفحة بتحمّلها) ومفيش أي probing خالص
- **L2 discovery:** ملفات `.env` و `.git` والـ dumps والنسخ الاحتياطية مكشوفة · directory listing · TRACE (XST) وأوامر خطرة في `Allow` · Swagger/GraphiQL مكشوفة · source maps بتنزّل الكود الأصلي — **كله مقفول ورا إثبات ملكية متحقق منه** للدومينات العامة (DNS TXT `anubis-guardian-challenge=<nonce>` أو ملف `/.well-known/anubis-guardian/<nonce>`) — والـ self-attestation محصورة localhost/staging ومعلَّمة في التقرير
- **L3 (نطاق v0.4):** L2 + **الـ Supabase live anon probe**: `GET /rest/v1/<table>?select=*&limit=1` بمفتاح anon المتلقى من الـ JS العام — إثبات حي إن الـ RLS شغال أو لا في البيئة الحية — **ملكية متحققة إجباريًا**، وعمره ما بيتشغل بالـ flag لوحده
- **البوابة القانونية:** أي L2+ على دومين عام من غير nonce متحقق منه ⇒ exit 2 **قبل أي طلب واحد** — `--i-own-this-domain` مجرد checkbox مش إثبات — وكل تقرير فيه **scan authorization record** (الرابط، التوقيت، المستوى، طريقة الملكية) + rate limits صارمة + احترام robots.txt + ممنوع الفحص ببيانات دخول
- **نفس عقد المخرجات:** `findings.json` + كل الصيغ + `fix-prompt.md` — وكل finding معاها إرشاد **"فين في الكود"** حسب الـ framework المكتشف، والـ verify line بتقول `scan-url` بنفس المستوى
- **الحتمية في Mode 2:** نفس الـ capture ⇒ نفس `findings.json` بايت-ببايت (`--from-capture` — صفر شبكة) — لأن الـ wire نفسه متغير بالطبيعة، فالحتمية معرّفة على الـ capture

## الجديد في v1.0 — بالعربي (الإصدار العام)

- **rules-lock (حرس سلسلة توريد القواعد):** `anubis-guardian rules-lock <dir>` بيثبّت ملفات القواعد بـ SHA-256 — والـ scan بيرفض أي ملف معدّل/غير مثبّت (exit 2) إلا لو `--allow-community-rules` (وقتها التقرير بيتعلّم `meta.rules_lock: bypassed` + `community_rules: true` — quarantine صريح)
- **الفحص التفاضلي المُقيَّد (`--active-tests` — قرار L3 النشط):** L3 بس + **ملكية متحققة إجباريًا** (الـ checkbox عمرها ما تكفي حتى محليًا) + **GET فقط بالبناء** + هويتين testing من المالك (`--identity-a` المميّزة و`--identity-b` المقيدة) + سقف 24 endpoint (مسارات JSON مكتشفة + `--idor-path` من المالك) + semantic diff — والـ **قيم الهويات عمرها ما بتتخزن** في الـ capture ولا في أي تقرير. النتيجة: `URL-061` HIGH مع `needs_confirmation` لما الهوية المقيدة تستقبل نفس رد المميزة — و`URL-909` ملخص إعلامي
- **init-zap (التفويض بدل التضمين):** توليد config جاهز لـ OWASP ZAP baseline على staging بتاعك — `--active` على دومين عام محتاجة nonce متحقق منه — **المحرك لسه من غير DAST بالتصميم**
- **هندسة النشر:** SBOM (CycloneDX 1.5) + provenance attestation + checksums + workflow إصدار موقّع (`.github/workflows/release.yml` بمسارات actions مثبتة بـ SHAs حقيقية) + `METHODOLOGY.md` + `CONTRIBUTING-RULES.md` + موقع docs جاهز لـ GitHub Pages + **`BENCHMARKS.md` بالأرقام المقاسة فقط** (honeypot 49/49 · clean 0 FP · NodeGoat وJuice Shop كمجموعات sanity خارجية)
- **اختبار install→report:** الحزمة بتعمل pack وتنصّب وتطلّع أول تقرير في أقل من دقيقتين — متحقق منه في بوابات الـ acceptance (45 بوابة جديدة)

## نظام الدرجات

```
score = 100 − (25 × CRITICAL + 10 × HIGH + 4 × MEDIUM + 1 × LOW)      درجات A–F
```

- **سقوف حسب السبب الجذري:** أول finding بيخصم كامل، والتكرار +10% بس، والمجموعة مسقوفة على 2×.
- **الثقة المنخفضة و INFO عمرها ما بتخصم** — ومطالبات الـ AI المرفوضة من الـ verifier بتتسجل كمراجعة وبتخصم صفر.
- `score_breakdown` بيوريك بالظبط إيه اللي خصم وليه.

## الضمانات — عقد الأداة

- **مفيش تنفيذ لكود المشروع المفحوص** — قراءة ملفات + git plumbing بس. الاختبارات المولّدة بتتحط في quarantine وإنت اللي بتشغلها. أي نداء شبكة ورا flags صريحة وبيتعلم في `meta`.
- **تقنيع إجباري في كل المخرجات** — بما فيه مسار برومبت الـ AI Review؛ الدليل = النوع + الموقع + أول 4 حروف + بادئة sha256.
- **حتمية كاملة افتراضيًا** — نفس الكود + نفس الإصدار ⇒ `findings.json` و`fix-prompt.md` متطابقين بايت-ببايت. وطبقة الـ AI اختيارية ومعلَّمة (`meta.ai_used`).
- **مفيش CRITICAL من غير تأكيد مستقل** — ونتائج الـ AI سقفها HIGH حتى لو الـ verifier أكدها.
- **Rotate-first** — كل سر مكتشف معاه خطوات تدوير مزوّده.
- **وقاية مش بس كشف** — الـ guard hook بيوقف الأخطاء الكلاسيكية قبل ما تتحفظ.

## الـ CI/CD — أتمتة الفحص على GitHub

```bash
node dist/cli.js init-ci
```

بينشئ `.github/workflows/anubis-guardian.yml`: أقل صلاحيات، actions مثبّتة بـ SHA حقيقية، الفحص على كل PR وpush، SARIF على تاب Security، وبوابة `--fail-on critical`. الأمر idempotent.

## الـ Agent Skill — تشغيل الأداة من جوه AI coding agent

```bash
cp skill/SKILL.md ~/.claude/skills/anubis-guardian/SKILL.md   # Claude Code
```

أو commitه وأشر عليه من `CLAUDE.md` / `AGENTS.md`. الـ skill بتعلّم الـ agent يشغّل الفحص، يقرا النتائج بصراحة، يوصل المالك لاختبارات الـ quarantine، ويقترح **suggested diffs بس — من غير تطبيق من غير موافقة بشرية صريحة**.

## الاختبارات — بوابات الانحدار

```bash
npm test   # build + honeypot + clean + sarif + acceptance v0.2 + v0.3 + mode2 + v0.4 + v1.0
```

- `tests/honeypot/` — **49 بذرة مزروعة** عبر root اتنين: أسرار، headers، seeders، RLS عمق تاني، CI، Docker، اعتماديات، crypto، rule packs II، تدفقات الـ taint الخمسة، وبيئة الـ agent
- `tests/clean/` — corpus نظيف لكل قاعدة — الدرجة لازم تفضل **100 / A**
- `tests/acceptance-v03.mjs` — الـ AI Review بمزوّد mock: الـ verifier بيقبل المدعّم ويرفض المهلوَل، والتقنيع متحقق على مستوى الـ wire، ومصفوفة الصلاحيات والـ hook بيمنع ويسمح صح

## خارطة الطريق وحالة البناء

| المرحلة | الحالة |
|---|---|
| Step 0 — دراسة تكرار الأنماط (100 مشروع) | ✅ تمت |
| v0.1 — نواة فحص الكود | ✅ تمت |
| v0.2 — العمق والتكاملات (SCA، NestJS، CI/Docker، SARIF، multi-root) | ✅ تمت |
| **v0.3 — Agent Skill + AI Review + taint-lite + authz matrix + rule packs II + guard hook** | ✅ **تمت** |
| **v0.4 — Mode 2: الفحص بالرابط — L1 passive + L2 بإثبات ملكية + L3 probe الـ Supabase (الإصدار ده)** | ✅ **تمت** |
| **v1.0 — الإصدار العام: rules-lock + الفحص التفاضلي المُقيَّد + init-zap + SBOM/provenance + METHODOLOGY.md + BENCHMARKS.md (أرقام مقاسة فقط) + اختبار install→report (الإصدار ده)** | ✅ **تمت** |
| v1.0 — خطوات المالك: `npm publish` الفعلي على السجل + التحقق الميداني على Business-OS | ⬜ المالك |

> **الوضعين اكتملوا + هندسة الإصدار تمت.** قرار L3 النشط اتنفّذ: الفحص التفاضلي المُقيَّد (`--active-tests`: GET فقط، ملكية متحققة، هويات من المالك، ≤24 endpoint، القيم عمرها ما بتتخزن) + `init-zap` بيفوّض الأعمق لـ config لـ ZAP — والمحرك من غير DAST بالتصميم. المتبقي على المالك: `npm publish` الفعلي (الـ workflow جاهز: Trusted Publishing + provenance + SBOM + checksums) والتحقق الميداني على Business-OS.

## ملفات الشرح والخطة في الريبو

| الملف | المحتوى |
|---|---|
| [`PLAN.ar.md`](PLAN.ar.md) | **الخطة كاملة بالعربية** — الرؤية، التغطية، الأنماط، الدرجات، خارطة الطريق بحالة البناء |
| [`PLAN.en.md`](PLAN.en.md) | The full plan in English |
| [`docs/PLAN.master.md`](docs/PLAN.master.md) | سجل التصميم التفصيلي ثنائي اللغة + Decision Log الكامل |

## الرخصة

MIT — شوف [LICENSE](LICENSE).
