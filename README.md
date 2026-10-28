<div align="center">

<img src="https://raw.githubusercontent.com/EMAD11223344/anubis-guardian/main/docs/assets/hero.svg" alt="Anubis Guardian — multi-layer repository security scanner: deterministic, offline static analysis" width="100%">

# ⚱ Anubis Guardian

**A multi-layer repository security scanner with a deterministic, reproducible report — built for codebases written by AI coding agents**

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.5.1-8b5cf6.svg)](package.json)
[![Node](https://img.shields.io/badge/node-%E2%89%A518-blue.svg)](package.json)
[![npm](https://img.shields.io/badge/npm-install%20--global-cb3837.svg)](https://www.npmjs.com/package/anubis-guardian)
[![Tests](https://img.shields.io/github/actions/workflow/status/EMAD11223344/anubis-guardian/ci.yml?branch=main&label=tests)](https://github.com/EMAD11223344/anubis-guardian/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/actions/workflow/status/EMAD11223344/anubis-guardian/release.yml?branch=main&label=release%20gate)](https://github.com/EMAD11223344/anubis-guardian/actions/workflows/release.yml)

**Secrets & git history · SAST & taint · Authorization · Dependencies · CI & supply-chain · Infra-as-code · SARIF · Coverage manifest — offline by default**

</div>

<!-- A short demo video / animated terminal recording belongs here when one exists. -->

---

## What it is

Anubis Guardian scans a **whole repository** — every text file, not just `.js`/`.ts` — and produces a deterministic, byte-reproducible report: masked secrets, severity scoring, a **coverage manifest** that states what ran and what didn't, and `needs_confirmation` review prompts for everything static analysis cannot see. It is offline-first (no network calls without explicit consent flags), never executes scanned code, and writes nothing into the scanned tree.

Detection is organized in **capability tiers**, so the report is honest about language boundaries:

| Tier | What it covers | Languages |
|---|---|---|
| **1 · Universal repo layers** | committed & git-history secrets, credentials in configuration formats, `.env` hygiene, sensitive files, GitHub Actions supply-chain, Docker hardening, Firebase rules, Terraform public-exposure, agent config (`.mcp.json`) | **any language / any stack** — config and repo surfaces |
| **2 · JS/TS code analysis** | SAST, taint-lite flows, authorization evidence, tenant isolation, data-leakage, resource-exhaustion, upload security | JavaScript / TypeScript |
| **3 · Framework playbooks (optional)** | Supabase (RLS, service-role), Next.js (client/server boundary), NestJS (guards, CORS, helmet) | only when the repo uses them — **never prerequisites** |
| **4 · Opt-in tools & modes** | gitleaks / osv-scanner / semgrep adapters, `--online` registry checks, consent-gated URL mode, AI review, agent write-guard hook | declared inputs only, disclosed in report metadata |

Tier 1 works on Python, Go, Java, Ruby, Rust, Terraform, YAML, shell, TOML/INI/JSON — anything textual. Tier 2's deeper code-level analysis is **JS/TS-only and this is disclosed, not implied** (see [Language coverage](#language-coverage--honest-boundaries)).

## 30-second start

```bash
npm install -g anubis-guardian

anubis-guardian scan .                 # offline audit of the current repo
anubis-guardian scan . --fail-on high  # CI gate: exit 1 on HIGH+
```

Open the report. Every finding carries a masked value, the exact file and line, a suggested fix, and — where static analysis cannot confirm — a `needs_confirmation` prompt naming the invisible layer (middleware, database RLS, runtime values). The coverage manifest in the same report states `checks_run / checks_applicable` and the full `classes_not_covered` list, so a grade **A** reads as *"nothing was found by the executed checks"* — never as *"this codebase is secure"*.

## What it detects (tier 1 — universal, any language)

| Layer | Rule family |
|---|---|
| Provider secret shapes (AWS/Stripe/OpenAI/Slack/JWT service-role keys by value, private-key material, DB URLs with passwords) | `SEC-001..009` |
| **Credentials in configuration formats** — tokenized key names (`DB_PASSWORD`, `spring.datasource.password`, `jwt.secret`) with quoted **or bare** values in `.properties`/`.ini`/`.toml`/`.tf`/`.yaml`/`.json`/`.py`/`.go`/shell | `SEC-010` |
| Committed `.env` files with live values; env hygiene vs public-by-design entries | `ENV-001`, `SUPA-001` |
| Secrets recoverable from git history — committed-then-removed keys, deleted env backups, scrubbed-file traces | `HIST-001..011` |
| Sensitive files in the tree — DB dumps, `.npmrc`, service-account JSON, SSH keys, tfstate | `FILE-001..006` |
| GitHub Actions — mutable action refs, `pull_request_target` footguns, script injection from event context, missing permissions | `CI-001..004` |
| Docker — root user, `:latest`, `ARG`-carried secrets | `DOCKER-001..003` |
| Firebase security rules — world-writable policies (`allow write: if true`); public-read as a review note | `FB-001` |
| Terraform — public-read storage ACLs (HIGH + `needs_confirmation`: static-site hosting can be intentional) | `TF-001` |
| npm dependency audit — CVEs against the bundled advisory snapshot, known-malicious packages, typosquats, no-lockfile hallucination candidates | `DEP-001..005` |
| Agent environment — unpinned MCP servers, secrets in agent configs, permission wildcards | `AGENT-001..004` |

## Tier 2 — JS/TS code analysis

- **SAST** — dynamic SQL, `eval`/`exec`, weak hashing, dangerous HTML (`SAST-001..004`, `CRYPTO-001`)
- **Taint-lite** — SSRF, open redirect, path traversal, injection, reflected XSS, code-execution flows through a **bounded data-flow chase** (≤4 assignment hops, same function, cycle-safe) (`TAINT-001..006`, `JWT-*`)
- **Authorization evidence** — mutating handlers with no recognizable authz call (`AUTHZ-001`) and decisions taken from client-controlled input, including parsed `request.json()` bodies and one-hop aliases (`AUTHZ-002`); tenant-isolation hints (`TEN-001/002`)
- **Data leakage / resources / uploads** — credential-shaped responses, whole-object serialization of wide queries, pagination-less reads, missing timeouts, upload & archive guards (`LEAK-*`, `RES-*`, `UPLOAD-*`, `MASS-001`, `WEBHOOK-001`, `WS-001`, `LOGS-001`)

## Language coverage — honest boundaries

| Your code | What fires |
|---|---|
| **JS / TypeScript** (any framework) | Tiers 1 + 2 in full |
| **Python, Go, Java, Ruby, Rust, …** | Tier 1 config/repo layers: secret shapes by value, `SEC-010` config credentials (e.g. Python `DB_PASSWORD = "…"`, Java properties, Terraform attributes), `FB-001`/`TF-001` infra policies, CI/Docker/history/dependencies-of-the-repo layers |
| **Code-level SAST for non-JS/TS languages** | ❌ **not analyzed** — declared non-goal (`classes_not_covered`); use the opt-in Semgrep adapter for code-level depth in other languages |
| **`requirements.txt` / `go.mod` / `Cargo.toml` version auditing** | ❌ **not audited** — the bundled advisory snapshot is npm-ecosystem-only; manifests are inventoried, versions are not checked |
| **Any database / ORM in JS/TS** | query-pattern recognition (raw SQL strings, Prisma/Drizzle/TypeORM-style calls, chained builders) — not an exhaustive SQL parser; reach is disclosed per report |

Supabase, Next.js and NestJS are **optional playbooks** that add host-aware depth when the repo uses them (`SUPA-R01..R08`, `NEXT-*`, `NEST-001..004`) — the universal layers never require them, and if none apply the coverage manifest says so.

## A real report excerpt

From the committed multilingual regression corpus (`tests/multilingual/`, scan of a Python/Go/Java/Terraform fixture — values are masked by contract):

```json
{
  "id": "SEC-010",
  "severity": "high",
  "title": "Hardcoded credential in configuration (\"spring.datasource.password\")",
  "file": "java/src/main/resources/application.properties",
  "line": 3,
  "evidence": {
    "type": "hardcoded_credential_config",
    "masked": "Pr0d•••… (first-4 + sha256:c2486be6)"
  },
  "needs_confirmation": false,
  "remediation": { "type": "rotate-first",
    "steps": "1) Confirm the value is real 2) Rotate it at the provider 3) Load from server-side env / secret manager 4) Scrub git history if committed" }
}
```

Findings carry `fix` + `fix_mode: "suggested-diff"` — for any AI agent, `--fix-prompt fix.md` turns the report into a deterministic repair prompt; `--format sarif` uploads to the GitHub Security tab.

## Measured performance & detection

Every number below reproduces from [`scripts/measure-benchmarks.mjs`](scripts/measure-benchmarks.mjs) on the environment recorded in [BENCHMARKS.md](BENCHMARKS.md) — no number appears there without a measurement, and unmeasurable entries are marked PENDING:

| Measured on the committed corpora (commit-pinned) | Result |
|---|---|
| Curated honeypot self-test (49 planted checks, 2 roots) | **49/49 detected**, masking contract intact |
| Clean-project false-positive control | **0 findings above threshold — score 100, grade A** |
| Labelled corpus - fixture-level expected-rule detection (17 vulnerable + 12 safe adjudicated cases) | **17/17 expected hits at exact rule+file+line, 0 unexpected findings on safe fixtures** (extras on vulnerable fixtures are counted and reported separately) - self-curated manifest [benchmarks/corpus](benchmarks/corpus/cases.json), case-level metric, not an external-recall claim |
| **Multilingual regression corpus** (Python/Go/Java-properties/Terraform/Actions/Docker/Firebase/manifests + safe counterparts) | **20/20 expected detections at exact rule+file+line, 0 FP, out-of-scope boundaries locked silent** — manifest [tests/multilingual/manifest.json](tests/multilingual/manifest.json) |
| Skilled-tool comparison (gitleaks, pinned 8.30.1, identical trees) | **3/3** labelled secret cases matched, 0 FP on safe files; Semgrep numerical comparison **PENDING** with a full scope matrix |
| Scale on the benchmark hardware | single-root fixture scan ≈ sub-second (0.66 s for the ~30-file honeypot tree) — per-measurement wall times, environment, and the adversarial worst case are recorded in [BENCHMARKS.md](BENCHMARKS.md) |

> Wall times are local-machine records for scale transparency — **not universal performance guarantees**. The documented worst case (an adversarial ~4 MB pathological file, ~70 s) and its regression gates are disclosed in the limitations.

## How it differs from a secret scanner or a general SAST engine

| | Anubis Guardian | Secret scanners (e.g. gitleaks) | General SAST engines (e.g. Semgrep) |
|---|---|---|---|
| **Detection focus** | repository surface (secrets, history, CI, deps, IaC) + JS/TS app logic: authz evidence, tenant isolation, taint to sinks, framework playbooks | secret patterns in files and git history | whatever rules/ruleset the operator curates — arbitrary breadth |
| **Zero-config value** | opinionated battery out of the box with masking + scoring + coverage manifest | strong on the one class it targets | depends entirely on the ruleset you pick; no scoring contract |
| **Evidence discipline** | two-tier contract: evidence-backed vs `needs_confirmation` review prompts; no-CRITICAL-without-confirmation; root-cause caps | matched/unmatched secrets | confidence calibration depends on the selected ruleset |
| **Measured overlap** | on identical trees both tools matched all labelled secret cases (**3/3**, 0 FP, with an FP-accounting calibration fixture) — scope and detail in [BENCHMARKS.md](BENCHMARKS.md) | | |

There is no "winner" to claim — the tool classes overlap on secrets and diverge everywhere else, and the [comparison section of BENCHMARKS.md](BENCHMARKS.md) pins versions, configuration, matching rules, and every pending scope instead of fabricating superiority.

## URL mode (consent-gated)

For a **deployed site you own** — passive-first, with a verified ownership gate before any active check:

```bash
anubis-guardian scan-url https://example.com            # L1 passive (browser-equivalent)
anubis-guardian ownership https://example.com           # generate a verification nonce
anubis-guardian scan-url https://example.com --level 2 --ownership-token <nonce>
```

L1 is always passive (headers, cookies, secrets in public bundles). L2 discovery and L3 probing require verified ownership — a DNS TXT record or `/.well-known` file — and private targets additionally need `--allow-private`. Cloud metadata endpoints are refused unconditionally. **Scanning systems you do not own is illegal; the tool enforces the gate rather than relying on your promise.**

<p align="center">
  <img src="https://raw.githubusercontent.com/EMAD11223344/anubis-guardian/main/docs/assets/modes.svg" alt="Anubis Guardian modes — Mode 1: offline codebase audit (universal repo layers, JS/TS analysis, optional framework playbooks); Mode 2: consent-gated URL audit (L1 passive, L2 discovery, L3 probe — verified ownership required)" width="100%">
</p>

## Output formats & exit codes

`terminal` (default) · `json` · `md` · `sarif` · `html` · `compact`, plus `--fix-prompt fix.md` (a deterministic repair prompt for any AI agent) and `--inventory inventory.json` (static attack-surface map).

| Exit | Meaning |
|---|---|
| `0` | scan completed; findings (if any) below the gate |
| `1` | gate threshold breached (`--fail-on` / `--fail-on-cve`) |
| `2` | fail-closed: no trustworthy report (bad path, unknown options, size cap, unreachable URL target, external-tool failure) |

No partial reports: a fail-closed run writes nothing and prints no score.

```bash
# common invocations
anubis-guardian scan . --format json -o findings.json
anubis-guardian scan . --sarif results.sarif             # GitHub Security tab
anubis-guardian scan ./web ./api                         # frontend + backend, cross-root linkage
anubis-guardian scan . --workspaces                      # monorepos
anubis-guardian scan . --tools gitleaks                  # opt-in adapters (fail-closed)
```

## Scoring, severity, confidence

```
score = 100 − (25 × CRITICAL + 10 × HIGH + 4 × MEDIUM + 1 × LOW)      grades A–F
```

- A **CRITICAL** requires independent confirmation (e.g. reachability analysis proving a service key is client-imported); everything merely suspicious is MEDIUM/HIGH + `needs_confirmation`
- Root-cause caps: repeated findings of the same root cause deduct at most 2× the first; `score_breakdown` in the JSON explains every deduction
- The coverage manifest lists what ran; `classes_not_covered` states what the tool does **not** attempt

## What Anubis Guardian does NOT prove

- **A finding is evidence, never proof.** Authorization/tenant findings follow the two-tier contract: a missing *visible* check (`AUTHZ-001`, MEDIUM) is a review prompt — middleware, framework guards, and database RLS are legitimately invisible to static analysis and always win.
- **The analysis is bounded, by design.** Rules are structured regex/heuristics over a shared bounded data-flow chase (≤4 assignment hops, same function scope, one imported-local-helper level) — **no AST parser, no call graph, no cross-function/cross-file data flow**. Deeper aliasing and helper-mediated flows are tracked only to documented bounds; what a scan did not chase is in the coverage manifest.
- **Non-JS/TS code-level defects are not claimed.** Python/Go/Java SQLi, debug-mode, weak-randomness and similar code patterns in other languages are out of scope (the multilingual corpus **locks these boundaries silent** so a future rule cannot start firing there unnoticed); the Semgrep adapter is the opt-in path.
- **Recall claims stay local.** The labelled corpus (29 adjudicated cases) and the multilingual corpus are **self-curated** - the labelled metric is **case-level fixture detection**: a vulnerable case counts as detected only when its manifest-listed rule fires at the expected file+line with at least the manifest severity floor, safe fixtures must show no unexpected findings, and additional findings on vulnerable fixtures are counted and reported separately (not adjudicated). This is a documented self-baseline, **not** external validation and **not** finding-level precision/recall; raw counts on unlabelled projects (NodeGoat, Juice Shop) are observations, not recall.
- **Known performance boundary.** Files >512 KB are analyzed in windows to 4 MB; above 4 MB is disclosed and skipped. Worst case measured: an adversarial ~4 MB file of ~2M single-character rows scans in ~70 s on the benchmark hardware. Locked by regression gates U26.1–U26.5.
- **No DAST engine** — URL mode is consent-gated, bounded, and passive-first; deep dynamic testing belongs to your own tooling (a ZAP baseline config can be generated).
- Full list with rationale: [METHODOLOGY.md §8](METHODOLOGY.md).

## AI-agent integration

The repo ships [`skill/SKILL.md`](skill/SKILL.md) (Agent Skills format) that teaches Claude Code / Cursor / opencode to run the scan, read findings honestly, and propose **suggested diffs only** — applying nothing without approval. The optional `init-hook` guard hook blocks service-role keys, RLS-killing SQL, and secret literals **at write time**, before they enter the codebase. See [docs/AGENT-INTEGRATION.md](docs/AGENT-INTEGRATION.md).

## CI/CD

`anubis-guardian init-ci` generates a hardened GitHub Actions workflow (SHA-pinned actions, SARIF upload, `--fail-on critical`):

```yaml
- run: npx anubis-guardian scan . --fail-on critical --sarif results.sarif
- uses: github/codeql-action/upload-sarif@<pinned-sha>
  with: { sarif_file: results.sarif }
```

More flags: `--exclude` globs, `--max-files` (fail-closed size cap), `--schema dump.sql` (Supabase dashboard-drift check), `--rules-dir <dir>` (organizational JSON rules), `--quarantine` (generated authorization/canary test suites — written, **never executed** by the tool), `test-authz`, `rules-lock`, `init-zap`.

## Architecture & extending

The engine is a single deterministic pipeline with deliberate seams — not a plugin framework. The detector taxonomy (universal line-regex packs / git history / npm dependency audit / JS/TS SAST / opt-in tools), every registration point, the shared finding contracts, and the repeatable **add-a-detector procedure** (with the `infra.ts` pack as the worked example) are documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Documentation

| Document | Contents |
|---|---|
| [METHODOLOGY.md](METHODOLOGY.md) | determinism contract, scoring, false-positive control, known limitations |
| [BENCHMARKS.md](BENCHMARKS.md) | measured results only — honeypot recall, labelled corpus P/R, multilingual corpus, clean corpus, tool comparison with pinned versions & configs, wall-time scale |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | engine pipeline, detector inventory, extension points, add-a-detector procedure |
| [ROADMAP.md](ROADMAP.md) | capability-calibrated prioritized roadmap (P1–P3 items with prereqs, fixtures, risks) |
| [docs/TRUST-AUDIT.md](docs/TRUST-AUDIT.md) | release-pipeline trust review — verified controls, ranked tasks, explicit non-claims |
| [benchmarks/corpus](benchmarks/corpus/cases.json) | the adjudicated labelled corpus manifest + reproducible vulnerable/safe fixture pairs |
| [CONTRIBUTING-RULES.md](CONTRIBUTING-RULES.md) | how to contribute rule packs (clean cases mandatory, CRITICAL gating) |
| [docs/AGENT-INTEGRATION.md](docs/AGENT-INTEGRATION.md) | AI-agent wiring recipes and the exit-code contract |
| [studies/RESULTS.md](studies/step0-pattern-study/RESULTS.md) | the pattern-frequency study (100 AI-built projects) that seeded the rules |
| [docs/site](docs/site/index.html) | GitHub Pages landing page |

## Contributing

Contributions are welcome — bug reports, new universal rules, new framework playbooks, clean-case fixtures. Rule contributions follow a strict evidence format (every detection ships with its false-positive control): see [CONTRIBUTING-RULES.md](CONTRIBUTING-RULES.md) and the add-a-detector procedure in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). General issues and pull requests go through the normal GitHub flow.

## Security policy

Found a security issue in Anubis Guardian itself (not in your scanned code)? Report it privately via [GitHub Security Advisories](https://github.com/EMAD11223344/anubis-guardian/security/advisories/new) rather than a public issue — see [SECURITY.md](SECURITY.md). Scanned-code findings are not tool vulnerabilities — run the scanner on your own repo and read the report.

## Roadmap

Detailed, calibrated roadmap with per-item value/prereqs/fixtures/risks: [ROADMAP.md](ROADMAP.md).

| Stage | Status |
|---|---|
| v1.4 — six capability groups + adversarial ReDoS battery + windowed large-file scanning | ✅ shipped |
| v1.5 — window-progress guarantee, whole-object LEAK-003, RES-003 timeouts, TEN-002 reads, SSRF severity accuracy | ✅ shipped |
| Unreleased fix rounds (labeled internally v1.5.2/v1.5.3 candidates) — Next.js App Router AUTHZ/TAINT fixes, 6 reported P0 detection defects reproduced + regression-locked, benchmark-integrity repairs (pinned external SHAs, gitleaks path calibration, corpus 29 cases) | 🚧 built on main — release pending owner review |
| Multilingual round (this phase) — `SEC-010` config-credential detection, `FB-001`/`TF-001` infra pack, committed multilingual regression corpus (20/20, 0 FP), benchmark row | 🚧 built on main — release pending owner review |
| Bounded interprocedural parameter-flow analysis | 🔜 unscheduled (contract change — see ROADMAP.md R7) |

## License

MIT — see [LICENSE](LICENSE).

---

## العربية (Quick Guide)

**أنوبس جارديان** — ماسح أمني متعدد الطبقات للمستودعات (Repository Security Scanner)، حتمي (Deterministic) وسريع على المشاريع المكتوبة بجافاسكربت/تايبسكربت — خصوصًا مشاريع الذكاء الاصطناعي (vibe coding). ثابت وغير متصل بالإنترنت، لا يُنفّذ الكود المفحوص، ويقنّع الأسرار في كل المخرجات.

**طبقات عالمية بأي لغة** (أسرار ملتزمة وسجل git، أسرار في ملفات الإعدادات بـ أي صيغة، CI وDocker وقواعد Firebase وTerraform، تبعيات npm) + **تحليل كود عميق لـ JS/TS** (SAST وtaint والصلاحيات) + **ملحقات إطارات اختيارية** (Supabase / Next.js / NestJS — ليست شرطًا أبدًا)؛ حدود التغطية معلنة بصراحة في تقرير التغطية.

```bash
npm install -g anubis-guardian

anubis-guardian scan ./my-project                   # فحص المستودع — بدون إنترنت
anubis-guardian scan . --fail-on high               # بوابة CI
anubis-guardian scan-url https://example.com        # فحص موقع منشور — L1 سلبي
anubis-guardian ownership https://example.com       # إثبات الملكية للـ L2+
```
