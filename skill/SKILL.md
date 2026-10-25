---
name: anubis-guardian
description: Security audit for AI-built (vibe-coded) projects — deterministic, offline-first, static-only. TWO modes: (1) Codebase — scans code for leaked secrets (service_role keys by value, DB creds in HTTP headers, seeder credentials, committed env files, git history leaks, secrets in logs), Supabase RLS gaps (incl. policy scoping, storage, verify_jwt, user_metadata policies, unauthed service_role edge functions), Next.js auth mistakes (middleware matcher gaps, CSRF heuristic), NestJS guards/CORS/helmet + unauthenticated Socket.IO gateways, dependency CVEs (bundled OSV snapshot) + hallucinated/typosquat packages, Math.random crypto misuse, mass assignment, unverified webhooks, jwt.decode authorization, exposed Swagger, taint-lite flows, CI/supply-chain mistakes, and agent-environment risks (unpinned MCP servers, secrets in agent configs, permission wildcards). (2) URL — scans a LIVE deployed site: L1 passive (TLS/cert, security headers, cookie flags, secrets shipped in public JS bundles — browser-equivalent requests only), L2 discovery (exposed .env/.git/backups, directory listing, TRACE, exposed API docs, source maps — requires VERIFIED domain ownership via DNS TXT or .well-known nonce), L3 = L2 + Supabase live anon RLS probe (GET-only). Produces findings.json + scored report (A–F) + fix-prompt.md + SARIF + scan authorization record. Optional AI review layer with an independent verifier (--ai-review). Use when the user asks to "audit this project", "audit this site", "check security", "scan for leaked keys", or before shipping any AI-generated app.
---

# Anubis Guardian — Security Audit Skill (v1.0)

You are running the Anubis Guardian audit skill. The tool is deterministic and offline-first: Codebase Mode never touches the network; URL Mode only talks to the single target origin the user named. It never installs, builds, or runs the target project's code (static files + git plumbing only). Generated tests land in a quarantine folder — **the tool never executes them; the human does**.

> **Install note (honest):** `npx anubis-guardian scan …` works once the npm package is published. Until then, install from source: `git clone https://github.com/EMAD11223344/anubis-guardian && cd anubis-guardian && npm install && npm run build`, then run `node <repo-path>/dist/cli.js <command>` — everything below maps 1:1.

## When to use

- Before shipping any AI-generated (vibe-coded) project
- When the user says: audit / security check / scan / افحص الموقع / هل في أسرار مسربة / راجع أمان المشروع
- After generating auth, database, payments, webhooks, or deployment code
- When the user gives you a URL of a DEPLOYED site (URL Mode — see below)

## Command picker — which command when

| The user wants… | Run | Exit codes |
|---|---|---|
| A codebase security audit | `scan <path>` | 0 pass · 1 gate (`--fail-on`) · 2 usage/scan error |
| An audit with machine output for you (the agent) | `scan <path> --format json --output findings.json --fix-prompt fix-prompt.md --compact compact.txt` | same |
| A monorepo / multi-root audit | `scan . --workspaces` or `scan ./frontend ./backend` | same |
| To know if a live site leaks secrets | `scan-url <url>` (L1 passive first) | same |
| Current dependency CVE data | `update-advisories` (refresh the bundled OSV snapshot) | same |
| To prove they own a domain | `ownership <url>` / `ownership <url> --check <nonce>` | 0 verified · 1 mismatch |
| An authz test matrix (quarantine) | `test-authz <path> --quarantine anubis-quarantine` | 0 · 1 with `--fail-on-risk` · 2 |
| Prevention at write time | `init-hook` (pins a PreToolUse guard hook) | |
| A CI gate | `init-ci` (SHA-pinned workflow, SARIF, `--fail-on critical`) | |
| Org rules under supply-chain lock | `rules-lock <dir>` then `scan --rules-dir <dir>` | 0 verified · 2 tamper/unpinned refusal |

**Branch on exit codes:** `exit 2` = the tool refuses (usage error, tampered rules, missing ownership) — read stderr, do not retry blind; `exit 1` = genuinely bad findings exist — report them, never suppress; `exit 0` = pass — still present the Classes-not-covered disclaimer.

## How to run

```bash
# 1. Run the audit (terminal report)
npx anubis-guardian scan <project-path>

# 2. Machine-readable results for you (the agent) + a ready fixing prompt
npx anubis-guardian scan <project-path> --format json --output findings.json --fix-prompt fix-prompt.md --compact compact.txt

# 2b. Monorepo / multi-root
npx anubis-guardian scan . --workspaces
npx anubis-guardian scan ./frontend ./backend

# 3. CI gate
npx anubis-guardian scan <project-path> --fail-on high

# 4. Authorization matrix + generated tests (quarantine — YOU do not run them; the human does)
npx anubis-guardian test-authz <project-path> --quarantine anubis-quarantine

# 5. Optional AI review (off by default; needs ANUBIS_AI_API_KEY; verifier-gated)
npx anubis-guardian scan <project-path> --ai-review

# 6. Prevention: install the pinned PreToolUse guard hook into the project
npx anubis-guardian init-hook
```

### URL Mode — when the user names a DEPLOYED site (v0.4)

```bash
# L1 — passive, free, no ownership needed: TLS/cert, security headers, cookie
# flags, secrets shipped in public JS bundles. Browser-equivalent requests ONLY.
npx anubis-guardian scan-url https://example.com

# L2 — discovery (exposed .env/.git/backups, directory listing, TRACE, exposed
# API docs, source maps). Public domains REQUIRE verified ownership:
npx anubis-guardian ownership https://example.com        # prints a nonce + instructions
#   owner publishes it (DNS TXT  anubis-guardian-challenge=<nonce>
#   or https://example.com/.well-known/anubis-guardian/<nonce>), then:
npx anubis-guardian scan-url https://example.com --level 2 --ownership-token <nonce>

# Localhost/private staging only — self-attestation is allowed and labeled:
npx anubis-guardian scan-url http://127.0.0.1:3000 --level 2 --i-own-this-domain

# L3 = L2 + Supabase live anon RLS probe (read-only GET) — VERIFIED ownership only:
npx anubis-guardian scan-url https://example.com --level 3 --ownership-token <nonce>

# Reproducibility: save the capture, re-analyze offline (byte-identical)
npx anubis-guardian scan-url https://example.com --capture capture.json --from-capture capture.json

# v1.0 — restricted differential access check (L3 + verified ownership + BOTH
# owner-provided testing identities; GET-only, <=24 endpoints, values never stored):
npx anubis-guardian scan-url https://example.com --level 3 --ownership-token <nonce> \
  --active-tests --identity-a "Authorization: Bearer <PRIVILEGED>" --identity-b "Authorization: Bearer <RESTRICTED>" \
  --idor-path /api/admin-panel --idor-path /api/orders

# v1.0 — delegate deeper active testing to OWASP ZAP (the engine embeds no DAST):
npx anubis-guardian init-zap https://staging.example.com            # passive baseline config
npx anubis-guardian init-zap https://staging.example.com --active --ownership-token <nonce>
```

**URL Mode hard rules for you (the agent):**
1. **Never raise the level yourself.** L1 needs nothing; L2 needs verified ownership the USER must publish; L3 is verified-only, never the checkbox. If the user asks for L2+ on a domain they haven't verified, hand them the `ownership` nonce instructions and stop.
2. **Never scan a URL the user does not control or explicitly name.** The report carries a scan authorization record (URL, timestamp, level, ownership method) — do not edit or hide it.
3. **Self-attestation ≠ verification.** A `self-attested (local only)` label means localhost/staging — say so when presenting results.
4. Every URL finding pairs with a `Code map:` hint — offer to run Codebase Mode on the repo to get exact file:line.
5. **`--active-tests` identities come from the OWNER, never from you.** You do not invent, guess, reuse, or store credentials for the differential probe. If the user has not provided both testing identities and verified ownership, do not run it. The tool caps it: GET-only, ≤24 endpoints, identity values never stored.

Read `findings.json` (not the terminal) — each finding has: `id`, `severity`, `file:line`, masked `evidence`, `confidence`, `needs_confirmation`, `fix`, and for secrets a `remediation.rotate-first` plan.

## Artifacts — what gets written and how you use each

| Artifact | Written by | You (the agent)… |
|---|---|---|
| `findings.json` | `scan --format json --output` | Read THIS, not the terminal — stable schema, one finding per object |
| `fix-prompt.md` | `--fix-prompt` | Use it as the base of your fix proposal — it is deterministic, do not rewrite its findings |
| `compact.txt` | `--compact` | Token-saving digest — good for long sessions; read full findings.json before proposing any diff |
| `*.sarif` | `--sarif` | CI/Security-tab handoff — hand it to the human, do not parse secrets from it (values are masked) |
| `inventory.json` | `--inventory` | Attack-surface map (routes/guards/tables/edge functions) — reason from it BEFORE proposing fixes |
| `capture.json` | `scan-url --capture` | Evidence snapshot — keep it next to the report for byte-identical re-analysis via `--from-capture` |
| `anubis-quarantine/` | `test-authz` / `--quarantine` | NEVER run these tests or wire them to CI; name the folder to the human and describe what to run |

## `needs_confirmation` — verify, never downgrade silently

Findings flagged `needs_confirmation: true` are UNCONFIRMED (the tool refuses to call anything CRITICAL without independent proof). Present them as "likely — here is how to confirm", and pick the matching recipe:

| Finding class | How to confirm (do this before upgrading the claim) |
|---|---|
| SUPA-R01/R02/R06/R07 missing/weak RLS | Ask the human for `supabase db dump --schema public`, then re-run `scan --schema dump.sql` — schema-based findings upgrade to confirmed |
| SUPA-003 unauthed service_role edge function | Open the edge function: does it call `auth.getUser()` before using the service key? If it does and logs show caller authz, it is a hold |
| SUPA-R08 `verify_jwt=false` | Check `config.toml` intent with the human — some webhooks legitimately disable JWT verification but MUST verify provider signatures manually (then WEBHOOK-001 applies) |
| WEBHOOK-001 unverified webhook | Confirm with the provider docs whether a signature header (Stripe `stripe-signature`, etc.) is verified before processing |
| TAINT-001..005 taint flows | The generated canary in `anubis-quarantine/` proves them — the HUMAN runs Playwright there (`npx playwright test`), never you |
| AUTH-001 middleware matcher gap | Manually send the mutating request without a session; a 200/chat response confirms the gap |
| URL-061 differential access | The human re-sends the owner-provided identities by hand — the API must reject the restricted identity for the gap to close |
| ORG-* community rule findings | They are always quarantine-labeled (`meta.rules_lock` != `verified`, org CRITICAL always `needs_confirmation`) — say so explicitly |

If you cannot verify yourself, hand the recipe to the human — do NOT present the finding as confirmed and do NOT downgrade it either.

## Acting on findings — hard rules

1. **Propose fixes, never auto-apply.** Every finding is `fix_mode: suggested-diff`. Show the user the diff first. No edits to RLS, auth, or production files without explicit human approval.
2. **Rotate-first for secrets.** If a finding has `remediation.type === "rotate-first"`, the credential is compromised *even if deleted from the code*. The fix prompt must START with the rotation steps — deleting the line is NOT the fix. Never write any change touching a secret before the user confirms rotation is done or explicitly waives it.
3. **Respect `needs_confirmation`.** Findings flagged `needs_confirmation: true` (missing RLS known only from migrations, service_role edge functions, webhooks, taint flows…) are not independently confirmed yet — present them as "likely, confirm by …", never as confirmed CRITICAL. CRITICAL exists only when the tool itself confirmed it (schema export, live probe, cross-root linkage). Use the verification recipes above.
4. **Never print full secret values.** Evidence is masked (first-4 + sha256 prefix). Keep it masked in anything you show, write, or send. If you enable `--ai-review`, the tool redacts code before it reaches the model — never paste raw secrets into any model yourself.
5. **No test tampering, no scope creep.** Fix the finding; do not modify tests to pass, do not refactor beyond the fix.
6. **Quarantine tests are the OWNER's.** `test-authz` / `--quarantine` generate failing-by-expectation tests. Point the human at them; never wire them into CI and never execute them yourself as part of the audit.
7. **Read "Classes not covered".** The report lists what the tool does NOT check (business logic, deep multi-file taint, URL Mode, compliance…). An A grade means "nothing found by these checks", not "secure". Tell the user this.

## Severity playbook — what each severity demands

- **CRITICAL (confirmed)** — act now. Secrets: rotate-first checklist verbatim, then scrub history, then code change; RLS live-exposed: fix the policy TODAY. These are independently confirmed by the tool itself.
- **HIGH** — fix this session (real exposure or exploit-relevant pattern, may still carry `needs_confirmation`).
- **MEDIUM** — schedule this week; verify with the matching recipe first (taint flows live here).
- **LOW** — hygiene; batch with the next pass.
- **INFO** — suppressed/holds/documented-correct patterns; mention only if the user asks.
- Suppressed findings (`suppression`, inline `anubis-ignore:`) are visible in the report but not scored — surface them once if they are near expiry, never obsess.

## v1.0 — supply-chain guard for org rules

```bash
npx anubis-guardian rules-lock ./org-rules      # pin the rules dir (sha256 per file) — commit rules-lock.json
npx anubis-guardian scan . --rules-dir ./org-rules   # refuses modified/unpinned rules (exit 2)
npx anubis-guardian scan . --rules-dir ./org-rules --allow-community-rules  # run quarantined (meta-labeled)
```

`meta.rules_lock` is `verified | off | bypassed` — when it is not `verified`, say so when presenting results (the rules ran unverified / quarantined).

## Interpreting v0.3 result shapes

- `summary` + `score_breakdown` — deterministic score (AI findings recompute it; low-confidence and INFO never deduct).
- `ai_review` (only when `--ai-review` ran) — `confirmed / corroborated / rejected` counts. Rejected claims never became findings: say so plainly ("the AI proposed N, the independent verifier kept 1").
- `inventory` — routes, server actions, controllers with guard state, Supabase tables/RPC/edge functions, socket events, webhooks. Use it to reason about the attack surface before proposing fixes.
- Taint findings (`TAINT-001..005`) are MEDIUM-capped single-file flows — the honest framing is "flow to verify with the generated canary", not "proven vulnerability".

## Output to the user

- Summary: score, grade, counts by severity (+ AI review counts if the layer ran)
- For each finding: what was found (masked), where (file:line), why it matters, the concrete fix
- Secrets: the rotate-first checklist verbatim from `remediation.steps`
- Generated artifacts: quarantine folder location + what the human should run there
- Close with the Classes-not-covered disclaimer

## Scope

v1.0 covers Codebase Mode fully (rules packs I+II, taint-lite, agent environment, optional AI review with verifier, authz matrix + quarantine, guard hook, rules supply-chain guard) **and URL Mode L1+L2+L3** (passive scan, verified-ownership discovery, live anon probe, restricted differential access check via `--active-tests`). Full active DAST stays out of scope by design — `init-zap` generates the OWASP ZAP baseline config for the owner to run themselves. Release engineering ships with v1.0: npm provenance attestation + CycloneDX SBOM + signed releases + `BENCHMARKS.md` (measured numbers only).
