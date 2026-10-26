# Changelog

## Unreleased — post-1.2.0 audit (evidence-based)

- **Fixed — OSV-001 severity mapping (`src/adapters.ts`)**: the `--tools osv-scanner` adapter previously collapsed every non-`CRITICAL` `database_specific.severity` into `HIGH`, inflating MODERATE/LOW advisories in score and summary. Now explicit: `CRITICAL→critical · HIGH→high · MODERATE/MEDIUM→medium · LOW→low`; unknown or missing severity follows a documented policy — `medium` + `needs_confirmation` + the raw value disclosed in the finding note (never silently treated as known, never inflated). Regression gates **U17.13/U17.14** (`tests/verify-units.mjs`) cover every supported severity plus missing/unknown.
- **Added test — CLI file-vs-directory refusal**: `scan <file>` was already refused with `not a project directory` + exit 2 (`src/cli.ts`), but no gate asserted it. **Phase-1 T1** now checks both the exit code and the stderr message (25 gates).
- **Benchmarks re-anchored**: `BENCHMARKS.md` regenerated at the current commit (the previously recorded provenance commit was rewritten out of history during the v1.2.0 push-protection fixture defusal; results themselves were reproduced fresh).
- **Audited, deferred (documented in §G of the audit report / METHODOLOGY §8)**: AST-based parsing for the SQL-sink rule (a measured false-negative exists for alias-built SQL strings — `const q = "…" + req.x; pool.query(q)` — while redirect/XSS/eval aliasing **is** caught by the taint layer); controlled POST/PATCH mutation testing in URL Mode L3 (GET-only differential IDOR stays enforced with verified ownership, A/B identities, 24-endpoint cap).

## 1.2.0 — 2026-10-26

Independent-review fixes in three phases — trust fixes → detection gaps → guard-hook rewrite. Every task shipped with at least one must-detect and one must-not-detect gate; the full test chain is green. **Behavior changes: exit codes are now fail-closed (2) for invalid input/unreachable targets, several severities were recalibrated, and the guard hook detection logic is rewritten (see below).**

### Phase 1 — trust fixes

- **T0 · adapters fail-closed + probe seam** (`src/adapters.ts`): gitleaks/OSV exit-code semantics are parsed per state (completed-clean / findings / execution failure / unavailable / invalid-report). Findings-related non-zero exits still yield every finding; execution failures are recorded in coverage and meta and can never masquerade as a clean result. Tests use controlled doubles — no reliance on host binaries.
- **T1 · fail-closed CLI**: nonexistent path, zero scannable files, unknown `--format`/`--fail-on`/`--tools` → stderr error + **exit 2, no score line, no partial report**. `--allow-empty` opts out explicitly. Unreachable `scan-url` keeps its finding but reports **grade N/A (score null) and exits 2** — a failed fetch can no longer print a fake 100/A.
- **T2 · value-based env classification** (shared `src/rules/valueclass.ts`): `.env*` CRITICAL requires a secret-shaped VALUE (decoded service_role JWT, provider prefixes, real private-key body, DB URL with real password, opaque 24+ entropy, or credential-named 20+ non-placeholder). Public-by-design values (anon JWT, `sb_publishable_*`, URLs, `pk_*`, Firebase/Google web keys, placeholders) never trigger it; a committed env with only public values emits a single LOW note with no score impact.
- **T3 · secret/shared belief module**: JWT role decoding, jwt.io sample and AWS documented-example skipping, ≥64-char private-key body requirement, placeholder DB-credential set, `.example/.sample/.template` value skips, and test/docs/`*.spec.*`/`*.md` path triage (low-confidence notes, no deduction) are shared by HEAD **and** git-history scanning (HIST-*).
- **T4 · DEP-003 calibration**: offline edit-distance evidence is LOW + low-confidence, never HIGH (HIGH requires a MAL advisory or `--online`); names <5 chars and packages on the extended popular list (nitro, qs, ms, ora, ky, tsx, pino, vite, zod, jose, ws, got, tar, uuid, cors) are never flagged.
- **T5 · DEP-004 noise**: one aggregated "no lockfile" finding per project (with dependency count); per-dependency findings only when a lockfile exists but lacks the package. pnpm/bun/shrinkwrap all recognized.
- **T6 · SAST/TAINT precision + HIST-010**: SAST-002 skips static literals and recognized sanitizers (DOMPurify and friends); TAINT-001 hostname-allowlist flows are LOW notes, not score deductions; git-root-aware `.gitignore` lookup for sub-folder scans.
- **T7 · coverage honesty**: skipped files (oversize >512 KB, binary, unreadable) are counted by reason in `meta`, the terminal summary warns when >0, and SARIF run properties carry the counts.

### Phase 2 — detection gaps

- **T8 · SAST-001 first-argument SQL analysis**: paren-balanced first-argument extraction across `$queryRawUnsafe`, `$executeRawUnsafe`, `knex.raw`, `sequelize.query`, `pool/client/db/connection.query`, and DB `.execute(`. Detects `${...}` interpolation and non-literal concatenation regardless of inner quotes. HIGH when the value traces to request data, MEDIUM + needs_confirmation otherwise. Tagged templates (`$queryRaw\``), `$1`/`?` placeholders with params arrays, and constant strings stay silent. Evidence carries the masked sink name (required by the engine dedupe key).
- **T9 · TAINT-006 dynamic code execution** (+ SAST-003 for non-tainted non-literals at MEDIUM): `eval`, `new Function`, `vm.runIn*/runInNewContext` of tainted values, plus `setTimeout(<tainted string>)`. `eval('1+1')`, comments and string mentions stay silent; request-traced eval is owned by TAINT-006 (no double verdict).
- **T10 · JWT-003 hardcoded signing/session secrets**: string literals (6+ chars) in `jwt.sign/verify`, `JwtModule.register`, `secretOrKey`, `session({ secret })`, `const JWT_SECRET = 'literal'`. The generic placeholder skip is deliberately NOT applied — `changeme-super-secret-key` IS the vulnerability; only `process.env.*` / `${...}` / `<...>` / `YOUR_*` / configService pass. HIGH, masked, rotate-first.
- **T11 · SEED-001 path expansion**: `seeds/`, `seeders/`, `fixtures/`, `factories/`, `db/seeds/**`, `prisma/seed-*`, `scripts/*seed*`, `create/init/bootstrap-admin` files. Placeholder passwords and `*.test.*` stay silent.
- **T12 · HDR-001 value-flow receivers**: any header read (`req.headers[...]`, `req.header(...)`, `headers().get(...)` incl. Next.js local aliases) flowing into DB sink props (`password`, `connectionString`, `url`, `host`, `user`, `uri`) of Pool/Client/createPool/`mongoose.connect`/postgres/drizzle is CRITICAL — covered even with unusual names (`x-pg-secret`, `x-dsn`) and positional call args. The old name heuristic remains sender-side only and downgrades to LOW. Lesson encoded: the alias matcher must use the last DEFINED capture group.
- **T13 · TAINT-002 redirect sinks extended**: `redirect()`/`permanentRedirect()` (next/navigation), `NextResponse.redirect`, `res.redirect`, with `searchParams` values through variables and casts (`as string`, `!`). Literal paths and `startsWith("/")` guards stay silent.
- **T14 · transitive dependency recall + advisory snapshot v2**: lockfile-resolved transitive packages are checked against the bundled OSV snapshot (moderate+ npm advisories; `DEP-001` reported at the lockfile with name-sorted, capped evidence). `meta.advisory_snapshot_date` + staleness warning (>90 days) in terminal, JSON, and SARIF-adjacent meta. Snapshot rebuild tooling: `scripts/build-advisory-snapshot.mjs`.

### Phase 3 — guard hook rewrite (`init-hook`)

- **Value-based R1**: every JWT-shaped string is decoded; `role=service_role` blocks in client-reachable contexts (`'use client'` files, `components/`, `pages/` non-api, or `.env*` entries with `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_`/`EXPO_PUBLIC_` names). `"use server"`, `app/api`, route handlers, middleware, server path segments, and `supabase/functions` are allowed. Comments are stripped first — a comment mentioning service_role never blocks. The substring-`"server"`-in-path heuristic is gone (a file named `observer.ts` is no longer misjudged).
- **Value-based R2**: blocks `disable row level security`, `create policy ... using (true)` / `with check (true)`, and `drop policy` ONLY when the same content has no `create policy` for the same table — drop-then-recreate migrations pass.
- **Value-based R3/R4** (twin of the scanner's env value classifier): secret-shaped VALUES or credential names into `.env*`; client-prefixed names assigned secret-shaped values in any file. Public-by-design names pass (FIREBASE_API_KEY, GOOGLE_MAPS, POSTHOG, ALGOLIA search keys, STRIPE_PUBLISHABLE/SUPABASE_ANON/PUBLISHABLE, SENTRY_DSN, MAPBOX `pk.*`); server-side `.env` service_role config (where it belongs) is allowed.
- **Bash coverage (best effort, documented)**: heredoc / redirect / tee / `sed -i` target extraction, then the same value detectors over the command text. Not a security boundary — path extraction is heuristic.
- **Escape hatches**: `ANUBIS_GUARD=block|warn|off` (default block) and the inline marker `anubis-allow: <reason of 8+ chars>` (echoed to stderr; a shorter reason still blocks). Still zero-dependency and fail-open on malformed/empty stdin.
- **Version wiring**: the hook header, `settings.json` entry, and the AGENTS.md snippet all derive from the real package version (the stale `v0.3.0` label is gone); snippet commands use `npx anubis-guardian@1.2.0`.

## 1.1.1 — 2026-10-26

Security fix — SSRF hardening for URL Mode (`src/urlmode/ssrf-guard.ts`, zero new deps):

- URL Mode refuses private/loopback/link-local/cloud-metadata targets by default.
  Use `--allow-private` for localhost staging (CLI only; ignored in service mode).
  Cloud metadata endpoints (169.254.169.254, 169.254.170.2, fd00:ec2::254) are
  refused unconditionally — the flag never covers them.
- Every request (and every redirect hop) runs resolve→pin→connect: one
  `dns.lookup(all:true)` per hop, EVERY returned address validated against
  binary-canonical range checks, then the connection dials the pinned IP with
  Host/SNI of the original hostname — DNS rebinding closed by construction.
- Redirects are followed manually (cap 10), re-guarded per hop; https→http
  demotion and non-http(s) `Location` schemes are refused. Refusals keep the
  last real response as evidence and surface in capture notes.
- `inspectTls` (the TLS probe) now passes the same guard.
- Service mode (`ANUBIS_SERVICE=1`): port allowlist 80/443/8080/8443 only,
  5 MB response cap (`ANUBIS_MAX_RESPONSE_BYTES`), 10s connect + 30s
  read-idle timeouts.
- CLI behavior change: private/loopback targets are refused without
  `--allow-private`; the ownership gate (`--i-own-this-domain`) is unchanged.
- Tests: units 108 → 145 (U14 SSRF gate block incl. per-hop refusals over a
  real local server, sequential-lookup rebinding, service port policy);
  mode2 suites updated for the new CLI default.

### Phase 2 — pending, deliberately NOT in this release

- **Service-mode hard-exit-2 wiring**: when `ANUBIS_SERVICE=1`, a private-range
  refusal must terminate the CLI with exit 2 (Phase 1 only records the refusal —
  the guard, port policy and limits are enforced, the fatal CLI wiring is not).
- **scan-url UX + integration**: usage flows, refusal messaging, and any
  hosted-deployment review flow around `scan-url`.
