# Changelog

## [1.3.0] — 2026-10-26

Minor release: **one new detection + one severity-accuracy fix + positioning docs.** Semver is MINOR (not 1.2.1) because it carries both a bug fix and a new detection capability. **`v1.2.0` on npm does NOT include any of the changes below** — the OSV severity fix in particular was shipped in the codebase after the v1.2.0 tag, so the published 1.2.0 still upscales non-critical OSV severities to HIGH.

### Added

- **SAST-001 — single-hop variable propagation to SQL sinks** (`src/rules/sast.ts`): when a recognized sink's first argument is a bare identifier, its nearest preceding same-function string assignment is resolved and the SAME dynamic-SQL analysis runs on the resolved value.
  - Before: `const q = "SELECT * FROM users WHERE name='" + req.query.name + "'"; pool.query(q)` was **silent** (a measured false-negative).
  - After: **SAST-001 HIGH** (request-traced, `needs_confirmation: false`), evidence masked deterministically as `pool.query(q -> "<resolved value>")`. Also fires for alias into `prisma.$queryRawUnsafe`, multi-line template literals, and `pool.query(q, [id])` binding shapes.
  - Scope stays one hop, same function only: chained aliases (`const q = r`) and cross-function assignments stay silent (gates U18.8f/U18.8g); tagged `prisma.$queryRaw` templates (U18.8d), `$1`-placeholder forms (U18.8c) and a constant alias (U18.8e) stay silent. Plain reassignments count as assignments — **the last assignment before the sink decides**: a var demoted to a constant stays silent and one promoted to a request-built string fires (U18.8j). Sinks themselves are unchanged; no new runtime dependencies.
  - Gates: U18.8a–U18.8j (units 241 → 251). Regression: U18.1–U18.8 and the phase-2 safe-form gates behave exactly as before.

### Tests

- **CLI file-vs-directory refusal gate** (phase-1 T1, gate #25): `scan <file>` was already refused with `not a project directory` + exit 2 (`src/cli.ts`), but no gate asserted it **(coverage for pre-existing behavior, no behavior change)**.
- **Scanner crash/timeout path** (U17.15): a gitleaks/OSV process crash or timeout (`status: null`) is surfaced as an execution failure — never a clean scan, never a findings exit code **(coverage for pre-existing behavior, no behavior change)**.

### Fixed

- **OSV severity mapping** (`src/adapters.ts` `mapOsvSeverity`): the `--tools osv-scanner` adapter previously collapsed every non-`CRITICAL` `database_specific.severity` into `HIGH`, inflating MODERATE/LOW advisories in score and summary. Now explicit: `CRITICAL→critical · HIGH→high · MODERATE/MEDIUM→medium · LOW→low`; unknown or missing severity follows a documented policy — `medium` + `needs_confirmation` + the raw value disclosed in the finding note (never silently treated as known, never inflated). Gates **U17.13/U17.14** cover every supported severity plus missing/unknown. **Shipped after the v1.2.0 tag — `v1.2.0` on npm did not include this fix.**

### Changed

- **README positioning**: universal capabilities now lead the capability line (`Secrets · SAST · Taint · Dependencies (OSV) · CI/supply-chain · SARIF · Supabase RLS · Next.js · NestJS`), and the intro sentence leads with universal coverage on any stack, framing Supabase/Next.js/NestJS as the batteries-included case. `package.json` keywords reordered so `security`/`sast`/`ai-generated-code` precede `supabase`/`nextjs` (search discoverability). **No capability, rule, or Supabase mention was removed.**
- **Benchmarks re-anchored**: `BENCHMARKS.md` re-measured at the current commit with an exact provenance SHA (the previously recorded provenance commit had been rewritten out of history; the dirty-tree label now honestly describes uncommitted code vs docs changes). 14 measured · 0 pending · 0 failed.
- **Documented, not adopted** (unchanged, METHODOLOGY §8): AST-based parsing (no TS-capable parser is dependency-justified for the current rule set; single-hop regex propagation now covers the measured alias gap) and controlled POST/PATCH mutation testing in URL Mode L3 (GET-only differential IDOR stays enforced with verified ownership, A/B identities, 24-endpoint cap).

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
