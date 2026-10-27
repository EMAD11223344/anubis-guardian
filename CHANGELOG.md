# Changelog

## [1.5.1] — 2026-10-28

Hotfix + release-hygiene round on top of v1.5.0. Units 332 → **334**; all 13 gates green; no new runtime dependencies; masking, determinism, coverage reporting and read-only contracts unchanged. Verified pre-release on the exact candidate: `npm ci` + full `npm test` exit 0, and CLI `--version` / scan-JSON / runtime constant / package.json / package-lock / README badge all at 1.5.1 (locked for every future release by **U26.6**).

### Fixed

- **`scanTenant` cost amplification on windowed large files (root cause found & fixed).** `tenantEntities()` executed the prisma model regex (`/^\s*model\s+…/m`) on **every** scanned file before the rel check; on windowed content, each window carries a `(start-1)`-row **empty pad block**, and `^\s*` backtracked across that empty run at every row start → **O(pad rows²) backtracking**. Measured on a 1 MB fixture (272k rows, 3 windows): the pack sweep took 116.2 s, **111.7 s of which was scanTenant**; a 4 MB adversarial fixture never completed (>35 min, killed). Fix: the regex is now gated behind the `schema.prisma` rel check (pure short-circuit — the result was discarded otherwise) and anchors locally as `^[\t ]*model` (match set provably identical: any newline-crossing match lands the keyword at a row start with its own `^` anchor), plus the per-entity access regexes are compiled once outside the row loop instead of once per row×entity. After: 1 MB full scan **117.9 → 4.85 s (24×)**, 2 MB **18.6 s**, 4 MB stress **69.7 s** (secret still found at exact absolute lines 262145/786433/1835009). `leakpack.ts`'s identical model regex got the same local-anchor hardening. Locked by **U26.4** (bounded + silent without a tenant schema; TEN-002 intact on a real `schema.prisma` inside a windowed file). U21.5/U25.6 gates unchanged and passing.

### Changed

- **Windowed-scanning pad construction no longer rebuilds pads through JS allocation loops** (`src/walk.ts`): each window's pad block ("(start)" empty rows + one `}` seam row) is now materialized with a native `fill` + exactly one body copy, and the content prefix is `"\n".repeat(start-1) + "}\n"`. Measured A/B on identical fixtures: walk **761 → 405 ms (−47%)**, heap after walk **139 → 103 MB (−26%)**; padded-row amplification quantified at 11.4M padded rows from 1.9M input rows. Window output is **byte-identical** to the v1.5 algorithm — proven by a reference-oracle gate (**U26.1**), plus deep-absolute-line correctness on a many-short-line file (**U26.2**), a construction budget gate (**U26.3**), and a whole-scan budget on the same many-short-line class (**U26.5**: <30 s at the 1 MB scale — measured ~5–7 s post-fix vs ~118 s pre-fix). U25 giant-line gates unchanged and passing. The residual ~70 s worst case for an adversarial 4 MB all-short-lines file is now **documented as a stated limitation** (README "Known limitations" + METHODOLOGY §8) together with the planned migration path (explicit absolute-line offsets instead of repeated pad rows — a design-quantified later refactor).
- **README reconciliation after peer review:** the section heading "Works everywhere — any database, any ORM" (itself an overstatement that survived the wording fix beneath it) is now "Any database, any ORM — what the scanner actually recognizes".
- **README visuals restored and made renderer-proof:** the missing modes visual is restored as a **new version-neutral `docs/assets/modes.svg`** and the hero banner is replaced by a new version-neutral `docs/assets/hero.svg` (both authored for current capabilities, no version chip, no package name, no protection overclaims — they do not age out at a new release; the obsolete jpgs — v1.0.0 chips, `@anubis-guardian/cli` package name in `modes.jpg`, stale layer list — are no longer referenced but kept on disk). Both images now use absolute `raw.githubusercontent` URLs, because GitHub renders relative image paths but npm rewrites relative paths to `blob/HEAD` pages (verified live against the published package page) — absolute raw URLs render on both. Documentation links are unaffected: relative links in the package README are rewritten by npm to the GitHub repository and are verified to resolve. The README's "any database and any ORM fully supported" claim was corrected to describe recognition of common query patterns, with the boundary stated and the coverage manifest referenced (English and Arabic).
- **Version consistency gate (U26.6):** the runtime `VERSION` constant, package.json, both package-lock root entries, the README version badge, `anubis-guardian --version` and a real scan's JSON `version` field are asserted pairwise equal on the built dist — a release can no longer ship with a runtime constant left behind.

## [1.5.0] — 2026-10-27

Quality + honest-coverage release on top of the v1.4 capability round. Every reported concern was **re-verified against the current code before acting**; several turned out already-fixed or not reproducible. Units 319 → **326**; all 13 gates green; no new runtime dependencies; masking, determinism, no-exec contracts unchanged.

### Fixed — confirmed defects

- **Windowed large-file scanning could silently stop at a giant line** (`src/walk.ts`): when a file contained a line longer than the per-window budget (≤512 KB), the window advance broke (`next ≤ start`) and **every following line was never scanned** — findings after a giant line went silently unnoticed. The v1.5 loop guarantees forward progress: a window whose body is ≤ the overlap size advances the full window; byte math bounds the window count (≤ ~16 per 4 MB file). Regression gates **U25.1/U25.2**: secrets after one giant line and after the last of an all-giant-lines file are found at their exact absolute lines.
- **SSRF hostname validation was only recognized in the extracted-variable form** (`src/rules/taint.ts`): `if (!ALLOWED.includes(new URL(t).host)) return …` — the inline form — missed the demotion and stayed at MEDIUM instead of the LOW review note that variable-shaped allowlists already got. Inline `new URL(x).host === …` and `h === u.host` shapes now demote too (U25.3/U25.4; unguarded fetches stay MEDIUM).
- **Trailing comments could silence RES-003** by the same statement window (`grabbed "no timeout"` text matched `\btimeout\b`) — the call statement strips line comments before the timeout-shape test.

### Added — coverage (capability-pack strengthening v1.5)

- **LEAK-003 — whole-object serialization of a wide query result** (`src/rules/leakpack.ts`): `res.json(user)` / `NextResponse.json(payload)` where the argument resolves (bounded chase ≤4 hops) to an un-projected query (`prisma.users.findUnique`, `.from().select()`, `SELECT *`). LOW review note by default; escalates to **MEDIUM when the queried model's own declaration (schema.prisma / SQL migration) declares credential-shaped columns**. `select:` / `omit:` / `pick()` / spread-strip shapes stay silent. This closes the previously documented "whole-object flows are not tracked" gap for the chase-resolvable core (nested/derived shapes remain documented limits; U25.7).
- **RES-003 — outbound requests without visible timeout/cancellation** (`src/rules/dospack.ts`): `fetch`/`axios`/`http.request`/`got` inside a request handler with no `signal` / `AbortSignal` / `timeout` shape in the **same call statement** (per-call paren-bounded, adjacent calls never cross-silence) → LOW + `needs_confirmation` (a shared client/wrapper may apply timeouts at an invisible layer; U25.5).
- **TEN-002 now covers by-ID READS** (`findUnique` was covered; `findFirst` added) — the classic tenant-IDOR read on a declared tenant entity keyed only by request input; title distinguishes read vs mutation; tenant-scoped reads stay silent (U25.6).
- **LEAK-001/TAINT-005 sink lists now recognize the plain `Response.json(…)` API** (Next.js App Router's default) — previously only `res.json` / `NextResponse.json` matched, so BOTH the field-level credential check and the new whole-object check missed the most common App-Router sink.

### Fixed — verification verdicts on earlier reports (not code)

- **"JWT-002 produces duplicate findings for one secret"** — not reproducible: three literal/alias re-uses of one secret produced **one** finding, one fingerprint, one root cause (the engine's fingerprint dedupe covers it).
- **"SQL tokenizer invents a `public.IF` table name"** — not reproducible: `IF(…)` function calls, `CREATE TABLE IF NOT EXISTS`, and schema-qualified names parse correctly; the declared table set stayed exact (probed with adversarial migration SQL).
- **SAST-003 benign eval-adjacent shapes** (`JSON.parse('…')`, `fn.call(null, "static")`, `new Function("return 42")`) and **LOGS benign logging** (`console.log("count", 42)`, `logger.info("health ok")`) — clean, no corrections needed.
- Re-run of the **48-case adversarial battery** against the current build: 4 sub-millisecond-base `SUPERLINEAR` flags disproven as noise by a dedicated 100 KB→3 MB stress test (~10× time for 30× input, worst 52 ms@3MB) — the linear guarantee holds through the 4 MB single-line worst case.

### Changed — documentation

- **`AUDIT-REPORT.md` and the owner-specific testing guide removed** from the repository (internal audit history / owner-personal instructions do not belong in the public release; no code references existed). README rewritten as a professional open-source project front page: any-database/any-ORM framing, npm install, honest capability boundaries, contributing/security-reporting channels.
- METHODOLOGY §8 updated for the window-progress guarantee, LEAK-003/RES-003 contracts, and the narrowed classes-not-covered entries (`src/coverage.ts`).

### Tests

- Units **319 → 326** (U25.1–U25.7). Full `npm test` green (exit 0): units 326, reachability 7, honeypot all seeds (masking intact), clean 100/A, capability acceptance 14, phase-1 25, phase-2 16, SARIF, acceptance v0.2 / v0.3 / v0.4 (47) / v1.0 (45).

## [1.4.0] — 2026-10-27

Capability + perf/verification release. Two workstreams ship together: **(1)** the flow/ReDoS hardening round started post-v1.3.0 (bounded multi-hop value chase, adversarial battery that *reversed* an earlier "ReDoS not reproduced" conclusion), and **(2)** six new capability groups (A–F) plus large-file windowed scanning and a test-authz attribution fix. Unit count 289 → 319; every gate green; no new runtime dependencies; masking, determinism and no-exec contracts unchanged. **`v1.3.0` on npm includes none of the sections below** (all three commits post-date the v1.3.0 tag).

### Fixed — ReDoS (verdict REVERSED from the "not reproduced" conclusion)

- The previous audit's performance gate (U20.34) measured benign single-line inputs; an **adversarial battery** (48 pathological inputs × N vs 3N growth testing, not one-point timings) exposed **quadratic breaches in HDR-001**: a word-run payload degrading 9s@100KB → 81s@300KB, and a quote-run 18s → 167s.
- Fixed by **bounding greedy `[\w$]*` identifier runs to `{0,64}`** in `hdr001.ts` (`SINK_ASSIGN_RE` + variable scanners), `sast.ts` (`requestDerivedVars` + the general app-layer sink regex) and `crypto.ts` (`assignTarget`). Re-run of the full battery: **all 48 cases LINEAR, worst 355ms@300KB**.
- Locked twice: U20.34 keeps the 512KB/budget guard, and the new **U22.1 adversarial battery gate** (16 cases, linear-growth assertion above a documented noise floor) fails the suite if any rule regresses.

### Added — flow layer (`src/rules/flow.ts`)

- **Bounded multi-hop value chase** shared by SAST-001/sha/taint: bare and method-wrapped intermediate assignments (`a.trim()`) are followed up to **4 hops**, cycle-safe, with **no half-resolved verdicts** (a chain that cannot be completed returns null, never a guess).
- **Cross-file helper flow** for imported SQL builders: local relative-import helpers are read (never executed; npm package specs are never followed).
- Enables SAST-001 and v1.4 capability rules to see one-assignment hops that v1.3's single-hop propagation missed.

### Added — capability groups A–F (real, wired into the engine and coverage registry)

- **§A RBAC/authorization** (`src/rules/authzpack.ts`): **AUTHZ-001** — mutating request handler with privileged op and no recognizable authorization call in its *own* handler body (**MEDIUM, needs_confirmation**, note names the invisible layers: middleware, APP_GUARD-style global guards, DB-level RLS); **AUTHZ-002** — authorization *decision* taken from client-controlled input (`req.body.isAdmin`-shape), **HIGH**.
- **§B multi-tenant isolation** (`scanTenant`): fires **only** where the repo declares tenant entities (Prisma models / SQL migrations with tenant columns — findings are TEN-002 by-ID tenant mutations, TEN-001 unscoped UPDATE/DELETE SQL; both MEDIUM review prompts naming invisible enforcement). Tenant-scope predicates stay silent; repo without declared tenant entities is never flagged.
- **§C data leakage** (`src/rules/leakpack.ts`): **LEAK-001** credential-shaped fields serialized into client-facing response sinks (**MEDIUM**, note: runtime value unobservable — hash vs live secret); **LEAK-002** PII-shaped values into logs (**LOW** note).
- **§D resource exhaustion** (`src/rules/dospack.ts`; scanner *self*-resilience is validated separately by the battery above): **RES-001** regexes built from request-controlled input (flow-assisted; **HIGH** direct / **MEDIUM**, needs_confirmation flow-resolved); **RES-002** pagination-less `findMany` inside request handlers (**MEDIUM**, note).
- **§F upload security** (`src/rules/upload.ts`): **UPLOAD-001** request-derived writes into served directories (**HIGH**); **UPLOAD-002** limit-less upload parsers (multer/Busboy/Formidable); **UPLOAD-003** guard-less archive extraction (zip-bomb/zip-slip surface, incl. `extractAllTo` + `tar.x` pipelines; deduped per root cause).
- All findings carry `needs_confirmation` + explicit invisible-layer notes per the honesty contract; the clean counterparts (authz calls, tenant-scoped predicates, `undefined`-stripped fields, `take`-caps, limit configs, guarded extraction) are unit-locked silent.
- **Honesty**: the `classes_not_covered` registry gained explicit §A–§F entries (policy-level RBAC invisible, tenant enforcement invisible, runtime values invisible, fetch-timeout absence undetected, serving-layer behavior invisible).

### Added — capability E: large-file windowed scanning (`src/walk.ts`)

- Files **>512KB are now analyzed** instead of skipped-oversize: line-boundary **windows (≤512KB each) with 16-line overlap** plus a synthetic `}` scope-break at each seam so cross-window function attribution cannot silently chain; the **4MB hard cap remains** and still lands in `meta.files_skipped.oversize`.
- Absolute line numbers verified through three seams on a 1.2MB fixture (JWT-003@line 2 + SAST-001@line 14004); overlap duplicates dedupe by fingerprint.
- Disclosure: `meta.files_windowed` (file · KB · windows); `files_scanned` now counts unique disk files, not window entries. **Contract change, gate-locked**: U16.9/T7+ moved the oversize boundary from 512KB to 4MB.

### Fixed — test-authz guard attribution (NEST-001 investigation)

- Prior report's "2,009 endpoints" figure referenced an external repo that is not available locally — **non-reproducible, documented as missing evidence**. The *mechanisms* were verified on synthetic Nest fixtures: NEST-001 counts one row per decorator, class-level provider → method-level `@UseGuards` → global `APP_GUARD` precedence works, and a global provider found in code (never prose) silences the rule (all pre-existing v1.3 behavior, re-verified).
- **Confirmed defect in `src/inventory.ts`**: `hasAuthzCheck()` was **file-level** for Next route rows and server actions — one guarded handler marked every handler in the file guarded, so a mixed POST-guarded/DELETE-unguarded route was reported `guarded` and test-authz *skipped* the unguarded mutation. Attribution is now **per handler** (brace-bounded body, same call-shape list as the AUTHZ pack), with the file-level truth kept only as the conservative fallback for bodies that cannot be closed within the bound (U24.1–U24.4). The AUTHZ-001 pack itself was already handler-scoped and stays unchanged.

### Tests

- Units **289 → 319** (all passing): U21.1–U21.13 capability positives/cleans/generalizations, U21.6b (ALTER TABLE tenant declaration), U22.1 battery lock, U23.1–U23.3 windowed-file gates, U24.1–U24.4 test-authz attribution.
- New **`capab:verify`** acceptance harness chained into `npm test` after `clean:verify` (`tests/capab/`): a synthetic fixture tree scanned by the real CLI; the verifier asserts each capability rule fires on its positive and stays silent on its clean counterpart — **14/14**.
- Full `npm test` green (exit 0): build, units 319, reachability 7, honeypot all seeds (masking intact), clean 100/A, capability acceptance 14, phase-1 25, phase-2 16, SARIF, acceptance v0.2 / v0.3 / v0.4 (47) / v1.0 (45).

### Changed — SQL-sink alias contract (behavior flip from 1.3.0)

- **Chained aliases are now followed**: `const r = build(req.query.x); const q = r; pool.query(q)` fired in 1.3 only when the sink's argument was the request-built var itself; v1.4's flow layer resolves bounded chains (**≤4 hops**, cycle-safe, no half-verdicts). **U18.8g flipped** from "chain stays silent" to "chain resolves HIGH", and the new edge gates (U18.8g-v2 cap, U18.8g-v3 cycle, U18.8g-v4 method-wrapped intermediates) lock the bounds. The cross-function boundary is unchanged (U18.8f still silent). METHODOLOGY §8 and the README limitation list were updated to the new contract.

### Fixed — false negatives (detections that were silent and now fire)

- **JWT-003 — fallback secret literals** (`src/rules/jwtsecrets.ts`): `||`/`??` fallbacks on credential-named identifiers are analyzed (case-insensitive `SECRETISH_NAME`), plus cookie-session `keys: ["…"]` arrays, `signingKey(s)`/`JWT_secret` object properties, and the jose `setSigningKey(` / `.sign(` method-call form (context-gated).
  - Before: `const secret = process.env.JWT_SECRET || "dev-secret-123"` and `new SignJWT(p).setSigningKey("literal")` were **silent** (audit items j1/j2/j4/j6).
  - After: **JWT-003 HIGH**; env/config-sourced values stay silent (U20.1–U20.5).
- **SAST-001 — SQL sink receiver generalization** (`src/rules/sast.ts`): the dynamic-SQL sink set now covers any `.query(` / `.execute(` receiver with a receiver-content blacklist (`NON_SQL_RECV`: document/window/ctx/canvas/dom/el/elem/html/api/router/program), so TypeORM `manager.query(`, mysql2 `conn.execute(`, and arbitrary entity managers are covered; `seenSinks` content-offset dedupe prevents duplicate findings across overlapping sink regexes.
  - Before: TypeORM/mysql/arbitrary-receiver dynamic SQL was **silent** (audit items s1/s2/s3); duplicate findings appeared when two sink regexes matched one line.
  - After: **SAST-001 HIGH** on all three shapes; xstate `.execute(state…)` stays silent (U20.6–U20.8, U20.10).
- **TAGGED_SAFE extends to drizzle `sql` tagged templates** — `sql\`…${id}\`` passed to `db.execute()` is parameterized by design and stays **silent** (was a false HIGH; audit item s4) (U20.9).
- **TAINT-006 / SAST-003 — bare `Function(`**: dynamic-code-execution detection now covers `Function('return ' + req.body.expr)()` without `new`, with a `[^\w$.]` guard keeping property calls (`obj.Function(`) out.
  - Before: bare-`Function` invocation was **silent** (audit item c1); After: **TAINT-006 MEDIUM (needs confirmation)**; literal `Function('return 1')()` stays silent (U20.11–U20.12).
- **TAINT-004 — shell-exec sink set**: `execFile`/`spawn` argument arrays are now tainted sinks; `execFile` was removed from the rule's sanitizer list (it does not sanitize; audit items c3/c4).
  - After: `execFile('convert', [req.query.path])` fires **MEDIUM**, literal argv stays silent, tainted `exec()` regression intact (U20.13–U20.15).
- **HDR-001 — destructured/dotted header receivers** (`src/rules/hdr001.ts`): bare `req.headers` fallback binding (`const { xPgPass } = req.headers`) and `req.get("x-…")` receiver patterns now flow into sink arguments (header name evaluated once per line).
  - Before: pass-the-header patterns were **silent** (audit items h1/h2); After: **HDR-001 CRITICAL** (U20.16–U20.17).
- **LOGS-001 — message-literal stripping and identifier gate** (`src/rules/packs2.ts`): string literals are stripped before scanning, then a secretish identifier token is required — so `console.log("issued api token", token)` now fires while constant diagnostic messages mentioning "password" stay silent (audit items l1/l2) (U20.22–U20.23).
- **JWT-002 — dedupe at source**: only the `jwt.verify(` call line is evaluated; the prior-3-lines re-trigger window is gone. Exactly **one finding per call site** (audit item d1) (U20.24).
- **SUPA quoted identifiers + DDL keyword guard** (`src/rules/supabase.ts`): `CREATE TABLE`/`ENABLE_RLS`/inventory regexes handle quoted `"public"."x"` and guard against `IF|NOT|EXISTS|ONLY`, so `CREATE TABLE IF NOT EXISTS`-style dynamic-DDL strings no longer produce `"public".IF` ghost findings; sensitive tables without RLS still fire (audit items q1/q2/q3/q4) (U20.25–U20.28).
- **NEST-001 / inventory guard-truth** (`src/rules/nestjs.ts`, `src/inventory.ts`): the globalGuard scan now reads **code files only** (`.ts/.js/.mjs/.cjs`, non-spec), so `APP_GUARD` prose in `.md`/docs can no longer silence the rule while a real provider module still does; route-guard detection replaced the bare-word `auth|guard|middleware` heuristic with `hasAuthzCheck()` (session/token/guard **call shapes**) plus method-level `@UseGuards` lookahead (audit items n1–n4) (U20.29–U20.33).

### Fixed — false positives (noise silenced, findings never excluded)

- **SSRF first-argument verdict** (`src/rules/taint.ts`): TAINT-001/002 now taint-check the **first top-level comma-terminated call argument** (quote/bracket-aware `balancedTopArg`, call-shaped sinks, rest-of-line fallback) — a fixed URL carrying header baggage no longer looks SSRF; `fetch(req.query.url)` still fires (audit item h3) (U20.18–U20.19).
- **Hostname allowlist = review note, not HIGH**: TAINT sanitizers recognize `host === req.headers.hostname`, `includes(…hostname)`, and `.origin` comparisons; matching findings are **LOW/low review notes** that never deduct score (audit item h6) (U20.20).
- **LOGS-001 constant-message FP** silenced (see counter-fix above — same mechanism, both directions).
- **SAST-003 test-path demotion** (`src/rules/sast.ts`): interpolated `eval`/shell-exec in **test-class paths** (`tests/`, `specs/`, `*.test.*`, `fixtures/`, `mocks/` — segment-scoped so `latest.ts` never matches) is demoted to a **LOW/low needs-confirmation review note**, never excluded; non-test paths keep the full HIGH/MEDIUM verdict (audit item §5.1) (U20.36–U20.38).
- **NEST-001 `.md` silencing FP** fixed (see counter-fix above).

### Added

- **Hook rule R5** (`src/inithook.ts`): a live secret literal (`sk_live_`, `ghp_`, `AKIA…`) written into client-reachable code is **BLOCKED** (exit 2). Name-only `NEXT_PUBLIC_*` references stay **ALLOWED** (documented law); `sk_test_` keys stay allowed.
- **Hook R3-redirect fallback**: a quoted secret-shaped literal (≥12 chars) written into `.env` via `echo … > .env` / heredoc **without a `KEY=` line** is BLOCKED; paths and flag-looking segments (containing `/` or `=`) are excluded.
- **4 hook acceptance cases** (`tests/acceptance-v03.mjs`): echo-redirect `.env` BLOCK, heredoc live-shaped value BLOCK, `sk_live_` into a client component BLOCK, `sk_test_` ALLOW — hook gate table is now **42/42** (was 38).
- **Performance gate U20.34**: a 500 KB single-line file scanned across the 5 heaviest rules must complete well under the 2 s budget (measured baseline <300 ms). This is the regression lock for the HDR-001 ReDoS claim, which was **not reproduced** (end-to-end flat ~0.4–1 s; worst single rule 134 ms).

### Changed

- **CLI usage-error contract** (`src/cli.ts`): unknown options/subcommands now exit **2** as documented in `docs/AGENT-INTEGRATION.md` and `SKILL.md` (commander's default surfaced the `--fail-on` findings code 1). Implemented via an `exitOverride()` rolled over the **whole command tree** (program + subcommands); `--help`/`--version` still exit 0 (U20.35).

### Tests

- Unit gates U20.1–U20.38 added (`tests/verify-units.mjs`): **289 units** (was 251), all passing; full `npm test` green across all suites (reachability 7, honeypot all seeds + masking intact, clean 100/A, phase-1 25, phase-2 16, SARIF, v0.2, v0.3 hook 42/42, mode2 33, v0.4 47, v1.0 45).

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
