# ROADMAP.md — prioritized, calibrated, and honest

> Written 2026-10-28 against commit-phase "v1.5.3 fix phase" (base `874bec1`).
> Every "missing" claim below was audited against the current source first —
> items marked **exists (partial)** cite the file:line where the capability
> already lives, so we never claim absence of something we already ship.

## Part 1 — capability audit (what exists today, calibrated)

| Area | Status | Evidence |
|---|---|---|
| Next.js middleware.ts detection | **exists** — AUTH-001 (middleware-only auth with matcher gaps), server-side classification, init-hook protection | `src/rules/packs2.ts:159`, `src/rules/context.ts:20`, `src/inithook.ts:151` |
| `@UseGuards` as authz evidence | **exists** — NEST-001 parses class/method guards; `UseGuards` is in the shared AUTHZ_CALL allowlist; APP_GUARD provider search | `src/rules/nestjs.ts:101-109`, `src/rules/authzpack.ts:32,493` |
| Named auth helpers (`getSession`, `requireUser`, `requireAdmin`, `verifyToken`, …) | **exists** — shared `AUTHZ_CALL` regex consumed by AUTHZ-001 and the recon inventory | `src/rules/authzpack.ts:31-32`, `src/inventory.ts:133,162` |
| Custom wrapper HOFs (`withAuth(myHandler)`) | **partial** — only a fixed name list; a project-defined wrapper is not learned | same lines; no wrapper-definition resolution anywhere |
| Server Actions (`'use server'`) | **partial** — the directive is classified server-side and mapped in recon; an `action={fn}` prop pointing at a 'use server' module is NOT tracked | `src/rules/context.ts:19`, `src/nextjs.ts` (directive in `isApiRoute`), `src/inventory.ts:48-49`; no `action=\{` handling |
| Supabase RLS | **exists** — SUPA-R01..R08 policy/view/hook checks + URL-mode live anon-read probe (URL-060) | `src/rules/supabase.ts:11-245`, `src/urlmode/checks-l3.ts:96-106` |
| Ordered-migration audit (RLS enabled before policy grants) | **partial** — hook blocks `DROP POLICY` without re-`CREATE POLICY` (`src/inithook.ts:182-195`); no migration-sequence lint of `supabase/migrations/*.sql` |
| tRPC / Hono / FastAPI / Express routers | **absent** — zero rule or detector code (only an advisory allowlist mention of `hono`) | grep across `src/` |
| Slopsquatting / hallucinated deps | **exists** — DEP-005 (`--online` registry 404 → high; fresh-unknown → medium) and DEP-004 lockfile drift | `src/rules/deps.ts:16,206-217`, `src/cli.ts:99` |
| URL-mode ↔ static correlation | **absent (programmatic)** — URL findings carry advisory "code map" text pointing at Codebase Mode, but no engine-level join by literal/file/endpoint | `src/urlmode/jsassets.ts:139-155`, `src/urlmode/checks-l2.ts:194`; grep `correlat` = 0 hits |
| Taint scope | **same-file, ≤4 hops** by contract (documented); one-level imported-helper sanitizer recognition allowed | `src/rules/taint.ts:8-10,119`, `src/rules/flow.ts` |
| Parser | **line-regex + bounded tokenizer**; no AST dependency at runtime (`typescript` is dev-only) | `src/rules/authzpack.ts` (handlerBodySpan), `package.json` deps = `commander` only |

## Part 2 — roadmap

Sizes: S = ≤1 day, M = 2–4 days, L = ≥1 week (incl. fixtures + calibration).
Release targets are suggestions; nothing here is scheduled or promised.

### P1 — high value / low risk / small

**R1. URL↔static correlation (programmatic join).**
- *Value:* the two product modes already produce the raw material — URL findings
  embed a key-literal fingerprint and an advisory "search the repo" hint
  (`src/urlmode/jsassets.ts:139-155`). A deterministic join (same literal
  prefix, same endpoint path, or URL-060 RLS probe ↔ SUPA-R finding on the
  referenced table) turns two disconnected reports into one evidence chain.
- *Prereqs:* none new — findings on both sides already exist.
- *Fixtures:* extend `tests/mode2/` with a paired static+URL case; assert the
  merged report links both finding IDs.
- *Risks:* false linkage — mitigate with exact-literal match first, path-match
  second, and mark correlated rows `needs_confirmation: true` (review
  calibration contract).
- *Size:* S–M. *Target:* next minor (v1.6.x).

**R2. Bounded authz-evidence additions to AUTHZ_CALL.**
- *Value:* two very common real-world shapes currently rely on the review note
  instead of silence-with-confidence: in-body `passport.authenticate(...)` /
  `ensureLoggedIn(...)` / `app.use(...)` per-route middleware closures, and
  `verifySignature`-style call names (webhook family already handles its own
  shapes).
- *Prereqs:* none — pure regex additions to the shared `AUTHZ_CALL` contract
  (`src/rules/authzpack.ts:31-32`), gated on being an actual CALL (paren
  required), same as the v1.5.3 webhook fix.
- *Fixtures:* one safe route per shape + one "comment-only mention" negative
  (mirror the NEXT-004 calibration).
- *Risks:* LOW — name-only matches were removed in v1.5.3 for exactly this
  reason; keep call-shape-only.
- *Size:* S. *Target:* v1.6.x.

**R3. Server-Action `action=` prop linkage.**
- *Value:* closes the biggest Server-Action gap: a client component passing an
  imported `'use server'` function to `action={fn}` makes that function
  client-invokable — exactly the boundary the SUPA-001 client-reachability
  contract already reasons about.
- *Prereqs:* import resolution already exists (`src/rules/context.ts`
  resolveAliased/candidatesFor, added in v1.5.3 for path aliases).
- *Fixtures:* vuln pair (secret used in a server-action module invoked via
  `action=` from a client component) + safe pair (same shape, env-only key).
- *Risks:* MEDIUM — `action={fn}` appears in many innocent forms (local
  closures); only fire on an IMPORTED symbol that resolves to a 'use server'
  module, bounded one hop, tsconfig-at-scan-root scope (same disclosure as
  v1.5.3 alias resolution).
- *Size:* M. *Target:* v1.6.x–v1.7.

### P2 — high value / medium effort

**R4. tRPC + Hono router packs.**
- *Value:* tRPC procedures and Hono handlers are the same "server endpoint with
  request-derived input" shape the taint/authz packs already handle; the seed
  expressions differ (`procedure.mutation(...)` input, `c.req.json()`).
- *Prereqs:* framework detection flags (`ctx.stack.frameworks`) + a corpus
  extension; NO parser change — taint seeding stays line-based.
- *Fixtures:* 4–6 labelled pairs (tRPC mutation w/o authz, Hono route w/o authz,
  + safe counterparts); add `trpc`/`hono` cases to `benchmarks/corpus/cases.json`.
- *Risks:* MEDIUM — new framework detection can misfire on library imports;
  keep detection to actual router instantiation calls, disclose detection
  bounds in METHODOLOGY.
- *Size:* M–L. *Target:* v1.7.

**R5. Project-defined auth-wrapper learning (one hop).**
- *Value:* `withAuth`, `requireRole`, `withWorkspace` wrappers are project
  idioms; today only a fixed name list is recognized.
- *Design (bounded):* at scan time, find local function definitions whose body
  contains an AUTHZ_CALL and whose signature takes a handler/request param;
  register their names as evidence — ONE hop, same scan root, no call-graph.
- *Fixtures:* vuln pair (wrapper without authz call inside → not evidence →
  AUTHZ-001 still fires) + safe pair (wrapper with in-body getSession).
- *Risks:* MEDIUM — a wrapper that conditionally skips auth would become a
  false-silence vector; mitigate by requiring the authz call to be
  unconditional-in-shape (no early-return-bypass recognition — review note
  stays for anything ambiguous) and by emitting the learned-name note in the
  report so the evidence source is auditable.
- *Size:* M. *Target:* v1.7.

**R6. Supabase ordered-migration lint.**
- *Value:* reads `supabase/migrations/*.sql` in filename order and reports
  sequences where a table serves policies before `ENABLE ROW LEVEL SECURITY`,
  or `DROP POLICY` without a later re-`CREATE` (hook already blocks the
  same-session edit; this extends to committed history).
- *Prereqs:* none new; SQL line parsing only (same shape as SUPA-R01/02).
- *Fixtures:* a two-file migration sequence vuln/safe pair.
- *Risks:* LOW — advisory medium notes only; never claims the live database
  state (that remains the URL-mode L3 probe's verified-only domain).
- *Size:* M. *Target:* v1.7.

### P3 — strategic / requires separate review

**R7. Cross-file taint (one-hop import of a source-returning helper).**
- The engine contract caps taint at one file; crossing that boundary is a
  *contract change*, not a patch: it needs a design note, FP calibration on the
  whole corpus, and a disclosed bound (which imports count, depth cap, cycle
  behavior). Deferred until R1–R6 land and the corpus is bigger.
- *Size:* L. *Target:* unscheduled.

**R8. AST parser evaluation (TypeScript API vs Oxc vs tree-sitter).**
- Facts measured today: runtime deps = `commander` only; `typescript` exists as
  a devDependency (so ts.createSourceFile would add a *runtime* dependency —
  not free); Oxc/tree-sitter add native binaries (supply-chain + packaging
  impact on the packed tarball that acceptance v1.0 gates scrutinize).
- Position: keep line-regex + bounded tokenizer as the default engine; if the
  tokenizer-fuzz gate (tests/verify-tokenizer-fuzz.mjs) ever reports a real
  bug class that regexes cannot bound, evaluate `typescript`'s parser API
  FIRST (same-language, no native binary), then tree-sitter. Any switch is a
  separate reviewed project with its own benchmark re-run.
- *Size:* L (evaluation alone). *Target:* unscheduled.

**R9. FastAPI / Python support.** Out of scope for this Node/TS scanner; the
honest position is METHODOLOGY's non-goal list, not a rule pack.
- *Size:* n/a. *Target:* never promised.

**R10. Express `app.use` global-middleware cross-file evidence.** Related to
R5 but cross-file: a `server/middleware.ts` with `app.use(session())` cannot
authorize a route in another file under the same-function contract — R2 covers
the in-body shapes; the cross-file variant rides on the R7 contract review.
- *Size:* L. *Target:* unscheduled.

## Part 3 — sequencing rationale

P1 items reuse v1.5.3 building blocks (import resolution, call-shape matching,
calibration pattern) and each ships with its own negative fixtures — the same
formula that took the six P0 defects from reproduction to regression-locked.
P2 items add framework surfaces and need corpus + METHODOLOGY updates. P3
items change contracts or dependencies and stay unscheduled until their
separate reviews are written.
