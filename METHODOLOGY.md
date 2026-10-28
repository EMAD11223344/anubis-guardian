# Anubis Guardian — Methodology (v1.0)

> This document is the public contract for how Anubis Guardian finds, scores and
> reports security issues. It exists so every number we publish can be checked,
> every finding can be reproduced, and every limitation is stated before you
> find it the hard way. The full design rationale lives in `docs/PLAN.master.md`.

## 1. Determinism-first

The engine is a **pure function of its inputs**. The same codebase snapshot and
the same rule set produce byte-identical `findings.json` — the acceptance suite
compares two full runs byte-for-byte (v0.2 gate, still enforced). Anything that
breaks this contract is opt-in and flagged in `meta`:

| Layer | Deterministic by default | Opt-in / flagged |
|---|---|---|
| Secrets, history, SAST, playbooks, CI, taint-lite, agent-env | ✅ | — |
| Dependency advisories | bundled snapshot pinned per release | `--online` (registry metadata, `meta.online_used`), `--advisories` local snapshot |
| External adapters | none run | `--tools gitleaks,osv-scanner,semgrep` (`meta.adapters_used`) |
| AI review | off | `--ai-review` (`meta.ai_used`) — redaction-before-LLM + independent verifier, findings capped HIGH + `needs_confirmation` |
| URL Mode (v0.4) | **capture-then-analyze**: the live wire is captured once, analysis is a pure function of the capture. Re-analyzing the same capture (`--from-capture`) is byte-identical and makes zero network requests | live capture itself reflects the site at scan time |

## 2. What the tool never does

- **Never executes project code** (`meta.no_exec` is structural — Section 9.7 of the plan).
- **Never applies a fix.** Every remediation is a suggested diff / generated test;
  a human applies it. There is no auto-fix path in the codebase, by design.
- **Never writes a full secret anywhere.** Masking is mandatory: type + location +
  first 4 chars + sha256 prefix (Section 9.2).
- **Never emits CRITICAL from AI or probes.** CRITICAL severity is reserved for
  deterministic findings with verified evidence; org CRITICAL rules and AI
  findings are forced to `needs_confirmation`.
- **Never scans a URL without the legal gate.** L1 is browser-equivalent passive
  reading (proven per-run by a request-log assertion in the acceptance suite).
  L2+ requires a **verified** ownership nonce (DNS TXT `anubis-guardian-challenge=…`
  or `/.well-known/anubis-guardian/<nonce>`). `--i-own-this-domain` is a checkbox,
  honored only for localhost/private staging and labeled as non-proof. L3 is
  verified-only — never the flag alone.

## 3. Scoring

```
score = 100 − (25·C + 10·H + 4·M + 1·L)
```

- Deductions are grouped by **root cause** (`rule_id` + root): the first finding
  deducts the full weight, each repeat adds +10%, and a group is capped at 2×
  the severity weight. One sloppy pattern repeated 40 times cannot nuke the score.
- **Low-confidence findings never deduct** — they are review notes.
- **INFO severity never deducts** — documented-correct patterns are reported so
  you know the check ran.
- Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, else F.

## 4. False-positive control (per-rule contract)

A rule is not accepted without:

1. **Clean cases** — inputs the rule must NOT flag, committed next to the honeypot
   seeds. The clean corpus must finish at 100/A (zero findings above threshold).
2. **A seed in the honeypot** — every shipped rule has a planted instance the
   e2e suite proves it catches (49/49 checks across 2 roots at v0.3).
3. **Suppression with a reason and an expiry** — `anubis-ignore: RULE-ID reason="…" expires="YYYY-MM-DD"`.
   Expired directives stop suppressing. CRITICAL is inline-only (no config-file silencing).
4. **Confidence + fingerprint on every finding** — the fingerprint is stable
   across runs (rule + path + normalized match) so reviews and suppressions are reproducible.

### 4.1 Known medium-severity heuristic findings (accepted by design)

These fire on ordinary code on purpose — they mark real weakness classes that a
static pass cannot prove or disprove, so they are priced at MEDIUM (−4 each),
never HIGH/CRITICAL:

| Finding | Fires on | Why it is accepted |
|---|---|---|
| `JWT-002` **jwt_alg_unpinned** | any `jwt.verify(token, secret)` call **without** a resolved `algorithms:` option — including `{ algorithms: undefined }` (an options object alone is not pinning; intended behavior, gate U10.1) | Unpinned verify accepts every registered algorithm — the JWT HS/RS confusion class. The FIX is one option object. Only `algorithms: [...]`-pinned calls stay silent; `algorithms:"none"` / `ignoreExpiration:true` are HIGH (seeded in the honeypot). Suppress with an inline `anubis-ignore` where the unpinned choice is deliberate, e.g. `expires="…" reason="internal verify with explicit alg check upstream"`. |
| `TAINT-001..005` | single-file untrusted-input → dangerous-sink flows | Static flow is capped MEDIUM by design ("flow to verify with the generated canary", not a proven vulnerability). |
| `DOCKER-001` | Dockerfile without a `USER` directive | Many images run fine without it; it is hardening advice, not proof of exposure. |

## 5. Org rules & the supply-chain guard (v1.0)

Custom rules run inside Layer-5 semantics. Since v1.0:

- `rules-lock <dir>` pins the directory: SHA-256 per rule file, committed with the rules.
- `scan --rules-dir` **refuses** modified/unpinned rules (exit 2) unless
  `--allow-community-rules` is passed — then the run is quarantined-labeled
  (`meta.rules_lock: "bypassed"`, `meta.community_rules: true`).
- No lock file = v0.2 behavior (warning + `meta.rules_lock: "off"`).
- The community registry itself ships signed post-release; the pinning/quarantine
  mechanism it will use is exactly this one.

## 6. URL Mode levels (Mode 2)

| Level | What runs | Authority required |
|---|---|---|
| L1 passive | page, robots.txt, sitemap.xml, security.txt, the public JS bundles the page loads; TLS + headers + cookies; secrets shipped in public bundles | none (browser-equivalent — request-log proven) |
| L2 discovery | curated sensitive-path probes (SecLists-derived, attributed), listing/method/doc checks, sourcemap exposure | verified ownership (public domains) / labeled self-attestation (local) |
| L3 | L2 + Supabase live anon probe (GET, limit=1, ≤12 tables) + optional restricted differential access check | **verified ownership — never the flag alone** |

The restricted active scope (v1.0 decision, Plan v1.2 #11): `--active-tests` +
both owner-provided testing identities + GET-only + ≤24 endpoints (discovered
JSON surfaces + owner-supplied paths, robots-aware) + semantic diff. Identity
**values** are used in-flight and never stored in the capture or any report.
Anything beyond that is delegated: `init-zap` generates a reviewable OWASP ZAP
baseline config for the owner's own staging target — the engine embeds no DAST.

## 7. Benchmarks policy

**No number is published without a measurement.** `BENCHMARKS.md` contains only
results produced by `scripts/measure-benchmarks.mjs` on the recorded environment
(tool version + full provenance commit, Node version, CPU/RAM/OS, date, and a
statement of trial policy). Claims that cannot be measured yet are listed as
pending, never estimated. Three result classes are kept strictly apart:

- **Curated self-tests** (honeypot 49 planted checks; the labelled corpus in
  `benchmarks/corpus/`) are self-curated by definition — the labels were authored
  in-repo and their provenance/matching rules are pinned in
  `benchmarks/corpus/cases.json`. Their precision/recall numbers are a documented
  self-baseline, **not** external validation.
- **Clean-project false-positive control** (tests/clean) must stay at 0 findings
  above threshold (score 100, grade A).
- **Unlabelled external projects** (OWASP NodeGoat / Juice Shop sanity clones)
  report **raw finding counts only — observations, never recall**: no ground truth
  exists to adjudicate TP/FP on them.

External tool comparisons (gitleaks, semgrep) run on identical directory
snapshots with pinned versions and disclosed configurations; matching rules and
excluded scopes are documented in BENCHMARKS.md. A numerical comparison that
cannot run in a given environment is published as **PENDING with the maintainer
command** — never fabricated, never used to claim a winner.

## 8. Known limitations (stated up front)

- **Next.js App Router handler analysis (v1.5.2 candidate + reported-defect round 2) — bounded
  heuristics**: the handler-body locator is a string/comment/template-aware bounded
  tokenizer, not an AST parser. The v1.5.2 corners (object-brace default values in
  callback parameters, object-brace TS return annotations, braces in the first
  argument string) plus the round-2 corner (an annotation group followed by `=>`)
  are now regression-locked by **both** the unit gates and a deterministic seeded
  fuzz battery (320 fixtures, `tests/verify-tokenizer-fuzz.mjs`, wired into
  `npm test`) that asserts exact declaration lines, span bounds, and planted-marker
  containment; pathological shapes outside the generator's grammar are still
  possible (bounded worst case: the 40-line window, never an unbounded scan).
  AUTHZ-001 handler recognition now also covers `export { handler as METHOD }`
  alias exports **only** when a local function-shaped declaration exists — a
  re-exported import fabricates no handler and no review note. AUTHZ-002's
  request-body tracking is bounded to ≤8 body locals, **one-hop** aliases
  (property alias and re-destructure; second-hop chains are test-locked silent),
  and a decision-shape contract (if/switch/equality/ternary) over the rule's
  documented authz-field list — deeper alias chains or field flows through helper
  functions are not chased. Taint treats parsed request bodies
  (`request.json()`, `request.formData()`, `request.text()`) as untrusted
  wholesale — any field reaching a sink is reviewable; field-level sensitivity is
  out of scope. SSRF (TAINT-001) demotion to the LOW review note requires an
  actual destination-validation OPERATION (host-set membership, host includes,
  host equality against a literal, or a recognized validation helper call) — a
  variable merely NAMED like an allowlist no longer demotes anything. Webhook
  signature recognition (NEXT-004) requires real call shapes (`constructEvent(...)`,
  `new Webhook(...)` + `.verify(...)`, `createHmac(...)` + `timingSafeEqual(...)`);
  signature authenticity counts as in-body authz evidence for AUTHZ-001 but is
  explicitly NOT application authorization. Client-reachability (SUPA-001)
  resolves imports through `tsconfig.json` `paths` at the scan root only —
  `node_modules`, nested workspace configs, and `#` subpath imports are
  unsupported and disclosed. The rule contract remains `needs_confirmation`
  review prompts, never verdicts.
- **RES-001 request-source recognition (closed in reported-defect round 2)**: as
  of this round the rule recognizes `await request.json()`-shaped sources (with
  quote/paren-aware first-argument extraction), in addition to the original
  `req.body` shapes. Remaining boundary: body-reading forms outside the
  recognized source set (custom parse helpers) stay invisible to RES-001 while
  the AUTHZ/TAINT layers may still see them.

- Static analysis sees patterns, not runtime truth — the authz matrix and taint
  canaries generate tests for **you** to run on staging; they do not confirm exploits.
- **File-size caps (v1.4, progress-guaranteed in v1.5)**: files ≤512 KB are
  analyzed in full; larger text files up to **4 MB** are analyzed in
  **overlapping line-boundary windows** (16-line overlap, synthetic scope-break
  at each seam) with exact absolute line numbers, disclosed in
  `meta.files_windowed`; files **above 4 MB stay oversize-skipped** and are
  counted in `meta.files_skipped.oversize`. v1.5 closes the large-line gap: the
  window advance always makes forward progress — a line longer than the window
  budget becomes its own window and the following content is still scanned
  (the v1.4 loop dropped it silently) (U25.1/U25.2 find secrets at exact absolute
  lines after giant lines and in the last line of an all-giant-lines file).
  Window-adjacent caveat: a variable chain whose assignment sits before a seam
  and whose sink lies after it (beyond the overlap) cannot resolve — a
  conservative non-detection, never a false positive. The scanner itself stays
  linear on adversarial inputs (U20.34 budget gate + U22.1 battery gate; the
  100 KB→3 MB stress run confirms sublinear behavior on the worst cases).
  **Cost is also disclosed:** pads preserve exact absolute line numbering by
  repeating rows into every window (Σ pad rows ≈ 4 × line count per 4 MB file),
  so an adversarial 4 MB file of ~2M single-character rows takes ~70 s to fully
  scan (measured 2026-10-27; realistic-density files scan far faster). Budget
  gates lock the behavior: U26.3 (walk construction), U26.4 (per-pack boundedness),
  U26.5 (whole-scan <30 s at the 1 MB scale this class was fixed at). **Planned
  evolution:** the per-window pad block is a candidate for explicit
  absolute-line offsets (windows without repeated rows, a `(lineBase=windowStart)`
  field consumed by a single line-number helper) — a later major-border refactor:
  it touches 78 per-rule `i+1` line computation sites across 15 rule files and
  must reproduce the seam `}` row's brace/scope-boundary semantics (9 files carry
  brace-depth logic that treats the seam row as a real closer), so it is gated on
  byte-identity + exact-line oracle tests of the U26 class before any switch.
- **Capability packs are review prompts, not verdicts (v1.4/1.5)**: AUTHZ/TEN/
  LEAK/RES/UPLOAD findings that depend on invisible layers carry
  `needs_confirmation` plus a note naming exactly what the static check cannot
  see (middleware, APP_GUARD/RLS, runtime values, serving behavior, shared
  clients/wrappers). The full honesty entries live in `classes_not_covered`
  in every report. v1.5 adds: LEAK-003 whole-object response review (scoped to
  chase-resolvable wide-query shapes — nested/derived objects remain
  invisible), RES-003 call-site timeout evidence (shared clients invisible),
  and TEN-002 by-ID reads.
- Codebase Mode covers the frameworks with observed signal (Next.js, Supabase,
  NestJS + generic Node). Other stacks get the generic layers only — the coverage
  registry in every report states what ran.
- URL Mode is a black box: no server internals, no subdomain takeover, no DNS
  level attacks, no business-logic flaws beyond the restricted differential check.
- **Dynamic-SQL value tracking (v1.4 — bounded multi-hop chase)**: SAST-001
  resolves a sink's bare-identifier argument through its value chain
  (`const q = "…" + req.query.x; pool.query(q)` → HIGH). The v1.3 single-hop
  aliasing was replaced by a **bounded chase in `src/rules/flow.ts`**: chained
  aliases ARE followed up to **4 hops** (U18.8g flipped to the new contract),
  method-wrapped intermediates (`const b = a.trim()`) still resolve the origin
  (U18.8g-v4), cycles never fire (U18.8g-v3), and a chain deeper than the bound
  yields **no verdict at all** — never a half-resolved guess (U18.8g-v2). Scope
  remains same-function; one extra hop exists for imported local SQL helpers
  (the helper's source is read, never executed; npm package specs are never
  followed). Tagged `$queryRaw` templates and `$1`-placeholder forms stay
  silent (U18.8c–U18.8e); sinks themselves are unchanged. This is bounded
  propagation within a function (plus one explicit import level), **not** a
  call-graph, an AST engine, or cross-function dataflow.
- **External adapter severities are explicit, not guessed**: `osv-scanner` findings
  map CRITICAL→critical · HIGH→high · MODERATE/MEDIUM→medium · LOW→low; a missing
  or unrecognized OSV severity lands at MEDIUM with `needs_confirmation` and the
  raw value in the note (U17.13/U17.14). A severity the scanner does not name is
  never silently inflated.
- Git-history scanning requires that the scan root sit inside a git repository
  that actually **tracks files under the scan root** (`gitScope`). An untracked
  folder inside an unrelated ancestor repo gets NO history layer — that repo's
  `git log` / `git ls-files` are never imported into the report (no foreign
  HIST findings, no foreign tracked-file paths). `ls-files` output is always
  rebased target-relative.
- URL Mode network exposure — CLOSED by the SSRF guard (v1.1.1 hardening,
  `src/urlmode/ssrf-guard.ts`, zero new deps): every `Fetcher` dial (and the
  `inspectTls` probe) now runs resolve→pin→connect — one `dns.lookup(all:true)`
  per hop, EVERY returned address validated against binary-canonical forms of
  the blocked ranges (loopback, RFC1918, link-local, CGNAT, ULA, v4-mapped/NAT64
  IPv6), then the connection is dialed to the PINNED IP with Host/SNI of the
  original hostname (DNS rebinding closed by construction). Redirects are
  followed manually (cap 10): every hop re-runs the full guard; https→http
  demotion and non-http(s) schemes are refused. CLI mode blocks private
  ranges by default (`--allow-private` re-opens them for local/staging
  targets, per the documented Local staging contract; the ownership gate on
  top is unchanged); cloud metadata endpoints (169.254.169.254 et al.) are
  never dialable in any mode, flag or not. `ANUBIS_SERVICE=1` (service mode)
  ignores `--allow-private`, allows ports 80/443/8080/8443 only, and enforces
  5 MB response caps + 10s/30s timeouts. Residual, deliberately Phase 2:
  the service-mode hard-exit-2 CLI wiring and any hosted deployment still
  need their own review before exposure.
- The advisory snapshot is a point-in-time capture per release; run
  `update-advisories` (or `--online`) for current registry state.
- Dockerfile **ARG/ENV values are not evaluated** — DOCKER-003 is name-only by
  design (the name declares build-time intent; values are build/runtime context).
  A secret-shaped literal baked INTO a value (e.g.
  `ARG DB_URL=postgres://user:pass@host`) is a **backlog item, not a bug**:
  planned rule `DOCKER-004` (HIGH) would inspect ARG/ENV value literals while
  excluding credential-less endpoint URLs.

## 9. v1.2 additions — heuristics and accepted trade-offs

Independent-review fixes introduced a set of new heuristics. Each ships with at
least one must-detect and one must-not-detect gate (unit + regression), and each
carries a deliberate trade-off, stated here.

### 9.1 SAST-001 — first-argument dynamic-SQL analysis

- The old line-slice regex stopped at the first inner quote and excluded lines
  containing `prisma.`. The new analysis extracts the **first argument of the
  call** with paren-balance counting, then looks for `${...}` interpolation or
  non-literal string concatenation inside it. This sees through inner quotes:
  `db.query("SELECT … WHERE name='"+req.query.name+"'")` is detected.
- Sinks: `$queryRawUnsafe`, `$executeRawUnsafe`, `knex.raw`, `sequelize.query`,
  `pool/client/db/connection.query`, DB-handle `.execute(`.
- **Safe-by-design silences (accepted FNs):** tagged templates
  (`prisma.$queryRaw\`…\``, `Prisma.sql`…``) are parameterized by construction;
  positional `$1`/`?` placeholders with a params array are parameterized;
  constant strings carry no taint. These are deliberately silent — a tagged
  template with interpolated input is FN-accepted because Prisma parameterizes
  the interpolation.
- **Severity ladder:** HIGH when the interpolated value traces to request data
  (`req.*`, `params`, `query`, `body`, `searchParams`); MEDIUM +
  `needs_confirmation` otherwise (non-request dynamic SQL is often builder code,
  not an exploit path).
- **Dedupe-key lesson:** the engine dedupes findings on
  `fingerprint(id | file | type | masked-evidence)`. Rules that emit structurally
  identical evidence for different findings collapse into one — SAST-001 keeps
  the **masked sink call** (`knex.raw(…)`) in `evidence.masked` so distinct
  findings stay distinct while the raw value stays masked.

### 9.2 TAINT-006 / SAST-003 — dynamic code execution

- TAINT-006 owns request-tainted `eval` / `new Function` / `vm.runIn*` /
  `setTimeout(<ident>)`; SAST-003 also fires MEDIUM + `needs_confirmation` for
  any non-literal argument **without** a trace to request data. Bare
  `Function(...)` invocation (without `new`) is covered by both, with a
  property-call guard; literal-only calls (`Function('return 1')()`) never fire.
- **Test-path demotion (not exclusion):** in test/demo-script paths (`tests/`,
  `specs/`, `*.test.*`, `fixtures/`, `mocks/` — segment-scoped so `latest.ts`
  cannot match) SAST-003 findings are demoted to LOW/low/needs-confirmation
  review notes; they stay visible but do not deduct. A real eval-shaped sink in
  a non-test path keeps the full verdict. Excluding whole rule classes by path
  is deliberately not done.
- **De-duplication policy:** request-traced eval is reported once, by TAINT-006
  (the taint layer has the data-flow evidence); SAST-003 defers. Literal
  `eval('1+1')`, and `eval` inside comments or strings, never fire. Argument
  extraction is paren-balanced within the line — a trailing comment after the
  call cannot change the argument's classification.

### 9.3 JWT-003 — hardcoded signing/session secrets

A string literal (≥6 chars) reaching `jwt.sign/verify`, `JwtModule.register`,
`secretOrKey`, `session({ secret })`, or a `JWT_SECRET`-like `const` is HIGH.
**The generic placeholder skip deliberately does not apply** — a default like
`'changeme-super-secret-key'` checked into source **is** the vulnerability
(git-guessable by design). Templates (`process.env.*`, `${…}`, `<…>`,
`YOUR_*`, `configService.get`) stay silent.

### 9.4 SEED-001 — path semantics

Matches `(seeds?|seeders?|factories|fixtures|db/seeds)/**` and named files
(`seed[-_.]*`, `create/init/bootstrap-admin`, `prisma/seed-*`, `scripts/*seed*`).
Encoding lesson: a bare `seeders?` alternation does **not** match the `seeds/`
directory — the class must spell both names. Placeholder passwords and
`*.test.*`/`__tests__` stay excluded (clean gates).

### 9.5 HDR-001 — value-flow receivers over name heuristics

- Receiver side: ANY value read from `req.headers[…]` / `req.header(…)` /
  `headers().get(…)` — including Next.js `headers()` local aliases — flowing
  into DB sink properties (`password`, `connectionString`, `url`, `host`,
  `user`, `uri`) on `Pool`/`Client`/`createPool`/`mongoose.connect`/postgres/
  drizzle is CRITICAL when sink-linked; header **names** no longer matter on the
  receiver side (`x-pg-secret`, `x-dsn` are detected). The name heuristic
  remains only for the client (sender) side, downgraded LOW.
- **Regex lesson encoded:** when an alternation has multiple capture variants,
  a matcher must use the **last DEFINED** capture group — undefined variant
  groups silently break the comparison otherwise.
- **Positional-call lesson:** argument scanning is nesting-aware
  (`mongoose.connect(req.headers.get("x-dsn"))` survives parenthesis depth).

### 9.6 Transitive dependency recall (DEP-001)

- The lockfile (package-lock/v8-resolved tree) now supplies transitive
  packages; any of them matching a moderate+ advisory produce one aggregated
  `DEP-001` per package at the lockfile path, name-sorted, evidence capped
  (5 advisories per package) — determinism holds.
- **Snapshot staleness as an honest meta-date:** `meta.advisory_snapshot_date`
  records the bundled OSV capture; terminal/JSON warn when >90 days old. This
  converts "the snapshot is old" from an error into visible, dated context —
  `update-advisories`/`--online` refresh it.
- **FP calibration:** the snapshot only grades what OSV says — patched releases
  of the same package (the clean comparator in the T14 gates) never fire.

### 9.7 Guard hook — value-based detection (R1–R5)

- **Decoded role beats substring:** every JWT-shaped stress (3 base64url
  segments) is decoded; only decoded `role === "service_role"` decides R1, in
  client-reachable contexts (`'use client'`, `components/`, pages/ non-api,
  client-prefix `.env` names). Server contexts (`"use server"`, `app/api`,
  route handlers, middleware, server path segments, `supabase/functions`) are
  allowed. The substring-`"server"`-in-path heuristic is retired — `observer.ts`
  is the regression-proof test.
- **Comment stripping before pattern tests:** a comment mentioning
  service_role never blocks (over-stripping biases fail-open, which is the
  correct alarm direction for a write-time hook with an escape hatch).
- **RLS pairing logic:** `drop policy` is blocked only when the same content
  contains no `create policy` for the same table (table = last dot-segment
  after `on`; quoted identifiers normalized). Drop-then-recreate migrations
  pass; a name-only `DROP POLICY` (no `on` clause) blocks conservatively.
- **Public-by-design env names** pass the R3/R4 name path (FIREBASE_API_KEY,
  GOOGLE_MAPS, POSTHOG, ALGOLIA search keys, STRIPE_PUBLISHABLE,
  SUPABASE_ANON/PUBLISHABLE, SENTRY_DSN, MAPBOX `pk.*`); the VALUE path still
  applies (a genuinely secret-shaped value under a public name still ships to
  the browser — blocked on the value).
- **Bash coverage is best effort and documented as such:** heredoc / redirect /
  tee / `sed -i` target extraction is heuristic token work; it is a guard, not
  a security boundary, and both the SKILL and the generated script say so.
- **Fail-open contract preserved:** malformed/empty stdin → exit 0. Escape
  hatches: `ANUBIS_GUARD=block|warn|off` and the inline marker
  `anubis-allow: <reason of 8+ chars>` (echoed to stderr; shorter reasons still
  block — the gate exists to record intent, not to be slipped past).
- **R5 — live secret literals into client-reachable code:** a value matching
  live-provider key shapes (`sk_live_…`, `ghp_…`, `AKIA…`) written into a
  client context is blocked. `sk_test_`/publishable keys stay allowed, and
  name-only `NEXT_PUBLIC_*` references stay allowed (the documented law: only
  secret-shaped VALUES ship secrets).
- **R3-redirect fallback:** a quoted secret-shaped literal (≥12 chars) written
  into `.env` via `echo … > .env` or heredoc **without a `KEY=` line** is
  blocked; segments containing `/` or `=` (paths, flags, existing assignments)
  are excluded. The ≥20-char credential-name gate for explicit `KEY=VALUE`
  writes is unchanged and documented as a deliberate tradeoff.
- **Version wiring:** the hook header, `settings.json` entry, and AGENTS.md
  snippet derive from the real package version — no stale `v0.3.0` labels.

### 9.8 Fail-closed CLI contract (behavior change)

Nonexistent paths, zero scannable files, unknown flags, and unreachable
`scan-url` targets now exit **2** with no score line and no report. The old
behavior — a fake `100/A` for work that never happened — is the failure mode
this contract exists to prevent; CI consumers should treat exit 2 as "fix the
invocation", not "all clear". `--allow-empty` keeps the explicit opt-out.

### 9.9 Accepted FN/FPP trade-offs (summary)

- Tagged-template Prisma SQL with interpolated input → silent (parameterized
  by design).
- Non-request dynamic SQL/dynamic code → MEDIUM + needs_confirmation, never
  HIGH without a request trace.
- `drop policy` with an `on` clause, same-table recreate → allowed by design.
- Bash-target extraction misses unusual redirection forms (quoted spaces,
  `dd of=`) — documented gap, best effort only.
- `create policy … using (true)` is blocked even when the table is genuinely
  public — deliberate friction; the escape hatch records the intent.

