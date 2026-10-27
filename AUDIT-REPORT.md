# v1.3.0 Security-Audit Report — multi-agent review verification

Date: 2026-10-27 · Baseline: `716162c` (tag v1.3.0) · Status: fixes implemented and verified, **uncommitted** — the owner decides commit/tag (version stays 1.3.0).

---

## 1. Executive summary

A multi-agent audit report claimed a set of defects in Anubis Guardian's own detection engine, CLI contract, and PreToolUse guard hook. Every claim was **reproduced against real code before any fix**; confirmed defects were fixed with regression gates, claimed false positives were silenced at the rule level (never by excluding paths), and one claim — a ReDoS in HDR-001 — was **not reproduced** and is instead locked out by a permanent performance gate.

Result: **10 confirmed false-negative classes fixed, 5 false-positive classes resolved (2 by downgrade to review notes, 3 by rule correction), 1 severity-accuracy demotion (SAST-003 in test paths), 1 CLI exit-code contract bug fixed, 1 hook enforcement extension (R5 + R3-redirect fallback).** No new runtime dependencies; masking, determinism, and read-only contracts unchanged. The full test suite is green, twice, with zero regressions: units **251 → 289**, hook acceptance table **38 → 42/42**, and all compliance suites passing.

The audit also scoped six owner-requested capability groups (RBAC, multi-tenant isolation, data-leakage, resource-DoS, large-file resilience, upload security). These remain **plan-only** (§5); a new detection or hook rule for them was intentionally not shipped as an untested drive-by.

---

## 2. Verified-issue classification

Legend: **CFN** = confirmed false-negative (silent detection), **CFP** = confirmed false-positive / noise, **SEV** = severity-accuracy defect, **CONTRACT** = documented behavior mismatch, **NR** = not reproduced, **BY-DESIGN** = documented tradeoff, left unchanged.

| # | Report claim | Class | Verdict | Fix / disposition |
|---|---|---|---|---|
| j1/j2 | `const secret = env \|\| "literal"` fallback secrets silent | CFN | Reproduced | JWT-003 fallback analysis (U20.1–U20.2) |
| j4 | cookie-session `keys: ["…"]` silent | CFN | Reproduced | JWT-003 keys-array rule (U20.3) |
| j6 | jose `setSigningKey("literal")` silent | CFN | Reproduced | JWT-003 JOSE method-call form (U20.4); clean env/config stays silent (U20.5) |
| s1–s3 | TypeORM / mysql2 / arbitrary-receiver dynamic SQL silent | CFN | Reproduced | SAST-001 sink generalization: `.query(`/`.execute(` + NON_SQL_RECV blacklist (U20.6–U20.8) |
| s4 | drizzle tagged `sql\`` template flagged | CFP | Reproduced | TAGGED_SAFE extended (U20.9); xstate non-SQL stays silent (U20.10) |
| c1 | bare `Function('return '+req.body.expr)()` silent | CFN | Reproduced | TAINT-006 + SAST-003 dynRe, property-call guarded (U20.11–U20.12) |
| c3/c4 | tainted argv into `exec` var / `execFile` silent | CFN | Reproduced | TAINT-004 sink set extended; `execFile` removed from sanitizer list (U20.13–U20.15) |
| c5 | clean exec argv | CFP | Already clean | Regression gate kept (U20.15) |
| h1 | `const { xPgPass } = req.headers` → Pool password silent | CFN | Reproduced | HDR-001 bare-`req.headers` binding (U20.16, now CRITICAL) |
| h2 | `req.get("x-…")` receiver silent | CFN | Reproduced | HDR-001 req.get patterns (U20.17) |
| h3 | fixed URL + header baggage flagged as SSRF | CFP | Reproduced | TAINT-001/002 first-top-level-argument verdict (`balancedTopArg`) (U20.18–U20.19) |
| h6 | hostname-allowlist flagged HIGH | CFP | Reproduced | hostname/`.origin` sanitizer → LOW/low review note, never deducts (U20.20) |
| h7/h8 | open-redirect startswith-guard regressions | mixed | Reproduced | TAINT-002 regression gates (U20.21) |
| l1 | constant message w/ "password" flagged | CFP | Reproduced | LOGS-001 literal-strip + secretish-identifier gate (U20.22) |
| l2 | `console.log("issued api token", token)` silent | CFN | Reproduced | Same mechanism, opposite direction (U20.23) |
| d1 | JWT-002 duplicated per option line | CFP | Reproduced | verify CALL line only, dedupe at source (U20.24) |
| q1/q2 | `"public".IF` ghost findings from quoted IDs / DDL strings | CFP | Reproduced | supabase quoted-ID + DDL keyword guard (U20.25–U20.26) |
| q3/q4 | genuine RLS findings silenced/kept | CFN+CFP | Reproduced | Rewrite fires q4, stays silent on correctly-guarded (U20.27–U20.28) |
| n1–n4 | NEST-001 silenced by prose in `.md`; inventory guard-truth | mixed | Reproduced | Code-file-only globalGuard scan; `hasAuthzCheck()` call-shape heuristic; `@UseGuards` lookahead (U20.29–U20.33) |
| §2.1 | ReDoS in HDR-001 on long lines | NR | **Not reproduced** | Measured flat end-to-end ~0.4–1 s; worst rule 134 ms on a 499 KB single line; MAX_FILE_BYTES=512 KB bounds per-file cost. Locked by perf gate U20.34 |
| §5.1 | SAST-003 storm in demo/proof scripts (~62 findings/project) | SEV | Reproduced | Demoted to LOW/low/needs-confirmation **review note** in test-class paths; never excluded (U20.36–U20.38) |
| CLI | unknown option exited 1 (findings code), docs say 2 | CONTRACT | Reproduced | `exitOverride()` over the whole command tree; help/version → 0 (U20.35) |
| hook | `echo "sk_live_…" > .env` / live literal into client code allowed | CFN | Reproduced | Hook R5 + R3-redirect fallback (acceptance E-table, 4 new cases) |
| — | ≥20-char `.env` credential-name gate; AST-parsing adoption; single-file taint scope; advisor offline snapshot | BY-DESIGN | Reviewed | Documented tradeoffs, unchanged (METHODOLOGY §8, §9) |

---

## 3. Implemented fixes (with regression gates)

**Detection engine** (`src/rules/taint.ts`, `sast.ts`, `hdr001.ts`, `jwtsecrets.ts`, `packs2.ts`, `supabase.ts`, `nestjs.ts`, `src/inventory.ts`):

1. **JWT-003** — `||`/`??` fallback literals on credential-named identifiers (case-insensitive `SECRETISH_NAME`), cookie-session key arrays, `signingKey(s)`/`JWT_secret` object properties, jose `setSigningKey(`/`.sign(` contexts. *Before:* j1/j2/j4/j6 silent → *After:* HIGH; env/config-sourced silent.
2. **SAST-001** — general `.query(`/`.execute(` sink with `NON_SQL_RECV` blacklist + `seenSinks` content-offset dedupe (no duplicate findings across overlapping sink regexes); TAGGED_SAFE covers drizzle-style tagged templates.
3. **TAINT-004/006** — `execFile`/`spawn` argv sinks; bare `Function(` with `[^\w$.]` property guard.
4. **HDR-001** — bare-`req.headers` destructure binding, `req.get("x…")` receivers.
5. **TAINT-001/002** — first top-level comma-terminated argument verdict (`balancedTopArg`); hostname/origin allowlist sanitizers downgrade to review notes.
6. **LOGS-001 / JWT-002** (packs2) — literal-stripped identifier gate; verify-line-only dedupe.
7. **SUPA / Nest / inventory** — quoted-identifier regexes + DDL keyword guard; code-file-only globalGuard; call-shape route-guard truth (`hasAuthzCheck()`, `@UseGuards` lookahead).
8. **SAST-003 demotion** — segment-scoped `isTestPath` (`latest.ts` can never match); LOW review note, never exclusion; non-test paths keep full verdict.

**CLI** (`src/cli.ts`): exit-2 usage refusal across the entire command tree — now matches `docs/AGENT-INTEGRATION.md` and `skill/SKILL.md`.

**Hook** (`src/inithook.ts`): R5 live-secret-into-client-code BLOCK (`sk_live_`/`ghp_`/`AKIA`); R3-redirect fallback for quoted literals into `.env` via `echo`/heredoc without `KEY=`; name-only `NEXT_PUBLIC_*` and `sk_test_` stay ALLOWED. 4 new acceptance cases; hook table **42/42**.

**Docs**: CHANGELOG `## [Unreleased]` entry; METHODOLOGY §9.2 (test-path demotion, bare `Function`) and §9.7 (R1–R5, R3-redirect); README hook rule summary. Exit-2 contract already documented pre-audit — code now matches it; no doc change needed.

Every fix is locked by a named gate: **U20.1–U20.38** in `tests/verify-units.mjs`, plus the hook acceptance cases and existing suite regressions.

---

## 4. Outstanding issues

1. **§2.1 ReDoS — closed as NR with a hysteresis lock.** If the engine's line model ever changes (e.g., unbounded multi-line regexes), U20.34 fails loudly. No code change warranted by evidence.
2. **Taint analysis remains single-file, single-scope.** Cross-file/cross-function flows are not tracked (documented in METHODOLOGY §8). The AST-parsing decision stays "documented, not adopted" — line-based evidence remains the determinism/masking contract's foundation.
3. **≥20-char `.env` credential-name gate** is a deliberate tradeoff (short names like `PW` can slip R3's explicit-assignment path unless the value itself is secret-shaped). The new R3-redirect fallback covers the majority of the residue; wider name modeling is deferred to the data-leakage capability (§5.3).
4. **`isTestPath` segment list is a fixed allowlist** (`tests|__tests__|specs|fixtures|mocks`, `.test.`/`.spec.`). Exotic layouts (e.g., `unittests/`) won't demote — demotion failing *open* (finding stays HIGH) is the safe direction; documented in METHODOLOGY §9.2.
5. **Hook Bash coverage stays best-effort** (heredoc/redirect/tee/sed token work). R5 covers `Write`/`Edit`-shaped tools exactly; Bash is heuristic by documented design.

---

## 5. §7 capability plan (plan-only; small safe slice shipped where noted)

### 5.1 RBAC / route authorization (planned)
- **Scope:** detect routes/endpoints whose handler performs privileged ops (DB write, admin table, `service_role` client) with no authorization check on any path segment (`hasAuthzCheck()` is the seed — it already powers inventory in v1.3-audit).
- **Method:** per-route call-graph-lite: handler body scan for authz call shapes (`getSession`, `requireAuth`, `verify`, `@UseGuards`, middleware chain) + privileged-op shapes; unchanged-file cross-reference with the existing inventory table.
- **Inputs/limits:** same single-file boundary as TAINT (middleware in another file can look like a gap). Emit MEDIUM `needs_confirmation` review notes, never auto-BLOCK, until the cross-file story is real.
- **Tests:** extend clean corpus with correctly-guarded variants (must stay silent), add honeypot seeds for admin-write-without-authz; unit gate mirrors U20.32/33 shapes.

### 5.2 Multi-tenant isolation (planned)
- **Scope:** detect tenant-scoped queries (`where` on `orgId`/`tenantId`) missing from mutations/reads in known-tenant schemas.
- **Method:** schema-signal-first (drizzle/pg-tables column definitions) → per-sink `where` clause check tagged into SAST-001 evidence; report as review note tied to the file's tenant entity.
- **Limits:** schema inference is heuristic; only fires where a tenant column is actually declared. False-positive risk high → notes-only at v1.4.
- **Tests:** table-driven unit gates with a fixture schema; clean corpus additions for correctly-scoped queries.

### 5.3 Data-leakage (near-term batch, highest value)
- **Scope:** generalize what HDR-001/JWT-003/LOGS-001 already do into an audited class: secret-ish values flowing to sinks that ship to clients/browsers (`res.json/send`, logging, `NEXT_PUBLIC_*` writes beyond the hook's R4).
- **Method:** valueclass reuse (already deterministic/masked), receiver blacklist per sink family; no new deps.
- **Tests:** extend U20 with per-sink family gates; honeypot seeds for `res.json({...token})`.

### 5.4 Resource exhaustion / app-DoS (planned, hook-first)
- **Scope:** hook-side R6 candidates (destructive `rm -rf /`, `drop database`, unbounded `while(true)` writes), engine-side `--max-files`-style per-rule budget reporting.
- **Method:** hook rules stay value-based and fail-open-commented; engine reports budgeted, never blocks on suspicion.
- **Limits:** this is a guard category, not a detection category — the SKILL wording ("guard, not security boundary") carries over.

### 5.5 Large-file resilience (largely DONE — verified in this audit)
- MAX_FILE_BYTES (512 KB) bounds per-file cost; performance gate U20.34 locks the single-line worst case. Remaining: a skip-summary line ("file truncated from N bytes") in the JSON report for transparency, locked by a small unit gate — candidate for the next batch, no behavior change to findings.

### 5.6 Upload security (planned)
- **Scope:** detect unvalidated upload shapes (`request.formData().file`, raw-body writes) landing in public/ or served paths without type/size checks.
- **Method:** receiver-shaped dataflow on first-argument (reuses `balancedTopArg` experience); review-note severity initially.
- **Limits:** file-served-later flows are cross-file; notes-only until §5.2's cross-file work.

**Roadmap:** v1.4 = §5.3 batch + 5.5 transparency line + 5.1 notes; v1.5 = 5.2/5.6 notes + hook 5.4-R6; cross-file taint (if ever) is its own major with a design doc first.

---

## 6. Validation results (actual, from the final green run)

`npm run build` clean; **`npm test` exit 0**, run twice after all fixes:

| Suite | Result | Count |
|---|---|---|
| Unit verification | PASS | **289** (was 251), incl. new U20.1–U20.38 |
| Reachability verification | PASS | 7 |
| Honeypot | PASS | all seeds detected; masking contract intact |
| Clean corpus | PASS | 0 findings above threshold, score **100**, grade **A** |
| Phase-1 regression | PASS | 25 |
| Phase-2 regression | PASS | 16 |
| SARIF verification | PASS | Security-tab ready |
| Acceptance v0.2 / v0.3 / mode2 / v0.4 / v1.0 | PASS | — / hook **42/42** (was 38) / 33 / 47 / 45 |

Zero regressions in any pre-existing gate. Probe batteries (`probes.mjs` 20-case rule battery, `probes3.mjs` nest 4/4, `probes4.mjs` hook verdicts incl. echo-redirect/R5/sk_live) all pass. Performance: 500 KB single-line worst case **<300 ms** against the 2 s budget (U20.34).

---

## 7. Ranked next priorities

1. **Land the audit commit** (review the uncommitted diff, run `npm test` once, commit on top of `716162c`; do **not** re-tag v1.3.0 — changes ship under the next release per the CHANGELOG `[Unreleased]` entry).
2. **Data-leakage batch (§5.3)** — generalizes this audit's HDR/JWT/LOGS work; highest signal-per-line-of-rules.
3. **Session-repair sweep of BY-DESIGN items** (§4 #2–#4): write the cross-file-taint design doc, and decide whether the ≥20-char gate gets value-shape-only mode.
4. **Hook R6 (§5.4)** after a fail-open/comment-out review with the owner — it is the only proposed capability that actively blocks.
5. **RBAC notes (§5.1)** — `hasAuthzCheck()` is already shipped as inventory truth; promoting it to a review-note rule is a small, testable step.
6. **Re-run of the multi-agent audit** as the acceptance criterion for the capability roadmap (same reports, new code).
