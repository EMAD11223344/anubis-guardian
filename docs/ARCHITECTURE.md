# Architecture & Extending the Detector Set

> Verified against the working tree of the W3 multilingual round (base `c5bd119`, fixes in the same dev phase as the v1.5.2/v1.5.3 fix commits — unreleased; npm stays at the last published version until the owner releases). This document describes the system as it **is** — every entry point, file filter, and count below was read from the implementation, not projected. Where numbers can drift, the *source* is named instead of a snapshot.

Anubis Guardian is deliberately **not a plugin framework**. It is a single deterministic pipeline with a small number of well-defined seams. This page inventories the pipeline, the detector taxonomy, the shared contracts every detector inherits, and the repeatable procedure for adding a detector — with `src/rules/infra.ts` (added in the multilingual round) as the worked, regression-locked example.

---

## 1. Pipeline overview

`src/engine.ts` — `scan(ctx)` is the only orchestration point:

1. **walk** — `src/walk.ts` collects every file under the scan root(s): **no extension filter** (all text files are candidates; binaries are skipped by content sniff, files ≤512 KB read whole, 512 KB–4 MB analyzed in overlapping line-boundary windows, >4 MB skipped + counted as `oversize` in `meta`). Files >512 KB window-advance is progress-mandatory (giant single lines never stall the scan).
2. **recon + inventory** — `src/recon.ts`, `src/inventory.ts` classify the stack (frameworks, migrations, lockfiles) and build the static attack-surface map. `stack.frameworks` gates the framework playbooks.
3. **detector packs** — every registered pack runs over every file; each pack applies its own file filter. Call sites: `engine.ts` lines 92–114 (order fixed; findings are severity-sorted later, so order is not semantic).
4. **merge + score** — dedupe by fingerprint, apply root-cause caps, `needs_confirmation` classification, coverage manifest (`checks_run / checks_applicable` from `src/coverage.ts`), score = `100 − (25·CRITICAL + 10·HIGH + 4·MEDIUM + 1·LOW)`, grade A–F.
5. **render** — `src/report/*`: terminal/json/md/sarif/html/compact. Fail-closed everywhere: no trustworthy scan ⇒ no report (`exit 2`).

## 2. Detector taxonomy — five categories

| Category | Examples | Runs on | File access |
|---|---|---|---|
| **A. Universal line-regex packs (language-independent)** | `secrets.ts` (SEC-001..010, SUPA-001, ENV-001, HDR-001, SEED-001), `sensitiveFiles.ts` (FILE-001..006), `ci.ts` (CI-001..004, DOCKER-001..003), `infra.ts` (FB-001, TF-001) | every file the walker reads | none beyond the walked files |
| **B. Repository/history** | `history.ts` (HIST-001..011) | git plumbing only | `git log -p --all`, `git ls-files` inside a `gitScope` containment guard (U12) |
| **C. Dependency audit (npm ecosystem)** | `deps.ts` (DEP-001..005) | `package.json` + npm lockfiles | reads lockfiles from disk; `npm view` **only behind `--online`** (DEP-005) |
| **D. Language-specific SAST (JS/TS only)** | `sast.ts`, `taint.ts`, `authzpack.ts`, `leakpack.ts`, `dospack.ts`, `upload.ts`, `packs2.ts`, `crypto.ts`, `jwtsecrets.ts`, `nextjs.ts`, `nestjs.ts`, `supabase.ts` | files matching the pack's JS/TS filters | `context.ts` may read `tsconfig.json` at the scan root (path aliases) |
| **E. Optional / opt-in** | agent-environment pack (`agentenv.ts`), org-rules DSL (`--rules-dir`), external adapters (`--tools gitleaks,osv-scanner,semgrep`), URL mode | declared inputs only | adapters: fail-closed child-process execution (T0) |

Non-JS/TS **code-level** SAST (Python/Go/Java/…) is a declared non-goal (`classes_not_covered` in `src/coverage.ts`) — configuration surfaces of those ecosystems *are* covered by category A (SEC-010 covers properties/ini/toml/tf/yaml/json/python/go/shell assignments; FB-001 covers Firebase rules; TF-001 covers Terraform ACLs). Dependency version auditing is npm-ecosystem-only (bundled advisory snapshot has no Python/Go data).

## 3. Shared contracts every detector inherits

- **Finding schema** — `src/types.ts`: `{ id, severity, title, file, line, evidence{type, masked, sha256_prefix, note?}, owasp, confidence, fix, fix_mode?, needs_confirmation?, root, root_cause, verified?, fingerprint?, suppression? }`.
- **`mkFinding`** — `src/util.ts`: composes the finding, the dedupe fingerprint, and root-cause attribution (`rootCause(ruleId, file)`). Prefer it over hand-rolled pushes (newer packs do; older packs push inline — both paths land in the same schema).
- **Masking law** — `maskSecret()` (first-4 chars + `sha256:8hex`): a raw secret value must **never** reach any report, log, or artifact. Regression-locked by the honeypot masking contract and the multilingual gate.
- **Path triage** — `src/rules/valueclass.ts`: `isNotePath` (test/fixture/doc paths) downgrades a secret finding to LOW/low-confidence review note (no score impact); `isTestPath`/`isDocPath` share the skip-lists. Fixture **scan roots are inside** `tests/`, so fixture-relative paths (`app/config.py`) are what reach the triage — this is why fixture scanners scan the fixture **directory** as root, not the repo root.
- **Evidence discipline** — `needs_confirmation: true` = review prompt naming the invisible layer (middleware, RLS, runtime values). CRITICAL requires independent confirmation (org rules and adapters cannot emit CRITICAL without it — enforced in `rulesdir.ts` and `adapters.ts`).
- **Deduction rule** — `info` severity or `low` confidence never deducts score; identical findings dedupe by fingerprint; repeated same-root-cause findings cap at 2× the first.

## 4. Per-pack registration

Registration is a single-file edit pair: **import + spread into the findings array in `src/engine.ts`** (lines ~5–25 imports, ~92–114 call sites), then **one `CHECKS` entry in `src/coverage.ts`** (so `checks_applicable` reflects the pack). That is the entire framework: no interfaces to implement, no manifest to register, no build step beyond `tsc`.

Reference table (function names are the stable anchors — line numbers drift):

| Pack | Entry function | Rule IDs | File filter | Side access |
|---|---|---|---|---|
| secrets | `scanSecrets` | SEC-001..009 (provider shapes), SEC-010 (config-format credential assignment), SUPA-001, ENV-001, HDR-001, SEED-001 | all files (md/env-example exclusions per branch; `.env*` handled by the dedicated env layer) | none |
| history | `scanHistory` | HIST-001..011 (`HIST-009` retired — see §9) | git plumbing | `git log -p --all`, `git ls-files` |
| sensitive files | `scanSensitiveFiles` | FILE-001..006 | path + content shapes | none |
| CI/Docker | `scanCi` | CI-001..004, DOCKER-001..003 | `.github/workflows/*`, `Dockerfile*` | none |
| infra/config | `scanInfra` | FB-001 (Firebase rules), TF-001 (Terraform ACL) | `*.rules`, `*.tf` | none |
| deps | `scanDeps` | DEP-001..005 | `package.json` + npm lockfiles | lockfile reads; `npm view` behind `--online` |
| SAST | `scanSast` | SAST-001..004 | JS/TS | none |
| taint | `scanTaint` | TAINT-001..006 | JS/TS | none |
| authz/tenant | `scanAuthz`, `scanTenant` | AUTHZ-001/002, TEN-001/002 | JS/TS | none |
| leak | `scanLeak` | LEAK-001..003 | JS/TS | none |
| dos | `scanDos` | RES-001..003 | JS/TS | none |
| upload | `scanUpload` | UPLOAD-001..003 | JS/TS | none |
| packs2 | `scanPacks2` | AUTH-001, PRISMA-001, MASS-001, WS-001, WEBHOOK-001, SWAGGER-001 | JS/TS | none |
| crypto | `scanCrypto` | CRYPTO-001 | JS/TS | none |
| jwt | `scanJwtSecrets` | JWT-001..003 | JS/TS | none |
| supabase playbook | `scanSupabase` | SUPA-R01..R08, SUPA-002/003 | migrations `.sql` + Supabase config (framework-gated) | none |
| nextjs playbook | `scanNextjs` | NEXT-001..005 | `.ts`/`.tsx` (+ client/server boundary) | none |
| nestjs playbook | `scanNestjs` | NEST-001..004 | `.ts` | none |
| agent env | `scanAgentEnv` | AGENT-001..004 | agent config files (`.mcp.json`, hooks) | none |
| org rules | `runOrgRules` | `ORG-*` | `--rules-dir` JSON DSL globs | reads the rules dir |
| adapters | `runAdapters` | GLK-001 / OSV-001 / SGP-001 result classes | `--tools` opt-in | fail-closed child-process execution |
| URL mode | `scan-url` command | URL-001..9xx (32 URL checks) | live target, consent-gated | network, ownership-gated |

Counts at verification time: the coverage registry defines **37 check entries** (ranges expanded: ≈96 concrete rule IDs — one range member, HIST-009, is retired), **32 URL-mode checks**, and **3 external-adapter result classes**. `src/coverage.ts` is the single source of truth; do not quote rule counts from this page when they disagree with the registry.

## 5. Fixtures and regression layers (where a detector must prove itself)

| Layer | File | Proves |
|---|---|---|
| Unit gates | `tests/verify-units.mjs` (U-groups; 386 gates) | rule behavior + safe counterexamples through the **real pack functions** imported from `dist/` |
| Tokenizer fuzz | `tests/verify-tokenizer-fuzz.mjs` | bounded seeded fixtures over the handler-body locator |
| Reachability | `tests/verify-reachability.mjs` | import-graph honesty |
| Honeypot | `tests/honeypot/` (setup.mjs generates the tree + git history; verify reads findings.json) | recall of planted vulnerabilities end-to-end through the real CLI, masking contract |
| Clean corpus | `tests/clean/` | false-positive control (score must stay 100/A) |
| Capability acceptance | `tests/capab/` (manifest + verify) | each capability fires on its fixture and stays silent on its clean counterpart |
| Multilingual corpus | `tests/multilingual/` (W3: committed `manifest.json`, generator `setup.mjs`, gate `tests/verify-multilingual.mjs`) | cross-language/config detection **and** locked-silent out-of-scope boundaries |
| Labelled corpus | `benchmarks/corpus/cases.json` (29 adjudicated cases) | precision/recall arithmetic reproducible from the manifest |
| Benchmarks | `scripts/measure-benchmarks.mjs` → `BENCHMARKS.md` | every documented number reproduces from a committed measurement-input commit |

Fixture conventions: values that look like real credentials are **generated at setup time** (fixed literals), never committed; fixture trees are deterministic; expected findings are recorded from **actual CLI runs**, then frozen in a manifest; gates assert exact rule + file + absolute line + severity floor.

## 6. Existing extension points (no core changes needed)

1. **`--rules-dir <dir>` (org rules, `src/rulesdir.ts`)** — JSON DSL: `{ id, severity?, title?, owasp?, files: [globs], regex, flags?, fix?, clean_cases? }`. Findings are tagged `source="org-rule"`, masked like core findings, and a CRITICAL org rule is auto-marked `needs_confirmation` (no-CRITICAL-without-confirmation law). `clean_cases` is required documentation (warned when missing). This is the supported seam for org-specific patterns — it needs **zero** core code.
2. **`--tools gitleaks,osv-scanner,semgrep` (`src/adapters.ts`)** — opt-in adapters, off by default (default scans stay byte-deterministic), marked in `meta.adapters_used`, confidence=medium, never CRITICAL, **fail-closed**: an explicitly requested tool that is missing/crashed/unreadable is surfaced (missing/failed/unsupported lists) and the run refuses to pretend the evidence exists. The adapter set is deliberately hardcoded (three curated integrations, not a marketplace) — adding a fourth is a code change under the same T0 test-double seam (`AdapterProbe`).

## 7. Adding a detector — the repeatable procedure

The minimal architecture **is** the procedure: a detector is a pack module following the shared contracts, registered in two places, proven in five layers. Worked example: `src/rules/infra.ts` (FB-001/TF-001) — written exactly this way in the multilingual round, end to end.

1. **Justify by evidence, not by rule name.** Reproduce the missed pattern through the real CLI on a fixture that mirrors the report. Record the before/after (the multilingual round: 14 findings before → 20 after, all at exact lines). If the pattern is a *value-shape* artifact (fires only under specific values), record that honestly instead of claiming detection.
2. **Pick the category (§2)** and the narrowest file filter that expresses it. Config-format rules stay line-regex over declared file shapes (no parsers, no new dependencies — the engine's determinism law).
3. **Write the pack** as `src/rules/<name>.ts`: export `scan<Name>(ctx): RuleResult`, filter files by path/extension, iterate lines, emit via `mkFinding` (or `notePush` inside the secrets pack for note-path triage). Fill every schema field; set `needs_confirmation` where an invisible layer can defeat the finding; choose severity/confidence per the evidence tier (documented calibration, e.g. TF-001 HIGH + `needs_confirmation` because public-read buckets can be intentional).
4. **Define the safe counterexample set** — every trigger shape needs its clean sibling: env reads (`os.environ`/`getenv`/`process.env`), `${…}` interpolation, `var.*` references, placeholder values, public-by-design values (`pk_live_`, `ssh-rsa …`), and the non-target file formats. These go into unit gates **and** fixture safe files.
5. **Avoid double-reporting.** If a line is already another rule's root cause, skip it (SEC-010 uses per-line fired-flags so a quoted Terraform password stays ONE SEC-009 finding — locked by U29.3).
6. **Register**: import + spread in `src/engine.ts`; add the `CHECKS` entry in `src/coverage.ts` (and update `CLASSES_COVERED` / `CLASSES_NOT_COVERED` when a boundary moves).
7. **Unit gates**: append a U-group to `tests/verify-units.mjs` — positives at exact lines through the real pack import, plus every safe counterexample, plus the scope claims (what stays silent on purpose). Update the header index.
8. **End-to-end fixture**: add the pattern + safe counterparts to an acceptance fixture (`tests/capab/` or `tests/multilingual/`) with manifest entries recorded from an actual run; wire the gate into `npm test` (package.json scripts chain, after `capab:verify` for multilingual).
9. **Corpus/benchmark row when the boundary is claim-worthy**: extend `scripts/measure-benchmarks.mjs` (section 2c pattern) and re-derive `BENCHMARKS.md` through the provenance flow (measurement-input commit first, report commit on top).
10. **Document the limits in the pack header** (multi-line statements not parsed, JSON-format rules files not matched, …), update `CHANGELOG.md` (Unreleased), and re-run the **full** `npm test` + `npm pack --dry-run`. A detector that cannot state its own limits is not done.

**Design laws that bound every step:** offline-first and deterministic by default (adapters/`--online` are opt-in and disclosed in meta); no execution of scanned code, ever; read-only on the scanned tree; masking before output; bounded linear engine (no AST parser dependency — rules are regex/line/tokenizer heuristics over a shared bounded flow chase); every detection ships with safe negatives; `classes_not_covered` is mandatory in every report.

## 8. Rejected alternatives (recorded trade-offs)

- **A plugin/loader framework (npm-installed rule packs):** would break the determinism + supply-chain story (third-party code inside a security gate), require a stability contract for `Finding`/`ScanContext`, and add a runtime dependency surface. The JSON DSL covers the actual org-rules need; packs are code — contributed via PR under the review rules.
- **An AST parser dependency (ts-morph/estree):** contradicts the bounded-engine law and would change every perf/determinism guarantee. The tokenizer is seeded-fuzz-locked instead.
- **A second generic "config credential" heuristic over JS/TS:** widening SEC-009's key alternation to arbitrary tokenized names in JS/TS risks real-world false HIGHs (score-bearing); SEC-010 is scoped to non-JS/TS config surfaces instead. The JS camelCase single-name boundary (`const dbPassword = "…"`) is documented as a known limit, not silently claimed as detection.

## 9. Known registry imprecisions (tracked, not hidden)

- `HIST-009` appears inside the `HIST-001..011` registry range but is retired (no emitter) — `checks_applicable` counts registry entries, so this is a documented over-count of one.
- `SUPA-002/003`, `AUTHZ-001/002`, `TEN-001/002` are single registry entries covering two rule IDs each.
- The `131 rule IDs` figure that circulated in earlier notes has no source in this tree; the registry-expanded counts above are the authoritative ones.
