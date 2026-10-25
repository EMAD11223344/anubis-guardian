# Contributing Rules & Playbooks

Thank you for helping Anubis Guardian catch more of what AI-generated code gets
wrong. Rule contributions are the highest-leverage way to help — and the easiest
way to get a PR rejected is to skip the false-positive contract. Read this once;
it saves everyone a review round.

## The non-negotiables

1. **Every rule ships with clean cases.** A rule that fires on code that is
   actually fine is a bug, not a feature. Your PR must include inputs the rule
   must NOT flag and the reason they are fine.
2. **Every rule ships with a honeypot seed.** A deterministic test that proves
   the rule catches what it claims to catch (wired into `tests/honeypot/`).
3. **Org/community rules live inside Layer 5.** No new execution layers, no
   processes, no network calls from rules — pattern checks over scanned files only.
4. **A community CRITICAL is forced to `needs_confirmation`.** The
   no-CRITICAL-without-confirmation law applies to your rule too.
5. **Masking is done for you.** Rules never write raw secret values into
   findings — use the provided finding constructors (`mkFinding`, `maskSecret`).

## The rule DSL (JSON, `--rules-dir`)

```json
{
  "id": "ORG-001",
  "severity": "high",
  "title": "Hardcoded third-party API key",
  "owasp": "A02",
  "files": ["**/*.ts", "**/*.js"],
  "regex": "sk_live_[0-9a-zA-Z]{20,}",
  "flags": "g",
  "fix": "Move the key to an environment variable and rotate the exposed one (rotate-first).",
  "clean_cases": "test fixtures using sk_live_ placeholders in a mocked client; keys read from process.env"
}
```

- `id` is auto-prefixed with `ORG-` if missing. Community rules use the same
  mechanism today; the signed community registry rides on `rules-lock.json`
  (see `METHODOLOGY.md` §5) when it comes online.
- `files` uses the engine's glob subset (`**/` prefix = any depth, `*` within a segment).
- `clean_cases` is required documentation — the loader warns without it, and PRs
  without it will not be merged.

## Built-in playbooks (TypeScript)

Framework playbooks (Next.js / Supabase / NestJS) live in `src/rules/` as typed
modules with access to the scan context, taint-lite and the inventory. A new
playbook check needs:

1. The check function returning `RawFinding[]` via `mkFinding` (deterministic defaults).
2. A `root_cause` (rule id + root) so score caps work.
3. A row in the coverage registry (`src/coverage.ts` / `src/urlmode/coverage.ts`)
   — including what the check does **not** cover (honesty contract).
4. Honeypot seed(s) + clean-case fixture(s) + updated verifiers
   (`tests/verify-honeypot.mjs`, `tests/verify-clean.mjs`).

## Validation checklist (run before opening the PR)

```bash
npm test          # build + honeypot + clean corpus + SARIF + all acceptance gates
```

- Honeypot: your seed is caught (`verify-honeypot` PASS).
- Clean corpus: still 0 findings above threshold / score 100/A (`verify-clean` PASS).
- All acceptance gates green — no regression in existing behavior.
- `npm run dogfood`-style sanity: scan this repo itself, no crash, no new FPs.

## URL-mode checks

URL checks (L1/L2/L3) follow the same contract with two extra requirements:

- **L1 stays browser-equivalent.** If your check requests anything a normal
  browser visit would not, it belongs in L2 (ownership-gated) — the acceptance
  suite proves this per-run from the request log.
- **Probing validates content, not just status codes.** A 200 on `/.env` from an
  SPA catch-all is not an exposed env file. Every probe has a content validator;
  include a decoy case for yours.

## Legal & licensing

- MIT (see `LICENSE`). By contributing you agree your contribution is MIT-licensed.
- URL checks must respect the consent/safety layer (rate limits, robots awareness,
  verified-ownership gates). A check that bypasses them will be rejected.

## Where to start

- `docs/PLAN.master.md` — design + decision log (why things are the way they are).
- `METHODOLOGY.md` — scoring, determinism and FP-control contracts.
- `src/rules/packs2.ts` and `src/rules/taint.ts` — realistic examples of
  well-formed built-in checks with negative-signal detection.
- `tests/honeypot/` — how seeds and clean cases are structured.
