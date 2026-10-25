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
| `JWT-002` **jwt_alg_unpinned** | any `jwt.verify(token, secret)` call **without** an `algorithms:` option | Unpinned verify accepts every registered algorithm — the JWT HS/RS confusion class. The FIX is one option object. Only `algorithms: [...]`-pinned calls stay silent; `algorithms:"none"` / `ignoreExpiration:true` are HIGH (seeded in the honeypot). Suppress with an inline `anubis-ignore` where the unpinned choice is deliberate, e.g. `expires="…" reason="internal verify with explicit alg check upstream"`. |
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
(tool version, Node version, date). Claims that cannot be measured yet are
listed as pending, not estimated. Honeypot recall is a *self-test* (we planted
the vulnerabilities we catch); external-corpus numbers (Juice Shop / NodeGoat
sanity, labeled AI-corpus) are the honest recall signal and are labeled as such.

## 8. Known limitations (stated up front)

- Static analysis sees patterns, not runtime truth — the authz matrix and taint
  canaries generate tests for **you** to run on staging; they do not confirm exploits.
- Codebase Mode covers the frameworks with observed signal (Next.js, Supabase,
  NestJS + generic Node). Other stacks get the generic layers only — the coverage
  registry in every report states what ran.
- URL Mode is a black box: no server internals, no subdomain takeover, no DNS
  level attacks, no business-logic flaws beyond the restricted differential check.
- Git-history scanning requires a git repository (`git ls-files`); without one,
  history layers are skipped and reported as such.
- The advisory snapshot is a point-in-time capture per release; run
  `update-advisories` (or `--online`) for current registry state.
