# TRUST-AUDIT.md — release-pipeline trust review (ranked, evidence-based)

> Scope of this audit: what is verifiable **from inside the repository** —
> workflow files, scripts, package configuration, and test gates. Repository
> SETTINGS (branch protection rules, environment protection, required reviews,
> secret hygiene on the npm side) cannot be inspected from a clone; where those
> matter, the task is phrased as **"verify in repo settings"** and this document
> deliberately does NOT claim they exist. Audit date: 2026-10-28.

## What is verifiably in place (evidence)

| Control | Evidence |
|---|---|
| All third-party workflow actions pinned to full commit SHAs | `.github/workflows/release.yml:47,77,78,110` — `actions/checkout@11d5960…`, `actions/setup-node@49933ea…`, `actions/upload-artifact@ea165f8…` (40-hex, with version comments) |
| A regression gate LOCKS that pinning | `tests/mode2/acceptance-v10.mjs:254-256` — release workflow must contain `--provenance`, `id-token: write`, and 40-hex-pinned `checkout` + `setup-node`, or the acceptance suite fails |
| Least-privilege workflow permissions | `release.yml:31-33` — only `contents: write` + `id-token: write` (provenance), nothing else |
| Tests run before publish | `release.yml:82-83` — `npm ci && npm test` gates the publish job |
| Duplicate-publication guard | `release.yml:91-103` — registry re-check immediately before `npm publish`; version appeared on npm meanwhile → publish skipped, never overwritten |
| npm provenance attestation | `release.yml:104-106` — `npm publish --provenance` (sigstore attestation via OIDC) |
| SBOM + checksums on the release | `release.yml:84-90,109-121` — CycloneDX JSON + `sha256sum` manifest attached to the GitHub Release |
| Release concurrency serialized | `release.yml:35-37` — `concurrency: release`, no cancel |
| Publish never races main pushes | gate job (`release.yml:40-70`): main push releases only when the version is missing from npm; tag push releases unconditionally |
| npm package surface is minimal | `package.json` `files` = `dist`, `skill`, `README.md`, `CHANGELOG.md`, `LICENSE` — benchmarks, tests, scripts and calibration fixtures never ship |
| Generated CI pins the same discipline for users | v0.2 acceptance gates assert `init-ci` output pins actions by SHA |

## Ranked actionable tasks

### T1 (high) — Verify + enforce branch protection on `main` *(repo settings — verify, do not assume)*
The main-push path auto-publishes whenever `package.json` carries an
unpublished version. That control is only as strong as whoever can push to
`main`. Verify in repo settings: (a) branch protection with required reviews or
admin-only pushes, (b) whether the token used by any automation can bypass it.
If protection cannot be enabled, prefer disabling the main-push auto-release
path and releasing exclusively from maintainer-signed tags.

### T2 (high) — Unsigned auto-created tags
On the main-push path the pipeline creates a **lightweight, unsigned**
`vX.Y.Z` tag via `gh release create` (`release.yml:117-119`). The tag-push path
preserves maintainer-signed tags, but the automatic path silently produces an
unsigned tag. Options, in preference order: (1) release only from signed tags
(`git tag -s`), (2) keep the auto path but document prominently that
auto-created tags are unsigned and verification should rely on the npm
provenance attestation + SBOM checksums instead.

### T3 (medium) — GitHub Environment protection for the publish job *(repo settings)*
Wrap `publish` in a GitHub Environment (`environment: npm-publish`) with
required-reviewer protection, so a compromised workflow run cannot publish
without a human approval. This is a settings-side change plus a one-line
workflow edit; the workflow edit alone is not protection.

### T4 (medium) — Retire the long-lived `NPM_TOKEN` fallback
`release.yml:104-108` falls back to `secrets.NPM_TOKEN` when OIDC trusted
publishing is not configured. The header already documents the migration
(`release.yml:15-19`). Action: configure npm Trusted Publisher on npmjs.com,
confirm a provenance-only release succeeds, then revoke the stored token.
Verify **in npm settings** — not claimable from the repo.

### T5 (low) — `persist-credentials: false` on checkout
`actions/checkout` persists the GITHUB_TOKEN in the local git config by
default; this workflow never pushes code itself (`gh` uses the explicit
`GH_TOKEN`), so the risk is small, but adding `with: persist-credentials:
false` to both checkout steps removes an unnecessary credential from the job
workspace.

### T6 (low) — Automated pin updates
The three SHA-pinned actions are manually updated. Add a Dependabot config
(`package-ecosystem: github-actions`, `versioning-strategy: pin`) so pin bumps
arrive as reviewable PRs instead of rotting until a manual audit.

### T7 (low) — Publish job hardening (informational)
`npm pack` output is checksummed but not compared against the SBOM component
list; a post-pack `npm publish --dry-run` diff or `cyclonedx` validation step
would close the loop. Optional; current risk is low because the tarball is
built in the same step chain that ran `npm test`.

## Explicit non-claims

- This document does NOT claim branch protection, environment protection,
  CODEOWNERS enforcement, or npm-side 2FA are configured — those are
  settings-side facts and are listed above as **verify** tasks.
- It does NOT claim sigstore provenance is currently *configured* on the npm
  package side; the workflow is ready for it (`--provenance` + `id-token`),
  which is the verifiable half.
- No claim is made about secret rotation history or who holds `NPM_TOKEN`.
