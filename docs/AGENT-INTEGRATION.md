# Agent Integration Guide

How to run **Anubis Guardian** as a security gate inside AI coding agents (Claude Code, Cursor, Codex CLI, Windsurf, opencode) and CI. The companion file [`skill/SKILL.md`](../skill/SKILL.md) carries the full agent-contract; this page is the practical wiring.

---

## 1. Install (until the npm publish)

```bash
git clone https://github.com/EMAD11223344/anubis-guardian.git
cd anubis-guardian && npm install && npm run build
# every command below: anubis-guardian <cmd>  ==  node /path/to/anubis-guardian/dist/cli.js <cmd>
```

## 2. The 30-second audit loop every agent should run

```bash
node dist/cli.js scan ./project --format json -o findings.json \
  --fix-prompt fix-prompt.md --compact compact.txt --fail-on critical
```

- `exit 0` — pass (still present the Classes-not-covered disclaimer)
- `exit 1` — `--fail-on` breach: report findings, never suppress
- `exit 2` — refusal (usage, tampered rule pack, missing ownership): read stderr

Read `findings.json` (not the terminal). Each finding: `id · severity · file:line · masked evidence · confidence · needs_confirmation · fix`. `fix-prompt.md` is a deterministic prompt for exactly this report — use it as the base of your fix proposal.

## 3. Agent configs

### Claude Code — skill

```bash
# per user:
mkdir -p ~/.claude/skills/anubis-guardian && cp skill/SKILL.md ~/.claude/skills/anubis-guardian/
# per repo:
cp -r skill /path/to/project/.claude/skills/anubis-guardian  # or reference it from CLAUDE.md
```

### Claude Code — auto-guard hook (prevention)

```bash
node dist/cli.js init-hook --dir ./project     # writes .claude/hooks/ + settings.json wiring
```

The hook blocks, at write time: service_role keys into client-reachable code, RLS-killing SQL, real-looking secrets into `.env`. It is pinned, local, and never runs `npx`/`@latest` (supply-chain safe).

### Cursor / Windsurf / opencode / AGENTS.md

No native skill format is needed — point the agent at the file:

```markdown
## Security auditing
Before shipping: run `node /path/to/anubis-guardian/dist/cli.js scan . --compact .anubis-summary.txt`
and read the full JSON. Follow ./skill/SKILL.md as the operating contract
(suggested-diff-only · rotate-first · needs_confirmation honesty · masking).
```

Copy `skill/SKILL.md` into the repo so the contract travels with it.

## 4. Token-efficient mode

Agents read the compact digest first, full JSON when acting:

```bash
node dist/cli.js scan ./project --compact .anubis-summary.txt --format json -o findings.json
```

## 5. Rendering for humans (pick any)

```bash
--format md          # markdown report
--html report.html   # self-contained HTML
--sarif results.sarif  # GitHub Security tab (upload-sarif)
```

## 6. URL Mode from an agent

Keep the agent to **L1** (passive, ownership-free). Anything deeper is a human consent flow:

```bash
node dist/cli.js scan-url https://example.com --format json -o url-findings.json
```

The agent must not raise the level, must not invent identities/ownership, and must surface the scan authorization record with the findings — full contract in [`skill/SKILL.md`](../skill/SKILL.md) → *URL Mode hard rules*.

## 7. CI — do not let the agent run the gate on modified rules

- `rules-lock <dir>` pins org/community rule packs (SHA-256); scans refuse tampered packs with exit 2 BEFORE scanning.
- `init-ci` generates a SHA-pinned GitHub Actions workflow (scan + SARIF + `--fail-on critical`).
- `update-advisories` refreshes the local OSV snapshot; `scan --advisories anubis-advisories.json` consumes it (determinism is preserved because the snapshot, not a live API, is pinned in the run).

## 8. Honesty contract (what the agent must repeat)

1. **Suggested diffs only** — no edit to RLS/auth/production files without explicit human approval.
2. **Rotate-first for secrets** — rotation steps come before any code edit.
3. **`needs_confirmation: true`** — present as "likely — here is how to confirm", never as confirmed CRITICAL; CRITICAL exists only from the tool's own independent confirmation (schema export, live probe, cross-root linkage).
4. **Full secret values never surface** — evidence is first-4 chars + sha256 prefix, everywhere.
5. **Quarantine tests are the owner's** — the agent names the folder; the human runs the generated suites.

Unconfirmed-but-likely classes and how to confirm them: see [`skill/SKILL.md`](../skill/SKILL.md) → *needs_confirmation — verify, never downgrade silently*.
