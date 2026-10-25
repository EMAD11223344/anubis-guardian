import type { ScanContext, RuleResult, ScannedFile } from "../types.js";
import { maskSecret, rootCause } from "../util.js";

/**
 * Agent-environment checks (Plan Section 11 v0.3, ECC-inspired):
 * the AI dev environment is part of the attack surface of AI-built projects.
 * Deterministic file checks over agent config:
 *   AGENT-001  MCP server launched from an UNPINNED package (npx/uvx without a version / @latest)
 *   AGENT-002  literal secrets inside agent/MCP config files (they get committed & shared)
 *   AGENT-003  dangerously broad agent permissions (Bash(*) wildcards, bypassPermissions)
 *   AGENT-004  hooks executing unpinned remote code (npx … / curl | sh / @latest)
 * Clean-cases: explicit version pins, ${ENV_VAR} placeholders, scoped allow-lists, local hook scripts.
 */

const AGENT_CONFIG = /(^|\/)\.mcp\.json$|(^|\/)mcp\.json$|(^|\/)\.claude\/[^/]*\.json$|(^|\/)\.cursor\/mcp\.json$|(^|\/)\.windsurf\/mcp\.json$|(^|\/)\.codeium\/[^/]*\.json$/i;
const PLACEHOLDER = /\$\{[^}]*\}|^\s*env:[A-Z_]|changeme|<[^>]*>|your[-_]|example/i;

export function scanAgentEnv(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];

  for (const f of ctx.files) {
    if (!AGENT_CONFIG.test(f.rel)) continue;

    // ---------- AGENT-001: unpinned MCP server packages ----------
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      const npx = line.match(/["'`]?(?:npx|bunx)\s+(?:-y\s+)?([@a-zA-Z0-9][^\s"']*)/);
      const uvx = line.match(/["'`]?(?:uvx|uv\s+tool\s+run)\s+([a-zA-Z0-9][^\s"']*)/);
      const spec = npx?.[1] ?? uvx?.[1];
      if (!spec) continue;
      const pinned = /@[A-Za-z0-9][A-Za-z0-9.\-]*$/.test(spec) && !/@latest$/i.test(spec) && !spec.endsWith("@");
      // scoped names (@scope/pkg) are unpinned unless "@scope/pkg@1.2.3"
      const scopedUnpinned = spec.startsWith("@") && (spec.match(/@/g) ?? []).length < 2;
      const uvPinned = uvx && /==/.test(line);
      if (pinned && !scopedUnpinned) continue; // clean case: explicit version pin
      if (uvx && (uvPinned || /@/.test(spec) && !/@latest/i.test(spec))) continue;
      findings.push({
        id: "AGENT-001",
        severity: "medium",
        confidence: "high",
        title: `MCP/agent tool server launched unpinned: "${spec}"${/latest/i.test(spec) ? " (@latest)" : ""} — supply-chain risk in the dev environment`,
        file: f.rel, line: i + 1,
        evidence: { type: "mcp_unpinned_package", masked: `${spec}`, note: "a renamed or hijacked package replaces the tool your agent runs with — pin the exact version" },
        owasp: "A08",
        fix: `Pin the exact version (e.g. "${spec}@1.4.2") or install it as a dev dependency and reference the local binary. Never @latest in agent config.`,
        fix_mode: "suggested-diff",
        root: f.rel,
        root_cause: rootCause("AGENT-001", `${f.rel}:${spec}`),
        verified: true,
      });
    }

    // ---------- AGENT-002: literal secrets in agent config ----------
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      const kv = line.match(/["'`]([A-Za-z_][A-Za-z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)[A-Za-z0-9_]*)["'`]\s*:\s*["'`]([^"'`\s][^"'`]{7,})["'`]/i)
        ?? line.match(/^\s*([A-Z_]*(?:TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)[A-Z_0-9]*)\s*=\s*["']?([^"'\s][^']{7,})["']?\s*$/i);
      if (!kv) continue;
      const [, key, value] = kv;
      if (PLACEHOLDER.test(value)) continue; // clean case: ${ENV_VAR} / docs placeholders
      if (/(localhost|127\.0\.0\.1|example\.com|YOUR_)/i.test(value)) continue;
      const masked = maskSecret(value.trim());
      findings.push({
        id: "AGENT-002",
        severity: "high",
        confidence: "high",
        title: `Literal secret "${key}" committed inside an agent/MCP config file — these files get pushed and shared`,
        file: f.rel, line: i + 1,
        evidence: { type: "agent_config_secret", masked: `${key}=${masked.masked}`, sha256_prefix: masked.sha256_prefix, note: "agent configs belong in the repo; the secret belongs in the environment it references" },
        owasp: "A02",
        fix: `Move "${key}" out of the config (reference an env var the agent host injects), then rotate the exposed value.`,
        fix_mode: "suggested-diff",
        remediation: { type: "rotate-first", provider: "generic", steps: `1) Rotate "${key}" — it is in a file designed to be committed 2) Replace the literal with an env reference 3) Scrub git history if already pushed` },
        root: masked.sha256_prefix,
        root_cause: rootCause("AGENT-002", masked.sha256_prefix),
        verified: true,
      });
    }

    // ---------- AGENT-003: dangerously broad permissions ----------
    if (/"allow"\s*:|"defaultMode"\s*:|dangerously-skip-permissions|bypassPermissions/.test(f.content)) {
      const allowBlock = f.content.match(/"allow"\s*:\s*\[([\s\S]*?)\]/)?.[1] ?? "";
      const bareWildcard = /^\s*["'`]\*["'`],?\s*$/m.test(allowBlock); // a bare "*" entry allow-all
      const emitted = new Set<string>();
      for (let i = 0; i < f.lines.length; i++) {
        const line = f.lines[i];
        const toolWildcard = /["'`](Bash|Edit|Write|WebFetch|WebSearch)\s*\(\s*\*\s*\)/.test(line);
        const bypass = /dangerously-skip-permissions|bypassPermissions|"defaultMode"\s*:\s*["'`]bypass/i.test(line);
        const bareHit = bareWildcard && /"allow"\s*:/.test(line) && !emitted.has("bare");
        if (!toolWildcard && !bypass && !bareHit) continue;
        const key = bypass ? "bypass" : toolWildcard ? `tw:${line}` : "bare";
        if (emitted.has(key)) continue;
        emitted.add(key);
        findings.push({
          id: "AGENT-003",
          severity: "high",
          confidence: "high",
          title: bypass
            ? "Agent permission bypass enabled — every tool call runs without confirmation"
            : "Agent allow-list grants a wildcard (e.g. Bash(*) or \"*\") — any command runs without approval",
          file: f.rel, line: i + 1,
          evidence: { type: "agent_permissions_wildcard", masked: line.trim().slice(0, 70) || '"allow": [ "*" ]', note: "one prompt injection away from arbitrary execution — scope allows to exact commands" },
          owasp: "A05",
          fix: 'Scope the allow-list to exact commands (e.g. "Bash(npm run test)", "Bash(npm run lint)") and remove bypass modes; keep everything else behind human confirmation.',
          fix_mode: "suggested-diff",
          root: f.rel,
          root_cause: rootCause("AGENT-003", f.rel),
          verified: true,
        });
      }
    }

    // ---------- AGENT-004: hooks running unpinned remote code ----------
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      if (!/"command"\s*:|hooks/.test(line)) continue;
      const npxm = /npx\s+(?:-y\s+)?([^\s"']+)/.exec(line);
      const curlm = /curl[^|]*\|\s*(?:ba|z|)sh/.exec(line)?.[0];
      const latestHit = /@latest/.test(line) ? line.trim().slice(0, 50) : undefined;
      const remote = curlm ?? (npxm ? `npx ${npxm[1]}` : latestHit);
      if (!remote) continue;
      const spec = npxm?.[1];
      const pinnedSpec = Boolean(spec && /@[A-Za-z0-9][A-Za-z0-9.\-]*$/.test(spec) && !/@latest/i.test(spec));
      if (pinnedSpec) continue; // clean case: version-pinned npx
      if (/\bnode\s+\.?\/|\bnpm\s+run\b|\.mjs|\.cjs|\.sh$/.test(line) && !npxm) continue; // clean case: local script
      findings.push({
        id: "AGENT-004",
        severity: "medium",
        confidence: "high",
        title: "Agent hook executes remote/unpinned code — hooks run automatically on every tool call",
        file: f.rel, line: i + 1,
        evidence: { type: "hook_unpinned_remote", masked: remote.slice(0, 60), note: "hooks are the agent's pre-execution gate — pointing them at unpinned packages hands the gate to npm" },
        owasp: "A08",
        fix: "Commit the hook script into the repo (pinned by version control) and invoke it locally (node .claude/hooks/<script>.mjs) — never npx/@latest inside hook config.",
        fix_mode: "suggested-diff",
        root: f.rel,
        root_cause: rootCause("AGENT-004", f.rel),
        verified: true,
      });
    }
  }

  return { findings };
}
