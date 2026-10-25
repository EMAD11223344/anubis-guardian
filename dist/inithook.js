import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
/**
 * Agent guard hook (Plan Section 11 v0.3, v1.2 design — PreToolUse interception):
 * وقاية لحظة التنفيذ — blocks the *writing* of the classic vibe-coding security
 * mistakes before they land in the codebase, not just their detection afterwards.
 *
 * Version-pinning contract (v1.3): `init-hook` copies this script INTO the
 * project (pinned by version control) and records the exact version in
 * .claude/settings.json — never npx, never @latest, never remote code.
 */
export const HOOK_VERSION = "0.3.0";
export const HOOK_SCRIPT = `#!/usr/bin/env node
/**
 * Anubis Guardian — Agent guard hook v${HOOK_VERSION}
 * Claude Code PreToolUse hook. Reads the tool-call event from stdin and BLOCKS
 * (exit 2) writes that match the classic AI-built-project security mistakes:
 *   R1  service_role key referenced into client-reachable code
 *   R2  SQL that disables/removes Row-Level Security
 *   R3  real-looking secrets written into .env files
 *   R4  NEXT_PUBLIC_* env names carrying secret-shaped values
 * Everything else passes (exit 0). Pinned copy — regenerate only via
 * \`anubis-guardian init-hook\` (never edit version-blind).
 */
let raw = "";
process.stdin.on("data", (d) => (raw += d));
process.stdin.on("end", () => {
  let evt;
  try { evt = JSON.parse(raw || "{}"); } catch { process.exit(0); }
  const tool = evt.tool_name || "";
  if (!/Write|Edit|MultiEdit|NotebookEdit/.test(tool)) process.exit(0);
  const input = evt.tool_input || {};
  const filePath = String(input.file_path || input.path || input.notebook_path || "");
  const content = [input.content, input.new_string, input.new_str, input.edits]
    .map((x) => (typeof x === "string" ? x : JSON.stringify(x ?? "")))
    .join("\\n");
  const blocks = [];
  if (
    /service[_-]?role/i.test(content) &&
    /\\.(ts|tsx|js|jsx)$/.test(filePath) &&
    /(app\\/|components\\/|client\\/|pages\\/|src\\/)/.test(filePath) &&
    !/(app\\/api\\/|server|middleware|supabase-admin|\\.server\\.)/.test(filePath)
  ) {
    blocks.push("service_role key referenced in client-reachable code (" + filePath + ") — use the server-side client");
  }
  if (/DISABLE\\s+ROW\\s+LEVEL\\s+SECURITY|DROP\\s+POLICY|FORCE\\s+ROW\\s+LEVEL\\s+SECURITY\\s+DISABLE/i.test(content)) {
    blocks.push("SQL disables/removes Row-Level Security — if intentional, say so explicitly and review who gains access");
  }
  if (
    /(^|\\/)\\.env/.test(filePath) &&
    !/\\.example|\\.template|\\.sample/.test(filePath) &&
    /[A-Za-z0-9_]*(SECRET|TOKEN|API_?KEY|PASSWORD|CREDENTIAL)[A-Za-z0-9_]*\\s*=\\s*["']?[A-Za-z0-9+/_-]{20,}/.test(content)
  ) {
    blocks.push("real-looking secret written into " + filePath + " — prefer env injection; if committed, rotate immediately");
  }
  if (/NEXT_PUBLIC_[A-Z0-9_]*(SECRET|TOKEN|API_?KEY|PASSWORD|SERVICE|PRIVATE)[A-Z0-9_]*/.test(content)) {
    blocks.push("NEXT_PUBLIC_* secret name — everything public ships to the browser bundle; move it server-side");
  }
  if (blocks.length) {
    console.error(
      "\\u26D0 Anubis Guardian guard hook v${HOOK_VERSION} blocked this change:\\n- " +
        blocks.join("\\n- ") +
        "\\n(rotate-first: if a secret was exposed, rotate the credential before retrying)"
    );
    process.exit(2);
  }
  process.exit(0);
});
`;
export const SNIPPET = `<!-- Anubis Guardian guard hook (pinned v${HOOK_VERSION}) -->
Run the audit before shipping: \`npx anubis-guardian scan . --fail-on high\`.
Treat every secret finding as compromised: rotate first, then remove (see fix-prompt.md).
Never apply suggested fixes without human approval — suggested diffs only.`;
/** idempotent: same version → left untouched; settings merge preserves existing keys */
export function installHook(projectDir, force = false) {
    const root = resolve(projectDir);
    const hookDir = join(root, ".claude", "hooks");
    mkdirSync(hookDir, { recursive: true });
    const scriptPath = join(hookDir, "anubis-guard-hook.mjs");
    let created = true;
    if (existsSync(scriptPath) && !force) {
        const existing = readFileSync(scriptPath, "utf8");
        created = false;
        if (!existing.includes(`v${HOOK_VERSION}`)) {
            writeFileSync(scriptPath, HOOK_SCRIPT); // stale version → refresh (still pinned, explicit)
            created = true;
        }
    }
    else {
        writeFileSync(scriptPath, HOOK_SCRIPT);
    }
    // merge hooks entry into .claude/settings.json (never overwrite other config)
    const settingsPath = join(root, ".claude", "settings.json");
    let settings = {};
    if (existsSync(settingsPath)) {
        try {
            settings = JSON.parse(readFileSync(settingsPath, "utf8"));
        }
        catch {
            settings = {};
        }
    }
    const hooks = settings.hooks ?? {};
    const pre = Array.isArray(hooks.PreToolUse) ? hooks.PreToolUse : [];
    const entry = {
        matcher: "Write|Edit|MultiEdit|NotebookEdit",
        hooks: [{ type: "command", command: "node .claude/hooks/anubis-guard-hook.mjs", version: HOOK_VERSION }],
    };
    const already = pre.some((e) => JSON.stringify(e).includes("anubis-guard-hook.mjs"));
    if (!already)
        pre.push(entry);
    settings.hooks = { ...hooks, PreToolUse: pre };
    mkdirSync(join(root, ".claude"), { recursive: true });
    writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n");
    return { scriptPath, settingsPath, created };
}
