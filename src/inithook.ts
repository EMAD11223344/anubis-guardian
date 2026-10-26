import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

/**
 * Agent guard hook (v1.2 guard-hook rewrite — PreToolUse interception):
 * وقاية لحظة التنفيذ — blocks the *writing* of the classic vibe-coding security
 * mistakes before they land in the codebase, not just their detection afterwards.
 *
 * v1.2 rewrite (independent-review fix): the old hook matched NAME regexes —
 * it missed a real service_role JWT value and blocked harmless edits (e.g. any
 * path containing the substring "server", like "observer.ts"). This hook is
 * VALUE-based: JWTs are decoded and decided by the `role` claim, comments are
 * stripped before pattern tests, RLS `drop policy` is only blocked without a
 * matching same-table `create policy`, and public-by-design env names pass.
 *
 * Version-pinning contract (v1.3): `init-hook` copies this script INTO the
 * project (pinned by version control) and records the exact version in
 * .claude/settings.json — never npx, never @latest, never remote code.
 * The version label comes from the real package version (package.json).
 */

const pkg = (() => {
  try {
    return JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version?: string };
  } catch {
    return {} as { version?: string };
  }
})();

/** Real package version — the hook header, settings.json and AGENTS.md snippet all use it. */
export const HOOK_VERSION = pkg.version ?? "0.0.0";

export const HOOK_SCRIPT = `#!/usr/bin/env node
/**
 * Anubis Guardian — Agent guard hook v${HOOK_VERSION}
 * Claude Code PreToolUse hook. Reads the tool-call event from stdin and BLOCKS
 * (exit 2) writes that match the classic AI-built-project security mistakes.
 * VALUE-based detectors (v1.2):
 *   R1  service_role JWT — decoded role claim === "service_role", referenced
 *       into client-reachable code ('use client' files, components/, pages/
 *       non-api, or .env entries with NEXT_PUBLIC_/VITE_/REACT_APP_/EXPO_PUBLIC_
 *       names). Server code (app/api, route handlers, "use server", middleware,
 *       server path segments) is allowed.
 *   R2  Row-Level Security -killing SQL: disable RLS, create policy with
 *       using(true)/with check (true), drop policy WITHOUT a matching
 *       same-table create policy (drop+recreate migrations pass).
 *   R3  secret-shaped values or credential names written into .env* files
 *       (public-by-design names pass — see PUBLIC_NAME).
 *   R4  client-env names (NEXT_PUBLIC_* & co) assigned secret-shaped values.
 *   Bash (best effort, heuristic): the same value detectors over
 *       heredoc/redirect/tee/sed -i writes targeting client paths.
 * Comments are stripped before pattern tests — a comment mentioning
 * service_role never blocks. Pinned copy — regenerate only via
 * \`anubis-guardian init-hook\` (never edit version-blind).
 */
let raw = "";
process.stdin.on("data", (d) => (raw += d));
process.stdin.on("end", () => {
  let evt;
  try { evt = JSON.parse(raw || "{}"); } catch { process.exit(0); } // malformed/empty stdin -> fail-open

  const mode = String(process.env.ANUBIS_GUARD || "block").toLowerCase();
  if (mode === "off") process.exit(0);
  const warnOnly = mode === "warn";

  const tool = String(evt.tool_name || "");
  if (!/^(?:Write|Edit|MultiEdit|NotebookEdit|Bash)$/.test(tool)) process.exit(0);
  const input = evt.tool_input || {};
  const isBash = tool === "Bash";
  const filePath = String(input.file_path || input.path || input.notebook_path || "");
  const content = isBash
    ? String(input.command || "")
    : [input.content, input.new_string, input.new_str, input.edits]
        .map((x) => (typeof x === "string" ? x : x ? JSON.stringify(x) : ""))
        .filter(Boolean)
        .join("\\n");
  if (!content.trim()) process.exit(0); // fail-open

  // ---- escape hatch: anubis-allow: <reason of 8+ chars> (searched BEFORE stripping) ----
  const allow = /anubis-allow:\\s*([^\\n]{8,})/i.exec(content);
  if (allow) {
    console.error("\\u26D0 Anubis Guardian: inline bypass — anubis-allow: " + allow[1].trim());
    process.exit(0);
  }

  // ---------- shared value logic (twin of src/rules/valueclass.ts + urlmode/jsassets.ts) ----------
  function jwtRole(token) {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    try {
      const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
      return payload && typeof payload.role === "string" ? payload.role : null;
    } catch { return null; }
  }
  /** unanchored JWT-ish finder (decoding + role check gates every hit) */
  const JWT_FIND = /[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}/g;
  function serviceRoleJwts(text) {
    const hits = [];
    JWT_FIND.lastIndex = 0;
    let m;
    while ((m = JWT_FIND.exec(text)) !== null) {
      if (jwtRole(m[0]) === "service_role") hits.push(m[0]);
    }
    return hits.length > 0;
  }
  const PLACEHOLDER = /(^|[\\w-])(change?me|placeholder|example|sample|your[-_]|xxx+|dummy|todo|fixme|<[^>]*>|\\$\\{[^}]{0,80}\\})/i;
  /** one VALUE verdict: "block" | "context" (service_role JWT — context decides) | "allow" */
  function valueVerdict(value) {
    const v = String(value).trim().replace(/^["']+|["']+$/g, "");
    if (!v || v.length < 12 || PLACEHOLDER.test(v) || /<[^>]*>/.test(v) || /\\$\\{[^}]{0,80}\\}/.test(v)) return "allow";
    if (/^-----BEGIN/.test(v)) return /PRIVATE KEY/.test(v) ? "block" : "allow";
    if (/^eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{8,}$/.test(v)) {
      const role = jwtRole(v);
      if (role === "anon" || role === "authenticated") return "allow";   // public by design
      if (role === "service_role") return "context";                     // context decides
      return "block";                                                    // opaque/non-role JWT = treat as live
    }
    if (/^[a-z][\\w+.\\-]*:\\/\\//i.test(v)) return "allow";              // URLs are endpoints, not secrets
    if (/^AIza[0-9A-Za-z_-]{35}$/.test(v)) return "allow";               // Firebase/Google web keys
    if (/^pk(?=[._])/i.test(v)) return "allow";                          // pk.eyJ… / pk_live / pk_test (MAPBOX public)
    if (/^(sk_test_|rk_test_|sb_publishable_)/.test(v)) return "allow";  // public key prefixes
    if (/^(sbp_|sk_live_|rk_live_|sk-[A-Za-z0-9]{20,}|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|xox[abprs]-|sb_secret_|npm_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|glpat-|shpat_|dop_v1_|tfp_)/i.test(v)) return "block";
    if (v.length >= 24 && /^[A-Za-z0-9+/=_-]{24,}$/.test(v) && /[a-z]/.test(v) && (/[A-Z]/.test(v) || /[0-9]/.test(v))) return "block";
    return "allow";
  }
  /** names that public-by-design: never credential violations */
  const PUBLIC_NAME = /(FIREBASE_API_?KEY|GOOGLE.?MAPS|POSTHOG_(KEY|TOKEN)|ALGOLIA[^_=]*(SEARCH|KEY)|STRIPE_PUBLISHABLE|SUPABASE_ANON|SUPABASE_PUBLISHABLE|CLERK_PUBLISHABLE|SENTRY_DSN|MAPBOX)/i;
  /** names that themselves declare a live credential */
  const CREDENTIAL_NAME = /(SECRET|PRIVATE_?KEY|SERVICE_?ROLE|PASSWORD|PASSWD|TOKEN|API_?KEY)/i;
  const CLIENT_ENV_PREFIX = /^(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC)_/i;

  // ---------- comment stripping (detection-only; never mutates the write) ----------
  function stripComments(text) {
    return text
      .replace(/\\/\\*[\\s\\S]*?\\*\\//g, " ")                          // /* block */ comments
      .replace(/(^|[^:"'\\w])\\/\\/[^\\n]*/g, "$1 ")                 // // line comments (not inside URLs)
      .replace(/(^|\\n)[ \\t]*--[ \\t][^\\n]*/g, "$1 ")              // SQL -- line comments
      ;
  }

  // ---------- R1 context ----------
  const head = content.slice(0, 160);
  const useServer = /["']use server["']/.test(head);
  const useClient = /["']use client["']/.test(head);
  function isServerishPath(path) {
    return (
      /(^|\\/)(api)(\\/|$)/.test(path) ||                       // any api path segment (app/api, pages/api, src/api/)
      /(^|\\/)server(\\/|\\.)/.test(path) ||                    // "server" as a path SEGMENT (fixes the "observer" substring bug)
      /(^|\\/)route\\.(?:ts|tsx|js|mjs|jsx)$/.test(path) ||     // Next route handlers — server by definition
      /\\.server\\./.test(path) ||
      /(^|\\/)middleware\\./.test(path) ||
      /(^|\\/)instrumentation\\./.test(path) ||
      /(^|\\/)supabase\\/functions\\//.test(path)
    );
  }
  function isClientishPath(path) {
    // components/ or pages/ (pages/api/** is the server side of the pages router)
    if (/(^|\\/)pages\\/api\\//.test(path)) return false;
    return /(^|\\/)components?\\//.test(path) || /(^|\\/)pages\\//.test(path);
  }
  function isEnvPath(path) {
    return /(^|\\/)\\.env(?:\\.[^/\\\\]*)?$/.test(path) && !/\\.(?:example|template|sample)$/i.test(path);
  }
  function envEntries(text) {
    const out = [];
    for (const line of text.split(/\\r?\\n/)) {
      const em = /^\\s*(?:export\\s+)?([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(.*)$/.exec(line);
      if (em) out.push({ key: em[1], value: em[2].trim().replace(/^["']|["']+$/g, "") });
    }
    return out;
  }

  // ---------- R2: Row-Level Security ----------
  function r2Findings(sql) {
    const out = [];
    if (/disable\\s+row\\s+level\\s+security|force\\s+row\\s+level\\s+security\\s+disable/i.test(sql)) {
      out.push("SQL disables Row-Level Security — every row of the table becomes readable/writable by the anon role");
    }
    if (/create\\s+policy[\\s\\S]{0,220}?\\busing\\s*\\(\\s*true\\s*\\)/i.test(sql) || /create\\s+policy[\\s\\S]{0,220}?\\bwith\\s+check\\s*\\(\\s*true\\s*\\)/i.test(sql)) {
      out.push("CREATE POLICY with using(true)/with check (true) exposes every row to anon/authenticated — if the table is deliberately public, note that explicitly");
    }
    // drop policy ONLY when the same content has no create policy for the same table
    const creates = new Set();
    const createAll = sql.replace(/["']/g, "");
    let cm;
    const createRe = /create\\s+policy[\\s\\S]{0,400}?\\bon\\s+(?:only\\s+)?([A-Za-z0-9_$.]+)/gi;
    while ((cm = createRe.exec(createAll)) !== null) {
      creates.add(cm[1].toLowerCase().split(".").pop());
    }
    let dm;
    const dropRe = /drop\\s+policy\\s+(?:if\\s+exists\\s+)?["']?([A-Za-z0-9_$.]+)["']?(?:\\s+on\\s+["']?([A-Za-z0-9_$.]+)["']?)?/gi;
    while ((dm = dropRe.exec(sql)) !== null) {
      const table = dm[2] ? dm[2].toLowerCase().split(".").pop() : null;
      if (!table || !creates.has(table)) {
        out.push("DROP POLICY without a matching CREATE POLICY for the same table in this change — RLS protection would be removed wholesale. If this is a drop-then-recreate, include the new CREATE POLICY in the same edit");
      }
    }
    return out;
  }

  // ---------- detector pass over (path, content) pairs ----------
  const blocks = [];
  function detect(path, contentRaw) {
    const file = String(path).replace(/\\\\/g, "/");
    if (!file && !isBash) return;
    const stripped = stripComments(contentRaw);
    const fh = contentRaw.slice(0, 160);
    const fServer = /["']use server["']/.test(fh) || isServerishPath(file);
    if (fServer) return; // server code: R1 context never applies
    const clientReachable = /["']use client["']/.test(fh) || isClientishPath(file);

    // R1 — decoded service_role JWT in a client-reachable context
    if (clientReachable && serviceRoleJwts(stripped)) {
      blocks.push("service_role JWT (decoded role claim) referenced in client-reachable code (" + file + ") — browser bundles leak it; keep it server-side and expose what the client needs via an API route");
    }
    if (isEnvPath(file)) {
      for (const e of envEntries(contentRaw)) {
        if (PUBLIC_NAME.test(e.key)) continue;                       // public-by-design names pass
        const verdict = valueVerdict(e.value);
        if (verdict === "context") {
          if (CLIENT_ENV_PREFIX.test(e.key)) {                       // R1-env: client-prefixed name + service_role value
            blocks.push(e.key + " carries a service_role JWT in " + file + " — client-env values ship to the browser bundle; the service role must stay server-only");
          }
          continue;                                                  // server-side .env service_role config is where it belongs
        }
        if (verdict === "block") {
          blocks.push("secret-shaped value written into " + e.key + " (" + file + ") — prefer env injection; if committed, rotate immediately");
          continue;
        }
        if (CREDENTIAL_NAME.test(e.key) && e.value.trim().length >= 20 && !PLACEHOLDER.test(e.value)) {
          blocks.push("credential-named entry " + e.key + " with a live-looking value in " + file + " — prefer env injection; if committed, rotate immediately");
        }
      }
    } else {
      // R4 — client-env names assigned secret-shaped values in any file
      let am;
      const assignRe = /((?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC)_[A-Za-z0-9_]+)\\s*[:=]\\s*(["'])([^"']{2,200})\\2/g;
      while ((am = assignRe.exec(stripped)) !== null) {
        if (PUBLIC_NAME.test(am[1])) continue;
        const verdict = valueVerdict(am[3]);
        if (verdict === "block" || verdict === "context") {
          blocks.push(am[1] + " is assigned a secret-shaped value — everything with a client-env prefix ships to the browser bundle; move it server-side");
        }
      }
    }
  }

  if (isBash) {
    // Bash best effort: find target paths written via redirect/heredoc/tee/sed -i.
    // Path extraction is heuristic — documented follow-up, never a security boundary.
    const targets = new Set();
    const addT = (t) => { if (t) targets.add(String(t).replace(/^["']+|["']+$/g, "").replace(/\\\\/g, "/")); };
    let m;
    const redirRe = /(?:^|[;\\s])>{1,2}\\s*("[^"]+"|'[^']+'|[\\w./@~+.%-]+)/g;
    while ((m = redirRe.exec(content)) !== null) addT(m[1]);
    const teeRe = /\\btee\\s+(?:-{1,2}[A-Za-z-]+\\s+)*(?:("[^"]+")|'([^']+)'|([\\w./@~+.%-]+))/g;
    while ((m = teeRe.exec(content)) !== null) addT(m[1] || m[2] || m[3]);
    const sedRe = /\\bsed\\b[^;|&\\n]{0,200}?-i[a-zA-Z.]*[^;|&\\n]{0,300}/gi;
    while ((m = sedRe.exec(content)) !== null) {
      for (const tok of m[0].split(/\\s+/)) {
        if (/^[A-Za-z0-9_./@~+%-]+\\.[A-Za-z0-9]{1,8}$/.test(tok)) addT(tok);
      }
    }
    for (const t of targets) detect(t, content);
    for (const f of r2Findings(stripComments(content))) blocks.push(f);
  } else {
    detect(filePath, content);
    for (const f of r2Findings(stripComments(content))) blocks.push(f);
  }

  const unique = [...new Set(blocks)];
  if (unique.length) {
    const banner = "\\u26D0 Anubis Guardian guard hook v" + "${HOOK_VERSION}" + " blocked this change:";
    if (warnOnly) {
      console.error(banner + "\\n- " + unique.join("\\n- ") + "\\n(warn mode — ANUBIS_GUARD=block to enforce, =off to silence entirely)");
      process.exit(0);
    }
    console.error(
      banner + "\\n- " + unique.join("\\n- ") +
      "\\n(rotate-first: if a secret was exposed, rotate the credential before retrying;" +
      "\\n deliberate changes: add an anubis-allow: <reason> marker, or set ANUBIS_GUARD=off)"
    );
    process.exit(2);
  }
  process.exit(0);
});
`;

export const SNIPPET = `<!-- Anubis Guardian guard hook (pinned v${HOOK_VERSION}) -->
Run the audit before shipping: \`npx anubis-guardian@${HOOK_VERSION} scan . --fail-on high\`.
Treat every secret finding as compromised: rotate first, then remove (see fix-prompt.md).
Never apply suggested fixes without human approval — suggested diffs only.`;

export interface HookInstallResult {
  scriptPath: string;
  settingsPath: string;
  created: boolean;
}

/** idempotent: same version → left untouched; settings merge preserves existing keys */
export function installHook(projectDir: string, force = false): HookInstallResult {
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
  } else {
    writeFileSync(scriptPath, HOOK_SCRIPT);
  }

  // merge hooks entry into .claude/settings.json (never overwrite other config)
  const settingsPath = join(root, ".claude", "settings.json");
  let settings: Record<string, unknown> = {};
  if (existsSync(settingsPath)) {
    try { settings = JSON.parse(readFileSync(settingsPath, "utf8")); } catch { settings = {}; }
  }
  const hooks = (settings.hooks as Record<string, unknown> | undefined) ?? {};
  const pre = Array.isArray(hooks.PreToolUse) ? (hooks.PreToolUse as unknown[]) : [];
  const entry = {
    matcher: "Write|Edit|MultiEdit|NotebookEdit|Bash",
    hooks: [{ type: "command", command: "node .claude/hooks/anubis-guard-hook.mjs", version: HOOK_VERSION }],
  };
  const already = pre.some((e) => JSON.stringify(e).includes("anubis-guard-hook.mjs"));
  if (!already) pre.push(entry);
  settings.hooks = { ...hooks, PreToolUse: pre };
  mkdirSync(join(root, ".claude"), { recursive: true });
  writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n");

  return { scriptPath, settingsPath, created };
}
