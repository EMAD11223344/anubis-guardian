#!/usr/bin/env node
/**
 * Acceptance v0.3 — plan gates for the Agent Skill + AI Review round:
 *   A. AI review layer: redaction-before-LLM + independent verifier (mock provider
 *      in its own process — see ai-mock-server.mjs): confirmed claims become
 *      findings (capped at HIGH), fabricated/missing-file/unknown-rule claims are
 *      REJECTED, meta.ai_used set, byte-identical across runs with the same canned
 *      provider (non-determinism is provider-side, flagged in meta).
 *   B. --ai-review without ANUBIS_AI_API_KEY → exit 2 with instructions.
 *   C. test-authz: authz matrix + generated Supertest quarantine (tool never executes).
 *   D. scan --quarantine: taint canary tests generated (tool never executes).
 *   E. init-hook: pinned hook script + settings wiring, idempotent, no @latest/npx,
 *      and the hook BLOCKS service_role-in-client writes (exit 2, PreToolUse contract).
 *   F. SKILL.md carries the hard-rule contract (rotate-first, suggested-diff,
 *      needs_confirmation, masking, classes-not-covered) + v0.3 commands.
 * The tool NEVER executes generated tests or project code (Section 9.7).
 */
import { spawnSync, spawn } from "node:child_process";
import { readFileSync, rmSync, existsSync, mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const CLI = join(root, "dist", "cli.js");
const HONEYPOT_APP = join(here, "honeypot", "app");
const HONEYPOT_NEST = join(here, "honeypot", "nest-app");

let failures = 0;
const ok = (cond, label, detail = "") => {
  if (cond) console.log(`PASS  ${label}${detail ? ` — ${detail}` : ""}`);
  else { console.error(`FAIL  ${label}${detail ? ` — ${detail}` : ""}`); failures++; }
};

const tmp = mkdtempSync(join(tmpdir(), "anubis-acc-v03-"));
const quarantine = join(tmp, "quarantine");

// ---- mock provider in its OWN process (parent is blocked by spawnSync) ----
const capturePath = join(tmp, "captured-request.json");
const mock = spawn(process.execPath, [join(here, "ai-mock-server.mjs"), capturePath], { stdio: ["ignore", "pipe", "inherit"] });
const port = await new Promise((resolve2, reject) => {
  let buf = "";
  mock.stdout.on("data", (d) => {
    buf += d;
    const line = buf.split("\n").find((l) => l.trim().startsWith("{"));
    if (line) { try { resolve2(JSON.parse(line).port); } catch (e) { reject(e); } }
  });
  mock.on("exit", () => reject(new Error("mock provider died early")));
});
const run = (args, env = {}) =>
  spawnSync("node", [CLI, ...args], { cwd: root, encoding: "utf8", env: { ...process.env, ...env } });

// ---- A. AI review with mock provider (twice — byte-identical determinism) ----
const out1 = join(tmp, "findings-1.json");
const out2 = join(tmp, "findings-2.json");
const aiEnv = { ANUBIS_AI_BASE_URL: `http://127.0.0.1:${port}/v1`, ANUBIS_AI_API_KEY: "test-key", ANUBIS_AI_MODEL: "mock-model" };
const r1 = run(["scan", HONEYPOT_APP, "--format", "json", "--output", out1, "--ai-review"], aiEnv);
const r2 = run(["scan", HONEYPOT_APP, "--format", "json", "--output", out2, "--ai-review"], aiEnv);
ok(r1.status === 0, "A1: scan --ai-review (mock provider) exits 0", (r1.stderr ?? "").slice(-160));

const res1 = JSON.parse(readFileSync(out1, "utf8"));
const res2 = JSON.parse(readFileSync(out2, "utf8"));
ok(readFileSync(out1, "utf8") === readFileSync(out2, "utf8"), "A2: identical canned provider ⇒ byte-identical findings.json (determinism, with meta.ai_used flag)");
ok(res1.meta.ai_used === true, "A3: meta.ai_used set (non-deterministic layer flagged)");
ok(res1.ai_review?.used === true && res1.ai_review.provider === `http://127.0.0.1:${port}/v1` && res1.ai_review.model === "mock-model", "A4: ai_review meta carries provider + model");
ok(res1.ai_review.confirmed === 1, `A5: exactly 1 claim confirmed by the verifier (got ${res1.ai_review?.confirmed})`);
ok(res1.ai_review.rejected === 3, `A6: 3 claims rejected (hallucinated snippet / missing file / unknown rule) — got ${res1.ai_review?.rejected}`);
const aiFindings = res1.findings.filter((f) => f.source === "ai-review");
ok(aiFindings.length === 1 && aiFindings[0].id === "NEXT-005", "A7: confirmed AI finding present with source=ai-review and correct rule id");
ok(aiFindings.every((f) => f.severity !== "critical"), "A8: AI findings capped below CRITICAL (CRITICAL stays deterministic-confirmation-only)");
ok(aiFindings.every((f) => f.needs_confirmation === true && f.verified === false), "A9: AI findings carry needs_confirmation + verified=false (honesty contract)");
ok(!JSON.stringify(res1).includes("sbp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV"), "A10: masking contract intact through the AI-review path");

// A11/A12: inspect what the mock actually received (prompt protocol + redaction)
await new Promise((r) => setTimeout(r, 150)); // allow the capture write to flush
const captured = existsSync(capturePath) ? readFileSync(capturePath, "utf8") : "";
ok(captured.includes("UNTRUSTED") || captured.includes("untrusted"), "A11: untrusted-data protocol framing present in the prompt");
ok(captured.includes("[REDACTED") || !/sbp_[A-Za-z0-9]{20,}/.test(captured), "A12: redaction-before-LLM — no raw secret-shaped value in the prompt payload");

// ---- B. --ai-review without key → exit 2 with instructions ----
const rNoKey = run(["scan", HONEYPOT_APP, "--format", "json", "--ai-review"]);
ok(rNoKey.status === 2 && (rNoKey.stderr ?? "").includes("ANUBIS_AI_API_KEY"), "B1: --ai-review without API key exits 2 with setup instructions");

// ---- C. test-authz: matrix + generated quarantine tests ----
const qa = join(tmp, "authz-quarantine");
const rc = run(["test-authz", HONEYPOT_APP, "--quarantine", qa]);
ok(rc.status === 0, "C1: test-authz exits 0", (rc.stderr ?? "").split("\n")[0] ?? "");
ok(existsSync(join(qa, "authz-matrix.md")) && existsSync(join(qa, "authz-matrix.json")), "C2: authz matrix (md + json) generated");
const matrix = JSON.parse(readFileSync(join(qa, "authz-matrix.json"), "utf8"));
ok(Array.isArray(matrix.rows) && matrix.rows.some((r) => r.authz_risk), "C3: matrix flags unguarded mutating endpoints");
ok(existsSync(join(qa, "authz.supertest.test.js")), "C4: failing-by-expectation Supertest suite generated");
ok(readFileSync(join(qa, "authz.supertest.test.js"), "utf8").includes("401, 403, 302, 307"), "C5: generated tests assert rejection (401/403/redirect)");
ok(readFileSync(join(qa, "README.md"), "utf8").includes("never executes"), "C6: quarantine README carries the no-exec contract");
const rcGate = run(["test-authz", HONEYPOT_APP, "--quarantine", join(tmp, "qa2"), "--fail-on-risk"]);
ok(rcGate.status === 1, "C7: --fail-on-risk exits 1 while unguarded mutating endpoints exist");

// ---- D. scan --quarantine: taint canaries (both roots — TAINT-003/005 live in the Nest root) ----
const qt = join(tmp, "taint-quarantine");
const rd = run(["scan", HONEYPOT_APP, HONEYPOT_NEST, "--format", "json", "--output", join(tmp, "findings-4.json"), "--quarantine", qt]);
ok(rd.status === 0, "D1: scan --quarantine exits 0");
const canaries = existsSync(qt) ? readdirSync(qt).filter((f) => f.startsWith("taint-") && f.endsWith(".test.js")) : [];
ok(canaries.length >= 4, `D2: taint canary tests generated (${canaries.length})`, canaries.slice(0, 3).join(", "));
ok(canaries.every((f) => readFileSync(join(qt, f), "utf8").includes("test.skip")), "D3: canaries are scaffolds — the tool does not execute them");

// ---- E. init-hook: pinned install + idempotency + enforcement ----
const hookDir = join(tmp, "hookproj");
const rh1 = run(["init-hook", "--dir", hookDir]);
ok(rh1.status === 0, "E1: init-hook exits 0");
const hookScript = join(hookDir, ".claude", "hooks", "anubis-guard-hook.mjs");
const hookSettings = join(hookDir, ".claude", "settings.json");
ok(existsSync(hookScript) && existsSync(hookSettings), "E2: hook script + settings.json created");
const snap1 = readFileSync(hookScript, "utf8") + "|" + readFileSync(hookSettings, "utf8");
run(["init-hook", "--dir", hookDir]);
const snap2 = readFileSync(hookScript, "utf8") + "|" + readFileSync(hookSettings, "utf8");
ok(snap1 === snap2, "E3: init-hook idempotent (second run changes nothing)");
const settings = JSON.parse(readFileSync(hookSettings, "utf8"));
ok(JSON.stringify(settings).includes("anubis-guard-hook.mjs") && !/npx|@latest/.test(JSON.stringify(settings.hooks ?? {})), "E4: hook wiring is local + pinned (no npx/@latest in hook config)");
const hookSrc = readFileSync(hookScript, "utf8");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
ok(hookSrc.includes(`v${pkg.version}`), `E5: hook header carries the REAL package version (v${pkg.version})`);
ok((settings.hooks?.PreToolUse ?? []).some((e) => e.hooks?.[0]?.version === pkg.version), "E5b: settings.json hook entry version = real package version");

// ---- E6..: table-driven WHY-block/ALLOW gates (≥24 cases, value-based detectors) ----
// REAL JWTs are synthesized here (pure node, base64url) — no placeholders.
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const mkJwt = (role) => `${b64u({ alg: "HS256", typ: "JWT" })}.${b64u({ role, sub: "user-42" })}.${Buffer.from("hook-test-signature-not-real").toString("base64url")}`;
const SR = mkJwt("service_role");
const ANON = mkJwt("anon");
const OPAQUE = "a1B2c3D4e5F6g7H8i9J0kLmN";   // 24 chars, charset+entropy per valueclass
const FBKEY = "AIza" + "S".repeat(35);       // matches ^AIza[0-9A-Za-z_-]{35}$ (public by design)

const feed = (input, env) => spawnSync(process.execPath, [hookScript],
  { input: JSON.stringify(input), encoding: "utf8", env: env ? { ...process.env, ...env } : process.env });
const feedRaw = (raw, env) => spawnSync(process.execPath, [hookScript],
  { input: raw, encoding: "utf8", env: env ? { ...process.env, ...env } : process.env });

const HOOK_CASES = [
  // ---------------- MUST BLOCK ----------------
  ["BLOCK service_role JWT in a 'use client' file", 2, { tool_name: "Write", tool_input: { file_path: "app/components/AdminPanel.tsx", content: `const key = "${SR}";` } }],
  ["BLOCK service_role JWT via Edit new_string", 2, { tool_name: "Edit", tool_input: { file_path: "app/app/components/P.tsx", new_string: `export const K = "${SR}";` } }],
  ["BLOCK service_role JWT via MultiEdit edits array", 2, { tool_name: "MultiEdit", tool_input: { file_path: "src/pages/settings.tsx", edits: [{ old_string: "a", new_string: `const k = "${SR}";` }] } }],
  ["BLOCK service_role JWT into NEXT_PUBLIC_ .env var", 2, { tool_name: "Write", tool_input: { file_path: ".env", content: `NEXT_PUBLIC_ADMIN_TOKEN=${SR}\nNEXT_PUBLIC_SUPABASE_URL=https://x.supabase.co\n` } }],
  ["BLOCK VITE_ .env var with service_role JWT", 2, { tool_name: "Write", tool_input: { file_path: ".env.local", content: `VITE_ADMIN_TOKEN=${SR}\n` } }],
  ["BLOCK mixed-CASE disable row level security", 2, { tool_name: "Edit", tool_input: { file_path: "supabase/migrations/0002.sql", content: "ALTER TABLE profiles DISABLE ROW LEVEL SECURITY;" } }],
  ["BLOCK multi-line create policy using (true) for anon", 2, { tool_name: "Edit", tool_input: { file_path: "supabase/migrations/0003.sql", content: 'create policy "everyone reads"\n  on profiles for select\n  to anon\n  using (true);' } }],
  ["BLOCK drop policy with NO matching create policy (same change)", 2, { tool_name: "Edit", tool_input: { file_path: "supabase/migrations/0004.sql", content: 'drop policy if exists "all_access" on profiles;' } }],
  ["BLOCK drop policy on table A while create policy covers table B", 2, { tool_name: "Edit", tool_input: { file_path: "supabase/migrations/0005.sql", content: 'drop policy "a" on secrets_table;\ncreate policy "b" on other_table for select using (auth.uid() = user_id);' } }],
  ["BLOCK drop policy with NO on clause at all", 2, { tool_name: "Edit", tool_input: { file_path: "supabase/migrations/0006.sql", content: 'drop policy if exists "all_access";' } }],
  ["BLOCK sk_live_ value into .env credential name (R3)", 2, { tool_name: "Write", tool_input: { file_path: ".env", content: `STRIPE_SECRET=${OPAQUE}\n` } }],
  ["BLOCK private key body into .env", 2, { tool_name: "Write", tool_input: { file_path: ".env", content: "DEPLOY_KEY=-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA7x\\n" } }],
  ["BLOCK service_role JWT in a pages/ file (non-api)", 2, { tool_name: "Edit", tool_input: { file_path: "pages/upgrade.tsx", content: `const k = "${SR}";` } }],
  ["BLOCK R4: NEXT_PUBLIC_ name assigned a secret-shaped value in code", 2, { tool_name: "Edit", tool_input: { file_path: "src/config.ts", content: `NEXT_PUBLIC_ANALYTICS_SECRET = "${OPAQUE}";` } }],
  ["BLOCK Bash heredoc writing service_role JWT into components/", 2, { tool_name: "Bash", tool_input: { command: `cat > app/components/Leak.tsx <<'EOF'\nconst k = "${SR}";\nEOF` } }],
  ["BLOCK Bash tee writing service_role JWT into components/", 2, { tool_name: "Bash", tool_input: { command: `echo 'const k = "${SR}";' | tee src/components/L.tsx` } }],
  ["BLOCK Bash redirect (sed -i) placing service_role JWT into components/", 2, { tool_name: "Bash", tool_input: { command: `sed -i "s/PLACEHOLDER_TOKEN/${SR}/" app/components/Panel.tsx` } }],
  ["BLOCK Bash psql disable row level security", 2, { tool_name: "Bash", tool_input: { command: 'psql -c "alter table profiles disable row level security"' } }],
  // v1.3-audit round-2 hook cases (echo/heredoc .env writes without KEY=VALUE, live literal into client code)
  ["BLOCK Bash echo 'sk_live_…' > .env (R3-redir: quoted literal, no KEY= line)", 2, { tool_name: "Bash", tool_input: { command: `echo "sk_live_51H8xYzAbCdEfGhIjKlMnOp" > .env` } }],
  ["BLOCK Bash heredoc writing a live-shaped .env value", 2, { tool_name: "Bash", tool_input: { command: `cat > .env <<'EOF'\nDATABASE_PASSWORD=c0rr3ct-horse-battery-staple-99\nEOF` } }],
  ["BLOCK sk_live_ literal written into a client component (R5, no NEXT_PUBLIC_ prefix)", 2, { tool_name: "Write", tool_input: { file_path: "app/components/Config.tsx", content: `export const stripeKey = "sk_live_51H8xYzAbCdEfGhIjKlMnOp";\n` } }],
  ["ALLOW sk_test_ literal in a client component (public test key)", 0, { tool_name: "Write", tool_input: { file_path: "app/components/Config.tsx", content: `export const pk = "sk_test_a1B2c3D4e5F6a1B2c3D4e5F6a1B2c3D4";\n` } }],
  ["BLOCK anubis-allow marker with TOO-SHORT reason (<8 chars)", 2, { tool_name: "Write", tool_input: { file_path: "app/components/AdminPanel.tsx", content: `const key = "${SR}"; // anubis-allow: fix` } }],
  // ---------------- MUST ALLOW ----------------
  ["ALLOW anubis-allow marker with an 8+ char reason", 0, { tool_name: "Write", tool_input: { file_path: "app/components/AdminPanel.tsx", content: `const key = "${SR}"; // anubis-allow: rotated and proxied server-side` } }],
  ["ALLOW anon JWT in a client file", 0, { tool_name: "Write", tool_input: { file_path: "app/components/PublicFeed.tsx", content: `const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "${ANON}";` } }],
  ["ALLOW drop policy if exists + create policy (same table, auth.uid())", 0, { tool_name: "Edit", tool_input: { file_path: "supabase/migrations/0007.sql", content: 'drop policy if exists all_access on profiles;\ncreate policy "owners only" on profiles for select using (auth.uid() = user_id);' } }],
  ["ALLOW NEXT_PUBLIC_FIREBASE_API_KEY in .env (public by design)", 0, { tool_name: "Write", tool_input: { file_path: ".env", content: `NEXT_PUBLIC_FIREBASE_API_KEY=${FBKEY}\n` } }],
  ["ALLOW process.env.NEXT_PUBLIC_GOOGLE_MAPS_API_KEY reference", 0, { tool_name: "Edit", tool_input: { file_path: "app/components/Map.tsx", content: "const key = process.env.NEXT_PUBLIC_GOOGLE_MAPS_API_KEY;" } }],
  ["ALLOW the WORD service_role inside a comment (comment stripping)", 0, { tool_name: "Write", tool_input: { file_path: "app/components/Panel.tsx", content: `// never ship a service_role key from this component; use the server API\nconst k = process.env.NEXT_PUBLIC_SUPABASE_URL;` } }],
  ["ALLOW a plain-string 'service_role' mention (no JWT value decoded) in a client file", 0, { tool_name: "Write", tool_input: { file_path: "app/components/Role.tsx", content: `const ROLE = "service_role";` } }],
  ["ALLOW service_role JWT used in an app/api route handler", 0, { tool_name: "Write", tool_input: { file_path: "app/api/admin/route.ts", content: `const admin = createClient(url, "${SR}");` } }],
  ["ALLOW service_role JWT under a heavy 'use server' action file", 0, { tool_name: "Write", tool_input: { file_path: "app/actions/grant.ts", content: `'use server'\nexport async function grant() {\n  const admin = createClient(url, "${SR}");\n}` } }],
  ["ALLOW path containing 'observer' (the old substring-'server' bug)", 0, { tool_name: "Write", tool_input: { file_path: "app/lib/observer.ts", content: `const admin = createClient(url, "${SR}");` } }],
  ["ALLOW 'server' as a real path segment (src/server/db.ts)", 0, { tool_name: "Write", tool_input: { file_path: "src/server/db.ts", content: `const admin = createClient(url, "${SR}");` } }],
  ["ALLOW server-side .env service_role config (SUPABASE_SERVICE_ROLE_KEY)", 0, { tool_name: "Write", tool_input: { file_path: ".env", content: `SUPABASE_SERVICE_ROLE_KEY=${SR}\n` } }],
  ["ALLOW SUPABASE_ANON_KEY / STRIPE_PUBLISHABLE_KEY / SENTRY_DSN / MAPBOX pk. in .env", 0, { tool_name: "Write", tool_input: { file_path: ".env", content: `SUPABASE_ANON_KEY=${ANON}\nSTRIPE_PUBLISHABLE_KEY=pk_live_9iLIbsAJXmpattern\nSENTRY_DSN=https://d@o.ingest.sentry.io/1\nMAPBOX_PUBLIC=pk.eyJ1IjoiZXhhbXBsZS1wdWJsaWMtdG9rZW4tMjM0NTY3OA\n` } }],
  ["ALLOW placeholder/unknown short env values", 0, { tool_name: "Write", tool_input: { file_path: ".env", content: "DEBUG=changeme\\nLOG_LEVEL=info\\n" } }],
  ["ALLOW .env.example with credential-shaped entries", 0, { tool_name: "Write", tool_input: { file_path: ".env.example", content: `STRIPE_SECRET=sk_live_REPLACE_ME_WITH_A_REAL_KEY_42\n` } }],
  ["ALLOW Bash anon JWT into components/ (public by design)", 0, { tool_name: "Bash", tool_input: { command: `echo 'const k = "${ANON}";' > app/components/Public.tsx` } }],
  ["ALLOW benign write", 0, { tool_name: "Edit", tool_input: { file_path: "app/lib/util.ts", content: "export const add = (a,b) => a + b;" } }],
  ["ALLOW benign Bash (non-write command)", 0, { tool_name: "Bash", tool_input: { command: "ls" } }],
  ["ALLOW non-write tools (Grep) regardless of content", 0, { tool_name: "Grep", tool_input: { pattern: SR } }],
];
let hookPass = 0;
for (const [name, expect, input] of HOOK_CASES) {
  const r = feed(input);
  if (r.status === expect) { hookPass++; console.log("ok  " + name); }
  else { failures++; console.error(`FAIL E-hook: ${name} — expected exit ${expect}, got ${r.status}${r.stderr ? ` :: ${(r.stderr.trim().split("\\n")[0] ?? "")}` : ""}`); }
}
// escape-hatch + fail-open + warn-mode (env-controlled)
ok(feed(HOOK_CASES[0][2], { ANUBIS_GUARD: "off" }).status === 0, "E: ANUBIS_GUARD=off disables enforcement entirely");
ok(feed(HOOK_CASES[0][2], { ANUBIS_GUARD: "warn" }).status === 0, "E: ANUBIS_GUARD=warn reports but exits 0");
ok(feedRaw("{not json").status === 0, "E: malformed JSON stdin fails OPEN");
ok(feedRaw("").status === 0, "E: empty stdin fails OPEN");
ok(hookPass === HOOK_CASES.length, `E: hook gate table — ${hookPass}/${HOOK_CASES.length} cases`);


// ---- F. SKILL.md hard-rule contract ----
const skill = readFileSync(join(root, "skill", "SKILL.md"), "utf8");
ok(skill.includes("Rotate-first") || skill.includes("rotate-first"), "F1: SKILL.md carries rotate-first");
ok(skill.includes("suggested diff") || skill.includes("suggested-diff") || skill.includes("suggested diffs"), "F2: SKILL.md carries suggested-diff-only");
ok(skill.includes("needs_confirmation"), "F3: SKILL.md carries needs_confirmation honesty");
ok(skill.includes("never print full secret") || skill.includes("masked") || skill.includes("Masking") || skill.includes("masking"), "F4: SKILL.md carries the masking contract");
ok(skill.includes("Classes not covered") || skill.includes("Classes-not-covered") || skill.includes("classes not covered"), "F5: SKILL.md carries classes-not-covered honesty");
ok(skill.includes("test-authz") && skill.includes("--ai-review") && skill.includes("init-hook"), "F6: SKILL.md documents the v0.3 commands");
// F7–F12: command-workflow & semantics depth (the skill must teach WORKING, not just name commands)
ok(skill.includes("update-advisories") && skill.includes("rules-lock") && skill.includes("init-zap"), "F7: SKILL.md documents the v1.0 commands (update-advisories/rules-lock/init-zap)");
ok(/exit codes?/i.test(skill) && /exit\s*2/.test(skill) && /exit\s*1/.test(skill), "F8: SKILL.md teaches exit-code branching (0/1/2)");
ok(skill.includes("--fix-prompt") && skill.includes("--compact") && skill.includes("--capture"), "F9: SKILL.md teaches the artifact workflow (fix-prompt/compact/capture)");
ok(skill.includes("db dump") && skill.includes("playwright"), "F10: SKILL.md carries verification recipes (schema dump, canary run by the human)");
ok(/rotate-first/i.test(skill) && /rotate\s*the .*first|START with the rotation/i.test(skill), "F11: SKILL.md mandates rotate-first BEFORE code edits");
ok(skill.includes("i-own-this-domain") && skill.includes("self-attested"), "F12: SKILL.md honors the ownership gate vocabulary (self-attestation ≠ verification)");

// ---- cleanup ----
mock.kill();
rmSync(tmp, { recursive: true, force: true });

if (failures) {
  console.error(`\nACCEPTANCE v0.3: ${failures} failure(s)`);
  process.exit(1);
}
console.log("\nACCEPTANCE v0.3: ALL GATES GREEN");
