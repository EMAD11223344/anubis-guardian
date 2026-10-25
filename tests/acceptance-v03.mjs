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
ok(hookSrc.includes("ROW\\s+LEVEL") && hookSrc.includes("service[_-]?role"), "E5: hook guards RLS-killing SQL + service_role");

const feedHook = (input) => spawnSync(process.execPath, [hookScript], { input: JSON.stringify(input), encoding: "utf8" });
ok(feedHook({ tool_name: "Edit", tool_input: { file_path: "app/components/P.tsx", content: "const k = process.env.SERVICE_ROLE_KEY" } }).status === 2, "E6: hook BLOCKS service_role into client-reachable code (exit 2)");
ok(feedHook({ tool_name: "Edit", tool_input: { file_path: "supabase/migrations/x.sql", content: "alter table t disable row level security;" } }).status === 2, "E7: hook BLOCKS RLS-killing SQL (exit 2)");
ok(feedHook({ tool_name: "Edit", tool_input: { file_path: ".env", content: "STRIPE_SECRET=sk_live_a1B2c3D4e5F6g7H8i9J0" } }).status === 2, "E8: hook BLOCKS real-looking secrets into .env (exit 2)");
ok(feedHook({ tool_name: "Edit", tool_input: { file_path: "app/lib/util.ts", content: "export const add = (a,b) => a + b;" } }).status === 0, "E9: hook allows benign writes (exit 0)");
ok(feedHook({ tool_name: "Bash", tool_input: { command: "ls" } }).status === 0, "E10: hook ignores non-write tools (exit 0)");

// ---- F. SKILL.md hard-rule contract ----
const skill = readFileSync(join(root, "skill", "SKILL.md"), "utf8");
ok(skill.includes("Rotate-first") || skill.includes("rotate-first"), "F1: SKILL.md carries rotate-first");
ok(skill.includes("suggested diff") || skill.includes("suggested-diff") || skill.includes("suggested diffs"), "F2: SKILL.md carries suggested-diff-only");
ok(skill.includes("needs_confirmation"), "F3: SKILL.md carries needs_confirmation honesty");
ok(skill.includes("never print full secret") || skill.includes("masked") || skill.includes("Masking") || skill.includes("masking"), "F4: SKILL.md carries the masking contract");
ok(skill.includes("Classes not covered") || skill.includes("Classes-not-covered") || skill.includes("classes not covered"), "F5: SKILL.md carries classes-not-covered honesty");
ok(skill.includes("test-authz") && skill.includes("--ai-review") && skill.includes("init-hook"), "F6: SKILL.md documents the v0.3 commands");

// ---- cleanup ----
mock.kill();
rmSync(tmp, { recursive: true, force: true });

if (failures) {
  console.error(`\nACCEPTANCE v0.3: ${failures} failure(s)`);
  process.exit(1);
}
console.log("\nACCEPTANCE v0.3: ALL GATES GREEN");
