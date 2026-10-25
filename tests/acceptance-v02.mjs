#!/usr/bin/env node
/**
 * v0.2 acceptance (Plan Section 11 v0.2 acceptance criteria):
 *  1. init-ci generates a least-privilege workflow with real SHA pins + --fail-on critical
 *  2. the generated gate WOULD block a PR with a critical finding (--fail-on critical → exit 1)
 *  3. byte-identical determinism for findings.json AND fix-prompt.md
 *  4. --workspaces portfolio mode
 *  5. --rules-dir org rules (CRITICAL → needs_confirmation enforced)
 *  6. multi-root HDR-001 cross-root linkage (sender in root A + receiver in root B → CRITICAL)
 *  7. --compact / --html / --inventory artifacts render
 */
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const CLI = join(root, "dist", "cli.js");
const tmp = "/tmp/anubis-acceptance";
let failures = 0;
const check = (ok, label) => {
  if (ok) console.log(`PASS  ${label}`);
  else { console.error(`FAIL  ${label}`); failures++; }
};
const run = (args, opts = {}) => spawnSync("node", [CLI, ...args], { encoding: "utf8", ...opts });

rmSync(tmp, { recursive: true, force: true });
mkdirSync(tmp, { recursive: true });

// ---------- 1) init-ci ----------
const projDir = join(tmp, "ci-project");
mkdirSync(projDir, { recursive: true });
const r1 = run(["init-ci", "--dir", projDir]);
const wfPath = join(projDir, ".github", "workflows", "anubis-guardian.yml");
check(r1.status === 0 && existsSync(wfPath), "init-ci generates .github/workflows/anubis-guardian.yml");
const wf = existsSync(wfPath) ? readFileSync(wfPath, "utf8") : "";
check(wf.includes("actions/checkout@11d5960a326750d5838078e36cf38b85af677262"), "workflow pins actions/checkout to a real 40-char SHA");
check(wf.includes("actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"), "workflow pins actions/setup-node to a real SHA");
check(/github\/codeql-action\/upload-sarif@[0-9a-f]{40}/.test(wf), "workflow pins upload-sarif to a real SHA");
check(wf.includes("permissions:\n  contents: read\n  security-events: write"), "workflow uses least-privilege permissions");
check(wf.includes("--fail-on critical"), "workflow gates on --fail-on critical (blocks bad PRs)");
check(!wf.includes("@latest"), "no @latest anywhere in the generated workflow (v1.6 discipline)");
const r1b = run(["init-ci", "--dir", projDir]);
check(r1b.status === 0 && r1b.stderr.includes("exists"), "init-ci is idempotent (never overwrites)");

// ---------- 2) the gate blocks a critical PR ----------
const r2 = run(["scan", join(root, "tests", "honeypot", "app"), "--fail-on", "critical", "--format", "compact"]);
check(r2.status === 1, `--fail-on critical exits 1 on the honeypot (got ${r2.status})`);
const r2b = run(["scan", join(root, "tests", "clean", "app"), "--fail-on", "critical", "--format", "compact"]);
check(r2b.status === 0, `--fail-on critical exits 0 on the clean app (got ${r2b.status})`);
const r2c = run(["scan", join(root, "tests", "clean", "app"), "--fail-on-cve", "--format", "compact"]);
check(r2c.status === 0, "--fail-on-cve passes on clean deps");

// ---------- 3) determinism: findings.json AND fix-prompt.md byte-identical ----------
const runDet = (tag) => {
  run(["scan", join(root, "tests", "honeypot", "app"), join(root, "tests", "honeypot", "nest-app"),
    "--format", "json", "--output", join(tmp, `f1-${tag}.json`),
    "--fix-prompt", join(tmp, `fp-${tag}.md`)]);
};
runDet("a"); runDet("b");
const fA = readFileSync(join(tmp, "f1-a.json")), fB = readFileSync(join(tmp, "f1-b.json"));
const pA = readFileSync(join(tmp, "fp-a.md")), pB = readFileSync(join(tmp, "fp-b.md"));
check(fA.equals(fB), "multi-root findings.json is byte-identical across runs");
check(pA.equals(pB), "fix-prompt.md is byte-identical across runs (v0.2 acceptance)");

// ---------- 4) --workspaces ----------
const mono = join(tmp, "mono");
mkdirSync(join(mono, "apps", "web"), { recursive: true });
mkdirSync(join(mono, "apps", "api"), { recursive: true });
writeFileSync(join(mono, "package.json"), JSON.stringify({ name: "mono", private: true, workspaces: ["apps/*"] }, null, 2));
writeFileSync(join(mono, "apps", "web", "package.json"), JSON.stringify({ name: "web", dependencies: { next: "15.1.0", react: "19.0.0" } }, null, 2));
writeFileSync(join(mono, "apps", "api", "package.json"), JSON.stringify({ name: "api", dependencies: { express: "4.21.0" } }, null, 2));
writeFileSync(join(mono, "apps", "web", "vulnerable.ts"), 'export const stripeKey = "sk_live_aaaaaaaaaaaaaaaaaaaaaaaa";\n');
const r4 = run(["scan", mono, "--workspaces", "--format", "json"]);
check(r4.status === 0, "--workspaces scan runs");
if (r4.status === 0) {
  const res = JSON.parse(r4.stdout);
  check(res.portfolio?.length === 2, `portfolio has 2 apps (got ${res.portfolio?.length})`);
  check(res.findings.some((f) => f.file.startsWith("web/") && f.id.startsWith("SEC-")), "workspace findings keep root-prefixed paths");
} else {
  check(false, "--workspaces scan runs");
}

// ---------- 5) --rules-dir org rules ----------
const rulesDir = join(tmp, "org-rules");
mkdirSync(rulesDir, { recursive: true });
writeFileSync(join(rulesDir, "org.json"), JSON.stringify([{
  id: "ORG-001",
  severity: "critical",
  title: "Internal API base URL must come from env (org policy)",
  owasp: "A05",
  files: ["*.ts", "*.tsx", "*.js"],
  regex: "https://internal\\.corp\\.local",
  fix: "Read the internal endpoint from an env var instead of hardcoding the internal host.",
  clean_cases: "endpoints read from process.env.INTERNAL_URL",
}], null, 2));
const orgApp = join(tmp, "org-app");
mkdirSync(orgApp, { recursive: true });
writeFileSync(join(orgApp, "service.ts"), "const url = \"https://internal.corp.local/api\";\nexport default url;\n");
writeFileSync(join(orgApp, "package.json"), JSON.stringify({ name: "org-app", private: true, dependencies: { next: "15.1.0" } }, null, 2));
const r5 = run(["scan", orgApp, "--rules-dir", rulesDir, "--format", "json"]);
check(r5.status === 0, "--rules-dir scan runs");
if (r5.status === 0) {
  const res = JSON.parse(r5.stdout);
  const orgF = res.findings.find((f) => f.id === "ORG-001");
  check(Boolean(orgF), "org rule fires");
  check(orgF?.source === "org-rule" && orgF?.needs_confirmation === true, "org CRITICAL is needs_confirmation (no-CRITICAL-without-confirmation law)");
  check(res.score_breakdown.groups.some((g) => g.rule_id === "ORG-001"), "org rule deducts in score_breakdown");
} else {
  check(false, "--rules-dir scan runs");
}

// ---------- 6) multi-root HDR-001 cross-root linkage ----------
const rootA = join(tmp, "frontend");
const rootB = join(tmp, "backend");
mkdirSync(rootA, { recursive: true });
mkdirSync(rootB, { recursive: true });
writeFileSync(join(rootA, "package.json"), JSON.stringify({ name: "frontend", private: true, dependencies: { react: "19.0.0" } }, null, 2));
writeFileSync(join(rootA, "client.ts"), `export function connect() {
  return fetch("https://api.internal/db", {
    headers: { "x-db-password": "Sup3rCrossRoot!", "x-db-user": "postgres" },
  });
}
`);
writeFileSync(join(rootB, "package.json"), JSON.stringify({ name: "backend", private: true, dependencies: { pg: "8.13.0", express: "4.21.0" } }, null, 2));
writeFileSync(join(rootB, "server.ts"), `import express from "express";
const app = express();
app.get("/db", (req, res) => {
  const password = req.headers["x-db-password"];
  const pool = new Pool({ host: "db", password });
  return res.json({ ok: true });
});
app.listen(3000);
`);
writeFileSync(join(rootB, "pool.ts"), 'import { Pool } from "pg";\nexport { Pool };\n');
const r6 = run(["scan", rootA, rootB, "--format", "json"]);
check(r6.status === 0, "multi-root scan runs");
if (r6.status === 0) {
  const res = JSON.parse(r6.stdout);
  const cross = res.findings.find((f) => f.id === "HDR-001" && f.evidence.type === "cross_root_linkage");
  check(Boolean(cross), "HDR-001 cross-root linkage emits");
  check(cross?.severity === "critical", "cross-root linkage is CRITICAL (sender↔receiver confirmed)");
  check(res.target.paths?.length === 2 && res.portfolio?.length === 2, "multi-root target + portfolio present");
} else {
  check(false, "multi-root scan runs");
}

// ---------- 7) aux artifacts ----------
const art = join(tmp, "artifacts");
const r7 = run(["scan", join(root, "tests", "clean", "app"),
  "--format", "json", "--output", join(art, "findings.json"),
  "--sarif", join(art, "r.sarif"), "--html", join(art, "r.html"),
  "--compact", join(art, "r.compact.txt"), "--inventory", join(art, "inventory.json"),
  "--fix-prompt", join(art, "fix-prompt.md")]);
check(r7.status === 0, "aux artifact flags run");
for (const f of ["r.sarif", "r.html", "r.compact.txt", "inventory.json", "fix-prompt.md"]) {
  check(existsSync(join(art, f)) && readFileSync(join(art, f), "utf8").length > 10, `artifact written: ${f}`);
}
const inv = existsSync(join(art, "inventory.json")) ? JSON.parse(readFileSync(join(art, "inventory.json"), "utf8")) : null;
check(Boolean(inv?.routes?.length), "inventory lists routes");
const html = existsSync(join(art, "r.html")) ? readFileSync(join(art, "r.html"), "utf8") : "";
check(html.includes("Classes NOT covered") || html.includes("classes NOT covered"), "HTML carries the honesty contract");

// ---------- 8) --exclude / --max-files (v1.0.2) ----------
const exclDir = join(tmp, "excl-app");
mkdirSync(join(exclDir, "generated"), { recursive: true });
writeFileSync(join(exclDir, "generated", "gen.ts"), 'export const dbPass = "postgres://user:SuperSecret123@host/db";\n');
writeFileSync(join(exclDir, "open.ts"), 'export const productionDbUrl = "postgres://anubis_owner:AnotherSecret123@db.prod.anubis-internal:5432/proddb";\n');
const rEx1 = run(["scan", exclDir, "--exclude", "**/generated/**", "--format", "json"]);
if (rEx1.status === 0) {
  const jEx = JSON.parse(rEx1.stdout);
  check(jEx.findings.some((f) => f.file === "open.ts"), "--exclude: in-scope code still reported");
  check(!jEx.findings.some((f) => f.file.startsWith("generated/")), "--exclude: excluded file produces NO finding");
  check(Array.isArray(jEx.meta.excluded?.globs) && jEx.meta.excluded.globs.includes("**/generated/**") && jEx.meta.excluded.files === 1, "--exclude: meta.excluded lists globs + skipped count");
  check(jEx.meta.files_scanned === 1, "--exclude: excluded files counted out of files_scanned (never fed to rules/graph)");
} else check(false, `--exclude scan runs (exit 0, got ${rEx1.status})`);
const rEx2 = run(["scan", exclDir, "--exclude", "**/generated/**", "--format", "json"]);
check(rEx1.stdout === rEx2.stdout, "--exclude: byte-identical re-run with scope reduction (determinism holds)");
const rEx3 = run(["scan", exclDir, "--format", "json"]);
check(rEx3.status === 0 && rEx3.stdout !== rEx1.stdout && JSON.parse(rEx3.stdout).findings.some((f) => f.file.startsWith("generated/")), "no --exclude → default none, generated code is scanned");
const rEx4 = run(["scan", exclDir, "--exclude", "**/generated/**", "--format", "json", "--inventory", join(tmp, "ex-inv.json")]);
check(rEx4.status === 0 && !readFileSync(join(tmp, "ex-inv.json"), "utf8").includes("generated"), "--exclude: inventory/reachability never see excluded files");
const rMx1 = run(["scan", join(root, "tests", "honeypot", "app"), "--max-files", "5", "--format", "json", "--output", join(tmp, "no-partial.json")]);
check(rMx1.status === 2 && rMx1.stderr.includes("--max-files"), "--max-files: fail-closed exit 2 refusal");
check(!existsSync(join(tmp, "no-partial.json")), "--max-files: refusal writes NO report (no partial output ever)");
const rMx2 = run(["scan", join(root, "tests", "clean", "app"), "--max-files", "0", "--format", "json"]);
check(rMx2.status === 2, "--max-files 0: invalid value → exit 2");
const rMx3 = run(["scan", join(root, "tests", "clean", "app"), "--max-files", "100000", "--format", "json"]);
check(rMx3.status === 0, "--max-files generous cap: scan exits 0 (cap is opt-in only)");

console.log(failures ? `\nACCEPTANCE v0.2: ${failures} failure(s)` : "\nACCEPTANCE v0.2: ALL PASS");
process.exit(failures ? 1 : 0);
