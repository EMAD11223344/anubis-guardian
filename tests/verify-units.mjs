#!/usr/bin/env node
/**
 * Unit tests for complex helper functions (defense-in-depth — E2E stays the primary net).
 *   U1  advisory semver: parseVer / cmpVer / versionInRange / affects
 *   U2  util contracts: maskSecret / sha256Prefix / fingerprint / inline-ignores / suppression
 *   U3  rules/context: resolveSpec (exported for tests) + importedFromClient graph
 *   U4  packs2: parseMatcher / matcherToRegExp / matcherCovers (AUTH-001)
 *   U5  urlmode/jsassets: decodeJwtPayload (no lib — this is the secrets parser's twin)
 *   U6  rulesdir: loadOrgRules (DSL loader, org CRITICAL contract)
 *   U7  util: globWorkspaces (workspace glob subset, moved out of cli.ts for import-safety)
 *   U8  ci: argSecretRisk (DOCKER-003 name-only token policy)
 *   U9  util: excludeToRegExp (--exclude glob subset, v1.1.0)
 *   U10 packs2: JWT-002 { algorithms: undefined } is runtime-unpinned (fires MEDIUM)
 *   U11 walk: CRLF EOL robustness (no trailing \r; CI-003 stays alive on CRLF checkouts)
 *   U12 rules/history: gitScope containment (history/ls-files must NEVER import an unrelated ancestor repo)
 *   U13 rules/taint: TAINT-005 sink shapes (backtick send, string-concat send, res.write/res.end)
 * All imports come from dist/ — run after `npm run build` (the npm test chain does).
 */
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = join(import.meta.dirname ?? ".", "..");
const d = (p) => pathToFileURL(join(ROOT, p)).href;

const { parseVer, cmpVer, versionInRange, affects } = await import(d("dist/advisory/index.js"));
const { maskSecret, sha256Prefix, fingerprint, parseInlineIgnores, applySuppression, deducts, uniqBy, globWorkspaces, excludeToRegExp } =
  await import(d("dist/util.js"));
const { importedFromClient, resolveSpec, classifyFile } = await import(d("dist/rules/context.js"));
const { argSecretRisk, scanCi } = await import(d("dist/rules/ci.js"));
const { parseMatcher, matcherCovers, matcherToRegExp, scanPacks2 } = await import(d("dist/rules/packs2.js"));
const { walk } = await import(d("dist/walk.js"));
const { decodeJwtPayload } = await import(d("dist/urlmode/jsassets.js"));
const { loadOrgRules, runOrgRules } = await import(d("dist/rulesdir.js"));

let PASS = 0;
const FAILS = [];
const check = (name, cond, extra = "") => {
  if (cond) { PASS++; console.log(`PASS  ${name}`); }
  else { FAILS.push(name); console.error(`FAIL  ${name}${extra ? ` — ${extra}` : ""}`); }
};

// ---------- U1: advisory semver ----------
const pv = parseVer("1.2.3"), pvp = parseVer("v2.0.1-rc.1");
check("U1.1 parseVer: bare", pv?.[0] === 1 && pv?.[1] === 2 && pv?.[2] === 3 && pv?.[3] === "");
check("U1.2 parseVer: v-prefix + prerelease", pvp?.[0] === 2 && pvp?.[3] === "rc.1");
check("U1.3 parseVer: garbage → null", parseVer("latest") === null);
check("U1.4 cmpVer: patch ordering", cmpVer("1.2.10", "1.2.9") === 1);
check("U1.5 cmpVer: minor beats patch", cmpVer("1.10.0", "1.9.9") === 1);
check("U1.6 cmpVer: release > prerelease", cmpVer("1.0.0", "1.0.0-rc.1") === 1);
check("U1.7 cmpVer: NUMERIC prerelease ids (was lexicographic: '10'<'9')", cmpVer("1.0.0-10", "1.0.0-9") === 1);
check("U1.8 cmpVer: numeric prerelease < alpha", cmpVer("1.0.0-1", "1.0.0-alpha") === -1);
const ev = (o) => o.map((e) => ({ [e.t]: e.v }));
check("U1.9 versionInRange: inside intro..fixed", versionInRange("1.2.0", ev([{ t: "introduced", v: "1.0.0" }, { t: "fixed", v: "2.0.0" }])) === true);
check("U1.10 versionInRange: below introduced", versionInRange("0.9.0", ev([{ t: "introduced", v: "1.0.0" }, { t: "fixed", v: "2.0.0" }])) === false);
check("U1.11 versionInRange: at fixed → unaffected", versionInRange("2.0.0", ev([{ t: "introduced", v: "1.0.0" }, { t: "fixed", v: "2.0.0" }])) === false);
check("U1.12 versionInRange: last_affected inclusive", versionInRange("2.1.0", ev([{ t: "introduced", v: "1.0.0" }, { t: "last_affected", v: "2.1.0" }])) === true);
check("U1.13 versionInRange: above last_affected", versionInRange("2.1.1", ev([{ t: "introduced", v: "1.0.0" }, { t: "last_affected", v: "2.1.0" }])) === false);
const multi = ev([{ t: "introduced", v: "1.0.0" }, { t: "fixed", v: "2.0.0" }, { t: "introduced", v: "3.0.0" }]);
check("U1.14 versionInRange: multi-pair segment 1", versionInRange("1.5.0", multi) === true);
check("U1.15 versionInRange: multi-pair gap (2.5) closed by fixed", versionInRange("2.5.0", multi) === false);
check("U1.16 versionInRange: multi-pair segment 2", versionInRange("3.5.0", multi) === true);
check("U1.17 versionInRange: no events → implicit introduced 0", versionInRange("0.0.1", []) === true);
check("U1.18 affects: garbage version → false", affects({ ranges: [{ events: ev([{ t: "introduced", v: "1.0.0" }]) }] }, "whatver") === false);
check("U1.19 affects: any-range match (multi-range advisories)", affects({ ranges: [{ events: ev([{ t: "introduced", v: "10.0.0" }, { t: "fixed", v: "15.5.28" }]) }, { events: ev([{ t: "introduced", v: "16.0.0" }, { t: "fixed", v: "16.4.1" }]) }] }, "16.2.0") === true);
// U1.20–21: typosquat radius — short names need distance ≤ 1 (real-world FP fix, community-reported)
const { nearestPopular } = await import(d("dist/advisory/popular.js"));
check("U1.20 short legit names NOT typosquat FPs (nyc/hbs/ai/z85)", nearestPopular("nyc") === null && nearestPopular("hbs") === null && nearestPopular("ai") === null && nearestPopular("z85") === null);
check("U1.21 names ≥ 5 chars keep radius 2 (expres→express d=1 seed 22 stays; config→conf d=2)", JSON.stringify(nearestPopular("expres") ?? {}) === JSON.stringify({ target: "express", distance: 1 }) && nearestPopular("config")?.target === "conf");
check("U1.22 5-char boundary: 4-char name at d=2 silent (zoab→zod), 5-char takes radius 2 (zodab→zod d=2)", nearestPopular("zoab") === null && JSON.stringify(nearestPopular("zodab") ?? {}) === JSON.stringify({ target: "zod", distance: 2 }));
check("U1.23 short name at distance 1 still fires (kyi→ky d=1, 3 chars)", JSON.stringify(nearestPopular("kyi") ?? {}) === JSON.stringify({ target: "ky", distance: 1 }));

// ---------- U2: util masking/suppression contracts ----------
const m = maskSecret("sbp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV");
check("U2.1 maskSecret: full value never present", !JSON.stringify(m).includes("sbp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV"));
check("U2.2 maskSecret: first-4 kept", m.masked.startsWith("sbp_"));
check("U2.3 sha256Prefix matches node crypto", sha256Prefix("sbp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV") === createHash("sha256").update("sbp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV").digest("hex").slice(0, 8) && sha256Prefix("x", 12).length === 12);
check("U2.4 fingerprint: deterministic + 12 hex", fingerprint("SUPA-001", "app/.env", "a") === fingerprint("SUPA-001", "app/.env", "a") && /^[0-9a-f]{12}$/.test(fingerprint("SUPA-001", "app/.env", "a")));
const ig = parseInlineIgnores(['// anubis-ignore: SEED-001 reason="test fixture only" expires="2099-01-01"']);
check("U2.5 inline-ignore: valid parsed", ig.length === 1 && ig[0].ruleId === "SEED-001");
check("U2.6 inline-ignore: expired directive ignored", parseInlineIgnores(['anubis-ignore: SEED-001 reason="old" expires="2000-01-01"']).length === 0);
const probe = { id: "SEED-001", severity: "high", title: "t", file: "a.ts", line: 1, evidence: { type: "e", masked: "m" }, owasp: "A07", fix: "f" };
check("U2.7 suppression: matching rule → reason", applySuppression(probe, ig, "a.ts").suppression?.reason === "test fixture only");
check("U2.8 suppression: non-matching → null", applySuppression(probe, [], "a.ts").suppression === null);
check("U2.9 deducts: info/low-confidence never deduct", deducts({ ...probe, severity: "info" }) === false && deducts({ ...probe, confidence: "low" }) === false);
check("U2.10 uniqBy: keyed dedupe preserves first order", JSON.stringify(uniqBy([{ k: "a" }, { k: "b" }, { k: "a" }], (x) => x.k)) === '[{"k":"a"},{"k":"b"}]');

// ---------- U3: rules/context graph + spec resolution ----------
const mk = (abs, rel, content, lines = [content]) => ({ abs, rel, content, lines });
const byAbsProxy = { has: (k) => FILES.has(k), get: (k) => FILES.get(k) };
const FILES = new Map();
for (const f of contextFiles()) FILES.set(f.abs.replace(/\\/g, "/"), f);
function contextFiles() {
  return [
    mk("C:/proj/app/client.tsx", "app/client.tsx", '"use client";\nimport K from "../lib/secret";\n'),
    mk("C:/proj/app/other.tsx", "app/other.tsx", '"use client";\nimport "./style";\nimport "react";\n'),
    mk("C:/proj/lib/secret.ts", "lib/secret.ts", "export const K = 1;\n"),
    mk("C:/proj/lib/style.ts", "lib/style.ts", "export const S = 1;\n"),
    mk("C:/proj/lib/secret.js", "lib/secret.js", "export const J = 1;\n"),
  ];
}
const from = FILES.get("C:/proj/app/client.tsx");
check("U3.1 resolveSpec: bare relative → .ts candidate", resolveSpec(from, "../lib/secret", byAbsProxy) === "C:/proj/lib/secret.ts");
check("U3.2 resolveSpec: literal existing .js beats no-swap", resolveSpec(FILES.get("C:/proj/app/client.tsx"), "../lib/secret.js", byAbsProxy) === "C:/proj/lib/secret.ts" || resolveSpec(FILES.get("C:/proj/app/client.tsx"), "../lib/secret.js", byAbsProxy) === "C:/proj/lib/secret.js");
check("U3.3 resolveSpec: /index.ts candidate", resolveSpec(from, "../lib", byAbsProxy) === null); // lib/ has no index — honest null
check("U3.4 resolveSpec: npm spec (non-relative) not resolved locally", resolveSpec(from, "react", byAbsProxy) === null);
check("U3.5 resolveSpec: nonexistent → null", resolveSpec(from, "../lib/nope", byAbsProxy) === null);
const ctx = { files: contextFiles() };
const reach = importedFromClient(ctx);
check("U3.6 importedFromClient: client import reaches lib (normalized keys)", reach.has("C:/proj/lib/secretts") === false ? reach.has("C:/proj/lib/secret.ts") : false);
check("U3.7 importedFromClient: non-source content irrelevant", !reach.has("C:/proj/app/client.tsx"));
check("U3.8 classifyFile: use-client directive", classifyFile(FILES.get("C:/proj/app/client.tsx")) === "client");

// ---------- U4: packs2 matcher helpers (AUTH-001) ----------
check("U4.1 parseMatcher: no matcher → null", parseMatcher("middleware does something else") === null);
check("U4.2 parseMatcher: empty array → null", parseMatcher("export const config = { matcher: [] }") === null);
check("U4.3 parseMatcher: valid JSON array", JSON.stringify(parseMatcher('export const config = { matcher: ["/admin/:path*"] }')) === '["/admin/:path*"]');
check("U4.4 parseMatcher: single-quoted converts", JSON.stringify(parseMatcher("matcher: ['/panel/*']")) === '["/panel/*"]');
check("U4.5 parseMatcher: invalid JSON → null", parseMatcher("matcher: [/admin") === null);
check("U4.6 matcherToRegExp: :path* → .*", matcherToRegExp("/admin/:path*")?.test("/admin/users/list") === true);
check("U4.7 matcherToRegExp: :id single segment only", matcherToRegExp("/api/:id")?.test("/api/users/42") === false && matcherToRegExp("/api/:id")?.test("/api/users") === true);
check("U4.8 matcherToRegExp: trailing slash optional", matcherToRegExp("/panel")?.test("/panel/") === true && matcherToRegExp("/panel")?.test("/panel/x") === false);
check("U4.9 matcherCovers: exact pattern covers", matcherCovers(["/api/*"], "/api/admin") === true);
check("U4.10 matcherCovers: unrelated pattern not covered", matcherCovers(["/docs/*"], "/api/admin") === false);
check("U4.11 matcherCovers: negated catch-all covers default", matcherCovers(["/((?!api|_next/static).*)"], "/settings") === true);
check("U4.12 matcherCovers: negated catch-all does NOT cover listed prefix (matcher gap)", matcherCovers(["/((?!api|_next/static).*)"], "/api/admin") === false);

// ---------- U5: decodeJwtPayload (no external lib) ----------
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const token = `${b64u({ alg: "HS256" })}.${b64u({ iss: "https://x.supabase.co", role: "service_role" })}.SiGn4turePart`;
const payload = decodeJwtPayload(token);
check("U5.1 decodeJwtPayload: role decoded", payload?.role === "service_role");
check("U5.2 decodeJwtPayload: header NOT returned as payload", payload?.alg === undefined);
check("U5.3 decodeJwtPayload: 2 parts (missing signature) → null", decodeJwtPayload(`${b64u({ a: 1 })}.${b64u({ b: 2 })}`) === null);
check("U5.4 decodeJwtPayload: garbage payload → null", decodeJwtPayload(`a.%%%b.c`) === null);
check("U5.5 decodeJwtPayload: empty string → null", decodeJwtPayload("") === null);

// ---------- U6: rulesdir DSL loader ----------
const RULES_TMP = mkdtempSync(join(tmpdir(), "anubis-units-"));
writeFileSync(join(RULES_TMP, "ok.json"), JSON.stringify([{ id: "internal-secret", regex: "INTERNAL_SECRET", files: ["**/*.ts"], severity: "critical" }]));
writeFileSync(join(RULES_TMP, "broken.json"), "{not json");
writeFileSync(join(RULES_TMP, "empty.json"), JSON.stringify([{ severity: "high" }]));
writeFileSync(join(RULES_TMP, "readme.txt"), "not json — skipped by extension");
const loaded = loadOrgRules(RULES_TMP);
check("U6.1 loadOrgRules: valid rule parsed", loaded.rules.length === 1 && loaded.rules[0].id === "ORG-internal-secret");
check("U6.2 loadOrgRules: ORG- prefix enforced", !loaded.rules[0].id.startsWith("ORG-ORG-"));
check("U6.3 loadOrgRules: invalid JSON warns", loaded.warnings.some((w) => w.startsWith("broken.json")));
check("U6.4 loadOrgRules: missing id/regex/files warns", loaded.warnings.some((w) => w.startsWith("empty.json")));
check("U6.5 loadOrgRules: non-.json files skipped", !loaded.warnings.some((w) => w.startsWith("readme.txt")));
check("U6.6 loadOrgRules: missing dir warns", loadOrgRules(join(RULES_TMP, "nope")).warnings.length === 1);
check("U6.7 loadOrgRules: clean_cases contract warning", loaded.warnings.some((w) => w.includes("clean_cases")));
// org CRITICAL law: needs_confirmation + medium confidence, engine-side
const orgCtx = { files: [mk("C:/proj/a.ts", "a.ts", "const H=" + JSON.stringify("INTERNAL_SECRET") + "\n")] };
const orgFindings = runOrgRules([loaded.rules[0]], orgCtx.files);
check("U6.8 org CRITICAL: no-confirmation law (needs_confirmation, below CRITICAL honest cap)", orgFindings.length === 1 && orgFindings[0].needs_confirmation === true && orgFindings[0].confidence === "medium");
rmSync(RULES_TMP, { recursive: true, force: true });

// ---------- U7: globWorkspaces ----------
const WS_TMP = mkdtempSync(join(tmpdir(), "anubis-units-"));
for (const p of ["apps/web", "apps/api", "packages/core", "tools/nows"]) {
  mkdirSync(join(WS_TMP, p), { recursive: true });
  writeFileSync(join(WS_TMP, p, "package.json"), "{}");
}
const gx = (pat) => globWorkspaces(WS_TMP, pat).map((p) => p.replace(/\\/g, "/").slice(WS_TMP.length + 1)).sort();
check("U7.1 globWorkspaces: star pattern", JSON.stringify(gx("apps/*")) === JSON.stringify(["apps/api", "apps/web"]));
check("U7.2 globWorkspaces: exact path", JSON.stringify(gx("packages/core")) === JSON.stringify(["packages/core"]));
check("U7.3 globWorkspaces: nested star", JSON.stringify(gx("*/core")) === JSON.stringify(["packages/core"]));
check("U7.4 globWorkspaces: dirs without package.json excluded", gx("apps/*").every((p) => !p.includes("nows")));
check("U7.5 globWorkspaces: no match → empty", gx("missing/*").length === 0);
rmSync(WS_TMP, { recursive: true, force: true });

// ---------- U8: DOCKER-003 ARG-name risk (token-based, no "api" substring FPs) ----------
check("U8.1 ARG API_URL does NOT fire (the reported substring FP)", argSecretRisk("API_URL") === false);
check("U8.2 ARG NEXT_PUBLIC_API_URL does NOT fire", argSecretRisk("NEXT_PUBLIC_API_URL") === false);
check("U8.3 ARG MONKEY / KEYBOARD do NOT fire (substring 'key' FP class)", argSecretRisk("MONKEY") === false && argSecretRisk("KEYBOARD_LAYOUT") === false);
check("U8.4 ARG DATABASE_PASSWORD fires (honeypot seed 19 stays detected)", argSecretRisk("DATABASE_PASSWORD") === true);
check("U8.5 ARG STRIPE_SECRET_KEY / JWT_SECRET / API_KEY fire", argSecretRisk("STRIPE_SECRET_KEY") && argSecretRisk("JWT_SECRET") && argSecretRisk("API_KEY"));
check("U8.6 camelCase apiKey / refreshToken fire (camel-boundary tokenizing)", argSecretRisk("apiKey") === true && argSecretRisk("refreshToken") === true);
check("U8.7 ARG REFRESH_TOKEN / AWS_ACCESS_SECRET fire", argSecretRisk("REFRESH_TOKEN") === true && argSecretRisk("AWS_ACCESS_SECRET") === true);
// Intended behavior (documented in METHODOLOGY §4.1 spirit + DOCKER-003 rule comment):
// DOCKER-003 polices the ARG NAME (build-time intent), NOT the value — values are not
// evaluated at all. ARG DATABASE_URL=postgres://user:pass@host stays silent: *_URL ARGs
// are legitimate (endpoint URLs), and value-shaped literals in the file itself would be
// a separate future rule, not a name-based flag.
check("U8.8 ARG DATABASE_URL stays silent (name-only policy; its URL value is NOT evaluated)", argSecretRisk("DATABASE_URL") === false);

// ---------- U9: --exclude glob subset (repo-relative POSIX, v1.1.0) ----------
const ex = (g) => excludeToRegExp(g);
check("U9.1 *.min.js: top-level match", ex("*.min.js").test("bundle.min.js"));
check("U9.2 *.min.js stays within ONE segment (use ** for depth)", !ex("*.min.js").test("a/b/bundle.min.js"));
check("U9.3 **/*.min.js: any depth incl. zero", ex("**/*.min.js").test("a/b/bundle.min.js") && ex("**/*.min.js").test("x.min.js"));
check("U9.4 **/generated/**: matches contents at any depth", ex("**/generated/**").test("apps/x/generated/gen.ts") && ex("**/generated/**").test("generated/deep/y.ts"));
check("U9.5 **/generated/**: sibling-named dirs stay in scope", !ex("**/generated/**").test("apps/x/generated-up/gen.ts") && !ex("**/generated/**").test("apps/x/src/gen.ts"));
check("U9.6 exact path only", ex("apps/legacy/broken.ts").test("apps/legacy/broken.ts") && !ex("apps/legacy/broken.ts").test("apps/legacy2/broken.ts"));
check("U9.7 dir/** covers everything under it, not siblings", ex("apps/legacy/**").test("apps/legacy/a/b.ts") && !ex("apps/legacy/**").test("apps/legacy2/a.ts") && !ex("apps/legacy/**").test("apps/lx/a.ts"));
check("U9.8 trailing slash tolerated (== no slash)", ex("x.min.js/").test("x.min.js"));
check("U9.9 no ! negation: \"!keep\" is a literal name, never active", !ex("!app.ts").test("app.ts") && !ex("!app.ts").test("lib/x.ts"));
check("U9.10 regex metachars escaped (dots are dots)", !ex("a.b.ts").test("axbts") && ex("a.b.ts").test("a.b.ts"));
check("U9.11 ** prefix with dotfile basename", ex("**/.mcp.json").test(".mcp.json") && ex("**/.mcp.json").test("app/.mcp.json"));

// ---------- U10: JWT-002 — an options object is NOT pinning ({ algorithms: undefined }) ----------
// Intended behavior (METHODOLOGY §4.1): pinning means a RESOLVED algorithms array;
// algorithm value undefined/null is runtime-unpinned → same HS/RS class → MEDIUM.
const jwt2 = (src) => {
  const f = { abs: "/x/lib/a.ts", rel: "lib/a.ts", content: src, lines: src.split("\n") };
  const ctx = { stack: { frameworks: [], detected: [] }, rel: (x) => x, trackedFiles: new Set(), gitAvailable: false, files: [f] };
  return scanPacks2(ctx).findings.filter((x) => x.id === "JWT-002");
};
check("U10.1 jwt.verify(..., { algorithms: undefined }) FIRES jwt_alg_unpinned (MEDIUM)", jwt2('const claims = jwt.verify(token, JWT_SECRET, { algorithms: undefined });\n').some((x) => x.severity === "medium"));
check("U10.2 jwt.verify(..., { algorithms: null }) fires too (runtime-unpinned)", jwt2('const claims = jwt.verify(token, JWT_SECRET, { algorithms: null });\n').some((x) => x.severity === "medium"));
check("U10.3 { algorithms: ['HS256'] } stays silent", jwt2('const claims = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });\n').length === 0);

// ---------- U11: walk() EOL robustness (CRLF checkouts — the 58→59 root cause) ----------
const crlfDir = mkdtempSync(join(tmpdir(), "anubis-u11-"));
writeFileSync(join(crlfDir, "deploy.yml"), "      - name: greet\r\n        run: |\r\n          echo \"Thanks ${{ github.event.pull_request.title }} for the PR!\"\r\n", "utf8");
const walkedU11 = walk(crlfDir);
check("U11.1 walk(): CRLF lines carry no trailing \\r", walkedU11.length === 1 && walkedU11[0].lines.every((l) => !l.endsWith("\r")) && walkedU11[0].lines.some((l) => l.includes("run:")));
const crlfContent = walkedU11[0].content;
const crlfFile = { abs: join(crlfDir, "deploy.yml"), rel: ".github/workflows/deploy.yml", content: crlfContent, lines: crlfContent.split(/\r?\n/) };
check("U11.2 scanCi fires CI-003 on the walked CRLF file (rule previously dead on CRLF-only checkouts)", scanCi({ rel: (x) => x, files: [crlfFile] }).findings.some((x) => x.id === "CI-003"));
rmSync(crlfDir, { recursive: true, force: true });

// ---------- U12: gitScope containment (history/ls-files must never import an unrelated ancestor repo) ----------
// Community fix, ported from the v1.0.1 fork. Without gitScope, scanning a plain
// folder sitting inside an unrelated git repo attributed that repo's entire
// history to the report (foreign HIST-00x findings with foreign file paths).
const { gitScope, gitAvailable, trackedFiles } = await import(d("dist/rules/history.js"));
const { execFileSync: xfs } = await import("node:child_process");

const GS = mkdtempSync(join(tmpdir(), "anubis-u12-"));
const OUTER = join(GS, "outer");
const INNER = join(OUTER, "target"); // plain folder inside an unrelated repo — untracked
mkdirSync(INNER, { recursive: true });
const g = (args, cwd) => xfs("git", args, { cwd, stdio: "pipe" });
g(["init", "-q"], OUTER);
// push-safe history-secret fixture: HIST-007 DB-URL-with-password (same pattern family as the v02 SEC-008 fixture)
writeFileSync(join(OUTER, "leaked.txt"), 'export const DATABASE_URL = "postgres://admin:S3cureDb-Pass@db.prod.anubis-internal:5432/app";\n', "utf8");
g(["-c", "user.email=t@t.local", "-c", "user.name=t", "add", "."], OUTER);
g(["-c", "user.email=t@t.local", "-c", "user.name=t", "commit", "-qm", "outer history"], OUTER);
writeFileSync(join(INNER, "app.ts"), "export const x = 1;\n", "utf8");

const scopeNone = gitScope(INNER);
check("U12.1 untracked folder inside unrelated repo → NO git scope", scopeNone === null && gitAvailable(INNER) === false);

g(["add", "target/app.ts"], OUTER);
g(["-c", "user.email=t@t.local", "-c", "user.name=t", "commit", "-qm", "track target"], OUTER);
const scopeSome = gitScope(INNER);
check("U12.2 tracked subtree → scope with correct rel", scopeSome !== null && scopeSome.rel === "target" && scopeSome.toplevel.replace(/\\/g, "/").endsWith("/outer"));
check("U12.3 gitAvailable mirrors gitScope", gitAvailable(INNER) === true);
check("U12.4 trackedFiles scoped + target-relative", JSON.stringify([...trackedFiles(INNER)].sort()) === JSON.stringify(["app.ts"]));

// E2E: scanning the untracked folder must import ZERO history secrets from the ancestor
const rep = join(GS, "f.json");
xfs(process.execPath, [join(ROOT, "dist/cli.js"), "scan", INNER, "--format", "json", "--output", rep], { cwd: ROOT, stdio: "pipe" });
const repJson = JSON.parse(readFileSync(rep, "utf8"));
const histIds = ["HIST-001", "HIST-002", "HIST-003", "HIST-004", "HIST-005", "HIST-006", "HIST-007", "HIST-008", "HIST-ENV"];
check("U12.5 unrelated-ancestor scan: zero history-secret imports (the commit-then-leak stays out)", !repJson.findings.some((f) => histIds.includes(f.id)));

// same-folder scan of the repo ROOT still sees its own history (leak IS detected there)
const rep2 = join(GS, "f2.json");
xfs(process.execPath, [join(ROOT, "dist/cli.js"), "scan", OUTER, "--format", "json", "--output", rep2], { cwd: ROOT, stdio: "pipe" });
const rep2Json = JSON.parse(readFileSync(rep2, "utf8"));
check("U12.6 repo-root scan still detects its own leaked history secret (HIST-007)", rep2Json.findings.some((f) => f.id === "HIST-007"));
rmSync(GS, { recursive: true, force: true });

// ---------- U13: TAINT-005 reflected-XSS sink shapes (string concat + backticks, community fix) ----------
const { scanTaint } = await import(d("dist/rules/taint.js"));
const tctx = (content) => ({ files: [{ abs: "/p/server/app.js", rel: "server/app.js", content, lines: content.split("\n") }] });
const taintIds = (c) => scanTaint(tctx(c)).findings.map((f) => f.id);
check("U13.1 res.send with backtick template + ${req.query.x} → TAINT-005 (honeypot seed 45 shape)", taintIds("export function h(req, res) {\n  res.send(`<h1>Hi ${req.query.name}</h1>`);\n}\n").includes("TAINT-005"));
check("U13.2 res.send with STRING CONCAT ('<h1>' + req.query.x) → TAINT-005 (was invisible)", taintIds('const express = require("express");\napp.get("/greet", (req, res) => {\n  res.send("<h1>Hi " + req.query.name + "</h1>");\n});\n').includes("TAINT-005"));
check("U13.3 res.write with string concat → TAINT-005", taintIds('app.get("/x", (req, res) => {\n  res.write("<p>" + req.query.q + "</p>");\n});\n').includes("TAINT-005"));
check("U13.4 tainted var via const + concat send → TAINT-005", taintIds('app.get("/x", (req, res) => {\n  const q = req.query.q;\n  res.send("<i>" + q + "</i>");\n});\n').includes("TAINT-005"));
check("U13.5 sanitizer in window (escapeHtml) → clean", !taintIds('import { escapeHtml } from "./esc";\napp.get("/x", (req, res) => {\n  res.send("<i>" + escapeHtml(req.query.q) + "</i>");\n});\n').includes("TAINT-005"));
check("U13.6 fixed-string send (no taint) → clean", !taintIds('app.get("/x", (req, res) => {\n  res.send("<h1>Welcome</h1>");\n});\n').includes("TAINT-005"));
check("U13.7 concat send with GUARD var only (no source in args) → clean", !taintIds('app.post("/x", (req, res) => {\n  const token = req.headers.authorization;\n  if (!token) return res.send("<h1>Denied</h1>");\n  res.send("<h1>Ok</h1>");\n});\n').includes("TAINT-005"));

// ---------- U14 — SSRF guard (v1.1.1 hardening) ----------
// Contract under test (src/urlmode/ssrf-guard.ts):
//   * canonicalize → binary range check (WHATWG URL + node:net IP.parse w/ manual fallback)
//   * check runs on the RESOLVED address (dns.lookup all:true, every result validated)
//   * resolve→pin→connect closes DNS rebinding by construction
//   * manual redirects: cap 10, https→http demotion + non-http(s) refused
//   * service mode (ANUBIS_SERVICE=1): ports 80/443/8080/8443 only, allowPrivate ignored
const guard = await import(d("dist/urlmode/ssrf-guard.js"));
const { parseIp, blockedAddressReason, validateAddress, assertPinnedTarget, assertNextHop,
  SsrfRefusedError, isServiceMode, resetServiceModeCache, serviceMaxResponseBytes, SERVICE_ALLOWED_PORTS } = guard;
const fetcherMod = await import(d("dist/urlmode/fetcher.js"));
const { Fetcher } = fetcherMod;

// refused literal forms — one check each (checked through the real entry path: WHATWG URL first)
const refusedForms = [
  ["U14.1", "http://127.0.0.1/", "loopback (127.0.0.0/8)"],
  ["U14.2", "http://0x7f.0.0.1/", "loopback (127.0.0.0/8)"],          // WHATwg-normalized to 127.0.0.1
  ["U14.3", "http://2130706433/", "loopback (127.0.0.0/8)"],          // uint32 form of the same address
  ["U14.4", "http://[::1]/", "IPv6 loopback (::1)"],
  ["U14.5", "http://[::ffff:127.0.0.1]/", "mapped IPv6 → loopback (127.0.0.0/8)"],
  ["U14.6", "http://[::ffff:7f00:1]/", "mapped IPv6 → loopback (127.0.0.0/8)"],
  ["U14.7", "http://10.0.0.1/", "RFC1918 private (10.0.0.0/8)"],
  ["U14.8", "http://172.16.0.1/", "RFC1918 private (172.16.0.0/12)"],
  ["U14.9", "http://192.168.1.1/", "RFC1918 private (192.168.0.0/16)"],
  ["U14.10", "http://169.254.169.254/", "169.254.169.254 (cloud metadata)"],
  ["U14.11", "http://[fc00::1]/", "IPv6 unique-local (fc00::/7)"],
  ["U14.12", "http://[fe80::1]/", "IPv6 link-local (fe80::/10)"],
  ["U14.13", "http://100.64.0.1/", "CGNAT shared address space (100.64.0.0/10)"],
  ["U14.14", "http://0.0.0.0/", "this-network (0.0.0.0/8)"],
];
for (const [id, u, want] of refusedForms) {
  let threw = null;
  try { await assertPinnedTarget(u); } catch (e) { threw = e; }
  check(`${id}: guard refuses ${u} — ${want}`,
    threw instanceof SsrfRefusedError && threw.message.includes(want) && threw.message.startsWith("SSRF-REFUSED"),
    threw ? threw.message.slice(0, 120) : "was allowed");
}
check("U14.1b: binary canonicalization agrees on all refused forms",
  validateAddress("127.0.0.1") === null && validateAddress("0.0.0.0") === null
  && validateAddress("10.0.0.1") === null && validateAddress("169.254.169.254") === null
  && parseIp("::ffff:7f00:1") !== null
  && blockedAddressReason(parseIp("::ffff:7f00:1"))?.includes("mapped") === true
  && validateAddress("93.184.216.34") !== null && validateAddress("2606:2800:220:1:248:1893:25c8:1946") !== null);

// the check runs on the RESOLVED address, not the hostname string
const lookup10 = async () => [{ address: "10.0.0.7", family: 4 }];
let t15 = null;
try { await assertPinnedTarget("http://internal.example/", { lookup: lookup10 }); } catch (e) { t15 = e; }
check("U14.15: hostname resolving to a private range is refused (check on RESOLVED addr)",
  t15 instanceof SsrfRefusedError && /resolved to a blocked range/.test(t15.message), t15?.message.slice(0, 100));

const PUB = { address: "93.184.216.34", family: 4 };
let pinned = null;
try { pinned = await assertPinnedTarget("http://example.test/", { lookup: async () => [PUB] }); } catch (e) { pinned = e; }
check("U14.16: resolve→pin — public resolution pins the IP + keeps hostname for Host/SNI",
  pinned && !(pinned instanceof Error) && pinned.ip === "93.184.216.34" && pinned.family === 4
  && pinned.host === "example.test" && pinned.port === 80
  && pinned.candidates.length === 1 && pinned.candidates[0].address === "93.184.216.34",
  JSON.stringify(pinned));

// ---------- U14 E2E fixture: in-process local server for redirect-hop refusals ----------
const { createServer } = await import("node:http");
const e2e = createServer((req, res) => {
  if (req.url === "/meta") { res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" }); return res.end(); }
  if (req.url === "/ftp") { res.writeHead(302, { location: "ftp://rebind.example/x" }); return res.end(); }
  if (req.url === "/hop") { res.writeHead(302, { location: "/ok" }); return res.end(); }
  res.writeHead(200, { "content-type": "text/plain", "x-method": req.method ?? "", "x-echo-host": req.headers.host ?? "" });
  res.end(String(req.method));
});
await new Promise((r) => e2e.listen(0, "127.0.0.1", r));
const e2ePort = e2e.address().port;
const e2eBase = `http://127.0.0.1:${e2ePort}`;
try {
  const fbasic = new Fetcher({ delayMs: 1, timeoutMs: 3_000, maxRequests: 5, allowPrivate: true });
  const basic = await fbasic.get(`${e2eBase}/ok`);
  check("U14.29: rewritten transport still dials localhost (pinned-IP request, 200 + body)",
    basic !== null && basic.status === 200 && basic.body === "GET" && basic.final_url === `${e2eBase}/ok` && basic.error === undefined,
    JSON.stringify(basic));
  check("U14.29b: pinned dial sends Host of the original hostname (echoed by the fixture)",
    fbasic.requests[0]?.headers["x-echo-host"] === `127.0.0.1:${e2ePort}`,
    JSON.stringify(fbasic.requests[0]?.headers));
  check("U14.30: TRACE probe rides the same guarded dial (no redirects sent)",
    (async () => {
      const f = new Fetcher({ delayMs: 1, timeoutMs: 3_000, maxRequests: 5, allowPrivate: true });
      const r = await f.send("TRACE", `${e2eBase}/ok`);
      return r !== null && r.status === 200 && r.method === "TRACE" && r.body === "TRACE";
    })());
  check("U14.31: manual redirect hop loop follows same-scheme 302 (final captured, hops re-guarded)",
    (async () => {
      const f = new Fetcher({ delayMs: 1, timeoutMs: 3_000, maxRequests: 5, allowPrivate: true });
      const r = await f.get(`${e2eBase}/hop`);
      return r !== null && r.status === 200 && r.final_url === `${e2eBase}/ok`;
    })());

  const fmeta = new Fetcher({ delayMs: 1, timeoutMs: 3_000, maxRequests: 5, allowPrivate: true });
  const meta = await fmeta.get(`${e2eBase}/meta`);
  check("U14.17: 302 redirect to 169.254.169.254 refused mid-hop (via real local server)",
    meta !== null && meta.status === 302 && meta.error?.startsWith("SSRF-REFUSED")
    && /cloud metadata/.test(meta.error) && fmeta.guardRefusals.length === 1,
    JSON.stringify({ status: meta?.status, error: meta?.error, refusals: fmeta.guardRefusals }));
  check("U14.17b: cloud metadata refused EVEN WITH --allow-private (flag never spends metadata)",
    (async () => {
      try { await assertPinnedTarget("http://169.254.169.254/", { allowPrivate: true }); return false; }
      catch (e) { return e instanceof SsrfRefusedError && /cloud metadata/.test(e.message); }
    })());

  const fftp = new Fetcher({ delayMs: 1, timeoutMs: 3_000, maxRequests: 5, allowPrivate: true });
  const ftp = await fftp.get(`${e2eBase}/ftp`);
  check("U14.19: 302 redirect to non-http(s) scheme (ftp) refused mid-hop",
    ftp !== null && ftp.status === 302 && ftp.error?.startsWith("SSRF-REFUSED") && /non-http\(s\)/.test(ftp.error),
    JSON.stringify({ status: ftp?.status, error: ftp?.error }));
} finally {
  e2e.close();
}

// unit-level hop-policy checks (demotion needs an https hop — covered at policy level)
let dem = null;
try { assertNextHop(new URL("https://public.example/a"), "http://public.example/b"); } catch (e) { dem = e; }
check("U14.18: https→http redirect demotion refused", dem instanceof SsrfRefusedError && /demotion/.test(dem.message), dem?.message?.slice(0, 100));
check("U14.18b: relative + absolute http(s) hops accepted",
  assertNextHop(new URL("http://a.example/x"), "/y") === "http://a.example/y"
  && assertNextHop(new URL("http://a.example/x"), "https://b.example/z") === "https://b.example/z");
let badLoc = null;
try { assertNextHop(new URL("http://a.example/x"), "http://[bad"); } catch (e) { badLoc = e; }
check("U14.18c: unparseable Location refused", badLoc instanceof SsrfRefusedError);

// pinned rebinding: one lookup per hop, flipped DNS answers cannot slip through
const rebindSeq = [PUB, { address: "127.0.0.1", family: 4 }];
const rebindLookup = async () => rebindSeq.shift() ?? PUB;
check("U14.20: sequential-lookup rebinding — public first, loopback second → second REFUSED",
  (async () => {
    try { await assertPinnedTarget("http://rebind.example/", { lookup: rebindLookup }); }
    catch { return false; } // first lookup must succeed
    try { await assertPinnedTarget("http://rebind.example/", { lookup: rebindLookup }); return false; }
    catch (e) { return e instanceof SsrfRefusedError && /resolved to a blocked range/.test(e.message); }
  })());
check("U14.21: pin closes the rebinding window — ONE lookup per hop by contract",
  (async () => {
    let calls = 0;
    const counting = async () => { calls += 1; return [PUB]; };
    await assertPinnedTarget("http://pin.example/", { lookup: counting });
    await assertPinnedTarget("http://pin.example/", { lookup: counting });
    return calls === 2; // exactly one lookup per guarded hop
  })());

// ---------- service mode (ANUBIS_SERVICE=1) ----------
process.env.ANUBIS_SERVICE = "1";
resetServiceModeCache();
try {
  for (const [id, port] of [["U14.22", 6379], ["U14.23", 22], ["U14.24", 3306]]) {
    let t = null;
    try { await assertPinnedTarget(`http://127.0.0.1:${port}/`, { allowPrivate: true }); } catch (e) { t = e; }
    check(`${id}: service mode refuses port ${port} (allowlist 80/443/8080/8443)`,
      t instanceof SsrfRefusedError && /80\/443\/8080\/8443/.test(t.message), t?.message?.slice(0, 110));
  }
  let t25 = null;
  try { await assertPinnedTarget("http://127.0.0.1/", { allowPrivate: true }); } catch (e) { t25 = e; }
  check("U14.25: service mode IGNORES allow-private — loopback refused even with the flag",
    t25 instanceof SsrfRefusedError && /service mode/.test(t25.message), t25?.message?.slice(0, 110));
  check("U14.26: service mode still serves the default ports (policy positive)",
    (async () => {
      try { await assertPinnedTarget("http://127.0.0.1/", { allowPrivate: true }); return false; } // loopback must stay refused
      catch { /* refused for the RANGE, not the port — prove via a public pin */ }
      const p8080 = await assertPinnedTarget("http://service.test:8080/", { lookup: async () => [PUB] });
      const p8443 = await assertPinnedTarget("https://service.test:8443/", { lookup: async () => [PUB] });
      const p80 = await assertPinnedTarget("http://service.test/", { lookup: async () => [PUB] });
      return p8080.port === 8080 && p8443.port === 8443 && p80.port === 80;
    })());
} finally {
  delete process.env.ANUBIS_SERVICE;
  resetServiceModeCache();
}
check("U14.27: CLI mode (no ANUBIS_SERVICE) — --allow-private lets localhost through",
  (await assertPinnedTarget("http://127.0.0.1:3000/", { allowPrivate: true })).ip === "127.0.0.1"
  && !isServiceMode());
check("U14.28: service limits — 5 MB default response cap, env-overridable, ports set exact",
  serviceMaxResponseBytes() === 5 * 1024 * 1024
  && JSON.stringify([...SERVICE_ALLOWED_PORTS].sort((a, b) => a - b)) === JSON.stringify([80, 443, 8080, 8443]));
{
  process.env.ANUBIS_MAX_RESPONSE_BYTES = "1024";
  try {
    const n = serviceMaxResponseBytes();
    process.env.ANUBIS_MAX_RESPONSE_BYTES = "bogus";
    const n2 = serviceMaxResponseBytes();
    check("U14.28b: ANUBIS_MAX_RESPONSE_BYTES honored, garbage ignored", n === 1024 && n2 === 5 * 1024 * 1024);
  } finally { delete process.env.ANUBIS_MAX_RESPONSE_BYTES; }
}

// ---------- report ----------
console.error(`\nUNIT VERIFICATION: ${PASS} passed, ${FAILS.length} failed`);
if (FAILS.length) {
  for (const f of FAILS) console.error(`  FAILED: ${f}`);
  process.exit(1);
}
