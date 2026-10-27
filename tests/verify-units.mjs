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

// ---------- U15: rules/valueclass — shared secret-VALUE classifier (v1.2 T2/T3) ----------
const vc = await import(d("dist/rules/valueclass.js"));
{
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const SERVICE_ROLE = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "https://abcdefghij1234567890.supabase.co/auth/v1", ref: "abcdefghij1234567890", role: "service_role" })}.SiGn4tureP4rtW1thM0reTh4nTenCh4r4cters`;
  const ANON = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "https://abcdefghij1234567890.supabase.co/auth/v1", ref: "abcdefghij1234567890", role: "anon" })}.An0nS1gn4tureP4rtW1thM0reTh4nTenCh4rs`;

  check("U15.1 jwtRole re-export agrees with jsassets (single source of truth)",
    vc.jwtRole(SERVICE_ROLE) === "service_role" && vc.jwtRole(ANON) === "anon");

  check("U15.2 classifyEnvValue: service_role JWT → service_role_jwt",
    vc.classifyEnvValue(SERVICE_ROLE) === "service_role_jwt");
  check("U15.3 classifyEnvValue: anon JWT → public_by_design (designed-public)",
    vc.classifyEnvValue(ANON) === "public_by_design");
  check("U15.4 classifyEnvValue: URL value is never 'live' (the Lovable FP root cause)",
    vc.classifyEnvValue("https://xyzcompany.supabase.co") === "public_by_design");
  check("U15.5 classifyEnvValue: sk_live_ prefix → live_secret",
    vc.classifyEnvValue("sk_live_abcdefghij1234567890") === "live_secret");
  check("U15.6 classifyEnvValue: placeholder/example → unknown (never conclusive)",
    vc.classifyEnvValue("changeme") === "unknown" && vc.classifyEnvValue("AKIAIOSFODNN7EXAMPLE") === "unknown");
  check("U15.7 classifyEnvValue: opaque 32-char token with entropy → live_secret",
    vc.classifyEnvValue("8fJ3kZ9pQ2wL5nVbCx7RtY4sM1aE6hG") === "live_secret");
  check("U15.8 classifyEnvValue: private-key block with a REAL body → live_secret",
    vc.classifyEnvValue("-----BEGIN RSA PRIVATE KEY-----\\n" + "A".repeat(80)) === "live_secret");
  check("U15.8b classifyEnvValue: privacy-key HEADER without a body → unknown (tutorial snippet)",
    vc.classifyEnvValue("-----BEGIN RSA PRIVATE KEY-----") === "unknown");
  check("U15.8c jwt.io sample token is public_by_design everywhere",
    vc.classifyEnvValue("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    === "public_by_design"
    && vc.skipHistoryFinding("src/api.ts", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c") === true);
  check("U15.8d placeholder DB URLs never trip the history/secret rules",
    vc.isPlaceholderDbUrl("postgres://user:password@localhost:5432/app") === true
    && vc.isPlaceholderDbUrl("postgres://admin:S3cureDb-Pass@db.prod.anubis-internal:5432/app") === false
    && vc.skipHistoryFinding("src/db.ts", "postgres://root:root@127.0.0.1:5432/dev") === true);
  check("U15.8e .example/.sample/.template file paths are value-agnostic skips",
    vc.skipHistoryFinding(".env.example", "postgres://admin:S3cureDb-Pass@db.prod.internal:5432/app") === true
    && vc.isNotePath("config.sample.json") === true);
  check("U15.9 classifyEnvValue: short hex id → unknown (not conclusive alone)",
    vc.classifyEnvValue("abc123de") === "unknown");

  check("U15.10 isLiveEnvEntry: NEXT_PUBLIC_* + URL → FALSE (key alone is not enough — THE fixed FP)",
    vc.isLiveEnvEntry("NEXT_PUBLIC_SUPABASE_URL", "https://xyzcompany.supabase.co") === false);
  check("U15.11 isLiveEnvEntry: NEXT_PUBLIC_* + service_role JWT → TRUE (still caught by value)",
    vc.isLiveEnvEntry("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY", SERVICE_ROLE) === true);
  check("U15.12 isLiveEnvEntry: anon JWT in NEXT_PUBLIC → false",
    vc.isLiveEnvEntry("NEXT_PUBLIC_SUPABASE_ANON_KEY", ANON) === false);

  check("U15.13 skipHistoryFinding (VALUE-level) ignores path class: docs path does NOT value-skip (caller notes it)",
    vc.isNotePath("docs/quickstart.md") === true && vc.skipHistoryFinding("docs/quickstart.md", "AKIA1234567890ABCDEF") === false);
  check("U15.14 isNotePath: tests/ path is a review note", vc.isNotePath("tests/unit/aws-client.ts") === true);
  check("U15.15 isNotePath: fixtures path is a review note", vc.isNotePath("fixtures/seed-data.ts") === true);
  check("U15.16 isNotePath: *.spec.* file is a review note", vc.isNotePath("app/api/auth.spec.ts") === true);
  check("U15.17 skipHistoryFinding: AWS docs example key pair → skip",
    vc.skipHistoryFinding("src/aws.ts", "AKIAIOSFODNN7EXAMPLE") === true
    && vc.skipHistoryFinding("src/aws.ts", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") === true);
  check("U15.18 skipHistoryFinding: anon JWT in real src path → skip (public-by-design)",
    vc.skipHistoryFinding("lib/api.ts", ANON) === true);
  check("U15.19 skipHistoryFinding: REAL secret in a real src path → NOT skipped (positive)",
    vc.skipHistoryFinding("src/config.ts", "sk_live_ZeAlCred4932abcdefgh") === false);
}

// ---------- U16: Phase 1 regression units (T0/T4/T5/T6/T7 wiring) ----------
{
  const mkCtx = (rootDir, files = []) => ({
    rootDir, rel: () => "", files, stack: { detected: [], frameworks: {}, notes: [] },
    gitAvailable: false, trackedFiles: new Set(), label: rootDir,
  });

  // --- T4: DEP-003 severity calibration (no fixture scan needed — pure rule unit) ---
  const depDir = mkdtempSync(join(tmpdir(), "anubis-u16-dep-"));
  const writePkg = (deps) => {
    writeFileSync(join(depDir, "package.json"), JSON.stringify({ name: "u16", private: true, dependencies: deps }, null, 2));
    rmSync(join(depDir, "package-lock.json"), { force: true });
    rmSync(join(depDir, "pnpm-lock.yaml"), { force: true });
  };
  const { scanDeps } = await import(d("dist/rules/deps.js"));
  writePkg({ expres: "4.18.0" }); // distance 1 from "express" — a classic typo
  let out = scanDeps(mkCtx(depDir));
  const t4a = out.findings.find((f) => f.id === "DEP-003");
  check("U16.1 DEP-003: offline distance-1 typosquat is a LOW note (never HIGH — review verdict)",
    t4a?.severity === "low" && t4a?.confidence === "low" && t4a?.needs_confirmation === true,
    JSON.stringify(out.findings.map((f) => `${f.id}/${f.severity}/${f.confidence}`)));

  writePkg({ nitro: "2.0.0", qs: "6.13.0" });
  out = scanDeps(mkCtx(depDir));
  check("U16.1b DEP-003: recently-extended popular names (nitro, qs) are never flagged",
    out.findings.every((f) => f.id !== "DEP-003"), JSON.stringify(out.findings.map((f) => `${f.id}`)));

  writePkg({ "some-madeup-util": "^1.0.0", reakt: "1.0.0" });
  out = scanDeps(mkCtx(depDir));
  const dep3 = out.findings.filter((f) => f.id === "DEP-003");
  const dep4 = out.findings.filter((f) => f.id === "DEP-004");
  check("U16.2 DEP-003: real typosquat (reakt) still flagged — as LOW with a clear note",
    dep3.some((f) => f.evidence.masked === "reakt" && f.severity === "low" && /typosquat|edit/i.test(f.evidence.note ?? f.evidence.type)),
    JSON.stringify(dep3.map((f) => `${f.evidence.masked}/${f.severity}`)));
  check("U16.2b DEP-003: distance-2 match (axiosss) also LOW + needs_confirmation (no score path)",
    (() => {
      writePkg({ "some-madeup-util": "^1.0.0", axiosss: "1.0.0" });
      const o = scanDeps(mkCtx(depDir));
      const d3 = o.findings.filter((f) => f.id === "DEP-003");
      return d3.length === 1 && d3[0].evidence.masked === "axiosss" && d3[0].severity === "low" && d3[0].needs_confirmation === true;
    })());
  check("U16.3 DEP-004: ONE aggregated finding per project (per-dep storm gone)",
    dep4.length === 1 && dep4[0].root === "(no-lockfile)" && dep4[0].file === "package.json" && /some-madeup-util/.test(dep4[0].evidence.masked),
    JSON.stringify(dep4.map((f) => f.evidence.masked)));

  // --- T5: a non-npm lockfile (pnpm) suppresses the false DEP-004 storm ---
  writeFileSync(join(depDir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
  out = scanDeps(mkCtx(depDir));
  check("U16.4 DEP-004: pnpm-lock.yaml counts as a lockfile (no unresolved finding)",
    out.findings.every((f) => f.id !== "DEP-004"));

  // --- T5: npm-PARSEABLE lockfile present but an unknown dep missing from it →
  // per-dependency DEP-004 (not the aggregated project-state form) ---
  rmSync(join(depDir, "pnpm-lock.yaml"), { force: true });
  writePkg({ express: "4.18.0", "some-madeup-util": "^1.0.0" });
  writeFileSync(join(depDir, "package-lock.json"), JSON.stringify({
    name: "u16", lockfileVersion: 3,
    packages: { "node_modules/express": { version: "4.18.0" } },
  }));
  out = scanDeps(mkCtx(depDir));
  {
    const perDep = out.findings.filter((f) => f.id === "DEP-004");
    check("U16.4b DEP-004: dep missing from an npm lockfile → per-dependency finding (root = name)",
      perDep.length === 1 && perDep[0].root === "some-madeup-util" && perDep[0].severity === "medium",
      JSON.stringify(perDep.map((f) => `${f.root}/${f.severity}`)));
  }

  // --- T6: SAST-002 sanitizer recognition (DOMPurify) — clean case ---
  const sf = (rel, content) => ({ abs: join(depDir, rel), rel, content, lines: content.split(/\r?\n/) });
  const { scanSast } = await import(d("dist/rules/sast.js"));
  const sanitized = [sf("app/components/Post.tsx", `import DOMPurify from "dompurify";\nexport default (p: any) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(p.body) }} />;\n`)];
  out = scanSast(mkCtx(depDir, sanitized));
  check("U16.5 SAST-002: DOMPurify.sanitize flow is NOT flagged",
    out.findings.every((f) => f.id !== "SAST-002"), JSON.stringify(out.findings.map((f) => f.id)));
  // --- T6 positive: raw non-literal flow still flagged ---
  const dirty = [sf("app/components/Post.tsx", `export default (p: any) => <div dangerouslySetInnerHTML={{ __html: p.body }} />;\n`)];
  out = scanSast(mkCtx(depDir, dirty));
  check("U16.6 SAST-002: raw non-literal __html still flagged (positive)",
    out.findings.some((f) => f.id === "SAST-002"));

  // --- T6: TAINT-001 allowlist → LOW (visible, no-score) instead of silent skip ---
  const { scanTaint } = await import(d("dist/rules/taint.js"));
  const allowlisted = [sf("app/api/fetch-url/route.ts",
    `const ALLOWED_HOSTS = ["api.github.com"];\nexport async function GET(req: Request) {\n  const target = new URL(req.url).searchParams.get("target") ?? "";\n  const host = new URL(target).host;\n  if (!ALLOWED_HOSTS.includes(host)) return new Response("no", { status: 400 });\n  const r = await fetch(target);\n  return new Response(await r.text());\n}\n`)];
  out = scanTaint(mkCtx(depDir, allowlisted));
  check("U16.7 TAINT-001: allowlisted flow visible at LOW confidence/low severity (no silent skip, no deduction)",
    out.findings.every((f) => f.id === "TAINT-001" && f.severity === "low" && f.confidence === "low"),
    JSON.stringify(out.findings.map((f) => `${f.id}/${f.severity}`)));
  const sans = [sf("app/api/fetch-url/route.ts",
    `export async function GET(req: Request) {\n  const target = new URL(req.url).searchParams.get("target") ?? "";\n  const r = await fetch(target);\n  return new Response(await r.text());\n}\n`)];
  out = scanTaint(mkCtx(depDir, sans));
  check("U16.8 TAINT-001: no-allowlist flow stays MEDIUM (positive)",
    out.findings.some((f) => f.id === "TAINT-001" && f.severity === "medium" && f.confidence === "medium"));

  // --- T7: walk skip accounting ---
  const wDir = mkdtempSync(join(tmpdir(), "anubis-u16-walk-"));
  writeFileSync(join(wDir, "ok.ts"), "export const a = 1;\n");
  writeFileSync(join(wDir, "big.ts"), "x".repeat(512 * 1024 + 1));
  writeFileSync(join(wDir, "blob.bin"), Buffer.concat([Buffer.from("PNG"), Buffer.alloc(16, 0)]));
  const { walkWithStats } = await import(d("dist/walk.js"));
  const stats = walkWithStats(wDir);
  check("U16.9 walkWithStats: >4MB + binary counted, text kept; 512KB file is WINDOWED (v1.4 capability E — the oversize boundary moved from 512KB to 4MB)",
    stats.skipped.oversize === 0 && stats.skipped.binary === 1 && stats.skipped.unreadable === 0
    && stats.files.length === 2 && stats.files.some((f) => f.rel === "ok.ts")
    && stats.windowed.length === 1 && stats.windowed[0].file === "big.ts" && stats.windowed[0].windows >= 1,
    JSON.stringify(stats));
  check("U16.10 walk(): CRLF robustness preserved (extract of U11)",
    (() => { const n = walkWithStats(wDir).files; return n.every((f) => !f.lines.some((l) => l.endsWith("\r"))); })());
  rmSync(wDir, { recursive: true, force: true });

  // --- T0: adapters fail-closed accounting (unknown tool) ---
  const { runAdapters } = await import(d("dist/adapters.js"));
  const adOut = runAdapters(mkCtx(depDir), ["made-up-scanner"]);
  check("U16.11 runAdapters: unsupported tool names are reported, never silently skipped",
    adOut.unsupported.length === 1 && adOut.unsupported[0] === "made-up-scanner" && adOut.used.length === 0);
  rmSync(depDir, { recursive: true, force: true });
}

// ---------- U17: adapters (T0) — controlled test doubles over the exit-code truth table ----------
{
  const mkCtx = (rootDir) => ({
    rootDir, rel: () => "", files: [], stack: { detected: [], frameworks: {}, notes: [] },
    gitAvailable: false, trackedFiles: new Set(), label: rootDir,
  });
  const dCtx = mkCtx(join(tmpdir(), "anubis-u17-nonexistent"));
  const { runAdapters } = await import(d("dist/adapters.js"));

  /** fake probe: writes the report file its args request, returns the wanted exit code */
  const fakeProbe = (status, { reportKey = "--report-path", reportJson, existsResult = true, stderr = "" } = {}) => ({
    exists: () => existsResult,
    exec: (_bin, args) => {
      const i = args.indexOf(reportKey);
      if (i !== -1 && reportJson !== undefined) writeFileSync(args[i + 1], reportJson);
      return { status, stdout: "", stderr };
    },
  });

  const GL_REPORT = JSON.stringify([
    { File: "src/a.ts", StartLine: 3, RuleID: "stripe-live-key", Fingerprint: "fp:x", Description: "Stripe key" },
  ]);

  // findings-exit code (gitleaks 1) must PRESERVE findings in the unified outcome
  let ad = runAdapters(dCtx, ["gitleaks"], fakeProbe(1, { reportJson: GL_REPORT }));
  check("U17.1 gitleaks exit 1 (findings) → findings preserved, counted used",
    ad.used.includes("gitleaks") && ad.findings.length === 1 && ad.findings[0].id === "GLK-001"
    && ad.findings[0].file === "src/a.ts" && ad.failed.length === 0,
    JSON.stringify({ used: ad.used, failed: ad.failed, n: ad.findings.length }));

  // clean exit (0) with a parseable EMPTY report = completed with no findings
  ad = runAdapters(dCtx, ["gitleaks"], fakeProbe(0, { reportJson: "[]" }));
  check("U17.2 gitleaks exit 0 (clean) → used with zero findings",
    ad.used.includes("gitleaks") && ad.findings.length === 0 && ad.failed.length === 0);

  ad = runAdapters(dCtx, ["gitleaks"], fakeProbe(2, { stderr: "panic: boom" }));
  check("U17.3 gitleaks exit 2 (unexpected) → execution failure surfaced, NOT used",
    !ad.used.includes("gitleaks") && ad.failed.length === 1 && ad.failed[0].status === 2 && /exit 2/.test(ad.failed[0].reason));

  ad = runAdapters(dCtx, ["gitleaks"], fakeProbe(1, { reportJson: "{not json" }));
  check("U17.4 gitleaks exit 1 + malformed report → invalid-report failure (never_clean)",
    !ad.used.includes("gitleaks") && ad.failed.length === 1 && /unparseable/.test(ad.failed[0].reason));

  ad = runAdapters(dCtx, ["gitleaks"], fakeProbe(1, { reportJson: "{\"oops\": true}" }));
  check("U17.5 gitleaks exit 1 + wrong report SHAPE → invalid report",
    !ad.used.includes("gitleaks") && ad.failed.length === 1 && /not a JSON array/.test(ad.failed[0].reason));

  ad = runAdapters(dCtx, ["gitleaks"], fakeProbe(1, {})); // writes nothing → report file missing
  check("U17.6 gitleaks exit 1 + report file missing → missing-report failure",
    !ad.used.includes("gitleaks") && ad.failed.length === 1 && /missing/.test(ad.failed[0].reason));

  const OSV_REPORT = JSON.stringify({
    results: [{ packages: [{ package: { name: "lodash", version: "4.17.4" }, vulnerabilities: [{ id: "GHSA-test", database_specific: { severity: "CRITICAL" }, summary: "prototype pollution RCE" }] }] }],
  });
  ad = runAdapters(dCtx, ["osv-scanner"], fakeProbe(1, { reportKey: "--output", reportJson: OSV_REPORT }));
  check("U17.7 osv-scanner exit 1 (vulns found) → findings preserved",
    ad.used.includes("osv-scanner") && ad.findings.length === 1 && ad.findings[0].id === "OSV-001"
    && ad.findings[0].severity === "critical" && /lodash/.test(ad.findings[0].evidence.masked));

  const SG_REPORT = JSON.stringify({ results: [{ check_id: "js-xss", path: "src/a.ts", start: { line: 7 }, extra: { severity: "ERROR", lines: "eval(x)", message: "XSS" } }] });
  ad = runAdapters(dCtx, ["semgrep"], fakeProbe(0, { reportKey: "--output", reportJson: SG_REPORT }));
  check("U17.8 semgrep exit 0 → findings preserved",
    ad.used.includes("semgrep") && ad.findings.length === 1 && ad.findings[0].id === "SGP-001" && ad.findings[0].severity === "high");

  ad = runAdapters(dCtx, ["semgrep"], fakeProbe(1, { stderr: "config not fetched" }));
  check("U17.9 semgrep nonzero exit → scan failure surfaced (never a findings code)",
    !ad.used.includes("semgrep") && ad.failed.length === 1);

  ad = runAdapters(dCtx, ["gitleaks"], { exists: () => false, exec: () => ({ status: 0, stdout: "", stderr: "" }) });
  check("U17.10 missing executable → missing list (fail-closed input)",
    ad.missing.includes("gitleaks") && ad.used.length === 0);

  // v1.2 audit — crash / timeout path: execFileSync timeout or process crash
  // surfaces as status=null; the truth table must treat it as a FAILURE (and
  // the engine-level refusal then prevents a "clean" misrepresentation).
  ad = runAdapters(dCtx, ["gitleaks"], fakeProbe(null, { stderr: "ETIMEDOUT" }));
  check("U17.15 gitleaks crashed/timed out (exit null) → execution failure surfaced (never clean, never used)",
    !ad.used.includes("gitleaks") && ad.failed.length === 1 && ad.failed[0].status === null && /crash/.test(ad.failed[0].reason));

  // engine-level seam: scan() with a controlled double keeps adapter findings
  // visible in the final unified report (+ fail-closed throw on failure)
  const { scan } = await import(d("dist/engine.js"));
  const fixtureRoot = mkdtempSync(join(tmpdir(), "anubis-u17-eng-"));
  writeFileSync(join(fixtureRoot, "index.ts"), "export const a = 1;\n");
  let result = scan(fixtureRoot, { tools: ["gitleaks"], adapterProbe: fakeProbe(1, { reportJson: GL_REPORT }) });
  check("U17.11 engine scan(): gitleaks finding remains visible in the unified report",
    result.findings.some((f) => f.id === "GLK-001" && f.file === "src/a.ts")
    && result.meta.adapters_used?.includes("gitleaks") && result.meta.adapters_requested?.join() === "gitleaks");
  let threw = null;
  try { scan(fixtureRoot, { tools: ["gitleaks"], adapterProbe: fakeProbe(2, { stderr: "booms" }) }); } catch (e) { threw = e; }
  check("U17.12 engine scan(): failed adapter refuses the report (fail-closed throw)",
    threw instanceof Error && /adapter fail-closed/.test(threw.message) && /exit 2/.test(threw.message),
    String(threw && threw.message).slice(0, 120));

  // v1.2 audit — OSV severity mapping: explicit per severity, no HIGH collapse
  const OSV_SEV = (sev) => JSON.stringify({
    results: [{ packages: [{ package: { name: "lodash", version: "4.17.4" },
      vulnerabilities: [sev === undefined ? { id: "GHSA-x", summary: "s" } : { id: "GHSA-x", database_specific: { severity: sev }, summary: "s" }] }] }],
  });
  const oneOsv = (sev) => runAdapters(dCtx, ["osv-scanner"], fakeProbe(1, { reportKey: "--output", reportJson: OSV_SEV(sev) })).findings[0];
  check("U17.13 OSV severity map: CRITICAL→critical · HIGH→high · MODERATE/MEDIUM→medium · LOW→low",
    ["CRITICAL|critical", "HIGH|high", "MODERATE|medium", "MEDIUM|medium", "LOW|low"].every((p) => {
      const [sev, want] = p.split("|");
      return oneOsv(sev).severity === want;
    }) && oneOsv("CRITICAL").needs_confirmation !== true,
    ["CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"].map((s) => `${s}:${oneOsv(s).severity}`).join(" "));
  check("U17.14 OSV severity map: missing/unknown severity → medium + needs_confirmation + raw value disclosed (never silent HIGH)",
    (() => {
      const fMissing = oneOsv(undefined);
      const fWeird = oneOsv("CATACLYSMIC");
      return fMissing.severity === "medium" && fMissing.needs_confirmation === true
        && /\(none\)/.test(fMissing.evidence.note)
        && fWeird.severity === "medium" && fWeird.needs_confirmation === true
        && /CATACLYSMIC/.test(fWeird.evidence.note);
    })());
  rmSync(fixtureRoot, { recursive: true, force: true });
}

// ---------- U18: Phase 2 detection gaps (T8–T14) ----------
{
  const sctx = (content, rel = "app/api/x.ts") => ({ rootDir: "/p", files: [{ abs: `/p/${rel}`, rel, content, lines: content.split("\n") }] });
  const { scanSast } = await import(d("dist/rules/sast.js"));
  const sastFind = (c, rel) => scanSast(sctx(c, rel)).findings;
  const sastIds = (c, rel) => sastFind(c, rel).map((f) => f.id);

  // ---- T8: SQL injection via unsafe dynamic SQL (first-argument analysis) ----
  check("U18.1 T8: $queryRawUnsafe with ${req.query.id} → SAST-001 HIGH",
    sastFind("const r = await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id=${req.query.id}`);\n").some((f) => f.id === "SAST-001" && f.severity === "high"));
  check("U18.2 T8: $executeRawUnsafe with '+ req.query.id' concat → SAST-001 HIGH",
    sastFind("const r = await prisma.$executeRawUnsafe('DELETE FROM users WHERE id=' + req.query.id);\n").some((f) => f.id === "SAST-001" && f.severity === "high"));
  check("U18.3 T8: pool.query with template interpolation → SAST-001 HIGH",
    sastFind('const r = await pool.query(`SELECT * FROM users WHERE name="${req.query.name}"`);\n').some((f) => f.id === "SAST-001" && f.severity === "high"));
  check("U18.4 T8: inner-quote concat db.query(\"…'\"+req.x+…\") no longer stops at the first quote",
    sastFind('const r = await db.query("SELECT * FROM users WHERE name=\'" + req.query.name + "\'");\n').some((f) => f.id === "SAST-001" && f.severity === "high"));
  check("U18.5 T8: knex.raw / sequelize.query / connection.execute sinks covered",
    ["connection.execute(`SELECT ${t}`)", "knex.raw(`SELECT ${req.query.id}`)", "sequelize.query(`SELECT ${req.query.id}`)"]
      .every((frag) => sastFind(`const r = ${frag};\n`).some((f) => f.id === "SAST-001")));
  check("U18.6 T8 clean: positional placeholder pool.query('…$1', [req.query.id]) stays SILENT",
    sastIds("const r = await pool.query('SELECT * FROM users WHERE id=$1', [req.query.id]);\n").length === 0);
  check("U18.7 T8 clean: tagged template prisma.$queryRaw`…${req.x}` stays SILENT (parameterized by design)",
    sastIds("const r = await prisma.$queryRaw`SELECT * FROM users WHERE id=${req.query.id}`;\n").length === 0);
  check("U18.8 T8: non-request dynamic SQL → SAST-001 at MEDIUM + needs_confirmation",
    sastFind("const userId = lookupId();\nconst r = await db.query(`DELETE FROM tokens WHERE id=${userId}`);\n")
      .some((f) => f.id === "SAST-001" && f.severity === "medium" && f.needs_confirmation === true));

  // ---- v1.3: single-hop variable propagation into SQL sinks (alias) ----
  check("U18.8a alias: const q built by concatenating req.query.x + pool.query(q) → SAST-001 HIGH",
    sastFind("const q = \"SELECT * FROM users WHERE name='\" + req.query.name + \"'\";\nawait pool.query(q);\n")
      .some((f) => f.id === "SAST-001" && f.severity === "high" && f.needs_confirmation !== true
        && /pool\.query\(q -> /.test(f.evidence.masked)));
  check("U18.8b alias: `…${req.query.id}` const q + prisma.$queryRawUnsafe(q) → SAST-001 HIGH",
    sastFind("const q = `SELECT * FROM users WHERE id=${req.query.id}`;\nconst r = await prisma.$queryRawUnsafe(q);\n")
      .some((f) => f.id === "SAST-001" && f.severity === "high" && /queryRawUnsafe\(q -> /.test(f.evidence.masked)));
  check("U18.8c alias clean: parameterized query via alias (const q = '…$1') stays SILENT",
    sastIds('const q = "SELECT * FROM users WHERE id=$1";\nawait pool.query(q, [req.query.id]);\n').length === 0);
  check("U18.8d alias clean: alias var interpolated into a TAGGED prisma.$queryRaw stays SILENT (parameterized by design)",
    sastIds("const q = `SELECT * FROM users WHERE id=${req.query.id}`;\nconst r = await prisma.$queryRaw`SELECT * FROM t WHERE id=${q}`;\n").length === 0);
  check("U18.8e alias clean: constant const q = 'SELECT 1' stays SILENT",
    sastIds('const q = "SELECT 1";\nawait pool.query(q);\n').length === 0);
  check("U18.8f alias scope: assignment in ANOTHER function does not resolve (same-function only)",
    sastIds("export function leaky(req: Request) {\n  const q = \"SELECT * FROM users WHERE name='\" + req.query.name + \"'\";\n  return q;\n}\nexport function innocent(pool: any, req: any) {\n  await pool.query(q);\n}\n").length === 0);
  check("U18.8g v1.4 flow: a chained alias (const q = r) IS followed (bounded multi-hop chase — was one-hop-only)",
    sastFind("const r = \"SELECT * FROM users WHERE name='\" + req.query.name + \"'\";\nconst q = r;\nawait pool.query(q);\n")
      .some((f) => f.id === "SAST-001" && f.severity === "high" && f.needs_confirmation !== true));
  check("U18.8g-v2 flow cap: a >4-hop alias chain does NOT resolve (bounded chase, no half-verdicts)",
    sastIds("const v0 = \"SELECT * FROM users WHERE name='\" + req.query.name + \"'\";\nconst v1 = v0;\nconst v2 = v1;\nconst v3 = v2;\nconst v4 = v3;\nconst v5 = v4;\nconst v6 = v5;\nawait pool.query(v6);\n").length === 0);
  check("U18.8g-v3 flow cycle: self/cross-referencing assignment chains never fire (cycle guard)",
    sastIds("let q = \"x\";\nq = q + q;\nconst r = q;\nawait pool.query(r);\n").length === 0);
  check("U18.8g-v4 flow method-wrap: intermediate b = a.trim() still resolves the origin SQL build",
    sastFind("const a = \"SELECT * FROM users WHERE name='\" + req.query.name + \"'\";\nconst b = a.trim();\nconst q = b;\nawait pool.query(q);\n")
      .some((f) => f.id === "SAST-001" && f.severity === "high"));
  check("U18.8h alias multi-line template: unterminated template joined across lines still resolves → HIGH",
    sastFind("const q = `SELECT * FROM users WHERE\n  name='${req.query.name}'`;\nawait pool.query(q);\n")
      .some((f) => f.id === "SAST-001" && f.severity === "high"));
  check("U18.8i alias with binding array: pool.query(q, [id]) still resolves the alias first arg",
    sastFind("const q = `SELECT * FROM users WHERE name='${req.query.name}'`;\nawait pool.query(q, [req.query.id]);\n")
      .some((f) => f.id === "SAST-001" && f.severity === "high" && /pool\.query\(q -> /.test(f.evidence.masked))
      && sastIds('const q = "SELECT * FROM users WHERE id=$1";\nawait pool.query(q, [req.query.id]);\n').length === 0);
  // v1.3 review fix — plain REASSIGNMENTS count as assignments: the last
  // assignment before the sink decides. `let q = tainted…; q = "SELECT 1"`
  // must stay SILENT (the FP direction), and the reverse must fire.
  check("U18.8j alias reassignment: last assignment wins — demoted to constant stays SILENT, promoted to request-built fires HIGH",
    sastIds('let q = "SELECT * FROM users WHERE id=" + req.query.id;\nq = "SELECT 1";\nawait pool.query(q);\n').length === 0
      && sastFind('let q = "SELECT 1";\nq = "SELECT * FROM users WHERE id=" + req.query.id;\nawait pool.query(q);\n')
          .some((f) => f.id === "SAST-001" && f.severity === "high" && /pool\.query\(q -> /.test(f.evidence.masked)));

  // ---- v1.4 (§2): cross-file imported-helper SQL build flow (no-exec: reads the helper source) ----
  check("U18.8k x-file: pool.query(buildQuery(req.params.id)) + local helper builds SQL → SAST-001 HIGH",
    (() => {
      const route = `import { buildQuery } from "../lib/sql";\nexport async function GET(req: Request) {\n  const rows = pool.query(buildQuery(req.params.id));\n}\n`;
      const helper = `export function buildQuery(id: string) { return "SELECT * FROM users WHERE id=" + id; }\n`;
      const out = scanSast({ rootDir: "/p", files: [
        { abs: "/p/app/api/route.ts", rel: "app/api/route.ts", content: route, lines: route.split("\n") },
        { abs: "/p/app/lib/sql.ts", rel: "app/lib/sql.ts", content: helper, lines: helper.split("\n") },
      ] }).findings;
      return out.some((f) => f.id === "SAST-001" && f.severity === "high" && /buildQuery/.test(f.evidence.masked) && /builds SQL/.test(f.evidence.masked));
    })());
  check("U18.8l x-file clean: local helper builds a parameterized query → SILENT",
    (() => {
      const route = `import { buildQuery } from "../lib/sql";\nexport async function GET(req: Request) {\n  const rows = pool.query(buildQuery(req.params.id));\n}\n`;
      const helper = `export function buildQuery(id: string) { return sql("SELECT * FROM users WHERE id=$1", [id]); }\n`;
      const out = scanSast({ rootDir: "/p", files: [
        { abs: "/p/app/api/route.ts", rel: "app/api/route.ts", content: route, lines: route.split("\n") },
        { abs: "/p/app/lib/sql.ts", rel: "app/lib/sql.ts", content: helper, lines: helper.split("\n") },
      ] }).findings;
      return out.filter((f) => f.id === "SAST-001").length === 0;
    })());
  check("U18.8m x-file: npm-imported helper is NEVER followed (non-relative spec)",
    (() => {
      const route = `import { buildQuery } from "some-npm-package";\nexport async function GET(req: Request) {\n  const rows = pool.query(buildQuery(req.params.id));\n}\n`;
      const helper = `export function buildQuery(id: string) { return "SELECT * FROM users WHERE id=" + id; }\n`;
      const out = scanSast({ rootDir: "/p", files: [
        { abs: "/p/app/api/route.ts", rel: "app/api/route.ts", content: route, lines: route.split("\n") },
        { abs: "/p/some-npm-package/sql.ts", rel: "some-npm-package/sql.ts", content: helper, lines: helper.split("\n") },
      ] }).findings;
      return out.filter((f) => f.id === "SAST-001").length === 0;
    })());
  check("U18.8n generalize: sink-arg resolver handles concat-with-traced-var + method wrap (var names not from any example)",
    sastFind("const r = req.query.filter;\nconst q2 = \"SELECT * FROM users WHERE name IN (\" + r.toUpperCase() + \")\";\nawait pool.query(q2);\n")
      .some((f) => f.id === "SAST-001" && f.severity === "high"));

  // ---- T9: dynamic code execution (SAST-003 non-literal + TAINT-006) ----
  check("U18.9 T9: eval(<non-literal user var>) → SAST-003 MEDIUM + needs_confirmation",
    sastFind("const out = eval(userProvidedString);\n").some((f) => f.id === "SAST-003" && f.severity === "medium" && f.needs_confirmation === true));
  check("U18.10 T9: new Function(<non-literal>) and vm.runInNewContext covered",
    ["const f = new Function(userCode);", "vm.runInNewContext(userCode, ctx);", "vm.runInThisContext(userCode);"]
      .every((frag) => sastFind(`export function h() {\n  ${frag}\n}\n`).some((f) => f.id === "SAST-003")));
  check("U18.11 T9 clean: eval('1+1') literal stays silent",
    !sastFind("const r = eval('1+1');\n").some((f) => f.id === "SAST-003"));
  check("U18.12 T9 clean: eval inside a comment / inside a string stays silent",
    sastFind("// upgrade note: replace eval(x) later\nconst msg = 'you should not eval(userInput) here';\n").every((f) => f.id !== "SAST-003"));
  check("U18.13 T9: eval(req.body.code) → TAINT-006 (taint layer, MEDIUM)",
    taintIds('export async function POST(req: Request) {\n  return eval(req.body.code);\n}\n').includes("TAINT-006"));
  check("U18.14 T9: setTimeout(<tainted string>) → TAINT-006",
    taintIds('export function h(req, res) {\n  const t = req.query.cb;\n  setTimeout(t);\n}\n').includes("TAINT-006"));
  check("U18.15 T9: request-traced eval does NOT double-report SAST-003 (taint owns it)",
    sastFind("export function h(req) {\n  return eval(req.body.code);\n}\n").every((f) => f.id !== "SAST-003"));

  // ---- T10: hardcoded signing/session secrets (JWT-003) ----
  const { scanJwtSecrets } = await import(d("dist/rules/jwtsecrets.js"));
  const jwtFind = (c, rel = "lib/auth.ts") => scanJwtSecrets(sctx(c, rel)).findings;
  check("U18.16 T10: jwt.sign(_, 'secret123') → JWT-003 HIGH",
    jwtFind("const token = jwt.sign({ sub: '1' }, 'secret123');\n").some((f) => f.id === "JWT-003" && f.severity === "high" && f.confidence === "high"));
  check("U18.17 T10: const JWT_SECRET = 'literal' → JWT-003",
    jwtFind("export const JWT_SECRET = 'super-secret-signing-key';\n").some((f) => f.id === "JWT-003"));
  check("U18.18 T10: session({ secret: 'changeme-super-secret-key' }) FIRES — placeholder defaults ARE the vulnerability",
    jwtFind("app.use(session({ secret: 'changeme-super-secret-key', resave: false }));\n").some((f) => f.id === "JWT-003"));
  check("U18.19 T10: jwt.verify with literal covered",
    jwtFind("const ok = jwt.verify(token, 'my-signing-secret');\n").some((f) => f.id === "JWT-003"));
  check("U18.20 T10: JwtModule.register({ secret: 'literal' }) covered",
    jwtFind("JwtModule.register({ secret: 'nestjs-jwt-secret-42' }),\n").some((f) => f.id === "JWT-003"));
  check("U18.21 T10 clean: process.env / configService / template secrets stay silent",
    ['const token = jwt.sign({ sub: "1" }, process.env.JWT_SECRET as string);',
     "app.use(session({ secret: configService.get('JWT_SECRET') }));",
     "JwtModule.register({ secret: `${process.env.NEST_JWT}` }),",
     "JwtModule.register({ secret: '<your-secret>' }),",
     "JwtModule.register({ secret: 'YOUR_SECRET HERE' }),"]
      .every((frag) => jwtFind(`export function h() {\n  ${frag}\n}\n`).every((f) => f.id !== "JWT-003")));

  // ---- T11: SEED-001 path expansion ----
  const { scanSeed001 } = await import(d("dist/rules/seed001.js"));
  const seedFind = (rel, content) => scanSeed001({ rootDir: "/p", files: [{ abs: `/p/${rel}`, rel, content, lines: content.split("\n") }] }).findings;
  check("U18.22 T11: seeds/001-users.js with a literal password → SEED-001",
    seedFind("seeds/001-users.js", 'await prisma.user.create({ data: { email: "admin@x.io", password: "Sup3r-Secret-Prod" } });\n').some((f) => f.id === "SEED-001"),
    JSON.stringify(seedFind("seeds/001-users.js", 'await prisma.user.create({ data: { email: "admin@x.io", password: "Sup3r-Secret-Prod" } });\n')));
  check("U18.23 T11: scripts/create-admin.ts and prisma/seed-admin.ts covered",
    seedFind("scripts/create-admin.ts", 'const password = "Admin-Default-2024";\n').some((f) => f.id === "SEED-001")
    && seedFind("prisma/seed-admin.ts", 'password: "Provision-Secret-9",\n').some((f) => f.id === "SEED-001"));
  check("U18.24 T11: db/seeds/ directory covered",
    seedFind("db/seeds/002-roles.js", 'role: "admin", password: "Role-Secret-77",\n').some((f) => f.id === "SEED-001"));
  check("U18.25 T11 clean: seeds with PLACEHOLDER passwords stay silent",
    !seedFind("seeds/001-users.js", 'await prisma.user.create({ data: { email: "a@b.io", password: "changeme-change-me-now" } });\n').some((f) => f.id === "SEED-001"));
  check("U18.26 T11 clean: *.test.* seed files stay excluded",
    !seedFind("seeds/001-users.test.ts", 'password: "Sup3r-Secret-Prod",\n').some((f) => f.id === "SEED-001"));

  // ---- T12: HDR-001 receiver value-flow ----
  const { scanHdr001 } = await import(d("dist/rules/hdr001.js"));
  const hdrFind = (c, rel = "app/api/x/route.ts") => scanHdr001(sctx(c, rel)).findings;
  const hdrCritical = (c, rel) => hdrFind(c, rel).some((f) => f.id === "HDR-001" && f.severity === "critical");
  check("U18.27 T12: x-pg-secret via headers() alias → new Pool({connectionString}) → HDR-001 CRITICAL",
    hdrCritical('import { Pool } from "pg";\nimport { headers } from "next/headers";\nexport async function GET() {\n  const h = await headers();\n  const secret = h.get("x-pg-secret");\n  const pool = new Pool({ connectionString: secret });\n  return Response.json(await pool.query("SELECT 1"));\n}\n'));
  check("U18.28 T12: direct req.headers['x-dsn'] → new Client({connectionString}) → CRITICAL",
    hdrCritical('import { Client } from "pg";\nexport async function POST(req: Request) {\n  const client = new Client({ connectionString: req.headers["x-dsn"] });\n}\n'));
  check("U18.29 T12: honeypot shape — pool.options.password = <headerVar> → CRITICAL",
    hdrCritical("const pool = new Pool({ max: 5 });\nexport async function POST(req: Request) {\n  const dbPassword = req.headers.get('x-db-connection-password') ?? '';\n  pool.options.password = dbPassword;\n}\n"));
  check("U18.30 T12: mongoose.connect with a header DSN → CRITICAL",
    hdrCritical('import mongoose from "mongoose";\nexport async function POST(req: Request) {\n  await mongoose.connect(req.headers.get("x-dsn") as string);\n}\n'));
  check("U18.31 T12 clean: x-request-id logged / Authorization verified / headers forwarded → NO HDR-001",
    hdrFind('import { headers } from "next/headers";\nexport async function GET() {\n  const h = await headers();\n  console.log("request id", h.get("x-request-id"));\n  const auth = h.get("authorization");\n  const ok = verifyToken(auth);\n  return fetch(upstream, { headers: { "x-forwarded-for": h.get("x-forwarded-for") } });\n}\n').every((f) => f.id !== "HDR-001"));

  // ---- T13: open-redirect sink expansion ----
  check("U18.32 T13: next/navigation redirect(<searchParams value>) → TAINT-002",
    taintIds('import { redirect } from "next/navigation";\nexport async function GET(req: Request) {\n  const to = new URL(req.url).searchParams.get("next") as string;\n  redirect(to);\n}\n').includes("TAINT-002"));
  check("U18.33 T13: permanentRedirect + NextResponse.redirect covered",
    taintIds('import { permanentRedirect } from "next/navigation";\nexport async function GET(req: Request) {\n  const to = new URL(req.url).searchParams.get("next") as string;\n  permanentRedirect(to);\n}\n').includes("TAINT-002"),
    JSON.stringify(taintIds('import { permanentRedirect } from "next/navigation";\nexport async function GET(req: Request) {\n  const to = new URL(req.url).searchParams.get("next") as string;\n  permanentRedirect(to);\n}\n')));
  check("U18.34 T13 clean: redirect to a LITERAL path stays silent",
    !taintIds('import { redirect } from "next/navigation";\nexport async function GET() {\n  redirect("/home");\n}\n').includes("TAINT-002"));
  check("U18.35 T13 clean: startsWith(\"/\") guard before redirect stays silent",
    !taintIds('import { redirect } from "next/navigation";\nexport async function GET(req: Request) {\n  const to = new URL(req.url).searchParams.get("next") ?? "/home";\n  if (!to.startsWith("/") || to.startsWith("//")) redirect("/home");\n  redirect(to);\n}\n').includes("TAINT-002"))

  // ---- T14: transitive dependency recall + snapshot staleness ----
  const { scanDeps, snapshotInfo } = await import(d("dist/rules/deps.js"));
  const depRoot = mkdtempSync(join(tmpdir(), "anubis-u18-deps-"));
  writeFileSync(join(depRoot, "package.json"), JSON.stringify({ name: "u18", version: "1.0.0", dependencies: { express: "^4.17.1" } }));
  writeFileSync(join(depRoot, "package-lock.json"), JSON.stringify({
    name: "u18", version: "1.0.0", lockfileVersion: 1, requires: true,
    dependencies: { express: { version: "4.17.1", dependencies: { handlebars: { version: "4.5.0" }, qs: { version: "6.5.2" } } } },
  }));
  const depFindings = scanDeps({ rootDir: depRoot, rel: () => "", files: [], stack: { detected: [], frameworks: {}, notes: [] } }).findings;
  check("U18.36 T14: TRANSITIVE handlebars@4.5.0 (via express lockfile) → DEP-001 HIGH/CRITICAL",
    depFindings.some((f) => f.id === "DEP-001" && f.file === "package-lock.json" && /handlebars@4\.5\.0/.test(f.evidence.masked) && (f.severity === "critical" || f.severity === "high")),
    JSON.stringify(depFindings.filter((f) => f.id === "DEP-001").map((f) => `${f.evidence.masked}:${f.severity}`)));
  check("U18.37 T14: transitive qs@6.5.2 covered + direct express moderate advisory → MEDIUM",
    depFindings.some((f) => f.id === "DEP-001" && /qs@6\.5\.2/.test(f.evidence.masked))
    && depFindings.some((f) => f.id === "DEP-001" && /express@4\.17\.1/.test(f.evidence.masked) && f.severity === "medium"));
  const cleanRoot = mkdtempSync(join(tmpdir(), "anubis-u18-deps-"));
  writeFileSync(join(cleanRoot, "package.json"), JSON.stringify({ name: "u18c", version: "1.0.0", dependencies: { express: "^4.21.0" } }));
  // moment@2.31.0 is past every bundled moment advisory (2.29.4 trips
  // GHSA-4p3w-j4w9-5jqw, fixed 2.31.0 — real OSV data, rule is right)
  writeFileSync(join(cleanRoot, "package-lock.json"), JSON.stringify({
    name: "u18c", version: "1.0.0", lockfileVersion: 1, requires: true,
    dependencies: { express: { version: "4.21.2", dependencies: { moment: { version: "2.31.0" } } } },
  }));
  const cleanDeps = scanDeps({ rootDir: cleanRoot, rel: () => "", files: [], stack: { detected: [], frameworks: {}, notes: [] } }).findings;
  check("U18.38 T14 clean: MVC-patched transitive moment@2.31.0 → NO transitive DEP-001",
    !cleanDeps.some((f) => f.id === "DEP-001" && f.file === "package-lock.json"));
  // stale snapshot detection (ctx.advisoryFile override)
  const staleRoot = mkdtempSync(join(tmpdir(), "anubis-u18-snap-"));
  const staleFile = join(staleRoot, "old-snapshot.json");
  writeFileSync(staleFile, JSON.stringify({ snapshot_date: "2020-01", advisories: {}, known_malicious: {} }));
  check("U18.39 T14: snapshotInfo() — 2020-01 snapshot is STALE, bundled 2026-10 is not",
    snapshotInfo({ advisoryFile: staleFile, rootDir: staleRoot }).stale === true
    && snapshotInfo({ rootDir: staleRoot }).stale === false);
  rmSync(depRoot, { recursive: true, force: true });
  rmSync(cleanRoot, { recursive: true, force: true });
  rmSync(staleRoot, { recursive: true, force: true });
}

// ---------- U19: guard-hook version wiring (real package version, no stale labels) ----------
{
  const { HOOK_SCRIPT, SNIPPET } = await import(d("dist/inithook.js"));
  const pkgVer = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;
  check(`U19.1 HOOK_SCRIPT header carries the REAL package version (v${pkgVer})`, HOOK_SCRIPT.includes(`v${pkgVer}`));
  check("U19.2 SNIPPET npx pin matches the real version", SNIPPET.includes(`npx anubis-guardian@${pkgVer} scan`));
  check("U19.3 settings.json hook entry will carry the real version", HOOK_SCRIPT.length > 0 && SNIPPET.includes(`v${pkgVer}`));
  check("U19.4 hook script is self-contained (no require/import of the tool, Buffer-based JWT decode)",
    !HOOK_SCRIPT.includes("from \"../") && !/^\s*import\s/m.test(HOOK_SCRIPT) && HOOK_SCRIPT.includes("Buffer.from"));
  check("U19.5 hook fail-open contract present (malformed/empty stdin → exit 0)",
    HOOK_SCRIPT.includes('catch { process.exit(0); }') && HOOK_SCRIPT.includes("if (!content.trim()) process.exit(0);"));
}

// ---------- U20: independent-review round 2 (v1.3.0 audit fixes, 2026-10) ----------
{
  const sctx = (content, rel = "app/api/x.ts") => ({ rootDir: "/p", files: [{ abs: `/p/${rel}`, rel, content, lines: content.split("\n") }], stack: { frameworks: {} } });

  // ---- JWT-003 hardcoded-secret edges (j1/j2/j4/j6/j7 probes) ----
  const { scanJwtSecrets } = await import(d("dist/rules/jwtsecrets.js"));
  const jwtFind = (c, rel = "app/api/k.ts") => scanJwtSecrets(sctx(c, rel)).findings;
  check("U20.1 JWT-003: credential-named const || 'literal' fallback fires HIGH",
    jwtFind('const JWT_SECRET = process.env.JWT_SECRET || "dev-fallback-secret-123";\nexport const t = jwt.sign({ a: 1 }, JWT_SECRET);\n')
      .some((f) => f.id === "JWT-003" && f.severity === "high" && /fallback/i.test(f.title)));
  check("U20.2 JWT-003: lowercase const secret = env ?? 'literal' fires HIGH",
    jwtFind('const secret = process.env.SIGNING_KEY ?? "supersecret-1234";\n')
      .some((f) => f.id === "JWT-003" && f.severity === "high"));
  check("U20.3 JWT-003: cookieSession keys:[\"literal\"] fires HIGH (±session context)",
    jwtFind('import cookieSession from "cookie-session";\napp.use(cookieSession({ name: "app", keys: ["keyboard-cat-99"] }));\n')
      .some((f) => f.id === "JWT-003" && f.severity === "high"));
  check("U20.4 JWT-003: jose new SignJWT().setSigningKey('literal') fires HIGH",
    jwtFind('import { SignJWT } from "jose";\nexport const t = new SignJWT(d).setSigningKey("opaque-signing-key-42").sign();\n')
      .some((f) => f.id === "JWT-003" && f.severity === "high"));
  check("U20.5 JWT-003 clean: secret from env / configService stays SILENT",
    jwtFind('export const cfg = JwtModule.register({ secret: process.env.JWT_SECRET });\nconfigService.get("auth.secret");\n').length === 0);

  // ---- SAST-001 receiver generalization (s1/s2/s3/s4 probes) ----
  const { scanSast } = await import(d("dist/rules/sast.js"));
  const sastFind = (c, rel = "app/api/s.ts") => scanSast(sctx(c, rel)).findings;
  const sastIds = (c, rel = "app/api/s.ts") => sastFind(c, rel).map((f) => f.id);
  check("U20.6 SAST-001: TypeORM myDataSource.query('…'+req.body.x) fires HIGH",
    sastFind('return myDataSource.query("SELECT * FROM users WHERE name = \'" + req.body.name + "\'");\n')
      .some((f) => f.id === "SAST-001" && f.severity === "high"));
  check("U20.7 SAST-001: arbitrary-receiver em.query(`…${req.params.id}`) fires HIGH",
    sastFind('await em.query(`DELETE FROM doc WHERE id=${req.params.id}`);\n')
      .some((f) => f.id === "SAST-001" && f.severity === "high"));
  check("U20.8 SAST-001: mysql conn.execute alias of dynamic SQL fires HIGH",
    sastFind('const sql = "SELECT * FROM t WHERE x = \'" + req.query.x + "\'";\nreturn conn.execute(sql);\n')
      .some((f) => f.id === "SAST-001" && f.severity === "high"));
  check("U20.9 SAST-001 clean: drizzle tagged db.execute(sql`…${id}`) stays SILENT (parameterized by design)",
    sastIds('return db.execute(sql`select * from orders where id = ${orderId}`);\n').length === 0);
  check("U20.10 SAST-001: non-SQL receivers (xstate .execute(state…)) stay SILENT",
    sastIds("actor.execute(state, { to: 'idle' });\n").length === 0);

  // ---- TAINT-006 / SAST-003 bare Function( (c1/c5) ----
  const { scanTaint } = await import(d("dist/rules/taint.js"));
  const taintFind = (c, rel = "app/api/c.ts") => scanTaint(sctx(c, rel)).findings;
  check("U20.11 TAINT-006: bare Function('return ' + req.body.expr)() fires MEDIUM/needconf",
    taintFind('const f = Function("return " + req.body.expr);\nreturn f();\n')
      .some((f) => f.id === "TAINT-006" && f.severity === "medium" && f.needs_confirmation === true));
  check("U20.12 TAINT-006/SAST-003 clean: literal Function('return 1')() stays SILENT",
    scanTaint(sctx('return Function("return 41 + 1")();\n')).findings.length === 0
      && scanSast(sctx('export function ok() { return Function("return 41 + 1")(); }\n')).findings.length === 0);

  // ---- TAINT-004 execFile/spawn argv (c3/c4) ----
  check("U20.13 TAINT-004: execFile('convert', [req.query.path]) fires MEDIUM/needconf",
    taintFind('import { execFile } from "child_process";\nreturn execFile("convert", [req.query.path, "/out.png"]);\n', "app/api/c.ts")
      .some((f) => f.id === "TAINT-004" && f.severity === "medium" && f.needs_confirmation === true));
  check("U20.14 TAINT-004: tainted var into exec() still covered (regression)",
    taintFind('import { exec } from "child_process";\nconst cmd = req.body.cmd;\nreturn exec(cmd);\n', "app/api/c.ts")
      .some((f) => f.id === "TAINT-004" && f.severity === "medium"));
  check("U20.15 TAINT-004 clean: execFile('convert', [literal]) stays SILENT",
    taintFind('return execFile("convert", ["in.png", "out.png"]);\n', "app/api/c.ts").length === 0);

  // ---- HDR-001 header receiver edges (h1/h2) ----
  const { scanHdr001 } = await import(d("dist/rules/hdr001.js"));
  const hdrIds = (c, rel = "app/api/h.ts") => scanHdr001(sctx(c, rel)).findings;
  check("U20.16 HDR-001: destructured const { xPgPass } = req.headers → Pool({password}) fires CRITICAL",
    hdrIds('import { Pool } from "pg";\nconst { xPgPass } = req.headers;\nconst pool = new Pool({ password: xPgPass });\n')
      .some((f) => f.id === "HDR-001" && f.severity === "critical"));
  check("U20.17 HDR-001: req.get('x-pg-password') → Pool({password}) fires CRITICAL",
    scanHdr001(sctx('import { Pool } from "pg";\nconst pass = req.get("x-pg-password");\nconst pool = new Pool({ password: pass });\n', "app/api/h.ts")).findings
      .some((f) => f.id === "HDR-001" && f.severity === "critical"));

  // ---- TAINT-001/002 first-argument verdicts (h3/h4/h6/h7/h8) ----
  check("U20.18 TAINT-001 clean: fixed URL + header-baggage fetch stays SILENT (destination not user-controlled)",
    scanTaint(sctx('const r = await fetch("https://relay.self-owned.com/api", { method: "POST", headers: { authorization: req.headers.authorization } });\n', "app/api/h.ts")).findings
      .every((f) => f.id !== "TAINT-001" || f.severity === "low"));
  check("U20.19 TAINT-001: fetch(req.query.url) still fires MEDIUM (regression)",
    scanTaint(sctx('return fetch(req.query.url);\n', "app/api/h.ts")).findings
      .some((f) => f.id === "TAINT-001" && f.severity === "medium"));
  check("U20.20 TAINT-001: hostname-based host allowlist stays VISIBLE at LOW/low (no score noise)",
    scanTaint(sctx('const u = new URL(req.query.next);\nif (!["app.self-owned.com"].includes(u.hostname)) return null;\nreturn fetch(u.toString());\n', "app/api/h.ts")).findings
      .every((f) => f.id !== "TAINT-001" || (f.severity === "low" && f.confidence === "low")));
  check("U20.21 TAINT-002: open redirect fires / startsWith-guarded stays SILENT (regressions)",
    scanTaint(sctx('return NextResponse.redirect(req.query.to);\n', "app/api/h.ts")).findings
      .some((f) => f.id === "TAINT-002" && f.severity === "medium")
    && scanTaint(sctx('const to = req.query.to;\nif (!to.startsWith("/")) return null;\nreturn NextResponse.redirect(to);\n', "app/api/h.ts")).findings
      .every((f) => f.id !== "TAINT-002"));

  // ---- LOGS-001 literal-strip var branch (l1/l2) ----
  const { scanPacks2 } = await import(d("dist/rules/packs2.js"));
  const logsFind = (c) => scanPacks2(sctx(c, "app/api/log.ts")).findings.filter((f) => f.id === "LOGS-001");
  check("U20.22 LOGS-001 clean: constant diagnostic mentioning 'password' stays SILENT",
    logsFind('if (!cfg.db) console.warn("database password was not configured; continuing with defaults");\n').length === 0);
  check("U20.23 LOGS-001: console.log('issued api token', token) fires MEDIUM",
    logsFind('console.log("issued api token", token, "for user", id);\n')
      .some((f) => f.id === "LOGS-001" && f.severity === "medium"));

  // ---- JWT-002 one verdict per verify call (d1) ----
  check("U20.24 JWT-002: multi-line jwt.verify → EXACTLY ONE finding (was one per option line)",
    (() => {
      const fs = scanPacks2(sctx('import jwt from "jsonwebtoken";\nexport function v(token) {\n  return jwt.verify(token, process.env.SECRET, {\n    ignoreExpiration: true,\n    clockTolerance: 0,\n  });\n}\n', "app/api/d.ts")).findings.filter((f) => f.id === "JWT-002");
      return fs.length === 1;
    })());

  // ---- SUPA-R01 quoted identifiers / dynamic-DDL strings (q1/q2/q3/q4) ----
  const { scanSupabase } = await import(d("dist/rules/supabase.js"));
  const supaFind = (c) => scanSupabase(sctx(c, "supabase/migrations/0001.sql")).findings;
  check("U20.25 SUPA-R01: quoted \"public\".\"profiles\" WITH RLS stays SILENT (no public.IF ghost)",
    supaFind('CREATE TABLE IF NOT EXISTS "public"."profiles" (\n  id uuid primary key\n);\nALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;\n').length === 0);
  check("U20.26 SUPA-R01: dynamic-DDL string ('CREATE TABLE IF NOT EXISTS ' || …) stays SILENT",
    supaFind('DO $$ BEGIN\n  EXECUTE \'CREATE TABLE IF NOT EXISTS \' || \'public.events (id int)\';\nEND $$;\n').length === 0);
  check("U20.27 SUPA-R01: sensitive table WITH IF NOT EXISTS and NO RLS still fires HIGH",
    supaFind('CREATE TABLE IF NOT EXISTS public.user_settings (id int);\n')
      .some((f) => f.id === "SUPA-R01" && f.severity === "high"));
  check("U20.28 SUPA-R01 clean: public.vehicles with RLS + policy stays SILENT",
    supaFind('CREATE TABLE IF NOT EXISTS public.vehicles (id int);\nALTER TABLE public.vehicles ENABLE ROW LEVEL SECURITY;\n').length === 0);

  // ---- NEST-001 global-guard source scoping (n1/n2/n3) ----
  const { scanNestjs } = await import(d("dist/rules/nestjs.js"));
  const nestCtx = (files) => ({ files, stack: { frameworks: { nestjs: true } } });
  const nf = (ctx) => scanNestjs(ctx).findings.filter((f) => f.id === "NEST-001");
  const ctrl = 'import { Controller, Get, Post } from "@nestjs/common";\n@Controller("admin")\nexport class AdminController {\n  @Get("stats")\n  stats() { return 1; }\n}\n';
  const fobj = (rel, content) => ({ abs: `/p/${rel}`, rel, content, lines: content.split("\n") });
  check("U20.29 NEST-001: unguarded controller in a real Nest project fires HIGH",
    nf(nestCtx([fobj("src/admin.controller.ts", ctrl)])).some((f) => f.severity === "high"));
  check("U20.30 NEST-001: APP_GUARD prose in a .md does NOT silence the rule (code files only)",
    nf(nestCtx([fobj("src/admin.controller.ts", ctrl), fobj("docs/GUIDE.md", "# Guide\nWe configure a global APP_GUARD with useClass(JwtAuthGuard).\n")]))
      .some((f) => f.severity === "high"));
  check("U20.31 NEST-001: real APP_GUARD provider in a .ts module IS honored (silent)",
    nf(nestCtx([fobj("src/admin.controller.ts", ctrl), fobj("src/app.module.ts", 'import { APP_GUARD } from "@nestjs/core";\nproviders: [{ provide: APP_GUARD, useClass: JwtAuthGuard }]\n')])).length === 0);

  // ---- inventory route guard heuristic (comment-only mention ≠ a check) ----
  const { buildInventory } = await import(d("dist/inventory.js"));
  const invOf = (content) => buildInventory({
    files: [fobj("app/api/x/route.ts", content)],
    stack: { frameworks: { nestjs: false } },
  });
  check("U20.32 inventory: comment-only 'authentication' mention does NOT mark POST guarded",
    invOf('// authentication handled by middleware elsewhere\nexport async function POST(req: Request) { return Response.json({ ok: true }); }\n')
      .routes.every((r) => r.guard === null));
  check("U20.33 inventory: real getSession check in the route marks it guarded",
    invOf('export async function POST(req: Request) {\n  const session = await getSession({ req });\n  if (!session) return new Response("no", { status: 401 });\n  return Response.json({ ok: true });\n}\n')
      .routes.every((r) => r.guard === "in-file"));

  // ---- perf lock: adversarial single-line 512KB file, heaviest rules (§2.1) ----
  check("U20.34 perf: 500KB single-line file across the heaviest rules completes well under budget (no ReDoS regressions)",
    (() => {
      const big = 'const z=1;\nconst w = "';
      const chunk = 'fn_call(arg("x",token_1))[0]_chain(a|b).map(f) => {return pool.query(r)}; ';
      let pad = "";
      while (big.length + pad.length < 512 * 1024 - 2) pad += chunk;
      const content = big + pad.slice(0, 512 * 1024 - big.length - 2) + '";\n';
      const files = [{ abs: "/p/huge.ts", rel: "huge.ts", content, lines: content.split("\n") }];
      const ctx = { files, stack: { frameworks: {} } };
      const t0 = Date.now();
      for (const fn of [scanSast, scanPacks2, scanHdr001, scanTaint, scanJwtSecrets]) fn(ctx);
      const ms = Date.now() - t0;
      return ms < 2000; // measured v1.3.0 baseline < 300 ms; 2 s budget = CI-safe
    })());

  // ---- CLI contract: unknown option exits 2 (docs/AGENT-INTEGRATION + SKILL) ----
  await (async () => {
    const { execFileSync } = await import("node:child_process");
    let code = 0;
    try {
      execFileSync("node", [join(ROOT, "dist", "cli.js"), "scan", "--definitely-not-an-option", join(ROOT, "tests", "clean", "app")], { encoding: "utf8", stdio: "pipe" });
    } catch (e) { code = e.status; }
    check("U20.35 CLI: unknown option is a USAGE refusal → exit 2 (commander default was the --fail-on code 1)", code === 2);
  })();

  // ---- §5.1: SAST-003 in test-class paths → LOW review note (never excluded) ----
  check("U20.36 SAST-003: interpolated eval in specs/proof.ts stays VISIBLE but LOW/low (demoted, not excluded)",
    sastFind('const out = eval("validate(" + expr + ")");\n', "specs/proof.ts")
      .some((f) => f.id === "SAST-003" && f.severity === "low" && f.confidence === "low" && f.needs_confirmation === true));
  check("U20.37 SAST-003: same eval in a NON-test path keeps the full HIGH verdict",
    sastFind('const out = eval("validate(" + expr + ")");\n', "scripts/tooling.ts")
      .some((f) => f.id === "SAST-003" && f.severity === "high" && f.confidence === "medium"));
  check("U20.38 SAST-003: path segment scoping — latest.ts is NOT a test path (no accidental demotion)",
    sastFind('const out = eval("validate(" + expr + ")");\n', "src/latest.ts")
      .some((f) => f.id === "SAST-003" && f.severity === "high"));
}

// ---------- U21: capability packs A–F (v1.4) — positives, cleans, generalizations ----------
{
  const actx = (files) => ({ stack: { frameworks: {}, detected: [] }, rel: (x) => x, trackedFiles: new Set(), gitAvailable: false, files });
  const mkf = (rel, content) => ({ abs: `/p/${rel}`, rel, content, lines: content.split("\n") });
  const { scanAuthz, scanTenant } = await import(d("dist/rules/authzpack.js"));
  const { scanLeak } = await import(d("dist/rules/leakpack.js"));
  const { scanDos } = await import(d("dist/rules/dospack.js"));
  const { scanUpload } = await import(d("dist/rules/upload.js"));
  const idsOf = (mod, files) => mod(actx(files)).findings.map((f) => `${f.id}/${f.severity}`);

  // ---- A: RBAC/authz ----
  const postBody =
    'export async function POST(req: NextRequest) {\n' +
    '  const data = await req.json();\n' +
    '  await prisma.user.update({ where: { id: data.id }, data: { role: data.role } });\n' +
    '  return NextResponse.json({ ok: true });\n' +
    '}\n';
  check("U21.1 A: mutating handler + privileged op, no authz shape → AUTHZ-001 MEDIUM needs_confirmation + invisible-layer note",
    (() => {
      const fs = scanAuthz(actx([mkf("app/api/u/route.ts", postBody)])).findings;
      return fs.some((f) => f.id === "AUTHZ-001" && f.severity === "medium" && f.needs_confirmation === true)
        && /middleware|APP_GUARD|RLS/.test(fs[0].evidence.note ?? "");
    })());
  check("U21.2 A clean: same handler with an authorization call in body → SILENT",
    scanAuthz(actx([mkf("app/api/u/route.ts",
      postBody.replace("const data =", "const session = await getSession(userEmail);\n  const data ="))])).findings.length === 0);
  check("U21.3 A: client-decided authorization (req.body.isAdmin) → AUTHZ-002 HIGH; server-state decision → SILENT",
    idsOf(scanAuthz, [mkf("app/api/a/route.ts", 'export async function POST(req: Request) {\n  if (req.body.isAdmin) { await grantAdmin(); }\n}\n')]).includes("AUTHZ-002/high")
    && scanAuthz(actx([mkf("app/api/a/route.ts", "export async function POST(req: Request) {\n  const u = await db.user.findUnique({ where: { id: sess.userId } });\n  if (u.role === 'admin') grantAdmin();\n}\n")])).findings.length === 0);
  check("U21.4 A generalize: express router + DB destructive call (different framework shape) → AUTHZ-001",
    idsOf(scanAuthz, [mkf("server/routes.ts", 'router.post("/users/del", (req, res) => {\n  db.collection("users").deleteOne({ _id: req.params.id });\n  res.json({ ok: true });\n});\n')]).includes("AUTHZ-001/medium"));

  // ---- B: multi-tenant ----
  const schema = mkf("prisma/schema.prisma", "model Doc {\n  id Int @id\n  organizationId Int\n  ownerId Int\n}\n");
  check("U21.5 B: by-ID mutation of tenant entity, request-sourced id → TEN-002; tenant-scoped where → SILENT; no tenant declaration → SILENT",
    idsOf(scanTenant, [schema, mkf("app/api/d/route.ts", "export async function DELETE(req: Request) {\n  await prisma.doc.update({ where: { id: req.params.id }, data: { deleted: true } });\n}\n")]).includes("TEN-002/medium")
    && scanTenant(actx([schema, mkf("app/api/d/route.ts", "export async function DELETE(req: Request) {\n  await prisma.doc.update({ where: { id: req.params.id, organizationId: sess.orgId }, data: { deleted: true } });\n}\n")])).findings.length === 0
    && scanTenant(actx([mkf("app/api/d/route.ts", "export async function DELETE(req: Request) {\n  await prisma.doc.update({ where: { id: req.params.id }, data: { deleted: true } });\n}\n")])).findings.length === 0);
  check("U21.6 B: unscoped SQL on tenant table + req value → TEN-001; scoped (org predicate) → SILENT",
    idsOf(scanTenant, [
      mkf("migrations/0001_init.sql", "CREATE TABLE workspace_docs (id INT, workspace_id INT, owner_id INT);\n"),
      mkf("server/db.ts", 'export async function rm(req: Request) {\n  return pool.query("DELETE FROM workspace_docs WHERE id = " + req.params.id);\n}\n'),
    ]).includes("TEN-001/medium")
    && scanTenant(actx([
      mkf("migrations/0001_init.sql", "CREATE TABLE workspace_docs (id INT, workspace_id INT, owner_id INT);\n"),
      mkf("server/db.ts", 'export async function rm(req: Request, org: number) {\n  return pool.query("DELETE FROM workspace_docs WHERE id = $1 AND workspace_id = $2", [req.params.id, org]);\n}\n'),
    ])).findings.length === 0);
  check("U21.6b B generalize: tenant entity declared via ALTER TABLE migration also gates the pack",
    idsOf(scanTenant, [
      mkf("migrations/0002.sql", "ALTER TABLE projects ADD COLUMN workspace_id INT;\n"),
      mkf("server/db.ts", 'export async function rm(req: Request) {\n  return pool.query("DELETE FROM projects WHERE id = " + req.params.id);\n}\n'),
    ]).includes("TEN-001/medium"));

  // ---- C: leakage ----
  check("U21.7 C: credential field in NextResponse.json → LEAK-001; password:undefined → SILENT",
    idsOf(scanLeak, [mkf("app/api/login/route.ts", "const u = await findUser(id);\nreturn NextResponse.json({ id: u.id, password: u.password });\n")]).includes("LEAK-001/medium")
    && scanLeak(actx([mkf("app/api/login/route.ts", "return NextResponse.json({ id: u.id, password: undefined });\n")])).findings.length === 0);
  check("U21.8 C: PII to log → LEAK-002 LOW note; redact() → SILENT; JSON.stringify variant also fires (generalization)",
    idsOf(scanLeak, [mkf("server/metrics.ts", "console.log('login ok', user.email);\n")]).includes("LEAK-002/low")
    && scanLeak(actx([mkf("server/metrics.ts", "console.log('login ok', redact(user.email));\n")])).findings.length === 0
    && idsOf(scanLeak, [mkf("server/app.js", "app.get('/n', (req, res) => {\n  res.send(JSON.stringify({ apiKey: cfg.apiKey }));\n});\n")]).includes("LEAK-001/medium"));

  // ---- D: resource exhaustion ----
  check("U21.9 D: new RegExp(req.query.q) → RES-001 HIGH; flow-resolved var → RES-001 MEDIUM needs_confirmation; literal regex → SILENT",
    idsOf(scanDos, [mkf("app/api/search/route.ts", "const re = new RegExp(req.query.q);\nreturn db.find(re);\n")]).includes("RES-001/high")
    && idsOf(scanDos, [mkf("app/api/search/route.ts", "const pat = req.query.q;\nconst re = new RegExp(pat);\n")]).includes("RES-001/medium")
    && scanDos(actx([mkf("app/api/search/route.ts", "const re = new RegExp('^\\\\w+$');\n")])).findings.length === 0);
  check("U21.9b D generalize: express route handler shape also reaches RES-001 (direct req.body regex)",
    idsOf(scanDos, [mkf("server/routes.js", "router.post('/search', (req, res) => {\n  const re = new RegExp(req.body.term);\n});\n")]).includes("RES-001/high"));
  check("U21.10 D: prisma.findMany() inside a handler → RES-002; take-cap → SILENT; same call OUTSIDE a handler → SILENT",
    idsOf(scanDos, [mkf("app/api/list/route.ts", "export async function GET() {\n  const rows = await prisma.user.findMany();\n  return NextResponse.json(rows);\n}\n")]).includes("RES-002/medium")
    && scanDos(actx([mkf("app/api/list/route.ts", "export async function GET() {\n  const rows = await prisma.user.findMany({ take: 20 });\n  return NextResponse.json(rows);\n}\n")])).findings.length === 0
    && scanDos(actx([mkf("server/seed.ts", "const all = await prisma.user.findMany();\nfor (const u of all) seed(u);\n")])).findings.length === 0);

  // ---- F: uploads ----
  check("U21.11 F: request-derived write into served dir → UPLOAD-001 HIGH; fixed name → SILENT",
    idsOf(scanUpload, [mkf("server/upload.ts", 'const file = req.file;\nfs.writeFile(path.join("public/uploads", file.originalname), data);\n')]).includes("UPLOAD-001/high")
    && scanUpload(actx([mkf("server/upload.ts", 'fs.writeFile(path.join("assets/brand", "logo.png"), data);\n')])).findings.length === 0);
  check("U21.12 F: multer({dest}) / Busboy without limits → UPLOAD-002; limits-config → SILENT",
    idsOf(scanUpload, [mkf("server/upload.ts", 'const upload = multer({ dest: "uploads/" });\n')]).includes("UPLOAD-002/medium")
    && scanUpload(actx([mkf("server/upload.ts", 'const upload = multer({ limits: { fileSize: 5 * 1024 * 1024 } });\n')])).findings.length === 0
    && idsOf(scanUpload, [mkf("server/up.js", "const busboy = new Busboy({ headers: req.headers });\n")]).includes("UPLOAD-002/medium"));
  check("U21.13 F: extractAllTo without guards → UPLOAD-003 EXACTLY ONCE (same root cause); guarded window → SILENT; tar.x pipeline variant fires",
    (() => {
      const pos = scanUpload(actx([mkf("server/extract.ts", "const zip = new AdmZip(buf);\nzip.extractAllTo(outputDir);\n")])).findings;
      return pos.filter((f) => f.id === "UPLOAD-003").length === 1
        && pos[0].severity === "medium" && pos[0].needs_confirmation === true
        && scanUpload(actx([mkf("server/extract.ts", "const zip = new AdmZip(buf);\nzip.getEntries().filter(e => !e.entryName.includes('..') && e.header.size < MAX).forEach(e => zip.extractEntryTo(e, outDir));\n")])).findings.length === 0
        && idsOf(scanUpload, [mkf("server/extract.js", "fs.createReadStream(p).pipe(tar.x({ cwd: out }))\n")]).includes("UPLOAD-003/medium");
    })());
}

// ---------- U22: adversarial ReDoS battery LOCK (scanner self-resilience, v1.4) ----------
// The v1.3 "ReDoS not reproduced" conclusion was WRONG: adversarial word-run /
// quote-run inputs exposed quadratic breaches in HDR-001 (9s@100KB → 81s@300KB,
// 18s@100KB → 167s@300KB) and friends — fixed by bounding greedy identifier runs
// to {0,64}. This gate locks the contract: pathological ≤512KB inputs stay
// LINEAR (growth < 6x when tripling) and under budget.
{
  const batteryCtx = (content) => ({ stack: { frameworks: {}, detected: [] }, rel: (x) => x, trackedFiles: new Set(), gitAvailable: false, files: [{ abs: "/p/a.ts", rel: "app/api/a.ts", content, lines: content.split("\n") }] });
  const { scanSecrets: bSecrets } = await import(d("dist/rules/secrets.js"));
  const { scanHdr001: bHdr } = await import(d("dist/rules/hdr001.js"));
  const { scanSast: bSast } = await import(d("dist/rules/sast.js"));
  const { scanTaint: bTaint } = await import(d("dist/rules/taint.js"));
  const bgen = {
    jwt_run: (n) => "eyJ" + "a".repeat(n) + "\n",
    quote_run: (n) => 'req.headers["' + "x".repeat(n) + "\n",
    ctx_bait: (n) => "eval " + "P".repeat(n) + "\n",
    stack_bait: (n) => "res.send('<p>" + "+".repeat(n) + "req.query.q</p>');\n",
  };
  const brules = [["secrets", bSecrets], ["hdr001", bHdr], ["sast", bSast], ["taint", bTaint]];
  let batteryOk = true;
  const BN = 60000, BN2 = 180000;
  for (const [bname, bfn] of brules) {
    for (const [bkind, bgenf] of Object.entries(bgen)) {
      const t1 = (() => { const t0 = process.hrtime.bigint(); bfn(batteryCtx(bgenf(BN))); return Number(process.hrtime.bigint() - t0) / 1e6; })();
      const t2 = (() => { const t0 = process.hrtime.bigint(); bfn(batteryCtx(bgenf(BN2))); return Number(process.hrtime.bigint() - t0) / 1e6; })();
      const growth = t2 / Math.max(t1, 0.05);
      // the GROWTH assert only means something when the base measurement itself
      // is above scheduler noise (≥10 ms); tiny runs are linear-or-better and
      // only the absolute budget is asserted for them
      if (t2 > 2000 || (t1 > 10 && growth > 6)) { batteryOk = false; console.error(`  battery ${bname}/${bkind}: n=${t1.toFixed(0)}ms 3n=${t2.toFixed(0)}ms growth=x${growth.toFixed(1)}`); }
    }
  }
  check(`U22.1 battery lock (${brules.length * Object.keys(bgen).length} cases): adversarial inputs stay LINEAR + under budget`, batteryOk);
}

// ---------- U23: capability E — large-file windowed scanning (v1.4) ----------
{
  const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(join(tmpdir(), "anubis-capE-"));
  const sub = join(dir, "app");
  mkdirSync(sub, { recursive: true });
  // 600KB+ file: JWT secret at line 2, dynamic-SQL sink near the bottom (>512KB)
  const lines = ["// capE fixture", 'const JWT_SECRET = "supa-staging-raw-pass-xyz-longenough";'];
  for (let i = 0; i < 14000; i++) lines.push(`const pad${i} = "padding padding padding padding padding padding padding padding padding";`);
  lines.push("const n = req.query.name;");
  lines.push('pool.query("SELECT * FROM users WHERE n = " + n);');
  writeFileSync(join(sub, "big.js"), lines.join("\n"));
  writeFileSync(join(sub, "huge.txt"), "y".repeat(5 * 1024 * 1024));
  const { walkWithStats } = await import(d("dist/walk.js"));
  const { windowed } = walkWithStats(dir);
  const { scan: bigScan } = await import(d("dist/engine.js"));
  const res = bigScan(dir, { format: "json" });
  const bigFinds = res.findings.filter((f) => f.file.includes("big.js"));
  check("U23.1 E: files >512KB are analyzed in windows (walk windowed + meta disclosure)",
    windowed.length === 1 && windowed[0].windows >= 2 && windowed[0].kb > 512
    && res.meta.files_windowed?.length === 1,
    JSON.stringify(windowed));
  check("U23.2 E: findings keep ABSOLUTE line numbers across seams (secret at line 2, sink at line " + lines.length + ")",
    bigFinds.some((f) => f.id === "JWT-003" && f.line === 2)
    && bigFinds.some((f) => f.id === "SAST-001" && f.line === lines.length),
    JSON.stringify(bigFinds.map((f) => `${f.id}:${f.line}`)));
  check("U23.3 E: >4MB stays skipped + disclosed (oversize) and files_scanned counts unique FILES",
    res.meta.files_skipped?.oversize === 1 && res.meta.files_scanned === 1);
  rmSync(dir, { recursive: true, force: true });
}

// ---------- U24: test-authz inventory — per-HANDLER guard attribution (v1.4) ----------
// NEST-001/test-authz investigation (synthetic Nest + Next fixtures): the
// v1.3-audit made hasAuthzCheck call-shape-based but still FILE-level — one
// guard call in one handler marked every route in the file "guarded", so a
// mixed POST-guarded/DELETE-unguarded route.ts under-reported test-authz risk
// (the authz matrix skipped the unguarded mutation). Attribution is now
// per handler body; file-level truth survives only as the conservative
// fallback for handlers whose body cannot be bounded.
{
  const { buildInventory } = await import(d("dist/inventory.js"));
  const { buildAuthzMatrix } = await import(d("dist/authz.js"));
  const ictx = (files) => ({ stack: { frameworks: { nestjs: true }, detected: [] }, rel: (x) => x, trackedFiles: new Set(), gitAvailable: false, files });
  const imkf = (rel, content) => ({ abs: `/p/${rel}`, rel, content, lines: content.split("\n") });

  const mixedRoute =
    "export async function POST(req: Request) {\n" +
    "  const s = await getSession();\n" +
    "  await prisma.user.update({ where: { id: s.userId }, data: { name: \"x\" } });\n" +
    "}\n" +
    "export async function DELETE(req: Request) {\n" +
    "  await prisma.user.delete({ where: { id: req.params.id } });\n" +
    "}\n";
  const nestBare =
    "import { Controller, Get, Delete } from '@nestjs/common';\n" +
    "@Controller('admin')\n" +
    "export class AdminController {\n" +
    "  @Get()\n" +
    "  stats() { return {}; }\n" +
    "  @Delete(':id')\n" +
    "  purge() { return {}; }\n" +
    "}\n";
  const inv = buildInventory(ictx([
    imkf("app/api/mixed/route.ts", mixedRoute),
    imkf("src/admin.controller.ts", nestBare),
  ]));
  const routeRows = inv.routes.filter((r) => r.kind === "route");
  const postRow = routeRows.find((r) => r.method === "POST");
  const delRow = routeRows.find((r) => r.method === "DELETE");
  check("U24.1 inventory: guard attribution is PER-HANDLER (POST guarded, DELETE null in the same file)",
    postRow?.guard === "in-file" && delRow?.guard === null,
    `post=${postRow?.guard} del=${delRow?.guard}`);

  const matrix = buildAuthzMatrix(inv);
  const delMatrix = matrix.find((r) => r.method === "DELETE" && r.path === "/api/mixed");
  check("U24.2 test-authz: the unguarded mutation now reaches the matrix as authz_risk=true (was silently guarded)",
    delMatrix?.authz_risk === true && delMatrix?.exposure === "unguarded"
    && matrix.find((r) => r.method === "POST" && r.path === "/api/mixed")?.authz_risk === false,
    JSON.stringify(delMatrix));

  // fallback honesty: a handler the bounder cannot close keeps the file-level truth
  const giant =
    "export async function POST(req: Request) {\n" +
    "  " + Array.from({ length: 70 }, (_, i) => `x${i} = ${i};`).join("\n  ") + "\n" +
    "  await requireAuth();\n" +
    "  await prisma.user.deleteMany();\n" +
    "}\n";
  const invGiant = buildInventory(ictx([imkf("app/api/giant/route.ts", giant)]));
  check("U24.3 inventory: handler beyond the bounding budget falls back to file-level truth (conservative, not silent)",
    invGiant.routes.find((r) => r.kind === "route")?.guard === "in-file");

  // Nest method-level > class-level > APP_GUARD attribution (seeded global guard via file content)
  const nestClass =
    "import { Controller, Get, UseGuards } from '@nestjs/common';\n" +
    "@UseGuards(JwtAuthGuard)\n" +
    "@Controller('pets')\n" +
    "export class PetsController {\n" +
    "  @Get()\n" +
    "  list() { return []; }\n" +
    "}\n";
  const invNest = buildInventory(ictx([
    imkf("src/admin.controller.ts", nestBare),
    imkf("src/pets.controller.ts", nestClass),
    imkf("src/app.module.ts", "import { APP_GUARD } from '@nestjs/core';\n{ provide: APP_GUARD, useClass: AdminGuard }\n"),
  ]));
  const nestRows = invNest.routes.filter((r) => r.kind === "controller-method");
  check("U24.4 inventory: Nest guard attribution = method-level > class-level > APP_GUARD (global sentinel in evidence)",
    nestRows.find((r) => r.method === "GET" && r.file.includes("pets"))?.guard === "JwtAuthGuard"
    && nestRows.filter((r) => r.file.includes("admin")).every((r) => r.guard === "APP_GUARD"),
    JSON.stringify(nestRows.map((r) => `${r.file}:${r.method}=${r.guard}`)));
}

// ---------- report ----------
console.error(`\nUNIT VERIFICATION: ${PASS} passed, ${FAILS.length} failed`);
if (FAILS.length) {
  for (const f of FAILS) console.error(`  FAILED: ${f}`);
  process.exit(1);
}
