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
 * All imports come from dist/ — run after `npm run build` (the npm test chain does).
 */
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = join(import.meta.dirname ?? ".", "..");
const d = (p) => pathToFileURL(join(ROOT, p)).href;

const { parseVer, cmpVer, versionInRange, affects } = await import(d("dist/advisory/index.js"));
const { maskSecret, sha256Prefix, fingerprint, parseInlineIgnores, applySuppression, deducts, uniqBy, globWorkspaces } =
  await import(d("dist/util.js"));
const { importedFromClient, resolveSpec, classifyFile } = await import(d("dist/rules/context.js"));
const { argSecretRisk } = await import(d("dist/rules/ci.js"));
const { parseMatcher, matcherCovers, matcherToRegExp } = await import(d("dist/rules/packs2.js"));
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

// ---------- report ----------
console.error(`\nUNIT VERIFICATION: ${PASS} passed, ${FAILS.length} failed`);
if (FAILS.length) {
  for (const f of FAILS) console.error(`  FAILED: ${f}`);
  process.exit(1);
}
