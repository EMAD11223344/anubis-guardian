import type { RawFinding } from "../util.js";
import { mkFinding, rootCause } from "../util.js";
import type { CapturedResponse, CaptureBundle } from "./types.js";
import { codeMapHint } from "./jsassets.js";
import { sourcemapHasSources } from "./checks-l1.js";

/**
 * Level 2 — Verified Discovery (Plan Section 7). Every request here is a
 * probing request, which is exactly why the whole level is gated behind
 * verified ownership for public domains (v1.3) — self-attestation exists
 * only for localhost/private staging and is labeled in the report.
 * Path list: SecLists-derived (MIT), curated + attributed — never the full repo.
 */

export interface Probe {
  path: string;
  rule: string;
  klass: string;               // code-map hint class
  validate: (r: CapturedResponse) => false | { severity: "critical" | "high" | "medium" | "low"; note: string };
}

const looksHtml = (r: CapturedResponse) => /<html[\s>]|<!doctype/i.test(r.body);

const isEnvBody = (r: CapturedResponse) =>
  !looksHtml(r) && /^[A-Z0-9_]+\s*=\s*\S+/m.test(r.body);

const envHasSecret = (r: CapturedResponse) =>
  /(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|DSN|URI|DATABASE_URL|SERVICE_ROLE)\s*=\s*["']?[^\s"']{8,}/i.test(r.body);

const isGitConfig = (r: CapturedResponse) => /\[core\]|\[branch|\[remote/i.test(r.body);
const isGitHead = (r: CapturedResponse) => /^ref:\s*refs\//.test(r.body.trim()) || /^[0-9a-f]{40}\b/.test(r.body.trim());
const isSqlDump = (r: CapturedResponse) => /(?:CREATE TABLE|INSERT INTO|COPY\s+[a-z"]+)/i.test(r.body);
const isBackupZip = (r: CapturedResponse) => r.body.startsWith("PK\u0003\u0004");
const isDsStore = (r: CapturedResponse) => r.body.includes("Bud1");
const isPhpBak = (r: CapturedResponse) => /<\?php/.test(r.body);
const isComposer = (r: CapturedResponse) => {
  try { const j = JSON.parse(r.body); return typeof j === "object" && ("require" in j || "name" in j); } catch { return false; }
};

/** Curated sensitive-path list (SecLists-derived, attributed — Plan Section 7 L2). */
export const PROBES: Probe[] = [
  { path: "/.env", rule: "URL-050", klass: "env", validate: (r) => isEnvBody(r) && (envHasSecret(r) ? { severity: "critical", note: "env file with secret-shaped values is publicly served" } : { severity: "high", note: "env file publicly served" }) },
  { path: "/.env.local", rule: "URL-050", klass: "env", validate: (r) => isEnvBody(r) && (envHasSecret(r) ? { severity: "critical", note: "env file with secret-shaped values is publicly served" } : { severity: "high", note: "env file publicly served" }) },
  { path: "/.env.production", rule: "URL-050", klass: "env", validate: (r) => isEnvBody(r) && (envHasSecret(r) ? { severity: "critical", note: "production env file with secret-shaped values is publicly served" } : { severity: "high", note: "production env file publicly served" }) },
  { path: "/.env.backup", rule: "URL-050", klass: "env", validate: (r) => isEnvBody(r) && (envHasSecret(r) ? { severity: "critical", note: "env backup with secret-shaped values is publicly served" } : { severity: "high", note: "env backup publicly served" }) },
  { path: "/.env.bak", rule: "URL-050", klass: "env", validate: (r) => isEnvBody(r) && (envHasSecret(r) ? { severity: "critical", note: "env backup with secret-shaped values is publicly served" } : { severity: "high", note: "env backup publicly served" }) },
  { path: "/backend/.env", rule: "URL-050", klass: "env", validate: (r) => isEnvBody(r) && (envHasSecret(r) ? { severity: "critical", note: "env file with secret-shaped values is publicly served" } : { severity: "high", note: "env file publicly served" }) },
  { path: "/api/.env", rule: "URL-050", klass: "env", validate: (r) => isEnvBody(r) && (envHasSecret(r) ? { severity: "critical", note: "env file with secret-shaped values is publicly served" } : { severity: "high", note: "env file publicly served" }) },
  { path: "/.git/config", rule: "URL-051", klass: "git", validate: (r) => isGitConfig(r) && { severity: "high", note: "the repository's .git directory is web-served" } },
  { path: "/.git/HEAD", rule: "URL-051", klass: "git", validate: (r) => isGitHead(r) && { severity: "high", note: "the repository's .git directory is web-served" } },
  { path: "/.git/logs/HEAD", rule: "URL-051", klass: "git", validate: (r) => /refs\/heads/.test(r.body) && { severity: "high", note: "git reflog is web-served" } },
  { path: "/db.sql", rule: "URL-052", klass: "dump", validate: (r) => isSqlDump(r) && { severity: "critical", note: "SQL dump (CREATE/INSERT statements) is publicly downloadable" } },
  { path: "/dump.sql", rule: "URL-052", klass: "dump", validate: (r) => isSqlDump(r) && { severity: "critical", note: "SQL dump (CREATE/INSERT statements) is publicly downloadable" } },
  { path: "/database.sql", rule: "URL-052", klass: "dump", validate: (r) => isSqlDump(r) && { severity: "critical", note: "SQL dump (CREATE/INSERT statements) is publicly downloadable" } },
  { path: "/backup.zip", rule: "URL-052", klass: "dump", validate: (r) => isBackupZip(r) && { severity: "high", note: "backup archive is publicly downloadable" } },
  { path: "/backup.tar.gz", rule: "URL-052", klass: "dump", validate: (r) => isBackupZip(r) && { severity: "high", note: "backup archive is publicly downloadable" } },
  { path: "/.DS_Store", rule: "URL-052", klass: "dump", validate: (r) => isDsStore(r) && { severity: "low", note: "macOS .DS_Store leaks directory names" } },
  { path: "/composer.json", rule: "URL-053", klass: "dump", validate: (r) => isComposer(r) && { severity: "low", note: "composer.json exposes the dependency map publicly" } },
  { path: "/wp-config.php.bak", rule: "URL-050", klass: "env", validate: (r) => isPhpBak(r) && /DB_PASSWORD|DB_USER/i.test(r.body) && { severity: "critical", note: "wp-config backup with DB credentials is publicly served" } },
  { path: "/config.php.bak", rule: "URL-050", klass: "env", validate: (r) => isPhpBak(r) && /PASSWORD|SECRET|KEY/i.test(r.body) && { severity: "critical", note: "config backup with credentials is publicly served" } },
];

/** Directory-listing candidate paths (L2: "Directory listing enabled"). */
export const LISTING_PATHS = ["/backup/", "/uploads/", "/static/", "/files/", "/assets/"];

/** API-doc candidate paths (L2: exposed API docs). */
export const APIDOC_PATHS: Array<{ path: string; marker: RegExp; product: string }> = [
  { path: "/swagger/index.html", marker: /swagger-ui|openapi/i, product: "Swagger UI" },
  { path: "/swagger", marker: /swagger|openapi/i, product: "Swagger" },
  { path: "/swagger-ui", marker: /swagger-ui/i, product: "Swagger UI" },
  { path: "/swagger-ui/index.html", marker: /swagger-ui/i, product: "Swagger UI" },
  { path: "/api-docs", marker: /swagger|openapi|api.?doc/i, product: "API docs" },
  { path: "/documentation", marker: /swagger|openapi/i, product: "API docs" },
  { path: "/graphiql", marker: /graphi?ql/i, product: "GraphiQL" },
  { path: "/playground", marker: /graphi?ql|playground/i, product: "GraphQL playground" },
];

/** Admin/login surface mapping (INFO — mapping only, no deduction). */
export const SURFACE_PATHS = ["/admin", "/login", "/signin", "/register", "/wp-admin", "/dashboard"];

export function runL2(bundle: CaptureBundle): RawFinding[] {
  const F: RawFinding[] = [];
  const stack = inferStack(bundle);
  const origin = new URL(bundle.meta.url).origin;

  // ---- sensitive files ----
  for (const r of bundle.requests) {
    const probe = PROBES.find((p) => r.method === "GET" && (r.url === `${origin}${p.path}` || r.final_url === `${origin}${p.path}`));
    if (!probe || r.status !== 200) continue;
    const v = probe.validate(r);
    if (!v) continue;
    F.push(mkFinding({
      id: probe.rule, severity: v.severity,
      title: v.severity === "critical" ? `Sensitive file publicly served: ${probe.path}` : `Exposed file: ${probe.path}`,
      file: r.final_url, line: 0,
      evidence: { type: "probed_file_exposed", masked: `${probe.path} (HTTP 200, ${r.bytes} bytes)`, note: v.note },
      owasp: "A05", confidence: "high",
      fix: `Remove ${probe.path} from the web root / deny serving it at the edge, rotate anything it contains (rotate-first), and purge CDN cache. ${codeMapHint(stack, probe.klass)}`,
      remediation: probe.rule === "URL-050" && v.severity === "critical"
        ? { type: "rotate-first", steps: "Treat every value in the exposed env file as compromised: rotate at the provider FIRST, then remove the file from the web root, then purge CDN/edge cache." }
        : undefined,
      root: probe.path, root_cause: rootCause(probe.rule, probe.path),
    }));
  }

  // ---- directory listing ----
  for (const r of bundle.requests) {
    if (r.method !== "GET" || r.status !== 200) continue;
    const p = LISTING_PATHS.find((lp) => r.url === `${origin}${lp}`);
    if (!p) continue;
    if (/(?:<title>)\s*Index of \/|(?:Directory listing for )/i.test(r.body) && !looksHtmlStrictApp(r)) {
      F.push(mkFinding({
        id: "URL-054", severity: "medium", title: `Directory listing enabled: ${p}`,
        file: r.final_url, line: 0,
        evidence: { type: "directory_listing", masked: `${p} (HTTP 200 — "Index of")` },
        owasp: "A05", confidence: "high",
        fix: `Disable autoindex for ${p} at the server/edge (nginx autoindex off; S3/CDN bucket policy) — listing exposes files no page links to. ${codeMapHint(stack, "env")}`,
        root: p, root_cause: rootCause("URL-054", p),
      }));
    }
  }

  // ---- HTTP methods: TRACE reflection + risky Allow ----
  const trace = bundle.requests.find((r) => r.method === "TRACE");
  if (trace && trace.status === 200 && /TRACE/i.test(trace.body)) {
    F.push(mkFinding({
      id: "URL-055", severity: "high", title: "TRACE method enabled (reflects requests — XST)",
      file: trace.final_url, line: 0,
      evidence: { type: "http_method_trace", masked: "TRACE returned 200 and reflected the request" },
      owasp: "A05", confidence: "high",
      fix: "Disable TRACE at the server/edge (nginx: trace_method off; most platforms deny it by default).",
      root: "methods", root_cause: rootCause("URL-055", "methods"),
    }));
  }
  const options = bundle.requests.find((r) => r.method === "OPTIONS");
  if (options && options.status < 400) {
    const allow = `${options.headers["allow"] ?? ""},${options.headers["access-control-allow-methods"] ?? ""}`.toUpperCase();
    const risky = ["PUT", "DELETE", "TRACE", "CONNECT"].filter((m) => new RegExp(`\\b${m}\\b`).test(allow));
    if (risky.length) {
      F.push(mkFinding({
        id: "URL-056", severity: "medium", title: `Permissive Allow header advertises risky methods (${risky.join(", ")})`,
        file: options.final_url, line: 0,
        evidence: { type: "http_method_allow", masked: allow.slice(0, 120) },
        owasp: "A05", confidence: "medium",
        fix: "Restrict allowed methods to what the app uses (GET/POST/HEAD); disable WebDAV-style verbs at the edge.", needs_confirmation: true,
        root: "methods", root_cause: rootCause("URL-056", "methods"),
      }));
    }
  }

  // ---- exposed API docs ----
  for (const r of bundle.requests) {
    if (r.method !== "GET" || r.status !== 200) continue;
    const doc = APIDOC_PATHS.find((d) => r.url === `${origin}${d.path}` || r.final_url === `${origin}${d.path}`);
    if (!doc) continue;
    if (doc.marker.test(r.body) && !looksHtmlStrictApp(r)) {
      F.push(mkFinding({
        id: "URL-057", severity: "medium", title: `${doc.product} exposed on production`,
        file: r.final_url, line: 0,
        evidence: { type: "api_doc_exposed", masked: `${doc.path} (HTTP 200)` },
        owasp: "A05", confidence: "high",
        fix: `Disable ${doc.product} outside development (NestJS SwaggerModule setup gated by NODE_ENV; GraphQL introspection off in prod), or protect it behind auth. ${codeMapHint(stack, "docs")}`,
        root: doc.path, root_cause: rootCause("URL-057", doc.path),
      }));
    }
  }

  // ---- sourcemap exposure (L2 upgrades the L1 advice) ----
  for (const r of bundle.requests) {
    if (r.method !== "GET" || r.status !== 200 || !r.url.endsWith(".map")) continue;
    if (sourcemapHasSources(r.body)) {
      const hasSecret = /(?:SECRET|TOKEN|PASSWORD|api[_-]?key|service_role|sk_live|AKIA)/i.test(r.body);
      F.push(mkFinding({
        id: "URL-042", severity: hasSecret ? "high" : "medium",
        title: hasSecret ? "Exposed source map ships original sources with secret-shaped content" : "Exposed source map ships original application sources",
        file: r.final_url, line: 0,
        evidence: { type: "sourcemap_exposed", masked: `${r.url} (JSON map with sources[])`, note: hasSecret ? "secret-shaped strings inside sourcesContent" : undefined },
        owasp: "A05", confidence: "high",
        fix: "Disable source maps in production builds; remove .map files from the deployed bundle and purge the CDN cache. " + codeMapHint(stack, "sourcemap"),
        root: r.url, root_cause: rootCause("URL-042", r.url),
      }));
    }
  }

  // ---- login/admin surface mapping (INFO) ----
  const surfaces = bundle.requests.filter((r) => r.method === "GET" && r.status === 200 && SURFACE_PATHS.some((p) => r.url === `${origin}${p}`));
  if (surfaces.length) {
    F.push(mkFinding({
      id: "URL-901", severity: "info",
      title: `Auth/admin surfaces reachable: ${surfaces.map((r) => new URL(r.url).pathname).join(", ")}`,
      file: surfaces[0].final_url, line: 0,
      evidence: { type: "surface_mapping", masked: surfaces.map((r) => new URL(r.url).pathname).join(",") },
      owasp: "A07", confidence: "high",
      fix: "Informational mapping — ensure each surface sits behind auth (Codebase Mode AUTH-001 checks the middleware).",
    }));
  }

  return F;
}

function looksHtmlStrictApp(r: CapturedResponse): boolean {
  // SPA index.html served for unknown routes (catch-all) — not a real doc hit
  return /<div id="(?:root|app)"><\/div>|__NEXT_DATA__/i.test(r.body);
}

export function inferStack(bundle: CaptureBundle): string[] {
  const homepage = bundle.requests[0];
  const s = new Set<string>();
  if (homepage) {
    if ((homepage.headers["x-powered-by"] ?? "").includes("Next.js") || homepage.body.includes("/_next/static")) s.add("nextjs");
    if ((homepage.headers["x-powered-by"] ?? "").includes("Express")) s.add("express");
    if (homepage.body.match(/https:\/\/[a-z0-9]{20}\.supabase\.co/i)) s.add("supabase");
    if (homepage.body.includes("wp-content")) s.add("wordpress");
  }
  return [...s].sort();
}
