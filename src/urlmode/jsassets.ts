import { maskSecret } from "../util.js";
import type { RawFinding } from "../util.js";
import { mkFinding, rootCause } from "../util.js";
import type { OwnershipResult } from "./types.js";

/**
 * Public JS bundle analysis — the L1 flagship (Plan v1.3: downloading public
 * assets is browser-equivalent, so the most common vibe-coding hole — secrets
 * shipped to the browser — is scanned in the FREE default level, not behind a gate).
 *
 * Patterns are gitleaks-inspired (MIT-attributed, same lineage as Layer 1).
 * The VALUE is masked (first-4 + sha256 prefix) exactly like Mode 1 — the full
 * value is never written anywhere (Section 9.2).
 */

const PLACEHOLDER = /(changeme|change_me|xxxxx|<[^>]*>|\$\{[^}]*\}|your[-_][a-z_]+|example|placeholder|dummy|todo|fixme|\*{3,}|test_key|sk-test|sk-proj-test)/i;

interface BundlePattern {
  name: string;
  re: RegExp;
  severity: "critical" | "high";
  provider: string;
  note: string;
}

const BUNDLE_PATTERNS: BundlePattern[] = [
  { name: "supabase_service_role", re: /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: "critical", provider: "supabase", note: "JWT-shaped token — confirmed below by decoding the role claim" },
  { name: "aws_access_key", re: /\bAKIA[0-9A-Z]{16}\b/g, severity: "critical", provider: "aws", note: "" },
  { name: "stripe_live", re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/g, severity: "critical", provider: "stripe", note: "" },
  { name: "openai", re: /\bsk-[A-Za-z0-9_-]{40,}\b/g, severity: "high", provider: "openai", note: "" },
  { name: "github", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g, severity: "high", provider: "github", note: "" },
  { name: "google", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: "high", provider: "google", note: "" },
  { name: "slack", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, severity: "high", provider: "slack", note: "" },
  { name: "private_key", re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY( BLOCK)?-----/g, severity: "critical", provider: "generic", note: "" },
  { name: "db_url", re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s'"@:/]+:([^\s'"@]{4,})@[^\s'"]+/g, severity: "high", provider: "generic", note: "" },
  { name: "resend", re: /\bre_[A-Za-z0-9]{30,}\b/g, severity: "high", provider: "resend", note: "" },
];

/** JWT role claim decode (unverified base64 — used to classify, never to trust). */
export function jwtRole(token: string): string | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
    return typeof payload?.role === "string" ? payload.role : null;
  } catch {
    return null;
  }
}

export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  } catch {
    return null;
  }
}

export interface BundleIntel {
  assetUrl: string;             // the bundle/inline-script location the intel came from
  secrets: RawFinding[];
  endpoints: string[];
  sourcemapRefs: string[];      // sourceMappingURL targets (relative or absolute)
  supabase: { url?: string; anonKey?: string; serviceRoleKey?: string };
}

export interface BundleScanArgs {
  text: string;
  assetUrl: string;             // the public .js URL the secret ships from
  origin: string;               // scheme://host[:port] of the scanned site
  stack: string[];
}

/** Scan one captured bundle text; deterministic order (patterns → matches by offset). */
export function scanBundle({ text, assetUrl, origin, stack }: BundleScanArgs): BundleIntel {
  const secrets: RawFinding[] = [];
  const endpoints = new Set<string>();
  const sourcemapRefs: string[] = [];
  const supabase: BundleIntel["supabase"] = {};

  for (const p of BUNDLE_PATTERNS) {
    p.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = p.re.exec(text)) !== null) {
      const value = m[0];
      if (PLACEHOLDER.test(value)) continue;
      if (p.name === "supabase_service_role") {
        const role = jwtRole(value);
        if (role === "anon") {
          supabase.anonKey = supabase.anonKey ?? value;
          continue; // anon key is public-by-design — RLS is the control, not secrecy
        }
        if (role !== "service_role") continue; // not a supabase JWT / not service_role → not this rule
        supabase.serviceRoleKey = supabase.serviceRoleKey ?? value;
      }
      if (p.name === "db_url" && PLACEHOLDER.test(value)) continue;
      secrets.push(mkFinding({
        id: "URL-040",
        severity: p.severity,
        title: `Secret shipped in a public JavaScript bundle (${p.provider})`,
        file: assetUrl,
        line: 0,
        evidence: { type: `public_bundle_${p.name}`, masked: maskSecret(value).masked, sha256_prefix: maskSecret(value).sha256_prefix, note: p.note || undefined },
        owasp: "A02",
        confidence: "high",
        fix: "Remove the secret from any code reachable by the client build, move it to server-side env only, rotate the credential at the provider (rotate-first), then purge old bundles/CDN cache.",
        remediation: { type: "rotate-first", provider: p.provider, steps: "Rotate the credential at the provider dashboard FIRST, then remove it from client code, then purge CDN/edge cache of old bundles." },
        root: maskSecret(value).sha256_prefix,
        root_cause: rootCause("URL-040", maskSecret(value).sha256_prefix),
        needs_confirmation: false,
      }));
    }
  }

  // internal endpoints + localhost references (mapping only)
  for (const m of text.matchAll(/https?:\/\/[a-z0-9.-]*(?:internal|intranet|local|localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s"'`)\]]*/gi)) {
    endpoints.add(m[0].replace(/[.,;)]+$/, ""));
  }

  // sourceMappingURL (advice at L1; actual exposure check is L2)
  for (const m of text.matchAll(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/g)) {
    sourcemapRefs.push(m[1]);
  }

  // supabase project URL + anon key (feeds the v0.4 live anon probe — GET-only)
  const supaUrl = text.match(/https:\/\/[a-z0-9]{20}\.supabase\.co/i);
  if (supaUrl) supabase.url = supaUrl[0];

  return { assetUrl, secrets, endpoints: [...endpoints].slice(0, 10), sourcemapRefs, supabase };
}

/** Where-in-code guidance (Plan v1.4 output contract — Mode 2 pairs every finding with a code map). */
export function codeMapHint(stack: string[], ruleClass: string): string {
  const has = (s: string) => stack.includes(s);
  switch (ruleClass) {
    case "secret":
      if (has("supabase")) return "Code map: search the repo for the key literal's first 4 chars and for `SUPABASE_SERVICE_ROLE` / `createClient(` — server-only files (e.g. src/lib/supabase*). Run Codebase Mode on the repo for exact file:line.";
      return "Code map: search the repo for the masked value's first 4 chars; the leak is in client-bundled code (components, lib, env vars exposed to the client). Run Codebase Mode for exact file:line.";
    case "header":
      if (has("nextjs")) return "Code map: middleware.ts (response headers) or next.config.js headers()/async headers — or the reverse proxy (nginx/vercel.json).";
      if (has("nestjs")) return "Code map: main.ts bootstrap (Helmet/registerMiddleware) or the reverse proxy config.";
      return "Code map: server bootstrap or reverse proxy config (nginx / platform headers settings).";
    case "env":
      return "Code map: the deployment pipeline is shipping dotfiles — check Dockerfile COPY scope, .dockerignore, static host config (e.g. `vercel.json`, `netlify.toml`), and the web root contents.";
    case "git":
      return "Code map: the web server is serving the repository folder — check nginx root config / static host rules; the .git dir must never be inside the web root.";
    case "sourcemap":
      if (has("nextjs")) return "Code map: next.config.js `productionBrowserSourceMaps` or the bundler config that emits .map files into the public build.";
      return "Code map: bundler config (webpack/vite/terser sourceMap option) that ships .map files with the production build.";
    case "cors":
      return "Code map: CORS middleware config (next.config / nest main.ts enableCors / proxy headers).";
    default:
      return "Code map: run Codebase Mode (anubis-guardian scan .) on the repository to map this to exact file:line.";
  }
}

export function ownershipNote(o: OwnershipResult): string {
  return o.verified
    ? `ownership: verified via ${o.method}`
    : o.method === "self-attested (local only)"
      ? "ownership: self-attested (local only)"
      : "ownership: none";
}
