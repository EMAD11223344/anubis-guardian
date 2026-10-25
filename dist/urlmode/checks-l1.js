import { mkFinding, rootCause } from "../util.js";
import { codeMapHint, scanBundle } from "./jsassets.js";
/**
 * Level 1 — Passive External Scan (Plan Section 7): browser-equivalent requests
 * ONLY. Homepage + robots.txt + sitemap.xml + security.txt + the public JS
 * assets the page itself loads (v1.3) + tech fingerprinting. Zero probing —
 * not a single request outside what an open browser would do.
 */
const HEADER_CHECKS = [
    { id: "URL-010", header: "content-security-policy", title: "Content-Security-Policy header missing", severity: "medium", owasp: "A05",
        fix: "Serve a Content-Security-Policy header (start with a report-then-enforce rollout; script-src 'self', no unsafe-inline for new code).", klass: "header" },
    { id: "URL-012", header: "x-frame-options", title: "Clickjacking protection missing (no X-Frame-Options / frame-ancestors)", severity: "medium", owasp: "A05",
        fix: "Serve X-Frame-Options: DENY (or CSP frame-ancestors 'none') so the site cannot be framed by attacker pages.", klass: "header" },
    { id: "URL-013", header: "x-content-type-options", title: "X-Content-Type-Options header missing", severity: "low", owasp: "A05",
        fix: "Serve X-Content-Type-Options: nosniff on all responses.", klass: "header" },
    { id: "URL-014", header: "referrer-policy", title: "Referrer-Policy header missing", severity: "low", owasp: "A05",
        fix: "Serve Referrer-Policy: strict-origin-when-cross-origin (or stricter).", klass: "header" },
    { id: "URL-015", header: "permissions-policy", title: "Permissions-Policy header missing", severity: "low", owasp: "A05",
        fix: "Serve a Permissions-Policy restricting camera/microphone/geolocation to none (or first-party only).", klass: "header" },
];
/** URL-042 helper — does the response look like a JSON source map with original sources? */
export function sourcemapHasSources(body) {
    try {
        const j = JSON.parse(body);
        return Array.isArray(j.sources) && j.sources.length > 0;
    }
    catch {
        return false;
    }
}
export function runL1(bundle) {
    const F = [];
    const homepage = pick(bundle.requests, "GET", (r) => samePath(r, bundle.meta.url) && r.status > 0);
    const stack = [];
    if (!homepage) {
        // target unreachable — single INFO, no score drama
        F.push(mkFinding({
            id: "URL-999", severity: "info", title: "Target unreachable — L1 capture produced no homepage response",
            file: bundle.meta.url, line: 0,
            evidence: { type: "unreachable", masked: bundle.requests[0]?.error ?? "no response captured", note: "A URL-mode report needs a reachable origin" },
            owasp: "A05", confidence: "high", fix: "Check the URL and re-run.",
        }));
        return { findings: F, bundles: [], stack, scriptUrls: [], inlineScripts: [] };
    }
    // ---- TLS/certificate (deterministic facts captured at scan time) ----
    if (bundle.meta.url.startsWith("http://")) {
        F.push(mkFinding({
            id: "URL-001", severity: "high", title: "Site served over plain HTTP (no TLS)",
            file: bundle.meta.url, line: 0,
            evidence: { type: "no_tls", masked: "http:// origin", note: "every request — including session cookies — travels in cleartext" },
            owasp: "A02", confidence: "high",
            fix: "Serve over HTTPS (terminate TLS at the edge/provider, redirect http→https, enable HSTS once stable).",
            root: "tls", root_cause: rootCause("URL-001", "tls"),
        }));
    }
    else if (bundle.tls) {
        const t = bundle.tls;
        if (t.error) {
            F.push(mkFinding({
                id: "URL-003", severity: "medium", title: "TLS handshake could not be validated",
                file: bundle.meta.url, line: 0,
                evidence: { type: "tls_error", masked: t.error }, owasp: "A02", confidence: "medium",
                fix: "Renew/fix the certificate (expired, self-signed, or hostname mismatch).", needs_confirmation: true,
                root: "tls", root_cause: rootCause("URL-003", "tls"),
            }));
        }
        else {
            if (t.protocol && /^TLSv1\.[0-1]$/.test(t.protocol)) {
                F.push(mkFinding({
                    id: "URL-002", severity: "high", title: `Weak TLS protocol negotiated (${t.protocol})`,
                    file: bundle.meta.url, line: 0,
                    evidence: { type: "weak_tls", masked: t.protocol }, owasp: "A02", confidence: "high",
                    fix: "Disable TLS 1.0/1.1 on the edge; serve TLS 1.2+ (1.3 preferred).",
                    root: "tls", root_cause: rootCause("URL-002", "tls"),
                }));
            }
            if (t.daysLeft !== null && t.daysLeft < 0) {
                F.push(mkFinding({
                    id: "URL-003", severity: "high", title: "TLS certificate expired",
                    file: bundle.meta.url, line: 0,
                    evidence: { type: "cert_expired", masked: `expired ${Math.abs(t.daysLeft)} day(s) ago (valid_to ${t.valid_to_iso ?? "?"})` },
                    owasp: "A02", confidence: "high", fix: "Renew the certificate now; automate renewal (ACME/cert-manager).",
                    root: "tls", root_cause: rootCause("URL-003", "tls"),
                }));
            }
            else if (t.daysLeft !== null && t.daysLeft <= 14) {
                F.push(mkFinding({
                    id: "URL-003", severity: "medium", title: `TLS certificate expires soon (${t.daysLeft} day(s))`,
                    file: bundle.meta.url, line: 0,
                    evidence: { type: "cert_expiring", masked: `valid_to ${t.valid_to_iso ?? "?"}` }, owasp: "A02", confidence: "high",
                    fix: "Renew the certificate; verify auto-renewal is actually scheduled.", needs_confirmation: false,
                    root: "tls", root_cause: rootCause("URL-003", "tls"),
                }));
            }
        }
    }
    // ---- security headers (homepage) ----
    if (homepage.status >= 200 && homepage.status < 400) {
        for (const h of HEADER_CHECKS) {
            if (h.id === "URL-012" && (homepage.headers[h.header] || homepage.headers["content-security-policy"]?.includes("frame-ancestors")))
                continue;
            if (homepage.headers[h.header])
                continue;
            F.push(mkFinding({
                id: h.id, severity: h.severity, title: h.title,
                file: homepage.final_url, line: 0,
                evidence: { type: "missing_header", masked: h.header, note: `response ${homepage.status} carries no ${h.header}` },
                owasp: h.owasp, confidence: "high",
                fix: `${h.fix} ${codeMapHint(stackFingerprint(bundle, homepage), h.klass)}`,
                root: "headers", root_cause: rootCause(h.id, "headers"),
            }));
        }
        // HSTS — only meaningful over https
        if (bundle.meta.url.startsWith("https://") && !homepage.headers["strict-transport-security"]) {
            F.push(mkFinding({
                id: "URL-011", severity: "medium", title: "Strict-Transport-Security (HSTS) header missing",
                file: homepage.final_url, line: 0,
                evidence: { type: "missing_header", masked: "strict-transport-security" },
                owasp: "A05", confidence: "high",
                fix: `Serve Strict-Transport-Security: max-age=31536000; includeSubDomains after confirming all subdomains are https-capable. ${codeMapHint(stackFingerprint(bundle, homepage), "header")}`,
                root: "headers", root_cause: rootCause("URL-011", "headers"),
            }));
        }
        // server version disclosure
        const server = homepage.headers["server"];
        if (server && /\d+\.\d+/.test(server)) {
            F.push(mkFinding({
                id: "URL-030", severity: "low", title: "Server header discloses a specific version",
                file: homepage.final_url, line: 0,
                evidence: { type: "version_disclosure", masked: server },
                owasp: "A05", confidence: "high",
                fix: "Strip or genericize the Server header version at the edge (banner disclosure feeds attacker recon).",
                root: "fingerprint", root_cause: rootCause("URL-030", "fingerprint"),
            }));
        }
        const xpb = homepage.headers["x-powered-by"];
        if (xpb) {
            F.push(mkFinding({
                id: "URL-031", severity: "low", title: "X-Powered-By header discloses the stack",
                file: homepage.final_url, line: 0,
                evidence: { type: "version_disclosure", masked: xpb },
                owasp: "A05", confidence: "high",
                fix: "Remove X-Powered-By at the server/proxy (e.g. helmet.hidePoweredBy / proxy hideHeaders).",
                root: "fingerprint", root_cause: rootCause("URL-031", "fingerprint"),
            }));
        }
    }
    // ---- cookies across ALL captured responses (browser-equivalent set) ----
    F.push(...cookieFindings(bundle.requests));
    // ---- security.txt / robots / sitemap hygiene ----
    const sectxt = bundle.requests.find((r) => r.url.endsWith("/.well-known/security.txt"));
    if (sectxt && sectxt.status === 200) {
        F.push(mkFinding({
            id: "URL-904", severity: "info", title: "security.txt present (RFC 9116) — good practice",
            file: sectxt.final_url, line: 0,
            evidence: { type: "documented_pattern", masked: "security.txt found" }, owasp: "A05", confidence: "high",
            fix: "Keep Contact/Expires fields current.",
        }));
    }
    else if (sectxt && sectxt.status === 404) {
        F.push(mkFinding({
            id: "URL-905", severity: "low", title: "security.txt absent (RFC 9116)",
            file: `${bundle.meta.url}/.well-known/security.txt`, line: 0,
            evidence: { type: "hygiene", masked: "no /.well-known/security.txt" }, owasp: "A05", confidence: "high",
            fix: "Publish /.well-known/security.txt so researchers can report issues safely.",
            root: "hygiene", root_cause: rootCause("URL-905", "hygiene"),
        }));
    }
    // ---- JS bundles (L1 since v1.3): fetch happened in capture phase; analyze offline ----
    const bundles = [];
    const html = homepage.body;
    const scriptUrls = extractScriptUrls(html, new URL(bundle.meta.url).origin);
    for (const r of bundle.requests) {
        if (r.status !== 200)
            continue;
        if (!isJsResponse(r))
            continue;
        const intel = scanBundle({ text: r.body, assetUrl: r.url, origin: new URL(bundle.meta.url).origin, stack });
        bundles.push(intel);
        F.push(...intel.secrets);
        // sourcemap advice (L1) — actual exposure check is L2
        if (intel.sourcemapRefs.length) {
            F.push(mkFinding({
                id: "URL-043", severity: "info", title: "Bundle references a sourceMappingURL (check exposure at Level 2)",
                file: r.url, line: 0,
                evidence: { type: "sourcemap_reference", masked: intel.sourcemapRefs[0] },
                owasp: "A05", confidence: "high",
                fix: `A .map file is referenced next to ${r.url}. Level 2 checks whether it is actually exposed and ships original sources.`,
            }));
        }
    }
    // inline scripts
    for (const m of html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)) {
        const text = m[1];
        if (text.trim().length < 32)
            continue;
        const intel = scanBundle({ text, assetUrl: `${homepage.final_url}#inline-script`, origin: new URL(bundle.meta.url).origin, stack });
        bundles.push(intel);
        F.push(...intel.secrets);
    }
    // internal endpoints / localhost refs shipped in public JS (mapping, LOW)
    const endpointAsset = bundles.find((b) => b.endpoints.length);
    const allEndpoints = [...new Set(bundles.flatMap((b) => b.endpoints))];
    if (endpointAsset && allEndpoints.length) {
        F.push(mkFinding({
            id: "URL-041", severity: "low", title: "Public bundle references internal/localhost endpoints",
            file: endpointAsset.assetUrl,
            line: 0,
            evidence: { type: "internal_endpoints", masked: allEndpoints.slice(0, 3).join(", ").slice(0, 120) },
            owasp: "A05", confidence: "high",
            fix: "Remove internal hostnames from client code; route internal calls through a server-side proxy.",
            root: "internal-endpoints", root_cause: rootCause("URL-041", "internal-endpoints"),
        }));
    }
    // ---- tech fingerprint (INFO, no deduction) ----
    const fp = stackFingerprint(bundle, homepage);
    stack.push(...fp);
    if (fp.length) {
        F.push(mkFinding({
            id: "URL-900", severity: "info", title: `Technology fingerprint: ${fp.join(", ")}`,
            file: homepage.final_url, line: 0,
            evidence: { type: "fingerprint", masked: fp.join(",") }, owasp: "A05", confidence: "high",
            fix: "Informational — findings below pair with code-map hints per detected framework.",
        }));
    }
    return { findings: F, bundles, stack: fp, scriptUrls, inlineScripts: [] };
}
// ---------- helpers ----------
function pick(reqs, method, pred) {
    return reqs.find((r) => r.method === method && pred(r));
}
function samePath(r, target) {
    try {
        return r.url === target || r.final_url === target;
    }
    catch {
        return false;
    }
}
export function extractScriptUrls(html, origin) {
    const out = [];
    for (const m of html.matchAll(/<script[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)) {
        try {
            const u = new URL(m[1], origin);
            if (u.origin === origin)
                out.push(u.toString());
        }
        catch { /* malformed href — skip */ }
    }
    return [...new Set(out)];
}
function isJsResponse(r) {
    const ct = r.headers["content-type"] ?? "";
    return r.status === 200 && (ct.includes("javascript") || /\.js(?:\?|$)/.test(r.url));
}
const SESSION_COOKIE = /(sess|session|auth|token|jwt|sid|login|remember)/i;
export function cookieFindings(reqs) {
    const F = [];
    const seen = new Set();
    for (const r of reqs) {
        const raw = r.headers["set-cookie"];
        if (!raw)
            continue;
        for (const cookie of raw.split("\n")) {
            const name = cookie.split("=", 1)[0]?.trim() ?? "";
            if (!name || seen.has(name))
                continue;
            seen.add(name);
            const lower = cookie.toLowerCase();
            const isSession = SESSION_COOKIE.test(name);
            if (!/\bsecure\b/.test(lower)) {
                F.push(mkFinding({
                    id: "URL-020", severity: "medium", title: `Cookie "${name}" set without the Secure flag`,
                    file: r.url, line: 0,
                    evidence: { type: "cookie_missing_secure", masked: name, note: "cookie can travel over plain http" },
                    owasp: "A05", confidence: "high",
                    fix: `Set the Secure attribute on "${name}" (and serve the site over https only).`,
                    root: name, root_cause: rootCause("URL-020", name),
                }));
            }
            if (!/\bhttponly\b/.test(lower)) {
                F.push(mkFinding({
                    id: "URL-021", severity: isSession ? "high" : "low",
                    title: isSession
                        ? `Session cookie "${name}" set without HttpOnly (readable by any XSS)`
                        : `Cookie "${name}" set without HttpOnly`,
                    file: r.url, line: 0,
                    evidence: { type: "cookie_missing_httponly", masked: name, note: isSession ? "session-shaped name" : undefined },
                    owasp: "A07", confidence: "high",
                    fix: `Set HttpOnly on "${name}"${isSession ? " — session cookies must never be readable from JS" : ""}.`,
                    root: name, root_cause: rootCause("URL-021", name),
                }));
            }
            if (!/;\s*samesite/i.test(cookie)) {
                F.push(mkFinding({
                    id: "URL-022", severity: "low", title: `Cookie "${name}" set without SameSite`,
                    file: r.url, line: 0,
                    evidence: { type: "cookie_missing_samesite", masked: name },
                    owasp: "A07", confidence: "high",
                    fix: `Set SameSite=Lax (or Strict) on "${name}" to blunt CSRF.`,
                    root: name, root_cause: rootCause("URL-022", name),
                }));
            }
        }
    }
    return F;
}
/** Deterministic framework fingerprint from public evidence only. */
export function stackFingerprint(_bundle, homepage) {
    const s = new Set();
    const h = homepage.headers;
    const html = homepage.body;
    if ((h["x-powered-by"] ?? "").includes("Next.js") || html.includes("/_next/static") || html.includes("__NEXT_DATA__"))
        s.add("nextjs");
    if ((h["server"] ?? "").includes("cloudflare"))
        s.add("cloudflare");
    if ((h["x-powered-by"] ?? "").includes("Express"))
        s.add("express");
    if (html.match(/https:\/\/[a-z0-9]{20}\.supabase\.co/i))
        s.add("supabase");
    if (html.includes("nest") && h["x-powered-by"]?.includes("Express"))
        s.add("nestjs");
    if (h["x-drupal-cache"] || html.includes("Drupal.settings"))
        s.add("drupal");
    if (html.includes("wp-content"))
        s.add("wordpress");
    return [...s].sort();
}
