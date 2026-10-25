import { maskSecret, rootCause } from "../util.js";
import { classifyFile } from "./context.js";
/**
 * HDR-001 — Database credentials transmitted in HTTP request headers (Plan Section 6).
 * Receiver-first principle (v1.3): the strongest signal is the SERVER reading DB
 * connection data from a request header — the client sender is corroborating evidence.
 *
 * severity ladder:
 *   critical = receiver_read + sink_linked   (server actually connects using header values)
 *   high     = client_sends + secret_pattern (real-looking secret sent in a header)
 *   medium   = client_sends without confirmed pattern (possible test/mock — review note)
 *   high*    = receiver_read without confirmed sink (confidence medium — review)
 */
const DB_HEADER_NAME = /(db|database|sql|conn|connection|supabase|postgres|pg[-_]?pass|root[-_]?pass|admin[-_]?pass|db[-_]?pass|secret[-_]?conn)/i;
const CLEAN_HEADER = /(signature|hmac|auth|token|csrf|cookie|user-agent|referer|request-id|trace|forwarded|host|api-?key|session|cache|content-|accept)/i;
const RECEIVER_RES = [
    /\breq(?:uest)?\.headers(?:\[["'`]([^"'`]+)["'`\]]|\.get\(\s*["'`]([^"'`]+)["'`]\s*\))/gi,
    /\bheaders\(\)\.get\(\s*["'`]([^"'`]+)["'`]\s*\)/gi, // Next.js server helper
    /\breq\.header\(\s*["'`]([^"'`]+)["'`]\s*\)/gi, // Express helper
];
const SINK_RES = [
    /\b(?:pg\.Pool|pg\.Client|new\s+Pool\s*\(|mongoose\.connect|mysql\.createPool|createPool\s*\()/,
    /\bconnectionString\b/, /\bpostgres\s*\(/, /\bdrizzle\s*\(/, /\bcreateClient\b/,
    /\bconnectToDatabase\b/, /\bgetDbConn/,
];
const SECRET_SHAPE = /^(?:[A-Za-z0-9+/=_-]{20,}|[A-Fa-f0-9]{16,}|.{8,}@[A-Za-z0-9.-]+:.{3,})$/;
const PLACEHOLDER = /(changeme|xxxxx|<[^>]*>|\$\{[^}]*\}|your[-_]|example|placeholder|test|dummy|\*{3,})/i;
const SENDER_HEADER_RES = [
    /["'`](x[-_]?|)(db|database|sql|conn|connection|supabase|postgres|db[-_]?pass|db[-_]?password|root[-_]?password|admin[-_]?password|db[-_]?user|db[-_]?host|db[-_]?port|db[-_]?name)([-_]?[a-z0-9-]*)["'`]\s*:\s*(?:["'`]([^"'`\n]+)["'`]|([A-Za-z_$][\w.$]*))/gi,
];
const FETCH_CONTEXT = /(fetch\s*\(|axios[.(]|ofetch|request\s*\(\s*\{|http\.)/i;
const FIX_RECEIVER = "Database credentials must never travel in HTTP headers. Connect from server-side code using isolated env vars + a connection pool; if a proxy needs to authorize, send a short-lived signed token instead of raw credentials.";
const FIX_SENDER = FIX_RECEIVER;
export function scanHdr001(ctx) {
    const findings = [];
    for (const f of ctx.files) {
        if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.rel))
            continue;
        const fileClass = classifyFile(f);
        const fileHasHttp = FETCH_CONTEXT.test(f.content); // sender check needs an HTTP-call context anywhere in the module
        for (let i = 0; i < f.lines.length; i++) {
            const line = f.lines[i];
            // ---------- receiver side ----------
            for (const re of RECEIVER_RES) {
                re.lastIndex = 0;
                let m;
                while ((m = re.exec(line)) !== null) {
                    const name = (m[1] || m[2] || "").trim();
                    if (!name || !DB_HEADER_NAME.test(name) || CLEAN_HEADER.test(name))
                        continue;
                    const window = f.lines.slice(Math.max(0, i - 2), i + 6).join("\n");
                    const sinkLinked = SINK_RES.some((s) => s.test(window)) || f.lines.some((l) => SINK_RES.some((s) => s.test(l)));
                    const masked = maskSecret(name);
                    const root = `${f.rel}:${masked.sha256_prefix}`;
                    const base = {
                        id: "HDR-001",
                        title: "Server reads database credentials from request headers",
                        file: f.rel, line: i + 1,
                        evidence: {
                            type: "receiver_read",
                            masked: `header "${name.toLowerCase()}"`,
                            sha256_prefix: masked.sha256_prefix,
                            note: sinkLinked ? "receiver read + DB connection sink in the same module" : "receiver read detected; sink linkage not confirmed in this file",
                        },
                        owasp: "A02",
                        fix: FIX_RECEIVER,
                        fix_mode: "suggested-diff",
                        root, root_cause: rootCause("HDR-001", root),
                        verified: true,
                    };
                    if (sinkLinked) {
                        findings.push({ ...base, severity: "critical", confidence: "high" });
                    }
                    else {
                        findings.push({ ...base, severity: "high", confidence: "medium", needs_confirmation: true });
                    }
                }
            }
            // ---------- sender side ----------
            if (!fileHasHttp)
                continue;
            for (const re of SENDER_HEADER_RES) {
                re.lastIndex = 0;
                let m;
                while ((m = re.exec(line)) !== null) {
                    const headerName = `${m[1] || "x-"}${m[2]}${m[3] || ""}`;
                    if (CLEAN_HEADER.test(headerName))
                        continue;
                    const literal = m[4];
                    const varRef = m[5];
                    if (literal !== undefined) {
                        if (PLACEHOLDER.test(literal))
                            continue;
                        const looksSecret = SECRET_SHAPE.test(literal);
                        if (!looksSecret && !DB_HEADER_NAME.test(m[2]))
                            continue;
                        const masked = maskSecret(literal);
                        const root = `${masked.sha256_prefix}:${headerName.toLowerCase()}`;
                        findings.push({
                            id: "HDR-001", severity: "high", confidence: "high",
                            title: "Client sends a hardcoded credential in a request header",
                            file: f.rel, line: i + 1,
                            evidence: { type: "client_sends_secret", masked: `header "${headerName.toLowerCase()}" = ${masked.masked}`, sha256_prefix: masked.sha256_prefix, note: "client-side sender; confirm the receiver side for full severity" },
                            owasp: "A02", fix: FIX_SENDER, fix_mode: "suggested-diff",
                            root, root_cause: rootCause("HDR-001", root), verified: true,
                        });
                    }
                    else if (varRef !== undefined && varRef !== "undefined") {
                        const root = `${f.rel}:${headerName.toLowerCase()}`;
                        findings.push({
                            id: "HDR-001", severity: "medium", confidence: "medium",
                            title: "Client sends DB-ish header from a variable — possible credential in transit",
                            file: f.rel, line: i + 1,
                            evidence: { type: "client_sends_var", masked: `header "${headerName.toLowerCase()}" ← ${varRef}`, note: "value not a literal — confirm it is not a real credential (may be test/mock)" },
                            owasp: "A02", fix: FIX_SENDER, fix_mode: "suggested-diff",
                            root, root_cause: rootCause("HDR-001", root), verified: true,
                        });
                    }
                }
            }
        }
    }
    return { findings };
}
