import { maskSecret, rootCause } from "../util.js";
import { isClientEnvKey, classifyFile } from "./context.js";
/**
 * Layer 5 — Next.js / JWT playbook (Plan Section 6).
 * v0.1 scope: localStorage/sessionStorage tokens, cookie flags, NEXT_PUBLIC_* secrets,
 * API routes / server actions missing auth (middleware-aware).
 * AUTH-001 full middleware-only analysis + HttpOnly verification + CSRF heuristic → v0.3.
 */
const TOKEN_KEY_NAME = /(?:token|jwt|auth|session|access[_-]?token|refresh[_-]?token)/i;
const FIX_STORAGE = "Tokens readable by JavaScript can be exfiltrated by any XSS. Store the session in an httpOnly + Secure + SameSite cookie instead (set by the server), and keep refresh tokens server-side.";
const PLACEHOLDER = /(changeme|xxxxx|<[^>]*>|\$\{[^}]*\}|your[-_]|example|placeholder|dummy|\*{3,})/i;
export function scanNextjs(ctx) {
    const findings = [];
    if (!ctx.stack.frameworks.nextjs)
        return { findings };
    const hasMiddleware = ctx.files.some((f) => /(^|\/)middleware\.(ts|js)$/.test(f.rel));
    for (const f of ctx.files) {
        // --- .env files: NEXT_PUBLIC_* carrying secret-shaped values ---
        if (/(^|\/)\.env/.test(f.rel)) {
            for (let i = 0; i < f.lines.length; i++) {
                const m = f.lines[i].match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?([^"'\n#]+)["']?\s*$/);
                if (!m)
                    continue;
                const [, key, value] = m;
                if (!isClientEnvKey(key))
                    continue;
                if (PLACEHOLDER.test(value))
                    continue;
                const jwtOnly = value.trim().match(/^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/);
                if (jwtOnly) {
                    // decode by value: anon/authenticated keys are designed-public — clean case
                    try {
                        const b64 = jwtOnly[0].split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
                        const payload = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
                        if (payload?.role === 'anon' || payload?.role === 'authenticated')
                            continue;
                    }
                    catch { /* fall through to shape checks */ }
                }
                const secretShaped = /(sk_live_|rk_live_|AKIA[0-9A-Z]{16}|gh[pousr]_|xox[baprs]-|sb_secret_|-----BEGIN|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/.test(value) ||
                    (/SUPA.*SERVICE|SERVICE.*ROLE|SECRET|PRIVATE|ADMIN|PASSWORD|TOKEN/i.test(key) && /^[A-Za-z0-9+/=_-]{24,}$/.test(value.trim()));
                if (!secretShaped)
                    continue;
                const masked = maskSecret(value.trim());
                findings.push({
                    id: "NEXT-001",
                    severity: "high",
                    confidence: "high",
                    title: `Secret value exposed via public env var ${key} — it ships to the browser bundle`,
                    file: f.rel, line: i + 1,
                    evidence: { type: "public_env_secret", masked: `${key}=${masked.masked}`, sha256_prefix: masked.sha256_prefix, note: "NEXT_PUBLIC_/VITE_/REACT_APP_/EXPO_PUBLIC_ vars are inlined into client JS at build time" },
                    owasp: "A02",
                    fix: `Remove ${key} from public env. Only truly public values (API URLs, anon keys) belong there; load secrets from server-side env in route handlers/server actions.`,
                    fix_mode: "suggested-diff",
                    remediation: { type: "rotate-first", provider: "generic", steps: "1) Rotate this credential — it IS public the moment the bundle ships 2) Move usage server-side 3) Scrub git history if committed", history_cleanup: "git filter-repo if committed" },
                    root: masked.sha256_prefix,
                    root_cause: rootCause("NEXT-001", masked.sha256_prefix),
                    verified: true,
                });
            }
            continue;
        }
        if (!/\.(ts|tsx|js|jsx)$/.test(f.rel))
            continue;
        const fileClass = classifyFile(f);
        // --- file-level: mutating endpoints without in-file auth (NEXT-004) ---
        const isApiRoute = /(^|\/)(app\/api\/.*\/route|pages\/api\/[^/]+)\.(ts|js)$/.test(f.rel) || /["']use server["']/.test(f.lines.slice(0, 3).join("\n"));
        if (isApiRoute && fileClass === "server") {
            const hasMutation = /\bexport\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b/.test(f.content);
            if (hasMutation) {
                const authIndicator = /(supabase\.auth|getServerSession|getSession|auth\(\)|verifyToken|jwt|authorization|cookies\(\)\.get|requireUser|requireAuth|currentUser|getUser|clerk|next-auth|NextAuth|session\.get)/i.test(f.content);
                if (!authIndicator) {
                    findings.push({
                        id: "NEXT-004",
                        severity: "medium",
                        confidence: hasMiddleware ? "low" : "medium",
                        title: `Mutating endpoint without in-file auth check${hasMiddleware ? " (middleware exists — verify matcher coverage)" : ""}`,
                        file: f.rel, line: 0,
                        evidence: { type: "missing_authz_indicator", masked: f.rel, note: hasMiddleware ? "middleware.ts present — middleware-only auth is fragile (matchers drift); confirm server-side check" : "no middleware and no in-file auth — verify this endpoint is intentionally public" },
                        owasp: "A01",
                        fix: "Add an explicit server-side auth check at the top of the handler (verify the session/token server-side, not just middleware), and reject unauthenticated mutations with 401.",
                        fix_mode: "suggested-diff",
                        root: f.rel,
                        root_cause: rootCause("NEXT-004", f.rel),
                        verified: true,
                    });
                }
            }
        }
        for (let i = 0; i < f.lines.length; i++) {
            const line = f.lines[i];
            // --- tokens in web storage ---
            const storage = line.match(/\b(localStorage|sessionStorage)\.setItem\s*\(\s*["'`]([^"'`]+)["'`]/);
            if (storage && TOKEN_KEY_NAME.test(storage[2])) {
                const keyName = storage[2];
                findings.push({
                    id: "NEXT-002",
                    severity: "high",
                    confidence: "high",
                    title: `Auth token stored in ${storage[1]} ("${keyName}") — stealable by any XSS`,
                    file: f.rel, line: i + 1,
                    evidence: { type: "token_in_web_storage", masked: `${storage[1]}.setItem("${keyName}", …)` },
                    owasp: "A02",
                    fix: FIX_STORAGE,
                    fix_mode: "suggested-diff",
                    root: `${f.rel}:${storage[1]}`,
                    root_cause: rootCause("NEXT-002", `${f.rel}:${storage[1]}`),
                    verified: true,
                });
            }
            // --- cookie flags on session-ish cookies ---
            const cookieSet = line.match(/\.cookies\.set\s*\(\s*\{([\s\S]{0,300}?)/) || line.match(/\bres\.cookie\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*[^,]+,\s*\{([\s\S]{0,300}?)/);
            if (cookieSet) {
                const keyName = cookieSet[1] || "(cookie)";
                const optsWindow = (cookieSet[2] || "") + f.lines.slice(i + 1, i + 8).join("\n");
                if (TOKEN_KEY_NAME.test(keyName) || /session|sid/i.test(keyName)) {
                    const flags = {
                        httpOnly: /httpOnly\s*:\s*true/.test(optsWindow),
                        secure: /secure\s*:\s*true/.test(optsWindow),
                        sameSite: /sameSite\s*:\s*["'`](strict|lax|none)["'`]/i.test(optsWindow),
                    };
                    const missing = Object.entries(flags).filter(([, ok]) => !ok).map(([k]) => k);
                    if (missing.length && flags.httpOnly === false) {
                        findings.push({
                            id: "NEXT-003",
                            severity: "medium",
                            confidence: "medium",
                            title: `Session cookie "${keyName}" set without httpOnly${missing.length > 1 ? " and " + missing.slice(1).join("/") : ""}`,
                            file: f.rel, line: i + 1,
                            evidence: { type: "cookie_flags_missing", masked: `cookies.set("${keyName}", { … }) — missing: ${missing.join(", ")}`, note: "CSRF/SameSite deep verification is a v0.3 heuristic — this is the flags-level check" },
                            owasp: "A02",
                            fix: `Set the cookie server-side with httpOnly: true, secure: true, sameSite: "lax" (or "strict") — missing flags keep the token readable/injectable.`,
                            fix_mode: "suggested-diff",
                            root: `${f.rel}:${keyName}`,
                            root_cause: rootCause("NEXT-003", `${f.rel}:${keyName}`),
                            verified: true,
                        });
                    }
                }
            }
        }
    }
    return { findings };
}
