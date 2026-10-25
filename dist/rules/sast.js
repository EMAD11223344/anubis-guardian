import { rootCause } from "../util.js";
import { classifyFile } from "./context.js";
/**
 * Layer 4 — SAST Light (Plan Section 6, v0.1 rows of the coverage matrix):
 * SQLi string-concat, XSS dangerouslySetInnerHTML, eval/exec/child_process,
 * weak hashing. Taint-lite (deep flow) is v0.3 — NOT in v0.1.
 */
const FIX = {
    sqli: "Parameterize the query (prepared statements / query builder placeholders). Never build SQL by string concatenation with request data.",
    xss: "Render text instead of raw HTML, or sanitize with DOMPurify before injecting; never pass unsanitized user content to dangerouslySetInnerHTML.",
    exec: "Avoid spawning shells with interpolated input. Use execFile with argument arrays and an allowlist; validate input server-side.",
    hash: "Use bcrypt/argon2/scrypt for passwords. MD5/SHA1 are broken for password storage.",
};
export function scanSast(ctx) {
    const findings = [];
    for (const f of ctx.files) {
        if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.rel))
            continue;
        const fileClass = classifyFile(f);
        const isServer = fileClass === "server" || fileClass === "unknown" || /(^|\/)(server|api|lib)\//.test(f.rel);
        for (let i = 0; i < f.lines.length; i++) {
            const line = f.lines[i];
            if (/^\s*(\/\/|\*|\/\*)/.test(line))
                continue; // skip comments
            // --- SQLi by concatenation ---
            if (/\b(?:select|insert|update|delete)\b[^;\n]{0,120}["'`]\s*\+|\+\s*["'`]\s*(?:where|and|or|from)\b|\bquery\s*\(\s*["'`][^"'`]*\$\{/i.test(line)) {
                const usesParam = /\$1|\?\s*[,)]|sql`|prisma\.|parameterized/i.test(line) || /pool\.query\(\s*["'`][^"'`]*\$\d/.test(line);
                if (!usesParam && isServer) {
                    findings.push({
                        id: "SAST-001", severity: "medium", confidence: "medium",
                        title: "SQL query built by string concatenation — possible injection",
                        file: f.rel, line: i + 1,
                        evidence: { type: "sqli_concat", masked: line.trim().slice(0, 120) },
                        owasp: "A03",
                        fix: FIX.sqli,
                        fix_mode: "suggested-diff",
                        root: `${f.rel}:${i + 1}`,
                        root_cause: rootCause("SAST-001", `${f.rel}:${i + 1}`),
                        verified: true,
                    });
                }
            }
            // --- XSS via dangerouslySetInnerHTML ---
            const dsih = line.match(/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\}\s*\}/);
            if (dsih) {
                const expr = dsih[1].trim();
                const isLiteral = /^["'`][^"'`]*["'`]$/.test(expr);
                // local-const tracking: `const html = "literal"` assigned in the same file is safe
                const ident = expr.match(/^([A-Za-z_$][\w.]*)$/);
                const localLiteral = ident
                    ? new RegExp(`(?:const|let|var)\\s+${ident[1].replace(/\./g, "\\.")}\\s*=\\s*["'\`][^"''\`]*["'\`]`).test(f.content)
                    : false;
                if (!isLiteral && !localLiteral) {
                    findings.push({
                        id: "SAST-002", severity: "medium", confidence: "medium",
                        title: "dangerouslySetInnerHTML receives a non-literal value — XSS risk",
                        file: f.rel, line: i + 1,
                        evidence: { type: "xss_dangerous_html", masked: expr.slice(0, 120) },
                        owasp: "A03",
                        fix: FIX.xss,
                        fix_mode: "suggested-diff",
                        root: `${f.rel}:${i + 1}`,
                        root_cause: rootCause("SAST-002", `${f.rel}:${i + 1}`),
                        verified: true,
                    });
                }
            }
            // --- eval / exec with interpolation ---
            if (/\beval\s*\(/.test(line) || /\bnew\s+Function\s*\(/.test(line) ||
                /\bchild_process\b.*\bexec\s*\(|\bexec\s*\(\s*[`"'][^`"']*(?:\$\{|"\s*\+)/.test(line)) {
                const interpolated = /\$\{|\+\s*\w|\w\s*\+/.test(line);
                if (interpolated) {
                    findings.push({
                        id: "SAST-003", severity: "high", confidence: "medium",
                        title: "Code executed from an interpolated string (eval/exec/new Function) — command injection risk",
                        file: f.rel, line: i + 1,
                        evidence: { type: "code_execution", masked: line.trim().slice(0, 120) },
                        owasp: "A03",
                        fix: FIX.exec,
                        fix_mode: "suggested-diff",
                        root: `${f.rel}:${i + 1}`,
                        root_cause: rootCause("SAST-003", `${f.rel}:${i + 1}`),
                        verified: true,
                    });
                }
            }
            // --- weak password hashing ---
            if (/createHash\s*\(\s*["'`](md5|sha1)["'`]\s*\)/i.test(line) && /(password|passwd|pwd|secret|token)/i.test(line)) {
                findings.push({
                    id: "SAST-004", severity: "medium", confidence: "medium",
                    title: "Weak hash (MD5/SHA1) applied to password-like material",
                    file: f.rel, line: i + 1,
                    evidence: { type: "weak_hashing", masked: line.trim().slice(0, 120) },
                    owasp: "A02",
                    fix: FIX.hash,
                    fix_mode: "suggested-diff",
                    root: `${f.rel}:${i + 1}`,
                    root_cause: rootCause("SAST-004", `${f.rel}:${i + 1}`),
                    verified: true,
                });
            }
        }
    }
    return { findings };
}
