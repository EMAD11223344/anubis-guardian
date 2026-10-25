import { maskSecret, rootCause } from "../util.js";
import { classifyFile, importedFromClient, isClientEnvKey } from "./context.js";
const PLACEHOLDER = /(changeme|change_me|xxxxx|<[^>]*>|\$\{[^}]*\}|your[-_][a-z_]+|example|placeholder|dummy|todo|fixme|\*{3,})/i;
const PATTERNS = [
    {
        rule: "SEC-001", title: "AWS access key committed",
        re: /\bAKIA[0-9A-Z]{16}\b/g, provider: "aws", severity: "critical", confidence: "high", owasp: "A02",
        fix: "Deactivate the access key in IAM, create a new one, store it in server-side env only, then scrub git history (rotate-first).",
    },
    {
        rule: "SEC-002", title: "Stripe live secret key committed",
        re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/g, provider: "stripe", severity: "critical", confidence: "high", owasp: "A02",
        fix: "Roll the Stripe live key from the dashboard, update server-side env, then scrub git history (rotate-first).",
        skip: (m) => PLACEHOLDER.test(m),
    },
    {
        rule: "SEC-003", title: "OpenAI API key committed",
        re: /\bsk-[A-Za-z0-9_-]{40,}\b/g, provider: "openai", severity: "high", confidence: "high", owasp: "A02",
        fix: "Revoke the key at platform.openai.com, mint a new one into server-side env, scrub git history (rotate-first).",
    },
    {
        rule: "SEC-004", title: "GitHub token committed",
        re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g, provider: "github", severity: "high", confidence: "high", owasp: "A02",
        fix: "Revoke the token in GitHub settings, create a fine-grained replacement, scrub git history (rotate-first).",
    },
    {
        rule: "SEC-005", title: "Google API key committed",
        re: /\bAIza[0-9A-Za-z_-]{35}\b/g, provider: "google", severity: "high", confidence: "high", owasp: "A02",
        fix: "Restrict/regenerate the key in Google Cloud console; serve proxy calls from server-side env.",
    },
    {
        rule: "SEC-006", title: "Slack token committed",
        re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, provider: "slack", severity: "high", confidence: "high", owasp: "A02",
        fix: "Revoke the Slack token and issue a scoped one stored server-side.",
    },
    {
        rule: "SEC-007", title: "Private key material committed",
        re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY( BLOCK)?-----/g, provider: "generic", severity: "critical", confidence: "high", owasp: "A02",
        fix: "Treat this key as compromised: generate a new keypair, deploy the public side, rotate anything signed by the old key, scrub git history.",
    },
    {
        rule: "SEC-008", title: "Database URL with embedded password committed",
        re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s'"@:/]+:([^\s'"@]{4,})@[^\s'"]+/g, provider: "generic", severity: "high", confidence: "high", owasp: "A02",
        fix: "Move connection strings to server-side env; rotate the DB password; scrub git history (rotate-first).",
        skip: (m) => PLACEHOLDER.test(m),
    },
];
/** Generic credential-assignment heuristic (context: value must look real, not placeholder). */
const ASSIGN_RE = /\b(api[_-]?key|api[_-]?secret|secret[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret|password|passwd|pwd)\b\s*[:=]\s*["']([^"'\n]{8,})["']/gi;
function looksReal(v) {
    if (PLACEHOLDER.test(v))
        return false;
    if (!/[A-Za-z]/.test(v) || !/\d/.test(v))
        return false;
    return v.length >= 20 || /^[A-Fa-f0-9]{32,}$/.test(v) || /^[A-Za-z0-9+/=_-]{28,}$/.test(v);
}
/** --- SUPA-001: value-based service_role detection --- */
const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;
function decodeJwtPayload(token) {
    try {
        const payload = token.split(".")[1];
        const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
        const json = Buffer.from(b64, "base64").toString("utf8");
        return JSON.parse(json);
    }
    catch {
        return null;
    }
}
const SUPA_FIX = "service_role must never reach client code: use the anon key client-side with RLS enabled; move all admin operations to server-side code (route handlers/server actions) reading the key from server env.";
function rotateFirstSupabase() {
    return {
        type: "rotate-first",
        provider: "supabase",
        steps: "1) Rotate the JWT secret / regenerate API keys in the Supabase dashboard 2) Invalidate active sessions 3) Update server-side env with the new key 4) Scrub git history (git filter-repo) 5) Verify the old key is dead",
        history_cleanup: "git filter-repo required — deletion from HEAD is not enough",
    };
}
export function scanSecrets(ctx) {
    const findings = [];
    const clientImporters = importedFromClient(ctx);
    for (const f of ctx.files) {
        const fileClass = classifyFile(f);
        const isMd = /\.(md|mdx|txt|rst)$/i.test(f.rel) || /(^|\/)(README|CHANGELOG)/i.test(f.rel);
        const isEnvExample = /(^|\/)\.env\.example$|(^|\/)\.env\.template$/i.test(f.rel);
        for (let i = 0; i < f.lines.length; i++) {
            const line = f.lines[i];
            // In .env* files the VARIABLE NAME defines reachability: public prefix → client,
            // plain name → server-only env (the documented-correct Supabase pattern).
            const inEnvFile = /(^|\/)\.env/.test(f.rel);
            const envKey = envKeyOf(line);
            const clientHit = inEnvFile
                ? isClientEnvKey(envKey)
                : fileClass === "client" || isClientEnvKey(envKey) || clientImporters.has(f.abs);
            const serverHit = inEnvFile
                ? Boolean(envKey) && !isClientEnvKey(envKey)
                : fileClass === "server";
            // --- SUPA-001 (value-based JWT) ---
            let m;
            JWT_RE.lastIndex = 0;
            while ((m = JWT_RE.exec(line)) !== null) {
                const token = m[0];
                const payload = decodeJwtPayload(token);
                const role = payload?.role;
                if (role === "anon" || role === "authenticated")
                    continue; // designed-public keys — clean case
                if (role !== "service_role")
                    continue;
                const masked = maskSecret(token);
                const root = masked.sha256_prefix;
                const base = {
                    id: "SUPA-001",
                    title: "Supabase service_role key reachable from client code",
                    file: f.rel,
                    line: i + 1,
                    evidence: { type: "service_role_jwt", masked: masked.masked, sha256_prefix: masked.sha256_prefix, note: "full value is never written to any report or artifact" },
                    owasp: "A01",
                    fix: SUPA_FIX,
                    fix_mode: "suggested-diff",
                    remediation: rotateFirstSupabase(),
                    root,
                    root_cause: rootCause("SUPA-001", root),
                    verified: true,
                };
                if (clientHit) {
                    findings.push({ ...base, severity: "critical", confidence: "high" });
                }
                else if (serverHit) {
                    findings.push({
                        ...base, severity: "info", confidence: "high",
                        title: "service_role key used in server-only code (documented-correct pattern — verify env hygiene)",
                        fix: "Correct placement. Ensure the key never leaks into client bundles and is not committed in plaintext env files.",
                    });
                }
                else {
                    findings.push({
                        ...base, severity: "medium", confidence: "medium", needs_confirmation: true,
                        title: "service_role key in unclassified context — confirm reachability",
                        fix: SUPA_FIX + " First confirm whether this module is imported from any client bundle.",
                    });
                }
            }
            // --- sb_secret_ (new Supabase key format) ---
            const SB_RE = /\bsb_secret_[A-Za-z0-9_-]{20,}\b/g;
            while ((m = SB_RE.exec(line)) !== null) {
                const v = m[0];
                const masked = maskSecret(v);
                const root = masked.sha256_prefix;
                const base = {
                    id: "SUPA-001",
                    title: "Supabase secret key (sb_secret_) present in code",
                    file: f.rel, line: i + 1,
                    evidence: { type: "service_role_jwt", masked: masked.masked, sha256_prefix: masked.sha256_prefix, note: "new-format secret key — equivalent privilege to service_role" },
                    owasp: "A01", fix: SUPA_FIX, fix_mode: "suggested-diff",
                    remediation: rotateFirstSupabase(),
                    root, root_cause: rootCause("SUPA-001", root), verified: true,
                };
                if (clientHit) {
                    findings.push({ ...base, severity: "critical", confidence: "high" });
                }
                else if (serverHit) {
                    findings.push({ ...base, severity: "info", confidence: "high", title: "secret key (sb_secret_) used in server-only code (verify env hygiene)" });
                }
                else {
                    findings.push({ ...base, severity: "medium", confidence: "medium", needs_confirmation: true, title: "secret key (sb_secret_) in unclassified context — confirm reachability" });
                }
            }
            // --- curated secret patterns ---
            for (const p of PATTERNS) {
                p.re.lastIndex = 0;
                while ((m = p.re.exec(line)) !== null) {
                    const v = m[0];
                    if (p.skip?.(v))
                        continue;
                    if (isMd && p.rule !== "SEC-007")
                        continue; // docs excluded except key material
                    if (isEnvExample)
                        continue; // .env.example handled by SEED-001 expansion
                    const masked = maskSecret(v);
                    const root = masked.sha256_prefix;
                    findings.push({
                        id: p.rule, severity: p.severity, confidence: p.confidence,
                        title: p.title, file: f.rel, line: i + 1,
                        evidence: { type: `${p.provider}_secret`, masked: masked.masked, sha256_prefix: masked.sha256_prefix, note: "full value is never written to any report or artifact" },
                        owasp: p.owasp, fix: p.fix, fix_mode: "suggested-diff",
                        remediation: { type: "rotate-first", provider: p.provider, steps: `1) Rotate/revoke the ${p.provider} credential 2) Update server-side env 3) Scrub git history (git filter-repo) 4) Verify the old credential is dead`, history_cleanup: "git filter-repo required — deletion from HEAD is not enough" },
                        root, root_cause: rootCause(p.rule, root), verified: true,
                    });
                }
            }
            // --- generic assignment heuristic ---
            if (!isMd && !isEnvExample) {
                ASSIGN_RE.lastIndex = 0;
                while ((m = ASSIGN_RE.exec(line)) !== null) {
                    const key = m[1], v = m[2];
                    if (!looksReal(v))
                        continue;
                    if (/(?:process\.env|os\.environ|getenv)/.test(line))
                        continue; // read from env — clean
                    const masked = maskSecret(v);
                    const root = masked.sha256_prefix;
                    findings.push({
                        id: "SEC-009", severity: "high", confidence: "medium",
                        title: `Hardcoded credential assignment ("${key.toLowerCase()}")`,
                        file: f.rel, line: i + 1,
                        evidence: { type: "hardcoded_credential", masked: masked.masked, sha256_prefix: masked.sha256_prefix, note: "heuristic match — confirm the value is a real credential" },
                        owasp: "A02",
                        fix: "Move this credential to server-side env and rotate it if it was ever committed (rotate-first).",
                        fix_mode: "suggested-diff",
                        remediation: { type: "rotate-first", provider: "generic", steps: "1) Confirm the value is real 2) Rotate it at the provider 3) Load from server-side env 4) Scrub git history if committed", history_cleanup: "git filter-repo if the value appears in history" },
                        root, root_cause: rootCause("SEC-009", root), verified: true,
                    });
                }
            }
        }
    }
    // --- committed .env files (worktree) ---
    const envRe = /(^|\/)\.env(\.local|\.production|\.staging|\.development)?$/i;
    for (const f of ctx.files) {
        if (!envRe.test(f.rel))
            continue;
        const hasRealSecret = f.lines.some((l) => {
            const kv = l.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?([^"'\n#]+)["']?/);
            if (!kv)
                return false;
            const [, key, value] = kv;
            if (isClientEnvKey(key))
                return true; // public env with secret-shaped value is judged by its own rule; committed env is still an exposure signal
            return value.trim().length >= 24 && /^[A-Za-z0-9+/=_-]+$/.test(value.trim()) && !PLACEHOLDER.test(value);
        });
        if (!hasRealSecret)
            continue;
        const tracked = ctx.trackedFiles.has(f.rel);
        if (tracked) {
            findings.push({
                id: "ENV-001", severity: "critical", confidence: "high",
                title: "Environment file with live values is committed to git",
                file: f.rel, line: 0,
                evidence: { type: "committed_env", masked: `${f.rel} (git-tracked)`, note: "values masked — see per-line secret findings" },
                owasp: "A02",
                fix: "1) Remove the file from tracking (git rm --cached) and gitignore it 2) Rotate every credential inside it (rotate-first) 3) Scrub history with git filter-repo 4) Load values from the deployment platform's secret store.",
                fix_mode: "suggested-diff",
                remediation: { type: "rotate-first", provider: "generic", steps: "Rotate ALL credentials inside this file, then scrub history — the file is already public if the repo is public.", history_cleanup: "git filter-repo required" },
                root: f.rel, root_cause: rootCause("ENV-001", f.rel), verified: true,
            });
        }
        else if (!ctx.gitAvailable) {
            findings.push({
                id: "ENV-001", severity: "medium", confidence: "medium",
                title: "Env file with live values present; no git repo — commit status unverifiable",
                file: f.rel, line: 0,
                evidence: { type: "env_no_repo", masked: f.rel },
                owasp: "A02",
                fix: "Ensure this file is gitignored before the project ever reaches a remote; prefer platform secret stores.",
                fix_mode: "suggested-diff", root: f.rel, root_cause: rootCause("ENV-001", f.rel), verified: true,
            });
        }
    }
    return { findings };
}
function envKeyOf(line) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/);
    return m ? m[1] : "";
}
