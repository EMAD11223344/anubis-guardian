import { execFileSync } from "node:child_process";
import { maskSecret, rootCause } from "../util.js";
/**
 * Layer 2 — Git history & config exposure (Plan Section 6).
 * Reading history is static analysis of the repo itself (allowed — Section 9.7);
 * the tool NEVER runs project code.
 */
const SECRET_LINE_PATTERNS = [
    { id: "HIST-001", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, label: "JWT-shaped token" },
    { id: "HIST-002", re: /\bAKIA[0-9A-Z]{16}\b/, label: "AWS access key" },
    { id: "HIST-003", re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/, label: "Stripe live key" },
    { id: "HIST-004", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/, label: "GitHub token" },
    { id: "HIST-005", re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY/, label: "Private key" },
    { id: "HIST-006", re: /\bsb_secret_[A-Za-z0-9_-]{20,}\b/, label: "Supabase secret key" },
    { id: "HIST-007", re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s:@'"]+:[^\s@'"]{4,}@[^\s'"]+/, label: "DB URL with password" },
    { id: "HIST-008", re: /\bAIza[0-9A-Za-z_-]{35}\b/, label: "Google API key" },
];
const ENV_FILE_RE = /^\.env(\..+)?$/;
export function scanHistory(ctx) {
    const findings = [];
    if (!ctx.gitAvailable)
        return { findings };
    const git = (args, maxBuf = 32 * 1024 * 1024) => {
        try {
            return execFileSync("git", args, { cwd: ctx.rootDir, maxBuffer: maxBuf, encoding: "utf8" });
        }
        catch {
            return "";
        }
    };
    // ---- 1) committed-then-deleted env files ----
    const envAdds = git(["log", "--all", "--diff-filter=A", "--name-only", "--pretty=format:", "-z", "--", ".env", ".env.*"])
        .split("\0").map((s) => s.trim()).filter(Boolean);
    const envEverCommitted = [...new Set(envAdds.filter((p) => ENV_FILE_RE.test(p)))];
    for (const envPath of envEverCommitted) {
        const stillTracked = ctx.trackedFiles.has(envPath);
        if (stillTracked)
            continue; // worktree rule (ENV-001) covers the live file — avoid double-count
        findings.push({
            id: "HIST-ENV",
            severity: "high",
            confidence: "high",
            title: `Env file committed in git history (${envPath}) — deleted from HEAD is NOT deleted from history`,
            file: envPath,
            line: 0,
            evidence: { type: "env_in_history", masked: envPath, note: "anyone with clone access can recover it" },
            owasp: "A02",
            fix: "Rotate EVERY credential that lived in that file (rotate-first), then scrub history: git filter-repo --path " + envPath + " --invert-paths, coordinate force-push with the team, and verify old credentials are dead.",
            fix_mode: "suggested-diff",
            remediation: {
                type: "rotate-first",
                provider: "generic",
                steps: "1) Rotate all credentials from that env file 2) git filter-repo to purge it from history 3) Force-push + notify team to re-clone 4) Verify old credentials are dead",
                history_cleanup: "git filter-repo required — this IS the fix, not an extra",
            },
            root: envPath,
            root_cause: rootCause("HIST-ENV", envPath),
            verified: true,
        });
    }
    // ---- 2) secret-shaped lines added anywhere in history (cap commits for performance) ----
    const diff = git(["log", "-p", "-U0", "--no-color", "--all", "--max-count=400"]);
    const seen = new Set();
    const lines = diff.split("\n");
    let currentFile = "";
    for (const line of lines) {
        const fm = line.match(/^\+\+\+\s+b\/(.+)$/);
        if (fm) {
            currentFile = fm[1];
            continue;
        }
        if (!line.startsWith("+") || line.startsWith("+++"))
            continue;
        const content = line.slice(1);
        if (content.length > 500)
            continue;
        for (const p of SECRET_LINE_PATTERNS) {
            const m = content.match(p.re);
            if (!m)
                continue;
            if (/PLACEHOLDER|changeme|xxxxx|example/i.test(content))
                continue;
            const value = m[0];
            const masked = maskSecret(value);
            const root = masked.sha256_prefix;
            const key = `${p.id}:${root}`;
            if (seen.has(key))
                continue;
            seen.add(key);
            findings.push({
                id: p.id,
                severity: "high",
                confidence: "high",
                title: `Secret in git history: ${p.label}`,
                file: currentFile || "(history)",
                line: 0,
                evidence: { type: "secret_in_history", masked: masked.masked, sha256_prefix: masked.sha256_prefix, note: "recovered from `git log -p` added lines — full value never written to reports" },
                owasp: "A02",
                fix: "Treat as compromised regardless of deletion: rotate the credential NOW (rotate-first), then scrub history with git filter-repo.",
                fix_mode: "suggested-diff",
                remediation: {
                    type: "rotate-first",
                    provider: "generic",
                    steps: "1) Rotate the credential at its provider 2) Update server-side env 3) git filter-repo purge 4) Verify old credential dead",
                    history_cleanup: "git filter-repo required",
                },
                root,
                root_cause: rootCause(p.id, root),
                verified: true,
            });
        }
    }
    // ---- 3) .gitignore completeness audit ----
    const gitignoreFile = ctx.files.find((f) => f.rel === ".gitignore");
    if (!gitignoreFile) {
        findings.push({
            id: "HIST-010", severity: "low", confidence: "high",
            title: "No .gitignore file",
            file: ".gitignore", line: 0,
            evidence: { type: "gitignore_missing", masked: ".gitignore" },
            owasp: "A05",
            fix: "Add .gitignore covering .env, .env.*, *.pem, *.tfstate, node_modules, dist.",
            fix_mode: "suggested-diff", root: ".gitignore", root_cause: rootCause("HIST-010", ".gitignore"), verified: true,
        });
    }
    else {
        const gi = gitignoreFile.content;
        const missing = [];
        if (!/^\.env$/m.test(gi) && !/^\.env\.\*/m.test(gi))
            missing.push(".env");
        if (!/\.pem|id_rsa/i.test(gi))
            missing.push("*.pem / SSH keys");
        if (!/tfstate/.test(gi))
            missing.push("*.tfstate");
        if (missing.length) {
            findings.push({
                id: "HIST-011", severity: "low", confidence: "high",
                title: `.gitignore missing entries: ${missing.join(", ")}`,
                file: ".gitignore", line: 0,
                evidence: { type: "gitignore_incomplete", masked: missing.join(", ") },
                owasp: "A05",
                fix: `Add ${missing.join(", ")} to .gitignore to prevent accidental commits.`,
                fix_mode: "suggested-diff", root: "gitignore", root_cause: rootCause("HIST-011", "gitignore"), verified: true,
            });
        }
    }
    return { findings };
}
export function gitAvailable(rootDir) {
    try {
        execFileSync("git", ["rev-parse", "--git-dir"], { cwd: rootDir, stdio: "pipe" });
        return true;
    }
    catch {
        return false;
    }
}
export function trackedFiles(rootDir) {
    try {
        const out = execFileSync("git", ["ls-files"], { cwd: rootDir, maxBuffer: 16 * 1024 * 1024, encoding: "utf8" });
        return new Set(out.split("\n").map((s) => s.trim()).filter(Boolean));
    }
    catch {
        return new Set();
    }
}
