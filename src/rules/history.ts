import { execFileSync } from "node:child_process";
import { join, relative, resolve } from "node:path";
import type { ScanContext, RuleResult } from "../types.js";
import { maskSecret, rootCause } from "../util.js";

/** Canonical forward-slash form (Windows-safe — same contract as context.normalizeAbs). */
const norm = (p: string) => p.replace(/\\/g, "/");

/**
 * Resolve the git repo that CONTAINS rootDir, plus rootDir's path inside it.
 * Returns null when:
 *  - rootDir is not inside a repo at all, OR
 *  - the enclosing repo does not track anything under rootDir (unrelated ancestor).
 * Without this containment check, `git log -p` run from a plain folder sitting
 * inside an UNRELATED git repo imported that repo's entire history into the
 * target's report (foreign HIST-00x findings with foreign file paths) — found by
 * real-world testing, not by the in-repo suites, because every fixture happens
 * to carry its own .git. Same discipline applies to `git ls-files` (trackedFiles).
 * (Community contribution, ported from the v1.0.1 fork — accepted as a real fix.)
 */
export function gitScope(rootDir: string): { toplevel: string; rel: string } | null {
  try {
    const toplevel = norm(execFileSync("git", ["rev-parse", "--show-toplevel"],
      { cwd: rootDir, stdio: "pipe", maxBuffer: 1 << 16, encoding: "utf8" }).trim());
    if (!toplevel) return null;
    const rel = norm(relative(resolve(toplevel), resolve(rootDir)));
    if (rel === "" || rel === ".") return { toplevel, rel: "" };
    if (rel.startsWith("../")) return null; // paranoid: toplevel is not an ancestor of the target
    // the enclosing repo must actually TRACK files under the target — otherwise its
    // history is unrelated to the target and must never be imported
    const inside = execFileSync("git", ["ls-files", "--", rel],
      { cwd: toplevel, stdio: "pipe", maxBuffer: 4 << 20, encoding: "utf8" });
    if (!inside.trim()) return null;
    return { toplevel, rel };
  } catch { return null; }
}

/** strip the toplevel→target prefix from a repo-root-relative path */
function rebase(scope: { rel: string }, p: string): string | null {
  const np = norm(p);
  if (!scope.rel) return np;
  const prefix = scope.rel + "/";
  return np.startsWith(prefix) ? np.slice(prefix.length) : null;
}

/**
 * Layer 2 — Git history & config exposure (Plan Section 6).
 * Reading history is static analysis of the repo itself (allowed — Section 9.7);
 * the tool NEVER runs project code.
 */

const SECRET_LINE_PATTERNS: Array<{ id: string; re: RegExp; label: string }> = [
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

export function scanHistory(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];
  const scope = gitScope(ctx.rootDir);
  if (!ctx.gitAvailable || !scope) return { findings };

  const git = (args: string[], maxBuf = 32 * 1024 * 1024): string => {
    try {
      return execFileSync("git", args, { cwd: scope.toplevel, maxBuffer: maxBuf, encoding: "utf8" });
    } catch { return ""; }
  };

  // ---- 1) committed-then-deleted env files ----
  // (git runs at the toplevel; pathspec + rebase() keep results scoped to the target)
  const envPathArgs = scope.rel ? ["--", join(scope.rel, ".env"), join(scope.rel, ".env.*")] : ["--", ".env", ".env.*"];
  const envAdds = git(["log", "--all", "--diff-filter=A", "--name-only", "--pretty=format:", "-z", ...envPathArgs])
    .split("\0").map((s) => s.trim()).filter(Boolean);
  const envEverCommitted = [...new Set(
    envAdds.map((p) => rebase(scope, p)).filter((p): p is string => p !== null && ENV_FILE_RE.test(p))
  )];

  for (const envPath of envEverCommitted) {
    const stillTracked = ctx.trackedFiles.has(envPath);
    if (stillTracked) continue; // worktree rule (ENV-001) covers the live file — avoid double-count
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
  // pathspec filter: when the target is a subtree of a bigger repo, ONLY that
  // subtree's history may be attributed to the report (never sibling dirs).
  const diff = git(["log", "-p", "-U0", "--no-color", "--all", "--max-count=400",
    ...(scope.rel ? ["--", scope.rel] : [])]);
  const seen = new Set<string>();
  const lines = diff.split("\n");
  let currentFile = "";
  for (const line of lines) {
    const fm = line.match(/^\+\+\+\s+b\/(.+)$/);
    if (fm) { currentFile = rebase(scope, fm[1]) ?? ""; continue; }
    if (!line.startsWith("+") || line.startsWith("+++")) continue;
    const content = line.slice(1);
    if (content.length > 500) continue;
    for (const p of SECRET_LINE_PATTERNS) {
      const m = content.match(p.re);
      if (!m) continue;
      if (/PLACEHOLDER|changeme|xxxxx|example/i.test(content)) continue;
      const value = m[0];
      const masked = maskSecret(value);
      const root = masked.sha256_prefix;
      const key = `${p.id}:${root}`;
      if (seen.has(key)) continue;
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
  } else {
    const gi = gitignoreFile.content;
    const missing: string[] = [];
    if (!/^\.env$/m.test(gi) && !/^\.env\.\*/m.test(gi)) missing.push(".env");
    if (!/\.pem|id_rsa/i.test(gi)) missing.push("*.pem / SSH keys");
    if (!/tfstate/.test(gi)) missing.push("*.tfstate");
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

export function gitAvailable(rootDir: string): boolean {
  return gitScope(rootDir) !== null;
}

/** Tracked files, TARGET-relative and scoped to the target subtree.
 *  `git ls-files` run bare from a subdirectory prints the WHOLE repo's files —
 *  scope + rebase keep the contract "paths are relative to the scan root". */
export function trackedFiles(rootDir: string): Set<string> {
  try {
    const scope = gitScope(rootDir);
    if (!scope) return new Set();
    const args = scope.rel ? ["ls-files", "--", scope.rel] : ["ls-files"];
    const out = execFileSync("git", args, { cwd: scope.toplevel, maxBuffer: 16 * 1024 * 1024, encoding: "utf8" });
    return new Set(out.split("\n").map((s) => s.trim()).filter(Boolean)
      .map((p) => rebase(scope, p)).filter((p): p is string => p !== null));
  } catch { return new Set(); }
}
