import type { ScanContext, RuleResult, Finding, Severity, Confidence } from "../types.js";
import { maskSecret, rootCause } from "../util.js";
import { classifyFile, importedFromClient, isClientEnvKey, normalizeAbs } from "./context.js";
import { isLiveEnvEntry, isNotePath, isPlaceholderDbUrl, looksLikeRealPrivateKey } from "./valueclass.js";

/**
 * Layer 1 — Secrets & Credentials (Plan Section 6).
 * Curated patterns (gitleaks-inspired, MIT-attributed) + value-based SUPA-001.
 * The VALUE is the identity: service_role is caught by decoding the JWT claim,
 * not by variable name. Direction is the verdict: client-reachable → CRITICAL,
 * server-only → INFO (the documented-correct pattern).
 */

interface SecretPattern {
  rule: string;
  title: string;
  re: RegExp;
  provider: string;
  severity: Severity;
  confidence: Confidence;
  owasp: string;
  fix: string;
  skip?: (match: string) => boolean;
}

const PLACEHOLDER = /(changeme|change_me|xxxxx|<[^>]*>|\$\{[^}]*\}|your[-_][a-z_]+|example|placeholder|dummy|todo|fixme|\*{3,})/i;

const PATTERNS: SecretPattern[] = [
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
    skip: (m) => PLACEHOLDER.test(m) || isPlaceholderDbUrl(m),
  },
];

/** Generic credential-assignment heuristic (context: value must look real, not placeholder). */
const ASSIGN_RE = /\b(api[_-]?key|api[_-]?secret|secret[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret|password|passwd|pwd)\b\s*[:=]\s*["']([^"'\n]{8,})["']/gi;

/**
 * SEC-010 (dev round) — credential assignment in NON-JS/TS configuration
 * formats (properties / ini / toml / tf / yaml / json / python / go / shell).
 * Two matcher gaps the JS-focused SEC-009 heuristic cannot see:
 *   1. key tokens: `DB_PASSWORD` / `spring.datasource.password` / `jwt.secret` —
 *      `\bpassword` can never match after a `_`/`.` junction or inside a
 *      camelCase name (word-char → word-char, no boundary), and bare `secret`
 *      is not in SEC-009's alternation at all;
 *   2. bare values: `.properties`/`.tf`/shell files rarely quote values, and
 *      SEC-009 requires a quoted string.
 * The key is TOKENIZED (same policy as DOCKER-003's ARG names) and must contain
 * a credential token; the value must look real (same looksReal bar) and must
 * not be a reference (env reads, `${…}` interpolation, TF `var.` references,
 * public-by-design key shapes) — and must itself be credential-SHAPED: opaque
 * printable-ASCII, not a multi-word prose sentence. The prose/ASCII guards came
 * out of the SEC-010 adjudication on the pinned Juice Shop corpus (120 of 122
 * findings were i18n catalog UI strings like `"TITLE_TWO_FACTOR_AUTH_ENTER":
 * "Enter the 6 digit token from your 2FA app"` in frontend/src/assets/i18n/*.json
 * — natural-language values with credential-ish key tokens `auth`/`token`).
 * Documented boundary: a quoted multi-word passphrase or a non-ASCII-charset
 * credential value is out of the heuristic's model and will be missed.
 * Lines already reported by SEC-001..009 or SEC-009's quoted-assignment
 * heuristic are skipped — one root cause, one finding.
 */
const SEC010_TOKENS = new Set([
  "secret", "password", "passwd", "pass", "pwd", "token", "key", "apikey",
  "credential", "credentials", "private", "jwt", "oauth", "bearer", "auth",
]);

function keyCredentialRisk(name: string): boolean {
  const tokens = name
    .replace(/(?<=[a-z0-9])(?=[A-Z])/g, "_") // camelCase → snake splitting
    .toLowerCase()
    .split(/[^a-z0-9]+/);
  return tokens.some((t) => SEC010_TOKENS.has(t));
}

const SEC010_KEY_RE = /^\s*"?([A-Za-z_][A-Za-z0-9_.-]{2,})"?\s*[:=]+\s*(.*)$/;
const SEC010_QUOTED = /^["']([^"'\n]{8,})["']/;
/** bare (unquoted) values must be single opaque tokens — no whitespace, quotes, parens or braces */
const SEC010_BARE_OK = /^[^\s"'`()[\]{}<>]+$/;
/** public-by-design key shapes (publishable keys, SSH public keys) are not secrets */
const SEC010_PUBLIC_VALUE = /^(?:pk_(?:live|test)_|sb_publishable_|ssh-(?:rsa|ed25519|ecdsa)\s)/;

/** Credential values are opaque printable-ASCII tokens; non-ASCII text (i18n
 * catalogs in Greek/Cyrillic/Thai/CJK scripts, etc.) is UI content, not a secret. */
const SEC010_ASCII = /^[\x20-\x7E]+$/;
/** ≥3 whitespace-separated words = a prose sentence (UI label/tooltip/title),
 * not a credential. Unquoted values are already single tokens (SEC010_BARE_OK);
 * this guard covers quoted values, where i18n strings otherwise pass looksReal. */
function isProse(v: string): boolean {
  return v.trim().split(/\s+/).length >= 3;
}

function looksReal(v: string): boolean {
  if (PLACEHOLDER.test(v)) return false;
  if (!/[A-Za-z]/.test(v) || !/\d/.test(v)) return false;
  return v.length >= 20 || /^[A-Fa-f0-9]{32,}$/.test(v) || /^[A-Za-z0-9+/=_-]{28,}$/.test(v);
}

/** --- SUPA-001: value-based service_role detection --- */
const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

function decodeJwtPayload(token: string): any | null {
  try {
    const payload = token.split(".")[1];
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const json = Buffer.from(b64, "base64").toString("utf8");
    return JSON.parse(json);
  } catch { return null; }
}

const SUPA_FIX =
  "service_role must never reach client code: use the anon key client-side with RLS enabled; move all admin operations to server-side code (route handlers/server actions) reading the key from server env.";

function rotateFirstSupabase(): Finding["remediation"] {
  return {
    type: "rotate-first",
    provider: "supabase",
    steps: "1) Rotate the JWT secret / regenerate API keys in the Supabase dashboard 2) Invalidate active sessions 3) Update server-side env with the new key 4) Scrub git history (git filter-repo) 5) Verify the old key is dead",
    history_cleanup: "git filter-repo required — deletion from HEAD is not enough",
  };
}

export function scanSecrets(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];
  const clientImporters = importedFromClient(ctx);

  // v1.2 (T3): one shared triage shared object — test/fixture/doc paths turn
  // secret findings into low-confidence review notes (no score impact).
  const notePush = (frel: string, fnd: RuleResult["findings"][number]) => {
    if (isNotePath(frel)) {
      fnd.severity = "low";
      fnd.confidence = "low";
      fnd.needs_confirmation = false;
    }
    findings.push(fnd);
  };

  for (const f of ctx.files) {
    const fileClass = classifyFile(f);
    const isMd = /\.(md|mdx|txt|rst)$/i.test(f.rel) || /(^|\/)(README|CHANGELOG)/i.test(f.rel);
    const isEnvExample = /(^|\/)\.env\.example$|(^|\/)\.env\.template$/i.test(f.rel);
    // SEC-010 scope: configuration/properties-style files OUTSIDE the JS/TS
    // surface. .env* files are owned by the dedicated env layer (ENV-001 +
    // per-line reachability); JS/TS code is owned by SEC-009 (quoted
    // assignments) — the format-agnostic surfaces live here.
    const inEnvFilePath = /(^|\/)\.env/.test(f.rel);
    const sec010File = !/\.[cm]?[jt]sx?$|\.tsx?$/i.test(f.rel) && !inEnvFilePath && !isMd && !isEnvExample;

    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      let lineSecFired = false; // a provider/assignment secret already reported on this line

      // In .env* files the VARIABLE NAME defines reachability: public prefix → client,
      // plain name → server-only env (the documented-correct Supabase pattern).
      const inEnvFile = inEnvFilePath;
      const envKey = envKeyOf(line);
      const clientHit = inEnvFile
        ? isClientEnvKey(envKey)
        : fileClass === "client" || isClientEnvKey(envKey) || clientImporters.has(normalizeAbs(f.abs));
      const serverHit = inEnvFile
        ? Boolean(envKey) && !isClientEnvKey(envKey)
        : fileClass === "server";

      // --- SUPA-001 (value-based JWT) ---
      let m: RegExpExecArray | null;
      JWT_RE.lastIndex = 0;
      while ((m = JWT_RE.exec(line)) !== null) {
        const token = m[0];
        const payload = decodeJwtPayload(token);
        const role = payload?.role;
        if (role === "anon" || role === "authenticated") continue; // designed-public keys — clean case
        if (role !== "service_role") continue;
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
          fix_mode: "suggested-diff" as const,
          remediation: rotateFirstSupabase(),
          root,
          root_cause: rootCause("SUPA-001", root),
          verified: true,
        };
        if (clientHit) {
          notePush(f.rel, { ...base, severity: "critical", confidence: "high" });
        } else if (serverHit) {
          notePush(f.rel, {
            ...base, severity: "info", confidence: "high",
            title: "service_role key used in server-only code (documented-correct pattern — verify env hygiene)",
            fix: "Correct placement. Ensure the key never leaks into client bundles and is not committed in plaintext env files.",
          });
        } else {
          notePush(f.rel, {
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
          owasp: "A01", fix: SUPA_FIX, fix_mode: "suggested-diff" as const,
          remediation: rotateFirstSupabase(),
          root, root_cause: rootCause("SUPA-001", root), verified: true,
        };
        if (clientHit) {
          notePush(f.rel, { ...base, severity: "critical", confidence: "high" });
        } else if (serverHit) {
          notePush(f.rel, { ...base, severity: "info", confidence: "high", title: "secret key (sb_secret_) used in server-only code (verify env hygiene)" });
        } else {
          notePush(f.rel, { ...base, severity: "medium", confidence: "medium", needs_confirmation: true, title: "secret key (sb_secret_) in unclassified context — confirm reachability" });
        }
      }

      // --- curated secret patterns ---
      for (const p of PATTERNS) {
        p.re.lastIndex = 0;
        while ((m = p.re.exec(line)) !== null) {
          const v = m[0];
          if (p.skip?.(v)) continue;
          // v1.2 (T3): a private-key HEADER without a following ≥64-base64 body
          // is a tutorial snippet, not committed key material.
          if (p.rule === "SEC-007" && !looksLikeRealPrivateKey(f.lines, i)) continue;
          // v1.2 (T3): test/fixture/doc paths — the value still gets REPORTED but
          // as a low-confidence review note (no score impact), replacing the old
          // blanket "docs excluded" silent skip so coverage stays honest.
          const notePath = isNotePath(f.rel);
          lineSecFired = true;
          const masked = maskSecret(v);
          const root = masked.sha256_prefix;
          findings.push({
            id: p.rule, severity: notePath ? "low" : p.severity, confidence: notePath ? "low" : p.confidence,
            title: p.title, file: f.rel, line: i + 1,
            evidence: { type: `${p.provider}_secret`, masked: masked.masked, sha256_prefix: masked.sha256_prefix, note: notePath ? "test/fixture/doc path — review note, no score impact; full value never written to any report or artifact" : "full value is never written to any report or artifact" },
            owasp: p.owasp, fix: p.fix, fix_mode: "suggested-diff",
            remediation: { type: "rotate-first", provider: p.provider, steps: `1) Rotate/revoke the ${p.provider} credential 2) Update server-side env 3) Scrub git history (git filter-repo) 4) Verify the old credential is dead`, history_cleanup: "git filter-repo required — deletion from HEAD is not enough" },
            root, root_cause: rootCause(p.rule, root), verified: true,
          });
        }
      }

      // --- generic assignment heuristic ---
      let assignFired = false;
      if (!isMd && !isEnvExample) {
        ASSIGN_RE.lastIndex = 0;
        while ((m = ASSIGN_RE.exec(line)) !== null) {
          const key = m[1], v = m[2];
          if (!looksReal(v)) continue;
          if (/(?:process\.env|os\.environ|getenv)/.test(line)) continue; // read from env — clean
          assignFired = true;
          lineSecFired = true;
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

      // --- SEC-010 (dev round): credential assignment in configuration formats ---
      if (sec010File && !lineSecFired && !assignFired) {
        const km = line.match(SEC010_KEY_RE);
        if (km && keyCredentialRisk(km[1])) {
          let v = (km[2] ?? "").trim();
          const q = v.match(SEC010_QUOTED);
          let quoted = false;
          if (q) { v = q[1]; quoted = true; }
          else { v = v.replace(/\s+[;#].*$/, "").trim(); } // trailing comment (properties/shell/yaml)
          if (
            v.length >= 8 &&
            (quoted || SEC010_BARE_OK.test(v)) &&
            looksReal(v) &&
            SEC010_ASCII.test(v) &&
            !isProse(v) &&
            !PLACEHOLDER.test(v) &&
            !SEC010_PUBLIC_VALUE.test(v) &&
            !/(?:process\.env|os\.environ|getenv)/.test(line) &&
            !/\$\{/.test(line)
          ) {
            const masked = maskSecret(v);
            const root = masked.sha256_prefix;
            notePush(f.rel, {
              id: "SEC-010", severity: "high", confidence: "medium",
              title: `Hardcoded credential in configuration ("${km[1].toLowerCase()}")`,
              file: f.rel, line: i + 1,
              evidence: { type: "hardcoded_credential_config", masked: masked.masked, sha256_prefix: masked.sha256_prefix, note: "configuration-format credential assignment — confirm the value is a real credential" },
              owasp: "A02",
              fix: "Move this credential to a secret store or environment reference and rotate it if it was ever committed (rotate-first).",
              fix_mode: "suggested-diff",
              remediation: { type: "rotate-first", provider: "generic", steps: "1) Confirm the value is real 2) Rotate it at the provider 3) Load from server-side env / secret manager 4) Scrub git history if committed", history_cleanup: "git filter-repo if the value appears in history" },
              root, root_cause: rootCause("SEC-010", root), verified: true,
            });
          }
        }
      }
    }
  }

  // --- committed .env files (worktree) ---
  const envRe = /(^|\/)\.env(\.local|\.production|\.staging|\.development)?$/i;
  for (const f of ctx.files) {
    if (!envRe.test(f.rel)) continue;
    const pairs = f.lines
      .map((l) => l.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?([^"'\n#]+)["']?/))
      .filter((kv): kv is RegExpMatchArray => kv !== null)
      .map((kv) => ({ key: kv[1], value: kv[2] }));
    const hasRealSecret = pairs.some((kv) =>
      // v1.2 (T2): the KEY alone is no longer the trigger (a NEXT_PUBLIC_* URL is
      // not a live secret — public-only env files are exactly the Lovable FP). The
      // VALUE is classified: JWTs by decoded role, provider prefixes by shape,
      // everything else by length+charset+entropy signal; a screaming credential
      // NAME with a 20+ char non-placeholder value still counts (T2 name rule).
      isLiveEnvEntry(kv.key, kv.value)
    );
    const tracked = ctx.trackedFiles.has(f.rel);
    if (hasRealSecret) {
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
      } else if (!ctx.gitAvailable) {
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
      continue;
    }
    // v1.2 (T2): a committed env file with NO secret-shaped values gets ONE LOW
    // review note (no score impact) — it fixes the old behavior of either
    // screaming CRITICAL on public keys or staying silently blind to a tracked .env.
    if (tracked && pairs.length > 0) {
      findings.push({
        id: "ENV-001", severity: "low", confidence: "low",
        title: "Environment file committed to git — public values only",
        file: f.rel, line: 0,
        evidence: { type: "committed_env_public", masked: `${f.rel} (${pairs.length} entries, none secret-shaped)`, note: "public-by-design values only (URLs / anon keys / publishable keys / project ids) — review note, no score impact; still keep .env gitignored so future secret-shaped entries never land in history" },
        owasp: "A05",
        fix: "Remove from tracking (git rm --cached .env) and add it to .gitignore — today's public values are fine, tomorrow's service_role paste would be committed too.",
        fix_mode: "suggested-diff", root: f.rel, root_cause: rootCause("ENV-001", `${f.rel}:public`), verified: true,
      });
    }
  }

  return { findings };
}

function envKeyOf(line: string): string {
  const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/);
  return m ? m[1] : "";
}
