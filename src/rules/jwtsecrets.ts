import type { ScanContext, RuleResult } from "../types.js";
import { maskSecret, rootCause } from "../util.js";

/**
 * JWT-003 — Hardcoded signing / session secrets (v1.2, T10 of the
 * independent-review fixes; next free JWT-0xx after JWT-001/002).
 *
 * What counts: a string literal (6+ chars) used as a SIGNING key —
 *   jwt.sign(payload, 'literal'), jwt.verify(token, 'literal'),
 *   JwtModule.register({ secret: 'literal' }),
 *   JwtStrategy super({ secretOrKey: 'literal' }),
 *   session({ secret: 'literal' }), const JWT_SECRET = 'literal'.
 *
 * What does NOT count (v1.2 T10 — the generic placeholder skip is DELIBERATELY
 * not applied to this rule): defaults like 'changeme-super-secret-key' ARE the
 * vulnerability — anyone who reads the repo can mint valid tokens. Only
 * obvious non-values are skipped: process.env.*, `${…}`, `<…>`, `YOUR_*`.
 */

const LITERAL_SECRET_OBJ =
  /\b(?:(?:secretOrKey)|(?:secret))\s*:\s*["'`]([^"'`\n]{6,})["'`]/g;

const HMAC_CALL =
  /\bjwt\.(?:sign|verify)\s*\(\s*[^,()]*,\s*["'`]([^"'`\n]{6,})["'`]/g;

/** const <name> = 'literal' — name must be a JWT/session-shaped credential name */
const CONST_SECRET =
  /\b(?:const|let|var)\s+((?:(?:JWT|SESSION|NEXTAUTH|AUTH|SUPABASE|SIGNING)|[A-Z_]*TOKEN)[A-Za-z0-9_]*(?:SECRET|_SECRET|KEY|_KEY))\s*=\s*["'`]([^"'`\n]{6,})["'`]/;

/** context that makes a bare `secret:` property a SIGNING secret (±3 lines) */
const SECRET_CONTEXT =
  /\bsession\s*\(\s*[{(]|JwtModule\.register\s*\(|JwtStrategy\b|passport-jwt|express-session|cookie-session|supertokens|LoginSession|jwt\.sign|jwt\.verify/;

/** only these non-values are skipped for this rule (NOT the generic placeholder list) */
const NON_VALUE_SKIP =
  /\$\{[^}]*\}|<[^>]*>|^\s*YOUR_|YOUR_[A-Z_]+|process\.env|configService|ioredis|undefined/i;

const FIX =
  "Move the signing secret to a server-only env var and generate a strong random value (openssl rand -base64 48). Any secret committed in source is compromised by definition — rotate it NOW (rotate-first): anyone with repo access (or every clone of a public repo) can mint valid tokens.";

export function scanJwtSecrets(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];

  for (const f of ctx.files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.rel)) continue;
    if (/(^|\/)(node_modules)\//.test(f.rel)) continue;

    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      if (/^\s*(?:\/\/|\*|\/\*)/.test(line)) continue; // comments are not config

      // ---- jwt.sign(payload, 'literal') / jwt.verify(token, 'literal') ----
      HMAC_CALL.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = HMAC_CALL.exec(line)) !== null) {
        const literal = m[1];
        if (NON_VALUE_SKIP.test(literal)) continue;
        const masked = maskSecret(literal);
        findings.push(mk(f.rel, i + 1, literal, `${f.rel}:${i + 1}`,
          `Signing secret hardcoded in jwt.${line.includes("jwt.sign") ? "sign" : "verify"}(...)`,
          "hardcoded_jwt_secret"));
      }

      // ---- { secret: 'literal' } / { secretOrKey: 'literal' } near a session /
      //      JwtModule / JwtStrategy / jwt context (±3 lines) ----
      LITERAL_SECRET_OBJ.lastIndex = 0;
      while ((m = LITERAL_SECRET_OBJ.exec(line)) !== null) {
        const literal = m[1];
        if (NON_VALUE_SKIP.test(literal)) continue;
        const window = f.lines.slice(Math.max(0, i - 3), i + 4).join("\n");
        if (!SECRET_CONTEXT.test(window)) continue;
        const masked = maskSecret(literal);
        findings.push(mk(f.rel, i + 1, literal, `${f.rel}:${i + 1}`,
          "Session/JWT secret hardcoded in a configuration object",
          "hardcoded_session_secret"));
      }

      // ---- const JWT_SECRET = 'literal' ----
      const cm = line.match(CONST_SECRET);
      if (cm) {
        const literal = cm[2];
        if (!NON_VALUE_SKIP.test(literal)) {
          const masked = maskSecret(literal);
          findings.push(mk(f.rel, i + 1, literal, `${f.rel}:${i + 1}`,
            `Signing secret hardcoded as module-level constant (${cm[1]})`,
            "hardcoded_jwt_secret", `${masked.sha256_prefix}:const`));
        }
      }
    }
  }

  return { findings };
}

function mk(rel: string, lineNo: number, literal: string, root: string, title: string, type: string, rootOverride?: string): RuleResult["findings"][number] {
  const masked = maskSecret(literal);
  const r = rootOverride ?? root;
  return {
    id: "JWT-003",
    severity: "high",
    confidence: "high",
    title,
    file: rel,
    line: lineNo,
    evidence: {
      type,
      masked: `secret = ${masked.masked}`,
      sha256_prefix: masked.sha256_prefix,
      note: "literal ≥6 chars used as a signing/verification key — placeholder defaults like 'changeme-super-secret-key' count as the vulnerability itself; rotate-first",
    },
    owasp: "A07",
    fix: FIX,
    fix_mode: "suggested-diff",
    remediation: { type: "rotate-first", provider: "generic", steps: "1) Generate a new strong secret (openssl rand -base64 48) 2) Move it to server-only env 3) Invalidate existing tokens (secret change does that) 4) Scrub history", history_cleanup: "git filter-repo if committed" },
    root: r,
    root_cause: rootCause("JWT-003", r),
    verified: true,
  };
}
