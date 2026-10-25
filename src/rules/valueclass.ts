/**
 * v1.2 — Shared secret-VALUE classifier (T2/T3 of the independent-review fixes).
 *
 * One canonical home for "is this env value / history line a real secret?" so
 * that ENV-001 (committed .env), SUPA-001, SEC-00x, the history pack (HIST-00x),
 * SEED-001 and the guard hook judge values identically (no duplicated logic).
 * Previously each rule guessed on its own:
 *   - ENV-001 trusted the KEY alone: any NEXT_PUBLIC_* entry in a committed .env
 *     counted as a "real secret" → CRITICAL false positives on Lovable-style
 *     public-only .env files (API URLs, anon keys, publishable keys).
 *   - History flagged placeholder/example credential SETS (AWS docs pair) as real.
 *
 * Laws kept intact (Section 9.2): nothing here ever returns or stores the raw
 * value beyond the caller's own memory; masking happens in the caller via
 * maskSecret() as before. All predicates are pure and deterministic.
 */
import { decodeJwtPayload, jwtRole } from "../urlmode/jsassets.js";

export { decodeJwtPayload, jwtRole };

// ---------------------------------------------------------------- placeholders

/**
 * Canonical placeholder/example detection. Kept deliberately WIDER than the
 * per-rule copies it replaces (superset is safe — it only ever PREVENTS findings).
 */
const PLACEHOLDER_VALUE =
  /(changeme|change_me|changeit|xxxxx|<[^>]*>|\$\{[^}]*\}|\$env:|your[-_][a-z_]+|example|placeholder|dummy|todo|fixme|\*{3,}|\.{3,}|XXXXXXXX|to\s*be\s*filled|fillmein|not[-_]?a[-_]?real|insert[-_]?key)/i;

export function isPlaceholderValue(value: string): boolean {
  const v = value.trim();
  if (!v) return true;
  return PLACEHOLDER_VALUE.test(v);
}

/**
 * Documented example credentials (provider documentation "your keys here" sets).
 * gitleaks-equivalent allowlist: these exact strings appear in every provider
 * quickstart and in a million test fixtures — they are NOT live secrets.
 */
const EXAMPLE_CREDENTIALS = new Set([
  "AKIAIOSFODNN7EXAMPLE", // AWS docs access key id
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", // AWS docs secret access key
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY==",
]);

const AWS_EXAMPLE_ID = /^AKIA[0-9A-Z]*EXAMPLE$/;

export function isExampleCredential(value: string): boolean {
  const v = value.trim();
  if (EXAMPLE_CREDENTIALS.has(v)) return true;
  if (AWS_EXAMPLE_ID.test(v)) return true;
  return false;
}

// ---------------------------------------------------------------- JWT values

/** JWT-shaped: three base64url segments of plausible length. */
const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/;

export function isJwtShaped(value: string): boolean {
  return JWT_RE.test(value);
}

/**
 * The jwt.io sample token (payload `{"sub":"1234567890","name":"John Doe",…}`)
 * is pasted into READMEs and tutorials everywhere — it authorizes nothing.
 */
export function isJwtIoSample(value: string): boolean {
  const p = decodeJwtPayload(value);
  return p?.sub === "1234567890" && p?.name === "John Doe";
}

// ---------------------------------------------------------------- private keys

const B64_RUN = /[A-Za-z0-9+/]{64,}/;

/** A private-key BLOCK header is only a secret when a body of ≥64 base64
 *  characters follows on the same or the next lines. `-----BEGIN RSA PRIVATE
 *  KEY-----\nabc` is not a key (T3 requirement). */
export function looksLikeRealPrivateKey(lines: string[], headerIdx: number): boolean {
  const own = lines[headerIdx] ?? "";
  const after = own.replace(/-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----/g, "").trim();
  if (B64_RUN.test(after)) return true;
  for (let k = 1; k <= 3; k++) {
    const l = (lines[headerIdx + k] ?? "").trim();
    if (!l || l.startsWith("-----")) break;
    if (B64_RUN.test(l)) return true;
  }
  return false;
}

/** Single-string convenience (the value may contain \n escapes). */
export function isPrivateKeyShaped(value: string): boolean {
  const lines = value.replace(/\\n/g, "\n").split("\n");
  const idx = lines.findIndex((l) => /=+- ?BEGIN [A-Z ]*PRIVATE KEY/.test(l) || /-----BEGIN [A-Z ]*PRIVATE KEY/.test(l));
  if (idx === -1) return false;
  return looksLikeRealPrivateKey(lines, idx);
}

// ---------------------------------------------------------------- DB URLs

/**
 * Placeholder DB passwords (T3): postgres://user:password@localhost etc. Never
 * real credentials regardless of the environment they appear in.
 */
const DB_URL_RE = /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/([^\s:@'"]+):([^\s@'"]+)@([^\s'"]+)/;
const DB_PLACEHOLDER_PASSWORDS = new Set([
  "password", "pass", "changeme", "postgres", "root", "secret", "example", "xxxx", "user", "test",
]);

export function isPlaceholderDbUrl(value: string): boolean {
  const m = value.match(DB_URL_RE);
  if (!m) return false;
  const [, , password, rawHost] = m;
  const host = rawHost.split(/[/:?]/)[0]; // strip port/query — host equality only
  if (DB_PLACEHOLDER_PASSWORDS.has(password.toLowerCase())) return true;
  // exact host match only — "db.prod.internal" is a REAL production host, not
  // the wire-example host "db"
  return /^(localhost|127\.0\.0\.1|::1|::|0\.0\.0\.0|db|database|example\.[a-z]+)$/i.test(host);
}

/** ".example"/".sample"/".template" files hold wiring examples by definition. */
export function isExampleFilePath(rel: string): boolean {
  return /\.(example|sample|template)\.[^/]*$|\.env\.example$|\.env\.template$/i.test(rel);
}

// ---------------------------------------------------------------- env values

/**
 * Value-level belief ladder for env entries (T2):
 *   "service_role_jwt"  → live server-only credential, client-path = CRITICAL
 *   "live_secret"       → secret-shaped value (long opaque token / provider prefix)
 *   "public_by_design"  → anon/authenticated JWTs, publishable keys, URLs, jwt.io sample
 *   "unknown"           → short or ambiguous — never conclusive on its own
 */
export type EnvValueVerdict = "service_role_jwt" | "live_secret" | "public_by_design" | "unknown";

const URLISH = /^[a-z][a-z0-9+.-]*:\/\//i;
const OPAQUE_RE = /^[A-Za-z0-9+/=_-]+$/;
const PROVIDER_SECRET_PREFIX =
  /^(sk_live_|rk_live_|sk-[A-Za-z0-9]{20,}|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|xox[abprs]-|sb_secret_|npm_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|glpat-|shpat_|dop_v1_|tfp_|sbp_)/;
const PUBLIC_KEY_PREFIX = /^(pk_live_|pk_test_|sk_test_|rk_test_|sb_publishable_)/;

/**
 * Classify ONE env value. Key name is used only as corroboration, never as the
 * sole basis (that is the exact FP bug this classifier fixes).
 */
export function classifyEnvValue(value: string): EnvValueVerdict {
  const v = value.trim().replace(/^["']|["']$/g, "");
  if (!v || isPlaceholderValue(v) || isExampleCredential(v)) return "unknown";

  // JWTs are decided by the decoded role, not the shape (shape alone ⇒ FPs on
  // anon keys and FNs on dark JWTs with no recognizable prefix).
  if (isJwtShaped(v)) {
    if (isJwtIoSample(v)) return "public_by_design";
    const role = jwtRole(v);
    if (role === "service_role") return "service_role_jwt";
    if (role === "anon" || role === "authenticated") return "public_by_design";
    // opaque/no-role JWT in an env file — treat as a live secret (server configs)
    return "live_secret";
  }

  if (URLISH.test(v)) return "public_by_design"; // endpoints/URLs are not secret-shaped
  // Firebase web config API keys are public-by-design client identifiers
  if (/^AIza[0-9A-Za-z_-]{35}$/.test(v)) return "public_by_design";
  if (PUBLIC_KEY_PREFIX.test(v)) return "public_by_design";
  if (PROVIDER_SECRET_PREFIX.test(v)) return "live_secret";
  if (/-----BEGIN [A-Z ]*PRIVATE KEY/.test(v)) return isPrivateKeyShaped(v) ? "live_secret" : "unknown";

  // generic opaque token: length + charset + some entropy signal
  if (
    v.length >= 24 &&
    OPAQUE_RE.test(v) &&
    /[a-z]/.test(v) &&
    (/[A-Z]/.test(v) || /[0-9]/.test(v))
  ) {
    return "live_secret";
  }
  return "unknown";
}

/** Names that themselves declare a live credential (T2 value+name combination). */
const LIVE_ENV_NAME = /(?:_SECRET|_PASSWORD|_PASSWD|_TOKEN|_PRIVATE_?KEY|SERVICE_?ROLE)/i;

/**
 * ENV-001 file-level gate: does this env ENTRY contribute "live values"?
 * (name + value pairs; the key ALONE is never enough — see classifyEnvValue)
 */
export function isLiveEnvEntry(key: string, value: string): boolean {
  const verdict = classifyEnvValue(value);
  if (verdict === "service_role_jwt" || verdict === "live_secret") return true;
  if (verdict === "public_by_design") return false;
  // "unknown" verdict — short/ambiguous. Only a screaming credential NAME with a
  // 20+ char non-placeholder value turns ambiguity into a live credential.
  const v = value.trim().replace(/^["']|["']$/g, "");
  return LIVE_ENV_NAME.test(key) && v.length >= 20 && !isPlaceholderValue(v) && !URLISH.test(v);
}

// ---------------------------------------------------------------- path triage

/**
 * T3 — shared skip-lists for HEAD + history scanning. A finding attached to a
 * test/fixture/documentation path is a REVIEW NOTE, not a live leak: the caller
 * downgrades it to severity low + confidence low (no score impact — deducts()).
 */
const TEST_PATH = /(^|\/)(tests?|__tests__|test\b|fixtures?|examples?|samples?|mocks?|__mocks__|testdata|snapshots?)\//i;
const TEST_EXT = /\.(test|spec|e2e|int)\.[cm]?[jt]sx?$/i;
const DOC_PATH = /(^|\/)(docs?|documentation|changelog|[A-Z_-]*CHANGE[A-Z_-]*)($|\/)/i;
const DOC_EXT = /\.mdx?$|\.adoc$|\.rst$/i;

export function isTestPath(rel: string): boolean {
  return TEST_PATH.test(rel) || TEST_EXT.test(rel);
}

export function isDocPath(rel: string): boolean {
  if (/\/readme/i.test(rel) || /(^|\/)readme\.mdx?$/i.test(rel.split("/").pop() ?? rel)) return true;
  const base = rel.split("/").pop() ?? rel;
  return DOC_PATH.test(base) || DOC_EXT.test(base);
}

/** true → the caller MUST re-emit this finding as a low-confidence note. */
export function isNotePath(rel: string): boolean {
  return isTestPath(rel) || isDocPath(rel) || isExampleFilePath(rel);
}

/**
 * Value-level history guard (value only — PATH triage is the caller's downgrade
 * decision so notes stay visible). Returns true when the finding must NOT be
 * emitted at all: placeholders, example credentials, designed-public JWTs,
 * jwt.io sample token, placeholder DB URLs.
 */
export function skipHistoryFinding(relPath: string, value: string): boolean {
  const v = value.trim();
  if (!v || isPlaceholderValue(v) || isExampleCredential(v)) return true;
  if (isJwtShaped(v)) {
    if (isJwtIoSample(v)) return true;
    const role = jwtRole(v);
    if (role === "anon" || role === "authenticated") return true; // public-by-design tokens
  }
  if (isPlaceholderDbUrl(v)) return true;
  if (isExampleFilePath(relPath)) return true;
  return false;
}
