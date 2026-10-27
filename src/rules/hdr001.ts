import type { ScanContext, RuleResult } from "../types.js";
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
  /\breq\.header\(\s*["'`]([^"'`]+)["'`]\s*\)/gi,      // Express helper
  /\breq\.get\(\s*["'`]([^"'`]+)["'`]\s*\)/gi,          // Express req.get("x…") (v1.3 audit)
];

/** v1.2 (T12): DB-connection construction sinks whose PROPERTIES get header values */
const SINK_CALL_RE =
  /\b(?:new\s+(?:pg\.)?(?:Pool|Client)|mongoose\.connect|mysql\.createPool|createPool|postgres|drizzle)\s*\(/;
const SINK_PROP_VALUE_RE = /\b(password|connectionString|url|host|user|uri)\s*:\s*([^,}]+)/g;
const SINK_POSITIONAL_RE = /\b(?:postgres|drizzle|mongoose\.connect)\s*\(\s*((?:[^(),]|\([^()]*\))+)/;

/** v1.2 (T12): options-object ASSIGNMENT form (honeypot shape):
 *   `pool.options.password = <headerValue>` / `client.connectionString = …` */
const SINK_ASSIGN_RE =
  /[\w$]*(?:[Pp]ool|[Cc]lient|onnection|mongoose)(?:\.options)?\.(?:password|connectionString|user|host|uri|url)\s*=\s*([^;\n]+)/;

const SECRET_SHAPE = /^(?:[A-Za-z0-9+/=_-]{20,}|[A-Fa-f0-9]{16,}|.{8,}@[A-Za-z0-9.-]+:.{3,})$/;
const PLACEHOLDER = /(changeme|xxxxx|<[^>]*>|\$\{[^}]*\}|your[-_]|example|placeholder|test|dummy|\*{3,})/i;

const SENDER_HEADER_RES = [
  /["'`](x[-_]?|)(db|database|sql|conn|connection|supabase|postgres|db[-_]?pass|db[-_]?password|root[-_]?password|admin[-_]?password|db[-_]?user|db[-_]?host|db[-_]?port|db[-_]?name)([-_]?[a-z0-9-]*)["'`]\s*:\s*(?:["'`]([^"'`\n]+)["'`]|([A-Za-z_$][\w.$]*))/gi,
];

const FETCH_CONTEXT = /(fetch\s*\(|axios[.(]|ofetch|request\s*\(\s*\{|http\.)/i;

const FIX_RECEIVER =
  "Database credentials must never travel in HTTP headers. Connect from server-side code using isolated env vars + a connection pool; if a proxy needs to authorize, send a short-lived signed token instead of raw credentials.";
const FIX_SENDER = FIX_RECEIVER;

/** v1.2 (T12): receiver-read matcher — direct `req.headers[…]`/`req.header(…)`/
 *  `headers().get(…)` PLUS local ALIASES of the Next.js headers() helper
 *  (`const h = await headers(); h.get("x-pg-secret")`) — the alias form was the
 *  x-pg-secret/x-dsn miss. Returns the HEADER NAME read, or null. */
function buildReceiverMatcher(lines: string[]): (text: string) => string | null {
  const aliases = new Set<string>();
  const aliasRe = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?headers\s*\(\s*\)/;
  for (const l of lines) {
    const m = l.match(aliasRe);
    if (m) aliases.add(m[1]);
  }
  const aliasAlt = aliases.size ? `(?:${[...aliases].map((a) => a.replace(/[.*+?^${}()|[\\]/g, "\\$&")).join("|")})\\.get\\s*\\(` : "(?:$never$)\\.get\\s*\\(";
  const patterns = [
    /req(?:uest)?\.headers(?:\[\s*["'`]([^"'`]+)["'`]\s*\]|\.get\s*\(\s*["'`]([^"'`]+)["'`]\s*\))/,
    /\breq(?:uest)?\.header\s*\(\s*["'`]([^"`\s]+)["'`\s]*\)/,
    /\breq(?:uest)?\.get\s*\(\s*["'`]([^"`\s]+)["'`\s]*\)/,
    /headers\s*\(\s*\)\s*\.\s*get\s*\(\s*["'`]([^"`\s]+)["'`\s]*\)/,
    new RegExp(aliasAlt + '["\'`]([^"\'`]+)["\'`]'),
  ];
  const bareHeadersRe = /\breq(?:uest)?\.headers\b/;
  return (text: string): string | null => {
    for (const p of patterns) {
      const m = p.exec(text);
      if (!m) continue;
      // the header NAME is the last DEFINED capture group (variant groups may
      // be undefined — `[…]` vs `.get(…)` share one pattern)
      for (let g = m.length - 1; g >= 1; g--) {
        if (typeof m[g] === "string" && m[g]) return m[g];
      }
    }
    // §3.5 (h1): bare `req.headers` — destructuring (`const { xPgPass } =
    // req.headers`), spreads and direct pass-throughs carry no header NAME.
    // The line still counts as a header READ so the destructure branch binds
    // the destructured locals; the evidence names the receiver itself.
    if (bareHeadersRe.test(text)) return "(req.headers)";
    return null;
  };
}

export function scanHdr001(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];

  for (const f of ctx.files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.rel)) continue;
    const fileClass = classifyFile(f);
    const fileHasHttp = FETCH_CONTEXT.test(f.content); // sender check needs an HTTP-call context anywhere in the module

    // v1.2 (T12): per-file map of VARIABLES assigned from a receiver read —
    // `const secret = req.headers.get("x-pg-secret")` makes `secret` a header
    // value for the rest of the file (same-file value-flow, documented scope).
    const hasHeaderRead = buildReceiverMatcher(f.lines);
    const headerVars = new Map<string, string>(); // varName → header name
    for (const line of f.lines) {
      if (!hasHeaderRead(line)) continue;
      const headerName = hasHeaderRead(line) ?? "(unknown header)";
      for (const m of line.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/g)) {
        if (!headerVars.has(m[1])) headerVars.set(m[1], headerName);
      }
      for (const m of line.matchAll(/([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?[A-Za-z_$.]/g)) {
        if (!headerVars.has(m[1])) headerVars.set(m[1], headerName);
      }
      // v1.3-audit (§3.5): destructured header reads also bind header values —
      //   `const { xPgSecret } = req.headers` / `const { "x-dsn": dsn } = req.headers`
      //   / `const { someName = req.get("x-pg-secret") }`-style aliasing (object pattern)
      if (/=\s*(?:await\s+)?req(?:uest)?\.headers\b/.test(line)) {
        const brace = line.match(/\{([^}]*)\}/);
        if (brace) {
          for (const part of brace[1].split(",")) {
            const pm = part.match(/["']?([A-Za-z_$][\w$]*)["']?\s*(?::\s*(["']?[A-Za-z_$][\w$]*["']?))?/);
            if (!pm) continue;
            const localName = (pm[2]?.replace(/["']/g, "") ?? pm[1]).trim();
            if (localName && !headerVars.has(localName)) headerVars.set(localName, headerName);
          }
        }
      }
    }

    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];

      // ---------- receiver (a) v1.2 T12: header value flows INTO a DB sink ----
      if (SINK_CALL_RE.test(line) || SINK_ASSIGN_RE.test(line)) {
        const window = f.lines.slice(i, Math.min(i + 4, f.lines.length)).join(" ");
        const values: Array<{ prop: string; expr: string }> = [];
        for (const p of window.matchAll(SINK_PROP_VALUE_RE)) {
          values.push({ prop: p[1], expr: p[2] });
        }
        const pos = window.match(SINK_POSITIONAL_RE);
        if (pos) values.push({ prop: "connectionString", expr: pos[1] });
        for (const ld of f.lines.slice(i, Math.min(i + 3, f.lines.length))) {
          const am = ld.match(SINK_ASSIGN_RE);
          if (am) values.push({ prop: (am[0].match(/\.(?:password|connectionString|user|host|uri|url)\b/) ?? ["", "password"])[1], expr: am[1] });
        }
        for (const { prop, expr } of values) {
          const v = expr.replace(/\?\?.*$/, "").trim();
          const directName = hasHeaderRead(v);
          const ident = /^([A-Za-z_$][\w$]*)\s*$/.exec(v)?.[1];
          const name = directName ?? (ident !== undefined ? headerVars.get(ident) : undefined);
          if (!name) continue;
          const masked = maskSecret(name);
          const root = `${f.rel}:${masked.sha256_prefix}`;
          findings.push({
            id: "HDR-001", severity: "critical", confidence: "high",
            title: "Database connection configured from a request-header value",
            file: f.rel, line: i + 1,
            evidence: {
              type: "receiver_read",
              masked: `header "${name}" → DB ${prop}`,
              sha256_prefix: masked.sha256_prefix,
              note: `any caller controls the DB credential/endpoint via the "${name}" header — connection string, password or user/host take request data (sink-linked in this file)`,
            },
            owasp: "A02",
            fix: FIX_RECEIVER,
            fix_mode: "suggested-diff",
            remediation: { type: "rotate-first", provider: "generic", steps: "1) Read DB config from server-side env only 2) Rotate any exposed credential 3) Reject header-provided connection data with 400", history_cleanup: "not needed unless the header value itself was a secret" },
            root,
            root_cause: rootCause("HDR-001", root),
            verified: true,
          });
          break; // one sink verdict per line block
        }
      }

      // ---------- receiver (b): DB-ish header NAME read — LOW review note ------
      // v1.2 (T12): the NAME heuristic no longer produces HIGH/CRITICAL on its
      // own (its 21/22-FP review verdict was wrong for unnamed sinks); it stays
      // as a low-confidence note for visibility + cross-root linkage.
      for (const re of RECEIVER_RES) {
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = re.exec(line)) !== null) {
          const name = (m[1] || m[2] || "").trim();
          if (!name || !DB_HEADER_NAME.test(name) || CLEAN_HEADER.test(name)) continue;
          const masked = maskSecret(name);
          const root = `${f.rel}:${masked.sha256_prefix}`;
          findings.push({
            id: "HDR-001",
            severity: "low", confidence: "low",
            title: "Server reads a DB-sounding header name (review note)",
            file: f.rel, line: i + 1,
            evidence: {
              type: "receiver_read",
              masked: `header "${name.toLowerCase()}"`,
              sha256_prefix: masked.sha256_prefix,
              note: "DB-sounding header name read on the server — no DB-sink linkage proven; upgrade happens automatically when the value flows into a connection (value-flow branch)",
            },
            owasp: "A02",
            fix: FIX_RECEIVER,
            fix_mode: "suggested-diff",
            root, root_cause: rootCause("HDR-001", root),
            needs_confirmation: true,
            verified: true,
          });
        }
      }

      // ---------- sender side ----------
      if (!fileHasHttp) continue;
      for (const re of SENDER_HEADER_RES) {
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = re.exec(line)) !== null) {
          const headerName = `${m[1] || "x-"}${m[2]}${m[3] || ""}`;
          if (CLEAN_HEADER.test(headerName)) continue;
          const literal = m[4];
          const varRef = m[5];
          if (literal !== undefined) {
            if (PLACEHOLDER.test(literal)) continue;
            const looksSecret = SECRET_SHAPE.test(literal);
            if (!looksSecret && !DB_HEADER_NAME.test(m[2])) continue;
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
          } else if (varRef !== undefined && varRef !== "undefined") {
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
