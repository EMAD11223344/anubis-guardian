import type { ScanContext, RuleResult } from "../types.js";
import { rootCause } from "../util.js";
import { classifyFile } from "./context.js";
import { collectAssignments, resolveVarFlow } from "./flow.js";

/**
 * Capability §C — data leakage / data-exfiltration risks (v1.4).
 *
 * Honest contract — this pack distinguishes:
 *  - LEAK-001 (medium + needs_confirmation): credential-shaped fields serialized
 *    into client-facing response sinks (`res.json({ password, … })`) — a
 *    risk pattern, since only the developer knows whether the value is a
 *    hash, a deliberate-but-expiring token, or a real secret;
 *  - LEAK-002 (low note): personal-data-shaped fields (email/phone/SSN/DOB)
 *    reaching log sinks — potential PII over-collection in logs.
 *
 * Both stay silent on documented-clean shapes (`password: undefined`,
 * `delete user.password`, masked/unset statements) and never claim a
 * confirmed exfiltration — static analysis cannot observe the runtime value.
 *
 * v1.5 — LEAK-003 covers the previously documented whole-object gap:
 * `res.json(user)` where `user` resolves (bounded chase, ≤4 hops) to a WIDE
 * query result (`prisma.user.findUnique`, supabase `.from().select()`,
 * `SELECT *`). LOW review note by default (most returns are public content);
 * escalates to MEDIUM when the queried model's own declaration (schema.prisma
 * model / SQL migration columns) declares a credential-shaped column.
 * Projection/strip shapes (`select:`, `omit:`, `pick()`, spread-strip,
 * `delete`) silence. Runtime values stay unobservable — every finding names
 * that invisible layer.
 */

/** client-facing response sinks (v1.5: plain `Response.json` API included) */
const RESPONSE_SINK = /(?:\b(?:[Rr]es(?:ponse)?|reply)\s*\.\s*(?:json|send|sendStatus)\s*\(|NextResponse\s*\.\s*json\s*\(|\.status\s*\(\s*\d{3}\s*\)\s*\.\s*json\s*\(|JSON\s*\.\s*stringify\s*\()/;

/** credential-shaped object keys serialized into a response */
const CREDENTIAL_KEY =
  /[{,]\s*["']?(?:passwordHash|password|passwd|pwd|secret|api[_-]?key|apiKey|authToken|refresh[_-]?token|access[_-]?token|private[_-]?key|privateKey|sessionSecret|encryption[_-]?key)["']?\s*:\s*(?!\s*(?:undefined|null|"\s*"|''|●●●))/i;

/** documented-clean shapes: the field is stripped on the same line or adjacent */
const CLEANUP_SHAPE = /delete\s+\w+\.(?:password|passwd|secret|token)|\[?(?:password|passwd|secret|token)[\]']?\s*:\s*undefined|\bsanitizeUser\b|\bstripped\b|\bomit\b/i;

/** personal-data-shaped keys / fields (LEAK-002) */
const PII_LOG_SINK = /\bconsole\s*\.\s*(?:log|warn|error|debug|info)\s*\(/;
const PII_SHAPE = /\b(?:email|phone|ssn|social[_-]?security|date[_-]?of[_-]?birth|dateOfBirth|medical|health|full[_-]?name|fullName|address)\b/i;

// ---- LEAK-003 (v1.5) — whole-object serialization of a wide query result ----
/** bare-identifier whole-object response sink: `res.json(user)`, `Response.json(rows)`, `NextResponse.json(payload)` */
const WHOLE_SINK =
  /(?:\b(?:[Rr]es(?:ponse)?|reply)\s*\.\s*(?:json|send)\s*\(|NextResponse\s*\.\s*json\s*\()\s*([A-Za-z_$][\w$]*)\s*[\),]/;

/** shapes whose value came from an UN-PROJECTED (wide) query — the response may carry fields nobody selected away */
const WIDE_QUERY_SHAPE =
  /\bprisma\s*\.\s*\w+\.\s*\w+\s*\(|\b(?:findFirst|findUnique|findMany|findOne|findAll)\s*\(|\.from\s*\([^)]*\)\s*\.\s*(?:select|match)\s*\(|SELECT\s+\*|\.collection\s*\([^)]*\)\s*\.\s*(?:find|aggregate)/i;

/** documented-clean shapes: an explicit projection/strip sits in the flow */
const PROJECTION_SHAPE = /\bselect\s*:|\bomit\s*:|\bpick\s*\(|\.\.\.rest\b|delete\s+\w+\.\w+|\.\.\.\w+,?\s*password/;

/** credential-shaped fields declared for a model in schema.prisma / SQL migrations */
const CRED_COLUMN = /\b[A-Za-z_]*[Pp]assword[A-Za-z_]*\b|\b[A-Za-z_]*secret[A-Za-z_]*\b|\b[A-Za-z_]*[Tt]oken\b|\bapi[_-]?[Kk]ey\b/i;

export function scanLeak(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];

  // v1.5: per-model credential-column index (schema.prisma + SQL migrations) —
  // turns the LEAK-003 whole-object note into a targeted MEDIUM when the
  // serialized model ITSELF declares a credential-shaped column.
  const credModels = new Set<string>();
  for (const sf of ctx.files) {
    if (/\.prisma$/.test(sf.rel)) {
      for (const m of sf.content.matchAll(/^[\t ]*model\s+([A-Za-z_][\w]*)\s*\{([\s\S]*?)^\}/gm)) {
        if (CRED_COLUMN.test(m[2])) credModels.add(m[1].toLowerCase());
      }
    }
    if (/\.sql$/.test(sf.rel)) {
      const stmts = sf.content.split(/;\s*(?:\n|$)/);
      for (const stmt of stmts) {
        const create = /create\s+table\s+(?:if\s+not\s+exists\s+)?["'`]*(?:[a-zA-Z_][\w]*\.)?["'`]*([a-zA-Z_][\w]*)["'`]*/i.exec(stmt);
        if (create && CRED_COLUMN.test(stmt)) credModels.add(create[1].toLowerCase());
      }
    }
  }

  for (const f of ctx.files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.rel)) continue;
    if (/(?:^|\/)(?:tests?|__tests__|specs?|fixtures?|mocks?)\/|\.test\.|\.spec\./i.test(f.rel)) continue;
    const fileClass = classifyFile(f);
    if (fileClass === "client") continue; // server-side response shaping only

    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      if (/^\s*(?:\/\/|\*|\/\*)/.test(line)) continue;

      // LEAK-001 — credential key serialized into a client response
      if (RESPONSE_SINK.test(line) && CREDENTIAL_KEY.test(line)) {
        // window ±2: a documented cleanup shape in the same statement silences
        const window = f.lines.slice(Math.max(0, i - 2), Math.min(f.lines.length, i + 3)).join("\n");
        if (CLEANUP_SHAPE.test(window)) continue;
        const key = line.match(/[{,]\s*["']?([A-Za-z_][\w]{2,20})["']?\s*:/)?.[1] ?? "(credential field)";
        findings.push({
          id: "LEAK-001", severity: "medium", confidence: "medium",
          title: `Credential-shaped field "${key}" serialized into a client-facing response (review)`,
          file: f.rel, line: i + 1,
          evidence: {
            type: "leak_credential_response",
            masked: line.trim().slice(0, 120),
            note: "static analysis cannot confirm the runtime VALUE (hash vs live secret) — confirm what is actually returned and strip server-only fields",
          },
          owasp: "A02",
          fix: "Never serialize credential material to clients. Explicitly select returned fields (or delete/strip server-only keys) before responding.",
          fix_mode: "suggested-diff",
          root: `${f.rel}:${i + 1}`,
          root_cause: rootCause("LEAK-001", `${f.rel}:${i + 1}`),
          needs_confirmation: true,
          verified: true,
        });
        continue;
      }

      // LEAK-002 — personal data into logs (low review note)
      if (PII_LOG_SINK.test(line) && PII_SHAPE.test(line) && !/redact|mask|anonymiz|pseudonym/i.test(line)) {
        findings.push({
          id: "LEAK-002", severity: "low", confidence: "low",
          title: "Personal-data-shaped value written to a log sink (PII hygiene review)",
          file: f.rel, line: i + 1,
          evidence: {
            type: "leak_pii_log",
            masked: line.trim().slice(0, 120),
            note: "PII categories in logs may breach your data-handling policy/GDPR data-minimization — confirm the variable actually carries personal data at runtime",
          },
          owasp: "A09",
          fix: "Log references/IDs instead of personal values, or apply field-level redaction at the logging boundary.",
          fix_mode: "suggested-diff",
          root: `${f.rel}:${i + 1}`,
          root_cause: rootCause("LEAK-002", `${f.rel}:${i + 1}`),
          needs_confirmation: true,
          verified: true,
        });
        continue;
      }

      // LEAK-003 (v1.5) — whole-object serialization of a wide query result:
      // the response argument is a bare identifier that resolves (bounded
      // chase) to an un-projected query. LOW review note; MEDIUM when the
      // queried model's declaration carries credential-shaped columns.
      const whole = WHOLE_SINK.exec(line);
      if (whole) {
        const ident = whole[1];
        const assigns = collectAssignments(f.lines);
        const flow = resolveVarFlow(f.lines, assigns, ident, i);
        const chainVals = flow ? [flow.value, ...flow.chain] : [];
        const wide = chainVals.find((v) => WIDE_QUERY_SHAPE.test(v));
        if (wide) {
          const joined = [wide, ...chainVals, line].join("\n");
          if (!PROJECTION_SHAPE.test(joined)) {
            const model =
              /\bprisma\s*\.\s*([A-Za-z_$][\w$]*)\s*\.\s*\w+\s*\(/.exec(joined)?.[1]
              ?? /\.from\s*\(\s*["'`](\w+)/.exec(joined)?.[1]
              ?? /\b(?:from|table|model)\s*["'`]?([A-Za-z_][\w]{2,30})["'`]?\s*\)?/.exec(joined)?.[1]
              ?? "";
            const credModel = model && credModels.has(model.toLowerCase());
            const modelNote = credModel
              ? `the queried model "${model}" declares credential-shaped columns (schema evidence) — this response may expose one of them`
              : model
                ? `the queried model "${model}" shows no credential-shaped column in its declaration — likely public content, keeping the LOW review note`
                : "the queried model's declaration was not located in the scanned file set — severity stays LOW";
            findings.push({
              id: "LEAK-003", severity: credModel ? "medium" : "low", confidence: "low",
              title: `Whole query result serialized into a client-facing response${credModel && model ? ` (model "${model}" declares credential columns)` : " (review)"}`,
              file: f.rel, line: i + 1,
              evidence: {
                type: "leak_whole_object_response",
                masked: line.trim().slice(0, 120),
                note: `static analysis cannot observe which fields the runtime object carries; ${modelNote} — RLS/middleware stripping is an invisible layer, confirm with a real response`,
              },
              owasp: "A02",
              fix: "Respond with an explicit field projection (select/pick of safe columns) rather than the whole query row; strip server-only fields at the boundary.",
              fix_mode: "suggested-diff",
              root: `${f.rel}:${i + 1}`,
              root_cause: rootCause("LEAK-003", `${f.rel}:${i + 1}`),
              needs_confirmation: true,
              verified: true,
            });
          }
          continue;
        }
      }
    }
  }
  return { findings };
}
