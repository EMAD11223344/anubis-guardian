import type { ScanContext, RuleResult } from "../types.js";
import { rootCause } from "../util.js";
import { classifyFile } from "./context.js";

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
 * Whole-object flows (`res.json(user)` where `user` carries a password from a
 * wide SELECT) are NOT detectable reliably here and stay documented as a
 * known limitation (classes_not_covered).
 */

/** client-facing response sinks */
const RESPONSE_SINK = /(?:\b(?:res(?:ponse)?|reply)\s*\.\s*(?:json|send|sendStatus)\s*\(|NextResponse\s*\.\s*json\s*\(|\.status\s*\(\s*\d{3}\s*\)\s*\.\s*json\s*\(|JSON\s*\.\s*stringify\s*\()/;

/** credential-shaped object keys serialized into a response */
const CREDENTIAL_KEY =
  /[{,]\s*["']?(?:passwordHash|password|passwd|pwd|secret|api[_-]?key|apiKey|authToken|refresh[_-]?token|access[_-]?token|private[_-]?key|privateKey|sessionSecret|encryption[_-]?key)["']?\s*:\s*(?!\s*(?:undefined|null|"\s*"|''|●●●))/i;

/** documented-clean shapes: the field is stripped on the same line or adjacent */
const CLEANUP_SHAPE = /delete\s+\w+\.(?:password|passwd|secret|token)|\[?(?:password|passwd|secret|token)[\]']?\s*:\s*undefined|\bsanitizeUser\b|\bstripped\b|\bomit\b/i;

/** personal-data-shaped keys / fields (LEAK-002) */
const PII_LOG_SINK = /\bconsole\s*\.\s*(?:log|warn|error|debug|info)\s*\(/;
const PII_SHAPE = /\b(?:email|phone|ssn|social[_-]?security|date[_-]?of[_-]?birth|dateOfBirth|medical|health|full[_-]?name|fullName|address)\b/i;

export function scanLeak(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];

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
      }
    }
  }
  return { findings };
}
