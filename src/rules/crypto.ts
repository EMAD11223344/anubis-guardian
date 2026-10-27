import type { ScanContext, RuleResult } from "../types.js";
import { rootCause } from "../util.js";

/**
 * CRYPTO-001 — Math.random() used to generate security material (Plan Section 6 Layer 5).
 * Promoted v0.3 → v0.2 by Step 0 sweep data (11% of 100 AI-built projects, 136 hits —
 * 2nd most frequent pattern after unpinned CI actions).
 *
 * Scope discipline (clean-cases first): only flag when the random value flows into a
 * token-shaped variable (token/otp/secret/nonce/password/code/salt/apiKey/sessionId)
 * or a security sink (jwt.sign, cookie set, Buffer token, crypto import in module),
 * within a ±4-line window. Innocent Math.random (UI jitter, tests, shuffles, ids for
 * display) stays silent.
 */

const TOKENISH_VAR = /(token|otp|secret|nonce|password|passwd|salt|api[_-]?key|apikey|session[_-]?id|sessionid|verification|confirm[_-]?code|reset[_-]?code|auth[_-]?code|invite[_-]?code|coupon|license[_-]?key|pin[_-]?code)/i;

const SECURITY_SINK = /(jwt\.sign|sign\(|setCookie|res\.cookie|\.cookie\(|Buffer\.from|createHmac|createCipheriv|hash|otp|two[-_]?factor|2fa|verify)/i;

const CLEAN_CONTEXT = /(test|spec|mock|fixture|example|sample|demo|story|dummy|random[_-]?color|shuffle|animation|delay|jitter|seed [_-]?data|console|log)/i;

const FIX =
  "Math.random() is not cryptographically secure — its output is predictable. Use crypto.randomBytes()/crypto.randomUUID() (node:crypto) or WebCrypto crypto.getRandomValues() for tokens, OTPs, secrets, and any security-relevant identifier.";

export function scanCrypto(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];
  if (!ctx.stack.frameworks) return { findings };

  for (const f of ctx.files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.rel)) continue;
    const fileClass = /spec|test|__tests__|fixtures?|mock/i.test(f.rel);
    if (fileClass) continue; // test files are clean by design

    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      if (!line.includes("Math.random")) continue;
      const trimmed = line.trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) continue; // docs/comments are not code
      if (CLEAN_CONTEXT.test(line)) continue;

      const window = f.lines.slice(Math.max(0, i - 4), i + 5).join("\n");
      // v1.4 (ReDoS re-audit): the `.*Math.random` alternative scanned O(n) per
      // start position on adversarial long lines — the assignment value is by
      // construction on the same line and short: bound both runs.
      const assignTarget = (line.match(/([A-Za-z_$][\w$]{0,64})\s*=\s*(?:Math\.random|.{0,200}Math\.random)/) ?? [])[1] ?? "";

      const tokenVar = TOKENISH_VAR.test(assignTarget) || TOKENISH_VAR.test(window.split("Math.random")[0].slice(-60));
      const sinkNear = SECURITY_SINK.test(window);

      if (!tokenVar && !sinkNear) continue; // clean-case: not security material

      findings.push({
        id: "CRYPTO-001",
        severity: "high",
        title: "Security material generated with Math.random() (predictable)",
        file: f.rel,
        line: i + 1,
        evidence: {
          type: "insecure_randomness",
          masked: (assignTarget || "Math.random()").slice(0, 40),
          note: tokenVar ? "random value assigned to a token/secret-shaped variable" : "random value used near a security sink (jwt/cookie/hash)",
        },
        owasp: "A02",
        confidence: "high",
        fix: FIX,
        fix_mode: "suggested-diff",
        verified: true,
        source: "builtin",
        root: f.rel,
        root_cause: rootCause("CRYPTO-001", f.rel),
      });
    }
  }

  return { findings };
}
