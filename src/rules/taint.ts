import type { ScanContext, RuleResult, ScannedFile } from "../types.js";
import { rootCause } from "../util.js";
import { classifyFile } from "./context.js";

/**
 * Taint-lite (Plan Section 6 Layer 4, v1.6 item — v0.3):
 * sources → sinks with a recognized-sanitizer allowlist, scope deliberately
 * capped at ONE file (plus sanitizer recognition at the call site, which may
 * be an imported helper — the "one-level import" allowance). Every finding:
 * severity MEDIUM (hard cap), confidence medium, needs_confirmation — the
 * final confirmation is a generated canary test the OWNER runs (Section 9.7),
 * never a verdict from the tool.
 *
 * TAINT-001 SSRF · TAINT-002 open redirect · TAINT-003 path traversal ·
 * TAINT-004 command injection · TAINT-005 reflected XSS (server-rendered)
 */

const SOURCE_EXPR =
  /req(?:uest)?\.(query|body|params|headers|cookies|nextUrl\.searchParams)|searchParams\.get|cookies\(\)\.get|headers\(\)\.get|url\.searchParams|getCookie|\.query\[|\.params\[|\.body\[/;

const SINK_RULES: Array<{
  id: string;
  title: string;
  sink: string;
  sanitizer: RegExp;
  owasp: string;
  fix: string;
  note: string;
}> = [
  {
    id: "TAINT-001",
    title: "User-controlled value flows into an outbound request URL — SSRF (server can be pointed anywhere)",
    sink: /(?:\bfetch\s*\(|axios(?:\.\w+)?\s*\(|axios\.\w+\s*\(|https?\.(?:get|request)\s*\()/.source,
    sanitizer: /allowlist|allowList|whitelist|allowed[_-]?hosts?|trusted[_-]?hosts?|isAllowed|validateUrl|assertUrl|ALLOWED_[A-Z_]+/,
    owasp: "A10",
    fix: "Validate the destination against a host allowlist (scheme + exact host) before any outbound request; block private/link-local ranges (169.254.x, 127.x, 10.x, 172.16-31.x, 192.168.x) and metadata endpoints.",
    note: "classic vibe-coding SSRF: 'fetch anything by URL' helpers — internal services/metadata IPs become reachable",
  },
  {
    id: "TAINT-002",
    title: "User-controlled value flows into a redirect target — open redirect (phishing pivot)",
    sink: /(?:\.(?:redirect)\s*\(|NextResponse\.redirect\s*\(|["'`]Location["'']\s*[,:]\s)/.source,
    sanitizer: /startsWith\s*\(\s*["'`]|isSafeRedirect|validateRedirect|allowedRedirect|safeRedirect|sameOrigin|ALLOWED_[A-Z_]+/,
    owasp: "A01",
    fix: "Only redirect to relative paths (reject absolute URLs and protocol-relative //host), or validate the target against an origin allowlist before redirecting.",
    note: "redirect(req.query.to) sends users anywhere — tokens/refs in the URL leak to attacker sites",
  },
  {
    id: "TAINT-003",
    title: "User-controlled value flows into a filesystem path — path traversal (../../ out of the data dir)",
    sink: /(?:fs\.promises\.\w+\s*\(|\bfs\.\w+\s*\(|readFileSync\s*\(|writeFileSync\s*\(|createReadStream\s*\(|\bunlink\s*\(|path\.join\s*\()/.source,
    sanitizer: /basename\s*\(|isSafePath|sanitizePath|validatePath|ensureWithin|startsWith\s*\(\s*[A-Z_]+(?:_DIR|_ROOT)|ALLOWED_[A-Z_]+/,
    owasp: "A01",
    fix: "Resolve the final path and assert it is still inside the intended root (path.resolve + startsWith(root)), or reduce the input to path.basename() before joining.",
    note: "path.join(base, req.params.file) with ../../etc/passwd escapes the base dir",
  },
  {
    id: "TAINT-004",
    title: "User-controlled value flows into a shell command string — command injection",
    sink: /(?:\bexec(?:Sync)?\s*\(|\bspawn(?:Sync)?\s*\([^)]*shell\s*:\s*true)/.source,
    sanitizer: /execFile|validateInput|sanitizeInput|escapeShell|allowlist|ALLOWED_[A-Z_]+|shell\s*:\s*false/,
    owasp: "A03",
    fix: "Never interpolate user input into shell strings — use execFile/spawn with an argv array (shell: false) and validate the input against an allowlist.",
    note: "exec(`convert ${req.query.file}`) — ';' or '$(...)' in the query executes as shell",
  },
  {
    id: "TAINT-005",
    title: "User-controlled value flows into server-rendered HTML — reflected XSS",
    sink: /(?:dangerouslySetInnerHTML|\.send\s*\(\s*`|res\.write\s*\(\s*`|innerHTML\s*=)/.source,
    sanitizer: /escape|sanitize|DOMPurify|encodeHTML|he\.encode|escapeHtml/,
    owasp: "A03",
    fix: "Escape the value before it enters HTML (or render as text, never raw HTML); if HTML is required, sanitize server-side with an allowlist-based sanitizer.",
    note: "template HTML with ${req.query.x} — script payloads execute in the victim's browser",
  },
];

/** a tainted variable: assigned from a source expression anywhere in the file */
function taintedVars(lines: string[]): Set<string> {
  const vars = new Set<string>();
  for (const line of lines) {
    if (!SOURCE_EXPR.test(line)) continue;
    for (const m of line.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/g)) vars.add(m[1]);
    for (const m of line.matchAll(/([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:req(?:uest)?\.(?:query|body|params)|searchParams\.get|cookies\(\)\.get|headers\(\)\.get)/g)) vars.add(m[1]);
  }
  // NestJS decorator-bound request values are sources too:
  //   read(@Param('name') name: string) / @Query('q') q / @Body() body
  for (const line of lines) {
    for (const m of line.matchAll(/@(?:Param|Query|Body|Headers)\s*\(\s*['"]?[\w.-]*['"]?\s*\)\s+([A-Za-z_$][\w$]*)/g)) vars.add(m[1]);
  }
  return vars;
}

function containsTaint(line: string, vars: Set<string>): boolean {
  if (SOURCE_EXPR.test(line)) return true;
  for (const v of vars) {
    if (new RegExp(`\\b${v}\\b`).test(line)) return true;
  }
  return false;
}

export function scanTaint(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];

  for (const f of ctx.files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.rel)) continue;
    if (/spec|test|__tests__|fixtures?|mock/i.test(f.rel)) continue;
    if (classifyFile(f) === "client") continue; // server-side taint only
    const vars = taintedVars(f.lines);
    if (!vars.size && !f.lines.some((l) => SOURCE_EXPR.test(l))) continue;

    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      const trimmed = line.trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) continue;

      for (const rule of SINK_RULES) {
        const sinkRe = new RegExp(rule.sink);
        const sinkMatch = sinkRe.exec(line);
        if (!sinkMatch) continue;
        // argument-level taint: only what comes AFTER the sink call counts.
        // (`if (!token) return NextResponse.redirect(new URL('/login', req.url))`
        //  is CLEAN — the redirect argument is a fixed string; token is a guard.)
        const argSpan = line.slice(sinkMatch.index);
        if (!containsTaint(argSpan, vars)) continue;
        // sanitizer window: same line ±6 (call-site recognition — the sanitizer
        // may be an imported helper; that is the one-level-import allowance)
        const window = f.lines.slice(Math.max(0, i - 6), i + 7).join("\n");
        if (rule.sanitizer.test(window)) continue; // clean case: recognized sanitizer cuts the path
        findings.push({
          id: rule.id,
          severity: "medium", // hard cap (Plan v1.6 — taint-lite never claims HIGH/CRITICAL)
          confidence: "medium",
          title: rule.title,
          file: f.rel,
          line: i + 1,
          evidence: { type: "taint_flow", masked: line.trim().slice(0, 80), note: rule.note },
          owasp: rule.owasp,
          fix: rule.fix,
          fix_mode: "suggested-diff",
          needs_confirmation: true,
          root: f.rel,
          root_cause: rootCause(rule.id, f.rel),
          verified: true,
        });
        break; // one finding per line — strongest rule wins
      }
    }
  }

  return { findings };
}

/** quarantine test scaffolds for taint findings (generated for the OWNER to run — never executed by the tool, Section 9.7) */
export function taintCanaryTest(finding: { id: string; file: string; line: number; evidence: { masked: string } }): string {
  return `/**
 * Canary confirmation for ${finding.id} — generated by Anubis Guardian (quarantine).
 * The tool does NOT run this test. Review it, adapt the URL/payload to your
 * staging environment, and run it YOURSELF. It must FAIL on the vulnerable
 * build and PASS after the fix.
 *
 * Flow: ${finding.file}:${finding.line}
 * Evidence: ${finding.evidence.masked}
 */
// import { test, expect } from '@playwright/test';

test.skip('canary ${finding.id}: ${finding.file}:${finding.line} — must fail while vulnerable', async ({ request }) => {
  // TODO(owner): point this at your staging deployment and adapt the payload
  // to the real endpoint/parameter shown in the evidence above.
  // const res = await request.get(process.env.STAGING_URL + '/<endpoint>?<param>=<canary-payload>');
  // expect([400, 401, 403, 404]).toContain(res.status());
  expect(true).toBe(true); // placeholder — replace, then remove test.skip
});
`;
}
