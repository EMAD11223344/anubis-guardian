import type { ScanContext, RuleResult, ScannedFile } from "../types.js";
import { rootCause } from "../util.js";
import { classifyFile } from "./context.js";
import { collectAssignments, propagateTaint } from "./flow.js";

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
    // §3.6 verdict: a hostname-based origin allowlist IS a destination
    // validation — `["app.example"].includes(u.hostname)` / `u.hostname === …`
    // counts, not just ALLOWED_-named variables.
    // v1.4: sanitizeUrl/safeUrl/cleanUrl/isValidUrl helpers count as URL validators too.
    // v1.5: inline URL-host validation shapes count (the v1.4 list only caught
    // the extracted-into-a-variable form) — `ALLOWED.includes(new URL(t).host)`,
    // `new URL(t).host === …`, `h === u.host` all demote to the LOW review note.
    sanitizer: /allowlist|allowList|whitelist|allowed[_-]?hosts?|trusted[_-]?hosts?|isAllowed|validateUrl|assertUrl|sanitizeUrl|safeUrl|cleanUrl|isValidUrl|ALLOWED_[A-Z_]+|hostname\s*(?:===|!==)|includes\s*\(\s*[A-Za-z_$][\w$.]*\.?hostname|\.includes\s*\(\s*(?:new\s+URL\s*\([^)]{0,100}\)|[A-Za-z_$][\w$.]*)\s*\.\s*\.?host\b|new\s+URL\s*\([^)]{0,100}\)\s*\.\s*\.?host(?:name)?\s*(?:===|!==)|(?:===|!==)\s*[A-Za-z_$][\w$.]*\.?\s*\.?host\b|\.host\b\s*(?:===|!==)/,
    owasp: "A10",
    fix: "Validate the destination against a host allowlist (scheme + exact host) before any outbound request; block private/link-local ranges (169.254.x, 127.x, 10.x, 172.16-31.x, 192.168.x) and metadata endpoints.",
    note: "classic vibe-coding SSRF: 'fetch anything by URL' helpers — internal services/metadata IPs become reachable",
  },
  {
    id: "TAINT-002",
    title: "User-controlled value flows into a redirect target — open redirect (phishing pivot)",
    // v1.2 (T13): sinks extended — next/navigation `redirect()`/`permanentRedirect()`
    // (bare call, no receiver dot), NextResponse.redirect and res.redirect.
    sink: /(?:\.(?:redirect|permanentRedirect)\s*\(|(?:^|[^.\w])(?:redirect|permanentRedirect)\s*\(|NextResponse\.redirect\s*\(|["'`]Location["'']\s*[,:]\s)/.source,
    // §3.6: hostname/origin allowlists validate redirect targets too
    sanitizer: /startsWith\s*\(\s*["'`]|isSafeRedirect|validateRedirect|allowedRedirect|safeRedirect|sameOrigin|ALLOWED_[A-Z_]+|rejectIfAbsolute|isRelative|hostname\s*(?:===|!==)|includes\s*\(\s*[A-Za-z_$][\w$.]*\.?hostname|\.origin\s*(?:===|!==)|includes\s*\(\s*[A-Za-z_$][\w$.]*\.?origin/,
    owasp: "A01",
    fix: "Only redirect to relative paths (reject absolute URLs and protocol-relative //host), or validate the target against an origin allowlist before redirecting. The recognized-safe guard is `value.startsWith(\"/\") && !value.startsWith(\"//\")` (or an origin allowlist).",
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
    title: "User-controlled value flows into a process-spawning call — command/argument injection",
    // v1.3 audit: adding execFile/spawn WITHOUT the shell:true gate — an untrusted
    // value in argv of child_process.execFile/spawn is argument injection even
    // with shell:false (e.g. `convert <input>` with an extra-hostile flag or a
    // hostile pathname argv). Verdict stays MEDIUM + needs_confirmation.
    sink: /(?:\bexec(?:Sync)?\s*\(|\bexecFile(?:Sync)?\s*\(|\bspawn(?:Sync)?\s*\()/.source,
    // v1.3 audit: `execFile` REMOVED from the sanitizer list — it is now a SINK
    // itself, so a bare mention inside the call would silence its own finding.
    sanitizer: /validateInput|sanitizeInput|escapeShell|escapeArg|allowlist|ALLOWED_[A-Z_]+|shell\s*:\s*false\s*[,}]/,
    owasp: "A03",
    fix: "Never interpolate user input into shell strings — use execFile/spawn with an argv array (shell: false) and validate the input against an allowlist.",
    note: "exec(`convert ${req.query.file}`) — ';' or '$(...)' in the query executes as shell",
  },
  {
    id: "TAINT-005",
    title: "User-controlled value flows into server-rendered HTML — reflected XSS",
    sink: /(?:dangerouslySetInnerHTML|\.send\s*\(\s*["'`]|res\.(?:write|end)\s*\(\s*["'`]|innerHTML\s*=)/.source,
    sanitizer: /escape|sanitize|DOMPurify|encodeHTML|he\.encode|escapeHtml/,
    owasp: "A03",
    fix: "Escape the value before it enters HTML (or render as text, never raw HTML); if HTML is required, sanitize server-side with an allowlist-based sanitizer.",
    note: "template HTML with ${req.query.x} — script payloads execute in the victim's browser",
  },
  {
    id: "TAINT-006",
    title: "User-controlled value flows into a code-evaluation sink — dynamic code execution",
    // v1.2 (T9): eval / Function (bare + new) / vm.runIn*Context / setTimeout(<string>).
    // There is NO recognized sanitizer for "execute this string as code" — the
    // escape hatch is validation, not sanitization — so the sanitizer window is
    // deliberately never-matching and the finding stands (MEDIUM taint cap).
    // SAST-003 additionally catches eval(new-literal) WITHOUT taint at MEDIUM.
    // v1.3 audit: bare `Function(...)` invocation (no `new`) is the same class.
    sink: /(?:\beval\s*\(|(?:new\s+|(?<![.\w$]))Function\s*\(|\bvm\.runIn(?:New|This)?Context\s*\(|setTimeout\s*\(\s*[A-Za-z_$][\w$]*)/.source,
    sanitizer: /$^/,
    owasp: "A03",
    fix: "Never pass request data to eval/new Function/vm. Replace with explicit parsing (JSON.parse), a safe expression evaluator, or allowlist-driven dispatch.",
    note: "eval(req.body.code) executes arbitrary user input on the server — RCE by design",
  },
];

/** a tainted variable: assigned from a source expression anywhere in the file,
 *  PLUS — v1.4 (§2) — every intermediate variable transitively derived from one
 *  (bounded fixpoint via rules/flow.ts): `const a = req.x; const b = a.trim()`
 *  no longer hides `b` from the sink check. */
function taintedVars(lines: string[]): Set<string> {
  const assigns = collectAssignments(lines);
  const tainted = propagateTaint(lines, assigns, (rhs) => SOURCE_EXPR.test(rhs));
  // NestJS decorator-bound request values are sources too:
  //   read(@Param('name') name: string) / @Query('q') q / @Body() body
  for (const line of lines) {
    for (const m of line.matchAll(/@(?:Param|Query|Body|Headers)\s*\(\s*['"]?[\w.-]*['"]?\s*\)\s+([A-Za-z_$][\w$]*)/g)) {
      if (!/^\s*(?:\/\/|\*|\/\*)/.test(line)) tainted.add(m[1]);
    }
  }
  return tainted;
}

function containsTaint(line: string, vars: Set<string>): boolean {
  if (SOURCE_EXPR.test(line)) return true;
  for (const v of vars) {
    if (new RegExp(`\\b${v}\\b`).test(line)) return true;
  }
  return false;
}

/** balanced first call argument WITHIN one line ("" when never closed) */
function balancedArg(line: string, openIdx: number): string {
  let depth = 0;
  for (let i = openIdx; i < line.length; i++) {
    const c = line[i];
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return line.slice(openIdx + 1, i);
    }
  }
  return "";
}

/**
 * §3.5 (h3): the FIRST TOP-LEVEL call argument — quote/bracket-aware scan that
 * stops at the call's closing paren or at a depth-1 comma (argument
 * separator). `fetch("https://fixed.example/api", { headers: req.headers })`
 * then yields only `"https://fixed.example/api"`, so unrelated header baggage
 * in argument #2 no longer reports as SSRF. "" when not closed on this line.
 */
function balancedTopArg(line: string, openIdx: number): string {
  let depth = 0;
  let quote: string | null = null;
  for (let i = openIdx; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === "\\") i++; // escaped char inside the string
      else if (c === quote) quote = null;
      continue;
    }
    if (c === "\"" || c === "'" || c === "`") {
      quote = c;
      continue;
    }
    if (c === "(" || c === "[" || c === "{") {
      depth++;
      continue;
    }
    if (c === ")" || c === "]" || c === "}") {
      depth--;
      if (depth <= 0) return line.slice(openIdx + 1, i);
      continue;
    }
    if (c === "," && depth === 1) return line.slice(openIdx + 1, i);
  }
  return "";
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
        // v1.3-audit (§3.5/3.6): for URL/redirect-kind sinks the DANGEROUS input is
        // the DESTINATION (argument #1), not any unrelated baggage in the tail of
        // the line. `fetch("https://relay.internal.example/api", { headers:
        // req.headers })` — fixed destination + request-header passthrough — was
        // classified as SSRF by the whole-rest-of-line check. For TAINT-001/002
        // the taint test runs on the FIRST TOP-LEVEL call argument (quote/
        // bracket-aware), falling back to the rest-of-line span when the call is
        // not closed on this line. Non-call sink forms (Location: header) keep
        // the whole-span check.
        let argSpan = line.slice(sinkMatch.index);
        if (rule.id === "TAINT-001" || rule.id === "TAINT-002") {
          const openIdx = /\(\s*$/.test(sinkMatch[0]) ? line.indexOf("(", sinkMatch.index) : -1;
          const first = openIdx !== -1 ? balancedTopArg(line, openIdx) : "";
          if (first) argSpan = first;
        }
        // argument-level taint: only what comes AFTER the sink call counts.
        // (`if (!token) return NextResponse.redirect(new URL('/login', req.url))`
        //  is CLEAN — the redirect argument is a fixed string; token is a guard.)
        if (!containsTaint(argSpan, vars)) continue;
        // sanitizer window: same line ±6 (call-site recognition — the sanitizer
        // may be an imported helper; that is the one-level-import allowance)
        const window = f.lines.slice(Math.max(0, i - 6), i + 7).join("\n");
        if (rule.sanitizer.test(window)) {
          // v1.2 (T6): a recognized SSRF allowlist no longer makes the finding
          // VANISH silently — the reviewer never saw why/what was skipped, and a
          // mis-recognized "sanitizer" hid a real flow without a trace. For
          // TAINT-001 the flow stays VISIBLE at LOW severity + LOW confidence:
          // a review note that never deducts (score.ts/deducts), keeping
          // allowlisted fetch helpers effectively clean while staying honest.
          if (rule.id === "TAINT-001") {
            findings.push({
              id: "TAINT-001",
              severity: "low",
              confidence: "low",
              title: "User-controlled value reaches an outbound request behind a recognized host allowlist — verify the allowlist is strict",
              file: f.rel,
              line: i + 1,
              evidence: {
                type: "taint_flow_allowlisted",
                masked: line.trim().slice(0, 80),
                note: "allowlist-shaped guard found near the sink (ALLOWED_*/allowlist/isAllowed…) — confirm it validates hostname exactly and rejects URL-encoded/bypass forms; LOW review note, no score impact",
              },
              owasp: rule.owasp,
              fix: rule.fix,
              fix_mode: "suggested-diff",
              needs_confirmation: true,
              root: f.rel,
              root_cause: rootCause(rule.id, `${f.rel}:allowlisted`),
              verified: true,
            });
            break; // one verdict per line — the strongest rule wins
          }
          continue;
        }
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
