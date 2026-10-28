import type { ScanContext, RuleResult } from "../types.js";
import { rootCause } from "../util.js";
import { classifyFile } from "./context.js";
import { collectAssignments, propagateTaint, resolveVarFlow } from "./flow.js";
import { balancedTopArg } from "./taint.js";
import { handlerBlocks } from "./authzpack.js";

/**
 * Capability §D — application-side resource exhaustion / DoS patterns (v1.4).
 *
 * Deliberately DISTINCT from scanner self-resilience (that lives in the
 * adversarial ReDoS battery + budget gates, U20.34/U23.x): this pack flags
 * application patterns that let a request consume unbounded resources.
 *
 *  - RES-001 (high, flow-assisted): a regular expression is BUILT from
 *    request-controlled input (`new RegExp(req.query.q)`) — attacker-chosen
 *    patterns make CPU cost attacker-chosen (ReDoS / quadratic engines).
 *  - RES-002 (medium + needs_confirmation): unbounded collection reads
 *    (`prisma.<model>.findMany()` with no `take`/`cursor`) inside a request
 *    handler — result size is attacker-influenced; note-level because
 *    pagination may exist at an invisible layer.
 *  - RES-003 (v1.5, low + needs_confirmation): outbound requests issued inside
 *    a request handler with NO visible timeout/cancellation (`signal`,
 *    `AbortSignal`, `timeout`). Without one, a stalled upstream keeps the
 *    request (and its server resources) alive indefinitely — slowloris-
 *    adjacent resource retention. Note-level because a shared client/wrapper
 *    may configure timeouts at an invisible layer.
 *
 * Remaining documented limitation: unbounded loops over request-controlled
 * arrays are NOT yet detectable without heavier flow analysis — named in
 * classes_not_covered.
 */

/** request-derived source shapes (same family as taint.ts SOURCE_EXPR;
 *  v1.5.3: parsed request-body forms count — json/formData/text — a regex
 *  built from `const body = await request.json()` content is exactly as
 *  attacker-shaped as one built from req.query) */
const REQ_SOURCE =
  /req(?:uest)?\.(?:query|body|params|headers|cookies|nextUrl\.searchParams)|req(?:uest)?\s*\.\s*(?:json|formData|text)\s*\(\s*\)|searchParams\.get|cookies\(\)\.get|headers\(\)\.get/;

/** regex construction sinks */
const REGEX_BUILD = /\bnew\s+RegExp\s*\(/;

/** pagination-less collection reads */
const UNBOUNDED_FIND = /\b\w+\.(?:findMany|find|scan|list)\s*\(\s*\)\./;          // chained, never bounded
const PRISMA_FIND_MANY = /\b[A-Za-z_$][\w$]*\.findMany\s*\(\s*\)/;                 // findMany() with NO args

export function scanDos(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];

  for (const f of ctx.files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.rel)) continue;
    if (/(?:^|\/)(?:tests?|__tests__|specs?|fixtures?|mocks?)\/|\.test\.|\.spec\./i.test(f.rel)) continue;
    if (classifyFile(f) === "client") continue;

    const assigns = collectAssignments(f.lines);
    const tainted = propagateTaint(f.lines, assigns, (rhs) => REQ_SOURCE.test(rhs));
    const hBlocks = handlerBlocks(f); // hoisted once per file (v1.5 — was per line)

    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      if (/^\s*(?:\/\/|\*|\/\*)/.test(line)) continue;

      // ---- RES-001: regex built from request-derived input ----
      const rb = REGEX_BUILD.exec(line);
      if (rb) {
        // v1.5.3: quote/paren-aware FIRST-argument extraction (balancedTopArg)
        // — the old cut-at-first-`)` slice truncated composite arguments like
        // `(await request.json()).pattern` before their parsed-body source.
        const openIdx = rb.index + rb[0].length - 1;
        const argText = balancedTopArg(line, openIdx)
          || line.slice(rb.index + rb[0].length).replace(/\s*[,)].*$/, "");
        let traced = REQ_SOURCE.test(argText) ? "direct" : "";
        let viaVar = "";
        if (!traced) {
          // flow-assisted: identifier in the RegExp(…) argument resolving to a request source
          const idents = [...new Set(argText.match(/[A-Za-z_$][\w$]*/g) ?? [])].slice(0, 4);
          for (const id of idents) {
            if (/\b(await|function|return|typeof|new|const|let|var|if|else|null|undefined|true|false)\b/.test(id)) continue;
            if (tainted.has(id)) { traced = "flow"; viaVar = id; break; }
            const flow = resolveVarFlow(f.lines, assigns, id, i);
            if (flow && REQ_SOURCE.test(flow.value)) { traced = "flow"; viaVar = id; break; }
          }
        }
        if (traced === "direct") {
          findings.push({
            id: "RES-001", severity: "high", confidence: "high",
            title: "Regular expression is built from request-controlled input — attacker-chosen CPU cost (ReDoS risk)",
            file: f.rel, line: i + 1,
            evidence: { type: "user_regex_build", masked: line.trim().slice(0, 120) },
            owasp: "A04",
            fix: "Never compile request data into a regex. Use a fixed allowlist of patterns, or a safe expression engine with a complexity/time budget (re2-style).",
            fix_mode: "suggested-diff",
            root: `${f.rel}:${i + 1}`,
            root_cause: rootCause("RES-001", `${f.rel}:${i + 1}`),
            needs_confirmation: false,
            verified: true,
          });
          continue;
        }
        if (traced === "flow") {
          findings.push({
            id: "RES-001", severity: "medium", confidence: "medium",
            title: `Regular expression built from an identifier ("${viaVar}") that resolves to request data (review)`,
            file: f.rel, line: i + 1,
            evidence: {
              type: "user_regex_build_flow",
              masked: line.trim().slice(0, 120),
              note: `flow-chased through intermediate variables (bounded, ${"≤"}4 hops) — confirm the value is truly request-controlled at runtime`,
            },
            owasp: "A04",
            fix: "Never compile request data into a regex; even sanitized input can drive catastrophic backtracking.",
            fix_mode: "suggested-diff",
            root: `${f.rel}:${i + 1}`,
            root_cause: rootCause("RES-001", `${f.rel}:${i + 1}`),
            needs_confirmation: true,
            verified: true,
          });
          continue;
        }
      }

      // handler containment is shared by RES-002/RES-003
      const handlerBlock = hBlocks.find((b) => i >= b.line0 && i <= b.bodyEnd0) ?? null;
      if (PRISMA_FIND_MANY.test(line) || UNBOUNDED_FIND.test(line)) {
        if (!handlerBlock) continue; // unbounded reads outside request context are not per-request DoS
        // ±2-line window: a take/cursor/limit arg in the same call silences
        const window = f.lines.slice(Math.max(0, i - 2), Math.min(f.lines.length, i + 3)).join("\n");
        if (/\b(?:take|cursor|limit|first|LIMIT)\b/i.test(window)) continue;
        const model = line.match(/([A-Za-z_$][\w$]*)\.(?:findMany|find|scan|list)\s*\(/)?.[1] ?? "(model)";
        findings.push({
          id: "RES-002", severity: "medium", confidence: "medium",
          title: `Pagination-less collection read (${model}.findMany) inside a request handler — unbounded result size (review)`,
          file: f.rel, line: i + 1,
          evidence: {
            type: "unbounded_collection_read",
            masked: line.trim().slice(0, 120),
            note: "a result cap/take or a repository-level global scope may apply invisibly — confirm before treating as exploitable",
          },
          owasp: "A04",
          fix: "Cap every list read a request can trigger (take/limit) at a sane page size; stream or paginate large exports.",
          fix_mode: "suggested-diff",
          root: `${f.rel}:${i + 1}`,
          root_cause: rootCause("RES-002", `${f.rel}:${i + 1}`),
          needs_confirmation: true,
          verified: true,
        });
      }

      // ---- RES-003 (v1.5): outbound request in a handler with no visible
      // timeout/cancellation. A stalled upstream then holds the request (and
      // its connection/socket/memory) open indefinitely. LOW review note —
      // a shared client/axios default or fetch wrapper may set timeouts at
      // an invisible layer (CONFIDENCE: this is missing-evidence, not proof).
      if (handlerBlock && /\b(?:await\s+)?fetch\s*\(|\baxios(?:\.\w+)?\s*\(|\bhttps?\.\s*(?:get|request)\s*\(|\bgot\s*\(/.test(line)) {
        // per-CALL statement: extend only while the call's own parens stay open
        // (an options object below belongs to THIS call; a different, adjacent
        // call on the next line must not silence this one — v1.5 probe fix)
        let stmt = line;
        let depth = (line.match(/\(/g) ?? []).length - (line.match(/\)/g) ?? []).length;
        for (let j = i + 1; j < f.lines.length && j - i < 8 && depth > 0; j++) {
          stmt += "\n" + f.lines[j];
          depth += (f.lines[j].match(/\(/g) ?? []).length - (f.lines[j].match(/\)/g) ?? []).length;
        }
        if (!/\b(?:signal|AbortSignal|AbortController|timeout|setTimeout)\b/.test(stmt.replace(/\s+\/\/.*$/gm, ""))) {
          findings.push({
            id: "RES-003", severity: "low", confidence: "low",
            title: "Outbound request inside a request handler with no visible timeout or cancellation — stalled upstream retains resources (review)",
            file: f.rel, line: i + 1,
            evidence: {
              type: "outbound_no_timeout",
              masked: line.trim().slice(0, 120),
              note: "no signal/AbortSignal/timeout shape found in this statement window; a shared client (axios instance, fetch wrapper) may configure timeouts at an invisible layer — confirm before treating as a gap",
            },
            owasp: "A04",
            fix: "Give every outbound call a deadline: fetch(url, { signal: AbortSignal.timeout(ms) }) or axios timeout, so a hung upstream cannot pin connections open.",
            fix_mode: "suggested-diff",
            root: `${f.rel}:${i + 1}`,
            root_cause: rootCause("RES-003", `${f.rel}:${i + 1}`),
            needs_confirmation: true,
            verified: true,
          });
        }
      }
    }
  }
  return { findings };
}
