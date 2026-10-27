import type { ScanContext, RuleResult } from "../types.js";
import { rootCause } from "../util.js";
import { classifyFile } from "./context.js";
import { collectAssignments, propagateTaint, resolveVarFlow } from "./flow.js";
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
 *
 * Documented limitation: missing `AbortController` timeouts on outbound
 * fetches and unbounded loops over request arrays are NOT yet detectable
 * without heavier flow analysis — named in classes_not_covered.
 */

/** request-derived source shapes (same family as taint.ts SOURCE_EXPR) */
const REQ_SOURCE =
  /req(?:uest)?\.(?:query|body|params|headers|cookies|nextUrl\.searchParams)|searchParams\.get|cookies\(\)\.get|headers\(\)\.get/;

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

    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      if (/^\s*(?:\/\/|\*|\/\*)/.test(line)) continue;

      // ---- RES-001: regex built from request-derived input ----
      const rb = REGEX_BUILD.exec(line);
      if (rb) {
        const argText = line.slice(rb.index + rb[0].length).replace(/\s*[,)].*$/, "");
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

      // ---- RES-002: unbounded collection read (no args / no take) inside a handler ----
      if (PRISMA_FIND_MANY.test(line) || UNBOUNDED_FIND.test(line)) {
        const blocks = handlerBlocks(f);
        const insideHandler = blocks.some(
          (b) => i >= b.line0 && i <= b.bodyEnd0
        );
        if (!insideHandler) continue; // unbounded reads outside request context are not per-request DoS
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
    }
  }
  return { findings };
}
