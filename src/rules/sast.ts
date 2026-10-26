import type { ScanContext, RuleResult } from "../types.js";
import { rootCause } from "../util.js";
import { classifyFile } from "./context.js";

/**
 * Layer 4 — SAST Light (Plan Section 6, v0.1 rows of the coverage matrix):
 * SQLi dynamic SQL, XSS dangerouslySetInnerHTML, eval/exec/child_process,
 * weak hashing. Taint-lite (deep flow) is the taint pack — NOT here.
 */

const FIX = {
  sqli: "Parameterize the query (prepared statements / query builder placeholders). Never build SQL by string concatenation with request data.",
  xss: "Render text instead of raw HTML, or sanitize with DOMPurify before injecting; never pass unsanitized user content to dangerouslySetInnerHTML.",
  exec: "Avoid spawning shells with interpolated input. Use execFile with argument arrays and an allowlist; validate input server-side.",
  codeexec: "Never evaluate user-controlled code. Replace eval/new Function with explicit parsing or a safe expression evaluator; validate inputs server-side.",
  hash: "Use bcrypt/argon2/scrypt for passwords. MD5/SHA1 are broken for password storage.",
};

/**
 * v1.2 (T8) — SQL sinks whose FIRST argument being dynamic SQL is an injection
 * risk. The v1.1.1 line-regex stopped at the first inner quote and blanket-
 * excluded any `prisma.` line, so pool.query(`…${req.x}`) and
 * prisma.$queryRawUnsafe('…'+req.x) were both invisible.
 */
const SQLI_SINKS: RegExp[] = [
  /\b(?:\$?[A-Za-z_$]*\.)*(?:queryRawUnsafe|executeRawUnsafe)\s*\(/g,   // prisma.$queryRawUnsafe / $executeRawUnsafe
  /\b(?:knex|knexClient)\.raw\s*\(/g,                                   // knex.raw
  /\bsequelize\.query\s*\(/g,                                           // sequelize.query
  /\b(?:pool|client|db|connection)\.query\s*\(/g,                       // pool/client/db/connection .query
  /\b(?:pool|client|db|connection|knex)\.execute\s*\(/g,                // .execute( on DB handles
];
/** tagged templates Prisma parameterizes safely — never a call-sink match */
const TAGGED_SAFE = /^(?:Prisma\.sql|sqltag|raw\s*\()/;

/** identifiers a file considers request-derived (severity trace for T8) */
function requestDerivedVars(content: string): Set<string> {
  const vars = new Set<string>();
  const source = /req(?:uest)?\s*\.\s*(?:query|params|body|headers|cookies)|searchParams\s*\.\s*get|@Param|@Query|@Body|@Headers/;
  for (const line of content.split(/\r?\n/)) {
    if (!source.test(line)) continue;
    for (const m of line.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/g)) vars.add(m[1]);
    for (const m of line.matchAll(/([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:req(?:uest)?\s*\.\s*(?:query|params|body|headers|cookies)|searchParams\s*\.\s*get)\s*\.?\s*[^;\n]{0,60}?;?$/g)) vars.add(m[1]);
  }
  return vars;
}

/** text of the first call argument, balancing parens across lines (bounded) */
function firstCallArg(content: string, openParenIdx: number, cap = 500): string {
  let depth = 0;
  let i = openParenIdx;
  for (; i < content.length && i - openParenIdx <= cap; i++) {
    const c = content[i];
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return content.slice(openParenIdx + 1, i);
    }
  }
  return content.slice(openParenIdx + 1, Math.min(i, openParenIdx + 1 + cap));
}

/** is snIdx inside a string literal on this line? (odd quote count before it) */
function insideStringLiteral(line: string, idx: number): boolean {
  const prefix = line.slice(0, idx);
  const odd = (ch: string) => ((prefix.match(new RegExp(ch === '"' ? `[^\\\\]"` : ch === "'" ? `[^\\\\]'` : "[^\\\\]`", "g")) ?? []).length) % 2 === 1;
  return odd('"') || odd("'") || odd("`");
}

/** balanced first argument WITHIN one line (unlike firstCallArg, keeps the
 *  trailing comment out — `eval('1+1'); // note` must stay a literal call) */
function lineArg(line: string, openIdx: number): string {
  let depth = 0;
  let end = line.length;
  for (let i = openIdx; i < line.length; i++) {
    const c = line[i];
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) { end = i; break; }
    }
  }
  return line.slice(openIdx + 1, end);
}

/** constant / safe first argument to an eval-family call */
function isLiteralArg(arg: string): boolean {
  const v = arg.trim();
  if (/^(?:["'`]([^"'`\\]|\\.)*["'`])$/.test(v)) return true;         // single string literal (no concat)
  if (/^-?\d+(\.\d+)?$/.test(v)) return true;                        // numeric
  if (/^(?:true|false|null|undefined|Number|parseInt|parseFloat|JSON\.parse)\b/.test(v)) return true;
  return false;
}

export function scanSast(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];

  for (const f of ctx.files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.rel)) continue;
    const fileClass = classifyFile(f);
    const isServer = fileClass === "server" || fileClass === "unknown" || /(^|\/)(server|api|lib)\//.test(f.rel);
    // request-derived identifiers in this file — severity trace for T8/T9
    const tracedVars = requestDerivedVars(f.content);
    const isReqDerived = (s: string): boolean =>
      /req(?:uest)?\s*\.\s*(?:query|params|body|headers|cookies)|searchParams\s*\.\s*get/.test(s) ||
      [...tracedVars].some((v) => new RegExp(`\\b${v}\\b`).test(s));

    // ---- v1.2 (T8): SQL injection via unsafe dynamic SQL — first-argument
    // analysis at recognized DB sinks, replacing the old first-quote-stopping
    // line regex (which had both a quote bug and a blanket `prisma.` exclusion).
    if (isServer) {
      for (const sinkRe of SQLI_SINKS) {
        sinkRe.lastIndex = 0;
        let sm: RegExpExecArray | null;
        while ((sm = sinkRe.exec(f.content)) !== null) {
          const sinkEnd = sm.index + sm[0].length;
          const openIdx = sinkEnd - 1; // "(" is the last char of the sink match
          const arg = firstCallArg(f.content, openIdx);
          const lineNo = f.content.slice(0, sm.index + 1).split("\n").length;
          const lineText = f.lines[lineNo - 1] ?? "";
          if (/^\s*(?:\/\/|\*|\/\*)/.test(lineText)) continue;             // commented sink
          if (TAGGED_SAFE.test(arg.trim())) continue;                       // Prisma.sql`…` inside Unsafe
          // unsafe = ${…} interpolation OR concat with a non-literal, in the
          // FIRST argument — regardless of inner quotes ("…'+req.x+'…" lands too)
          const interp = /\$\{[^}]*\}/.test(arg) || (arg.includes("${") && arg.length > 8);
          const usesConcat = /["'`]\s*\+\s*[A-Za-z_$]|\.concat\s*\(/.test(arg) || /(?:[A-Za-z_$)\]])\s*\+\s*["'`]/.test(arg);
          if (!interp && !usesConcat) continue;                             // constant / $1 / ? anchored — safe
          const traced = isReqDerived(arg);
          // v1.2: the SINK NAME is part of the masked evidence — same argument
          // text at different sinks (pool.query vs knex.raw) must stay distinct
          // findings (the engine dedupe keys on evidence text).
          const sinkName = sm[0].replace(/\s*\($/, "").trim();
          findings.push({
            id: "SAST-001", severity: traced ? "high" : "medium", confidence: traced ? "high" : "medium",
            title: traced
              ? "SQL query built from request data by interpolation/concatenation — injection risk"
              : "Dynamic SQL built with interpolation/concatenation — parameterize",
            file: f.rel, line: lineNo,
            evidence: { type: "sqli_dynamic_sql", masked: `${sinkName}(${arg.replace(/\s+/g, " ").trim().slice(0, 120)})` },
            owasp: "A03",
            fix: FIX.sqli,
            fix_mode: "suggested-diff",
            root: `${f.rel}:${lineNo}`,
            root_cause: rootCause("SAST-001", `${f.rel}:${lineNo}`),
            needs_confirmation: !traced,
            verified: true,
          });
        }
      }
    }

    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue; // skip comments

      // --- XSS via dangerouslySetInnerHTML ---
      const dsih = line.match(/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\}\s*\}/);
      if (dsih) {
        const expr = dsih[1].trim();
        const isLiteral = /^["'`][^"'`]*["'`]$/.test(expr);
        // local-const tracking: `const html = "literal"` assigned in the same file is safe
        const ident = expr.match(/^([A-Za-z_$][\w.]*)$/);
        const localLiteral = ident
          ? new RegExp(`(?:const|let|var)\\s+${ident[1].replace(/\./g, "\\.")}\\s*=\\s*["'\`][^"''\`]*["'\`]`).test(f.content)
          : false;
        // v1.2 (T6): sanitizer-recognized flows are not flagged as raw XSS.
        // `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(x) }}` (or an
        // identifier bound to a sanitize call in the same file) is the
        // documented-correct pattern — flagging it was a top review-note FP.
        const sanitized =
          /DOMPurify|purify|sanitize|xss\s*\(/i.test(line) ||
          (ident !== null &&
            new RegExp(
              `(?:const|let|var)\\s+${ident[1].replace(/\./g, "\\.")}\\s*=\\s*[^;\\n]*(?:DOMPurify|purify|sanitize|sanitize-html|xss)`,
              "i"
            ).test(f.content));
        if (!isLiteral && !localLiteral && !sanitized) {
          findings.push({
            id: "SAST-002", severity: "medium", confidence: "medium",
            title: "dangerouslySetInnerHTML receives a non-literal value — XSS risk",
            file: f.rel, line: i + 1,
            evidence: { type: "xss_dangerous_html", masked: expr.slice(0, 120) },
            owasp: "A03",
            fix: FIX.xss,
            fix_mode: "suggested-diff",
            root: `${f.rel}:${i + 1}`,
            root_cause: rootCause("SAST-002", `${f.rel}:${i + 1}`),
            verified: true,
          });
        }
      }

      // --- v1.2 (T9): dynamic code execution ---
      // eval/new Function/vm.runIn*Context of a NON-LITERAL value is SAST-003
      // (MEDIUM without taint — "the value is code, review this"); with explicit
      // interpolation it was already HIGH. Literal-only eval (eval('1+1')) and
      // eval mentioned inside comments or string literals stay untouched.
      const dynRe = /\b(?:eval|new\s+Function|vm\.runIn(?:New|This)?Context)\s*\(/g;
      let dm: RegExpExecArray | null;
      while ((dm = dynRe.exec(line)) !== null) {
        if (insideStringLiteral(line, dm.index)) continue;  // eval mentioned in a string/console message
        const openIdx = line.indexOf("(", dm.index);
        if (openIdx === -1) continue;
        const arg = lineArg(line, openIdx).replace(/\s*[),;]+\s*$/, "").trim();
        if (!arg || isLiteralArg(arg)) continue;            // constants are not dynamic code
        if (isServer && isReqDerived(arg)) {
          continue; // request-traced code execution is TAINT-006's job — no duplicate verdict
        }
        const interpolated = /\$\{|["'`]\s*\+\s*[A-Za-z_$]|[A-Za-z_$)\]]\s*\+\s*["'`]/.test(arg);
        findings.push({
          id: "SAST-003",
          severity: interpolated ? "high" : "medium",
          confidence: "medium",
          title: interpolated
            ? "Code executed from an interpolated string (eval/new Function) — code injection risk"
            : "Dynamic code execution of a non-literal value (eval/new Function/vm) — confirm the value can never be user-controlled",
          file: f.rel, line: i + 1,
          evidence: { type: "code_execution", masked: line.trim().slice(0, 120) },
          owasp: "A03",
          fix: FIX.codeexec,
          fix_mode: "suggested-diff",
          root: `${f.rel}:${i + 1}`,
          root_cause: rootCause("SAST-003", `${f.rel}:${i + 1}`),
          needs_confirmation: !interpolated,
          verified: true,
        });
        break; // one verdict per line — strongest shape wins
      }

      // --- exec/child_process with interpolation (unchanged from v1.1) ---
      if (/\bchild_process\b.*\bexec\s*\(|\bexec\s*\(\s*[`"'][^`"']*(?:\$\{|"\s*\+)/.test(line)) {
        const interpolated = /\$\{|\+\s*\w|\w\s*\+/.test(line);
        if (interpolated) {
          findings.push({
            id: "SAST-003", severity: "high", confidence: "medium",
            title: "Code executed from an interpolated string (shell exec) — command injection risk",
            file: f.rel, line: i + 1,
            evidence: { type: "code_execution", masked: line.trim().slice(0, 120) },
            owasp: "A03",
            fix: FIX.exec,
            fix_mode: "suggested-diff",
            root: `${f.rel}:${i + 1}`,
            root_cause: rootCause("SAST-003", `${f.rel}:${i + 1}`),
            verified: true,
          });
        }
      }

      // --- weak password hashing ---
      if (/createHash\s*\(\s*["'`](md5|sha1)["'`]\s*\)/i.test(line) && /(password|passwd|pwd|secret|token)/i.test(line)) {
        findings.push({
          id: "SAST-004", severity: "medium", confidence: "medium",
          title: "Weak hash (MD5/SHA1) applied to password-like material",
          file: f.rel, line: i + 1,
          evidence: { type: "weak_hashing", masked: line.trim().slice(0, 120) },
          owasp: "A02",
          fix: FIX.hash,
          fix_mode: "suggested-diff",
          root: `${f.rel}:${i + 1}`,
          root_cause: rootCause("SAST-004", `${f.rel}:${i + 1}`),
          verified: true,
        });
      }
    }
  }

  return { findings };
}
