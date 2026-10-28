import type { ScanContext, RuleResult, ScannedFile } from "../types.js";
import { rootCause } from "../util.js";
import { classifyFile } from "./context.js";

/**
 * Capability §A — RBAC / route authorization (v1.4).
 *
 * Two-tier honesty contract (product requirement: findings must DISTINGUISH
 * missing evidence of authorization from a confirmed vulnerability):
 *  - AUTHZ-001 (medium + needs_confirmation): a request handler performing a
 *    privileged operation (DB write / destructive call) with NO recognizable
 *    authorization-check call shape in its body — "missing evidence", never
 *    "confirmed vulnerable". Frameworks' guard layers (middleware, APP_GUARD,
 *    server-side RLS) are legitimately INVISIBLE to static analysis at this
 *    scope, so the finding is a review prompt.
 *  - AUTHZ-002 (high, evidence-backed): the authorization DECISION ITSELF is
 *    taken from client-controlled input (`if (req.body.isAdmin)`,
 *    `role === req.query.role`) — a flagged anti-pattern, still labelled
 *    needs-work-in-review but evidence-backed (not "missing evidence").
 *
 * Reuses the inventory's hasAuthzCheck call-shape list (same truth source as
 * the guard-truth feature), scoped to the handler body rather than the file.
 */

const FIX_AUTHZ =
  "Add server-side authorization before the privileged operation (session/middleware/guard), and derive the decision from server-stored state — never from client-submitted fields.";
const FIX_CLIENT_AUTHZ =
  "The authorization decision reads client-controlled input. Load the user's role/permissions from the database/session and compare SERVER-side state only.";

/** authorization-check call shapes — SAME list the AUTHZ pack attributes per handler */
export const AUTHZ_CALL =
  /(?:getSession|getServerSession|getAuth|auth\s*\(\)|requireUser|requireAuth|requireAdmin|requireLogin|requireSignIn|assertAuth|checkAuth|isAuthenticated|isLoggedIn|verifyToken|jwt\.verify|verifyJWT|UseGuards|getCurrentUser|currentUser\s*\(|getUser\s*\(|cookies\s*\(\s*\)\s*\.get|\.cookies\.get|authorization["'`]?\s*[,\]:]|headers\(\)\.get\(\s*["'`]authorization|authori[sz]ation\s*[:=]|can\s*\(|canAbili|ability\.|authorize\s*\(|hasPermission|hasRole|checkPermission|accessCheck|policy\.(?:allow|check)|constructEvent(?:Async)?\s*\(|\bcreateHmac\b|\btimingSafeEqual\b|\bnew\s+Webhook\s*\()/i;
/** comments never count as a check */
const isComment = (line: string): boolean => /^\s*(?:\/\/|\*|\/\*)/.test(line.trim());

/**
 * v1.5.3 — webhook signature verification is an AUTHENTICATION check: a route
 * whose body verifies the provider signature (Stripe constructEvent /
 * constructEventAsync, Svix/Standard-Webhooks `new Webhook(...)` + `.verify`,
 * hand-rolled `createHmac` + `timingSafeEqual`) is NOT "unauthenticated".
 * Precise call shapes only — the bare WORDS constructEvent/verify/Webhook in
 * prose or a comment prove nothing (comment lines are never matched).
 * Honesty note kept everywhere: signature authenticity ≠ application
 * authorization — verifying the sender does not authorize every operation.
 */
const WEBHOOK_AUTH_CALL =
  /constructEvent(?:Async)?\s*\(|\bcreateHmac\b|\btimingSafeEqual\b|\bnew\s+Webhook\s*\(/;

/** privileged operations: writes/destructive calls on data layers */
const PRIVILEGED_OP =
  /(?:\.\s*(?:create|createMany|update|updateMany|delete|deleteMany|upsert|destroy|remove|insert|replaceOne|deleteOne|deleteMany)\s*\(|\bINSERT\s+INTO\b|\bUPDATE\s+[A-Za-z_"'\[\]]+\s+SET\b|\bDELETE\s+FROM\b|\bDROP\s+(?:TABLE|USER|ROLE)\b|\bGRANT\b)/i;

/** client-controlled authorization decision: the decision value itself is request data */
const CLIENT_AUTHZ_DECISION =
  /(?:if\s*\(|(?:===|!==|==|!=)\s*["'`]?(?:true|false|admin|1)|=\s*(?:true|"admin"|"1"))?\s*(?:req(?:uest)?|session|auth)\s*\.\s*(?:body|query|headers|nextUrl\.searchParams|cookies)\b[^\n]{0,60}\b(?:is[_-]?admin|admin|role|permission|privilege|is[_-]?super(?:user)?)/i;

/**
 * v1.5.2 — the parsed request BODY (`const body = await request.json()`) is
 * exactly as client-controlled as `req.body`; decisions taken from ITS fields
 * are the same AUTHZ-002 anti-pattern. Precision contract: only a
 * DECISION shape (if/switch, equality, ternary) over authorization-related
 * fields fires — ordinary body fields (displayName, item, …) never do.
 */
const AUTHZ_FIELD =
  /\b(?:is[_-]?admin|is[_-]?super(?:user)?|admin|role|roles|permission|permissions|privilege|privileges|is[_-]?owner|scope|scopes)\b/i;
/** conditional/decision operators a line must carry besides the authz-field access */
const DECISION_OP = /\b(?:if|switch)\s*\(|===|!==|==|!=|\?(?!\.)/;
/** `const body = (await)? request.json()` — the parsed-body local */
const REQ_JSON_PARSE =
  /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:\(?\s*)?(?:await\s+)?req(?:uest)?\s*\.\s*json\s*\(\s*\)/;
/** `const { a, b: c } = await request.json()` — destructured fields */
const REQ_JSON_DESTRUCTURE =
  /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(?:\(?\s*)?(?:await\s+)?req(?:uest)?\s*\.\s*json\s*\(\s*\)/;
/** one-hop body alias: `const auth = body;` */
const REQ_JSON_ALIAS = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*;?\s*$/;
/** one-hop property alias: `const r = body.role;` (field must be authz-relevant) */
const REQ_JSON_PROP = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\??\.\s*([A-Za-z_$][\w$]*)\s*;?\s*$/;
/** re-destructure from an existing body local: `const { role } = body;` */
const REQ_JSON_REDESTRUCT = /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*([A-Za-z_$][\w$]*)\s*;?\s*$/;

interface BodyLocals { bodyVars: string[]; authzIdents: string[] }
/**
 * Bounded per-block collection of request-body locals (parse + destructure +
 * one-hop alias/property-alias/re-destructure). Bounds (documented): ≤8 body
 * locals, ≤8 authz idents, ONE hop — `const s = r;` after `const r = body.role`
 * is beyond the bound and deliberately untracked (deterministic, review-note
 * rule; deeper alias chains are named in classes_not_covered).
 */
function requestBodyLocals(body: string[]): BodyLocals {
  const bodyVars: string[] = [];
  const authzIdents: string[] = [];
  for (const bl of body) {
    if (isComment(bl)) continue;
    if (bodyVars.length < 8) { // bounded local set (documented)
      const mp = REQ_JSON_PARSE.exec(bl);
      if (mp) { bodyVars.push(mp[1] as string); continue; }
      const md = REQ_JSON_DESTRUCTURE.exec(bl);
      if (md) {
        for (const part of (md[1] as string).split(",")) {
          const id = /^([A-Za-z_$][\w$]*)/.exec(part.split(":").pop()?.trim() ?? "")?.[1];
          if (id && AUTHZ_FIELD.test(id)) authzIdents.push(id);
        }
      }
    }
  }
  for (const bl of body) {
    if (bodyVars.length >= 8 && authzIdents.length >= 8) break;
    if (!bodyVars.length) break;
    const t = bl.trim();
    if (isComment(t)) continue;
    const ma = REQ_JSON_ALIAS.exec(t);
    if (ma && bodyVars.includes(ma[2] as string) && !bodyVars.includes(ma[1] as string) && bodyVars.length < 8) {
      bodyVars.push(ma[1] as string);
      continue;
    }
    const mp = REQ_JSON_PROP.exec(t);
    if (mp && bodyVars.includes(mp[2] as string) && AUTHZ_FIELD.test(mp[3] as string)
      && authzIdents.length < 8 && !authzIdents.includes(mp[1] as string)) {
      authzIdents.push(mp[1] as string); // `const r = body.role` — the alias now carries the authz field
      continue;
    }
    const mr = REQ_JSON_REDESTRUCT.exec(t);
    if (mr && bodyVars.includes(mr[2] as string) && authzIdents.length < 8) {
      for (const part of (mr[1] as string).split(",")) {
        const id = /^([A-Za-z_$][\w$]*)/.exec(part.split(":").pop()?.trim() ?? "")?.[1];
        if (id && AUTHZ_FIELD.test(id) && !authzIdents.includes(id)) authzIdents.push(id);
      }
    }
  }
  return { bodyVars, authzIdents };
}
/** does line decide on `<var>.<authzField>` (incl. optional chains)? */
const bodyVarDecision = (l: string, v: string): boolean =>
  new RegExp(`\\b${v}\\b\\s*\\??\\s*\\.[\\s\\S]{0,40}?${AUTHZ_FIELD.source}`, "i").test(l);
/** does line decide on a bare destructured authz field? */
const bareIdentDecision = (l: string, a: string): boolean =>
  new RegExp(`(^|[^\\w$.])${a}\\b`, "i").test(l);

interface HandlerBlock { name: string; line0: number; bodyEnd0: number; mutating: boolean; }

/** bounded signature search window (lines) for the handler body locator */
const SIG_WINDOW = 60;
/** per-handler body budget in lines (same documented bound as v1.4) */
const BODY_MAX = 40;
/** absolute character cap for one bounded body-location scan */
const CHAR_BUDGET = 20000;

type HMode = "fn" | "express";

/** string/comment/template frames of the bounded tokenizer */
type Frame =
  | { kind: "linec" }
  | { kind: "blockc" }
  | { kind: "str"; quote: string }
  | { kind: "tpl" }
  | { kind: "tplcode"; depth: number };

interface BodySpan { open0: number; close0: number }

/**
 * Bounded balanced `{…}` scan starting at (li, col) — used by the fn-mode
 * header logic to tell a TS return-type ANNOTATION group
 * (`): { id: string } { … }`) from the real body brace. Skips string/template
 * frames like the main loop; bounded by `budget` characters. Returns the
 * position AFTER the closing brace and the next non-space char, or null when
 * the budget is exhausted (null = "unknown" — the caller then treats the
 * candidate as the body, which keeps the conservative 40-line window).
 */
function balancedBraceGroup(
  lines: string[], li0: number, col0: number, hiLine: number, budget: number
): { endLine: number; endCol: number; nextNonSpace: string; next2: string } | null {
  let depth = 0, chars = 0;
  let quote: string | null = null;
  for (let li = li0; li < hiLine; li++) {
    const line = lines[li] ?? "";
    for (let col = li === li0 ? col0 : 0; col < line.length; col++) {
      if (++chars > budget) return null;
      const c = line[col] as string;
      const nx = col + 1 < line.length ? (line[col + 1] as string) : "";
      if (quote) {
        if (c === "\\") { col++; }
        else if (c === quote) quote = null;
        continue;
      }
      // backticks are treated as ordinary characters here: the scanner is only
      // used on TS type-annotation groups, where a template literal is itself
      // the arg of a bounded balanced count — string quotes stay the frame that
      // matters (a `${ "}" }`-style brace inside a quote is skipped via quote).
      if (c === '"' || c === "'") { quote = c; continue; }
      if (c === "/" && nx === "/") break; // rest of the line is a comment
      if (c === "/" && nx === "*") { while (col < line.length - 1 && !(line[col] === "*" && line[col + 1] === "/")) col++; col++; continue; }
      if (c === "{") depth++;
      else if (c === "}") {
        depth--;
        if (depth === 0) {
          // find the next TWO non-space chars after the group — the caller
          // distinguishes `…} {` (annotation → body) from `…} => {`
          // (annotation → arrow → body)
          let first = "", second = "";
          for (let j = col + 1; j < line.length; j++) {
            const n = line[j] as string;
            if (/\s/.test(n)) continue;
            if (!first) { first = n; continue; }
            second = n;
            return { endLine: li, endCol: col + 1, nextNonSpace: first, next2: second };
          }
          for (let k = li + 1; k < Math.min(lines.length, li + 4); k++) {
            const t = (lines[k] ?? "").trim();
            if (!t) continue;
            if (!first) { first = t[0] as string; if (t.length > 1) { second = t[1] as string; break; } continue; }
            second = t[0] as string;
            break;
          }
          return { endLine: li, endCol: col + 1, nextNonSpace: first, next2: second };
        }
      }
    }
  }
  return null;
}

/**
 * v1.5.3 — robust handler-body identification (was: "first `{` in a 4-line
 * window", which mistook destructured-parameter / TS-annotation braces for the
 * body opening and truncated the handler before the security-relevant calls).
 *
 * Bounded, string/comment/template-aware scanner: parentheses of the parameter
 * list/type arguments are tracked, and the BODY is the depth-0 `{` AFTER the
 * parameter list closes (`fn` mode: `export (async) function METHOD(...)`,
 * `export const METHOD = ... =>`, alias-exported handlers, NestJS
 * `@Post() method(...)`), or the `{` following the callback `=>` while the
 * call is still open (`express` mode: `app.post("/path", (req, res) => { … })`).
 *
 * fn-mode header handling (v1.5.3): after the parameter list closes, the header
 * may still contain TS type material — generic arguments
 * (`): Record<string, {a: 1}> => {`) and return-type annotations whose braces
 * are OBJECTS, not the body (`): { id: string } {`). Both are resolved:
 * `<…>` brackets open a type-argument region (braces inside are skipped), an
 * arrow `=>` after the close marks the next `{` as the body, and a `{…}` group
 * followed by another `{` in a `:`-annotation context is skipped as an
 * annotation group via a bounded balanced lookahead.
 *
 * Documented corners (bounded heuristic, review-note rule — never a verdict):
 * an object-brace default inside an express callback parameter, or a body
 * whose first statement is a nested bare block after a `:`-annotated
 * signature, can still misplace the boundary; both are rare in route handlers
 * and the rule contract stays needs_confirmation.
 */
function handlerBodySpan(lines: string[], start0: number, mode: HMode): BodySpan | null {
  const hiLine = Math.min(lines.length, start0 + SIG_WINDOW);
  const frames: Frame[] = [];
  let paren = 0, openedParen = false, closedOnce = false, sawArrow = false;
  let bodyOpen0 = -1, bodyDepth = 0;
  let chars = 0;
  // fn-mode header state (active only AFTER the parameter list closed)
  let headerAngle = 0, colonSeen = false, arrowAfterParen = false;
  // `col` lives ACROSS the outerLine label: the annotation-skip jump resumes
  // scanning at the balanced group's end position, so it must not be reset by
  // a per-iteration redeclaration.
  let col = 0;
  outerLine: for (let li = start0; li < hiLine; li++) {
    const line = lines[li] ?? "";
    while (col < line.length) {
      if (++chars > CHAR_BUDGET) {
        return bodyOpen0 === -1 ? null : { open0: bodyOpen0, close0: Math.min(lines.length - 1, bodyOpen0 + BODY_MAX) };
      }
      const c = line[col] as string;
      const nx = col + 1 < line.length ? (line[col + 1] as string) : "";
      const top = frames[frames.length - 1];
      if (top) {
        if (top.kind === "linec") break; // rest of the line is a comment
        if (top.kind === "blockc") {
          if (c === "*" && nx === "/") { frames.pop(); col += 2; } else col++;
          continue;
        }
        if (top.kind === "str") {
          if (c === "\\") { col += 2; }
          else if (c === top.quote) { frames.pop(); col++; }
          else col++;
          continue;
        }
        if (top.kind === "tpl") {
          if (c === "\\") { col += 2; }
          else if (c === "`") { frames.pop(); col++; }
          else if (c === "$" && nx === "{") { frames.push({ kind: "tplcode", depth: 1 }); col += 2; }
          else col++;
          continue;
        }
        // tplcode — inside `${ … }` of a template literal
        if (c === "{") { top.depth++; col++; continue; }
        if (c === "}") { top.depth--; col++; if (top.depth === 0) frames.pop(); continue; }
        if (c === "`") { frames.push({ kind: "tpl" }); col++; continue; }
        if (c === '"' || c === "'") { frames.push({ kind: "str", quote: c }); col++; continue; }
        col++;
        continue;
      }
      // ————— top is code —————
      if (c === "/" && nx === "/") { frames.push({ kind: "linec" }); col += 2; continue; }
      if (c === "/" && nx === "*") { frames.push({ kind: "blockc" }); col += 2; continue; }
      if (c === '"' || c === "'") { frames.push({ kind: "str", quote: c }); col++; continue; }
      if (c === "`") { frames.push({ kind: "tpl" }); col++; continue; }
      if (bodyOpen0 !== -1) {
        // body already located — count only braces to its close
        if (c === "{") { bodyDepth++; col++; continue; }
        if (c === "}") { bodyDepth--; col++; if (bodyDepth === 0) return { open0: bodyOpen0, close0: li }; continue; }
        col++;
        continue;
      }
      if (c === "(") { paren++; openedParen = true; sawArrow = false; col++; continue; }
      if (c === ")") { if (paren > 0) { paren--; if (paren === 0) closedOnce = true; } col++; continue; }
      if (c === "=" && nx === ">") {
        sawArrow = true;
        if (mode === "fn" && paren === 0 && closedOnce) arrowAfterParen = true; // `): Type => {`
        col += 2; continue;
      }
      if (mode === "fn" && paren === 0 && closedOnce && bodyOpen0 === -1) {
        // header material after the signature's parens: `: Type<…>`, generics
        if (c === ":") colonSeen = true;
        if (c === "<") headerAngle++;
        if (c === ">" && headerAngle > 0) headerAngle--;
      }
      if (c === "{") {
        let openBody = false;
        if (mode === "fn") {
          if (headerAngle > 0) { col++; continue; } // generic-argument brace — type material, not the body
          if (paren === 0) {
            if (!openedParen) openBody = sawArrow;      // parameterless arrow: `async x => {`
            else if (arrowAfterParen) openBody = true;  // body after `): Type => `
            else if (colonSeen) {
              // `:`-annotated return type: this `{` may be an ANNOTATION group.
              // Bounded lookahead: followed by another `{` (annotation → body)
              // or by `=>` (annotation → arrow → body) → skip the group;
              // anything else means this `{` IS the body.
              const g = balancedBraceGroup(lines, li, col, hiLine, CHAR_BUDGET - chars);
              if (g && (g.nextNonSpace === "{" || (g.nextNonSpace === "=" && g.next2 === ">"))) {
                if (g.nextNonSpace === "=") arrowAfterParen = true;
                li = g.endLine - 1; col = g.endCol; continue outerLine;
              }
              openBody = true;
            } else openBody = true; // plain `function METHOD() {`
          }
          // paren > 0 && fn mode: brace inside the parameter list (default value
          // / type) — never the body
        } else {
          openBody = paren > 0 && sawArrow && !closedOnce;
        }
        if (openBody) { bodyOpen0 = li; bodyDepth = 1; }
        col++;
        continue;
      }
      col++;
    }
    col = 0; // next line starts fresh (preserved across `continue outerLine` jumps)
  }
  if (bodyOpen0 === -1) return null;
  return { open0: bodyOpen0, close0: Math.min(lines.length - 1, bodyOpen0 + BODY_MAX) };
}

/**
 * Bounded handler extraction (body windows budgeted ≤ BODY_MAX lines):
 * Next.js App Router `export (async) function POST(req…)` AND — v1.5.2 —
 * arrow route handlers `export const POST = (async) (…) => { … }`,
 * Express-style `app.<method>("path", …)` callbacks, and NestJS decorated
 * methods (@Post/@Get …). Body identification is brace-position-exact via
 * handlerBodySpan (destructuring/type braces no longer truncate the block).
 */
export function handlerBlocks(f: ScannedFile): HandlerBlock[] {
  const out: HandlerBlock[] = [];
  const lines = f.lines;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    if (isComment(line)) continue;
    const exportHandler = /export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/.exec(line);
    const exportArrow = /export\s+const\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*(?::[^=\n]{0,80})?=\s*(?:async\s*)?/.exec(line);
    const expressHandler = /\b(?:app|router|server)\.(get|post|put|patch|delete|all)\s*\(\s*["'`][^"'`]+["'`]/.exec(line);
    const nestMethod = /@(Get|Post|Put|Patch|Delete|All)\s*\(/.exec(line);
    /**
     * v1.5.3 — Next.js App Router handlers can also be exported by alias:
     *   `const handler = async function (…) { … }; export { handler as DELETE };`
     *   `const DELETE = async (…) => { … };          export { DELETE };`
     * The LOCAL function/arrow declaration is the handler (its body is what the
     * rules need). An export whose name has NO locally declared function-shaped
     * declaration — typically an import re-exported under a method name —
     * proves nothing about any body in THIS file, so NO handler is fabricated
     * (an arbitrary export alias is not evidence a handler exists here).
     */
    const exportAlias = /export\s*\{\s*([A-Za-z_$][\w$]*)\s+as\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*\}/.exec(line);
    const exportSame = !exportAlias ? /export\s*\{\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*\}/.exec(line) : null;
    let mode: HMode = "fn";
    let method = "";
    let start0 = i;
    if (exportHandler) method = (exportHandler[1] as string).toUpperCase();
    else if (exportArrow) method = (exportArrow[1] as string).toUpperCase();
    else if (exportAlias || exportSame) {
      const local = exportAlias ? (exportAlias[1] as string) : (exportSame as RegExpExecArray)[1];
      const decl0 = localHandlerDecl(lines, local, i);
      if (decl0 === -1) continue; // re-exported import — no local body, no fabricated handler
      method = ((exportAlias ? exportAlias[2] : (exportSame as RegExpExecArray)[1]) as string).toUpperCase();
      start0 = decl0;
    }
    else if (expressHandler) { mode = "express"; method = (expressHandler[1] as string).toUpperCase(); }
    else if (nestMethod) method = (nestMethod[1] as string).toUpperCase();
    if (!method) continue;
    // bounded fallback (concise-bodies / signatureless): same 40-line window as v1.4
    let end = Math.min(lines.length - 1, start0 + BODY_MAX);
    const span = handlerBodySpan(lines, start0, mode);
    if (span) end = Math.min(span.close0, span.open0 + BODY_MAX);
    else if (start0 === i && exportArrow && !/\(|=>/.test(lines.slice(i, Math.min(lines.length, i + 4)).join(""))) {
      continue; // `export const METHOD = <not a function>` — not a route handler
    }
    out.push({ name: `${method}:${lines[start0]?.slice(0, 60).trim()}`, line0: start0, bodyEnd0: end, mutating: /^(POST|PUT|PATCH|DELETE)$/.test(method) });
    i = Math.max(end, i); // skip the body — nested handlers are not a thing per language
  }
  return out;
}

/**
 * v1.5.3 — locate a LOCAL handler-shaped declaration of `name` before line
 * `before0` (function declaration, or a const/let/var bound to `function`,
 * a parenthesized arrow, or a single-identifier arrow). Returns the 0-based
 * line of the declaration or -1. Comments are never declarations.
 */
function localHandlerDecl(lines: string[], name: string, before0: number): number {
  const decl = new RegExp(
    `(?:function\\s+${name}\\s*\\(|(?:const|let|var)\\s+${name}\\s*=\\s*(?:async\\s*)?(?:function\\b|[A-Za-z_$][\\w$]*\\s*=>|\\())`
  );
  for (let i = 0; i < before0; i++) {
    const l = lines[i] ?? "";
    if (isComment(l)) continue;
    if (decl.test(l)) return i;
  }
  return -1;
}

export function scanAuthz(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];

  for (const f of ctx.files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.rel)) continue;
    if (/(?:^|\/)(?:tests?|__tests__|specs?|fixtures?|mocks?)\/|\.test\.|\.spec\./i.test(f.rel)) continue;
    const fileClass = classifyFile(f);
    if (fileClass === "client") continue; // server-side authorization only
    const blocks = handlerBlocks(f);
    if (!blocks.length) continue;

    for (const block of blocks) {
      const body = f.lines.slice(block.line0, block.bodyEnd0 + 1);
      // AUTHZ-002 first (evidence-backed anti-pattern) — the authorization
      // DECISION is taken from client-controlled input. Two bounded
      // recognitions, one finding per block (the first decision line wins):
      //  a) legacy direct form: `req.body.isAdmin`, `req.query.role`, …
      //  b) v1.5.2 parsed-body form: locals bound via `await request.json()`
      //     (direct / destructured / one-hop alias) deciding on authz fields.
      const locals = requestBodyLocals(body);
      let decisionLine = -1;
      let decisionText = "";
      for (let bi = 0; bi < body.length; bi++) {
        const bl = body[bi] as string;
        if (isComment(bl)) continue;
        const legacy = CLIENT_AUTHZ_DECISION.test(bl);
        let parsed = false;
        if (!legacy && (DECISION_OP.test(bl))) {
          for (const v of locals.bodyVars) { if (bodyVarDecision(bl, v)) { parsed = true; break; } }
          if (!parsed) {
            for (const a of locals.authzIdents) { if (bareIdentDecision(bl, a)) { parsed = true; break; } }
          }
        }
        if (legacy || parsed) {
          decisionLine = block.line0 + bi + 1; // absolute 1-based line (v1.5.2: exact index, was dup-prone indexOf)
          decisionText = bl;
          break;
        }
      }
      if (decisionLine !== -1) {
        findings.push({
          id: "AUTHZ-002", severity: "high", confidence: "medium",
          title: "Authorization decision is taken from client-controlled input (mass-role / is-admin anti-pattern)",
          file: f.rel, line: decisionLine,
          evidence: { type: "authz_client_decision", masked: decisionText.trim().slice(0, 120) },
          owasp: "A01",
          fix: FIX_CLIENT_AUTHZ,
          fix_mode: "suggested-diff",
          root: `${f.rel}:${decisionLine}`,
          root_cause: rootCause("AUTHZ-002", `${f.rel}:${decisionLine}`),
          needs_confirmation: true, // evidence-backed anti-pattern; still reviewed before enforcement
          verified: true,
        });
      }
      // AUTHZ-001 (missing evidence) — mutating handler with a privileged op, no authz shape
      if (!block.mutating) continue;
      const privileged = body.find((l) => !isComment(l) && PRIVILEGED_OP.test(l));
      if (!privileged) continue;
      const hasCheck = body.some((l) => !isComment(l) && AUTHZ_CALL.test(l));
      if (hasCheck) continue; // guard call in body — AUTHZ-001 not applicable
      findings.push({
        id: "AUTHZ-001", severity: "medium", confidence: "medium",
        title: "Mutating request handler has no recognizable authorization check (missing-evidence review note)",
        file: f.rel, line: block.line0 + 1,
        evidence: {
          type: "authz_missing_evidence",
          masked: `${block.name} · ${privileged.trim().slice(0, 80)}`,
          note: "no authz/guard/session call found IN-BODY; middleware, APP_GUARD-style global guards and DB-level RLS are legitimate enforcement layers this static check cannot see — confirm before treating as a gap",
        },
        owasp: "A01",
        fix: FIX_AUTHZ,
        fix_mode: "suggested-diff",
        root: `${f.rel}:${block.line0 + 1}`,
        root_cause: rootCause("AUTHZ-001", `${f.rel}:${block.line0 + 1}`),
        needs_confirmation: true,
        verified: true,
      });
    }
  }
  return { findings };
}

/**
 * Capability §B — SaaS multi-tenant isolation (v1.4).
 *
 * Honest contract: tenant isolation CANNOT be confirmed from static analysis —
 * enforcement often lives in RLS/DB policies or ORM global scopes invisible
 * here. So the pack works ONLY where the repo itself declares tenant entities
 * (schema/migrations with org_id/tenant_id/…), and every finding is a
 * MEDIUM needs_confirmation review prompt naming the enforcement layers it
 * cannot see. No repository applying tenant scoping at the query layer
 * (where clauses, RLS-shape keywords) is flagged.
 */

const TENANT_COL =
  /\b(?:org(?:anization)?[_-]?id|tenant[_-]?id|workspace[_-]?id|company[_-]?id|account[_-]?id)\b/i;

/** declare-and-establish tenant entities per table (bounded rebuild per file set) */
export interface TenantEntity { table: string; declFile: string; }

export function tenantEntities(ctx: ScanContext): Map<string, TenantEntity> {
  const out = new Map<string, TenantEntity>();
  for (const f of ctx.files) {
    // prisma schema models — v1.5.1: the model regex is only meaningful for
    // schema.prisma files, so it is gated behind the rel check first. Running
    // it on every scanned file made the pack quadratic on windowed large
    // files: `^\s*model` backtracked across the window's (start-1)-row empty
    // pad run at EVERY row start — O(pad rows²) ≈ minutes on a 4MB file with
    // many short lines (profiled: 111.7s of a 116s full scan; U26.4).
    // `^[\t ]*model` instead of `^\s*model` removes the cross-empty-run
    // backtracking entirely; the match SET is provably identical (any
    // newline-crossing \s* match reaching "model" lands model at a row start
    // that carries its own `^` anchor), so detection is unchanged.
    if (/schema\.prisma$/.test(f.rel)) {
      const model = /^[\t ]*model\s+([A-Za-z_][\w]*)\s*\{([\s\S]*?)^\}/m.exec(f.content);
      if (model && TENANT_COL.test(model[2])) {
        out.set(model[1].toLowerCase(), { table: model[1], declFile: f.rel });
        continue;
      }
    }
    // SQL migrations: CREATE TABLE / ALTER TABLE … ADD COLUMN with a tenant column in the SAME statement
    if (/\.sql$/.test(f.rel)) {
      const stmts = f.content.split(/;\s*(?:\n|$)/);
      for (const stmt of stmts) {
        // v1.4 review fix: the optional schema prefix requires its OWN literal `.` —
        // an optional prefix without the `.` backtracks into the table name and
        // captures a suffix ("workspace_docs" once yielded entity "s").
        const create = /create\s+table\s+(?:if\s+not\s+exists\s+)?["'`]*(?:[a-zA-Z_][\w]*\.)?["'`]*([a-zA-Z_][\w]*)["'`]*\s*\(/i.exec(stmt);
        if (create && TENANT_COL.test(stmt)) {
          out.set(create[1].toLowerCase(), { table: create[1], declFile: f.rel });
          continue;
        }
        const alter = /alter\s+table\s+(?:if\s+exists\s+)?["'`]*(?:[a-zA-Z_][\w]*\.)?["'`]*([a-zA-Z_][\w]*)["'`]*/i.exec(stmt);
        if (alter && TENANT_COL.test(stmt)) {
          out.set(alter[1].toLowerCase(), { table: alter[1], declFile: f.rel });
        }
      }
    }
  }
  return out;
}

export function scanTenant(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];
  const entities = tenantEntities(ctx);
  if (!entities.size) return { findings }; // no tenant model declared → pack stays silent (not applicable)

  // v1.5.1: the two per-entity access regexes are compiled ONCE per entity
  // (previously once per line × per entity — for a windowed many-row file
  // that was up to rows × entities × 2 RegExp compilations in the hot loop).
  // Pattern strings are byte-identical, so detection is unchanged.
  const perEntity = Array.from(entities, ([table, ent]) => ({
    table,
    model: ent.table,
    declFile: ent.declFile,
    prismaByIdRe: new RegExp(`\\b\\w+\\.${ent.table}\\.(?:update|delete|findUnique|findFirst|upsert)\\s*\\(`, "i"),
    stmtSqlRe: new RegExp(`\\b(?:UPDATE|DELETE\\s+FROM)\\s+["'\`]*(?:[a-zA-Z_][\\w]*\\.)?["'\`]*${table}["'\`]*\\b`, "i"),
  }));

  for (const f of ctx.files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.rel)) continue;
    if (/(?:^|\/)(?:tests?|__tests__|specs?|fixtures?|mocks?)\/|\.test\.|\.spec\./i.test(f.rel)) continue;
    if (classifyFile(f) === "client") continue;
    const lines = f.lines;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\s*(?:\/\/|\*|\/\*)/.test(line)) continue;

      // TEN-002 — by-ID access (mutation OR read) of a tenant entity with a
      // request-sourced id and no tenant/ownership condition anywhere in the
      // statement window. v1.5: by-ID READS (findUnique already covered,
      // findFirst added) are the classic tenant-IDOR read — same review
      // prompt, title distinguishes read vs mutation.
      for (const ent of perEntity) {
        const table = ent.table;
        const model = ent.model;
        const prismaById = ent.prismaByIdRe.test(line);
        const stmtSql = ent.stmtSqlRe.test(line);
        if (!prismaById && !stmtSql) continue;
        const stmt = lines.slice(Math.max(0, i - 1), Math.min(lines.length, i + 6)).join("\n");
        const hasOwnership = /(?:where\s*:\s*\{[^}]{0,240}(?:AND|\.\.\.|tenant|org|workspace|company|userId)|\btenant\b|\borg[_-]?id\b|\bworkspace[_-]?id\b|\buser[_-]?id\b\s*=|\bAND\s+(?:user|org|tenant|workspace|company)[_-]?id\b)/i.test(stmt);
        const reqSourced = /(?:req(?:uest)?|params|query|body)/i.test(stmt);
        if (!hasOwnership && prismaById && reqSourced && /where\s*:\s*\{\s*\{?\s*(?:id|_\w+)\s*:/.test(stmt)) {
          const opKind = /findFirst/i.test(line) ? "read" : "mutation";
          findings.push({
            id: "TEN-002", severity: "medium", confidence: "medium",
            title: `By-ID ${opKind} of tenant entity "${model}" keyed only on request input — cross-tenant IDOR risk (review)`,
            file: f.rel, line: i + 1,
            evidence: {
              type: "tenant_byid_mutation",
              masked: `${line.trim().slice(0, 90)} (declared in ${ent.declFile})`,
              note: 'the repo declares tenant columns for this entity but this statement shows no tenant/workspace scoping around the where:id — RLS policies, ORM global scopes and service-layer checks are legitimate invisible layers: confirm before treating as a gap',
            },
            owasp: "A01",
            fix: "Scope every tenant-entity operation by the authenticated principal's workspace/org (e.g. add tenantId/orgId to the where clause from the session, ideally also enforced by DB RLS); never accept the tenant discriminator from request input.",
            fix_mode: "suggested-diff",
            root: `${f.rel}:${i + 1}`,
            root_cause: rootCause("TEN-002", `${f.rel}:${i + 1}`),
            needs_confirmation: true,
            verified: true,
          });
        }
        if (!hasOwnership && stmtSql && reqSourced && !/\bLIMIT\b/i.test(line)) {
          findings.push({
            id: "TEN-001", severity: "medium", confidence: "medium",
            title: `Tenant-scoped table "${table}" mutated/read without a visible tenant filter (review)`,
            file: f.rel, line: i + 1,
            evidence: {
              type: "tenant_statement_unscoped",
              masked: `${line.trim().slice(0, 90)} (declared in ${ent.declFile})`,
              note: "the statement carries no tenant/org predicate in this window; DB RLS or a repository-level global scope may provide it invisibly — confirm",
            },
            owasp: "A01",
            fix: "Add an explicit tenant predicate to the statement (or prove the DB RLS policy covers it); default-deny cross-tenant reads/writes.",
            fix_mode: "suggested-diff",
            root: `${f.rel}:${i + 1}`,
            root_cause: rootCause("TEN-001", `${f.rel}:${i + 1}`),
            needs_confirmation: true,
            verified: true,
          });
        }
      }
    }
  }
  return { findings };
}
