import type { ScannedFile } from "../types.js";

/**
 * Bounded value-flow analysis (v1.4, §2 of the capability plan).
 *
 * The engine's rules are line-regex based by design (determinism, masking,
 * no-exec, zero runtime deps). This module gives every rule a SHARED,
 * bounded, single-function value-flow helper so rules stop treating each
 * pattern as an island:
 *
 *   const a = req.body.sql;          // hop 1 original
 *   const b = a.trim();              // hop 2 intermediate variable
 *   pool.query("…" + b);             // sink sees only `b` before this module
 *
 * Scope contract (documented in METHODOLOGY §8.1):
 *  - assignment chains only — NO call-graph, NO cross-function/cross-file
 *    transfer (SAST-001 cross-file import resolution is a separate helper —
 *    see `importedCallFlow` — because it needs the file list),
 *  - maxHops bound (default 4) with a cycle guard — pathological chains
 *    (`q = q`) cannot blow up,
 *  - every hop must sit in the same function scope (column-0 `}` and
 *    scope-opening lines break the bound, same rule as v1.3 SAST-001),
 *  - last assignment before the use wins (plain reassignments counted).
 *
 *不发 new runtime dependencies — pure string/regex work.
 */

/** lines that OPEN a new scope (same-function bound) */
const SCOPE_OPEN_LINE = /(?:^|\W)(?:function\s*\(|function\s+[A-Za-z_$]|class\s+[A-Za-z_$]|=>\s*\{)/;

export interface Assignment {
  name: string;
  line0: number;      // 0-based
  rhs: string;        // RHS text (template literals joined forward ≤8 lines)
  isDecl: boolean;    // const/let/var vs plain reassignment
}

/** true when lines strictly between the two 0-based indices stay in one function body */
export function sameFunctionBound(lines: string[], from0: number, to0: number): boolean {
  for (let i = from0 + 1; i < to0; i++) {
    const line = lines[i] ?? "";
    if (line.startsWith("}")) return false;
    if (SCOPE_OPEN_LINE.test(line)) return false;
  }
  return true;
}

/**
 * All assignments per variable (last-before-use wins, reassignments counted —
 * a var demoted to a constant stops being tainted, one promoted to
 * request-built becomes tainted). A single unterminated template literal is
 * joined forward (bounded ≤8 lines) so multi-line SQL templates resolve.
 */
export function collectAssignments(lines: string[]): Map<string, Assignment[]> {
  const out = new Map<string, Assignment[]>();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*(?:\/\/|\*|\/\*)/.test(line)) continue; // comments never assign
    const m = /^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?!=)(.+?)\s*;?\s*$/.exec(line);
    if (!m) continue;
    let rhs = m[2].replace(/;\s*$/, "").trim();
    if ((rhs.match(/`/g) ?? []).length % 2 === 1) {
      let joined = rhs;
      for (let j = i + 1; j < lines.length && j - i < 8 && (joined.match(/`/g) ?? []).length % 2 === 1; j++) {
        joined += "\n" + lines[j];
      }
      if ((joined.match(/`/g) ?? []).length % 2 === 0) rhs = joined;
    }
    rhs = rhs.replace(/;\s*$/, "").trim();
    if (!rhs) continue;
    const arr = out.get(m[1]) ?? [];
    arr.push({ name: m[1], line0: i, rhs, isDecl: /^(?:const|let|var)\s+/.test(line.trim()) });
    out.set(m[1], arr);
  }
  return out;
}

/** nearest assignment to `name` strictly before line `to0` in the same function body */
export function lastAssignmentBefore(
  assigns: Map<string, Assignment[]>,
  lines: string[],
  name: string,
  to0: number
): Assignment | undefined {
  const cands = assigns.get(name);
  return cands
    ? [...cands].reverse().find((a) => a.line0 < to0 && sameFunctionBound(lines, a.line0, to0))
    : undefined;
}

export interface FlowTrace {
  /** identifiers chased, in chase order (first = the sink argument) */
  via: string[];
  /** effective RHS text after the chase (the value that reaches the sink) */
  value: string;
  /** 0 = sink argument is not an identifier (direct expression), else hop count */
  hops: number;
  /** RHS text at each chase level (chain[0] = the first assignment found) */
  chain: string[];
}

/**
 * Backward chase from an identifier to its effective value (v1.4 runtime):
 *  - bare identifier RHS (`const q = r`) keeps chasing within maxHops,
 *  - string-method–wrapped RHS (`const b = a.trim()`, `.slice(1)`, `.replace(…)`)
 *    continues the chase through the leading identifier — the underlying value
 *    still reaches the sink shape-wise (verdicts stay bounded + reviewable),
 *  - cycle-guarded (a var reached twice stops the chase with NO verdict),
 *  - chase cap: when maxHops intermediate hops are exhausted and the value is
 *    still a bare identifier (multi-hop cap exceeded), returns null — never a
 *    half-resolved verdict. Consumers re-run shape predicates on `value`.
 */
export function resolveVarFlow(
  lines: string[],
  assigns: Map<string, Assignment[]>,
  name: string,
  atLine0: number,
  maxHops = 4
): FlowTrace | null {
  const via: string[] = [name];
  const seen = new Set<string>([name]);
  const cur = lastAssignmentBefore(assigns, lines, name, atLine0);
  if (!cur) return null;
  let hops = 0;
  const chainRhs: string[] = [cur.rhs];
  let at = cur;
  while (true) {
    const bare = /^([A-Za-z_$][\w$]*)$/.exec(at.rhs.trim());
    // continue the chase when the RHS IS another identifier …
    let nextIdent: string | null = bare ? bare[1] : null;
    // … or when it is a string-method wrapper around one (`a.trim()`, `a.slice(1)` —
    // the wrapper cannot change the SQL-shape/secret-identity of the underlying value)
    if (!nextIdent) {
      const wrapped = /^([A-Za-z_$][\w$]*)\s*(?:\.[A-Za-z_$][\w$]*\s*\(\s*[^()]{0,80}\?*\s*\))+\s*;?$/.exec(at.rhs.trim());
      if (wrapped) nextIdent = wrapped[1];
    }
    if (!nextIdent) break; // shaped value reached
    if (seen.has(nextIdent)) return null; // cycle — no verdict, never a false fire
    seen.add(nextIdent);
    via.push(nextIdent);
    hops++;
    if (hops > maxHops) return null; // chase cap exceeded — no verdict
    const nxt = lastAssignmentBefore(assigns, lines, nextIdent, at.line0);
    if (!nxt) return null; // aliased-but-unassigned (param/loop var) — no evidence
    at = nxt;
    chainRhs.push(at.rhs);
  }
  return { via, value: at.rhs, hops, chain: chainRhs };
}

/**
 * Transitive taint propagation (TAINT rules, capability modules): seed vars
 * assigned directly from request-derived sources, then fixpoint-extend to any
 * var whose RHS mentions a tainted identifier (bounded iterations). This is
 * what makes `const a = req.x; const b = a.trim(); fetch(b)` visible.
 */
export function propagateTaint(
  lines: string[],
  assigns: Map<string, Assignment[]>,
  isSourceRhs: (rhs: string) => boolean
): Set<string> {
  const tainted = new Set<string>();
  for (const [name, arr] of assigns) {
    for (const a of arr) {
      if (isSourceRhs(a.rhs)) { tainted.add(name); break; }
    }
  }
  // fixpoint extension — intermediate variables inherit the taint of the
  // identifiers they are built from (e.g. `const b = a.trim()` from tainted a).
  // Bounded passes; string/template mentions count (FP direction is review-
  // note, never silent — the taint verdict stays MEDIUM + needs_confirmation).
  for (let pass = 0; pass < 4; pass++) {
    let grew = false;
    for (const [name, arr] of assigns) {
      if (tainted.has(name)) continue;
      for (const a of arr) {
        const plain = a.rhs.match(/[A-Za-z_$][\w$]*/g) ?? [];
        if (plain.some((id) => tainted.has(id))) { tainted.add(name); grew = true; break; }
      }
    }
    if (!grew) break;
  }
  return tainted;
}

/**
 * Cross-file import flow (single-hop, bounded): `.query(<local helper>(<tainted arg>))`
 * — locate the helper's declaration in the scanned file set, then run the same
 * dynamic-SQL shape analysis on the helper's built value. Never follows npm
 * packages; never deeper than the helper's own first function body.
 */
export function findLocalHelperBody(
  helperName: string,
  spec: string,
  fromFile: ScannedFile,
  files: ScannedFile[]
): ScannedFile | null {
  if (!spec || !spec.startsWith(".")) return null; // relative local modules only
  const norm = (p: string): string => p.replace(/\\/g, "/");
  // resolve target path from the importing file's directory (".." pops the DIR stack)
  const stack = norm(fromFile.rel).split("/").slice(0, -1);
  for (const part of norm(spec).split("/")) {
    if (part === "..") stack.pop();
    else if (part !== "." && part !== "") stack.push(part);
  }
  const base = stack.filter((s) => s !== "").join("/");
  const cands = new Set([
    `${base}.ts`, `${base}.tsx`, `${base}.js`, `${base}.jsx`, `${base}.mjs`, `${base}.cjs`,
    `${base}/index.ts`, `${base}/index.js`,
  ]);
  const helperRe = new RegExp(
    `(?:\\bfunction\\s+${helperName}\\b|\\b(?:const|let|var)\\s+${helperName}\\s*=)`
  );
  for (const f of files) {
    if (!cands.has(norm(f.rel))) continue;
    if (helperRe.test(f.content)) return f;
  }
  return null;
}

/**
 * Does a local helper build a string (or run code/exec) from a given
 * parameter? Bounded: only the helper's first ~80 lines from the match.
 * Returns the parameter name when the body references param N in a
 * string-building (interp/concat) shape, else null.
 */
export function helperParamFlow(
  helperFile: ScannedFile,
  helperName: string,
  paramIdx: number
): string | null {
  const content = helperFile.content;
  // function declaration or arrow/exported const
  const re = new RegExp(
    `(?:function\\s+${helperName}\\s*\\(|const\\s+${helperName}\\s*=\\s*(?:async\\s*)?\\()`
  );
  const m = re.exec(content);
  if (!m) return null;
  const openParen = content.indexOf("(", m.index);
  // collect parameter list
  let depth = 0, end = openParen;
  for (let i = openParen; i < content.length && i - openParen < 400; i++) {
    if (content[i] === "(") depth++;
    else if (content[i] === ")") { depth--; if (depth === 0) { end = i; break; } }
  }
  const params = content.slice(openParen + 1, end)
    .split(",")
    .map((p) => (p.match(/([A-Za-z_$][\w$]*)/) ?? [])[1])
    .filter(Boolean) as string[];
  const param = params[paramIdx];
  if (!param) return null;
  const body = content.slice(end, end + 6000);
  // dynamic-SQL build shape mentioning the parameter
  if (new RegExp(`\\$\\{[^}]*\\b${param}\\b|["'\`][^"'\\n]*["'\`]\\s*\\+\\s*${param}\\b|\\b${param}\\b\\s*\\+\\s*["'\`]`).test(body)) {
    return param;
  }
  return null;
}
