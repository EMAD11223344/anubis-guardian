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
  /(?:getSession|getServerSession|getAuth|auth\s*\(\)|requireUser|requireAuth|requireAdmin|requireLogin|requireSignIn|assertAuth|checkAuth|isAuthenticated|isLoggedIn|verifyToken|jwt\.verify|verifyJWT|UseGuards|getCurrentUser|currentUser\s*\(|getUser\s*\(|cookies\s*\(\s*\)\s*\.get|\.cookies\.get|authorization["'`]?\s*[,\]:]|headers\(\)\.get\(\s*["'`]authorization|authori[sz]ation\s*[:=]|can\s*\(|canAbili|ability\.|authorize\s*\(|hasPermission|hasRole|checkPermission|accessCheck|policy\.(?:allow|check))/i;
/** comments never count as a check */
const isComment = (line: string): boolean => /^\s*(?:\/\/|\*|\/\*)/.test(line.trim());

/** privileged operations: writes/destructive calls on data layers */
const PRIVILEGED_OP =
  /(?:\.\s*(?:create|createMany|update|updateMany|delete|deleteMany|upsert|destroy|remove|insert|replaceOne|deleteOne|deleteMany)\s*\(|\bINSERT\s+INTO\b|\bUPDATE\s+[A-Za-z_"'\[\]]+\s+SET\b|\bDELETE\s+FROM\b|\bDROP\s+(?:TABLE|USER|ROLE)\b|\bGRANT\b)/i;

/** client-controlled authorization decision: the decision value itself is request data */
const CLIENT_AUTHZ_DECISION =
  /(?:if\s*\(|(?:===|!==|==|!=)\s*["'`]?(?:true|false|admin|1)|=\s*(?:true|"admin"|"1"))?\s*(?:req(?:uest)?|session|auth)\s*\.\s*(?:body|query|headers|nextUrl\.searchParams|cookies)\b[^\n]{0,60}\b(?:is[_-]?admin|admin|role|permission|privilege|is[_-]?super(?:user)?)/i;

interface HandlerBlock { name: string; line0: number; bodyEnd0: number; mutating: boolean; }

/**
 * Bounded handler-body extraction (never deeper than ~40 lines/block, brace-depth
 * counted): Next.js App Router `export async function POST(req)`, Express-style
 * `(req, res) => {`-handlers via app.<method>(“/path”, …), and NestJS decorated
 * methods (@Post/@Get … when NestJS is in the stack).
 */
export function handlerBlocks(f: ScannedFile): HandlerBlock[] {
  const out: HandlerBlock[] = [];
  const lines = f.lines;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isComment(line)) continue;
    const exportHandler = /export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/.exec(line);
    const expressHandler = /\b(?:app|router|server)\.(get|post|put|patch|delete|all)\s*\(\s*["'`][^"'`]+["'`]/.exec(line);
    const nestMethod = /@(Get|Post|Put|Patch|Delete|All)\s*\(/.exec(line);
    const method = (exportHandler?.[1] ?? expressHandler?.[1]?.toUpperCase() ?? nestMethod?.[1]?.toUpperCase() ?? "").toUpperCase();
    if (!method) continue;
    const braceStart = lines.slice(i, i + 4).join("\n").indexOf("{");
    let depth = 0;
    let end = i + 40; // hard bound: handlers larger than 40 lines are scanned as-is (bounded budget)
    if (braceStart !== -1) {
      depth = 0;
      let started = false;
      outer: for (let j = i; j < Math.min(lines.length, i + 60); j++) {
        for (const ch of lines[j]) {
          if (ch === "{") { depth++; started = true; }
          else if (ch === "}") { depth--; if (started && depth === 0) { end = j; break outer; } }
        }
      }
    }
    out.push({ name: `${method}:${line.slice(0, 60).trim()}`, line0: i, bodyEnd0: end, mutating: /^(POST|PUT|PATCH|DELETE)$/.test(method) });
    i = end; // skip the body — nested handlers are not a thing per language
  }
  return out;
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
      // AUTHZ-002 first (evidence-backed anti-pattern) — client-sourced decision
      const clientDecision = body.find((l) => !isComment(l) && CLIENT_AUTHZ_DECISION.test(l));
      if (clientDecision) {
        findings.push({
          id: "AUTHZ-002", severity: "high", confidence: "medium",
          title: "Authorization decision is taken from client-controlled input (mass-role / is-admin anti-pattern)",
          file: f.rel, line: f.lines.indexOf(clientDecision) + 1,
          evidence: { type: "authz_client_decision", masked: clientDecision.trim().slice(0, 120) },
          owasp: "A01",
          fix: FIX_CLIENT_AUTHZ,
          fix_mode: "suggested-diff",
          root: `${f.rel}:${f.lines.indexOf(clientDecision) + 1}`,
          root_cause: rootCause("AUTHZ-002", `${f.rel}:${f.lines.indexOf(clientDecision) + 1}`),
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
    // prisma schema models
    const model = /^\s*model\s+([A-Za-z_][\w]*)\s*\{([\s\S]*?)^\}/m.exec(f.content);
    if (model && /schema\.prisma$/.test(f.rel) && TENANT_COL.test(model[2])) {
      out.set(model[1].toLowerCase(), { table: model[1], declFile: f.rel });
      continue;
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

  for (const f of ctx.files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.rel)) continue;
    if (/(?:^|\/)(?:tests?|__tests__|specs?|fixtures?|mocks?)\/|\.test\.|\.spec\./i.test(f.rel)) continue;
    if (classifyFile(f) === "client") continue;
    const lines = f.lines;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\s*(?:\/\/|\*|\/\*)/.test(line)) continue;

      // TEN-002 — by-ID mutation of a tenant entity with a request-sourced id
      // and no tenant/ownership condition anywhere in the statement window
      for (const [table, ent] of entities) {
        const model = ent.table;
        const prismaById = new RegExp(`\\b\\w+\\.${model}\\.(?:update|delete|findUnique|upsert)\\s*\\(`, "i").test(line);
        const stmtSql = new RegExp(`\\b(?:UPDATE|DELETE\\s+FROM)\\s+["'\`]*(?:[a-zA-Z_][\\w]*\\.)?["'\`]*${table}["'\`]*\\b`, "i").test(line);
        if (!prismaById && !stmtSql) continue;
        const stmt = lines.slice(Math.max(0, i - 1), Math.min(lines.length, i + 6)).join("\n");
        const hasOwnership = /(?:where\s*:\s*\{[^}]{0,240}(?:AND|\.\.\.|tenant|org|workspace|company|userId)|\btenant\b|\borg[_-]?id\b|\bworkspace[_-]?id\b|\buser[_-]?id\b\s*=|\bAND\s+(?:user|org|tenant|workspace|company)[_-]?id\b)/i.test(stmt);
        const reqSourced = /(?:req(?:uest)?|params|query|body)/i.test(stmt);
        if (!hasOwnership && prismaById && reqSourced && /where\s*:\s*\{\s*\{?\s*(?:id|_\w+)\s*:/.test(stmt)) {
          findings.push({
            id: "TEN-002", severity: "medium", confidence: "medium",
            title: `By-ID mutation of tenant entity "${model}" keyed only on request input — cross-tenant IDOR risk (review)`,
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
