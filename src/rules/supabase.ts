import type { ScanContext, RuleResult } from "../types.js";
import { rootCause } from "../util.js";

/**
 * Layer 5 — Supabase playbook (v1.1 depth, Plan Section 6).
 * Severity honesty (v1.3): missing RLS from migrations alone = HIGH + needs_confirmation;
 * CRITICAL only with independent confirmation (schema export / live probe — v0.4).
 */

const CREATE_TABLE = /\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:"?(\w+)"?\.)?"?(?!IF\b|NOT\b|EXISTS\b|ONLY\b)([a-zA-Z_][\w]*)"?/gi;
const ENABLE_RLS = /\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?(?:"?(\w+)"?\.)?"?(?!IF\b|NOT\b|EXISTS\b|ONLY\b)([a-zA-Z_][\w]*)"?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;


const POLICY_TRUE = /\bCREATE\s+(?:OR\s+REPLACE\s+)?POLICY\s+"?([\w-]+)"?\s+ON\s+(?:(\w+)\.)?([\w]+)([\s\S]*?)(?:USING|WITH\s+CHECK)\s*\(\s*(true)\s*\)/gi;
const CREATE_VIEW = /\bCREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+([\w.]+)([\s\S]*?);/gi;
const SECURITY_DEFINER = /\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w.]+)\s*\(([^)]*)\)\s*([\s\S]*?);\s*$/gi;

const SENSITIVE_TABLE = /(user|profile|account|admin|payment|order|invoice|billing|token|session|credential|secret|customer|employee|member)/i;

export function scanSupabase(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];
  const migrationFiles = ctx.files.filter((f) => /\.sql$/i.test(f.rel) && /(^|\/)(supabase\/migrations|migrations|db\/migrations)\//.test(f.rel));

  if (migrationFiles.length === 0) return { findings };

  const tables = new Map<string, { file: string; line: number; sensitive: boolean; rls: boolean }>();

  for (const f of migrationFiles) {
    // --- CREATE TABLE + RLS enablement across all migration files ---
    for (const f2 of migrationFiles) {
      let m: RegExpExecArray | null;
      CREATE_TABLE.lastIndex = 0;
      while ((m = CREATE_TABLE.exec(f2.content)) !== null) {
        const schema = (m[1] || "public").toLowerCase();
        const name = m[2];
        const key = `${schema}.${name}`;
        if (!tables.has(key)) {
          const lineNo = f2.content.slice(0, m.index).split("\n").length;
          tables.set(key, { file: f2.rel, line: lineNo, sensitive: SENSITIVE_TABLE.test(name), rls: false });
        }
      }
      ENABLE_RLS.lastIndex = 0;
      while ((m = ENABLE_RLS.exec(f2.content)) !== null) {
        const schema = (m[1] || "public").toLowerCase();
        const key = `${schema}.${m[2]}`;
        const t = tables.get(key);
        if (t) t.rls = true;
        else tables.set(key, { file: f2.rel, line: f2.content.slice(0, m.index).split("\n").length, sensitive: SENSITIVE_TABLE.test(m[2]), rls: true });
      }
    }

    // --- policies USING(true)/WITH CHECK(true) ---
    let m: RegExpExecArray | null;
    POLICY_TRUE.lastIndex = 0;
    while ((m = POLICY_TRUE.exec(f.content)) !== null) {
      const [, policyName, schema, table] = m;
      const lineNo = f.content.slice(0, m.index).split("\n").length;
      const fullTable = `${schema || "public"}.${table}`;
      const sensitive = SENSITIVE_TABLE.test(table);
      findings.push({
        id: "SUPA-R02",
        severity: sensitive ? "high" : "medium",
        confidence: "high",
        title: `RLS policy "${policyName}" opens ${fullTable} to everyone — USING (true)`,
        file: f.rel, line: lineNo,
        evidence: { type: "rls_permissive_policy", masked: `POLICY ${policyName} ON ${fullTable} USING (true)`, note: sensitive ? "sensitive table — exploit-ready if exposed via API" : "sometimes intentional for public data — verify" },
        owasp: "A01",
        fix: `Scope the policy to the owner/tenant, e.g. USING (auth.uid() = user_id)${sensitive ? " — this table looks sensitive" : ""}. If the table is intentionally public, document it and narrow the columns exposed.`,
        fix_mode: "suggested-diff",
        root: `${fullTable}:${policyName}`,
        root_cause: rootCause("SUPA-R02", `${fullTable}:${policyName}`),
        verified: true,
      });
    }

    // --- views bypassing RLS (security_invoker) ---
    CREATE_VIEW.lastIndex = 0;
    while ((m = CREATE_VIEW.exec(f.content)) !== null) {
      const viewName = m[1];
      const body = m[2];
      if (/security_invoker\s*=\s*true/i.test(body)) continue;
      const lineNo = f.content.slice(0, m.index).split("\n").length;
      const referencesKnownTable = [...tables.keys()].some((t) => body.toLowerCase().includes(t.split(".")[1].toLowerCase()));
      const sensitive = SENSITIVE_TABLE.test(body);
      if (!referencesKnownTable && !sensitive) continue;
      findings.push({
        id: "SUPA-R03",
        severity: sensitive || referencesKnownTable ? "high" : "medium",
        confidence: "medium",
        title: `View ${viewName} bypasses RLS — created without WITH (security_invoker = true)`,
        file: f.rel, line: lineNo,
        evidence: { type: "view_bypasses_rls", masked: `CREATE VIEW ${viewName}`, note: "views run with the owner's rights by default in Postgres < 15 — they expose RLS-protected rows to API clients" },
        owasp: "A01",
        fix: `Recreate with: CREATE VIEW ${viewName} WITH (security_invoker = true) AS ... — or restrict the view from the exposed schema.`,
        fix_mode: "suggested-diff",
        root: viewName,
        root_cause: rootCause("SUPA-R03", viewName),
        verified: true,
      });
    }

    // --- SECURITY DEFINER functions without search_path pinning ---
    const funcRe = /\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w.]+)\s*\([^)]*\)\s*(?:RETURNS\s+[\w.\[\]]+\s*)?/gi;
    while ((m = funcRe.exec(f.content)) !== null) {
      const fnName = m[1];
      const tailStart = m.index + m[0].length;
      const tail = f.content.slice(tailStart, tailStart + 400);
      if (!/SECURITY\s+DEFINER/i.test(tail)) continue;
      if (/SET\s+search_path/i.test(tail)) continue;
      const lineNo = f.content.slice(0, m.index).split("\n").length;
      findings.push({
        id: "SUPA-R04",
        severity: "high",
        confidence: "high",
        title: `SECURITY DEFINER function ${fnName} without SET search_path`,
        file: f.rel, line: lineNo,
        evidence: { type: "security_definer_unpinned", masked: `FUNCTION ${fnName} SECURITY DEFINER`, note: "search_path hijacking can redirect table/function resolution inside a definer (privilege escalation)" },
        owasp: "A01",
        fix: `Add SET search_path = public, pg_temp to the function definition, and re-check that its body respects RLS.`,
        fix_mode: "suggested-diff",
        root: fnName,
        root_cause: rootCause("SUPA-R04", fnName),
        verified: true,
      });
    }
  }

  // --- missing RLS on public tables (HIGH + needs_confirmation — v1.3 ladder) ---
  for (const [key, t] of tables) {
    if (!key.startsWith("public.")) continue;
    if (t.rls) continue;
    findings.push({
      id: "SUPA-R01",
      severity: "high",
      confidence: "high",
      needs_confirmation: true,
      title: `Table ${key} has no ENABLE ROW LEVEL SECURITY in migrations`,
      file: t.file, line: t.line,
      evidence: { type: "missing_rls", masked: `CREATE TABLE ${key}`, note: "from migrations only — CRITICAL requires confirmation: run `supabase db dump --schema public` (read-only) and pass it via --schema, or use URL Mode live probe (v0.4). RLS may be enabled via dashboard drift." },
      owasp: "A01",
      fix: `Enable RLS and add scoped policies: ALTER TABLE ${key} ENABLE ROW LEVEL SECURITY; then CREATE POLICY ... USING (auth.uid() = user_id) as appropriate.`,
      fix_mode: "suggested-diff",
      root: key,
      root_cause: rootCause("SUPA-R01", key),
      verified: true,
    });
  }

  // --- dashboard drift: tables in user-provided schema dump but absent from migrations ---
  if (ctx.schemaDump) {
    const dumpTables = new Set<string>();
    let m: RegExpExecArray | null;
    const dt = /\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:"?(\w+)"?\.)?"?(?!IF\b|NOT\b|EXISTS\b|ONLY\b)([a-zA-Z_][\w]*)"?/gi;
    while ((m = dt.exec(ctx.schemaDump)) !== null) dumpTables.add(`${(m[1] || "public").toLowerCase()}.${m[2]}`);
    for (const t of dumpTables) {
      if (tables.has(t)) continue;
      if (t.startsWith("auth.") || t.startsWith("storage.")) continue; // managed schemas
      findings.push({
        id: "SUPA-R05",
        severity: "medium",
        confidence: "high",
        title: `Dashboard drift: table ${t} exists in the live schema but not in migrations`,
        file: "(schema export)", line: 0,
        evidence: { type: "dashboard_drift", masked: t, note: "created outside migration files — no code-review trail; verify its RLS manually" },
        owasp: "A08",
        fix: "Recreate this table via a migration file (source of truth), verify its RLS/policies, and drop it from the dashboard-managed path.",
        fix_mode: "suggested-diff",
        root: t,
        root_cause: rootCause("SUPA-R05", t),
        verified: true,
      });
    }
  }

  // ---------- v0.2 Supabase depth II ----------

  // SUPA-R06 — policies on sensitive tables without user scoping (auth.uid()/auth.jwt())
  {
    const policyRe = /\bCREATE\s+(?:OR\s+REPLACE\s+)?POLICY\s+"?([\w-]+)"?\s+ON\s+(?:(\w+)\.)?([\w]+)([\s\S]*?);/gi;
    let m: RegExpExecArray | null;
    for (const f of migrationFiles) {
      policyRe.lastIndex = 0;
      while ((m = policyRe.exec(f.content)) !== null) {
        const [, policyName, schema, table, body] = m;
        if ((schema || "public").toLowerCase() !== "public") continue;
        if (!SENSITIVE_TABLE.test(table)) continue;
        if (/auth\.uid\(\)|auth\.jwt\(\)|to\s+authenticated/i.test(body)) continue; // scoped or role-restricted
        const lineNo = f.content.slice(0, m.index).split("\n").length;
        findings.push({
          id: "SUPA-R06",
          severity: "medium",
          confidence: "medium",
          needs_confirmation: true,
          title: `Policy "${policyName}" on ${table} has no user scoping (auth.uid())`,
          file: f.rel, line: lineNo,
          evidence: { type: "policy_unscoped", masked: `POLICY ${policyName} ON ${table}`, note: "any authenticated client may satisfy this policy — scoping to auth.uid() (or a role check) is expected on user-data tables" },
          owasp: "A01",
          fix: `Scope the policy: USING (auth.uid() = user_id) (or the correct ownership column), or restrict it TO a specific role.`,
          fix_mode: "suggested-diff",
          root: `${table}:${policyName}`,
          root_cause: rootCause("SUPA-R06", `${table}:${policyName}`),
          verified: true,
        });
      }
    }
  }

  // SUPA-R07 — storage.objects RLS not configured in migrations (buckets exposed to anon)
  {
    const bucketRe = /storage\.buckets/gi;
    let storageMention = false;
    let storageRls = false;
    let mentionFile = "";
    for (const f of migrationFiles) {
      bucketRe.lastIndex = 0;
      if (bucketRe.test(f.content)) { storageMention = true; mentionFile = f.rel; }
      if (/storage\.objects[\s\S]{0,200}(ENABLE\s+ROW\s+LEVEL\s+SECURITY)/i.test(f.content) || /ALTER\s+TABLE\s+storage\.objects[\s\S]{0,120}ENABLE\s+ROW\s+LEVEL\s+SECURITY/i.test(f.content)) storageRls = true;
    }
    if (storageMention && !storageRls) {
      findings.push({
        id: "SUPA-R07",
        severity: "medium",
        confidence: "medium",
        needs_confirmation: true,
        title: "Buckets created in migrations but no storage.objects RLS policies found",
        file: mentionFile, line: 0,
        evidence: { type: "storage_rls_missing", masked: "storage.buckets without storage.objects policies", note: "bucket inserts alone do not protect object access — public/anon policies must exist deliberately" },
        owasp: "A01",
        fix: "Add explicit storage.objects policies (e.g. USING (bucket_id = 'x' AND auth.role() = 'authenticated')) or confirm the bucket is intentionally public-read.",
        fix_mode: "suggested-diff",
        root: "storage.objects",
        root_cause: rootCause("SUPA-R07", "storage.objects"),
        verified: true,
      });
    }
  }

  // SUPA-R08 — Edge Functions with verify_jwt = false
  {
    const edgeFiles = ctx.files.filter((f) => /supabase\/functions\/[^/]+\/(index\.)?(ts|js)$/.test(f.rel));
    for (const f of edgeFiles) {
      const cfg = ctx.files.find((c) => c.rel === f.rel.replace(/\/(index\.)?(ts|js)$/, "/config.toml"));
      if (cfg && /verify_jwt\s*=\s*false/i.test(cfg.content)) {
        findings.push({
          id: "SUPA-R08",
          severity: "high",
          confidence: "high",
          title: `Edge Function (${f.rel.split("/")[2]}) disables JWT verification (verify_jwt = false)`,
          file: cfg.rel, line: cfg.content.split("\n").findIndex((l) => /verify_jwt/i.test(l)) + 1,
          evidence: { type: "edge_verify_jwt_disabled", masked: "verify_jwt = false", note: "anonymous traffic reaches the function — auth must be enforced inside the handler" },
          owasp: "A07",
          fix: "Set verify_jwt = true (default) or implement explicit in-function auth validation for every request path.",
          fix_mode: "suggested-diff",
          root: cfg.rel,
          root_cause: rootCause("SUPA-R08", cfg.rel),
          verified: true,
        });
      }
    }
  }

  return { findings };
}
