import type { RawFinding } from "../util.js";
import { mkFinding, rootCause } from "../util.js";
import type { CapturedResponse, CaptureBundle } from "./types.js";
import { decodeJwtPayload } from "./jsassets.js";

/**
 * Supabase live anon probe (Plan v1.2 → v0.4 item; read-only GET, verified
 * ownership enforced): pairs with Codebase Mode's RLS analysis — the same
 * class of problem seen from both directions (Plan Section 6 severity ladder).
 * GET /rest/v1/<table>?select=*&limit=1 with the anon key — never a mutation.
 */

export interface SupabaseTarget {
  url: string;                 // https://<ref>.supabase.co
  anonKey: string;
}

export function detectSupabaseTarget(bundle: CaptureBundle): SupabaseTarget | null {
  let url: string | undefined;
  let anonKey: string | undefined;
  for (const r of bundle.requests) {
    if (!url) {
      const m = r.body.match(/https:\/\/[a-z0-9]{20}\.supabase\.co/i);
      if (m) url = m[0];
    }
    if (!anonKey) {
      for (const m of r.body.matchAll(/\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g)) {
        const payload = decodeJwtPayload(m[0]);
        if (payload?.role === "anon" && typeof payload.ref === "string") { anonKey = m[0]; break; }
        if (payload?.role === "anon") { anonKey = anonKey ?? m[0]; }
      }
    }
    if (url && anonKey) break;
  }
  if (!url || !anonKey) return null;
  return { url, anonKey };
}

export interface SupabaseProbeRequest {
  url: string;
  table: string;
}

/** Requests the probe needs (executed by the capture phase; GET-only). */
export function supabaseProbeRequests(target: SupabaseTarget): SupabaseProbeRequest[] {
  return [
    { url: `${target.url}/rest/v1/`, table: "(openapi)" },
  ];
}

/** Analyze the captured OpenAPI listing + per-table probes. */
export function runSupabaseProbe(
  openapi: CapturedResponse | undefined,
  tableProbes: CapturedResponse[],
  target: SupabaseTarget,
  scannedUrl: string
): RawFinding[] {
  const F: RawFinding[] = [];
  if (!openapi || openapi.status !== 200) {
    F.push(mkFinding({
      id: "URL-906", severity: "info", title: "Supabase REST endpoint detected but the anon OpenAPI listing is not readable",
      file: target.url, line: 0,
      evidence: { type: "supabase_probe", masked: `GET /rest/v1/ → ${openapi?.status ?? 0}` },
      owasp: "A01", confidence: "high",
      fix: "Informational — the data API may be gated (verify_jwt on / or paths disabled). Run Codebase Mode on the repo for the migrations view.",
    }));
    return F;
  }

  let tables: string[] = [];
  try {
    const spec = JSON.parse(openapi.body) as { paths?: Record<string, unknown> };
    tables = Object.keys(spec.paths ?? {})
      .filter((p) => p.startsWith("/") && !p.includes("(") && p.split("/").length === 2)
      .map((p) => p.slice(1))
      .sort();
  } catch { /* non-JSON — fall through with empty list */ }

  if (!tables.length) return F;

  F.push(mkFinding({
    id: "URL-907", severity: "info",
    title: `Supabase data API enumerates ${tables.length} table(s) with the anon key`,
    file: target.url, line: 0,
    evidence: { type: "supabase_probe", masked: tables.slice(0, 12).join(",") },
    owasp: "A01", confidence: "high",
    fix: "Informational — anon key is public by design; the control is RLS. Live row probes below report which tables actually return data.",
  }));

  for (const r of tableProbes) {
    const table = r.url.split("/rest/v1/")[1]?.split("?")[0];
    if (!table) continue;
    if (r.status === 200 && r.body.trim().startsWith("[")) {
      F.push(mkFinding({
        id: "URL-060", severity: "high",
        title: `Live anon read returned rows from "${table}" — RLS not effective in production`,
        file: r.final_url, line: 0,
        evidence: { type: "anon_rest_read", masked: `GET /rest/v1/${table}?select=*&limit=1 → 200 rows[] (anon key from public JS of ${scannedUrl})` },
        owasp: "A01", confidence: "high",
        fix: `Enable RLS on "${table}" and add a policy, or revoke anon access: this live probe read real rows with the public anon key. Pair with Codebase Mode SUPA-R rules on the repo's migrations.`,
        root: table, root_cause: rootCause("URL-060", table),
      }));
    } else if (r.status === 401 || r.status === 403 || r.status === 404) {
      F.push(mkFinding({
        id: "URL-908", severity: "info",
        title: `Live anon read of "${table}" rejected (HTTP ${r.status}) — RLS holding`,
        file: r.final_url, line: 0,
        evidence: { type: "anon_rest_read", masked: `GET /rest/v1/${table} → ${r.status}` },
        owasp: "A01", confidence: "high",
        fix: "Documented-correct behavior — keep the policy tests in Codebase Mode green.",
      }));
    }
  }
  return F;
}
