import { connect as tlsConnect } from "node:tls";
import type { ScanResult, Finding } from "../types.js";
import { computeScore } from "../score.js";
import { applySuppression, type RawFinding } from "../util.js";
import { ADVISORY_SNAPSHOT, VERSION } from "../engine.js";
import { SEVERITY_ORDER } from "../types.js";
import { Fetcher } from "./fetcher.js";
import {
  generateNonce, instructions, isLocalOrPrivate, verifyOwnership,
} from "./ownership.js";
import type { CaptureBundle, OwnershipResult, TlsInfo, UrlScanOptions } from "./types.js";
import { LEVEL_REQUEST_CAPS } from "./types.js";
import { runL1, extractScriptUrls } from "./checks-l1.js";
import { runL2, PROBES, LISTING_PATHS, APIDOC_PATHS, SURFACE_PATHS } from "./checks-l2.js";
import { detectSupabaseTarget, runSupabaseProbe, type SupabaseTarget } from "./checks-l3.js";
import { URL_CHECKS, URL_CLASSES_COVERED, URL_CLASSES_NOT_COVERED } from "./coverage.js";
import { scanBundle } from "./jsassets.js";

/**
 * URL Mode orchestrator (Plan Section 7):
 *   Phase A — capture: rate-limited, capped, browser-equivalent (L1) or
 *             ownership-gated probing (L2+) → CaptureBundle
 *   Phase B — analyze: pure function bundle → ScanResult (same contract as Mode 1)
 * Re-analyzing a saved capture (`--from-capture`) is byte-identical.
 */

export class GateError extends Error {
  constructor(message: string, readonly help?: string) {
    super(message);
  }
}

/** TLS facts captured out-of-band (tls.connect) — deterministic per scan instant. */
export function inspectTls(url: URL, timeoutMs: number): Promise<TlsInfo | null> {
  return new Promise((resolve) => {
    if (url.protocol !== "https:") return resolve(null);
    const port = url.port ? Number(url.port) : 443;
    const done = (info: TlsInfo) => resolve(info);
    let settled = false;
    const finish = (info: TlsInfo) => { if (!settled) { settled = true; try { sock.destroy(); } catch { /* already closed */ } done(info); } };
    const sock = tlsConnect(
      { host: url.hostname, port, servername: url.hostname, rejectUnauthorized: false, timeout: timeoutMs },
      () => {
        const cert = sock.getPeerCertificate();
        const proto = sock.getProtocol();
        if (!cert || !cert.valid_to) return finish({ protocol: proto, authorized: sock.authorized, daysLeft: null, valid_from_iso: null, valid_to_iso: null, error: "no peer certificate" });
        const to = new Date(cert.valid_to).getTime();
        const daysLeft = Number.isFinite(to) ? Math.round((to - Date.now()) / 86_400_000) : null;
        finish({
          protocol: proto,
          authorized: sock.authorized,
          daysLeft,
          valid_from_iso: cert.valid_from ? new Date(cert.valid_from).toISOString().slice(0, 10) : null,
          valid_to_iso: cert.valid_to ? new Date(cert.valid_to).toISOString().slice(0, 10) : null,
        });
      }
    );
    sock.on("error", (e) => finish({ protocol: null, authorized: false, daysLeft: null, valid_from_iso: null, valid_to_iso: null, error: e.message }));
    sock.on("timeout", () => finish({ protocol: null, authorized: false, daysLeft: null, valid_from_iso: null, valid_to_iso: null, error: "tls handshake timeout" }));
  });
}

/**
 * The legal gate (Plan v1.3): L2+ on a public domain requires a VERIFIED
 * nonce. Self-attestation works ONLY for localhost/private staging, and L3
 * always requires verified ownership (never the flag alone). Throws GateError
 * with setup instructions BEFORE any request is sent.
 */
export async function resolveOwnership(
  targetUrl: string,
  opts: UrlScanOptions,
  verify?: (origin: string, nonce: string) => Promise<OwnershipResult>
): Promise<OwnershipResult> {
  const u = new URL(targetUrl);
  const host = u.hostname;
  const origin = u.origin;
  const local = isLocalOrPrivate(host);

  if (opts.level === 1) return { verified: false, method: "none", host };

  // L3 is verified-only BY DESIGN (Plan: "مش بيتشغل بالـ flag لوحده أبدًا") — even locally.
  if (opts.level >= 3 && !opts.ownershipToken) {
    throw new GateError(
      `Level 3 requires VERIFIED ownership (enforced — never the flag alone). Publish the nonce, then pass --ownership-token.`,
      instructions(new URL(targetUrl).hostname, generateNonce())
    );
  }

  // explicit token → verify (DNS TXT first, then .well-known)
  if (opts.ownershipToken) {
    const check = verify ?? ((o: string, n: string) => {
      const f = new Fetcher({ delayMs: opts.delayMs, timeoutMs: opts.timeoutMs, maxRequests: 4 });
      return verifyOwnership({ host, origin: o, nonce: n, fetcher: f });
    });
    const res = await check(origin, opts.ownershipToken);
    if (res.verified) return res;
    throw new GateError(
      `ownership verification FAILED: the nonce was not found in DNS TXT or /.well-known for ${host}. Level ${opts.level} stays locked.`,
      instructions(host, opts.ownershipToken)
    );
  }

  // self-attestation — local/private staging only (v1.3)
  if (opts.selfAttest) {
    if (local) return { verified: false, method: "self-attested (local only)", host };
    throw new GateError(
      `--i-own-this-domain is a checkbox, not proof. For public domains, Level ${opts.level} requires VERIFIED ownership (DNS TXT or .well-known nonce).`,
      instructions(host, generateNonce())
    );
  }

  // local target, L2, no attestation flag → tell the user the local path
  if (local) {
    throw new GateError(
      `Level 2 on a local/private target needs --i-own-this-domain (self-attestation is local-only and will be labeled in the report).`,
      undefined
    );
  }

  throw new GateError(
    `Level ${opts.level} on a public domain requires VERIFIED ownership (DNS TXT record or /.well-known file). Nothing was requested.`,
    instructions(host, generateNonce())
  );
}

interface RobotsRules { disallowAll: boolean; disallow: string[]; }

export function parseRobots(body: string): RobotsRules {
  const rules: RobotsRules = { disallowAll: false, disallow: [] };
  let inStar = false;
  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.split("#")[0].trim();
    if (!line) continue;
    const [k, ...rest] = line.split(":");
    const key = k.trim().toLowerCase();
    const val = rest.join(":").trim();
    if (key === "user-agent") inStar = val === "*";
    else if (inStar && key === "disallow") {
      if (val === "") rules.disallowAll = false;
      else if (val === "/") rules.disallowAll = true;
      else rules.disallow.push(val);
    }
  }
  return rules;
}

/** Phase A — capture everything the chosen level requests. */
export async function captureUrl(targetUrl: string, opts: UrlScanOptions, ownership: OwnershipResult): Promise<CaptureBundle> {
  const u = new URL(targetUrl);
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new GateError("scan-url accepts http(s) URLs only");
  }
  const origin = u.origin;
  const cap = LEVEL_REQUEST_CAPS[opts.level];
  const fetcher = new Fetcher({
    delayMs: opts.delayMs ?? 250,
    timeoutMs: opts.timeoutMs ?? 10_000,
    maxRequests: opts.maxRequests ?? cap,
  });
  const notes: string[] = [];

  const homepage = await fetcher.get(targetUrl);
  await Promise.all([
    fetcher.get(`${origin}/robots.txt`),
    fetcher.get(`${origin}/sitemap.xml`),
    fetcher.get(`${origin}/.well-known/security.txt`),
  ]);

  // L1: public JS assets the page itself loads (browser-equivalent, v1.3)
  const scriptUrls = homepage ? extractScriptUrls(homepage.body, origin).slice(0, opts.maxAssets ?? 10) : [];
  for (const js of scriptUrls) await fetcher.get(js);

  // parse robots for L2 gating
  const robotsRes = fetcher.requests.find((r) => r.url === `${origin}/robots.txt`);
  const robots = parseRobots(robotsRes && robotsRes.status === 200 ? robotsRes.body : "");
  const robotsSkipped: string[] = [];
  const robotAllows = (path: string): boolean => {
    if (robots.disallowAll) return false;
    return !robots.disallow.some((d) => path === d || path.startsWith(d));
  };

  // L2 probes (ownership already gated by resolveOwnership before capture)
  if (opts.level >= 2) {
    const probeAll = async (path: string) => {
      if (!robotAllows(path)) { fetcher.skipForRobots(path); return; }
      await fetcher.get(`${origin}${path}`);
    };
    for (const p of PROBES) await probeAll(p.path);
    for (const p of LISTING_PATHS) await probeAll(p);
    for (const p of APIDOC_PATHS) await probeAll(p.path);
    for (const p of SURFACE_PATHS) await probeAll(p);
    await fetcher.send("OPTIONS", targetUrl);
    if (robotAllows("/")) await fetcher.send("TRACE", targetUrl);

    // sourcemap exposure (from L1 bundle intel)
    if (homepage) {
      for (const js of scriptUrls) {
        const captured = fetcher.requests.find((r) => r.url === js && r.status === 200);
        if (!captured) continue;
        const intel = scanBundle({ text: captured.body, assetUrl: js, origin, stack: [] });
        for (const ref of intel.sourcemapRefs.slice(0, 5)) {
          try {
            const mapUrl = new URL(ref, js).toString();
            if (new URL(mapUrl).origin === origin) await fetcher.get(mapUrl);
          } catch { /* malformed ref */ }
        }
      }
    }
  }

  // L3 (v0.4): Supabase live anon probe — read-only GETs, verified ownership enforced
  let supabaseTarget: SupabaseTarget | null = null;
  if (opts.level >= 3 && ownership.verified) {
    // detect from already-captured content
    const mini: CaptureBundle = {
      capture_version: 1,
      meta: { url: targetUrl, captured_at: new Date().toISOString(), level: opts.level, ownership, tool: "anubis-guardian", version: "0", max_requests: 0, delay_ms: 0 },
      tls: null,
      requests: fetcher.requests,
      robots: { skipped: robotsSkipped, disallow_all: robots.disallowAll },
      notes: [],
    };
    supabaseTarget = detectSupabaseTarget(mini);
    if (supabaseTarget) {
      if (robotAllows("/rest/v1/")) {
        await fetcher.get(`${supabaseTarget.url}/rest/v1/`);
        const openapi = fetcher.requests[fetcher.requests.length - 1];
        let tables: string[] = [];
        try {
          const spec = JSON.parse(openapi?.body ?? "{}") as { paths?: Record<string, unknown> };
          tables = Object.keys(spec.paths ?? {}).filter((p) => p.startsWith("/") && p.split("/").length === 2).map((p) => p.slice(1)).sort();
        } catch { /* listing unreadable */ }
        for (const t of tables.slice(0, 12)) {
          await fetcher.get(`${supabaseTarget.url}/rest/v1/${t}?select=*&limit=1`);
        }
        notes.push(`supabase probe: ${tables.length} table(s) listed, ${Math.min(tables.length, 12)} probed (GET-only, limit=1)`);
      } else {
        fetcher.skipForRobots("/rest/v1/");
      }
    } else {
      notes.push("level 3: no Supabase target detected in public assets — nothing probed");
    }
  }

  const tls = await inspectTls(u, opts.timeoutMs ?? 10_000);

  return {
    capture_version: 1,
    meta: {
      url: targetUrl,
      captured_at: new Date().toISOString(),
      level: opts.level,
      ownership,
      tool: "anubis-guardian",
      version: VERSION,
      max_requests: fetcher.maxRequests,
      delay_ms: fetcher.delayMs,
    },
    tls,
    requests: fetcher.requests,
    robots: { skipped: fetcher.robotsSkipped, disallow_all: robots.disallowAll },
    notes,
  };
}

/** Phase B — deterministic: capture → findings + ScanResult (same contract as Mode 1). */
export function analyzeBundle(bundle: CaptureBundle): ScanResult {
  const level = bundle.meta.level;
  const l1 = runL1(bundle);
  const raw: RawFinding[] = [...l1.findings];
  if (level >= 2) raw.push(...runL2(bundle));

  if (level >= 3 && bundle.meta.ownership.verified) {
    const target = detectSupabaseTarget(bundle);
    if (target) {
      const origin2 = new URL(target.url).origin;
      const openapi = bundle.requests.find((r) => r.url === `${origin2}/rest/v1/`);
      const tableProbes = bundle.requests.filter((r) => /\/rest\/v1\/[^/]+\?select=\*&limit=1$/.test(r.url));
      raw.push(...runSupabaseProbe(openapi, tableProbes, target, bundle.meta.url));
    } else {
      raw.push({
        id: "URL-906", severity: "info", title: "Level 3: no Supabase target detected in public assets",
        file: bundle.meta.url, line: 0,
        evidence: { type: "supabase_probe", masked: "no supabase project ref / anon key found in captured content" },
        owasp: "A01", confidence: "high", verified: true, fix_mode: "suggested-diff",
        fix: "Informational — nothing probed. If the app uses Supabase, ensure the JS actually references the project (or scan the repo with Codebase Mode).",
      });
    }
  }

  // suppression (no inline ignores in URL mode — fingerprints + dedupe only)
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const f of raw) {
    const sup = applySuppression(f, [], f.file);
    if (seen.has(sup.fingerprint)) continue;
    seen.add(sup.fingerprint);
    findings.push(sup);
  }
  findings.sort((a, b) => {
    const s = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (s !== 0) return s;
    return a.file.localeCompare(b.file);
  });

  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) summary[f.severity] = (summary[f.severity] ?? 0) + 1;
  const score_breakdown = computeScore(findings);

  const byMethod: Record<string, number> = {};
  for (const r of bundle.requests) byMethod[r.method] = (byMethod[r.method] ?? 0) + 1;

  const levelsRun = ["L1-passive", ...(level >= 2 ? ["L2-discovery"] : []), ...(level >= 3 ? ["L3-supabase-probe"] : [])];

  return {
    tool: "anubis-guardian",
    version: bundle.meta.version,
    advisory_snapshot: ADVISORY_SNAPSHOT,
    target: { mode: "url", path: bundle.meta.url, stack: l1.stack.length ? l1.stack : inferStackForAnalyze(bundle) },
    score: score_breakdown.score,
    grade: score_breakdown.grade,
    summary,
    coverage: {
      checks_run: URL_CHECKS.filter((c) => c.level <= level).length,
      checks_applicable: URL_CHECKS.length,
      classes_covered: URL_CLASSES_COVERED,
      classes_not_covered: URL_CLASSES_NOT_COVERED,
    },
    score_breakdown,
    findings,
    url_meta: {
      authorization: {
        url: bundle.meta.url,
        timestamp: bundle.meta.captured_at,
        level,
        ownership_method: bundle.meta.ownership.method,
        ownership_verified: bundle.meta.ownership.verified,
        note: bundle.meta.ownership.verified
          ? `ownership verified via ${bundle.meta.ownership.method} (nonce challenge)`
          : bundle.meta.ownership.method === "self-attested (local only)"
            ? "self-attested (local only) — not proof; report consumers should treat Level 2+ results accordingly"
            : "Level 1 passive — no ownership required",
      },
      requests: { total: bundle.requests.length, by_method: byMethod },
      robots: { checked: true, disallow_all: bundle.robots.disallow_all, skipped_paths: bundle.robots.skipped },
      levels_run: levelsRun,
      notes: bundle.notes,
    },
    meta: {
      no_exec: true,
      files_scanned: bundle.requests.length,
      git_history_scanned: false,
    },
  };
}

function inferStackForAnalyze(bundle: CaptureBundle): string[] {
  const homepage = bundle.requests[0];
  if (!homepage) return [];
  const s = new Set<string>();
  if ((homepage.headers["x-powered-by"] ?? "").includes("Next.js") || homepage.body.includes("/_next/static")) s.add("nextjs");
  if ((homepage.headers["x-powered-by"] ?? "").includes("Express")) s.add("express");
  if (homepage.body.match(/https:\/\/[a-z0-9]{20}\.supabase\.co/i)) s.add("supabase");
  return [...s].sort();
}

/** Full pipeline: gate → capture → analyze. */
export async function scanUrl(targetUrl: string, opts: UrlScanOptions): Promise<ScanResult> {
  const ownership = await resolveOwnership(targetUrl, opts);
  const bundle = await captureUrl(targetUrl, opts, ownership);
  return analyzeBundle(bundle);
}

/** Re-analyze a saved capture — deterministic, zero network (v0.4 determinism contract). */
export function fromCapture(json: string): ScanResult {
  const bundle = JSON.parse(json) as CaptureBundle;
  if (bundle.capture_version !== 1) throw new Error(`unsupported capture_version: ${String((bundle as { capture_version?: number }).capture_version)}`);
  return analyzeBundle(bundle);
}

/** Convenience for the `ownership` CLI command. */
export const ownershipHelp = { generateNonce, instructions };
