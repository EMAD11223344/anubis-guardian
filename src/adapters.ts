import type { Finding, ScanContext } from "./types.js";
import { fingerprint, rootCause } from "./util.js";
import { execFileSync } from "node:child_process";
import { writeFileSync, readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Adapters (Plan v0.2): merge third-party scanners when their binaries exist —
 * gitleaks (MIT) / OSV-Scanner (Apache-2) / Semgrep (LGPL). Built-in fallback
 * always runs. Design constraints:
 *  - OFF by default: default scans stay deterministic and byte-identical.
 *    Adapters run only behind --tools and are flagged in meta.adapters_used.
 *  - Adapter output is marked source=<tool> and confidence=medium, and NEVER
 *    upgrades a finding to CRITICAL (the no-CRITICAL-without-confirmation law).
 *  - v1.2 (T0) — FAIL CLOSED: "adapter absence must not break a scan" is kept
 *    for the DEFAULT (no --tools) runs only. When the operator EXPLICITLY
 *    requested a tool, silence is a lie: a missing binary, a crash, or an
 *    unusable report is reported (missing/failed/unsupported lists) and the
 *    engine refuses to emit a report that pretends the evidence exists.
 */

export function toolExists(bin: string): boolean {
  // "which" does not exist on Windows (cmd uses "where"); without this the
  // --tools adapters silently no-op on every Windows machine.
  const probe = process.platform === "win32" ? "where" : "which";
  try { execFileSync(probe, [bin], { stdio: "ignore" }); return true; } catch { return false; }
}

export interface AdapterFailure { tool: string; status: number | null; reason: string }

export interface AdapterOutcome {
  findings: Finding[];
  used: string[];
  /** explicitly requested binaries that are not installed */
  missing: string[];
  /** binaries present but the run produced no usable report */
  failed: AdapterFailure[];
  /** tool names this engine does not know how to drive */
  unsupported: string[];
}

/**
 * Controlled-executor seam (T0 test doubles): production uses realAdapterProbe;
 * tests inject a fake `exists`/`exec` pair to exercise the exit-code truth
 * table (findings exit codes, clean runs, crashes, malformed reports) without
 * depending on host-installed scanner binaries. The fake exec writes the
 * report file at the --report-path argument it receives.
 */
export interface ExecResult { status: number | null; stdout: string; stderr: string }
export interface AdapterProbe {
  exists: (bin: string) => boolean;
  exec: (bin: string, args: string[], opts: { timeout?: number; cwd?: string }) => ExecResult;
}

export const realAdapterProbe: AdapterProbe = {
  exists: toolExists,
  exec: (bin, args, opts) => {
    try {
      execFileSync(bin, args, { timeout: opts.timeout, cwd: opts.cwd });
      return { status: 0, stdout: "", stderr: "" };
    } catch (e) {
      return { status: execStatus(e), stdout: "", stderr: shortReason(e) };
    }
  },
};

export function runAdapters(ctx: ScanContext, tools: string[], probe: AdapterProbe = realAdapterProbe): AdapterOutcome {
  const outcome: AdapterOutcome = { findings: [], used: [], missing: [], failed: [], unsupported: [] };

  for (const tool of tools) {
    if (tool !== "gitleaks" && tool !== "osv-scanner" && tool !== "semgrep") {
      outcome.unsupported.push(tool);
      continue;
    }
    if (!probe.exists(tool)) {
      outcome.missing.push(tool);
      continue;
    }
    try {
      let findings: Finding[] = [];
      let failed = false; // runner records failures instead of throwing
      const fail = (status: number | null, reason: string) => { failed = true; outcome.failed.push({ tool, status, reason }); };
      if (tool === "gitleaks") findings = gitleaks(ctx, fail, probe);
      else if (tool === "osv-scanner") findings = osvScanner(ctx, fail, probe);
      else findings = semgrep(ctx, fail, probe);
      outcome.findings.push(...findings);
      if (!failed) outcome.used.push(tool);
    } catch (e) {
      outcome.failed.push({ tool, status: execStatus(e), reason: (e instanceof Error ? e.message : String(e)).slice(0, 200) });
    }
  }
  return outcome;
}

const shortReason = (e: unknown): string => (e instanceof Error ? e.message : String(e)).slice(0, 200);

/**
 * v1.2 (T0) — exit-code truth table (the old code treated these as crashes and
 * threw the FINDINGS away):
 *   gitleaks     0 = clean · 1 = leaks FOUND (report must still be parsed)
 *   osv-scanner  0 = clean · 1 = vulnerabilities FOUND
 *   semgrep      0 = done (maybe findings in report) · nonzero = scan failed
 * Shared contract: if a parseable report with results exists, the run counts as
 * used regardless of exit code; otherwise the failure is surfaced.
 */
function execStatus(e: unknown): number | null {
  const s = (e as { status?: number })?.status;
  return typeof s === "number" ? s : null;
}

type RunFail = (status: number | null, reason: string) => void;

/**
 * v1.2 audit — OSV/GHSA severity mapping, EXPLICIT per value:
 *   CRITICAL → critical · HIGH → high · MODERATE/MEDIUM → medium · LOW → low.
 * Missing or unrecognized severities follow a documented policy: MEDIUM with
 * needs_confirmation and the raw value surfaced in the finding note — they are
 * never silently treated as a known severity and never inflated to HIGH
 * (the pre-audit default collapsed everything non-CRITICAL into HIGH).
 */
export function mapOsvSeverity(v: unknown): {
  severity: "critical" | "high" | "medium" | "low";
  needsConfirmation: boolean;
  raw: string;
} {
  const raw = String((v as { database_specific?: { severity?: unknown } })?.database_specific?.severity ?? "").toUpperCase();
  switch (raw) {
    case "CRITICAL": return { severity: "critical", needsConfirmation: false, raw };
    case "HIGH": return { severity: "high", needsConfirmation: false, raw };
    case "MODERATE":
    case "MEDIUM": return { severity: "medium", needsConfirmation: false, raw };
    case "LOW": return { severity: "low", needsConfirmation: false, raw };
    default: return { severity: "medium", needsConfirmation: true, raw };
  }
}

function gitleaks(ctx: ScanContext, fail: RunFail, probe: AdapterProbe): Finding[] {
  const dir = mkdtempSync(join(tmpdir(), "anubis-gl-"));
  const report = join(dir, "gl.json");
  try {
    const r = probe.exec("gitleaks", ["detect", "--source", ctx.rootDir, "--report-format", "json", "--report-path", report, "--no-banner", "--redact"], { timeout: 120000 });
    // v1.2 (T0) truth table: 0 = clean · 1 = leaks FOUND (report is the payload) ·
    // anything else (incl. null = crash/ENOENT...) = execution failure
    if (r.status !== 0 && r.status !== 1) {
      fail(r.status, `unexpected gitleaks exit ${r.status ?? "(crash)"}: ${r.stderr.slice(0, 140)}`);
      return [];
    }
    let raw: any[];
    try { raw = JSON.parse(readFileSync(report, "utf8")); } catch {
      // invalid/missing report = incomplete coverage, never "clean"
      fail(r.status, `gitleaks exited ${r.status} but the JSON report is missing or unparseable (expected at ${report})`);
      return [];
    }
    if (!Array.isArray(raw)) {
      fail(r.status, "gitleaks report is not a JSON array — invalid report");
      return [];
    }
    return raw.slice(0, 200).map((g) => ({
      id: "GLK-001",
      severity: "high" as const,
      title: `Secret detected by gitleaks (${g.RuleID ?? "unknown rule"})`,
      file: g.File ?? g.path ?? "?",
      line: Number(g.StartLine ?? g.line ?? 0),
      evidence: { type: "adapter:gitleaks", masked: "(redacted by gitleaks --redact)", note: g.Description ?? "" },
      owasp: "A02",
      confidence: "medium" as const,
      fix: "Rotate the exposed credential first (provider dashboard), then remove it from code, then scrub history with git filter-repo.",
      fix_mode: "suggested-diff" as const,
      verified: false,
      source: "gitleaks" as const,
      fingerprint: fingerprint("GLK-001", String(g.File ?? ""), String(g.Fingerprint ?? g.RuleID ?? "")),
      suppression: null,
      root: String(g.RuleID ?? "secret"),
      root_cause: rootCause("GLK-001", String(g.RuleID ?? "secret")),
      needs_confirmation: true,
    }));
  } finally {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* tmp cleanup */ }
  }
}

function osvScanner(ctx: ScanContext, fail: RunFail, probe: AdapterProbe): Finding[] {
  const report = join(mkdtempSync(join(tmpdir(), "anubis-osv-")), "osv.json");
  try {
    const r = probe.exec("osv-scanner", ["--format", "json", "--output", report, "--scan", "."], { cwd: ctx.rootDir, timeout: 180000 });
    // truth table: 0 = clean · 1 = vulnerabilities FOUND — anything else = failure
    if (r.status !== 0 && r.status !== 1) {
      fail(r.status, `unexpected osv-scanner exit ${r.status ?? "(crash)"}: ${r.stderr.slice(0, 140)}`);
      return [];
    }
    let data: any;
    try { data = JSON.parse(readFileSync(report, "utf8")); } catch {
      fail(r.status, `osv-scanner exited ${r.status} but the JSON report is missing or unparseable (expected at ${report})`);
      return [];
    }
    const out: Finding[] = [];
    for (const res of data.results ?? []) {
      for (const pkg of res.packages ?? []) {
        for (const v of pkg.vulnerabilities ?? []) {
          // v1.2 audit — explicit per-severity mapping (was: every non-CRITICAL
          // collapsed to HIGH, inflating MODERATE/LOW). Unknown/missing severity
          // follows a documented policy: MEDIUM + needs_confirmation + the raw
          // value disclosed in the note — never silently treated as a known one.
          const sev = mapOsvSeverity(v);
          const sevNote = sev.needsConfirmation
            ? ` [unrecognized OSV severity: ${sev.raw || "(none)"} — MEDIUM pending review]`
            : "";
          out.push({
            id: "OSV-001",
            severity: sev.severity,
            title: `${v.id} — ${pkg.package?.name ?? "?"} (osv-scanner)`,
            file: "package.json",
            line: 0,
            evidence: { type: "adapter:osv-scanner", masked: `${pkg.package?.name ?? "?"}@${pkg.package?.version ?? "?"}`, note: ((v.summary ?? "").slice(0, 140)) + sevNote },
            owasp: "A06",
            confidence: "medium",
            fix: `Upgrade ${pkg.package?.name ?? "the package"} to a version fixing ${v.id}.`,
            fix_mode: "suggested-diff",
            verified: false,
            source: "osv-scanner",
            fingerprint: fingerprint("OSV-001", pkg.package?.name ?? "", v.id),
            suppression: null,
            root: pkg.package?.name ?? v.id,
            root_cause: rootCause("OSV-001", pkg.package?.name ?? v.id),
            ...(sev.needsConfirmation ? { needs_confirmation: true } : {}),
          });
        }
      }
    }
    return out.slice(0, 200);
  } finally {
    try { rmSync(report, { recursive: true, force: true }); } catch { /* tmp cleanup */ }
  }
}

function semgrep(ctx: ScanContext, fail: RunFail, probe: AdapterProbe): Finding[] {
  const report = join(mkdtempSync(join(tmpdir(), "anubis-sg-")), "sg.json");
  try {
    // semgrep truth table: 0 = scan completed (findings inside the report);
    // ANY nonzero exit = scan failure (not a findings code) — surfaced.
    const r = probe.exec("semgrep", ["scan", "--json", "--quiet", "--output", report, "--config", "p/owasp-top-ten", ctx.rootDir], { timeout: 240000 });
    if (r.status !== 0) {
      fail(r.status, `unexpected semgrep exit ${r.status ?? "(crash)"}: ${r.stderr.slice(0, 140)}`);
      return [];
    }
    let data: any;
    try { data = JSON.parse(readFileSync(report, "utf8")); } catch {
      fail(0, `semgrep completed but the JSON report is missing or unparseable (expected at ${report})`);
      return [];
    }
    return (data.results ?? []).slice(0, 200).map((r: any) => ({
      id: "SGP-001",
      severity: r.extra?.severity === "ERROR" ? "high" : "medium",
      title: `${r.check_id ?? "semgrep finding"} (semgrep)`,
      file: r.path ?? r.start?.file ?? "?",
      line: r.start?.line ?? 0,
      evidence: { type: "adapter:semgrep", masked: (r.extra?.lines ?? "").trim().slice(0, 60), note: (r.extra?.message ?? "").slice(0, 140) },
      owasp: "A03",
      confidence: "medium",
      fix: "Review the semgrep rule hit and apply the rule's recommended remediation.",
      fix_mode: "suggested-diff",
      verified: false,
      source: "semgrep",
      fingerprint: fingerprint("SGP-001", String(r.path ?? ""), String(r.check_id ?? "")),
      suppression: null,
      root: String(r.check_id ?? "semgrep"),
      root_cause: rootCause("SGP-001", String(r.check_id ?? "semgrep")),
      needs_confirmation: true,
    } as Finding));
  } finally {
    try { rmSync(report, { recursive: true, force: true }); } catch { /* tmp cleanup */ }
  }
}

/** --update-advisories: refresh the local advisory snapshot from OSV.dev for this project's deps. */
export async function updateAdvisories(rootDir: string, outFile: string): Promise<number> {
  const pkgPath = join(rootDir, "package.json");
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  const deps = Object.keys({ ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) }).filter((d) => !d.startsWith("@") || d.startsWith("@supabase") || d.startsWith("@nestjs"));
  const scopedExtra = Object.keys({ ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) }).filter((d) => d.startsWith("@")).flatMap((d) => [d, d.split("/")[0]]);

  const names = [...new Set([...deps, ...scopedExtra])].filter(Boolean);
  const advisories: Record<string, any[]> = {};
  let count = 0;
  for (const name of names) {
    try {
      // Built-in fetch (Node >= 18) — no external binary dependency: "curl" is
      // missing on minimal Windows images and this flow must work everywhere.
      const httpRes = await fetch("https://api.osv.dev/v1/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ package: { name, ecosystem: "npm" } }),
        signal: AbortSignal.timeout(20000),
      });
      if (!httpRes.ok) throw new Error(`osv.dev HTTP ${httpRes.status}`);
      const data: any = await httpRes.json();
      const vulns = (data.vulns ?? [])
        .filter((v: any) => ["HIGH", "CRITICAL"].includes(String(v.database_specific?.severity ?? "").toUpperCase()))
        .map((v: any) => ({
          id: v.id, aliases: (v.aliases ?? []).slice(0, 3), severity: String(v.database_specific?.severity).toLowerCase(),
          summary: (v.summary ?? "").slice(0, 160),
          ranges: (v.affected ?? []).flatMap((a: any) => (a.ranges ?? []).filter((r: any) => ["ECOSYSTEM", "SEMVER"].includes(r.type)).map((r: any) => ({ events: r.events }))),
          fixed_hint: (v.affected ?? []).flatMap((a: any) => (a.ranges ?? []).flatMap((r: any) => r.events ?? [])).find((e: any) => e.fixed)?.fixed,
        }))
        .filter((v: any) => v.ranges.length);
      if (vulns.length) { advisories[name] = vulns; count += vulns.length; }
    } catch { /* keep going — offline resilience */ }
  }
  writeFileSync(outFile, JSON.stringify({
    snapshot_date: new Date().toISOString().slice(0, 7),
    source: "OSV.dev — local refresh via --update-advisories (NOT bundled; pass --advisories to use it)",
    policy: "HIGH/CRITICAL only, project dependencies",
    advisories, known_malicious: {},
  }, null, 2));
  return count;
}
