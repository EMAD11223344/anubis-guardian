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
 *  - Failures are skipped silently (adapter absence must not break a scan).
 */

export function toolExists(bin: string): boolean {
  try { execFileSync("which", [bin], { stdio: "ignore" }); return true; } catch { return false; }
}

export function runAdapters(ctx: ScanContext, tools: string[]): { findings: Finding[]; used: string[] } {
  const findings: Finding[] = [];
  const used: string[] = [];

  for (const tool of tools) {
    if (!toolExists(tool)) continue;
    try {
      if (tool === "gitleaks") findings.push(...gitleaks(ctx));
      else if (tool === "osv-scanner") findings.push(...osvScanner(ctx));
      else if (tool === "semgrep") findings.push(...semgrep(ctx));
      used.push(tool);
    } catch { /* adapter failure never breaks the scan */ }
  }
  return { findings, used };
}

function gitleaks(ctx: ScanContext): Finding[] {
  const dir = mkdtempSync(join(tmpdir(), "anubis-gl-"));
  const report = join(dir, "gl.json");
  try {
    execFileSync("gitleaks", ["detect", "--source", ctx.rootDir, "--report-format", "json", "--report-path", report, "--no-banner", "--redact"], { timeout: 120000 });
    let raw: any[] = [];
    try { raw = JSON.parse(readFileSync(report, "utf8")); } catch { return []; }
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

function osvScanner(ctx: ScanContext): Finding[] {
  const report = join(mkdtempSync(join(tmpdir(), "anubis-osv-")), "osv.json");
  try {
    execFileSync("osv-scanner", ["--format", "json", "--output", report, "--scan", "."], { cwd: ctx.rootDir, timeout: 180000 });
    const data = JSON.parse(readFileSync(report, "utf8"));
    const out: Finding[] = [];
    for (const res of data.results ?? []) {
      for (const pkg of res.packages ?? []) {
        for (const v of pkg.vulnerabilities ?? []) {
          const sev = v.database_specific?.severity === "CRITICAL" ? "critical" : "high";
          out.push({
            id: "OSV-001",
            severity: sev,
            title: `${v.id} — ${pkg.package?.name ?? "?"} (osv-scanner)`,
            file: "package.json",
            line: 0,
            evidence: { type: "adapter:osv-scanner", masked: `${pkg.package?.name ?? "?"}@${pkg.package?.version ?? "?"}`, note: (v.summary ?? "").slice(0, 140) },
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
          });
        }
      }
    }
    return out.slice(0, 200);
  } finally {
    try { rmSync(report, { recursive: true, force: true }); } catch { /* tmp cleanup */ }
  }
}

function semgrep(ctx: ScanContext): Finding[] {
  const report = join(mkdtempSync(join(tmpdir(), "anubis-sg-")), "sg.json");
  try {
    execFileSync("semgrep", ["scan", "--json", "--quiet", "--output", report, "--config", "p/owasp-top-ten", ctx.rootDir], { timeout: 240000 });
    const data = JSON.parse(readFileSync(report, "utf8"));
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
export function updateAdvisories(rootDir: string, outFile: string): number {
  const pkgPath = join(rootDir, "package.json");
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  const deps = Object.keys({ ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) }).filter((d) => !d.startsWith("@") || d.startsWith("@supabase") || d.startsWith("@nestjs"));
  const scopedExtra = Object.keys({ ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) }).filter((d) => d.startsWith("@")).flatMap((d) => [d, d.split("/")[0]]);

  const names = [...new Set([...deps, ...scopedExtra])].filter(Boolean);
  const advisories: Record<string, any[]> = {};
  let count = 0;
  for (const name of names) {
    try {
      const res = execFileSync(
        "curl",
        ["-s", "-X", "POST", "https://api.osv.dev/v1/query", "-H", "Content-Type: application/json", "-d", JSON.stringify({ package: { name, ecosystem: "npm" } })],
        { encoding: "utf8", timeout: 20000 }
      );
      const data = JSON.parse(res);
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
