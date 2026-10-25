import type { OrgRule, ScannedFile } from "./types.js";
import { rootCause, fingerprint } from "./util.js";
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, relative, sep } from "node:path";
import type { Finding } from "./types.js";

/**
 * --rules-dir loader (Plan Section 4 "Custom Rules & Organizational Deployment";
 * v1.4 item; shipped v0.2). JSON rule files using the plan's DSL subset:
 *   { id, severity, title, owasp, files: [globs], regex, flags?, fix, clean_cases? }
 * Hard limits honored by the engine:
 *  - org rules live inside Layer-5 semantics (pattern checks, no exec)
 *  - a CRITICAL org rule is auto-marked needs_confirmation + medium confidence
 *    (the no-CRITICAL-without-confirmation law, Section 8)
 *  - findings are tagged source="org-rule" and org-tagged in score_breakdown
 *  - clean_cases is REQUIRED documentation (not enforced runtime) — the DSL
 *    requirement from v1.6; a rule without it gets a warning on stderr.
 */

export function loadOrgRules(dir: string): { rules: OrgRule[]; warnings: string[] } {
  const rules: OrgRule[] = [];
  const warnings: string[] = [];
  if (!existsSync(dir)) return { rules, warnings: [`rules-dir not found: ${dir}`] };

  for (const name of readdirSync(dir).sort()) {
    if (!name.endsWith(".json")) continue;
    const path = join(dir, name);
    if (!statSync(path).isFile()) continue;
    try {
      const parsed = JSON.parse(readFileSync(path, "utf8"));
      const arr: any[] = Array.isArray(parsed) ? parsed : [parsed];
      for (const r of arr) {
        if (!r?.id || !r?.regex || !r?.files?.length) {
          warnings.push(`${name}: rule missing id/regex/files — skipped`);
          continue;
        }
        if (!r.clean_cases) warnings.push(`${name}#${r.id}: missing clean_cases note (required by the v1.6 DSL contract)`);
        rules.push({
          id: String(r.id).startsWith("ORG-") ? String(r.id) : `ORG-${r.id}`,
          severity: ["critical", "high", "medium", "low", "info"].includes(r.severity) ? r.severity : "medium",
          title: r.title ?? String(r.id),
          owasp: r.owasp ?? "A05",
          files: r.files,
          regex: r.regex,
          flags: r.flags ?? "gim",
          fix: r.fix ?? "Review this org-specific pattern and apply your team's standard fix.",
          clean_cases: r.clean_cases,
        });
      }
    } catch (e) {
      warnings.push(`${name}: invalid JSON (${e instanceof Error ? e.message : e})`);
    }
  }
  return { rules, warnings };
}

/** glob subset identical to CANDIDATE_PATTERNS loader semantics. */
function fileMatches(fPatterns: string[], abs: string, rel: string): boolean {
  const base = rel.split("/").pop() ?? "";
  for (let pat of fPatterns) {
    let p = pat;
    let anyDepth = false;
    if (p.startsWith("**/")) { anyDepth = true; p = p.slice(3); }
    const re = new RegExp("^" + p.split("*").map(escapeRe).join("[^/]*") + "$");
    if (re.test(base) || re.test(rel)) return true;
    if (anyDepth) {
      const tailRe = new RegExp("(^|/)" + re.source.slice(1, -1) + "$");
      if (tailRe.test(rel)) return true;
    }
  }
  return false;
}

function escapeRe(s: string): string {
  return s.replace(/[.+^${}()|[\]\\]/g, "\\$&");
}

export function runOrgRules(rules: OrgRule[], files: ScannedFile[]): Finding[] {
  const findings: Finding[] = [];
  for (const r of rules) {
    let re: RegExp;
    try { re = new RegExp(r.regex, r.flags ?? "gim"); } catch { continue; }
    for (const f of files) {
      if (!fileMatches(r.files, f.abs, f.rel)) continue;
      let m: RegExpExecArray | null;
      const local = new RegExp(re.source, re.flags);
      while ((m = local.exec(f.content)) !== null && findings.length < 2000) {
        const lineNo = f.content.slice(0, m.index).split("\n").length;
        const severity = r.severity === "critical" ? "critical" : r.severity;
        findings.push({
          id: r.id,
          severity,
          title: r.title,
          file: f.rel,
          line: lineNo,
          evidence: { type: "org-rule", masked: (m[0] ?? "").slice(0, 60) || r.id, note: r.clean_cases ? `clean case: ${r.clean_cases}` : undefined },
          owasp: r.owasp,
          confidence: severity === "critical" ? "medium" : "medium",
          fix: r.fix,
          fix_mode: "suggested-diff",
          verified: false,
          source: "org-rule",
          needs_confirmation: severity === "critical", // no-CRITICAL-without-confirmation law
          root: f.rel,
          root_cause: rootCause(r.id, f.rel),
          fingerprint: fingerprint(r.id, f.rel, (m[0] ?? "").slice(0, 60)),
          suppression: null,
        } as Finding);
        if (m[0] === "") local.lastIndex++;
      }
    }
  }
  return findings;
}
