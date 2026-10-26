import type { ScanResult, Finding } from "../types.js";
import { SEVERITY_ORDER } from "../types.js";

/**
 * Deterministic renderers over one canonical ScanResult (Output Contract, v1.4):
 * same findings.json → same terminal/report.md, byte for byte. No timestamps.
 */

const C = {
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  cyan: (s: string) => `\x1b[36m${s}\x1b[0m`,
  gray: (s: string) => `\x1b[90m${s}\x1b[0m`,
  bold: (s: string) => `\x1b[1m${s}\x1b[0m`,
};

const GRADE_COLOR: Record<string, (s: string) => string> = {
  A: C.green, B: C.green, C: C.yellow, D: C.yellow, F: C.red,
};

export const DISCLAIMER =
  "The grade reflects only the checks Anubis Guardian implements — absence of findings is not proof of security.";

const scoreLabel = (r: ScanResult): string => `${r.score ?? "N/A"}/100 (${r.grade})`;

export function renderTerminal(r: ScanResult): string {
  const L: string[] = [];
  const gradeC = GRADE_COLOR[r.grade] ?? C.cyan;
  const isUrl = r.target.mode === "url";
  L.push("");
  L.push(C.bold(`  Anubis Guardian v${r.version} — ${isUrl ? "URL Mode" : "Codebase Mode"}`));
  if (isUrl && r.url_meta) {
    const a = r.url_meta.authorization;
    L.push(C.gray(`  target: ${r.target.path} · level ${a.level} (${r.url_meta.levels_run.join(" + ")})`));
    L.push(C.gray(`  ownership: ${a.ownership_verified ? C.green(`verified via ${a.ownership_method}`) : a.ownership_method === "none" ? "none (Level 1 — passive)" : C.yellow(a.ownership_method)} · scan authorized: ${a.timestamp}`));
    L.push("");
    L.push(`  Score: ${gradeC(C.bold(scoreLabel(r)))}   ` +
      C.gray(`checks ${r.coverage.checks_run}/${r.coverage.checks_applicable} · requests ${r.url_meta.requests.total}${r.url_meta.robots.skipped_paths.length ? ` · robots-skipped ${r.url_meta.robots.skipped_paths.length}` : ""}`));
  } else {
    L.push(C.gray(`  target: ${r.target.path} · stack: ${r.target.stack.join(", ") || "unknown"}`));
    L.push("");
    L.push(`  Score: ${gradeC(C.bold(scoreLabel(r)))}   ` +
      C.gray(`checks ${r.coverage.checks_run}/${r.coverage.checks_applicable} · files ${r.meta.files_scanned} · git history ${r.meta.git_history_scanned ? "scanned" : "not a repo"}`));
    // v1.2 (T7) coverage honesty: skipped files make the report PARTIAL — never
    // let it look complete. Warned here and recorded in meta + SARIF properties.
    const sk = r.meta.files_skipped;
    if (sk) {
      L.push(C.yellow(`  ⚠ coverage partial: ${[sk.oversize ? `${sk.oversize} oversize (>512KB) files skipped` : null, sk.binary ? `${sk.binary} binary files skipped` : null, sk.unreadable ? `${sk.unreadable} unreadable files skipped` : null].filter(Boolean).join(" · ")}`));
    }
    // v1.2 (T14) dependency-recall honesty: the bundled advisory snapshot is a
    // point-in-time resource — stale snapshots under-report known CVEs.
    if (r.meta.advisory_snapshot_stale) {
      const d = r.meta.advisory_snapshot_date;
      const age = d ? ` (snapshot ${d}, > 90 days old)` : "";
      L.push(C.yellow(`  ⚠ advisory snapshot is stale${age} — re-run "anubis-guardian update-advisories" or fetch a newer release; results can silently miss recent CVEs`));
    }
  }
  L.push("");
  L.push(`  ${C.red(`CRITICAL ${r.summary.critical}`)}  ${C.red(`HIGH ${r.summary.high}`)}  ${C.yellow(`MEDIUM ${r.summary.medium}`)}  ${C.gray(`LOW ${r.summary.low}`)}  ${C.cyan(`INFO ${r.summary.info}`)}`);
  L.push("");

  if (r.findings.length === 0) {
    L.push(C.green("  No findings from the checks this version implements."));
    L.push("");
    L.push(C.gray(`  ${DISCLAIMER}`));
    return L.join("\n");
  }

  const bySeverity = new Map<string, Finding[]>();
  for (const f of r.findings) {
    if (!bySeverity.has(f.severity)) bySeverity.set(f.severity, []);
    bySeverity.get(f.severity)!.push(f);
  }

  const icons: Record<string, string> = { critical: "⛔", high: "🔺", medium: "🔸", low: "▫️ ", info: "ℹ️ " };
  for (const sev of SEVERITY_ORDER) {
    const list = bySeverity.get(sev);
    if (!list?.length) continue;
    L.push(C.bold(`  ${icons[sev]} ${sev.toUpperCase()} (${list.length})`));
    for (const f of list) {
      const loc = f.line > 0 ? `${f.file}:${f.line}` : f.file;
      const sup = f.suppression ? C.gray(` [suppressed: ${f.suppression.reason} → ${f.suppression.expires}]`) : "";
      L.push(`    ${sev === "critical" ? C.red(f.id) : sev === "high" ? C.red(f.id) : sev === "medium" ? C.yellow(f.id) : C.gray(f.id)}  ${C.bold(f.title)}`);
      L.push(`      ${C.gray(loc)}${sup}`);
      if (f.evidence.masked) L.push(`      ${C.gray(`evidence: ${f.evidence.masked}`)}`);
      if (f.needs_confirmation) L.push(`      ${C.yellow("needs confirmation — severity may rise after verification")}`);
      L.push(`      ${C.cyan("fix:")} ${f.fix}`);
      if (f.remediation?.type === "rotate-first") {
        L.push(`      ${C.red("rotate-first:")} ${f.remediation.steps}`);
        if (f.remediation.history_cleanup) L.push(`      ${C.gray(f.remediation.history_cleanup)}`);
      }
    }
    L.push("");
  }

  L.push(C.gray("  Classes not covered by this version:"));
  for (const cls of r.coverage.classes_not_covered) L.push(C.gray(`    - ${cls}`));
  L.push("");
  L.push(C.gray(`  ${DISCLAIMER}`));
  L.push(C.gray(isUrl
    ? "  No probing beyond the authorized level · no credentialed scanning · authorization record in findings.json (url_meta.authorization)."
    : "  No project code was executed (install/build/tests) — static scan only (Section 9.7)."));
  L.push("");
  return L.join("\n");
}

export function renderMarkdown(r: ScanResult): string {
  const L: string[] = [];
  const isUrl = r.target.mode === "url";
  L.push(`# Anubis Guardian Report — \`${r.target.path}\``);
  L.push("");
  L.push(`**Score: ${r.score ?? "N/A"}/100 (${r.grade})** · tool v${r.version} · advisory snapshot \`${r.advisory_snapshot}\``);
  L.push("");
  L.push(`| CRITICAL | HIGH | MEDIUM | LOW | INFO |`);
  L.push(`|---|---|---|---|---|`);
  L.push(`| ${r.summary.critical} | ${r.summary.high} | ${r.summary.medium} | ${r.summary.low} | ${r.summary.info} |`);
  L.push("");
  if (isUrl && r.url_meta) {
    const a = r.url_meta.authorization;
    L.push(`## Scan authorization record`);
    L.push("");
    L.push(`| Field | Value |`);
    L.push(`|---|---|`);
    L.push(`| Target | \`${a.url}\` |`);
    L.push(`| Timestamp | ${a.timestamp} |`);
    L.push(`| Level | ${a.level} (${r.url_meta.levels_run.join(" + ")}) |`);
    L.push(`| Ownership | **${a.ownership_method}**${a.ownership_verified ? " (verified)" : ""} |`);
    L.push(`| Requests | ${r.url_meta.requests.total} (${Object.entries(r.url_meta.requests.by_method).map(([m, c]) => `${m}:${c}`).join(", ")}) |`);
    if (r.url_meta.robots.skipped_paths.length) L.push(`| robots-skipped paths | ${r.url_meta.robots.skipped_paths.join(", ")} |`);
    L.push("");
    L.push(`_${a.note}_`);
    L.push("");
    L.push(`**Stack (fingerprinted):** ${r.target.stack.join(", ") || "unknown"} · **Requests:** ${r.meta.files_scanned}`);
  } else {
    L.push(`**Stack:** ${r.target.stack.join(", ") || "unknown"} · **Files scanned:** ${r.meta.files_scanned} · **Git history:** ${r.meta.git_history_scanned ? "scanned" : "not a git repo"}`);
  }
  L.push("");
  L.push(`## Score breakdown (root-cause caps)`);
  L.push("");
  if (r.score_breakdown.groups.length === 0) {
    L.push("_No deductions._");
  } else {
    L.push(`| Rule | Root | Severity | Count | Deducted |`);
    L.push(`|---|---|---|---|---|`);
    for (const g of r.score_breakdown.groups) {
      L.push(`| ${g.rule_id} | \`${g.root}\` | ${g.severity} | ${g.count} | −${g.deducted} |`);
    }
  }
  L.push("");
  L.push(`> ${r.score_breakdown.note}`);
  L.push("");

  const visible = r.findings.filter((f) => f.severity !== "info");
  if (visible.length) {
    L.push(`## Findings (${visible.length})`);
    L.push("");
    for (const sev of SEVERITY_ORDER) {
      const list = visible.filter((f) => f.severity === sev);
      if (!list.length) continue;
      L.push(`### ${sev.toUpperCase()} (${list.length})`);
      L.push("");
      for (const f of list) {
        const loc = f.line > 0 ? `${f.file}:${f.line}` : f.file;
        L.push(`#### ${f.id} — ${f.title}`);
        L.push("");
        L.push(`- **Location:** \`${loc}\``);
        L.push(`- **Evidence (masked):** \`${f.evidence.masked}\``);
        L.push(`- **OWASP:** ${f.owasp} · **Confidence:** ${f.confidence}${f.needs_confirmation ? " · ⚠️ needs confirmation" : ""}`);
        L.push(`- **Fingerprint:** \`${f.fingerprint}\`${f.suppression ? ` · **Suppressed:** ${f.suppression.reason} → ${f.suppression.expires}` : ""}`);
        L.push(`- **Fix:** ${f.fix}`);
        if (f.remediation?.type === "rotate-first") {
          L.push(`- **Rotate-first:** ${f.remediation.steps}`);
          if (f.remediation.history_cleanup) L.push(`- **History cleanup:** ${f.remediation.history_cleanup}`);
        }
        L.push("");
      }
    }
  } else {
    L.push(`## Findings`);
    L.push("");
    L.push("_No findings from the checks this version implements._");
    L.push("");
  }

  const infos = r.findings.filter((f) => f.severity === "info");
  if (infos.length) {
    L.push(`### INFO (documented-correct patterns — verify env hygiene)`);
    L.push("");
    for (const f of infos) {
      L.push(`- \`${f.file}:${f.line}\` — ${f.title}`);
    }
    L.push("");
  }

  L.push(`## Classes not covered`);
  L.push("");
  for (const cls of r.coverage.classes_not_covered) L.push(`- ${cls}`);
  L.push("");
  L.push(`---`);
  L.push("");
  L.push(`_${DISCLAIMER}_`);
  L.push("");
  L.push(isUrl
    ? `_Black-box external view only — pair with Codebase Mode (anubis-guardian scan .) for the code-level view. No probing beyond the authorized level; no credentialed scanning; authorization record above._`
    : `_No project code was executed (install/build/tests) — static scan only (Anubis Guardian Section 9.7)._`);
  return L.join("\n");
}
