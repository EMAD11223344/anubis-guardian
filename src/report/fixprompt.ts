import type { ScanResult } from "../types.js";

/**
 * fix-prompt.md renderer (Plan Section 8 Output Contract — v1.4; shipped v0.2).
 * A deterministic PROMPT (not an LLM product): ranked findings + verification
 * steps + guardrails. Byte-stable for the same findings.json (v0.2 acceptance).
 */

const SEV_LABEL: Record<string, string> = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", info: "INFO" };

const GUARDRAILS = [
  "## Guardrails (hard rules for the fixing agent)",
  "1. Secrets: NEVER touch code that prints/uses a secret before rotating it. Rotate the credential FIRST (provider dashboard), then update the code, then scrub history (git filter-repo).",
  "2. Scope: fix ONLY the findings listed here. No refactoring, no dependency upgrades, no style changes outside the flagged lines.",
  "3. Tests: do NOT edit, skip, or weaken tests to make a fix pass. Add a regression test only when the finding requires one.",
  "4. Confirmation findings: items marked [needs confirmation] must be verified by a human (or an owner-run probe) before treating them as exploitable.",
  "5. Output: propose a suggested diff per finding — apply nothing automatically.",
].join("\n");

export function renderFixPrompt(result: ScanResult): string {
  const f = result.findings.filter((x) => x.suppression === null);
  const order = ["critical", "high", "medium", "low", "info"];
  const ranked = [...f].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity) || a.file.localeCompare(b.file) || a.line - b.line);

  const isUrl = result.target.mode === "url";
  const lines: string[] = [];
  lines.push("# Anubis Guardian — Fix Prompt");
  lines.push("");
  lines.push(`> Generated deterministically from findings.json (anubis-guardian ${result.version}).`);
  lines.push(`> Target: \`${result.target.path}\` · Score: **${result.score}/100 (${result.grade})** · Findings: ${ranked.length} (C:${result.summary.critical} H:${result.summary.high} M:${result.summary.medium} L:${result.summary.low} I:${result.summary.info})`);
  if (isUrl && result.url_meta) {
    const a = result.url_meta.authorization;
    lines.push(`> URL Mode · level ${a.level} · ownership: **${a.ownership_method}**${a.ownership_verified ? " (verified)" : ""} · scan authorized: ${a.timestamp}`);
  }
  if (result.portfolio?.length) {
    lines.push(`> Portfolio: ${result.portfolio.map((p) => `${p.path} ${p.score}/100`).join(" · ")}`);
  }
  lines.push("");
  if (isUrl) {
    lines.push("This report is a black-box EXTERNAL view (no source access). For every finding: first MAP the flagged URL/endpoint to the code (the evidence + the `Code map:` hint in each fix), verify it, then fix and redeploy; re-run this URL scan to confirm.");
  } else {
    lines.push("Fix the following findings, highest severity first. For each item: read the flagged location, verify it is real, then propose a minimal fix (suggested diff).");
  }
  lines.push("");

  if (ranked.length === 0) {
    lines.push("No open findings — nothing to fix in this run.");
    lines.push("");
  }

  let n = 0;
  for (const x of ranked) {
    n++;
    lines.push(`## ${n}. [${SEV_LABEL[x.severity]}] ${x.id} — ${x.title}`);
    lines.push(`- Location: \`${x.file}:${x.line}\``);
    lines.push(`- Evidence: ${x.evidence.masked}${x.evidence.note ? ` — ${x.evidence.note}` : ""}`);
    if (x.needs_confirmation) lines.push(`- ⚠️ [needs confirmation] — verify before treating as exploitable (deterministic hint only).`);
    lines.push(`- Fix: ${x.fix}`);
    if (x.remediation?.steps) lines.push(`- Remediation: ${x.remediation.steps}${x.remediation.history_cleanup ? ` History: ${x.remediation.history_cleanup}` : ""}`);
    lines.push(`- Verify: ${isUrl
      ? `re-run \`npx anubis-guardian scan-url ${result.target.path}\` (same level) and confirm the finding is gone and the score moves.`
      : `re-run \`npx anubis-guardian scan ${result.target.path}\` and confirm the finding is gone and the score moves.`}`);
    lines.push("");
  }

  lines.push("");
  lines.push(GUARDRAILS);
  lines.push("");
  if (result.coverage.classes_not_covered.length) {
    lines.push("## Not covered by this scan (do not assume absence of risk)");
    for (const c of result.coverage.classes_not_covered) lines.push(`- ${c}`);
    lines.push("");
  }

  return lines.join("\n");
}
