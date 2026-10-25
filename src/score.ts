import type { Finding, ScoreBreakdown, ScoreGroup, Severity } from "./types.js";
import { SEVERITY_WEIGHT } from "./types.js";
import { deducts } from "./util.js";

/**
 * Code Score /100 with root-cause caps (Plan Section 8, v1.3):
 * - deduction grouped by root_cause = (rule_id + root)
 * - first finding: full weight; each repeat: +10% of weight; group cap = 2× weight
 * - low-confidence findings NEVER deduct (they are review notes)
 * - INFO severity = 0 (documented-correct patterns)
 * Deterministic and recomputable from findings alone.
 */
export function computeScore(findings: Finding[]): ScoreBreakdown {
  const groups = new Map<string, ScoreGroup & { weight: number }>();

  for (const f of findings) {
    if (!deducts(f)) continue;
    const key = f.root_cause ?? `${f.id}:${f.file}:${f.line}`;
    const weight = SEVERITY_WEIGHT[f.severity as Severity] ?? 0;
    if (weight === 0) continue;
    const g = groups.get(key);
    if (g) {
      g.count += 1;
      if (weight > g.weight) g.weight = weight;
      if (severityRankOf(f.severity) < severityRankOf(g.severity)) g.severity = f.severity;
    } else {
      groups.set(key, {
        rule_id: f.id, root: f.root ?? f.file, severity: f.severity,
        count: 1, deducted: 0, weight,
      });
    }
  }

  const out: ScoreGroup[] = [];
  let total = 0;
  for (const g of groups.values()) {
    const raw = g.weight * (1 + 0.1 * (g.count - 1));
    const capped = Math.min(raw, 2 * g.weight);
    g.deducted = Math.round(capped * 100) / 100;
    total += g.deducted;
    out.push({
      rule_id: g.rule_id, root: g.root, severity: g.severity,
      count: g.count, deducted: Math.round(g.deducted * 100) / 100,
    });
  }
  out.sort((a, b) => b.deducted - a.deducted);

  const score = Math.max(0, Math.round(100 - total));
  return {
    base: 100,
    total_deducted: Math.round(total * 100) / 100,
    score,
    grade: gradeOf(score),
    groups: out,
    note: "Low-confidence findings and INFO do not deduct. Repeats of the same root cause add +10% each, capped at 2× the severity weight (v1.3).",
  };
}

function severityRankOf(s: Severity): number {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s];
}

export function gradeOf(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}
