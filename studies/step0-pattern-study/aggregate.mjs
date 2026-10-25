#!/usr/bin/env node
/**
 * Step 0 sweep — aggregator.
 * Reads out/sweep.json (produced by: node measure.mjs <dir...> --json --out out/sweep.json)
 * plus clone-list.json metadata, writes the final RESULTS.md (launch material).
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join, basename } from "node:path";

const here = new URL(".", import.meta.url).pathname;
const sweep = JSON.parse(readFileSync(join(here, "out", "sweep.json"), "utf8"));
const meta = JSON.parse(readFileSync(join(here, "clone-list.json"), "utf8"));
const metaByName = new Map(meta.map((m) => [m.full_name.replace("/", "__"), m]));

const N = sweep.projects.length;
const patternIds = Object.keys(sweep.projects[0].counts);
const patterns = JSON.parse(readFileSync(join(here, "out", "patterns.json"), "utf8")); // [{id,label}]
const labelOf = new Map(patterns.map((p) => [p.id, p.label]));

// per-pattern aggregates + per-population split
const rows = patternIds.map((id) => {
  let total = 0, projAffected = 0, aiTotal = 0, stackTotal = 0, aiAffected = 0, stackAffected = 0;
  for (const p of sweep.projects) {
    const c = p.counts[id] ?? 0;
    total += c;
    if (c > 0) projAffected++;
    const m = metaByName.get(basename(p.root));
    if (m?.pop === "ai-built") { aiTotal += c; if (c > 0) aiAffected++; }
    else { stackTotal += c; if (c > 0) stackAffected++; }
  }
  return { id, label: labelOf.get(id) ?? id, total, projAffected, aiTotal, aiAffected, stackTotal, stackAffected };
}).sort((a, b) => b.projAffected - a.projAffected || b.total - a.total);

const totalFiles = sweep.projects.reduce((a, p) => a + p.fileCount, 0);
const aiN = meta.filter((m) => m.pop === "ai-built").length;
const stackN = meta.filter((m) => m.pop === "ai-stack").length;
const tagCounts = {};
for (const m of meta) for (const t of m.tags) tagCounts[t] = (tagCounts[t] ?? 0) + 1;

let md = `# Step 0 — Pattern-Frequency Results (Full Sweep)

**Sample:** ${N} public project(s) (${totalFiles.toLocaleString("en")} source files measured) · collected ${new Date().toISOString().slice(0, 10)} · GitHub search API (queries documented below) · shallow clones (depth 1)
**Population:** ${aiN} AI-tool-built (lovable/bolt/cursor/claude/windsurf/vibe signals) + ${stackN} AI-default-stack (Next.js+Supabase) · tags: ${Object.entries(tagCounts).map(([t, c]) => `${t}=${c}`).join(" · ")}

> **منهجية القياس:** عدّاد grep حتمي offline — كل رقم هو **تكرار النمط النصي** مش حكم أمني مُتحقق منه؛ الأنماط "leads" بتحدد أولوية الـ rule packs، والقياس الفعلي بيحصل جوه المحرك بقواعده الكاملة + clean-cases. الـ history check معطّل فعليًا في الاستنساخ الضحل (depth 1) — env_in_git_history هنا أقل من الواقع.

| Rank | Pattern | Projects affected | % of sample | Total hits | AI-built (${aiN}) | Stack (${stackN}) |
|---|---|---|---|---|---|---|
`;
rows.forEach((r, i) => {
  md += `| ${i + 1} | ${r.label} (\`${r.id}\`) | ${r.projAffected}/${N} | **${((r.projAffected / N) * 100).toFixed(0)}%** | ${r.total} | ${r.aiAffected}/${r.aiTotal} | ${r.stackAffected}/${r.stackTotal} |\n`;
});

md += `\n## Selection protocol (reproducible)\n\n- GitHub search API, unauthenticated, ${new Date().toISOString().slice(0, 10)} — filters: not a fork · size ≤ 20 MB · per_page=80/query · smallest-first cloning · queries:\n`;
md += JSON.parse(readFileSync(join(here, "candidates.json"), "utf8")).queries.map((q) => `  - \`${q}\``).join("\n") + "\n";
md += `\n## Per-project appendix\n\n| Project | Population | Files | Dominant signal |\n|---|---|---|---|\n`;
for (const p of [...sweep.projects].sort((a, b) => b.fileCount - a.fileCount)) {
  const name = basename(p.root);
  const m = metaByName.get(name) ?? {};
  const top = Object.entries(p.counts).filter(([, c]) => c > 0).sort((a, b) => b[1] - a[1]).slice(0, 2)
    .map(([id, c]) => `${id}:${c}`).join(" ") || "—";
  md += `| ${m.url ? `[${m.full_name}](${m.url})` : name} | ${m.pop ?? "?"} | ${p.fileCount} | ${top} |\n`;
}

writeFileSync(join(here, "out", "RESULTS-sweep.md"), md);
// machine-readable totals for the plan/decision log
writeFileSync(join(here, "out", "totals.json"), JSON.stringify({ N, aiN, stackN, totalFiles, rows }, null, 2));
console.error(`written: out/RESULTS-sweep.md + out/totals.json — ${N} projects, ${rows.filter(r => r.projAffected > 0).length} patterns observed`);
