#!/usr/bin/env node
/**
 * Step 0 sweep — candidate collector.
 * Queries the GitHub search API (unauthenticated, 10 req/min) for projects
 * built with AI coding tools (Lovable / Bolt / v0 / Cursor / Claude Code /
 * Windsurf / Copilot) + the default AI stack (Next.js + Supabase).
 * Writes candidates.json — the deduplicated, filtered sample frame.
 *
 * Selection protocol (documented for reproducibility):
 *   - signals: platform/tool keywords in name/description/readme
 *   - filters: not a fork · size <= 20 MB · pushed within 18 months
 *   - language: typescript (primary) / javascript (secondary) balance
 */
import { writeFileSync, readFileSync, existsSync } from "node:fs";

const QUERIES = [
  // platform-built apps (primary AI-build signals)
  { q: "lovable in:name,description,readme language:typescript", tag: "lovable" },
  { q: "lovable.dev in:readme language:javascript", tag: "lovable" },
  { q: "bolt.new in:name,description,readme", tag: "bolt" },
  { q: "built with v0 in:readme language:typescript", tag: "v0" },
  { q: "cursorrules in:name,description", tag: "cursor" },
  { q: "vibe coding language:typescript", tag: "vibe" },
  { q: "generated with claude in:readme", tag: "claude" },
  { q: "windsurf in:readme language:typescript", tag: "windsurf" },
  // default AI stack (secondary population)
  { q: "supabase nextjs app language:typescript pushed:>2025-06-01", tag: "stack" },
  { q: "supabase nextjs dashboard language:javascript pushed:>2025-06-01", tag: "stack" },
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function search(q) {
  const url = `https://api.github.com/search/repositories?q=${encodeURIComponent(q)}&sort=updated&order=desc&per_page=80`;
  const res = await fetch(url, {
    headers: { Accept: "application/vnd.github+json", "User-Agent": "anubis-step0-sweep" },
  });
  if (!res.ok) {
    console.error(`  ! HTTP ${res.status} for: ${q}`);
    const body = await res.text().catch(() => "");
    if (body.includes("rate limit")) throw new Error("rate-limited");
    return [];
  }
  const data = await res.json();
  return data.items ?? [];
}

const outPath = new URL("./candidates.json", import.meta.url).pathname;
const seen = new Map();
let qn = 0;

for (const { q, tag } of QUERIES) {
  qn++;
  console.error(`[${qn}/${QUERIES.length}] ${q}`);
  let items = [];
  try { items = await search(q); } catch (e) { console.error(`  ! ${e.message}`); await sleep(30000); }
  let kept = 0;
  for (const r of items) {
    if (r.fork) continue;
    if ((r.size ?? 0) > 20480) continue; // 20 MB cap → fast shallow clones
    if (seen.has(r.full_name)) { seen.get(r.full_name).tags.push(tag); continue; }
    seen.set(r.full_name, {
      full_name: r.full_name,
      url: r.html_url,
      clone: r.clone_url,
      description: (r.description ?? "").slice(0, 140),
      size_kb: r.size,
      stars: r.stargazers_count,
      license: r.license?.spdx_id ?? "none",
      pushed_at: r.pushed_at,
      language: r.language,
      tags: [tag],
    });
    kept++;
  }
  console.error(`  + ${items.length} results, ${kept} new (total ${seen.size})`);
  await sleep(7000); // search API: 10 req/min unauthenticated
}

const candidates = [...seen.values()];
writeFileSync(outPath, JSON.stringify({ collected: new Date().toISOString().slice(0, 10), queries: QUERIES.map((x) => x.q), candidates }, null, 2));
console.error(`written: ${outPath} — ${candidates.length} candidates`);
