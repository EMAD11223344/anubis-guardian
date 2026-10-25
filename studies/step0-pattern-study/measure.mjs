#!/usr/bin/env node
/**
 * Step 0 — Pattern-Frequency Study (Plan Section 11).
 * Measures how often each candidate pattern actually occurs across a sample of
 * projects. Usage:
 *   node studies/step0-pattern-study/measure.mjs <project-dir> [<project-dir> ...] [--out results.md]
 * The full 50–100 repo sweep (Lovable/Bolt/v0/Cursor builds) is an owner-run
 * collection step — this script is the measurement instrument, deterministic
 * and offline. It also powers the labeled recall corpus (v1.3): every project
 * scanned here is a corpus entry keyed by its findings.
 */
import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

// --- tiny YAML subset loader for CANDIDATE_PATTERNS.yaml (no deps) ---
function loadPatterns() {
  const raw = readFileSync(join(here, "CANDIDATE_PATTERNS.yaml"), "utf8");
  const out = [];
  let cur = null;
  const unquote = (v) => v.replace(/^["']|["']$/g, "");
  for (const line of raw.split("\n")) {
    if (/^  - id:/.test(line)) { if (cur) out.push(cur); cur = { id: line.split("id:")[1].trim() }; }
    else if (cur && /^    label:/.test(line)) cur.label = unquote(line.slice(line.indexOf("label:") + 6).trim());
    else if (cur && /^    regex:/.test(line)) {
      const v = unquote(line.slice(line.indexOf("regex:") + 6).trim());
      cur.regex = v === "null" ? null : v;
    } else if (cur && /^    files:/.test(line)) {
      cur.files = unquote(line.slice(line.indexOf("files:") + 6).trim()).split(",").map((s) => s.trim());
    } else if (cur && /^    note:/.test(line)) cur.note = unquote(line.slice(line.indexOf("note:") + 5).trim());
  }
  if (cur) out.push(cur);
  return out;
}

const SKIP = new Set(["node_modules", ".git", ".next", "dist", "build", "out", "coverage", ".venv"]);

function* walkFiles(root) {
  let entries = [];
  try { entries = readdirSync(root, { withFileTypes: true }); } catch { return; }
  for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const p = join(root, e.name);
    if (e.isDirectory()) { if (!SKIP.has(e.name)) yield* walkFiles(p); }
    else if (e.isFile()) yield p;
  }
}

function escapeRe(s) {
  return s.replace(/[.+^${}()|[\]\\]/g, "\\$&");
}

/** Glob subset: exact names, star basename/path wildcards, double-star any-depth prefix. */
function fileMatches(fPatterns, abs, rel) {
  const base = rel.split("/").pop();
  for (let pat of fPatterns) {
    let p = pat;
    let anyDepth = false;
    if (p.startsWith("**/")) { anyDepth = true; p = p.slice(3); }
    const re = new RegExp("^" + p.split("*").map(escapeRe).join("[^/]*") + "$");
    if (re.test(base)) return true;
    if (re.test(rel)) return true;
    if (anyDepth) {
      const tailRe = new RegExp("(^|/)" + re.source.slice(1, -1) + "$");
      if (tailRe.test(rel)) return true;
    }
  }
  return false;
}

function measureProject(root) {
  const patterns = loadPatterns();
  const counts = new Map(patterns.map((p) => [p.id, 0]));
  let fileCount = 0;

  for (const abs of walkFiles(root)) {
    const rel = relative(root, abs).split("\\").join("/");
    const name = rel.split("/").pop();
    fileCount++;
    for (const p of patterns) {
      if (p.regex === null) {
        // presence checks
        if (p.files.includes("git-history")) continue;
        if (p.files.some((f) => f === name || f === rel)) counts.set(p.id, counts.get(p.id) + 1);
        continue;
      }
      if (!fileMatches(p.files, abs, rel)) continue;
      let content;
      try { if (statSync(abs).size > 512 * 1024) continue; content = readFileSync(abs, "utf8"); } catch { continue; }
      let re;
      try { re = new RegExp(p.regex, "gim"); } catch { continue; }
      const hits = content.match(re);
      if (hits) counts.set(p.id, counts.get(p.id) + hits.length);
    }
  }

  // git history env check
  const hist = patterns.find((p) => p.files.includes("git-history"));
  if (hist && existsSync(join(root, ".git"))) {
    try {
      const out = execFileSync("git", ["log", "--all", "--diff-filter=A", "--name-only", "--pretty=format:"], { cwd: root, encoding: "utf8", maxBuffer: 16e6 });
      const envAdds = out.split("\n").map((l) => l.trim()).filter((l) => /^\.env(\..+)?$/.test(l) && !/\.(example|sample|template|development|dev)$/.test(l));
      if (envAdds.length) counts.set(hist.id, envAdds.length);
    } catch { /* not a repo */ }
  }

  return { root, fileCount, counts: Object.fromEntries(counts) };
}

// --- CLI ---
const args = process.argv.slice(2);
const outIdx = args.indexOf("--out");
const outFile = outIdx >= 0 ? args[outIdx + 1] : null;
if (outIdx >= 0) { args.splice(outIdx, 2); }
const jsonMode = args.includes("--json");
if (jsonMode) args.splice(args.indexOf("--json"), 1);
if (args.length === 0) {
  console.error("usage: node measure.mjs <project-dir> [...] [--json] [--out results.md]");
  process.exit(2);
}

const results = args.map(measureProject);

if (jsonMode) {
  const payload = { measured_at_commit: "step0", projects: results };
  const text = JSON.stringify(payload, null, 2);
  if (outFile) writeFileSync(outFile, text, "utf8");
  else console.log(text);
  process.exit(0);
}

const patterns = loadPatterns();

// --- aggregate table sorted by total frequency ---
const totals = patterns.map((p) => {
  const per = results.map((r) => r.counts[p.id] ?? 0);
  return { id: p.id, label: p.label, per, total: per.reduce((a, b) => a + b, 0) };
}).sort((a, b) => b.total - a.total);

let md = "# Step 0 — Pattern-Frequency Results\n\n";
md += `**Sample:** ${results.length} project(s) · ${results.map((r) => `${r.root} (${r.fileCount} files)`).join(" · ")}\n\n`;
md += "| Rank | Pattern | " + results.map((r, i) => `S${i + 1}`).join(" | ") + " | Total |\n";
md += "|---|---|" + results.map(() => "---").join("|") + "|---|\n";
totals.forEach((t, i) => {
  md += `| ${i + 1} | ${t.label} (\`${t.id}\`) | ${t.per.join(" | ")} | **${t.total}** |\n`;
});
md += "\n> Deterministic, offline measurement. Full owner-run sweep: 50–100 public AI-built projects (Lovable/Bolt/v0/Cursor) — collect with licenses respected, run this script per project, publish the aggregate table as launch material. This table decides final rule priority inside the already-frozen v0.1 scope (plan v1.5/v1.6).\n";

if (outFile) { writeFileSync(outFile, md, "utf8"); console.error(`written: ${outFile}`); }
else console.log(md);
