#!/usr/bin/env node
/**
 * v1.2 (T14) — Advisory snapshot builder (OSV.dev, npm ecosystem).
 *
 * UPSTREAM : https://api.osv.dev/v1/query  (POST) + /v1/vulns/{id} (GET)
 * POLICY   : v1.2 bundles ALL npm advisories of severity MODERATE and above
 *            (v1.1 bundled HIGH/CRITICAL only — moderate transitive CVEs were
 *            a review gap). Max 60 advisories per package. The bundled file is
 *            a committed build artifact — scanning stays offline + deterministic.
 *
 * Usage:
 *   node scripts/build-advisory-snapshot.mjs
 *       Refresh every package currently in the bundle (default target list =
 *       bundled packages + POPULAR names parsed from src/advisory/popular.ts).
 *   node scripts/build-advisory-snapshot.mjs --pkg express --pkg handlebars
 *       Merge only the listed packages into the current bundle.
 *   node scripts/build-advisory-snapshot.mjs --full
 *       FULL npm ecosystem via the OSV npm dump (osv-vulnerabilities npm/all.zip
 *       streamed, extracted with bsdtar/tar, filtered to moderate+). Large.
 *
 * The script MERGES with the committed snapshot (advisories for packages that
 * fail to resolve are KEPT, never lost), then rewrites src/advisory/snapshot.ts
 * in the same stable, pretty-printed, name-sorted shape.
 */
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync, readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";

const OSV_API = "https://api.osv.dev/v1";
const SNAPSHOT_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "advisory", "snapshot.ts");
const POPULAR_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "advisory", "popular.ts");
const MAX_ADVISORIES_PER_PACKAGE = 60;
const STAMP = new Date().toISOString().slice(0, 7); // YYYY-MM

const args = [];
for (let i = 2; i < process.argv.length; i++) args.push(process.argv[i]);
const pkgs = [];
while (args.indexOf("--pkg") !== -1) {
  const at = args.indexOf("--pkg");
  pkgs.push(args[at + 1]);
  args.splice(at, 2);
}
const FULL = args.includes("--full");

function loadCurrent() {
  const src = readFileSync(SNAPSHOT_PATH, "utf8");
  // skip the TYPE ANNOTATION braces — find the `= {` that starts the object
  const eq = src.indexOf("= {", src.indexOf("export const SNAPSHOT"));
  const start = src.indexOf("{", eq);
  // brace-walk to the SNAPSHOT object's own closing `}` — the file continues
  // with other exports (ACTION_PINS) that must survive the rebuild verbatim
  let depth = 0;
  let end = -1;
  for (let i = start; i < src.length; i++) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) { end = i; break; }
    }
  }
  if (end === -1) throw new Error("cannot locate the SNAPSHOT object's closing brace");
  return { snapshot: JSON.parse(src.slice(start, end + 1)), trailing: src.slice(end + 1) };
}

function popularNames() {
  try {
    const src = readFileSync(POPULAR_PATH, "utf8");
    const t = src.slice(src.indexOf("`") + 1, src.lastIndexOf("`"));
    return t.split(/\s+/).filter((s) => /^[@a-z][\w/.-]*$/i.test(s));
  } catch {
    return [];
  }
}

/** OSV severity normalize → moderate | high | critical, else null (policy: below moderate) */
function severityOf(vuln) {
  const ds = vuln.database_specific?.severity;
  if (ds) {
    const up = String(ds).toUpperCase();
    if (up === "MODERATE" || up === "MEDIUM") return "moderate";
    if (up === "HIGH") return "high";
    if (up === "CRITICAL") return "critical";
  }
  const sevArr = Array.isArray(vuln.severity) ? vuln.severity : vuln.severities ?? (vuln.severity ? [vuln.severity] : []);
  for (const sev of sevArr) {
    if ((sev?.type === "CVSS_V3" || sev?.type === "CVSS_V4") && typeof sev.score === "string") {
      // score may be a plain number ("7.5") or a full CVSS vector — parse the leading number
      const num = parseFloat(sev.score);
      if (!Number.isNaN(num) && /^\d/.test(sev.score.trim())) {
        return num >= 9 ? "critical" : num >= 7 ? "high" : num >= 4 ? "moderate" : null;
      }
    }
    const up2 = String(sev?.severity ?? sev?.type ?? "").toUpperCase();
    if (up2 === "MODERATE" || up2 === "MEDIUM") return "moderate";
    if (up2 === "HIGH") return "high";
    if (up2 === "CRITICAL") return "critical";
  }
  return null; // LOW / n/a — policy says moderate+
}

/** reduce one OSV vuln to the bundled Advisory shape (npm ranges only) */
function toAdvisory(vuln) {
  const ranges = [];
  let fixedHint;
  for (const aff of vuln.affected ?? []) {
    const pkg = aff.package ?? {};
    if (pkg.ecosystem !== "npm" || pkg.name !== vulnIDName) continue;
    for (const r of aff.ranges ?? []) {
      if (r.type !== "ECOSYSTEM" && r.type !== "SEMVER") continue;
      const events = r.events ?? [];
      ranges.push({ events });
      const fx = events.find((e) => "fixed" in e);
      if (fx) fixedHint ??= fx.fixed;
    }
  }
  if (!ranges.length) return null;
  const sev = severityOf(vuln);
  if (!sev) return null;
  return {
    id: vuln.id,
    aliases: (vuln.aliases ?? []).filter((a) => a.startsWith("CVE") || a.startsWith("GHSA")),
    severity: sev,
    summary: (vuln.summary || vuln.details || "").split("\n")[0].slice(0, 200),
    ranges,
    fixed_hint: fixedHint,
  };
}

let vulnIDName = ""; // package being merged (set by fetch — OSV name field may differ)

async function fetchPackage(name) {
  const q = await fetch(`${OSV_API}/query`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ package: { name, ecosystem: "npm" } }),
  });
  if (!q.ok) throw new Error(`query ${name}: HTTP ${q.status}`);
  const { vulns } = await q.json();
  const list = vulns ?? [];
  const out = [];
  let creator = 0;
  for (const v of list) {
    if (out.length >= MAX_ADVISORIES_PER_PACKAGE) break;
    const r = await fetch(`${OSV_API}/vulns/${encodeURIComponent(v.id)}`);
    if (!r.ok) continue;
    vulnIDName = name;
    try {
      const a = toAdvisory(await r.json());
      if (a) out.push(a);
    } catch { /* malformed advisory — skip */ }
    creator++;
  }
  return out;
}

const SEV_RANK = { critical: 0, high: 1, moderate: 2 };

function mergeAdvisories(existing, fresh) {
  const map = new Map();
  for (const a of existing ?? []) map.set(a.id, a);
  for (const a of fresh) map.set(a.id, a);
  return [...map.values()]
    .sort((x, y) => (SEV_RANK[x.severity] ?? 3) - (SEV_RANK[y.severity] ?? 3) || x.id.localeCompare(y.id))
    .slice(0, MAX_ADVISORIES_PER_PACKAGE);
}

async function main() {
  const { snapshot: current, trailing } = loadCurrent();
  const snapshot = {
    snapshot_date: STAMP,
    source: "OSV.dev (api.osv.dev) — fetched at build time, bundled per tool release for determinism",
    policy: "npm advisories MODERATE and above (v1.2), ECOSYSTEM/SEMVER ranges, max 60 per package",
    packages: 0,
    advisories: {},
    known_malicious: current.known_malicious ?? {},
  };

  // start from the CURRENT bundle — targets are merged in place, nothing is lost
  snapshot.advisories = { ...current.advisories };
  let targets;
  if (FULL) {
    targets = await dumpFull(snapshot);
    console.log(`--full: ${targets} advisories parsed from the npm dump — merging with existing bundle`);
  } else if (pkgs.length) {
    targets = pkgs;
    console.log(`merging: ${targets.join(", ")}`);
  } else {
    targets = [...new Set([...Object.keys(current.advisories ?? {}), ...popularNames()])].sort((a, b) => a.localeCompare(b));
    console.log(`refreshing ${targets.length} packages (bundle + POPULAR list)`);
  }

  const failures = [];
  for (const name of targets) {
    let fresh = [];
    try {
      fresh = await fetchPackage(name);
    } catch (e) {
      failures.push(`${name}: ${String(e.message || e)}`);
    }
    snapshot.advisories[name] = mergeAdvisories(current.advisories?.[name], fresh);
    process.stdout.write(`  ${snapshot.advisories[name].length.toString().padStart(3)}  ${name}${fresh.length ? ` (+${fresh.length} refreshed)` : " (kept)"}\n`);
  }

  snapshot.packages = Object.keys(snapshot.advisories).length;

  const header =
    `// AUTO-GENERATED from OSV.dev (${STAMP}) — do not edit by hand.\n` +
    `// Rebuild via scripts/build-advisory-snapshot.mjs (real advisories, bundled per tool release).\n` +
    `// v1.2 policy: npm advisories MODERATE and above, max 60 per package (T14 dependency recall).\n\n` +
    `export interface Advisory { id: string; aliases?: string[]; severity: string; summary: string; ranges: Array<{ events: Array<Record<string, string>> }>; fixed_hint?: string }\n\n` +
    `export const SNAPSHOT: { snapshot_date: string; source: string; policy: string; packages: number; advisories: Record<string, Advisory[]>; known_malicious: Record<string, Advisory[]> } = `;

  writeFileSync(SNAPSHOT_PATH, header + JSON.stringify(snapshot, null, 2) + ";" + trailing);
  console.log(`\nwritten: ${SNAPSHOT_PATH} (${snapshot.packages} packages)`);
  if (failures.length) {
    console.log(`\n${failures.length} package(s) failed to refresh (their bundled advisories were KEPT):`);
    for (const f of failures) console.log(`  - ${f}`);
  }
}

/** --full: stream the OSV npm ecosystem dump (zip), extract with bsdtar, filter moderate+ */
async function dumpFull(snapshot) {
  const dir = join(tmpdir(), `anubis-osv-dump-${process.pid}`);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const zip = join(dir, "npm-all.zip");
  console.log("streaming OSV npm dump (all.zip) — this is large…");
  const ok = await fetchDumpTo("https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip", zip);
  if (!ok) throw new Error("dump download failed");
  execFileSync("tar", ["-xf", zip, "-C", dir], { stdio: "ignore" });
  rmSync(zip, { force: true });
  let count = 0;
  for (const f of readdirSync(dir, { recursive: true })) {
    if (!String(f).endsWith(".json")) continue;
    try {
      const vuln = JSON.parse(readFileSync(join(dir, String(f)), "utf8"));
      const sev = severityOf(vuln);
      if (!sev) continue;
      const a = toAdvisoryFileDump(vuln);
      if (!a) continue;
      const pkg = a.__pkg;
      delete a.__pkg;
      (snapshot.advisories[pkg] ??= []).push(a);
      count++;
    } catch { /* skip malformed */ }
  }
  // cap + sort every package's advisory list (same policy as query mode)
  for (const name of Object.keys(snapshot.advisories)) {
    snapshot.advisories[name] = mergeAdvisories(snapshot.advisories[name], []);
  }
  return count;
}

function toAdvisoryFileDump(vuln) {
  for (const aff of vuln.affected ?? []) {
    if (aff.package?.ecosystem !== "npm") continue;
    const ranges = [];
    let fixedHint;
    for (const r of aff.ranges ?? []) {
      if (r.type !== "ECOSYSTEM" && r.type !== "SEMVER") continue;
      ranges.push({ events: r.events ?? [] });
      const fx = (r.events ?? []).find((e) => "fixed" in e);
      if (fx) fixedHint ??= fx.fixed;
    }
    if (!ranges.length) continue;
    return {
      id: vuln.id,
      aliases: (vuln.aliases ?? []).filter((a) => a.startsWith("CVE") || a.startsWith("GHSA")),
      severity: severityOf(vuln),
      summary: (vuln.summary || vuln.details || "").split("\n")[0].slice(0, 200),
      ranges,
      fixed_hint: fixedHint,
      __pkg: aff.package.name,
    };
  }
  return null;
}

function fetchDumpTo(url, dest) {
  return fetch(url)
    .then(async (r) => {
      if (!r.ok) return false;
      writeFileSync(dest, Buffer.from(await r.arrayBuffer()));
      return true;
    })
    .catch(() => false);
}

main().catch((e) => {
  console.error(`snapshot build failed: ${e.message || e}`);
  process.exit(1);
});
