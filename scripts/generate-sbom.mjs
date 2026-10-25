#!/usr/bin/env node
/**
 * v1.0 — CycloneDX 1.5 SBOM generator (Plan Section 9.6: "SBOM (CycloneDX)
 * generated with every release — so users of the tool itself can monitor its
 * dependencies"). Zero extra dependencies: reads package-lock.json + hashes
 * the dist artifacts. Deterministic except the ISO timestamp, which is the
 * release build instant (SBOMs describe a build, not a source tree).
 *
 * Usage: node scripts/generate-sbom.mjs [out=anubis-guardian-<version>.cdx.json]
 */
import { readFileSync, writeFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const lockPath = join(root, "package-lock.json");

if (!existsSync(lockPath)) {
  console.error("generate-sbom: package-lock.json not found — run npm install first");
  process.exit(2);
}
const lock = JSON.parse(readFileSync(lockPath, "utf8"));

const purl = (name, version) => `pkg:npm/${encodeURIComponent(name)}@${version}`;
const components = [];

// lockfile v2/v3: packages["node_modules/..."] (nested deps flattened to their real name)
const packages = lock.packages ?? {};
for (const [key, info] of Object.entries(packages)) {
  if (!key.startsWith("node_modules/") || !info.version) continue;
  const nm = key.replace(/^node_modules\//, "").split("/node_modules/").pop();
  components.push({
    type: "library",
    "bom-ref": `${nm}@${info.version}`,
    name: nm,
    version: info.version,
    purl: purl(nm, info.version),
    properties: [{ name: "anubis-guardian:lockfile-path", value: key }],
  });
}
// dedupe by bom-ref + sort (deterministic)
const seen = new Set();
const deduped = components
  .filter((c) => (seen.has(c["bom-ref"]) ? false : (seen.add(c["bom-ref"]), true)))
  .sort((a, b) => a["bom-ref"].localeCompare(b["bom-ref"]));

// the tool itself is the root component
const rootComponent = {
  type: "application",
  "bom-ref": `${pkg.name}@${pkg.version}`,
  name: pkg.name,
  version: pkg.version,
  licenses: [{ license: { id: "MIT" } }],
  purl: purl(pkg.name, pkg.version),
};

// dist artifact hashes (supply-chain transparency for the shipped bundle)
const distDir = join(root, "dist");
const artifacts = [];
const walkDist = (dir) => {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walkDist(p);
    else artifacts.push({ path: p, sha256: createHash("sha256").update(readFileSync(p)).digest("hex") });
  }
};
if (existsSync(distDir)) walkDist(distDir);

const sbom = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  serialNumber: `urn:uuid:${createHash("sha256").update(`${pkg.name}@${pkg.version}`).digest("hex").slice(0, 8)}-0000-4000-8000-${createHash("sha256").update(String(pkg.version)).digest("hex").slice(0, 12)}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: [{ vendor: "anubis-guardian", name: "generate-sbom.mjs", version: pkg.version }],
    components: [rootComponent],
    properties: [
      { name: "anubis-guardian:advisory_snapshot", value: "2026-10" },
      { name: "anubis-guardian:runtime", value: `node>=${pkg.engines?.node ?? "18"}` },
    ],
  },
  components: deduped,
};

if (artifacts.length) {
  sbom.metadata.properties.push({
    name: "anubis-guardian:dist-sha256",
    value: artifacts.map((a) => `${a.path.replace(distDir + "/", "")}:${a.sha256}`).join("\n"),
  });
}

const out = process.argv[2] || join(root, `anubis-guardian-${pkg.version}.cdx.json`);
writeFileSync(out, JSON.stringify(sbom, null, 2) + "\n", "utf8");
console.error(`written: ${out} — ${deduped.length} component(s) + root ${pkg.name}@${pkg.version} + ${artifacts.length} dist artifact hash(es)`);
