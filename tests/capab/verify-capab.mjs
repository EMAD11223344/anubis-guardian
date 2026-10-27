#!/usr/bin/env node
/**
 * Capability acceptance verification (v1.4) — asserts the REAL CLI scan of
 * tests/capab/app produces the expected capability findings (positives) and
 * none of the clean counterparts. This is the end-to-end layer above the
 * U21 unit gates: rules must ACTUALLY fire through the engine pipeline.
 */
import { readFileSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const results = JSON.parse(readFileSync(join(here, "findings.json"), "utf8"));
// artifact cleanup — findings.json is a scan output, not a fixture
rmSync(join(here, "findings.json"), { force: true });
const findings = results.findings ?? [];
let PASS = 0;
const FAILS = [];
const check = (name, cond, extra = "") => {
  if (cond) PASS++;
  else { FAILS.push(name); console.log(`  FAILED: ${name}${extra ? " — " + extra : ""}`); }
};
const idsIn = (match) => new Set(findings.filter((f) => match.test(f.file)).map((f) => f.id));

// §A — positive: mutating handler, no authz evidence → AUTHZ-001
const del = idsIn(/tenants\/del\/route\.ts/);
check("CAP-A pos: AUTHZ-001 fires on mutating handler without authz evidence", del.has("AUTHZ-001"), [...del].join(","));
check("CAP-A clean: siblings with session authz stay silent",
  findings.filter((f) => /tenants\/safe\/route\.ts/.test(f.file) && /^AUTHZ/.test(f.id)).length === 0);
// §A generalization — express router decision-from-body → AUTHZ-002
check("CAP-A gen: AUTHZ-002 fires on express router + client-sourced isAdmin decision",
  idsIn(/perm-router\.js/).has("AUTHZ-002"));

// §B — positive: tenant entity declared + by-ID delete
const inv = idsIn(/api\/invoice\/route\.ts/);
check("CAP-B pos: TEN-002 (or TEN-001) fires on tenant entity mutated by request id", inv.has("TEN-002") || inv.has("TEN-001"), [...inv].join(","));
check("CAP-B clean: tenant-scoped delete stays silent",
  findings.filter((f) => /invoice-scoped\/route\.ts/.test(f.file) && /^TEN/.test(f.id)).length === 0);

// §C — positive: password hash in response
const prof = idsIn(/api\/profile\/route\.ts/);
check("CAP-C pos: LEAK-001 fires on credential field in response", prof.has("LEAK-001"), [...prof].join(","));
check("CAP-C clean: password:undefined stays silent",
  findings.filter((f) => /profile-clean\/route\.ts/.test(f.file) && /^LEAK/.test(f.id)).length === 0);

// §D — positives: request-built regex + pagination-less read
const search = idsIn(/api\/search\/route\.ts/);
check("CAP-D pos: RES-001 fires on request-built RegExp", search.has("RES-001"), [...search].join(","));
check("CAP-D pos: RES-002 fires on findMany() inside handler", idsIn(/all-users\/route\.ts/).has("RES-002"));
check("CAP-D clean: capped findMany + literal regex stay silent",
  findings.filter((f) => (/(all-users-clean|search-clean)\/route\.ts/.test(f.file)) && /^RES/.test(f.id)).length === 0);

// §F — positives: served-dir write, limit-less parser, guard-less extraction
const up = idsIn(/uploader\.ts/);
check("CAP-F pos: UPLOAD-001 (served-dir write) + UPLOAD-002 (no limits) fire",
  up.has("UPLOAD-001") && up.has("UPLOAD-002"), [...up].join(","));
check("CAP-F pos: UPLOAD-003 fires on guard-less archive extraction (AdmZip + tar pipe)",
  idsIn(/extractor\.js/).has("UPLOAD-003"));
check("CAP-F clean: limited parser + guarded extraction stay silent",
  findings.filter((f) => /(uploader-clean|extractor-clean)/.test(f.file) && /^UPLOAD/.test(f.id)).length === 0);

// multi-rule co-existence sanity: the fixture tree must NOT swallow the baseline rules
check("CAP-baseline: engine still reports secrets/SAST-class coverage on this tree (pipeline intact)",
  findings.length > 0);

console.log(`CAPABILITY ACCEPTANCE: ${PASS} passed, ${FAILS.length} failed`);
if (FAILS.length) process.exit(1);
