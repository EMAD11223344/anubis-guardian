/**
 * Bundled advisory data (OSV.dev, real advisories) — rebuilt per tool release
 * so "same code + same tool version = same score" stays exact (Plan Section 8).
 */
export { SNAPSHOT, ACTION_PINS } from "./snapshot.js";
export type { Advisory } from "./snapshot.js";

// ---- minimal semver (Node-semver subset sufficient for OSV ECOSYSTEM ranges) ----

export function parseVer(v: string): [number, number, number, string] | null {
  const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(v.trim());
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3]), m[4] ?? ""];
}

export function cmpVer(a: string, b: string): number {
  const pa = parseVer(a), pb = parseVer(b);
  if (!pa || !pb) return a === b ? 0 : a < b ? -1 : 1;
  if (pa[0] !== pb[0]) return pa[0] - pb[0];
  if (pa[1] !== pb[1]) return pa[1] - pb[1];
  if (pa[2] !== pb[2]) return pa[2] - pb[2];
  const pre = pa[3], pre2 = pb[3];
  if (pre === pre2) return 0;
  if (pre === "") return 1;  // release > prerelease
  if (pre2 === "") return -1;
  return pre < pre2 ? -1 : 1;
}

/** OSV ECOSYSTEM/SEMVER event ranges → does `version` fall inside? */
export function versionInRange(version: string, events: Array<Record<string, string>>): boolean {
  let introduced = "0";
  let fixed: string | null = null;
  let lastAffected: string | null = null;
  for (const e of events) {
    if (e.introduced !== undefined) introduced = e.introduced;
    if (e.fixed !== undefined) fixed = e.fixed;
    if (e.last_affected !== undefined) lastAffected = e.last_affected;
  }
  const c1 = cmpVer(version, introduced);
  if (c1 < 0) return false;
  if (fixed && cmpVer(version, fixed) >= 0) return false;
  if (lastAffected && cmpVer(version, lastAffected) > 0) return false;
  return true;
}

/** Does this advisory (any of its ranges) affect `version`? */
export function affects(advisory: { ranges: Array<{ events: Array<Record<string, string>> }> }, version: string): boolean {
  if (!parseVer(version)) return false;
  return advisory.ranges.some((r) => versionInRange(version, r.events));
}
