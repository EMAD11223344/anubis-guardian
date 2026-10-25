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
  // numeric-aware prerelease ordering: split identifiers; numeric comparison when both are numeric,
  // otherwise lexicographic (semver §11.4). String-only compare got "1.0.0-10" < "1.0.0-9" wrong.
  const ids = pre.split("."), ids2 = pre2.split(".");
  for (let i = 0; i < Math.max(ids.length, ids2.length); i++) {
    const a = ids[i], b = ids2[i];
    if (a === undefined) return -1; // fewer fields = lower precedence
    if (b === undefined) return 1;
    const na = /^\d+$/.test(a), nb = /^\d+$/.test(b);
    if (na && nb) { const d = Number(a) - Number(b); if (d) return d; }
    else if (a !== b) return na ? -1 : nb ? 1 : a < b ? -1 : 1;
  }
  return 0;
}

/** OSV ECOSYSTEM/SEMVER event ranges → does `version` fall inside? */
export function versionInRange(version: string, events: Array<Record<string, string>>): boolean {
  // OSV ranges may carry MULTIPLE introduced/fixed segments in one events array —
  // evaluate each segment independently and return whether ANY segment contains the
  // version. The previous single-scalar collapse mis-evaluated multi-pair ranges:
  // [{introduced:1,fixed:2},{introduced:3}] silently resolved to "≥3 and <2" ⇒ never fires.
  // Without any `introduced` event, the implicit segment starts at "0" (old default).
  let sawIntro = false;
  let any = false;
  let inSeg = false;   // version ≥ current segment's introduced
  let closed = false;  // version is beyond the current segment's boundary
  for (const e of events) {
    if (e.introduced !== undefined) {
      if (sawIntro && inSeg && !closed) any = true; // previous *real* segment contained the version
      sawIntro = true;
      inSeg = cmpVer(version, e.introduced) >= 0;
      closed = false;
    }
    if (inSeg && !closed) {
      if (e.fixed !== undefined && cmpVer(version, e.fixed) >= 0) closed = true;
      else if (e.last_affected !== undefined && cmpVer(version, e.last_affected) > 0) closed = true;
    }
  }
  if (!sawIntro) return !closed;          // implicit introduced "0"
  return any || (inSeg && !closed);
}

/** Does this advisory (any of its ranges) affect `version`? */
export function affects(advisory: { ranges: Array<{ events: Array<Record<string, string>> }> }, version: string): boolean {
  if (!parseVer(version)) return false;
  return advisory.ranges.some((r) => versionInRange(version, r.events));
}
