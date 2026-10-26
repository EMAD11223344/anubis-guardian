import type { ScanContext, RuleResult } from "../types.js";
import { rootCause, mkFinding, type MkIn } from "../util.js";
import { SNAPSHOT, affects, type Advisory } from "../advisory/index.js";
import { POPULAR, nearestPopular } from "../advisory/popular.js";
import { existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";

/**
 * Layer 3 — Dependency audit (Plan Section 6; v0.2).
 * Offline-first against the BUNDLED advisory snapshot (deterministic per tool version):
 *   DEP-001 known CVE affecting a locked dependency          (severity from snapshot)
 *   DEP-002 known-malicious package (OSV MAL snapshot)       (high)
 *   DEP-003 typosquat distance ≤ 2 from a popular package    (high, medium confidence)
 *   DEP-004 unknown package with NO lockfile (hallucination candidate — v1.3 design) (medium)
 *   DEP-005 slopsquat — --online registry metadata only      (high 404 / medium fresh-unknown)
 * Determinism: DEP-001..004 are pure functions of the repo + bundled snapshot.
 * DEP-005 runs ONLY behind --online (meta.online_used=true, excluded from default runs).
 */

interface LockedDep { name: string; version: string }

/** Parse package-lock.json (v1 tree + v2/v3 packages) — offline lockfile truth. */
function lockfileDeps(root: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const lockName of ["package-lock.json", "npm-shrinkwrap.json"]) {
    const p = join(root, lockName);
    if (!existsSync(p)) continue;
    try {
      const lock = JSON.parse(readFileSync(p, "utf8"));
      if (lock.packages) {
        for (const [path, info] of Object.entries<Record<string, string>>(lock.packages)) {
          const name = path.replace(/^node_modules\//, "").replace(/^.*node_modules\//, "");
          if (!path.includes("node_modules") || !info.version) continue;
          if (!out.has(name)) out.set(name, info.version);
        }
      } else if (lock.dependencies) {
        const visit = (deps: Record<string, any>) => {
          for (const [name, info] of Object.entries(deps)) {
            if (info?.version && !out.has(name)) out.set(name, info.version);
            if (info?.dependencies) visit(info.dependencies);
          }
        };
        visit(lock.dependencies);
      }
    } catch { /* malformed lockfile — skip */ }
    if (out.size) break;
  }
  return out;
}

function declaredDeps(pkg: Record<string, any>): string[] {
  return Object.keys({ ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) });
}

function loadSnapshot(ctx: ScanContext): typeof SNAPSHOT {
  if (ctx.advisoryFile) {
    try { return JSON.parse(readFileSync(ctx.advisoryFile, "utf8")); } catch { /* fall back to bundled */ }
  }
  return SNAPSHOT;
}

function mk(_ctx: ScanContext, f: MkIn): RuleResult["findings"][number] {
  return mkFinding(f);
}

export function scanDeps(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];
  const pkgPath = join(ctx.rootDir, "package.json");
  if (!existsSync(pkgPath)) return { findings };

  let pkg: Record<string, any>;
  try { pkg = JSON.parse(readFileSync(pkgPath, "utf8")); } catch { return { findings }; }

  const declared = declaredDeps(pkg);
  const locked = lockfileDeps(ctx.rootDir);
  // v1.2 (T5): "has a lockfile" must be answered by ALL recognized lockfiles —
  // pnpm/yarn/bun projects previously produced a DEP-004 storm (one finding per
  // dependency) because only npm's two formats counted. Walk may also drop a
  // large lockfile (size cap) — probe the filesystem directly for existence.
  // Per-dependency findings additionally require an npm-PARSEABLE lockfile
  // (package-lock.json / npm-shrinkwrap.json — the only formats whose exact
  // package membership can be verified offline).
  const npmLockParsed =
    locked.size > 0 ||
    existsSync(join(ctx.rootDir, "package-lock.json")) ||
    existsSync(join(ctx.rootDir, "npm-shrinkwrap.json"));
  const hasAnyLock = npmLockParsed ||
    ["pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"]
      .some((n) => existsSync(join(ctx.rootDir, n)));
  const unresolvedScoped: string[] = [];
  const snap = loadSnapshot(ctx);
  const isWorkspaceMember = Boolean(pkg.workspaces || pkg.name === ctx.rootDir.split(/[\\/]/).pop());
  const scoped = (n: string) => n.startsWith("@");

  for (const name of declared) {
    const lockedVersion = locked.get(name);

    // ---------- DEP-002 known malicious ----------
    const mal = snap.known_malicious?.[name];
    if (mal?.length) {
      const hit: Advisory | undefined = lockedVersion ? mal.find((m) => affects(m, lockedVersion)) : undefined;
      findings.push(mk(ctx, {
        id: "DEP-002",
        severity: "high",
        title: `Dependency "${name}" is a documented malicious/compromised package${hit ? "" : " (name match)"}`,
        file: "package.json", line: depLine(pkg, name),
        evidence: {
          type: "known_malicious_package",
          masked: `${name}${lockedVersion ? `@${lockedVersion}` : ""}`,
          note: hit ? `${hit.id} — ${hit.summary}` : "package name appears in the bundled known-malicious list — verify the exact version you resolved",
        },
        owasp: "A06",
        fix: `Remove "${name}" immediately. It is documented malicious/compromised in the bundled advisory snapshot (${hit?.id ?? "MAL list"}). Rotate any secret the package could have reached (rotate-first), purge lockfile and node_modules, and re-install from a clean source.`,
        root: name, root_cause: rootCause("DEP-002", name),
      }));
      continue;
    }

    // ---------- DEP-001 CVEs from bundled snapshot ----------
    const advisories = snap.advisories?.[name];
    if (advisories?.length && lockedVersion) {
      const hits = advisories.filter((a) => affects(a, lockedVersion));
      for (const h of hits.slice(0, 5)) {
        const severity = advisorySeverity(h.severity);
        findings.push(mk(ctx, {
          id: "DEP-001",
          severity,
          title: `${name}@${lockedVersion} — known ${h.severity} advisory ${h.id}${h.aliases?.[0] ? ` (${h.aliases[0]})` : ""}`,
          file: "package.json", line: depLine(pkg, name),
          evidence: {
            type: "vulnerable_dependency",
            masked: `${name}@${lockedVersion}`,
            note: `${h.summary}${h.fixed_hint ? ` — fixed in ${h.fixed_hint}` : ""} [snapshot ${snap.snapshot_date}]`,
          },
          owasp: "A06",
          fix: `Upgrade ${name} to ${h.fixed_hint ?? "the patched release"} (advisory ${h.id}). Run installs from a clean environment and commit the updated lockfile.`,
          root: name, root_cause: rootCause("DEP-001", name),
        }));
      }
    }

      // v1.2 (T4): OFFLINE edit-distance-only evidence must never produce HIGH —
      // the FP rate proved far too high (21/22 loud findings in the review were
      // FPs from five root causes; typosquat guesses were among them). Offline
      // candidates become LOW + low-confidence review notes (no score impact).
      // HIGH requires a MAL advisory match (DEP-002) or --online registry
      // metadata (DEP-005). Names < 5 chars are never candidates (nearestPopular
      // already refuses them) — kept as defense in depth here.
      if (!POPULAR.has(name) && name.length >= 5 && !scoped(name)) {
        const near = nearestPopular(name, 2);
        if (near) {
          findings.push(mk(ctx, {
            id: "DEP-003",
            severity: "low",
            confidence: "low",
            needs_confirmation: true,
            title: `Possible typosquat: "${name}" is ${near.distance} edit(s) from popular "${near.target}" (offline heuristic — review note)`,
            file: "package.json", line: depLine(pkg, name),
            evidence: {
              type: "typosquat_candidate",
              masked: name,
              note: `offline edit-distance heuristic (distance ${near.distance} from "${near.target}") — LOW review note, no score impact; upgrade requires registry evidence (--online) or a MAL advisory match`,
            },
            owasp: "A06",
            fix: `Confirm "${name}" is the package you intend (it is ${near.distance} edits from the popular "${near.target}"). Typosquats steal install-time secrets. If it is a typo, install "${near.target}" instead and remove the attacker-controlled name.`,
            root: name, root_cause: rootCause("DEP-003", name),
          }));
          continue;
        }

        // v1.2 (T5): DEP-004 is a PROJECT-STATE finding when NO lockfile exists
        // anywhere (one root cause — collected here, emitted once after the
        // loop). When an npm-parseable lockfile EXISTS but lacks the package,
        // the unknown gets its own per-dependency finding instead.
        if (!isWorkspaceMember) {
          if (npmLockParsed && !lockedVersion) {
            findings.push(mk(ctx, {
              id: "DEP-004",
              severity: "medium",
              title: `"${name}" is not in the lockfile (resolution drift / hallucinated dependency)`,
              file: "package.json", line: depLine(pkg, name),
              evidence: {
                type: "missing_from_lockfile",
                masked: name,
                note: "a lockfile exists but does not contain this dependency — install without a lockfile update, or an AI-invented name that never resolved", 
              },
              owasp: "A06",
              confidence: "medium",
              fix: `Regenerate the lockfile (npm install --package-lock-only) or remove "${name}" if it is not actually used. Re-run with --online to check the registry.`,
              root: name, root_cause: rootCause("DEP-004", name),
            }));
          } else if (!hasAnyLock) {
            unresolvedScoped.push(name);
          }
        }

        // ---------- DEP-005 slopsquat (online only) ----------
        if (ctx.online) {
          // eslint-disable-next-line no-await-in-loop -- sequential, bounded by declared deps
          const meta = registryMeta(name);
          if (meta === null) {
            findings.push(mk(ctx, {
              id: "DEP-005",
              severity: "high",
              title: `"${name}" does not exist on the npm registry (hallucinated dependency)`,
              file: "package.json", line: depLine(pkg, name),
              evidence: { type: "registry_404", masked: name, note: "registry returned 404 — install would fail or resolve to nothing" },
              owasp: "A06",
              fix: `Remove "${name}" — it does not exist on the registry. If you need this capability, find a real, established package.`,
              root: name, root_cause: rootCause("DEP-005", name),
            }));
          } else if (!POPULAR.has(name) && !scoped(name) && meta.fresh) {
            findings.push(mk(ctx, {
              id: "DEP-005",
              severity: "medium",
              title: `"${name}" is a freshly-published unknown package (slopsquat candidate)`,
              file: "package.json", line: depLine(pkg, name),
              evidence: {
                type: "fresh_unknown_package",
                masked: `${name} (created ${meta.created})`,
                note: "AI-suggested hallucinated names get registered by attackers days later — a very young package with no track record deserves manual verification",
              },
              owasp: "A06",
              confidence: "medium",
              fix: `Manually verify "${name}" (maintainers, repository, downloads). Prefer an established package over a days-old one.`,
              root: name, root_cause: rootCause("DEP-005", name),
            }));
          }
        }
      }
  }

  // ---------- v1.2 (T14): TRANSITIVE recall — the lockfile, not package.json,
  // decides what is actually installed. Direct dependencies were checked above;
  // every OTHER resolved package in an npm-parsed lockfile gets the same
  // advisory + known-malicious check (e.g. handlebars arriving via express).
  // Deterministic: name-sorted, capped at 5 advisories per package.
  const declaredSet = new Set(declared);
  const transitiveNames = [...locked.keys()].sort((a, b) => a.localeCompare(b));
  for (const name of transitiveNames) {
    if (declaredSet.has(name)) continue;
    const version = locked.get(name)!;
    const mal = snap.known_malicious?.[name];
    const malHit = mal?.length ? mal.find((m) => affects(m, version)) ?? mal[0] : undefined;
    if (malHit) {
      findings.push(mk(ctx, {
        id: "DEP-002",
        severity: "high",
        title: `Transitive dependency "${name}@${version}" is a documented malicious/compromised package`,
        file: "package-lock.json", line: 0,
        evidence: {
          type: "known_malicious_package",
          masked: `${name}@${version}`,
          note: `${malHit.id} — ${malHit.summary} [arrives transitively through the lockfile; snapshot ${snap.snapshot_date}]`,
        },
        owasp: "A06",
        fix: `Find which direct dependency pulls "${name}" in (npm ls ${name}) and replace that branch. Remove, rotate any secret it could have reached (rotate-first), purge lockfile + node_modules.`,
        root: name, root_cause: rootCause("DEP-002", name),
      }));
      continue;
    }
    const advisories = snap.advisories?.[name];
    for (const h of (advisories ?? []).filter((a) => affects(a, version)).slice(0, 5)) {
      const severity = advisorySeverity(h.severity);
      findings.push(mk(ctx, {
        id: "DEP-001",
        severity,
        title: `${name}@${version} — known ${h.severity} advisory ${h.id}${h.aliases?.[0] ? ` (${h.aliases[0]})` : ""}`,
        file: "package-lock.json", line: 0,
        evidence: {
          type: "vulnerable_dependency",
          masked: `${name}@${version}`,
          note: `${h.summary}${h.fixed_hint ? ` — fixed in ${h.fixed_hint}` : ""} [transitive — resolved via the lockfile; snapshot ${snap.snapshot_date}]`,
        },
        owasp: "A06",
        fix: `Upgrade ${name} to ${h.fixed_hint ?? "the patched release"} (advisory ${h.id}). npm ls ${name} shows which direct dependency pulls it in; commit the updated lockfile.`,
        root: name, root_cause: rootCause("DEP-001", name),
      }));
    }
  }

  // ---------- DEP-004 aggregated emission (v1.2 T5): ONE finding per project ----------
  if (unresolvedScoped.length) {
    const shown = unresolvedScoped.slice(0, 12);
    const more = unresolvedScoped.length - shown.length;
    findings.push(mk(ctx, {
      id: "DEP-004",
      severity: "medium",
      title: unresolvedScoped.length === 1
        ? `"${unresolvedScoped[0]}" cannot be resolved offline and the project has no lockfile`
        : `${unresolvedScoped.length} dependencies cannot be resolved offline and the project has no lockfile`,
      file: "package.json", line: depLine(pkg, unresolvedScoped[0]),
      evidence: {
        type: "unresolved_offline",
        masked: unresolvedScoped.join(", "),
        note: "no lockfile proves these packages ever resolved — hallucinated/slopsquat candidates land here; one finding per project (the missing lockfile is the root cause); re-run with --online to check the registry",
      },
      owasp: "A06",
      confidence: "medium",
      fix: `Verify each listed package exists on the npm registry and is the package you intend (${shown.join(", ")}${more ? ` · +${more} more` : ""}). Generate a lockfile (npm install --package-lock-only) so dependency resolution becomes reproducible and retry the scan.`,
      root: "(no-lockfile)", root_cause: rootCause("DEP-004", "(no-lockfile)"),
    }));
  }

  return { findings };
}

/** v1.2 (T14): snapshot severities now include moderate — map to finding ranks */
function advisorySeverity(s: string): "critical" | "high" | "medium" {
  return s === "critical" ? "critical" : s === "high" ? "high" : "medium";
}

const DAY_MS = 24 * 60 * 60 * 1000;

/** v1.2 (T14): provenance + staleness of the snapshot the scan actually used
 *  (> 90 days ⇒ stale — terminal warning + meta.advisory_snapshot_stale). */
export function snapshotInfo(ctx: ScanContext): { snapshot_date: string; stale: boolean; age_days: number | null } {
  const snap = loadSnapshot(ctx);
  const date = snap.snapshot_date;
  const parsed = /^(\d{4})-(\d{2})(?:-(\d{2}))?/.exec(date);
  const start = parsed
    ? new Date(Number(parsed[1]), Number(parsed[2]) - 1, parsed[3] ? Number(parsed[3]) : 1).getTime()
    : null;
  const age = start === null ? null : Math.floor((Date.now() - start) / DAY_MS);
  return { snapshot_date: date, stale: age !== null && age > 90, age_days: age };
}

function depLine(pkg: Record<string, any>, name: string): number {
  // line number of the dep inside package.json (stable: first occurrence of `"name":`)
  const lines = JSON.stringify(pkg, null, 2).split("\n");
  const i = lines.findIndex((l) => l.includes(`"${name}"`));
  return i >= 0 ? i + 1 : 0;
}

interface RegistryInfo { created: string; fresh: boolean }

/** --online only: npm registry metadata (non-deterministic — flagged in meta by the engine). */
function registryMeta(name: string): RegistryInfo | null {
  try {
    const out = execFileSync("npm", ["view", name, "time.created", "--json"], { encoding: "utf8", timeout: 15000 });
    const created = String(JSON.parse(out)).slice(0, 10);
    const freshDays = (Date.now() - new Date(created).getTime()) / 86400000;
    return { created, fresh: freshDays < 90 };
  } catch {
    return null; // 404 / offline — treated as non-existent
  }
}
