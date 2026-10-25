import { rootCause, mkFinding } from "../util.js";
import { SNAPSHOT, affects } from "../advisory/index.js";
import { POPULAR, nearestPopular } from "../advisory/popular.js";
import { existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
/** Parse package-lock.json (v1 tree + v2/v3 packages) — offline lockfile truth. */
function lockfileDeps(root) {
    const out = new Map();
    for (const lockName of ["package-lock.json", "npm-shrinkwrap.json"]) {
        const p = join(root, lockName);
        if (!existsSync(p))
            continue;
        try {
            const lock = JSON.parse(readFileSync(p, "utf8"));
            if (lock.packages) {
                for (const [path, info] of Object.entries(lock.packages)) {
                    const name = path.replace(/^node_modules\//, "").replace(/^.*node_modules\//, "");
                    if (!path.includes("node_modules") || !info.version)
                        continue;
                    if (!out.has(name))
                        out.set(name, info.version);
                }
            }
            else if (lock.dependencies) {
                const visit = (deps) => {
                    for (const [name, info] of Object.entries(deps)) {
                        if (info?.version && !out.has(name))
                            out.set(name, info.version);
                        if (info?.dependencies)
                            visit(info.dependencies);
                    }
                };
                visit(lock.dependencies);
            }
        }
        catch { /* malformed lockfile — skip */ }
        if (out.size)
            break;
    }
    return out;
}
function declaredDeps(pkg) {
    return Object.keys({ ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) });
}
function loadSnapshot(ctx) {
    if (ctx.advisoryFile) {
        try {
            return JSON.parse(readFileSync(ctx.advisoryFile, "utf8"));
        }
        catch { /* fall back to bundled */ }
    }
    return SNAPSHOT;
}
function mk(_ctx, f) {
    return mkFinding(f);
}
export function scanDeps(ctx) {
    const findings = [];
    const pkgPath = join(ctx.rootDir, "package.json");
    if (!existsSync(pkgPath))
        return { findings };
    let pkg;
    try {
        pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
    }
    catch {
        return { findings };
    }
    const declared = declaredDeps(pkg);
    const locked = lockfileDeps(ctx.rootDir);
    const snap = loadSnapshot(ctx);
    const isWorkspaceMember = Boolean(pkg.workspaces || pkg.name === ctx.rootDir.split("/").pop());
    const scoped = (n) => n.startsWith("@");
    for (const name of declared) {
        const lockedVersion = locked.get(name);
        const hasLock = locked.size > 0;
        // ---------- DEP-002 known malicious ----------
        const mal = snap.known_malicious?.[name];
        if (mal?.length) {
            const hit = lockedVersion ? mal.find((m) => affects(m, lockedVersion)) : undefined;
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
                const severity = h.severity === "critical" ? "critical" : "high";
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
        // ---------- DEP-003 typosquat ----------
        if (!POPULAR.has(name) && !scoped(name)) {
            const near = nearestPopular(name, 2);
            if (near) {
                findings.push(mk(ctx, {
                    id: "DEP-003",
                    severity: "high",
                    title: `Possible typosquat: "${name}" is ${near.distance} edit(s) from popular "${near.target}"`,
                    file: "package.json", line: depLine(pkg, name),
                    evidence: {
                        type: "typosquat_candidate",
                        masked: name,
                        note: `offline heuristic (distance ${near.distance}) — verify the intended package is "${near.target}" or that this is the real, established name`,
                    },
                    owasp: "A06",
                    confidence: "medium",
                    fix: `Confirm "${name}" is the package you intend (it is ${near.distance} edits from "${near.target}"). Typosquats steal install-time secrets. If it is a typo, install "${near.target}" instead and remove the attacker-controlled name.`,
                    root: name, root_cause: rootCause("DEP-003", name),
                }));
                continue;
            }
            // ---------- DEP-004 unknown + no lockfile (v1.3 hallucination design) ----------
            const workspaceException = scoped(name) || isWorkspaceMember; // org/private packages
            if (!hasLock && !workspaceException) {
                findings.push(mk(ctx, {
                    id: "DEP-004",
                    severity: "medium",
                    title: `"${name}" cannot be resolved offline and the project has no lockfile`,
                    file: "package.json", line: depLine(pkg, name),
                    evidence: {
                        type: "unresolved_offline",
                        masked: name,
                        note: "no lockfile proves this package ever resolved — hallucinated/slopsquat candidates land here; re-run with --online to check the registry",
                    },
                    owasp: "A06",
                    confidence: "medium",
                    fix: `Verify "${name}" exists on the npm registry and is the package you intend. Generate a lockfile (npm install --package-lock-only) so dependency resolution becomes reproducible and auditable.`,
                    root: name, root_cause: rootCause("DEP-004", name),
                }));
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
                }
                else if (!POPULAR.has(name) && !scoped(name) && meta.fresh) {
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
    return { findings };
}
function depLine(pkg, name) {
    // line number of the dep inside package.json (stable: first occurrence of `"name":`)
    const lines = JSON.stringify(pkg, null, 2).split("\n");
    const i = lines.findIndex((l) => l.includes(`"${name}"`));
    return i >= 0 ? i + 1 : 0;
}
/** --online only: npm registry metadata (non-deterministic — flagged in meta by the engine). */
function registryMeta(name) {
    try {
        const out = execFileSync("npm", ["view", name, "time.created", "--json"], { encoding: "utf8", timeout: 15000 });
        const created = String(JSON.parse(out)).slice(0, 10);
        const freshDays = (Date.now() - new Date(created).getTime()) / 86400000;
        return { created, fresh: freshDays < 90 };
    }
    catch {
        return null; // 404 / offline — treated as non-existent
    }
}
