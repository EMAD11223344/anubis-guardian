import { createHash } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync, existsSync, statSync } from "node:fs";
import { join, basename } from "node:path";
/**
 * v1.0 — Rules registry signing (Plan Section 9.4 "org rules as supply chain"):
 * - `rules-lock <dir>` writes <dir>/rules-lock.json — the SHA-256 pin of every
 *   rule file in the directory (the "signature" the org commits with its rules).
 * - `scan --rules-dir <dir>` verifies the directory against the lock when one
 *   exists: any modified / added / removed rule file refuses to run (exit 2)
 *   unless `--allow-community-rules` is passed — which quarantines the run
 *   (meta.rules_lock = "bypassed", meta.community_rules = true, stderr warning).
 * - No lock file at all = v0.2 behavior preserved (warning only, meta.rules_lock
 *   = "off") — orgs adopt the pin deliberately, never silently.
 * The remote community registry itself ships post-release; this is the local
 * pinning/quarantine mechanism the registry will use.
 */
export const LOCK_VERSION = 1;
export function sha256File(path) {
    return createHash("sha256").update(readFileSync(path)).digest("hex");
}
export function ruleFiles(dir) {
    return readdirSync(dir).filter((n) => n.endsWith(".json") && n !== "rules-lock.json" && statSync(join(dir, n)).isFile()).sort();
}
/** Generate (or refresh) rules-lock.json for a rules directory. */
export function writeRulesLock(dir) {
    const files = ruleFiles(dir).map((name) => ({ name, sha256: sha256File(join(dir, name)) }));
    const lock = { lock_version: LOCK_VERSION, algorithm: "sha256", tool: "anubis-guardian", files };
    const file = join(dir, "rules-lock.json");
    writeFileSync(file, JSON.stringify(lock, null, 2) + "\n", "utf8");
    return { file, count: files.length };
}
export function readRulesLock(dir) {
    const file = join(dir, "rules-lock.json");
    if (!existsSync(file))
        return null;
    try {
        const parsed = JSON.parse(readFileSync(file, "utf8"));
        if (parsed.lock_version !== LOCK_VERSION || parsed.algorithm !== "sha256" || !Array.isArray(parsed.files))
            return null;
        return parsed;
    }
    catch {
        return null;
    }
}
/**
 * Verify a rules directory against its lock (if any). Throws nothing — the
 * caller decides whether "failed" exits 2 (no --allow-community-rules) or
 * downgrades to "bypassed".
 */
export function checkRulesLock(dir) {
    const lock = readRulesLock(dir);
    if (!lock) {
        return {
            status: "off",
            failures: [],
            warning: `rules supply-chain guard: ${basename(dir)} has no rules-lock.json — run \`anubis-guardian rules-lock ${dir}\` and commit it (unpinned rules are treated as community rules)`,
        };
    }
    const failures = [];
    const locked = new Map(lock.files.map((f) => [f.name, f.sha256]));
    const present = ruleFiles(dir);
    for (const name of present) {
        const actual = sha256File(join(dir, name));
        const expected = locked.get(name);
        if (expected === undefined)
            failures.push(`unpinned rule file: ${name} (not in rules-lock.json)`);
        else if (expected !== actual)
            failures.push(`modified rule file: ${name} (sha256 mismatch against rules-lock.json)`);
    }
    for (const [name] of locked) {
        if (!existsSync(join(dir, name)))
            failures.push(`missing rule file: ${name} (locked but absent)`);
    }
    return failures.length
        ? { status: "failed", failures }
        : { status: "verified", failures: [] };
}
