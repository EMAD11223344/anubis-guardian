import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
/**
 * Phase 0 — Recon & Sanity (Plan Section 6):
 * stack detection + framework fingerprint + static sanity notes.
 * Purely static — never installs/builds/runs the target (Section 9.7).
 */
export function recon(root, files) {
    const frameworks = {};
    const notes = [];
    const detected = [];
    let pkg = null;
    const pkgPath = join(root, "package.json");
    if (existsSync(pkgPath)) {
        try {
            pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
        }
        catch {
            notes.push("package.json exists but is not valid JSON");
        }
    }
    const allDeps = { ...(pkg?.dependencies ?? {}), ...(pkg?.devDependencies ?? {}) };
    const has = (n) => Boolean(allDeps[n]);
    if (pkg)
        detected.push("node");
    if (has("next")) {
        frameworks.nextjs = true;
        detected.push("nextjs");
    }
    if (has("@nestjs/core")) {
        frameworks.nestjs = true;
        detected.push("nestjs");
    }
    if (has("@supabase/supabase-js") || has("@supabase/ssr")) {
        frameworks.supabase = true;
        detected.push("supabase");
    }
    if (has("express")) {
        frameworks.express = true;
        detected.push("express");
    }
    if (has("socket.io")) {
        frameworks.socketio = true;
        detected.push("socketio");
    }
    if (has("react") || has("vue") || has("svelte"))
        detected.push("frontend-ui");
    if (has("prisma") || has("@prisma/client")) {
        frameworks.prisma = true;
        detected.push("prisma");
    }
    // Supabase local project layout
    const hasMigrations = files.some((f) => /(^|\/)(supabase\/migrations|migrations|db\/migrations)\//.test(f.rel) && f.rel.endsWith(".sql"));
    if (hasMigrations) {
        frameworks.supabaseMigrations = true;
        detected.push("supabase-migrations");
    }
    // Sanity (static-only, honest notes — no build/test execution per Section 9.7)
    const hasLock = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"].some((l) => existsSync(join(root, l)));
    if (pkg && !hasLock)
        notes.push("No lockfile found — dependency installs are not reproducible (advisory pinning limited).");
    if (existsSync(join(root, "tsconfig.json")))
        detected.push("typescript");
    return { detected, frameworks, notes };
}
