const CLIENT_ENV_PREFIX = /^(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_)/;
const PUBLIC_PATH = /(^|\/)(public|dist|\.next\/static|build|out)\//;
export function classifyFile(f) {
    if (PUBLIC_PATH.test(f.rel))
        return "client";
    const head = f.lines.slice(0, 3).join("\n");
    if (/["']use client["']/.test(head))
        return "client";
    if (/["']use server["']/.test(head))
        return "server";
    if (/(^|\/)middleware\.(ts|js)$/.test(f.rel))
        return "server";
    if (/(^|\/)(route|page|layout)\.(ts|tsx|js|jsx)$/.test(f.rel) && /app\//.test(f.rel)) {
        // App Router route handlers are server by default unless marked "use client"
        return "server";
    }
    if (/(^|\/)pages\/api\//.test(f.rel))
        return "server";
    return "unknown";
}
/** Does a client-reachable file import (transitively, depth ≤ 3) this module? */
export function importedFromClient(ctx) {
    const byAbs = new Map();
    for (const f of ctx.files)
        byAbs.set(f.abs, f);
    const importsOf = new Map(); // target abs → importer abs set
    const importRe = /(?:import|export)\s[^;]*?from\s*["']([^"']+)["']|import\s*\(\s*["']([^"']+)["']\s*\)|require\(\s*["']([^"']+)["']\s*\)/g;
    for (const f of ctx.files) {
        if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.rel))
            continue;
        let m;
        while ((m = importRe.exec(f.content)) !== null) {
            const spec = m[1] || m[2] || m[3];
            if (!spec || !spec.startsWith("."))
                continue;
            const target = resolveSpec(f, spec, byAbs);
            if (target) {
                if (!importsOf.has(target))
                    importsOf.set(target, new Set());
                importsOf.get(target).add(f.abs);
            }
        }
    }
    // BFS from client files backwards through importers (depth 3)
    const clientAbs = ctx.files.filter((f) => classifyFile(f) === "client").map((f) => f.abs);
    const reach = new Set();
    let frontier = new Set(clientAbs);
    for (let depth = 0; depth < 3 && frontier.size; depth++) {
        const next = new Set();
        for (const abs of frontier) {
            for (const importer of importsOf.get(abs) ?? []) {
                if (!reach.has(importer)) {
                    reach.add(importer);
                    next.add(importer);
                }
            }
        }
        frontier = next;
    }
    return reach;
}
function resolveSpec(from, spec, byAbs) {
    const baseDir = from.abs.replace(/[/\\][^/\\]+$/, "");
    const parts = baseDir.split(/[/\\]/);
    for (const seg of spec.split("/")) {
        if (seg === "." || seg === "")
            continue;
        if (seg === "..")
            parts.pop();
        else
            parts.push(seg);
    }
    const bare = parts.join("/");
    const candidates = [bare, `${bare}.ts`, `${bare}.tsx`, `${bare}.js`, `${bare}.jsx`, `${bare}/index.ts`, `${bare}/index.js`];
    for (const c of candidates)
        if (byAbs.has(c))
            return c;
    return null;
}
export function isClientEnvKey(key) {
    return CLIENT_ENV_PREFIX.test(key);
}
export { CLIENT_ENV_PREFIX };
