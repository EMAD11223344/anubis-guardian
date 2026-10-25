import type { ScannedFile, ScanContext } from "../types.js";

/**
 * Reachability classification shared by SUPA-001 and the NEXT_PUBLIC_* rule
 * (Plan Section 6 — "الاتجاه هو الحكم": client-reachable → CRITICAL, server-only → INFO).
 */

export type FileClass = "client" | "server" | "unknown";

const CLIENT_ENV_PREFIX = /^(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_)/;
const PUBLIC_PATH = /(^|\/)(public|dist|\.next\/static|build|out)\//;

export function classifyFile(f: ScannedFile): FileClass {
  if (PUBLIC_PATH.test(f.rel)) return "client";
  const head = f.lines.slice(0, 3).join("\n");
  if (/["']use client["']/.test(head)) return "client";
  if (/["']use server["']/.test(head)) return "server";
  if (/(^|\/)middleware\.(ts|js)$/.test(f.rel)) return "server";
  if (/(^|\/)(route|page|layout)\.(ts|tsx|js|jsx)$/.test(f.rel) && /app\//.test(f.rel)) {
    // App Router route handlers are server by default unless marked "use client"
    return "server";
  }
  if (/(^|\/)pages\/api\//.test(f.rel)) return "server";
  return "unknown";
}

/** Does a client-reachable file import (transitively, depth ≤ 3) this module? */
export function importedFromClient(ctx: ScanContext): Set<string> {
  const byAbs = new Map<string, ScannedFile>();
  for (const f of ctx.files) byAbs.set(f.abs, f);

  const importsOf = new Map<string, Set<string>>(); // target abs → importer abs set
  const importRe = /(?:import|export)\s[^;]*?from\s*["']([^"']+)["']|import\s*\(\s*["']([^"']+)["']\s*\)|require\(\s*["']([^"']+)["']\s*\)/g;

  for (const f of ctx.files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.rel)) continue;
    let m: RegExpExecArray | null;
    while ((m = importRe.exec(f.content)) !== null) {
      const spec = m[1] || m[2] || m[3];
      if (!spec || !spec.startsWith(".")) continue;
      const target = resolveSpec(f, spec, byAbs);
      if (target) {
        if (!importsOf.has(target)) importsOf.set(target, new Set());
        importsOf.get(target)!.add(f.abs);
      }
    }
  }

  // BFS from client files backwards through importers (depth 3)
  const clientAbs = ctx.files.filter((f) => classifyFile(f) === "client").map((f) => f.abs);
  const reach = new Set<string>();
  let frontier = new Set(clientAbs);
  for (let depth = 0; depth < 3 && frontier.size; depth++) {
    const next = new Set<string>();
    for (const abs of frontier) {
      for (const importer of importsOf.get(abs) ?? []) {
        if (!reach.has(importer)) { reach.add(importer); next.add(importer); }
      }
    }
    frontier = next;
  }
  return reach;
}

function resolveSpec(from: ScannedFile, spec: string, byAbs: Map<string, ScannedFile>): string | null {
  const baseDir = from.abs.replace(/[/\\][^/\\]+$/, "");
  const parts = baseDir.split(/[/\\]/);
  for (const seg of spec.split("/")) {
    if (seg === "." || seg === "") continue;
    if (seg === "..") parts.pop();
    else parts.push(seg);
  }
  const bare = parts.join("/");
  const candidates = [bare, `${bare}.ts`, `${bare}.tsx`, `${bare}.js`, `${bare}.jsx`, `${bare}/index.ts`, `${bare}/index.js`];
  for (const c of candidates) if (byAbs.has(c)) return c;
  return null;
}

export function isClientEnvKey(key: string): boolean {
  return CLIENT_ENV_PREFIX.test(key);
}

export { CLIENT_ENV_PREFIX };
