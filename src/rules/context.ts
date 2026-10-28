import type { ScannedFile, ScanContext } from "../types.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";

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

/** Canonical absolute-path form: forward slashes everywhere (Windows-safe). */
export function normalizeAbs(p: string): string {
  return p.replace(/\\/g, "/");
}

/** Importers (any file) → normalized targets they import. */
const importEdgeRe =
  /(?:import|export)\s[^;]*?from\s*["']([^"']+)["']|import\s*\(\s*["']([^"']+)["']\s*\)|require\(\s*["']([^"']+)["']\s*\)/g;

/**
 * v1.5.3 (P0-6) — configured path aliases. SUPPORTED resolution scope
 * (documented contract): `compilerOptions.paths` from the tsconfig.json /
 * jsconfig.json AT THE SCAN ROOT (JSONC tolerated: comments + trailing commas
 * stripped before parse; unparseable config → no aliases, the safe default),
 * wildcard (`@/*` → `src/*`) and exact keys, `compilerOptions.baseUrl`.
 * NOT supported (and named in classes_not_covered): node_modules resolution,
 * nested/workspace tsconfigs beyond the scan root, package.json `#` subpath
 * imports, bundler-only alias plugins. A spec that resolves to NO scanned file
 * stays unresolved — never guessed.
 */
export interface AliasConfig { baseDir: string; rules: Array<{ prefix: string; targets: string[] }> }

export function pathAliases(rootDir: string): AliasConfig | null {
  for (const name of ["tsconfig.json", "jsconfig.json"]) {
    try {
      const raw = readFileSync(join(rootDir, name), "utf8");
      const json = JSON.parse(
        raw.replace(/^\uFEFF/, "")
          .replace(/\/\*[\s\S]*?\*\//g, "")
          .replace(/(^|[^:"'\\])\/\/.*$/gm, "$1")
          .replace(/,(\s*[}\]])/g, "$1")
      );
      const paths = json?.compilerOptions?.paths;
      if (!paths || typeof paths !== "object" || Array.isArray(paths)) continue;
      const rules = Object.entries(paths as Record<string, unknown>)
        .filter(([, t]) => Array.isArray(t))
        .map(([prefix, t]) => ({ prefix, targets: (t as unknown[]).map(String) }));
      if (!rules.length) continue;
      const baseUrl = typeof json?.compilerOptions?.baseUrl === "string" ? json.compilerOptions.baseUrl : ".";
      return { baseDir: normalizeAbs(join(rootDir, baseUrl)), rules };
    } catch { /* unparseable / missing — try next candidate config */ }
  }
  return null;
}

/** candidate absolute paths (slash-normalized) for a resolved module path */
function candidatesFor(bare: string): string[] {
  const candidates = [bare, `${bare}.ts`, `${bare}.tsx`, `${bare}.js`, `${bare}.jsx`, `${bare}/index.ts`, `${bare}/index.js`];
  // NodeNext / TS-style relative imports carry a runtime extension: "../lib/secret.js"
  // must resolve to secret.ts on disk. Map runtime extensions to scanned source extensions.
  const swapped = bare.replace(/\.(m|c)?js$/i, (ext) =>
    ext === ".mjs" ? ".mts" : ext === ".cjs" ? ".cts" : ".ts");
  if (swapped !== bare) {
    candidates.unshift(swapped, `${swapped}x`); // .js→.ts/.tsx, .mjs→.mts, .cjs→.cts
  }
  return candidates;
}

/** resolve an ALIASED spec (`@/lib/x`) against the configured alias rules */
function resolveAliased(spec: string, aliases: AliasConfig, byAbs: Map<string, ScannedFile>): string | null {
  for (const rule of aliases.rules) {
    const wildcard = rule.prefix.includes("*");
    const keyBase = wildcard ? rule.prefix.slice(0, rule.prefix.indexOf("*")) : rule.prefix;
    let rest: string | null = null;
    if (wildcard) { if (!spec.startsWith(keyBase)) continue; rest = spec.slice(keyBase.length); }
    else if (spec !== rule.prefix) continue;
    for (const target of rule.targets) {
      const tgt = wildcard ? (target.includes("*") ? target.replace("*", rest as string) : target + (rest as string)) : target;
      const bare = `${aliases.baseDir}/${tgt}`.replace(/\/+/g, "/");
      for (const c of candidatesFor(bare)) if (byAbs.has(c)) return c;
    }
  }
  return null;
}

/** Normalized abs paths of every module a client file reaches through imports (depth ≤ 3). */
export function importedFromClient(ctx: ScanContext): Set<string> {
  // All keys/values in this graph use normalizeAbs() — on Windows raw f.abs carries
  // backslashes, and a raw-vs-normalized key mismatch silently empties the import
  // graph (SUPA-001 transitive reachability would never fire on Windows).
  const byAbs = new Map<string, ScannedFile>();
  for (const f of ctx.files) byAbs.set(normalizeAbs(f.abs), f);

  // v1.5.3 (P0-6): configured path aliases (tsconfig/jsconfig at the scan root)
  // are resolved ONCE per scan — a client component importing
  // `@/lib/server-secret` must reach the secret module exactly like a
  // relative import would. Unresolvable specs (npm packages, unknown aliases)
  // stay ignored — never guessed.
  const aliasConfig = pathAliases(ctx.rootDir);

  // importer abs → set of normalized target abs it imports (forward import edges)
  const importsOf = new Map<string, Set<string>>();

  for (const f of ctx.files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.rel)) continue;
    let m: RegExpExecArray | null;
    const importer = normalizeAbs(f.abs);
    const aliases = aliasConfig; // v1.5.3: configured path aliases resolve too
    while ((m = importEdgeRe.exec(f.content)) !== null) {
      const spec = m[1] || m[2] || m[3];
      const isRelative = Boolean(spec && spec.startsWith("."));
      if (!spec || (!isRelative && !aliases)) continue;
      const target = resolveSpec(f, spec, byAbs, aliases ?? undefined);
      if (!importsOf.has(importer)) importsOf.set(importer, new Set());
      if (target) importsOf.get(importer)!.add(target);
    }
  }

  // BFS forward from client files along import edges (depth ≤ 3):
  // everything a client file reaches — directly or through intermediaries —
  // is shipped to the browser bundle. Returns normalized target abs paths.
  const clientAbs = ctx.files.filter((f) => classifyFile(f) === "client").map((f) => normalizeAbs(f.abs));
  const reach = new Set<string>();
  const visited = new Set(clientAbs);
  let frontier = new Set(clientAbs);
  for (let depth = 0; depth < 3 && frontier.size; depth++) {
    const next = new Set<string>();
    for (const abs of frontier) {
      for (const target of importsOf.get(abs) ?? []) {
        if (!visited.has(target)) {
          visited.add(target);
          reach.add(target);
          next.add(target);
        }
      }
    }
    frontier = next;
  }
  return reach;
}

/** exported for unit tests (tests/verify-units.mjs) — pure spec→abs resolution */
export function resolveSpec(
  from: ScannedFile,
  spec: string,
  byAbs: Map<string, ScannedFile>,
  aliases?: AliasConfig
): string | null {
  if (spec.startsWith(".")) {
    const baseDir = normalizeAbs(from.abs).replace(/[/\\][^/\\]+$/, "");
    const parts = baseDir.split(/[/\\]/);
    for (const seg of spec.split("/")) {
      if (seg === "." || seg === "") continue;
      if (seg === "..") parts.pop();
      else parts.push(seg);
    }
    const bare = parts.join("/");
    for (const c of candidatesFor(bare)) if (byAbs.has(c)) return c;
    return null;
  }
  if (aliases) return resolveAliased(spec, aliases, byAbs);
  return null;
}

export function isClientEnvKey(key: string): boolean {
  return CLIENT_ENV_PREFIX.test(key);
}

export { CLIENT_ENV_PREFIX };
