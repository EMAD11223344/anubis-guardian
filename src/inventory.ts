import type { Inventory, ScanContext } from "./types.js";
import { AUTHZ_CALL } from "./rules/authzpack.js";

/**
 * Recon inventory (Plan Section 6 Phase 0 — v1.6 item A; shipped v0.2).
 * Static map of the attack surface: routes / server actions / controllers with
 * guard state / Supabase tables + RPCs + edge functions / socket events / webhooks.
 * Feeds later rules (AUTH-001, WS-001) and the v0.3 authz matrix. Purely static.
 */
export function buildInventory(ctx: ScanContext): Inventory {
  const inv: Inventory = {
    routes: [],
    controllers: [],
    supabase: { tables: [], rpcs: [], edge_functions: [] },
    socket_events: [],
    webhooks: [],
  };

  for (const f of ctx.files) {
    // ---- Next.js App Router routes (app/**/route.ts) ----
    const routeMatch = f.rel.match(/(?:^|\/)app\/(.*)\/route\.(ts|js)$/);
    if (routeMatch) {
      const path = "/" + routeMatch[1].replace(/\((.*?)\)\//g, "").replace(/\[\.\.\.(\w+)\]/, "*").replace(/\[(\w+)\]/, ":$1");
      const methods = [...f.content.matchAll(/export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/gi)].map((m) => m[1].toUpperCase());
      // v1.3-audit (§5.4): the guard heuristic walked the whole file for the bare
      // words auth/session/guard/… — a comment mentioning "authentication" (or the
      // URL "/login") marked EVERY route in the file as guarded, so large backends
      // reported 0 unguarded mutations. Now it requires a recognizable
      // AUTHORIZATION CHECK shape (a session/token/guard CALL or a real header
      // read), not a word.
      // v1.4 investigation fix (§NEST-001 probe): attribution is per-HANDLER —
      // one guard call in one handler no longer marks every handler in the
      // file guarded (a mixed POST-guarded/DELETE-unguarded route.ts used to
      // report DELETE as "in-file guarded"). File-level truth remains only as
      // the conservative fallback when a handler body cannot be bounded.
      for (const m of methods.length ? methods : ["GET"]) {
        inv.routes.push({
          path,
          file: f.rel,
          kind: "route",
          method: m,
          guard: handlerGuardAttribution(f, new RegExp(`export\\s+(?:async\\s+)?function\\s+${m}\\b`, "i")),
        });
      }
      if (/webhook/i.test(path)) inv.webhooks.push({ path, file: f.rel });
    }

    // ---- Server actions ("use server" exported functions) ----
    if (/\b["'`]use server["'`]\b/.test(f.content) && /\.(ts|tsx|js|jsx)$/.test(f.rel)) {
      const actions = [...f.content.matchAll(/export\s+(?:async\s+)?function\s+([A-Za-z_]\w*)/g)].map((m) => m[1]);
      for (const a of actions) {
        inv.routes.push({
          path: `${f.rel}#${a}`,
          file: f.rel,
          kind: "server-action",
          method: "POST",
          guard: handlerGuardAttribution(f, new RegExp(`export\\s+(?:async\\s+)?function\\s+${a}\\b`)),
        });
      }
    }

    // ---- NestJS controllers + guard state ----
    if (ctx.stack.frameworks.nestjs && /\.controller\.ts$/.test(f.rel)) {
      const className = (f.content.match(/export\s+class\s+([A-Za-z_]\w*)/) ?? [])[1] ?? f.rel;
      const hasGlobalGuard = ctx.files.some((x) => /\.(?:ts|js|mjs|cjs)$/.test(x.rel) && /APP_GUARD/.test(x.content));
      // class-level @UseGuards = decorators ABOVE the class declaration
      const classIdx = f.content.search(/export\s+class\s+[A-Za-z_]\w*/);
      const head = classIdx > -1 ? f.content.slice(0, classIdx) : "";
      const classGuards = (head.match(/@UseGuards\s*\(([^)]*)\)/) ?? [])[1]?.trim() ?? null;
      const methods = [...f.content.matchAll(/@(Get|Post|Put|Patch|Delete|All|Head|Options)\s*\(\s*(?:["'`]([^"'`]*)["'`])?\s*\)/g)];
      for (const m of methods) {
        // method-level @UseGuards within the decorator/method block after the route
        const block = f.content.slice(m.index, m.index + 300);
        const methodGuard = (block.match(/^\s*@UseGuards\s*\(([^)]*)\)/m) ?? [])[1]?.trim() ?? null;
        inv.routes.push({
          path: `/${m[2] ?? ""}`.replace(/\/+$/, "/"),
          file: f.rel,
          kind: "controller-method",
          method: m[1].toUpperCase(),
          guard: methodGuard ?? classGuards ?? (hasGlobalGuard ? "APP_GUARD" : null),
        });
      }
      if (!inv.controllers.some((c) => c.file === f.rel)) {
        inv.controllers.push({ name: className, file: f.rel, guard: classGuards, global_guard: hasGlobalGuard });
      }
    }

    // ---- Supabase: tables / RPCs / edge functions ----
    if (f.rel.endsWith(".sql") && /(^|\/)(supabase\/migrations|migrations|db\/migrations)\//.test(f.rel)) {
      for (const m of f.content.matchAll(/\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:"?(\w+)"?\.)?"?(?!IF\b|NOT\b|EXISTS\b|ONLY\b)([a-zA-Z_][\w]*)"?/gi)) {
        const schema = (m[1] || "public").toLowerCase();
        inv.supabase.tables.push({
          name: `${schema}.${m[2]}`,
          file: f.rel,
          rls_enabled: new RegExp(`ALTER\\s+TABLE\\s+(?:ONLY\\s+)?(?:IF\\s+EXISTS\\s+)?"?${schema}"?\\.?"?${m[2]}"?\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`, "i").test(
            ctx.files.filter((x) => x.rel.endsWith(".sql")).map((x) => x.content).join("\n")
          ),
        });
      }
      for (const m of f.content.matchAll(/CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w.]+)/gi)) {
        inv.supabase.rpcs.push({ name: m[1], file: f.rel });
      }
    }
    const edge = f.rel.match(/supabase\/functions\/([^/]+)\/(index\.)?(ts|js)$/);
    if (edge && !inv.supabase.edge_functions.includes(edge[1])) inv.supabase.edge_functions.push(edge[1]);

    // ---- Socket.IO gateways ----
    if (/@WebSocketGateway/.test(f.content)) {
      const gateway = (f.content.match(/class\s+([A-Za-z_]\w*)/) ?? [])[1] ?? f.rel;
      for (const m of f.content.matchAll(/@SubscribeMessage\s*\(\s*["'`]([^"'`]+)["'`]/g)) {
        inv.socket_events.push({ event: m[1], file: f.rel, gateway });
      }
    }

    // ---- Express-style webhooks ----
    if (/\.(ts|js|mjs|cjs)$/.test(f.rel) && /app|router|server/.test(f.rel)) {
      for (const m of f.content.matchAll(/\.(?:post|use)\s*\(\s*["'`](\/[^"']*webhook[^"']*)["'`]/gi)) {
        inv.webhooks.push({ path: m[1], file: f.rel });
      }
    }
  }

  return inv;
}

/**
 * v1.3-audit (§5.4): recognizable AUTHORIZATION-CHECK shape — a session/token
 * call, a guards decorator, or a credentials header read. A bare mention of
 * the words auth/session/middleware (often just a comment or a URL) is NOT a
 * check; word-presence marked every route "guarded" in big backends.
 */
function hasAuthzCheck(content: string): boolean {
  return /(?:getSession|getServerSession|getAuth|auth\s*\(\)|requireUser|requireAuth|requireAdmin|requireLogin|requireSignIn|assertAuth|checkAuth|isAuthenticated|isLoggedIn|verifyToken|jwt\.verify|verifyJWT|UseGuards|getCurrentUser|currentUser\s*\(|getUser\s*\(|cookies\s*\(\s*\)\s*\.get|\.cookies\.get|authorization["'`]?\s*[,\]:]|headers\(\)\.get\(\s*["'`]authorization)/i.test(content);
}

/**
 * v1.4 — per-HANDLER guard attribution for the authz matrix (test-authz).
 * Finds the handler's `export (async) function NAME` declaration, bounds its
 * body by brace-walking (≤60 lines), and answers "does THIS handler contain a
 * recognizable authorization-check call?". File-level truth (hasAuthzCheck)
 * stays ONLY as the conservative fallback when the declaration cannot be
 * found or the body cannot be closed within the bound — never as proof for a
 * different, fully-visible handler.
 */
function handlerGuardAttribution(
  f: { content: string; lines: string[] },
  declRe: RegExp
): "in-file" | null {
  const isComment = (l: string) => /^\s*(?:\/\/|\*|\/\*)/.test(l);
  const declIdx = f.lines.findIndex((l) => declRe.test(l));
  if (declIdx === -1) return hasAuthzCheck(f.content) ? "in-file" : null;

  // brace-walk from the declaration line (first "{" within the next 4 lines)
  let started = false;
  let depth = 0;
  for (let j = declIdx; j < Math.min(f.lines.length, declIdx + 60); j++) {
    for (const ch of f.lines[j]) {
      if (ch === "{") { depth++; started = true; }
      else if (ch === "}") { depth--; if (started && depth === 0) {
        // body fully visible — THIS handler's truth (comments never count)
        const body = f.lines.slice(declIdx, j + 1);
        return body.some((l) => !isComment(l) && AUTHZ_CALL.test(l)) ? "in-file" : null;
      } }
    }
  }
  // body exceeded the bounding budget — conservative file-level fallback
  return hasAuthzCheck(f.content) ? "in-file" : null;
}
