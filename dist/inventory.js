/**
 * Recon inventory (Plan Section 6 Phase 0 — v1.6 item A; shipped v0.2).
 * Static map of the attack surface: routes / server actions / controllers with
 * guard state / Supabase tables + RPCs + edge functions / socket events / webhooks.
 * Feeds later rules (AUTH-001, WS-001) and the v0.3 authz matrix. Purely static.
 */
export function buildInventory(ctx) {
    const inv = {
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
            const guard = /auth|session|guard|middleware|verify/i.test(f.content) ? "in-file" : null;
            for (const m of methods.length ? methods : ["GET"]) {
                inv.routes.push({ path, file: f.rel, kind: "route", method: m, guard });
            }
            if (/webhook/i.test(path))
                inv.webhooks.push({ path, file: f.rel });
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
                    guard: /auth|session|getCurrentUser|verify/i.test(f.content) ? "in-file" : null,
                });
            }
        }
        // ---- NestJS controllers + guard state ----
        if (ctx.stack.frameworks.nestjs && /\.controller\.ts$/.test(f.rel)) {
            const className = (f.content.match(/export\s+class\s+([A-Za-z_]\w*)/) ?? [])[1] ?? f.rel;
            const hasGlobalGuard = ctx.files.some((x) => /APP_GUARD/.test(x.content));
            const classGuards = (f.content.match(/@UseGuards\s*\(([^)]*)\)/) ?? [])[1]?.trim() ?? null;
            const methods = [...f.content.matchAll(/@(Get|Post|Put|Patch|Delete|All|Head|Options)\s*\(\s*(?:["'`]([^"'`]*)["'`])?\s*\)/g)];
            for (const m of methods) {
                inv.routes.push({
                    path: `/${m[2] ?? ""}`.replace(/\/+$/, "/"),
                    file: f.rel,
                    kind: "controller-method",
                    method: m[1].toUpperCase(),
                    guard: classGuards ?? (hasGlobalGuard ? "APP_GUARD" : null),
                });
            }
            if (!inv.controllers.some((c) => c.file === f.rel)) {
                inv.controllers.push({ name: className, file: f.rel, guard: classGuards, global_guard: hasGlobalGuard });
            }
        }
        // ---- Supabase: tables / RPCs / edge functions ----
        if (f.rel.endsWith(".sql") && /(^|\/)(supabase\/migrations|migrations|db\/migrations)\//.test(f.rel)) {
            for (const m of f.content.matchAll(/\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(\w+)\.)?(\w+)/gi)) {
                const schema = (m[1] || "public").toLowerCase();
                inv.supabase.tables.push({
                    name: `${schema}.${m[2]}`,
                    file: f.rel,
                    rls_enabled: new RegExp(`ALTER\\s+TABLE\\s+(?:ONLY\\s+)?(?:IF\\s+EXISTS\\s+)?${schema}\\.${m[2]}\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`, "i").test(ctx.files.filter((x) => x.rel.endsWith(".sql")).map((x) => x.content).join("\n")),
                });
            }
            for (const m of f.content.matchAll(/CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w.]+)/gi)) {
                inv.supabase.rpcs.push({ name: m[1], file: f.rel });
            }
        }
        const edge = f.rel.match(/supabase\/functions\/([^/]+)\/(index\.)?(ts|js)$/);
        if (edge && !inv.supabase.edge_functions.includes(edge[1]))
            inv.supabase.edge_functions.push(edge[1]);
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
