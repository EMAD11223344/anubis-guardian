import type { ScanContext, RuleResult } from "../types.js";
import { rootCause, mkFinding, type MkIn } from "../util.js";

/**
 * Layer 5 — NestJS playbook (Plan Section 6; v0.2 — APP_GUARD-aware per v1.1 correction).
 * NEST-001 controller endpoints without any guard (global APP_GUARD honored)
 * NEST-002 CORS enabled with a permissive origin
 * NEST-003 helmet not registered (security headers missing)
 * NEST-004 ThrottlerModule absent (no rate limiting)
 */

const HTTP_DECORATORS = ["Get", "Post", "Put", "Patch", "Delete", "All", "Head", "Options"];

const FIX_GUARD =
  "Protect the endpoint with an auth guard (@UseGuards(AuthGuard) / RolesGuard) or confirm a global APP_GUARD is registered in the module. A public-by-default endpoint is anonymous internet surface.";
const FIX_CORS =
  "Restrict CORS to an explicit origin allowlist (cors: { origin: [...], credentials: true }). origin: '*' lets any website read authenticated responses from your API.";
const FIX_HELMET =
  "Register helmet() (app.use(helmet())) so security headers (HSTS, X-Content-Type-Options, frameguard) are set on every response.";
const FIX_THROTTLE =
  "Add ThrottlerModule + APP_GUARD ThrottlerGuard (or express-rate-limit) so login/OTP/auth routes resist brute force.";

interface Endpoint { line: number; method: string; path: string; guards: string[]; isPublic: boolean }
interface ControllerInfo { name: string; file: string; classLine: number; guards: string[]; endpoints: Endpoint[] }

export function scanNestjs(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];
  if (!ctx.stack.frameworks.nestjs) return { findings };

  // global APP_GUARD (class-based or string provider) anywhere in the codebase
  const globalGuard = ctx.files.some((f) =>
    /APP_GUARD/.test(f.content) && /useClass|useExisting|useFactory|ThrottlerGuard|AuthGuard|JwtAuthGuard/.test(f.content)
  );

  const controllers: ControllerInfo[] = [];

  for (const f of ctx.files) {
    if (!/\.ts$/.test(f.rel) || /spec\.ts$/.test(f.rel) || /\.d\.ts$/.test(f.rel)) continue;

    // NEST-002 CORS permissive in bootstrap
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      if (/enableCors\s*\(/.test(line) || /cors\s*:\s*\{/.test(line)) {
        const window = f.lines.slice(i, i + 6).join("\n");
        if (/origin\s*:\s*("|'|\`)\*(\1)|origin\s*:\s*true/.test(window)) {
          findings.push(mk(ctx, {
            id: "NEST-002", severity: "medium",
            title: "CORS allows any origin",
            file: f.rel, line: i + 1,
            evidence: { type: "cors_wildcard", masked: "origin: * / true" },
            owasp: "A05", fix: FIX_CORS,
            root: f.rel, root_cause: rootCause("NEST-002", f.rel),
          }));
        }
      }
    }

    // NEST-003 / NEST-004 — bootstrap hygiene
    if (/(^|\/)main\.ts$/.test(f.rel)) {
      if (!/helmet\s*\(/.test(f.content)) {
        findings.push(mk(ctx, {
          id: "NEST-003", severity: "medium",
          title: "helmet() not registered — security headers missing",
          file: f.rel, line: 0,
          evidence: { type: "helmet_missing", masked: "no helmet() in main.ts" },
          owasp: "A05", confidence: "medium", fix: FIX_HELMET,
          root: f.rel, root_cause: rootCause("NEST-003", f.rel),
        }));
      }
      const all = ctx.files.map((x) => x.content).join("\n");
      if (!/ThrottlerModule|ThrottlerGuard/.test(all) && !/rate[-_]?limit/i.test(all)) {
        findings.push(mk(ctx, {
          id: "NEST-004", severity: "medium",
          title: "No rate limiting found (ThrottlerModule / rate-limit)",
          file: f.rel, line: 0,
          evidence: { type: "throttler_missing", masked: "no ThrottlerModule in the codebase" },
          owasp: "A04", confidence: "medium", fix: FIX_THROTTLE,
          root: f.rel, root_cause: rootCause("NEST-004", f.rel),
        }));
      }
    }

    // controller extraction
    const ctrl = f.content.match(/@Controller\s*\(\s*(?:["'`]([^"'`]*)["'`]\s*)?\)/);
    if (ctrl && /class\s+[A-Z]/.test(f.content)) {
      const info: ControllerInfo = {
        name: (f.rel.split("/").pop() ?? "").replace(/\.controller\.ts$/, ""),
        file: f.rel,
        classLine: f.lines.findIndex((l) => /@Controller/.test(l)) + 1,
        guards: [],
        endpoints: [],
      };
      // class-level guards
      for (let i = 0; i < f.lines.length; i++) {
        const l = f.lines[i];
        if (/@UseGuards\s*\(/.test(l) && !info.endpoints.length) {
          const names = (l.match(/@UseGuards\s*\(([^)]*)\)/)?.[1] ?? "").split(",").map((s) => s.trim()).filter(Boolean);
          if (names.length) info.guards.push(...names);
        }
        const ep = l.match(new RegExp(`@(${HTTP_DECORATORS.join("|")})\\s*\\(\\s*(?:["'\`]([^"'\`]*)["'\`])?\\s*\\)`));
        if (ep) {
          // look ahead for method-level @UseGuards/@Public within the next 6 lines
          const ahead = f.lines.slice(i, i + 8).join("\n");
          const mg = ahead.match(/@UseGuards\s*\(([^)]*)\)/);
          const methodGuards = (mg?.[1] ?? "").split(",").map((s) => s.trim()).filter(Boolean);
          const isPublic = /@Public\s*\(\)|@SkipThrottle|@AllowAnonymous/.test(ahead);
          info.endpoints.push({ line: i + 1, method: ep[1], path: ep[2] ?? "", guards: methodGuards, isPublic });
        }
      }
      controllers.push(info);
    }
  }

  // NEST-001 — endpoints with zero guards (APP_GUARD-aware: global guard covers them)
  for (const c of controllers) {
    const unprotected = c.endpoints.filter((e) => !e.isPublic && e.guards.length === 0 && c.guards.length === 0);
    if (unprotected.length && !globalGuard) {
      const first = unprotected[0];
      findings.push(mk(ctx, {
        id: "NEST-001",
        severity: "high",
        title: `${unprotected.length} endpoint(s) in ${c.name}.controller with no guard and no global APP_GUARD`,
        file: c.file, line: first.line,
        evidence: {
          type: "unguarded_controller",
          masked: `${c.name}: ${unprotected.map((e) => `${e.method}(${e.path || "/"})`).join(", ").slice(0, 90)}`,
          note: "no @UseGuards on these routes and no APP_GUARD provider found — they are anonymous surface",
        },
        owasp: "A01",
        fix: FIX_GUARD,
        root: c.file, root_cause: rootCause("NEST-001", c.file),
      }));
    }
  }

  return { findings };
}

function mk(_ctx: ScanContext, f: MkIn): RuleResult["findings"][number] {
  return mkFinding(f);
}
