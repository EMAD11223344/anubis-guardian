import type { ScanContext, RuleResult, ScannedFile } from "../types.js";
import { maskSecret, rootCause } from "../util.js";
import { classifyFile } from "./context.js";

/**
 * Rule packs II (Plan Section 11 v0.3 — priorities re-checked against the
 * Step 0 sweep: all of these measured ≤ 1% in the public 100-project sample;
 * their value is proven by real dogfooding, not public frequency).
 *
 * LOGS-001   secrets leaked into logs
 * SUPA-002   user_metadata inside RLS policies (user-writable ⇒ escalation)
 * SUPA-003   Edge Function builds a service_role client with no caller-auth check
 * AUTH-001   auth lives in middleware only — and the matcher does NOT cover the route
 * MASS-001   mass assignment: req.body flows into a DB write without a whitelist
 * WS-001     Socket.IO gateway without any auth hook
 * WEBHOOK-001 webhook endpoint without signature verification
 * JWT-001    jwt.decode() feeding an authorization decision (no signature check)
 * JWT-002    jwt.verify with algorithms:"none" / ignoreExpiration / unpinned algos
 * SWAGGER-001 Swagger/OpenAPI exposed without a production guard
 * NEXT-005   CSRF heuristic: cookie-authenticated mutating endpoint, no CSRF/origin check
 * PRISMA-001 Prisma multi-tenancy hint (low-confidence review note — never deducts)
 *
 * Clean-case discipline (Plan v1.6): every rule documents what silence looks like.
 */

const CODE = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const isCodeFile = (f: ScannedFile) => CODE.test(f.rel);
const isTestFile = (f: ScannedFile) => /spec|test|__tests__|fixtures?|mock/i.test(f.rel);

const SECRETISH_VAR = /(password|passwd|secret|api[_-]?key|apikey|service[_-]?role|private[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?token|bearer|credential)/i;
const LOG_CALL = /\b(?:console|logger|this\.logger)\.(log|error|warn|info|debug)\s*\(/;
const MASK_SIGNAL = /slice\s*\(\s*0|mask|redact|\[REDACTED|sha256|replace\s*\(\s*\/|substring\s*\(\s*0|\.hash/i;
const JWT_LITERAL = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/;
const LONG_SECRET = /\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{16,}|[a-f0-9]{48,})\b/i;

export function scanPacks2(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];
  const fw = ctx.stack.frameworks;

  // ---------- LOGS-001 ----------
  for (const f of ctx.files) {
    if (!isCodeFile(f) || isTestFile(f)) continue;
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      const trimmed = line.trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) continue; // docs are not code
      if (!LOG_CALL.test(line)) continue;
      const args = line.slice(line.search(LOG_CALL));
      if (MASK_SIGNAL.test(line)) continue; // masked before logging — clean case
      const literalSecret = JWT_LITERAL.test(line) || LONG_SECRET.test(line);
      const varLeak =
        SECRETISH_VAR.test(args) &&
        !/\.(length|size|count|exists|expired|valid)\b/.test(args) &&
        !/typeof|Boolean\(|!!/.test(args);
      if (!literalSecret && !varLeak) continue; // clean case: ids, counts, non-secret context
      if (literalSecret) {
        findings.push({
          id: "LOGS-001",
          severity: "high",
          confidence: "high",
          title: "Secret-shaped literal written to logs — the credential now lives in log storage",
          file: f.rel, line: i + 1,
          evidence: { type: "secret_in_logs_literal", masked: `log call at ${f.rel}:${i + 1} carries a secret-shaped literal (${maskSecret(line.match(JWT_LITERAL)?.[0] ?? line.match(LONG_SECRET)![0]).masked})` },
          owasp: "A09",
          fix: "Remove the secret from the log statement and rotate the credential (it is already in log aggregation/retention). Log identifiers, not values.",
          fix_mode: "suggested-diff",
          remediation: { type: "rotate-first", provider: "generic", steps: "1) Rotate the logged credential now (logs persist) 2) Remove it from the log call 3) Purge the value from log storage if retention allows" },
          root: f.rel,
          root_cause: rootCause("LOGS-001", f.rel),
          verified: true,
        });
      } else {
        findings.push({
          id: "LOGS-001",
          severity: "medium",
          confidence: "medium",
          title: "Security-sensitive variable flows into a log call — verify it is masked before logging",
          file: f.rel, line: i + 1,
          evidence: { type: "secret_in_logs_var", masked: args.replace(/\s+/g, " ").slice(0, 60), note: "if the variable can hold a real credential, the value reaches log storage" },
          owasp: "A09",
          fix: "Log only non-sensitive identifiers (ids, counts) or mask the value (first-4 + hash) before it reaches the logger.",
          fix_mode: "suggested-diff",
          root: f.rel,
          root_cause: rootCause("LOGS-001", f.rel),
          verified: true,
        });
      }
    }
  }

  // ---------- SUPA-002: user_metadata inside RLS policies ----------
  const sqlFiles = ctx.files.filter((f) => /\.sql$/i.test(f.rel) && /(^|\/)(supabase\/migrations|migrations|db\/migrations)\//.test(f.rel));
  for (const f of sqlFiles) {
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      const sqlTrim = line.trimStart();
      if (sqlTrim.startsWith("--") || sqlTrim.startsWith("/*") || sqlTrim.startsWith("*")) continue; // SQL comments are not policy code
      if (!/user[_-]metadata/i.test(line)) continue;
      if (/app[_-]metadata/i.test(line)) continue; // clean case: app_metadata is server-managed
      // must sit inside a policy statement (USING/WITH CHECK window)
      const window = f.lines.slice(Math.max(0, i - 12), i + 12).join("\n");
      if (!/CREATE\s+(?:OR\s+REPLACE\s+)?POLICY|USING\s*\(|WITH\s+CHECK\s*\(/i.test(window)) continue;
      if (/SECURITY\s+DEFINER[\s\S]{0,40}SET[\s\S]{0,20}auth\.uid/i.test(window) && !/USING|WITH\s+CHECK/i.test(window)) continue;
      findings.push({
        id: "SUPA-002",
        severity: "high",
        confidence: "high",
        title: "RLS policy references auth.user_metadata — users can edit their own metadata ⇒ self-granted access",
        file: f.rel, line: i + 1,
        evidence: { type: "rls_user_metadata", masked: line.trim().slice(0, 80), note: "user_metadata is writable by the user via updateUser(); use app_metadata (server-managed) or a lookup table" },
        owasp: "A01",
        fix: "Move the authorization attribute to app_metadata (server-managed) or a dedicated memberships table, and scope the policy to auth.uid() against it.",
        fix_mode: "suggested-diff",
        needs_confirmation: true,
        root: f.rel,
        root_cause: rootCause("SUPA-002", f.rel),
        verified: true,
      });
    }
  }

  // ---------- SUPA-003: edge function service_role without caller auth ----------
  for (const f of ctx.files) {
    if (!/(^|\/)supabase\/functions\/[^/]+\/(index\.)?(ts|js|mts)$/.test(f.rel)) continue;
    if (!/SERVICE[_-]?ROLE/i.test(f.content)) continue; // rule is about service-role clients
    const noClient = f.content.replace(/createClient\s*\([^;]*?\)[^;]*;?/gs, " ");
    const callerAuth =
      /headers\.get\s*\(\s*["'`]authorization["'`]/i.test(noClient) ||
      /getUser\s*\(/.test(noClient) ||
      /jwt\.verify|verifyJWT|supabase\.auth/i.test(noClient) ||
      /verify_jwt\s*=\s*true/i.test(f.content);
    if (callerAuth) continue; // clean case: caller is verified before the service client
    findings.push({
      id: "SUPA-003",
      severity: "high",
      confidence: "medium",
      title: "Edge Function uses service_role with no caller-auth check in code — anyone who can invoke it gets admin data access",
      file: f.rel, line: 0,
      evidence: { type: "service_role_no_auth", masked: f.rel, note: "verify the caller (Authorization header / auth.getUser) before using the service client; confirm verify_jwt in config.toml" },
      owasp: "A01",
      fix: "Verify the caller before any service-role usage: read the Authorization header, call supabase.auth.getUser(token), and reject unauthenticated invokes with 401.",
      fix_mode: "suggested-diff",
      needs_confirmation: true,
      root: f.rel,
      root_cause: rootCause("SUPA-003", f.rel),
      verified: true,
    });
  }

  // ---------- AUTH-001: middleware-only auth with matcher gaps (Next.js) ----------
  if (fw.nextjs) {
    const mw = ctx.files.find((f) => /(^|\/)middleware\.(ts|js)$/.test(f.rel));
    if (mw && /(auth|session|token|login|sign[-_]?in)/i.test(mw.content)) {
      const matcherPatterns = parseMatcher(mw.content);
      if (matcherPatterns !== null) {
        for (const f of ctx.files) {
          if (!isCodeFile(f) || isTestFile(f) || classifyFile(f) !== "server") continue;
          const route = f.rel.match(/(?:^|\/)app\/(.*)\/route\.(ts|js)$/);
          if (!route) continue;
          if (/\bexport\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b/.test(f.content) === false) continue;
          const hasInFileAuth = /(supabase\.auth|getServerSession|getSession|auth\(\)|verifyToken|jwt|authorization|cookies\(\)\.get|requireUser|requireAuth|currentUser|getUser|clerk|next-auth|NextAuth|session\.get)/i.test(f.content);
          if (hasInFileAuth) continue; // clean case: explicit server-side check
          const routePath = "/" + route[1].replace(/\((.*?)\)\//g, "").replace(/\[\.\.\.(\w+)\]/, "*").replace(/\[(\w+)\]/, ":$1");
          if (matcherCovers(matcherPatterns, routePath)) continue; // covered by middleware — NEXT-004's note territory
          findings.push({
            id: "AUTH-001",
            severity: "high",
            confidence: "medium",
            title: `Middleware exists but its matcher does NOT cover ${routePath} — and the handler has no in-file auth`,
            file: f.rel, line: 0,
            evidence: { type: "middleware_matcher_gap", masked: `${routePath} vs matcher: ${matcherPatterns.join(", ").slice(0, 80)}`, note: "middleware-only auth is fragile: matchers drift as routes are added; add a server-side check in the handler" },
            owasp: "A01",
            fix: `Add an explicit auth check at the top of the ${routePath} handler (verify session/token server-side, return 401), independent of middleware.`,
            fix_mode: "suggested-diff",
            root: f.rel,
            root_cause: rootCause("AUTH-001", f.rel),
            verified: true,
          });
        }
      }
    }
  }

  // ---------- MASS-001: mass assignment ----------
  for (const f of ctx.files) {
    if (!isCodeFile(f) || isTestFile(f) || classifyFile(f) === "client") continue;
    // prepass: track body-derived vars — `const body|payload = await req.json()` / `= req.body`
    const bodyVars = new Set<string>();
    for (const line of f.lines) {
      for (const m of line.matchAll(/(?:const|let)\s+(body|payload|requestBody)\s*=\s*(?:await\s+)?(?:req(?:uest)?\.(?:json\s*\(\s*\)|body)|request\.body)/g)) bodyVars.add(m[1]);
    }
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      const bodyExpr = `(?:${["req\\.body", "request\\.body", "requestBody", ...bodyVars].join("|")})`;
      const directBody =
        new RegExp(`\\.\\s*(insert|upsert|update)\\s*\\(\\s*${bodyExpr}\\b`).test(line) ||
        /data\s*:\s*(req\.body|request\.body|requestBody)\b/.test(line) ||
        new RegExp(`\\.\\s*(insert|upsert|update|create)\\s*\\(\\s*\\{\\s*\\.\\.\\.\\s*${bodyExpr}\\b`).test(line) ||
        /create\s*\(\s*\{\s*data\s*:\s*(req\.body|request\.body)\b/.test(line);
      if (!directBody) continue;
      const window = f.lines.slice(Math.max(0, i - 8), i + 9).join("\n");
      const whitelisted =
        /\.pick\s*\(|\.omit\s*\(|whitelist\s*:\s*true|ValidationPipe|plainTo(Instance|Class)|safeParse|(?<!JSON)\.parse\s*\(|class-validator|zod|select\s*:\s*\{/.test(window);
      if (whitelisted) continue; // clean case: explicit whitelist/validation
      findings.push({
        id: "MASS-001",
        severity: "high",
        confidence: "medium",
        title: "Request body flows into a database write without a whitelist — clients can set fields they must not (role, is_admin, …)",
        file: f.rel, line: i + 1,
        evidence: { type: "mass_assignment", masked: line.trim().slice(0, 80), note: "attacker adds \"role\": \"admin\" to the JSON body — nothing strips it" },
        owasp: "A04",
        fix: "Map the request to an explicit whitelist (pick only known fields, or a validated DTO/schema) before persisting. Never pass the raw body object.",
        fix_mode: "suggested-diff",
        root: f.rel,
        root_cause: rootCause("MASS-001", f.rel),
        verified: true,
      });
    }
  }

  // ---------- WS-001: Socket.IO gateways without auth ----------
  for (const f of ctx.files) {
    if (!isCodeFile(f) || isTestFile(f)) continue;
    // negative-signal detection runs on CODE only — seed comments literally name
    // the missing defenses ("io.use", "WsGuard") and must not silence the rule
    const codeOnly = f.lines.filter((l) => { const t = l.trimStart(); return !t.startsWith("//") && !t.startsWith("*") && !t.startsWith("/*"); }).join("\n");
    const isNestGateway = /@WebSocketGateway\s*\(/.test(codeOnly);
    const isPlainIo = /\bio\.on\s*\(\s*["'`]connection["'`]/.test(codeOnly) || /new\s+Server\s*\([^)]*socketio/i.test(codeOnly) || /require\(\s*["'`]socket\.io|from\s+["'`]socket\.io/.test(codeOnly) && /io\.on\s*\(\s*["'`]connection/.test(codeOnly);
    if (!isNestGateway && !isPlainIo) continue;
    const hasHandlers = isNestGateway ? /@SubscribeMessage/.test(codeOnly) : /socket\.on\s*\(/.test(codeOnly);
    if (!hasHandlers) continue;
    const authHook =
      /io\.use\s*\(|server\.use\s*\(|@UseGuards|WsGuard|handleConnection[\s\S]{0,400}(auth|token|verify|handshake)/i.test(codeOnly) ||
      /handshake\?*\.auth|handshake\.headers\[?['"]?authorization/i.test(codeOnly);
    if (authHook) continue; // clean case: connection-level auth middleware exists
    findings.push({
      id: "WS-001",
      severity: isNestGateway ? "high" : "medium",
      confidence: "medium",
      title: isNestGateway
        ? "WebSocket gateway handles events with no connection auth — any client can join and emit"
        : "Socket.IO connection handler has no io.use() auth middleware — verify identity at connection time",
      file: f.rel, line: 0,
      evidence: { type: "socket_no_auth", masked: f.rel, note: "auth may live in a shared adapter — confirm before treating as exploitable" },
      owasp: "A07",
      fix: "Authenticate at connection time: verify the token from handshake.auth/handshake.headers in io.use() (or handleConnection / a WsGuard) and reject unauthenticated sockets.",
      fix_mode: "suggested-diff",
      needs_confirmation: true,
      root: f.rel,
      root_cause: rootCause("WS-001", f.rel),
      verified: true,
    });
  }

  // ---------- WEBHOOK-001: webhooks without signature verification ----------
  for (const f of ctx.files) {
    if (!isCodeFile(f) || isTestFile(f) || classifyFile(f) === "client") continue;
    const codeOnly = f.lines.filter((l) => { const t = l.trimStart(); return !t.startsWith("//") && !t.startsWith("*") && !t.startsWith("/*"); }).join("\n");
    const isWebhook =
      /webhook/i.test(f.rel) ||
      /\.(post|all)\s*\(\s*["'`][^"'`]*webhook[^"'`]*["'`]/i.test(codeOnly);
    if (!isWebhook) continue;
    if (!/\bexport\s+(?:async\s+)?function\s+(POST|PUT)\b|router\.post|app\.post/i.test(codeOnly)) continue;
    const signatureCheck =
      /constructEvent|createHmac|hmac|\bsignature\b|verifySignature|sig[-_]?verify|sha1|sha256/i.test(codeOnly);
    if (signatureCheck) continue; // clean case: signature verified in-file
    findings.push({
      id: "WEBHOOK-001",
      severity: "high",
      confidence: "medium",
      title: "Webhook endpoint processes requests without verifying a signature — anyone can forge provider events",
      file: f.rel, line: 0,
      evidence: { type: "webhook_no_signature", masked: f.rel, note: "verification may live in a shared proxy/middleware — confirm" },
      owasp: "A07",
      fix: "Verify the provider signature before processing: compute the HMAC over the raw body (e.g. stripe.webhooks.constructEvent) and reject mismatches with 400 before any side effect.",
      fix_mode: "suggested-diff",
      needs_confirmation: true,
      root: f.rel,
      root_cause: rootCause("WEBHOOK-001", f.rel),
      verified: true,
    });
  }

  // ---------- JWT-001 / JWT-002 ----------
  for (const f of ctx.files) {
    if (!isCodeFile(f) || isTestFile(f)) continue;
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      const trimmed = line.trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) continue; // docs are not code
      if (/jwt\.decode\s*\(|\.decode\s*\(\s*(token|jwt|accessToken|access_token)/.test(line)) {
        const window = f.lines.slice(Math.max(0, i - 8), i + 9).join("\n");
        const authzDecision =
          /isAdmin|is_admin|\brole\b|permission|authoriz|req\.user|context\.user|can[A-Z]\w*|allowed|forbid/i.test(window);
        if (authzDecision) {
          findings.push({
            id: "JWT-001",
            severity: "high",
            confidence: "high",
            title: "jwt.decode() feeds an authorization decision — decode does NOT verify the signature",
            file: f.rel, line: i + 1,
            evidence: { type: "jwt_decode_authz", masked: line.trim().slice(0, 80), note: "anyone can craft a token with any role/claim — jwt.decode trusts it blindly" },
            owasp: "A07",
            fix: "Use jwt.verify(token, secret, { algorithms: [...] }) — verification first; only then read claims for decisions.",
            fix_mode: "suggested-diff",
            root: f.rel,
            root_cause: rootCause("JWT-001", f.rel),
            verified: true,
          });
        }
        // decode for display/debug only → clean case, silent
      }
      if (/jwt\.verify\s*\(|\.verify\s*\(\s*(token|jwt|accessToken)/.test(line) || /jwt\.verify\s*\(/.test(f.lines.slice(Math.max(0, i - 3), i + 1).join("\n"))) {
        const verifyWindow = f.lines.slice(Math.max(0, i - 3), i + 4).join("\n");
        if (/algorithms\s*:\s*\[[^\]]*["'`]none["'`]/i.test(verifyWindow) || /algorithms\s*:\s*["'`]none["'`]/i.test(verifyWindow)) {
          findings.push({
            id: "JWT-002",
            severity: "high",
            confidence: "high",
            title: "jwt.verify accepts algorithm \"none\" — unsigned tokens pass verification",
            file: f.rel, line: i + 1,
            evidence: { type: "jwt_alg_none", masked: line.trim().slice(0, 80) },
            owasp: "A07",
            fix: 'Pin the expected algorithms explicitly, e.g. { algorithms: ["HS256"] } (or RS256) — never allow "none".',
            fix_mode: "suggested-diff",
            root: f.rel,
            root_cause: rootCause("JWT-002", f.rel),
            verified: true,
          });
        } else if (/ignoreExpiration\s*:\s*true/i.test(verifyWindow)) {
          findings.push({
            id: "JWT-002",
            severity: "high",
            confidence: "high",
            title: "jwt.verify called with ignoreExpiration: true — expired tokens are accepted forever",
            file: f.rel, line: i + 1,
            evidence: { type: "jwt_ignore_expiration", masked: line.trim().slice(0, 80) },
            owasp: "A07",
            fix: "Remove ignoreExpiration — let verification enforce exp. For refresh flows, verify the refresh token separately.",
            fix_mode: "suggested-diff",
            root: f.rel,
            root_cause: rootCause("JWT-002", f.rel),
            verified: true,
          });
        } else if (
          // Unpinned = NO resolved algorithms list. "{ algorithms: undefined }" (or
          // null) is runtime-unpinned exactly like a missing option — same HS/RS
          // confusion class, MEDIUM (intended behavior, METHODOLOGY §4.1, gate U10.1).
          !/algorithms\s*:/.test(verifyWindow) ||
          /algorithms\s*:\s*(undefined|null)\b/.test(verifyWindow)
        ) {
          findings.push({
            id: "JWT-002",
            severity: "medium",
            confidence: "medium",
            title: "jwt.verify without a pinned algorithms option — verification accepts every registered algorithm",
            file: f.rel, line: i + 1,
            evidence: { type: "jwt_alg_unpinned", masked: line.trim().slice(0, 80), note: "pin { algorithms: [\"HS256\"] } (or your RS variant) to kill algorithm-confusion classes" },
            owasp: "A07",
            fix: "Pin the algorithms array in the verify options — algorithm confusion (HS/RS mixups) is a whole exploit class this closes.",
            fix_mode: "suggested-diff",
            root: f.rel,
            root_cause: rootCause("JWT-002", f.rel),
            verified: true,
          });
        } else {
          // clean case: algorithms pinned, no ignoreExpiration — silent
        }
      }
    }
  }

  // ---------- SWAGGER-001 ----------
  for (const f of ctx.files) {
    if (!isCodeFile(f) || isTestFile(f)) continue;
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      if (!/SwaggerModule\.setup\s*\(|swaggerUi\.setup\s*\(|swagger-ui-express/.test(line)) continue;
      const window = f.lines.slice(Math.max(0, i - 8), i + 9).join("\n");
      const guarded = /NODE_ENV|process\.env\.[A-Z_]*ENV/.test(window) && /production|prod/.test(window);
      if (guarded) continue; // clean case: env-guarded
      findings.push({
        id: "SWAGGER-001",
        severity: "medium",
        confidence: "high",
        title: "Swagger/OpenAPI UI served without a production guard — full API surface is public",
        file: f.rel, line: i + 1,
        evidence: { type: "swagger_public", masked: line.trim().slice(0, 80) },
        owasp: "A05",
        fix: 'Serve Swagger only outside production: if (process.env.NODE_ENV !== "production") SwaggerModule.setup(...).',
        fix_mode: "suggested-diff",
        root: f.rel,
        root_cause: rootCause("SWAGGER-001", f.rel),
        verified: true,
      });
    }
  }

  // ---------- NEXT-005: CSRF heuristic (cookie-authenticated mutations) ----------
  if (fw.nextjs) {
    for (const f of ctx.files) {
      if (!isCodeFile(f) || isTestFile(f) || classifyFile(f) !== "server") continue;
      if (!/\bexport\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b/.test(f.content)) continue;
      const cookieAuth = /cookies\(\)\.get|req\.cookies|request\.cookies|\.cookies\.get/.test(f.content);
      if (!cookieAuth) continue;
      const csrfDefense =
        /csrf|xsrf|sec-fetch-site|sameSite\s*:\s*["'`]strict["'`]|origin\s*===|checkOrigin|double[_-]?submit/i.test(f.content);
      if (csrfDefense) continue; // clean case
      findings.push({
        id: "NEXT-005",
        severity: "medium",
        confidence: "medium",
        title: "Cookie-authenticated mutating endpoint with no CSRF defense signal (heuristic)",
        file: f.rel, line: 0,
        evidence: { type: "csrf_heuristic", masked: f.rel, note: "heuristic — SameSite=Lax cookies block most cross-site POSTs; confirm whether this endpoint needs an origin check or CSRF token" },
        owasp: "A01",
        fix: "Add a defense-in-depth CSRF check: verify Origin/Sec-Fetch-Site against your host (or a CSRF token), keep SameSite strict/lax on the session cookie.",
        fix_mode: "suggested-diff",
        root: f.rel,
        root_cause: rootCause("NEXT-005", f.rel),
        verified: true,
      });
    }
  }

  // ---------- PRISMA-001: multi-tenancy hint (low-confidence — never deducts) ----------
  for (const f of ctx.files) {
    if (!isCodeFile(f) || isTestFile(f) || classifyFile(f) === "client") continue;
    if (!/from\s+["'`]@prisma\/client|new\s+PrismaClient/.test(f.content)) continue;
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      const m = line.match(/prisma\.(\w+)\.(findMany|findFirst|findUnique|update|updateMany|delete|deleteMany|aggregate)\s*\(/);
      if (!m) continue;
      if (!/(org|tenant|workspace|team|company|account)/i.test(m[1])) continue; // not a tenant-scoped model
      const window = f.lines.slice(Math.max(0, i - 6), i + 8).join("\n");
      const scoped = /(org|tenant|workspace|team|company)[A-Za-z]*\s*[:=]|userId|user_id|authorId|ownerId|where\s*:\s*\{\s*id/.test(window);
      if (scoped) continue; // clean case: tenant/user scoping present
      findings.push({
        id: "PRISMA-001",
        severity: "low",
        confidence: "low",
        title: `Prisma query on tenant-scoped model "${m[1]}" without a visible tenant/user filter (hint)`,
        file: f.rel, line: i + 1,
        evidence: { type: "multitenancy_hint", masked: line.trim().slice(0, 70), note: "review note — confirm the filter exists upstream (middleware, RLS, or a where clause) so tenants cannot read each other's rows" },
        owasp: "A01",
        fix: "Scope every query to the caller's tenant/org (where: { orgId }) — or prove scoping comes from RLS/middleware.",
        fix_mode: "suggested-diff",
        root: f.rel,
        root_cause: rootCause("PRISMA-001", f.rel),
        verified: true,
      });
      break; // one hint per file is enough — this is a review note
    }
  }

  return { findings };
}

// ---------- middleware matcher helpers (AUTH-001) ----------
// exported for unit tests (tests/verify-units.mjs) — pure pattern functions

export function parseMatcher(content: string): string[] | null {
  const m = content.match(/matcher\s*:\s*(\[[\s\S]*?\])/);
  if (!m) return null; // no matcher — middleware runs for everything except its own exclusions; can't reason statically
  try {
    const arr = JSON.parse(m[1].replace(/'/g, '"'));
    return Array.isArray(arr) && arr.length ? arr.map(String) : null;
  } catch {
    return null;
  }
}

export function matcherCovers(patterns: string[], routePath: string): boolean {
  for (const p of patterns) {
    // Next.js regex-style matcher: "/((?!api|_next/static|favicon.ico).*)" — covers everything EXCEPT listed prefixes
    const neg = p.match(/\(\?!\s*([^)]+?)\s*\)/);
    if (neg) {
      const negatives = neg[1].split("|").map((s) => s.replace(/^\/+/, "").replace(/\/.*$/, ""));
      const isNegative = negatives.some((n) => n && (routePath === `/${n}` || routePath.startsWith(`/${n}/`) || routePath.startsWith(`/${n}`)));
      if (!isNegative) return true; // covered by the catch-all
      continue;
    }
    const re = matcherToRegExp(p);
    if (re && re.test(routePath)) return true;
  }
  return false;
}

export function matcherToRegExp(pattern: string): RegExp | null {
  try {
    // trailing wildcard ("/api/*", "/admin/:path*") = Next-style prefix semantics:
    // covers the named segment and everything under it — a literal `/ *` regex
    // ("zero or more slashes") under-covered subtrees and produced matcher-gap FPs.
    if (/\*$/.test(pattern)) {
      const base = pattern.replace(/\/(?::path)?\*$/, ""); // strip "/:path*" or "/*" or "/**" suffix
      const body = base.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
      return new RegExp(`^${body}(/.*)?/?$`);
    }
    let body = pattern
      .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
      .replace(/:path\*/g, ".*")
      .replace(/:path\+/g, ".+")
      .replace(/:(\w+)\*/g, ".*")
      .replace(/:(\w+)\+/g, ".+")
      .replace(/:(\w+)\?/g, "[^/]*")
      .replace(/:(\w+)/g, "[^/]+");
    return new RegExp(`^${body}\\/?$`);
  } catch {
    return null;
  }
}
