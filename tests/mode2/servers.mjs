/**
 * v0.4 Mode 2 test fixtures — local HTTP servers (127.0.0.1) that plant every
 * class the scanner must catch, plus a clean site that must score high, plus a
 * fake Supabase data API and a .well-known ownership verifier.
 *
 * Nothing here leaves the machine — the whole v0.4 acceptance runs offline.
 */
import { createServer } from "node:http";

const HTML_BAD = `<!doctype html><html><head><title>Bad Vibe Shop</title></head>
<body><div id="app"></div>
<script src="/_next/static/app.js"></script>
<script src="/_next/static/vendor.js"></script>
<script>var cfg = { api: "https://internal.corp.local/api" };</script>
</body></html>`;

const HTML_CLEAN = `<!doctype html><html><head><title>Clean Site</title>
<meta name="generator" content="plain">
</head><body><div id="root"></div>
<script src="/static/main.js"></script>
</body></html>`;

// JWT-shaped tokens with correct HS256 structure (header.payload.signature)
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const SERVICE_ROLE_JWT = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "https://abcdefghij1234567890.supabase.co/auth/v1", ref: "abcdefghij1234567890", role: "service_role" })}.SiGn4tureP4rtW1thM0reTh4nTenCh4r4cters`;
const ANON_JWT = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "https://abcdefghij1234567890.supabase.co/auth/v1", ref: "abcdefghij1234567890", role: "anon" })}.An0nS1gn4tureP4rtW1thM0reTh4nTenCh4rs`;

export const OWNING_NONCE = process.env.ANUBIS_TEST_NONCE ?? "test-nonce-0123456789abcdef";

const BAD_JS = `var SUPABASE_URL="https://abcdefghij1234567890.supabase.co";
var SUPABASE_KEY="${ANON_JWT}";
var SR="${SERVICE_ROLE_JWT}";
var stripeKey="sk_live_51H8xYq2eZvKYlo2C9xAbCdEfGh";
//# sourceMappingURL=/_next/static/app.js.map`;

const CLEAN_JS = `console.log("clean bundle — no secrets here");`;

const BAD_MAP = JSON.stringify({
  version: 3,
  sources: ["app/index.ts", "lib/supabase.ts"],
  sourcesContent: ["const ADMIN_TOKEN = 'ghp_16CharactersXXXXXXXXXXXXXXXXXXXX';", "export const db = 'postgres://admin:s3cr3tPw@db.internal:5432/app';"],
  names: [], mappings: "",
});

/** Requests the scanner makes are recorded here (request-log assertions). */
export const requestLog = [];
export const methodLog = [];

function record(req) {
  const u = req.url ?? "/";
  if (u.startsWith("/__")) return; // test-control endpoints are never recorded
  requestLog.push({ method: req.method, url: u });
  methodLog.push(req.method);
}

/** Bad site: every planted hole. */
export function createBadServer({ port = 0 } = {}) {
  const srv = createServer((req, res) => {
    record(req);
    const u = req.url ?? "/";
    const send = (status, body, headers = {}) => {
      res.writeHead(status, { "content-type": "text/plain; charset=utf-8", ...headers });
      res.end(body);
    };

    // insecure session cookie on everything
    if (res.setHeader) res.setHeader("Set-Cookie", "sid=abc123; Path=/");

    // method probes must be matched BEFORE the "/" route (path "/" intercepts them otherwise)
    if (req.method === "OPTIONS") {
      res.writeHead(200, { Allow: "GET, POST, PUT, DELETE, OPTIONS", "content-type": "text/plain" });
      return res.end();
    }
    if (req.method === "TRACE") {
      // reflect — the XST classic
      res.writeHead(200, { "content-type": "message/http" });
      return res.end(`TRACE / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Marker: anubis-trace-reflection`);
    }

    if (u === "/") return send(200, HTML_BAD, { "content-type": "text/html", server: "nginx/1.24.0", "x-powered-by": "Express" });
    if (u === "/__requestlog") {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ requests: requestLog, methods: methodLog }));
    }
    if (u === "/robots.txt") return send(200, "User-agent: *\nDisallow: /admin\n", { "content-type": "text/plain" });
    if (u === "/sitemap.xml") return send(200, '<?xml version="1.0"?><urlset></urlset>', { "content-type": "application/xml" });
    if (u === "/.well-known/security.txt") return send(404, "not found");
    if (u === "/_next/static/app.js") return send(200, BAD_JS, { "content-type": "application/javascript" });
    if (u === "/_next/static/vendor.js") return send(200, "console.log('vendor');", { "content-type": "application/javascript" });
    if (u === "/_next/static/app.js.map") return send(200, BAD_MAP, { "content-type": "application/json" });

    // planted L2 holes
    if (u === "/.env") return send(200, "DATABASE_PASSWORD=CorrectHorse9x!\nSTRIPE_SECRET_KEY=sk_live_51H8xYq2eZvKYlo2C9xAbCdEfGh\n", { "content-type": "application/octet-stream" });
    if (u === "/.env.local") return send(200, "<!doctype html><html>404 SPA shell</html>", { "content-type": "text/html" }); // decoy — SPA catch-all, NOT an env file
    if (u === "/.git/config") return send(200, "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:owner/repo.git\n", { "content-type": "text/plain" });
    if (u === "/db.sql") return send(200, "CREATE TABLE users (id int);\nINSERT INTO users VALUES (1,'a@b.c');\n", { "content-type": "application/sql" });
    if (u === "/backup/") return send(200, "<html><head><title>Index of /backup/</title></head><body><a href=\"db.sql\">db.sql</a></body></html>", { "content-type": "text/html" });
    if (u === "/swagger/index.html") return send(200, "<html><head><title>Swagger UI</title></head><body class='swagger-ui'></body></html>", { "content-type": "text/html" });
    if (u === "/admin") return send(200, "<html><head><title>Admin Panel</title></head><body><div id=\"app\">login</div></body></html>", { "content-type": "text/html" });

    if (u === "/.well-known/anubis-guardian/" + OWNING_NONCE) return send(200, "anubis-guardian ownership verification: " + OWNING_NONCE);
    if (u.startsWith("/.well-known/anubis-guardian/")) return send(404, "wrong nonce");

    return send(404, "not found");
  });
  return new Promise((resolve) => srv.listen(port, "127.0.0.1", () => resolve(srv)));
}

/** Clean site: headers right, cookies right, nothing planted. */
export function createCleanServer({ port = 0 } = {}) {
  const srv = createServer((req, res) => {
    record(req);
    const u = req.url ?? "/";
    const H = {
      "content-security-policy": "default-src 'self'",
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "x-frame-options": "DENY",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "camera=(), microphone=(), geolocation=()",
      "set-cookie": "sid=clean123; Path=/; Secure; HttpOnly; SameSite=Lax",
    };
    const send = (status, body, headers = {}) => {
      res.writeHead(status, { ...H, ...headers });
      res.end(body);
    };
    if (u === "/") return send(200, HTML_CLEAN, { "content-type": "text/html" });
    if (u === "/robots.txt") return send(200, "User-agent: *\nAllow: /\n", { "content-type": "text/plain" });
    if (u === "/sitemap.xml") return send(200, '<?xml version="1.0"?><urlset></urlset>', { "content-type": "application/xml" });
    if (u === "/.well-known/security.txt") return send(200, "Contact: mailto:security@example.test\nExpires: 2027-01-01T00:00:00Z\n");
    if (u === "/static/main.js") return send(200, CLEAN_JS, { "content-type": "application/javascript" });
    return send(404, "not found");
  });
  return new Promise((resolve) => srv.listen(port, "127.0.0.1", () => resolve(srv)));
}

/** Fake Supabase data API: OpenAPI listing + one exposed table + one locked. */
export function createSupabaseServer({ port = 0 } = {}) {
  const tables = { profiles: true, audit_log: false }; // true = returns rows (RLS broken), false = 401
  const srv = createServer((req, res) => {
    record(req);
    const u = req.url ?? "/";
    const key = req.headers.apikey ?? "";
    if (!key.startsWith("eyJ")) {
      res.writeHead(401, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "invalid api key" }));
    }
    if (u === "/rest/v1/") {
      res.writeHead(200, { "content-type": "application/openapi+json" });
      const paths = {};
      for (const t of Object.keys(tables)) paths["/" + t] = {};
      return res.end(JSON.stringify({ openapi: "3.0.0", paths }));
    }
    const m = u.match(/^\/rest\/v1\/([a-z_]+)\?select=\*&limit=1$/);
    if (m) {
      const t = m[1];
      if (tables[t] === true) {
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(JSON.stringify([{ id: 1, email: "victim@example.test" }]));
      }
      res.writeHead(401, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "permission denied" }));
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end("{}");
  });
  return new Promise((resolve) => srv.listen(port, "127.0.0.1", () => resolve(srv)));
}

export async function listen(srv) {
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${srv.address().port}`;
}

// ---- child-server mode: `node servers.mjs --serve` (tests spawnSync the CLI —
// servers must live in a separate process or the event loop deadlocks) ----
if (process.argv.includes("--serve")) {
  const bad = await createBadServer();
  const clean = await createCleanServer();
  const p = (s) => s.address().port;
  process.stdout.write(JSON.stringify({ ready: true, bad: p(bad), clean: p(clean), nonce: OWNING_NONCE }) + "\n");
  const close = () => { try { bad.close(); clean.close(); } catch { /* exiting */ } process.exit(0); };
  process.on("SIGTERM", close);
  process.on("SIGINT", close);
}
