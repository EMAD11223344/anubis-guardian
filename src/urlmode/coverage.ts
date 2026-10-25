/**
 * URL Mode coverage registry (honesty contract — Plan Section 8/13):
 * checks_run / checks_applicable reflect what the chosen level actually ran.
 */

export interface UrlCheck {
  id: string;
  level: 1 | 2 | 3;
  description: string;
}

export const URL_CHECKS: UrlCheck[] = [
  { id: "URL-001", level: 1, description: "site served over plain HTTP" },
  { id: "URL-002", level: 1, description: "weak TLS protocol negotiated (<1.2)" },
  { id: "URL-003", level: 1, description: "certificate expired / expiring / invalid" },
  { id: "URL-010", level: 1, description: "Content-Security-Policy missing" },
  { id: "URL-011", level: 1, description: "HSTS missing (https)" },
  { id: "URL-012", level: 1, description: "clickjacking protection missing" },
  { id: "URL-013", level: 1, description: "X-Content-Type-Options missing" },
  { id: "URL-014", level: 1, description: "Referrer-Policy missing" },
  { id: "URL-015", level: 1, description: "Permissions-Policy missing" },
  { id: "URL-020", level: 1, description: "cookie without Secure" },
  { id: "URL-021", level: 1, description: "cookie without HttpOnly (session-shaped → high)" },
  { id: "URL-022", level: 1, description: "cookie without SameSite" },
  { id: "URL-030", level: 1, description: "Server version disclosure" },
  { id: "URL-031", level: 1, description: "X-Powered-By disclosure" },
  { id: "URL-040", level: 1, description: "secret shipped in a public JS bundle" },
  { id: "URL-043", level: 1, description: "sourceMappingURL referenced (advice)" },
  { id: "URL-900", level: 1, description: "technology fingerprint (info)" },
  { id: "URL-904/905", level: 1, description: "security.txt present/absent" },
  { id: "URL-050", level: 2, description: "env/credential files publicly served" },
  { id: "URL-051", level: 2, description: ".git directory web-served" },
  { id: "URL-052", level: 2, description: "backups / SQL dumps / .DS_Store exposed" },
  { id: "URL-053", level: 2, description: "composer.json exposed" },
  { id: "URL-054", level: 2, description: "directory listing enabled" },
  { id: "URL-055", level: 2, description: "TRACE method enabled" },
  { id: "URL-056", level: 2, description: "risky methods advertised via Allow" },
  { id: "URL-057", level: 2, description: "API docs / GraphiQL exposed" },
  { id: "URL-042", level: 2, description: "source map ships original sources" },
  { id: "URL-901", level: 2, description: "auth/admin surface mapping (info)" },
  { id: "URL-060", level: 3, description: "Supabase live anon read returns rows (RLS not effective)" },
  { id: "URL-906/907/908", level: 3, description: "Supabase probe info results" },
];

export const URL_CLASSES_COVERED = [
  "TLS & certificate posture (external view)",
  "security headers & cookie flags",
  "secrets shipped in public JS bundles (L1 since v1.3)",
  "exposed env/git/backup files (L2, ownership-gated)",
  "directory listing / risky HTTP methods / exposed API docs (L2)",
  "source map exposure (L2)",
  "Supabase live anon RLS probe (L3 v0.4 — read-only GET)",
];

export const URL_CLASSES_NOT_COVERED = [
  "authenticated-area testing & business-logic flaws",
  "injection testing (XSS/SQLi canaries — L3 active, v1.0 decision point)",
  "differential IDOR (v1.0: owner accounts + --active-tests + GET-only)",
  "full DAST / fuzzing (by design — generate ZAP config instead)",
  "server internals, databases, queues (black-box view only — pair with Codebase Mode)",
  "subdomain takeover & DNS-level attacks",
  "rate-limit/lockout behavior checks (v1.0)",
];
