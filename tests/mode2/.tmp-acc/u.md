# Anubis Guardian Report — `http://127.0.0.1:61787`

**Score: 10/100 (F)** · tool v1.0.1 · advisory snapshot `2026-10`

| CRITICAL | HIGH | MEDIUM | LOW | INFO |
|---|---|---|---|---|
| 2 | 2 | 3 | 8 | 2 |

## Scan authorization record

| Field | Value |
|---|---|
| Target | `http://127.0.0.1:61787` |
| Timestamp | 2026-10-25T13:42:31.947Z |
| Level | 1 (L1-passive) |
| Ownership | **none** |
| Requests | 6 (GET:6) |

_Level 1 passive — no ownership required_

**Stack (fingerprinted):** express, nextjs · **Requests:** 6

## Score breakdown (root-cause caps)

| Rule | Root | Severity | Count | Deducted |
|---|---|---|---|---|
| URL-040 | `b805303b` | critical | 1 | −25 |
| URL-040 | `0a040371` | critical | 1 | −25 |
| URL-001 | `tls` | high | 1 | −10 |
| URL-021 | `sid` | high | 1 | −10 |
| URL-020 | `sid` | medium | 1 | −4 |
| URL-010 | `headers` | medium | 1 | −4 |
| URL-012 | `headers` | medium | 1 | −4 |
| URL-022 | `sid` | low | 1 | −1 |
| URL-013 | `headers` | low | 1 | −1 |
| URL-014 | `headers` | low | 1 | −1 |
| URL-015 | `headers` | low | 1 | −1 |
| URL-030 | `fingerprint` | low | 1 | −1 |
| URL-031 | `fingerprint` | low | 1 | −1 |
| URL-905 | `hygiene` | low | 1 | −1 |
| URL-041 | `internal-endpoints` | low | 1 | −1 |

> Low-confidence findings and INFO do not deduct. Repeats of the same root cause add +10% each, capped at 2× the severity weight (v1.3).

## Findings (15)

### CRITICAL (2)

#### URL-040 — Secret shipped in a public JavaScript bundle (supabase)

- **Location:** `http://127.0.0.1:61787/_next/static/app.js`
- **Evidence (masked):** `eyJh•••… (first-4 + sha256:b805303b)`
- **OWASP:** A02 · **Confidence:** high
- **Fingerprint:** `17cd71a369ac`
- **Fix:** Remove the secret from any code reachable by the client build, move it to server-side env only, rotate the credential at the provider (rotate-first), then purge old bundles/CDN cache.
- **Rotate-first:** Rotate the credential at the provider dashboard FIRST, then remove it from client code, then purge CDN/edge cache of old bundles.

#### URL-040 — Secret shipped in a public JavaScript bundle (stripe)

- **Location:** `http://127.0.0.1:61787/_next/static/app.js`
- **Evidence (masked):** `sk_l•••… (first-4 + sha256:0a040371)`
- **OWASP:** A02 · **Confidence:** high
- **Fingerprint:** `db17671458c0`
- **Fix:** Remove the secret from any code reachable by the client build, move it to server-side env only, rotate the credential at the provider (rotate-first), then purge old bundles/CDN cache.
- **Rotate-first:** Rotate the credential at the provider dashboard FIRST, then remove it from client code, then purge CDN/edge cache of old bundles.

### HIGH (2)

#### URL-001 — Site served over plain HTTP (no TLS)

- **Location:** `http://127.0.0.1:61787`
- **Evidence (masked):** `http:// origin`
- **OWASP:** A02 · **Confidence:** high
- **Fingerprint:** `8cd6448d9fd2`
- **Fix:** Serve over HTTPS (terminate TLS at the edge/provider, redirect http→https, enable HSTS once stable).

#### URL-021 — Session cookie "sid" set without HttpOnly (readable by any XSS)

- **Location:** `http://127.0.0.1:61787`
- **Evidence (masked):** `sid`
- **OWASP:** A07 · **Confidence:** high
- **Fingerprint:** `c163efda0690`
- **Fix:** Set HttpOnly on "sid" — session cookies must never be readable from JS.

### MEDIUM (3)

#### URL-020 — Cookie "sid" set without the Secure flag

- **Location:** `http://127.0.0.1:61787`
- **Evidence (masked):** `sid`
- **OWASP:** A05 · **Confidence:** high
- **Fingerprint:** `8e868ae03d37`
- **Fix:** Set the Secure attribute on "sid" (and serve the site over https only).

#### URL-010 — Content-Security-Policy header missing

- **Location:** `http://127.0.0.1:61787/`
- **Evidence (masked):** `content-security-policy`
- **OWASP:** A05 · **Confidence:** high
- **Fingerprint:** `7f2226189752`
- **Fix:** Serve a Content-Security-Policy header (start with a report-then-enforce rollout; script-src 'self', no unsafe-inline for new code). Code map: middleware.ts (response headers) or next.config.js headers()/async headers — or the reverse proxy (nginx/vercel.json).

#### URL-012 — Clickjacking protection missing (no X-Frame-Options / frame-ancestors)

- **Location:** `http://127.0.0.1:61787/`
- **Evidence (masked):** `x-frame-options`
- **OWASP:** A05 · **Confidence:** high
- **Fingerprint:** `38c058cb36bb`
- **Fix:** Serve X-Frame-Options: DENY (or CSP frame-ancestors 'none') so the site cannot be framed by attacker pages. Code map: middleware.ts (response headers) or next.config.js headers()/async headers — or the reverse proxy (nginx/vercel.json).

### LOW (8)

#### URL-022 — Cookie "sid" set without SameSite

- **Location:** `http://127.0.0.1:61787`
- **Evidence (masked):** `sid`
- **OWASP:** A07 · **Confidence:** high
- **Fingerprint:** `23cb02a1b0e1`
- **Fix:** Set SameSite=Lax (or Strict) on "sid" to blunt CSRF.

#### URL-013 — X-Content-Type-Options header missing

- **Location:** `http://127.0.0.1:61787/`
- **Evidence (masked):** `x-content-type-options`
- **OWASP:** A05 · **Confidence:** high
- **Fingerprint:** `07630cfa91c5`
- **Fix:** Serve X-Content-Type-Options: nosniff on all responses. Code map: middleware.ts (response headers) or next.config.js headers()/async headers — or the reverse proxy (nginx/vercel.json).

#### URL-014 — Referrer-Policy header missing

- **Location:** `http://127.0.0.1:61787/`
- **Evidence (masked):** `referrer-policy`
- **OWASP:** A05 · **Confidence:** high
- **Fingerprint:** `07cb7f2d0175`
- **Fix:** Serve Referrer-Policy: strict-origin-when-cross-origin (or stricter). Code map: middleware.ts (response headers) or next.config.js headers()/async headers — or the reverse proxy (nginx/vercel.json).

#### URL-015 — Permissions-Policy header missing

- **Location:** `http://127.0.0.1:61787/`
- **Evidence (masked):** `permissions-policy`
- **OWASP:** A05 · **Confidence:** high
- **Fingerprint:** `b7a65e747702`
- **Fix:** Serve a Permissions-Policy restricting camera/microphone/geolocation to none (or first-party only). Code map: middleware.ts (response headers) or next.config.js headers()/async headers — or the reverse proxy (nginx/vercel.json).

#### URL-030 — Server header discloses a specific version

- **Location:** `http://127.0.0.1:61787/`
- **Evidence (masked):** `nginx/1.24.0`
- **OWASP:** A05 · **Confidence:** high
- **Fingerprint:** `0e7ae89e8b5a`
- **Fix:** Strip or genericize the Server header version at the edge (banner disclosure feeds attacker recon).

#### URL-031 — X-Powered-By header discloses the stack

- **Location:** `http://127.0.0.1:61787/`
- **Evidence (masked):** `Express`
- **OWASP:** A05 · **Confidence:** high
- **Fingerprint:** `dddd0fe91663`
- **Fix:** Remove X-Powered-By at the server/proxy (e.g. helmet.hidePoweredBy / proxy hideHeaders).

#### URL-905 — security.txt absent (RFC 9116)

- **Location:** `http://127.0.0.1:61787/.well-known/security.txt`
- **Evidence (masked):** `no /.well-known/security.txt`
- **OWASP:** A05 · **Confidence:** high
- **Fingerprint:** `ab1ddc5098ff`
- **Fix:** Publish /.well-known/security.txt so researchers can report issues safely.

#### URL-041 — Public bundle references internal/localhost endpoints

- **Location:** `http://127.0.0.1:61787/#inline-script`
- **Evidence (masked):** `https://internal.corp.local/api`
- **OWASP:** A05 · **Confidence:** high
- **Fingerprint:** `9f5c089af677`
- **Fix:** Remove internal hostnames from client code; route internal calls through a server-side proxy.

### INFO (documented-correct patterns — verify env hygiene)

- `http://127.0.0.1:61787/:0` — Technology fingerprint: express, nextjs
- `http://127.0.0.1:61787/_next/static/app.js:0` — Bundle references a sourceMappingURL (check exposure at Level 2)

## Classes not covered

- authenticated-area testing & business-logic flaws beyond the restricted differential check
- injection testing (XSS/SQLi canaries — delegated: init-zap generates the ZAP baseline config, v1.0 decision)
- full DAST / fuzzing (by design — delegated to the generated ZAP config)
- server internals, databases, queues (black-box view only — pair with Codebase Mode)
- subdomain takeover & DNS-level attacks
- rate-limit/lockout behavior checks

---

_The grade reflects only the checks Anubis Guardian implements — absence of findings is not proof of security._

_Black-box external view only — pair with Codebase Mode (anubis-guardian scan .) for the code-level view. No probing beyond the authorized level; no credentialed scanning; authorization record above._