# Anubis Guardian — Fix Prompt

> Generated deterministically from findings.json (anubis-guardian 1.0.1).
> Target: `http://127.0.0.1:61787` · Score: **10/100 (F)** · Findings: 17 (C:2 H:2 M:3 L:8 I:2)
> URL Mode · level 1 · ownership: **none** · scan authorized: 2026-10-25T13:42:31.947Z

This report is a black-box EXTERNAL view (no source access). For every finding: first MAP the flagged URL/endpoint to the code (the evidence + the `Code map:` hint in each fix), verify it, then fix and redeploy; re-run this URL scan to confirm.

## 1. [CRITICAL] URL-040 — Secret shipped in a public JavaScript bundle (supabase)
- Location: `http://127.0.0.1:61787/_next/static/app.js:0`
- Evidence: eyJh•••… (first-4 + sha256:b805303b) — JWT-shaped token — confirmed below by decoding the role claim
- Fix: Remove the secret from any code reachable by the client build, move it to server-side env only, rotate the credential at the provider (rotate-first), then purge old bundles/CDN cache.
- Remediation: Rotate the credential at the provider dashboard FIRST, then remove it from client code, then purge CDN/edge cache of old bundles.
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.

## 2. [CRITICAL] URL-040 — Secret shipped in a public JavaScript bundle (stripe)
- Location: `http://127.0.0.1:61787/_next/static/app.js:0`
- Evidence: sk_l•••… (first-4 + sha256:0a040371)
- Fix: Remove the secret from any code reachable by the client build, move it to server-side env only, rotate the credential at the provider (rotate-first), then purge old bundles/CDN cache.
- Remediation: Rotate the credential at the provider dashboard FIRST, then remove it from client code, then purge CDN/edge cache of old bundles.
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.

## 3. [HIGH] URL-001 — Site served over plain HTTP (no TLS)
- Location: `http://127.0.0.1:61787:0`
- Evidence: http:// origin — every request — including session cookies — travels in cleartext
- Fix: Serve over HTTPS (terminate TLS at the edge/provider, redirect http→https, enable HSTS once stable).
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.

## 4. [HIGH] URL-021 — Session cookie "sid" set without HttpOnly (readable by any XSS)
- Location: `http://127.0.0.1:61787:0`
- Evidence: sid — session-shaped name
- Fix: Set HttpOnly on "sid" — session cookies must never be readable from JS.
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.

## 5. [MEDIUM] URL-020 — Cookie "sid" set without the Secure flag
- Location: `http://127.0.0.1:61787:0`
- Evidence: sid — cookie can travel over plain http
- Fix: Set the Secure attribute on "sid" (and serve the site over https only).
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.

## 6. [MEDIUM] URL-010 — Content-Security-Policy header missing
- Location: `http://127.0.0.1:61787/:0`
- Evidence: content-security-policy — response 200 carries no content-security-policy
- Fix: Serve a Content-Security-Policy header (start with a report-then-enforce rollout; script-src 'self', no unsafe-inline for new code). Code map: middleware.ts (response headers) or next.config.js headers()/async headers — or the reverse proxy (nginx/vercel.json).
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.

## 7. [MEDIUM] URL-012 — Clickjacking protection missing (no X-Frame-Options / frame-ancestors)
- Location: `http://127.0.0.1:61787/:0`
- Evidence: x-frame-options — response 200 carries no x-frame-options
- Fix: Serve X-Frame-Options: DENY (or CSP frame-ancestors 'none') so the site cannot be framed by attacker pages. Code map: middleware.ts (response headers) or next.config.js headers()/async headers — or the reverse proxy (nginx/vercel.json).
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.

## 8. [LOW] URL-022 — Cookie "sid" set without SameSite
- Location: `http://127.0.0.1:61787:0`
- Evidence: sid
- Fix: Set SameSite=Lax (or Strict) on "sid" to blunt CSRF.
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.

## 9. [LOW] URL-013 — X-Content-Type-Options header missing
- Location: `http://127.0.0.1:61787/:0`
- Evidence: x-content-type-options — response 200 carries no x-content-type-options
- Fix: Serve X-Content-Type-Options: nosniff on all responses. Code map: middleware.ts (response headers) or next.config.js headers()/async headers — or the reverse proxy (nginx/vercel.json).
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.

## 10. [LOW] URL-014 — Referrer-Policy header missing
- Location: `http://127.0.0.1:61787/:0`
- Evidence: referrer-policy — response 200 carries no referrer-policy
- Fix: Serve Referrer-Policy: strict-origin-when-cross-origin (or stricter). Code map: middleware.ts (response headers) or next.config.js headers()/async headers — or the reverse proxy (nginx/vercel.json).
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.

## 11. [LOW] URL-015 — Permissions-Policy header missing
- Location: `http://127.0.0.1:61787/:0`
- Evidence: permissions-policy — response 200 carries no permissions-policy
- Fix: Serve a Permissions-Policy restricting camera/microphone/geolocation to none (or first-party only). Code map: middleware.ts (response headers) or next.config.js headers()/async headers — or the reverse proxy (nginx/vercel.json).
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.

## 12. [LOW] URL-030 — Server header discloses a specific version
- Location: `http://127.0.0.1:61787/:0`
- Evidence: nginx/1.24.0
- Fix: Strip or genericize the Server header version at the edge (banner disclosure feeds attacker recon).
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.

## 13. [LOW] URL-031 — X-Powered-By header discloses the stack
- Location: `http://127.0.0.1:61787/:0`
- Evidence: Express
- Fix: Remove X-Powered-By at the server/proxy (e.g. helmet.hidePoweredBy / proxy hideHeaders).
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.

## 14. [LOW] URL-905 — security.txt absent (RFC 9116)
- Location: `http://127.0.0.1:61787/.well-known/security.txt:0`
- Evidence: no /.well-known/security.txt
- Fix: Publish /.well-known/security.txt so researchers can report issues safely.
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.

## 15. [LOW] URL-041 — Public bundle references internal/localhost endpoints
- Location: `http://127.0.0.1:61787/#inline-script:0`
- Evidence: https://internal.corp.local/api
- Fix: Remove internal hostnames from client code; route internal calls through a server-side proxy.
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.

## 16. [INFO] URL-900 — Technology fingerprint: express, nextjs
- Location: `http://127.0.0.1:61787/:0`
- Evidence: express,nextjs
- Fix: Informational — findings below pair with code-map hints per detected framework.
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.

## 17. [INFO] URL-043 — Bundle references a sourceMappingURL (check exposure at Level 2)
- Location: `http://127.0.0.1:61787/_next/static/app.js:0`
- Evidence: /_next/static/app.js.map
- Fix: A .map file is referenced next to http://127.0.0.1:61787/_next/static/app.js. Level 2 checks whether it is actually exposed and ships original sources.
- Verify: re-run `npx anubis-guardian scan-url http://127.0.0.1:61787` (same level) and confirm the finding is gone and the score moves.


## Guardrails (hard rules for the fixing agent)
1. Secrets: NEVER touch code that prints/uses a secret before rotating it. Rotate the credential FIRST (provider dashboard), then update the code, then scrub history (git filter-repo).
2. Scope: fix ONLY the findings listed here. No refactoring, no dependency upgrades, no style changes outside the flagged lines.
3. Tests: do NOT edit, skip, or weaken tests to make a fix pass. Add a regression test only when the finding requires one.
4. Confirmation findings: items marked [needs confirmation] must be verified by a human (or an owner-run probe) before treating them as exploitable.
5. Output: propose a suggested diff per finding — apply nothing automatically.

## Not covered by this scan (do not assume absence of risk)
- authenticated-area testing & business-logic flaws beyond the restricted differential check
- injection testing (XSS/SQLi canaries — delegated: init-zap generates the ZAP baseline config, v1.0 decision)
- full DAST / fuzzing (by design — delegated to the generated ZAP config)
- server internals, databases, queues (black-box view only — pair with Codebase Mode)
- subdomain takeover & DNS-level attacks
- rate-limit/lockout behavior checks
