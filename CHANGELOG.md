# Changelog

## 1.1.1 — 2026-10-26

Security fix — SSRF hardening for URL Mode (`src/urlmode/ssrf-guard.ts`, zero new deps):

- URL Mode refuses private/loopback/link-local/cloud-metadata targets by default.
  Use `--allow-private` for localhost staging (CLI only; ignored in service mode).
  Cloud metadata endpoints (169.254.169.254, 169.254.170.2, fd00:ec2::254) are
  refused unconditionally — the flag never covers them.
- Every request (and every redirect hop) runs resolve→pin→connect: one
  `dns.lookup(all:true)` per hop, EVERY returned address validated against
  binary-canonical range checks, then the connection dials the pinned IP with
  Host/SNI of the original hostname — DNS rebinding closed by construction.
- Redirects are followed manually (cap 10), re-guarded per hop; https→http
  demotion and non-http(s) `Location` schemes are refused. Refusals keep the
  last real response as evidence and surface in capture notes.
- `inspectTls` (the TLS probe) now passes the same guard.
- Service mode (`ANUBIS_SERVICE=1`): port allowlist 80/443/8080/8443 only,
  5 MB response cap (`ANUBIS_MAX_RESPONSE_BYTES`), 10s connect + 30s
  read-idle timeouts.
- CLI behavior change: private/loopback targets are refused without
  `--allow-private`; the ownership gate (`--i-own-this-domain`) is unchanged.
- Tests: units 108 → 145 (U14 SSRF gate block incl. per-hop refusals over a
  real local server, sequential-lookup rebinding, service port policy);
  mode2 suites updated for the new CLI default.

### Phase 2 — pending, deliberately NOT in this release

- **Service-mode hard-exit-2 wiring**: when `ANUBIS_SERVICE=1`, a private-range
  refusal must terminate the CLI with exit 2 (Phase 1 only records the refusal —
  the guard, port policy and limits are enforced, the fatal CLI wiring is not).
- **scan-url UX + integration**: usage flows, refusal messaging, and any
  hosted-deployment review flow around `scan-url`.
