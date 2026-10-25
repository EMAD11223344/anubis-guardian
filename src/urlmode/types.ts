/**
 * URL Mode (v0.4) — data contracts for Mode 2 (Plan Section 7).
 *
 * Design: capture-then-analyze. Phase A (network) produces a CaptureBundle;
 * Phase B (analyze) is a pure deterministic function bundle → findings.
 * Re-analyzing the SAME capture is byte-identical (the v0.4 determinism
 * contract — the live wire itself is not deterministic, the pipeline is).
 */

export interface CapturedResponse {
  seq: number;
  method: string;
  url: string;
  final_url: string;          // after redirects
  status: number;             // 0 = network error
  headers: Record<string, string>; // lowercased names; set-cookie joined with \n
  body: string;               // truncated to max_body_bytes
  body_truncated: boolean;
  bytes: number;              // original body byte length
  error?: string;             // network error (fetch failed etc.)
}

export interface CaptureMeta {
  url: string;
  captured_at: string;        // ISO — lives in the capture, NOT recomputed at analyze
  level: 1 | 2 | 3;
  ownership: OwnershipResult;
  tool: "anubis-guardian";
  version: string;
  max_requests: number;
  delay_ms: number;
}

export interface TlsInfo {
  protocol: string | null;      // negotiated protocol, e.g. "TLSv1.3"
  authorized: boolean;          // cert chain + hostname authorized
  daysLeft: number | null;      // days until notAfter (negative = expired)
  valid_from_iso: string | null;
  valid_to_iso: string | null;
  error?: string;
}

export interface CaptureBundle {
  capture_version: 1;
  meta: CaptureMeta;
  tls: TlsInfo | null;          // null for plain-http targets
  requests: CapturedResponse[];
  robots: { skipped: string[]; disallow_all: boolean };
  notes: string[];
  idor?: {                      // v1.0 — present only when --active-tests ran (values NEVER stored)
    endpoints: Array<{ url: string; path: string }>;
    requests: Array<{ endpoint: string; identity: "a" | "b"; seq: number }>;
    identities: string[];       // header NAMES only (e.g. ["authorization", "cookie"])
    note: string;
  };
}

export interface OwnershipResult {
  verified: boolean;
  method: "dns-txt" | "well-known" | "self-attested (local only)" | "none";
  host: string;
}

export interface UrlScanOptions {
  level: 1 | 2 | 3;
  ownershipToken?: string;    // user-published nonce to verify (DNS TXT / .well-known)
  selfAttest?: boolean;       // --i-own-this-domain — honored ONLY for local/private hosts
  timeoutMs?: number;         // per request, default 10_000
  delayMs?: number;           // min interval between same-host requests, default 250
  maxRequests?: number;       // hard cap; default per level (40 / 120 / 150)
  maxAssets?: number;         // max JS bundles fetched at L1, default 10
  // v1.0 — restricted differential IDOR (Plan v1.2 #11 — the whole L3-active scope):
  activeTests?: boolean;      // --active-tests — explicit opt-in, verified ownership enforced
  identityA?: string;         // "Header-Name: value" — privileged testing identity (value never stored)
  identityB?: string;         // "Header-Name: value" — RESTRICTED testing identity (value never stored)
  idorPaths?: string[];       // owner-supplied extra endpoints (repeatable --idor-path)
}

// UrlMeta (authorization record) lives in the canonical contract: ../types.js (single source of truth)

export const USER_AGENT =
  "anubis-guardian (security audit tool; deterministic; +https://github.com/EMAD11223344/anubis-guardian)";

export const MAX_BODY_BYTES = 512 * 1024;

/** Hard per-level request caps (Plan Section 7: "hard rate-limits"). */
export const LEVEL_REQUEST_CAPS: Record<1 | 2 | 3, number> = { 1: 40, 2: 120, 3: 150 };
