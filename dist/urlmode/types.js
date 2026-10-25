/**
 * URL Mode (v0.4) — data contracts for Mode 2 (Plan Section 7).
 *
 * Design: capture-then-analyze. Phase A (network) produces a CaptureBundle;
 * Phase B (analyze) is a pure deterministic function bundle → findings.
 * Re-analyzing the SAME capture is byte-identical (the v0.4 determinism
 * contract — the live wire itself is not deterministic, the pipeline is).
 */
// UrlMeta (authorization record) lives in the canonical contract: ../types.js (single source of truth)
export const USER_AGENT = "anubis-guardian (security audit tool; deterministic; +https://github.com/EMAD11223344/anubis-guardian)";
export const MAX_BODY_BYTES = 512 * 1024;
/** Hard per-level request caps (Plan Section 7: "hard rate-limits"). */
export const LEVEL_REQUEST_CAPS = { 1: 40, 2: 120, 3: 150 };
