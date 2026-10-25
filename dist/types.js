/**
 * Anubis Guardian — canonical data contract (findings.json schema, Plan Section 8).
 * Every renderer (terminal/md/json) is a deterministic function over ScanResult.
 */
export const SEVERITY_WEIGHT = {
    critical: 25, high: 10, medium: 4, low: 1, info: 0,
};
export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
