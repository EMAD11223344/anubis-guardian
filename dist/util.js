import { createHash } from "node:crypto";
/** sha256 hex prefix (8) — links findings across runs without exposing the value. */
export function sha256Prefix(value, len = 8) {
    return createHash("sha256").update(value).digest("hex").slice(0, len);
}
/**
 * Mandatory masking (Plan Section 9.2): type + location + first 4 chars + sha256 prefix.
 * The full value is NEVER written to any report, artifact or log.
 */
export function maskSecret(value) {
    const first4 = value.slice(0, 4);
    return {
        masked: `${first4}•••… (first-4 + sha256:${sha256Prefix(value)})`,
        sha256_prefix: sha256Prefix(value),
    };
}
/** Stable fingerprint: rule id + path + normalized match → first 12 hex. */
export function fingerprint(ruleId, path, normalizedMatch) {
    return createHash("sha256").update(`${ruleId}|${path}|${normalizedMatch}`).digest("hex").slice(0, 12);
}
/** Rule-side finding constructor: deterministic defaults + full override (v0.2). */
export function mkFinding(f) {
    return {
        confidence: "high",
        verified: true,
        source: "builtin",
        fix_mode: "suggested-diff",
        ...f,
    };
}
/** root_cause = rule_id + root (Plan v1.3 caps). */
export function rootCause(ruleId, root) {
    return `${ruleId}:${root}`;
}
/**
 * Inline suppression (Plan v1.2): `anubis-ignore: RULE-ID reason="..." expires="YYYY-MM-DD"`.
 * v0.1 supports inline-only suppression — config-file suppression (anubis.toml) arrives
 * later and is reserved for LOW/MEDIUM; CRITICAL is inline-only by contract.
 * Expired directives are ignored (they no longer suppress).
 */
export function parseInlineIgnores(lines) {
    const out = [];
    const re = /anubis-ignore:\s*([A-Z]+-\d+)[^\n]*?reason="([^"]*)"[^\n]*?expires="(\d{4}-\d{2}-\d{2})"/g;
    const today = new Date().toISOString().slice(0, 10);
    for (const line of lines) {
        let m;
        while ((m = re.exec(line)) !== null) {
            const [, ruleId, reason, expires] = m;
            if (expires >= today)
                out.push({ ruleId, reason, expires });
        }
    }
    return out;
}
export function applySuppression(f, ignores, path) {
    const fp = fingerprint(f.id, path, `${f.evidence.type}|${f.evidence.masked}`);
    const hit = ignores.find((i) => i.ruleId === f.id);
    return {
        ...f,
        fingerprint: fp,
        suppression: hit ? { reason: hit.reason || "(no reason given)", expires: hit.expires } : null,
    };
}
/** Low-confidence findings never deduct from the score (Plan v1.3) — they are review notes. */
export function deducts(f) {
    return f.severity !== "info" && f.confidence !== "low";
}
export const nowStamp = () => new Date().toISOString().slice(0, 10);
export function uniqBy(arr, key) {
    const seen = new Set();
    const out = [];
    for (const x of arr) {
        const k = key(x);
        if (!seen.has(k)) {
            seen.add(k);
            out.push(x);
        }
    }
    return out;
}
export const severityRank = { high: 0, medium: 1, low: 2 };
