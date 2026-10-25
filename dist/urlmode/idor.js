import { createHash } from "node:crypto";
import { mkFinding, rootCause, fingerprint } from "../util.js";
/**
 * v1.0 — Restricted differential IDOR probe (Plan v1.2 item #11, the WHOLE
 * L3-active scope — "ده هو نطاق L3 النشط كله، مفيش DAST عام"):
 * - verified ownership enforced (dns-txt / well-known — NEVER the checkbox,
 *   never self-attestation) + `--active-tests` explicit + GET-only by
 *   construction + owner-provided testing identities + semantic diff.
 * - Candidates come ONLY from surfaces the L2 discovery already touched
 *   (no new endpoints invented) + owner-supplied --idor-path list. Hard cap.
 * - Identity header/cookie VALUES never enter the capture, the findings or
 *   any report — identities are recorded as "a"/"b" plus the header NAME only.
 * - capture-then-analyze holds: the probe requests are part of the bundle and
 *   the diff runs in Phase B (pure function) — re-analysis is byte-identical.
 */
export const IDOR_ENDPOINT_CAP = 24;
/** Paths never worth diffing — public/static by nature (FP control). */
const STATIC_PREFIXES = ["/_next/", "/static/", "/assets/", "/vendor/", "/__"];
const STATIC_SUFFIXES = [".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf"];
const ALWAYS_PUBLIC = ["/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt"];
/**
 * Candidate selection (Phase B-safe: pure function over the bundle so
 * --from-capture reproduces the exact same candidate list).
 * A candidate = a GET that L2 discovery already made, returned 200, has an
 * HTML/JSON content type, is not static/public, and is same-origin.
 */
export function selectIdorCandidates(bundle, ownerPaths = []) {
    const origin = new URL(bundle.meta.url).origin;
    const seen = new Set();
    const out = [];
    const push = (absUrl) => {
        let u;
        try {
            u = new URL(absUrl);
        }
        catch {
            return;
        }
        if (u.origin !== origin)
            return;
        const path = u.pathname;
        if (seen.has(path))
            return;
        if (ALWAYS_PUBLIC.includes(path))
            return;
        if (STATIC_PREFIXES.some((p) => path.startsWith(p)))
            return;
        if (STATIC_SUFFIXES.some((s) => path.endsWith(s)))
            return;
        if (path.startsWith("/.well-known/"))
            return;
        seen.add(path);
        out.push({ url: `${origin}${path}`, path });
    };
    for (const owner of ownerPaths) {
        try {
            push(new URL(owner, origin + "/").toString());
        }
        catch { /* malformed — skipped */ }
    }
    if (out.length < IDOR_ENDPOINT_CAP) {
        for (const r of bundle.requests) {
            if (out.length >= IDOR_ENDPOINT_CAP)
                break;
            if (r.method !== "GET" || r.status !== 200)
                continue;
            // Discovered candidates are JSON API surfaces ONLY: identical HTML for two
            // identities is the NORM (SPA shells serve the same app to everyone) — a
            // documented FP factory. Owner-supplied --idor-path endpoints skip this filter.
            const ct = r.headers["content-type"] ?? "";
            if (!/application\/json|application\/problem\+json/i.test(ct))
                continue;
            if (r.bytes === 0)
                continue;
            push(r.url);
        }
    }
    return out.slice(0, IDOR_ENDPOINT_CAP);
}
export function responseShape(r) {
    if (!r)
        return { status: 0, kind: "error", json_keys: null, body_hash: "none", bytes: 0 };
    const ct = r.headers["content-type"] ?? "";
    const kind = r.status === 0 ? "error"
        : r.bytes === 0 ? "empty"
            : /application\/json/i.test(ct) ? "json"
                : /text\/html/i.test(ct) ? "html"
                    : "text";
    let jsonKeys = null;
    if (kind === "json") {
        try {
            const j = JSON.parse(r.body);
            jsonKeys = Array.isArray(j) ? "array" : Object.keys(j).sort().join(",");
        }
        catch {
            jsonKeys = null;
        }
    }
    const normalized = r.body.replace(/\s+/g, " ").trim();
    const hash = createHashSha256(normalized);
    return { status: r.status, kind, json_keys: jsonKeys, body_hash: hash, bytes: r.bytes };
}
function createHashSha256(s) {
    return createHash("sha256").update(s).digest("hex").slice(0, 12);
}
export function diffPair(endpoint, a, b) {
    const sa = responseShape(a);
    const sb = responseShape(b);
    const identical = sa.status === sb.status && sa.kind !== "error" && sa.body_hash === sb.body_hash;
    const denied = sb.status === 401 || sb.status === 403 || sb.status === 404;
    const boundary_held = denied || (!identical && sa.kind !== "error" && sb.kind !== "error" && sa.status === 200 && sb.status !== 0);
    return { endpoint, a: sa, b: sb, identical, boundary_held };
}
/**
 * Phase B: analyze the recorded identity pairs (from bundle.idor.requests —
 * seq → CapturedResponse). Deterministic: same bundle → same verdict.
 */
export function analyzeIdor(bundle) {
    const findings = [];
    const bySeq = new Map(bundle.requests.map((r) => [r.seq, r]));
    const idor = bundle.idor;
    // NOTE: identities[] = unique header NAMES (both identities may share one name,
    // e.g. different cookies) — the "two identities" contract is proven by the pairs.
    if (!idor || idor.requests.length === 0) {
        return { findings, pairs: [], suspects: [], note: "active-tests: no differential pairs recorded" };
    }
    const pairs = [];
    const suspects = [];
    for (const ep of idor.endpoints) {
        const ra = bySeq.get(idor.requests.find((q) => q.endpoint === ep.path && q.identity === "a")?.seq ?? -1) ?? null;
        const rb = bySeq.get(idor.requests.find((q) => q.endpoint === ep.path && q.identity === "b")?.seq ?? -1) ?? null;
        if (!ra && !rb)
            continue;
        const pair = diffPair(ep.path, ra, rb);
        pairs.push(pair);
        if (pair.identical && pair.a.status === 200 && pair.a.kind !== "empty")
            suspects.push(pair);
    }
    for (const s of suspects) {
        findings.push(mkFinding({
            id: "URL-061",
            severity: "high",
            title: "Differential access check: restricted identity received the privileged response",
            file: `${bundle.meta.url}${s.endpoint}`,
            line: 0,
            evidence: {
                type: "idor-differential",
                masked: `GET ${s.endpoint} — identity-a: ${s.a.status} (${s.a.kind}) · identity-b(restricted): ${s.b.status} (${s.b.kind}) — semantically identical responses`,
                note: "Both owner-provided testing identities received the same response. If this endpoint is intentionally public, mark it suppressed; otherwise it may be a broken access control (IDOR). GET-only probe, verified ownership, identity values never stored.",
            },
            owasp: "A01",
            confidence: "medium",
            verified: true,
            fix: "Verify the endpoint's authorization for the restricted identity in code (Codebase Mode: map the endpoint, then add an ownership/role check server-side — never client-side only).",
            fix_mode: "suggested-diff",
            needs_confirmation: true,
            root: s.endpoint,
            root_cause: rootCause("URL-061", s.endpoint),
            source: "builtin",
        }));
    }
    const note = `active-tests: differential IDOR ran GET-only on ${pairs.length} endpoint(s) with 2 owner-provided identities — ${suspects.length} suspect pair(s), ${pairs.length - suspects.length} boundary(ies) confirmed. Identity VALUES were never stored.`;
    findings.push(mkFinding({
        id: "URL-909",
        severity: "info",
        title: "Active-tests summary (differential access)",
        file: bundle.meta.url,
        line: 0,
        evidence: { type: "idor-summary", masked: note },
        owasp: "A01",
        confidence: "high",
        verified: true,
        fix: "Informational — full DAST is out of scope by design; run the generated ZAP baseline (init-zap) or the quarantine canaries for deeper checks.",
        fix_mode: "suggested-diff",
        root: bundle.meta.url,
        root_cause: rootCause("URL-909", bundle.meta.url),
        source: "builtin",
    }));
    return { findings, pairs, suspects, note };
}
/** Stable evidence hash helper for the capture record (no identity values). */
export const idorRequestMarker = (endpoint, identity) => fingerprint("idor", endpoint, identity);
