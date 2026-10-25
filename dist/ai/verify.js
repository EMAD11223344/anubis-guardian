import { readFileSync } from "node:fs";
import { join } from "node:path";
export const RULE_CATALOG = new Set([
    "SUPA-001", "HDR-001", "SEED-001", "ENV-001", "LOGS-001",
    "SUPA-R01", "SUPA-R02", "SUPA-R03", "SUPA-R04", "SUPA-R05", "SUPA-R06", "SUPA-R07", "SUPA-R08",
    "SUPA-002", "SUPA-003",
    "NEXT-001", "NEXT-002", "NEXT-003", "NEXT-004", "NEXT-005",
    "NEST-001", "NEST-002", "NEST-003", "NEST-004",
    "SAST-001", "SAST-002", "SAST-003", "SAST-004",
    "CRYPTO-001", "MASS-001", "WS-001", "WEBHOOK-001", "JWT-001", "JWT-002", "SWAGGER-001",
    "AUTH-001", "PRISMA-001",
    "CI-001", "CI-002", "CI-003", "CI-004", "DOCKER-001", "DOCKER-002", "DOCKER-003",
    "TAINT-001", "TAINT-002", "TAINT-003", "TAINT-004", "TAINT-005",
    "AGENT-001", "AGENT-002", "AGENT-003", "AGENT-004",
]);
/** rule → keyword signature its evidence must carry (pattern sanity, gate 4) */
const HINT_SIGNATURE = {
    "LOGS-001": /console\.|logger\.|log\(/i,
    "SUPA-R01": /CREATE\s+TABLE|ROW\s+LEVEL\s+SECURITY|POLICY/i,
    "SUPA-R02": /POLICY|USING/i,
    "SUPA-002": /POLICY|USING|user[_-]metadata/i,
    "SUPA-003": /SERVICE[_-]?ROLE|createClient/i,
    "NEXT-001": /NEXT_PUBLIC|process\.env/i,
    "NEXT-002": /localStorage|sessionStorage/i,
    "NEXT-004": /export\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)|use server/i,
    "NEST-001": /@Controller|@Get|@Post/i,
    "SAST-001": /SELECT|INSERT|query\(|execute\(/i,
    "SAST-002": /innerHTML|dangerouslySetInnerHTML/i,
    "SAST-003": /eval\(|exec\(|child_process/i,
    "CRYPTO-001": /Math\.random/,
    "MASS-001": /req\.body|request\.body|\.\.\./,
    "WS-001": /WebSocketGateway|socket|io\.on/i,
    "WEBHOOK-001": /webhook/i,
    "JWT-001": /jwt\.decode|\.decode\(/i,
    "JWT-002": /jwt\.verify|algorithms|ignoreExpiration/i,
    "SWAGGER-001": /Swagger|swagger|openapi/i,
    "AUTH-001": /middleware|matcher|route/i,
    "TAINT-001": /fetch|axios|request\(/i,
    "TAINT-002": /redirect/i,
    "TAINT-003": /path\.|readFile|createReadStream|unlink/i,
    "TAINT-004": /exec|spawn/i,
    "TAINT-005": /innerHTML|dangerouslySetInnerHTML|send\(/i,
    "AGENT-001": /npx|uvx|command/i,
    "AGENT-002": /TOKEN|KEY|SECRET|PASSWORD/i,
    "AGENT-003": /allow|permissions|bypass/i,
    "AGENT-004": /command|hooks/i,
};
const normalize = (s) => s.replace(/\s+/g, " ").trim();
function resolveFile(rel, rootDirs) {
    const candidates = [rel, rel.replace(/^[^/]+\//, "")]; // as-is, then label-stripped (multi-root)
    for (const base of rootDirs) {
        for (const c of candidates) {
            try {
                return { abs: join(base, c), content: readFileSync(join(base, c), "utf8") };
            }
            catch { /* try next */ }
        }
    }
    return null;
}
export function verifyClaims(claims, rootDirs, deterministicFindings) {
    const confirmed = [];
    const rejected = [];
    let corroborated = 0;
    for (const claim of claims) {
        const file = String(claim.file ?? "").replace(/\\/g, "/");
        const hint = String(claim.rule_hint ?? "").trim().toUpperCase();
        const snippet = String(claim.evidence_snippet ?? "");
        if (!RULE_CATALOG.has(hint)) {
            rejected.push({ file, rule_hint: hint, reason: "unknown rule id — not in the tool's catalog" });
            continue;
        }
        if (normalize(snippet).length < 12) {
            rejected.push({ file, rule_hint: hint, reason: "evidence snippet too short to verify" });
            continue;
        }
        const resolved = resolveFile(file, rootDirs);
        if (!resolved) {
            rejected.push({ file, rule_hint: hint, reason: "file not found in the scanned tree" });
            continue;
        }
        const normFile = normalize(resolved.content);
        const normSnippet = normalize(snippet).slice(0, 400);
        if (!normFile.includes(normSnippet)) {
            rejected.push({ file, rule_hint: hint, reason: "evidence snippet not present in the file (hallucination gate)" });
            continue;
        }
        const sig = HINT_SIGNATURE[hint];
        if (sig && !sig.test(normSnippet) && !sig.test(resolved.content)) {
            rejected.push({ file, rule_hint: hint, reason: "snippet does not carry the rule's pattern signature" });
            continue;
        }
        // duplicate gate: deterministic finding already covers this exact spot → count as corroboration
        const line = Number(claim.line ?? 0);
        const dup = deterministicFindings.find((d) => d.id === hint && (d.file.endsWith(file) || file.endsWith(d.file)) && (line === 0 || Math.abs((d.line || 0) - line) <= 5));
        if (dup) {
            corroborated++;
            continue;
        }
        const claimSeverity = String(claim.severity ?? "medium").toLowerCase();
        const severity = claimSeverity === "high" ? "high" : claimSeverity === "low" ? "low" : "medium";
        confirmed.push({
            id: hint,
            severity, // capped at HIGH — CRITICAL is deterministic-confirmation-only (v0.3 contract)
            title: `[AI review] ${hint}: ${normalize(claim.rationale ?? "pattern claimed by AI review").slice(0, 140)}`,
            file,
            line: line > 0 ? line : 1,
            evidence: { type: "ai_review_verified", masked: snippet.slice(0, 80), note: `AI-proposed, verifier-checked (evidence present + pattern signature match)${claim.rationale ? ` — ${normalize(claim.rationale).slice(0, 160)}` : ""}` },
            owasp: "A05",
            confidence: "medium",
            fix: `Review the AI-confirmed pattern at ${file}:${line || 1} — apply the ${hint} guidance from the rule catalog; nothing is applied automatically.`,
            fix_mode: "suggested-diff",
            needs_confirmation: true,
            verified: false,
            source: "ai-review",
            root: file,
            root_cause: `${hint}:ai-review:${file}`,
        });
    }
    return { confirmed, rejected, corroborated };
}
