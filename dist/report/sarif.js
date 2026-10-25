import { VERSION } from "../engine.js";
/**
 * SARIF 2.1.0 emitter (Plan Section 8; v1.3 decision — lands in GitHub code
 * scanning / Security tab). Deterministic: no timestamps, stable ordering.
 * level mapping: critical/high → error · medium → warning · low/info → note.
 */
export function renderSarif(result) {
    const rules = new Map();
    for (const f of result.findings) {
        if (!rules.has(f.id))
            rules.set(f.id, { id: f.id, title: f.title, help: f.fix });
    }
    const sarif = {
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: [
            {
                tool: {
                    driver: {
                        name: "anubis-guardian",
                        version: VERSION,
                        informationUri: "https://github.com/anubis-guardian/anubis-guardian",
                        rules: [...rules.values()].map((r) => ({
                            id: r.id,
                            shortDescription: { text: r.title },
                            help: { text: r.help },
                            helpUri: "https://github.com/anubis-guardian/anubis-guardian#rules",
                        })),
                    },
                },
                results: result.findings.filter((f) => f.suppression === null).map((f) => ({
                    ruleId: f.id,
                    ruleIndex: [...rules.keys()].indexOf(f.id),
                    level: f.severity === "critical" || f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "note",
                    message: {
                        text: `${f.title} — ${f.evidence.masked}${f.evidence.note ? ` (${f.evidence.note})` : ""}${f.needs_confirmation ? " [needs confirmation]" : ""}`,
                    },
                    locations: [
                        {
                            physicalLocation: {
                                artifactLocation: { uri: normalizeUri(f.file) },
                                region: { startLine: Math.max(1, f.line) },
                            },
                        },
                    ],
                    partialFingerprints: { anubisFingerprint: f.fingerprint },
                })),
            },
        ],
    };
    return JSON.stringify(sarif, null, 2);
}
function normalizeUri(file) {
    return file.replace(/\\/g, "/").replace(/^\//, "");
}
/** helpers shared with fix-prompt renderer */
export function confirmed(findings) {
    return findings.filter((f) => f.suppression === null);
}
