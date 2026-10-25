/**
 * --compact renderer (Plan Section 8 Output Contract — v1.4): token-saving
 * summary for agents. One line per finding + coverage note. Deterministic.
 */
export function renderCompact(result) {
    const lines = [];
    const s = result.summary;
    lines.push(`anubis-guardian ${result.version} | score ${result.score}/100 (${result.grade}) | C:${s.critical} H:${s.high} M:${s.medium} L:${s.low} I:${s.info} | files:${result.meta.files_scanned}${result.meta.git_history_scanned ? " +git-history" : ""}`);
    const order = ["critical", "high", "medium", "low", "info"];
    const ranked = [...result.findings.filter((f) => f.suppression === null)].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
    for (const f of ranked) {
        lines.push(`${f.severity.toUpperCase()[0]} ${f.id} ${f.file}:${f.line} ${f.evidence.masked}${f.needs_confirmation ? " [confirm]" : ""}`);
    }
    if (result.coverage.classes_not_covered.length) {
        lines.push(`not-covered: ${result.coverage.classes_not_covered.length} classes (full list in findings.json)`);
    }
    return lines.join("\n");
}
