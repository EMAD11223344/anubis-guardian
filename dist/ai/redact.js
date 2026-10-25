/**
 * Redaction-before-LLM (Plan Section 9.3): no secret-shaped value ever leaves
 * the machine, even when the user explicitly enables the AI review layer.
 * Applied to every code context before it enters a prompt.
 */
const JWT_LIT = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const KNOWN_PREFIX = /\b(?:sk-[A-Za-z0-9_-]{12,}|sk-proj-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9_]{16,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{12,}|sbp?_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,})\b/g;
const KEYVAL_ASSIGN = /((?:password|passwd|secret|token|api[_-]?key|apikey|service[_-]?role|private[_-]?key|credential)[A-Za-z0-9_]*\s*[:=]\s*)["'`]([^"'`\s]{6,})["'`]/gi;
const LONG_BLOB = /\b[A-Fa-f0-9]{40,}\b|\b[A-Za-z0-9+/]{44,}={0,2}\b/g;
export function redactSecrets(text) {
    return text
        .replace(JWT_LIT, "[REDACTED:jwt]")
        .replace(KNOWN_PREFIX, "[REDACTED:key]")
        .replace(KEYVAL_ASSIGN, (_m, prefix) => `${prefix}"[REDACTED:value]"`)
        .replace(LONG_BLOB, "[REDACTED:blob]");
}
