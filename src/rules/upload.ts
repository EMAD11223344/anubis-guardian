import type { ScanContext, RuleResult } from "../types.js";
import { rootCause } from "../util.js";
import { classifyFile } from "./context.js";
import { collectAssignments, propagateTaint } from "./flow.js";

/**
 * Capability §F — user-upload security (v1.4).
 *
 * The application's implementation and attack paths are in scope (no active
 * testing — the engine never executes what it scans, Section 9.7):
 *  - UPLOAD-001 (HIGH evidence-backed): request-derived file NAME/content is
 *    written into a SERVED directory (public/ static/ www/ uploads/…) —
 *    stored-XSS/code-execution location + unvalidated filename;
 *  - UPLOAD-002 (medium + needs_confirmation): upload parsers configured
 *    WITHOUT size/type limits (multer/busboy/formidable) — the limit fields
 *    may be enforced by an invisible layer (proxy framework), so review note;
 *  - UPLOAD-003 (medium + needs_confirmation): archive extraction without
 *    visible entry guards (zip-bomb/zip-slip surface; entry validation may
 *    exist behind helpers — hence review note).
 *
 * Path-traversal-shaped flows into fs sinks are ALREADY TAINT-003's verdict —
 * this pack does not duplicate them; it targets storage location & limits.
 */

/** request-derived source shapes (same family as taint.ts SOURCE_EXPR) */
const REQ_SOURCE =
  /req(?:uest)?\.(?:query|body|params|headers|cookies|file|files|files\[)|(?:originalname|\.file\b|\.files\b|mimetype)/;

/** write-to-disk sinks */
const WRITE_SINK = /(?:\bwriteFile(?:Sync)?\s*\(|\bcreateWriteStream\s*\(|\bfs\.promises\.write\b|\.mv\s*\(|\bsaveAs\s*\(|\bwriteFileSync\s*\()/;

/** served directories = attacker files are executed/rendered by the server/web root */
const SERVED_DIR = /(?:["'`]|[\\/=(])\s*(?:[\w./-]+)?(?:public|static|www|wwwroot|uploads|webroot|assets)[\\/]/i;

/** upload parser configs (±3-line window completeness) */
const MULTER_NO_LIMITS = /(?:\bmulter\s*\(\s*(?:\{(?![^}]{0,240}\blimits\b)[^}]{0,240}\}\s*\)|(?=\))))/;
const BUSBOY_NO_LIMITS = /\b(?:new\s+)?Busboy\s*\(\s*\{(?![^}]{0,240}\blimits\b)[^}]{0,240}\}/;
const FORMIDABLE_NO_LIMITS = /\bnew\s+Formidable\s*\(\s*\{(?![^}]{0,240}\b(?:maxFileSize|maxFieldsSize)\b)[^}]{0,240}\}/;

/** archive extraction with/without guards (±4-line window completeness) */
const ARCHIVE_EXTRACT = /\b(?:unzip|extractZip|extractAllTo|extract(?:All)?Tar|unzipper|execSync\s*\(\s*["'`]?(?:unzip|tar)\b|tar\s*\.\s*[xz]\b|yauzl|decompress\s*\(|unrar)/;
const ARCHIVE_GUARD = /(?:sanitize|basename|entry\.size|fileSize|maxEntries|compressionRatio|\.filter\s*\(|\.on\s*\(\s*["'`]entry|validateEntry|pathCheck|join\s*\(\s*outDir)/i;

export function scanUpload(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];

  for (const f of ctx.files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.rel)) continue;
    if (/(?:^|\/)(?:tests?|__tests__|specs?|fixtures?|mocks?)\/|\.test\.|\.spec\./i.test(f.rel)) continue;
    if (classifyFile(f) === "client") continue;

    const assigns = collectAssignments(f.lines);
    const tainted = propagateTaint(f.lines, assigns, (rhs) => REQ_SOURCE.test(rhs));

    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      if (/^\s*(?:\/\/|\*|\/\*)/.test(line)) continue;

      // ---- UPLOAD-001: request-derived write into a served directory ----
      if (WRITE_SINK.test(line) && SERVED_DIR.test(line)) {
        const idents = [...new Set(line.match(/[A-Za-z_$][\w$]*/g) ?? [])].filter(
          (id) => !/^(?:const|let|var|await|function|return|require|import|path|join|fs|node|process|True|False|null|undefined)$/i.test(id)
        ).slice(0, 5);
        const reqDerived = idents.some((id) => tainted.has(id)) || REQ_SOURCE.test(line.replace(/\b(?:path|join|public|static|uploads)\b/gi, "").slice(0, 40));
        if (reqDerived) {
          findings.push({
            id: "UPLOAD-001", severity: "high", confidence: "medium",
            title: "Request-derived filename/content is written into a SERVED directory — stored-XSS / code-execution location",
            file: f.rel, line: i + 1,
            evidence: {
              type: "upload_to_served_dir",
              masked: line.trim().slice(0, 120),
              note: "the flow from request input into the persisted path/content is visible in this file; confirm the serving layer's content-type/disposition handling too",
            },
            owasp: "A04",
            fix: "Store uploads OUTSIDE the web root with generated server-side names (uuid/obj-store keys); validate extension+mimetype server-side; serve with a safe Content-Disposition.",
            fix_mode: "suggested-diff",
            root: `${f.rel}:${i + 1}`,
            root_cause: rootCause("UPLOAD-001", `${f.rel}:${i + 1}`),
            needs_confirmation: true,
            verified: true,
          });
        }
        continue;
      }

      // ---- UPLOAD-002: upload parser without limits ----
      if (MULTER_NO_LIMITS.test(line) || BUSBOY_NO_LIMITS.test(line) || FORMIDABLE_NO_LIMITS.test(line)) {
        const parser = /multer/i.test(line) ? "multer" : /busboy/i.test(line) ? "busboy" : "formidable";
        const window = f.lines.slice(Math.max(0, i - 3), Math.min(f.lines.length, i + 4)).join("\n");
        if (/\blimits\b|\bmaxFileSize\b|\bmaxCount\b|\bfileSize\b/.test(window)) continue;
        findings.push({
          id: "UPLOAD-002", severity: "medium", confidence: "medium",
          title: `${parser} upload parser configured without visible size/count limits (review)`,
          file: f.rel, line: i + 1,
          evidence: {
            type: "upload_parser_unlimited",
            masked: line.trim().slice(0, 120),
            note: "a reverse proxy, framework default or global body-size limit may enforce the cap invisibly — confirm before treating as exploitable",
          },
          owasp: "A04",
          fix: "Set explicit limits: fileSize, files, fields counts in the parser config; reject oversized uploads before buffering them in memory/disk.",
          fix_mode: "suggested-diff",
          root: `${f.rel}:${i + 1}`,
          root_cause: rootCause("UPLOAD-002", `${f.rel}:${i + 1}`),
          needs_confirmation: true,
          verified: true,
        });
        continue;
      }

      // ---- UPLOAD-003: archive extraction without visible entry guards ----
      if (ARCHIVE_EXTRACT.test(line)) {
        const window = f.lines.slice(Math.max(0, i - 4), Math.min(f.lines.length, i + 5)).join("\n");
        if (ARCHIVE_GUARD.test(window)) continue;
        findings.push({
          id: "UPLOAD-003", severity: "medium", confidence: "medium",
          title: "Archive extraction without visible entry validation (zip-bomb / zip-slip surface)",
          file: f.rel, line: i + 1,
          evidence: {
            type: "archive_extract_unguarded",
            masked: line.trim().slice(0, 120),
            note: "entry filtering may exist behind a helper this rule cannot see — confirm sizes/entry counts/paths are validated before extraction",
          },
          owasp: "A04",
          fix: "Validate every archive entry before extracting: destination path stays under outDir (no ..), per-entry and total size caps, entry-count cap, compression-ratio cap.",
          fix_mode: "suggested-diff",
          root: `${f.rel}:${i + 1}`,
          root_cause: rootCause("UPLOAD-003", `${f.rel}:${i + 1}`),
          needs_confirmation: true,
          verified: true,
        });
      }
    }
  }
  return { findings };
}
