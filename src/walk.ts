import { readdirSync, statSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import type { ScannedFile } from "./types.js";

/**
 * Static file collection. The engine ONLY reads files (Section 9.7 — Execution Safety):
 * no install, no build, no test runs, no lifecycle scripts of the scanned project, ever.
 */
const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", "dist", "build", "out", "coverage",
  ".cache", ".turbo", ".vercel", "vendor", "__pycache__", ".venv", "venv",
]);

/** full-analysis bytes — unchanged v1.3 behavior for files ≤ this size */
const MAX_FILE_BYTES = 512 * 1024;
/**
 * v1.4 (capability E) — large-file windowed scanning:
 *  - files up to 4 MB are ANALYZED (never skipped-oversize anymore) — the whole
 *    engine must still stay linear/bounded (locked by the adversarial battery),
 *  - files >512KB are analyzed in overlapping line-boundary windows
 *    (≤512KB content each + 16-line overlap) so every rule keeps its budget,
 *  - >4MB stays skipped + counted (oversize) — the honest disclosed limit.
 */
const HARD_FILE_BYTES = 4 * 1024 * 1024;
const WINDOW_OVERLAP_LINES = 16;

function isBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 4096);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

export interface WalkSkipped { oversize: number; binary: number; unreadable: number }
export interface WalkWindowed { file: string; kb: number; windows: number }

/**
 * v1.4 (capability E) — split a large TEXT file into overlapping line-boundary
 * windows the rules scan as ordinary files. Absolute line numbers stay exact:
 * the window's lines/content are padded with (start) newline rows, the LAST
 * pad row being a synthetic column-0 `}` so the sameFunctionBound heuristic
 * cannot chain a variable backwards ACROSS the window seam (an assignment
 * before the seam resolving into this window). Consecutive windows re-include
 * the previous window's tail (16-line overlap), so multi-line template joins
 * spanning the seam still resolve — duplicate findings share one fingerprint
 * and dedupe in the engine.
 */
function windowedScans(abs: string, rel: string, content: string): ScannedFile[] {
  const lines = content.split(/\r?\n/);
  const out: ScannedFile[] = [];
  let start = 0;
  while (start < lines.length && out.length < 64) { // 64-window hard bound
    let end = start;
    let bytes = 0;
    while (end < lines.length) {
      const w = Buffer.byteLength(lines[end], "utf8") + 1;
      if (end > start && bytes + w > MAX_FILE_BYTES) break;
      bytes += w;
      end++;
    }
    if (end === start) end = start + 1; // single line > 512KB — one-line window
    // pads: (start-1) empty rows + one synthetic `}` scope-break at the seam
    const pads: string[] = [];
    for (let k = 0; k < start; k++) pads.push(k === start - 1 ? "}" : "");
    const body = lines.slice(start, end);
    const winLines = [...pads, ...body];
    const winContent = (pads.length ? pads.join("\n") + "\n" : "") + body.join("\n");
    out.push({ abs, rel, content: winContent, lines: winLines });
    const next = end - WINDOW_OVERLAP_LINES;
    if (next <= start) break;
    start = next;
  }
  return out;
}

export function walkWithStats(root: string): { files: ScannedFile[]; skipped: WalkSkipped; windowed: WalkWindowed[] } {
  const out: ScannedFile[] = [];
  const skipped: WalkSkipped = { oversize: 0, binary: 0, unreadable: 0 };
  const windowed: WalkWindowed[] = [];
  const visit = (dir: string) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { skipped.unreadable++; return; }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const abs = join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) visit(abs);
        continue;
      }
      if (!e.isFile()) continue;
      let st;
      try { st = statSync(abs); } catch { skipped.unreadable++; continue; }
      // v1.4 (capability E): the oversize skip moves from 512KB to the 4MB hard
      // cap; 512KB–4MB files are analyzed in bounded windows (disclosed in
      // meta.files_windowed) so coverage grows without unbounded rule work.
      if (st.size > HARD_FILE_BYTES) { skipped.oversize++; continue; }
      let buf: Buffer;
      try { buf = readFileSync(abs); } catch { skipped.unreadable++; continue; }
      if (isBinary(buf)) { skipped.binary++; continue; }
      const content = buf.toString("utf8");
      const rel = relative(root, abs).split(sep).join("/");
      if (st.size > MAX_FILE_BYTES) {
        // EOL robustness (v1.1.0) applies to window split too
        const wins = windowedScans(abs, rel, content);
        out.push(...wins);
        windowed.push({ file: rel, kb: Math.round(st.size / 1024), windows: wins.length });
        continue;
      }
      out.push({
        abs,
        rel,
        content,
        // EOL robustness (v1.1.0): split on /\r?\n/ so CRLF checkouts (Windows
        // autocrlf clones/worktrees) never leave a trailing \r on a line. A bare
        // \r is invisible in rules but fatal to $-anchored regexes like CI-003's
        // /run:\s*(.*)$/ — "." does not match "\r" and "$" will not match before
        // it, so the whole rule silently died on CRLF-only checkouts.
        lines: content.split(/\r?\n/),
      });
    }
  };
  visit(root);
  return { files: out, skipped, windowed };
}

/** Back-compat: engine/CLI callers that only need the file list. */
export function walk(root: string): ScannedFile[] {
  return walkWithStats(root).files;
}

export function findFiles(files: ScannedFile[], re: RegExp): ScannedFile[] {
  return files.filter((f) => re.test(f.rel));
}
