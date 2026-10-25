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

const MAX_FILE_BYTES = 512 * 1024;

function isBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 4096);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

/**
 * v1.2 — walk WITH honest skip accounting (T7 of the independent-review fixes):
 * oversize (>512KB) and binary files were previously dropped SILENTLY, so the
 * report overstated its evidence base. Counts are deterministic and land in
 * meta.files_skipped (engine.ts).
 */
export interface WalkSkipped { oversize: number; binary: number; unreadable: number }

export function walkWithStats(root: string): { files: ScannedFile[]; skipped: WalkSkipped } {
  const out: ScannedFile[] = [];
  const skipped: WalkSkipped = { oversize: 0, binary: 0, unreadable: 0 };
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
      if (st.size > MAX_FILE_BYTES) { skipped.oversize++; continue; }
      let buf: Buffer;
      try { buf = readFileSync(abs); } catch { skipped.unreadable++; continue; }
      if (isBinary(buf)) { skipped.binary++; continue; }
      const content = buf.toString("utf8");
      out.push({
        abs,
        rel: relative(root, abs).split(sep).join("/"),
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
  return { files: out, skipped };
}

/** Back-compat: engine/CLI callers that only need the file list. */
export function walk(root: string): ScannedFile[] {
  return walkWithStats(root).files;
}

export function findFiles(files: ScannedFile[], re: RegExp): ScannedFile[] {
  return files.filter((f) => re.test(f.rel));
}
