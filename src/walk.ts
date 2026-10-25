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

export function walk(root: string): ScannedFile[] {
  const out: ScannedFile[] = [];
  const visit = (dir: string) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const abs = join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) visit(abs);
        continue;
      }
      if (!e.isFile()) continue;
      let st;
      try { st = statSync(abs); } catch { continue; }
      if (st.size > MAX_FILE_BYTES) continue;
      let buf: Buffer;
      try { buf = readFileSync(abs); } catch { continue; }
      if (isBinary(buf)) continue;
      const content = buf.toString("utf8");
      out.push({
        abs,
        rel: relative(root, abs).split(sep).join("/"),
        content,
        lines: content.split("\n"),
      });
    }
  };
  visit(root);
  return out;
}

export function findFiles(files: ScannedFile[], re: RegExp): ScannedFile[] {
  return files.filter((f) => re.test(f.rel));
}
