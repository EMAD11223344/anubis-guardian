#!/usr/bin/env node
/**
 * Step 0 sweep — build the ordered clone list from candidates.json.
 * Priority: strong AI-build signal tags first (lovable/bolt/v0/cursor/claude/
 * windsurf/vibe), smallest repos first (fast clones); then stack-tag projects
 * as the secondary population. Caps: 80 strong + 20 stack = 100 attempts.
 */
import { readFileSync, writeFileSync } from "node:fs";

const { candidates } = JSON.parse(readFileSync(new URL("./candidates.json", import.meta.url), "utf8"));
const STRONG = new Set(["lovable", "bolt", "v0", "cursor", "claude", "windsurf", "vibe"]);

const strong = candidates
  .filter((c) => c.tags.some((t) => STRONG.has(t)))
  .sort((a, b) => a.size_kb - b.size_kb)
  .slice(0, 80)
  .map((c) => ({ ...c, pop: "ai-built" }));

const stack = candidates
  .filter((c) => !strong.includes(c) && c.tags.includes("stack"))
  .sort((a, b) => a.size_kb - b.size_kb)
  .slice(0, 20)
  .map((c) => ({ ...c, pop: "ai-stack" }));

const list = [...strong, ...stack];
writeFileSync(new URL("./clone-list.json", import.meta.url).pathname, JSON.stringify(list, null, 2));
console.error(`clone list: ${list.length} (strong ${strong.length} + stack ${stack.length})`);
