#!/usr/bin/env node
/**
 * Clean-corpus git setup — repo with complete .gitignore, .env never tracked.
 */
import { execFileSync } from "node:child_process";
import { rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const app = join(here, "app");
const git = (...args) => execFileSync("git", ["-c", "user.name=anubis-test", "-c", "user.email=test@anubis.local", ...args], { cwd: app, stdio: "pipe" });

rmSync(join(app, ".git"), { recursive: true, force: true });
git("init", "-q");
git("add", "-A");
git("commit", "-q", "-m", "clean reference app");
console.log("clean corpus git repo ready (.env gitignored, never tracked)");
