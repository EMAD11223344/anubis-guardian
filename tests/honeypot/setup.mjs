#!/usr/bin/env node
/**
 * Honeypot setup — builds the git history the scanner must see:
 * commit everything (including a .env.local that gets deleted in a later commit)
 * so Layer 2 can catch committed-then-removed secrets. Deterministic content.
 */
import { execFileSync } from "node:child_process";
import { writeFileSync, rmSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const app = join(here, "app");

const git = (...args) => execFileSync("git", ["-c", "user.name=anubis-test", "-c", "user.email=test@anubis.local", ...args], { cwd: app, stdio: "pipe" });

// fresh repo every run
rmSync(join(app, ".git"), { recursive: true, force: true });

// the committed-then-deleted env file (seed #12)
writeFileSync(
  join(app, ".env.local"),
  "DATABASE_URL=postgres://admin:OldPassw0rd!@db.demokey.supabase.co:5432/postgres\nSTRIPE_KEY=pk_live_demo_publishable_only\n"
);

git("init", "-q");
git("add", "-A");
git("commit", "-q", "-m", "init demo app");
rmSync(join(app, ".env.local"));
git("add", "-A");
git("commit", "-q", "-m", "remove local env from repo");

console.log("honeypot git history ready (2 commits, .env.local committed then removed)");
