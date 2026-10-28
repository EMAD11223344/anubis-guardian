#!/usr/bin/env node
/**
 * Clean-corpus git setup — repo with complete .gitignore, .env never tracked.
 *
 * v1.5.3 integrity fix: setup now CREATES the .env env-hygiene fixture
 * deterministically (anon key + server-side service-role key — the same
 * documented demo JWT literals used across this repo's fixtures). Before this
 * fix the file existed only as an untracked leftover in the maintainer's
 * working tree, so the published "2 reviewed gitleaks hits on the clean
 * corpus" row was not reproducible from a pristine checkout (0 hits there).
 * The file stays UNTRACKED in the fixture repo by design (the fixture
 * .gitignore excludes .env): Anubis reports only the documented
 * SUPA-001/info advisory and keeps 100/A, while gitleaks (--no-git) reports
 * the 2 JWT hits the comparison row reviews individually.
 */
import { execFileSync } from "node:child_process";
import { rmSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const app = join(here, "app");
const git = (...args) => execFileSync("git", ["-c", "user.name=anubis-test", "-c", "user.email=test@anubis.local", ...args], { cwd: app, stdio: "pipe" });

// Deterministic env-hygiene fixture (untracked by design; see header).
// Line 2 = public-by-design anon key; line 3 = service-role key used as the
// server-side env-hygiene advisory fixture.
writeFileSync(join(app, ".env"), [
  "NEXT_PUBLIC_SUPABASE_URL=https://cleandemo.supabase.co",
  "NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRlbW9rZXkiLCJyb2xlIjoiYW5vbiIsImlhdCI6MTczNTY4OTYwMCwiZXhwIjoxODkzNDU2MDAwfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  "SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRlbW9rZXkiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzM1Njg5NjAwLCJleHAiOjE4OTM0NTYwMDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  "",
].join("\n"));

rmSync(join(app, ".git"), { recursive: true, force: true });
git("init", "-q");
git("add", "-A");
git("commit", "-q", "-m", "clean reference app");
console.log("clean corpus git repo ready (.env gitignored, never tracked)");
