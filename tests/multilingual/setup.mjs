#!/usr/bin/env node
/**
 * Multilingual regression corpus — deterministic fixture generator (W3).
 *
 * Recreates the independently-reported multilingual scan fixture (Python, Go,
 * Java properties, Terraform, Docker, GitHub Actions, Firebase rules,
 * dependency manifests) with the REPORTED source patterns preserved verbatim,
 * plus safe-counterpart files for every fixed rule and documented
 * out-of-scope cases. Secret VALUES are generated here (not committed) so the
 * public repo never contains fake-but-plausible credentials; every value is a
 * fixed literal → the tree is byte-deterministic across runs.
 *
 * The git-history case mirrors tests/honeypot/setup.mjs: a Stripe-shaped key
 * is committed, then removed, so HIST-003 has an actual `log -p` artifact to
 * recover. A final .env stays committed (live values) for ENV-001.
 *
 * Fixture layout under app/:
 *   python/config.py             SEC-009 (SECRET_KEY) + SEC-010 (DB_PASSWORD) + out-of-scope SQLi
 *   go/main.go                   SEC-003 (OpenAI key shape) — cross-language value shape
 *   go/db.go                     OUT-OF-SCOPE Go SQLi (locked silent, documented)
 *   java/src/main/resources/application.properties  SEC-010 ×2 (spring.datasource.password, jwt.secret)
 *   infra/main.tf                SEC-009 (tf password attr) + TF-001 (public-read ACL) + SEC-010 (tfvars-style unquoted)
 *   infra/firestore.rules        FB-001 (allow read, write: if true)
 *   .github/workflows/ci.yml     CI-002/001/003/004
 *   Dockerfile                   DOCKER-001/002/003
 *   .env                         SEC-008 + SEC-001 + ENV-001 (committed, live values)
 *   keys/deploy.pem              SEC-007 + FILE-005
 *   requirements.txt             OUT-OF-SCOPE vulnerable pins (no Python advisory snapshot)
 *   .gitignore                   complete (HIST-010/011 stay silent)
 *   safe/config.py               SEC-009/SEC-010 clean (env reads)
 *   safe/application.properties  SEC-010 clean (${...} interpolation)
 *   safe/main.tf                 TF-001/SEC-010 clean (private ACL, var reference)
 *   safe/firestore.rules         FB-001 clean (request.auth != null)
 *   safe/Dockerfile              DOCKER-001/002/003 clean (USER node, pinned tag, benign ARG)
 *   safe/ci.yml                  CI-001..004 clean (SHA pin, permissions, env-injected script, pull_request)
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const app = join(here, "app");

rmSync(app, { recursive: true, force: true });
const mk = (rel, body) => {
  const p = join(app, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, body);
};
const git = (...args) =>
  execFileSync("git", ["-c", "user.name=anubis-test", "-c", "user.email=test@anubis.local", ...args], {
    cwd: app,
    stdio: "pipe",
  });

// ---------- vulnerable fixture (reported patterns, line-exact) ----------
mk("python/config.py", [
  "import os",
  "",
  "# Django-style settings (vibe-coded shape)",
  'SECRET_KEY = "django-insecure-x7#p2m9v$q4w8n1z&h3j6k5l"',
  'DB_PASSWORD = "Pr0d-Secret-2026!xYz9"',
  "DEBUG = True",
  "",
].join("\n"));

mk("python/db.py", [
  "import sqlite3",
  "",
  "def get_user(cursor, user_id):",
  "    # OUT-OF-SCOPE for Anubis (non-JS/TS SAST non-goal) — documented boundary",
  "    cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
  "",
].join("\n"));

mk("go/main.go", [
  "package main",
  "",
  'import "fmt"',
  "",
  "func main() {",
  '    openAIKey := "sk-proj-4x9K2mL8pQ7vN3bR6tY1wE5uI0oS8aD3fG7hJ2kL4mN9"',
  "    fmt.Println(openAIKey)",
  "}",
  "",
].join("\n"));

mk("go/db.go", [
  "package main",
  "",
  'import "database/sql"',
  "",
  "func query(name string, db *sql.DB) {",
  "    // OUT-OF-SCOPE for Anubis (non-JS/TS SAST non-goal) — documented boundary",
  "    q := \"SELECT * FROM users WHERE name = '\" + name + \"'\"",
  "    db.Exec(q)",
  "}",
  "",
].join("\n"));

mk("java/src/main/resources/application.properties", [
  "spring.datasource.url=jdbc:postgresql://db.internal:5432/prod",
  "spring.datasource.username=app_user",
  "spring.datasource.password=Pr0d-Secret-2026!xYz9",
  "jwt.secret=x7Kp9mQw2vB4nZ8hJ3fL6dRs5tYgUe1C",
  "spring.jpa.show-sql=false",
  "",
].join("\n"));

mk("infra/main.tf", [
  'provider "aws" {',
  '  region = "us-east-1"',
  "}",
  "",
  'resource "aws_db_instance" "app" {',
  '  identifier     = "app-db"',
  '  engine         = "postgres"',
  '  username       = "app_admin"',
  '  password       = "Pr0d-Secret-2026!xYz9"',
  '  instance_class = "db.t3.micro"',
  "}",
  "",
  'resource "aws_s3_bucket" "uploads" {',
  '  bucket = "app-uploads"',
  '  acl    = "public-read"',
  "}",
  "",
].join("\n"));

mk("infra/firestore.rules", [
  "rules_version = '2';",
  "service cloud.firestore {",
  "  match /databases/{database}/documents {",
  "    match /public/{document=**} {",
  "      allow read, write: if true;",
  "    }",
  "  }",
  "}",
  "",
].join("\n"));

mk(".github/workflows/ci.yml", [
  "name: CI",
  "on:",
  "  pull_request_target:",
  "jobs:",
  "  build:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - uses: actions/checkout@v4",
  "      - name: Greet reporter",
  "        run: echo \"Report: ${{ github.event.issue.title }}\"",
  "",
].join("\n"));

mk("Dockerfile", [
  "FROM node:latest",
  "WORKDIR /app",
  "COPY . .",
  "ARG STRIPE_API_KEY",
  "RUN npm ci",
  'CMD ["node", "server.js"]',
  "",
].join("\n"));

mk(".env", [
  "DATABASE_URL=postgres://ci_user:Sk9-Live-Pass-77@db.prod.internal:5432/appdb",
  "AWS_ACCESS_KEY_ID=AKIA4YKJ7RQ3XMP2LE9T",
  "",
].join("\n"));

// PEM body: deterministic pseudo-base64 (SEC-007 requires a ≥64-char b64 run;
// FILE-005 matches *.pem + PRIVATE KEY). Format-true, not a valid key.
const pemBody = Array.from({ length: 24 }, (_, i) => {
  let row = "";
  for (let j = 0; j < 64; j++) row += "ABCDEFghij012345klmnopQR6789STuvwx234567yz890JKLMN"[(i * 17 + j * 3) % 48];
  return row;
}).join("\n");
mk("keys/deploy.pem", ["-----BEGIN RSA PRIVATE KEY-----", pemBody, "-----END RSA PRIVATE KEY-----", ""].join("\n"));

mk("requirements.txt", [
  "# OUT-OF-SCOPE: Anubis dependency auditing is npm-ecosystem-only (bundled",
  "# advisory snapshot has no Python data) — these vulnerable pins are recorded",
  "# as a documented boundary, not a detection expectation.",
  "flask==1.0",
  "django==2.0.1",
  "requests==2.6.0",
  "",
].join("\n"));

mk(".gitignore", ["node_modules", ".next", ".env", ".env.*", "*.pem", "*.tfstate", "dist", "__pycache__", ""].join("\n"));

// ---------- safe counterparts (every rule above needs its negative) ----------
mk("safe/config.py", [
  "import os",
  "",
  'SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]',
  'DB_PASSWORD = os.environ["DB_PASSWORD"]',
  "DEBUG = False",
  "",
].join("\n"));

mk("safe/application.properties", [
  "spring.datasource.url=${DB_URL}",
  "spring.datasource.username=${DB_USER}",
  "spring.datasource.password=${DB_PASSWORD}",
  "jwt.secret=${JWT_SECRET}",
  "",
].join("\n"));

mk("safe/main.tf", [
  'provider "aws" {',
  '  region = "us-east-1"',
  "}",
  "",
  'resource "aws_db_instance" "app" {',
  '  identifier     = "app-db"',
  '  engine         = "postgres"',
  '  username       = "app_admin"',
  "  password       = var.db_password",
  '  instance_class = "db.t3.micro"',
  "}",
  "",
  'resource "aws_s3_bucket" "uploads" {',
  '  bucket = "app-uploads"',
  '  acl    = "private"',
  "}",
  "",
].join("\n"));

mk("safe/firestore.rules", [
  "rules_version = '2';",
  "service cloud.firestore {",
  "  match /databases/{database}/documents {",
  "    match /public/{document=**} {",
  "      allow read, write: if request.auth != null;",
  "    }",
  "  }",
  "}",
  "",
].join("\n"));

mk("safe/Dockerfile", [
  "FROM node:20.11.1-alpine",
  "WORKDIR /app",
  "COPY . .",
  "ARG CONFIG_PATH",
  "RUN npm ci",
  "USER node",
  'CMD ["node", "server.js"]',
  "",
].join("\n"));

mk("safe/ci.yml", [
  "name: CI",
  "permissions:",
  "  contents: read",
  "on: pull_request",
  "jobs:",
  "  build:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.2.2",
  "      - name: Greet reporter",
  "        env:",
  "          TITLE: ${{ github.event.issue.title }}",
  '        run: echo "Report: $TITLE"',
  "",
].join("\n"));

// ---------- git history (HIST-003: committed-then-removed Stripe key) ----------
git("init", "-q");
git("add", "-A");
git("commit", "-q", "-m", "fixture tree");
mk("stripe.env.bak", ["STRIPE_SECRET_KEY=sk_live_51Dem0KeyN0tRealZ9xQ2vB", ""].join("\n"));
git("add", "-A");
git("commit", "-q", "-m", "backup env during migration");
rmSync(join(app, "stripe.env.bak"));
git("add", "-A");
git("commit", "-q", "-m", "remove backup env");

console.log("multilingual fixture ready (git history: stripe key committed then removed)");
