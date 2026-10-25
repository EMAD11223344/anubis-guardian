import type { ScanContext, RuleResult } from "../types.js";
import { maskSecret, rootCause } from "../util.js";

/**
 * SEED-001 — Credentials hardcoded in seeders / fixtures (Plan Section 6, expanded v1.6).
 * Default HIGH; escalates to CRITICAL only with production proof:
 *   (a) deploy pipeline references the seed, or
 *   (b) default admin password + no env guard in the seeder.
 * v1.6 expansion: generic SQL INSERTs on user/role tables, docker-compose literal
 * connection values, and .env.example files carrying REAL (non-placeholder) secrets.
 */

const SEED_FILE = /(^|\/)(seeders?|factories|fixtures)\//;
const SEED_NAMED = /(^|\/)(seed|seeds)\.(ts|js|sql)$|(^|\/)prisma\/seed\.(ts|js)$|(^|\/)supabase\/seed\.sql$/i;

const PW_ASSIGN = /\b(?:password|passwd|pwd)\b\s*[:=]\s*["'`]([^"'`\n]{4,})["'`]/gi;
const ADMIN_USER = /\b(?:role|isAdmin|role_name)\b\s*[:=]\s*["'`]?(admin|superuser|super_admin|owner|root)["'`]?/i;
const ADMIN_EMAIL = /\b(email|username|user)\b\s*[:=]\s*["'`]admin["'`@]/i;

const WEAK_DEFAULT = /^(admin|password|123456|12345678|changeme|change_me|admin123|root|toor|secret|letmein|qwerty|password123|admin@123|test1234)$/i;

const SQL_INSERT_USER = /\bINSERT\s+INTO\s+(?:"?)(users?|roles?|admins?|accounts?|profiles|auth\.users)(?:"?)\b/gi;
const SQL_PASSWORD_VALUE = /["'`]([A-Za-z0-9!@#$%^&*_.-]{8,})["'`](?=\s*[,)])/g;

const COMPOSE_VAR = /\b(POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|DB_PASSWORD|DATABASE_URL|SUPABASE_DB_PASSWORD|REDIS_PASSWORD|REDIS_HOST_PASSWORD)\b\s*[:=]\s*(["']?)([^"'\n\s#]+)\2/gi;

const STRONG_SECRET = /(sk_live_|rk_live_|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|sb_secret_|-----BEGIN)/;

const ENV_LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?([^"'\n#]+)["']?\s*$/;
const PLACEHOLDER = /(changeme|change_me|xxxxx|<[^>]*>|\$\{[^}]*\}|your[-_][a-z_]*|example|placeholder|dummy|todo|fixme|\*{3,}|\.\.\.)/i;

const FIX_SEED =
  "Remove credentials from code. Bootstrap the first admin through a safe provisioning flow (invite / first-run setup). Seed scripts must never run in production — gate them behind NODE_ENV checks and rotate any credential that was committed (rotate-first).";

function envGuarded(lines: string[]): boolean {
  return lines.some((l) => /process\.env\.|os\.environ|getenv|import\.meta\.env/.test(l));
}

export function scanSeed001(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];

  // (a) production-linkage proof: deploy artifacts referencing seed
  const deployRefsSeed = checkDeployReferencesSeed(ctx);

  for (const f of ctx.files) {
    const isSeedFile = SEED_FILE.test(f.rel) || SEED_NAMED.test(f.rel);
    const isCompose = /(^|\/)docker-compose[^/]*\.ya?ml$|(^|\/)compose[^/]*\.ya?ml$/i.test(f.rel);
    const isEnvExample = /(^|\/)\.env\.(example|template|sample)$/i.test(f.rel);
    const isSql = /\.sql$/i.test(f.rel);

    if (isSeedFile) {
      const guarded = envGuarded(f.lines);
      for (let i = 0; i < f.lines.length; i++) {
        const line = f.lines[i];
        let m: RegExpExecArray | null;
        PW_ASSIGN.lastIndex = 0;
        while ((m = PW_ASSIGN.exec(line)) !== null) {
          const value = m[1];
          if (PLACEHOLDER.test(value)) continue;
          if (/\$\{[^}]*\}|process\.env\./.test(value)) continue;
          const contextWindow = f.lines.slice(i, i + 6).join("\n");
          const adminContext = ADMIN_USER.test(contextWindow) || ADMIN_EMAIL.test(contextWindow);
          const weakDefault = WEAK_DEFAULT.test(value);
          const escalate = deployRefsSeed.referenced || (weakDefault && adminContext && !guarded);
          const masked = maskSecret(value);
          findings.push({
            id: "SEED-001",
            severity: escalate ? "critical" : "high",
            confidence: "high",
            title: escalate
              ? "Seeder credential runs in production (deploy pipeline references seed)"
              : "Credential hardcoded in seeder/fixture",
            file: f.rel, line: i + 1,
            evidence: {
              type: "seeder_credential",
              masked: `password = ${masked.masked}`,
              sha256_prefix: masked.sha256_prefix,
              note: escalate
                ? `escalated: ${deployRefsSeed.detail || "default admin credential without env guard"}`
                : "default HIGH — CRITICAL requires production-linkage proof (no false CRITICALs)",
            },
            owasp: "A07",
            fix: FIX_SEED,
            fix_mode: "suggested-diff",
            remediation: { type: "rotate-first", provider: "generic", steps: "1) Rotate the credential 2) Provision admin via invite/first-run flow 3) Add env guard around seed 4) Scrub git history if committed", history_cleanup: "git filter-repo if committed" },
            root: masked.sha256_prefix,
            root_cause: rootCause("SEED-001", masked.sha256_prefix),
            verified: true,
          });
        }
      }
    }

    // (b) v1.6: generic SQL INSERT into user/role tables with password-ish literal
    if (isSql) {
      // v1.6 expansion: INSERT into user-ish tables — position-based extraction of the
      // password-ish column value (high confidence), or password-shaped literal when
      // no column list exists (medium). Applies to seed files AND generic SQL dumps.
      const insertRe = /\bINSERT\s+INTO\s+"?([\w.]+)"?\s*(?:\(([^)]*)\))?\s*VALUES\s*/gi;
      let im: RegExpExecArray | null;
      while ((im = insertRe.exec(f.content)) !== null) {
        const table = im[1] || "";
        if (!/(users?|roles?|admins?|accounts?|profiles|auth\.users)/i.test(table)) continue;
        const colsRaw = (im[2] || "").split(",").map((c) => c.trim().replace(/^"(.*)"$/, "$1").toLowerCase());
        const passwordColIdx = colsRaw.findIndex((c) => /(password|passwd|pwd|encrypted_password|password_hash)/.test(c));
        const lineNo = f.content.slice(0, im.index).split("\n").length;
        const valuesWindow = f.content.slice(im.index + im[0].length, im.index + im[0].length + 600);
        const tuple = valuesWindow.match(/\(((?:[^'"]|'[^']*'|"[^"]*")*)\)/);
        let flagged: Array<{ value: string; confident: boolean }> = [];
        if (tuple && passwordColIdx >= 0) {
          const parts = tuple[1].match(/(?:[^,']+|'[^']*')+/g) ?? [];
          const v = (parts[passwordColIdx] ?? "").replace(/^'|'$/g, "").trim();
          if (v && !PLACEHOLDER.test(v) && v.length >= 4) flagged.push({ value: v, confident: true });
        } else if (!tuple || passwordColIdx < 0) {
          const window = f.lines.slice(lineNo - 1, lineNo + 3).join("\n");
          const valRe = /["'`]([A-Za-z0-9!@#$%^&*_.+\-/]{8,})["'`]/g;
          let vm: RegExpExecArray | null;
          while ((vm = valRe.exec(window)) !== null) {
            const value = vm[1];
            if (PLACEHOLDER.test(value)) continue;
            if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value)) continue;       // emails
            if (/^(19|20)\d{2}-\d{2}-\d{2}/.test(value)) continue;         // dates
            if (/^[a-f0-9]{8}-[a-f0-9]{4}/i.test(value)) continue;         // uuids
            if (/^[A-Za-z]+$/.test(value) && value.length < 16) continue;  // bare words (roles/status)
            if (/\d/.test(value) && /[^A-Za-z0-9]/.test(value) && !/^https?:/i.test(value)) {
              flagged.push({ value, confident: false });
            }
          }
        }
        for (const { value, confident } of flagged) {
          const masked = maskSecret(value);
          findings.push({
            id: "SEED-001",
            severity: confident ? (deployRefsSeed.referenced ? "critical" : "high") : "medium",
            confidence: confident ? "high" : "medium",
            title: confident
              ? `SQL INSERT into "${table}" sets a password column with a literal value`
              : `SQL INSERT into "${table}" contains a password-like literal`,
            file: f.rel, line: lineNo,
            evidence: { type: "sql_insert_credential", masked: masked.masked, sha256_prefix: masked.sha256_prefix, note: confident ? "password column gets a committed literal (v1.6 expansion) — confirm plaintext vs hash" : "generic SQL seed expansion (v1.6) — confirm the column is a credential" },
            owasp: "A07", fix: FIX_SEED, fix_mode: "suggested-diff",
            remediation: { type: "rotate-first", provider: "generic", steps: "1) Confirm plaintext vs hash 2) If plaintext: rotate + provision via safe flow 3) Scrub history", history_cleanup: "git filter-repo if committed" },
            root: masked.sha256_prefix, root_cause: rootCause("SEED-001", masked.sha256_prefix), verified: true,
          });
        }
      }
    }

    // (c) v1.6: docker-compose literal connection values
    if (isCompose) {
      for (let i = 0; i < f.lines.length; i++) {
        const line = f.lines[i];
        let m: RegExpExecArray | null;
        COMPOSE_VAR.lastIndex = 0;
        while ((m = COMPOSE_VAR.exec(line)) !== null) {
          const [, key, , value] = m;
          if (!value || /^\$\{/.test(value)) continue;
          const isPlaceholder = PLACEHOLDER.test(value);
          const masked = maskSecret(value);
          findings.push({
            id: "SEED-001", severity: isPlaceholder ? "medium" : "high", confidence: isPlaceholder ? "medium" : "high",
            title: isPlaceholder
              ? `Compose file carries placeholder value for ${key} — review`
              : `Compose file hardcodes ${key} literal`,
            file: f.rel, line: i + 1,
            evidence: { type: "compose_credential", masked: `${key}=${masked.masked}`, sha256_prefix: masked.sha256_prefix, note: isPlaceholder ? "placeholder value" : "literal value committed (v1.6 expansion)" },
            owasp: "A07",
            fix: "Load compose secrets from env interpolation or Docker secrets — never inline literals; rotate anything committed.",
            fix_mode: "suggested-diff",
            remediation: { type: "rotate-first", provider: "generic", steps: "1) Rotate the credential 2) Switch to env interpolation / secrets 3) Scrub history if committed", history_cleanup: "git filter-repo if committed" },
            root: masked.sha256_prefix, root_cause: rootCause("SEED-001", masked.sha256_prefix), verified: true,
          });
        }
      }
    }

    // (d) v1.6: .env.example carrying REAL secrets (not placeholders)
    if (isEnvExample) {
      for (let i = 0; i < f.lines.length; i++) {
        const line = f.lines[i];
        const m = line.match(ENV_LINE);
        if (!m) continue;
        const [, key, value] = m;
        if (!value || PLACEHOLDER.test(value)) continue;
        const strong = STRONG_SECRET.test(value) || /^[A-Za-z0-9+/=_-]{32,}$/.test(value);
        if (!strong) continue;
        const masked = maskSecret(value);
        findings.push({
          id: "SEED-001", severity: "high", confidence: "medium",
          title: `.env.example contains a REAL-looking secret (${key})`,
          file: f.rel, line: i + 1,
          evidence: { type: "env_example_real_value", masked: `${key}=${masked.masked}`, sha256_prefix: masked.sha256_prefix, note: "example files ship to every clone — placeholders only (v1.6 expansion)" },
          owasp: "A07",
          fix: "Replace with an obvious placeholder (e.g. your-api-key-here). If the value is real, rotate it now — example files are frequently cloned and searched by bots.",
          fix_mode: "suggested-diff",
          remediation: { type: "rotate-first", provider: "generic", steps: "1) Rotate the real credential 2) Replace with placeholder 3) Scrub history", history_cleanup: "git filter-repo if committed" },
          root: masked.sha256_prefix, root_cause: rootCause("SEED-001", masked.sha256_prefix), verified: true,
        });
      }
    }
  }

  return { findings };
}

function checkDeployReferencesSeed(ctx: ScanContext): { referenced: boolean; detail?: string } {
  const deployFiles = ctx.files.filter((f) =>
    /(^|\/)(Dockerfile|Procfile|fly\.toml|render\.yaml|ecosystem\.config\.js)$/.test(f.rel) ||
    /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(f.rel) ||
    /(^|\/)package\.json$/.test(f.rel)
  );
  for (const f of deployFiles) {
    const isPkg = f.rel.endsWith("package.json");
    if (isPkg) {
      try {
        const pkg = JSON.parse(f.content);
        const scripts = pkg.scripts ?? {};
        for (const [name, cmd] of Object.entries<string>(scripts)) {
          if (/^(pre)?start$|^start|^deploy|^heroku-postbuild$/.test(name) && /\bseed\b/.test(cmd)) {
            return { referenced: true, detail: `package.json script "${name}" runs the seed` };
          }
        }
      } catch { /* not JSON */ }
      continue;
    }
    const seedLine = f.lines.find((l) =>
      /\b(?:CMD|ENTRYPOINT|run:|command|web:|processes|prestart)\b/i.test(l) && /\bseed\b/i.test(l)
    );
    if (seedLine) return { referenced: true, detail: `${f.rel} references seed in a deploy/run directive` };
  }
  return { referenced: false };
}
