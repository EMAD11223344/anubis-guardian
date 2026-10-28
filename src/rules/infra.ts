import type { ScanContext, RuleResult } from "../types.js";
import { rootCause, mkFinding, type MkIn } from "../util.js";

/**
 * Layer 5 — infrastructure / config-as-policy pack (dev round W3).
 *
 * These rules are LANGUAGE-INDEPENDENT: they match declarative configuration
 * formats by file shape + line regex, the same bounded style as the CI/Docker
 * pack — no new parser, no new dependency.
 *
 *   FB-001  Firebase security rules (*.rules) grant write verbs with `if true`
 *           — the database is world-writable. Read-only `if true` stays a LOW
 *           review note (public static content can be intentional).
 *   TF-001  Terraform storage bucket with a public-read ACL — often legitimate
 *           (static sites), so HIGH + needs_confirmation.
 *
 * Known limits (documented): single-line `allow` statements only (multi-line
 * conditions are not parsed); `database.rules.json` (JSON format) is not
 * matched; only the literal `acl = "public-read(-write)"` attribute is checked,
 * not provider-specific public-access-block resources.
 */

const FIREBASE_RULES_FILE = /\.(rules)$/i;
const TF_FILE = /\.(tf)$/i;

const ALLOW_STMT = /^\s*allow\s+([^;]+);\s*$/;
const ALLOW_CLAUSE = /^([^:]+?)\s*:\s*if\s+(.+)$/;

function mk(ctx: ScanContext, f: MkIn): RuleResult["findings"][number] {
  return mkFinding(f);
}

export function scanInfra(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"][number][] = [];

  for (const f of ctx.files) {
    // ---------- FB-001: Firebase security rules ----------
    if (FIREBASE_RULES_FILE.test(f.rel)) {
      for (let i = 0; i < f.lines.length; i++) {
        const stmt = f.lines[i].match(ALLOW_STMT);
        if (!stmt) continue;
        const clause = stmt[1].match(ALLOW_CLAUSE);
        if (!clause) continue;
        const [, verbsRaw, condition] = clause;
        const conditionTrue = /^\s*true\s*$/.test(condition.trim());
        if (!conditionTrue) continue;
        const verbs = verbsRaw.toLowerCase();
        const writeGranted = /\b(write|create|update|delete)\b/.test(verbs);
        if (writeGranted) {
          findings.push(mk(ctx, {
            id: "FB-001",
            severity: "high",
            title: "Firebase security rules grant public write access (if true)",
            file: f.rel,
            line: i + 1,
            evidence: {
              type: "firebase_public_write",
              masked: stmt[1].trim().slice(0, 60),
              note: "any unauthenticated client can create/overwrite/delete data — scope the condition to auth state (e.g. request.auth != null) or specific fields",
            },
            owasp: "A01",
            confidence: "high",
            fix: "Restrict the condition: require a signed-in user (request.auth != null), per-owner scoping (resource.data.uid == request.auth.uid), or server-side writes only. Deploy the updated rules and verify in the Firebase console.",
            root: f.rel,
            root_cause: rootCause("FB-001", f.rel),
          }));
        } else {
          findings.push(mk(ctx, {
            id: "FB-001",
            severity: "low",
            confidence: "medium",
            needs_confirmation: true,
            title: "Firebase security rules grant public read access (if true)",
            file: f.rel,
            line: i + 1,
            evidence: {
              type: "firebase_public_read",
              masked: stmt[1].trim().slice(0, 60),
              note: "public read may be intentional for static/public content — confirm nothing private is exposed under this match block",
            },
            owasp: "A01",
            fix: "If the collection holds only public content this is fine; otherwise scope reads to auth state or per-owner conditions.",
            root: f.rel,
            root_cause: rootCause("FB-001", f.rel),
          }));
        }
      }
    }

    // ---------- TF-001: Terraform public-read storage ACL ----------
    if (TF_FILE.test(f.rel)) {
      for (let i = 0; i < f.lines.length; i++) {
        const m = f.lines[i].match(/\bacl\s*=\s*"(public-read(?:-write)?)"/);
        if (m) {
          findings.push(mk(ctx, {
            id: "TF-001",
            severity: "high",
            title: `Terraform storage bucket ACL is public-${m[1] === "public-read" ? "read" : "read/write"}`,
            file: f.rel,
            line: i + 1,
            evidence: {
              type: "terraform_public_acl",
              masked: `acl = "${m[1]}"`,
              note: "any unauthenticated principal can list/read (and with public-read-write, write) this bucket — for static-site hosting prefer a CDN/OAC setup and a public-access block",
            },
            owasp: "A01",
            confidence: "medium",
            needs_confirmation: true,
            fix: "Set acl = \"private\" and add an aws_s3_bucket_public_access_block with block_public_acls/policies enabled; serve public content through a CDN with an origin access control if needed.",
            root: f.rel,
            root_cause: rootCause("TF-001", f.rel),
          }));
        }
      }
    }
  }

  return { findings };
}
