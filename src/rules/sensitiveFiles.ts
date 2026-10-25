import type { ScanContext, RuleResult } from "../types.js";
import { rootCause } from "../util.js";

/**
 * Layer 2 (part) — Sensitive-file inventory (v1.6, Plan Section 6).
 * Real value present = HIGH · empty/placeholder = MEDIUM review.
 */

interface FileProbe {
  id: string;
  match: (f: { rel: string; content: string; lines: string[] }) => boolean;
  real: (f: { rel: string; content: string; lines: string[] }) => boolean;
  title: (real: boolean, f: { rel: string }) => string;
  fix: string;
  owasp: string;
  evidenceType: string;
}

const PROBES: FileProbe[] = [
  {
    id: "FILE-001",
    match: (f) => /(^|\/)(dump|backup|export|db)[^/]*\.sql$|[^/]*\.(dump|bak)$/i.test(f.rel),
    real: (f) => /INSERT\s+INTO|COPY\s+/i.test(f.content),
    title: (real, f) => real ? `Database dump file with data committed (${f.rel})` : `Database dump/backup file present (${f.rel}) — review`,
    fix: "Data dumps contain full user tables — remove from the repo, move to secure offline storage, rotate any credentials inside, and purge git history.",
    owasp: "A05",
    evidenceType: "db_dump_file",
  },
  {
    id: "FILE-002",
    match: (f) => /(^|\/)\.npmrc$/.test(f.rel) && /_authToken/i.test(f.content),
    real: (f) => f.lines.some((l) => /^\s*_authToken\s*=\s*(\S{8,})/.test(l) && !/\$\{|xxxx|<|placeholder/i.test(l)),
    title: (real, f) => real ? "npm auth token committed in .npmrc" : ".npmrc contains a placeholder token — review",
    fix: "Move the registry token to environment or keychain-level npm config (~/.npmrc outside the repo); rotate the leaked token.",
    owasp: "A02",
    evidenceType: "npmrc_token",
  },
  {
    id: "FILE-003",
    match: (f) => /service[-_]?account[-_]?key[^/]*\.json$|(^|\/)[^/]*firebase-adminsdk[^/]*\.json$/i.test(f.rel) || (/\.json$/.test(f.rel) && f.content.includes('"private_key"') && f.content.includes('"client_email"')),
    real: () => true,
    title: (_real, f) => `Cloud service-account JSON with private key committed (${f.rel})`,
    fix: "Remove the service-account file, rotate/revoke the key in the cloud console, use workload identity or mounted secrets instead.",
    owasp: "A02",
    evidenceType: "service_account_json",
  },
  {
    id: "FILE-004",
    match: (f) => /(^|\/)terraform\.tfstate$|(^|\/)terraform\.tfstate\.backup$/.test(f.rel),
    real: (f) => f.content.trim().length > 10 && f.content.includes("{"),
    title: (real, f) => real ? "terraform.tfstate committed — state files embed secrets in plaintext" : "Empty terraform.tfstate present — review",
    fix: "Never commit tfstate: store it in a locked remote backend (S3+KMS/GCS). Rotate every secret it referenced and purge git history.",
    owasp: "A05",
    evidenceType: "terraform_state",
  },
  {
    id: "FILE-005",
    match: (f) => /(^|\/)id_rsa$|(^|\/)id_ed25519$|(^|\/)id_ecdsa$|[^/]*\.pem$/i.test(f.rel) && /PRIVATE KEY/.test(f.content),
    real: () => true,
    title: (_real, f) => `SSH private key committed (${f.rel})`,
    fix: "Remove the key, generate a new keypair, update authorized_keys/deploy keys, and purge git history.",
    owasp: "A02",
    evidenceType: "ssh_private_key",
  },
  {
    id: "FILE-006",
    match: (f) => /(^|\/)\.env\.production$|(^|\/)config\/production\.(json|js|ts)$|(^|\/)config\.production\.json$/i.test(f.rel),
    real: (f) => f.lines.some((l) => /=|:\s*["']/.test(l) && !/^\s*#/.test(l)),
    title: (real, f) => real ? "Production config/env file committed with values" : "Production env/config file present — review",
    fix: "Keep production values in the deployment platform's secret store; commit only sanitized examples.",
    owasp: "A05",
    evidenceType: "production_config",
  },
];

export function scanSensitiveFiles(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];
  for (const f of ctx.files) {
    for (const p of PROBES) {
      if (!p.match(f)) continue;
      const real = p.real(f);
      const tracked = ctx.trackedFiles.has(f.rel);
      findings.push({
        id: p.id,
        severity: real ? "high" : "medium",
        confidence: real ? "high" : "medium",
        title: p.title(real, f),
        file: f.rel,
        line: 0,
        evidence: {
          type: p.evidenceType,
          masked: `${f.rel} (${tracked ? "git-tracked" : "present"})`,
          note: real ? "real content detected" : "empty/placeholder content — review note",
        },
        owasp: p.owasp,
        fix: p.fix,
        fix_mode: "suggested-diff",
        remediation: real ? {
          type: "rotate-first", provider: "generic",
          steps: "1) Rotate every credential inside this file 2) Remove it from the repo + gitignore 3) Scrub git history 4) Verify old credentials are dead",
          history_cleanup: "git filter-repo required — deletion from HEAD is not enough",
        } : undefined,
        root: f.rel,
        root_cause: rootCause(p.id, f.rel),
        verified: true,
      });
    }
  }
  return { findings };
}
