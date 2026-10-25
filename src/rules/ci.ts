import type { ScanContext, RuleResult } from "../types.js";
import { rootCause, mkFinding, type MkIn } from "../util.js";

/**
 * DOCKER-003 ARG-name risk (token-based, substring-free):
 * "API_URL" must NOT match because it contains "api"; "API_KEY" must.
 * So tokenize the name on `_` AND camelCase boundaries and require a risky TOKEN,
 * never a raw substring (the old `/api/i` regex turned every API_URL into a HIGH finding).
 */
const ARG_RISKY_TOKENS = new Set([
  "secret", "password", "passwd", "pass", "pwd", "token", "key",
  "apikey", "credential", "credentials", "private", "jwt", "oauth", "bearer",
]);

export function argSecretRisk(name: string): boolean {
  const tokens = name
    .replace(/(?<=[a-z0-9])(?=[A-Z])/g, "_") // camelCase → snake splitting
    .toLowerCase()
    .split(/[^a-z0-9]+/);
  return tokens.some((t) => ARG_RISKY_TOKENS.has(t));
}

/**
 * Layer 5 — CI / supply-chain pack (Plan Section 6, v1.6 item D; v0.2 priority #1
 * per Step 0 sweep: unpinned actions hit 22% of a 100-project sample).
 *
 * CI-001  GitHub Actions pinned by tag/branch instead of full commit SHA
 * CI-002  pull_request_target trigger (fork code runs with repo secrets)
 * CI-003  script injection — untrusted input interpolated into `run:`
 * CI-004  over-broad workflow/job permissions (write-all or unused write scopes)
 * DOCKER-001 container runs as root (no USER directive / USER root)
 * DOCKER-002 FROM :latest tag (unpinned base image)
 * DOCKER-003 secrets passed via ARG (persist in image history)
 */

const WORKFLOW_FILE = /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/;

const USES_RE = /^\s*(?:-\s+)?uses:\s*(\S+)@(\S+)\s*$/;
const SHA_RE = /^[0-9a-f]{40}$/;

const UNTRUSTED_EXPR = /\$\{\{\s*(event\.(issue|pull_request|discussion|head_commit|comment)\.(body|title|message|author|login)|github\.event\.pull_request\.title|github\.event\.issue\.title|github\.head_ref|github\.event\.head_commit\.message)[^}]*\}\}/;

const RUN_RE = /^\s*(?:-\s+)?run:\s*(.*)$/;

const FIX_CI001 =
  "Pin third-party actions to a full 40-char commit SHA (immutable) instead of a mutable tag/branch, and comment the version above the line. Tags are attacker-moveable; SHAs are not.";
const FIX_CI002 =
  "Avoid pull_request_target with checkout of the PR head: fork code would run with repository secrets. If you must label/comment, checkout the base ref and never execute untrusted PR code in a privileged job.";
const FIX_CI003 =
  "Never interpolate untrusted event data (titles, bodies, branch names) directly into run: scripts. Pass the value through the environment: env: TITLE: ${{ ... }} then use \"$TITLE\" quoted inside the script.";
const FIX_CI004 =
  "Grant least-privilege: set the top-level permissions block explicitly (e.g. contents: read) and add only the scopes a job truly needs (security-events: write for SARIF upload). Avoid permissions: write-all.";
const FIX_DOCKER1 =
  "Run the container as a non-root user: add a dedicated user in the Dockerfile (USER app) or set runAsNonRoot in the deployment. Root containers escalate container escapes.";
const FIX_DOCKER2 =
  "Pin base images by digest or at least a specific version tag — :latest is mutable and breaks reproducibility; a registry compromise silently changes your base.";
const FIX_DOCKER3 =
  "Never pass secrets via ARG — args are baked into image history (docker history shows them). Use BuildKit --mount=type=secret or runtime env/orchestrator secrets.";

function ai(_ctx: ScanContext, f: MkIn): RuleResult["findings"][number] {
  return mkFinding(f);
}

export function scanCi(ctx: ScanContext): RuleResult {
  const findings: RuleResult["findings"] = [];

  for (const f of ctx.files) {
    // ---------- GitHub Actions workflows ----------
    if (WORKFLOW_FILE.test(f.rel)) {
      for (let i = 0; i < f.lines.length; i++) {
        const line = f.lines[i];

        // CI-004 — permissions blocks (workflow-level and job-level)
        if (/^permissions:/.test(line) || /^\s{4,}permissions:/.test(line)) {
          // capture the block (next few lines)
          const block = f.lines.slice(i, i + 8).join("\n");
          if (/write-all/.test(block)) {
            findings.push(ai(ctx, {
              id: "CI-004",
              severity: "high",
              title: "Workflow grants write-all permissions",
              file: f.rel, line: i + 1,
              evidence: { type: "permissions_write_all", masked: "permissions: write-all", note: "every token in this workflow can write repos/packages — least privilege required" },
              owasp: "A05",
              fix: FIX_CI004,
              root: f.rel, root_cause: rootCause("CI-004", f.rel),
            }));
          }
        }

        // CI-001 — unpinned uses:
        const uses = line.match(USES_RE);
        if (uses) {
          const [, action, ref] = uses;
          const isLocal = action.startsWith("./") || action.startsWith("./");
          if (!isLocal && !SHA_RE.test(ref)) {
            findings.push(ai(ctx, {
              id: "CI-001",
              severity: "medium",
              title: `Action pinned by mutable ref (${ref}) instead of commit SHA`,
              file: f.rel, line: i + 1,
              evidence: { type: "unpinned_action", masked: `${action}@${ref}`, note: "tags/branches are moveable — tag hijacking injects code into CI" },
              owasp: "A08",
              fix: FIX_CI001,
              root: f.rel, root_cause: rootCause("CI-001", f.rel),
            }));
          }
        }

        // CI-002 — pull_request_target
        if (/\bpull_request_target\b/.test(line)) {
          findings.push(ai(ctx, {
            id: "CI-002",
            severity: "high",
            title: "Workflow uses pull_request_target (fork code with repo secrets)",
            file: f.rel, line: i + 1,
            evidence: { type: "pr_target_trigger", masked: "pull_request_target", note: "combined with checkout of the PR head this executes fork code in a privileged context" },
            owasp: "A08",
            fix: FIX_CI002,
            root: f.rel, root_cause: rootCause("CI-002", f.rel),
          }));
        }

        // CI-003 — script injection (untrusted ${{ }} inside run:, inline or block-scalar)
        const run = line.match(RUN_RE);
        if (run && UNTRUSTED_EXPR.test(run[1])) {
          findings.push(ai(ctx, {
            id: "CI-003",
            severity: "high",
            title: "Untrusted event data interpolated directly into run: script",
            file: f.rel, line: i + 1,
            evidence: { type: "script_injection", masked: run[1].trim().slice(0, 60), note: "a crafted PR title/branch name becomes shell code with workflow-token access" },
            owasp: "A03",
            fix: FIX_CI003,
            root: f.rel, root_cause: rootCause("CI-003", f.rel),
          }));
        } else if (run && /^\|\s*$/.test(run[1])) {
          // block scalar: scan the indented body for untrusted interpolation
          let j = i + 1;
          while (j < f.lines.length && (/^\s*#/.test(f.lines[j]) || f.lines[j].trim() === "" || /^\s{6,}/.test(f.lines[j]))) {
            if (UNTRUSTED_EXPR.test(f.lines[j])) {
              findings.push(ai(ctx, {
                id: "CI-003",
                severity: "high",
                title: "Untrusted event data interpolated directly into run: script (block)",
                file: f.rel, line: j + 1,
                evidence: { type: "script_injection", masked: f.lines[j].trim().slice(0, 60), note: "a crafted PR title/branch name becomes shell code with workflow-token access" },
                owasp: "A03",
                fix: FIX_CI003,
                root: f.rel, root_cause: rootCause("CI-003", f.rel),
              }));
              break;
            }
            j++;
          }
        }
      }

      // workflow with jobs but no explicit permissions block at all → GH defaults can be write on older repos
      const hasPermissions = /^permissions:/m.test(f.content);
      const hasJobs = /^jobs:/m.test(f.content);
      if (hasJobs && !hasPermissions) {
        findings.push(ai(ctx, {
          id: "CI-004",
          severity: "medium",
          title: "Workflow declares no permissions block (GH default token scope applies)",
          file: f.rel, line: 0,
          evidence: { type: "permissions_undeclared", masked: "no permissions:", note: "declare a minimal top-level permissions block explicitly" },
          owasp: "A05",
          confidence: "medium",
          fix: FIX_CI004,
          root: f.rel, root_cause: rootCause("CI-004", f.rel),
        }));
      }
    }

    // ---------- Dockerfiles ----------
    if (/(^|\/)Dockerfile[^/]*$/.test(f.rel)) {
      let hasUser = false;
      for (let i = 0; i < f.lines.length; i++) {
        const line = f.lines[i];
        const from = line.match(/^FROM\s+([\w./-]+)(?::([\w.-]+))?(?:@(\S+))?\s*/i);
        if (from) {
          const [, image, tag, digest] = from;
          if (!tag && !digest) {
            findings.push(ai(ctx, {
              id: "DOCKER-002",
              severity: "medium",
              title: `Base image has no tag or digest (mutable)`,
              file: f.rel, line: i + 1,
              evidence: { type: "unpinned_base_image", masked: `${image}:${tag ?? "(none)"}` },
              owasp: "A08",
              fix: FIX_DOCKER2,
              root: f.rel, root_cause: rootCause("DOCKER-002", f.rel),
            }));
          } else if (tag && tag.toLowerCase() === "latest" && !digest) {
            findings.push(ai(ctx, {
              id: "DOCKER-002",
              severity: "medium",
              title: `Base image pinned to :latest (mutable)`,
              file: f.rel, line: i + 1,
              evidence: { type: "unpinned_base_image", masked: `${image}:latest` },
              owasp: "A08",
              fix: FIX_DOCKER2,
              root: f.rel, root_cause: rootCause("DOCKER-002", f.rel),
            }));
          }
        }
        if (/^USER\s+/i.test(line)) {
          const u = line.replace(/^USER\s+/i, "").trim().toLowerCase();
          if (u !== "root" && u !== "0") hasUser = true;
        }
        const arg = line.match(/^ARG\s+([A-Za-z_][A-Za-z0-9_]*)/i);
        if (arg && argSecretRisk(arg[1])) {
          findings.push(ai(ctx, {
            id: "DOCKER-003",
            severity: "high",
            title: "Secret passed via ARG (baked into image history)",
            file: f.rel, line: i + 1,
            evidence: { type: "arg_secret", masked: arg[1], note: "docker history exposes ARG values — use BuildKit --mount=type=secret" },
            owasp: "A05",
            fix: FIX_DOCKER3,
            root: f.rel, root_cause: rootCause("DOCKER-003", f.rel),
          }));
        }
      }
      if (!hasUser) {
        findings.push(ai(ctx, {
          id: "DOCKER-001",
          severity: "medium",
          title: "Container runs as root (no USER directive)",
          file: f.rel, line: 0,
          evidence: { type: "root_container", masked: "no USER <non-root>", note: "add a non-root user and switch before the runtime stage" },
          owasp: "A05",
          confidence: "medium",
          fix: FIX_DOCKER1,
          root: f.rel, root_cause: rootCause("DOCKER-001", f.rel),
        }));
      }
    }
  }

  return { findings };
}
