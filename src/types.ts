/**
 * Anubis Guardian — canonical data contract (findings.json schema, Plan Section 8).
 * Every renderer (terminal/md/json) is a deterministic function over ScanResult.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";

export interface Evidence {
  type: string;
  masked: string;          // first-4 + … + sha256 prefix — full value is NEVER written (Section 9.2)
  sha256_prefix?: string;  // 8 hex chars
  note?: string;
}

export interface Remediation {
  type: "rotate-first" | "config-change" | "code-change";
  provider?: string;
  steps: string;
  history_cleanup?: string;
}

export interface Finding {
  id: string;                 // e.g. SUPA-001
  severity: Severity;
  title: string;
  file: string;               // relative path (or URL/endpoint in URL mode — v0.4)
  line: number;               // 1-based; 0 = file-level
  evidence: Evidence;
  owasp: string;
  confidence: Confidence;
  fingerprint: string;        // stable across runs (rule + path + normalized match)
  suppression: null | { reason: string; expires: string };
  fix: string;                // fix-first phrasing (Output Contract, v1.4)
  fix_mode: "suggested-diff"; // never auto-apply (Section 9.1)
  remediation?: Remediation;
  needs_confirmation?: boolean;
  root_cause?: string;        // rule_id + root — drives score caps (v1.3)
  root?: string;              // per-rule grouping root (secret hash / migration file / …)
  verified: boolean;          // deterministic checks emit verified evidence (Section 8 schema)
  source?: "builtin" | "org-rule" | "gitleaks" | "osv-scanner" | "semgrep" | "ai-review"; // v0.2 adapters + v0.3 AI provenance
}

export interface ScoreGroup {
  rule_id: string;
  root: string;
  severity: Severity;
  count: number;
  deducted: number;           // after repeat +10% and 2x cap (v1.3)
}

export interface ScoreBreakdown {
  base: 100;
  total_deducted: number;
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  groups: ScoreGroup[];
  note: string;               // low-confidence findings never deduct
}

export interface Coverage {
  checks_run: number;
  checks_applicable: number;
  classes_covered: string[];
  classes_not_covered: string[];
}

export interface StackInfo {
  detected: string[];         // e.g. ["nextjs", "supabase", "typescript"]
  frameworks: Record<string, boolean>;
  notes: string[];            // Phase 0 sanity notes (static-only — Section 9.7)
}

/** v0.2 — Recon inventory (Plan Section 6 Phase 0, v1.6 item A). */
export interface Inventory {
  routes: Array<{ path: string; file: string; kind: "route" | "server-action" | "controller-method"; method?: string; guard?: string | null }>;
  controllers: Array<{ name: string; file: string; guard: string | null; global_guard: boolean }>;
  supabase: {
    tables: Array<{ name: string; file: string; rls_enabled: boolean }>;
    rpcs: Array<{ name: string; file: string }>;
    edge_functions: string[];
  };
  socket_events: Array<{ event: string; file: string; gateway: string }>;
  webhooks: Array<{ path: string; file: string }>;
}

/** v0.4 — URL Mode metadata (authorization record + ownership label, Plan Section 7). */
export interface UrlMeta {
  authorization: {
    url: string;
    timestamp: string;
    level: number;
    ownership_method: string;
    ownership_verified: boolean;
    note: string;
  };
  requests: { total: number; by_method: Record<string, number> };
  robots: { checked: boolean; disallow_all: boolean; skipped_paths: string[] };
  levels_run: string[];
  notes: string[];
}

/** v0.3 — AI review layer metadata (opt-in, off by default; meta.ai_used mirrors it). */
export interface AiReviewMeta {
  used: boolean;
  provider: string;
  model?: string;
  candidates: number;
  confirmed: number;
  corroborated: number;
  rejected: number;
  notes: string[];
}

export interface ScanResult {
  tool: "anubis-guardian";
  version: string;
  advisory_snapshot: string;  // bundled per release — deterministic per tool version
  target: { mode: "codebase" | "url"; path: string; paths?: string[]; stack: string[] }; // paths = multi-root (v0.2) · mode "url" = v0.4
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  summary: { critical: number; high: number; medium: number; low: number; info: number };
  coverage: Coverage;
  score_breakdown: ScoreBreakdown;
  findings: Finding[];
  inventory?: Inventory;      // v0.2 recon inventory
  url_meta?: UrlMeta;         // v0.4 URL Mode (authorization record — Plan Section 7.4)
  ai_review?: AiReviewMeta;   // v0.3 AI review (only when --ai-review ran)
  portfolio?: Array<{ path: string; score: number; grade: string; findings: number }>; // --workspaces (v0.2)
  meta: {
    no_exec: true;            // Section 9.7 — the tool never executes project code
    files_scanned: number;
    git_history_scanned: boolean;
    online_used?: boolean;    // --online registry checks ran (non-deterministic — excluded from default runs)
    adapters_used?: string[]; // external tools merged (run only when explicitly requested)
    ai_used?: boolean;        // v0.3: AI review layer ran (--ai-review) — non-deterministic, flagged
    rules_lock?: "verified" | "off" | "bypassed"; // v1.0: rules supply-chain guard state (--rules-dir)
    community_rules?: boolean;   // v1.0: unpinned/bypassed org rules ran (quarantine label)
    active_tests?: boolean;      // v1.0: restricted differential IDOR ran (--active-tests, verified ownership)
  };
}

/** Internal rule context passed to every scanner. */
export interface ScanContext {
  rootDir: string;
  rel: (abs: string) => string;
  files: ScannedFile[];
  stack: StackInfo;
  gitAvailable: boolean;
  trackedFiles: Set<string>;  // from `git ls-files` (empty when not a repo)
  schemaDump?: string;        // --schema <file>: user-run `supabase db dump` for drift check
  label?: string;             // v0.2: root label in multi-root scans
  online?: boolean;           // v0.2: --online registry metadata (non-deterministic, off by default)
  advisoryFile?: string;      // v0.2: local advisory snapshot override (--advisories)
  aiReview?: boolean;         // v0.3: AI review layer (opt-in; verifier-gated; flagged in meta)
  quarantine?: string;        // v0.3: quarantine dir for generated tests (tool never executes them)
}

/** v0.2 — custom org rule (--rules-dir, Plan Section 4 organizational deployment). */
export interface OrgRule {
  id: string;                 // ORG-<name>
  severity: Severity;
  title: string;
  owasp: string;
  files: string[];            // glob subset (same as CANDIDATE_PATTERNS)
  regex: string;
  flags?: string;             // regex flags, default "gim"
  fix: string;
  clean_cases?: string;       // mandatory note: what a clean file looks like (Plan v1.6 DSL requirement)
}

export interface ScannedFile {
  abs: string;
  rel: string;
  content: string;
  lines: string[];
}

export interface RuleResult {
  findings: Omit<Finding, "fingerprint" | "suppression">[];
}

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25, high: 10, medium: 4, low: 1, info: 0,
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
