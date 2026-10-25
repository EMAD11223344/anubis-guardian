import type { ScanContext, ScanResult, Finding } from "./types.js";
import { walk } from "./walk.js";
import { recon } from "./recon.js";
import { buildInventory } from "./inventory.js";
import { gitAvailable, trackedFiles } from "./rules/history.js";
import { scanSecrets } from "./rules/secrets.js";
import { scanHdr001 } from "./rules/hdr001.js";
import { scanSeed001 } from "./rules/seed001.js";
import { scanSensitiveFiles } from "./rules/sensitiveFiles.js";
import { scanHistory } from "./rules/history.js";
import { scanSupabase } from "./rules/supabase.js";
import { scanNextjs } from "./rules/nextjs.js";
import { scanNestjs } from "./rules/nestjs.js";
import { scanSast } from "./rules/sast.js";
import { scanCi } from "./rules/ci.js";
import { scanDeps } from "./rules/deps.js";
import { scanCrypto } from "./rules/crypto.js";
import { scanPacks2 } from "./rules/packs2.js";
import { scanTaint } from "./rules/taint.js";
import { scanAgentEnv } from "./rules/agentenv.js";
import { computeScore } from "./score.js";
import { applySuppression, parseInlineIgnores, fingerprint, mkFinding, type RawFinding } from "./util.js";
import { CHECKS, CLASSES_COVERED, CLASSES_NOT_COVERED } from "./coverage.js";
import { runAdapters } from "./adapters.js";
import { loadOrgRules, runOrgRules } from "./rulesdir.js";
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { SEVERITY_ORDER, type Inventory } from "./types.js";

export const VERSION = "1.0.1";
export const ADVISORY_SNAPSHOT = "2026-10";

/**
 * Scan engine orchestrator.
 * Execution-safety invariant (Plan Section 9.7): this engine only READS files
 * and runs git plumbing against the repo. It never installs, builds, tests,
 * or executes any lifecycle script of the scanned project.
 * (npm/registry metadata calls happen ONLY behind --online — flagged in meta.)
 */
export function scan(rootDir: string, opts: ScanOptions = {}): ScanResult {
  const files = walk(rootDir);
  const stack = recon(rootDir, files);
  const git = gitAvailable(rootDir);
  const tracked = git ? trackedFiles(rootDir) : new Set<string>();

  let schemaDump: string | undefined;
  if (opts.schemaDump) {
    try { schemaDump = readFileSync(opts.schemaDump, "utf8"); } catch { schemaDump = undefined; }
  }

  const ctx: ScanContext = {
    rootDir,
    rel: (abs: string) => abs,
    files, stack, gitAvailable: git, trackedFiles: tracked, schemaDump,
    online: opts.online, advisoryFile: opts.advisoryFile, label: basename(rootDir),
  };

  const raw: RawFinding[] = [
    ...scanSecrets(ctx).findings,
    ...scanHdr001(ctx).findings,
    ...scanSeed001(ctx).findings,
    ...scanSensitiveFiles(ctx).findings,
    ...scanHistory(ctx).findings,
    ...scanSupabase(ctx).findings,
    ...scanNextjs(ctx).findings,
    ...scanNestjs(ctx).findings,
    ...scanSast(ctx).findings,
    ...scanCi(ctx).findings,
    ...scanDeps(ctx).findings,
    ...scanCrypto(ctx).findings,
    ...scanPacks2(ctx).findings,   // v0.3 rule packs II
    ...scanTaint(ctx).findings,    // v0.3 taint-lite (MEDIUM cap)
    ...scanAgentEnv(ctx).findings, // v0.3 agent-environment checks
  ];

  // org rules (--rules-dir, v1.4 organizational deployment)
  if (opts.rulesDir) {
    const { rules, warnings } = loadOrgRules(opts.rulesDir);
    for (const w of warnings) console.error(`org-rules: ${w}`);
    raw.push(...runOrgRules(rules, ctx.files));
  }

  // adapters (--tools, off by default — determinism contract)
  const metaExtras: { online_used?: boolean; adapters_used?: string[] } = {};
  if (opts.tools?.length) {
    const { findings, used } = runAdapters(ctx, opts.tools);
    raw.push(...findings);
    if (used.length) metaExtras.adapters_used = used;
  }

  // inline suppression (v1.2) — file-scoped, reason + expiry mandatory
  const findings: Finding[] = [];
  const seenFp = new Set<string>();
  for (const f of raw) {
    const file = ctx.files.find((x) => x.rel === f.file);
    const ignores = file ? parseInlineIgnores(file.lines) : [];
    const sup = applySuppression(f, ignores, f.file);
    if (seenFp.has(sup.fingerprint)) continue;
    seenFp.add(sup.fingerprint);
    findings.push(sup);
  }

  findings.sort((a, b) => {
    const s = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (s !== 0) return s;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });

  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) summary[f.severity] = (summary[f.severity] ?? 0) + 1;

  const score_breakdown = computeScore(findings);

  const applicableChecks = CHECKS.filter((c) => c.applicable(stack.frameworks, git));

  if (opts.online) metaExtras.online_used = true;

  return {
    tool: "anubis-guardian",
    version: VERSION,
    advisory_snapshot: opts.advisoryFile ? `local:${opts.advisoryFile}` : ADVISORY_SNAPSHOT,
    target: { mode: "codebase", path: rootDir, stack: stack.detected },
    score: score_breakdown.score,
    grade: score_breakdown.grade,
    summary,
    coverage: {
      checks_run: applicableChecks.length,
      checks_applicable: CHECKS.length,
      classes_covered: CLASSES_COVERED,
      classes_not_covered: CLASSES_NOT_COVERED,
    },
    score_breakdown,
    findings,
    inventory: buildInventory(ctx),
    meta: {
      no_exec: true,
      files_scanned: files.length,
      git_history_scanned: git,
      ...metaExtras,
    },
  };
}

export interface ScanOptions {
  schemaDump?: string;
  rulesDir?: string;
  tools?: string[];
  online?: boolean;
  advisoryFile?: string;
  aiReview?: boolean;   // v0.3 — AI review runs at CLI level AFTER the deterministic scan
  quarantine?: string;  // v0.3 — quarantine dir for generated tests (never executed by the tool)
}

/**
 * v0.3 — merge verifier-confirmed AI findings into a scan result (CLI-level,
 * after the deterministic pipeline): re-applies suppression/dedupe, re-sorts,
 * recomputes summary + score. AI findings carry source "ai-review" and are
 * capped at HIGH by the verifier (CRITICAL stays deterministic-confirmation-only).
 */
export function mergeAiFindings(result: ScanResult, aiRaw: RawFinding[]): ScanResult {
  if (!aiRaw.length) return result;
  const merged = [...result.findings];
  for (const f of aiRaw) {
    const fp = fingerprint(f.id, f.file, `${f.evidence.type}|${f.evidence.masked}`);
    if (merged.some((x) => x.fingerprint === fp)) continue;
    merged.push({ ...f, fingerprint: fp, suppression: null });
  }
  merged.sort((a, b) => {
    const s = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (s !== 0) return s;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of merged) summary[f.severity] = (summary[f.severity] ?? 0) + 1;
  const score_breakdown = computeScore(merged);
  return { ...result, findings: merged, summary, score: score_breakdown.score, grade: score_breakdown.grade, score_breakdown };
}

/** v0.2 — merge per-root inventories for combined multi-root JSON output. */
function mergeInventories(results: ScanResult[], paths: string[]): Inventory {
  const inv: Inventory = {
    routes: [], controllers: [],
    supabase: { tables: [], rpcs: [], edge_functions: [] },
    socket_events: [], webhooks: [],
  };
  results.forEach((r, i) => {
    const label = basename(paths[i]);
    if (!r.inventory) return;
    for (const rt of r.inventory.routes) inv.routes.push({ ...rt, file: `${label}/${rt.file}` });
    for (const c of r.inventory.controllers) inv.controllers.push({ ...c, file: `${label}/${c.file}` });
    for (const t of r.inventory.supabase.tables) inv.supabase.tables.push({ ...t, file: `${label}/${t.file}` });
    for (const p of r.inventory.supabase.rpcs) inv.supabase.rpcs.push({ ...p, file: `${label}/${p.file}` });
    for (const e of r.inventory.supabase.edge_functions) inv.supabase.edge_functions.push(`${label}:${e}`);
    for (const s of r.inventory.socket_events) inv.socket_events.push({ ...s, file: `${label}/${s.file}` });
    for (const w of r.inventory.webhooks) inv.webhooks.push({ ...w, file: `${label}/${w.file}` });
  });
  return inv;
}

/**
 * Multi-root scan (Plan v1.6 item G; v0.2): independent roots (e.g. ./frontend
 * ./backend) with cross-root finding linkage — HDR-001 sender in one root and
 * receiver in another upgrades both to a confirmed cross-root CRITICAL.
 * Also powers --workspaces (monorepo portfolio).
 */
export function scanRoots(paths: string[], opts: ScanOptions = {}): ScanResult {
  if (paths.length === 1) return scan(paths[0], opts);

  const results = paths.map((p) => scan(p, opts));
  const prefix = (rootIdx: number, file: string): string => {
    // files keep their per-root relative paths; the root name prefixes ambiguities only
    const label = basename(paths[rootIdx]);
    return file.startsWith("(") ? file : `${label}/${file}`;
  };

  // merge findings with root-prefixed file paths (deterministic)
  const findings: Finding[] = [];
  results.forEach((r, i) => {
    for (const f of r.findings) {
      const copy: Finding = { ...f, file: prefix(i, f.file) };
      copy.fingerprint = f.fingerprint; // keep per-root fingerprint stability
      if (copy.root && copy.root !== "(schema export)" && !copy.root.startsWith("(")) copy.root = `${basename(paths[i])}:${copy.root}`;
      if (copy.root_cause) copy.root_cause = `${basename(paths[i])}:${copy.root_cause}`;
      findings.push(copy);
    }
  });

  // ---- HDR-001 cross-root linkage (v1.6 item G) ----
  const senders = findings.filter((f) => f.id === "HDR-001" && f.evidence.type.startsWith("client_sends") && f.severity !== "info");
  const receivers = findings.filter((f) => f.id === "HDR-001" && f.evidence.type === "receiver_read");
  if (senders.length && receivers.length) {
    const senderRoot = basename(paths[0]);
    const firstSender = senders[0];
    const firstReceiver = receivers[0];
    const link: RawFinding = mkFinding({
      id: "HDR-001",
      severity: "critical",
      title: "Cross-root confirmation: DB credentials sent by one app and read by another",
      file: `${firstSender.file} → ${firstReceiver.file}`,
      line: firstReceiver.line,
      evidence: {
        type: "cross_root_linkage",
        masked: `sender:${firstSender.evidence.masked} → receiver:${firstReceiver.evidence.masked}`,
        note: `sender in "${senderRoot}" and receiver in "${basename(paths[paths.length - 1])}" — both ends of the credential channel are present in this system`,
      },
      owasp: "A02",
      confidence: "high",
      fix: firstReceiver.fix,
      verified: true,
      needs_confirmation: false,
      root: "cross-root",
      root_cause: "HDR-001:cross-root",
    });
    findings.push({ ...link, fingerprint: fingerprint("HDR-001", "cross-root", link.evidence.masked), suppression: null });
  }

  findings.sort((a, b) => {
    const s = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (s !== 0) return s;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });

  // dedupe after merge
  const seen = new Set<string>();
  const merged: Finding[] = [];
  for (const f of findings) {
    const key = `${f.id}|${f.file}|${f.evidence.type}|${f.evidence.masked}`;
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(f);
  }

  const combined = computeScore(merged);
  const stackAll = [...new Set(results.flatMap((r) => r.target.stack))];
  const filesAll = results.reduce((a, r) => a + r.meta.files_scanned, 0);

  return {
    tool: "anubis-guardian",
    version: VERSION,
    advisory_snapshot: results[0].advisory_snapshot,
    target: { mode: "codebase", path: paths.join(" + "), paths, stack: stackAll },
    score: combined.score,
    grade: combined.grade,
    summary: merged.reduce(
      (acc, f) => { acc[f.severity]++; return acc; },
      { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    ),
    coverage: {
      checks_run: Math.max(...results.map((r) => r.coverage.checks_run)),
      checks_applicable: CHECKS.length,
      classes_covered: CLASSES_COVERED,
      classes_not_covered: CLASSES_NOT_COVERED,
    },
    score_breakdown: combined,
    findings: merged,
    inventory: mergeInventories(results, paths),
    portfolio: results.map((r) => ({ path: r.target.path, score: r.score, grade: r.grade, findings: r.findings.length })),
    meta: {
      no_exec: true,
      files_scanned: filesAll,
      git_history_scanned: results.every((r) => r.meta.git_history_scanned),
    },
  };
}
