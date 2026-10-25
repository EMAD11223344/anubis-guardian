#!/usr/bin/env node
import { Command } from "commander";
import { resolve } from "node:path";
import { writeFileSync, mkdirSync, existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, basename } from "node:path";
import { scan, scanRoots, VERSION, mergeAiFindings } from "./engine.js";
import { walk } from "./walk.js";
import { recon } from "./recon.js";
import { buildInventory } from "./inventory.js";
import type { ScanContext } from "./types.js";
import { runAiReview, AiConfigError } from "./ai/review.js";
import { buildAuthzMatrix, writeQuarantine } from "./authz.js";
import { installHook, SNIPPET } from "./inithook.js";
import { renderTerminal, renderMarkdown, DISCLAIMER } from "./report/render.js";
import { renderSarif } from "./report/sarif.js";
import { renderFixPrompt } from "./report/fixprompt.js";
import { renderCompact } from "./report/compact.js";
import { renderHtml } from "./report/html.js";
import { updateAdvisories } from "./adapters.js";
import { generateWorkflow } from "./initci.js";
import { captureUrl, analyzeBundle, fromCapture, resolveOwnership, GateError } from "./urlmode/analyze.js";
import { isLocalOrPrivate, generateNonce, instructions } from "./urlmode/ownership.js";
import type { OwnershipResult } from "./urlmode/types.js";
import type { ScanResult } from "./types.js";

const program = new Command();

program
  .name("anubis-guardian")
  .description("Deterministic security auditor for AI-built projects — Codebase Mode (offline, static-only)")
  .version(VERSION);

type Opts = {
  format: string;
  output?: string;
  failOn?: string;
  failOnCve?: boolean;
  schema?: string;
  sarif?: string;
  fixPrompt?: string;
  compact?: string;
  html?: string;
  inventory?: string;
  workspaces?: boolean;
  rulesDir?: string;
  tools?: string;
  online?: boolean;
  advisories?: string;
  aiReview?: boolean;
  quarantine?: string;
};

program
  .command("scan")
  .description("Scan one or more project roots (multi-root cross-linking: scan ./frontend ./backend)")
  .argument("<paths...>", "project directory (or several roots — v0.2 links findings across them)")
  .option("-f, --format <format>", "output format: terminal | json | md | sarif | html | compact | all", "terminal")
  .option("-o, --output <file>", "write output to file instead of stdout")
  .option("--fail-on <severity>", "exit 1 when findings at/above this severity exist: high | critical")
  .option("--fail-on-cve", "exit 1 when dependency CVE findings (DEP-001) exist")
  .option("--schema <file>", "path to a user-run schema export (e.g. `supabase db dump --schema public`) for dashboard-drift check")
  .option("--sarif <file>", "also write SARIF 2.1.0 report (GitHub Security tab)")
  .option("--fix-prompt <file>", "also write fix-prompt.md (deterministic fixing prompt — Output Contract)")
  .option("--compact <file>", "also write a token-saving compact summary for agents")
  .option("--html <file>", "also write a self-contained HTML report")
  .option("--inventory <file>", "also write inventory.json (routes/controllers/tables/socket events/webhooks)")
  .option("--workspaces", "monorepo mode: treat the root as a workspace portfolio (per-app scan + combined report)")
  .option("--rules-dir <dir>", "load custom org rules (JSON DSL — Plan Section 4 organizational deployment)")
  .option("--tools <list>", "comma list of external adapters to merge if installed: gitleaks,osv-scanner,semgrep (default: none — deterministic built-in only)")
  .option("--online", "enable registry metadata checks for slopsquat detection (DEP-005) — non-deterministic, flagged in meta")
  .option("--advisories <file>", "use a local advisory snapshot (from --update-advisories) instead of the bundled one")
  .option("--ai-review", "v0.3: enable the optional AI review layer (needs ANUBIS_AI_API_KEY; redaction-before-LLM + independent verifier; flagged in meta.ai_used)")
  .option("--quarantine <dir>", "v0.3: write generated canary tests for taint findings into this folder (the tool never executes them)")
  .action(async (paths: string[], opts: Opts) => {
    const failOn = (opts.failOn ?? "").toLowerCase();
    if (failOn && failOn !== "high" && failOn !== "critical") {
      console.error("--fail-on accepts: high | critical");
      process.exit(2);
    }

    // ---- workspace expansion ----
    let roots = paths.map((p) => resolve(p));
    if (opts.workspaces) {
      if (paths.length !== 1) {
        console.error("--workspaces takes a single root directory");
        process.exit(2);
      }
      roots = expandWorkspaces(roots[0]);
    }

    let result;
    try {
      result = roots.length === 1 ? scan(roots[0], { schemaDump: opts.schema, rulesDir: opts.rulesDir, tools: parseTools(opts.tools), online: opts.online, advisoryFile: opts.advisories })
                                  : scanRoots(roots, { schemaDump: opts.schema, rulesDir: opts.rulesDir, tools: parseTools(opts.tools), online: opts.online, advisoryFile: opts.advisories });
    } catch (e) {
      console.error(`scan failed: ${e instanceof Error ? e.message : String(e)}`);
      process.exit(2);
    }

    // ---- v0.3 AI review layer (opt-in; verifier-gated; flagged in meta) ----
    if (opts.aiReview) {
      try {
        const ai = await runAiReview(result, roots);
        result = mergeAiFindings(result, ai.findings);
        result.ai_review = ai.meta;
        result.meta.ai_used = true;
      } catch (e) {
        if (e instanceof AiConfigError) {
          console.error(`ai-review: ${e.message}`);
          process.exit(2);
        }
        console.error(`ai-review failed: ${e instanceof Error ? e.message : String(e)} — continuing with deterministic findings only`);
        process.exit(2);
      }
    }

    // ---- v0.3 quarantine: generated tests for taint findings (owner executes, never the tool) ----
    if (opts.quarantine) {
      const taint = result.findings.filter((f) => f.id.startsWith("TAINT-"));
      const files = writeQuarantine(opts.quarantine, {
        matrix: buildAuthzMatrix(result.inventory ?? { routes: [], controllers: [], supabase: { tables: [], rpcs: [], edge_functions: [] }, socket_events: [], webhooks: [] }),
        taintFindings: taint,
        source: result.target.path,
      });
      console.error(`quarantine: ${files.length} file(s) written to ${opts.quarantine} — the tool does NOT execute them; review and run yourself`);
    }

    // ---- auxiliary artifacts (deterministic renderers over the same findings.json) ----
    if (opts.sarif) writeArtifact(opts.sarif, renderSarif(result));
    if (opts.fixPrompt) writeArtifact(opts.fixPrompt, renderFixPrompt(result));
    if (opts.compact) writeArtifact(opts.compact, renderCompact(result));
    if (opts.html) writeArtifact(opts.html, renderHtml(result));
    if (opts.inventory && result.inventory) writeArtifact(opts.inventory, JSON.stringify(result.inventory, null, 2));

    const outputs: string[] = [];
    if (opts.format === "terminal" || opts.format === "all") outputs.push(renderTerminal(result));
    if (opts.format === "md") outputs.push(renderMarkdown(result));
    if (opts.format === "sarif") outputs.push(renderSarif(result));
    if (opts.format === "html") outputs.push(renderHtml(result));
    if (opts.format === "compact") outputs.push(renderCompact(result));
    if (opts.format === "json" || opts.format === "all") outputs.push(JSON.stringify(result, null, 2));

    const text = outputs.join("\n");
    if (opts.output) {
      writeArtifact(opts.output, text);
    } else {
      console.log(text);
    }

    // ---- CI gates ----
    let breach = false;
    if (failOn) {
      const threshold = failOn === "critical" ? 0 : 1;
      const order = ["critical", "high", "medium", "low", "info"];
      breach = result.findings.some((f) => f.suppression === null && order.indexOf(f.severity) <= threshold);
    }
    if (opts.failOnCve) {
      breach = breach || result.findings.some((f) => f.id === "DEP-001" && f.suppression === null);
    }
    if (breach) {
      const gates = [failOn && `--fail-on ${failOn}`, opts.failOnCve && "--fail-on-cve"].filter(Boolean).join(" + ");
      console.error(`\ngate: ${gates} — failing (see findings above). ${DISCLAIMER}`);
      process.exit(1);
    }
    process.exit(0);
  });

program
  .command("scan-url")
  .description("v0.4 Mode 2: scan a live deployed site by URL — L1 passive (browser-equivalent, free) · L2 discovery (verified ownership for public domains) · L3 = L2 + Supabase live anon probe (GET-only, verified ownership)")
  .argument("<url>", "target URL (http/https)")
  .option("-l, --level <1|2|3>", "scan level: 1 passive (default) · 2 discovery (ownership-gated) · 3 = 2 + Supabase anon probe (verified ownership only)", "1")
  .option("--ownership-token <nonce>", "verify a nonce you published (DNS TXT anubis-guardian-challenge=… or /.well-known/anubis-guardian/<nonce>)")
  .option("--i-own-this-domain", "self-attestation — honored ONLY for localhost/127.0.0.1/*.local/private staging (labeled in the report; never enough for L3)")
  .option("--from-capture <file>", "re-analyze a saved capture bundle (--capture) — zero network, byte-identical")
  .option("--capture <file>", "save the raw capture bundle (evidence + reproducibility)")
  .option("--timeout-ms <n>", "per-request timeout", "10000")
  .option("--delay-ms <n>", "minimum delay between same-host requests (rate limit)", "250")
  .option("--max-requests <n>", "hard request cap (default per level: 40/120/150)")
  .option("--max-assets <n>", "max public JS bundles fetched at L1", "10")
  .option("-f, --format <format>", "output format: terminal | json | md | sarif | html | compact | all", "terminal")
  .option("-o, --output <file>", "write output to file instead of stdout")
  .option("--fail-on <severity>", "exit 1 when findings at/above this severity exist: high | critical")
  .option("--sarif <file>", "also write SARIF 2.1.0 report")
  .option("--fix-prompt <file>", "also write fix-prompt.md (includes the map-endpoints-to-code instruction)")
  .option("--compact <file>", "also write a token-saving compact summary")
  .option("--html <file>", "also write a self-contained HTML report")
  .action(async (url: string, opts: Opts & { level: string; ownershipToken?: string; iOwnThisDomain?: boolean; fromCapture?: string; capture?: string; timeoutMs: string; delayMs: string; maxRequests?: string; maxAssets: string }) => {
    const level = Number(opts.level) as 1 | 2 | 3;
    if (![1, 2, 3].includes(level)) {
      console.error("--level accepts 1 | 2 | 3");
      process.exit(2);
    }

    // ---- from-capture path: deterministic re-analysis, zero network ----
    if (opts.fromCapture) {
      let result;
      try {
        result = fromCapture(readFileSync(opts.fromCapture, "utf8"));
      } catch (e) {
        console.error(`from-capture failed: ${e instanceof Error ? e.message : String(e)}`);
        process.exit(2);
      }
      emitUrlResult(result, opts, level);
      return;
    }

    // ---- live path: legal gate FIRST (nothing is requested before it passes) ----
    try {
      // dry-run gate for the consent banner + early refusal (throws GateError before any request)
      const host = new URL(url).hostname;
      const isLocal = isLocalOrPrivate(host);
      if (level >= 2 && !opts.ownershipToken && !(opts.iOwnThisDomain && isLocal)) {
        // let resolveOwnership produce the exact refusal + instructions
        await resolveOwnership(url, { level, ownershipToken: opts.ownershipToken, selfAttest: opts.iOwnThisDomain });
      }
    } catch (e) {
      if (e instanceof GateError) {
        console.error(`\nGate: ${e.message}`);
        if (e.help) console.error(`\n${e.help}\n`);
        process.exit(2);
      }
      console.error(`scan-url: invalid target — ${e instanceof Error ? e.message : String(e)}`);
      process.exit(2);
    }

    const ownership = await resolveOwnership(url, { level, ownershipToken: opts.ownershipToken, selfAttest: opts.iOwnThisDomain });
    printConsentBanner(url, level, ownership, Number(opts.delayMs));

    let bundle;
    try {
      bundle = await captureUrl(url, {
        level,
        ownershipToken: opts.ownershipToken,
        selfAttest: opts.iOwnThisDomain,
        timeoutMs: Number(opts.timeoutMs),
        delayMs: Number(opts.delayMs),
        maxRequests: opts.maxRequests ? Number(opts.maxRequests) : undefined,
        maxAssets: Number(opts.maxAssets),
      }, ownership);
    } catch (e) {
      console.error(`scan-url failed: ${e instanceof Error ? e.message : String(e)}`);
      process.exit(2);
    }

    if (opts.capture) writeArtifact(opts.capture, JSON.stringify(bundle, null, 2));
    const result = analyzeBundle(bundle);
    emitUrlResult(result, opts, level);
  });

program
  .command("ownership")
  .description("v0.4: generate a domain-ownership nonce + instructions (DNS TXT / .well-known) — or verify a published one with --check")
  .argument("<url>", "target origin (scheme://host[:port])")
  .option("--check <nonce>", "verify a nonce you have already published")
  .action(async (url: string, opts: { check?: string }) => {
    let u: URL;
    try { u = new URL(url); } catch {
      console.error("ownership: pass a full origin, e.g. https://example.com");
      process.exit(2);
    }
    const nonce = opts.check ?? generateNonce();
    if (opts.check) {
      try {
        const res = await resolveOwnership(u.origin, { level: 2, ownershipToken: nonce });
        console.error(res.verified
          ? `VERIFIED via ${res.method} — Level 2 is unlocked for ${u.host}. Re-run scan-url with --ownership-token ${nonce} --level 2 (or 3).`
          : `NOT verified — the nonce was not found (DNS TXT or /.well-known). Level 2 stays locked.`);
        process.exit(res.verified ? 0 : 1);
      } catch (e) {
        if (e instanceof GateError) {
          console.error(`NOT verified — ${e.message}`);
          process.exit(1);
        }
        throw e;
      }
    }
    console.error(`\n${instructions(u.hostname, nonce)}\n`);
    console.error(`(This nonce is generated fresh each run — publish it, then verify with: anubis-guardian ownership ${u.origin} --check ${nonce})`);
    process.exit(0);
  });

program
  .command("init-ci")
  .description("Generate a least-privilege GitHub Actions workflow: scan + SARIF to Security tab + --fail-on critical gate")
  .option("--dir <dir>", "project root (default: current directory)", ".")
  .option("--package-manager <pm>", "npm | pnpm | yarn", "npm")
  .action((opts: { dir: string; packageManager: string }) => {
    const { file, created } = generateWorkflow(resolve(opts.dir), { packageManager: opts.packageManager });
    console.error(created ? `created: ${file}` : `exists: ${file} (left untouched)`);
    console.error("The workflow runs the scan on every PR/push, blocks PRs with CRITICAL findings, and uploads SARIF to the Security tab.");
    process.exit(created ? 0 : 0);
  });

program
  .command("test-authz")
  .description("v0.3 (experimental): build the authorization matrix from the recon inventory and generate failing-by-expectation Supertest/Playwright tests into a quarantine folder — the tool NEVER executes them")
  .argument("<path>", "project directory previously scanned (inventory is rebuilt from it)")
  .option("--quarantine <dir>", "quarantine output directory", "anubis-quarantine")
  .option("--base-url <url>", "staging base URL baked into the generated tests as a comment default")
  .option("--fail-on-risk", "exit 1 when unguarded mutating endpoints exist (CI-usable without executing tests)")
  .action((path: string, opts: { quarantine: string; baseUrl?: string; failOnRisk?: boolean }) => {
    const root = resolve(path);
    const files = walk(root);
    const stack = recon(root, files);
    const ctx: ScanContext = { rootDir: root, rel: (a: string) => a, files, stack, gitAvailable: false, trackedFiles: new Set(), label: basename(root) };
    const inv = buildInventory(ctx);
    const matrix = buildAuthzMatrix(inv);
    const written = writeQuarantine(resolve(opts.quarantine), { matrix, taintFindings: [], baseUrl: opts.baseUrl, source: root });
    const risky = matrix.filter((r) => r.authz_risk);
    console.error(`authz matrix: ${matrix.length} endpoints — ${risky.length} unguarded mutating (⚠️ verify)`);
    console.error(`quarantine: ${written.length} file(s) in ${opts.quarantine} — the tool does NOT execute them; review + run yourself`);
    if (opts.failOnRisk && risky.length) process.exit(1);
    process.exit(0);
  });

program
  .command("init-hook")
  .description("v0.3: install the pinned agent guard hook (PreToolUse) — blocks service_role-in-client, RLS-killing SQL, secrets into .env, NEXT_PUBLIC secrets at write time")
  .option("--dir <dir>", "project root (default: current directory)", ".")
  .option("--force", "overwrite an existing hook script even if the version matches")
  .action((opts: { dir: string; force?: boolean }) => {
    const r = installHook(resolve(opts.dir), opts.force);
    console.error(`${r.created ? "created" : "exists (pinned v-same)"}: ${r.scriptPath}`);
    console.error(`wired: ${r.settingsPath} (PreToolUse — idempotent, other settings preserved)`);
    console.error(`\nAdd to AGENTS.md / CLAUDE.md:\n${SNIPPET}\n`);
    process.exit(0);
  });

program
  .command("update-advisories")
  .description("Refresh a local HIGH/CRITICAL advisory snapshot from OSV.dev for this project's dependencies (writes ./anubis-advisories.json)")
  .option("--dir <dir>", "project root (default: current directory)", ".")
  .option("--out <file>", "output snapshot file", "anubis-advisories.json")
  .action((opts: { dir: string; out: string }) => {
    const count = updateAdvisories(resolve(opts.dir), opts.out);
    console.error(`written: ${opts.out} — ${count} HIGH/CRITICAL advisories`);
    console.error(`Re-run the scan with --advisories ${opts.out} to use it (bundled snapshot stays the deterministic default).`);
    process.exit(0);
  });

program.parseAsync(process.argv).catch((e) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(2);
});

// ---- helpers ----

function writeArtifact(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, "utf8");
  console.error(`written: ${path}`);
}

function parseTools(list?: string): string[] | undefined {
  if (!list) return undefined;
  const tools = list.split(",").map((t) => t.trim()).filter(Boolean);
  return tools.length ? tools : undefined;
}

/** v0.4 — shared output tail for scan-url (artifacts + formats + CI gate + exit codes). */
function emitUrlResult(
  result: ScanResult,
  opts: { format: string; output?: string; failOn?: string; sarif?: string; fixPrompt?: string; compact?: string; html?: string },
  _level: number
): void {
  if (opts.sarif) writeArtifact(opts.sarif, renderSarif(result));
  if (opts.fixPrompt) writeArtifact(opts.fixPrompt, renderFixPrompt(result));
  if (opts.compact) writeArtifact(opts.compact, renderCompact(result));
  if (opts.html) writeArtifact(opts.html, renderHtml(result));

  const outputs: string[] = [];
  if (opts.format === "terminal" || opts.format === "all") outputs.push(renderTerminal(result));
  if (opts.format === "md") outputs.push(renderMarkdown(result));
  if (opts.format === "sarif") outputs.push(renderSarif(result));
  if (opts.format === "html") outputs.push(renderHtml(result));
  if (opts.format === "compact") outputs.push(renderCompact(result));
  if (opts.format === "json" || opts.format === "all") outputs.push(JSON.stringify(result, null, 2));

  const text = outputs.join("\n");
  if (opts.output) writeArtifact(opts.output, text);
  else console.log(text);

  const failOn = (opts.failOn ?? "").toLowerCase();
  if (failOn && failOn !== "high" && failOn !== "critical") {
    console.error("--fail-on accepts: high | critical");
    process.exit(2);
  }
  if (failOn) {
    const threshold = failOn === "critical" ? 0 : 1;
    const order = ["critical", "high", "medium", "low", "info"];
    const breach = result.findings.some((f) => f.suppression === null && order.indexOf(f.severity) <= threshold);
    if (breach) {
      console.error(`\ngate: --fail-on ${failOn} — failing (see findings above). ${DISCLAIMER}`);
      process.exit(1);
    }
  }
  process.exit(0);
}

/** v0.4 — consent banner (Plan Section 7): what will be requested, at what pace, under what authority. */
function printConsentBanner(url: string, level: number, ownership: OwnershipResult, delayMs: number): void {
  const nature = level === 1
    ? "L1 passive — browser-equivalent requests only (page, robots.txt, sitemap.xml, security.txt, the public JS assets the page loads). NO probing."
    : level === 2
      ? "L2 discovery — probing requests to curated sensitive paths, method checks and doc surfaces. Ownership-gated."
      : "L3 — L2 + Supabase live anon probe (read-only GET, limit=1). Verified ownership enforced.";
  console.error(`\nAnubis Guardian URL Mode — consent & safety`);
  console.error(`  target:    ${url}`);
  console.error(`  level:     ${level} — ${nature}`);
  console.error(`  ownership: ${ownership.verified ? `verified via ${ownership.method}` : ownership.method === "none" ? "none (Level 1 needs none)" : ownership.method}`);
  console.error(`  pace:      hard rate-limit ${delayMs}ms between requests · per-level request cap · no credentialed scanning · no DoS patterns`);
  console.error(`  record:    an authorization record (URL, timestamp, level, ownership) is written into the report`);
  console.error(`  legal:     scanning systems you do not own/operate without written permission is illegal in most jurisdictions (incl. Egyptian law 175/2018).\n`);
}

/** v1.4 organizational deployment: package.json workspaces / pnpm-workspace.yaml → app roots. */
function expandWorkspaces(root: string): string[] {
  const out: string[] = [];
  const pkgPath = resolve(root, "package.json");
  const pnpmPath = resolve(root, "pnpm-workspace.yaml");

  if (existsSync(pnpmPath)) {
    const yaml = readFileSync(pnpmPath, "utf8");
    for (const m of yaml.matchAll(/-\s*['"]?([^'"\n*]+\/\*|[^'"\n*]+)['"]?/g)) {
      out.push(...globWorkspaces(root, m[1].trim()));
    }
  } else if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
      for (const w of pkg.workspaces ?? []) out.push(...globWorkspaces(root, typeof w === "string" ? w : String(w)));
    } catch {
      console.error("--workspaces: package.json is not valid JSON");
      process.exit(2);
    }
  }

  const unique = [...new Set(out)].sort();
  if (!unique.length) {
    console.error(`--workspaces: no workspace packages found under ${root}`);
    process.exit(2);
  }
  return unique;
}

/** tiny glob subset for workspaces: "apps/*", "packages/*", exact paths */
function globWorkspaces(root: string, pattern: string): string[] {
  const out: string[] = [];
  const visit = (base: string, pat: string) => {
    const [head, ...rest] = pat.split("/");
    if (!head) return;
    if (head === "*") {
      let entries: string[] = [];
      try { entries = readdirSync(base); } catch { return; }
      for (const e of entries) {
        const p = join(base, e);
        try { if (!statSync(p).isDirectory()) continue; } catch { continue; }
        if (rest.length === 0) {
          if (existsSync(join(p, "package.json"))) out.push(resolve(p));
        } else visit(p, rest.join("/"));
      }
    } else {
      const p = join(base, head);
      if (!existsSync(p)) return;
      if (rest.length === 0) {
        if (existsSync(join(p, "package.json"))) out.push(resolve(p));
      } else visit(p, rest.join("/"));
    }
  };
  visit(root, pattern);
  return out;
}
