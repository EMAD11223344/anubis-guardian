#!/usr/bin/env node
/**
 * anubis-callback.mjs — runner-side callback for the Arena Anubis Scan web bridge.
 *
 * Copy this file into the anubis-guardian repo as `scripts/anubis-callback.mjs`
 * and let the scan workflow call: `node scripts/anubis-callback.mjs report.json exit-code.txt`
 *
 * ─── HMAC CONTRACT (single source of truth — mirrored in
 *     backend/src/anubis-scan/anubis-scan.util.ts) ────────────────────────────
 *   message  = "${scanId}|${toolVersion}|${exitCode}|${timestamp}|${sha256hex(bodyJson)}"
 *   bodyJson = the EXACT JSON.stringify of the body object sent below (must be
 *              byte-identical to what the backend re-stringifies from the
 *              parsed request — keep the key order as written here).
 *   headers  = x-anubis-timestamp : ms epoch
 *              x-anubis-signature : v1=<hex hmac-sha256 over message>
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * ┌───────────────────────── STANDING NO-LEAK LEDGER (4 rules) ────────────────┐
 * │ 1. NEVER echo or print target_url, ownership_token, or the nonce — not to  │
 * │    output, not to the step summary, not into annotations.                  │
 * │ 2. Reports never leave the runner except through this HMAC-gated POST;     │
 * │    on callback failure the report dies with the runner (no artifacts).     │
 * │ 3. No artifacts, no check-run annotations, no job summaries are written.   │
 * │ 4. Completion lines name ONLY the opaque nonce_prefix + exit code.         │
 * └────────────────────────────────────────────────────────────────────────────┘
 */

import { createHash, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';

const CALLBACK_URL = process.env.ANUBIS_CALLBACK_URL || '';
const CALLBACK_SECRET = process.env.ANUBIS_CALLBACK_SECRET || '';
const SCAN_ID = process.env.SCAN_ID || '';
const TOOL_VERSION = process.env.EXPECTED_VERSION || '';
const NONCE_PREFIX = process.env.NONCE_PREFIX || '';

function fail(msg) {
  // Allowed vocabulary only — no target/nonce/report content ever.
  console.error(`anubis-callback: ${msg}`);
}

async function main() {
  const [reportPath, exitCodePath] = process.argv.slice(2);
  if (!CALLBACK_URL || !CALLBACK_SECRET || !SCAN_ID) {
    fail('missing ANUBIS_CALLBACK_URL / ANUBIS_CALLBACK_SECRET / SCAN_ID — aborting without draining');
    process.exit(1);
  }

  // Exit code: from file if present (scanner already ran), else parse env fallback.
  let exitCode = Number.parseInt(process.env.SCAN_EXIT_CODE || '', 10);
  if (!Number.isFinite(exitCode)) {
    try {
      exitCode = Number.parseInt(readFileSync(exitCodePath, 'utf8').trim(), 10);
    } catch {
      exitCode = -1;
    }
  }
  if (!Number.isFinite(exitCode)) exitCode = -1;

  // Report: in-memory only — never copied, never logged.
  let report = null;
  if (reportPath) {
    try {
      const parsed = JSON.parse(readFileSync(reportPath, 'utf8'));
      if (parsed && typeof parsed === 'object' && Array.isArray(parsed.findings)) {
        report = parsed;
      }
    } catch {
      report = null; // absent/corrupt report → callback carries the exit code only
    }
  }

  const body = {
    scan_id: SCAN_ID,
    tool_version: TOOL_VERSION,
    exit_code: exitCode,
    report,
  };
  const bodyJson = JSON.stringify(body); // exact string both signed AND sent
  const timestamp = Date.now();
  const sha256hex = createHash('sha256').update(bodyJson, 'utf8').digest('hex');
  const message = `${SCAN_ID}|${TOOL_VERSION}|${exitCode}|${timestamp}|${sha256hex}`;
  const signature = createHmac('sha256', CALLBACK_SECRET).update(message, 'utf8').digest('hex');

  const MAX_ATTEMPTS = 4;
  const RETRY_MS = 5000;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      const res = await fetch(CALLBACK_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-anubis-timestamp': String(timestamp),
          'x-anubis-signature': `v1=${signature}`,
        },
        body: bodyJson,
      });
      if (res.status >= 200 && res.status < 300) {
        const prefix = NONCE_PREFIX ? ` for ${NONCE_PREFIX}` : '';
        console.log(`anubis-callback: report delivered${prefix} (attempt ${attempt}, exit=${exitCode})`);
        return;
      }
      if (res.status === 401) {
        fail('signature rejected — check ANUBIS_CALLBACK_SECRET sync (not retrying auth failures)');
        process.exit(1);
      }
      fail(`HTTP ${res.status} — retrying (${attempt}/${MAX_ATTEMPTS})`);
    } catch (e) {
      fail(`network error — retrying (${attempt}/${MAX_ATTEMPTS})`);
    }
    if (attempt < MAX_ATTEMPTS) await new Promise((r) => setTimeout(r, RETRY_MS));
  }

  // All retries exhausted: report expires with the runner (no-storage contract).
  const prefix2 = NONCE_PREFIX ? ` for ${NONCE_PREFIX}` : '';
  fail(`callback refused after ${MAX_ATTEMPTS} attempts${prefix2}; report expires with runner`);
  process.exit(1);
}

main().catch((e) => {
  fail(`unexpected error — report expires with runner`);
  process.exit(1);
});
