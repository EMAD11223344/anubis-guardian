import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { IncomingMessage } from "node:http";
import {
  USER_AGENT, MAX_BODY_BYTES, type CapturedResponse,
} from "./types.js";
import {
  assertPinnedTarget, assertNextHop, SsrfRefusedError,
  isServiceMode, serviceMaxResponseBytes,
  SERVICE_CONNECT_TIMEOUT_MS, SERVICE_READ_TIMEOUT_MS, SERVICE_MAX_REDIRECTS,
} from "./ssrf-guard.js";

/** Injectable DNS resolver so tests can simulate rebinding (unit-testable contract). */
export interface LookupResult { address: string; family: number }
export type LookupAllFn = (host: string) => Promise<Array<{ address: string; family: number }>>;

interface DialResult {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
  truncatedByPolicy: boolean;
  error?: string;
}

/**
 * Dial ONE validated+pinnd hop. The connection is made to the PINNED IP
 * literal with Host/SNI of the original hostname — node never re-resolves
 * (host option is an IP + explicit lookup hook shut) → no rebinding window.
 */
function dialHop(
  scheme: "http:" | "https:",
  target: { ip: string; family: 4 | 6; port: number; host: string },
  u: URL,
  method: string,
  headers: Record<string, string>,
  timeouts: { connectMs: number; readIdleMs: number | null; overallMs: number | null },
  byteCap: number,
): Promise<DialResult> {
  return new Promise((resolve) => {
    const reqFn = scheme === "https:" ? httpsRequest : httpRequest;
    let settled = false;
    let done: (out: DialResult) => void;
    const finish = (out: DialResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(connectTimer);
      if (idleTimer) clearTimeout(idleTimer);
      if (overallTimer) clearTimeout(overallTimer);
      resolve(out);
    };

    // CLI keeps the old single overall deadline; service mode splits connect/read.
    let overallTimer: NodeJS.Timeout | null = timeouts.overallMs !== null
      ? setTimeout(() => { finishErr("timeout"); try { req.destroy(); } catch { /* gone */ } }, timeouts.overallMs)
      : null;
    const connectTimer = setTimeout(() => {
      finishErr("connect timeout");
      try { req.destroy(); } catch { /* gone */ }
    }, timeouts.connectMs);
    let idleTimer: NodeJS.Timeout | null = null;
    const finishErr = (msg: string): void => {
      if (settled) return;
      finish({ status: 0, headers: {}, body: Buffer.alloc(0), truncatedByPolicy: false, error: msg });
    };
    const resetIdle = (): void => {
      if (timeouts.readIdleMs === null) return;
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(() => { finishErr("read idle timeout"); try { req.destroy(); } catch { /* gone */ } }, timeouts.readIdleMs);
    };

    const lower: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
    if (!lower["user-agent"]) lower["user-agent"] = USER_AGENT;
    lower.host = u.host; // hostname[:port] of the TARGET — not the pinned IP

    const req = reqFn(u, {
      host: target.ip,
      port: target.port,
      method,
      headers: lower,
      // TLS SNI + certificate subject check use the original hostname, not the IP
      servername: scheme === "https:" ? target.host : undefined,
      // belt & braces: host is already a literal IP; outlaw any further resolution
      lookup: (hostnameOpt, o, cb) => {
        void hostnameOpt;
        (cb as unknown as (err: NodeJS.ErrnoException | null, addr: string, fam: number) => void)(null, target.ip, target.family === 6 ? 6 : 4);
      },
      setHost: false,
    }, (res: InstanceType<typeof IncomingMessage>) => {
      clearTimeout(connectTimer);
      resetIdle();
      const headersOut: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.headers)) {
        const value = Array.isArray(v) ? v.join("\n") : v ?? "";
        headersOut[k.toLowerCase()] = typeof value === "string" ? value : String(value);
      }
      const chunks: Buffer[] = [];
      let bytes = 0;
      res.on("data", (c: Buffer) => {
        resetIdle();
        bytes += c.length;
        chunks.push(c);
        if (byteCap > 0 && bytes > byteCap) {
          try { res.destroy(); } catch { /* gone */ }
          finish({ status: res.statusCode ?? 0, headers: headersOut, body: Buffer.concat(chunks), truncatedByPolicy: true });
        }
      });
      res.on("end", () => {
        finish({
          status: res.statusCode ?? 0,
          headers: headersOut,
          body: Buffer.concat(chunks),
          truncatedByPolicy: false,
        });
      });
      res.on("error", (e: Error) => finishErr(e.message));
    });
    req.on("error", (e: Error) => finishErr(e.message));
    req.end();
  });
}

/**
 * Rate-limited capture fetcher (Plan Section 7 consent & safety layer):
 * - single User-Agent identifying the tool
 * - hard request cap + minimum delay between same-host requests
 * - every response is captured verbatim (truncated) so analysis is a pure
 *   function of the bundle — reproducible without the network
 * - http/https only; no cookies jar, no credentials (no credentialed scanning)
 * - v1.1.1: EVERY request (and every redirect hop) passes the SSRF guard:
 *   resolve→pin→connect (one dns.lookup per hop, every address validated,
 *   dialed to the pinned IP, Host/SNI of the hostname), manual redirects
 *   (cap 10), https→http demotion / non-http(s) schemes refused.
 * - service mode (ANUBIS_SERVICE=1): port allowlist, `allowPrivate` ignored,
 *   5 MB response cap (env), 10s connect + 30s read-idle timeouts.
 */
export class Fetcher {
  readonly requests: CapturedResponse[] = [];
  readonly robotsSkipped: string[] = [];
  /** Every guard refusal this Fetcher produced (for report notes / service-mode hard fail). */
  readonly guardRefusals: string[] = [];
  private seq = 0;
  private lastAt = 0;
  readonly delayMs: number;
  private readonly timeoutMs: number;
  readonly maxRequests: number;
  private readonly allowPrivate: boolean;
  private readonly lookup?: LookupAllFn;

  constructor(opts: { delayMs?: number; timeoutMs?: number; maxRequests?: number; allowPrivate?: boolean; lookup?: LookupAllFn } = {}) {
    this.delayMs = opts.delayMs ?? 250;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.maxRequests = opts.maxRequests ?? 40;
    this.allowPrivate = opts.allowPrivate === true;
    this.lookup = opts.lookup;
  }

  get remaining(): number { return this.maxRequests - this.seq; }
  get exhausted(): boolean { return this.seq >= this.maxRequests; }

  /** GET with capture. Returns null when the cap was reached. init.headers allowed (v1.0 active-tests identities — in-flight only). */
  async get(url: string, init?: { headers?: Record<string, string> }): Promise<CapturedResponse | null> {
    return this.send("GET", url, init);
  }

  /** Raw method request (TRACE/OPTIONS probes at L2). */
  async send(method: string, url: string, init?: { body?: string; headers?: Record<string, string> }): Promise<CapturedResponse | null> {
    if (this.exhausted) return null;
    const service = isServiceMode();
    await this.throttle(url);
    this.seq += 1;

    const record = (out: Omit<CapturedResponse, "seq" | "method">): CapturedResponse => {
      const full: CapturedResponse = { seq: this.seq, method, ...out };
      this.requests.push(full);
      return full;
    };
    const recordErr = (finalUrl: string, error: string): CapturedResponse => {
      if (error.startsWith("SSRF-REFUSED")) this.guardRefusals.push(`${this.seq}: ${url} → ${error}`);
      return record({ url, final_url: finalUrl, status: 0, headers: {}, body: "", body_truncated: false, bytes: 0, error });
    };

    let current: URL;
    try { current = new URL(url); }
    catch { return recordErr(url, "malformed URL"); }
    if (current.protocol !== "http:" && current.protocol !== "https:") {
      return recordErr(url, "SSRF-REFUSED: non-http(s) scheme");
    }

    /** Refusal mid-chain: keep the last REAL response as evidence, append the refusal reason. */
    const recordHopRefused = (origUrl: string, baseUrl: string, last: DialResult | null, error: string, fresh = false): CapturedResponse => {
      if (error.startsWith("SSRF-REFUSED")) this.guardRefusals.push(`${this.seq}: ${origUrl} → ${error}`);
      if (fresh || !last) {
        return record({ url: origUrl, final_url: baseUrl, status: 0, headers: {}, body: "", body_truncated: false, bytes: 0, error });
      }
      return record({
        url: origUrl,
        final_url: baseUrl,
        status: last.status,
        headers: last.headers,
        body: new TextDecoder("utf-8", { fatal: false }).decode(last.body.slice(0, MAX_BODY_BYTES)),
        body_truncated: last.truncatedByPolicy || last.body.length > MAX_BODY_BYTES,
        bytes: last.body.length,
        error,
      });
    };

    const follow = method !== "TRACE"; // TRACE must not be auto-forwarded
    const timeouts = service
      ? { connectMs: SERVICE_CONNECT_TIMEOUT_MS, readIdleMs: SERVICE_READ_TIMEOUT_MS, overallMs: null }
      : { connectMs: this.timeoutMs, readIdleMs: null, overallMs: this.timeoutMs };
    const byteCap = service ? serviceMaxResponseBytes() : 0; // 0 = unlimited (CLI keeps old buffering)

    let hops = 0;
    let lastRes: DialResult | null = null;
    for (;;) {
      if (hops > SERVICE_MAX_REDIRECTS) {
        return recordHopRefused(url, current.toString(), lastRes, `SSRF-REFUSED: redirect hop cap (${SERVICE_MAX_REDIRECTS}) exceeded`);
      }
      let pinned;
      try {
        pinned = await assertPinnedTarget(current, { allowPrivate: this.allowPrivate, lookup: this.lookup });
      } catch (e) {
        if (e instanceof SsrfRefusedError) return recordHopRefused(url, current.toString(), lastRes, e.message, hops === 0);
        return recordHopRefused(url, current.toString(), lastRes, `${e instanceof Error ? e.name : "Error"}: ${e instanceof Error ? e.message : String(e)}`, hops === 0);
      }

      const res = await dialHop(current.protocol as "http:" | "https:", pinned, current, method, { "user-agent": USER_AGENT, ...(init?.headers ?? {}) }, timeouts, byteCap);
      if (res.error !== undefined) {
        if (res.error.startsWith("SSRF-REFUSED")) this.guardRefusals.push(`${this.seq}: ${current.toString()} → ${res.error}`);
        return record({ url, final_url: current.toString(), status: 0, headers: {}, body: "", body_truncated: false, bytes: 0, error: res.error });
      }
      lastRes = res;

      const isRedirect = res.status === 301 || res.status === 302 || res.status === 303 || res.status === 307 || res.status === 308;
      if (follow && isRedirect && res.headers.location) {
        hops += 1;
        let nextUrlStr: string;
        try { nextUrlStr = assertNextHop(current, res.headers.location); }
        catch (e) {
          if (e instanceof SsrfRefusedError) {
            // refusal mid-chain: keep the last real response as evidence + append the reason
            return recordHopRefused(url, current.toString(), lastRes, e.message);
          }
          throw e; // unreachable — assertNextHop throws SsrfRefusedError only
        }
        current = new URL(nextUrlStr); // absolute by construction
        continue; // full fresh guard: DNS + IP + port + scheme
      }
      // final response
      const bytes = res.body.length;
      const text = new TextDecoder("utf-8", { fatal: false }).decode(res.body.slice(0, MAX_BODY_BYTES));
      return record({
        url,
        final_url: current.toString(),
        status: res.status,
        headers: res.headers,
        body: text,
        body_truncated: res.truncatedByPolicy || bytes > MAX_BODY_BYTES,
        bytes,
      });
    }
  }

  /** Robots-aware skip (Plan: "All levels respect robots.txt"): record, don't request. */
  skipForRobots(path: string): void {
    this.robotsSkipped.push(path);
  }

  private async throttle(host: string): Promise<void> {
    const now = Date.now();
    const wait = this.lastAt + this.delayMs - now;
    if (wait > 0 && this.seq > 0) await new Promise((r) => setTimeout(r, wait));
    this.lastAt = Date.now();
    void host;
  }
}
