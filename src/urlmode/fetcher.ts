import { USER_AGENT, MAX_BODY_BYTES, type CapturedResponse } from "./types.js";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

/**
 * Rate-limited capture fetcher (Plan Section 7 consent & safety layer):
 * - single User-Agent identifying the tool
 * - hard request cap + minimum delay between same-host requests
 * - every response is captured verbatim (truncated) so analysis is a pure
 *   function of the bundle — reproducible without the network
 * - http/https only; no cookies jar, no credentials (no credentialed scanning)
 * - TRACE (forbidden by the fetch spec) goes through node:http raw — same capture shape
 */
export class Fetcher {
  readonly requests: CapturedResponse[] = [];
  readonly robotsSkipped: string[] = [];
  private seq = 0;
  private lastAt = 0;
  readonly delayMs: number;
  private readonly timeoutMs: number;
  readonly maxRequests: number;

  constructor(opts: { delayMs?: number; timeoutMs?: number; maxRequests?: number } = {}) {
    this.delayMs = opts.delayMs ?? 250;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.maxRequests = opts.maxRequests ?? 40;
  }

  get remaining(): number {
    return this.maxRequests - this.seq;
  }

  get exhausted(): boolean {
    return this.seq >= this.maxRequests;
  }

  /** GET with capture. Returns null when the cap was reached. init.headers allowed (v1.0 active-tests identities — in-flight only). */
  async get(url: string, init?: { headers?: Record<string, string> }): Promise<CapturedResponse | null> {
    return this.send("GET", url, init);
  }

  /** Raw method request (TRACE/OPTIONS probes at L2). TRACE uses node:http (fetch spec forbids it). */
  async send(method: string, url: string, init?: { body?: string; headers?: Record<string, string> }): Promise<CapturedResponse | null> {
    if (this.exhausted) return null;
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    if (method === "TRACE") {
      this.seq += 1;
      await this.throttle(u.host);
      const out = await this.rawSend(url);
      if (out) this.requests.push(out);
      return out;
    }
    await this.throttle(u.host);
    this.seq += 1;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await fetch(u, {
        method,
        redirect: "follow",
        signal: ctrl.signal,
        headers: { "user-agent": USER_AGENT, ...(init?.headers ?? {}) },
        body: init?.body,
      });
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        headers[k.toLowerCase()] = k.toLowerCase() === "set-cookie" && headers[k.toLowerCase()]
          ? `${headers[k.toLowerCase()]}\n${v}`
          : v;
      });
      const buf = await res.arrayBuffer();
      const bytes = buf.byteLength;
      const text = new TextDecoder("utf-8", { fatal: false }).decode(buf.slice(0, MAX_BODY_BYTES));
      const out: CapturedResponse = {
        seq: this.seq,
        method,
        url,
        final_url: res.url || url,
        status: res.status,
        headers,
        body: text,
        body_truncated: bytes > MAX_BODY_BYTES,
        bytes,
      };
      this.requests.push(out);
      return out;
    } catch (e) {
      const out: CapturedResponse = {
        seq: this.seq,
        method,
        url,
        final_url: url,
        status: 0,
        headers: {},
        body: "",
        body_truncated: false,
        bytes: 0,
        error: e instanceof Error ? `${e.name}: ${e.message}` : String(e),
      };
      this.requests.push(out);
      return out;
    } finally {
      clearTimeout(timer);
    }
  }

  /** node:http path for methods the fetch spec forbids (TRACE). Captures identically. */
  private rawSend(url: string): Promise<CapturedResponse | null> {
    const u = new URL(url);
    return new Promise((resolve) => {
      const reqFn = u.protocol === "https:" ? httpsRequest : httpRequest;
      let settled = false;
      const finish = (out: CapturedResponse) => { if (!settled) { settled = true; resolve(out); } };
      const timer = setTimeout(() => {
        finish({ seq: this.seq, method: "TRACE", url, final_url: url, status: 0, headers: {}, body: "", body_truncated: false, bytes: 0, error: "timeout" });
        try { req.destroy(); } catch { /* already gone */ }
      }, this.timeoutMs);
      const req = reqFn(u, { method: "TRACE", headers: { "user-agent": USER_AGENT }, timeout: this.timeoutMs }, (res) => {
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          headers[k.toLowerCase()] = Array.isArray(v) ? v.join("\n") : (v ?? "");
        }
        const chunks: Buffer[] = [];
        let bytes = 0;
        res.on("data", (c: Buffer) => { bytes += c.length; if (bytes <= MAX_BODY_BYTES) chunks.push(c); });
        res.on("end", () => {
          clearTimeout(timer);
          finish({
            seq: this.seq,
            method: "TRACE",
            url,
            final_url: url,
            status: res.statusCode ?? 0,
            headers,
            body: Buffer.concat(chunks).toString("utf8"),
            body_truncated: bytes > MAX_BODY_BYTES,
            bytes,
          });
        });
      });
      req.on("error", (e) => {
        clearTimeout(timer);
        finish({ seq: this.seq, method: "TRACE", url, final_url: url, status: 0, headers: {}, body: "", body_truncated: false, bytes: 0, error: e.message });
      });
      req.end();
    });
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
