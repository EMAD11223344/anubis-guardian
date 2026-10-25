import { USER_AGENT, MAX_BODY_BYTES } from "./types.js";
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
    requests = [];
    robotsSkipped = [];
    seq = 0;
    lastAt = 0;
    delayMs;
    timeoutMs;
    maxRequests;
    constructor(opts = {}) {
        this.delayMs = opts.delayMs ?? 250;
        this.timeoutMs = opts.timeoutMs ?? 10_000;
        this.maxRequests = opts.maxRequests ?? 40;
    }
    get remaining() {
        return this.maxRequests - this.seq;
    }
    get exhausted() {
        return this.seq >= this.maxRequests;
    }
    /** GET with capture. Returns null when the cap was reached. */
    async get(url) {
        return this.send("GET", url);
    }
    /** Raw method request (TRACE/OPTIONS probes at L2). TRACE uses node:http (fetch spec forbids it). */
    async send(method, url, init) {
        if (this.exhausted)
            return null;
        const u = new URL(url);
        if (u.protocol !== "http:" && u.protocol !== "https:")
            return null;
        if (method === "TRACE") {
            this.seq += 1;
            await this.throttle(u.host);
            const out = await this.rawSend(url);
            if (out)
                this.requests.push(out);
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
            const headers = {};
            res.headers.forEach((v, k) => {
                headers[k.toLowerCase()] = k.toLowerCase() === "set-cookie" && headers[k.toLowerCase()]
                    ? `${headers[k.toLowerCase()]}\n${v}`
                    : v;
            });
            const buf = await res.arrayBuffer();
            const bytes = buf.byteLength;
            const text = new TextDecoder("utf-8", { fatal: false }).decode(buf.slice(0, MAX_BODY_BYTES));
            const out = {
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
        }
        catch (e) {
            const out = {
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
        }
        finally {
            clearTimeout(timer);
        }
    }
    /** node:http path for methods the fetch spec forbids (TRACE). Captures identically. */
    rawSend(url) {
        const u = new URL(url);
        return new Promise((resolve) => {
            const reqFn = u.protocol === "https:" ? httpsRequest : httpRequest;
            let settled = false;
            const finish = (out) => { if (!settled) {
                settled = true;
                resolve(out);
            } };
            const timer = setTimeout(() => {
                finish({ seq: this.seq, method: "TRACE", url, final_url: url, status: 0, headers: {}, body: "", body_truncated: false, bytes: 0, error: "timeout" });
                try {
                    req.destroy();
                }
                catch { /* already gone */ }
            }, this.timeoutMs);
            const req = reqFn(u, { method: "TRACE", headers: { "user-agent": USER_AGENT }, timeout: this.timeoutMs }, (res) => {
                const headers = {};
                for (const [k, v] of Object.entries(res.headers)) {
                    headers[k.toLowerCase()] = Array.isArray(v) ? v.join("\n") : (v ?? "");
                }
                const chunks = [];
                let bytes = 0;
                res.on("data", (c) => { bytes += c.length; if (bytes <= MAX_BODY_BYTES)
                    chunks.push(c); });
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
    skipForRobots(path) {
        this.robotsSkipped.push(path);
    }
    async throttle(host) {
        const now = Date.now();
        const wait = this.lastAt + this.delayMs - now;
        if (wait > 0 && this.seq > 0)
            await new Promise((r) => setTimeout(r, wait));
        this.lastAt = Date.now();
        void host;
    }
}
