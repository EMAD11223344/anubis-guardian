/**
 * SSRF guard for URL Mode (v1.1.1 hardening).
 *
 * Why: URL Mode must be safe to run in CI and on shared hosts. Before this
 * module the Fetcher dialed whatever the URL said — including RFC1918 /
 * loopback / link-local / cloud-metadata ranges — and followed redirects
 * blind (fetch `redirect: "follow"`), with the only "guard" being a
 * hostname-STRING check in ownership.ts (used for labeling, not blocking).
 *
 * Defense contract:
 *  1. addresses are canonicalized to BINARY form before range checks —
 *     WHATWG URL parsing normalizes host literals first (0x7f.0.0.1,
 *     2130706433, ::ffff:7f00:1 all arrive as canonical text), then
 *     node:net's IP.parse (Node ≥ 22.9 — used when available, manual parser
 *     as authoritative fallback) produces the bytes every range test runs
 *     on. No string prefix hacks; unknown shapes are refused.
 *  2. resolve→pin→connect: ONE dns.lookup(all:true) per hop, EVERY returned
 *     address validated, connection dialed to the PINNED IP with Host/SNI of
 *     the original hostname → DNS rebinding is closed by construction.
 *  3. redirects are followed manually; every hop re-runs the full guard;
 *     scheme demotion (https→http) and non-http(s) schemes are refused.
 *  4. SERVICE mode (env ANUBIS_SERVICE=1): port allowlist 80/443/8080/8443,
 *     `--allow-private` is IGNORED, private/loopback/link-local is refused —
 *     a hosted deployment must never become SSRF into its own network.
 *     CLI mode keeps the operator's full choice (opt-in --allow-private),
 *     EXCEPT cloud metadata endpoints (169.254.169.254 et al.) which are
 *     never dialable in any mode.
 */

import { lookup } from "node:dns/promises";
import { createRequire } from "node:module";

const require_ = createRequire(import.meta.url);

/** Feature-detected use of node:net IP.parse as an extra canonicalizer. */
function netIpParse(text: string): string | null {
  try {
    const net = require_("node:net") as { IP?: { parse(s: string): unknown } };
    if (net.IP && typeof net.IP.parse === "function") {
      try {
        const parsed = net.IP.parse(text) as unknown as { toString(): string };
        const s = parsed.toString();
        return typeof s === "string" && s.length > 0 ? s : null;
      } catch { return null; }
    }
  } catch { /* unreachable — node:net always loads */ }
  return null;
}

export interface IpBinary { v: 4 | 6; bytes: Uint8Array }

/**
 * Parse any canonical IPv4/IPv6 textual address to binary bytes.
 * IPv6 handles `::` compression and embedded IPv4 (::ffff:x.y.z.w,
 * x:y:…:w.z.z.w). Returns null for anything unparseable (unknown shapes
 * are REFUSED by callers — safe direction).
 */
export function parseIp(text: string): IpBinary | null {
  const t = text.replace(/^\[|\]$/g, "").replace(/%.*$/, ""); // strip brackets + zone index
  const viaNet = netIpParse(t);
  const s = viaNet ?? t;

  // ---- IPv4 dotted ----
  if (/^(\d{1,3})(\.\d{1,3}){3}$/.test(s)) {
    const parts = s.split(".");
    const out = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
      const n = Number(parts[i]);
      if (!Number.isInteger(n) || n < 0 || n > 255) return null;
      out[i] = n;
    }
    return { v: 4, bytes: out };
  }

  // ---- IPv6 ----
  if (!/^[0-9A-Fa-f:.]+$/.test(s) || !s.includes(":")) return null;
  const groups = (part: string): number[] | null => {
    if (part === "") return [];
    const pieces = part.split(":");
    const out: number[] = [];
    for (let i = 0; i < pieces.length; i++) {
      const piece = pieces[i];
      if (/^(\d{1,3})(\.\d{1,3}){3}$/.test(piece)) {
        // embedded IPv4 — must be the LAST group
        if (i !== pieces.length - 1) return null;
        const v4 = parseIp(piece);
        if (!v4 || v4.v !== 4) return null;
        out.push((v4.bytes[0] << 8) | v4.bytes[1]);
        out.push((v4.bytes[2] << 8) | v4.bytes[3]);
      } else {
        if (!/^[0-9A-Fa-f]{1,4}$/.test(piece)) return null;
        out.push(parseInt(piece, 16));
      }
    }
    return out;
  };
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = groups(halves[0]);
  if (head === null) return null;
  const tail = halves.length === 2 ? groups(halves[1] ?? "") : ([] as number[]);
  if (tail === null) return null;
  if (halves.length === 1) {
    if (head.length !== 8) return null; // full-form IPv6 must have exactly 8 groups
  } else if (head.length + tail.length >= 8) {
    return null; // "::" must stand for at least one zero group
  }
  const words = new Array<number>(8).fill(0);
  head.forEach((g, i) => { words[i] = g; });
  tail.forEach((g, i) => { words[8 - tail.length + i] = g; });
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = words[i] >> 8;
    bytes[i * 2 + 1] = words[i] & 0xff;
  }
  return { v: 6, bytes };
}

const v4toText = (b: Uint8Array): string => `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;

/**
 * Hard-blocked cloud metadata endpoints. These are refused UNCONDITIONALLY —
 * --allow-private does NOT spend them (no legitimate local/staging target
 * ever lives at a metadata address; dialing one is the canonical SSRF win).
 */
export function metadataAddressReason(ip: IpBinary): string | null {
  if (ip.v === 4) {
    const b = ip.bytes;
    if (b[0] === 169 && b[1] === 254 && b[2] === 169 && b[3] === 254) return "169.254.169.254 (cloud metadata)";
    if (b[0] === 169 && b[1] === 254 && b[2] === 170 && b[3] === 2) return "169.254.170.2 (ECS task metadata)";
    return null;
  }
  const b = ip.bytes;
  // fd00:ec2::254 — AWS IPv6 metadata endpoint
  if (b[0] === 0xfd && b[1] === 0x00 && b[2] === 0x0e && b[3] === 0xc2
    && b.slice(4, 14).every((x) => x === 0) && b[14] === 0x02 && b[15] === 0x54) {
    return "fd00:ec2::254 (cloud metadata, IPv6)";
  }
  return null;
}

/** Human-readable reason an address is blocked, or null when allowed. */
export function blockedAddressReason(ip: IpBinary): string | null {
  if (ip.v === 4) {
    const b = ip.bytes;
    if (b[0] === 127) return "loopback (127.0.0.0/8)";
    if (b[0] === 0) return "this-network (0.0.0.0/8)";
    if (b[0] === 10) return "RFC1918 private (10.0.0.0/8)";
    if (b[0] === 172 && b[1] >= 16 && b[1] <= 31) return "RFC1918 private (172.16.0.0/12)";
    if (b[0] === 192 && b[1] === 168) return "RFC1918 private (192.168.0.0/16)";
    if (b[0] === 169 && b[1] === 254) return "link-local / cloud metadata (169.254.0.0/16)";
    if (b[0] === 100 && b[1] >= 64 && b[1] <= 127) return "CGNAT shared address space (100.64.0.0/10)";
    if (b[0] === 198 && (b[1] === 18 || b[1] === 19)) return "benchmark space (198.18.0.0/15)";
    if (b[0] === 192 && b[1] === 0 && (b[2] === 0 || b[2] === 2)) return "protocol/doc space (192.0.0.0/24, 192.0.2.0/24)";
    if (b[0] === 198 && b[1] === 51 && b[2] === 100) return "documentation space (198.51.100.0/24)";
    if (b[0] === 203 && b[1] === 0 && b[2] === 113) return "documentation space (203.0.113.0/24)";
    if (b[0] === 255) return "reserved broadcast (255.0.0.0/8)";
    return null;
  }
  const b = ip.bytes;
  if (b.every((x) => x === 0)) return "unspecified (::)";
  if (b.slice(0, 15).every((x) => x === 0) && b[15] === 1) return "IPv6 loopback (::1)";
  if (b[0] === 0xff && b[1] >= 0xf0) return "IPv6 multicast (ff00::/8)";
  // mapped / compatible / NAT64 forms all embed an IPv4 that must be judged
  const embedV4 = (() => {
    const mapped = b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff;
    const compat = b.slice(0, 12).every((x) => x === 0) && !mapped;
    const nat64 = b[0] === 0 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && b.slice(4, 12).every((x) => x === 0);
    return mapped || compat || nat64;
  })();
  if (embedV4) {
    const r = blockedAddressReason({ v: 4, bytes: b.slice(12, 16) });
    if (r) return `mapped IPv6 → ${r}`;
  }
  if ((b[0] & 0xfe) === 0xfc) return "IPv6 unique-local (fc00::/7)";
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return "IPv6 link-local (fe80::/10)";
  return null;
}

/** Canonical textual address → binary, refusing every blocked range. */
export function validateAddress(text: string): IpBinary | null {
  const ip = parseIp(text);
  if (!ip) return null;
  return blockedAddressReason(ip) !== null ? null : ip;
}

export const SERVICE_ALLOWED_PORTS = new Set([80, 443, 8080, 8443]);
export const SERVICE_MAX_REDIRECTS = 10;
export const SERVICE_CONNECT_TIMEOUT_MS = 10_000;
export const SERVICE_READ_TIMEOUT_MS = 30_000;
export const SERVICE_DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

let serviceModeCache: boolean | null = null;
export function isServiceMode(): boolean {
  if (serviceModeCache === null) {
    try { serviceModeCache = process.env.ANUBIS_SERVICE === "1"; }
    catch { serviceModeCache = false; }
  }
  return serviceModeCache;
}

/** Test-only reset for the cached env read. */
export function resetServiceModeCache(): void { serviceModeCache = null; }

export function serviceMaxResponseBytes(): number {
  const raw = process.env.ANUBIS_MAX_RESPONSE_BYTES;
  if (!raw) return SERVICE_DEFAULT_MAX_RESPONSE_BYTES;
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : SERVICE_DEFAULT_MAX_RESPONSE_BYTES;
}

export class SsrfRefusedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfRefusedError";
  }
}

export interface LookupResult { address: string; family: number }
export type LookupAllFn = (host: string) => Promise<LookupResult[]>;

const defaultLookupAll: LookupAllFn = (host) =>
  lookup(host, { all: true, verbatim: true }) as unknown as Promise<LookupResult[]>;

export interface PinnedTarget {
  ip: string;           // the IP actually followed (first validated candidate)
  family: 4 | 6;
  port: number;
  host: string;         // original hostname (Host header + TLS SNI)
  candidates: Array<{ address: string; family: 4 | 6 }>;
}

/**
 * Guard + pin ONE hop target. Throws SsrfRefusedError on any violation:
 * non-http(s) scheme, service-mode port policy, unresolvable host,
 * ANY resolved address inside a blocked range (unless private explicitly
 * allowed in CLI mode), or unparseable/unknown address shapes.
 * Literal IPs skip DNS entirely; names resolve exactly once are pinned —
 * DNS rebinding cannot get a second word in.
 */
export async function assertPinnedTarget(
  rawUrl: string | URL,
  opts: { allowPrivate?: boolean; lookup?: LookupAllFn } = {},
): Promise<PinnedTarget> {
  const service = isServiceMode();
  const allowPrivate = opts.allowPrivate === true && !service;
  let u: URL;
  try { u = rawUrl instanceof URL ? rawUrl : new URL(rawUrl); }
  catch { throw new SsrfRefusedError("SSRF-REFUSED: malformed URL"); }

  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new SsrfRefusedError(`SSRF-REFUSED: non-http(s) scheme (${u.protocol.replace(/:$/, "") || "unknown"})`);
  }

  const port = u.port === "" ? (u.protocol === "https:" ? 443 : 80) : Number(u.port);
  if (service && !SERVICE_ALLOWED_PORTS.has(port)) {
    throw new SsrfRefusedError(`SSRF-REFUSED: service mode allows ports 80/443/8080/8443 only (got ${port})`);
  }

  const hostText = u.hostname.replace(/^\[|\]$/g, "");
  const candidates: Array<{ address: string; family: 4 | 6 }> = [];

  const literal = parseIp(hostText);
  if (literal) {
    if (metadataAddressReason(literal)) {
      throw new SsrfRefusedError(`SSRF-REFUSED: cloud metadata endpoint — ${metadataAddressReason(literal) as string} (never dialable; --allow-private does not cover it)`);
    }
    const reason = blockedAddressReason(literal);
    if (reason && !allowPrivate) {
      throw new SsrfRefusedError(`SSRF-REFUSED: blocked literal address — ${reason}${service ? " (service mode: private ranges are never allowed)" : " (pass --allow-private for local/staging targets)"}`);
    }
    // connect-string: net canonicalization when it agrees, v4 dotted form for v4,
    // else the URL's own canonical text (WHATWG already normalized it)
    const netCanon = netIpParse(hostText);
    const preferred = netCanon ?? hostText;
    const bin = preferred === hostText ? literal : parseIp(preferred);
    if (!bin) throw new SsrfRefusedError(`SSRF-REFUSED: literal address failed canonical re-check (${hostText})`);
    if (bin.v === 4) candidates.push({ address: v4toText(bin.bytes), family: 4 });
    else candidates.push({ address: preferred, family: 6 });
  } else {
    const looked = opts.lookup ?? defaultLookupAll;
    let results: LookupResult[];
    try { results = await looked(hostText); }
    catch (e) {
      throw new SsrfRefusedError(`SSRF-REFUSED: DNS resolution failed for ${hostText} (${e instanceof Error ? e.message : String(e)})`);
    }
    if (!results || results.length === 0) {
      throw new SsrfRefusedError(`SSRF-REFUSED: DNS returned no addresses for ${hostText}`);
    }
    for (const r of results) {
      const bin = parseIp(r.address);
      if (!bin) throw new SsrfRefusedError(`SSRF-REFUSED: unparseable resolved address (${r.address}) for ${hostText}`);
      const metaReason = metadataAddressReason(bin);
      if (metaReason) throw new SsrfRefusedError(`SSRF-REFUSED: cloud metadata endpoint — ${metaReason} (never dialable; DNS-rebind bait for ${hostText})`);
      const reason = blockedAddressReason(bin);
      if (reason && !allowPrivate) {
        throw new SsrfRefusedError(
          service ? `SSRF-REFUSED: ${hostText} resolved to a blocked range — ${reason}`
            : `SSRF-REFUSED: ${hostText} resolved to a blocked range — ${reason} (pass --allow-private for local/staging targets)`
        );
      }
      if (!reason || allowPrivate) candidates.push({ address: r.address, family: bin.v });
    }
  }

  if (candidates.length === 0) {
    throw new SsrfRefusedError(`SSRF-REFUSED: no usable address for ${hostText}`);
  }
  return { ip: candidates[0].address, family: candidates[0].family, port, host: hostText, candidates };
}

/**
 * Redirect-hop guard. Returns the ABSOLUTE next URL string. Refuses:
 * malformed Location, non-http(s) scheme, scheme demotion (https → http).
 * The caller must re-run assertPinnedTarget() on the result — every hop is
 * a full fresh guard (DNS + IP + port).
 */
export function assertNextHop(currentUrl: URL, location: string): string {
  if (location === "") throw new SsrfRefusedError("SSRF-REFUSED: empty redirect Location");
  let next: URL;
  try { next = new URL(location, currentUrl); }
  catch { throw new SsrfRefusedError(`SSRF-REFUSED: unparseable redirect Location (${location.slice(0, 80)})`); }
  if (next.protocol !== "http:" && next.protocol !== "https:") {
    throw new SsrfRefusedError(`SSRF-REFUSED: redirect to non-http(s) scheme (${next.protocol.replace(/:$/, "")})`);
  }
  if (currentUrl.protocol === "https:" && next.protocol === "http:") {
    throw new SsrfRefusedError("SSRF-REFUSED: scheme demotion refused (https → http redirect)");
  }
  return next.toString();
}
