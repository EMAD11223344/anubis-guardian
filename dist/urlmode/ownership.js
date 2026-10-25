import { resolveTxt } from "node:dns/promises";
import { randomBytes } from "node:crypto";
/**
 * Ownership verification (Plan Section 7, v1.1+v1.3 — the legal gate of Mode 2):
 * - `--i-own-this-domain` is a checkbox, NOT proof. Self-attestation is honored
 *   ONLY for localhost/127.0.0.1/*.local/private staging networks — the cases
 *   where DNS proof is impossible by design.
 * - Any public domain: Level 2+ requires a VERIFIED nonce the owner published:
 *   (a) DNS TXT record `anubis-guardian-challenge=<nonce>` (preferred), or
 *   (b) web file `https://<host>/.well-known/anubis-guardian/<nonce>` (200 + nonce in body).
 * - Reports always label the method: `verified` vs `self-attested (local only)`.
 * - DNS resolver is injectable so the verifier is unit-testable offline.
 */
export const CHALLENGE_PREFIX = "anubis-guardian-challenge=";
export function generateNonce() {
    return randomBytes(16).toString("hex");
}
export function isLocalOrPrivate(host) {
    const h = host.toLowerCase().replace(/\.$/, "");
    if (h === "localhost" || h === "::1" || h === "[::1]")
        return true;
    if (h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".test") || h.endsWith(".staging"))
        return true;
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
    if (m) {
        const [a, b] = [Number(m[1]), Number(m[2])];
        if (a === 127 || a === 10)
            return true; // loopback / RFC1918 10/8
        if (a === 172 && b >= 16 && b <= 31)
            return true; // 172.16/12
        if (a === 192 && b === 168)
            return true; // 192.168/16
        if (a === 169 && b === 254)
            return true; // link-local
    }
    return false;
}
export const realTxtResolver = async (name) => resolveTxt(name);
/**
 * Verify the nonce via DNS TXT: check the host itself and the dedicated
 * `_anubis-guardian.<host>` record name (both are accepted spellings).
 */
export async function verifyDnsTxt(host, nonce, resolveTxtFn = realTxtResolver) {
    const names = [host, `_anubis-guardian.${host}`];
    for (const name of names) {
        try {
            const records = await resolveTxtFn(name);
            for (const chunks of records) {
                if (chunks.join("").trim().toLowerCase() === `${CHALLENGE_PREFIX}${nonce.toLowerCase()}`)
                    return true;
            }
        }
        catch {
            // ENODATA / ENOTFOUND — try the next name
        }
    }
    return false;
}
/** Verify the nonce via the .well-known web file (200 + nonce present in body). */
export async function verifyWellKnown(origin, nonce, fetcher) {
    const res = await fetcher.get(`${origin}/.well-known/anubis-guardian/${nonce}`);
    return !!res && res.status === 200 && res.body.includes(nonce);
}
/** Try DNS TXT first (no server involvement), then the .well-known file. */
export async function verifyOwnership({ host, origin, nonce, fetcher, resolveTxtFn }) {
    if (await verifyDnsTxt(host, nonce, resolveTxtFn)) {
        return { verified: true, method: "dns-txt", host };
    }
    if (await verifyWellKnown(origin, nonce, fetcher)) {
        return { verified: true, method: "well-known", host };
    }
    return { verified: false, method: "none", host };
}
/** Human-readable setup instructions (printed by `ownership` + refused scans). */
export function instructions(host, nonce) {
    return [
        `Publish this nonce to prove control of ${host} — either way works:`,
        `  1) DNS TXT record  (preferred — no server changes):`,
        `       host/name: ${host}   (or _anubis-guardian.${host})`,
        `       value:     ${CHALLENGE_PREFIX}${nonce}`,
        `  2) Web file at:`,
        `       https://${host}/.well-known/anubis-guardian/${nonce}`,
        `       (body must contain the nonce; plain text is fine)`,
        ``,
        `Then re-run with:  --ownership-token ${nonce}`,
    ].join("\n");
}
