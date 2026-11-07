"use strict";

/**
 * The relay's guards, kept out of server.js so they can be tested:
 *   - resolveCaller: may this request use the access key, and with what role?
 *   - makeRateLimiter: requests per caller address per minute;
 *   - corsOriginsFrom: which browser origins may call the relay.
 * Settings come from the environment (see .env.example).
 */

const ANONYMOUS_WARNING =
  "RELAY_ALLOW_ANONYMOUS=true — ANYONE who can reach this relay mints sessions with your " +
  "access key, as any role they ask for. Local bench only; never on a reachable deployment.";

/**
 * @param {object} p
 * @param {object} p.req
 * @param {"session"|"presence"} p.kind
 * @param {boolean} p.allowAnonymous - RELAY_ALLOW_ANONYMOUS
 * @param {Function} p.authenticateCaller - relayAuth.authenticateCaller
 * @returns {Promise<{ ok: true, participantType?: string, anonymous?: boolean } | { ok: false, status: number, message: string }>}
 */
async function resolveCaller({ req, kind, allowAnonymous, authenticateCaller }) {
  if (allowAnonymous) {
    // Bench only: the caller's own requested role is forwarded, so test flows
    // that join as moderator keep working. In production the role comes from
    // authenticateCaller, never from the request.
    const asked = req && req.body && req.body.participantType;
    return { ok: true, anonymous: true, ...(asked ? { participantType: String(asked) } : {}) };
  }
  let r;
  try {
    r = await authenticateCaller(req, { kind });
  } catch (e) {
    return { ok: false, status: 500, message: "Caller check failed" };
  }
  if (r && r.ok === true) {
    return { ok: true, ...(r.participantType ? { participantType: String(r.participantType) } : {}) };
  }
  return {
    ok: false,
    status: (r && r.status) || 401,
    message: (r && r.message) || "Caller not authenticated",
    // A camera decides what to do from this code: CAMERA_DISABLED and the org's
    // billing 403s retry slowly, a room it may not join stops it. Without it, every
    // 403 from a device check reads the same.
    ...(r && r.code ? { code: String(r.code) } : {}),
  };
}

/**
 * Fixed-window counter per key (the caller's address), in memory — one relay
 * process. 0 = no limit.
 */
function makeRateLimiter({ perMinute, now = () => Date.now() }) {
  const windows = new Map();
  return function hit(key) {
    if (!(perMinute > 0)) return { allowed: true };
    const minute = Math.floor(now() / 60000);
    const k = String(key || "unknown");
    const w = windows.get(k);
    const entry = w && w.minute === minute ? w : { minute, n: 0 };
    entry.n += 1;
    windows.set(k, entry);
    if (windows.size > 10000) {
      for (const [key2, v] of windows) if (v.minute !== minute) windows.delete(key2);
    }
    if (entry.n > perMinute) {
      return { allowed: false, retryAfterSec: Math.max(1, 60 - Math.floor((now() % 60000) / 1000)) };
    }
    return { allowed: true };
  };
}

/** RELAY_ALLOWED_ORIGINS (comma-separated) → a cors `origin` option. Unset = any. */
function corsOriginsFrom(value) {
  const list = String(value || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return list.length ? list : true;
}

module.exports = { resolveCaller, makeRateLimiter, corsOriginsFrom, ANONYMOUS_WARNING };
