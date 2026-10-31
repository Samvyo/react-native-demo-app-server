"use strict";

/**
 * WHO MAY USE YOUR ACCESS KEY — replace authenticateCaller with your own check.
 *
 * This relay holds your org's access key and secret, and mints Samvyo sessions
 * with them for whoever calls it. A session minted with your key joins your
 * rooms, draws your credit, and is not held to a dashboard room's password
 * (your backend is trusted to have decided who may join). So the relay must
 * decide who its callers are. Out of the box it decides NOBODY: every
 * access-key request is refused until you fill this in.
 *
 * Typical implementations:
 *   - your web/mobile app's own sign-in: verify the session cookie or the JWT
 *     your app issued, look the user up, and grant the role they hold in the
 *     room (moderator for the host, participant for everyone else);
 *   - a camera or other device: verify a per-device credential you provisioned
 *     at install time, and grant "participant".
 *
 * Return the role to grant. The autoscaler refuses a join above it, so a caller
 * cannot claim moderator on its own: { ok: true, participantType: "moderator" }.
 * Leave participantType out to grant no role.
 *
 * For a local bench ONLY, RELAY_ALLOW_ANONYMOUS=true skips this (and the relay
 * says so loudly at startup). Never set it on a reachable deployment.
 *
 * @param {import("express").Request} req
 * @param {{ kind: "session" | "presence" }} ctx - a session token, or a camera's direct-view presence token
 * @returns {Promise<{ ok: true, participantType?: string } | { ok: false, status?: number, message?: string }>}
 */
async function authenticateCaller(req, ctx) {
  return {
    ok: false,
    status: 401,
    message:
      "This relay authenticates no callers yet: implement authenticateCaller in relayAuth.js " +
      "(or, for a local bench only, set RELAY_ALLOW_ANONYMOUS=true).",
  };
}

module.exports = { authenticateCaller };
