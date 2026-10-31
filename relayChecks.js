"use strict";

/**
 * RELAY_AUTH — which check decides who may use the access key. A
 * comma-separated list of:
 *
 *   device  cameras and other devices with a per-device secret (relayDevices.js)
 *   jwt     your apps' users, with a token your sign-in issued (relayJwt.js)
 *   custom  your own code in relayAuth.js (authenticateCaller)
 *
 * Unset = custom, which refuses everyone until you write it.
 *
 * With several, the request decides which one runs: one carrying
 * X-Samvyo-Device-Id goes to `device`; else one with `Authorization: Bearer`
 * goes to `jwt`; else `custom`. Each refusal is final: a request is never
 * passed on to the next check after one refuses it.
 */

const axios = require("axios");
const { makeJwtCheck, jwtOptionsFromEnv, jwtWarnings } = require("./relayJwt");
const { makeDeviceCheck, HEADER: DEVICE_HEADER } = require("./relayDevices");

const MODES = ["device", "jwt", "custom"];

const fetchJsonDefault = async (url) => {
  const r = await axios.get(url, { timeout: 5000 });
  return r.data;
};

/**
 * @param {object} env - process.env
 * @param {object} deps
 * @param {Function} deps.authenticateCaller - relayAuth.authenticateCaller
 * @returns {{ authenticate: Function, summary: string, warnings: string[] }} throws on a misconfiguration
 */
function buildAuthenticator(env, { authenticateCaller, fetchJson = fetchJsonDefault, log = console } = {}) {
  const modes = String(env.RELAY_AUTH || "custom")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const unknown = modes.filter((m) => !MODES.includes(m));
  if (unknown.length) throw new Error(`RELAY_AUTH: unknown "${unknown.join(", ")}" (use ${MODES.join(", ")})`);

  const warnings = [];
  const parts = [];
  let device = null;
  let jwtCheck = null;
  const custom = modes.includes("custom") ? authenticateCaller : null;

  if (modes.includes("device")) {
    if (!env.RELAY_DEVICES_FILE) throw new Error("RELAY_AUTH=device needs RELAY_DEVICES_FILE (the device list)");
    try {
      device = makeDeviceCheck({ file: env.RELAY_DEVICES_FILE, log });
    } catch (e) {
      throw new Error(`RELAY_DEVICES_FILE ${env.RELAY_DEVICES_FILE}: ${e.message}`);
    }
    parts.push(`device (${device.deviceCount()} in ${env.RELAY_DEVICES_FILE})`);
  }
  if (modes.includes("jwt")) {
    const opts = jwtOptionsFromEnv(env);
    jwtCheck = makeJwtCheck(opts, { fetchJson, log });
    warnings.push(...jwtWarnings(opts));
    parts.push(`jwt (${opts.jwksUrl ? `JWKS ${opts.jwksUrl}` : opts.secret ? "shared secret" : "public key"})`);
  }
  if (custom) parts.push("custom (relayAuth.js)");

  const hasBearer = (req) => /^Bearer\s+/i.test(String((req.headers && req.headers.authorization) || ""));

  async function authenticate(req, ctx) {
    const headers = req.headers || {};
    if (headers[DEVICE_HEADER]) {
      if (device) return device(req, ctx);
      return { ok: false, status: 401, message: "This relay does not accept device credentials" };
    }
    if (jwtCheck && (hasBearer(req) || !custom)) return jwtCheck(req, ctx);
    if (custom) return custom(req, ctx);
    return { ok: false, status: 401, message: "Missing device credentials" };
  }

  return { authenticate, summary: parts.join(", "), warnings };
}

module.exports = { buildAuthenticator, MODES };
