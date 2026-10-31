"use strict";

/**
 * RELAY_AUTH=jwt — the caller presents a JWT that YOUR sign-in system issued
 * (`Authorization: Bearer <token>`), and the relay verifies it before minting
 * with your access key. For web and mobile apps with their own login.
 *
 * The key that verifies it is one of (exactly one):
 *   RELAY_JWT_SECRET           a shared HMAC secret (HS256), at least 32 characters
 *   RELAY_JWT_PUBLIC_KEY_FILE  a PEM public key (RS256 / PS256 / ES256 ...)
 *   RELAY_JWT_JWKS_URL         your identity provider's JWKS (Auth0, Cognito, Keycloak, Firebase ...)
 *
 * The token must have an expiry; issuer and audience are checked when set.
 *
 * The ROLE comes from a claim (RELAY_JWT_ROLE_CLAIM, default `samvyo_role`):
 *   - a string: the role in every room, e.g. "participant";
 *   - an object: per room, e.g. { "1234567890": "moderator", "*": "participant" }.
 * RELAY_JWT_ROLE_MAP maps your own role names (`host=moderator,member=participant`).
 * No claim, or no entry for the room: RELAY_JWT_DEFAULT_ROLE (participant).
 *
 * RELAY_JWT_ROOM_CLAIM, when set, binds the token to rooms: the claim (a room id
 * or a list of them) must name the room asked for, or the request is refused.
 *
 * A camera's direct-view presence token is never minted for a JWT caller: that
 * is a device's credential (RELAY_AUTH=device).
 */

const crypto = require("crypto");
const fs = require("fs");
const jwt = require("jsonwebtoken");

const ROLES = ["moderator", "participant", "viewer"];
const HMAC_ALGS = ["HS256", "HS384", "HS512"];
const KEY_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"];
const MIN_SECRET_LENGTH = 32;
// A token signed with a key the cached set does not have triggers a refetch,
// at most this often — enough for a key rotation, not a way to make the relay
// hammer the identity provider.
const JWKS_REFETCH_MIN_MS = 30000;

const list = (v) =>
  String(v || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

/** A claim by exact name (namespaced claims contain dots), else as a dotted path. */
function claim(payload, name) {
  if (!name) return undefined;
  if (Object.prototype.hasOwnProperty.call(payload, name)) return payload[name];
  return name.split(".").reduce((o, k) => (o && typeof o === "object" ? o[k] : undefined), payload);
}

function parseRoleMap(text) {
  const map = {};
  for (const pair of list(text)) {
    const [from, to] = pair.split("=").map((s) => s && s.trim());
    if (!from || !ROLES.includes(to)) {
      throw new Error(`RELAY_JWT_ROLE_MAP: "${pair}" must be <your role>=<${ROLES.join("|")}>`);
    }
    map[from] = to;
  }
  return map;
}

/** Settings from the environment → options for makeJwtCheck. Throws on a misconfiguration. */
function jwtOptionsFromEnv(env) {
  const sources = ["RELAY_JWT_SECRET", "RELAY_JWT_PUBLIC_KEY_FILE", "RELAY_JWT_JWKS_URL"].filter((k) => env[k]);
  if (sources.length !== 1) {
    throw new Error(
      "RELAY_AUTH=jwt needs exactly one of RELAY_JWT_SECRET, RELAY_JWT_PUBLIC_KEY_FILE, RELAY_JWT_JWKS_URL" +
        (sources.length ? ` (got ${sources.join(" and ")})` : "")
    );
  }
  const opts = {
    issuer: env.RELAY_JWT_ISSUER || undefined,
    audience: env.RELAY_JWT_AUDIENCE || undefined,
    roleClaim: env.RELAY_JWT_ROLE_CLAIM || "samvyo_role",
    roomClaim: env.RELAY_JWT_ROOM_CLAIM || undefined,
    defaultRole: env.RELAY_JWT_DEFAULT_ROLE || "participant",
    roleMap: parseRoleMap(env.RELAY_JWT_ROLE_MAP),
    clockToleranceSec: parseInt(env.RELAY_JWT_CLOCK_TOLERANCE_SEC || "30", 10),
    jwksCacheSec: parseInt(env.RELAY_JWT_JWKS_CACHE_SEC || "600", 10),
  };
  if (!ROLES.includes(opts.defaultRole)) {
    throw new Error(`RELAY_JWT_DEFAULT_ROLE must be one of ${ROLES.join(", ")}`);
  }

  let allowed;
  if (env.RELAY_JWT_SECRET) {
    if (env.RELAY_JWT_SECRET.length < MIN_SECRET_LENGTH) {
      throw new Error(`RELAY_JWT_SECRET must be at least ${MIN_SECRET_LENGTH} characters`);
    }
    opts.secret = env.RELAY_JWT_SECRET;
    allowed = HMAC_ALGS;
    opts.algorithms = ["HS256"];
  } else {
    if (env.RELAY_JWT_PUBLIC_KEY_FILE) {
      opts.publicKey = crypto.createPublicKey(fs.readFileSync(env.RELAY_JWT_PUBLIC_KEY_FILE));
    } else {
      opts.jwksUrl = env.RELAY_JWT_JWKS_URL;
      if (!/^https:\/\//.test(opts.jwksUrl) && env.RELAY_JWT_JWKS_ALLOW_HTTP !== "true") {
        throw new Error("RELAY_JWT_JWKS_URL must be https:// (a key set fetched in the clear can be swapped)");
      }
    }
    allowed = KEY_ALGS;
    opts.algorithms = ["RS256", "PS256", "ES256"];
  }
  if (env.RELAY_JWT_ALGORITHMS) {
    // Never a mix: an HMAC algorithm accepted alongside a public key lets a
    // token be signed WITH the public key (algorithm confusion).
    const algs = list(env.RELAY_JWT_ALGORITHMS);
    const bad = algs.filter((a) => !allowed.includes(a));
    if (!algs.length || bad.length) {
      throw new Error(`RELAY_JWT_ALGORITHMS: ${bad.join(", ") || "empty"} not allowed with this key; use ${allowed.join(", ")}`);
    }
    opts.algorithms = algs;
  }
  return opts;
}

/** Fetches and caches a JWKS; keys by kid. `fetchJson(url)` is injectable for tests. */
function makeJwksStore({ url, cacheSec, fetchJson, now = () => Date.now() }) {
  let keys = new Map();
  let fetchedAt = 0;
  let inflight = null;

  const refresh = () => {
    if (!inflight) {
      inflight = (async () => {
        try {
          const body = await fetchJson(url);
          const next = new Map();
          for (const jwk of (body && body.keys) || []) {
            if (jwk.use && jwk.use !== "sig") continue;
            try {
              next.set(jwk.kid || "", crypto.createPublicKey({ key: jwk, format: "jwk" }));
            } catch (_) {
              // A key type Node cannot import (or a malformed entry) is skipped.
            }
          }
          keys = next;
          fetchedAt = now();
        } finally {
          inflight = null;
        }
      })();
    }
    return inflight;
  };

  return async function keyFor(kid) {
    const stale = !fetchedAt || now() - fetchedAt > cacheSec * 1000;
    if (stale) {
      try {
        await refresh();
      } catch (e) {
        // Keep serving the keys we have; with none, the caller is told why.
        if (!keys.size) throw e;
      }
    }
    const pick = () => (kid ? keys.get(kid) : keys.size === 1 ? [...keys.values()][0] : undefined);
    let key = pick();
    if (!key && kid && now() - fetchedAt > JWKS_REFETCH_MIN_MS) {
      await refresh().catch(() => {});
      key = pick();
    }
    return key;
  };
}

const bearerOf = (req) => {
  const h = String((req.headers && req.headers.authorization) || "");
  return /^Bearer\s+/i.test(h) ? h.replace(/^Bearer\s+/i, "").trim() : "";
};

/**
 * @returns {(req, ctx) => Promise<{ok:true, participantType} | {ok:false, status, message}>}
 */
function makeJwtCheck(opts, { fetchJson, log = console } = {}) {
  const keyFor = opts.jwksUrl
    ? makeJwksStore({ url: opts.jwksUrl, cacheSec: opts.jwksCacheSec, fetchJson })
    : null;
  const refuse = (status, message, why) => {
    log.warn(`relay: JWT caller refused (${why || message})`);
    return { ok: false, status, message };
  };

  return async function checkJwt(req, ctx) {
    if (ctx && ctx.kind === "presence") {
      return refuse(403, "Presence tokens are minted for devices only", "presence asked with a JWT");
    }
    const token = bearerOf(req);
    if (!token) return refuse(401, "Missing Authorization: Bearer <token>", "no token");

    let key = opts.secret || opts.publicKey;
    if (keyFor) {
      const header = (jwt.decode(token, { complete: true }) || {}).header;
      if (!header) return refuse(401, "Invalid or expired token", "not a JWT");
      try {
        key = await keyFor(header.kid);
      } catch (e) {
        return refuse(503, "Cannot verify tokens right now", `JWKS fetch failed: ${e.message}`);
      }
      if (!key) return refuse(401, "Invalid or expired token", `no key for kid ${header.kid || "(none)"}`);
    }

    let payload;
    try {
      payload = jwt.verify(token, key, {
        algorithms: opts.algorithms,
        issuer: opts.issuer,
        audience: opts.audience,
        clockTolerance: opts.clockToleranceSec,
      });
    } catch (e) {
      return refuse(401, "Invalid or expired token", e.message);
    }
    if (typeof payload !== "object" || !payload.exp) {
      return refuse(401, "Token has no expiry", "no exp");
    }

    const roomId = req.body && req.body.roomId != null ? String(req.body.roomId) : "";
    if (opts.roomClaim) {
      const rooms = claim(payload, opts.roomClaim);
      const allowed = (Array.isArray(rooms) ? rooms : rooms != null ? [rooms] : []).map(String);
      if (!allowed.includes(roomId)) {
        return refuse(403, "This token is not for this room", `room ${roomId} not in ${opts.roomClaim}`);
      }
    }

    let raw = claim(payload, opts.roleClaim);
    if (raw && typeof raw === "object" && !Array.isArray(raw)) raw = raw[roomId] ?? raw["*"];
    if (raw == null) return { ok: true, participantType: opts.defaultRole };
    const role = opts.roleMap[raw] || raw;
    if (!ROLES.includes(role)) {
      return refuse(403, "This token's role is not recognised", `${opts.roleClaim}=${JSON.stringify(raw).slice(0, 40)}`);
    }
    return { ok: true, participantType: role };
  };
}

/** Startup notes for a configuration that works but is weaker than it should be. */
function jwtWarnings(opts) {
  const w = [];
  if (!opts.audience) w.push("RELAY_JWT_AUDIENCE is unset: a token your sign-in issued for any other service is accepted too.");
  if (!opts.issuer && !opts.secret) w.push("RELAY_JWT_ISSUER is unset.");
  if (!opts.roomClaim) {
    w.push(
      "RELAY_JWT_ROOM_CLAIM is unset: a token is good for every room, so a moderator role in it is moderator everywhere. " +
        "Bind tokens to rooms, or give the role per room ({\"<roomId>\": \"moderator\"})."
    );
  }
  return w;
}

module.exports = { makeJwtCheck, jwtOptionsFromEnv, jwtWarnings, makeJwksStore, ROLES };
