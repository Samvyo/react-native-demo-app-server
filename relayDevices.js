"use strict";

/**
 * RELAY_AUTH=device — cameras and other devices, each with its own secret.
 *
 * At install time you give each device an id and a random secret
 * (`npm run add-device`); the relay keeps only a SHA-256 of the secret, in the
 * device list (RELAY_DEVICES_FILE). On every request the device sends
 *
 *   X-Samvyo-Device-Id: <id>
 *   Authorization: Bearer <secret>
 *
 * over HTTPS, and the relay grants "participant" (a camera publishes; it never
 * moderates).
 *
 * The device list (JSON):
 *   { "devices": [
 *       { "id": "lobby-cam-1",            // the camera's PEER_ID
 *         "secretSha256": "<64 hex>",
 *         "rooms": ["1234567890"],        // optional: only these rooms
 *         "disabled": false }             // optional: refuse without deleting it
 *   ] }
 * The device id IS the camera's PEER_ID: the id it joins and registers presence
 * with. A presence token (direct view) is minted only for that id. A list from
 * before this may still carry a "peerIds" field; it is ignored, with a warning.
 *
 * The file is re-read when it changes, so adding or disabling a device needs no
 * restart. A change that does not parse is ignored (the relay keeps the last
 * good list, and says so).
 *
 * The secret is random and at least 32 bytes, so a plain SHA-256 is enough to
 * store it: there is nothing to guess. The relay's per-address rate limit
 * bounds attempts anyway.
 */

const crypto = require("crypto");
const fs = require("fs");

const HEADER = "x-samvyo-device-id";
// How often a request may look at the file's modification time.
const STAT_EVERY_MS = 5000;

const sha256 = (s) => crypto.createHash("sha256").update(String(s), "utf8").digest();

/**
 * Parse and check a device list; throws with the reason. `warn` hears about what
 * is accepted but ignored.
 */
function parseDevices(text, warn = () => {}) {
  const doc = JSON.parse(text);
  const list = doc && Array.isArray(doc.devices) ? doc.devices : null;
  if (!list) throw new Error('expected { "devices": [ ... ] }');
  const byId = new Map();
  for (const d of list) {
    const id = d && typeof d.id === "string" ? d.id.trim() : "";
    if (!id) throw new Error("a device has no id");
    if (byId.has(id)) throw new Error(`device "${id}" is listed twice`);
    if (!/^[0-9a-f]{64}$/i.test(String(d.secretSha256 || ""))) {
      throw new Error(`device "${id}": secretSha256 must be 64 hex characters`);
    }
    if (d.rooms != null && !(Array.isArray(d.rooms) && d.rooms.every((x) => typeof x === "string" || typeof x === "number"))) {
      throw new Error(`device "${id}": rooms must be a list`);
    }
    if (d.peerIds !== undefined) {
      warn(
        `device "${id}": "peerIds" is no longer used and is ignored. A device's presence token is for its own id, ` +
          `which must be the camera's PEER_ID; if this camera's PEER_ID is not "${id}", add it again under its PEER_ID. ` +
          `Remove the field to silence this.`
      );
    }
    byId.set(id, {
      id,
      hash: Buffer.from(d.secretSha256, "hex"),
      rooms: Array.isArray(d.rooms) && d.rooms.length ? d.rooms.map(String) : null,
      disabled: d.disabled === true,
    });
  }
  return byId;
}

/** The device list from a file, re-read when the file changes. */
function makeDeviceStore({ file, now = () => Date.now(), log = console }) {
  const warn = (w) => log.warn(`relay: device list ${file}: ${w}`);
  let devices = parseDevices(fs.readFileSync(file, "utf8"), warn); // a bad file at startup is fatal
  let mtimeMs = fs.statSync(file).mtimeMs;
  let checkedAt = now();

  return function current() {
    if (now() - checkedAt >= STAT_EVERY_MS) {
      checkedAt = now();
      try {
        const m = fs.statSync(file).mtimeMs;
        if (m !== mtimeMs) {
          mtimeMs = m;
          devices = parseDevices(fs.readFileSync(file, "utf8"), warn);
          log.info(`relay: device list reloaded (${devices.size} devices)`);
        }
      } catch (e) {
        log.error(`relay: device list ${file} not reloaded, keeping the last good one: ${e.message}`);
      }
    }
    return devices;
  };
}

// Compared against when the device id is unknown, so an unknown id and a wrong
// secret take the same time.
const DUMMY_HASH = sha256("no such device");

function makeDeviceCheck({ file, store, log = console }) {
  const devices = store || makeDeviceStore({ file, log });
  // A camera's own 403s carry the same code Samvyo's token URL sends, so the camera
  // can tell them from the org's billing-state 403s, which it must keep retrying.
  const refuse = (status, message, why, code) => {
    log.warn(`relay: device refused (${why})`);
    return code ? { ok: false, status, message, code } : { ok: false, status, message };
  };

  const check = async function checkDevice(req, ctx) {
    const headers = req.headers || {};
    const id = String(headers[HEADER] || "").trim();
    const auth = String(headers.authorization || "");
    const secret = /^Bearer\s+/i.test(auth) ? auth.replace(/^Bearer\s+/i, "").trim() : "";
    if (!id || !secret) {
      return refuse(401, "Missing device credentials", "no device id or secret");
    }
    const device = devices().get(id);
    const match = crypto.timingSafeEqual(sha256(secret), device ? device.hash : DUMMY_HASH);
    // One answer for an unknown device, a wrong secret and a disabled device:
    // the caller learns nothing about which ids exist.
    if (!device || !match || device.disabled) {
      return refuse(401, "Device credentials not accepted", `${id}: ${!device ? "unknown id" : !match ? "wrong secret" : "disabled"}`);
    }
    const body = req.body || {};
    if (ctx && ctx.kind === "presence") {
      const peerId = String(body.peerId || "");
      if (peerId !== device.id) {
        return refuse(403, "This device may not mint a presence token for that camera id", `${id}: peerId ${peerId}`, "DEVICE_PRESENCE_NOT_ALLOWED");
      }
      return { ok: true, participantType: "participant" };
    }
    const roomId = String(body.roomId ?? "");
    if (device.rooms && !device.rooms.includes(roomId)) {
      return refuse(403, "This device may not join that room", `${id}: room ${roomId}`, "DEVICE_ROOM_NOT_ALLOWED");
    }
    return { ok: true, participantType: "participant" };
  };
  check.deviceCount = () => devices().size;
  return check;
}

module.exports = { makeDeviceCheck, makeDeviceStore, parseDevices, sha256, HEADER };
