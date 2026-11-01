#!/usr/bin/env node
"use strict";

/**
 * Give a device (a camera) its credential for RELAY_AUTH=device.
 *
 *   npm run add-device -- --id <PEER_ID> --sha256 <64 hex> \
 *       [--room 1234567890 ...] [--file devices.json] [--rotate]
 *   npm run add-device -- --id <PEER_ID> --secret-out ./lobby-cam-1.secret \
 *       [--room 1234567890 ...] [--file devices.json] [--rotate]
 *
 * --id is the camera's PEER_ID: the id it joins and registers presence with.
 *
 * --sha256 adds the SHA-256 of a secret made on the camera's own box, so the
 * secret never leaves it (README: "Cameras"). --secret-out instead generates a
 * random secret here and writes it to that file (mode 0600, never over an
 * existing file), for a gateway that cannot make its own: copy the file to the
 * camera (its DEVICE_SECRET_FILE) and delete it here. Either way the list keeps
 * only the hash, and no secret is ever printed.
 *
 * --rotate replaces an existing device's secret (its rooms are kept unless given
 * again). The relay picks the change up within seconds.
 * The list is RELAY_DEVICES_FILE, else ./devices.json, unless --file is given.
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { parseDevices, sha256 } = require("../relayDevices");

// The camera's PEER_ID, as Samvyo checks it.
const PEER_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const SHA256_RE = /^[0-9a-f]{64}$/i;

function parseArgs(argv) {
  const a = { rooms: [] };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    const v = () => {
      if (i + 1 >= argv.length) throw new Error(`${k} needs a value`);
      return argv[++i];
    };
    if (k === "--id") a.id = v();
    else if (k === "--sha256") a.sha256 = v();
    else if (k === "--secret-out") a.secretOut = v();
    else if (k === "--file") a.file = v();
    else if (k === "--room") a.rooms.push(v());
    else if (k === "--rotate") a.rotate = true;
    else if (k === "--peer-id") {
      throw new Error("--peer-id was removed: a device's id is the camera's PEER_ID, and its presence token is for that id only");
    } else throw new Error(`unknown option ${k}`);
  }
  return a;
}

function addDevice({ id, sha256: hash, secretOut, file, rooms = [], rotate = false }) {
  if (!id || !PEER_ID_RE.test(id)) throw new Error("--id is the camera's PEER_ID: letters, digits and . _ : - only, up to 128");
  if (hash != null && secretOut) throw new Error("give --sha256 or --secret-out, not both");
  if (hash == null && !secretOut) {
    throw new Error("give --sha256 <the hash of a secret made on the camera> or --secret-out <file>; a secret never goes to the screen");
  }
  if (hash != null && !SHA256_RE.test(String(hash).trim())) throw new Error("--sha256 must be 64 hex characters (a SHA-256)");
  if (secretOut && fs.existsSync(secretOut)) throw new Error(`${secretOut} already exists; not overwriting a secret`);

  const doc = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : { devices: [] };
  parseDevices(JSON.stringify(doc)); // refuse to build on a list the relay would refuse
  const at = doc.devices.findIndex((d) => d.id === id);
  if (at >= 0 && !rotate) throw new Error(`device "${id}" exists; use --rotate to give it a new secret`);
  if (at < 0 && rotate) throw new Error(`device "${id}" does not exist; leave out --rotate to add it`);

  const secret = secretOut ? crypto.randomBytes(32).toString("base64url") : null;
  // Rewriting the entry drops the old "peerIds", which the relay no longer reads.
  const { peerIds: _unused, ...prev } = at >= 0 ? doc.devices[at] : {};
  const entry = {
    ...prev,
    id,
    secretSha256: secret ? sha256(secret).toString("hex") : String(hash).trim().toLowerCase(),
    ...(rooms.length ? { rooms } : {}),
  };
  if (at >= 0) doc.devices[at] = entry;
  else doc.devices.push(entry);

  // The secret first: if the list cannot be written, nothing points at a secret nobody has.
  if (secret) fs.writeFileSync(secretOut, secret, { mode: 0o600, flag: "wx" });
  const tmp = path.join(path.dirname(path.resolve(file)), `.${path.basename(file)}.${process.pid}.tmp`);
  fs.writeFileSync(tmp, JSON.stringify(doc, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, file);
  return entry;
}

if (require.main === module) {
  try {
    const a = parseArgs(process.argv.slice(2));
    a.file = a.file || process.env.RELAY_DEVICES_FILE || "devices.json";
    const e = addDevice(a);
    console.log(
      `${a.rotate ? "Rotated" : "Added"} device "${e.id}" in ${a.file}` +
        `${e.rooms ? `; rooms: ${e.rooms.join(", ")}` : "; any room"}.`
    );
    if (a.secretOut) {
      console.log(`Secret written to ${a.secretOut} (0600). Put it on the camera as its DEVICE_SECRET_FILE, then delete it here.`);
    } else {
      console.log("The camera's own secret file is now accepted; nothing to copy.");
    }
  } catch (err) {
    console.error(`add-device: ${err.message}`);
    process.exit(1);
  }
}

module.exports = { addDevice, parseArgs };
