#!/usr/bin/env node
"use strict";

/**
 * Give a device (a camera) its credential for RELAY_AUTH=device.
 *
 *   npm run add-device -- --id lobby-cam-1 --secret-out ./lobby-cam-1.secret \
 *       [--room 1234567890 ...] [--peer-id lobby-cam-1 ...] [--file devices.json] [--rotate]
 *
 * Generates a random secret, writes it to --secret-out (mode 0600, never over an
 * existing file), and adds the device to the device list with only the secret's
 * SHA-256. Copy the secret file to the camera (its DEVICE_SECRET_FILE) and
 * delete it here. The secret is never printed.
 *
 * --rotate replaces an existing device's secret (its rooms and peerIds are kept
 * unless given again). The relay picks the change up within seconds.
 * The list is RELAY_DEVICES_FILE, else ./devices.json, unless --file is given.
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { parseDevices, sha256 } = require("../relayDevices");

function parseArgs(argv) {
  const a = { rooms: [], peerIds: [] };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    const v = () => {
      if (i + 1 >= argv.length) throw new Error(`${k} needs a value`);
      return argv[++i];
    };
    if (k === "--id") a.id = v();
    else if (k === "--secret-out") a.secretOut = v();
    else if (k === "--file") a.file = v();
    else if (k === "--room") a.rooms.push(v());
    else if (k === "--peer-id") a.peerIds.push(v());
    else if (k === "--rotate") a.rotate = true;
    else throw new Error(`unknown option ${k}`);
  }
  return a;
}

function addDevice({ id, secretOut, file, rooms = [], peerIds = [], rotate = false }) {
  if (!id || !/^[A-Za-z0-9._:-]{1,128}$/.test(id)) throw new Error("--id: letters, digits and . _ : - only");
  if (!secretOut) throw new Error("--secret-out is required: the secret goes to a file, never to the screen");
  if (fs.existsSync(secretOut)) throw new Error(`${secretOut} already exists; not overwriting a secret`);

  const doc = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : { devices: [] };
  parseDevices(JSON.stringify(doc)); // refuse to build on a list the relay would refuse
  const at = doc.devices.findIndex((d) => d.id === id);
  if (at >= 0 && !rotate) throw new Error(`device "${id}" exists; use --rotate to give it a new secret`);
  if (at < 0 && rotate) throw new Error(`device "${id}" does not exist; leave out --rotate to add it`);

  const secret = crypto.randomBytes(32).toString("base64url");
  const prev = at >= 0 ? doc.devices[at] : {};
  const entry = {
    ...prev,
    id,
    secretSha256: sha256(secret).toString("hex"),
    ...(rooms.length ? { rooms } : {}),
    ...(peerIds.length ? { peerIds } : {}),
  };
  if (at >= 0) doc.devices[at] = entry;
  else doc.devices.push(entry);

  // The secret first: if the list cannot be written, nothing points at a secret nobody has.
  fs.writeFileSync(secretOut, secret, { mode: 0o600, flag: "wx" });
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
        `${e.rooms ? `; rooms: ${e.rooms.join(", ")}` : "; any room"}` +
        `; presence for: ${(e.peerIds || [e.id]).join(", ")}.`
    );
    console.log(`Secret written to ${a.secretOut} (0600). Put it on the camera as its DEVICE_SECRET_FILE, then delete it here.`);
  } catch (err) {
    console.error(`add-device: ${err.message}`);
    process.exit(1);
  }
}

module.exports = { addDevice, parseArgs };
