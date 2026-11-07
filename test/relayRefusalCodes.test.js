"use strict";
// The relay's own 403s carry their code all the way to the camera, through the real
// server.js: resolveCaller dropped it once, and only a request through the server
// showed that (bench, 2026-11-06). Run: npm test
const test = require("node:test");
const assert = require("node:assert");
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");

const post = (port, body, headers) =>
  new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const r = http.request(
      { host: "127.0.0.1", port, path: "/api/create-session-token", method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data), ...headers } },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => resolve({ status: res.statusCode, body: JSON.parse(text) }));
      }
    );
    r.on("error", reject);
    r.end(data);
  });

const freePort = () =>
  new Promise((resolve) => {
    const s = http.createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

test("through server.js: session and presence requests get the device check's 403 code", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "relay-codes-"));
  const file = path.join(dir, "devices.json");
  fs.writeFileSync(file, JSON.stringify({ devices: [
    { id: "cam-off", secretSha256: sha("s-off"), disabled: true },
    { id: "cam-room", secretSha256: sha("s-room"), rooms: ["100"] },
  ] }));
  const port = await freePort();
  const child = spawn(process.execPath, ["server.js"], {
    cwd: path.join(__dirname, ".."),
    env: {
      PATH: process.env.PATH,
      PORT: String(port),
      RELAY_AUTH: "device",
      RELAY_DEVICES_FILE: file,
      ACCESS_KEY: "test-key",
      SECRET_ACCESS_KEY: "test-secret",
      SERVER_URL: "http://127.0.0.1:9",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  t.after(() => {
    child.kill();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("the relay did not start")), 10000);
    child.stdout.on("data", (c) => {
      if (String(c).includes("running on port")) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.on("exit", (code) => reject(new Error(`the relay exited ${code}`)));
  });

  const creds = (id, secret) => ({ "x-samvyo-device-id": id, authorization: `Bearer ${secret}` });
  const session = await post(port, { roomId: "100" }, creds("cam-off", "s-off"));
  assert.strictEqual(session.status, 403);
  assert.strictEqual(session.body.code, "CAMERA_DISABLED");

  const presence = await post(port, { peerId: "cam-off" }, creds("cam-off", "s-off"));
  assert.strictEqual(presence.status, 403);
  assert.strictEqual(presence.body.code, "CAMERA_DISABLED");

  const room = await post(port, { roomId: "200" }, creds("cam-room", "s-room"));
  assert.strictEqual(room.status, 403);
  assert.strictEqual(room.body.code, "DEVICE_ROOM_NOT_ALLOWED");

  const wrong = await post(port, { roomId: "100" }, creds("cam-off", "nope"));
  assert.strictEqual(wrong.status, 401);
  assert.strictEqual("code" in wrong.body, false);
});
