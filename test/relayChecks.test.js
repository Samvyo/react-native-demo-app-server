"use strict";
// The built-in caller checks: RELAY_AUTH = jwt | device | custom. Run: npm test
const test = require("node:test");
const assert = require("node:assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const jwt = require("jsonwebtoken");
const { buildAuthenticator } = require("../relayChecks");
const { makeJwtCheck, jwtOptionsFromEnv, makeJwksStore } = require("../relayJwt");
const { makeDeviceCheck, makeDeviceStore, parseDevices, sha256 } = require("../relayDevices");
const { addDevice } = require("../scripts/add-device");
const { authenticateCaller } = require("../relayAuth");

const quiet = { warn() {}, info() {}, error() {} };
const SECRET = "a-shared-secret-of-at-least-32-characters!";
const tmpdir = () => fs.mkdtempSync(path.join(os.tmpdir(), "relay-test-"));
const req = ({ token, deviceId, body = {} } = {}) => ({
  headers: {
    ...(token ? { authorization: `Bearer ${token}` } : {}),
    ...(deviceId ? { "x-samvyo-device-id": deviceId } : {}),
  },
  body,
});
const hs = (claims, opts = {}) => jwt.sign(claims, SECRET, { expiresIn: 300, ...opts });
const jwtCheck = (env) => makeJwtCheck(jwtOptionsFromEnv({ RELAY_JWT_SECRET: SECRET, ...env }), { log: quiet });

// ─── jwt ─────────────────────────────────────────────────────────────────────

test("jwt: a valid token grants its role; no role claim grants participant", async () => {
  const check = jwtCheck({});
  assert.deepStrictEqual(await check(req({ token: hs({ samvyo_role: "moderator" }), body: { roomId: "1" } }), { kind: "session" }), {
    ok: true, participantType: "moderator",
  });
  assert.deepStrictEqual(await check(req({ token: hs({ sub: "u1" }), body: { roomId: "1" } }), { kind: "session" }), {
    ok: true, participantType: "participant",
  });
});

test("jwt: a role per room, with a fallback, and the deployer's own role names", async () => {
  const check = jwtCheck({ RELAY_JWT_ROLE_CLAIM: "app.roles", RELAY_JWT_ROLE_MAP: "host=moderator,member=participant" });
  const token = hs({ app: { roles: { 42: "host", "*": "member" } } });
  assert.strictEqual((await check(req({ token, body: { roomId: "42" } }), { kind: "session" })).participantType, "moderator");
  assert.strictEqual((await check(req({ token, body: { roomId: "7" } }), { kind: "session" })).participantType, "participant");
  const odd = await check(req({ token: hs({ app: { roles: "superuser" } }), body: { roomId: "7" } }), { kind: "session" });
  assert.deepStrictEqual([odd.ok, odd.status], [false, 403]);
});

test("jwt: refused when missing, forged, expired, without expiry, or for another audience", async () => {
  const check = jwtCheck({ RELAY_JWT_AUDIENCE: "samvyo-relay", RELAY_JWT_ISSUER: "https://login.example" });
  const good = { aud: "samvyo-relay", iss: "https://login.example" };
  assert.strictEqual((await check(req({ token: hs(good) }), { kind: "session" })).ok, true);
  const cases = [
    req(),
    req({ token: jwt.sign(good, "another-secret-another-secret-another!", { expiresIn: 300 }) }),
    req({ token: jwt.sign({ ...good, exp: Math.floor(Date.now() / 1000) - 3600 }, SECRET) }), // expired
    req({ token: jwt.sign(good, SECRET) }), // no exp
    req({ token: hs({ ...good, aud: "billing-api" }) }),
    req({ token: hs({ ...good, iss: "https://evil.example" }) }),
  ];
  for (const r of cases) {
    const out = await check(r, { kind: "session" });
    assert.deepStrictEqual([out.ok, out.status], [false, 401], JSON.stringify(r.headers));
  }
});

test("jwt: RELAY_JWT_ROOM_CLAIM binds a token to its rooms", async () => {
  const check = jwtCheck({ RELAY_JWT_ROOM_CLAIM: "rooms" });
  const token = hs({ rooms: ["11", 12], samvyo_role: "moderator" });
  assert.strictEqual((await check(req({ token, body: { roomId: "12" } }), { kind: "session" })).ok, true);
  const other = await check(req({ token, body: { roomId: "13" } }), { kind: "session" });
  assert.deepStrictEqual([other.ok, other.status], [false, 403]);
});

test("jwt: never mints a camera's presence token", async () => {
  const out = await jwtCheck({})(req({ token: hs({}), body: { peerId: "cam" } }), { kind: "presence" });
  assert.deepStrictEqual([out.ok, out.status], [false, 403]);
});

test("jwt: an RS256 public key, and an HS256 token signed with that public key is refused", async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const dir = tmpdir();
  const pem = path.join(dir, "pub.pem");
  fs.writeFileSync(pem, publicKey.export({ type: "spki", format: "pem" }));
  const check = makeJwtCheck(jwtOptionsFromEnv({ RELAY_JWT_PUBLIC_KEY_FILE: pem }), { log: quiet });
  const good = jwt.sign({ samvyo_role: "viewer" }, privateKey, { algorithm: "RS256", expiresIn: 300 });
  assert.deepStrictEqual(await check(req({ token: good }), { kind: "session" }), { ok: true, participantType: "viewer" });
  // Algorithm confusion: an attacker HMAC-signs with the (public) PEM text.
  const forged = jwt.sign({ samvyo_role: "moderator" }, crypto.createSecretKey(fs.readFileSync(pem)), { algorithm: "HS256", expiresIn: 300 });
  assert.strictEqual((await check(req({ token: forged }), { kind: "session" })).ok, false);
});

test("jwt: a JWKS is fetched once, cached, and refetched for an unknown kid (a key rotation)", async () => {
  const k1 = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const k2 = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = (k, kid) => ({ ...k.publicKey.export({ format: "jwk" }), kid, use: "sig" });
  let keys = [jwk(k1, "one")];
  let fetches = 0;
  let t = 1_000_000;
  const fetchJson = async () => {
    fetches++;
    return { keys };
  };
  const opts = jwtOptionsFromEnv({ RELAY_JWT_JWKS_URL: "https://login.example/.well-known/jwks.json" });
  const check = makeJwtCheck(opts, { fetchJson, log: quiet });
  const sign = (k, kid) => jwt.sign({}, k.privateKey, { algorithm: "ES256", keyid: kid, expiresIn: 300 });

  assert.strictEqual((await check(req({ token: sign(k1, "one") }), { kind: "session" })).ok, true);
  assert.strictEqual((await check(req({ token: sign(k1, "one") }), { kind: "session" })).ok, true);
  assert.strictEqual(fetches, 1, "cached");

  // The store on its own, with a clock, for the refetch rule.
  const store = makeJwksStore({ url: "u", cacheSec: 600, fetchJson, now: () => t });
  fetches = 0;
  assert.ok(await store("one"));
  keys = [jwk(k1, "one"), jwk(k2, "two")];
  assert.strictEqual(await store("two"), undefined, "no refetch within 30 s of the last one");
  t += 31000;
  assert.ok(await store("two"), "refetched for the new kid");
  assert.strictEqual(fetches, 2);
});

test("jwt: an unreachable JWKS with no keys yet is a 503, not a 401", async () => {
  const opts = jwtOptionsFromEnv({ RELAY_JWT_JWKS_URL: "https://login.example/jwks" });
  const check = makeJwtCheck(opts, { fetchJson: async () => { throw new Error("ECONNREFUSED"); }, log: quiet });
  const k = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const token = jwt.sign({}, k.privateKey, { algorithm: "ES256", keyid: "x", expiresIn: 300 });
  const out = await check(req({ token }), { kind: "session" });
  assert.deepStrictEqual([out.ok, out.status], [false, 503]);
});

test("jwt settings: one key source, a long secret, https JWKS, no mixed algorithms", () => {
  assert.throws(() => jwtOptionsFromEnv({}), /exactly one/);
  assert.throws(() => jwtOptionsFromEnv({ RELAY_JWT_SECRET: SECRET, RELAY_JWT_JWKS_URL: "https://x" }), /exactly one/);
  assert.throws(() => jwtOptionsFromEnv({ RELAY_JWT_SECRET: "short" }), /at least 32/);
  assert.throws(() => jwtOptionsFromEnv({ RELAY_JWT_JWKS_URL: "http://x/jwks" }), /https/);
  assert.throws(() => jwtOptionsFromEnv({ RELAY_JWT_JWKS_URL: "https://x", RELAY_JWT_ALGORITHMS: "RS256,HS256" }), /not allowed/);
  assert.throws(() => jwtOptionsFromEnv({ RELAY_JWT_SECRET: SECRET, RELAY_JWT_ROLE_MAP: "host=owner" }), /ROLE_MAP/);
  assert.throws(() => jwtOptionsFromEnv({ RELAY_JWT_SECRET: SECRET, RELAY_JWT_DEFAULT_ROLE: "moderator!" }), /DEFAULT_ROLE/);
});

// ─── device ──────────────────────────────────────────────────────────────────

const deviceFile = (devices) => {
  const f = path.join(tmpdir(), "devices.json");
  fs.writeFileSync(f, JSON.stringify({ devices }));
  return f;
};
const dev = (id, secret, extra = {}) => ({ id, secretSha256: sha256(secret).toString("hex"), ...extra });

test("device: the right secret grants participant; wrong, unknown and disabled get the same 401", async () => {
  const check = makeDeviceCheck({
    file: deviceFile([dev("cam-1", "s1"), dev("cam-off", "s2", { disabled: true })]),
    log: quiet,
  });
  assert.deepStrictEqual(await check(req({ deviceId: "cam-1", token: "s1", body: { roomId: "9" } }), { kind: "session" }), {
    ok: true, participantType: "participant",
  });
  const outs = [
    await check(req({ deviceId: "cam-1", token: "wrong", body: { roomId: "9" } }), { kind: "session" }),
    await check(req({ deviceId: "nobody", token: "s1", body: { roomId: "9" } }), { kind: "session" }),
    await check(req({ deviceId: "cam-off", token: "s2", body: { roomId: "9" } }), { kind: "session" }),
  ];
  for (const o of outs) assert.deepStrictEqual(o, { ok: false, status: 401, message: "Device credentials not accepted" });
  const none = await check(req({ deviceId: "cam-1", body: { roomId: "9" } }), { kind: "session" });
  assert.deepStrictEqual([none.ok, none.status], [false, 401]);
});

test("device: rooms limit sessions (403); presence only for its own camera id", async () => {
  const check = makeDeviceCheck({
    file: deviceFile([dev("cam-1", "s1", { rooms: ["100"] }), dev("cam-2", "s2", { peerIds: ["gate-a", "gate-b"] })]),
    log: quiet,
  });
  const s = (id, secret, body, kind) => check(req({ deviceId: id, token: secret, body }), { kind });
  assert.strictEqual((await s("cam-1", "s1", { roomId: "100" }, "session")).ok, true);
  assert.deepStrictEqual((await s("cam-1", "s1", { roomId: "101" }, "session")).status, 403);
  assert.strictEqual((await s("cam-1", "s1", { peerId: "cam-1" }, "presence")).ok, true, "default: its device id");
  assert.strictEqual((await s("cam-1", "s1", { peerId: "cam-2" }, "presence")).status, 403);
  assert.strictEqual((await s("cam-2", "s2", { peerId: "gate-b" }, "presence")).ok, true);
  assert.strictEqual((await s("cam-2", "s2", { peerId: "cam-2" }, "presence")).status, 403);
});

test("device list: re-read when it changes; a broken edit keeps the last good list", async () => {
  const file = deviceFile([dev("cam-1", "s1")]);
  let t = 0;
  const store = makeDeviceStore({ file, now: () => t, log: quiet });
  assert.deepStrictEqual([...store().keys()], ["cam-1"]);
  fs.writeFileSync(file, JSON.stringify({ devices: [dev("cam-1", "s1"), dev("cam-2", "s2")] }));
  fs.utimesSync(file, new Date(), new Date(Date.now() + 5000));
  assert.strictEqual(store().size, 1, "not looked at again within 5 s");
  t += 5000;
  assert.strictEqual(store().size, 2);
  fs.writeFileSync(file, "{ not json");
  fs.utimesSync(file, new Date(), new Date(Date.now() + 10000));
  t += 5000;
  assert.strictEqual(store().size, 2);
});

test("device list: a bad list is refused with the reason", () => {
  assert.throws(() => parseDevices("[]"), /devices/);
  assert.throws(() => parseDevices(JSON.stringify({ devices: [{ id: "a", secretSha256: "abc" }] })), /64 hex/);
  assert.throws(() => parseDevices(JSON.stringify({ devices: [dev("a", "x"), dev("a", "y")] })), /twice/);
  assert.throws(() => parseDevices(JSON.stringify({ devices: [dev("a", "x", { rooms: "100" })] })), /rooms must be a list/);
});

test("add-device: the secret goes to a 0600 file, only its hash to the list, and it works", async () => {
  const dir = tmpdir();
  const file = path.join(dir, "devices.json");
  const out = path.join(dir, "cam.secret");
  addDevice({ id: "lobby-cam-1", secretOut: out, file, rooms: ["555"] });
  const secret = fs.readFileSync(out, "utf8");
  assert.ok(secret.length >= 43);
  assert.strictEqual(fs.statSync(out).mode & 0o777, 0o600);
  assert.ok(!fs.readFileSync(file, "utf8").includes(secret), "the list never holds the secret");

  const check = makeDeviceCheck({ file, log: quiet });
  assert.strictEqual((await check(req({ deviceId: "lobby-cam-1", token: secret, body: { roomId: "555" } }), { kind: "session" })).ok, true);

  assert.throws(() => addDevice({ id: "lobby-cam-1", secretOut: path.join(dir, "b"), file }), /--rotate/);
  assert.throws(() => addDevice({ id: "lobby-cam-1", secretOut: out, file, rotate: true }), /not overwriting/);
  addDevice({ id: "lobby-cam-1", secretOut: path.join(dir, "new.secret"), file, rotate: true });
  const doc = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.deepStrictEqual(doc.devices[0].rooms, ["555"], "a rotation keeps the rooms");
  assert.notStrictEqual(doc.devices[0].secretSha256, sha256(secret).toString("hex"), "the old secret stops working");
  assert.throws(() => addDevice({ id: "x", file }), /secret-out/);
  assert.throws(() => addDevice({ id: "bad id!", secretOut: path.join(dir, "c"), file }), /--id/);
});

// ─── RELAY_AUTH ──────────────────────────────────────────────────────────────

test("RELAY_AUTH unset is custom: relayAuth.js, which refuses until written", async () => {
  const { authenticate, summary } = buildAuthenticator({}, { authenticateCaller, log: quiet });
  assert.strictEqual(summary, "custom (relayAuth.js)");
  const out = await authenticate(req({ token: "x", body: { roomId: "1" } }), { kind: "session" });
  assert.deepStrictEqual([out.ok, out.status], [false, 401]);
  assert.match(out.message, /relayAuth\.js/);
});

test("RELAY_AUTH=device,jwt: the device header goes to the device list, a bearer token to jwt", async () => {
  const file = deviceFile([dev("cam-1", "s1")]);
  const { authenticate, summary } = buildAuthenticator(
    { RELAY_AUTH: "device,jwt", RELAY_DEVICES_FILE: file, RELAY_JWT_SECRET: SECRET },
    { authenticateCaller, log: quiet }
  );
  assert.match(summary, /device \(1 in .*\), jwt \(shared secret\)/);
  assert.strictEqual((await authenticate(req({ deviceId: "cam-1", token: "s1", body: { roomId: "1" } }), { kind: "session" })).ok, true);
  assert.strictEqual((await authenticate(req({ token: hs({ samvyo_role: "moderator" }), body: { roomId: "1" } }), { kind: "session" })).participantType, "moderator");
  // A device secret is not a JWT, and a JWT with a device header is not a device.
  assert.strictEqual((await authenticate(req({ deviceId: "cam-1", token: hs({}), body: { roomId: "1" } }), { kind: "session" })).ok, false);
  assert.strictEqual((await authenticate(req({ body: { roomId: "1" } }), { kind: "session" })).status, 401);
});

test("RELAY_AUTH=jwt alone refuses a device; RELAY_AUTH=jwt,custom sends a request without a token to custom", async () => {
  const jwtOnly = buildAuthenticator({ RELAY_AUTH: "jwt", RELAY_JWT_SECRET: SECRET }, { authenticateCaller, log: quiet });
  const d = await jwtOnly.authenticate(req({ deviceId: "cam-1", token: "s1" }), { kind: "session" });
  assert.deepStrictEqual([d.ok, d.status], [false, 401]);
  assert.match(d.message, /device credentials/);

  const custom = async () => ({ ok: true, participantType: "viewer" });
  const both = buildAuthenticator({ RELAY_AUTH: "jwt,custom", RELAY_JWT_SECRET: SECRET }, { authenticateCaller: custom, log: quiet });
  assert.deepStrictEqual(await both.authenticate(req({ body: { roomId: "1" } }), { kind: "session" }), { ok: true, participantType: "viewer" });
  const badJwt = await both.authenticate(req({ token: "not-a-jwt", body: { roomId: "1" } }), { kind: "session" });
  assert.strictEqual(badJwt.ok, false, "a refused token is not passed on to custom");
});

test("RELAY_AUTH misconfigurations stop the relay at startup", () => {
  const b = (env) => buildAuthenticator(env, { authenticateCaller, log: quiet });
  assert.throws(() => b({ RELAY_AUTH: "ldap" }), /unknown/);
  assert.throws(() => b({ RELAY_AUTH: "device" }), /RELAY_DEVICES_FILE/);
  assert.throws(() => b({ RELAY_AUTH: "device", RELAY_DEVICES_FILE: "/nonexistent/devices.json" }), /RELAY_DEVICES_FILE/);
  assert.throws(() => b({ RELAY_AUTH: "jwt" }), /exactly one/);
});

test("jwt warnings: no audience, no room binding", () => {
  const { warnings } = buildAuthenticator({ RELAY_AUTH: "jwt", RELAY_JWT_SECRET: SECRET }, { authenticateCaller, log: quiet });
  assert.ok(warnings.some((w) => /AUDIENCE/.test(w)));
  assert.ok(warnings.some((w) => /ROOM_CLAIM/.test(w)));
  const bound = buildAuthenticator(
    { RELAY_AUTH: "jwt", RELAY_JWT_SECRET: SECRET, RELAY_JWT_AUDIENCE: "relay", RELAY_JWT_ROOM_CLAIM: "rooms" },
    { authenticateCaller, log: quiet }
  );
  assert.deepStrictEqual(bound.warnings, []);
});
