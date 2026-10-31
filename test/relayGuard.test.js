"use strict";
// The relay's guards (relayGuard.js + relayAuth.js). Run: npm test
const test = require("node:test");
const assert = require("node:assert");
const { resolveCaller, makeRateLimiter, corsOriginsFrom } = require("../relayGuard");
const { authenticateCaller } = require("../relayAuth");

test("out of the box, every access-key caller is refused", async () => {
  const r = await resolveCaller({ req: { body: { roomId: "1" } }, kind: "session", allowAnonymous: false, authenticateCaller });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.status, 401);
  assert.match(r.message, /relayAuth\.js/);
  const p = await resolveCaller({ req: { body: { peerId: "cam" } }, kind: "presence", allowAnonymous: false, authenticateCaller });
  assert.strictEqual(p.ok, false);
});

test("an accepting hook grants ITS role, never the one the caller asked for", async () => {
  const hook = async () => ({ ok: true, participantType: "participant" });
  const r = await resolveCaller({ req: { body: { participantType: "moderator" } }, kind: "session", allowAnonymous: false, authenticateCaller: hook });
  assert.deepStrictEqual(r, { ok: true, participantType: "participant" });
  const none = await resolveCaller({ req: { body: { participantType: "moderator" } }, kind: "session", allowAnonymous: false, authenticateCaller: async () => ({ ok: true }) });
  assert.deepStrictEqual(none, { ok: true });
});

test("a refusing or throwing hook refuses", async () => {
  const r = await resolveCaller({ req: {}, kind: "session", allowAnonymous: false, authenticateCaller: async () => ({ ok: false, status: 403, message: "no" }) });
  assert.deepStrictEqual(r, { ok: false, status: 403, message: "no" });
  const t = await resolveCaller({ req: {}, kind: "session", allowAnonymous: false, authenticateCaller: async () => { throw new Error("db down"); } });
  assert.strictEqual(t.ok, false);
  assert.strictEqual(t.status, 500);
});

test("bench anonymous mode admits and forwards the caller's own role", async () => {
  const r = await resolveCaller({ req: { body: { participantType: "moderator" } }, kind: "session", allowAnonymous: true, authenticateCaller });
  assert.deepStrictEqual(r, { ok: true, anonymous: true, participantType: "moderator" });
});

test("the rate limiter allows N per minute per address, then refuses until the minute turns", () => {
  let t = 5000;
  const hit = makeRateLimiter({ perMinute: 2, now: () => t });
  assert.ok(hit("a").allowed);
  assert.ok(hit("a").allowed);
  const third = hit("a");
  assert.strictEqual(third.allowed, false);
  assert.strictEqual(third.retryAfterSec, 55);
  assert.ok(hit("b").allowed, "another address has its own count");
  t = 61000;
  assert.ok(hit("a").allowed);
  assert.ok(makeRateLimiter({ perMinute: 0 })("x").allowed, "0 = no limit");
});

test("RELAY_ALLOWED_ORIGINS: a list, or any origin when unset", () => {
  assert.deepStrictEqual(corsOriginsFrom("https://a.example, https://b.example"), ["https://a.example", "https://b.example"]);
  assert.strictEqual(corsOriginsFrom(""), true);
  assert.strictEqual(corsOriginsFrom(undefined), true);
});
