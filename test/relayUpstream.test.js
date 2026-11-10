// N230 follow-up — every call from the relay to the app-server has a time limit,
// under the camera's own 10 s, and a timeout answers 504 (the camera retries a
// 5xx) rather than holding the camera's request open.
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { DEFAULT_TIMEOUT_MS, timeoutFrom, makeUpstream, isTimeout } = require("../relayUpstream");

const SRC = fs.readFileSync(path.join(__dirname, "..", "server.js"), "utf8");

// A server that accepts the request and never answers, or drips a byte now and then.
function stalled({ drip } = {}) {
  const sockets = new Set();
  const server = http.createServer((req, res) => {
    if (drip) {
      res.writeHead(200, { "content-type": "application/json" });
      const t = setInterval(() => res.write(" "), drip);
      res.on("close", () => clearInterval(t));
    }
  });
  server.on("connection", (s) => { sockets.add(s); s.on("close", () => sockets.delete(s)); });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({
    url: `http://127.0.0.1:${server.address().port}/api/x`,
    close: () => { for (const s of sockets) s.destroy(); server.close(); },
  })));
}

test("the default is under the camera's 10 s", () => {
  assert.strictEqual(timeoutFrom({}), DEFAULT_TIMEOUT_MS);
  assert.ok(DEFAULT_TIMEOUT_MS > 0 && DEFAULT_TIMEOUT_MS < 10000);
  assert.strictEqual(timeoutFrom({ RELAY_UPSTREAM_TIMEOUT_MS: "3000" }), 3000);
  assert.strictEqual(timeoutFrom({ RELAY_UPSTREAM_TIMEOUT_MS: "0" }), 0);
  assert.throws(() => timeoutFrom({ RELAY_UPSTREAM_TIMEOUT_MS: "soon" }), /RELAY_UPSTREAM_TIMEOUT_MS/);
  assert.throws(() => timeoutFrom({ RELAY_UPSTREAM_TIMEOUT_MS: "-1" }), /RELAY_UPSTREAM_TIMEOUT_MS/);
});

test("an app-server that never answers is given up on at the limit", async () => {
  const s = await stalled();
  const t0 = Date.now();
  try {
    await assert.rejects(makeUpstream(300).post(s.url, {}, { validateStatus: () => true }), (e) => isTimeout(e));
    const took = Date.now() - t0;
    assert.ok(took >= 250 && took < 1500, `gave up after ${took} ms`);
  } finally { s.close(); }
});

test("one that sends a byte now and then is given up on too (the whole request is bounded)", async () => {
  const s = await stalled({ drip: 50 });
  const t0 = Date.now();
  try {
    await assert.rejects(makeUpstream(400).post(s.url, {}), (e) => isTimeout(e));
    assert.ok(Date.now() - t0 < 1500);
  } finally { s.close(); }
});

test("an answer, an error answer and a refused connection are not timeouts", async () => {
  const server = http.createServer((req, res) => { res.writeHead(503); res.end("{}"); });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}/api/x`;
  try {
    const r = await makeUpstream(1000).post(url, {}, { validateStatus: () => true });
    assert.strictEqual(r.status, 503);
    await assert.rejects(makeUpstream(1000).post(url, {}), (e) => !isTimeout(e) && e.response.status === 503);
  } finally { server.close(); }
  await assert.rejects(makeUpstream(1000).post(url, {}), (e) => !isTimeout(e));
});

test("server.js sends every app-server call through the limit and answers a timeout 504", () => {
  const live = SRC.split("\n").filter((l) => !/^\s*\/\//.test(l)).join("\n");
  assert.doesNotMatch(live, /axios\.(post|get|put|request)\(/);
  assert.strictEqual((live.match(/await upstream\.post\(/g) || []).length, 4);
  assert.strictEqual((live.match(/if \(isTimeout\(error\)\)/g) || []).length, 2);
  assert.strictEqual((live.match(/status\(504\)/g) || []).length, 2);
});

test("a failed mint is logged without the request (it carries the secret access key)", () => {
  const live = SRC.split("\n").filter((l) => !/^\s*\/\//.test(l)).join("\n");
  assert.doesNotMatch(live, /console\.(error|log|warn)\([^)]*,\s*(error|err|e)\s*\)/);
});
