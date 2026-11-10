// Calls from this relay to the Samvyo app-server (SERVER_URL), with a time limit.
//
// A C++ camera gives up on its token URL after 10 s in total and retries. Without
// a limit here, an app-server that stopped answering kept every one of those
// requests open on the relay, one more per retry, and the camera only ever saw
// silence. With it, the relay answers before the camera gives up: 504, which the
// camera retries like any 5xx, and the request is closed.
//
// RELAY_UPSTREAM_TIMEOUT_MS: the whole request, connecting included. Keep it under
// the camera's 10 s so the camera hears the relay's answer. 0 = no limit.
const axios = require("axios");

const DEFAULT_TIMEOUT_MS = 8000;

function timeoutFrom(env) {
  const raw = env.RELAY_UPSTREAM_TIMEOUT_MS;
  if (raw === undefined || raw === "") return DEFAULT_TIMEOUT_MS;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 0) throw new Error(`RELAY_UPSTREAM_TIMEOUT_MS must be a whole number of ms, 0 or more (got "${raw}")`);
  return n;
}

// axios's `timeout` is an idle timer on the socket: an app-server that sends a
// byte now and then never trips it. The AbortSignal bounds the whole request,
// connect included; the idle timer stays as a second net.
function makeUpstream(timeoutMs) {
  const client = axios.create(timeoutMs > 0 ? { timeout: timeoutMs } : {});
  return {
    timeoutMs,
    post(url, body, opts = {}) {
      if (!(timeoutMs > 0)) return client.post(url, body, opts);
      return client.post(url, body, { ...opts, signal: AbortSignal.timeout(timeoutMs) });
    },
  };
}

// The app-server did not answer within the limit (not: it answered with an error).
function isTimeout(err) {
  if (!err || err.response) return false;
  return err.code === "ECONNABORTED" || err.code === "ETIMEDOUT" || err.code === "ERR_CANCELED" ||
    err.name === "CanceledError" || err.name === "AbortError" || err.name === "TimeoutError";
}

module.exports = { DEFAULT_TIMEOUT_MS, timeoutFrom, makeUpstream, isTimeout };
