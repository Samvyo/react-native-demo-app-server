// P7 open items A5 — the relay forwards a presenter link (`presenterInvite`,
// from the meeting UI's `?pinv=`) to the app-server's session mint and passes
// the outcome back, like the room invite. Without it, an event room's
// presenters would all join as viewers through this relay.
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const SRC = fs.readFileSync(path.join(__dirname, "..", "server.js"), "utf8");

test("the mint request carries the presenter link when one was sent", () => {
  assert.match(SRC, /const \{[^}]*\bpresenterInvite\b[^}]*\} = req\.body;/);
  assert.match(SRC, /\.\.\.\(presenterInvite \? \{ presenterInvite \} : \{\}\)/);
});

test("the response passes back whether it was honoured, and why not", () => {
  assert.match(SRC, /presenterInviteAccepted: response\.data\.presenterInviteAccepted \?\? null/);
  assert.match(SRC, /presenterInviteRefusal: response\.data\.presenterInviteRefusal \?\? null/);
});
