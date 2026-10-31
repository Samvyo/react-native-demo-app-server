# Samvyo token relay (reference)

A small server that mints Samvyo session tokens for your apps and devices. It
holds your organisation's **access key and secret**; your browsers, mobile apps
and cameras never do. They call this relay, the relay checks who they are, adds
the key, and asks Samvyo for a session token.

You run it. Whoever can make it mint can join your rooms with your key and
draw your credit, so treat it like any other server that holds a credential.

```
app / camera ──POST /api/create-session-token {roomId}──▶ relay (holds the key) ──▶ Samvyo app-server
             ◀──────────────── session token ────────────┘
```

## Endpoint

`POST /api/create-session-token`

| Body | Mints |
|---|---|
| `{ roomId }` | a session token with your access key (SDK mode) |
| `{ roomId, uuid, sdkMode: false, invite? }` | a dashboard-room session (no access key; the room link's own rules, its password, and room invite links apply) |
| `{ peerId }` | a camera's direct-view presence token, with your access key |

## Before you deploy: decide who may use the key

Every request that would use the access key is **refused (401)** until you
implement `authenticateCaller` in [relayAuth.js](relayAuth.js). Fill it in with
your own check and return the role to grant:

- **Your web or mobile app:** verify your own sign-in (session cookie, the JWT
  your app issued), and grant the role the user has in that room —
  `{ ok: true, participantType: "moderator" }` for a host, `"participant"` for
  everyone else. The autoscaler refuses a join above the granted role, so a
  caller cannot make itself a moderator.
- **A camera or other device:** verify a per-device credential you provisioned
  when you installed it, and grant `"participant"`.

A session minted with your access key is trusted the way your backend is: it is
**not** asked for a dashboard room's password. That is why the relay must know
its callers.

For a local bench only, `RELAY_ALLOW_ANONYMOUS=true` skips the check (and
forwards the role the caller asks for). The relay warns at startup when it is
set. Never set it on a deployment anyone else can reach.

## Settings

| Variable | Default | Purpose |
|---|---|---|
| `SERVER_URL` | — | the Samvyo app-server |
| `ACCESS_KEY`, `SECRET_ACCESS_KEY` | — | your org's API key; keep them in your secret store |
| `RELAY_ALLOWED_ORIGINS` | any | browser origins allowed to call the relay (your meeting UI), comma-separated |
| `RELAY_RATE_LIMIT_PER_MIN` | 60 | token requests per caller address per minute; 0 = no limit |
| `RELAY_TRUST_PROXY` | unset | express `trust proxy`, so the caller's address is seen behind a load balancer |
| `RELAY_ALLOW_ANONYMOUS` | false | local bench only — see above |
| `CERT_DIR` | unset | serve HTTPS from `server.key` + `server.crt`; unset = HTTP behind your TLS terminator |

See [.env.sample](.env.sample).

## Protect the key itself

Set these on the key's scopes. The dashboard (Settings → API keys) sets the SDK
types; the IP allowlist and the mint limit are set, for now, with
`PATCH /api/siteSetting/apiKeys/scopes` as an org admin
(`{ id, scopes: { ipAllowlist: [...], rateLimit: { sessionMintsPerMinute: N } } }`);
editing a key in the dashboard keeps them.

- **IP allowlist:** the relay's outbound address(es). A copied key then mints
  nowhere else.
- **Separate keys for separate callers:** one key for cameras, restricted to
  the C++ SDK (`sdkTypes: ["cpp"]`), and one for your web/mobile apps. A leak
  of one does not expose the other, and you can rotate each on its own.
- **Mint rate limit:** Samvyo limits each key to 120 session mints a minute by
  default and refuses above it (429, `SESSION_MINT_RATE_LIMITED`). Set
  `rateLimit.sessionMintsPerMinute` on a key that needs more — or less.
- **Expiry and rotation:** give keys an expiry and rotate them; a rotated key
  stops minting at once.

## Tests

```
npm test
```
