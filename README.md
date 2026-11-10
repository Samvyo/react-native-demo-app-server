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
choose who may make it. Set `RELAY_AUTH` to one or more of:

| `RELAY_AUTH` | For | The caller sends |
|---|---|---|
| `device` | cameras and other devices | `X-Samvyo-Device-Id: <id>` and `Authorization: Bearer <its secret>` |
| `jwt` | your web and mobile apps' users | `Authorization: Bearer <a token your sign-in issued>` |
| `custom` (default) | anything else | whatever your code in [relayAuth.js](relayAuth.js) checks |

With several (`RELAY_AUTH=device,jwt`), a request with `X-Samvyo-Device-Id`
goes to `device`, one with a bearer token to `jwt`, anything else to `custom`.
A refusal is final; a request is not tried against the next check.

The relay checks its settings at startup and refuses to start with a broken
one, so a mistake shows up when you deploy rather than at the first camera.

A session minted with your access key is trusted the way your backend is: it is
**not** asked for a dashboard room's password. That is why the relay must know
its callers.

### Cameras: `RELAY_AUTH=device`

Each camera has its own id and secret. **The device id is the camera's
`PEER_ID`**: the id it joins rooms and registers presence with.

Make the secret on the camera's own box, so it never leaves it, and give the
relay only its SHA-256. On the gateway (any machine with OpenSSL):

```
umask 077
openssl rand 32 | openssl base64 -A | tr '+/' '-_' | tr -d '=' > /etc/samvyo/lobby-cam-1.secret
tr -d '\n' < /etc/samvyo/lobby-cam-1.secret | openssl dgst -sha256 -r | cut -d' ' -f1
```

That file is the camera's `DEVICE_SECRET_FILE`; the second line prints the hash.
On the relay host:

```
RELAY_DEVICES_FILE=/etc/samvyo-relay/devices.json \
  npm run add-device -- --id lobby-cam-1 --sha256 <the 64-character hash> --room 1234567890
```

For a gateway where you cannot run that, `--secret-out ./lobby-cam-1.secret`
instead of `--sha256` generates the secret on the relay host and writes it to
that file (mode 0600); copy it to the camera and delete it here. Either way the
device list keeps only the hash, and no secret is ever printed. The camera sends
its id and secret on every request, over HTTPS, and is granted `participant`.

- `--room` (repeatable) limits the camera to those rooms; another room gets a
  403. Leave it out to allow any room.
- A camera's direct-view presence token is minted only for its own id, its
  `PEER_ID`. (A device list from before this may carry a `peerIds` field: it is
  ignored, and the relay warns about it at startup.)
- `--rotate` gives an existing camera a new secret (or hash); the old one stops
  working. To take a camera out of service, set `"disabled": true` on it in the
  list.
- The relay re-reads the list within seconds of a change: no restart.

An unknown device and a wrong secret get the same 401, so the answer does not
reveal which ids exist. A disabled camera that sends its own correct secret gets
403 with the code `CAMERA_DISABLED`: it keeps retrying slowly and comes back by
itself once you remove the flag.

**A camera on a relay is still registered with Samvyo.** Every camera that
publishes into a surveillance room must be on your organisation's camera list,
whatever minted its token. A relay camera joins with your access key, so it is
added to that list automatically at its first join, up to your plan's camera
limit. If your organisation allows only cameras added in advance ("Only cameras
added here or through the API may join"), add it first: on the dashboard's
Cameras page, or with `POST /api/v1/cameras` using an API key with the `cameras`
access. Use the same `PEER_ID` there as here.

### Your apps' users: `RELAY_AUTH=jwt`

Your app sends the token your sign-in already issues, or a short-lived one your
backend issues for joining a room. The relay verifies it with exactly one of:

- `RELAY_JWT_JWKS_URL`: your identity provider's key set (Auth0, Cognito,
  Keycloak, Firebase and so on), fetched over HTTPS and cached;
- `RELAY_JWT_PUBLIC_KEY_FILE`: a PEM public key (RS256, PS256 or ES256);
- `RELAY_JWT_SECRET`: a shared HS256 secret of at least 32 characters.

The token must carry an expiry. Set `RELAY_JWT_AUDIENCE` and
`RELAY_JWT_ISSUER`, or a token your sign-in issued for any other service works
here too. The relay warns at startup when they are unset.

**The role** comes from a claim (`RELAY_JWT_ROLE_CLAIM`, default `samvyo_role`;
a dotted path such as `app_metadata.samvyo_role` works too):

- a string is the role in every room: `"participant"`;
- an object gives it per room: `{ "1234567890": "moderator", "*": "participant" }`.

`RELAY_JWT_ROLE_MAP=host=moderator,member=participant` maps your own role
names. A token with no role gets `RELAY_JWT_DEFAULT_ROLE` (`participant`). The
autoscaler refuses a join above the granted role, so a caller cannot make
itself a moderator.

**Bind tokens to rooms** with `RELAY_JWT_ROOM_CLAIM`: the claim (a room id or a
list of them) must name the room asked for, or the request gets a 403. Without
it, a token is good for every room, so a string `"moderator"` role is a
moderator everywhere; the relay warns about this at startup.

A JWT caller never gets a camera's presence token: that takes a device
credential.

### Anything else: `RELAY_AUTH=custom`

Write `authenticateCaller` in [relayAuth.js](relayAuth.js): check the request
your way and return `{ ok: true, participantType }` or a refusal. It can sit
beside the built-in checks (`RELAY_AUTH=device,custom`).

### A local bench

`RELAY_ALLOW_ANONYMOUS=true` skips every check and forwards the role the caller
asks for. The relay warns at startup when it is set. Never set it on a
deployment anyone else can reach.

## Settings

| Variable | Default | Purpose |
|---|---|---|
| `SERVER_URL` | — | the Samvyo app-server |
| `ACCESS_KEY`, `SECRET_ACCESS_KEY` | — | your org's API key; keep them in your secret store |
| `RELAY_AUTH` | `custom` | who may use the key: `device`, `jwt`, `custom`, comma-separated |
| `RELAY_DEVICES_FILE` | — | the device list, for `device` |
| `RELAY_JWT_JWKS_URL` / `RELAY_JWT_PUBLIC_KEY_FILE` / `RELAY_JWT_SECRET` | — | what verifies a token, for `jwt` (exactly one) |
| `RELAY_JWT_ISSUER`, `RELAY_JWT_AUDIENCE` | unset | checked when set; set them |
| `RELAY_JWT_ROLE_CLAIM` | `samvyo_role` | the claim with the role |
| `RELAY_JWT_ROLE_MAP` | — | your role names → `moderator` / `participant` / `viewer` |
| `RELAY_JWT_DEFAULT_ROLE` | `participant` | the role when the token has none |
| `RELAY_JWT_ROOM_CLAIM` | unset | the claim listing the rooms a token is good for |
| `RELAY_JWT_ALGORITHMS` | `HS256`, or `RS256,PS256,ES256` | accepted algorithms; never a mix of HMAC and public-key |
| `RELAY_JWT_CLOCK_TOLERANCE_SEC` | 30 | allowed clock difference on expiry |
| `RELAY_JWT_JWKS_CACHE_SEC` | 600 | how long a fetched key set is used |
| `RELAY_ALLOWED_ORIGINS` | any | browser origins allowed to call the relay (your meeting UI), comma-separated |
| `RELAY_RATE_LIMIT_PER_MIN` | 60 | token requests per caller address per minute; 0 = no limit |
| `RELAY_TRUST_PROXY` | unset | express `trust proxy`, so the caller's address is seen behind a load balancer |
| `RELAY_UPSTREAM_TIMEOUT_MS` | 8000 | the time limit on each call to the app-server, connecting included; the relay answers 504 when it runs out. Keep it under 10000: a camera gives up on the relay after 10 s. 0 = no limit |
| `RELAY_ALLOW_ANONYMOUS` | false | local bench only — see above |
| `CERT_DIR` | unset | serve HTTPS from `server.key` + `server.crt`; unset = HTTP behind your TLS terminator |

See [.env.sample](.env.sample).

## Protect the key itself

Set these on the key in the Samvyo dashboard (Settings → API keys → edit access
scope):

- **Allowed IP addresses:** the relay's outbound address(es). A copied key then
  mints nowhere else.
- **Separate keys for separate callers:** one key for cameras, restricted to
  the C++ SDK, and one for your web/mobile apps. A leak of one does not expose
  the other, and you can rotate each on its own.
- **Session mints per minute:** Samvyo refuses mints above it (429,
  `SESSION_MINT_RATE_LIMITED`). Each key gets the deployment's default (shown
  on the page) unless you set its own.
- **Expiry and rotation:** give keys an expiry and rotate them; a rotated key
  stops minting at once.

## Tests

```
npm test
```
