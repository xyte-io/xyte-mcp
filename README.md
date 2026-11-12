# xyte-mcp

An [MCP](https://modelcontextprotocol.io) server for the [Xyte](https://www.xyte.io) platform
API. It gives an AI agent typed, validated access to the public Xyte REST API — endpoint
discovery plus a generic call tool — over stdio locally, or over Streamable HTTP as a
remote server.

Reads and writes are both available by default; `XYTE_MCP_READ_ONLY=1` makes it a
read-only server.

Xyte is a device management platform: connected device fleets, the spaces they live in,
their telemetry and incidents, service tickets, commands, models and warranties. This server
puts that API in front of an agent as three tools instead of 78 hand-written ones — it can
discover the right endpoint, read its exact contract, and call it with arguments validated
against that contract before a request goes out.

Useful for asking an agent to investigate a fleet ("which devices in the Tel Aviv office
went offline this week, and what do their open tickets say"), to script routine operations,
or to work against the Xyte API without you writing the client.

By default it runs locally as a subprocess of your MCP host and talks to `hub.xyte.io`
directly — nothing to deploy and no third party in the path. `--http` serves the same tools
over the network for clients that only support remote servers; see
[Remote HTTP transport](#remote-http-transport).

## Install

```bash
# In an MCP host, e.g. Claude Code:
claude mcp add xyte -e XYTE_ORG_API_KEY=<your-key> -- npx -y @xyteai/mcp
```

Or configure a host directly:

```jsonc
{
  "command": "npx",
  "args": ["-y", "@xyteai/mcp"],
  "env": { "XYTE_ORG_API_KEY": "<your-key>" }
}
```

Requires Node.js 22 or newer.

MCP servers are loaded when a session starts, so restart your host — or open a new session —
after adding it.

## Getting an API key

Create one in the Xyte portal under **Settings → API Keys**; see
[Core API Keys](https://docs.xyte.io/reference/core-api-keys) for the walkthrough. An
organization key acts as that organization, a partner key as the partner — set whichever
scopes you need, or both.

The key is all the tenancy there is: it is bound to its tenant server-side, so there is no
tenant or URL to configure.

## Documentation

| | |
| --- | --- |
| [docs.xyte.io](https://docs.xyte.io) | Platform documentation — concepts, portal guides, how the pieces fit together. |
| [API reference](https://docs.xyte.io/reference) | The REST API this server wraps: authentication, pagination, every endpoint. |
| [llms.txt](https://docs.xyte.io/llms.txt) | The whole documentation set as Markdown, plus the endpoints as OpenAPI — written for agents. Worth pointing your agent at alongside this server. |
| [github.com/xyte-io/xyte-mcp](https://github.com/xyte-io/xyte-mcp) | This server's source, issues and releases. |

Everything below is about running the server itself.

## Configuration

| Variable | Purpose |
| --- | --- |
| `XYTE_ORG_API_KEY` | Organization-scoped API key. |
| `XYTE_PARTNER_API_KEY` | Partner-scoped API key. Set either or both. |
| `XYTE_MCP_READ_ONLY` | Set to `1` to refuse every mutating endpoint. Writes are permitted by default. |
| `XYTE_HUB_URL` | Override the hub base URL. Defaults to `https://hub.xyte.io`. |
| `XYTE_ENTRY_URL` | Override the entry base URL. |
| `XYTE_MCP_TIMEOUT_MS` | Per-request timeout. Defaults to `15000`. |
| `XYTE_MCP_HTTP_TOKEN` | **`--http` only.** Static bearer fronting the process API key (dev/CI). At least one of this and `XYTE_MCP_ISSUER_URL` is required. |
| `XYTE_MCP_ISSUER_URL` | **`--http` only.** This deployment's public https URL; setting it enables OAuth 2.1. |
| `XYTE_MCP_HUB_OAUTH_CLIENT_ID` | **`--http` + OAuth, required.** This server's client id at hub's OAuth server — see [OAuth 2.1](#oauth-21) for registering it. |
| `XYTE_MCP_HUB_OAUTH_CLIENT_SECRET` | **`--http` + OAuth, required.** The matching client secret (sent as `client_secret_basic`). |
| `DATABASE_URL` | **`--http` + OAuth only.** Postgres DSN for the token store; set by the Heroku Postgres add-on. Absent → in-memory, tokens die with the process. |
| `PORT` | **`--http` only.** Port to listen on. Defaults to `3000`; set by the platform on Heroku. |

`XYTE_HUB_URL`, `XYTE_ENTRY_URL` and `XYTE_MCP_TIMEOUT_MS` are escape hatches for
non-production hubs; the defaults are what you want.

`XYTE_MCP_ALLOW_WRITES` from 0.1.x is still honoured with its original meaning: if it is set
at all, it decides, so a server pinned shut with `XYTE_MCP_ALLOW_WRITES=0` stays shut across
the upgrade. Where the two disagree, the restrictive one wins. New configuration should use
`XYTE_MCP_READ_ONLY`.

## Tools

| Tool | What it does |
| --- | --- |
| `xyte_endpoints_list` | Discover endpoints. Filter by `namespace`, `group`, `method`, `search`, `readOnly`. Returns compact rows. |
| `xyte_endpoint_describe` | Full contract for one endpoint: path params, query params, body shape, required credential. |
| `xyte_api_call` | Invoke an endpoint by key with `path`, `query` and `body`. |

The intended sequence is list → describe → call. Endpoint keys are stable identifiers such
as `organization.devices.getDevices`; the server rejects unknown keys with suggestions
rather than guessing.

Arguments are validated against the endpoint spec before any request is sent, so a wrong
parameter name produces a precise message instead of an opaque HTTP 4xx.

## Write policy

- **Default:** `GET`/`HEAD`/`POST`/`PUT`/`PATCH` are all permitted.
- **`DELETE`:** additionally requires `confirm` set to the endpoint key verbatim. This holds
  even with writes enabled — an irreversible call is the one that cannot be walked back.
- **`XYTE_MCP_READ_ONLY=1`:** only `GET`/`HEAD` can be called. Anything else is refused
  before a request is built, and the model is told an operator alone can lift it.

`xyte_api_call`'s MCP annotations (`readOnlyHint`, `destructiveHint`) follow the live
configuration, so a host prompts according to what the server can actually do.

**Worth knowing before you point it at a live fleet.** The caller is a model, and read tools
return content a third party can influence — device names, ticket bodies, notes. Nothing
stops a model from treating text it just read as an instruction, so the server tells it
outright that fleet content is untrusted and that mutating intent must come from you. That is
a mitigation, not a guarantee. Prefer read-only when the agent runs unattended, when it is
working through content you do not control, or when you simply want to look around:

```bash
claude mcp add xyte-ro -e XYTE_ORG_API_KEY=<key> -e XYTE_MCP_READ_ONLY=1 -- npx -y @xyteai/mcp
```

Both can coexist — register a read-only server for exploration and a writable one for the
sessions where you want changes to land.

API keys are never echoed back: output is filtered both by field name (`api_key`, `token`,
`authorization`, …) and by literal secret value.

## The endpoint catalog

`src/catalog/endpoints.generated.json` holds 78 endpoints (64 organization, 14 partner). It
is **generated** from hub's Bruno collection — `hub/docs/api/Xyte Public/` — which is the
upstream source the [public API reference](https://docs.xyte.io/reference) is built from, and
committed so this repo has no dependency on a hub checkout at runtime.

Device API endpoints are deliberately excluded: they authenticate as a device with a device
access token, not as an operator.

To refresh after an API change:

```bash
npm run catalog:generate -- --hub-path ../hub
git diff src/catalog/endpoints.generated.json    # review, then commit
```

CI cannot regenerate this (it has no hub checkout), so refreshing it is a maintainer step
in the release checklist. `--check` verifies a committed file matches a fresh generation:

```bash
node scripts/generate-catalog.mjs --hub-path ../hub --check
```

## Verifying a real setup

To check the server, your credential and production connectivity in one step —
independently of any MCP host wiring:

```bash
npm run smoke:live -- --key-stdin     # paste the key; keeps it out of shell history
# or
XYTE_ORG_API_KEY=<key> npm run smoke:live
```

It spawns the built server and drives real MCP requests against the live API. The child is
started with `XYTE_MCP_READ_ONLY=1` regardless of your environment, only `GET` endpoints are
exercised, and the key is never printed — this runs against production, so it cannot mutate
anything. A pass means the whole path works; if this passes but your host still shows
nothing, the problem is the host registration, not the server.

## Remote HTTP transport

`xyte-mcp --http` serves the same three tools over MCP's Streamable HTTP transport, for
clients that cannot spawn a local subprocess. Two authentication modes exist, independently
switchable and composable:

- **Static bearer** (`XYTE_MCP_HTTP_TOKEN`): one token in front of one API key held by the
  server. Every caller shares one identity — a dev/CI mode, not a product. Keep it on a dev
  hub, read-only.
- **OAuth 2.1** (`XYTE_MCP_ISSUER_URL`): the real thing — see
  [OAuth 2.1](#oauth-21). Users add the URL as a custom connector (claude.ai web included),
  sign in at hub and pick an organization, and every call runs with a hub OAuth token for
  that organization. The token carries the organization's full authority, like an org API
  key; the signed-in user is recorded for attribution, not used to narrow access.

It is **stateless**: no session ids, no session table, every POST a complete
request/response. So there is nothing to keep warm, any instance can answer any request,
and a restart costs a client nothing.

| Route | Auth | Purpose |
| --- | --- | --- |
| `POST /mcp` | bearer | The MCP endpoint. The whole protocol. |
| `GET /healthz` | none | Platform health probe. Reveals nothing a port scan would not. |
| `/.well-known/*`, `/authorize`, `/token`, `/register`, `/revoke`, `POST /oauth/consent`, `GET /oauth/callback` | — | OAuth mode only; the MCP SDK's auth router plus our consent page and hub's callback. |

`GET` and `DELETE` on `/mcp` are `405` with `Allow: POST`, which the spec permits for a
server that offers no SSE stream. Do not "fix" this by letting the SDK handle them: a
stateless server has no session to push to, so its `GET` answers with a stream that can
never emit, and every connected client then parks an idle connection until the platform
times it out (Heroku's router: 55s, then a reconnect). Observed with Claude Code before the
405 was added.

Any other path is `404`. A missing or wrong token is `401` — with a `WWW-Authenticate`
challenge pointing at the resource metadata when OAuth is on (RFC 9728, how clients discover
the flow), and deliberately *without* one in static-only mode (a challenge makes
`mcp-remote` open a browser for an OAuth flow that does not exist there).

### Run it

```bash
npm run build
XYTE_MCP_HTTP_TOKEN=$(node -e "console.log('xmcp_'+require('node:crypto').randomBytes(32).toString('base64url'))") \
  XYTE_ORG_API_KEY=<key> XYTE_MCP_READ_ONLY=1 PORT=3000 \
  node dist/index.js --http
```

`XYTE_MCP_READ_ONLY=1` is strongly advised: on stdio the blast radius of a write is one
laptop, here it is whoever holds the token. The server logs a warning if you leave writes on.

### Deploy it

The `Procfile` is all a Heroku Node app needs — the buildpack runs `npm run build` and
`engines.node` pins the runtime.

```bash
heroku create <app> --region eu --team xyte
heroku addons:create heroku-postgresql:essential-0 -a <app>   # OAuth token store (sets DATABASE_URL)
heroku config:edit -a <app>    # XYTE_MCP_ISSUER_URL, XYTE_HUB_URL, XYTE_MCP_READ_ONLY=1,
                                # XYTE_MCP_HUB_OAUTH_CLIENT_ID / _SECRET
                                # (+ XYTE_MCP_HTTP_TOKEN and XYTE_ORG_API_KEY for the static mode)
git push heroku HEAD:main       # HEAD, so a branch can be deployed without merging it
```

`config:edit` rather than `config:set`: the latter puts the API key in your shell history
and in `ps` while it runs.

`HEAD:main` is what lets this be deployed from a feature branch — Heroku builds the app's
own `main`, which has nothing to do with the GitHub branch you are on.

The DEV-6742 POC runs at **`xyte-mcp-aran`** (Heroku team `xyte`, EU), pointed at
`hub-aran.xyte.io` and read-only:
`https://xyte-mcp-aran-6f8c801d1b74.herokuapp.com`. It holds one org API key and one bearer
token, so treat the URL as a shared dev credential, not a service.

### Connect a client

```bash
claude mcp add --transport http --scope user xyte-dev \
  https://<app>.herokuapp.com/mcp \
  --header "Authorization: Bearer <token>"
```

Then restart the client and check `/mcp` reports Connected. By hand — note that the MCP
spec requires the client to accept both content types, whichever one comes back:

```bash
curl -sS -X POST https://<app>.herokuapp.com/mcp \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq -r '.result.tools[].name'
```

No `initialize` handshake is needed, because there is no session to establish.

### Verify a deploy

```bash
XYTE_MCP_HTTP_TOKEN=<token> npm run smoke:remote -- https://<app>.herokuapp.com
```

`scripts/remote-smoke.mjs` asserts the positives (health, handshake, tool list, a real read
against the configured org — and, with OAuth on, registration and the consent page) *and*
the denials that fail silently otherwise: no token, wrong token, unknown path, and a
mutating endpoint refused. The hub sign-in needs a browser, so verify the rest of the OAuth
flow by connecting a real client. The denials are
the point — a server that answers everything with `200` passes a happy-path check and is
still wide open. Run it after every deploy, and add a case whenever you touch the boundary.

## Development

```bash
npm install
npm run typecheck
npm test          # builds, then runs unit + protocol tests
npm run lint
npm run inspect   # build and open the MCP Inspector
```

The OAuth store contract (`tests/oauth-store.test.ts`) always runs against the in-memory store, and against Postgres too when `TEST_DATABASE_URL` names a throwaway database (its tables are truncated); otherwise the Postgres run is skipped.

Two invariants are enforced by lint rather than convention, because both erode silently:

- **Nothing but JSON-RPC may reach stdout.** On stdio, stdout *is* the protocol channel; one
  stray `console.log` corrupts the stream and the host disconnects. `no-console` is an error
  in `src/`; use `src/log.ts`, which writes to stderr.
- **Tools take `(args, ctx)` and nothing else.** No environment reads, no transport imports.
  Credential resolution and transport wiring live in `src/transports/`.

That second rule is what keeps the door open for a remote transport (see below).

## Releasing

A release is a pushed semver tag. `.github/workflows/publish.yml` then packs the tarball,
installs and runs it on Linux, macOS and Windows, re-checks the gates, and publishes to npm
with provenance. The npm token lives on the repo's `ci` GitHub environment, so it is not
reachable from a run on an arbitrary branch.

Checklist, from `main` with a clean tree:

```bash
# 1. Refresh the endpoint catalog. CI cannot do this — it has no hub checkout —
#    so a stale catalog is the one release defect nothing else will catch.
npm run catalog:generate -- --hub-path ../hub
git diff src/catalog/endpoints.generated.json    # review, commit if changed

# 2. Verify everything the publish job will verify, locally.
npm run typecheck && npm run lint && npm test
npm run smoke:pack-install                       # packs, installs, runs the binary

# 3. Bump the version and tag it. The publish job refuses to ship a tag that
#    disagrees with package.json.
npm version 0.1.0 --no-git-tag-version
git commit -am "Release v0.1.0" && git push origin main
git tag v0.1.0 && git push origin v0.1.0
```

`node scripts/generate-catalog.mjs --hub-path ../hub --check` exits non-zero when the
committed catalog is stale, if you would rather assert than diff.

Then verify from a machine that has never seen the repo:

```bash
npx -y @xyteai/mcp --version
claude mcp add xyte --scope user -e XYTE_ORG_API_KEY=<key> -- npx -y @xyteai/mcp
claude mcp list | grep -i xyte      # expect: ✔ Connected
```

MCP servers load at session start, so confirm the tools in a *new* session.

## OAuth 2.1

MCP's OAuth 2.1 authorization applies to HTTP transports; for stdio the specification
directs servers to take credentials from the environment, which is what stdio mode does.

Setting `XYTE_MCP_ISSUER_URL` (the deployment's public https URL) makes `--http` a full
authorization server. The protocol surface is the MCP TypeScript SDK's `mcpAuthRouter` —
RFC 8414 metadata, RFC 7591 dynamic client registration, `/authorize` + `/token` with PKCE,
revocation — nothing hand-rolled. Our part (`src/oauth/`) is the policy behind it:

- **Consent first.** `/authorize` never redirects straight away: it shows our own consent
  page naming the registering client (its `client_name` is self-declared, and labelled so)
  and the host the code will be sent to, with Approve / Deny. The page cannot be framed.
  Approve binds the flow to that browser with a `__Host-` cookie and sends it on to hub;
  the callback refuses any browser without the cookie, so an attacker cannot approve their
  own consent and hand the hub URL to a victim.
- **Sign-in at hub.** xyte-mcp is a confidential OAuth client of hub (`/oauth/authorize`,
  `/oauth/token`, `/oauth/revoke`): authorization code with its own S256 PKCE,
  `client_secret_basic`, `scope=openid email profile`. The user signs in and picks one
  organization on hub's consent screen; the hub token is bound to it. A denial at hub
  (`error`, plus `error_reason` such as `org_not_approved`) is passed back to the MCP
  client's redirect URI. A success becomes a **grant** storing the hub access + refresh
  token, and the `sub` / `xyte_tenant_id` / `email` from the id_token for attribution.
- **Audience-bound tokens.** The access/refresh tokens we mint are our own, hashed at rest,
  and bound to this server as the RFC 8707 resource. A client's token is **never forwarded
  to the hub** — each request resolves its grant and calls the hub with the stored hub
  token (the classic confused-deputy guard).
- **Organization authority.** Calls send `Authorization: Bearer xoat_…` and
  `X-Xyte-Client: xyte-mcp/<version>` to `/core/v1/organization`. The token carries the
  organization's full authority, like an org API key; the user is attribution only.
  `XYTE_MCP_READ_ONLY=1` is the control for what the agent may do.
- **Hub token lifecycle.** A hub access token lives an hour; within a minute of expiry, or
  after a hub `401`, it is refreshed once (one refresh per grant at a time — hub refresh
  tokens are single-use, and a late replay revokes the user's sign-in) and the call retried
  once. A refresh is never retried. Hub `invalid_grant` with the current refresh token
  revokes the grant: that tool call errors and the next request gets a `401`, so the client
  re-authorizes. A hub outage during refresh only fails the call. The chain ends 90 days
  after the first sign-in.
- **Disconnect.** Revoking any of our tokens revokes its grant, and calls hub's revoke —
  which ends that user's sign-in on that organization for every client — only when no
  other live grant rides the same sign-in.
- **Storage.** `DATABASE_URL` (Heroku Postgres) persists clients, grants and token hashes
  across dyno restarts; without it an in-memory store logs a loud warning and every restart
  logs users out. The schema is created at boot and only ever extended (nullable columns,
  nothing dropped), so rolling back to an older build still boots. Grants from the earlier
  password/Descope login hold no hub tokens and are treated as invalid: their clients get a
  `401` and re-authorize.
- **One dyno.** The pending consent state and the refresh single-flight are in memory, so
  the app must run on a single dyno.

**Registering at hub.** Once per hub environment, from a hub console:

```bash
GLOBAL=true rake "oauth:register_application[Xyte MCP,,https://<host>/oauth/callback]"
```

It prints the client id and secret for `XYTE_MCP_HUB_OAUTH_CLIENT_ID` /
`XYTE_MCP_HUB_OAUTH_CLIENT_SECRET`. The callback must match `XYTE_MCP_ISSUER_URL` +
`/oauth/callback` exactly. Before any member of an organization can connect, an admin of
that organization has to connect (approve) the app on hub's consent screen first — until
then hub denies with `error_reason=org_not_approved`.

The static-bearer mode stays available alongside (set both env vars) or instead (unset the
issuer); the two map to different upstream identities and neither weakens the other.

## Security notes

- Read tools return fleet data (device names, notes, ticket text) that a third party can
  influence, and that data enters the model's context. Treat it as untrusted input — see
  [Write policy](#write-policy) for what the server does about it and where `XYTE_MCP_READ_ONLY`
  is the right call.
- The API key sets the blast radius, and it is the one control the model cannot talk its way
  around. Scope it to what the agent needs.
- Prefer passing keys through your host's secret handling rather than committing them into a
  shared `.mcp.json`.

## License

Apache-2.0
