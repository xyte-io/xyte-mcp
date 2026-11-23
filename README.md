# xyte-mcp

An [MCP](https://modelcontextprotocol.io) server for the [Xyte](https://www.xyte.io) platform
API. It gives an AI agent typed, validated access to the public Xyte REST API — endpoint
discovery plus a generic call tool. The `@xyteai/mcp` package serves it over stdio, for a
local MCP host. A separate hosted server, kept in the
[GitHub repository](https://github.com/xyte-io/xyte-mcp#remote-http-transport) and not
published to npm, serves the same tools over Streamable HTTP.

Locally, reads and writes are both available by default; `XYTE_MCP_READ_ONLY=1` makes it a
read-only server. The hosted HTTP server is read-only unless `XYTE_MCP_ALLOW_WRITES=1`.

Xyte is a device management platform: connected device fleets, the spaces they live in,
their telemetry and incidents, service tickets, commands, models and warranties. This server
puts that API in front of an agent as three tools instead of one hand-written tool per
endpoint — it can discover the right endpoint, read its exact contract, and call it with
arguments validated against that contract before a request goes out.

Useful for asking an agent to investigate a fleet ("which devices in the Tel Aviv office
went offline this week, and what do their open tickets say"), to script routine operations,
or to work against the Xyte API without you writing the client.

By default it runs locally as a subprocess of your MCP host and talks to `hub.xyte.io`
directly — nothing to deploy and no third party in the path. A hosted server (in this repo,
not in the npm package) serves the same tools over the network for clients that only support remote servers; see
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
| `XYTE_MCP_READ_ONLY` | Set to `1` to refuse every mutating endpoint. Writes are permitted by default over stdio; this always wins. |
| `XYTE_MCP_ALLOW_WRITES` | **Hosted server:** set to `1` to permit writes; a hosted server is read-only otherwise. Over stdio, see below. |
| `XYTE_HUB_URL` | Override the hub base URL. Defaults to `https://hub.xyte.io`. |
| `XYTE_ENTRY_URL` | Override the entry base URL. |
| `XYTE_MCP_TIMEOUT_MS` | Per-request timeout. Defaults to `15000`. |
| `XYTE_MCP_HTTP_TOKEN` | **Hosted server only.** Static bearer fronting the process API key (dev/CI). At least 24 characters, not counting an `xmcp_` prefix (a grep-able marker for secret scanners). Exactly one of this and `XYTE_MCP_ISSUER_URL`: setting both refuses to start. |
| `XYTE_MCP_ISSUER_URL` | **Hosted server only.** This deployment's public https URL; setting it enables OAuth 2.1. |
| `XYTE_MCP_HUB_OAUTH_CLIENT_ID` | **Hosted server + OAuth, required.** This server's client id at hub's OAuth server — see [OAuth 2.1](#oauth-21) for registering it. |
| `XYTE_MCP_HUB_OAUTH_CLIENT_SECRET` | **Hosted server + OAuth, required.** The matching client secret (sent as `client_secret_basic`). |
| `DATABASE_URL` | **Hosted server + OAuth only.** Postgres DSN for the token store; set by the Heroku Postgres add-on. Required unless `XYTE_MCP_ISSUER_URL` is on `localhost` or `127.0.0.1` (without it, on Heroku the release fails and the old build keeps serving; elsewhere the server refuses to boot); with a local issuer, absent → in-memory, tokens and sign-ins in progress die with the process. TLS: none for `localhost`, otherwise the certificate is verified (chain and hostname) — see Storage under the hosted server. An `sslmode` in the DSN wins (`sslmode=disable` for a compose DB). |
| `PGSSLMODE` | **Hosted server + OAuth only.** `no-verify` keeps TLS but skips the certificate check (an accepted MITM risk, the on-call recovery switch); `disable` turns TLS off. Any other value keeps full verification. |
| `NODE_EXTRA_CA_CERTS` | **Hosted server only.** One PEM file of extra CAs for the Postgres certificate. The Procfile defaults it to the Heroku stack's system bundle; a config var of the same name replaces that default. |
| `XYTE_MCP_TOKEN_KEY` | **Hosted server + OAuth + `DATABASE_URL`, required.** Standard, padded base64 (not base64url) of exactly 32 random bytes; the hub tokens in the database, and the hub PKCE verifier of each sign-in in progress, are encrypted with it (AES-256-GCM). Generate one with `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"` or, equivalently, `openssl rand -base64 32`. |
| `XYTE_MCP_TOKEN_KEY_PREVIOUS` | **Hosted server + OAuth + `DATABASE_URL`, optional.** The key being rotated out, same format: only decrypts. See [Security notes](#security-notes) for rotation. |
| `XYTE_MCP_RATE_BUCKET_SECRET` | **Hosted server, optional.** Shared secret sent on every hub call so the hub rate-limits this server's traffic in one bucket; must equal `MCP_RATE_BUCKET_SECRET` on the hub. Leading and trailing whitespace is trimmed; inner spaces, tabs, line breaks or non-ASCII characters fail the boot and the release. Never logged. Blank, unset or different from the hub's value → the hub limits hosted traffic per IP. |
| `PORT` | **Hosted server only.** Port to listen on. Defaults to `3000`; set by the platform on Heroku. |

`XYTE_HUB_URL`, `XYTE_ENTRY_URL` and `XYTE_MCP_TIMEOUT_MS` are escape hatches for
non-production hubs; the defaults are what you want.

`XYTE_MCP_ALLOW_WRITES` from 0.1.x is still honoured with its original meaning: if it is set
at all, it decides, so a server pinned shut with `XYTE_MCP_ALLOW_WRITES=0` stays shut across
the upgrade. Where the two disagree, the restrictive one wins. New stdio configuration should
use `XYTE_MCP_READ_ONLY`; on the hosted server, `XYTE_MCP_ALLOW_WRITES=1` is the one way to turn
writes on (`XYTE_MCP_READ_ONLY=0` alone does not).

From 0.4.0, `@xyteai/mcp` resolves only `.` and the subpaths listed in its
`package.json` `exports`; deep imports into `dist/` no longer resolve.

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

- **Default over stdio:** `GET`/`HEAD`/`POST`/`PUT`/`PATCH` are all permitted.
- **Default on the hosted server:** read-only, as below, unless `XYTE_MCP_ALLOW_WRITES=1`.
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

`packages/mcp/src/catalog/endpoints.generated.json` holds 89 endpoints (75 organization, 14 partner). It
is **generated** from hub's Bruno collection — `hub/docs/api/Xyte Public/` — which is the
upstream source the [public API reference](https://docs.xyte.io/reference) is built from, and
committed so this repo has no dependency on a hub checkout at runtime.

Device API endpoints are deliberately excluded: they authenticate as a device with a device
access token, not as an operator.

To refresh after an API change:

```bash
node packages/mcp/scripts/generate-catalog.mjs --hub-path ../hub
git diff packages/mcp/src/catalog/endpoints.generated.json    # review, then commit
```

CI cannot regenerate this (it has no hub checkout), so refreshing it is a maintainer step
in the release checklist. `--check` verifies a committed file matches a fresh generation:

```bash
node packages/mcp/scripts/generate-catalog.mjs --hub-path ../hub --check
```

## Verifying a real setup

To check the server, your credential and production connectivity in one step —
independently of any MCP host wiring:

```bash
npm run smoke:live -w @xyteai/mcp -- --key-stdin     # paste the key; keeps it out of shell history
# or
XYTE_ORG_API_KEY=<key> npm run smoke:live -w @xyteai/mcp
```

It spawns the built server and drives real MCP requests against the live API. The child is
started with `XYTE_MCP_READ_ONLY=1` regardless of your environment, only `GET` endpoints are
exercised, and the key is never printed — this runs against production, so it cannot mutate
anything. A pass means the whole path works; if this passes but your host still shows
nothing, the problem is the host registration, not the server.

## Remote HTTP transport

The hosted server (`packages/remote`, private: not part of the `@xyteai/mcp` npm package,
whose binary serves stdio only) serves the same three tools over MCP's Streamable HTTP transport, for
clients that cannot spawn a local subprocess. A deployment runs one of two authentication
modes; setting both is a config error, so a shared bearer never sits next to the per-user
sign-in on the same URL:

- **Static bearer** (`XYTE_MCP_HTTP_TOKEN`): one token in front of one API key held by the
  server. Every caller shares one identity — a dev/CI mode, not a product. Keep it on a dev
  hub, read-only.
- **OAuth 2.1** (`XYTE_MCP_ISSUER_URL`): the product — see
  [OAuth 2.1](#oauth-21). Users add the URL as a custom connector (claude.ai web included),
  sign in at hub and pick an organization, and every call runs with a hub OAuth token for
  that organization. With the hub setting named under [OAuth 2.1](#oauth-21) on, the hub
  applies the signed-in user's own access on every call, so a user who is not an
  organization administrator can do only what the hub allows them. The setting is off by
  default, and without it every signed-in user gets the organization's full access.

It is **stateless**: no session ids, no session table, every POST a complete
request/response. So there is nothing to keep warm, any instance can answer any request,
and a restart costs a client nothing.

Stopping it, cutting off one organization or connection, its log events and alerts:
[packages/remote/OPERATIONS.md](packages/remote/OPERATIONS.md).

| Route | Auth | Purpose |
| --- | --- | --- |
| `POST /mcp` | bearer | The MCP endpoint. The whole protocol. |
| `GET /healthz` | none | Health probe for uptime monitors and the smoke script. In OAuth mode it also checks the token database: `503` when the database does not answer. Reveals nothing a port scan would not. |
| `/.well-known/*`, `/authorize`, `/token`, `/register`, `/revoke`, `POST /oauth/consent`, `GET /oauth/callback` | — | OAuth mode only; the MCP SDK's auth router plus our consent page and hub's callback. |

`GET` and `DELETE` on `/mcp` are `405` with `Allow: POST`, which the spec permits for a
server that offers no SSE stream. Do not "fix" this by letting the SDK handle them: a
stateless server has no session to push to, so its `GET` answers with a stream that can
never emit, and every connected client then parks an idle connection until the platform
times it out (Heroku's router: 55s, then a reconnect). Observed with Claude Code before the
405 was added.

Any other path is `404`. A missing or wrong token is `401` — with a `WWW-Authenticate`
challenge pointing at the resource metadata when OAuth is on (RFC 9728, how clients discover
the flow), and deliberately *without* one in static mode (a challenge makes
`mcp-remote` open a browser for an OAuth flow that does not exist there).
`/mcp` can also answer `429` (rate limited; `405`s count against the same budget), `413`
(body over 1 MiB), `415` (the body must be uncompressed UTF-8 JSON), `400` (a JSON-RPC
batch) and `503` (the database is unavailable for the token check or the rate counter;
retry); see the rate limits under [OAuth 2.1](#oauth-21).

### Run it

```bash
npm run build
XYTE_MCP_HTTP_TOKEN=$(node -e "console.log('xmcp_'+require('node:crypto').randomBytes(32).toString('base64url'))") \
  XYTE_ORG_API_KEY=<key> PORT=3000 \
  node packages/remote/dist/index.js
```

It is read-only unless you set `XYTE_MCP_ALLOW_WRITES=1`: on stdio the blast radius of a
write is one laptop, here it is whoever holds a token. The server logs a warning when you opt
in, and `XYTE_MCP_READ_ONLY=1` still wins over it.

### Deploy it

The `Procfile` is all a Heroku Node app needs — the buildpack runs the root `npm run build`
(both workspace packages) and the root `engines.node` pins the runtime.

```bash
heroku create <app> --region eu --team <team>
heroku addons:create heroku-postgresql:essential-0 -a <app>   # OAuth token store (sets DATABASE_URL)
heroku config:edit -a <app>    # XYTE_MCP_ISSUER_URL, XYTE_HUB_URL,
                                # XYTE_MCP_HUB_OAUTH_CLIENT_ID / _SECRET,
                                # XYTE_MCP_TOKEN_KEY
                                # (or, for the static mode instead: XYTE_MCP_HTTP_TOKEN
                                #  and XYTE_ORG_API_KEY — never both modes)
git push heroku HEAD:main       # HEAD, so a branch can be deployed without merging it
```

`config:edit` rather than `config:set`: the latter puts the API key in your shell history
and in `ps` while it runs.

Upgrading an OAuth app from a build that stored the hub tokens unencrypted: set
`XYTE_MCP_TOKEN_KEY` before deploying this version; every connection then signs in once; then
rotate the hub OAuth client secret (see Storage under [OAuth 2.1](#oauth-21)). This upgrade
(schema version 2) cannot be rolled back: an older build refuses to start against it.

On an OAuth app (`XYTE_MCP_ISSUER_URL` set) with `DATABASE_URL`, the Procfile's release phase
applies the schema migrations once per release, before any new dyno starts; a failed migration
fails the release, and the running dynos keep serving the old build. It first resolves the HTTP config
as a web dyno's boot does: a config error (say `XYTE_MCP_TOKEN_KEY` missing) fails the
release before any migration runs. It does not check the token key against the stored hub
tokens: a key the live connections were not written with passes the release and is refused
only when the new dynos boot (see [key rotation](#security-notes)). Heroku also runs the
release phase on a config-var change you make (not on an add-on's own change, such as a
Postgres credential rotation of `DATABASE_URL`) and on a rollback: a rollback to an older build that has
the release phase (this one onward) against a newer breaking schema fails there (the older
build refuses it), so the rollback stops before any dyno restarts. A rollback to an earlier
build has no release phase: its dynos restart and refuse to boot, so never roll back past a
breaking migration. Preboot, rolling deploys and several web dynos are
allowed (see **Several dynos** below). The exception is a release that contains a
`breaksRollback: true` migration: turn preboot off for that release
(`heroku features:disable preboot -a <app>`; `strategy: Recreate` on EKS), so no new process
serves next to an old one longer than the shutdown drain. Off Heroku (EKS, a local run) there is
no release phase and the migrations run at boot, so with `Recreate` a failed migration means
downtime until a fixed build ships. With N replicas starting together, a migration that holds
the schema lock longer than 10 s fails the other pods with `55P03`; they recover on their next
restart.

Upgrading from a build without the cross-process refresh lock, a refresh on an old and a new
process while they overlap can race; the loser gets `invalid_grant` from hub and that
connection has to sign in again. Upgrading from a build without the shared per-grant counter,
the per-grant budget doubles while they overlap. Both last only for that one deploy and are
accepted.

An OAuth app whose issuer is not localhost or 127.0.0.1 needs `DATABASE_URL` and
`XYTE_MCP_TOKEN_KEY` on this build: without them the release fails on Heroku (the old build
keeps serving), and elsewhere the boot refuses. Set both before deploying it.

An app that had both modes configured fails the same way on this build (the release on
Heroku, the boot elsewhere): remove
`XYTE_MCP_HTTP_TOKEN` (and the org key it fronted) from an OAuth app. Writes are now off
unless `XYTE_MCP_ALLOW_WRITES=1`, so `XYTE_MCP_READ_ONLY=1` is no longer needed there.

This build verifies the Postgres certificate against the Procfile's CA bundle path, which is
checked on the `heroku-24` stack; run the app on that stack. If it stops the release (on
Heroku; the old build keeps serving) or, elsewhere, the boot, `PGSSLMODE=no-verify` restores the old behaviour while the CA is sorted out.

A database created by a pre-release build of the OAuth branch has an incompatible schema:
drop its tables (`oauth_tokens`, `oauth_grants`, `oauth_clients` and, if present,
`oauth_schema_migrations` and `oauth_pending_sign_ins`) once before this build is released;
its release phase recreates them.

`HEAD:main` is what lets this be deployed from a feature branch — Heroku builds the app's
own `main`, which has nothing to do with the GitHub branch you are on.

### Connect a client

An OAuth deployment needs only its URL — the client discovers the rest and opens the sign-in:

```bash
claude mcp add --transport http --scope user xyte https://<app>.herokuapp.com/mcp
```

A static-bearer deployment takes the token as a header:

```bash
claude mcp add --transport http --scope user xyte-dev \
  https://<app>.herokuapp.com/mcp \
  --header "Authorization: Bearer <token>"
```

Then restart the client, run the client's `/mcp` command and check `xyte-dev` reports
Connected. By hand — note that the MCP
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
npm run smoke:remote -w @xyteai/mcp-remote -- https://<app>.herokuapp.com                               # OAuth
XYTE_MCP_HTTP_TOKEN=<token> npm run smoke:remote -w @xyteai/mcp-remote -- https://<app>.herokuapp.com   # static
```

`packages/remote/scripts/remote-smoke.mjs` picks the mode from the deployment: OAuth metadata served means
OAuth, and no token is needed or accepted.

- **OAuth:** discovery metadata, the `401` challenge pointing at it, dynamic registration,
  the consent page for a valid PKCE `/authorize`, refusal of an unregistered `redirect_uri`,
  a junk bearer, health and unknown paths. The hub sign-in needs a browser, so verify the
  rest of the flow by connecting a real client. The `401` must carry rate-limit headers.
- **Static bearer:** health, handshake, tool list, a real read with the configured key
  (organization, or partner on a partner-only deploy), and the denials: no token (with
  rate-limit headers), wrong token, unknown path, a body over 1 MiB answered `413` by the
  server itself, and — only on a server that reported itself read-only — a mutating
  endpoint refused. A writable server fails the handshake check unless you pass
  `--expect-writes`, and is never sent a write.

The denials are the point — a server that answers everything with `200` passes a happy-path
check and is still wide open. Run it after every deploy, and add a case whenever you touch
the boundary.

## Development

```bash
npm install
npm run build     # install no longer builds; needed before any single-workspace command
npm run typecheck
npm test          # builds, then runs unit + protocol tests of both packages
npm run lint
npm run inspect -w @xyteai/mcp   # build and open the MCP Inspector
```

The OAuth store contract (`packages/remote/tests/oauth-store.test.ts`) always runs against the in-memory store, and against Postgres too when `TEST_DATABASE_URL` names a throwaway database (its tables are truncated); otherwise the Postgres run is skipped. CI's `pg-store` job runs it against a Postgres service on every push. With `TEST_DATABASE_URL` set, the spawned-server OAuth flow (`oauth-http.test.ts`) also runs on Postgres, in a schema of its own, adding a restart that must keep the connection.

Two invariants are enforced by lint rather than convention, because both erode silently:

- **Nothing but JSON-RPC may reach stdout.** On stdio, stdout *is* the protocol channel; one
  stray `console.log` corrupts the stream and the host disconnects. `no-console` is an error
  in `packages/*/src/`; use `packages/mcp/src/log.ts`, which writes to stderr.
- **Tools take `(args, ctx)` and nothing else.** No environment reads, no transport imports.
  Credential resolution and transport wiring live in `packages/mcp/src/transports/` (stdio) and
  `packages/remote/src/transports/` (HTTP).

That second rule is what let the hosted server reuse the tools unchanged — see
[Remote HTTP transport](#remote-http-transport).

## Releasing

A release is a pushed semver tag. `.github/workflows/publish.yml` then packs the tarball,
installs and runs it on Linux, macOS and Windows, re-checks the gates, and publishes to npm
with provenance. The npm token lives on the repo's `ci` GitHub environment, so it is not
reachable from a run on an arbitrary branch.

Checklist, from `main` with a clean tree:

```bash
# 1. Refresh the endpoint catalog. CI cannot do this — it has no hub checkout —
#    so a stale catalog is the one release defect nothing else will catch.
node packages/mcp/scripts/generate-catalog.mjs --hub-path ../hub
git diff packages/mcp/src/catalog/endpoints.generated.json    # review, commit if changed

# 2. Verify everything the publish job will verify, locally.
npm run typecheck && npm run lint && npm test
npm run smoke:pack-install -w @xyteai/mcp       # packs, installs, runs the binary

# 3. Bump the version and tag it. The publish job refuses to ship a tag that
#    disagrees with packages/mcp/package.json.
npm version <x.y.z> -w @xyteai/mcp --no-git-tag-version
git commit -am "Release v<x.y.z>" && git push origin main
git tag v<x.y.z> && git push origin v<x.y.z>
```

`node packages/mcp/scripts/generate-catalog.mjs --hub-path ../hub --check` exits non-zero when the
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

Setting `XYTE_MCP_ISSUER_URL` (the deployment's public https URL) makes the hosted server a
full authorization server. The protocol surface is the MCP TypeScript SDK's `mcpAuthRouter` —
RFC 8414 metadata, RFC 7591 dynamic client registration, `/authorize` + `/token` with PKCE,
revocation — nothing hand-rolled. Our part (`packages/remote/src/oauth/`) is the policy behind it:

- **Consent first.** `/authorize` never redirects straight away: it shows our own consent
  page naming the registering client (its `client_name` is self-declared, and labelled so)
  and the host the code will be sent to, with Approve / Deny. The page cannot be framed.
  It binds the flow to that browser with a `__Host-` cookie, set with the page itself so a
  cross-site auto-submitted Approve (no `SameSite=Lax` cookie) fails. Approve sends the
  browser on to hub; the callback refuses any browser without the cookie, so an attacker
  cannot approve their own consent and hand the hub URL to a victim. The pending consent
  expires after 10 minutes.
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
  token (the classic confused-deputy guard). Lifetimes: authorization code 10 minutes,
  access token 1 hour, refresh token 30 days (single-use, rotated on every exchange).
- **Your own access.** Calls send `Authorization: Bearer xoat_…` and
  `X-Xyte-Client: xyte-mcp/<version>` to `/core/v1/organization`. With the hub setting
  below on, the hub applies the signed-in user's own access on every call, so a user who is
  not an organization administrator can do only what the hub allows them. Who may sign in is the
  organization's choice when its administrator connects the app at hub. Writes are off unless
  `XYTE_MCP_ALLOW_WRITES=1` — that flag decides whether the agent may write at all, and the
  with that setting on, the signed-in user's own access limits what it may read or change. A sign-in
  yields an organization token only, so partner endpoints are not available through it.
- **Hub token lifecycle.** A hub access token lives an hour; within a minute of expiry, or
  after hub rejects it (`401` with `WWW-Authenticate: Bearer error="invalid_token"`; a plain
  `401` such as a device outside the organization is returned as is), it is refreshed once (one refresh per grant at a time — hub refresh
  tokens are single-use, and a late replay revokes the user's sign-in) and the call retried
  once. A refresh is never retried. Hub `invalid_grant` with the current refresh token
  revokes the grant: that tool call errors and the next request gets a `401`, so the client
  re-authorizes. A refresh with an unclear outcome (timeout, network error, hub 5xx) also
  revokes the grant, because the refresh token may already be used and replaying it later
  would end the user's sign-in at hub. The chain ends 90 days after the first sign-in
  (hub's refresh tokens inherit the first one's expiry): then the client's next request
  gets a `401` and the user signs in again. Hub's token response carries no chain expiry,
  so this cannot be announced ahead.
- **Disconnect.** Revoking any of our tokens revokes its grant, and calls hub's revoke —
  which ends that user's sign-in on that organization for every client — only when no
  other live grant rides the same sign-in.
- **Storage.** `DATABASE_URL` (Heroku Postgres) persists clients, grants, token hashes,
  sign-ins in progress and the per-connection `/mcp` rate counters across dyno restarts, so a sign-in started on one instance finishes on
  any other. It is required unless the issuer is on `localhost` or `127.0.0.1`; there, without
  it, an in-memory store logs a loud warning and every restart logs users out. At boot and
  then hourly the server deletes sign-ins in progress past their 10 minutes, expired tokens,
  revoked grants with no token left after 7 days (the row shows who was signed out and
  when), sign-ins with no token left, 97 days after the sign-in (hub's 90-day chain has
  ended, plus a week), sign-ins whose client is gone, and registered clients with no grant
  after 30 days (registration is open, so junk registrations go; a client in use keeps its
  grant; client secrets themselves never expire, `client_secret_expires_at` 0), and ended `/mcp` rate-limit windows. A returning user whose client was deleted must re-add the connector; see "Cleanup
  of old rows" in [packages/remote/OPERATIONS.md](packages/remote/OPERATIONS.md). The hub
  tokens in each grant are encrypted with AES-256-GCM under
  `XYTE_MCP_TOKEN_KEY` (required with `DATABASE_URL`), stored as `v1.<key id>.<data>`; the
  key id (the first 8 hex characters of the key's SHA-256) is logged at boot, the key never.
  A grant whose tokens cannot be decrypted (unknown key, tampered or plain-text value) is
  logged with its id, the key id when there is one (a plain-text or malformed value has none)
  and the reason, and revoked on first read: the client gets a `401` and its user connects
  again. A live grant with a plain-text or malformed token (written by an older build still
  serving during a deploy) is revoked at the next boot, which logs their count.
  Upgrading from a build that stored them unencrypted
  signs every existing connection out once. That clears the plain-text tokens only in this
  database: a backup, fork or follower taken before still holds hub refresh tokens. They are
  usable only by someone who also has the current hub OAuth client secret (a hub refresh needs
  it, and it lives in config, not in the database), which is why rotating it works: after that
  upgrade, have the hub re-issue this server's OAuth client secret and set it as
  `XYTE_MCP_HUB_OAUTH_CLIENT_SECRET` right away — hub refreshes fail from the moment the hub
  re-issues the secret until the new value is set. Treat those copies as sensitive until then. The schema is versioned: the
  Procfile's release phase applies the migrations not yet recorded in `oauth_schema_migrations`,
  in order and once each, under a lock so two runs take turns; each boot runs the same check
  again, which then applies nothing. All of them run in one transaction, so a failed migration
  leaves the database unchanged and stops the release (old dynos keep serving) with the
  migration's version and the database error. Each migration declares whether it is
  rollback-safe, i.e. whether an older build still boots against it: adding tables, nullable
  columns or indexes is safe; dropping, renaming or tightening is not. An older build boots
  against a newer rollback-safe schema, and refuses one that is not: its release phase fails,
  naming the version (a build from before the release phase has none, so its dynos restart
  and refuse to boot). A build from before versioning does not check, so never roll back past this
  release once a breaking migration has run. During a deploy the old dynos still serve
  against the new schema while the release phase and the new boot run, even with preboot off,
  so a breaking migration may only drop or rewrite what the previous release already stopped
  reading (schema version 2 is a deliberate pre-launch exception: see
  the upgrade note under [Deploy it](#deploy-it)). A database created before versioning is adopted as
  version 1 with its data; a pre-release database needs the one-time drop under
  [Deploy it](#deploy-it).
  TLS to a non-local database verifies the certificate (chain and hostname) against Node's CA bundle
  plus `NODE_EXTRA_CA_CERTS`, one PEM file added to Node's built-in CAs (the Procfile
  defaults it to the system bundle, which holds Heroku Postgres's CAs; a config var of the
  same name replaces that path), or a DSN `sslmode=verify-full&sslrootcert=<pem path>`. A compose
  or CI database without TLS takes `sslmode=disable`. `PGSSLMODE=no-verify` skips the check
  — an explicit, accepted MITM risk. A missing or wrong CA stops the boot with a message
  naming these options. The Procfile sets `NODE_EXTRA_CA_CERTS` for the web and release lines
  only: a one-off dyno (`heroku run`) needs it as a config var
  (`NODE_EXTRA_CA_CERTS=/usr/lib/ssl/certs/ca-certificates.crt`) to reach the database.
- **Several dynos.** Sign-ins in progress, the hub token refresh lock (a Postgres row lock lets
  one process at a time refresh a connection) and the per-connection `/mcp` counter are shared
  through Postgres, so a sign-in started on one process finishes on any other. The per-IP
  limits stay per process by design: N processes allow N times the per-IP budget. One other
  piece is per process: after a database error during a hub refresh, the rotated hub token
  pair may live only in that process's memory; another dyno serving that connection then
  sends the stored, already-used refresh token, and the user has to sign in again. Each process
  holds up to 8 Postgres connections (5 for requests, 3 for the refresh lock); at boot it
  first holds 1 for the schema check, closed before the other 8 open. The release phase holds 1
  while it runs. So the peak is dynos × 8 + 1 during the release (the old dynos hold theirs),
  and about 2 × dynos × 8 during a preboot or rolling deploy, while old and new dynos overlap.
  Check both against the Postgres plan's connection limit before scaling.
- **Shutdown.** On `SIGTERM` (every deploy and daily restart) or `SIGINT` (Ctrl+C) the
  listener stops accepting, in-flight requests get 10 s, then in-flight hub refreshes are
  awaited and any rotated hub pair not yet saved is written before exit; a hard deadline of
  28 s stays inside Heroku's 30 s before `SIGKILL`.
- **Rate limits.** Per IP (behind Heroku's router, `trust proxy` 1): `/register` 1000/hour,
  `/token` 2000 and `/revoke` 500 per 15 minutes, `/authorize` the SDK's 100 per 15 minutes.
  The first three are raised from the SDK defaults because claude.ai and ChatGPT call them
  from shared backend IPs. `/mcp` allows 60 calls a minute per connection (OAuth grant) and
  300 a minute per IP for requests without a valid token; over that it answers 429 with
  `Retry-After` and draft-8 `RateLimit` / `RateLimit-Policy` headers (sent on every `/mcp`
  answer), so a flooded IP sees 429 instead of 401 for up to a minute. The per-connection
  limit is shared by all processes through Postgres (without a database, localhost only, it
  is kept in memory per process); if the database fails there, `/mcp` answers 503 (retry). `/oauth/callback`
  allows 30 a minute per IP. The per-IP limits assume exactly one trusted proxy hop
  (Heroku's router): behind a CDN every client counts as the CDN's egress IP (raise the hop
  count), and with no proxy the client's own `X-Forwarded-For` decides, so the per-IP limit
  is spoofable. An `/mcp` body over 1 MiB is a 413, a compressed or non-UTF-8 body a 415, and
  a JSON-RPC batch a 400, so one request is one call. These are JSON-RPC error bodies:
  `-32000` (429, 413, 415) and `-32600` (batch).

**Registering at hub.** Once per hub environment, from a hub console:

```bash
GLOBAL=true rake "oauth:register_application[Xyte MCP,,https://<host>/oauth/callback]"
```

It prints the client id and secret for `XYTE_MCP_HUB_OAUTH_CLIENT_ID` /
`XYTE_MCP_HUB_OAUTH_CLIENT_SECRET`. The callback must match `XYTE_MCP_ISSUER_URL` +
`/oauth/callback` exactly. Before any member of an organization can connect, an admin of
that organization has to connect (approve) the app on hub's consent screen first — until
then hub denies with `error_reason=org_not_approved`.

The app must also have the hub setting "acts with the signed-in user's access" turned on;
the command above leaves it off. To turn it on, run this in the same hub console:

```ruby
Oauth::Application.find_by!(client_id: '<client id>').update!(acts_with_signed_in_user_access: true)
```

Without it every signed-in user gets the organization's
full access and the consent page text is not true, so do not open sign-in to
non-administrators until it is on.

The static-bearer mode is the alternative, not an addition: unset the issuer to use it.
Setting both refuses to start — a shared bearer mapping to the process keys has no place on
a public sign-in URL.

## Security notes

- Read tools return fleet data (device names, notes, ticket text) that a third party can
  influence, and that data enters the model's context. Treat it as untrusted input — see
  [Write policy](#write-policy) for what the server does about it and where `XYTE_MCP_READ_ONLY`
  is the right call.
- In API-key mode the API key sets the blast radius, and it is the one control the model
  cannot talk its way around. Scope it to what the agent needs.
- In sign-in mode, with the hub setting on, the signed-in user's own access sets the blast
  radius; without it, the whole organization does.
- Prefer passing keys through your host's secret handling rather than committing them into a
  shared `.mcp.json`.
- The hosted server is reachable from the network. Its static bearer is one shared identity — every
  holder acts as the process API key — so keep it to dev/CI, read-only, and rotate it by
  setting a new value and restarting the server (it is read only at boot; on Heroku,
  changing a config var restarts the dyno). OAuth gives each user their own sign-in
  instead. See [Remote HTTP transport](#remote-http-transport) and [OAuth 2.1](#oauth-21).
- `XYTE_MCP_TOKEN_KEY` protects every stored hub token: keep it in the platform's config and
  a copy in a secret store, never next to a database backup. Use a different key per
  environment: the key id in each boot line would show a reuse. Rotate it in two config changes, since a dyno
  running the old config keeps serving while the new one starts: first keep
  `XYTE_MCP_TOKEN_KEY` and set the new key as `XYTE_MCP_TOKEN_KEY_PREVIOUS` (every dyno can
  now read it; none writes with it yet); once that is fully rolled out, change both in one
  config change: the new key as `XYTE_MCP_TOKEN_KEY` and the old one as
  `XYTE_MCP_TOKEN_KEY_PREVIOUS` together. Setting only `XYTE_MCP_TOKEN_KEY` to the new key
  makes the server refuse to boot while any live connection still uses the old key; with none
  it boots, and the old process may then write rows under the old key that get revoked on
  read — so always change both together. A grant is rewritten
  under the new key only at its next hub refresh, which a tool call triggers once the hub
  access token has expired (hourly by default at the hub); refreshing this server's own tokens does not reach the
  hub. Count the live connections still on the old key; its id is the one the boot line shows
  as "previous" after the second change (or as "key id" before the rotation began):

  ```sql
  SELECT count(*) FROM oauth_grants
   WHERE revoked_at IS NULL AND hub_refresh_token LIKE 'v1.<old key id>.%';
  ```

  Remove `XYTE_MCP_TOKEN_KEY_PREVIOUS` when that is 0; a sign-in started under the old key in
  the 10 minutes before ends on the expired page, and its user starts it again. After 30 days, the ones left have made
  no tool call in that time; revoke them first (their users connect again once):

  ```sql
  UPDATE oauth_grants
     SET revoked_at = now(), hub_access_token = NULL, hub_refresh_token = NULL,
         hub_refresh_token_hash = NULL
   WHERE revoked_at IS NULL AND hub_refresh_token LIKE 'v1.<old key id>.%';
  ```

  The server refuses to boot while a live connection uses a key it has neither as
  `XYTE_MCP_TOKEN_KEY` nor as `XYTE_MCP_TOKEN_KEY_PREVIOUS`, naming that key id, so a wrong
  key keeps the server from starting (the app is down until the key is fixed) instead of
  signing everyone out. If the key is lost, run the revoke `UPDATE` above with the key id from
  that boot error; those users connect again once.

## License

Apache-2.0
