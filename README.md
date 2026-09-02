# xyte-mcp

An [MCP](https://modelcontextprotocol.io) server for the [Xyte](https://www.xyte.io) platform
API. It gives an AI agent typed, validated access to the public Xyte REST API — endpoint
discovery plus a generic call tool — over stdio locally, or over Streamable HTTP as a
remote server.

Reads and writes are both available by default; `XYTE_MCP_READ_ONLY=1` makes it a
read-only server.

Xyte is a device management platform: connected device fleets, the spaces they live in,
their telemetry and incidents, service tickets, commands, models and warranties. This server
puts that API in front of an agent as three tools instead of 77 hand-written ones — it can
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
| `XYTE_MCP_HTTP_TOKEN` | **`--http` only, required.** The static bearer every request must present. |
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

`src/catalog/endpoints.generated.json` holds 77 endpoints (63 organization, 14 partner). It
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
clients that cannot spawn a local subprocess. Auth today is **one static bearer token** in
front of **one API key** held by the server, which is what makes the rest of this section
short — and what makes it a dev-environment tool rather than a product. See
[What about OAuth](#what-about-oauth).

It is **stateless**: no session ids, no session table, every POST a complete
request/response. So there is nothing to keep warm, any instance can answer any request,
and a restart costs a client nothing.

| Route | Auth | Purpose |
| --- | --- | --- |
| `POST /mcp` | bearer | The MCP endpoint. |
| `GET /healthz` | none | Platform health probe. Reveals nothing a port scan would not. |

Anything else is `404`; a missing or wrong token is `401` with no `WWW-Authenticate` header
(a challenge makes `mcp-remote` open a browser for an OAuth flow that does not exist yet).

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
heroku config:edit -a <app>    # XYTE_MCP_HTTP_TOKEN, XYTE_ORG_API_KEY, XYTE_HUB_URL, XYTE_MCP_READ_ONLY=1
git push heroku HEAD:main
```

`config:edit` rather than `config:set`: the latter puts the API key in your shell history
and in `ps` while it runs.

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
against the configured org) *and* the denials that fail silently otherwise: no token, wrong
token, unknown path, and a mutating endpoint refused. The denials are the point — a server
that answers everything with `200` passes a happy-path check and is still wide open. Run it
after every deploy, and add a case whenever you touch the boundary.

## Development

```bash
npm install
npm run typecheck
npm test          # builds, then runs unit + protocol tests
npm run lint
npm run inspect   # build and open the MCP Inspector
```

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

## What about OAuth

MCP's OAuth 2.1 authorization applies to HTTP transports; for stdio the specification
directs servers to take credentials from the environment, which is what stdio mode does.

`--http` does not implement it. It authenticates with a single static bearer and holds a
single API key, so **every caller shares one identity and one blast radius** — there is no
user to scope anything to. That is a deliberate ceiling, not an oversight, and it is why
that mode belongs on a dev hub, read-only, behind a token you can revoke by redeploying.

Real OAuth needs an authorization server (Xyte has none today; hub's `oauth2` gem is a
*client* for Zoho/Salesforce/Zoom) and a decision about whether hub accepts OAuth tokens
directly or this server holds customer API keys. That is a separate program. What makes it
tractable is that it replaces `src/transports/http.ts` and nothing else: a per-request
context built from a validated token is the same `createToolContext` call, and no tool
changes.

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
