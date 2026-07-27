# xyte-mcp

An [MCP](https://modelcontextprotocol.io) server for the Xyte platform API. It gives an AI
agent typed, validated access to the public Xyte REST API — endpoint discovery plus a
generic call tool — over a local stdio transport.

Read-only by default.

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

## Configuration

| Variable | Purpose |
| --- | --- |
| `XYTE_ORG_API_KEY` | Organization-scoped API key. |
| `XYTE_PARTNER_API_KEY` | Partner-scoped API key. Set either or both. |
| `XYTE_MCP_ALLOW_WRITES` | Set to `1` to permit mutating endpoints. Off by default. |
| `XYTE_HUB_URL` | Override the hub base URL. Defaults to `https://hub.xyte.io`. |
| `XYTE_ENTRY_URL` | Override the entry base URL. |
| `XYTE_MCP_TIMEOUT_MS` | Per-request timeout. Defaults to `15000`. |

There is no tenant setting: a Xyte API key is already bound to its tenant server-side.
The key you supply determines which organization or partner you are acting as.

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

The caller here is a model, and it may be acting on content a third party can influence —
device names, ticket bodies, notes. So mutations are off unless an operator turns them on
out of band:

- **Default:** only `GET`/`HEAD` endpoints can be called. Anything else is refused, and no
  request goes out.
- **`XYTE_MCP_ALLOW_WRITES=1`:** `POST`/`PUT`/`PATCH` are permitted.
- **`DELETE`:** additionally requires `confirm` set to the endpoint key verbatim, on top of
  writes being enabled.

`xyte_api_call`'s MCP annotations (`readOnlyHint`, `destructiveHint`) follow the live
configuration, so a host can prompt appropriately.

API keys are never echoed back: output is filtered both by field name (`api_key`, `token`,
`authorization`, …) and by literal secret value.

## The endpoint catalog

`src/catalog/endpoints.generated.json` holds 77 endpoints (63 organization, 14 partner). It
is **generated** from hub's Bruno collection — `hub/docs/api/Xyte Public/` — which is the
upstream source the public API reference is built from, and committed so this repo has no
dependency on a hub checkout at runtime.

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

It spawns the built server and drives real MCP requests against the live API. Writes are
force-disabled for the run regardless of your environment, only `GET` endpoints are
exercised, and the key is never printed. A pass means the whole path works; if this passes
but your host still shows nothing, the problem is the host registration, not the server.

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

## Why stdio only, and what about OAuth

MCP's OAuth 2.1 authorization applies to HTTP transports; for stdio the specification
directs servers to take credentials from the environment, which is what this server does.
Supporting OAuth is therefore not an additive feature — it means running as a remote HTTP
service, which additionally needs an authorization server (Xyte has none today; hub's
`oauth2` gem is a *client* for Zoho/Salesforce/Zoom), a hosted deployment, and a decision
about whether hub accepts OAuth tokens directly or this server holds customer API keys.

That is a separate program, so v1 ships stdio. The tool layer is written to be
transport-agnostic so it can be reused unchanged: adding `src/transports/http.ts` plus a
resource-server layer would not touch any tool.

## Security notes

- Read tools return fleet data (device names, notes, ticket text) that a third party can
  influence, and that data enters the model's context. Treat it as untrusted input. The
  read-only default is the mitigation; enable writes deliberately.
- Prefer passing keys through your host's secret handling rather than committing them into a
  shared `.mcp.json`.

## License

Apache-2.0
