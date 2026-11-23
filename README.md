# xyte-mcp

An [MCP](https://modelcontextprotocol.io) server for the [Xyte](https://www.xyte.io) platform
API. It gives an AI agent typed, validated access to the public Xyte REST API — endpoint
discovery plus a generic call tool — over a local stdio transport.

Reads and writes are both available by default; `XYTE_MCP_READ_ONLY=1` makes it a
read-only server.

Xyte is a device management platform: connected device fleets, the spaces they live in,
their telemetry and incidents, service tickets, commands, models, warranties and maintenance
schedules, and for partners the store coupons they give their customers. This server
puts that API in front of an agent as three tools instead of 112 hand-written ones — it can
discover the right endpoint, read its exact contract, and call it with arguments validated
against that contract before a request goes out.

Useful for asking an agent to investigate a fleet ("which devices in the Tel Aviv office
went offline this week, and what do their open tickets say"), to script routine operations,
or to work against the Xyte API without you writing the client.

It runs locally as a subprocess of your MCP host and talks to `hub.xyte.io` directly — there
is nothing to deploy and no third party in the path.

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

The last three are escape hatches for non-production hubs; the defaults are what you want.

`XYTE_MCP_ALLOW_WRITES` from 0.1.x is still honoured with its original meaning: if it is set
at all, it decides, so a server pinned shut with `XYTE_MCP_ALLOW_WRITES=0` stays shut across
the upgrade. Where the two disagree, the restrictive one wins. New configuration should use
`XYTE_MCP_READ_ONLY`.

## Tools

| Tool | What it does |
| --- | --- |
| `xyte_endpoints_list` | Discover endpoints. Filter by `namespace`, `group`, `method`, `search` (matches key, title, path and description), `readOnly`. Returns compact rows. |
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
- **Ask before destroying:** the server instructions tell the model to explain in plain words
  what a delete, a removal (such as a tag off an organization) or a change to something live
  or scheduled will cost the customer, and to wait for your explicit yes before it acts.
  Before it proposes a delete or removal it reads that endpoint's contract, so its plan says
  what the API will refuse and what it will do instead. A create request that matches
  something existing is reported, not applied.
- **Approving an order is not confirm-gated:** it is a `POST`, so it goes ahead like any
  other write, though it cannot be undone (see DEV-8178).
- **Other writes go ahead:** creates and updates you asked for are made without a second
  question, and the model makes every write the request needs — a change "for" a named
  customer is done only when that customer has it. It then reads those customers back and
  tells you what each one now gets. Your host's write-approval prompt still applies.
- **Answers:** the model answers in plain words — names and dates, no ids, endpoint keys,
  field names or setting names unless you ask. API times are UTC, so it shows dates in your
  time zone, asks for it, or names the zone next to the date.
- **`XYTE_MCP_READ_ONLY=1`:** only `GET`/`HEAD` can be called. Anything else is refused
  before a request is built, and the model tells the user the connection is set up to look
  only.
- **Write log:** every mutating call the server sends writes one line to stderr —
  `[xyte-mcp] write <key> <METHOD> status=<code> duration_ms=<n>` — so you can tell later
  what an agent changed. It never holds the API key or a request or response body.
  `status=error` means no HTTP status came back (timeout, network), so the write may still
  have landed.

`xyte_api_call`'s MCP annotations (`readOnlyHint`, `destructiveHint`) follow the live
configuration, so a host prompts according to what the server can actually do.

**This is guidance, not enforcement.** The ask-first rules and `confirm` are text the model
reads; the model fills in `confirm` itself, so neither can stop a model that ignores them. The
real stop is the write-approval prompt of your own agent host (Claude Code, Claude Desktop, …):
keep approval on for `xyte_api_call`, and use `XYTE_MCP_READ_ONLY=1` when you only want to look.

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

`src/catalog/endpoints.generated.json` holds 112 endpoints (74 organization, 38 partner). It
is **generated** from hub's Bruno collection — `hub/docs/api/Xyte Public/` — which is the
upstream source the [public API reference](https://docs.xyte.io/reference) is built from, and
committed so this repo has no dependency on a hub checkout at runtime.

Partner endpoints cover devices, tickets and organizations, plus the partner's store:
`partner.organizations.getOrganizations`, `partner.organizationTags.*` (add, update, remove,
list organization tags), `partner.coupons.*` (create, list, update, delete coupons),
`partner.storeSettings.getStoreSettings`, `partner.products.*` and `partner.storeListings.*`
(list, get one), `partner.orders.*` (list, get one, approve), `partner.payments.*` (list,
get one), `partner.subscriptions.*` (list, get one, its invoice items) and
`partner.soldProducts.*` (list, get one). A coupon reaches a customer by code or by an
organization tag. Coupons need the Store plan feature and store coupons enabled for the
partner; the other store endpoints need only the Store plan feature.

Organization endpoints also gained `organization.edges.devices.changeModel`, maintenance schedules
(`organization.maintenanceSchedules.*`) and incident notes (`organization.notes.*IncidentNote*`), picked up from hub with this
catalog refresh.

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

### Partner coupon loop

`npm run loop:partner-coupons` runs every partner coupon and organization tag flow through the
built server and checks each result: percent, fixed-amount and code coupons, tagging customers,
changing, deactivating and deleting coupons, removing a tag, and the lists. It also checks that
another partner sees and changes nothing, that coupon calls return 403 without store coupons,
that read-only mode refuses every write, and that the write log holds no key or body.

It **writes** (every name it creates carries a run id), so it refuses to start without an
explicit `XYTE_HUB_URL` and refuses `hub.xyte.io`. Use a local or staging hub.

| Variable | Needed | What it is |
| --- | --- | --- |
| `XYTE_HUB_URL` | yes | The hub to test, e.g. `http://localhost:3000`. |
| `XYTE_PARTNER_API_KEY` | yes | Key of a partner with the Store plan and store coupons on. |
| `XYTE_LOOP_CUSTOMERS` | yes | Five of that partner's customers, comma separated, visible in its store. |
| `XYTE_LOOP_HIDDEN_CUSTOMER` | no | A customer that cannot see the store; checks `store_visible: false`. |
| `XYTE_LOOP_LISTING` | no | Store listing name for the fixed-amount coupon (default: the first). A name that matches no listing stops the run. |
| `XYTE_LOOP_USED_COUPON_ID` | no | A coupon used in an order; checks that deleting it is refused. |
| `XYTE_LOOP_OTHER_PARTNER_KEY` | no | Another partner's key, for the isolation checks. |
| `XYTE_LOOP_NO_COUPONS_PARTNER_KEY` | no | Key of a partner with store coupons off, for the 403 checks. |
| `XYTE_LOOP_RUN_ID` | no | Suffix for created names (default: a timestamp). |
| `XYTE_LOOP_FLOWS` | no | Run only some flows, e.g. `1,2,3,4`, to check the portals between steps. Valid: `1,2,3,4,5,6,10,7,8,11,isolation,gates,readonly`. |

To run the flows in steps, set the same `XYTE_LOOP_RUN_ID` on every step (the first run prints
it) and keep the order above: later flows find the coupons and tags by run-id names, and flow
11 expects flows 10 and 7 to have run.

A check whose optional variable is unset is skipped, not failed. The script exits 1 when any
check fails.

### Partner store reads loop

`npm run loop:partner-store-reads` reads the partner store through the built server and checks
each result: store settings, products and store listings (the list and the first one), and the
order, payment, subscription and sold product lists. It then follows a coupon used in an order
to that order, its payment, its subscription with the invoice items, and its sold product; a
missing link (no used coupon, no payment, no subscription item, no sold product) is skipped
with the reason, and so are the links after it. It also checks that a time filter with a
`+02:00` offset passed plain is accepted and one without an offset is 422, that read-only mode
reads but refuses to approve, and that the key appears in no server log and none of its own
output.

It is **read-only** unless `XYTE_LOOP_APPROVE_ORDER_ID` is set; then it approves that order,
which cannot be undone. It refuses to start without an explicit `XYTE_HUB_URL` and refuses
`hub.xyte.io`. Use a local or staging hub.

| Variable | Needed | What it is |
| --- | --- | --- |
| `XYTE_HUB_URL` | yes | The hub to test, e.g. `http://localhost:3000`. |
| `XYTE_PARTNER_API_KEY` | yes | Key of a partner with the Store plan. For the approve checks it must be a non-brand partner key (a brand partner key is read-only, 403). |
| `XYTE_LOOP_COUPON_ID` | no | Coupon to follow to its order (default: the first coupon used in an order). |
| `XYTE_LOOP_APPROVE_ORDER_ID` | no | An order waiting for approval; checks approving it, then approving it again. |

The script exits 1 when any check fails.

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
  influence, and that data enters the model's context. Treat it as untrusted input — see
  [Write policy](#write-policy) for what the server does about it and where `XYTE_MCP_READ_ONLY`
  is the right call.
- The API key sets the blast radius, and it is the one control the model cannot talk its way
  around. Scope it to what the agent needs.
- Prefer passing keys through your host's secret handling rather than committing them into a
  shared `.mcp.json`.

## License

Apache-2.0
