# Operating the hosted server

How to stop the hosted MCP server, how to cut off one organization or one connection, what
it logs, and which alerts to set up. It assumes the Heroku deployment from the
[README](../../README.md#deploy-it). `<app>` is the Heroku app name.

Who acts: the on-call engineer with access to the hosting app. The names and the alert
targets are in the internal runbook, not here.

**Connection** in this document means one MCP grant: one user who signed in through one
client (for example, one person's claude.ai connector). It is not the hub's org-level
"connected app". The `connection` field in the logs is the grant's id.

## Kill switch: stop the whole server

```bash
heroku maintenance:on -a <app>    # stop
heroku maintenance:off -a <app>   # start again
```

- It works at once, with no deploy.
- Heroku's router answers `503` on every path, `/healthz` too. So the "server down" alert
  fires. This is expected.
- It is safe for users. A `503` is not a `401` and not `invalid_grant`, so clients keep
  their tokens and nothing is revoked. When you switch it off, connections work again
  without a new sign-in, as long as the stop is shorter than the token lifetimes: MCP access
  tokens live 1 hour and refresh tokens 30 days (clients refresh on their own).
- A stop does not extend a connection. Every connection ends 90 days after its sign-in, however
  often it is used: the hub refresh chain behind it keeps the expiry of the first sign-in (see
  [the 90-day end](#the-90-day-end)).

Accepted limits:

- No `Retry-After` header, so clients cannot know when to try again.
- Users cannot disconnect from their client during the stop (the revoke call also gets `503`).
- A sign-in in progress fails. The user starts it again after the stop.

Do **not** use hub's `oauth:disable` as a kill switch. `oauth:enable` does not bring the
grants back: every connection stays revoked and every user must sign in again. Use it only as
the last resort, to cut the whole app off permanently at the hub.

## Cut off one organization

An admin of that organization disconnects the app in the hub, under **Connected apps**. This
ends the connection of every member of that organization. To connect again, an admin must
approve the app again.

The hub shows **Connected apps** to every organization that has approved the app (its hub
grant is active), so no flag is needed. A user who disconnects from their client does not
change this. Once an admin disconnects the app there (or the hub grant is revoked another
way), the screen hides again, unless the partner has the `connected_apps` feature flag on. When no admin of the organization is available, the steps
for support are in the hub's internal runbook (`docs/remote_mcp_support_runbook.md`).

## Cut off one connection

Run one statement on the MCP database (`heroku pg:psql -a <app>`), with the `connection` id
from the logs:

```sql
UPDATE oauth_grants
   SET revoked_at = now(), hub_access_token = NULL, hub_refresh_token = NULL,
       hub_refresh_token_hash = NULL
 WHERE id = <connection> AND revoked_at IS NULL;
```

This is the same change the server makes when a client disconnects (the table's `CHECK`
needs `revoked_at` set when the hub tokens are removed). It works on the next request: the
client gets a `401` and its refresh fails. A hub call already running can still finish.

The user can sign in again and get a new connection. It does not sign the user out at the
hub. To keep them out, cut off the organization (above).

This cut-off writes no `revoke` event: only the server writes those. Record it, with the
`connection` id, in the ticket or the runbook, so the next person searching the logs for why
the connection ended finds the reason. Record there too whatever you may need from its row
later (user, organization): the cleanup deletes the row about a week after its last token
expires (see "Cleanup of old rows").

## Log events

Besides plain `[xyte-mcp] ...` lines, the server writes one JSON line per event to stderr.
The event lines are the ones whose message starts with `{`; a query parses only those. They
carry no time or level of their own: the platform's line prefix (`app[web.1]:` on Heroku)
gives the time. The lines never hold a token, a request or response body, an email or a tool
argument. A field without a value is left out.

| Event | When | Fields |
| --- | --- | --- |
| `tool_call` | Every tool call that reaches a tool handler (calls the MCP library rejects first, for an unknown tool or invalid arguments, are not logged) | `connection`, `organization` (hub tenant id), `user` (hub user id) — OAuth mode only; `tool`; `endpoint` (catalog key of the hub request); `status` (final hub HTTP status; absent when there was no hub call, no answer, or a failed hub token refresh — see below); `outcome` (`ok` or `error`; a tool that throws is `error`); `duration_ms` |
| `sign_in` | The end of a sign-in | `outcome`: `ok` (with `connection`, `organization`, `user`), `denied` (the user said no on our consent page or at the hub), `failed` (with `reason`, below); `client` (the registered client id) on `denied` and `failed` when the sign-in got far enough to know it |
| `hub_refresh` | The server refreshes a hub token | `connection`, `organization`, `user`; `outcome`: `ok`, `rate_limited` (hub `429`, the connection is kept), `rejected` (other hub `4xx`, the connection is kept), `invalid_grant` (the hub chain is dead), `unknown` (timeout, network error, hub `5xx` or an unreadable answer: the connection ends); `hub_status` when known |
| `revoke` | A connection ends | `connection`, `organization`, `user`; `reason`: `client` (the user disconnected), `invalid_grant` (the hub chain is dead), `refresh_unknown` (the refresh outcome was unknown), `hub_save_failed` (the hub refresh worked but the new tokens could not be saved, after retries: the connection is revoked rather than left holding the old, now used token), `unreadable_token` (its stored hub tokens could not be decrypted on read: an unknown key, a tampered or plain-text value). Not written for the operator's SQL cut-off, nor by a hub refresh that finds the connection already ended, nor per connection by the boot sweep of plain-text or malformed tokens (one `[xyte-mcp]` line with their count) or by schema version 2's one-time sign-out of every connection |

`sign_in` `failed` reasons:

- `expired`: the sign-in link is unknown or older than 10 minutes, or was already used (a
  replayed hub callback). Also an Approve or Deny on a sign-in used or expired between the
  consent page and the click, a hub callback that lost the race for the sign-in to another
  instance, and a sign-in whose hub PKCE verifier this instance cannot decrypt, logged as
  `[xyte-mcp] error: pending sign-in unreadable: <reason> (key id …)` (`XYTE_MCP_TOKEN_KEY`
  changed mid-sign-in without the old key as `XYTE_MCP_TOKEN_KEY_PREVIOUS`; the user starts
  the sign-in again). The user sees "Authorization expired".
- `csrf`, `cookie`: the consent form or the hub callback did not come from the browser that
  opened the consent page. One-off: a user switched browsers. Many: someone is forging them.
- `not_approved`: the hub callback came for a sign-in nobody approved on our consent page.
- `hub_error`: the hub answered with an error other than `access_denied`.
- `exchange`: the hub code exchange or saving the connection failed (an `[xyte-mcp] error:
  hub sign-in failed` line has the detail).
- `store`: `/authorize` could not save the new sign-in (the database is down or slow); the
  client gets a `server_error` redirect. An `[xyte-mcp] error: authorize:` line has the
  error code. Not to be confused with the cap: 10,000 sign-ins in progress, counted across
  all instances, answer `/authorize` with `503` "Too many sign-ins in progress" and write no
  `sign_in` event.
- `error`: an unexpected failure (a stack trace is on the line above).

When the hub rejects a tool call's token and the token refresh that follows fails, the
`tool_call` line has `outcome` `error` and no `status`. The reason is on the `hub_refresh` line
of the same `connection` just before it; if there is none, look for that grant's
`grant lock transaction failed for a hub refresh` line (below).

One connection's hub refresh runs once at a time across all server processes (a Postgres row
lock); a revoke of the connection waits for it too. A call that waits longer than the hub
timeout plus 5 s (20 s by default) for the lock fails with a retryable error ("This Xyte
sign-in is busy") and an `[xyte-mcp] error: grant <id>: grant lock transaction failed for a
hub refresh (<code>)` line (`55P03` for the lock wait; another code when the lock's database
transaction failed some other way); nothing was sent to the hub, and the connection is kept.
When all 3 lock connections of the process are busy, the call first waits up to 10 s for one,
so the worst case is about the hub timeout plus 15 s; a failed wait for a connection shows the
code literally as `Error`. A disconnect that cannot get the lock in that time answers `500`,
with an `[xyte-mcp] error: grant <id>: grant lock transaction failed for a revoke (<code>)`
line; the connection is not revoked, and the client may retry. During shutdown a disconnect
answers `400` `temporarily_unavailable`, with no log line.

Saving the new tokens after a hub refresh is retried while the lock is held, and if every try
fails the connection is revoked under the same lock (`hub_save_failed`). Only when the lock's
own database connection or its commit fails is the lock released before the tokens are safe:
the save is then retried outside it, and another process may meanwhile send the stored,
already used token and end that connection. If the database is fully down, so that neither
saving the new tokens nor revoking the connection works, the new tokens live only in that
process's memory (an `[xyte-mcp] error: ERROR grant <id>: could not save rotated hub tokens`
line) until a later refresh saves them; a restart before the save loses them.

Two more `[xyte-mcp] error: ERROR grant <id>:` lines mean the stored token may be one hub has
already used, so that connection may end on its next refresh:
`could not revoke the grant after a failed hub refresh` (the hub refresh failed or its new
tokens could not be saved, and the database refused the revoke too), and
`rotated hub tokens lost at shutdown` (new tokens held in memory were never saved).

Each server process holds up to 8 Postgres connections: 5 for requests and 3 for the refresh
lock; at boot it first holds 1 for the schema check, closed before the other 8 open. The release
phase holds 1 while it runs. So the peak is dynos × 8 + 1 during the release (the old dynos hold
theirs), and about 2 × dynos × 8 during a preboot or rolling deploy, while old and new dynos
overlap. Check both against the Postgres plan's connection limit before scaling.

### Cleanup of old rows

At boot and then every hour the server deletes sign-ins in progress past their 10 minutes,
expired tokens, revoked connections with no token left 7 days after the revoke, connections
left without a client (a sign-in still in progress when its client was deleted), connections
with no token left 97 days after the sign-in (a sign-in never completed, or a user idle past
the refresh lifetime: [the 90-day end](#the-90-day-end) has passed, plus a week),
registered clients with no connection 30 days after registration, and ended `/mcp`
rate-limit windows. When it deletes any counted row it writes one line (a run that deletes
only ended rate-limit windows writes none): `[xyte-mcp] OAuth store cleanup: deleted <n> expired token(s), <n> ended
grant(s), <n> unused client(s), <n> expired pending sign-in(s)`. Every dyno runs the
cleanup; a run at the same time as another deletes nothing more, so the counts are not
doubled and a dyno may log nothing. A failed step writes `[xyte-mcp] error: OAuth store
cleanup: the <pendingSignIns|tokens|grants|clients|rateLimitCounters> step failed, retried within
an hour: <code>` and ends that run; the steps before it are kept and still logged in the
`deleted` line, and the next run tries again. `<code>` is the error code, as in `healthz:
token store check failed: <code>`, except that `query timeout` (pg's query timeout, 10 s) and
`connection terminated` (a dropped connection) stand for pg errors with no code; a plain `Error`
is usually a connect timeout (10 s). A query timeout stops only the wait: the delete may still
finish in Postgres, so the next run's counts are lower. A run that fails outside the steps writes
`[xyte-mcp] error: OAuth store cleanup failed, retried within an hour: <reason>`.

A returning user can hit this: when all connections of a client were revoked (a disconnect,
or [the 90-day end](#the-90-day-end)) or abandoned (no token left and signed in more than 97
days ago) and deleted, and the client is more than 30 days old, the client is deleted too. The user's next sign-in from that
client gets a `400` `invalid_client` ("Invalid client_id") answer from `/authorize`, and
from `/token` and `/revoke` too (a client usually first retries its stored refresh token).
The server logs nothing for it: the router's lines are the only trace. The fix is to remove
the connector in the client and add it again.

Client secrets do not expire. A confidential client (one registered with a secret) stored by
an older pre-release build still carries that build's 30-day secret expiry: from then on
`/token` and `/revoke` answer `400` `invalid_client` ("Client secret has expired") while
`/authorize` still accepts it. The fix is the same: remove the connector and add it again.

### The 90-day end

Every connection ends 90 days after its sign-in, however often it is used: each hub refresh
hands out a new token with the expiry of the first sign-in. The first hub refresh after that
day logs `hub_refresh` `invalid_grant`, then `revoke` `invalid_grant`, and the user has to sign
in again. This is expected. Everyone who signed in on the same day (launch day, for example)
reaches it together, 90 days later.

## A failed release

The Procfile's release phase runs on every release (and Heroku runs it again on a config-var
change you make and on a rollback, not on an add-on's own config-var change such as a Postgres
credential rotation of `DATABASE_URL`). On every app it first resolves the HTTP config as a web
dyno's boot does, so a config error fails the release even without OAuth or a database. Then,
when the app is not in OAuth mode (`XYTE_MCP_ISSUER_URL` unset) or has no `DATABASE_URL`, it
logs `nothing to migrate` and passes; otherwise it applies the schema migrations once per
release. It does not check the token key against the stored hub tokens, so a
key the live connections were not written with passes the release and is refused only at boot
(see [key rotation](../../README.md#security-notes)). When it fails, the release log
(`heroku releases:output <version> -a <app>`) ends with `[xyte-mcp] error: OAuth store
migration failed: <reason>`, or with the config error,
possibly followed by hints, and `heroku releases -a <app>` shows that release as failed. No new
dyno starts: the old build keeps serving, and the database is unchanged (a config error stops
the release before any migration; all pending migrations run in one transaction). A SQL or
migration failure shows the inner `OAuth store schema migration N (<name>) failed:` (or
`OAuth store schema lock/version check failed:`) after the outer `OAuth store migration
failed:`; a connect or TLS failure has the outer prefix only.

- A config error (any `[xyte-mcp] error:` without `OAuth store migration failed`, other than a
  `postgres migration pool:` line, which is a connection error): fix the config var it names,
  which starts a new release.
- A certificate or TLS config error (with hints): fix the config var it names (`DATABASE_URL`,
  `NODE_EXTRA_CA_CERTS`, `PGSSLMODE`), which starts a new release.
- `28P01` (bad password), `3D000` (no such database) or `Invalid URL` (a malformed DSN) on an
  `OAuth store migration failed` line: fix `DATABASE_URL`; a retry does not help.
- The database down, a failover or a connect timeout (a connection error names no config
  var): wait until the database is reachable, then run the release again
  (`heroku releases:retry -a <app>`).
- Code `53300` (too_many_connections): the old dynos hold the plan's connections. Scale web
  down or restart it (`heroku ps:restart web -a <app>`), then retry the release.
- `… which this build … does not know and which breaks rollback`: a rollback or an older build
  against a newer breaking schema. Release a build at that version or later instead. This
  stop covers only builds with the release phase: a rollback to an earlier build restarts the
  dynos, which then refuse to boot in a crash loop. To stop it, roll forward: deploy (or roll
  back to) a build at or above the schema version. A build from before schema versioning does
  not check at all and runs against the newer schema. So never roll back past a breaking
  migration.
- Code `57P01` (admin shutdown), an `08…` code, or a code-less `Connection terminated
  unexpectedly` on a migration line: the connection dropped (a failover); retry the release.
- Code `55P03` (lock timeout: another run, or a running query, holds the lock) on the
  lock/version check or a migration line: retry the release. Only other database codes on a
  migration line mean the migration needs fixing, in a new build.
- A stack trace with no `[xyte-mcp]` line: a bug in the build. Roll forward with a fixed
  build; do not roll back past a breaking migration.

## Alerts

Written as log queries, so they fit any log tool. Every threshold is a **first guess; tune
it from production data**.

| Alert | Query | First guess |
| --- | --- | --- |
| Server down | Uptime check on `GET /healthz` | Fails 2 checks in a row. Timeout about 25 s: with a hung database the check can take up to 20 s (connect + query timeout, 10 s each) before it answers `503`. Probes share one database check and reuse its answer for 2 s. |
| 5xx rate | Router lines with `status>=500` (this includes our own `500` and `503` answers) | More than 5% of requests over 5 minutes, with at least 20 requests |
| Hub refresh failures | `hub_refresh` with `outcome` other than `ok` | More than 5 in 15 minutes. Expect it to fire 90 days after a busy sign-in day ([the 90-day end](#the-90-day-end)). |
| Revoke spike | `revoke` events, counted by `reason` | More than 10 with a reason other than `client` in 1 hour. Expect it to fire 90 days after a busy sign-in day ([the 90-day end](#the-90-day-end)). |
| Cleanup failures | `OAuth store cleanup: the <step> step failed` or `OAuth store cleanup failed` | The same failure in 3 consecutive hourly runs on a dyno. The `deleted` line after a partial run still looks normal. |
| Rate-limit hits | Router lines with `status=429` (the limits on `/register`, `/token`, `/revoke`, `/authorize`), plus `hub_refresh` with `outcome=rate_limited`, plus `tool_call` with `status=429` | More than 10 in 15 minutes |

### Where to look first

- **Server down:** `heroku ps -a <app>` and the latest lines of `heroku logs -a <app>`.
  `healthz: token store check failed: <code>` means the database; check the Postgres add-on.
  The code is the error code (`ECONNREFUSED`, or a Postgres one such as `28P01`), not the
  message. A crash at boot shows in the lines above the router errors.
- **Server down, boot stopped on the token key:** a missing or invalid `XYTE_MCP_TOKEN_KEY`,
  or `live grants use hub token key id(s) …` (a live connection uses a key the server has
  neither as `XYTE_MCP_TOKEN_KEY` nor as `XYTE_MCP_TOKEN_KEY_PREVIOUS`). See the key, rotation
  and lost-key notes under [Security notes](../../README.md#security-notes). On Heroku a
  missing or invalid `XYTE_MCP_TOKEN_KEY` now fails the release instead (see `heroku
  releases:output`), and the old build keeps serving.
- **Server down, boot stopped on `DATABASE_URL`:** `XYTE_MCP_ISSUER_URL is not local, so
  DATABASE_URL is required: without it OAuth state is held in memory, lost on every restart
  and not shared between instances.` The Postgres add-on or its config var is missing: set
  `DATABASE_URL` and `XYTE_MCP_TOKEN_KEY`. A release without `DATABASE_URL` fails on Heroku
  instead; removing the Postgres add-on is an add-on config change that skips the release
  phase, so that path still ends here, at boot.
- **5xx rate:** the router `code=` (`H10` crashed, `H12` timeout, `H80` maintenance mode) and
  the `[xyte-mcp] error:` lines at the same time. `token check failed` means the database.
  So does `rate limit check failed: <code>` (a `503` on `/mcp`: the per-connection rate
  counter could not be written); a plain `Error` code there is a pg pool or query timeout.
- **Hub refresh failures:** the `outcome` and `hub_status`. Many `unknown` or `5xx` at once
  means the hub or the network to it; check the hub's health first. Many `rejected` with
  `hub_status` `401` or `400` at once means the hub refuses this server itself: check its hub
  OAuth client id and secret (`XYTE_MCP_HUB_OAUTH_CLIENT_ID`, `XYTE_MCP_HUB_OAUTH_CLIENT_SECRET`).
  A hub OAuth client-secret rotation in progress (the step after the token-encryption upgrade)
  causes such a burst until `XYTE_MCP_HUB_OAUTH_CLIENT_SECRET` holds the new secret.
  `invalid_grant` on connections signed in about 90 days ago is [the 90-day end](#the-90-day-end).
- **Revoke spike:** the `reason`. First rule out [the 90-day end](#the-90-day-end):
  `invalid_grant` on connections whose sign-in was about 90 days ago (find it on their
  `sign_in` `ok` line). Otherwise `invalid_grant` for many users at once often means a change
  at the hub (for example the OAuth app was disabled there). `hub_save_failed` means database
  trouble: the new hub tokens could not be saved, so look at the database first.
- **Rate-limit hits:** which source. Router `429` on `/token` or `/register` from one IP is
  usually a client's backend. A hub `429` (`tool_call` `status=429` or `hub_refresh`
  `rate_limited`) usually means the hub's limit for this server's address, which every
  organization on the server shares, not one tenant. Count the `organization` values before
  chasing one.
