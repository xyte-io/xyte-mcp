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
  tokens live 1 hour and refresh tokens 30 days (clients refresh on their own), and the hub
  refresh chain behind each grant lives 90 days.

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

## Cut off one connection

Run one statement on the MCP database (`heroku pg:psql -a <app>`), with the `connection` id
from the logs:

```sql
UPDATE oauth_grants
   SET revoked_at = now(), hub_access_token = NULL, hub_refresh_token = NULL
 WHERE id = <connection> AND revoked_at IS NULL;
```

This is the same change the server makes when a client disconnects (the table's `CHECK`
needs `revoked_at` set when the hub tokens are removed). It works on the next request: the
client gets a `401` and its refresh fails. A hub call already running can still finish.

The user can sign in again and get a new connection. It does not sign the user out at the
hub. To keep them out, cut off the organization (above).

## Log events

Besides plain `[xyte-mcp] ...` lines, the server writes one JSON line per event to stderr.
On Heroku the JSON follows the platform's line prefix (`app[web.1]:`). The lines never hold a
token, a request or response body, an email or a tool argument. A field without a value is
left out.

| Event | When | Fields |
| --- | --- | --- |
| `tool_call` | Every tool call | `connection`, `organization` (hub tenant id), `user` (hub user id) — OAuth mode only; `tool`; `endpoint` (catalog key of the hub request); `status` (final hub HTTP status, absent when there was no hub call or no answer); `outcome` (`ok` or `error`); `duration_ms` |
| `sign_in` | The end of a sign-in | `outcome`: `ok` (with `connection`, `organization`, `user`), `denied` (the user said no on our consent page or at the hub), `failed` (the hub answered with an error other than `access_denied`, or the hub exchange or saving the grant failed) |
| `hub_refresh` | The server refreshes a hub token | `connection`; `outcome`: `ok`, `rate_limited` (hub `429`, the connection is kept), `rejected` (other hub `4xx`, the connection is kept), `invalid_grant` (the hub chain is dead), `already_rotated` (hub said `invalid_grant` because another request rotated the token first; the connection is kept), `unknown` (timeout, network error, hub `5xx` or an unreadable answer: the connection ends); `hub_status` when known |
| `revoke` | A connection ends | `connection`, `organization`, `user`; `reason`: `client` (the user disconnected), `invalid_grant` (the hub chain is dead), `refresh_unknown` (the refresh outcome was unknown) |

## Alerts

Written as log queries, so they fit any log tool. Every threshold is a **first guess; tune
it from production data**.

| Alert | Query | First guess |
| --- | --- | --- |
| Server down | Uptime check on `GET /healthz` | Fails 2 checks in a row. Timeout about 25 s: with a hung database the check can take up to 20 s (connect + query timeout, 10 s each) before it answers `503`. |
| 5xx rate | Router lines with `status>=500` (this includes our own `500` and `503` answers) | More than 5% of requests over 5 minutes, with at least 20 requests |
| Hub refresh failures | `hub_refresh` with `outcome` other than `ok` or `already_rotated` | More than 5 in 15 minutes |
| Revoke spike | `revoke` events, counted by `reason` | More than 10 with a reason other than `client` in 1 hour |
| Rate-limit hits | Router lines with `status=429` (the limits on `/register`, `/token`, `/revoke`, `/authorize`), plus `hub_refresh` with `outcome=rate_limited`, plus `tool_call` with `status=429` | More than 10 in 15 minutes |

### Where to look first

- **Server down:** `heroku ps -a <app>` and the latest lines of `heroku logs -a <app>`.
  `healthz: token store check failed` means the database; check the Postgres add-on. A
  crash at boot shows in the lines above the router errors.
- **5xx rate:** the router `code=` (`H10` crashed, `H12` timeout, `H80` maintenance mode) and
  the `[xyte-mcp] error:` lines at the same time. `token check failed` means the database.
- **Hub refresh failures:** the `outcome` and `hub_status`. Many `unknown` or `5xx` at once
  means the hub or the network to it; check the hub's health first.
- **Revoke spike:** the `reason`. `invalid_grant` for many users at once often means a change
  at the hub (for example the OAuth app was disabled there).
- **Rate-limit hits:** which source. Router `429` on `/token` or `/register` from one IP is
  usually a client's backend; hub `429` points at one `organization` or `connection`.
