# The hosted server is its own workspace package (packages/remote), so the web
# process runs its entry, which always serves Streamable HTTP. The public
# @xyteai/mcp binary serves stdio only and would fail Heroku's boot check (bind
# $PORT within 60s, else R10). $PORT is assigned by the platform and read via
# resolveHttpConfig.
#
# Exactly one web dyno (README, "One dyno"). The MCP transport itself is
# stateless, but in OAuth mode two things still live in this process's memory:
# the pending consent/sign-in state (a second dyno would lose callbacks) and the
# rate-limit counters (a second dyno doubles every budget). The hub-token refresh
# is already serialized across dynos by a row lock in Postgres.
#
# NODE_EXTRA_CA_CERTS: Node does not read the system CA bundle on its own, and that
# bundle holds the CAs of Heroku Postgres's certificates, which the server verifies.
# A config var of the same name replaces this default.
web: NODE_EXTRA_CA_CERTS=${NODE_EXTRA_CA_CERTS:-/usr/lib/ssl/certs/ca-certificates.crt} node packages/remote/dist/index.js
