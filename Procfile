# The hosted server is its own workspace package (packages/remote), so the web
# process runs its entry, which always serves Streamable HTTP. The public
# @xyteai/mcp binary serves stdio only and would fail Heroku's boot check (bind
# $PORT within 60s, else R10). $PORT is assigned by the platform and read via
# resolveHttpConfig.
#
# release runs the OAuth store migrations once per release, before any new dyno
# starts. A non-zero exit stops the release, and the old dynos keep serving.
#
# NODE_EXTRA_CA_CERTS (both lines): Node does not read the system CA bundle on its
# own, and that bundle holds the CAs of Heroku Postgres's certificates, which the
# server verifies. A config var of the same name replaces this default.
release: NODE_EXTRA_CA_CERTS=${NODE_EXTRA_CA_CERTS:-/usr/lib/ssl/certs/ca-certificates.crt} node packages/remote/dist/migrate.js
web: NODE_EXTRA_CA_CERTS=${NODE_EXTRA_CA_CERTS:-/usr/lib/ssl/certs/ca-certificates.crt} node packages/remote/dist/index.js
