# The hosted server is its own workspace package (packages/remote), so the web
# process runs its entry, which always serves Streamable HTTP. The public
# @xyteai/mcp binary serves stdio only and would fail Heroku's boot check (bind
# $PORT within 60s, else R10). $PORT is assigned by the platform and read via
# resolveHttpConfig.
#
# Exactly one web dyno. The MCP transport itself is stateless, but in OAuth mode
# the pending consent/sign-in state and the per-grant hub-token refresh
# single-flight live in this process's memory: a second dyno would lose
# callbacks and race single-use hub refresh tokens (which hub reads as replay).
web: node packages/remote/dist/index.js
