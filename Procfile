# `--http` selects the Streamable HTTP transport; without it the binary serves
# stdio and Heroku's health check would never get an answer. $PORT is assigned by
# the platform and read via resolveHttpConfig.
#
# Exactly one web dyno. The MCP transport itself is stateless, but in OAuth mode
# the pending consent/sign-in state and the per-grant hub-token refresh
# single-flight live in this process's memory: a second dyno would lose
# callbacks and race single-use hub refresh tokens (which hub reads as replay).
web: node dist/index.js --http
