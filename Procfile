# `--http` selects the Streamable HTTP transport; without it the binary serves
# stdio and Heroku's health check would never get an answer. $PORT is assigned by
# the platform and read via resolveHttpConfig.
#
# One web dyno is enough and there is nothing here that breaks with more: the
# transport is stateless, so any dyno can answer any request. Concurrency is
# bounded by the hub, not by this process.
web: node dist/index.js --http
