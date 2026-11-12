#!/usr/bin/env node
import { ENV } from './config.js';
import { isXyteError } from './http/errors.js';
import { logError } from './log.js';
import { startHttpServer } from './transports/http.js';
import { startStdioServer } from './transports/stdio.js';
import { VERSION } from './version.js';

const USAGE = `xyte-mcp ${VERSION} — MCP server for the Xyte platform API

Usage:
  xyte-mcp                Serve over stdio (the default, for a local MCP host).
  xyte-mcp --http         Serve over Streamable HTTP, for a remote MCP client.
  xyte-mcp --version      Print version and exit.
  xyte-mcp --help         Print this message and exit.

Environment:
  ${ENV.orgKey}        Organization-scoped API key.
  ${ENV.partnerKey}    Partner-scoped API key. Set either or both.
  ${ENV.readOnly}     Set to 1 to refuse all mutating endpoints. Writes are on by default.
  ${ENV.hubUrl}            Override the hub base URL (default https://hub.xyte.io).
  ${ENV.entryUrl}          Override the entry base URL.
  ${ENV.timeoutMs}     Per-request timeout in ms (default 15000).

Environment, --http only:
  ${ENV.httpToken}   Static bearer token every request must present. Required.
  ${ENV.httpPort}                     Port to listen on (default 3000).

Example MCP host configuration:
  {
    "command": "npx",
    "args": ["-y", "@xyteai/mcp"],
    "env": { "${ENV.orgKey}": "<key>" }
  }
`;

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    process.stderr.write(USAGE);
    return;
  }
  if (args.includes('--version') || args.includes('-V')) {
    process.stderr.write(`${VERSION}\n`);
    return;
  }
  const http = args.includes('--http');
  const unknown = args.filter((arg) => arg.startsWith('-') && arg !== '--http');
  if (unknown.length) {
    logError(`unknown argument(s): ${unknown.join(', ')}`);
    process.stderr.write(USAGE);
    process.exitCode = 2;
    return;
  }

  if (http) {
    await startHttpServer();
    return; // The listener keeps the process alive.
  }
  await startStdioServer();
}

main().catch((error: unknown) => {
  // A misconfiguration is the common case and deserves an actionable message
  // rather than a stack trace.
  if (isXyteError(error)) {
    logError(error.message);
    for (const hint of error.hints) process.stderr.write(`  - ${hint}\n`);
  } else {
    logError(error instanceof Error ? (error.stack ?? error.message) : String(error));
  }
  process.exit(1);
});
