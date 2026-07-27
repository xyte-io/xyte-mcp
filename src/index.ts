#!/usr/bin/env node
import { ENV } from './config.js';
import { isXyteError } from './http/errors.js';
import { logError } from './log.js';
import { startStdioServer } from './transports/stdio.js';
import { VERSION } from './version.js';

const USAGE = `xyte-mcp ${VERSION} — MCP server for the Xyte platform API

Usage:
  xyte-mcp                Serve over stdio (the only transport today).
  xyte-mcp --version      Print version and exit.
  xyte-mcp --help         Print this message and exit.

Environment:
  ${ENV.orgKey}        Organization-scoped API key.
  ${ENV.partnerKey}    Partner-scoped API key. Set either or both.
  ${ENV.readOnly}     Set to 1 to refuse all mutating endpoints. Writes are on by default.
  ${ENV.hubUrl}            Override the hub base URL (default https://hub.xyte.io).
  ${ENV.entryUrl}          Override the entry base URL.
  ${ENV.timeoutMs}     Per-request timeout in ms (default 15000).

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
  const unknown = args.filter((arg) => arg.startsWith('-'));
  if (unknown.length) {
    logError(`unknown argument(s): ${unknown.join(', ')}`);
    process.stderr.write(USAGE);
    process.exitCode = 2;
    return;
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
