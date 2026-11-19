#!/usr/bin/env node
import { isXyteError } from '@xyteai/mcp/http/errors.js';
import { logError } from '@xyteai/mcp/log.js';
import { VERSION } from '@xyteai/mcp/version.js';
import { startHttpServer } from './transports/http.js';

// ponytail: --http is accepted and ignored so existing tests and start commands keep working; drop it once nothing passes it.
const args = process.argv.slice(2);
const unknown = args.filter((arg) => arg.startsWith('-') && !['--http', '--version', '-V'].includes(arg));
if (unknown.length) {
  logError(`unknown argument(s): ${unknown.join(', ')}`);
  process.exitCode = 2;
} else if (args.includes('--version') || args.includes('-V')) {
  process.stderr.write(`${VERSION}\n`);
} else {
  // The listener keeps the process alive. A misconfiguration gets its message and hints, not a stack.
  startHttpServer().catch((error: unknown) => {
    if (isXyteError(error)) {
      logError(error.message);
      for (const hint of error.hints) process.stderr.write(`  - ${hint}\n`);
    } else {
      logError(error instanceof Error ? (error.stack ?? error.message) : String(error));
    }
    process.exit(1);
  });
}
