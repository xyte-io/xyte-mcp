/**
 * Diagnostics for a stdio server MUST go to stderr.
 *
 * On stdio, stdout carries the JSON-RPC frames: a single stray `console.log`
 * corrupts the stream and the host drops the connection with a parse error.
 * This module is the only sanctioned way to emit a message, and an eslint rule
 * (`no-console`) keeps `console` out of `src/`.
 */

export function log(message: string): void {
  process.stderr.write(`[xyte-mcp] ${message}\n`);
}

export function logError(message: string): void {
  process.stderr.write(`[xyte-mcp] error: ${message}\n`);
}
