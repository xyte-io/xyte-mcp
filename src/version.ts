import { createRequire } from 'node:module';

/**
 * Package version, reported to MCP clients during initialize.
 *
 * Read from package.json at runtime so it cannot drift from what was published.
 * Resolves from both `dist/` and `src/` (via tsx), since package.json sits one
 * level above either.
 */
function readVersion(): string {
  try {
    const require = createRequire(import.meta.url);
    const pkg = require('../package.json') as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export const VERSION = readVersion();
