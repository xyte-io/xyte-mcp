#!/usr/bin/env node
/**
 * The release-phase entry (Procfile `release:`): applies the OAuth store
 * migrations once per release, before any new dyno starts. A non-zero exit
 * fails the release, so the running dynos keep serving the old build. The web
 * boot still calls migrateOAuthSchema, which then finds nothing to apply.
 *
 * It resolves the HTTP config first (resolveHttpConfig, as the web boot does),
 * so a config error fails the release before a migration (perhaps one that
 * breaks rollback) is applied. It does not run the boot's hub token key-id
 * check: a token key the live grants were not written with passes the release
 * and is refused only at boot (README, key rotation). resolveHttpConfig is pure (no log, no I/O) and needs no
 * PORT: unset, it defaults (a release dyno gets none); set but invalid, the web
 * boot would refuse it too.
 */
import pg from 'pg';
import { ENV, resolveHttpConfig, type HttpConfig } from '@xyteai/mcp/config.js';
import { isXyteError } from '@xyteai/mcp/http/errors.js';
import { log, logError } from '@xyteai/mcp/log.js';
import { errorCodeOf } from './log-event.js';
import { bootConnectionHints, bootFailureMessage, migrateOAuthSchema, sslOption } from './oauth/pg-store.js';

let config: HttpConfig | undefined;
try {
  config = resolveHttpConfig();
} catch (error) {
  if (!isXyteError(error)) throw error;
  // Same output as the web boot's (index.ts).
  logError(error.message);
  for (const hint of error.hints) process.stderr.write(`  - ${hint}\n`);
  process.exitCode = 1;
}
const databaseUrl = config?.oauth?.databaseUrl;
if (!config) {
  // The config error is reported above.
} else if (!config.oauth) {
  log(`${ENV.issuerUrl} is not set (not in OAuth mode), nothing to migrate`);
} else if (!databaseUrl) {
  log('no DATABASE_URL, nothing to migrate');
} else {
  let pool: pg.Pool | undefined;
  try {
    // Inside the try: parsing the DSN reads an sslrootcert file, which may be missing.
    pool = new pg.Pool({
      connectionString: databaseUrl,
      ...sslOption(databaseUrl),
      connectionTimeoutMillis: 10_000,
      // A half-open connection during a failover then errors instead of hanging the
      // release. pg's initial delay defaults to 0, which leaves the OS default (hours).
      keepAlive: true,
      keepAliveInitialDelayMillis: 10_000,
      max: 1
    });
    pool.on('error', (error) => logError(`postgres migration pool: ${errorCodeOf(error)}`));
    await migrateOAuthSchema(pool);
    log('OAuth store migrations done');
  } catch (error) {
    logError(`OAuth store migration failed: ${bootFailureMessage(error)}`);
    for (const hint of bootConnectionHints(error)) process.stderr.write(`  - ${hint}\n`);
    process.exitCode = 1;
  } finally {
    await pool?.end().catch(() => {});
  }
}
