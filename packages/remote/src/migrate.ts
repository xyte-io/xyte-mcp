#!/usr/bin/env node
/**
 * The release-phase entry (Procfile `release:`): applies the OAuth store
 * migrations once per release, before any new dyno starts. A non-zero exit
 * fails the release, so the running dynos keep serving the old build. The web
 * boot still calls migrateOAuthSchema, which then finds nothing to apply.
 */
import pg from 'pg';
import { log, logError } from '@xyteai/mcp/log.js';
import { errorCodeOf } from './log-event.js';
import { bootConnectionHints, bootFailureMessage, migrateOAuthSchema, sslOption } from './oauth/pg-store.js';

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  log('no DATABASE_URL, nothing to migrate');
} else {
  let pool: pg.Pool | undefined;
  try {
    // Inside the try: parsing the DSN reads an sslrootcert file, which may be missing.
    pool = new pg.Pool({
      connectionString: databaseUrl,
      ...sslOption(databaseUrl),
      connectionTimeoutMillis: 10_000,
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
