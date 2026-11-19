import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { MIGRATIONS, migrateOAuthSchema } from '../src/oauth/pg-store.js';

/**
 * The schema migrator against a throwaway database (TEST_DATABASE_URL). Each
 * test runs in its own Postgres schema, so it never meets the shared tables
 * oauth-store.test.ts truncates in parallel.
 */

const PG_URL = process.env.TEST_DATABASE_URL;

describe.skipIf(!PG_URL)('migrateOAuthSchema', () => {
  let admin: pg.Pool;
  let schema: string;
  let pools: pg.Pool[];

  const poolForSchema = (): pg.Pool => {
    const pool = new pg.Pool({ connectionString: PG_URL, options: `-c search_path=${schema}` });
    pools.push(pool);
    return pool;
  };
  const tablesIn = async (): Promise<string[]> =>
    (
      await admin.query<{ table_name: string }>(
        'SELECT table_name FROM information_schema.tables WHERE table_schema = $1 ORDER BY 1',
        [schema]
      )
    ).rows.map((row) => row.table_name);
  const appliedVersions = async (): Promise<Array<{ version: number; breaks_rollback: boolean }>> =>
    (
      await admin.query<{ version: number; breaks_rollback: boolean }>(
        `SELECT version, breaks_rollback FROM ${schema}.oauth_schema_migrations ORDER BY version`
      )
    ).rows;

  beforeAll(() => {
    admin = new pg.Pool({ connectionString: PG_URL, max: 2 });
  });
  afterAll(async () => {
    await admin.end();
  });
  beforeEach(async () => {
    schema = `migrations_test_${randomUUID().replaceAll('-', '')}`;
    pools = [];
    await admin.query(`CREATE SCHEMA ${schema}`);
  });
  afterEach(async () => {
    await Promise.all(pools.map((pool) => pool.end()));
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  });

  it('creates the schema on an empty database and records version 1', async () => {
    await migrateOAuthSchema(poolForSchema());

    expect(await tablesIn()).toEqual([
      'oauth_clients',
      'oauth_grants',
      'oauth_schema_migrations',
      'oauth_tokens'
    ]);
    expect(await appliedVersions()).toEqual([{ version: 1, breaks_rollback: false }]);
  });

  it('adopts a database created before versioning as version 1, keeping its rows', async () => {
    const pool = poolForSchema();
    await pool.query(MIGRATIONS[0]!.sql);
    await pool.query(`INSERT INTO oauth_clients (client_id, data) VALUES ('c1', '{}')`);
    await pool.query(
      `INSERT INTO oauth_grants (client_id, hub_sub, hub_tenant, hub_access_token, hub_refresh_token, hub_expires_at)
       VALUES ('c1', 'sub', 'tenant', 'a', 'r', now())`
    );

    await migrateOAuthSchema(pool);

    expect(await appliedVersions()).toEqual([{ version: 1, breaks_rollback: false }]);
    expect((await pool.query('SELECT client_id FROM oauth_clients')).rows).toEqual([
      { client_id: 'c1' }
    ]);
    expect((await pool.query('SELECT count(*)::int AS n FROM oauth_grants')).rows).toEqual([
      { n: 1 }
    ]);
  });

  it('runs nothing again on a second boot', async () => {
    const pool = poolForSchema();
    const counted = [
      { sql: 'CREATE TABLE runs (n int); INSERT INTO runs VALUES (1);', breaksRollback: false }
    ];
    await migrateOAuthSchema(pool, counted);
    await migrateOAuthSchema(pool, counted);

    expect((await pool.query('SELECT count(*)::int AS n FROM runs')).rows).toEqual([{ n: 1 }]);
    expect(await appliedVersions()).toEqual([{ version: 1, breaks_rollback: false }]);
  });

  it('lets two boots migrate an empty database at once without racing', async () => {
    await Promise.all([migrateOAuthSchema(poolForSchema()), migrateOAuthSchema(poolForSchema())]);

    expect(await appliedVersions()).toEqual([{ version: 1, breaks_rollback: false }]);
  });

  it('leaves the database unchanged when a migration fails, naming it', async () => {
    const failing = [
      MIGRATIONS[0]!,
      {
        sql: 'CREATE TABLE half_done (n int); SELECT no_such_column FROM half_done;',
        breaksRollback: false
      }
    ];

    await expect(migrateOAuthSchema(poolForSchema(), failing)).rejects.toThrow(
      /^OAuth store schema migration 2 failed: column "no_such_column" does not exist$/
    );

    // One transaction: not even version 1 or the version table survives.
    expect(await tablesIn()).toEqual([]);
  });

  it('leaves an already-migrated database at its version when a later migration fails', async () => {
    const pool = poolForSchema();
    await migrateOAuthSchema(pool);

    const failing = [
      MIGRATIONS[0]!,
      { sql: 'CREATE TABLE half_done (n int); SELECT 1/0;', breaksRollback: false }
    ];

    await expect(migrateOAuthSchema(pool, failing)).rejects.toThrow(/^OAuth store schema migration 2 failed: division by zero$/);

    expect(await tablesIn()).not.toContain('half_done');
    expect(await appliedVersions()).toEqual([{ version: 1, breaks_rollback: false }]);
  });

  it('boots against a newer version that keeps the rollback promise', async () => {
    const pool = poolForSchema();
    await migrateOAuthSchema(pool);
    await pool.query('INSERT INTO oauth_schema_migrations (version, breaks_rollback) VALUES (2, false)');

    await expect(migrateOAuthSchema(pool)).resolves.toBeUndefined();
  });

  it('refuses to boot against a newer version that breaks rollback', async () => {
    const pool = poolForSchema();
    await migrateOAuthSchema(pool);
    await pool.query('INSERT INTO oauth_schema_migrations (version, breaks_rollback) VALUES (2, true)');

    await expect(migrateOAuthSchema(pool)).rejects.toThrow(
      'OAuth store schema version 2 is newer than this build and cannot be rolled back to; deploy a build that knows it'
    );
  });
});
