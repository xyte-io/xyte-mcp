import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { MIGRATIONS, PgOAuthStore, migrateOAuthSchema, type Migration } from '../src/oauth/pg-store.js';
import { TokenCipher } from '../src/oauth/token-cipher.js';

/**
 * The schema migrator against a throwaway database (TEST_DATABASE_URL). Each
 * test runs in its own Postgres schema, so it never meets the shared tables
 * oauth-store.test.ts truncates in parallel.
 */

const PG_URL = process.env.TEST_DATABASE_URL;

const BASELINE = { version: 1, name: 'baseline', breaks_rollback: false };
const ENCRYPT = { version: 2, name: 'encrypt_hub_tokens', breaks_rollback: true };
const PENDING = { version: 3, name: 'pending_sign_ins', breaks_rollback: false };
/** A build that only knew the baseline. */
const V1 = [MIGRATIONS[0]!];

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
  const appliedVersions = async (): Promise<
    Array<{ version: number; name: string; breaks_rollback: boolean }>
  > =>
    (
      await admin.query<{ version: number; name: string; breaks_rollback: boolean }>(
        `SELECT version, name, breaks_rollback FROM ${schema}.oauth_schema_migrations ORDER BY version`
      )
    ).rows;
  /** Silences log() and returns a reader for what it wrote since. */
  const captureLog = (): (() => string) => {
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    return () => write.mock.calls.map((call) => String(call[0])).join('');
  };

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
    vi.restoreAllMocks();
    await Promise.all(pools.map((pool) => pool.end()));
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  });

  it('creates the schema on an empty database and records every version', async () => {
    const logText = captureLog();
    await migrateOAuthSchema(poolForSchema());

    expect(await tablesIn()).toEqual([
      'oauth_clients',
      'oauth_grants',
      'oauth_pending_sign_ins',
      'oauth_schema_migrations',
      'oauth_tokens'
    ]);
    expect(await appliedVersions()).toEqual([BASELINE, ENCRYPT, PENDING]);
    expect(logText()).toContain('OAuth store schema migrated to version 1 (baseline)');
    expect(logText()).toContain('OAuth store schema migrated to version 2 (encrypt_hub_tokens)');
    expect(logText()).toContain('OAuth store schema migrated to version 3 (pending_sign_ins)');
  });

  it('adopts a database created before versioning as version 1, keeping its rows', async () => {
    const pool = poolForSchema();
    await pool.query(MIGRATIONS[0]!.sql);
    await pool.query(`INSERT INTO oauth_clients (client_id, data) VALUES ('c1', '{}')`);
    await pool.query(
      `INSERT INTO oauth_grants (client_id, hub_sub, hub_tenant, hub_access_token, hub_refresh_token, hub_expires_at)
       VALUES ('c1', 'sub', 'tenant', 'a', 'r', now())`
    );

    const logText = captureLog();
    await migrateOAuthSchema(pool);

    expect(await appliedVersions()).toEqual([BASELINE, ENCRYPT, PENDING]);
    expect(logText()).toContain('adopted the existing schema as version 1 (baseline)');
    expect((await pool.query('SELECT client_id FROM oauth_clients')).rows).toEqual([
      { client_id: 'c1' }
    ]);
    // Kept, but signed out by version 2: its hub tokens were plain text.
    expect(
      (await pool.query('SELECT revoked_at IS NOT NULL AS revoked FROM oauth_grants')).rows
    ).toEqual([{ revoked: true }]);
  });

  // Their hub tokens are plain text, which the encrypting build cannot read.
  it('version 2 signs out every live grant written unencrypted, keeping the rows', async () => {
    const pool = poolForSchema();
    await migrateOAuthSchema(pool, V1);
    await pool.query(
      `INSERT INTO oauth_grants (client_id, hub_sub, hub_tenant, hub_access_token, hub_refresh_token, hub_expires_at)
       VALUES ('c1', 'sub', 'tenant', 'xoat_plain', 'xort_plain', now())`
    );
    await pool.query(
      `INSERT INTO oauth_grants (client_id, hub_sub, hub_tenant, hub_expires_at, revoked_at)
       VALUES ('c1', 'sub', 'tenant', now(), '2020-01-01')`
    );

    captureLog();
    await migrateOAuthSchema(pool);

    expect(await appliedVersions()).toEqual([BASELINE, ENCRYPT, PENDING]);
    const grants = await pool.query(
      `SELECT revoked_at IS NOT NULL AS revoked, revoked_at < '2021-01-01' AS revoked_earlier,
              hub_access_token, hub_refresh_token, hub_refresh_token_hash
         FROM oauth_grants ORDER BY id`
    );
    const signedOut = {
      revoked: true,
      hub_access_token: null,
      hub_refresh_token: null,
      hub_refresh_token_hash: null
    };
    expect(grants.rows).toEqual([
      { ...signedOut, revoked_earlier: false },
      { ...signedOut, revoked_earlier: true }
    ]);
  });

  // The previous release (up to version 2) keeps serving during the rollout,
  // and may be rolled back to: it must still boot against version 3.
  it('lets a build that only knows versions 1 and 2 boot against version 3', async () => {
    const pool = poolForSchema();
    await migrateOAuthSchema(pool);

    const logText = captureLog();
    await expect(migrateOAuthSchema(pool, MIGRATIONS.slice(0, 2))).resolves.toBeUndefined();

    expect(await appliedVersions()).toEqual([BASELINE, ENCRYPT, PENDING]);
    expect(logText()).toContain(
      "OAuth store schema is at version 3, newer than this build's 2; those versions are rollback-safe, booting"
    );
  });

  it('runs nothing again on a second boot', async () => {
    const pool = poolForSchema();
    const counted: Migration[] = [
      { version: 1, name: 'runs', sql: 'CREATE TABLE runs (n int); INSERT INTO runs VALUES (1);', breaksRollback: false }
    ];
    await migrateOAuthSchema(pool, counted);
    await migrateOAuthSchema(pool, counted);

    expect((await pool.query('SELECT count(*)::int AS n FROM runs')).rows).toEqual([{ n: 1 }]);
    expect(await appliedVersions()).toEqual([{ version: 1, name: 'runs', breaks_rollback: false }]);
  });

  it('lets two boots migrate an empty database at once without racing', async () => {
    await Promise.all([migrateOAuthSchema(poolForSchema()), migrateOAuthSchema(poolForSchema())]);

    expect(await appliedVersions()).toEqual([BASELINE, ENCRYPT, PENDING]);
  });

  it('records whether a migration breaks rollback', async () => {
    await migrateOAuthSchema(poolForSchema(), [
      MIGRATIONS[0]!,
      { version: 2, name: 'breaking', sql: 'SELECT 1', breaksRollback: true }
    ]);

    expect(await appliedVersions()).toEqual([
      BASELINE,
      { version: 2, name: 'breaking', breaks_rollback: true }
    ]);
  });

  it('refuses a migration list whose versions do not run 1, 2, 3 in order', async () => {
    await expect(
      migrateOAuthSchema(poolForSchema(), [
        MIGRATIONS[0]!,
        { version: 3, name: 'skipped', sql: 'SELECT 1', breaksRollback: false }
      ])
    ).rejects.toThrow(/^OAuth store migration at position 2 says version 3/);
    expect(await tablesIn()).toEqual([]);
  });

  it('refuses to boot when a recorded version came from a different migration', async () => {
    const pool = poolForSchema();
    await migrateOAuthSchema(pool, [
      MIGRATIONS[0]!,
      { version: 2, name: 'branch_a', sql: 'SELECT 1', breaksRollback: false }
    ]);

    await expect(
      migrateOAuthSchema(pool, [
        MIGRATIONS[0]!,
        { version: 2, name: 'branch_b', sql: 'CREATE TABLE branch_b (n int)', breaksRollback: false }
      ])
    ).rejects.toThrow(
      /^OAuth store schema version 2 in the database is "branch_a", but this build's version 2 is "branch_b"/
    );
    expect(await tablesIn()).not.toContain('branch_b');
  });

  it('leaves the database unchanged when a migration fails, naming it', async () => {
    const failing: Migration[] = [
      MIGRATIONS[0]!,
      {
        version: 2,
        name: 'half_done',
        sql: 'CREATE TABLE half_done (n int); SELECT no_such_column FROM half_done;',
        breaksRollback: false
      }
    ];

    await expect(migrateOAuthSchema(poolForSchema(), failing)).rejects.toMatchObject({
      message: expect.stringMatching(/^OAuth store schema migration 2 \(half_done\) failed: .*\(code 42703/),
      cause: expect.objectContaining({ code: '42703' })
    });

    // One transaction: not even version 1 or the version table survives.
    expect(await tablesIn()).toEqual([]);
  });

  it('leaves an already-migrated database at its version when a later migration fails', async () => {
    const pool = poolForSchema();
    await migrateOAuthSchema(pool, V1);

    const failing: Migration[] = [
      MIGRATIONS[0]!,
      { version: 2, name: 'half_done', sql: 'CREATE TABLE half_done (n int); SELECT 1/0;', breaksRollback: false }
    ];

    await expect(migrateOAuthSchema(pool, failing)).rejects.toMatchObject({
      message: expect.stringMatching(/^OAuth store schema migration 2 \(half_done\) failed: /),
      cause: expect.objectContaining({ code: '22012' })
    });

    expect(await tablesIn()).not.toContain('half_done');
    expect(await appliedVersions()).toEqual([BASELINE]);
  });

  it('boots against a newer version that is rollback-safe, changing nothing', async () => {
    const pool = poolForSchema();
    await migrateOAuthSchema(pool, V1);
    await pool.query(
      `INSERT INTO oauth_schema_migrations (version, name, breaks_rollback) VALUES (2, 'newer', false)`
    );

    const logText = captureLog();
    await expect(migrateOAuthSchema(pool, V1)).resolves.toBeUndefined();

    expect(await appliedVersions()).toEqual([BASELINE, { version: 2, name: 'newer', breaks_rollback: false }]);
    expect(logText()).toContain(
      "OAuth store schema is at version 2, newer than this build's 1; those versions are rollback-safe, booting"
    );
    expect(logText()).not.toContain('migrated to version');
  });

  it('refuses to boot against a newer version that breaks rollback, before running anything', async () => {
    const pool = poolForSchema();
    await migrateOAuthSchema(pool, V1);
    await pool.query(
      `INSERT INTO oauth_schema_migrations (version, name, breaks_rollback) VALUES (3, 'breaking', true)`
    );
    const before = await appliedVersions();

    await expect(
      migrateOAuthSchema(pool, [
        MIGRATIONS[0]!,
        { version: 2, name: 'pending', sql: 'CREATE TABLE should_not_exist (n int)', breaksRollback: false }
      ])
    ).rejects.toThrow(
      'OAuth store schema is at version 3, which this build (up to version 2) does not know and which breaks rollback; release a build at version 3 or later instead of rolling back'
    );

    expect(await tablesIn()).not.toContain('should_not_exist');
    expect(await appliedVersions()).toEqual(before);
  });

  it('fails PgOAuthStore.connect with the migration error', async () => {
    const pool = poolForSchema();
    await migrateOAuthSchema(pool);
    const newer = MIGRATIONS.length + 1;
    await pool.query(
      `INSERT INTO oauth_schema_migrations (version, name, breaks_rollback) VALUES ($1, 'breaking', true)`,
      [newer]
    );
    const url = new URL(PG_URL!);
    url.searchParams.set('options', `-c search_path=${schema}`);

    await expect(
      PgOAuthStore.connect(url.toString(), new TokenCipher(Buffer.alloc(32)))
    ).rejects.toThrow(
      new RegExp(`^Postgres setup failed at boot: OAuth store schema is at version ${newer}, which this build`)
    );
  });
});
