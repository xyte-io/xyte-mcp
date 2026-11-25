import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MIGRATIONS } from '../src/oauth/pg-store.js';
import { createTestSchema, newTokenKey, type TestSchema } from './support/two-process.js';

/**
 * The release-phase entry's wiring only (the migrations themselves are
 * pg-migrations.test.ts): it spawns the built dist, so run `npm run build` first.
 */

const PG_URL = process.env.TEST_DATABASE_URL;
const MIGRATE_ENTRY = path.resolve(import.meta.dirname, '..', 'dist', 'migrate.js');
/** Port 1 refuses at once: a connection attempt would fail the run with a connection error. */
const UNREACHABLE_DSN = 'postgres://127.0.0.1:1/none?sslmode=disable';

/** A complete OAuth config, as on the app; overrides with `undefined` unset a variable. */
function oauthEnv(databaseUrl: string | undefined): Record<string, string | undefined> {
  return {
    XYTE_MCP_ISSUER_URL: 'https://mcp.example.com',
    XYTE_MCP_HUB_OAUTH_CLIENT_ID: 'mcp-client',
    XYTE_MCP_HUB_OAUTH_CLIENT_SECRET: 'mcp-secret',
    XYTE_MCP_TOKEN_KEY: newTokenKey(),
    DATABASE_URL: databaseUrl
  };
}

async function runMigrate(vars: Record<string, string | undefined>): Promise<{ code: number | null; stderr: string }> {
  if (!existsSync(MIGRATE_ENTRY)) throw new Error(`Build first: ${MIGRATE_ENTRY} is missing (npm run build).`);
  const env: NodeJS.ProcessEnv = {};
  // Only this test's config: none of the runner's XYTE_*, DATABASE_URL or PORT.
  for (const [name, value] of Object.entries(process.env)) {
    if (!/^(XYTE_|DATABASE_URL$|PORT$)/.test(name)) env[name] = value;
  }
  for (const [name, value] of Object.entries(vars)) if (value !== undefined) env[name] = value;
  const child = spawn(process.execPath, [MIGRATE_ENTRY], { env, stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
  const code = await new Promise<number | null>((resolve) => child.on('close', resolve));
  return { code, stderr };
}

describe('migrate entry without a database', () => {
  it('is the entry the Procfile release line runs', () => {
    const procfile = readFileSync(path.resolve(import.meta.dirname, '..', '..', '..', 'Procfile'), 'utf8');
    // A Windows checkout has CRLF line ends and backslash paths.
    const lines = procfile.split(/\r?\n/);
    const release = lines.find((line) => line.startsWith('release:'));
    const web = lines.find((line) => line.startsWith('web:'));
    expect(release).toMatch(/ node packages\/remote\/dist\/migrate\.js$/);
    // The same CA default as the web line, so the two cannot drift.
    expect(release).toBe(web?.replace(/^web:/, 'release:').replace('dist/index.js', 'dist/migrate.js'));
    expect(path.relative(path.resolve(import.meta.dirname, '..', '..', '..'), MIGRATE_ENTRY).split(path.sep).join('/')).toBe(
      'packages/remote/dist/migrate.js'
    );
  });

  it('exits 1 with a migration failure when the database is unreachable', async () => {
    const { code, stderr } = await runMigrate(oauthEnv(UNREACHABLE_DSN));
    expect(code).toBe(1);
    expect(stderr).toContain('[xyte-mcp] error: OAuth store migration failed:');
  });

  it('exits 1 with a migration failure, and no stack trace, when the sslrootcert file is missing', async () => {
    const { code, stderr } = await runMigrate(
      oauthEnv('postgres://127.0.0.1:1/x?sslmode=verify-full&sslrootcert=/nonexistent')
    );
    expect(code).toBe(1);
    expect(stderr).toContain('[xyte-mcp] error: OAuth store migration failed:');
    // Windows resolves it to <drive>:\nonexistent.
    expect(stderr).toMatch(/[\\/]nonexistent/);
    expect(stderr).not.toMatch(/^\s+at /m);
  });

  it('exits 0 and says there is nothing to migrate for a local issuer without a database', async () => {
    const { code, stderr } = await runMigrate({
      ...oauthEnv(undefined),
      XYTE_MCP_ISSUER_URL: 'http://localhost:3000'
    });
    expect(code, stderr).toBe(0);
    expect(stderr).toContain('[xyte-mcp] no DATABASE_URL, nothing to migrate');
  });

  it('exits 0 without connecting when the app is not in OAuth mode', async () => {
    const { code, stderr } = await runMigrate({
      XYTE_MCP_HTTP_TOKEN: `xmcp_${'a'.repeat(32)}`,
      XYTE_ORG_API_KEY: 'org-key',
      DATABASE_URL: UNREACHABLE_DSN
    });
    expect(code, stderr).toBe(0);
    expect(stderr).toContain('[xyte-mcp] XYTE_MCP_ISSUER_URL is not set (not in OAuth mode), nothing to migrate');
  });

  it('exits 1 with the config error, before connecting, when the web boot would refuse the config', async () => {
    const { code, stderr } = await runMigrate({
      ...oauthEnv(UNREACHABLE_DSN),
      XYTE_MCP_HTTP_TOKEN: `xmcp_${'a'.repeat(32)}`,
      XYTE_ORG_API_KEY: 'org-key'
    });
    expect(code).toBe(1);
    expect(stderr).toContain(
      '[xyte-mcp] error: XYTE_MCP_HTTP_TOKEN and XYTE_MCP_ISSUER_URL are both set; a deployment serves one or the other.'
    );
    expect(stderr).toContain('  - Unset XYTE_MCP_HTTP_TOKEN for OAuth');
    expect(stderr).not.toContain('migration failed');
  });

  it('exits 1 on a rate bucket secret that is not visible ASCII, without logging the value', async () => {
    const { code, stderr } = await runMigrate({
      XYTE_MCP_HTTP_TOKEN: `xmcp_${'a'.repeat(32)}`,
      XYTE_ORG_API_KEY: 'org-key',
      XYTE_MCP_RATE_BUCKET_SECRET: 'leaky-secret\nx'
    });
    expect(code, stderr).toBe(1);
    expect(stderr).toContain('[xyte-mcp] error: XYTE_MCP_RATE_BUCKET_SECRET must be visible ASCII');
    expect(stderr).not.toContain('leaky');
  });
});

describe.skipIf(!PG_URL)('migrate entry against Postgres', () => {
  let schema: TestSchema;
  beforeAll(async () => {
    schema = await createTestSchema(PG_URL!);
  });
  afterAll(async () => {
    await schema?.drop();
  });

  // First: the schema is still fresh here.
  it('exits 1 and leaves a fresh schema unmigrated when the token key is missing', async () => {
    const { code, stderr } = await runMigrate({ ...oauthEnv(schema.databaseUrl), XYTE_MCP_TOKEN_KEY: undefined });
    expect(code).toBe(1);
    expect(stderr).toContain('[xyte-mcp] error: XYTE_MCP_TOKEN_KEY must be the base64 of exactly 32 random bytes');
    const { rows } = await schema.admin.query<{ table: string | null }>(
      `SELECT to_regclass('oauth_schema_migrations')::text AS table`
    );
    expect(rows[0]!.table).toBeNull();
  });

  it('migrates a fresh schema and exits 0, and a second run exits 0 too', async () => {
    const first = await runMigrate(oauthEnv(schema.databaseUrl));
    expect(first.code, first.stderr).toBe(0);
    const { rows } = await schema.admin.query<{ n: number }>('SELECT count(*)::int AS n FROM oauth_schema_migrations');
    expect(rows[0]!.n).toBe(MIGRATIONS.length);
    expect(first.stderr).toContain('OAuth store schema migrated to version');

    const second = await runMigrate(oauthEnv(schema.databaseUrl));
    expect(second.code, second.stderr).toBe(0);
    expect(second.stderr).not.toContain('migrated to version');
    const again = await schema.admin.query<{ n: number }>('SELECT count(*)::int AS n FROM oauth_schema_migrations');
    expect(again.rows[0]!.n).toBe(MIGRATIONS.length);
  });

  it('exits 1 and names the version when the database holds a newer version that breaks rollback', async () => {
    await schema.admin.query(
      `INSERT INTO oauth_schema_migrations (version, name, breaks_rollback) VALUES (9999, 'from the future', true)`
    );
    const { code, stderr } = await runMigrate(oauthEnv(schema.databaseUrl));
    expect(code).toBe(1);
    expect(stderr).toContain('[xyte-mcp] error: OAuth store migration failed:');
    expect(stderr).toContain('version 9999');
  });
});
