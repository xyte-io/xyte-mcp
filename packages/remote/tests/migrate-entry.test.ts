import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestSchema, type TestSchema } from './support/two-process.js';

/**
 * The release-phase entry's wiring only (the migrations themselves are
 * pg-migrations.test.ts): it spawns the built dist, so run `npm run build` first.
 */

const PG_URL = process.env.TEST_DATABASE_URL;
const MIGRATE_ENTRY = path.resolve(import.meta.dirname, '..', 'dist', 'migrate.js');

async function runMigrate(
  databaseUrl: string | undefined,
  issuerUrl: string | undefined = 'https://mcp.example.com'
): Promise<{ code: number | null; stderr: string }> {
  if (!existsSync(MIGRATE_ENTRY)) throw new Error(`Build first: ${MIGRATE_ENTRY} is missing (npm run build).`);
  const env = { ...process.env };
  delete env.DATABASE_URL;
  delete env.XYTE_MCP_ISSUER_URL;
  if (databaseUrl) env.DATABASE_URL = databaseUrl;
  if (issuerUrl) env.XYTE_MCP_ISSUER_URL = issuerUrl;
  const child = spawn(process.execPath, [MIGRATE_ENTRY], { env, stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
  const code = await new Promise<number | null>((resolve) => child.on('close', resolve));
  return { code, stderr };
}

describe('migrate entry without a database', () => {
  it('exits 0 and says there is nothing to migrate', async () => {
    const { code, stderr } = await runMigrate(undefined);
    expect(code).toBe(0);
    expect(stderr).toContain('[xyte-mcp] no DATABASE_URL, nothing to migrate');
  });

  it('exits 0 without connecting when the app is not in OAuth mode', async () => {
    // Port 1 refuses at once: a connection attempt would fail the run.
    const { code, stderr } = await runMigrate('postgres://127.0.0.1:1/none?sslmode=disable', '');
    expect(code, stderr).toBe(0);
    expect(stderr).toContain('[xyte-mcp] XYTE_MCP_ISSUER_URL is not set (not in OAuth mode), nothing to migrate');
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

  it('migrates a fresh schema and exits 0, and a second run exits 0 too', async () => {
    const first = await runMigrate(schema.databaseUrl);
    expect(first.code, first.stderr).toBe(0);
    const { rows } = await schema.admin.query<{ n: number }>('SELECT count(*)::int AS n FROM oauth_schema_migrations');
    expect(rows[0]!.n).toBeGreaterThan(0);

    const second = await runMigrate(schema.databaseUrl);
    expect(second.code, second.stderr).toBe(0);
  });

  it('exits 1 and names the version when the database holds a newer version that breaks rollback', async () => {
    await schema.admin.query(
      `INSERT INTO oauth_schema_migrations (version, name, breaks_rollback) VALUES (9999, 'from the future', true)`
    );
    const { code, stderr } = await runMigrate(schema.databaseUrl);
    expect(code).toBe(1);
    expect(stderr).toContain('[xyte-mcp] error: OAuth store migration failed:');
    expect(stderr).toContain('version 9999');
  });
});
