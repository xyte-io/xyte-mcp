import { afterEach, describe, expect, it } from 'vitest';
import { isXyteError } from '@xyteai/mcp/http/errors.js';
import { PgOAuthStore, sslOption } from '../src/oauth/pg-store.js';

const REMOTE = 'postgres://u:p@db.example.com:5432/db';
const SAVED_PGSSLMODE = process.env.PGSSLMODE;

afterEach(() => {
  if (SAVED_PGSSLMODE === undefined) delete process.env.PGSSLMODE;
  else process.env.PGSSLMODE = SAVED_PGSSLMODE;
});

describe('sslOption', () => {
  it('leaves a local database to pg (no TLS)', () => {
    delete process.env.PGSSLMODE;
    expect(sslOption('postgres://u:p@localhost:5432/db')).toEqual({});
    expect(sslOption('postgres://u:p@127.0.0.1:5432/db')).toEqual({});
  });

  it('verifies the certificate of a remote database', () => {
    delete process.env.PGSSLMODE;
    expect(sslOption(REMOTE)).toEqual({ ssl: true });
  });

  it.each(['no-verify', 'disable'])('leaves an explicit PGSSLMODE=%s to pg', (mode) => {
    process.env.PGSSLMODE = mode;
    expect(sslOption(REMOTE)).toEqual({});
  });

  it('keeps verifying on any other PGSSLMODE value', () => {
    process.env.PGSSLMODE = 'noverify';
    expect(sslOption(REMOTE)).toEqual({ ssl: true });
  });
});

describe('PgOAuthStore.connect', () => {
  it('turns a boot connection failure into a config error', async () => {
    const error = await PgOAuthStore.connect('postgres://u:p@127.0.0.1:1/db?sslmode=disable').catch(
      (caught: unknown) => caught
    );
    expect(isXyteError(error)).toBe(true);
    expect((error as Error).message).toMatch(/^Postgres connection failed at boot/);
  });
});
