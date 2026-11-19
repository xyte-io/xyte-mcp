import pg from 'pg';
import { afterEach, describe, expect, it } from 'vitest';
import { isXyteError } from '@xyteai/mcp/http/errors.js';
import { bootConnectionHints, PgOAuthStore, sslOption } from '../src/oauth/pg-store.js';

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

  // sslOption no longer checks the DSN: pg applies a DSN sslmode over the passed `ssl`.
  it.each([
    ['disable', false],
    ['no-verify', { rejectUnauthorized: false }]
  ])('lets a DSN sslmode=%s win in pg', (mode, expected) => {
    delete process.env.PGSSLMODE;
    const connectionString = `${REMOTE}?sslmode=${mode}`;
    const client = new pg.Client({ connectionString, ...sslOption(connectionString) });
    expect((client as unknown as { connectionParameters: { ssl: unknown } }).connectionParameters.ssl).toEqual(
      expected
    );
  });
});

function errorWithCode(code: string, message = code): Error {
  return Object.assign(new Error(message), { code });
}

describe('bootConnectionHints', () => {
  it.each(['SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'])(
    'points an untrusted certificate (%s) at the CA settings',
    (code) => {
      const hints = bootConnectionHints(errorWithCode(code));
      expect(hints[0]).toMatch(/NODE_EXTRA_CA_CERTS/);
      expect(hints[1]).toMatch(/PGSSLMODE=no-verify/);
    }
  );

  it.each(['CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'])(
    'points a certificate outside its validity window (%s) at the certificate and clock',
    (code) => {
      const hints = bootConnectionHints(errorWithCode(code));
      expect(hints).toHaveLength(1);
      expect(hints[0]).toMatch(/expired or not yet valid/);
      expect(hints[0]).not.toMatch(/NODE_EXTRA_CA_CERTS/);
    }
  );

  it('points a hostname mismatch at the DATABASE_URL host', () => {
    const hints = bootConnectionHints(errorWithCode('ERR_TLS_CERT_ALTNAME_INVALID'));
    expect(hints).toHaveLength(1);
    expect(hints[0]).toMatch(/DATABASE_URL host/);
    expect(hints[0]).not.toMatch(/NODE_EXTRA_CA_CERTS/);
  });

  it('points a server without TLS at sslmode=disable', () => {
    expect(bootConnectionHints(new Error('The server does not support SSL connections'))).toEqual([
      expect.stringMatching(/sslmode=disable/)
    ]);
  });

  it('gives no hint for a refused connection', () => {
    expect(bootConnectionHints(errorWithCode('ECONNREFUSED', 'connect ECONNREFUSED'))).toEqual([]);
  });
});

describe('PgOAuthStore.connect', () => {
  it('turns a boot connection failure into a config error', async () => {
    const error = await PgOAuthStore.connect('postgres://u:p@127.0.0.1:1/db?sslmode=disable').catch(
      (caught: unknown) => caught
    );
    expect(isXyteError(error)).toBe(true);
    expect((error as Error).message).toMatch(/^Postgres setup failed at boot/);
  });
});
