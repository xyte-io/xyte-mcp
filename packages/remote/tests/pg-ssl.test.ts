import pg from 'pg';
import { afterEach, describe, expect, it } from 'vitest';
import { isXyteError } from '@xyteai/mcp/http/errors.js';
import {
  bootConnectionHints,
  bootFailureMessage,
  PgOAuthStore,
  sslOption
} from '../src/oauth/pg-store.js';
import { TokenCipher } from '../src/oauth/token-cipher.js';

const REMOTE = 'postgres://u:p@db.example.com:5432/db';
const SAVED_PGSSLMODE = process.env.PGSSLMODE;

/** The TLS setting pg ends up with for this DSN and our option. */
function pgSsl(connectionString: string): unknown {
  const client = new pg.Client({
    connectionString,
    ...sslOption(connectionString)
  });
  return (client as unknown as { connectionParameters: { ssl: unknown } }).connectionParameters.ssl;
}

function pgHost(connectionString: string): string {
  return (
    new pg.Client({ connectionString }) as unknown as {
      connectionParameters: { host: string };
    }
  ).connectionParameters.host;
}

afterEach(() => {
  if (SAVED_PGSSLMODE === undefined) delete process.env.PGSSLMODE;
  else process.env.PGSSLMODE = SAVED_PGSSLMODE;
});

describe('sslOption', () => {
  it('leaves a local database to pg (no TLS)', () => {
    delete process.env.PGSSLMODE;
    expect(sslOption('postgres://u:p@localhost:5432/db')).toEqual({});
    expect(sslOption('postgres://u:p@127.0.0.1:5432/db')).toEqual({});
    expect(sslOption('postgres://u:p@[::1]:5432/db')).toEqual({});
  });

  // pg lets a `host` query param override the URL host: that is where it connects.
  it('decides on the host param over the URL host', () => {
    delete process.env.PGSSLMODE;
    expect(sslOption('postgres://u:p@localhost/db?host=db.example.com')).toEqual({ ssl: true });
    expect(pgHost('postgres://u:p@localhost/db?host=db.example.com')).toBe('db.example.com');
    expect(sslOption('postgres://u:p@db.example.com/db?host=127.0.0.1')).toEqual({});
    expect(pgHost('postgres://u:p@db.example.com/db?host=127.0.0.1')).toBe('127.0.0.1');
  });

  // URL can't parse an empty host with credentials; pg can, and connects to the host param.
  it('verifies a remote host param behind an empty URL host', () => {
    delete process.env.PGSSLMODE;
    expect(sslOption('postgres://u:p@/db?host=db.example.com')).toEqual({
      ssl: true
    });
  });

  it('leaves a unix socket to pg (no TLS)', () => {
    delete process.env.PGSSLMODE;
    expect(sslOption('postgres://u:p@/db?host=/var/run/postgresql')).toEqual({});
    expect(sslOption('postgres://u:p@db.example.com/db?host=/var/run/postgresql')).toEqual({});
    expect(sslOption('postgres://u:p@%2Fvar%2Frun%2Fpostgresql/db')).toEqual({});
    expect(sslOption('socket:/var/run/postgresql?db=db')).toEqual({});
  });

  it('verifies the certificate of a remote database', () => {
    delete process.env.PGSSLMODE;
    expect(sslOption(REMOTE)).toEqual({ ssl: true });
    expect(pgSsl(REMOTE)).toBe(true);
  });

  it.each([
    ['no-verify', { rejectUnauthorized: false }],
    ['disable', false]
  ])('leaves an explicit PGSSLMODE=%s to pg', (mode, expected) => {
    process.env.PGSSLMODE = mode;
    expect(sslOption(REMOTE)).toEqual({});
    expect(pgSsl(REMOTE)).toEqual(expected);
  });

  it('keeps verifying on any other PGSSLMODE value', () => {
    process.env.PGSSLMODE = 'noverify';
    expect(sslOption(REMOTE)).toEqual({ ssl: true });
    expect(pgSsl(REMOTE)).toBe(true);
  });

  it('lets a DSN sslmode win over PGSSLMODE', () => {
    process.env.PGSSLMODE = 'disable';
    expect(pgSsl(`${REMOTE}?sslmode=require`)).toEqual({});
  });

  // sslOption no longer checks the DSN: pg applies a DSN sslmode over the passed `ssl`.
  it.each([
    ['disable', false],
    ['no-verify', { rejectUnauthorized: false }],
    // pg 8 treats require as verify-full ({} keeps rejectUnauthorized on); pg 9 weakens it.
    ['require', {}]
  ])('lets a DSN sslmode=%s win in pg', (mode, expected) => {
    delete process.env.PGSSLMODE;
    expect(pgSsl(`${REMOTE}?sslmode=${mode}`)).toEqual(expected);
  });
});

function errorWithCode(code: string, message = code): Error {
  return Object.assign(new Error(message), { code });
}

describe('bootConnectionHints', () => {
  it.each([
    'SELF_SIGNED_CERT_IN_CHAIN',
    'DEPTH_ZERO_SELF_SIGNED_CERT',
    'UNABLE_TO_VERIFY_LEAF_SIGNATURE'
  ])('points an untrusted certificate (%s) at the CA settings', (code) => {
    const hints = bootConnectionHints(errorWithCode(code));
    expect(hints[0]).toMatch(/NODE_EXTRA_CA_CERTS/);
    expect(hints[1]).toMatch(/PGSSLMODE=no-verify/);
    expect(hints[1]).toMatch(/sslmode=no-verify there/);
  });

  it('shows the effective NODE_EXTRA_CA_CERTS in the CA hint', () => {
    const saved = process.env.NODE_EXTRA_CA_CERTS;
    process.env.NODE_EXTRA_CA_CERTS = '/no/such/bundle.pem';
    try {
      expect(bootConnectionHints(errorWithCode('SELF_SIGNED_CERT_IN_CHAIN'))[0]).toMatch(
        /now \/no\/such\/bundle\.pem, missing/
      );
    } finally {
      if (saved === undefined) delete process.env.NODE_EXTRA_CA_CERTS;
      else process.env.NODE_EXTRA_CA_CERTS = saved;
    }
  });

  it.each(['CERT_REVOKED', 'CERT_REJECTED', 'CERT_SIGNATURE_FAILURE'])(
    'offers no opt-out for a rejected certificate (%s)',
    (code) => {
      const hints = bootConnectionHints(errorWithCode(code));
      expect(hints).toHaveLength(1);
      expect(hints[0]).toMatch(/revoked or a bad signature/);
      expect(hints.join(' ')).not.toMatch(/no-verify|NODE_EXTRA_CA_CERTS/);
    }
  );

  it('points an unreadable sslrootcert at its path', () => {
    const error = Object.assign(errorWithCode('ENOENT'), {
      syscall: 'open',
      path: '/nope.pem'
    });
    expect(bootConnectionHints(error)).toEqual([
      'Cannot read /nope.pem: check the sslrootcert path in DATABASE_URL.'
    ]);
  });

  it('gives no hint for a non-Error or an Error without a code', () => {
    expect(bootConnectionHints('boom')).toEqual([]);
    expect(bootConnectionHints(new Error('x'))).toEqual([]);
  });

  it.each(['CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'])(
    'points a certificate outside its validity window (%s) at the certificate and clock',
    (code) => {
      const hints = bootConnectionHints(errorWithCode(code));
      expect(hints[0]).toMatch(/expired or not yet valid/);
      expect(hints[1]).toMatch(/PGSSLMODE=no-verify/);
      expect(hints.join(' ')).not.toMatch(/NODE_EXTRA_CA_CERTS/);
    }
  );

  it('points a hostname mismatch at the DATABASE_URL host', () => {
    const hints = bootConnectionHints(errorWithCode('ERR_TLS_CERT_ALTNAME_INVALID'));
    expect(hints[0]).toMatch(/DATABASE_URL host/);
    expect(hints[1]).toMatch(/PGSSLMODE=no-verify/);
    expect(hints.join(' ')).not.toMatch(/NODE_EXTRA_CA_CERTS/);
  });

  it('points a server without TLS at sslmode=disable', () => {
    expect(bootConnectionHints(new Error('The server does not support SSL connections'))).toEqual([
      'A database without TLS: add sslmode=disable to DATABASE_URL, or set PGSSLMODE=disable.'
    ]);
  });

  it('gives no hint for a refused connection', () => {
    expect(bootConnectionHints(errorWithCode('ECONNREFUSED', 'connect ECONNREFUSED'))).toEqual([]);
  });
});

describe('PgOAuthStore.connect', () => {
  it('turns a boot connection failure into a config error', async () => {
    const error = await PgOAuthStore.connect(
      'postgres://u:p@127.0.0.1:1/db?sslmode=disable',
      new TokenCipher(Buffer.alloc(32))
    ).catch(
      (caught: unknown) => caught
    );
    expect(isXyteError(error)).toBe(true);
    expect((error as Error).message).toMatch(/^Postgres setup failed at boot: .*\[ECONNREFUSED\]/);
    expect((error as { hints: string[] }).hints).toEqual([]);
  });

  it('turns an unreadable sslrootcert into a config error with a hint', async () => {
    const error = await PgOAuthStore.connect(
      'postgres://u:p@db.example.com/db?sslrootcert=/no/such.pem',
      new TokenCipher(Buffer.alloc(32))
    ).catch((caught: unknown) => caught);
    expect(isXyteError(error)).toBe(true);
    expect((error as { hints: string[] }).hints[0]).toMatch(/sslrootcert/);
  });
});

describe('bootFailureMessage', () => {
  it('keeps the pg code and detail', () => {
    const error = Object.assign(new Error('relation exists'), {
      code: '42P07',
      detail: 'Key (x)=(1).'
    });
    expect(bootFailureMessage(error)).toBe('relation exists [42P07] Key (x)=(1).');
  });

  it('shows the inner errors of an AggregateError with no message', () => {
    const error = Object.assign(
      new AggregateError(
        [
          new Error('connect ECONNREFUSED ::1:5432'),
          new Error('connect ECONNREFUSED 127.0.0.1:5432')
        ],
        ''
      ),
      {
        code: 'ECONNREFUSED'
      }
    );
    expect(bootFailureMessage(error)).toBe(
      'connect ECONNREFUSED ::1:5432; connect ECONNREFUSED 127.0.0.1:5432 [ECONNREFUSED]'
    );
  });
});
