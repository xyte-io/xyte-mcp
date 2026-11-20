import { existsSync } from 'node:fs';
import pg from 'pg';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { XyteError } from '@xyteai/mcp/http/errors.js';
import { log, logError } from '@xyteai/mcp/log.js';
import { errorCodeOf, logEvent } from '../log-event.js';
import type { HubSignIn, HubTokens } from './hub-oauth.js';
import {
  hashToken,
  type GrantRecord,
  type NewToken,
  type OAuthStore,
  type TokenKind,
  type TokenRecord
} from './store.js';
import { TokenDecryptError, type TokenCipher } from './token-cipher.js';

/**
 * Postgres-backed OAuthStore — the "survives a dyno restart" requirement.
 *
 * This service owns its whole schema: three tables built at boot by the
 * ordered MIGRATIONS below, plus the oauth_schema_migrations ledger that
 * migrateOAuthSchema keeps. Client metadata is one jsonb blob because the
 * server never queries inside it — it goes back to the SDK exactly as
 * registered. The hub tokens are encrypted (TokenCipher); the refresh token's
 * hash sits next to them, so a rotation compares without decrypting.
 */

/**
 * One schema change. `version` must equal its place in MIGRATIONS (checked at
 * boot), and `name` is recorded with it: a database whose version N came from
 * another build's migration N (two branches each adding one) refuses to boot
 * instead of skipping this build's N.
 */
export interface Migration {
  version: number;
  name: string;
  sql: string;
  breaksRollback: boolean;
}

/**
 * The schema history, oldest first. Append only — never edit, renumber or
 * reorder a shipped entry.
 *
 * Each entry says whether it is rollback-safe, i.e. whether an older build
 * still boots against the schema it leaves: adding a table, a nullable column
 * or an index is safe (`breaksRollback: false`); dropping, renaming or
 * tightening anything an older build reads is not (`true`), and an older build
 * then refuses to boot instead of running against a schema it does not know.
 *
 * The flag guards a later boot of an older build, not the rollout itself:
 * during a deploy the old dyno keeps serving against the new schema until it
 * stops. So a breaking migration may only drop or rewrite what the previous
 * release already stopped reading — ship the reader change one release ahead.
 * Version 2 is a deliberate pre-launch exception (README, "Deploy it").
 *
 * All pending migrations run in one transaction, so a statement that cannot
 * run inside one (CREATE INDEX CONCURRENTLY, ALTER TYPE ... ADD VALUE on old
 * Postgres) is not allowed here. Statements have no time limit, but they run
 * before the server listens, so a long data rewrite still counts against the
 * platform's boot timeout — keep those out of the boot path.
 */
export const MIGRATIONS: ReadonlyArray<Migration> = [
  // IF NOT EXISTS, so a database created before versioning is adopted as
  // version 1 untouched.
  {
    version: 1,
    name: 'baseline',
    breaksRollback: false,
    sql: `
  CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id  text PRIMARY KEY,
    data       jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE TABLE IF NOT EXISTS oauth_grants (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    client_id         text NOT NULL,
    hub_sub           text NOT NULL,
    hub_tenant        text NOT NULL,
    hub_email         text,
    -- NULL only once revoked: revocation drops the hub tokens.
    hub_access_token  text,
    hub_refresh_token text,
    hub_expires_at    timestamptz NOT NULL,
    revoked_at        timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    CHECK (revoked_at IS NOT NULL OR (hub_access_token IS NOT NULL AND hub_refresh_token IS NOT NULL))
  );
  CREATE TABLE IF NOT EXISTS oauth_tokens (
    token_hash     text NOT NULL,
    kind           text NOT NULL CHECK (kind IN ('code', 'access', 'refresh')),
    grant_id       bigint NOT NULL REFERENCES oauth_grants(id),
    code_challenge text,
    redirect_uri   text,
    resource       text,
    expires_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, token_hash)
  );
  -- The sibling check on revoke (hasLiveHubSibling) joins on both.
  CREATE INDEX IF NOT EXISTS oauth_tokens_grant_id ON oauth_tokens (grant_id);
  CREATE INDEX IF NOT EXISTS oauth_grants_hub_sign_in ON oauth_grants (hub_sub, hub_tenant);
`
  },
  // The hub tokens are encrypted from here on. Live grants hold plain text this
  // build cannot read, so they are signed out (their users connect again once);
  // and an older build would send this build's ciphertext to hub as a token.
  {
    version: 2,
    name: 'encrypt_hub_tokens',
    breaksRollback: true,
    sql: `
  ALTER TABLE oauth_grants ADD COLUMN hub_refresh_token_hash text;
  UPDATE oauth_grants
     SET revoked_at = now(), hub_access_token = NULL, hub_refresh_token = NULL
   WHERE revoked_at IS NULL;
`
  }
];

/** Arbitrary, constant: the advisory lock serializing schema migrations. */
const SCHEMA_LOCK_ID = 674_601;

/** The error a failed schema step throws, with the pg fields that locate it. */
function schemaError(step: string, error: unknown): Error {
  const pgError = error as Partial<pg.DatabaseError>;
  const details = [
    pgError.code && `code ${pgError.code}`,
    pgError.detail,
    pgError.hint,
    pgError.position && `at character ${pgError.position}`
  ]
    .filter(Boolean)
    .join('; ');
  const message = error instanceof Error ? error.message : String(error);
  return new Error(`OAuth store schema ${step} failed: ${message}${details ? ` (${details})` : ''}`, {
    cause: error
  });
}

/**
 * Brings the schema up to the newest migration this build knows, once per
 * version, under a transaction-scoped advisory lock: two boots on one database
 * (preboot, a one-off dyno) take turns, and the second finds nothing left to
 * apply. Everything runs in one transaction, so a failure leaves the database
 * exactly as it was and throws, which stops the boot.
 */
export async function migrateOAuthSchema(
  pool: pg.Pool,
  migrations: ReadonlyArray<Migration> = MIGRATIONS
): Promise<void> {
  const misplaced = migrations.findIndex((migration, index) => migration.version !== index + 1);
  if (misplaced !== -1) {
    throw new Error(
      `OAuth store migration at position ${misplaced + 1} says version ${migrations[misplaced]!.version}; versions must run 1, 2, 3 in order`
    );
  }
  const client = await pool.connect();
  let failed = false;
  try {
    await client.query('BEGIN');
    try {
      let applied: Array<{ version: number; name: string; breaks_rollback: boolean }>;
      let adopting: boolean;
      try {
        // Server-side, unlike pg's client-side query_timeout: waiting longer
        // than this for another boot's lock, or for a table a running query
        // holds, fails the boot instead of hanging it.
        await client.query(`SET LOCAL lock_timeout = '10s'`);
        await client.query(`SELECT pg_advisory_xact_lock(${SCHEMA_LOCK_ID})`);
        await client.query(`CREATE TABLE IF NOT EXISTS oauth_schema_migrations (
          version         integer PRIMARY KEY,
          name            text NOT NULL,
          breaks_rollback boolean NOT NULL DEFAULT false,
          applied_at      timestamptz NOT NULL DEFAULT now()
        )`);
        applied = (
          await client.query<{ version: number; name: string; breaks_rollback: boolean }>(
            'SELECT version, name, breaks_rollback FROM oauth_schema_migrations ORDER BY version'
          )
        ).rows;
        adopting =
          !applied.length &&
          (await client.query<{ found: boolean }>(`SELECT to_regclass('oauth_grants') IS NOT NULL AS found`))
            .rows[0]!.found;
      } catch (error) {
        throw schemaError('lock/version check', error);
      }
      const renamed = applied.find(
        (row) => row.version <= migrations.length && row.name !== migrations[row.version - 1]!.name
      );
      if (renamed) {
        throw new Error(
          `OAuth store schema version ${renamed.version} in the database is "${renamed.name}", but this build's version ${renamed.version} is "${migrations[renamed.version - 1]!.name}"; two builds added different migrations under one version — renumber the newer one`
        );
      }
      const newer = applied.filter((row) => row.version > migrations.length);
      const blocking = newer.find((row) => row.breaks_rollback);
      if (blocking) {
        throw new Error(
          `OAuth store schema is at version ${blocking.version}, which this build (up to version ${migrations.length}) does not know and which breaks rollback; release a build at version ${blocking.version} or later instead of rolling back`
        );
      }
      if (newer.length) {
        log(
          `OAuth store schema is at version ${newer.at(-1)!.version}, newer than this build's ${migrations.length}; those versions are rollback-safe, booting`
        );
      }
      const appliedVersions = new Set(applied.map((row) => row.version));
      for (const migration of migrations) {
        if (appliedVersions.has(migration.version)) continue;
        const label = `${migration.version} (${migration.name})`;
        try {
          await client.query(migration.sql);
          await client.query(
            'INSERT INTO oauth_schema_migrations (version, name, breaks_rollback) VALUES ($1, $2, $3)',
            [migration.version, migration.name, migration.breaksRollback]
          );
        } catch (error) {
          throw schemaError(`migration ${label}`, error);
        }
        log(
          adopting && migration.version === 1
            ? `OAuth store adopted the existing schema as version ${label}`
            : `OAuth store schema migrated to version ${label}`
        );
      }
      await client.query('COMMIT');
    } catch (error) {
      failed = true;
      // A failed ROLLBACK (connection gone) must not hide the migration error;
      // the server rolls the transaction back on disconnect anyway.
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    }
  } finally {
    // After a failure the connection may still hold an open transaction:
    // destroy it rather than hand it back to the pool.
    client.release(failed);
  }
}

/**
 * TLS verifies the server certificate (chain and hostname) by default, against
 * Node's CA bundle plus NODE_EXTRA_CA_CERTS (one PEM file). Heroku's Postgres
 * plans present AWS RDS-issued certificates whose CAs are in the platform's
 * system bundle, which the Procfile loads that way unless a config var of the
 * same name replaces it. A DSN `sslmode` (e.g. `disable` for a
 * compose or CI host) still wins: pg applies it over this option. A local
 * database (the `host` param, which pg prefers over the URL host, or a unix
 * socket) gets no TLS, and an explicit PGSSLMODE=no-verify|disable is left to
 * pg — no-verify is TLS without a certificate check, an accepted MITM risk.
 * The host is the one pg itself resolves (the `host` param over the URL host, a
 * %2F-encoded socket path, PGHOST), so this decides TLS for the host pg reaches.
 */
export function sslOption(databaseUrl: string): { ssl?: true } {
  // ponytail: connectionParameters is pg's untyped internal; the pg-ssl specs pin its shape.
  const client = new pg.Client({
    connectionString: databaseUrl
  }) as unknown as PgClientInternals;
  const host = client.connectionParameters.host;
  if (LOCAL_HOSTS.has(host) || host.startsWith('/')) return {};
  if (process.env.PGSSLMODE === 'no-verify' || process.env.PGSSLMODE === 'disable') return {};
  return { ssl: true };
}

interface PgClientInternals {
  connectionParameters: { host: string };
}

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

// Unknown-issuer codes: the chain is fine, only its CA is missing from the trust store.
const MISSING_CA_CODES = new Set([
  'SELF_SIGNED_CERT_IN_CHAIN',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY'
]);

const NO_VERIFY_HINT =
  'PGSSLMODE=no-verify skips the check (TLS without certificate verification — an accepted MITM risk); if DATABASE_URL carries an sslmode, use sslmode=no-verify there instead.';

/** What to try when the boot connection fails, by the kind of failure. */
export function bootConnectionHints(error: unknown): string[] {
  if (!(error instanceof Error)) return [];
  const { code, syscall, path } = error as NodeJS.ErrnoException;
  // A trusted certificate for another name: no CA setting fixes that.
  if (code === 'ERR_TLS_CERT_ALTNAME_INVALID') {
    return ["The DATABASE_URL host must match a name on the server's certificate.", NO_VERIFY_HINT];
  }
  if (code === 'CERT_HAS_EXPIRED' || code === 'CERT_NOT_YET_VALID') {
    return [
      "The server certificate is expired or not yet valid — check the database's certificate, or this machine's clock.",
      NO_VERIFY_HINT
    ];
  }
  if (code && MISSING_CA_CODES.has(code)) {
    const extraCa = process.env.NODE_EXTRA_CA_CERTS;
    return [
      `Give the server's CA: NODE_EXTRA_CA_CERTS=<pem path> (one PEM file, added to Node's built-in CAs; now ${extraCa ? `${extraCa}, ${existsSync(extraCa) ? 'present' : 'missing'}` : 'unset'}), or add sslmode=verify-full&sslrootcert=<pem path> to DATABASE_URL.`,
      NO_VERIFY_HINT
    ];
  }
  // Revoked, rejected or a bad signature: a sign of tampering, so no opt-out is offered.
  if (code && /CERT|SIGNATURE/.test(code)) {
    return [
      "The server's certificate was rejected (revoked or a bad signature) — check the database's certificate before trusting it."
    ];
  }
  if ((code === 'ENOENT' || code === 'EACCES') && syscall === 'open') {
    return [`Cannot read ${path ?? 'a file'}: check the sslrootcert path in DATABASE_URL.`];
  }
  if (/does not support SSL/.test(error.message)) {
    return [
      'A database without TLS: add sslmode=disable to DATABASE_URL, or set PGSSLMODE=disable.'
    ];
  }
  return [];
}

/**
 * The boot failure in one line. pg's own code and detail are kept, and a Node 22
 * multi-address connect failure (an AggregateError with an empty message) shows
 * its inner errors.
 */
export function bootFailureMessage(error: unknown): string {
  if (!(error instanceof Error)) return String(error);
  const inner =
    error instanceof AggregateError
      ? error.errors.map((e: unknown) => (e instanceof Error ? e.message : String(e)))
      : [];
  const { code, detail } = error as Error & { code?: string; detail?: string };
  return [error.message || inner.join('; '), code && `[${code}]`, detail].filter(Boolean).join(' ');
}

/**
 * The shape of an encrypted value up to its key id, as a Postgres regex (a
 * parameter, so no escaping rules apply). Anything else is plain text from an
 * older build or a malformed value.
 */
const ENCRYPTED_SHAPE = '^v1\\.[0-9a-f]{8}\\.';

/**
 * Boot checks over the live grants, in one transaction under the migrations'
 * lock_timeout, so a boot never hangs on a row a running query holds.
 *
 * First revoke (same columns as revokeGrant) every live grant with either
 * token not in the encrypted shape: an older build still serving during the
 * rollout writes plain text, which must not stay at rest. Then, as a wrong key
 * would revoke every remaining live grant on its first read, refuse to boot
 * (rolling the sweep back) while any uses a key id this build lacks. Revoked
 * rows are never decrypted, so they don't count. Only an 8-hex key id is ever
 * read out, so the error never echoes a token.
 */
async function checkAndSweepHubTokens(pool: pg.Pool, cipher: TokenCipher): Promise<void> {
  const client = await pool.connect();
  let failed = false;
  try {
    await client.query('BEGIN');
    try {
      await client.query(`SET LOCAL lock_timeout = '10s'`);
      const plaintext = await client.query(
        `UPDATE oauth_grants
            SET revoked_at = now(), hub_access_token = NULL, hub_refresh_token = NULL,
                hub_refresh_token_hash = NULL
          WHERE revoked_at IS NULL
            AND (COALESCE(hub_access_token, '') !~ $1 OR COALESCE(hub_refresh_token, '') !~ $1)`,
        [ENCRYPTED_SHAPE]
      );
      // ponytail: two sequential scans of every grants row, revoked ones included
      // (nothing indexes revoked_at); a partial index on live grants if it ever matters.
      const { rows } = await client.query<{ key_id: string }>(
        `SELECT DISTINCT split_part(token, '.', 2) AS key_id FROM (
           SELECT hub_refresh_token AS token FROM oauth_grants WHERE revoked_at IS NULL
           UNION ALL
           SELECT hub_access_token FROM oauth_grants WHERE revoked_at IS NULL
         ) live WHERE token ~ $1`,
        [ENCRYPTED_SHAPE]
      );
      const unknown = rows
        .map((row) => row.key_id)
        .filter((keyId) => keyId !== cipher.currentKeyId && keyId !== cipher.previousKeyId);
      if (unknown.length) {
        // A key problem, not a connection one: thrown as is past the boot wrapper.
        throw new XyteError(
          'config',
          `OAuth store: live grants use hub token key id(s) ${unknown.join(', ')}, which XYTE_MCP_TOKEN_KEY (key id ${cipher.currentKeyId}) and XYTE_MCP_TOKEN_KEY_PREVIOUS do not match; set the key those grants were written with as XYTE_MCP_TOKEN_KEY, or as XYTE_MCP_TOKEN_KEY_PREVIOUS while rotating`
        );
      }
      await client.query('COMMIT');
      if (plaintext.rowCount) {
        log(`OAuth store: revoked ${plaintext.rowCount} live grant(s) holding unencrypted hub tokens`);
      }
    } catch (error) {
      failed = true;
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    }
  } finally {
    client.release(failed);
  }
}

interface TokenRow {
  grant_id: string;
  code_challenge: string | null;
  redirect_uri: string | null;
  resource: string | null;
  expires_at: Date;
}

interface GrantRow {
  id: string;
  client_id: string;
  hub_access_token: string | null;
  hub_refresh_token: string | null;
  hub_expires_at: Date;
  hub_sub: string;
  hub_tenant: string;
  hub_email: string | null;
  revoked_at: Date | null;
}

export class PgOAuthStore implements OAuthStore {
  private constructor(
    private readonly pool: pg.Pool,
    private readonly cipher: TokenCipher
  ) {}

  static async connect(databaseUrl: string, cipher: TokenCipher): Promise<PgOAuthStore> {
    let migrationPool: pg.Pool | undefined;
    let pool: pg.Pool | undefined;
    try {
      // Inside the try: parsing the DSN reads an sslrootcert file, which may be missing.
      const connection = {
        connectionString: databaseUrl,
        ...sslOption(databaseUrl),
        // Unbounded by default: an unreachable or hung database would hang boot
        // past Heroku's R10 and every token check instead of failing with a 503.
        connectionTimeoutMillis: 10_000
      };
      // Migrations get their own connection without query_timeout: pg's timeout
      // only abandons a statement client-side, so a migration statement over
      // 10 s could never commit. lock_timeout bounds their waits instead.
      migrationPool = new pg.Pool({ ...connection, max: 1 });
      migrationPool.on('error', (error) => logError(`postgres migration pool: ${errorCodeOf(error)}`));
      await migrateOAuthSchema(migrationPool);
      await checkAndSweepHubTokens(migrationPool, cipher);
      pool = new pg.Pool({ ...connection, max: 5, query_timeout: 10_000 });
      // An idle client dropped server-side (maintenance, failover) is emitted here;
      // unhandled, it exits the process. The pool replaces the client on its own.
      pool.on('error', (error) => logError(`postgres pool: ${errorCodeOf(error)}`));
    } catch (error) {
      await pool?.end().catch(() => {});
      if (error instanceof XyteError) throw error;
      throw new XyteError(
        'config',
        `Postgres setup failed at boot: ${bootFailureMessage(error)}`,
        bootConnectionHints(error)
      );
    } finally {
      await migrationPool?.end().catch(() => {});
    }
    log(
      `OAuth store: hub token key id ${cipher.currentKeyId}` +
        (cipher.previousKeyId ? ` (previous: ${cipher.previousKeyId})` : '')
    );
    return new PgOAuthStore(pool, cipher);
  }

  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    const result = await this.pool.query<{ data: OAuthClientInformationFull }>(
      'SELECT data FROM oauth_clients WHERE client_id = $1',
      [clientId]
    );
    return result.rows[0]?.data;
  }

  async saveClient(client: OAuthClientInformationFull): Promise<void> {
    await this.pool.query(
      `INSERT INTO oauth_clients (client_id, data) VALUES ($1, $2)
       ON CONFLICT (client_id) DO UPDATE SET data = EXCLUDED.data`,
      [client.client_id, JSON.stringify(client)]
    );
  }

  async createGrant(clientId: string, hub: HubSignIn): Promise<string> {
    const result = await this.pool.query<{ id: string }>(
      `INSERT INTO oauth_grants (client_id, hub_access_token, hub_tenant, hub_refresh_token,
                                 hub_refresh_token_hash, hub_expires_at, hub_sub, hub_email)
       VALUES ($1, $2, $3, $4, $5, to_timestamp($6), $7, $8) RETURNING id`,
      [
        clientId,
        this.cipher.encrypt(hub.accessToken, 'hub_access_token'),
        hub.tenantId,
        this.cipher.encrypt(hub.refreshToken, 'hub_refresh_token'),
        hashToken(hub.refreshToken),
        hub.expiresAt,
        hub.sub,
        hub.email ?? null
      ]
    );
    const row = result.rows[0];
    if (!row) throw new Error('grant insert returned no row');
    return row.id;
  }

  async getGrant(grantId: string): Promise<GrantRecord | undefined> {
    const result = await this.pool.query<GrantRow>('SELECT * FROM oauth_grants WHERE id = $1', [
      grantId
    ]);
    const row = result.rows[0];
    if (!row) return undefined;
    const tokens = this.hubTokensOf(row);
    if (tokens === 'unreadable') {
      // Revoked, not just signed out: a grant left unrevoked would still count
      // as a live sibling and skip the hub revoke of the user's next sign-in.
      await this.revokeGrant(row.id);
      if (row.revoked_at === null) {
        logEvent('revoke', {
          connection: row.id,
          organization: row.hub_tenant,
          user: row.hub_sub,
          reason: 'unreadable_token'
        });
      }
      return { id: row.id, clientId: row.client_id, revoked: true };
    }
    return {
      id: row.id,
      clientId: row.client_id,
      ...(tokens
        ? {
            hub: {
              ...tokens,
              expiresAt: Math.floor(row.hub_expires_at.getTime() / 1000),
              sub: row.hub_sub,
              tenantId: row.hub_tenant,
              ...(row.hub_email ? { email: row.hub_email } : {})
            }
          }
        : {}),
      revoked: row.revoked_at !== null
    };
  }

  /**
   * The decrypted pair; undefined when there is none; 'unreadable' when it
   * cannot be read (a plaintext row from an older build, a key no longer
   * configured): the grant is then revoked, and its user connects again.
   */
  private hubTokensOf(
    row: GrantRow
  ): { accessToken: string; refreshToken: string } | 'unreadable' | undefined {
    if (row.hub_access_token === null || row.hub_refresh_token === null) return undefined;
    try {
      return {
        accessToken: this.cipher.decrypt(row.hub_access_token, 'hub_access_token'),
        refreshToken: this.cipher.decrypt(row.hub_refresh_token, 'hub_refresh_token')
      };
    } catch (error) {
      if (!(error instanceof TokenDecryptError)) throw error;
      logError(`grant ${row.id}: ${error.message}; revoking the grant`);
      return 'unreadable';
    }
  }

  async revokeGrant(grantId: string): Promise<void> {
    await this.pool.query(
      `UPDATE oauth_grants
          SET revoked_at = now(), hub_access_token = NULL, hub_refresh_token = NULL,
              hub_refresh_token_hash = NULL
        WHERE id = $1 AND revoked_at IS NULL`,
      [grantId]
    );
  }

  async rotateHubTokens(
    grantId: string,
    previousRefreshToken: string,
    next: HubTokens
  ): Promise<boolean> {
    // Encryption is randomized, so the swap compares the refresh token's hash.
    const result = await this.pool.query(
      `UPDATE oauth_grants
          SET hub_access_token = $3, hub_refresh_token = $4, hub_refresh_token_hash = $5,
              hub_expires_at = to_timestamp($6)
        WHERE id = $1 AND hub_refresh_token_hash = $2 AND revoked_at IS NULL`,
      [
        grantId,
        hashToken(previousRefreshToken),
        this.cipher.encrypt(next.accessToken, 'hub_access_token'),
        this.cipher.encrypt(next.refreshToken, 'hub_refresh_token'),
        hashToken(next.refreshToken),
        next.expiresAt
      ]
    );
    return result.rowCount === 1;
  }

  async hasLiveHubSibling(sub: string, tenantId: string, exceptGrantId: string): Promise<boolean> {
    const result = await this.pool.query(
      `SELECT 1 FROM oauth_grants g JOIN oauth_tokens t ON t.grant_id = g.id
        WHERE g.hub_sub = $1 AND g.hub_tenant = $2 AND g.id <> $3 AND g.revoked_at IS NULL
          AND t.kind IN ('access', 'refresh') AND t.expires_at > now()
        LIMIT 1`,
      [sub, tenantId, exceptGrantId]
    );
    return (result.rowCount ?? 0) > 0;
  }

  async saveToken(token: NewToken): Promise<void> {
    await this.pool.query(
      `INSERT INTO oauth_tokens (token_hash, kind, grant_id, code_challenge, redirect_uri, resource, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7))`,
      [
        hashToken(token.token),
        token.kind,
        token.grantId,
        token.codeChallenge ?? null,
        token.redirectUri ?? null,
        token.resource ?? null,
        token.expiresAt
      ]
    );
  }

  async getToken(token: string, kind: TokenKind): Promise<TokenRecord | undefined> {
    const result = await this.pool.query<TokenRow>(
      'SELECT * FROM oauth_tokens WHERE kind = $1 AND token_hash = $2',
      [kind, hashToken(token)]
    );
    const row = result.rows[0];
    if (!row) return undefined;
    return {
      kind,
      grantId: row.grant_id,
      expiresAt: Math.floor(row.expires_at.getTime() / 1000),
      ...(row.code_challenge ? { codeChallenge: row.code_challenge } : {}),
      ...(row.redirect_uri ? { redirectUri: row.redirect_uri } : {}),
      ...(row.resource ? { resource: row.resource } : {})
    };
  }

  async deleteToken(token: string, kind: TokenKind): Promise<boolean> {
    const result = await this.pool.query(
      'DELETE FROM oauth_tokens WHERE kind = $1 AND token_hash = $2 RETURNING 1',
      [kind, hashToken(token)]
    );
    return result.rowCount === 1;
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
