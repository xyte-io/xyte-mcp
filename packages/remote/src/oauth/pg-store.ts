import { existsSync } from 'node:fs';
import pg from 'pg';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { XyteError } from '@xyteai/mcp/http/errors.js';
import { log, logError } from '@xyteai/mcp/log.js';
import { errorCodeOf, logEvent } from '../log-event.js';
import type { HubSignIn, HubTokens } from './hub-oauth.js';
import {
  hashToken,
  ABANDONED_GRANT_RETENTION_SECONDS,
  REVOKED_GRANT_RETENTION_SECONDS,
  UNUSED_CLIENT_RETENTION_SECONDS,
  type DeletedOAuthRowCounts,
  type GrantRecord,
  type LockedGrant,
  type NewToken,
  type OAuthStore,
  type PendingSignIn,
  type TokenKind,
  type TokenRecord
} from './store.js';
import { TokenDecryptError, type TokenCipher } from './token-cipher.js';

/**
 * Postgres-backed OAuthStore — the "survives a dyno restart" requirement.
 *
 * This service owns its whole schema: the tables built by the ordered
 * MIGRATIONS below (in the release phase, see migrateOAuthSchema), plus the
 * oauth_schema_migrations ledger that migrateOAuthSchema keeps. Client metadata is one jsonb blob because the
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
 * The flag guards a later release or boot of an older build, not the rollout
 * itself: during a deploy the old dyno keeps serving against the new schema until it
 * stops. So a breaking migration may only drop or rewrite what the previous
 * release already stopped reading — ship the reader change one release ahead.
 * Version 2 is a deliberate pre-launch exception (README, "Deploy it").
 *
 * All pending migrations run in one transaction, so a statement that cannot
 * run inside one (CREATE INDEX CONCURRENTLY, ALTER TYPE ... ADD VALUE on old
 * Postgres) is not allowed here. They run in the release phase (src/migrate.ts),
 * before any new dyno starts; the boot call then finds nothing to apply and only
 * refuses a newer breaking schema. Statements have no time limit, but a release
 * without a release phase (a local run, another platform) migrates at boot,
 * where a long data rewrite counts against the boot timeout — keep those out.
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
  },
  // Sign-ins in progress, so any instance can serve each step of one. Only a
  // new table: an older build keeps its in-memory map and ignores it. No
  // foreign key to oauth_clients: a client swept mid-sign-in fails at /token.
  {
    version: 3,
    name: 'pending_sign_ins',
    breaksRollback: false,
    sql: `
  CREATE TABLE IF NOT EXISTS oauth_pending_sign_ins (
    id_hash           text PRIMARY KEY,
    client_id         text NOT NULL,
    redirect_uri      text NOT NULL,
    code_challenge    text NOT NULL,
    client_state      text,
    resource          text,
    csrf_hash         text NOT NULL,
    browser_key_hash  text NOT NULL,
    approved          boolean NOT NULL DEFAULT false,
    -- Encrypted (TokenCipher, this column name as the AAD).
    hub_pkce_verifier text NOT NULL,
    expires_at        timestamptz NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now()
  );
  -- The expired-row deletes and the live count on every /authorize.
  CREATE INDEX IF NOT EXISTS oauth_pending_sign_ins_expires_at ON oauth_pending_sign_ins (expires_at);
`
  },
  // The per-grant /mcp rate-limit counters, shared by every instance. UNLOGGED:
  // a crash that loses the counts only reopens one window. An older build keeps
  // its in-memory counters and ignores the table.
  {
    version: 4,
    name: 'rate_limit_counters',
    breaksRollback: false,
    sql: `
  CREATE UNLOGGED TABLE IF NOT EXISTS mcp_rate_limit_counters (
    key      text PRIMARY KEY,
    hits     integer NOT NULL,
    reset_at timestamptz NOT NULL
  );
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
 * version, under a transaction-scoped advisory lock: two runs on one database
 * (the release phase and a boot, preboot, a one-off dyno) take turns, and the
 * second finds nothing left to apply. Everything runs in one transaction, so a
 * failure leaves the database exactly as it was and throws. The release phase
 * (src/migrate.ts) runs it first, where a failure stops the release; the boot
 * call is then a no-op that still refuses a newer breaking schema.
 */
export async function migrateOAuthSchema(
  pool: pg.Pool,
  migrations: ReadonlyArray<Migration> = MIGRATIONS
): Promise<void> {
  const misplaced = migrations.findIndex((migration, index) => migration.version !== index + 1);
  if (misplaced !== -1) {
    throw new Error(
      `OAuth store migration at position ${misplaced + 1} says version ${migrations[misplaced]!.version}; versions must equal their position, starting at 1`
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

interface PendingSignInRow {
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  client_state: string | null;
  resource: string | null;
  csrf_hash: string;
  browser_key_hash: string;
  approved: boolean;
  hub_pkce_verifier: string;
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

/** The pool, or one checked-out connection (inside a transaction). */
type Queryable = Pick<pg.ClientBase, 'query'>;

export class PgOAuthStore implements OAuthStore {
  /** Set by close(): a cleanup run stops before its next statement. */
  private closing = false;

  private constructor(
    private readonly pool: pg.Pool,
    /** withGrantLock's transactions: they wait on a row lock, then on a hub refresh. */
    private readonly lockPool: pg.Pool,
    private readonly cipher: TokenCipher,
    /** How long a hub refresh may take (the hub client's timeout); the grant lock's waits derive from it. */
    private readonly hubTimeoutMs: number
  ) {}

  static async connect(
    databaseUrl: string,
    cipher: TokenCipher,
    /** The hub client's timeout (XYTE_MCP_TIMEOUT_MS); capped at 10 minutes. */
    hubTimeoutMs: number
  ): Promise<PgOAuthStore> {
    const hubWaitMs = Math.min(hubTimeoutMs, 600_000);
    let migrationPool: pg.Pool | undefined;
    let pool: pg.Pool | undefined;
    let lockPool: pg.Pool | undefined;
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
      // lock_timeout, a startup parameter: query_timeout only abandons a
      // statement client-side, so lock waits are bounded server-side below it
      // and an abandoned UPDATE does not land later.
      pool = new pg.Pool({ ...connection, max: 5, query_timeout: 10_000, lock_timeout: 9_000 });
      // An idle client dropped server-side (maintenance, failover) is emitted here;
      // unhandled, it exits the process. The pool replaces the client on its own.
      pool.on('error', (error) => logError(`postgres pool: ${errorCodeOf(error)}`));
      // query_timeout is per statement, so the hub POST between statements is
      // not bounded by it; it sits above the SELECT's lock_timeout (hub + 5 s),
      // and with keepAlive it ends a statement hung on a half-open connection.
      // ponytail: 3 grants refreshing at once per process; more wait for a
      // connection (10 s, then a retryable error). Raise it if that shows up.
      lockPool = new pg.Pool({ ...connection, max: 3, keepAlive: true, query_timeout: hubWaitMs + 10_000 });
      lockPool.on('error', (error) => logError(`postgres grant lock pool: ${errorCodeOf(error)}`));
    } catch (error) {
      await pool?.end().catch(() => {});
      await lockPool?.end().catch(() => {});
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
    return new PgOAuthStore(pool, lockPool, cipher, hubWaitMs);
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
    return row && this.grantOf(row, this.pool);
  }

  /**
   * A grant row as a record; an unreadable one is revoked through `db`. Inside
   * a transaction, pass `afterCommit`: the revoke event waits for the commit.
   */
  private async grantOf(row: GrantRow, db: Queryable, afterCommit?: Array<() => void>): Promise<GrantRecord> {
    const tokens = this.hubTokensOf(row);
    if (tokens === 'unreadable') {
      // Revoked, not just signed out: a grant left unrevoked would still count
      // as a live sibling and skip the hub revoke of the user's next sign-in.
      await revokeGrantOn(db, row.id);
      const logRevoke = () =>
        logEvent('revoke', {
          connection: row.id,
          organization: row.hub_tenant,
          user: row.hub_sub,
          reason: 'unreadable_token'
        });
      if (row.revoked_at === null) {
        if (afterCommit) afterCommit.push(logRevoke);
        else logRevoke();
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

  async revokeGrant(grantId: string, onlyIfRefreshToken?: string): Promise<boolean> {
    return revokeGrantOn(this.pool, grantId, onlyIfRefreshToken);
  }

  async rotateHubTokens(
    grantId: string,
    previousRefreshToken: string,
    next: HubTokens
  ): Promise<boolean> {
    return this.rotateHubTokensOn(this.pool, grantId, previousRefreshToken, next);
  }

  private async rotateHubTokensOn(
    db: Queryable,
    grantId: string,
    previousRefreshToken: string,
    next: HubTokens
  ): Promise<boolean> {
    // Encryption is randomized, so the swap compares the refresh token's hash.
    const result = await db.query(
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

  /**
   * A row lock (SELECT ... FOR NO KEY UPDATE) in one transaction on lockPool:
   * it serializes refreshes, revokes and other UPDATEs of the row, but not a
   * token INSERT's foreign-key check (FOR KEY SHARE), so a /token exchange
   * never waits for a hub refresh. A
   * waiter gives up after lock_timeout (SQLSTATE 55P03), sized past one hub
   * refresh; a holder whose process hangs is ended by
   * idle_in_transaction_session_timeout, and one that dies (kill -9) by
   * Postgres on disconnect: both roll back, so the stored pair is unchanged.
   */
  async withGrantLock<T>(grantId: string, fn: (locked: LockedGrant) => Promise<T>): Promise<T> {
    if (this.closing) {
      throw new XyteError('network', 'The server is restarting.', ['Retry in a few seconds.']);
    }
    let client: pg.PoolClient;
    try {
      client = await this.lockPool.connect();
    } catch (error) {
      // close() ended the pool after the check above.
      if (this.closing) throw new XyteError('network', 'The server is restarting.', ['Retry in a few seconds.']);
      throw error;
    }
    let failed = false;
    const afterCommit: Array<() => void> = [];
    // pg-pool drops its idle 'error' listener on checkout. Unhandled, the server
    // ending this session while fn awaits hub (idle in transaction) would crash
    // the process; the next statement on the client then fails instead.
    const onError = (error: Error) => {
      failed = true;
      logError(`postgres grant lock connection: ${errorCodeOf(error)}`);
    };
    client.on('error', onError);
    try {
      try {
        await client.query('BEGIN');
        await client.query(`SET LOCAL lock_timeout = ${this.hubTimeoutMs + 5_000}`);
        await client.query(
          `SET LOCAL idle_in_transaction_session_timeout = ${this.hubTimeoutMs + 15_000}`
        );
        const { rows } = await client.query<GrantRow>(
          'SELECT * FROM oauth_grants WHERE id = $1 FOR NO KEY UPDATE',
          [grantId]
        );
        const result = await fn({
          grant: rows[0] && (await this.grantOf(rows[0], client, afterCommit)),
          // In a savepoint, so a failed try leaves the transaction (and the lock) usable for the next.
          rotate: async (previous, next) => {
            await client.query('SAVEPOINT rotate');
            try {
              const rotated = await this.rotateHubTokensOn(client, grantId, previous, next);
              await client.query('RELEASE SAVEPOINT rotate');
              return rotated;
            } catch (error) {
              await client.query('ROLLBACK TO SAVEPOINT rotate');
              throw error;
            }
          },
          revoke: async () => {
            await revokeGrantOn(client, grantId);
          }
        });
        await client.query('COMMIT');
        for (const log of afterCommit) log();
        return result;
      } catch (error) {
        failed = true;
        await client.query('ROLLBACK').catch(() => {});
        throw error;
      }
    } finally {
      client.off('error', onError);
      // After a failure the connection may still hold an open transaction.
      client.release(failed);
    }
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

  /**
   * One statement: the expired rows go, and the insert happens only while
   * fewer than `max` live rows remain (≤ 10 000 rows, counted on the
   * expires_at index). Both parts read the same snapshot, so the count skips
   * the expired rows rather than waiting for their delete. SKIP LOCKED: an
   * expired row another deleter (a concurrent /authorize, the cleanup) holds
   * is left to it, not waited on up to the pool's lock_timeout.
   */
  async createPendingSignIn(
    id: string,
    entry: PendingSignIn,
    max: number,
    now: number
  ): Promise<boolean> {
    const result = await this.pool.query(
      `WITH expired AS (
         DELETE FROM oauth_pending_sign_ins WHERE id_hash IN (
           SELECT id_hash FROM oauth_pending_sign_ins
            WHERE expires_at <= to_timestamp($11) FOR UPDATE SKIP LOCKED
         )
       )
       INSERT INTO oauth_pending_sign_ins
         (id_hash, client_id, redirect_uri, code_challenge, client_state, resource,
          csrf_hash, browser_key_hash, hub_pkce_verifier, expires_at)
       SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, to_timestamp($10)
        WHERE (SELECT count(*) FROM oauth_pending_sign_ins WHERE expires_at > to_timestamp($11)) < $12`,
      [
        hashToken(id),
        entry.clientId,
        entry.redirectUri,
        entry.codeChallenge,
        entry.state ?? null,
        entry.resource ?? null,
        entry.csrfHash,
        entry.browserKeyHash,
        this.cipher.encrypt(entry.hubVerifier, 'hub_pkce_verifier'),
        entry.expiresAt,
        now,
        max
      ]
    );
    return result.rowCount === 1;
  }

  async getPendingSignIn(id: string, now: number): Promise<PendingSignIn | undefined> {
    const result = await this.pool.query<PendingSignInRow>(
      'SELECT * FROM oauth_pending_sign_ins WHERE id_hash = $1 AND expires_at > to_timestamp($2)',
      [hashToken(id), now]
    );
    return this.pendingSignInOf(result.rows[0]);
  }

  async approvePendingSignIn(id: string, now: number): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE oauth_pending_sign_ins SET approved = true
        WHERE id_hash = $1 AND expires_at > to_timestamp($2)`,
      [hashToken(id), now]
    );
    return result.rowCount === 1;
  }

  // pg's query_timeout is client-side, so a take that timed out may still have
  // deleted the row; the user then restarts the sign-in (accepted).
  async takePendingSignIn(id: string, now: number): Promise<PendingSignIn | undefined> {
    const result = await this.pool.query<PendingSignInRow>(
      `DELETE FROM oauth_pending_sign_ins
        WHERE id_hash = $1 AND expires_at > to_timestamp($2) RETURNING *`,
      [hashToken(id), now]
    );
    return this.pendingSignInOf(result.rows[0]);
  }

  async livePendingSignInIds(ids: string[], now: number): Promise<Set<string>> {
    if (!ids.length) return new Set();
    const byHash = new Map(ids.map((id) => [hashToken(id), id]));
    const result = await this.pool.query<{ id_hash: string }>(
      `SELECT id_hash FROM oauth_pending_sign_ins
        WHERE id_hash = ANY($1) AND expires_at > to_timestamp($2)`,
      [[...byHash.keys()], now]
    );
    return new Set(result.rows.map((row) => byHash.get(row.id_hash)!));
  }

  /**
   * One hit on `key` in a fixed window of `windowMs`, timed by the database
   * clock so every instance agrees; the window restarts at the first hit after
   * it ends, or once it ends more than one window ahead (the database clock
   * stepped back), so a grant is never locked out longer than one window.
   * resetTime is the time left added to this process's clock, the clock the
   * Retry-After header and the 'retry in N s' text are computed against.
   * The express-rate-limit store of the per-grant /mcp limit.
   *
   * pg's query_timeout is client-side, so an upsert that timed out may still
   * commit and count a hit the caller got a 503 for (accepted).
   */
  async countRateLimitHit(key: string, windowMs: number): Promise<{ totalHits: number; resetTime: Date }> {
    const result = await this.pool.query<{ hits: number; remaining_ms: number }>(
      `INSERT INTO mcp_rate_limit_counters (key, hits, reset_at)
       VALUES ($1, 1, now() + $2 * interval '1 millisecond')
       ON CONFLICT (key) DO UPDATE SET
         hits = CASE WHEN mcp_rate_limit_counters.reset_at <= now()
                       OR mcp_rate_limit_counters.reset_at > EXCLUDED.reset_at THEN 1
                     ELSE mcp_rate_limit_counters.hits + 1 END,
         reset_at = CASE WHEN mcp_rate_limit_counters.reset_at <= now()
                           OR mcp_rate_limit_counters.reset_at > EXCLUDED.reset_at THEN EXCLUDED.reset_at
                         ELSE mcp_rate_limit_counters.reset_at END
       RETURNING hits, (extract(epoch FROM reset_at - now()) * 1000)::float8 AS remaining_ms`,
      [key, windowMs]
    );
    const row = result.rows[0]!;
    return { totalHits: row.hits, resetTime: new Date(Date.now() + row.remaining_ms) };
  }

  /**
   * Undefined for no row, and for one whose verifier this instance cannot
   * decrypt (written under a key it lacks): that sign-in cannot finish, so it
   * reads as gone and the user restarts the connection.
   */
  private pendingSignInOf(row: PendingSignInRow | undefined): PendingSignIn | undefined {
    if (!row) return undefined;
    let hubVerifier: string;
    try {
      hubVerifier = this.cipher.decrypt(row.hub_pkce_verifier, 'hub_pkce_verifier');
    } catch (error) {
      if (!(error instanceof TokenDecryptError)) throw error;
      logError(`pending sign-in unreadable: ${error.reason}${error.keyId ? ` (key id ${error.keyId})` : ''}`);
      return undefined;
    }
    return {
      clientId: row.client_id,
      redirectUri: row.redirect_uri,
      codeChallenge: row.code_challenge,
      ...(row.client_state !== null ? { state: row.client_state } : {}),
      ...(row.resource !== null ? { resource: row.resource } : {}),
      csrfHash: row.csrf_hash,
      browserKeyHash: row.browser_key_hash,
      approved: row.approved,
      hubVerifier,
      expiresAt: Math.floor(row.expires_at.getTime() / 1000)
    };
  }

  /**
   * Five autocommit DELETEs: expired pending sign-ins, then the rest in
   * foreign-key order (a token references its grant, without cascade), then
   * ended rate-limit windows (on the database clock, not counted). Each
   * locks only the rows it deletes, which no request uses any more, so requests
   * keep being served. A failing step is logged (its name and error code) and
   * ends the run; the counts of the steps before it are returned, and the next
   * run retries.
   *
   * Token expiries come from this app's clock, created_at and revoked_at from
   * Postgres now(); a skew between the two is harmless at day-scale retentions.
   *
   * The grants step also deletes an unrevoked grant with no token whose client
   * is gone (see OAuthStore.sweepExpiredOAuthRows); no time cutoff, its code
   * row lives 10 minutes, so it goes on the run after the code expires. And an
   * unrevoked grant with no token created more than
   * ABANDONED_GRANT_RETENTION_SECONDS ago, whose hub sign-in chain has ended.
   *
   * ponytail: unbatched deletes, and no index on oauth_tokens.expires_at nor
   * oauth_grants.client_id, so each step scans its table and the client step is
   * one hash anti-join. Fine at pilot scale, but not bounded: the /register
   * rate limit (1000/h) is per IP per process and resets on restart, so junk
   * clients grow with the number of source IPs; there is no global cap. Batched
   * deletes plus those indexes and one on oauth_clients.created_at (a
   * migration) if a run ever gets slow; a global registration cap is separate work.
   */
  async sweepExpiredOAuthRows(now: number): Promise<DeletedOAuthRowCounts> {
    const deleted = { tokens: 0, grants: 0, clients: 0, pendingSignIns: 0 };
    const steps: Array<[keyof DeletedOAuthRowCounts | 'rateLimitCounters', string, number[]]> = [
      ['pendingSignIns', 'DELETE FROM oauth_pending_sign_ins WHERE expires_at <= to_timestamp($1)', [now]],
      ['tokens', 'DELETE FROM oauth_tokens WHERE expires_at <= to_timestamp($1)', [now]],
      [
        'grants',
        // SKIP LOCKED: a grant held by the grant lock (a hub refresh) waits for
        // the next run instead of failing the step on the pool's lock_timeout.
        `DELETE FROM oauth_grants WHERE id IN (
           SELECT g.id FROM oauth_grants g
            WHERE NOT EXISTS (SELECT 1 FROM oauth_tokens t WHERE t.grant_id = g.id)
              AND (g.revoked_at < to_timestamp($1)
                -- An orphan: its sign-in was at the hub when its client was swept.
                OR (g.revoked_at IS NULL
                  AND NOT EXISTS (SELECT 1 FROM oauth_clients c WHERE c.client_id = g.client_id))
                -- Abandoned: hub has ended its sign-in chain.
                OR (g.revoked_at IS NULL AND g.created_at < to_timestamp($2)))
            FOR UPDATE SKIP LOCKED)`,
        [now - REVOKED_GRANT_RETENTION_SECONDS, now - ABANDONED_GRANT_RETENTION_SECONDS]
      ],
      [
        'clients',
        `DELETE FROM oauth_clients c
          WHERE c.created_at < to_timestamp($1)
            AND NOT EXISTS (SELECT 1 FROM oauth_grants g WHERE g.client_id = c.client_id)`,
        [now - UNUSED_CLIENT_RETENTION_SECONDS]
      ],
      ['rateLimitCounters', 'DELETE FROM mcp_rate_limit_counters WHERE reset_at <= now()', []]
    ];
    for (const [step, sql, cutoffs] of steps) {
      // Shutdown waits for the statement in flight, not for the whole run.
      if (this.closing) break;
      try {
        const rowCount = (await this.pool.query(sql, cutoffs)).rowCount ?? 0;
        if (step !== 'rateLimitCounters') deleted[step] = rowCount;
      } catch (error) {
        // The code only: a pg message can name the database host and role. The
        // steps already run have committed, so their counts are still returned.
        logError(`OAuth store cleanup: the ${step} step failed, retried within an hour: ${errorCodeOf(error)}`);
        break;
      }
    }
    return deleted;
  }

  async close(): Promise<void> {
    this.closing = true;
    // Waits for statements in flight (a cleanup step included), then disconnects.
    // ponytail: the grant lock pool gets 1 s. drain() has already awaited every
    // flight that reached hub; what is left waits on another process's lock and
    // sends nothing, and would hold shutdown for its whole lock_timeout. On exit
    // Postgres rolls its transaction back.
    await Promise.all([
      this.pool.end(),
      Promise.race([this.lockPool.end(), new Promise((resolve) => setTimeout(resolve, 1_000).unref())])
    ]);
  }
}

/**
 * Also drops the hub tokens: nothing may use them after this. With
 * `onlyIfRefreshToken`, only while the grant still holds that refresh token.
 * True when this call revoked it.
 */
async function revokeGrantOn(db: Queryable, grantId: string, onlyIfRefreshToken?: string): Promise<boolean> {
  const result = await db.query(
    `UPDATE oauth_grants
        SET revoked_at = now(), hub_access_token = NULL, hub_refresh_token = NULL,
            hub_refresh_token_hash = NULL
      WHERE id = $1 AND revoked_at IS NULL AND ($2::text IS NULL OR hub_refresh_token_hash = $2)`,
    [grantId, onlyIfRefreshToken === undefined ? null : hashToken(onlyIfRefreshToken)]
  );
  return result.rowCount === 1;
}
