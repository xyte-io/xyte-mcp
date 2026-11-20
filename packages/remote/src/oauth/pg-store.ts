import pg from 'pg';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { log, logError } from '@xyteai/mcp/log.js';
import type { HubSignIn, HubTokens } from './hub-oauth.js';
import {
  hashToken,
  type GrantRecord,
  type NewToken,
  type OAuthStore,
  type TokenKind,
  type TokenRecord
} from './store.js';

/**
 * Postgres-backed OAuthStore — the "survives a dyno restart" requirement.
 *
 * This service owns its whole schema: three tables built at boot by the
 * ordered MIGRATIONS below, plus the oauth_schema_migrations ledger that
 * migrateOAuthSchema keeps. Client metadata is one jsonb blob because the
 * server never queries inside it — it goes back to the SDK exactly as
 * registered.
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
 * An `sslmode` in the DSN decides on its own (pg lets it override this option
 * anyway), so a compose or CI host can opt out with `sslmode=disable`. Without
 * one: none for a local database, and Heroku's TLS otherwise — it requires TLS
 * but presents a chain the dyno can't verify.
 */
function sslOption(databaseUrl: string): { ssl?: { rejectUnauthorized: false } } {
  const url = new URL(databaseUrl);
  if (url.searchParams.has('sslmode')) return {};
  if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') return {};
  return { ssl: { rejectUnauthorized: false } };
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
  private constructor(private readonly pool: pg.Pool) {}

  static async connect(databaseUrl: string): Promise<PgOAuthStore> {
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
    const migrationPool = new pg.Pool({ ...connection, max: 1 });
    migrationPool.on('error', (error) => logError(`postgres migration pool: ${error.message}`));
    try {
      await migrateOAuthSchema(migrationPool);
    } finally {
      await migrationPool.end();
    }
    const pool = new pg.Pool({ ...connection, max: 5, query_timeout: 10_000 });
    // An idle client dropped server-side (maintenance, failover) is emitted here;
    // unhandled, it exits the process. The pool replaces the client on its own.
    pool.on('error', (error) => logError(`postgres pool: ${error.message}`));
    return new PgOAuthStore(pool);
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
      `INSERT INTO oauth_grants (client_id, hub_access_token, hub_tenant,
                                 hub_refresh_token, hub_expires_at, hub_sub, hub_email)
       VALUES ($1, $2, $3, $4, to_timestamp($5), $6, $7) RETURNING id`,
      [
        clientId,
        hub.accessToken,
        hub.tenantId,
        hub.refreshToken,
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
    return {
      id: row.id,
      clientId: row.client_id,
      ...(row.hub_access_token !== null && row.hub_refresh_token !== null
        ? {
            hub: {
              accessToken: row.hub_access_token,
              refreshToken: row.hub_refresh_token,
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

  async revokeGrant(grantId: string): Promise<void> {
    await this.pool.query(
      `UPDATE oauth_grants
          SET revoked_at = now(), hub_access_token = NULL, hub_refresh_token = NULL
        WHERE id = $1 AND revoked_at IS NULL`,
      [grantId]
    );
  }

  async rotateHubTokens(
    grantId: string,
    previousRefreshToken: string,
    next: HubTokens
  ): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE oauth_grants
          SET hub_access_token = $3, hub_refresh_token = $4, hub_expires_at = to_timestamp($5)
        WHERE id = $1 AND hub_refresh_token = $2`,
      [grantId, previousRefreshToken, next.accessToken, next.refreshToken, next.expiresAt]
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
