import pg from 'pg';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { HubUserCredential } from '../config.js';
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
 * Three tables, created at boot with IF NOT EXISTS instead of a migration
 * framework: this service owns its whole schema and the schema is additive.
 * Client metadata is one jsonb blob because the server never queries inside
 * it — it goes back to the SDK exactly as registered.
 */

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id  text PRIMARY KEY,
    data       jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE TABLE IF NOT EXISTS oauth_grants (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    client_id        text NOT NULL,
    hub_access_token text NOT NULL,
    hub_client       text NOT NULL,
    hub_uid          text NOT NULL,
    hub_tenant       text,
    revoked_at       timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now()
  );
  CREATE TABLE IF NOT EXISTS oauth_tokens (
    token_hash     text NOT NULL,
    kind           text NOT NULL CHECK (kind IN ('code', 'access', 'refresh')),
    grant_id       bigint NOT NULL REFERENCES oauth_grants(id),
    code_challenge text,
    redirect_uri   text,
    resource       text,
    expires_at     timestamptz NOT NULL,
    revoked_at     timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, token_hash)
  );
`;

interface TokenRow {
  grant_id: string;
  code_challenge: string | null;
  redirect_uri: string | null;
  resource: string | null;
  expires_at: Date;
  revoked_at: Date | null;
}

interface GrantRow {
  id: string;
  client_id: string;
  hub_access_token: string;
  hub_client: string;
  hub_uid: string;
  hub_tenant: string | null;
  revoked_at: Date | null;
}

export class PgOAuthStore implements OAuthStore {
  private constructor(private readonly pool: pg.Pool) {}

  static async connect(databaseUrl: string): Promise<PgOAuthStore> {
    const pool = new pg.Pool({
      connectionString: databaseUrl,
      // Heroku Postgres requires TLS but presents a chain the dyno can't verify.
      ...(databaseUrl.includes('localhost') || databaseUrl.includes('127.0.0.1')
        ? {}
        : { ssl: { rejectUnauthorized: false } }),
      max: 5
    });
    await pool.query(SCHEMA);
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

  async createGrant(clientId: string, hub: HubUserCredential): Promise<string> {
    const result = await this.pool.query<{ id: string }>(
      `INSERT INTO oauth_grants (client_id, hub_access_token, hub_client, hub_uid, hub_tenant)
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [clientId, hub.accessToken, hub.client, hub.uid, hub.tenant ?? null]
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
      hub: {
        accessToken: row.hub_access_token,
        client: row.hub_client,
        uid: row.hub_uid,
        ...(row.hub_tenant ? { tenant: row.hub_tenant } : {})
      },
      revoked: row.revoked_at !== null
    };
  }

  async revokeGrant(grantId: string): Promise<void> {
    await this.pool.query(
      'UPDATE oauth_grants SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL',
      [grantId]
    );
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
      ...(row.resource ? { resource: row.resource } : {}),
      revoked: row.revoked_at !== null
    };
  }

  async deleteToken(token: string, kind: TokenKind): Promise<void> {
    await this.pool.query('DELETE FROM oauth_tokens WHERE kind = $1 AND token_hash = $2', [
      kind,
      hashToken(token)
    ]);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
