import { createHash } from 'node:crypto';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { HubUserCredential } from '../config.js';

/**
 * Persistence for the OAuth server: registered clients, grants (one per
 * successful hub login, holding the hub credential every later call runs
 * under), and the tokens hanging off each grant.
 *
 * Tokens are stored as SHA-256 hashes — a leaked database row must not be a
 * usable credential. The hub access token inside a grant is the exception: it
 * has to be sent upstream verbatim, so it is stored as-is. Revocation is
 * grant-level on purpose: revoking any one token kills the login it came from,
 * which is the behavior a "disconnect" button needs.
 */

export type TokenKind = 'code' | 'access' | 'refresh';

export interface GrantRecord {
  id: string;
  clientId: string;
  hub: HubUserCredential;
  revoked: boolean;
}

export interface TokenRecord {
  kind: TokenKind;
  grantId: string;
  /** Seconds since epoch. */
  expiresAt: number;
  /** PKCE challenge; codes only. */
  codeChallenge?: string;
  /** The redirect the code was issued for; codes only. */
  redirectUri?: string;
  /** RFC 8707 audience the token was requested for, if any. */
  resource?: string;
  revoked: boolean;
}

export interface NewToken extends Omit<TokenRecord, 'revoked'> {
  token: string;
}

export interface OAuthStore {
  getClient(clientId: string): Promise<OAuthClientInformationFull | undefined>;
  saveClient(client: OAuthClientInformationFull): Promise<void>;

  createGrant(clientId: string, hub: HubUserCredential): Promise<string>;
  getGrant(grantId: string): Promise<GrantRecord | undefined>;
  revokeGrant(grantId: string): Promise<void>;

  saveToken(token: NewToken): Promise<void>;
  getToken(token: string, kind: TokenKind): Promise<TokenRecord | undefined>;
  /** Codes are single-use: the exchange deletes, never marks. */
  deleteToken(token: string, kind: TokenKind): Promise<void>;

  close(): Promise<void>;
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/**
 * Dev/test store. Real deployments set DATABASE_URL and get Postgres; this one
 * forgets everything on restart, which the transport warns about at boot.
 */
export class MemoryOAuthStore implements OAuthStore {
  private readonly clients = new Map<string, OAuthClientInformationFull>();
  private readonly grants = new Map<string, GrantRecord>();
  private readonly tokens = new Map<string, TokenRecord>();
  private nextGrantId = 1;

  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    return this.clients.get(clientId);
  }

  async saveClient(client: OAuthClientInformationFull): Promise<void> {
    this.clients.set(client.client_id, client);
  }

  async createGrant(clientId: string, hub: HubUserCredential): Promise<string> {
    const id = String(this.nextGrantId++);
    this.grants.set(id, { id, clientId, hub, revoked: false });
    return id;
  }

  async getGrant(grantId: string): Promise<GrantRecord | undefined> {
    return this.grants.get(grantId);
  }

  async revokeGrant(grantId: string): Promise<void> {
    const grant = this.grants.get(grantId);
    if (grant) grant.revoked = true;
  }

  async saveToken({ token, ...record }: NewToken): Promise<void> {
    this.tokens.set(`${record.kind}:${hashToken(token)}`, { ...record, revoked: false });
  }

  async getToken(token: string, kind: TokenKind): Promise<TokenRecord | undefined> {
    return this.tokens.get(`${kind}:${hashToken(token)}`);
  }

  async deleteToken(token: string, kind: TokenKind): Promise<void> {
    this.tokens.delete(`${kind}:${hashToken(token)}`);
  }

  async close(): Promise<void> {
    // Nothing to release.
  }
}
