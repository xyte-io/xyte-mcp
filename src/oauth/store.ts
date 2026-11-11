import { createHash } from 'node:crypto';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { HubSignIn, HubTokens } from './hub-oauth.js';

/**
 * Persistence for the OAuth server: registered clients, grants (one per
 * successful hub sign-in, holding the hub tokens every later call runs under),
 * and the tokens hanging off each grant.
 *
 * Our tokens are stored as SHA-256 hashes — a leaked database row must not be
 * a usable credential. The hub tokens inside a grant are the exception: they
 * have to be sent to the hub verbatim, so they are stored as-is. Revocation is
 * grant-level on purpose: revoking any one token kills the login it came from,
 * which is the behavior a "disconnect" button needs.
 */

export type TokenKind = 'code' | 'access' | 'refresh';

export interface GrantRecord {
  id: string;
  clientId: string;
  /** Absent on grants from the old devise-triplet login: those are dead. */
  hub?: HubSignIn;
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

  createGrant(clientId: string, hub: HubSignIn): Promise<string>;
  getGrant(grantId: string): Promise<GrantRecord | undefined>;
  /** Also drops the grant's hub tokens: nothing may use them after this. */
  revokeGrant(grantId: string): Promise<void>;
  /**
   * Store a rotated hub token pair — only if the grant still holds
   * `previousRefreshToken`. False means someone else rotated first.
   */
  rotateHubTokens(
    grantId: string,
    previousRefreshToken: string,
    next: HubTokens
  ): Promise<boolean>;
  /**
   * Whether another grant on the same hub sign-in is still in use: not
   * revoked, and holding an unexpired, unrevoked access or refresh token.
   */
  hasLiveHubSibling(sub: string, tenantId: string, exceptGrantId: string): Promise<boolean>;

  saveToken(token: NewToken): Promise<void>;
  getToken(token: string, kind: TokenKind): Promise<TokenRecord | undefined>;
  /**
   * Codes and refresh tokens are single-use: the exchange deletes, never
   * marks. True only for the one caller whose delete removed the row.
   */
  deleteToken(token: string, kind: TokenKind): Promise<boolean>;

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

  async createGrant(clientId: string, hub: HubSignIn): Promise<string> {
    const id = String(this.nextGrantId++);
    this.grants.set(id, { id, clientId, hub, revoked: false });
    return id;
  }

  async getGrant(grantId: string): Promise<GrantRecord | undefined> {
    // A copy, like a row read from Postgres: callers compare snapshots across awaits.
    const grant = this.grants.get(grantId);
    return grant && { ...grant };
  }

  async revokeGrant(grantId: string): Promise<void> {
    const grant = this.grants.get(grantId);
    if (grant) {
      grant.revoked = true;
      delete grant.hub;
    }
  }

  async rotateHubTokens(
    grantId: string,
    previousRefreshToken: string,
    next: HubTokens
  ): Promise<boolean> {
    const grant = this.grants.get(grantId);
    if (!grant?.hub || grant.hub.refreshToken !== previousRefreshToken) return false;
    grant.hub = { ...grant.hub, ...next };
    return true;
  }

  async hasLiveHubSibling(sub: string, tenantId: string, exceptGrantId: string): Promise<boolean> {
    const now = Math.floor(Date.now() / 1000);
    const used = new Set(
      [...this.tokens.values()]
        .filter((token) => token.kind !== 'code' && !token.revoked && token.expiresAt > now)
        .map((token) => token.grantId)
    );
    return [...this.grants.values()].some(
      (grant) =>
        grant.id !== exceptGrantId &&
        !grant.revoked &&
        used.has(grant.id) &&
        grant.hub?.sub === sub &&
        grant.hub.tenantId === tenantId
    );
  }

  async saveToken({ token, ...record }: NewToken): Promise<void> {
    this.tokens.set(`${record.kind}:${hashToken(token)}`, { ...record, revoked: false });
  }

  async getToken(token: string, kind: TokenKind): Promise<TokenRecord | undefined> {
    return this.tokens.get(`${kind}:${hashToken(token)}`);
  }

  async deleteToken(token: string, kind: TokenKind): Promise<boolean> {
    return this.tokens.delete(`${kind}:${hashToken(token)}`);
  }

  async close(): Promise<void> {
    // Nothing to release.
  }
}
