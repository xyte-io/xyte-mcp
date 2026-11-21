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
 * have to be sent to the hub verbatim, so the Postgres store encrypts them
 * (token-cipher.ts) rather than hashing them. Revocation is
 * grant-level on purpose: revoking any one token kills the login it came from,
 * which is the behavior a "disconnect" button needs.
 */

export type TokenKind = 'code' | 'access' | 'refresh';

export interface GrantRecord {
  id: string;
  clientId: string;
  /** Absent once revoked: revocation drops the hub tokens. */
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
}

export interface NewToken extends TokenRecord {
  token: string;
}

/**
 * How long a revoked grant is kept once it has no tokens left: a week, so the
 * row still shows who (subject, tenant, email) and when it was revoked; the
 * reason is on the `revoke` log line, read with it. Its hub tokens are already
 * gone at revoke, so it holds nothing usable. A revoked grant keeps its token
 * rows until they expire, so the real retention is at least this.
 */
export const REVOKED_GRANT_RETENTION_SECONDS = 7 * 24 * 60 * 60;

/**
 * How long an unrevoked grant with no token left is kept: a sign-in whose code
 * was never exchanged, or a user idle past the refresh lifetime. Hub ends the
 * sign-in chain 90 days after the first sign-in (README "OAuth 2.1"), so such a
 * grant can never reach hub again; plus a week's margin, like the revoked-grant
 * retention. A refresh exchange that loses the race with this delete answers
 * 500; if that was the client's last grant and the client is past
 * UNUSED_CLIENT_RETENTION_SECONDS, the same run deletes the client too, so the
 * next attempt gets invalid_client and the connector must be re-added (without
 * the race the user would re-authorize on the same client).
 */
export const ABANDONED_GRANT_RETENTION_SECONDS = 97 * 24 * 60 * 60;

/**
 * How long a registered client with no grant is kept. Registration is open
 * (dynamic client registration), so junk registrations must go; this is far
 * above the 10-minute pending sign-in window, and a client in use keeps its
 * unrevoked grant, so it is never deleted.
 */
export const UNUSED_CLIENT_RETENTION_SECONDS = 30 * 24 * 60 * 60;

/** A grant as read under its lock, and the writes that commit with the lock's release. */
export interface LockedGrant {
  grant: GrantRecord | undefined;
  /** rotateHubTokens, inside the lock. */
  rotate(previousRefreshToken: string, next: HubTokens): Promise<boolean>;
  /** revokeGrant, inside the lock. */
  revoke(): Promise<void>;
}

/** Rows one cleanup run deleted, per table. */
export interface DeletedOAuthRowCounts {
  tokens: number;
  grants: number;
  clients: number;
}

export interface OAuthStore {
  getClient(clientId: string): Promise<OAuthClientInformationFull | undefined>;
  saveClient(client: OAuthClientInformationFull): Promise<void>;

  createGrant(clientId: string, hub: HubSignIn): Promise<string>;
  getGrant(grantId: string): Promise<GrantRecord | undefined>;
  /**
   * Also drops the grant's hub tokens: nothing may use them after this. With
   * `onlyIfRefreshToken`, only while the grant still holds that hub refresh
   * token. True when this call revoked it.
   */
  revokeGrant(grantId: string, onlyIfRefreshToken?: string): Promise<boolean>;
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
   * revoked, and holding an unexpired access or refresh token.
   */
  hasLiveHubSibling(sub: string, tenantId: string, exceptGrantId: string): Promise<boolean>;
  /**
   * Runs `fn` holding the grant's lock, across every process on the store: the
   * hub refresh and the revoke of one grant take turns, so a single-use hub
   * refresh token is never sent twice. `fn` gets the grant read under the lock.
   * Postgres only: its writes and the release are one commit, and a throw rolls
   * them back (the memory store keeps what `fn` wrote before throwing). Inside
   * `fn`, read and write the grant only through `locked`:
   * getGrant or revokeGrant there would wait on the lock `fn` holds.
   */
  withGrantLock<T>(grantId: string, fn: (locked: LockedGrant) => Promise<T>): Promise<T>;

  saveToken(token: NewToken): Promise<void>;
  getToken(token: string, kind: TokenKind): Promise<TokenRecord | undefined>;
  /**
   * Codes and refresh tokens are single-use: the exchange deletes, never
   * marks. True only for the one caller whose delete removed the row.
   */
  deleteToken(token: string, kind: TokenKind): Promise<boolean>;

  /**
   * Deletes, as of `now` (seconds since epoch): expired tokens; grants with no
   * token left that were revoked more than REVOKED_GRANT_RETENTION_SECONDS ago,
   * or are unrevoked but whose client is gone (a sign-in still at the hub when
   * a sweep deleted its client: nothing can use it, /token needs the client),
   * or are unrevoked and created more than ABANDONED_GRANT_RETENTION_SECONDS
   * ago; clients with no grant, registered more than
   * UNUSED_CLIENT_RETENTION_SECONDS ago. Never a younger unrevoked grant whose
   * client exists: a refresh exchange deletes the old refresh token before it
   * saves the new pair, so a live grant can briefly have none (and a client
   * with a grant is never deleted).
   * An orphan's hub tokens are not revoked at hub: nobody holds them once the
   * row is gone, and hub ends the chain by itself.
   * Safe while requests are served; a second run deletes nothing more.
   */
  sweepExpiredOAuthRows(now: number): Promise<DeletedOAuthRowCounts>;

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
  /** Seconds since epoch of each client's first save; kept out of the client record. */
  private readonly clientCreatedAt = new Map<string, number>();
  private readonly grants = new Map<string, GrantRecord>();
  /** Seconds since epoch of each grant's creation; kept out of GrantRecord. */
  private readonly grantCreatedAt = new Map<string, number>();
  /** Seconds since epoch of each grant's first revoke; kept out of GrantRecord. */
  private readonly grantRevokedAt = new Map<string, number>();
  private readonly tokens = new Map<string, TokenRecord>();
  /** Per grant, the tail of its lock holders' queue. */
  private readonly grantLocks = new Map<string, Promise<unknown>>();
  private nextGrantId = 1;

  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    return this.clients.get(clientId);
  }

  async saveClient(client: OAuthClientInformationFull): Promise<void> {
    if (!this.clients.has(client.client_id)) {
      this.clientCreatedAt.set(client.client_id, Math.floor(Date.now() / 1000));
    }
    this.clients.set(client.client_id, client);
  }

  async createGrant(clientId: string, hub: HubSignIn): Promise<string> {
    const id = String(this.nextGrantId++);
    this.grants.set(id, { id, clientId, hub, revoked: false });
    this.grantCreatedAt.set(id, Math.floor(Date.now() / 1000));
    return id;
  }

  async getGrant(grantId: string): Promise<GrantRecord | undefined> {
    // A copy, like a row read from Postgres: callers compare snapshots across awaits.
    const grant = this.grants.get(grantId);
    return grant && { ...grant };
  }

  async revokeGrant(grantId: string, onlyIfRefreshToken?: string): Promise<boolean> {
    const grant = this.grants.get(grantId);
    if (!grant || grant.revoked) return false;
    if (onlyIfRefreshToken !== undefined && grant.hub?.refreshToken !== onlyIfRefreshToken) return false;
    this.grantRevokedAt.set(grantId, Math.floor(Date.now() / 1000));
    grant.revoked = true;
    delete grant.hub;
    return true;
  }

  async rotateHubTokens(
    grantId: string,
    previousRefreshToken: string,
    next: HubTokens
  ): Promise<boolean> {
    const grant = this.grants.get(grantId);
    if (!grant?.hub || grant.revoked || grant.hub.refreshToken !== previousRefreshToken) return false;
    grant.hub = { ...grant.hub, ...next };
    return true;
  }

  async hasLiveHubSibling(sub: string, tenantId: string, exceptGrantId: string): Promise<boolean> {
    const now = Math.floor(Date.now() / 1000);
    const used = new Set(
      [...this.tokens.values()]
        .filter((token) => token.kind !== 'code' && token.expiresAt > now)
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

  /** One process: a per-grant queue. No rollback, so a throw keeps what `fn` wrote. */
  async withGrantLock<T>(grantId: string, fn: (locked: LockedGrant) => Promise<T>): Promise<T> {
    const run = (this.grantLocks.get(grantId) ?? Promise.resolve()).then(async () =>
      fn({
        grant: await this.getGrant(grantId),
        rotate: (previous, next) => this.rotateHubTokens(grantId, previous, next),
        revoke: async () => {
          await this.revokeGrant(grantId);
        }
      })
    );
    const tail = run.catch(() => undefined);
    this.grantLocks.set(grantId, tail);
    void tail.then(() => {
      if (this.grantLocks.get(grantId) === tail) this.grantLocks.delete(grantId);
    });
    return run;
  }

  async saveToken({ token, ...record }: NewToken): Promise<void> {
    this.tokens.set(`${record.kind}:${hashToken(token)}`, record);
  }

  async getToken(token: string, kind: TokenKind): Promise<TokenRecord | undefined> {
    return this.tokens.get(`${kind}:${hashToken(token)}`);
  }

  async deleteToken(token: string, kind: TokenKind): Promise<boolean> {
    return this.tokens.delete(`${kind}:${hashToken(token)}`);
  }

  async sweepExpiredOAuthRows(now: number): Promise<DeletedOAuthRowCounts> {
    const deleted = { tokens: 0, grants: 0, clients: 0 };
    for (const [key, token] of this.tokens) {
      if (token.expiresAt <= now && this.tokens.delete(key)) deleted.tokens += 1;
    }
    const grantsWithTokens = new Set([...this.tokens.values()].map((token) => token.grantId));
    for (const [id, grant] of this.grants) {
      if (grantsWithTokens.has(id)) continue;
      const revokedAt = this.grantRevokedAt.get(id);
      const ended =
        revokedAt === undefined
          ? !this.clients.has(grant.clientId) ||
            this.grantCreatedAt.get(id)! < now - ABANDONED_GRANT_RETENTION_SECONDS
          : revokedAt < now - REVOKED_GRANT_RETENTION_SECONDS;
      if (ended) {
        this.grants.delete(id);
        this.grantRevokedAt.delete(id);
        this.grantCreatedAt.delete(id);
        deleted.grants += 1;
      }
    }
    const clientsWithGrants = new Set([...this.grants.values()].map((grant) => grant.clientId));
    for (const [clientId, createdAt] of this.clientCreatedAt) {
      if (createdAt < now - UNUSED_CLIENT_RETENTION_SECONDS && !clientsWithGrants.has(clientId)) {
        this.clients.delete(clientId);
        this.clientCreatedAt.delete(clientId);
        deleted.clients += 1;
      }
    }
    return deleted;
  }

  async close(): Promise<void> {
    // Nothing to release.
  }
}
