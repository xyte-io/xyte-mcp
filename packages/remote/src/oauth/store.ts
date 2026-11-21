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

/** Rows one cleanup run deleted, per table. */
export interface DeletedOAuthRowCounts {
  tokens: number;
  grants: number;
  clients: number;
  pendingSignIns: number;
}

/**
 * An /authorize request parked across our consent page and hub's sign-in. Any
 * instance may serve each step, so it lives in the store. Its id (in the
 * consent form and hub's state) is hashed by the store; the csrf token and
 * the browser key arrive hashed already, so a leaked row cannot complete the
 * sign-in. The hub verifier must be read back, so Postgres encrypts it.
 */
export interface PendingSignIn {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  /** The MCP client's own state, echoed on its redirect. */
  state?: string;
  resource?: string;
  /** SHA-256 (hashToken) of the token the consent form echoes. */
  csrfHash: string;
  /** SHA-256 (hashToken) of the key the consenting browser holds in a cookie. */
  browserKeyHash: string;
  approved: boolean;
  /** Our PKCE verifier for the hub leg. */
  hubVerifier: string;
  /** Seconds since epoch. */
  expiresAt: number;
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
   * revoked, and holding an unexpired access or refresh token.
   */
  hasLiveHubSibling(sub: string, tenantId: string, exceptGrantId: string): Promise<boolean>;

  saveToken(token: NewToken): Promise<void>;
  getToken(token: string, kind: TokenKind): Promise<TokenRecord | undefined>;
  /**
   * Codes and refresh tokens are single-use: the exchange deletes, never
   * marks. True only for the one caller whose delete removed the row.
   */
  deleteToken(token: string, kind: TokenKind): Promise<boolean>;

  /**
   * Parks a sign-in unless `max` live ones are parked already (false then).
   * Deletes the expired ones on the way. The cap is soft across instances: two
   * concurrent inserts at max - 1 can both pass.
   */
  createPendingSignIn(id: string, entry: PendingSignIn, max: number, now: number): Promise<boolean>;
  /** Live only (expiresAt > now). One the store cannot read back counts as gone. */
  getPendingSignIn(id: string, now: number): Promise<PendingSignIn | undefined>;
  /** True while it is live, also when it was approved already (a double-clicked Approve). */
  approvePendingSignIn(id: string, now: number): Promise<boolean>;
  /**
   * Removes a live one and returns it: of two concurrent takes, only one gets
   * it, so a sign-in completes (or is denied) once.
   */
  takePendingSignIn(id: string, now: number): Promise<PendingSignIn | undefined>;
  /** Which of `ids` are live, for expiring the cookies of flows that are gone. */
  livePendingSignInIds(ids: string[], now: number): Promise<Set<string>>;

  /**
   * Deletes, as of `now` (seconds since epoch): expired pending sign-ins;
   * expired tokens; grants with no token left that were revoked more than
   * REVOKED_GRANT_RETENTION_SECONDS ago, or are unrevoked but whose client is
   * gone (a sign-in still at the hub when a sweep deleted its client: nothing
   * can use it, /token needs the client), or are unrevoked and created more
   * than ABANDONED_GRANT_RETENTION_SECONDS ago; clients with no grant,
   * registered more than UNUSED_CLIENT_RETENTION_SECONDS ago. Never a younger
   * unrevoked grant whose client exists: a refresh exchange deletes the old
   * refresh token before it saves the new pair, so a live grant can briefly
   * have none (and a client with a grant is never deleted).
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
  private readonly pendingSignIns = new Map<string, PendingSignIn>();
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

  async revokeGrant(grantId: string): Promise<void> {
    const grant = this.grants.get(grantId);
    if (grant && !grant.revoked) {
      this.grantRevokedAt.set(grantId, Math.floor(Date.now() / 1000));
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

  async saveToken({ token, ...record }: NewToken): Promise<void> {
    this.tokens.set(`${record.kind}:${hashToken(token)}`, record);
  }

  async getToken(token: string, kind: TokenKind): Promise<TokenRecord | undefined> {
    return this.tokens.get(`${kind}:${hashToken(token)}`);
  }

  async deleteToken(token: string, kind: TokenKind): Promise<boolean> {
    return this.tokens.delete(`${kind}:${hashToken(token)}`);
  }

  async createPendingSignIn(
    id: string,
    entry: PendingSignIn,
    max: number,
    now: number
  ): Promise<boolean> {
    this.deleteExpiredPendingSignIns(now);
    if (this.pendingSignIns.size >= max) return false;
    // Like the Postgres column's default: only Approve sets it.
    this.pendingSignIns.set(id, { ...entry, approved: false });
    return true;
  }

  async getPendingSignIn(id: string, now: number): Promise<PendingSignIn | undefined> {
    // A copy, like a row read from Postgres.
    const entry = this.pendingSignIns.get(id);
    return entry && entry.expiresAt > now ? { ...entry } : undefined;
  }

  async approvePendingSignIn(id: string, now: number): Promise<boolean> {
    const entry = this.pendingSignIns.get(id);
    if (!entry || entry.expiresAt <= now) return false;
    entry.approved = true;
    return true;
  }

  async takePendingSignIn(id: string, now: number): Promise<PendingSignIn | undefined> {
    // No await before the delete: a concurrent take must find it gone.
    const entry = this.pendingSignIns.get(id);
    if (!entry || entry.expiresAt <= now) return undefined;
    this.pendingSignIns.delete(id);
    return entry;
  }

  async livePendingSignInIds(ids: string[], now: number): Promise<Set<string>> {
    return new Set(ids.filter((id) => (this.pendingSignIns.get(id)?.expiresAt ?? 0) > now));
  }

  private deleteExpiredPendingSignIns(now: number): number {
    let deleted = 0;
    for (const [id, entry] of this.pendingSignIns) {
      if (entry.expiresAt <= now && this.pendingSignIns.delete(id)) deleted += 1;
    }
    return deleted;
  }

  async sweepExpiredOAuthRows(now: number): Promise<DeletedOAuthRowCounts> {
    const deleted = { tokens: 0, grants: 0, clients: 0, pendingSignIns: this.deleteExpiredPendingSignIns(now) };
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
