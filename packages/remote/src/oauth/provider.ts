import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Request, Response } from 'express';
import {
  InvalidClientError,
  InvalidGrantError,
  InvalidTokenError,
  TemporarilyUnavailableError
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type {
  AuthorizationParams,
  OAuthServerProvider
} from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens
} from '@modelcontextprotocol/sdk/shared/auth.js';
import type { HttpClient } from '@xyteai/mcp/http/client.js';
import { XyteError, XyteHttpError } from '@xyteai/mcp/http/errors.js';
import { logError } from '@xyteai/mcp/log.js';
import { errorCodeOf, logEvent } from '../log-event.js';
import {
  HubPausedError,
  HubRefreshError,
  nowSeconds,
  type HubOAuth,
  type HubSignIn,
  type HubTokens
} from './hub-oauth.js';
import { hashToken, type OAuthStore, type PendingSignIn, type TokenRecord } from './store.js';

/**
 * The OAuth 2.1 authorization server, backed by hub's own OAuth server.
 *
 * The protocol surface (metadata, DCR, /authorize, /token, PKCE verification)
 * is the SDK's `mcpAuthRouter`; this class is only the policy behind it:
 * `/authorize` shows our consent page, Approve sends the browser to hub's
 * `/oauth/authorize` (we are a confidential client there), and the callback
 * turns hub's tokens into a grant. The tokens we mint are our own,
 * audience-bound to this server. The client's token is never forwarded to the
 * hub — each request looks up the grant and uses the stored hub token — so a
 * token stolen from a client is useless against the hub directly.
 *
 * A hub token is bound to one organization. When the app's hub setting is on,
 * the hub applies the signed-in user's own access in it on each call.
 */

const CODE_TTL_SECONDS = 10 * 60;
const ACCESS_TTL_SECONDS = 60 * 60;
const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;
/** Refresh a hub access token this close to its expiry rather than risk a 401. */
const HUB_REFRESH_SKEW_SECONDS = 60;
/** Attempts at saving a rotated hub pair. Only the DB write repeats — never the hub POST. */
const HUB_SAVE_ATTEMPTS = 3;

const PENDING_TTL_SECONDS = 10 * 60;
// ponytail: a fixed ceiling on parked logins (DCR is open, so /authorize is
// reachable from any number of IPs); per-client caps if this is ever hit.
const MAX_PENDING = 10_000;
/** Clients send a short random value; this bounds what an unauthenticated /authorize parks for 10 minutes. */
const MAX_STATE_LENGTH = 1024;
const COOKIE_PREFIX = '__Host-xmcp_';
const EXPIRED = 'Authorization expired or invalid. Restart the connection.';

export class XyteOAuthProvider implements OAuthServerProvider {
  readonly clientsStore: OAuthRegisteredClientsStore;
  // Pending sign-ins live in the store (Postgres off localhost), so a sign-in
  // started on one instance finishes on any other.
  /** This process's hub refresh per grant; across processes, the store's grant lock serializes them. */
  private readonly refreshing = new Map<string, Promise<string>>();
  /**
   * Rotated hub pairs the store failed to save, used in place of the stored ones.
   * Only when revoking the grant failed too: this process alone knows the pair.
   */
  private readonly unsaved = new Map<string, HubTokens>();
  /** Set by drain(): no new hub refresh may start, so its snapshot is final. */
  private draining = false;
  /** Grants whose flight here has passed the draining check: only these can still reach hub. */
  private readonly posting = new Set<string>();

  constructor(
    private readonly store: OAuthStore,
    private readonly hub: HubOAuth,
    /** e.g. https://<app>.herokuapp.com — no trailing slash. */
    private readonly issuerUrl: string
  ) {
    this.clientsStore = {
      getClient: (clientId) => this.store.getClient(clientId),
      registerClient: async (client) => {
        // The SDK's registration handler has already minted client_id/secret.
        const full = client as OAuthClientInformationFull;
        await this.store.saveClient(full);
        return full;
      }
    };
  }

  /** The RFC 8707 audience of every token this server mints. */
  private get expectedResource(): string {
    return `${this.issuerUrl}/mcp`;
  }

  /**
   * Never auto-approves: a DCR client names itself, so the user has to see
   * that name and where the code will go before anything reaches the hub.
   */
  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    if (params.resource && params.resource.href !== this.expectedResource) {
      res.status(400).type('html').send(errorPage('This authorization is for a different server.'));
      return;
    }
    if (params.state && params.state.length > MAX_STATE_LENGTH) {
      res.status(400).type('html').send(errorPage('The state parameter is too long.'));
      return;
    }
    const pendingId = random();
    const csrf = random();
    const browserKey = random();
    const now = nowSeconds();
    const entry: PendingSignIn = {
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      ...(params.state ? { state: params.state } : {}),
      ...(params.resource ? { resource: params.resource.href } : {}),
      csrfHash: hashToken(csrf),
      browserKeyHash: hashToken(browserKey),
      approved: false,
      // RFC 7636 4.1 (and hub) require 43-128 chars: 32 bytes is 43 in base64url.
      hubVerifier: randomBytes(32).toString('base64url'),
      expiresAt: now + PENDING_TTL_SECONDS
    };
    // The SDK turns a throw here into a server_error redirect without a log
    // line, so on-call would not see the sign-ins failing.
    let created: boolean;
    try {
      created = await this.store.createPendingSignIn(pendingId, entry, MAX_PENDING, now);
    } catch (error) {
      logError(`authorize: saving the pending sign-in failed (${errorCodeOf(error)})`);
      logEvent('sign_in', { outcome: 'failed', reason: 'store', client: client.client_id });
      throw error;
    }
    if (!created) {
      res.status(503).type('html').send(errorPage('Too many sign-ins in progress. Try again shortly.'));
      return;
    }
    // One cookie per started flow: expire the ones whose flow is gone, or
    // enough abandoned flows grow the Cookie header past the server's limit.
    const flowCookies = cookieNames(res.req);
    if (flowCookies.length) {
      // Housekeeping only: on a failed lookup the old cookies wait for the next
      // /authorize.
      const live = await this.store
        .livePendingSignInIds(
          flowCookies.map((name) => name.slice(COOKIE_PREFIX.length)),
          now
        )
        .catch((error: unknown) => {
          logError(`authorize: flow-cookie lookup failed (${errorCodeOf(error)}); cookies kept`);
          return undefined;
        });
      for (const name of flowCookies) {
        if (live && !live.has(name.slice(COOKIE_PREFIX.length))) clearBrowserCookie(res, name);
      }
    }

    // Set with the page, not only on Approve: a cross-site auto-submitted
    // Approve carries no SameSite=Lax cookie, so it cannot skip this page.
    setBrowserCookie(res, pendingId, browserKey);
    frameDeny(res)
      .status(200)
      .type('html')
      .send(
        consentPage({
          clientName: typeof client.client_name === 'string' ? client.client_name : undefined,
          redirectTarget: redirectTarget(params.redirectUri),
          pendingId,
          csrf
        })
      );
  }

  /** POST /oauth/consent: Approve goes on to hub, Deny back to the client. */
  async consent(req: Request, res: Response): Promise<void> {
    const form = (req.body ?? {}) as Record<string, unknown>;
    const pendingId = typeof form.pending === 'string' ? form.pending : '';
    const entry = await this.store.getPendingSignIn(pendingId, nowSeconds());
    const cookie = readCookie(req, COOKIE_PREFIX + pendingId);
    // A mismatch leaves the entry alone: the pending id travels in URLs, so
    // dropping it here would let anyone who saw one cancel that login.
    if (!entry) {
      if (cookie !== undefined) clearBrowserCookie(res, COOKIE_PREFIX + pendingId);
      endOnExpiredPage(res, 'expired');
      return;
    }
    if (!matchesHash(form.csrf, entry.csrfHash)) {
      endOnExpiredPage(res, 'csrf', entry.clientId);
      return;
    }
    if (!matchesHash(cookie, entry.browserKeyHash)) {
      endOnExpiredPage(res, 'cookie', entry.clientId);
      return;
    }

    if (form.decision !== 'approve') {
      // Taken, not just deleted: a callback racing this Deny finds it gone.
      // Gone already: that callback ran first, so this Deny decides nothing.
      const taken = await this.store.takePendingSignIn(pendingId, nowSeconds());
      clearBrowserCookie(res, COOKIE_PREFIX + pendingId);
      if (!taken) {
        endOnExpiredPage(res, 'expired', entry.clientId);
        return;
      }
      logEvent('sign_in', { outcome: 'denied', client: entry.clientId });
      res.redirect(302, clientRedirect(entry, { error: 'access_denied' }));
      return;
    }

    // Gone since the read above: its callback already ran, or it just expired.
    if (!(await this.store.approvePendingSignIn(pendingId, nowSeconds()))) {
      clearBrowserCookie(res, COOKIE_PREFIX + pendingId);
      endOnExpiredPage(res, 'expired', entry.clientId);
      return;
    }
    // The verified cookie set again (the store keeps only its hash): the same
    // key as set with the page, so a double-clicked Approve stays valid.
    setBrowserCookie(res, pendingId, cookie);
    res.redirect(
      302,
      this.hub.authorizeUrl({
        state: pendingId,
        codeChallenge: createHash('sha256').update(entry.hubVerifier).digest('base64url')
      })
    );
  }

  /**
   * GET /oauth/callback: hub's answer. Only the browser that approved our
   * consent page may complete it — otherwise an attacker could approve their
   * own consent and hand the hub URL to a victim, whose sign-in would then
   * mint a code for the attacker's client.
   */
  async callback(req: Request, res: Response): Promise<void> {
    const query = req.query as Record<string, unknown>;
    const pendingId = typeof query.state === 'string' ? query.state : '';
    const entry = await this.store.getPendingSignIn(pendingId, nowSeconds());
    const cookie = readCookie(req, COOKIE_PREFIX + pendingId);
    // Without the cookie the entry is left alone, as in consent(): the state is
    // in hub's URL, and knowing it must not be enough to cancel the login.
    if (!entry) {
      if (cookie !== undefined) clearBrowserCookie(res, COOKIE_PREFIX + pendingId);
      endOnExpiredPage(res, 'expired');
      return;
    }
    if (!matchesHash(cookie, entry.browserKeyHash)) {
      endOnExpiredPage(res, 'cookie', entry.clientId);
      return;
    }
    // Single-use from here: of a replayed or a concurrent second callback, on
    // any instance, only the one whose delete took the row goes on. Approved
    // is read from the taken row, so an Approve landing meanwhile counts.
    const taken = await this.store.takePendingSignIn(pendingId, nowSeconds());
    clearBrowserCookie(res, COOKIE_PREFIX + pendingId);
    if (!taken) {
      endOnExpiredPage(res, 'expired', entry.clientId);
      return;
    }
    if (!taken.approved) {
      endOnExpiredPage(res, 'not_approved', taken.clientId);
      return;
    }

    if (typeof query.error === 'string') {
      logEvent(
        'sign_in',
        query.error === 'access_denied'
          ? { outcome: 'denied', client: taken.clientId }
          : { outcome: 'failed', reason: 'hub_error', client: taken.clientId }
      );
      const description = [query.error_reason, query.error_description]
        .filter((part): part is string => typeof part === 'string' && part.length > 0)
        .join(': ');
      res.redirect(
        302,
        clientRedirect(taken, {
          error: query.error,
          ...(description ? { error_description: description } : {})
        })
      );
      return;
    }

    try {
      if (typeof query.code !== 'string') throw new Error('hub callback has no code or error');
      const signIn = await this.hub.exchangeCode(query.code, taken.hubVerifier);
      const grantId = await this.store.createGrant(taken.clientId, signIn);
      const code = mintToken('ac');
      await this.store.saveToken({
        token: code,
        kind: 'code',
        grantId,
        codeChallenge: taken.codeChallenge,
        redirectUri: taken.redirectUri,
        ...(taken.resource ? { resource: taken.resource } : {}),
        expiresAt: nowSeconds() + CODE_TTL_SECONDS
      });
      logEvent('sign_in', {
        outcome: 'ok',
        connection: grantId,
        organization: signIn.tenantId,
        user: signIn.sub
      });
      res.redirect(302, clientRedirect(taken, { code }));
    } catch (error) {
      // A JSON parse error quotes its input — the id_token or the response body.
      const detail =
        error instanceof SyntaxError
          ? 'unreadable hub response'
          : error instanceof Error
            ? error.message
            : String(error);
      logError(`hub sign-in failed: ${detail}`);
      logEvent('sign_in', { outcome: 'failed', reason: 'exchange', client: taken.clientId });
      res.redirect(
        302,
        clientRedirect(
          taken,
          error instanceof HubPausedError
            ? {
                error: 'temporarily_unavailable',
                error_description: 'Xyte has paused this connection for now. Try signing in again later.'
              }
            : { error: 'server_error', error_description: 'Xyte sign-in failed' }
        )
      );
    }
  }

  /**
   * The hub client for one grant's tool calls: swaps in a fresh hub token
   * before each call, and when hub rejects the token itself (expired and
   * revoked look the same) refreshes once and retries once. Every hub token
   * it sends is added to `secrets`, so a refreshed one is redacted too.
   */
  hubHttp(grantId: string, upstream: HttpClient, secrets?: string[]): HttpClient {
    return {
      request: async (request) => {
        const send = (token: string) => {
          if (secrets && !secrets.includes(token)) secrets.push(token);
          return upstream.request({
            ...request,
            headers: { ...request.headers, Authorization: `Bearer ${token}` }
          });
        };
        const token = await this.hubAccessToken(grantId);
        try {
          return await send(token);
        } catch (error) {
          // Hub also answers 401 for a record outside the organization (a wrong
          // device id); only a rejected token carries `error="invalid_token"`
          // (hub's OauthBearerAuthentication). Refreshing on the other kind would
          // burn a single-use refresh token per typo.
          if (
            !(
              error instanceof XyteHttpError &&
              error.status === 401 &&
              /error="invalid_token"/.test(error.wwwAuthenticate ?? '')
            )
          ) {
            throw error;
          }
          return send(await this.refreshHub(grantId, token));
        }
      }
    };
  }

  private async hubAccessToken(grantId: string): Promise<string> {
    const hub = (await this.liveHub(grantId))?.hub;
    if (!hub) throw signInGone();
    if (hub.expiresAt - nowSeconds() > HUB_REFRESH_SKEW_SECONDS) return hub.accessToken;
    return this.refreshHub(grantId, hub.accessToken);
  }

  /** The grant's current hub pair (an unsaved rotation wins), and the refresh token in the store. */
  private async liveHub(grantId: string): Promise<{ hub: HubSignIn; stored: string } | undefined> {
    const grant = await this.store.getGrant(grantId);
    if (!grant?.hub || grant.revoked) {
      this.unsaved.delete(grantId);
      return undefined;
    }
    return { hub: { ...grant.hub, ...this.unsaved.get(grantId) }, stored: grant.hub.refreshToken };
  }

  /**
   * Single-flight per grant: hub refresh tokens are single-use, so concurrent
   * calls must share one refresh rather than race (a loser's replay would be
   * read by hub as theft). Calls in this process share one flight; flights in
   * other processes queue on the store's grant lock (doRefresh).
   */
  private refreshHub(grantId: string, staleAccessToken: string): Promise<string> {
    let flight = this.refreshing.get(grantId);
    if (!flight) {
      // A rotation started now could land after the store closes and be lost.
      if (this.draining) {
        return Promise.reject(
          new XyteError('network', 'The server is restarting.', ['Retry in a few seconds.'])
        );
      }
      flight = this.doRefresh(grantId, staleAccessToken).finally(() => {
        this.refreshing.delete(grantId);
        this.posting.delete(grantId);
      });
      this.refreshing.set(grantId, flight);
    }
    return flight;
  }

  /**
   * Under the grant lock, so a refresh or revoke in another process waits:
   * re-read the pair, return one a flight elsewhere already rotated, else send
   * hub the refresh token once and save its answer in the lock's commit.
   */
  private async doRefresh(grantId: string, staleAccessToken: string): Promise<string> {
    /** Set once hub answered with a new pair: from then on it must not be lost. */
    const answered: { hub?: HubSignIn; stored?: string; next?: HubTokens } = {};
    /** Set when this refresh ended the grant; logged once the revoke has committed. */
    const ended: { hub?: HubSignIn; stored?: string; reason?: string; detail?: string } = {};
    let accessToken: string | undefined;
    try {
      // Every signed-out outcome returns undefined rather than throwing: a throw
      // would roll back the revoke (or the unreadable-token revoke of the locked read).
      accessToken = await this.store.withGrantLock(grantId, async (locked) => {
        if (!locked.grant?.hub || locked.grant.revoked) return undefined;
        const stored = locked.grant.hub.refreshToken;
        const hub = { ...locked.grant.hub, ...this.unsaved.get(grantId) };
        // A flight here or in another process already replaced the token this caller saw.
        if (
          hub.accessToken !== staleAccessToken &&
          hub.expiresAt - nowSeconds() > HUB_REFRESH_SKEW_SECONDS
        ) {
          return hub.accessToken;
        }

        // Shutdown began while this flight waited on the lock: a POST now could
        // outlast the shutdown deadline. Nothing is sent, so the rollback is harmless.
        if (this.draining) {
          throw new XyteError('network', 'The server is restarting.', ['Retry in a few seconds.']);
        }
        // Sent once, never retried: once hub answers, it is burned.
        this.posting.add(grantId);
        let next: HubTokens | 'invalid_grant';
        try {
          next = await this.hub.refresh(hub.refreshToken);
        } catch (error) {
          const hubStatus = error instanceof HubRefreshError ? error.status : undefined;
          // A plain 4xx rejection ('auth') never rotated anything: keep the grant.
          if (error instanceof XyteError && error.kind === 'auth') {
            logEvent('hub_refresh', {
              ...whoOf(grantId, hub),
              outcome: hubStatus === 429 ? 'rate_limited' : 'rejected',
              hub_status: hubStatus
            });
            throw error;
          }
          logEvent('hub_refresh', { ...whoOf(grantId, hub), outcome: 'unknown', hub_status: hubStatus });
          // Timeout, network, 5xx or an unreadable 200: hub may have rotated and
          // burned the token. A replay inside hub's 60 s window only gets invalid_grant
          // (no pair), and one after it ends the user's sign-in — so it is never
          // sent again: the grant ends here and the client reconnects.
          // Only our own messages: a JSON parse error would quote the response body.
          logError(
            `grant ${grantId}: hub refresh outcome unknown ` +
              `(${error instanceof XyteError ? error.message : 'unreadable hub response'}); ending the grant`
          );
          Object.assign(ended, { hub, stored, reason: 'refresh_unknown' });
          await locked.revoke();
          return undefined;
        }
        if (next === 'invalid_grant') {
          logEvent('hub_refresh', { ...whoOf(grantId, hub), outcome: 'invalid_grant', hub_status: 400 });
          Object.assign(ended, { hub, stored, reason: 'invalid_grant' });
          await locked.revoke();
          return undefined;
        }
        logEvent('hub_refresh', { ...whoOf(grantId, hub), outcome: 'ok' });
        Object.assign(answered, { hub, stored, next });
        // Retried here, holding the lock: released between tries, a flight in
        // another process would read the stored token (burned now) and send it.
        let saved: boolean;
        try {
          saved = await withSaveRetries(() => locked.rotate(stored, next));
        } catch (error) {
          // Fail closed, as saveHubTokens does: the stored token is burned.
          Object.assign(ended, {
            hub,
            reason: 'hub_save_failed',
            detail: `could not save rotated hub tokens after ${HUB_SAVE_ATTEMPTS} attempts (${errorCodeOf(error)})`
          });
          await locked.revoke();
          return undefined;
        }
        if (!saved) {
          // The row was read under this lock, so it can only not match if it is
          // inconsistent: dropping the pair would leave the burned token stored.
          Object.assign(ended, { hub, reason: 'hub_save_failed', detail: 'saved hub tokens matched no stored pair' });
          await locked.revoke();
          return undefined;
        }
        this.unsaved.delete(grantId);
        return next.accessToken;
      });
    } catch (error) {
      if (answered.next) {
        // The locked connection or the commit failed after hub answered: save outside the lock.
        await this.saveHubTokens(grantId, answered.hub!, answered.stored!, answered.next);
        return answered.next.accessToken;
      }
      if (ended.reason) {
        // The revoke or its commit failed and rolled back: the stored refresh
        // token may be burned at hub, so the grant must still end.
        // Only if it still holds the token read under the lock: if not, another
        // process refreshed (hub had not rotated) or ended it meanwhile.
        const outcome = await this.revokeGrantWithRetries(grantId, ended.stored!);
        this.unsaved.delete(grantId);
        if (outcome === 'moved') {
          logError(`grant ${grantId}: not revoked after a failed hub refresh: its stored hub tokens changed meanwhile`);
          throw signInBusy();
        }
        if (outcome === 'revoked') {
          logEvent('revoke', { ...whoOf(grantId, ended.hub), reason: ended.reason });
        } else {
          logError(
            `ERROR grant ${grantId}: could not revoke the grant after a failed hub refresh; ` +
              'its next refresh may replay a burned hub token'
          );
        }
        throw signInGone();
      }
      // A XyteError is ours (signed out, hub rejected, restarting); after the
      // POST, anything else is not a lock failure.
      if (this.posting.has(grantId) || error instanceof XyteError) throw error;
      // No lock (another refresh holds it past lock_timeout, no connection, a
      // failed BEGIN): nothing was sent to hub, so the call may simply retry.
      logError(`grant ${grantId}: grant lock transaction failed for a hub refresh (${errorCodeOf(error)})`);
      throw signInBusy();
    }
    if (accessToken === undefined) {
      this.unsaved.delete(grantId);
      if (ended.detail) logError(`grant ${grantId}: ${ended.detail}; revoked the grant`);
      if (ended.reason) logEvent('revoke', { ...whoOf(grantId, ended.hub), reason: ended.reason });
      throw signInGone();
    }
    return accessToken;
  }

  /**
   * Revokes on the main pool, retried like saveHubTokens, only while the grant
   * still holds `storedRefreshToken`. 'moved': it no longer does (or is ended).
   */
  private async revokeGrantWithRetries(
    grantId: string,
    storedRefreshToken: string
  ): Promise<'revoked' | 'moved' | 'failed'> {
    try {
      return (await withSaveRetries(() => this.store.revokeGrant(grantId, storedRefreshToken))) ? 'revoked' : 'moved';
    } catch {
      return 'failed';
    }
  }

  /**
   * Hub has already burned the old refresh token, so losing `next` would leave
   * a replay-on-next-refresh that hub answers by ending the user's sign-in.
   * The DB write is retried; if it still fails, the grant is revoked and this
   * throws signInGone (fail closed: another process would replay the stored,
   * burned token). Only if that revoke fails too does the pair live in memory
   * for this process (a restart before the next successful save loses it). A
   * grant revoked meanwhile throws signInGone, after revoking `next` at hub:
   * nothing would ever use or revoke that pair otherwise.
   */
  private async saveHubTokens(
    grantId: string,
    signIn: HubSignIn,
    stored: string,
    next: HubTokens
  ): Promise<void> {
    let rotated: boolean;
    try {
      rotated = await withSaveRetries(() => this.store.rotateHubTokens(grantId, stored, next));
    } catch (error) {
      const outcome = await this.revokeGrantWithRetries(grantId, stored);
      // The stored pair changed meanwhile: as after a lost compare-and-set.
      if (outcome === 'moved') return this.lostHubTokenSave(grantId, signIn, next);
      if (outcome === 'revoked') {
        // `next` is not revoked at hub: the sibling check needs the database
        // that just failed, and unused, the pair expires on its own.
        this.unsaved.delete(grantId);
        logError(
          `grant ${grantId}: could not save rotated hub tokens after ${HUB_SAVE_ATTEMPTS} attempts ` +
            `(${errorCodeOf(error)}); revoked the grant`
        );
        logEvent('revoke', { ...whoOf(grantId, signIn), reason: 'hub_save_failed' });
        throw signInGone();
      }
      // Known limit: a grant revoked outside the provider (operator cut-off, revoke-on-read)
      // drops an unsaved pair without a hub revoke; it expires on its own.
      this.unsaved.set(grantId, next);
      logError(
        `ERROR grant ${grantId}: could not save rotated hub tokens after ${HUB_SAVE_ATTEMPTS} attempts ` +
          `(${errorCodeOf(error)}), nor revoke the grant; ` +
          'holding them in memory until a later refresh saves; ' +
          'another instance may replay the stored hub token until the save lands'
      );
      return;
    }
    this.unsaved.delete(grantId);
    if (!rotated) await this.lostHubTokenSave(grantId, signIn, next);
  }

  /**
   * The compare-and-set found another pair stored: keep that one; or, the
   * grant was revoked meanwhile, revoke `next` at hub and throw signInGone.
   */
  private async lostHubTokenSave(grantId: string, signIn: HubSignIn, next: HubTokens): Promise<void> {
    try {
      if (await this.liveHub(grantId)) {
        logError(`grant ${grantId}: stored hub tokens changed during refresh; not overwritten`);
        return;
      }
    } catch (error) {
      // Whether a sibling rides the new pair is unknown, so hub is not asked to
      // revoke it; unused, it expires on its own.
      logError(
        `grant ${grantId}: could not check the grant after a lost hub token save ` +
          `(${errorCodeOf(error)}); not revoking the new hub pair`
      );
      throw signInGone();
    }
    logError(
      `grant ${grantId}: revoked during the hub refresh; ` +
        'revoking the new hub pair unless a live sibling shares the hub sign-in'
    );
    await this.revokeAtHubUnlessSibling(grantId, { ...signIn, ...next });
    throw signInGone();
  }

  /**
   * For shutdown: lets in-flight hub refreshes land, then makes a last attempt
   * at saving every rotated pair held only in memory (a save that fails again
   * revokes the grant, if the revoke lands). Losing either leaves the store
   * with a refresh token hub has burned; the next refresh replays it, and hub
   * ends the user's sign-in on that organization.
   */
  async drain(): Promise<void> {
    this.draining = true;
    // Only flights already past the draining check: one still queued on the
    // grant lock sends nothing, and waiting for it could outlast the deadline.
    await Promise.allSettled(
      [...this.refreshing].filter(([grantId]) => this.posting.has(grantId)).map(([, flight]) => flight)
    );
    for (const grantId of [...this.unsaved.keys()]) {
      try {
        const live = await this.liveHub(grantId);
        const next = this.unsaved.get(grantId);
        if (live && next) await this.saveHubTokens(grantId, live.hub, live.stored, next);
      } catch {
        // The grant read failed (the pair is still unsaved), or the grant was
        // revoked (meanwhile, or by saveHubTokens after the save failed again):
        // saveHubTokens threw signInGone and dropped the pair.
      }
      if (this.unsaved.has(grantId)) {
        logError(`ERROR grant ${grantId}: rotated hub tokens lost at shutdown`);
      }
    }
  }

  async challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    const record = await this.liveCode(client, authorizationCode);
    if (!record.codeChallenge) throw new InvalidGrantError('authorization code has no challenge');
    return record.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL
  ): Promise<OAuthTokens> {
    const record = await this.liveCode(client, authorizationCode);
    if (redirectUri && record.redirectUri !== redirectUri) {
      throw new InvalidGrantError('redirect_uri does not match the authorization request');
    }
    if (resource && resource.href !== (record.resource ?? this.expectedResource)) {
      throw new InvalidGrantError('resource does not match the authorization request');
    }
    // Single-use: a replayed code must fail, per OAuth 2.1 — and of two
    // concurrent exchanges, only the one whose delete took the row mints.
    if (!(await this.store.deleteToken(authorizationCode, 'code'))) {
      throw new InvalidGrantError('authorization code is invalid or expired');
    }
    return this.mintTokenPair(record.grantId, record.resource);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    _scopes?: string[],
    resource?: URL
  ): Promise<OAuthTokens> {
    const record = await this.store.getToken(refreshToken, 'refresh');
    if (!record || record.expiresAt <= nowSeconds()) {
      throw new InvalidGrantError('refresh token is invalid or expired');
    }
    const grant = await this.store.getGrant(record.grantId);
    // Defensive, like liveHub and verifyAccessToken: the store revokes an unreadable
    // grant on read, so a live grant without its hub pair should not reach here.
    if (!grant?.hub || grant.revoked || grant.clientId !== client.client_id) {
      throw new InvalidGrantError('refresh token is invalid or expired');
    }
    if (resource && resource.href !== (record.resource ?? this.expectedResource)) {
      throw new InvalidGrantError('resource does not match the original grant');
    }
    // Rotation: the old refresh token dies with the exchange, once.
    if (!(await this.store.deleteToken(refreshToken, 'refresh'))) {
      throw new InvalidGrantError('refresh token is invalid or expired');
    }
    return this.mintTokenPair(record.grantId, record.resource);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const record = await this.store.getToken(token, 'access');
    if (!record || record.expiresAt <= nowSeconds()) {
      throw new InvalidTokenError('access token is invalid or expired');
    }
    const grant = await this.store.getGrant(record.grantId);
    if (!grant?.hub || grant.revoked) {
      throw new InvalidTokenError('access token is invalid or expired');
    }
    const hub: HubIdentity = {
      grantId: grant.id,
      accessToken: grant.hub.accessToken,
      tenantId: grant.hub.tenantId,
      sub: grant.hub.sub
    };
    return {
      token,
      clientId: grant.clientId,
      scopes: [],
      expiresAt: record.expiresAt,
      resource: new URL(record.resource ?? this.expectedResource),
      extra: { hub }
    };
  }

  /**
   * Revoking either token kind revokes the whole grant — every token from that
   * login stops working, which is what a "disconnect" must mean. Hub's revoke
   * ends that user's sign-in on the organization for every client, so it is
   * only called when no other live grant rides the same sign-in.
   */
  async revokeToken(
    client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest
  ): Promise<void> {
    for (const kind of ['refresh', 'access'] as const) {
      const record = await this.store.getToken(request.token, kind);
      if (!record) continue;
      const grant = await this.store.getGrant(record.grantId);
      // Spec: revoking someone else's token is a silent no-op, not an oracle.
      if (grant && grant.clientId === client.client_id && !grant.revoked) {
        // Under the grant lock: a hub refresh in any process lands first, and
        // none starts until the revoke commits — either would rotate the pair
        // just after we read it, and hub would be sent the already-burned token.
        let revoked: { hub?: HubSignIn } | undefined;
        try {
          revoked = await this.store.withGrantLock(grant.id, async (locked) => {
            // Ended since the check above, by whoever logged and revoked it then.
            if (!locked.grant || locked.grant.revoked) return undefined;
            await locked.revoke();
            return { hub: locked.grant.hub && { ...locked.grant.hub, ...this.unsaved.get(grant.id) } };
          });
        } catch (error) {
          // The store is closing: a 400 temporarily_unavailable the client may retry, not a 500.
          if (error instanceof XyteError) throw new TemporarilyUnavailableError(error.message);
          logError(`grant ${grant.id}: grant lock transaction failed for a revoke (${errorCodeOf(error)})`);
          throw error;
        }
        this.unsaved.delete(grant.id);
        if (!revoked) return;
        logEvent('revoke', { ...whoOf(grant.id, revoked.hub), reason: 'client' });
        if (revoked.hub) await this.revokeAtHubUnlessSibling(grant.id, revoked.hub);
      }
      return;
    }
  }

  /** After a committed revoke: best effort, so a failure is logged and the client still gets success. */
  private async revokeAtHubUnlessSibling(grantId: string, hub: HubSignIn): Promise<void> {
    let sibling: boolean;
    try {
      sibling = await this.store.hasLiveHubSibling(hub.sub, hub.tenantId, grantId);
    } catch (error) {
      logError(`grant ${grantId}: sibling check failed after the revoke (${errorCodeOf(error)}); not revoking at hub`);
      return;
    }
    if (sibling) return;
    await this.hub
      .revoke(hub.refreshToken)
      .catch((error: unknown) => logError(`grant ${grantId}: hub revoke failed (${errorCodeOf(error)})`));
  }

  private async liveCode(
    client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<TokenRecord> {
    const record = await this.store.getToken(authorizationCode, 'code');
    if (!record || record.expiresAt <= nowSeconds()) {
      throw new InvalidGrantError('authorization code is invalid or expired');
    }
    const grant = await this.store.getGrant(record.grantId);
    if (!grant || grant.revoked) {
      throw new InvalidGrantError('authorization code is invalid or expired');
    }
    if (grant.clientId !== client.client_id) {
      throw new InvalidClientError('authorization code was issued to another client');
    }
    return record;
  }

  private async mintTokenPair(grantId: string, resource?: string): Promise<OAuthTokens> {
    const accessToken = mintToken('at');
    const refreshToken = mintToken('rt');
    const shared = { grantId, ...(resource ? { resource } : {}) };
    await this.store.saveToken({
      token: accessToken,
      kind: 'access',
      ...shared,
      expiresAt: nowSeconds() + ACCESS_TTL_SECONDS
    });
    await this.store.saveToken({
      token: refreshToken,
      kind: 'refresh',
      ...shared,
      expiresAt: nowSeconds() + REFRESH_TTL_SECONDS
    });
    return {
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: ACCESS_TTL_SECONDS,
      refresh_token: refreshToken
    };
  }
}

/** What a verified token resolves to: its grant and that grant's hub token. */
export interface HubIdentity {
  grantId: string;
  /** As stored at verify time; hubHttp sends the current one, possibly refreshed. */
  accessToken: string;
  /** Hub organization and user of the sign-in, for log attribution only. */
  tenantId: string;
  sub: string;
}

export function hubIdentityOf(auth: AuthInfo): HubIdentity {
  const hub = auth.extra?.hub as HubIdentity | undefined;
  if (!hub) throw new InvalidTokenError('token carries no hub identity');
  return hub;
}

/** A grant's log identity: the connection, plus its organization and user when known. */
function whoOf(grantId: string, hub: HubSignIn | undefined) {
  return { connection: grantId, organization: hub?.tenantId, user: hub?.sub };
}

/** A consent or callback that cannot go on: the expired page, and the sign-in's end in the logs. */
function endOnExpiredPage(res: Response, reason: string, clientId?: string): void {
  logEvent('sign_in', { outcome: 'failed', reason, client: clientId });
  res.status(400).type('html').send(errorPage(EXPIRED));
}

/** Retryable: the grant lock could not be taken, or another process moved the sign-in on. */
function signInBusy(): XyteError {
  return new XyteError(
    'network',
    'This Xyte sign-in is busy: another request is refreshing it, or the server is busy.',
    ['Retry in a few seconds.']
  );
}

function signInGone(): XyteError {
  return new XyteError('auth', 'The Xyte sign-in behind this connection has ended.', [
    'Reconnect the Xyte connector to sign in again.'
  ]);
}

function mintToken(kind: 'ac' | 'at' | 'rt'): string {
  return `xmcp_${kind}_${randomBytes(32).toString('base64url')}`;
}

function random(): string {
  return randomBytes(24).toString('base64url');
}

/** Whether `presented` hashes to `expectedHash`, compared in constant time; a non-string never matches. */
function matchesHash(presented: unknown, expectedHash: string): presented is string {
  if (typeof presented !== 'string') return false;
  const a = Buffer.from(hashToken(presented));
  const b = Buffer.from(expectedHash);
  return a.length === b.length && timingSafeEqual(a, b);
}

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  path: '/'
} as const;

/** `__Host-` pins the cookie to this exact host over https, path /. */
function setBrowserCookie(res: Response, pendingId: string, value: string): void {
  res.cookie(COOKIE_PREFIX + pendingId, value, {
    ...COOKIE_OPTIONS,
    maxAge: PENDING_TTL_SECONDS * 1000
  });
}

function clearBrowserCookie(res: Response, name: string): void {
  res.cookie(name, '', { ...COOKIE_OPTIONS, maxAge: 0 });
}

/** Our flow cookies the browser sent; their names came from us, so they are safe to set back. */
function cookieNames(req: Request | undefined): string[] {
  return (req?.headers.cookie ?? '')
    .split(';')
    .map((part) => part.trim().split('=')[0] ?? '')
    .filter((name) => name.startsWith(COOKIE_PREFIX));
}

function readCookie(req: Request, name: string): string | undefined {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const [key, ...value] = part.trim().split('=');
    if (key === name) return value.join('=');
  }
  return undefined;
}

/** Only ever to the redirect URI stored at /authorize, where the SDK checked it against the client. */
function clientRedirect(entry: PendingSignIn, params: Record<string, string>): string {
  const target = new URL(entry.redirectUri);
  for (const [key, value] of Object.entries(params)) target.searchParams.set(key, value);
  if (entry.state) target.searchParams.set('state', entry.state);
  return target.toString();
}

/** Scheme + host, or the whole URI when it has no host (e.g. `cursor:/callback`). */
function redirectTarget(uri: string): string {
  const url = new URL(uri);
  return url.host ? `${url.protocol}//${url.host}` : url.href;
}

function frameDeny(res: Response): Response {
  return res
    .setHeader('Content-Security-Policy', "frame-ancestors 'none'")
    .setHeader('X-Frame-Options', 'DENY')
    .setHeader('Cache-Control', 'no-store');
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function consentPage(options: {
  clientName?: string;
  redirectTarget: string;
  pendingId: string;
  csrf: string;
}): string {
  const name = options.clientName
    ? `<strong>${escapeHtml(options.clientName)}</strong> ` +
      '<span class="note">(name chosen by the app itself)</span>'
    : 'An unnamed app';
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Connect to Xyte</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #f4f5f7; margin: 0;
           display: grid; place-items: center; min-height: 100vh; }
    form { background: #fff; padding: 2rem; border-radius: 8px; width: min(24rem, 90vw);
           box-shadow: 0 1px 4px rgba(0,0,0,.15); }
    h1 { font-size: 1.1rem; margin: 0 0 1rem; }
    p { color: #333; font-size: .9rem; margin: 0 0 .75rem; }
    .note { color: #777; font-size: .8rem; }
    .actions { display: flex; gap: .75rem; margin-top: 1.25rem; }
    button { flex: 1; padding: .6rem; border: 1px solid #2450ff; border-radius: 4px;
             font-size: .95rem; cursor: pointer; background: #fff; color: #2450ff; }
    button[value=approve] { background: #2450ff; color: #fff; }
  </style>
</head>
<body>
  <form method="post" action="/oauth/consent">
    <h1>Connect to Xyte</h1>
    <p>${name} wants to use the Xyte API on your behalf, with your own access in the
      organization you pick next.</p>
    <p>After you sign in, you will be sent back to
      <strong>${escapeHtml(options.redirectTarget)}</strong>.</p>
    <p class="note">Only approve if you started this connection yourself.</p>
    <input type="hidden" name="pending" value="${escapeHtml(options.pendingId)}">
    <input type="hidden" name="csrf" value="${escapeHtml(options.csrf)}">
    <div class="actions">
      <button type="submit" name="decision" value="deny">Deny</button>
      <button type="submit" name="decision" value="approve">Approve</button>
    </div>
  </form>
</body>
</html>`;
}

function errorPage(message: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Xyte MCP</title></head>
<body style="font-family: system-ui, sans-serif; padding: 3rem">
  <h1 style="font-size: 1.1rem">Cannot continue</h1>
  <p>${escapeHtml(message)}</p>
</body></html>`;
}

/** Tries `attempt` up to HUB_SAVE_ATTEMPTS times, 100 ms and 200 ms apart; rethrows the last error. */
async function withSaveRetries<T>(attempt: () => Promise<T>): Promise<T> {
  for (let tries = 1; ; tries += 1) {
    try {
      return await attempt();
    } catch (error) {
      if (tries >= HUB_SAVE_ATTEMPTS) throw error;
      await new Promise((resolve) => setTimeout(resolve, 100 * tries));
    }
  }
}
