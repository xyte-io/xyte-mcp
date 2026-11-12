import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Request, Response } from 'express';
import {
  InvalidClientError,
  InvalidGrantError,
  InvalidTokenError
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
import type { HttpClient } from '../http/client.js';
import { XyteError, XyteHttpError } from '../http/errors.js';
import { logError } from '../log.js';
import { redactText } from '../redact.js';
import { nowSeconds, type HubOAuth, type HubSignIn, type HubTokens } from './hub-oauth.js';
import type { OAuthStore, TokenRecord } from './store.js';

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
 * A hub token carries its organization's full authority, like an org API key;
 * the user who signed in is attribution only, not a role the hub enforces.
 */

const CODE_TTL_SECONDS = 10 * 60;
const ACCESS_TTL_SECONDS = 60 * 60;
const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;
/** Refresh a hub access token this close to its expiry rather than risk a 401. */
const HUB_REFRESH_SKEW_SECONDS = 60;
/** Attempts at saving a rotated hub pair. Only the DB write repeats — never the hub POST. */
const HUB_SAVE_ATTEMPTS = 3;

/** An /authorize request parked across our consent page and hub's sign-in. */
interface PendingAuthorization {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state?: string;
  resource?: string;
  /** Echoed by the consent form. */
  csrf: string;
  /** Held by the consenting browser in a cookie; the callback must present it. */
  browserKey: string;
  approved: boolean;
  /** Our PKCE verifier for the hub leg. */
  hubVerifier: string;
  expiresAt: number;
}

const PENDING_TTL_SECONDS = 10 * 60;
const COOKIE_PREFIX = '__Host-xmcp_';
const EXPIRED = 'Authorization expired or invalid. Restart the connection.';

export class XyteOAuthProvider implements OAuthServerProvider {
  readonly clientsStore: OAuthRegisteredClientsStore;
  // ponytail: in-memory, as is the refresh single-flight below — which is why
  // the Procfile pins one dyno. A restart mid-login just makes the user retry.
  private readonly pending = new Map<string, PendingAuthorization>();
  private readonly refreshing = new Map<string, Promise<string>>();
  /** Rotated hub pairs the store failed to save, used in place of the stored ones. */
  private readonly unsaved = new Map<string, HubTokens>();

  constructor(
    private readonly store: OAuthStore,
    private readonly hub: HubOAuth,
    /** e.g. https://xyte-mcp-aran.herokuapp.com — no trailing slash. */
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
    const pendingId = random();
    const entry: PendingAuthorization = {
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      ...(params.state ? { state: params.state } : {}),
      ...(params.resource ? { resource: params.resource.href } : {}),
      csrf: random(),
      browserKey: random(),
      approved: false,
      // RFC 7636 4.1 (and hub) require 43-128 chars: 32 bytes is 43 in base64url.
      hubVerifier: randomBytes(32).toString('base64url'),
      expiresAt: nowSeconds() + PENDING_TTL_SECONDS
    };
    this.prunePending();
    this.pending.set(pendingId, entry);

    // Set with the page, not only on Approve: a cross-site auto-submitted
    // Approve carries no SameSite=Lax cookie, so it cannot skip this page.
    setBrowserCookie(res, pendingId, entry.browserKey);
    frameDeny(res)
      .status(200)
      .type('html')
      .send(
        consentPage({
          clientName: typeof client.client_name === 'string' ? client.client_name : undefined,
          redirectTarget: redirectTarget(params.redirectUri),
          pendingId,
          csrf: entry.csrf
        })
      );
  }

  /** POST /oauth/consent: Approve goes on to hub, Deny back to the client. */
  async consent(req: Request, res: Response): Promise<void> {
    const form = (req.body ?? {}) as Record<string, unknown>;
    const pendingId = typeof form.pending === 'string' ? form.pending : '';
    const entry = this.livePending(pendingId);
    if (
      !entry ||
      !same(form.csrf, entry.csrf) ||
      !same(readCookie(req, COOKIE_PREFIX + pendingId), entry.browserKey)
    ) {
      if (entry) this.pending.delete(pendingId);
      res.status(400).type('html').send(errorPage(EXPIRED));
      return;
    }

    if (form.decision !== 'approve') {
      this.pending.delete(pendingId);
      res.redirect(302, clientRedirect(entry, { error: 'access_denied' }));
      return;
    }

    // Same key as set with the page, so a double-clicked Approve stays valid.
    entry.approved = true;
    setBrowserCookie(res, pendingId, entry.browserKey);
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
    const entry = this.livePending(pendingId);
    // Single-use either way: a replayed callback must not mint twice.
    if (entry) {
      this.pending.delete(pendingId);
      res.cookie(COOKIE_PREFIX + pendingId, '', { ...COOKIE_OPTIONS, maxAge: 0 });
    }
    if (!entry?.approved || !same(readCookie(req, COOKIE_PREFIX + pendingId), entry.browserKey)) {
      res.status(400).type('html').send(errorPage(EXPIRED));
      return;
    }

    if (typeof query.error === 'string') {
      const description = [query.error_reason, query.error_description]
        .filter((part): part is string => typeof part === 'string' && part.length > 0)
        .join(': ');
      res.redirect(
        302,
        clientRedirect(entry, {
          error: query.error,
          ...(description ? { error_description: description } : {})
        })
      );
      return;
    }

    try {
      if (typeof query.code !== 'string') throw new Error('hub callback has no code or error');
      const signIn = await this.hub.exchangeCode(query.code, entry.hubVerifier);
      const grantId = await this.store.createGrant(entry.clientId, signIn);
      const code = mintToken('ac');
      await this.store.saveToken({
        token: code,
        kind: 'code',
        grantId,
        codeChallenge: entry.codeChallenge,
        redirectUri: entry.redirectUri,
        ...(entry.resource ? { resource: entry.resource } : {}),
        expiresAt: nowSeconds() + CODE_TTL_SECONDS
      });
      res.redirect(302, clientRedirect(entry, { code }));
    } catch (error) {
      logError(`hub sign-in failed: ${error instanceof Error ? error.message : String(error)}`);
      res.redirect(
        302,
        clientRedirect(entry, { error: 'server_error', error_description: 'Xyte sign-in failed' })
      );
    }
  }

  private livePending(pendingId: string): PendingAuthorization | undefined {
    const entry = this.pending.get(pendingId);
    return entry && entry.expiresAt > nowSeconds() ? entry : undefined;
  }

  private prunePending(): void {
    const now = nowSeconds();
    for (const [key, value] of this.pending) {
      if (value.expiresAt <= now) this.pending.delete(key);
    }
  }

  /**
   * The hub client for one grant's tool calls: swaps in a fresh hub token
   * before each call, and on a hub 401 (expired and revoked look the same)
   * refreshes once and retries once.
   */
  hubHttp(grantId: string, upstream: HttpClient): HttpClient {
    return {
      request: async (request) => {
        const send = (token: string) =>
          upstream.request({
            ...request,
            headers: { ...request.headers, Authorization: `Bearer ${token}` }
          });
        const token = await this.hubAccessToken(grantId);
        try {
          return await send(token);
        } catch (error) {
          if (!(error instanceof XyteHttpError && error.status === 401)) throw error;
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
   * read by hub as theft). One process only — see the Procfile.
   */
  private refreshHub(grantId: string, staleAccessToken: string): Promise<string> {
    let flight = this.refreshing.get(grantId);
    if (!flight) {
      flight = this.doRefresh(grantId, staleAccessToken).finally(() => {
        this.refreshing.delete(grantId);
      });
      this.refreshing.set(grantId, flight);
    }
    return flight;
  }

  private async doRefresh(grantId: string, staleAccessToken: string): Promise<string> {
    const live = await this.liveHub(grantId);
    if (!live) throw signInGone();
    const { hub, stored } = live;
    // An earlier flight already replaced the token this caller saw.
    if (
      hub.accessToken !== staleAccessToken &&
      hub.expiresAt - nowSeconds() > HUB_REFRESH_SKEW_SECONDS
    ) {
      return hub.accessToken;
    }

    const sent = hub.refreshToken;
    // Sent once, never retried: once hub answers, `sent` is burned.
    let next: HubTokens | 'invalid_grant';
    try {
      next = await this.hub.refresh(sent);
    } catch (error) {
      // A plain 4xx rejection ('auth') never rotated anything: keep the grant.
      if (error instanceof XyteError && error.kind === 'auth') throw error;
      // Timeout, network, 5xx or an unreadable 200: hub may have rotated and
      // burned `sent`. A replay inside hub's 60 s window only gets invalid_grant
      // (no pair), and one after it ends the user's sign-in — so `sent` is never
      // sent again: the grant ends here and the client reconnects.
      // Only our own messages: a JSON parse error would quote the response body.
      logError(
        `grant ${grantId}: hub refresh outcome unknown ` +
          `(${error instanceof XyteError ? error.message : 'unreadable hub response'}); ending the grant`
      );
      await this.store.revokeGrant(grantId);
      this.unsaved.delete(grantId);
      throw signInGone();
    }
    if (next === 'invalid_grant') {
      const current = await this.liveHub(grantId);
      if (current && current.hub.refreshToken !== sent) {
        return current.hub.accessToken; // Someone else rotated; theirs is good.
      }
      await this.store.revokeGrant(grantId);
      this.unsaved.delete(grantId);
      throw signInGone();
    }
    await this.saveHubTokens(grantId, stored, next);
    return next.accessToken;
  }

  /**
   * Hub has already burned the old refresh token, so losing `next` would leave
   * a replay-on-next-refresh that hub answers by ending the user's sign-in.
   * The DB write is retried; if it still fails, the pair lives in memory for
   * this process (a restart before the next successful save loses it).
   */
  private async saveHubTokens(grantId: string, stored: string, next: HubTokens): Promise<void> {
    for (let attempt = 1; ; attempt += 1) {
      try {
        if (!(await this.store.rotateHubTokens(grantId, stored, next))) {
          logError(`grant ${grantId}: stored hub tokens changed during refresh; not overwritten`);
        }
        this.unsaved.delete(grantId);
        return;
      } catch (error) {
        if (attempt < HUB_SAVE_ATTEMPTS) {
          await new Promise((resolve) => setTimeout(resolve, 100 * attempt));
          continue;
        }
        this.unsaved.set(grantId, next);
        const detail = error instanceof Error ? error.message : String(error);
        logError(
          `ERROR grant ${grantId}: could not save rotated hub tokens after ${attempt} attempts ` +
            `(${redactText(detail, [stored, next.accessToken, next.refreshToken])}); ` +
            'holding them in memory until a later refresh saves'
        );
        return;
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
    if (!record || record.revoked || record.expiresAt <= nowSeconds()) {
      throw new InvalidGrantError('refresh token is invalid or expired');
    }
    const grant = await this.store.getGrant(record.grantId);
    if (!grant || grant.revoked || grant.clientId !== client.client_id) {
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
    if (!record || record.revoked || record.expiresAt <= nowSeconds()) {
      throw new InvalidTokenError('access token is invalid or expired');
    }
    const grant = await this.store.getGrant(record.grantId);
    // No hub tokens = a grant from the retired devise-triplet login: re-auth.
    if (!grant?.hub || grant.revoked) {
      throw new InvalidTokenError('access token is invalid or expired');
    }
    const hub: HubIdentity = { grantId: grant.id, accessToken: grant.hub.accessToken };
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
        // Let an in-flight hub refresh land first: otherwise it rotates the pair
        // just after we read it, and hub is sent the already-burned token.
        await this.refreshing.get(grant.id)?.catch(() => undefined);
        const hub = (await this.liveHub(grant.id))?.hub;
        await this.store.revokeGrant(grant.id);
        this.unsaved.delete(grant.id);
        if (hub && !(await this.store.hasLiveHubSibling(hub.sub, hub.tenantId, grant.id))) {
          await this.hub.revoke(hub.refreshToken);
        }
      }
      return;
    }
  }

  private async liveCode(
    client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<TokenRecord> {
    const record = await this.store.getToken(authorizationCode, 'code');
    if (!record || record.revoked || record.expiresAt <= nowSeconds()) {
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
  accessToken: string;
}

export function hubIdentityOf(auth: AuthInfo): HubIdentity {
  const hub = auth.extra?.hub as HubIdentity | undefined;
  if (!hub) throw new InvalidTokenError('token carries no hub identity');
  return hub;
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

/** Constant-time string comparison; anything that is not a string never matches. */
function same(presented: unknown, expected: string): boolean {
  if (typeof presented !== 'string') return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
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

function readCookie(req: Request, name: string): string | undefined {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const [key, ...value] = part.trim().split('=');
    if (key === name) return value.join('=');
  }
  return undefined;
}

/** Only ever to the redirect URI stored at /authorize, where the SDK checked it against the client. */
function clientRedirect(entry: PendingAuthorization, params: Record<string, string>): string {
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
    <p>${name} wants to use the Xyte API on your behalf, with the full access of the
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
