import { randomBytes } from 'node:crypto';
import type { Response } from 'express';
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
import type { HubUserCredential } from '../config.js';
import type { OAuthStore, TokenRecord } from './store.js';

/**
 * The OAuth 2.1 authorization server, backed by hub logins.
 *
 * The protocol surface (metadata, DCR, /authorize, /token, PKCE verification)
 * is the SDK's `mcpAuthRouter`; this class is only the policy behind it:
 * `/authorize` renders a login form, a successful hub sign-in becomes a grant
 * holding that user's hub credential, and the tokens we mint are our own,
 * audience-bound to this server. The client's token is never forwarded to the
 * hub — each request looks up the grant and uses the stored hub credential —
 * so a token stolen from a client is useless against the hub directly.
 */

const CODE_TTL_SECONDS = 10 * 60;
const ACCESS_TTL_SECONDS = 60 * 60;
const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;

/** Validates hub credentials; returns undefined on a wrong email/password. */
export type HubSignIn = (email: string, password: string) => Promise<HubUserCredential | undefined>;

export interface LoginForm {
  email?: string;
  password?: string;
  client_id?: string;
  redirect_uri?: string;
  code_challenge?: string;
  state?: string;
  resource?: string;
}

export type LoginResult = { redirectTo: string } | { html: string; status: number };

export class XyteOAuthProvider implements OAuthServerProvider {
  readonly clientsStore: OAuthRegisteredClientsStore;

  constructor(
    private readonly store: OAuthStore,
    private readonly signIn: HubSignIn,
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

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    res
      .status(200)
      .type('html')
      .send(
        loginPage({
          clientName: typeof client.client_name === 'string' ? client.client_name : client.client_id,
          hidden: {
            client_id: client.client_id,
            redirect_uri: params.redirectUri,
            code_challenge: params.codeChallenge,
            ...(params.state ? { state: params.state } : {}),
            ...(params.resource ? { resource: params.resource.href } : {})
          }
        })
      );
  }

  /**
   * The POST /login handler's logic: validate the replayed OAuth parameters
   * against the client's registration (they arrive from a browser form, so
   * they are attacker-writable), check the credentials with the hub, and mint
   * a single-use authorization code bound to the PKCE challenge.
   */
  async completeLogin(form: LoginForm): Promise<LoginResult> {
    const { client_id, redirect_uri, code_challenge, state, resource, email, password } = form;

    const client = client_id ? await this.store.getClient(client_id) : undefined;
    // Registered redirect URIs only — anything else turns the login page into
    // an open redirector that hands codes to whoever forged the form.
    if (!client || !redirect_uri || !client.redirect_uris.includes(redirect_uri)) {
      return { html: errorPage('Invalid authorization request. Restart the connection.'), status: 400 };
    }
    if (!code_challenge) {
      return { html: errorPage('Missing PKCE challenge. Restart the connection.'), status: 400 };
    }
    if (resource && resource !== this.expectedResource) {
      return { html: errorPage('This authorization is for a different server.'), status: 400 };
    }

    const retry = (message: string): LoginResult => ({
      status: 401,
      html: loginPage({
        clientName: typeof client.client_name === 'string' ? client.client_name : client.client_id,
        error: message,
        hidden: {
          client_id: client.client_id,
          redirect_uri,
          code_challenge,
          ...(state ? { state } : {}),
          ...(resource ? { resource } : {})
        }
      })
    });

    if (!email || !password) return retry('Email and password are required.');
    const hub = await this.signIn(email, password);
    if (!hub) return retry('Wrong email or password.');

    const grantId = await this.store.createGrant(client.client_id, hub);
    const code = mintToken('ac');
    await this.store.saveToken({
      token: code,
      kind: 'code',
      grantId,
      codeChallenge: code_challenge,
      redirectUri: redirect_uri,
      ...(resource ? { resource } : {}),
      expiresAt: nowSeconds() + CODE_TTL_SECONDS
    });

    const target = new URL(redirect_uri);
    target.searchParams.set('code', code);
    if (state) target.searchParams.set('state', state);
    return { redirectTo: target.toString() };
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
    // Single-use: a replayed code must fail, per OAuth 2.1.
    await this.store.deleteToken(authorizationCode, 'code');
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
    // Rotation: the old refresh token dies with the exchange.
    await this.store.deleteToken(refreshToken, 'refresh');
    return this.mintTokenPair(record.grantId, record.resource);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const record = await this.store.getToken(token, 'access');
    if (!record || record.revoked || record.expiresAt <= nowSeconds()) {
      throw new InvalidTokenError('access token is invalid or expired');
    }
    const grant = await this.store.getGrant(record.grantId);
    if (!grant || grant.revoked) {
      throw new InvalidTokenError('access token is invalid or expired');
    }
    return {
      token,
      clientId: grant.clientId,
      scopes: [],
      expiresAt: record.expiresAt,
      resource: new URL(record.resource ?? this.expectedResource),
      extra: { hub: grant.hub }
    };
  }

  /**
   * Revoking either token kind revokes the whole grant — every token from that
   * login stops working, which is what a "disconnect" must mean.
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
      if (grant && grant.clientId === client.client_id) {
        await this.store.revokeGrant(grant.id);
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

/** The hub credential attached to a verified token, typed out of `extra`. */
export function hubCredentialOf(auth: AuthInfo): HubUserCredential {
  const hub = auth.extra?.hub as HubUserCredential | undefined;
  if (!hub) throw new InvalidTokenError('token carries no hub credential');
  return hub;
}

function mintToken(kind: 'ac' | 'at' | 'rt'): string {
  return `xmcp_${kind}_${randomBytes(32).toString('base64url')}`;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function loginPage(options: {
  clientName: string;
  error?: string;
  hidden: Record<string, string>;
}): string {
  const hiddenFields = Object.entries(options.hidden)
    .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
    .join('\n      ');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in to Xyte</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #f4f5f7; margin: 0;
           display: grid; place-items: center; min-height: 100vh; }
    form { background: #fff; padding: 2rem; border-radius: 8px; width: min(22rem, 90vw);
           box-shadow: 0 1px 4px rgba(0,0,0,.15); }
    h1 { font-size: 1.1rem; margin: 0 0 .25rem; }
    p { color: #555; font-size: .85rem; margin: 0 0 1rem; }
    label { display: block; font-size: .8rem; margin: .75rem 0 .25rem; }
    input[type=email], input[type=password] { width: 100%; box-sizing: border-box;
      padding: .5rem; border: 1px solid #ccc; border-radius: 4px; }
    button { margin-top: 1.25rem; width: 100%; padding: .6rem; border: 0; border-radius: 4px;
             background: #2450ff; color: #fff; font-size: .95rem; cursor: pointer; }
    .error { color: #b3261e; font-size: .85rem; margin: .75rem 0 0; }
  </style>
</head>
<body>
  <form method="post" action="/login">
    <h1>Sign in to Xyte</h1>
    <p>${escapeHtml(options.clientName)} is asking to access Xyte on your behalf.</p>
    <label for="email">Email</label>
    <input id="email" name="email" type="email" autocomplete="username" required autofocus>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    ${options.error ? `<p class="error">${escapeHtml(options.error)}</p>` : ''}
    <button type="submit">Sign in</button>
      ${hiddenFields}
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
