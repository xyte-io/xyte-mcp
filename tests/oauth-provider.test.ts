import { describe, expect, it, vi } from 'vitest';
import type { Request, Response as ExpressResponse } from 'express';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { XyteError, XyteHttpError } from '../src/http/errors.js';
import { createHubOAuth } from '../src/oauth/hub-oauth.js';
import { hubIdentityOf, XyteOAuthProvider } from '../src/oauth/provider.js';
import { MemoryOAuthStore } from '../src/oauth/store.js';
import { stubHttp } from './support/context.js';
import { hubAcceptsPkce } from './support/pkce.js';

const ISSUER = 'https://mcp.test';
const HUB = 'https://hub.test';
const REDIRECT = 'https://client.test/callback';
const ID_CLAIMS = { sub: 'user-1', xyte_tenant_id: 'org-1', email: 'user@example.com' };
const ID_TOKEN = `h.${Buffer.from(JSON.stringify(ID_CLAIMS)).toString('base64url')}.s`;

/**
 * Hub's token and revoke endpoints behind a fetch mock. Every token response
 * mints a fresh pair; `onRefresh` overrides the refresh answer per test. A code
 * exchange is refused unless its verifier fits `challenge`, the one sent on the
 * last authorize redirect.
 */
function fakeHub() {
  const calls: Array<{ path: string; form: URLSearchParams; auth: string }> = [];
  let minted = 0;
  const pair = (expiresIn = 3600) => {
    minted += 1;
    return json(200, {
      access_token: `xoat_${minted}`,
      refresh_token: `xort_${minted}`,
      expires_in: expiresIn,
      token_type: 'Bearer',
      id_token: ID_TOKEN
    });
  };
  const hub = {
    calls,
    expiresIn: 3600,
    challenge: undefined as string | undefined,
    onRefresh: undefined as undefined | ((form: URLSearchParams) => Promise<Response> | Response),
    refreshes: () => calls.filter((call) => call.form.get('grant_type') === 'refresh_token'),
    revokes: () => calls.filter((call) => call.path === '/oauth/revoke'),
    fetchImpl: (async (url: string, init: RequestInit) => {
      const path = new URL(url).pathname;
      const form = new URLSearchParams(String(init.body));
      calls.push({ path, form, auth: String((init.headers as Record<string, string>).Authorization) });
      if (path === '/oauth/revoke') return new Response(null, { status: 200 });
      if (form.get('grant_type') === 'refresh_token' && hub.onRefresh) return hub.onRefresh(form);
      if (
        form.get('grant_type') === 'authorization_code' &&
        !hubAcceptsPkce(form.get('code_verifier'), hub.challenge)
      ) {
        return json(400, { error: 'invalid_grant' });
      }
      return pair(hub.expiresIn);
    }) as unknown as typeof fetch
  };
  return hub;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

let currentHub: ReturnType<typeof fakeHub> | undefined;

function makeProvider() {
  const store = new MemoryOAuthStore();
  const hub = fakeHub();
  currentHub = hub;
  const provider = new XyteOAuthProvider(
    store,
    createHubOAuth({
      hubUrl: HUB,
      clientId: 'mcp-client',
      clientSecret: 's3cret',
      redirectUri: `${ISSUER}/oauth/callback`,
      timeoutMs: 1000,
      fetchImpl: hub.fetchImpl
    }),
    ISSUER
  );
  return { provider, store, hub };
}

async function registeredClient(
  provider: XyteOAuthProvider,
  clientId = 'client-1'
): Promise<OAuthClientInformationFull> {
  // The SDK's DCR handler mints ids before calling registerClient; mimic that.
  return provider.clientsStore.registerClient!({
    client_id: clientId,
    client_id_issued_at: 1,
    client_name: '<b>Test</b> Client',
    redirect_uris: [REDIRECT],
    token_endpoint_auth_method: 'none'
  } as OAuthClientInformationFull) as Promise<OAuthClientInformationFull>;
}

/** Just enough of express's Response to record what the provider did. */
function fakeRes() {
  const out = {
    status: 200,
    html: '',
    location: '',
    headers: {} as Record<string, string>,
    cookies: {} as Record<string, { value: string; options: Record<string, unknown> }>
  };
  const res = {
    headersSent: false,
    status: (code: number) => ((out.status = code), res),
    type: () => res,
    send: (body: string) => ((out.html = body), res),
    setHeader: (name: string, value: string) => ((out.headers[name] = value), res),
    cookie: (name: string, value: string, options: Record<string, unknown>) => (
      (out.cookies[name] = { value, options }), res
    ),
    redirect: (code: number, url: string) => {
      out.status = code;
      out.location = url;
    }
  };
  return { out, res: res as unknown as ExpressResponse };
}

function fakeReq(fields: { body?: unknown; query?: unknown; cookie?: string }): Request {
  return {
    body: fields.body,
    query: fields.query ?? {},
    headers: fields.cookie ? { cookie: fields.cookie } : {}
  } as unknown as Request;
}

/** /authorize → consent page; returns what the page and its cookie carry. */
async function openConsent(provider: XyteOAuthProvider, client: OAuthClientInformationFull) {
  const { out, res } = fakeRes();
  await provider.authorize(
    client,
    { codeChallenge: 'client-challenge', redirectUri: REDIRECT, state: 'st4te' },
    res
  );
  const pending = /name="pending" value="([^"]+)"/.exec(out.html)![1]!;
  const csrf = /name="csrf" value="([^"]+)"/.exec(out.html)![1]!;
  const [cookieName, cookie] = Object.entries(out.cookies)[0]!;
  return { out, pending, csrf, cookie: `${cookieName}=${cookie.value}` };
}

/** Approve on the consent page; returns the hub redirect and the rotated cookie. */
async function approve(provider: XyteOAuthProvider, client: OAuthClientInformationFull) {
  const consent = await openConsent(provider, client);
  const { out, res } = fakeRes();
  await provider.consent(
    fakeReq({
      body: { pending: consent.pending, csrf: consent.csrf, decision: 'approve' },
      cookie: consent.cookie
    }),
    res
  );
  const [cookieName, cookie] = Object.entries(out.cookies)[0]!;
  currentHub!.challenge = new URL(out.location).searchParams.get('code_challenge') ?? undefined;
  return { out, pending: consent.pending, cookie: `${cookieName}=${cookie.value}` };
}

async function callback(
  provider: XyteOAuthProvider,
  query: Record<string, string>,
  cookie?: string
) {
  const { out, res } = fakeRes();
  await provider.callback(fakeReq({ query, ...(cookie ? { cookie } : {}) }), res);
  return out;
}

/** The whole browser leg, ending in our code for the MCP client. */
async function signIn(provider: XyteOAuthProvider, client: OAuthClientInformationFull) {
  const { pending, cookie } = await approve(provider, client);
  const out = await callback(provider, { state: pending, code: 'hub-code' }, cookie);
  const url = new URL(out.location);
  return { code: url.searchParams.get('code')!, state: url.searchParams.get('state') };
}

async function connected(provider: XyteOAuthProvider, client: OAuthClientInformationFull) {
  const { code } = await signIn(provider, client);
  const tokens = await provider.exchangeAuthorizationCode(client, code);
  const { grantId } = hubIdentityOf(await provider.verifyAccessToken(tokens.access_token));
  return { tokens, grantId };
}

describe('XyteOAuthProvider: consent and hub sign-in', () => {
  it('registers and retrieves clients through the store', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);

    expect(await provider.clientsStore.getClient(client.client_id)).toMatchObject({
      client_id: client.client_id,
      redirect_uris: [REDIRECT]
    });
  });

  it('renders a consent page — escaped self-declared name, redirect host, no framing', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { out, cookie } = await openConsent(provider, client);

    expect(out.status).toBe(200);
    expect(out.location).toBe(''); // never auto-approves
    expect(out.html).toContain('&lt;b&gt;Test&lt;/b&gt; Client');
    expect(out.html).not.toContain('<b>Test</b>');
    expect(out.html).toContain('name chosen by the app itself');
    expect(out.html).toContain('client.test');
    expect(out.html).toContain('action="/oauth/consent"');
    expect(out.headers['Content-Security-Policy']).toBe("frame-ancestors 'none'");
    expect(out.headers['X-Frame-Options']).toBe('DENY');
    expect(cookie).toMatch(/^__Host-xmcp_/);
    expect(hub.calls).toHaveLength(0);
  });

  it('approve sets a __Host- cookie and redirects to hub with our own PKCE + scope', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const { out, pending } = await approve(provider, client);

    const cookie = Object.values(out.cookies)[0]!;
    expect(cookie.options).toMatchObject({ httpOnly: true, secure: true, sameSite: 'lax', path: '/' });
    const url = new URL(out.location);
    expect(url.origin + url.pathname).toBe(`${HUB}/oauth/authorize`);
    expect(Object.fromEntries(url.searchParams)).toMatchObject({
      response_type: 'code',
      client_id: 'mcp-client',
      redirect_uri: `${ISSUER}/oauth/callback`,
      scope: 'openid email profile',
      state: pending,
      code_challenge_method: 'S256'
    });
    // Our challenge toward hub, not the MCP client's.
    expect(url.searchParams.get('code_challenge')).not.toBe('client-challenge');
  });

  it('refuses an approve without the browser cookie or with a wrong CSRF token', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    for (const tamper of [{ cookie: undefined }, { csrf: 'forged' }]) {
      const consent = await openConsent(provider, client);
      const { out, res } = fakeRes();
      await provider.consent(
        fakeReq({
          body: { pending: consent.pending, csrf: tamper.csrf ?? consent.csrf, decision: 'approve' },
          ...('cookie' in tamper ? {} : { cookie: consent.cookie })
        }),
        res
      );
      expect(out.status).toBe(400);
      expect(out.location).toBe('');
    }
  });

  it('deny sends access_denied back to the client with its state', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const consent = await openConsent(provider, client);
    const { out, res } = fakeRes();
    await provider.consent(
      fakeReq({
        body: { pending: consent.pending, csrf: consent.csrf, decision: 'deny' },
        cookie: consent.cookie
      }),
      res
    );

    const url = new URL(out.location);
    expect(url.origin + url.pathname).toBe(REDIRECT);
    expect(url.searchParams.get('error')).toBe('access_denied');
    expect(url.searchParams.get('state')).toBe('st4te');
    expect(hub.calls).toHaveLength(0);
  });

  it('callback mints a code bound to the client challenge and stores the hub sign-in', async () => {
    const { provider, store, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { code, state } = await signIn(provider, client);

    expect(code).toMatch(/^xmcp_ac_/);
    expect(state).toBe('st4te');
    const exchange = hub.calls[0]!;
    expect(exchange.path).toBe('/oauth/token');
    expect(exchange.form.get('grant_type')).toBe('authorization_code');
    expect(hubAcceptsPkce(exchange.form.get('code_verifier'), hub.challenge)).toBe(true);
    expect(exchange.auth).toBe(`Basic ${Buffer.from('mcp-client:s3cret').toString('base64')}`);

    const record = await store.getToken(code, 'code');
    expect(record?.codeChallenge).toBe('client-challenge');
    expect((await store.getGrant(record!.grantId))?.hub).toMatchObject({
      accessToken: 'xoat_1',
      refreshToken: 'xort_1',
      sub: 'user-1',
      tenantId: 'org-1',
      email: 'user@example.com'
    });
  });

  it('callback without, or with the wrong, browser cookie issues nothing and drops the entry', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);

    const missing = await approve(provider, client);
    expect((await callback(provider, { state: missing.pending, code: 'c' })).status).toBe(400);
    // Dropped: even the right cookie cannot complete it now.
    expect(
      (await callback(provider, { state: missing.pending, code: 'c' }, missing.cookie)).status
    ).toBe(400);

    const wrong = await approve(provider, client);
    const forged = `${wrong.cookie.split('=')[0]}=attacker-value`;
    const out = await callback(provider, { state: wrong.pending, code: 'c' }, forged);
    expect(out.status).toBe(400);
    expect(out.location).toBe('');
    expect(hub.calls).toHaveLength(0);
  });

  it('passes a hub error and error_reason through to the client redirect', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { pending, cookie } = await approve(provider, client);

    const out = await callback(
      provider,
      {
        state: pending,
        error: 'access_denied',
        error_reason: 'org_not_approved',
        error_description: 'Ask your administrator'
      },
      cookie
    );
    const url = new URL(out.location);
    expect(url.origin + url.pathname).toBe(REDIRECT);
    expect(url.searchParams.get('error')).toBe('access_denied');
    expect(url.searchParams.get('error_description')).toBe('org_not_approved: Ask your administrator');
    expect(url.searchParams.get('state')).toBe('st4te');
    expect(url.searchParams.get('code')).toBeNull();
    expect(hub.calls).toHaveLength(0);
  });

  it('refuses an /authorize for another resource', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const { out, res } = fakeRes();
    await provider.authorize(
      client,
      { codeChallenge: 'c', redirectUri: REDIRECT, resource: new URL('https://other.test/mcp') },
      res
    );
    expect(out.status).toBe(400);
  });
});

describe('XyteOAuthProvider: our tokens', () => {
  it('exchanges a code once, returning our own tokens with the hub grant behind them', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const { code } = await signIn(provider, client);

    expect(await provider.challengeForAuthorizationCode(client, code)).toBe('client-challenge');
    const tokens = await provider.exchangeAuthorizationCode(client, code, undefined, REDIRECT);
    expect(tokens.access_token).toMatch(/^xmcp_at_/);
    expect(tokens.refresh_token).toMatch(/^xmcp_rt_/);
    expect(hubIdentityOf(await provider.verifyAccessToken(tokens.access_token))).toMatchObject({
      accessToken: 'xoat_1'
    });

    await expect(provider.exchangeAuthorizationCode(client, code)).rejects.toThrow(/invalid/);
  });

  it('refuses a code issued to another client, or a mismatched redirect_uri', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const other = await registeredClient(provider, 'client-2');
    const { code } = await signIn(provider, client);

    await expect(provider.exchangeAuthorizationCode(other, code)).rejects.toThrow(/another client/);
    await expect(
      provider.exchangeAuthorizationCode(client, code, undefined, 'https://client.test/other')
    ).rejects.toThrow(/redirect_uri/);
  });

  it('rotates refresh tokens and kills the old one', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const { tokens: first } = await connected(provider, client);

    const second = await provider.exchangeRefreshToken(client, first.refresh_token!);
    await expect(provider.verifyAccessToken(second.access_token)).resolves.toBeTruthy();
    await expect(provider.exchangeRefreshToken(client, first.refresh_token!)).rejects.toThrow(
      /invalid or expired/
    );
  });

  it('expires access tokens', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const { tokens } = await connected(provider, client);
    vi.useFakeTimers({ now: Date.now() + 61 * 60 * 1000 });
    try {
      await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(/expired/);
    } finally {
      vi.useRealTimers();
    }
  });

  it('treats a grant without hub tokens (the old devise login) as invalid', async () => {
    const { provider, store } = makeProvider();
    const grantId = await store.createGrant('client-1', undefined as never);
    await store.saveToken({ token: 'old-at', kind: 'access', grantId, expiresAt: 2 ** 31 });
    await expect(provider.verifyAccessToken('old-at')).rejects.toThrow(/invalid/);
  });
});

describe('XyteOAuthProvider: hub token lifecycle', () => {
  const upstreamOk = () => stubHttp(() => ({ data: {} }));

  it('sends the hub token as a Bearer through the grant client', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    const upstream = upstreamOk();

    await provider.hubHttp(grantId, upstream).request({
      method: 'GET',
      url: `${HUB}/core/v1/organization/devices`,
      headers: { Authorization: 'Bearer stale' },
      endpointKey: 'k'
    });
    expect(upstream.calls[0]!.headers.Authorization).toBe('Bearer xoat_1');
  });

  it('N parallel calls across hub-token expiry share exactly one refresh', async () => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30; // inside the refresh window from the start
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    hub.expiresIn = 3600;
    const upstream = upstreamOk();
    const http = provider.hubHttp(grantId, upstream);

    await Promise.all(
      Array.from({ length: 8 }, () =>
        http.request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
      )
    );
    expect(hub.refreshes()).toHaveLength(1);
    expect(hub.refreshes()[0]!.form.get('refresh_token')).toBe('xort_1');
    expect(upstream.calls.map((call) => call.headers.Authorization)).toEqual(
      Array(8).fill('Bearer xoat_2')
    );
  });

  it('on a hub 401, refreshes once and retries once', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    const upstream = stubHttp((request) =>
      request.headers.Authorization === 'Bearer xoat_1'
        ? new XyteHttpError(401, 'Unauthorized', {}, 'k')
        : { data: {} }
    );

    await provider
      .hubHttp(grantId, upstream)
      .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });
    expect(hub.refreshes()).toHaveLength(1);
    expect(upstream.calls.map((call) => call.headers.Authorization)).toEqual([
      'Bearer xoat_1',
      'Bearer xoat_2'
    ]);
  });

  it('keeps a rotated hub pair in memory when saving it keeps failing, and saves it later', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    hub.expiresIn = 3600;
    const save = vi.spyOn(store, 'rotateHubTokens').mockRejectedValue(new Error('db down'));
    const http = provider.hubHttp(grantId, upstreamOk());
    const get = () => http.request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });

    await get();
    expect(save).toHaveBeenCalledTimes(3); // the DB write is retried...
    expect(hub.refreshes()).toHaveLength(1); // ...the hub POST is not
    expect((await store.getGrant(grantId))?.hub?.refreshToken).toBe('xort_1');

    // Later calls use the unsaved pair instead of refreshing (or replaying xort_1).
    await get();
    expect(hub.refreshes()).toHaveLength(1);

    // The next refresh sends the in-memory token and saves over the stored one.
    save.mockRestore();
    const upstream = stubHttp((request) =>
      request.headers.Authorization === 'Bearer xoat_2'
        ? new XyteHttpError(401, 'Unauthorized', {}, 'k')
        : { data: {} }
    );
    await provider
      .hubHttp(grantId, upstream)
      .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });
    expect(hub.refreshes()[1]!.form.get('refresh_token')).toBe('xort_2');
    expect((await store.getGrant(grantId))?.hub?.refreshToken).toBe('xort_3');
  });

  it('invalid_grant with a stale refresh token does not revoke: the rotated token is used', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    hub.onRefresh = async () => {
      // Someone else rotated while our POST was in flight.
      await store.rotateHubTokens(grantId, 'xort_1', {
        accessToken: 'xoat_other',
        refreshToken: 'xort_other',
        expiresAt: Math.floor(Date.now() / 1000) + 3600
      });
      return json(400, { error: 'invalid_grant' });
    };
    const upstream = upstreamOk();

    await provider
      .hubHttp(grantId, upstream)
      .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });
    expect(upstream.calls[0]!.headers.Authorization).toBe('Bearer xoat_other');
    await expect(provider.verifyAccessToken(tokens.access_token)).resolves.toBeTruthy();
  });

  it('invalid_grant with the current refresh token revokes the grant: tool error now, 401 next', async () => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    hub.onRefresh = () => json(400, { error: 'invalid_grant' });
    const upstream = upstreamOk();

    const call = provider
      .hubHttp(grantId, upstream)
      .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });
    await expect(call).rejects.toMatchObject({ kind: 'auth' });
    expect(upstream.calls).toHaveLength(0);
    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(/invalid/);
  });

  it('a hub 5xx on refresh fails the call without revoking, and is not retried', async () => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    hub.onRefresh = () => json(503, { error: 'temporarily_unavailable' });

    const call = provider
      .hubHttp(grantId, upstreamOk())
      .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });
    await expect(call).rejects.toBeInstanceOf(XyteError);
    expect(hub.refreshes()).toHaveLength(1);
    await expect(provider.verifyAccessToken(tokens.access_token)).resolves.toBeTruthy();
  });
});

describe('XyteOAuthProvider: revocation', () => {
  it('revoking any token revokes the whole grant and, alone on the sign-in, revokes at hub', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { tokens } = await connected(provider, client);

    await provider.revokeToken(client, { token: tokens.refresh_token! });

    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(/invalid/);
    await expect(provider.exchangeRefreshToken(client, tokens.refresh_token!)).rejects.toThrow(
      /invalid/
    );
    expect(hub.revokes()).toHaveLength(1);
    expect(hub.revokes()[0]!.form.get('token')).toBe('xort_1');
  });

  it('skips the hub revoke while a sibling grant rides the same hub sign-in', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const first = await connected(provider, client);
    const second = await connected(provider, client);

    await provider.revokeToken(client, { token: first.tokens.access_token });

    expect(hub.revokes()).toHaveLength(0);
    await expect(provider.verifyAccessToken(second.tokens.access_token)).resolves.toBeTruthy();
  });

  it("revoking another client's token is a silent no-op", async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const other = await registeredClient(provider, 'client-2');
    const { tokens } = await connected(provider, client);

    await provider.revokeToken(other, { token: tokens.access_token });

    await expect(provider.verifyAccessToken(tokens.access_token)).resolves.toBeTruthy();
    expect(hub.revokes()).toHaveLength(0);
  });
});
