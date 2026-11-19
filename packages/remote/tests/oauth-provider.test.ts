import { describe, expect, it, vi } from 'vitest';
import type { Request, Response as ExpressResponse } from 'express';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { HttpClient, HttpRequest, HttpResponse } from '../src/http/client.js';
import { XyteError, XyteHttpError } from '../src/http/errors.js';
import { createHubOAuth } from '../src/oauth/hub-oauth.js';
import { hubIdentityOf, XyteOAuthProvider } from '../src/oauth/provider.js';
import { MemoryOAuthStore } from '../src/oauth/store.js';
import { stubHttp } from './support/context.js';
import { hubAcceptsPkce } from './support/pkce.js';

const ISSUER = 'https://mcp.test';
const HUB = 'https://hub.test';
const REDIRECT = 'https://client.test/callback';
const idTokenFor = (claims: Record<string, string>) =>
  `h.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.s`;
const ID_TOKEN = idTokenFor({ sub: 'user-1', xyte_tenant_id: 'org-1', email: 'user@example.com' });

/**
 * Hub's token and revoke endpoints behind a fetch mock. Every token response
 * mints a fresh pair; `onRefresh` / `onCode` override the refresh / code-exchange
 * answer per test. A code
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
      id_token: hub.idToken
    });
  };
  const hub = {
    calls,
    expiresIn: 3600,
    idToken: ID_TOKEN,
    challenge: undefined as string | undefined,
    onRefresh: undefined as undefined | ((form: URLSearchParams) => Promise<Response> | Response),
    onCode: undefined as undefined | (() => Promise<Response> | Response),
    refreshes: () => calls.filter((call) => call.form.get('grant_type') === 'refresh_token'),
    revokes: () => calls.filter((call) => call.path === '/oauth/revoke'),
    fetchImpl: (async (url: string, init: RequestInit) => {
      const path = new URL(url).pathname;
      const form = new URLSearchParams(String(init.body));
      calls.push({ path, form, auth: String((init.headers as Record<string, string>).Authorization) });
      if (path === '/oauth/revoke') return new Response(null, { status: 200 });
      if (form.get('grant_type') === 'refresh_token' && hub.onRefresh) return hub.onRefresh(form);
      if (form.get('grant_type') === 'authorization_code' && hub.onCode) return hub.onCode();
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

const okResponse = (): HttpResponse => ({
  status: 200,
  statusText: 'OK',
  durationMs: 1,
  attempts: 1,
  data: {}
});

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

/** Runs `fn` with stderr captured; returns what was written. */
async function captureStderr(fn: () => Promise<unknown>): Promise<string> {
  const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
  try {
    await fn();
    return stderr.mock.calls.map(([line]) => String(line)).join('');
  } finally {
    stderr.mockRestore();
  }
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

/** Hub's answer to an expired or revoked bearer token (OauthBearerAuthentication). */
function tokenRejected(): XyteHttpError {
  return new XyteHttpError(401, 'Unauthorized', {}, 'k', 'Bearer error="invalid_token"');
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
    expect(out.html).toContain('https://client.test');
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
    // The flow is over, so its cookie goes too.
    expect(out.cookies[consent.cookie.split('=')[0]!]?.options.maxAge).toBe(0);
  });

  it('expires flow cookies whose flow is gone when a new /authorize starts', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const live = await openConsent(provider, client);
    const { out, res } = fakeRes();
    (res as unknown as { req: Request }).req = fakeReq({
      cookie: `${live.cookie}; __Host-xmcp_gone=v; other=1`
    });

    await provider.authorize(client, { codeChallenge: 'c', redirectUri: REDIRECT }, res);
    expect(out.cookies['__Host-xmcp_gone']?.options.maxAge).toBe(0);
    expect(out.cookies[live.cookie.split('=')[0]!]).toBeUndefined();
    expect(out.cookies.other).toBeUndefined();
  });

  it('answers 503 instead of parking more than 10 000 pending sign-ins', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const start = () => {
      const { out, res } = fakeRes();
      return provider
        .authorize(client, { codeChallenge: 'c', redirectUri: REDIRECT }, res)
        .then(() => out.status);
    };
    for (let i = 0; i < 10_000; i += 1) await start();

    expect(await start()).toBe(503);
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

  it('callback without, or with the wrong, browser cookie issues nothing', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);

    const missing = await approve(provider, client);
    expect((await callback(provider, { state: missing.pending, code: 'c' })).status).toBe(400);

    const wrong = await approve(provider, client);
    const forged = `${wrong.cookie.split('=')[0]}=attacker-value`;
    const out = await callback(provider, { state: wrong.pending, code: 'c' }, forged);
    expect(out.status).toBe(400);
    expect(out.location).toBe('');
    expect(hub.calls).toHaveLength(0);
  });

  // The state is in hub's URL (history, logs): knowing it must not cancel a login.
  it('a cookieless callback leaves the login for its own browser to finish', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const { pending, cookie } = await approve(provider, client);

    expect((await callback(provider, { state: pending, code: 'c' })).status).toBe(400);
    const out = await callback(provider, { state: pending, code: 'hub-code' }, cookie);
    expect(new URL(out.location).searchParams.get('code')).toMatch(/^xmcp_ac_/);
    // ...once: the replay is refused.
    expect((await callback(provider, { state: pending, code: 'hub-code' }, cookie)).status).toBe(400);
  });

  it('refuses a callback for a consent that was never approved, even with its cookie', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { pending, cookie } = await openConsent(provider, client);

    const out = await callback(provider, { state: pending, code: 'c' }, cookie);
    expect(out.status).toBe(400);
    expect(out.location).toBe('');
    expect(hub.calls).toHaveLength(0);
  });

  it.each([
    ['a refused code exchange', (hub: ReturnType<typeof fakeHub>) => (hub.challenge = 'other')],
    [
      'an id_token without xyte_tenant_id',
      (hub: ReturnType<typeof fakeHub>) =>
        (hub.idToken = `h.${Buffer.from(JSON.stringify({ sub: 'user-1' })).toString('base64url')}.s`)
    ],
    [
      'an id_token that is not JSON',
      (hub: ReturnType<typeof fakeHub>) =>
        (hub.idToken = `h.${Buffer.from('not-json-user@example.com').toString('base64url')}.s`)
    ],
    [
      'a 5xx from the code exchange',
      (hub: ReturnType<typeof fakeHub>) =>
        (hub.onCode = () => json(502, { error: 'server_error', detail: 'user@example.com' }))
    ],
    [
      'an unreadable 200 from the code exchange',
      (hub: ReturnType<typeof fakeHub>) =>
        (hub.onCode = () => new Response('<html>user@example.com</html>', { status: 200 }))
    ],
    [
      'a code exchange timeout',
      (hub: ReturnType<typeof fakeHub>) =>
        (hub.onCode = () => Promise.reject(new DOMException('slow', 'TimeoutError')))
    ],
    [
      'a code exchange network error',
      (hub: ReturnType<typeof fakeHub>) =>
        (hub.onCode = () => Promise.reject(new TypeError('fetch failed')))
    ]
  ])('%s sends server_error with the state back to the client, no code', async (_name, breakHub) => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { pending, cookie } = await approve(provider, client);
    breakHub(hub);

    let out!: Awaited<ReturnType<typeof callback>>;
    const stderr = await captureStderr(async () => {
      out = await callback(provider, { state: pending, code: 'hub-code' }, cookie);
    });
    expect(out.status).toBe(302);
    const url = new URL(out.location);
    expect(url.origin + url.pathname).toBe(REDIRECT);
    expect(url.searchParams.get('error')).toBe('server_error');
    expect(url.searchParams.get('state')).toBe('st4te');
    expect(url.searchParams.get('code')).toBeNull();
    // The log names the failure without quoting what hub sent.
    expect(stderr).toContain('hub sign-in failed');
    expect(stderr).not.toContain('user@example.com');
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
    // The error ended the login: a later code on the same state mints nothing.
    expect((await callback(provider, { state: pending, code: 'hub-code' }, cookie)).status).toBe(400);
    expect(hub.calls).toHaveLength(0);
  });

  it('a callback with neither code nor error sends server_error, asking hub nothing', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { pending, cookie } = await approve(provider, client);

    let out!: Awaited<ReturnType<typeof callback>>;
    await captureStderr(async () => {
      out = await callback(provider, { state: pending }, cookie);
    });
    const url = new URL(out.location);
    expect(url.searchParams.get('error')).toBe('server_error');
    expect(url.searchParams.get('state')).toBe('st4te');
    expect(hub.calls).toHaveLength(0);
  });

  it('refuses an unknown or an expired state, asking hub nothing', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);

    const unknown = await callback(provider, { state: 'no-such-state', code: 'c' }, '__Host-xmcp_no-such-state=v');
    expect(unknown.status).toBe(400);
    expect(unknown.cookies['__Host-xmcp_no-such-state']?.options.maxAge).toBe(0);

    const { pending, cookie } = await approve(provider, client);
    vi.useFakeTimers({ now: Date.now() + 11 * 60 * 1000 });
    try {
      const expired = await callback(provider, { state: pending, code: 'hub-code' }, cookie);
      expect(expired.status).toBe(400);
      expect(expired.location).toBe('');
    } finally {
      vi.useRealTimers();
    }
    expect(hub.calls).toHaveLength(0);
  });

  it('names a custom-scheme redirect by its whole URI on the consent page', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const { out, res } = fakeRes();
    await provider.authorize(client, { codeChallenge: 'c', redirectUri: 'cursor:/oauth/cb' }, res);
    expect(out.html).toContain('<strong>cursor:/oauth/cb</strong>');
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

  it('lets only one of two concurrent exchanges of a code or refresh token mint', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const { code } = await signIn(provider, client);
    const codeRuns = await Promise.allSettled([
      provider.exchangeAuthorizationCode(client, code),
      provider.exchangeAuthorizationCode(client, code)
    ]);
    expect(codeRuns.map((run) => run.status).sort()).toEqual(['fulfilled', 'rejected']);

    const tokens = (codeRuns.find((run) => run.status === 'fulfilled') as PromiseFulfilledResult<
      Awaited<ReturnType<typeof provider.exchangeAuthorizationCode>>
    >)!.value;
    const refreshRuns = await Promise.allSettled([
      provider.exchangeRefreshToken(client, tokens.refresh_token!),
      provider.exchangeRefreshToken(client, tokens.refresh_token!)
    ]);
    expect(refreshRuns.map((run) => run.status).sort()).toEqual(['fulfilled', 'rejected']);
  });

  it('refuses a refresh token presented by another client, which leaves it usable', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const other = await registeredClient(provider, 'client-2');
    const { tokens } = await connected(provider, client);

    await expect(provider.exchangeRefreshToken(other, tokens.refresh_token!)).rejects.toThrow(
      /invalid or expired/
    );
    await expect(provider.exchangeRefreshToken(client, tokens.refresh_token!)).resolves.toBeTruthy();
  });

  it('checks the RFC 8707 resource on both exchanges', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const ours = new URL(`${ISSUER}/mcp`);
    const theirs = new URL('https://other.test/mcp');

    const { code } = await signIn(provider, client);
    await expect(
      provider.exchangeAuthorizationCode(client, code, undefined, undefined, theirs)
    ).rejects.toThrow(/resource/);
    const tokens = await provider.exchangeAuthorizationCode(client, code, undefined, undefined, ours);

    await expect(
      provider.exchangeRefreshToken(client, tokens.refresh_token!, undefined, theirs)
    ).rejects.toThrow(/resource/);
    await expect(
      provider.exchangeRefreshToken(client, tokens.refresh_token!, undefined, ours)
    ).resolves.toBeTruthy();
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

  it('expires codes after 10 minutes and refresh tokens after 30 days', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const { code } = await signIn(provider, client);
    const { tokens } = await connected(provider, client);
    const start = Date.now();
    try {
      vi.useFakeTimers({ now: start + 11 * 60 * 1000 });
      await expect(provider.challengeForAuthorizationCode(client, code)).rejects.toThrow(/expired/);
      await expect(provider.exchangeAuthorizationCode(client, code)).rejects.toThrow(/expired/);
      vi.setSystemTime(start + 31 * 24 * 60 * 60 * 1000);
      await expect(provider.exchangeRefreshToken(client, tokens.refresh_token!)).rejects.toThrow(
        /expired/
      );
    } finally {
      vi.useRealTimers();
    }
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

  it('adds every hub token it sends, a refreshed one too, to the secrets to redact', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    const upstream = stubHttp((request) =>
      request.headers.Authorization === 'Bearer xoat_1' ? tokenRejected() : { data: {} }
    );
    const secrets = ['xoat_1'];

    await provider
      .hubHttp(grantId, upstream, secrets)
      .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });
    expect(secrets).toEqual(['xoat_1', 'xoat_2']);
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

  it('a hub 401 without invalid_token (record not in the org) is returned unchanged, no refresh', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    const notAuthorized = new XyteHttpError(401, 'Unauthorized', { error: 'Not authorized' }, 'k');
    const upstream = stubHttp(() => notAuthorized);

    await expect(
      provider
        .hubHttp(grantId, upstream)
        .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
    ).rejects.toBe(notAuthorized);
    expect(hub.refreshes()).toHaveLength(0);
    expect(upstream.calls).toHaveLength(1);
  });

  it('on a hub 401 with invalid_token, refreshes once and retries once', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    const upstream = stubHttp((request) =>
      request.headers.Authorization === 'Bearer xoat_1'
        ? tokenRejected()
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

  it('a retry rejected again with invalid_token fails the call: no second refresh, no loop', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    const rejected = tokenRejected();
    const upstream = stubHttp(() => rejected);

    await expect(
      provider
        .hubHttp(grantId, upstream)
        .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
    ).rejects.toBe(rejected);
    expect(hub.refreshes()).toHaveLength(1);
    expect(upstream.calls.map((call) => call.headers.Authorization)).toEqual([
      'Bearer xoat_1',
      'Bearer xoat_2'
    ]);
  });

  it.each([
    ['invalid_grant', () => json(400, { error: 'invalid_grant' })],
    ['a 5xx', () => json(503, { error: 'temporarily_unavailable' })]
  ])('N parallel calls during a refresh that ends in %s all fail on its one refresh', async (_name, answer) => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    hub.onRefresh = answer;
    const upstream = upstreamOk();
    const http = provider.hubHttp(grantId, upstream);

    let runs!: PromiseSettledResult<unknown>[];
    await captureStderr(async () => {
      runs = await Promise.allSettled(
        Array.from({ length: 8 }, () =>
          http.request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
        )
      );
    });
    expect(runs.map((run) => run.status === 'rejected' && (run.reason as XyteError).kind)).toEqual(
      Array(8).fill('auth')
    );
    expect(hub.refreshes()).toHaveLength(1);
    expect(upstream.calls).toHaveLength(0);
  });

  // A call that read xoat_1 before another call's refresh landed must not burn
  // xort_2 with a second refresh: the stored token is already fresh.
  it('a stale token rejected after a finished refresh reuses its result, no second refresh', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const slow: HttpRequest[] = [];
    const slowUpstream: HttpClient = {
      request: async (request) => {
        slow.push(request);
        if (request.headers.Authorization !== 'Bearer xoat_1') return okResponse();
        await gate;
        throw tokenRejected();
      }
    };
    const request = { method: 'GET' as const, url: `${HUB}/x`, headers: {}, endpointKey: 'k' };

    const stale = provider.hubHttp(grantId, slowUpstream).request(request);
    await vi.waitFor(() => expect(slow).toHaveLength(1));
    const rejectsXoat1 = stubHttp((sent) =>
      sent.headers.Authorization === 'Bearer xoat_1' ? tokenRejected() : { data: {} }
    );
    await provider.hubHttp(grantId, rejectsXoat1).request(request);
    expect(hub.refreshes()).toHaveLength(1);

    release();
    await stale;
    expect(hub.refreshes()).toHaveLength(1);
    expect(slow.map((call) => call.headers.Authorization)).toEqual([
      'Bearer xoat_1',
      'Bearer xoat_2'
    ]);
  });

  it('a lost compare-and-set on save logs, keeps the stored pair and still serves the call', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    hub.expiresIn = 3600;
    vi.spyOn(store, 'rotateHubTokens').mockResolvedValueOnce(false);
    const upstream = upstreamOk();

    const stderr = await captureStderr(() =>
      provider
        .hubHttp(grantId, upstream)
        .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
    );
    expect(stderr).toContain(`grant ${grantId}: stored hub tokens changed during refresh; not overwritten`);
    expect((await store.getGrant(grantId))?.hub?.refreshToken).toBe('xort_1');
    expect(upstream.calls[0]!.headers.Authorization).toBe('Bearer xoat_2');
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
        ? tokenRejected()
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

  // Hub may have rotated (and burned xort_1) before the answer was lost; a
  // later replay would end the user's sign-in at hub, so the grant ends here.
  it.each([
    ['a timeout', () => Promise.reject(new DOMException('slow', 'TimeoutError'))],
    ['a network error', () => Promise.reject(new TypeError('fetch failed'))],
    ['a 5xx', () => json(503, { error: 'temporarily_unavailable' })],
    ['an unreadable 200', () => new Response('<html>', { status: 200 })]
  ])('%s on refresh ends the grant and never re-sends the refresh token', async (_name, answer) => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    hub.onRefresh = answer as () => Promise<Response>;
    const get = () =>
      provider
        .hubHttp(grantId, upstreamOk())
        .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });

    await expect(get()).rejects.toMatchObject({ kind: 'auth' });
    await expect(get()).rejects.toMatchObject({ kind: 'auth' });
    expect(hub.refreshes()).toHaveLength(1);
    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(/invalid/);
  });

  it('a plain 4xx on refresh (nothing rotated) fails the call and keeps the grant', async () => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    hub.onRefresh = () => json(401, { error: 'invalid_client' });

    const call = provider
      .hubHttp(grantId, upstreamOk())
      .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });
    await expect(call).rejects.toBeInstanceOf(XyteError);
    await expect(call).rejects.toMatchObject({
      kind: 'auth',
      message: expect.stringMatching(/refresh failed: 401/)
    });
    expect(hub.refreshes()).toHaveLength(1);
    await expect(provider.verifyAccessToken(tokens.access_token)).resolves.toBeTruthy();
  });
});

describe('XyteOAuthProvider: drain on shutdown', () => {
  it('waits for an in-flight hub refresh and saves its pair', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    let answer!: () => void;
    hub.onRefresh = () =>
      new Promise<Response>((resolve) => {
        answer = () =>
          resolve(json(200, { access_token: 'xoat_2', refresh_token: 'xort_2', expires_in: 3600 }));
      });
    const call = provider
      .hubHttp(grantId, stubHttp(() => ({ data: {} })))
      .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });
    await vi.waitFor(() => expect(hub.refreshes()).toHaveLength(1));

    let drained = false;
    const drain = provider.drain().then(() => (drained = true));
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(drained).toBe(false); // still waiting on hub

    answer();
    await Promise.all([call, drain]);
    expect((await store.getGrant(grantId))?.hub?.refreshToken).toBe('xort_2');
  });

  it('saves a rotated pair that was only held in memory', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    hub.expiresIn = 3600;
    const save = vi.spyOn(store, 'rotateHubTokens').mockRejectedValue(new Error('db down'));
    await provider
      .hubHttp(grantId, stubHttp(() => ({ data: {} })))
      .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });
    expect((await store.getGrant(grantId))?.hub?.refreshToken).toBe('xort_1');

    save.mockRestore();
    await provider.drain();
    expect((await store.getGrant(grantId))?.hub?.refreshToken).toBe('xort_2');
    expect(hub.refreshes()).toHaveLength(1); // saved, not refreshed again
  });

  it('says the pair is lost when the store is still down at shutdown', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    hub.expiresIn = 3600;
    vi.spyOn(store, 'rotateHubTokens').mockRejectedValue(new Error('db down'));
    await provider
      .hubHttp(grantId, stubHttp(() => ({ data: {} })))
      .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });

    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    try {
      await provider.drain();
      expect(stderr.mock.calls.map(([line]) => String(line)).join('')).toContain(
        `grant ${grantId}: rotated hub tokens lost at shutdown`
      );
    } finally {
      stderr.mockRestore();
    }
  });

  it('starts no hub refresh once draining: the call fails retryably, hub is never asked', async () => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);

    await provider.drain();
    const call = provider
      .hubHttp(grantId, stubHttp(() => ({ data: {} })))
      .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });
    await expect(call).rejects.toMatchObject({ kind: 'network' });
    expect(hub.refreshes()).toHaveLength(0);
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

  it('an abandoned sibling grant (no live tokens) does not block the hub revoke', async () => {
    const { provider, store, hub } = makeProvider();
    const client = await registeredClient(provider);
    const first = await connected(provider, client);
    const abandoned = await connected(provider, client);
    await store.deleteToken(abandoned.tokens.access_token, 'access');
    await store.deleteToken(abandoned.tokens.refresh_token!, 'refresh');

    await provider.revokeToken(client, { token: first.tokens.access_token });

    expect(hub.revokes()).toHaveLength(1);
    expect((await store.getGrant(first.grantId))?.hub).toBeUndefined(); // hub tokens dropped
  });

  it('a revoke during an in-flight hub refresh revokes the rotated token at hub', async () => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    hub.expiresIn = 3600;
    let answer!: () => void;
    hub.onRefresh = () =>
      new Promise<Response>((resolve) => {
        answer = () =>
          resolve(
            json(200, { access_token: 'xoat_2', refresh_token: 'xort_2', expires_in: 3600 })
          );
      });
    const call = provider
      .hubHttp(grantId, stubHttp(() => ({ data: {} })))
      .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });
    await vi.waitFor(() => expect(hub.refreshes()).toHaveLength(1));

    const revoke = provider.revokeToken(client, { token: tokens.access_token });
    await tick();
    expect(hub.revokes()).toEqual([]); // waiting on the refresh, not racing it
    answer();
    await Promise.allSettled([call, revoke]);

    expect(hub.revokes().map((r) => r.form.get('token'))).toEqual(['xort_2']);
    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(/invalid/);
  });

  it('starts no hub refresh on a grant while it is being revoked', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30; // every call wants a refresh
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    // Hold revoke inside its window: after it marks the grant, before it is revoked.
    const getGrant = store.getGrant.bind(store);
    let reads = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    vi.spyOn(store, 'getGrant').mockImplementation(async (id) => {
      reads += 1;
      if (reads === 2) await gate;
      return getGrant(id);
    });

    const revoke = provider.revokeToken(client, { token: tokens.access_token });
    await vi.waitFor(() => expect(reads).toBe(2));
    const call = provider
      .hubHttp(grantId, stubHttp(() => ({ data: {} })))
      .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });
    await expect(call).rejects.toMatchObject({ kind: 'auth' });

    release();
    await revoke;
    expect(hub.refreshes()).toHaveLength(0);
    expect(hub.revokes().map((r) => r.form.get('token'))).toEqual(['xort_1']);
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

describe('XyteOAuthProvider: several organizations on one server', () => {
  const get = { method: 'GET' as const, url: `${HUB}/x`, headers: {}, endpointKey: 'k' };

  /** A whole sign-in whose hub id_token names `sub` in organization `org`. */
  async function connectedAs(
    provider: XyteOAuthProvider,
    client: OAuthClientInformationFull,
    sub: string,
    org: string
  ) {
    currentHub!.idToken = idTokenFor({ sub, xyte_tenant_id: org });
    return connected(provider, client);
  }

  /** What one of our access tokens makes hub see, from verify to the hub call. */
  async function hubBearerFor(
    provider: XyteOAuthProvider,
    accessToken: string,
    upstream = stubHttp(() => ({ data: {} }))
  ) {
    const { grantId } = hubIdentityOf(await provider.verifyAccessToken(accessToken));
    await provider.hubHttp(grantId, upstream).request(get);
    return upstream.calls.at(-1)!.headers.Authorization;
  }

  it("each token reaches hub only with its own organization's hub token, across refreshes", async () => {
    const { provider, store, hub } = makeProvider();
    const client = await registeredClient(provider);
    const a = await connectedAs(provider, client, 'user-a', 'org-a');
    const b = await connectedAs(provider, client, 'user-b', 'org-b');
    expect((await store.getGrant(a.grantId))?.hub).toMatchObject({ tenantId: 'org-a', accessToken: 'xoat_1' });
    expect((await store.getGrant(b.grantId))?.hub).toMatchObject({ tenantId: 'org-b', accessToken: 'xoat_2' });

    expect(await hubBearerFor(provider, a.tokens.access_token)).toBe('Bearer xoat_1');
    expect(await hubBearerFor(provider, b.tokens.access_token)).toBe('Bearer xoat_2');

    // Hub rejects A's token: A refreshes with A's refresh token; B is untouched.
    const rejectsA = stubHttp((request) =>
      request.headers.Authorization === 'Bearer xoat_1' ? tokenRejected() : { data: {} }
    );
    expect(await hubBearerFor(provider, a.tokens.access_token, rejectsA)).toBe('Bearer xoat_3');
    expect(hub.refreshes().map((call) => call.form.get('refresh_token'))).toEqual(['xort_1']);
    expect(await hubBearerFor(provider, b.tokens.access_token)).toBe('Bearer xoat_2');
    expect((await store.getGrant(b.grantId))?.hub?.refreshToken).toBe('xort_2');

    // Our own token refresh keeps each connection on its own grant.
    const a2 = await provider.exchangeRefreshToken(client, a.tokens.refresh_token!);
    const b2 = await provider.exchangeRefreshToken(client, b.tokens.refresh_token!);
    expect(await hubBearerFor(provider, a2.access_token)).toBe('Bearer xoat_3');
    expect(await hubBearerFor(provider, b2.access_token)).toBe('Bearer xoat_2');
  });

  it('a dead hub refresh chain on one organization leaves the same user on another working', async () => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30; // both start inside the refresh window
    const client = await registeredClient(provider);
    const a = await connectedAs(provider, client, 'user-a', 'org-a');
    const b = await connectedAs(provider, client, 'user-a', 'org-b');
    hub.onRefresh = (form) =>
      form.get('refresh_token') === 'xort_1'
        ? json(400, { error: 'invalid_grant' })
        : json(200, { access_token: 'xoat_b', refresh_token: 'xort_b', expires_in: 3600 });
    const upstreamB = stubHttp(() => ({ data: {} }));

    // In parallel: the per-grant single-flight must not hand one grant's outcome to the other.
    const [runA, runB] = await Promise.allSettled([
      provider.hubHttp(a.grantId, stubHttp(() => ({ data: {} }))).request(get),
      provider.hubHttp(b.grantId, upstreamB).request(get)
    ]);
    expect(runA).toMatchObject({ status: 'rejected', reason: { kind: 'auth' } });
    expect(runB.status).toBe('fulfilled');
    expect(upstreamB.calls[0]!.headers.Authorization).toBe('Bearer xoat_b');
    expect(hub.refreshes().map((call) => call.form.get('refresh_token')).sort()).toEqual([
      'xort_1',
      'xort_2'
    ]);
    await expect(provider.verifyAccessToken(a.tokens.access_token)).rejects.toThrow(/invalid/);
    await expect(provider.verifyAccessToken(b.tokens.access_token)).resolves.toBeTruthy();
  });

  it('revoking one connection revokes it at hub: another org or another user is no sibling', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const a = await connectedAs(provider, client, 'user-a', 'org-a');
    const sameUserOtherOrg = await connectedAs(provider, client, 'user-a', 'org-b');
    const otherUserSameOrg = await connectedAs(provider, client, 'user-b', 'org-a');

    await provider.revokeToken(client, { token: a.tokens.access_token });

    expect(hub.revokes().map((call) => call.form.get('token'))).toEqual(['xort_1']);
    await expect(provider.verifyAccessToken(a.tokens.access_token)).rejects.toThrow(/invalid/);
    expect(await hubBearerFor(provider, sameUserOtherOrg.tokens.access_token)).toBe('Bearer xoat_2');
    expect(await hubBearerFor(provider, otherUserSameOrg.tokens.access_token)).toBe('Bearer xoat_3');
    await expect(
      provider.exchangeRefreshToken(client, otherUserSameOrg.tokens.refresh_token!)
    ).resolves.toBeTruthy();
  });
});
