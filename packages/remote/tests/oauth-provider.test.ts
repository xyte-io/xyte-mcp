import { randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Request, Response as ExpressResponse } from 'express';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { HttpClient, HttpRequest, HttpResponse } from '@xyteai/mcp/http/client.js';
import { APPLICATION_PAUSED_HINT, XyteError, XyteHttpError } from '@xyteai/mcp/http/errors.js';
import { TemporarilyUnavailableError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { createHubOAuth } from '../src/oauth/hub-oauth.js';
import { hubIdentityOf, XyteOAuthProvider } from '../src/oauth/provider.js';
import { PgOAuthStore } from '../src/oauth/pg-store.js';
import { MemoryOAuthStore, type OAuthStore } from '../src/oauth/store.js';
import { TokenCipher } from '../src/oauth/token-cipher.js';
import { stubHttp } from '../../mcp/tests/support/context.js';
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
    revokeStatus: 200,
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
      if (path === '/oauth/revoke') return new Response(null, { status: hub.revokeStatus });
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

/**
 * The grant lock's connection or commit fails once, after its holder ran: what
 * it wrote rolls back (here: its save writes nothing), and the provider saves
 * the new pair outside the lock (saveHubTokens).
 */
function failGrantLockCommitOnce(store: OAuthStore): void {
  const withLock = store.withGrantLock.bind(store);
  vi.spyOn(store, 'withGrantLock').mockImplementationOnce((async (
    id: string,
    fn: Parameters<OAuthStore['withGrantLock']>[1]
  ) => {
    await withLock(id, (locked) => fn({ ...locked, rotate: async () => true }));
    throw Object.assign(new Error('connection lost'), { code: '08006' });
  }) as never);
}

function makeProvider(store: OAuthStore = new MemoryOAuthStore(), hub = fakeHub()) {
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

/** Every pending sign-in row in the store, live or not. */
async function pendingRowCount(store: OAuthStore): Promise<number> {
  if (store instanceof MemoryOAuthStore) {
    return (store as unknown as { pendingSignIns: Map<string, unknown> }).pendingSignIns.size;
  }
  const { pool } = store as unknown as { pool: pg.Pool };
  const { rows } = await pool.query<{ n: number }>('SELECT count(*)::int AS n FROM oauth_pending_sign_ins');
  return rows[0]!.n;
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
  const approved = await submitApprove(provider, await openConsent(provider, client));
  // Specs built on this would otherwise pass on a refused Approve.
  expect(approved.out.status).toBe(302);
  expect(approved.cookie).not.toBe('');
  return approved;
}

/** Approve a consent page opened earlier, possibly on another instance. */
async function submitApprove(
  provider: XyteOAuthProvider,
  consent: { pending: string; csrf: string; cookie: string }
) {
  const { out, res } = fakeRes();
  await provider.consent(
    fakeReq({
      body: { pending: consent.pending, csrf: consent.csrf, decision: 'approve' },
      cookie: consent.cookie
    }),
    res
  );
  const [cookieName, cookie] = Object.entries(out.cookies)[0] ?? [];
  if (out.location) currentHub!.challenge = new URL(out.location).searchParams.get('code_challenge') ?? undefined;
  return { out, pending: consent.pending, cookie: cookieName ? `${cookieName}=${cookie!.value}` : '' };
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

  it('says the app acts with the signed-in user\'s own access', async () => {
    const { provider } = makeProvider();
    const { out } = await openConsent(provider, await registeredClient(provider));

    expect(out.html).toContain('your own access');
    expect(out.html).not.toContain('full access');
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

  it('refuses an approve without the browser cookie or with a wrong CSRF token, leaving the sign-in', async () => {
    const { provider, store } = makeProvider();
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
      expect(await store.getPendingSignIn(consent.pending, Math.floor(Date.now() / 1000))).toBeDefined();
      expect((await submitApprove(provider, consent)).out.status).toBe(302);
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
    // ...and a callback on it, even with that cookie, finds nothing.
    const late = await callback(provider, { state: consent.pending, code: 'hub-code' }, consent.cookie);
    expect(late.status).toBe(400);
    expect(late.location).toBe('');
    expect(hub.calls).toHaveLength(0);
  });

  it('refuses an Approve once the sign-in has expired, asking hub nothing', async () => {
    const { provider, hub } = makeProvider();
    const consent = await openConsent(provider, await registeredClient(provider));
    vi.useFakeTimers({ now: Date.now() + 11 * 60 * 1000 });
    try {
      const { out } = await submitApprove(provider, consent);
      expect(out.status).toBe(400);
      expect(out.html).toContain('Authorization expired or invalid');
      expect(out.location).toBe('');
    } finally {
      vi.useRealTimers();
    }
    expect(hub.calls).toHaveLength(0);
  });

  // Saved for ten minutes from an unauthenticated request, so it is bounded.
  it('refuses an /authorize whose state is over 1024 characters, saving nothing', async () => {
    const { provider, store } = makeProvider();
    const client = await registeredClient(provider);
    const create = vi.spyOn(store, 'createPendingSignIn');
    const start = async (state: string) => {
      const { out, res } = fakeRes();
      await provider.authorize(client, { codeChallenge: 'c', redirectUri: REDIRECT, state }, res);
      return out;
    };

    const long = await start('x'.repeat(1025));
    expect(long.status).toBe(400);
    expect(long.location).toBe('');
    expect(long.cookies).toEqual({});
    expect(create).not.toHaveBeenCalled();
    expect((await start('x'.repeat(1024))).status).toBe(200);
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

  it('still serves the consent page when the flow-cookie lookup fails, keeping the old cookies', async () => {
    const { provider, store } = makeProvider();
    const client = await registeredClient(provider);
    vi.spyOn(store, 'livePendingSignInIds').mockRejectedValueOnce(
      Object.assign(new Error('connect ECONNREFUSED db.internal:5432'), { code: 'ECONNREFUSED' })
    );
    const { out, res } = fakeRes();
    (res as unknown as { req: Request }).req = fakeReq({ cookie: '__Host-xmcp_gone=v' });

    const stderr = await captureStderr(() =>
      provider.authorize(client, { codeChallenge: 'c', redirectUri: REDIRECT }, res)
    );
    expect(out.status).toBe(200);
    expect(out.html).toContain('name="pending"');
    expect(out.cookies['__Host-xmcp_gone']).toBeUndefined();
    expect(stderr).toContain('ECONNREFUSED');
    expect(stderr).not.toContain('db.internal');
    expect(eventsIn(stderr)).toEqual([]);
  });

  it('logs a store failure on /authorize and rethrows it for the SDK to redirect', async () => {
    const { provider, store } = makeProvider();
    const client = await registeredClient(provider);
    vi.spyOn(store, 'createPendingSignIn').mockRejectedValueOnce(
      Object.assign(new Error('connect ECONNREFUSED db.internal:5432'), { code: 'ECONNREFUSED' })
    );
    const { out, res } = fakeRes();

    let thrown: unknown;
    const stderr = await captureStderr(() =>
      provider
        .authorize(client, { codeChallenge: 'c', redirectUri: REDIRECT }, res)
        .catch((error: unknown) => (thrown = error))
    );
    expect(thrown).toBeInstanceOf(Error);
    expect(out.cookies).toEqual({});
    expect(stderr).toContain('ECONNREFUSED');
    expect(stderr).not.toContain('db.internal');
    expect(eventsIn(stderr)).toEqual([
      { event: 'sign_in', outcome: 'failed', reason: 'store', client: 'client-1' }
    ]);
  });

  it('answers 503 instead of parking more than 10 000 pending sign-ins', async () => {
    const { provider, store } = makeProvider();
    const client = await registeredClient(provider);
    const start = async () => {
      const { out, res } = fakeRes();
      await provider.authorize(client, { codeChallenge: 'c', redirectUri: REDIRECT }, res);
      return out;
    };
    for (let i = 0; i < 10_000; i += 1) await start();

    const out = await start();
    expect(out.status).toBe(503);
    expect(out.html).toContain('Too many sign-ins in progress');
    expect(await pendingRowCount(store)).toBe(10_000);
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
    const { provider, store, hub } = makeProvider();
    const client = await registeredClient(provider);

    const missing = await approve(provider, client);
    expect((await callback(provider, { state: missing.pending, code: 'c' })).status).toBe(400);

    const wrong = await approve(provider, client);
    const forged = `${wrong.cookie.split('=')[0]}=attacker-value`;
    const out = await callback(provider, { state: wrong.pending, code: 'c' }, forged);
    expect(out.status).toBe(400);
    expect(out.location).toBe('');
    expect(hub.calls).toHaveLength(0);

    // ...and leaves the sign-in for its own browser to finish.
    expect(await store.getPendingSignIn(wrong.pending, Math.floor(Date.now() / 1000))).toBeDefined();
    const real = await callback(provider, { state: wrong.pending, code: 'hub-code' }, wrong.cookie);
    expect(new URL(real.location).searchParams.get('code')).toMatch(/^xmcp_ac_/);
  });

  // The state is in hub's URL (history, logs): knowing it must not cancel a login.
  it('a cookieless callback leaves the login for its own browser to finish', async () => {
    const { provider, store } = makeProvider();
    const client = await registeredClient(provider);
    const { pending, cookie } = await approve(provider, client);

    expect((await callback(provider, { state: pending, code: 'c' })).status).toBe(400);
    expect(await store.getPendingSignIn(pending, Math.floor(Date.now() / 1000))).toBeDefined();
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

  it('a paused application on the code exchange sends temporarily_unavailable with a try-later message', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { pending, cookie } = await approve(provider, client);
    hub.onCode = () => json(403, { error: 'application_paused', error_code: 'application_paused' });

    const stderr = await captureStderr(async () => {
      const out = await callback(provider, { state: pending, code: 'hub-code' }, cookie);
      const url = new URL(out.location);
      expect(url.origin + url.pathname).toBe(REDIRECT);
      expect(url.searchParams.get('error')).toBe('temporarily_unavailable');
      expect(url.searchParams.get('error_description')).toBe(
        'Xyte has paused this connection for now. Try signing in again later.'
      );
      expect(url.searchParams.get('state')).toBe('st4te');
      expect(url.searchParams.get('code')).toBeNull();
    });
    expect(stderr).toContain('hub sign-in failed: hub code exchange failed: 403 application_paused');
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

const PG_URL = process.env.TEST_DATABASE_URL;
const KEY_A = randomBytes(32);
const KEY_B = randomBytes(32);

/** A Postgres schema of its own, so oauth-store.test.ts's truncates never meet these rows. */
async function pgSchema() {
  const schema = `provider_test_${randomUUID().replaceAll('-', '')}`;
  const admin = new pg.Pool({ connectionString: PG_URL, max: 1 });
  await admin.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(PG_URL!);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const stores: PgOAuthStore[] = [];
  return {
    connect: async (key: Buffer) => {
      const store = await PgOAuthStore.connect(url.toString(), new TokenCipher(key), 15_000);
      stores.push(store);
      return store;
    },
    drop: async () => {
      await Promise.all(stores.map((store) => store.close().catch(() => undefined)));
      await admin.query(`DROP SCHEMA ${schema} CASCADE`);
      await admin.end();
    }
  };
}

/**
 * Two stores on one database, as two server instances have. The memory pair is
 * one shared store: only the Postgres pair proves cross-instance behaviour.
 */
const storePairs: Array<[string, () => Promise<{ stores: [OAuthStore, OAuthStore]; drop(): Promise<void> }>]> = [
  [
    'memory, one shared store',
    async () => {
      const store = new MemoryOAuthStore();
      return { stores: [store, store], drop: async () => {} };
    }
  ]
];
if (PG_URL) {
  storePairs.push([
    'postgres',
    async () => {
      const db = await pgSchema();
      return { stores: [await db.connect(KEY_A), await db.connect(KEY_A)], drop: db.drop };
    }
  ]);
}

describe.each(storePairs)('XyteOAuthProvider: a sign-in across instances (%s)', (_name, makeStores) => {
  let pair: Awaited<ReturnType<typeof makeStores>>;
  let instances: [XyteOAuthProvider, XyteOAuthProvider];
  let hub: ReturnType<typeof fakeHub>;
  beforeEach(async () => {
    vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    pair = await makeStores();
    hub = fakeHub();
    instances = [makeProvider(pair.stores[0], hub).provider, makeProvider(pair.stores[1], hub).provider];
  });
  afterEach(async () => {
    await pair.drop();
    vi.restoreAllMocks();
  });

  it.each([
    [0, 1, 0],
    [1, 0, 1],
    [0, 0, 1],
    [0, 1, 1]
  ])('authorize on %i, consent on %i, callback on %i mints a working code', async (authorizeOn, consentOn, callbackOn) => {
    const client = await registeredClient(instances[0]);
    const consent = await openConsent(instances[authorizeOn]!, client);
    const approved = await submitApprove(instances[consentOn]!, consent);
    expect(approved.out.status).toBe(302);

    const out = await callback(instances[callbackOn]!, { state: consent.pending, code: 'hub-code' }, approved.cookie);
    const code = new URL(out.location).searchParams.get('code')!;
    expect(code).toMatch(/^xmcp_ac_/);
    const tokens = await instances[1 - callbackOn]!.exchangeAuthorizationCode(client, code);
    expect(hubIdentityOf(await instances[authorizeOn]!.verifyAccessToken(tokens.access_token)).accessToken).toBe(
      'xoat_1'
    );
  });

  it('a replayed callback, and two concurrent ones on both instances, mint one code', async () => {
    const client = await registeredClient(instances[0]);
    const { pending, cookie } = await approve(instances[0], client);

    const outs = await Promise.all(
      instances.map((instance) => callback(instance, { state: pending, code: 'hub-code' }, cookie))
    );
    expect(outs.map((out) => out.status).sort()).toEqual([302, 400]);
    expect(outs.filter((out) => out.location.includes('code=xmcp_ac_'))).toHaveLength(1);
    expect((await callback(instances[1], { state: pending, code: 'hub-code' }, cookie)).status).toBe(400);
    expect(hub.calls.filter((call) => call.form.get('grant_type') === 'authorization_code')).toHaveLength(1);
  });

  it('a double-clicked Approve, on either instance, still finishes the sign-in', async () => {
    const client = await registeredClient(instances[0]);
    const consent = await openConsent(instances[0], client);
    const first = await submitApprove(instances[0], consent);
    const second = await submitApprove(instances[1], consent);

    expect([first.out.status, second.out.status]).toEqual([302, 302]);
    expect(second.out.location).toBe(first.out.location);
    expect(second.cookie).toBe(consent.cookie);
    const out = await callback(instances[0], { state: consent.pending, code: 'hub-code' }, second.cookie);
    expect(new URL(out.location).searchParams.get('code')).toMatch(/^xmcp_ac_/);
  });

  it('an Approve whose sign-in is taken between its read and its approve ends on the expired page', async () => {
    const client = await registeredClient(instances[0]);
    const consent = await openConsent(instances[0], client);
    // The other instance takes the row right after this consent has read it.
    const read = pair.stores[1].getPendingSignIn.bind(pair.stores[1]);
    vi.spyOn(pair.stores[1], 'getPendingSignIn').mockImplementationOnce(async (id, now) => {
      const entry = await read(id, now);
      await pair.stores[0].takePendingSignIn(id, now);
      return entry;
    });

    const { out } = await submitApprove(instances[1], consent);
    expect(out.status).toBe(400);
    expect(out.html).toContain('Authorization expired or invalid');
    expect(out.cookies[consent.cookie.split('=')[0]!]?.options.maxAge).toBe(0);
    expect(out.location).toBe('');
    expect(hub.calls).toHaveLength(0);
  });

  it('a Deny whose sign-in is taken between its read and its take ends on the expired page', async () => {
    const client = await registeredClient(instances[0]);
    const consent = await openConsent(instances[0], client);
    const read = pair.stores[1].getPendingSignIn.bind(pair.stores[1]);
    vi.spyOn(pair.stores[1], 'getPendingSignIn').mockImplementationOnce(async (id, now) => {
      const entry = await read(id, now);
      await pair.stores[0].takePendingSignIn(id, now);
      return entry;
    });

    const { out, res } = fakeRes();
    await instances[1].consent(
      fakeReq({ body: { pending: consent.pending, csrf: consent.csrf, decision: 'deny' }, cookie: consent.cookie }),
      res
    );
    expect(out.status).toBe(400);
    expect(out.html).toContain('Authorization expired or invalid');
    expect(out.cookies[consent.cookie.split('=')[0]!]?.options.maxAge).toBe(0);
    expect(out.location).toBe('');
  });

  it('a callback whose sign-in is taken between its read and its take ends on the expired page', async () => {
    const client = await registeredClient(instances[0]);
    const { pending, cookie } = await approve(instances[0], client);
    const read = pair.stores[1].getPendingSignIn.bind(pair.stores[1]);
    vi.spyOn(pair.stores[1], 'getPendingSignIn').mockImplementationOnce(async (id, now) => {
      const entry = await read(id, now);
      await pair.stores[0].takePendingSignIn(id, now);
      return entry;
    });

    const out = await callback(instances[1], { state: pending, code: 'hub-code' }, cookie);
    expect(out.status).toBe(400);
    expect(out.html).toContain('Authorization expired or invalid');
    expect(out.cookies[cookie.split('=')[0]!]?.options.maxAge).toBe(0);
    expect(out.location).toBe('');
    expect(hub.calls).toHaveLength(0);
  });

  it('a wrong-cookie callback on one instance leaves the sign-in for the other to finish', async () => {
    const client = await registeredClient(instances[0]);
    const { pending, cookie } = await approve(instances[0], client);

    const forged = `${cookie.split('=')[0]}=attacker-value`;
    expect((await callback(instances[1], { state: pending, code: 'c' }, forged)).status).toBe(400);
    expect(await pair.stores[0].getPendingSignIn(pending, Math.floor(Date.now() / 1000))).toBeDefined();
    const out = await callback(instances[0], { state: pending, code: 'hub-code' }, cookie);
    expect(new URL(out.location).searchParams.get('code')).toMatch(/^xmcp_ac_/);
  });

  it('a cookieless callback on one instance leaves the sign-in for the other to finish', async () => {
    const client = await registeredClient(instances[0]);
    const { pending, cookie } = await approve(instances[0], client);

    expect((await callback(instances[1], { state: pending, code: 'c' })).status).toBe(400);
    expect(await pair.stores[0].getPendingSignIn(pending, Math.floor(Date.now() / 1000))).toBeDefined();
    const out = await callback(instances[0], { state: pending, code: 'hub-code' }, cookie);
    expect(new URL(out.location).searchParams.get('code')).toMatch(/^xmcp_ac_/);
  });

  it('answers 503 once the store is at its cap', async () => {
    const client = await registeredClient(instances[0]);
    for (const store of new Set(pair.stores)) {
      const create = store.createPendingSignIn.bind(store);
      vi.spyOn(store, 'createPendingSignIn').mockImplementation((id, entry, _max, now) => create(id, entry, 2, now));
    }
    await openConsent(instances[0], client);
    await openConsent(instances[1], client);

    const { out, res } = fakeRes();
    await instances[0].authorize(client, { codeChallenge: 'c', redirectUri: REDIRECT }, res);
    expect(out.status).toBe(503);
    expect(out.html).toContain('Too many sign-ins in progress');
    expect(out.cookies).toEqual({});
    expect(await pendingRowCount(pair.stores[0])).toBe(2);
  });
});

describe.skipIf(!PG_URL)('XyteOAuthProvider: pending sign-ins on Postgres', () => {
  let db: Awaited<ReturnType<typeof pgSchema>>;
  beforeEach(async () => {
    vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    db = await pgSchema();
  });
  afterEach(async () => {
    await db.drop();
    vi.restoreAllMocks();
  });

  // An instance without the key the sign-in was started under (a rotation
  // without XYTE_MCP_TOKEN_KEY_PREVIOUS) cannot read its hub verifier.
  it('a callback on an instance without the key of the hub verifier ends on the expired page, not a 500', async () => {
    const hub = fakeHub();
    const writer = makeProvider(await db.connect(KEY_A), hub).provider;
    const reader = makeProvider(await db.connect(KEY_B), hub).provider;
    const client = await registeredClient(writer);
    const { pending, cookie } = await approve(writer, client);

    const out = await callback(reader, { state: pending, code: 'hub-code' }, cookie);
    expect(out.status).toBe(400);
    expect(out.html).toContain('Authorization expired or invalid');
    expect(out.location).toBe('');
    expect(hub.calls).toHaveLength(0);
    const logged = vi.mocked(process.stderr.write).mock.calls.map(([line]) => String(line)).join('');
    expect(logged).toContain('pending sign-in unreadable: unknown key id');

    // An Approve there reads the same row: the expired page too.
    const approved = await submitApprove(reader, await openConsent(writer, client));
    expect(approved.out.status).toBe(400);
    expect(approved.out.html).toContain('Authorization expired or invalid');
    expect(approved.out.location).toBe('');
  });

  // The SDK's authorize handler turns the rejection into a server_error
  // redirect to the client: a clean error, bounded by the pool's connect
  // timeout.
  it('rejects an /authorize promptly while Postgres is down, setting no cookie', async () => {
    const store = await db.connect(KEY_A);
    const { provider } = makeProvider(store);
    const client = await registeredClient(provider);
    const live = (store as unknown as { pool: pg.Pool }).pool;
    const down = new pg.Pool({ connectionString: 'postgres://127.0.0.1:9/none', connectionTimeoutMillis: 2000 });
    (store as unknown as { pool: pg.Pool }).pool = down;
    try {
      const { out, res } = fakeRes();
      const started = Date.now();
      await expect(
        provider.authorize(client, { codeChallenge: 'c', redirectUri: REDIRECT }, res)
      ).rejects.toThrow();
      expect(Date.now() - started).toBeLessThan(5000);
      expect(out.cookies).toEqual({});
      expect(out.html).toBe('');
    } finally {
      (store as unknown as { pool: pg.Pool }).pool = live;
      await down.end();
    }
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

  // Defensive: the Postgres store revokes an unreadable grant on read, but the `!grant?.hub`
  // check stays, matching liveHub and verifyAccessToken.
  it('refuses a refresh on a grant whose hub tokens are unreadable, like an access check', async () => {
    const { provider, store } = makeProvider();
    const client = await registeredClient(provider);
    const { tokens } = await connected(provider, client);
    const getGrant = store.getGrant.bind(store);
    vi.spyOn(store, 'getGrant').mockImplementation(async (id) => {
      const grant = (await getGrant(id))!;
      delete grant.hub; // a copy: the store hands out snapshots
      return grant;
    });

    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(/invalid or expired/);
    await expect(provider.exchangeRefreshToken(client, tokens.refresh_token!)).rejects.toThrow(
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

  it('a hub 403 application_paused on a call is returned unchanged, no refresh', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    const paused = new XyteHttpError(
      403,
      'Forbidden',
      { error: 'paused', error_code: 'application_paused' },
      'k'
    );
    const upstream = stubHttp(() => paused);

    await expect(
      provider
        .hubHttp(grantId, upstream)
        .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
    ).rejects.toBe(paused);
    expect(hub.refreshes()).toHaveLength(0);
  });

  it.each([
    [403, 'unauthorized_client'],
    [401, 'application_paused']
  ])('a refresh %i %s carries no paused hint', async (status, error) => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    hub.onRefresh = () => json(status, { error });

    await expect(
      provider
        .hubHttp(grantId, upstreamOk())
        .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
    ).rejects.toMatchObject({ kind: 'auth', hints: [] });
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

  // Under the lock the stored pair is the one just read, so a save that matches
  // nothing means the row is inconsistent: fail closed rather than drop the pair.
  it('a save under the lock that matches no stored pair revokes the grant and signs the call out', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    hub.expiresIn = 3600;
    vi.spyOn(store, 'rotateHubTokens').mockResolvedValueOnce(false);
    const upstream = upstreamOk();

    const stderr = await captureStderr(() =>
      expect(
        provider.hubHttp(grantId, upstream).request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
      ).rejects.toThrow(/sign-in behind this connection has ended/)
    );
    expect(upstream.calls).toHaveLength(0);
    expect(eventsIn(stderr)).toContainEqual(
      expect.objectContaining({ event: 'revoke', connection: grantId, reason: 'hub_save_failed' })
    );
    expect(hub.revokes()).toEqual([]);
    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(/invalid/);
  });

  it('a store that is closing fails the refresh as restarting, asking hub nothing', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    vi.spyOn(store, 'withGrantLock').mockRejectedValueOnce(
      new XyteError('network', 'The server is restarting.', ['Retry in a few seconds.'])
    );

    await expect(
      provider.hubHttp(grantId, upstreamOk()).request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
    ).rejects.toMatchObject({ kind: 'network', message: 'The server is restarting.' });
    expect(hub.refreshes()).toHaveLength(0);
    await expect(provider.verifyAccessToken(tokens.access_token)).resolves.toBeTruthy();
  });

  it('a lost compare-and-set on save logs, keeps the stored pair and still serves the call', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    hub.expiresIn = 3600;
    failGrantLockCommitOnce(store);
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

  // Revoked between the refresh and its save (another process, the operator's SQL):
  // the pair hub just minted belongs to nothing, so it is revoked at hub.
  it('revokes the new hub pair at hub when the grant was revoked during the refresh, and fails as signed out', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    hub.expiresIn = 3600;
    failGrantLockCommitOnce(store);
    const rotate = store.rotateHubTokens.bind(store);
    vi.spyOn(store, 'rotateHubTokens').mockImplementationOnce(async (id, previous, next) => {
      await store.revokeGrant(id);
      return rotate(id, previous, next);
    });
    const upstream = upstreamOk();

    const stderr = await captureStderr(() =>
      expect(
        provider
          .hubHttp(grantId, upstream)
          .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
      ).rejects.toThrow(/sign-in behind this connection has ended/)
    );
    expect(hub.revokes().map((r) => r.form.get('token'))).toEqual(['xort_2']);
    expect(upstream.calls).toHaveLength(0);
    expect(stderr).toContain(`grant ${grantId}: revoked during the hub refresh`);
    expect(stderr).not.toContain('xort_2');
    expect(stderr).not.toContain('xoat_2');
  });

  it('keeps a new hub pair a live sibling still rides on: no hub revoke, still signed out', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    // A second connection on the same hub sign-in.
    const { grantId: siblingId } = await connected(provider, client);
    const siblingHub = (await store.getGrant(siblingId))?.hub;
    hub.expiresIn = 3600;
    failGrantLockCommitOnce(store);
    const rotate = store.rotateHubTokens.bind(store);
    vi.spyOn(store, 'rotateHubTokens').mockImplementationOnce(async (id, previous, next) => {
      await store.revokeGrant(id);
      return rotate(id, previous, next);
    });

    const stderr = await captureStderr(() =>
      expect(
        provider
          .hubHttp(grantId, upstreamOk())
          .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
      ).rejects.toMatchObject({ kind: 'auth' })
    );
    expect(hub.revokes()).toEqual([]);
    expect(stderr).toContain(
      `grant ${grantId}: revoked during the hub refresh; revoking the new hub pair unless a live sibling shares the hub sign-in`
    );
    expect(siblingHub).toBeDefined();
    expect((await store.getGrant(siblingId))?.hub).toEqual(siblingHub);
  });

  it('still fails as signed out when the hub revoke of the orphaned pair fails, and logs it', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    hub.expiresIn = 3600;
    hub.revokeStatus = 503;
    failGrantLockCommitOnce(store);
    const rotate = store.rotateHubTokens.bind(store);
    vi.spyOn(store, 'rotateHubTokens').mockImplementationOnce(async (id, previous, next) => {
      await store.revokeGrant(id);
      return rotate(id, previous, next);
    });

    const stderr = await captureStderr(() =>
      expect(
        provider
          .hubHttp(grantId, upstreamOk())
          .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
      ).rejects.toThrow(/sign-in behind this connection has ended/)
    );
    expect(hub.revokes()).toHaveLength(1);
    expect(stderr).toContain('hub revoke failed');
    expect(stderr).not.toContain('xort_2');
  });

  // Whether a sibling still rides the pair is unknown, so hub is not asked to revoke it.
  it.each(['getGrant', 'hasLiveHubSibling'] as const)(
    'after a lost compare-and-set, a failing %s logs and fails as signed out, with no hub revoke',
    async (failing) => {
      const { provider, store, hub } = makeProvider();
      hub.expiresIn = 30;
      const client = await registeredClient(provider);
      const { grantId } = await connected(provider, client);
      hub.expiresIn = 3600;
      failGrantLockCommitOnce(store);
      vi.spyOn(store, 'rotateHubTokens').mockImplementationOnce(async (id) => {
        if (failing === 'hasLiveHubSibling') await store.revokeGrant(id);
        vi.spyOn(store, failing).mockRejectedValueOnce(new Error('db down'));
        return false;
      });

      const stderr = await captureStderr(() =>
        expect(
          provider
            .hubHttp(grantId, upstreamOk())
            .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
        ).rejects.toThrow(/sign-in behind this connection has ended/)
      );
      expect(hub.revokes()).toEqual([]);
      expect(stderr).toContain(
        failing === 'getGrant'
          ? `grant ${grantId}: could not check the grant after a lost hub token save`
          : `grant ${grantId}: sibling check failed after the revoke`
      );
      expect(stderr).not.toContain('xort_2');
      expect(stderr).not.toContain('xoat_2');
    }
  );

  // `unsaved` is this process's only: another one would replay the burned stored
  // token. So when the save fails for good, the grant ends (fail closed).
  it('revokes the grant when saving a rotated hub pair keeps failing: signed out, and no instance refreshes again', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    hub.expiresIn = 3600;
    const save = vi.spyOn(store, 'rotateHubTokens').mockRejectedValue(
      Object.assign(new Error('db down at db.internal'), { code: '57P01' })
    );
    const upstream = upstreamOk();

    const stderr = await captureStderr(() =>
      expect(
        provider.hubHttp(grantId, upstream).request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
      ).rejects.toThrow(/sign-in behind this connection has ended/)
    );
    save.mockRestore();
    expect(upstream.calls).toHaveLength(0); // the new access token is never used
    expect(eventsIn(stderr)).toContainEqual({
      event: 'revoke', connection: grantId, organization: 'org-1', user: 'user-1', reason: 'hub_save_failed'
    });
    expect(stderr).toContain(`grant ${grantId}: could not save rotated hub tokens after 3 attempts (57P01); revoked the grant`);
    expect(stderr).not.toContain('db.internal');
    expect(stderr).not.toContain('xort_2');
    expect(hub.revokes()).toEqual([]); // the new pair expires on its own
    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(/invalid/);

    // Another instance on the same store: nothing left to refresh with.
    const other = new XyteOAuthProvider(
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
    await expect(
      other.hubHttp(grantId, upstreamOk()).request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
    ).rejects.toMatchObject({ kind: 'auth' });
    expect(hub.refreshes()).toHaveLength(1);
  });

  it('keeps a rotated hub pair in memory when saving it and revoking the grant both keep failing, and saves it later', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    hub.expiresIn = 3600;
    const save = vi.spyOn(store, 'rotateHubTokens').mockRejectedValue(new Error('db down'));
    const revoke = vi.spyOn(store, 'revokeGrant').mockRejectedValue(new Error('db down'));
    const http = provider.hubHttp(grantId, upstreamOk());
    const get = () => http.request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });

    const stderr = await captureStderr(get);
    // 3 tries under the lock, then (the revoke under the lock failed too) 3 more after it...
    expect(save).toHaveBeenCalledTimes(6);
    expect(revoke).toHaveBeenCalledTimes(4);
    expect(hub.refreshes()).toHaveLength(1); // ...the hub POST is not
    expect(stderr).toContain('another instance may replay the stored hub token until the save lands');
    expect((await store.getGrant(grantId))?.hub?.refreshToken).toBe('xort_1');

    // Later calls use the unsaved pair instead of refreshing (or replaying xort_1).
    await get();
    expect(hub.refreshes()).toHaveLength(1);

    // The next refresh sends the in-memory token and saves over the stored one.
    save.mockRestore();
    revoke.mockRestore();
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
      message: expect.stringMatching(/refresh failed: 401/),
      hints: []
    });
    expect(hub.refreshes()).toHaveLength(1);
    await expect(provider.verifyAccessToken(tokens.access_token)).resolves.toBeTruthy();
  });

  it('a 403 application_paused on refresh says the connection is paused and keeps the grant', async () => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    const sentBefore = hub.refreshes().length;
    hub.onRefresh = () =>
      json(403, {
        error: 'application_paused',
        error_description: 'This application is temporarily paused. Try again later.'
      });
    const get = () =>
      provider
        .hubHttp(grantId, upstreamOk())
        .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });

    await expect(get()).rejects.toMatchObject({
      kind: 'auth',
      message: 'hub token refresh failed: 403 application_paused',
      hints: [APPLICATION_PAUSED_HINT]
    });
    expect(hub.refreshes()).toHaveLength(sentBefore + 1);
    await expect(provider.verifyAccessToken(tokens.access_token)).resolves.toBeTruthy();

    // Once unpaused, the same refresh token works: the paused answer burned nothing.
    hub.onRefresh = undefined;
    await get();
    expect(hub.refreshes()).toHaveLength(sentBefore + 2);
    const [paused, resumed] = hub
      .refreshes()
      .slice(-2)
      .map((call) => call.form.get('refresh_token'));
    expect(resumed).toBe(paused);
  });

  // A lock wait past lock_timeout, no free connection, a failed BEGIN: nothing reached hub.
  it('fails retryably, keeping the grant and asking hub nothing, when the grant lock cannot be taken', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    vi.spyOn(store, 'withGrantLock').mockRejectedValueOnce(
      Object.assign(new Error('canceling statement due to lock timeout'), { code: '55P03' })
    );

    const stderr = await captureStderr(() =>
      expect(
        provider
          .hubHttp(grantId, upstreamOk())
          .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
      ).rejects.toMatchObject({
        kind: 'network',
        message: 'This Xyte sign-in is busy: another request is refreshing it, or the server is busy.'
      })
    );
    expect(stderr).toContain(`grant ${grantId}: grant lock transaction failed for a hub refresh (55P03)`);
    expect(hub.refreshes()).toHaveLength(0);
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
    const revoke = vi.spyOn(store, 'revokeGrant').mockRejectedValue(new Error('db down'));
    await captureStderr(() =>
      provider
        .hubHttp(grantId, stubHttp(() => ({ data: {} })))
        .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
    );
    expect((await store.getGrant(grantId))?.hub?.refreshToken).toBe('xort_1');

    save.mockRestore();
    revoke.mockRestore();
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
    vi.spyOn(store, 'revokeGrant').mockRejectedValue(new Error('db down'));
    await captureStderr(() =>
      provider
        .hubHttp(grantId, stubHttp(() => ({ data: {} })))
        .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
    );

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

  it('revokes, and does not report as lost, a held pair whose last save at shutdown fails while the revoke lands', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    hub.expiresIn = 3600;
    vi.spyOn(store, 'rotateHubTokens').mockRejectedValue(new Error('db down'));
    const revoke = vi.spyOn(store, 'revokeGrant').mockRejectedValue(new Error('db down'));
    await captureStderr(() =>
      provider
        .hubHttp(grantId, stubHttp(() => ({ data: {} })))
        .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' })
    );

    revoke.mockRestore(); // the save still fails at shutdown, the revoke lands
    const stderr = await captureStderr(() => provider.drain());
    vi.restoreAllMocks();
    expect(stderr).not.toContain('lost at shutdown');
    expect(eventsIn(stderr)).toContainEqual(expect.objectContaining({ event: 'revoke', reason: 'hub_save_failed' }));
    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(/invalid/);
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

// A flight queued on the grant lock (another process refreshing) must not reach hub
// after drain started: its POST could outlast the shutdown deadline.
describe('XyteOAuthProvider: drain while a refresh waits on the grant lock', () => {
  it('drain does not wait for it, and it sends nothing once it gets the lock: the call fails retryably, the grant is kept', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    let release!: () => void;
    const holder = store.withGrantLock(grantId, () => new Promise<void>((resolve) => (release = resolve)));

    const call = provider
      .hubHttp(grantId, stubHttp(() => ({ data: {} })))
      .request({ method: 'GET', url: `${HUB}/x`, headers: {}, endpointKey: 'k' });
    call.catch(() => undefined);
    await tick();
    // drain() does not wait for a flight still queued on the lock: it sends nothing.
    await provider.drain();
    release();
    await holder;

    await expect(call).rejects.toMatchObject({ kind: 'network', message: 'The server is restarting.' });
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
    await Promise.all([call, revoke]); // both succeed: the call with the new pair, then the revoke

    expect(hub.revokes().map((r) => r.form.get('token'))).toEqual(['xort_2']);
    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(/invalid/);
  });

  it('starts no hub refresh on a grant while it is being revoked', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30; // every call wants a refresh
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    // Hold revoke inside the grant lock, before it revokes.
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
    await vi.waitFor(() => expect(reads).toBe(3)); // the call's read, before it queues on the lock

    release();
    await revoke;
    await expect(call).rejects.toMatchObject({ kind: 'auth' });
    expect(hub.refreshes()).toHaveLength(0);
    expect(hub.revokes().map((r) => r.form.get('token'))).toEqual(['xort_1']);
  });

  // A disconnect with an expired token: still a revoke until a cleanup run deletes the token.
  it('revoking with an expired token revokes its grant before a cleanup run, and nothing after one', async () => {
    const { provider, store } = makeProvider();
    const client = await registeredClient(provider);
    const before = await connected(provider, client);
    const after = await connected(provider, client);
    const now = Math.floor(Date.now() / 1000);
    await store.saveToken({ token: 'expired-before', kind: 'refresh', grantId: before.grantId, expiresAt: now - 1 });
    await store.saveToken({ token: 'expired-after', kind: 'refresh', grantId: after.grantId, expiresAt: now - 1 });

    await provider.revokeToken(client, { token: 'expired-before' });
    expect((await store.getGrant(before.grantId))?.revoked).toBe(true);

    await store.sweepExpiredOAuthRows(now);
    await provider.revokeToken(client, { token: 'expired-after' });
    expect((await store.getGrant(after.grantId))?.revoked).toBe(false);
  });

  it('logs and fails a revoke that cannot take the grant lock', async () => {
    const { provider, store, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    vi.spyOn(store, 'withGrantLock').mockRejectedValueOnce(
      Object.assign(new Error('canceling statement due to lock timeout'), { code: '55P03' })
    );
    const stderr = await captureStderr(() =>
      expect(provider.revokeToken(client, { token: tokens.access_token })).rejects.toMatchObject({ code: '55P03' })
    );
    expect(stderr).toContain(`grant ${grantId}: grant lock transaction failed for a revoke (55P03)`);
    expect(eventsIn(stderr)).toEqual([]);
    await expect(provider.verifyAccessToken(tokens.access_token)).resolves.toBeTruthy();
    expect(hub.revokes()).toEqual([]);
  });

  // An OAuth error the SDK answers with 400 temporarily_unavailable, not a 500.
  it('answers a revoke while the store is closing as temporarily unavailable', async () => {
    const { provider, store } = makeProvider();
    const client = await registeredClient(provider);
    const { tokens } = await connected(provider, client);
    vi.spyOn(store, 'withGrantLock').mockRejectedValueOnce(
      new XyteError('network', 'The server is restarting.', ['Retry in a few seconds.'])
    );
    await expect(provider.revokeToken(client, { token: tokens.access_token })).rejects.toBeInstanceOf(
      TemporarilyUnavailableError
    );
    await expect(provider.verifyAccessToken(tokens.access_token)).resolves.toBeTruthy();
  });

  // The revoke has committed: what is left is best effort, and the client is answered.
  it('a failing sibling check after the revoke is logged, skips the hub revoke, and the revoke succeeds', async () => {
    const { provider, store, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    vi.spyOn(store, 'hasLiveHubSibling').mockRejectedValueOnce(
      Object.assign(new Error('db down'), { code: '57P01' })
    );
    const stderr = await captureStderr(() => provider.revokeToken(client, { token: tokens.access_token }));
    expect(stderr).toContain(`grant ${grantId}: sibling check failed after the revoke (57P01); not revoking at hub`);
    expect(hub.revokes()).toEqual([]);
    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(/invalid/);
  });

  it('a hub revoke that throws after the revoke is logged, and the revoke succeeds', async () => {
    const { provider, store } = makeProvider();
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    const hubOAuth = (provider as unknown as { hub: { revoke(token: string): Promise<void> } }).hub;
    vi.spyOn(hubOAuth, 'revoke').mockRejectedValueOnce(new TypeError('fetch failed'));
    const stderr = await captureStderr(() => provider.revokeToken(client, { token: tokens.access_token }));
    expect(stderr).toContain(`grant ${grantId}: hub revoke failed (TypeError)`);
    expect((await store.getGrant(grantId))?.revoked).toBe(true);
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

/** The JSON event lines in captured stderr, in order. */
function eventsIn(stderr: string): Array<Record<string, unknown>> {
  return stderr
    .split('\n')
    .filter((line) => line.startsWith('{'))
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

describe('XyteOAuthProvider: log events', () => {
  const get = { method: 'GET' as const, url: `${HUB}/x`, headers: {}, endpointKey: 'k' };

  it('logs sign_in ok with the connection, organization and user — never a token or email', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    let grantId = '';
    const stderr = await captureStderr(async () => {
      ({ grantId } = await connected(provider, client));
    });
    expect(eventsIn(stderr)).toEqual([
      { event: 'sign_in', outcome: 'ok', connection: grantId, organization: 'org-1', user: 'user-1' }
    ]);
    expect(stderr).not.toContain('xoat_');
    expect(stderr).not.toContain('user@example.com');
  });

  it('logs sign_in denied for access_denied and for Deny on our consent page, failed for another hub error or a broken exchange', async () => {
    const { provider, hub } = makeProvider();
    const client = await registeredClient(provider);
    const stderr = await captureStderr(async () => {
      const denied = await approve(provider, client);
      await callback(provider, { state: denied.pending, error: 'access_denied' }, denied.cookie);

      const hubError = await approve(provider, client);
      await callback(provider, { state: hubError.pending, error: 'server_error' }, hubError.cookie);

      const consent = await openConsent(provider, client);
      await provider.consent(
        fakeReq({
          body: { pending: consent.pending, csrf: consent.csrf, decision: 'deny' },
          cookie: consent.cookie
        }),
        fakeRes().res
      );

      const failed = await approve(provider, client);
      hub.onCode = () => json(502, {});
      await callback(provider, { state: failed.pending, code: 'hub-code' }, failed.cookie);
    });
    expect(eventsIn(stderr)).toEqual([
      { event: 'sign_in', outcome: 'denied', client: 'client-1' },
      { event: 'sign_in', outcome: 'failed', reason: 'hub_error', client: 'client-1' },
      { event: 'sign_in', outcome: 'denied', client: 'client-1' },
      { event: 'sign_in', outcome: 'failed', reason: 'exchange', client: 'client-1' }
    ]);
  });

  it('logs sign_in failed for a sign-in that ends on the expired page', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const stderr = await captureStderr(async () => {
      // Consent: unknown pending id, wrong CSRF token, wrong browser cookie.
      await provider.consent(fakeReq({ body: { pending: 'gone', csrf: 'x', decision: 'approve' } }), fakeRes().res);
      const badCsrf = await openConsent(provider, client);
      await provider.consent(
        fakeReq({ body: { pending: badCsrf.pending, csrf: 'wrong', decision: 'approve' }, cookie: badCsrf.cookie }),
        fakeRes().res
      );
      await provider.consent(
        fakeReq({ body: { pending: badCsrf.pending, csrf: badCsrf.csrf, decision: 'approve' } }),
        fakeRes().res
      );

      // Callback: unknown state, wrong browser cookie, never approved.
      await callback(provider, { state: 'gone', code: 'hub-code' });
      const approved = await approve(provider, client);
      await callback(provider, { state: approved.pending, code: 'hub-code' });
      const unapproved = await openConsent(provider, client);
      await callback(provider, { state: unapproved.pending, code: 'hub-code' }, unapproved.cookie);
    });
    expect(eventsIn(stderr)).toEqual([
      { event: 'sign_in', outcome: 'failed', reason: 'expired' },
      { event: 'sign_in', outcome: 'failed', reason: 'csrf', client: 'client-1' },
      { event: 'sign_in', outcome: 'failed', reason: 'cookie', client: 'client-1' },
      { event: 'sign_in', outcome: 'failed', reason: 'expired' },
      { event: 'sign_in', outcome: 'failed', reason: 'cookie', client: 'client-1' },
      { event: 'sign_in', outcome: 'failed', reason: 'not_approved', client: 'client-1' }
    ]);
  });

  it('logs hub_refresh ok', async () => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    const stderr = await captureStderr(() =>
      provider.hubHttp(grantId, stubHttp(() => ({ data: {} }))).request(get)
    );
    expect(eventsIn(stderr)).toEqual([
      { event: 'hub_refresh', connection: grantId, organization: 'org-1', user: 'user-1', outcome: 'ok' }
    ]);
  });

  it('a hub 429 on refresh keeps the grant and logs rate_limited with the status', async () => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    hub.onRefresh = () => json(429, { error: 'rate_limited' });
    const stderr = await captureStderr(() =>
      expect(provider.hubHttp(grantId, stubHttp(() => ({ data: {} }))).request(get)).rejects.toMatchObject({
        kind: 'auth'
      })
    );
    expect(eventsIn(stderr)).toEqual([
      { event: 'hub_refresh', connection: grantId, organization: 'org-1', user: 'user-1', outcome: 'rate_limited', hub_status: 429 }
    ]);
    await expect(provider.verifyAccessToken(tokens.access_token)).resolves.toBeTruthy();
  });

  it('a plain 4xx on refresh logs rejected with the status', async () => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    hub.onRefresh = () => json(401, { error: 'invalid_client' });
    const stderr = await captureStderr(() =>
      provider.hubHttp(grantId, stubHttp(() => ({ data: {} }))).request(get).catch(() => undefined)
    );
    expect(eventsIn(stderr)).toEqual([
      { event: 'hub_refresh', connection: grantId, organization: 'org-1', user: 'user-1', outcome: 'rejected', hub_status: 401 }
    ]);
  });

  it('invalid_grant on refresh logs hub_refresh invalid_grant, then revoke invalid_grant', async () => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    hub.onRefresh = () => json(400, { error: 'invalid_grant' });
    const stderr = await captureStderr(() =>
      provider.hubHttp(grantId, stubHttp(() => ({ data: {} }))).request(get).catch(() => undefined)
    );
    expect(eventsIn(stderr)).toEqual([
      { event: 'hub_refresh', connection: grantId, organization: 'org-1', user: 'user-1', outcome: 'invalid_grant', hub_status: 400 },
      { event: 'revoke', connection: grantId, reason: 'invalid_grant', organization: 'org-1', user: 'user-1' }
    ]);
  });

  it('an unknown refresh outcome logs hub_refresh unknown (with a 5xx status), then revoke refresh_unknown', async () => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    hub.onRefresh = () => json(503, {});
    const stderr = await captureStderr(() =>
      provider.hubHttp(grantId, stubHttp(() => ({ data: {} }))).request(get).catch(() => undefined)
    );
    expect(eventsIn(stderr)).toEqual([
      { event: 'hub_refresh', connection: grantId, organization: 'org-1', user: 'user-1', outcome: 'unknown', hub_status: 503 },
      { event: 'revoke', connection: grantId, reason: 'refresh_unknown', organization: 'org-1', user: 'user-1' }
    ]);
  });

  it('a refresh timeout logs hub_refresh unknown without a status', async () => {
    const { provider, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId } = await connected(provider, client);
    hub.onRefresh = () => Promise.reject(new DOMException('slow', 'TimeoutError'));
    const stderr = await captureStderr(() =>
      provider.hubHttp(grantId, stubHttp(() => ({ data: {} }))).request(get).catch(() => undefined)
    );
    expect(eventsIn(stderr)).toEqual([
      { event: 'hub_refresh', connection: grantId, organization: 'org-1', user: 'user-1', outcome: 'unknown' },
      { event: 'revoke', connection: grantId, reason: 'refresh_unknown', organization: 'org-1', user: 'user-1' }
    ]);
  });

  it('a client revoke logs revoke client with the organization and user', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    const stderr = await captureStderr(() =>
      provider.revokeToken(client, { token: tokens.access_token })
    );
    expect(eventsIn(stderr)).toEqual([
      { event: 'revoke', connection: grantId, reason: 'client', organization: 'org-1', user: 'user-1' }
    ]);
  });

  // Ended by someone else after the revoke's own check: that one logged and revoked it.
  it('a client revoke of a grant ended before it took the lock logs nothing and revokes nothing at hub', async () => {
    const { provider, store, hub } = makeProvider();
    const client = await registeredClient(provider);
    const { tokens } = await connected(provider, client);
    const getGrant = store.getGrant.bind(store);
    vi.spyOn(store, 'getGrant').mockImplementationOnce(async (id) => {
      const grant = await getGrant(id);
      await store.revokeGrant(id);
      return grant;
    });
    const stderr = await captureStderr(() =>
      provider.revokeToken(client, { token: tokens.access_token })
    );
    expect(eventsIn(stderr)).toEqual([]);
    expect(hub.revokes()).toEqual([]);
  });

  it('a client revoke while the current hub pair is held only in memory revokes that pair at hub', async () => {
    const { provider, store, hub } = makeProvider();
    hub.expiresIn = 30;
    const client = await registeredClient(provider);
    const { grantId, tokens } = await connected(provider, client);
    hub.expiresIn = 3600;
    const save = vi.spyOn(store, 'rotateHubTokens').mockRejectedValue(new Error('db down'));
    const revoke = vi.spyOn(store, 'revokeGrant').mockRejectedValue(new Error('db down'));
    await captureStderr(() =>
      provider.hubHttp(grantId, stubHttp(() => ({ data: {} }))).request(get)
    );
    save.mockRestore();
    revoke.mockRestore();
    expect((await store.getGrant(grantId))?.hub?.refreshToken).toBe('xort_1'); // xort_2 only in memory

    await captureStderr(() => provider.revokeToken(client, { token: tokens.access_token }));
    expect(hub.revokes().map((r) => r.form.get('token'))).toEqual(['xort_2']);
  });
});
