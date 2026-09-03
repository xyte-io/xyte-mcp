import { describe, expect, it, vi } from 'vitest';
import type { Response } from 'express';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { HubUserCredential } from '../src/config.js';
import { hubCredentialOf, XyteOAuthProvider } from '../src/oauth/provider.js';
import { MemoryOAuthStore } from '../src/oauth/store.js';

const ISSUER = 'https://mcp.test';
const REDIRECT = 'https://client.test/callback';
const HUB_USER: HubUserCredential = {
  accessToken: 'hub-at',
  client: 'hub-client',
  uid: 'user@example.com',
  tenant: 'tenant-1'
};

function makeProvider(options: { signInOk?: boolean } = {}) {
  const store = new MemoryOAuthStore();
  const signIn = vi.fn(async () => ((options.signInOk ?? true) ? HUB_USER : undefined));
  const provider = new XyteOAuthProvider(store, signIn, ISSUER);
  return { provider, store, signIn };
}

async function registeredClient(provider: XyteOAuthProvider): Promise<OAuthClientInformationFull> {
  // The SDK's DCR handler mints ids before calling registerClient; mimic that.
  return provider.clientsStore.registerClient!({
    client_id: 'client-1',
    client_id_issued_at: 1,
    client_name: 'Test Client',
    redirect_uris: [REDIRECT],
    token_endpoint_auth_method: 'none'
  } as OAuthClientInformationFull) as Promise<OAuthClientInformationFull>;
}

/** Run the login and pull the code out of the redirect. */
async function loginForCode(
  provider: XyteOAuthProvider,
  client: OAuthClientInformationFull,
  overrides: Record<string, string> = {}
): Promise<{ code: string; state: string | null }> {
  const result = await provider.completeLogin({
    email: 'user@example.com',
    password: 'pw',
    client_id: client.client_id,
    redirect_uri: REDIRECT,
    code_challenge: 'challenge-1',
    state: 'st4te',
    ...overrides
  });
  if (!('redirectTo' in result)) throw new Error(`login did not redirect: ${result.html}`);
  const url = new URL(result.redirectTo);
  return { code: url.searchParams.get('code')!, state: url.searchParams.get('state') };
}

describe('XyteOAuthProvider', () => {
  it('registers and retrieves clients through the store', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);

    expect(await provider.clientsStore.getClient(client.client_id)).toMatchObject({
      client_id: client.client_id,
      redirect_uris: [REDIRECT]
    });
  });

  it('renders a login form that replays the OAuth parameters as hidden fields', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    let html = '';
    const res = {
      status: () => res,
      type: () => res,
      send: (body: string) => {
        html = body;
        return res;
      }
    } as unknown as Response;

    await provider.authorize(
      client,
      { codeChallenge: 'challenge-1', redirectUri: REDIRECT, state: 'st4te' },
      res
    );

    expect(html).toContain('action="/login"');
    for (const [name, value] of [
      ['client_id', client.client_id],
      ['redirect_uri', REDIRECT],
      ['code_challenge', 'challenge-1'],
      ['state', 'st4te']
    ]) {
      expect(html).toContain(`name="${name}" value="${value}"`);
    }
  });

  it('escapes markup in form-controlled values', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const result = await provider.completeLogin({
      client_id: client.client_id,
      redirect_uri: REDIRECT,
      code_challenge: 'c',
      state: '"><script>alert(1)</script>',
      email: '',
      password: ''
    });

    expect('html' in result && result.html).not.toContain('<script>alert');
  });

  it('completes a login and redirects with code and state', async () => {
    const { provider, signIn } = makeProvider();
    const client = await registeredClient(provider);

    const { code, state } = await loginForCode(provider, client);

    expect(signIn).toHaveBeenCalledWith('user@example.com', 'pw');
    expect(code).toMatch(/^xmcp_ac_/);
    expect(state).toBe('st4te');
  });

  it('rejects a login replay with an unregistered redirect_uri', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const result = await provider.completeLogin({
      email: 'user@example.com',
      password: 'pw',
      client_id: client.client_id,
      redirect_uri: 'https://evil.test/steal',
      code_challenge: 'c'
    });

    expect('html' in result && result.status).toBe(400);
  });

  it('re-renders the form on wrong credentials, without minting a code', async () => {
    const { provider } = makeProvider({ signInOk: false });
    const client = await registeredClient(provider);
    const result = await provider.completeLogin({
      email: 'user@example.com',
      password: 'wrong',
      client_id: client.client_id,
      redirect_uri: REDIRECT,
      code_challenge: 'c'
    });

    expect('html' in result && result.status).toBe(401);
    expect('html' in result && result.html).toContain('Wrong email or password');
  });

  it('exchanges a code once, returning our own tokens with the hub credential behind them', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const { code } = await loginForCode(provider, client);

    expect(await provider.challengeForAuthorizationCode(client, code)).toBe('challenge-1');
    const tokens = await provider.exchangeAuthorizationCode(client, code, undefined, REDIRECT);
    expect(tokens.access_token).toMatch(/^xmcp_at_/);
    expect(tokens.refresh_token).toMatch(/^xmcp_rt_/);

    const info = await provider.verifyAccessToken(tokens.access_token);
    expect(hubCredentialOf(info)).toEqual(HUB_USER);
    // None of our tokens are the hub's token.
    expect([tokens.access_token, tokens.refresh_token]).not.toContain(HUB_USER.accessToken);

    // Single-use: the same code again must fail.
    await expect(provider.exchangeAuthorizationCode(client, code)).rejects.toThrow(/invalid/);
  });

  it('refuses a code issued to another client', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const other = (await provider.clientsStore.registerClient!({
      client_id: 'client-2',
      client_id_issued_at: 1,
      redirect_uris: [REDIRECT],
      token_endpoint_auth_method: 'none'
    } as OAuthClientInformationFull)) as OAuthClientInformationFull;
    const { code } = await loginForCode(provider, client);

    await expect(provider.exchangeAuthorizationCode(other, code)).rejects.toThrow(/another client/);
  });

  it('refuses an exchange with a mismatched redirect_uri', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const { code } = await loginForCode(provider, client);

    await expect(
      provider.exchangeAuthorizationCode(client, code, undefined, 'https://client.test/other')
    ).rejects.toThrow(/redirect_uri/);
  });

  it('rotates refresh tokens and kills the old one', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const { code } = await loginForCode(provider, client);
    const first = await provider.exchangeAuthorizationCode(client, code);

    const second = await provider.exchangeRefreshToken(client, first.refresh_token!);
    expect(second.access_token).not.toBe(first.access_token);
    await expect(provider.verifyAccessToken(second.access_token)).resolves.toBeTruthy();

    await expect(provider.exchangeRefreshToken(client, first.refresh_token!)).rejects.toThrow(
      /invalid or expired/
    );
  });

  it('revoking any token revokes the whole grant', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const { code } = await loginForCode(provider, client);
    const tokens = await provider.exchangeAuthorizationCode(client, code);

    await provider.revokeToken(client, { token: tokens.refresh_token! });

    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(/invalid/);
    await expect(provider.exchangeRefreshToken(client, tokens.refresh_token!)).rejects.toThrow(
      /invalid/
    );
  });

  it("revoking another client's token is a silent no-op", async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);
    const other = (await provider.clientsStore.registerClient!({
      client_id: 'client-2',
      client_id_issued_at: 1,
      redirect_uris: [REDIRECT],
      token_endpoint_auth_method: 'none'
    } as OAuthClientInformationFull)) as OAuthClientInformationFull;
    const { code } = await loginForCode(provider, client);
    const tokens = await provider.exchangeAuthorizationCode(client, code);

    await provider.revokeToken(other, { token: tokens.access_token });

    await expect(provider.verifyAccessToken(tokens.access_token)).resolves.toBeTruthy();
  });

  it('expires access tokens', async () => {
    vi.useFakeTimers();
    try {
      const { provider } = makeProvider();
      const client = await registeredClient(provider);
      const { code } = await loginForCode(provider, client);
      const tokens = await provider.exchangeAuthorizationCode(client, code);

      vi.advanceTimersByTime(61 * 60 * 1000);
      await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(/expired/);
    } finally {
      vi.useRealTimers();
    }
  });

  it('binds tokens to this server as the resource and refuses another audience', async () => {
    const { provider } = makeProvider();
    const client = await registeredClient(provider);

    const foreign = await provider.completeLogin({
      email: 'user@example.com',
      password: 'pw',
      client_id: client.client_id,
      redirect_uri: REDIRECT,
      code_challenge: 'c',
      resource: 'https://other-server.test/mcp'
    });
    expect('html' in foreign && foreign.status).toBe(400);

    const { code } = await loginForCode(provider, client, { resource: `${ISSUER}/mcp` });
    await expect(
      provider.exchangeAuthorizationCode(
        client,
        code,
        undefined,
        undefined,
        new URL('https://other-server.test/mcp')
      )
    ).rejects.toThrow(/resource/);
  });
});

describe('XyteOAuthProvider with Descope login', () => {
  function makeDescopeProvider(options: { exchangeOk?: boolean } = {}) {
    const store = new MemoryOAuthStore();
    const signIn = vi.fn(async () => HUB_USER);
    const exchange = vi.fn(async () => ((options.exchangeOk ?? true) ? HUB_USER : undefined));
    const authorizeRedirect = vi.fn(
      ({ state, codeChallenge }: { state: string; codeChallenge: string }) =>
        `https://descope.test/authorize?state=${state}&code_challenge=${codeChallenge}`
    );
    const provider = new XyteOAuthProvider(store, signIn, ISSUER, { authorizeRedirect, exchange });
    return { provider, store, exchange, authorizeRedirect };
  }

  function fakeRes() {
    const redirects: string[] = [];
    return {
      redirects,
      res: { redirect: (url: string) => void redirects.push(url) } as unknown as Response
    };
  }

  async function startAuthorize(provider: XyteOAuthProvider, client: OAuthClientInformationFull) {
    const { redirects, res } = fakeRes();
    await provider.authorize(
      client,
      {
        redirectUri: REDIRECT,
        codeChallenge: 'client-challenge',
        state: 'client-state',
        resource: new URL(`${ISSUER}/mcp`)
      } as Parameters<XyteOAuthProvider['authorize']>[1],
      res
    );
    const url = new URL(redirects[0]!);
    return { descopeState: url.searchParams.get('state')!, url };
  }

  it('redirects /authorize to Descope with a fresh PKCE challenge', async () => {
    const { provider, authorizeRedirect } = makeDescopeProvider();
    const client = await registeredClient(provider);
    const { url } = await startAuthorize(provider, client);

    expect(url.origin).toBe('https://descope.test');
    expect(authorizeRedirect).toHaveBeenCalledOnce();
    const challenge = url.searchParams.get('code_challenge')!;
    // Our own challenge toward Descope, not the MCP client's.
    expect(challenge).not.toBe('client-challenge');
    expect(challenge.length).toBeGreaterThan(20);
  });

  it('callback mints a code for the original client, bound to its challenge and state', async () => {
    const { provider, store, exchange } = makeDescopeProvider();
    const client = await registeredClient(provider);
    const { descopeState } = await startAuthorize(provider, client);

    const result = await provider.completeDescopeCallback(descopeState, 'descope-code');
    if (!('redirectTo' in result)) throw new Error(result.html);
    const url = new URL(result.redirectTo);
    expect(url.origin + url.pathname).toBe(REDIRECT);
    expect(url.searchParams.get('state')).toBe('client-state');
    expect(exchange).toHaveBeenCalledWith('descope-code', expect.any(String));

    const code = url.searchParams.get('code')!;
    const record = await store.getToken(code, 'code');
    expect(record?.codeChallenge).toBe('client-challenge');
    const grant = await store.getGrant(record!.grantId);
    expect(grant?.hub).toEqual(HUB_USER);
  });

  it('rejects a replayed or unknown callback state', async () => {
    const { provider } = makeDescopeProvider();
    const client = await registeredClient(provider);
    const { descopeState } = await startAuthorize(provider, client);

    const first = await provider.completeDescopeCallback(descopeState, 'descope-code');
    expect('redirectTo' in first).toBe(true);
    const replay = await provider.completeDescopeCallback(descopeState, 'descope-code');
    expect(replay).toMatchObject({ status: 400 });
    const unknown = await provider.completeDescopeCallback('never-issued', 'descope-code');
    expect(unknown).toMatchObject({ status: 400 });
  });

  it('a refused hub login yields 401 and no code', async () => {
    const { provider } = makeDescopeProvider({ exchangeOk: false });
    const client = await registeredClient(provider);
    const { descopeState } = await startAuthorize(provider, client);

    const result = await provider.completeDescopeCallback(descopeState, 'descope-code');
    expect(result).toMatchObject({ status: 401 });
  });
});
