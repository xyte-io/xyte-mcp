import { spawn, type ChildProcess } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { hubAcceptsPkce } from './support/pkce.js';
import { existsSync, readFileSync } from 'node:fs';
import {
  createServer,
  request as httpRequest,
  type IncomingMessage,
  type Server,
  type ServerResponse
} from 'node:http';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

/**
 * The whole OAuth dance against a real `--http` child process, with a fake hub
 * behind it: discovery → dynamic registration → /authorize consent page →
 * approve → hub /oauth/authorize → callback → code → /token with PKCE → an
 * authenticated MCP tool call that reaches the hub under the grant's hub
 * token → revocation, at hub too. One sequential suite,
 * because each step consumes the previous one's output — exactly like a real
 * client.
 */

const DIST_ENTRY = path.resolve(import.meta.dirname, '..', 'dist', 'index.js');
/** Well-formed, long enough, and no token of ours. */
const JUNK_TOKEN = 'xmcp_junk_token_0123456789abcdef';
const ORG_KEY = 'org-key-abcdef123456';
const VERSION = (
  JSON.parse(readFileSync(path.resolve(import.meta.dirname, '..', 'package.json'), 'utf8')) as {
    version: string;
  }
).version;
const ID_TOKEN = `h.${Buffer.from(
  JSON.stringify({ sub: 'user-1', xyte_tenant_id: 'org-1', email: 'user@example.com' })
).toString('base64url')}.s`;
const MCP_HEADERS = {
  'Content-Type': 'application/json',
  Accept: 'application/json, text/event-stream'
};

async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address() as { port: number };
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

/** Hub token lifetime the fake hub hands out; a test sets it inside the refresh window. */
let hubExpiresIn = 3600;
/** While set, the fake hub parks refresh requests here instead of answering. */
let heldRefreshes: Array<() => void> | undefined;

/** Just enough hub: OAuth token + revoke, plus one org API read that echoes headers. */
function fakeHub(): { server: Server; requests: Array<Record<string, unknown>> } {
  const requests: Array<Record<string, unknown>> = [];
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let body = '';
    req.on('data', (chunk: string) => (body += chunk));
    req.on('end', () => {
      requests.push({ method: req.method, url: req.url, headers: { ...req.headers }, body });
      if (req.method === 'POST' && req.url === '/oauth/token') {
        const tokenForm = new URLSearchParams(body);
        if (
          tokenForm.get('grant_type') === 'authorization_code' &&
          !hubAcceptsPkce(tokenForm.get('code_verifier'), hubChallenge)
        ) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid_grant' }));
          return;
        }
        const answer = () => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              access_token: 'xoat_1',
              refresh_token: 'xort_1',
              expires_in: hubExpiresIn,
              token_type: 'Bearer',
              id_token: ID_TOKEN
            })
          );
        };
        if (tokenForm.get('grant_type') === 'refresh_token' && heldRefreshes) {
          heldRefreshes.push(answer);
        } else {
          answer();
        }
        return;
      }
      if (req.method === 'POST' && req.url === '/oauth/revoke') {
        res.writeHead(200);
        res.end();
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ devices: [] }));
    });
  });
  return { server, requests };
}

let child: ChildProcess | undefined;
/** The challenge on the last hub authorize redirect; the fake hub checks verifiers against it. */
let hubChallenge: string | undefined;
let base = '';
let hub: ReturnType<typeof fakeHub>;
const stderr: string[] = [];

beforeAll(async () => {
  if (!existsSync(DIST_ENTRY)) {
    throw new Error(`Build first: ${DIST_ENTRY} is missing (npm run build).`);
  }
  hub = fakeHub();
  const hubPort = await freePort();
  await new Promise<void>((resolve) => hub.server.listen(hubPort, '127.0.0.1', resolve));

  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, [DIST_ENTRY, '--http'], {
    env: {
      ...process.env,
      PORT: String(port),
      XYTE_MCP_ISSUER_URL: base,
      XYTE_MCP_HUB_OAUTH_CLIENT_ID: 'mcp-client',
      XYTE_MCP_HUB_OAUTH_CLIENT_SECRET: 'mcp-secret',
      XYTE_ORG_API_KEY: ORG_KEY,
      XYTE_HUB_URL: `http://127.0.0.1:${hubPort}`,
      XYTE_MCP_READ_ONLY: '1',
      DATABASE_URL: ''
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stderr?.setEncoding('utf8');
  child.stderr?.on('data', (chunk: string) => stderr.push(chunk));

  const deadline = Date.now() + 10_000;
  for (;;) {
    if (child.exitCode !== null) throw new Error(`server exited\n${stderr.join('')}`);
    try {
      if ((await fetch(`${base}/healthz`)).ok) break;
    } catch {
      // Not listening yet.
    }
    if (Date.now() > deadline) throw new Error(`server never became ready\n${stderr.join('')}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}, 20_000);

afterAll(async () => {
  child?.kill('SIGKILL');
  await new Promise<void>((resolve) => hub.server.close(() => resolve()));
});

function form(fields: Record<string, string>): string {
  return new URLSearchParams(fields).toString();
}

async function mcp(token: string | null, body: unknown): Promise<Response> {
  return fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { ...MCP_HEADERS, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body)
  });
}

/** `name=value` of the first Set-Cookie, as a browser would send it back. */
function cookieOf(response: Response): string {
  return response.headers.getSetCookie()[0]!.split(';')[0]!;
}

function authorizeUrl(): URL {
  const url = new URL(`${base}/authorize`);
  url.search = form({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: 'st4te'
  });
  return url;
}

/** GET /authorize, then Approve; returns hub's state and the browser cookie. */
async function approve(): Promise<{ hubUrl: URL; cookie: string }> {
  const page = await fetch(authorizeUrl());
  const html = await page.text();
  const field = (name: string) => new RegExp(`name="${name}" value="([^"]+)"`).exec(html)![1]!;
  const response = await fetch(`${base}/oauth/consent`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookieOf(page) },
    body: form({ pending: field('pending'), csrf: field('csrf'), decision: 'approve' })
  });
  expect(response.status).toBe(302);
  const hubUrl = new URL(response.headers.get('location')!);
  hubChallenge = hubUrl.searchParams.get('code_challenge') ?? undefined;
  return { hubUrl, cookie: cookieOf(response) };
}

// State threaded through the sequential dance.
const verifier = randomBytes(32).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');
let clientId = '';
let code = '';
let accessToken = '';
let refreshToken = '';
const REDIRECT = 'http://127.0.0.1:9/callback';

describe('oauth over http, in order', () => {
  it('serves authorization-server and protected-resource metadata', async () => {
    const as = (await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json()) as {
      issuer: string;
      registration_endpoint?: string;
      code_challenge_methods_supported: string[];
    };
    expect(as.issuer).toBe(`${base}/`);
    expect(as.registration_endpoint).toBe(`${base}/register`);
    expect(as.code_challenge_methods_supported).toContain('S256');

    const rs = (await (
      await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)
    ).json()) as { resource: string; authorization_servers: string[] };
    expect(rs.resource).toBe(`${base}/mcp`);
  });

  it('401s an unauthenticated /mcp call WITH a WWW-Authenticate challenge', async () => {
    const response = await mcp(null, { jsonrpc: '2.0', id: 1, method: 'tools/list' });
    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toBe(
      `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"`
    );
  });

  it('registers a client dynamically', async () => {
    const response = await fetch(`${base}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'test-connector',
        redirect_uris: [REDIRECT],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code']
      })
    });
    expect(response.status).toBe(201);
    const client = (await response.json()) as { client_id: string };
    clientId = client.client_id;
    expect(clientId).toBeTruthy();
  });

  it('serves a consent page from /authorize — never a redirect, never framable', async () => {
    const response = await fetch(authorizeUrl(), { redirect: 'manual' });
    expect(response.status).toBe(200);
    expect(response.headers.get('content-security-policy')).toBe("frame-ancestors 'none'");
    expect(response.headers.get('x-frame-options')).toBe('DENY');
    expect(response.headers.getSetCookie()[0]).toMatch(
      /^__Host-xmcp_[^=]+=[^;]+;.*Path=\/;.*HttpOnly;.*Secure;.*SameSite=Lax/
    );
    const html = await response.text();
    expect(html).toContain('test-connector');
    expect(html).toContain('127.0.0.1:9');
  });

  // Errors here must be direct answers: redirecting would hand the outcome to an unvetted URI.
  it('refuses /authorize for an unknown client or an unregistered redirect_uri, never redirecting', async () => {
    for (const [field, value, error] of [
      ['client_id', 'no-such-client', 'invalid_client'],
      ['redirect_uri', 'https://attacker.example.test/callback', 'invalid_request']
    ] as const) {
      const url = authorizeUrl();
      url.searchParams.set(field, value);
      const response = await fetch(url, { redirect: 'manual' });
      expect(response.status).toBe(400);
      expect(response.headers.get('location')).toBeNull();
      expect(response.headers.getSetCookie()).toEqual([]);
      expect(((await response.json()) as { error: string }).error).toBe(error);
    }
  });

  it('refuses a callback without the browser cookie, issuing nothing', async () => {
    const { hubUrl } = await approve();
    const before = hub.requests.length;
    const response = await fetch(
      `${base}/oauth/callback?state=${hubUrl.searchParams.get('state')}&code=hub-code`,
      { redirect: 'manual' }
    );
    expect(response.status).toBe(400);
    expect(hub.requests.length).toBe(before);
  });

  it('approve redirects to hub with our PKCE, then the callback mints a code', async () => {
    const { hubUrl, cookie } = await approve();
    expect(hubUrl.pathname).toBe('/oauth/authorize');
    expect(hubUrl.searchParams.get('client_id')).toBe('mcp-client');
    expect(hubUrl.searchParams.get('scope')).toBe('openid email profile');
    expect(hubUrl.searchParams.get('code_challenge_method')).toBe('S256');
    expect(hubUrl.searchParams.get('code_challenge')).toBeTruthy();
    expect(hubUrl.searchParams.get('redirect_uri')).toBe(`${base}/oauth/callback`);

    const response = await fetch(
      `${base}/oauth/callback?state=${hubUrl.searchParams.get('state')}&code=hub-code`,
      { redirect: 'manual', headers: { Cookie: cookie } }
    );
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('location')!);
    expect(location.origin + location.pathname).toBe(REDIRECT);
    expect(location.searchParams.get('state')).toBe('st4te');
    code = location.searchParams.get('code')!;
    expect(code).toMatch(/^xmcp_ac_/);

    const exchange = hub.requests.find((request) => request.url === '/oauth/token')!;
    expect((exchange.headers as Record<string, string>).authorization).toBe(
      `Basic ${Buffer.from('mcp-client:mcp-secret').toString('base64')}`
    );
    expect(new URLSearchParams(exchange.body as string).get('code')).toBe('hub-code');
  });

  it('refuses the token exchange with a wrong PKCE verifier', async () => {
    const response = await fetch(`${base}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form({
        grant_type: 'authorization_code',
        code,
        code_verifier: 'not-the-verifier',
        client_id: clientId,
        redirect_uri: REDIRECT
      })
    });
    expect(response.status).toBe(400);
  });

  it('refuses the token exchange for an unknown client, leaving the code usable', async () => {
    const response = await fetch(`${base}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form({
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        client_id: 'no-such-client',
        redirect_uri: REDIRECT
      })
    });
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.status).toBeLessThan(500);
    expect(((await response.json()) as { error: string }).error).toBe('invalid_client');
  });

  it('exchanges the code with the right verifier', async () => {
    const response = await fetch(`${base}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form({
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        client_id: clientId,
        redirect_uri: REDIRECT
      })
    });
    expect(response.status).toBe(200);
    const tokens = (await response.json()) as { access_token: string; refresh_token: string };
    accessToken = tokens.access_token;
    refreshToken = tokens.refresh_token;
    expect(accessToken).toMatch(/^xmcp_at_/);
  });

  it('calls a hub endpoint with the hub OAuth token, not the org key', async () => {
    const listed = await mcp(accessToken, { jsonrpc: '2.0', id: 1, method: 'tools/list' });
    expect(listed.status).toBe(200);

    const response = await mcp(accessToken, {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'xyte_api_call', arguments: { key: 'organization.devices.getDevices' } }
    });
    expect(response.status).toBe(200);
    const result = (await response.json()) as { result?: { isError?: boolean } };
    expect(result.result?.isError).toBeFalsy();

    const hubRequest = hub.requests.at(-1)!;
    expect(hubRequest.url).toMatch(/^\/core\/v1\/organization\/devices/);
    const headers = hubRequest.headers as Record<string, string>;
    expect(headers.authorization).toBe('Bearer xoat_1');
    expect(headers['x-xyte-client']).toBe(`xyte-mcp/${VERSION}`);
    expect(headers.tenant).toBeUndefined();
  });

  it('401s a bearer that is no token of ours, with the challenge', async () => {
    const response = await mcp(JUNK_TOKEN, { jsonrpc: '2.0', id: 3, method: 'tools/list' });
    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toContain('resource_metadata=');
  });

  it('refreshes, rotating the refresh token', async () => {
    const response = await fetch(`${base}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: clientId })
    });
    expect(response.status).toBe(200);
    const tokens = (await response.json()) as { access_token: string; refresh_token: string };
    expect(tokens.access_token).not.toBe(accessToken);
    accessToken = tokens.access_token;
    refreshToken = tokens.refresh_token;
  });

  it('revocation kills the grant: both tokens stop working', async () => {
    const revoke = await fetch(`${base}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form({ token: refreshToken, client_id: clientId })
    });
    expect(revoke.status).toBe(200);
    const hubRevoke = hub.requests.find((request) => request.url === '/oauth/revoke')!;
    expect(new URLSearchParams(hubRevoke.body as string).get('token')).toBe('xort_1');

    expect((await mcp(accessToken, { jsonrpc: '2.0', id: 4, method: 'tools/list' })).status).toBe(
      401
    );
    const refresh = await fetch(`${base}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: clientId })
    });
    expect(refresh.status).toBe(400);
  });

  it('warned at boot that the token store is in-memory', () => {
    expect(stderr.join('')).toContain('no DATABASE_URL');
  });

  // claude.ai and ChatGPT register from shared egress IPs; the SDK default is 20/h per IP.
  it('lets one IP register more clients than the SDK default allows', async () => {
    for (let i = 0; i < 25; i += 1) {
      const response = await fetch(`${base}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' })
      });
      expect(response.status).toBe(201);
    }
  });

  // The request that started the refresh is gone (client hung up), so only
  // drain() stands between SIGTERM and an exit that loses the rotated pair.
  // Windows has no SIGTERM: kill() ends the child at once, so there is no shutdown to observe.
  it.skipIf(process.platform === 'win32')('on SIGTERM, waits for an in-flight hub refresh, then exits cleanly', async () => {
    hubExpiresIn = 30; // this sign-in's hub token starts inside the refresh window
    const { hubUrl, cookie } = await approve();
    const callback = await fetch(
      `${base}/oauth/callback?state=${hubUrl.searchParams.get('state')}&code=hub-code`,
      { redirect: 'manual', headers: { Cookie: cookie } }
    );
    const freshCode = new URL(callback.headers.get('location')!).searchParams.get('code')!;
    const exchange = await fetch(`${base}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form({
        grant_type: 'authorization_code',
        code: freshCode,
        code_verifier: verifier,
        client_id: clientId,
        redirect_uri: REDIRECT
      })
    });
    const { access_token: token } = (await exchange.json()) as { access_token: string };
    hubExpiresIn = 3600;

    heldRefreshes = [];
    // A raw request, so hanging up really closes the socket under it.
    const call = httpRequest(`${base}/mcp`, {
      method: 'POST',
      headers: { ...MCP_HEADERS, Authorization: `Bearer ${token}` }
    });
    call.on('error', () => undefined);
    call.end(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 5,
        method: 'tools/call',
        params: { name: 'xyte_api_call', arguments: { key: 'organization.devices.getDevices' } }
      })
    );
    await vi.waitFor(() => expect(heldRefreshes).toHaveLength(1));
    call.destroy();

    const exited = new Promise<number | null>((resolve) => child!.once('exit', resolve));
    child!.kill('SIGTERM');
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(child!.exitCode).toBeNull(); // still waiting on hub

    for (const answer of heldRefreshes!) answer();
    heldRefreshes = undefined;
    expect(await exited).toBe(0);
    expect(stderr.join('')).toContain('SIGTERM');
    expect(stderr.join('')).not.toContain('lost at shutdown');
  });
});
