import { spawn, type ChildProcess } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { hubAcceptsPkce } from './support/pkce.js';
import { existsSync, readFileSync } from 'node:fs';
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse
} from 'node:http';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

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
const STATIC_TOKEN = 'xmcp_static_token_0123456789abcdef';
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
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            access_token: 'xoat_1',
            refresh_token: 'xort_1',
            expires_in: 3600,
            token_type: 'Bearer',
            id_token: ID_TOKEN
          })
        );
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
      XYTE_MCP_HTTP_TOKEN: STATIC_TOKEN,
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
    expect(response.headers.get('www-authenticate')).toContain(
      '/.well-known/oauth-protected-resource/mcp'
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

  it('refuses a callback from a browser that did not approve, issuing nothing', async () => {
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

  it('still accepts the phase-1 static bearer alongside OAuth', async () => {
    const response = await mcp(STATIC_TOKEN, { jsonrpc: '2.0', id: 3, method: 'tools/list' });
    expect(response.status).toBe(200);
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
});
