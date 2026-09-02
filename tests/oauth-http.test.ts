import { spawn, type ChildProcess } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
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
 * behind it: discovery → dynamic registration → /authorize → login form →
 * code → /token with PKCE → an authenticated MCP tool call that reaches the
 * hub under the *user's* credential → revocation. One sequential suite,
 * because each step consumes the previous one's output — exactly like a real
 * client.
 */

const DIST_ENTRY = path.resolve(import.meta.dirname, '..', 'dist', 'index.js');
const STATIC_TOKEN = 'xmcp_static_token_0123456789abcdef';
const ORG_KEY = 'org-key-abcdef123456';
const HUB_USER = { email: 'user@example.com', password: 'pw-123', tenant: 'tenant-1' };
const HUB_TOKENS = { 'access-token': 'hub-at-1', client: 'hub-client-1', uid: HUB_USER.email };
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

/** Just enough hub: devise sign_in plus one org API read that echoes headers. */
function fakeHub(): { server: Server; requests: Array<Record<string, unknown>> } {
  const requests: Array<Record<string, unknown>> = [];
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let body = '';
    req.on('data', (chunk: string) => (body += chunk));
    req.on('end', () => {
      if (req.method === 'POST' && req.url === '/auth/sign_in') {
        const { email, password } = JSON.parse(body || '{}') as Record<string, string>;
        if (email === HUB_USER.email && password === HUB_USER.password) {
          res.writeHead(200, { 'Content-Type': 'application/json', ...HUB_TOKENS });
          res.end(JSON.stringify({ data: { last_tenant_id: HUB_USER.tenant } }));
        } else {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ errors: ['Invalid login credentials.'] }));
        }
        return;
      }
      requests.push({ method: req.method, url: req.url, headers: { ...req.headers } });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ devices: [] }));
    });
  });
  return { server, requests };
}

let child: ChildProcess | undefined;
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

  it('serves the login form from /authorize', async () => {
    const url = new URL(`${base}/authorize`);
    url.search = form({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: REDIRECT,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: 'st4te'
    });
    const response = await fetch(url);
    expect(response.status).toBe(200);
    const html = await response.text();
    expect(html).toContain('Sign in to Xyte');
    expect(html).toContain(challenge);
  });

  it('rejects a wrong password by re-rendering the form', async () => {
    const response = await fetch(`${base}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form({
        email: HUB_USER.email,
        password: 'wrong',
        client_id: clientId,
        redirect_uri: REDIRECT,
        code_challenge: challenge
      })
    });
    expect(response.status).toBe(401);
    expect(await response.text()).toContain('Wrong email or password');
  });

  it('logs in against the hub and redirects with a code', async () => {
    const response = await fetch(`${base}/login`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form({
        email: HUB_USER.email,
        password: HUB_USER.password,
        client_id: clientId,
        redirect_uri: REDIRECT,
        code_challenge: challenge,
        state: 'st4te'
      })
    });
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('location')!);
    expect(location.origin + location.pathname).toBe(REDIRECT);
    expect(location.searchParams.get('state')).toBe('st4te');
    code = location.searchParams.get('code')!;
    expect(code).toMatch(/^xmcp_ac_/);
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

  it('calls a hub endpoint under the logged-in user, not the org key', async () => {
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
    const headers = hubRequest.headers as Record<string, string>;
    expect(headers['access-token']).toBe(HUB_TOKENS['access-token']);
    expect(headers.client).toBe(HUB_TOKENS.client);
    expect(headers.uid).toBe(HUB_TOKENS.uid);
    expect(headers.tenant).toBe(HUB_USER.tenant);
    expect(headers.authorization).toBeUndefined();
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
