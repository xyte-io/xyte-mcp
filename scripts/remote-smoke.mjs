#!/usr/bin/env node
/**
 * Acceptance check for a deployed `--http` server.
 *
 *   XYTE_MCP_HTTP_TOKEN=<token> npm run smoke:remote -- https://<app>.herokuapp.com
 *   npm run smoke:remote -- https://<app>.herokuapp.com --token-stdin
 *
 * With hub credentials, also smokes the OAuth 2.1 surface end to end —
 * discovery, dynamic registration, login, PKCE token exchange, a call under
 * the minted token, and revocation:
 *
 *   XYTE_SMOKE_EMAIL=<email> XYTE_SMOKE_PASSWORD=<pw> npm run smoke:remote -- https://<app>...
 *
 * Asserts the positives (health, handshake, tool list, a real read against the
 * configured org) *and* the denials that fail silently otherwise: no token,
 * wrong token, unknown path, a revoked token, and a mutating endpoint on a
 * read-only server. The denials are the point — a server that answers
 * everything with 200 passes a happy-path check and is still wide open.
 *
 * Read-only by construction: nothing here can mutate hub state. The write
 * check expects a refusal, and treats a success as a failed test. (The OAuth
 * dance does mint and revoke tokens on the MCP server itself.)
 *
 * No token or password is ever printed, not even on failure.
 */

import { createHash, randomBytes } from 'node:crypto';
import process from 'node:process';
import { URL, URLSearchParams } from 'node:url';

const MCP_HEADERS = {
  'Content-Type': 'application/json',
  // The spec requires both, whatever the server chooses to return.
  Accept: 'application/json, text/event-stream'
};
const PROTOCOL_VERSION = '2025-06-18';
const TIMEOUT_MS = 20_000;

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8').trim();
}

async function resolveToken(argv) {
  if (argv.includes('--token-stdin')) {
    if (process.stdin.isTTY) {
      process.stderr.write('Paste the bearer token, then press Ctrl-D:\n');
    }
    const token = await readStdin();
    if (!token) throw new Error('No token received on stdin.');
    return token;
  }
  const fromEnv = process.env.XYTE_MCP_HTTP_TOKEN?.trim();
  if (fromEnv) return fromEnv;
  return undefined;
}

/** True when the deployment serves OAuth metadata (issuer configured). */
async function detectOAuth(base) {
  try {
    return (await request(`${base}/.well-known/oauth-authorization-server`)).ok;
  } catch {
    return false;
  }
}

function resolveBase(argv) {
  const url = argv.find((arg) => arg.startsWith('http://') || arg.startsWith('https://'));
  if (!url) {
    throw new Error('Pass the base URL: npm run smoke:remote -- https://<app>.herokuapp.com');
  }
  return url.replace(/\/+$/, '');
}

function request(url, init) {
  return fetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS) });
}

function post(base, token, body, route = '/mcp') {
  return request(`${base}${route}`, {
    method: 'POST',
    headers: { ...MCP_HEADERS, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body)
  });
}

let id = 0;

async function call(base, token, method, params) {
  const response = await post(base, token, {
    jsonrpc: '2.0',
    id: ++id,
    method,
    ...(params ? { params } : {})
  });
  if (response.status !== 200) {
    throw new Error(`${method}: expected 200, got ${response.status}`);
  }
  const payload = await response.json();
  if (payload.error) throw new Error(`${method}: ${payload.error.message}`);
  return payload.result;
}

const checks = [];
const check = (name, fn, when) => checks.push({ name, fn, when });

/** The token authenticated checks run under: static if set, else OAuth-minted. */
const authToken = (ctx) => ctx.token ?? ctx.minted?.access;

check('GET /healthz answers without a token', async ({ base }) => {
  const response = await request(`${base}/healthz`, { method: 'GET' });
  if (response.status !== 200) throw new Error(`expected 200, got ${response.status}`);
  return 'ok';
});

check('POST with no token is 401', async ({ base, oauth }) => {
  const response = await post(base, null, { jsonrpc: '2.0', id: 0, method: 'tools/list' });
  if (response.status !== 401) throw new Error(`expected 401, got ${response.status}`);
  const challenge = response.headers.get('www-authenticate');
  if (oauth && !challenge?.includes('oauth-protected-resource')) {
    // RFC 9728: without this pointer, claude.ai cannot discover the flow.
    throw new Error(`OAuth is on but the 401 challenge is ${challenge ?? 'missing'}`);
  }
  if (!oauth && challenge) {
    // A challenge sends mcp-remote off to a browser OAuth flow that does not exist.
    throw new Error('unexpected WWW-Authenticate challenge on 401');
  }
  return oauth ? '401 with resource-metadata challenge' : '401, no challenge';
});

check('POST with a wrong token is 401', async ({ base }) => {
  const response = await post(base, 'not-the-token-0123456789abcdef', {
    jsonrpc: '2.0',
    id: 0,
    method: 'tools/list'
  });
  if (response.status !== 401) throw new Error(`expected 401, got ${response.status}`);
  return '401';
});

// ---- The OAuth dance runs early so later checks can use its minted token ----

const OAUTH_WHEN = (ctx) => ctx.oauth && ctx.login;

check(
  'OAuth: discovery, registration, login, PKCE exchange',
  async (ctx) => {
    const { base, login } = ctx;
    const redirectUri = 'http://127.0.0.1:9/smoke-callback';

    const registered = await request(`${base}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'remote-smoke',
        redirect_uris: [redirectUri],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code']
      })
    });
    if (registered.status !== 201) throw new Error(`register: ${registered.status}`);
    const { client_id: clientId } = await registered.json();

    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const loggedIn = await request(`${base}/login`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        email: login.email,
        password: login.password,
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: challenge
      }).toString()
    });
    if (loggedIn.status !== 302) throw new Error(`login: expected 302, got ${loggedIn.status}`);
    const code = new URL(loggedIn.headers.get('location')).searchParams.get('code');

    const exchanged = await request(`${base}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        client_id: clientId,
        redirect_uri: redirectUri
      }).toString()
    });
    if (exchanged.status !== 200) throw new Error(`token: ${exchanged.status}`);
    const tokens = await exchanged.json();
    ctx.minted = { access: tokens.access_token, refresh: tokens.refresh_token, clientId };
    return 'registered, logged in, exchanged';
  },
  OAUTH_WHEN
);

check('an authenticated request to another path is 404', async (ctx) => {
  const response = await post(
    ctx.base,
    authToken(ctx),
    { jsonrpc: '2.0', id: 0, method: 'tools/list' },
    '/'
  );
  if (response.status !== 404) throw new Error(`expected 404, got ${response.status}`);
  return '404';
});

check('GET and DELETE on /mcp are 405', async (ctx) => {
  for (const method of ['GET', 'DELETE']) {
    const response = await request(`${ctx.base}/mcp`, {
      method,
      headers: { ...MCP_HEADERS, Authorization: `Bearer ${authToken(ctx)}` }
    });
    if (response.status !== 405) throw new Error(`${method}: expected 405, got ${response.status}`);
  }
  return '405 on both';
});

check('initialize handshake', async (ctx) => {
  const { base } = ctx;
  const token = authToken(ctx);
  const result = await call(base, token, 'initialize', {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: 'xyte-mcp-remote-smoke', version: '0.0.0' }
  });
  if (result.serverInfo?.name !== 'xyte-mcp') {
    throw new Error(`unexpected serverInfo: ${JSON.stringify(result.serverInfo)}`);
  }
  if (!result.instructions?.includes('READ-ONLY')) {
    throw new Error('server does not report itself read-only — set XYTE_MCP_READ_ONLY=1');
  }
  return `${result.serverInfo.name} ${result.serverInfo.version}, read-only`;
});

check('tools/list returns the three tools', async (ctx) => {
  const { tools } = await call(ctx.base, authToken(ctx), 'tools/list');
  const names = tools.map((tool) => tool.name).sort();
  const expected = ['xyte_api_call', 'xyte_endpoint_describe', 'xyte_endpoints_list'];
  if (names.join(',') !== expected.join(',')) throw new Error(`got ${names.join(', ')}`);
  return names.join(', ');
});

check('a real read reaches the configured org', async (ctx) => {
  const result = await call(ctx.base, authToken(ctx), 'tools/call', {
    name: 'xyte_api_call',
    arguments: { key: 'organization.devices.getDevices', query: { page: 1, per_page: 1 } }
  });
  if (result.isError) throw new Error(result.content?.[0]?.text ?? 'tool returned isError');
  const status = result.structuredContent?.status;
  if (status !== 200) throw new Error(`hub returned ${status ?? 'no status'}`);
  return 'hub 200';
});

check('a mutating endpoint is refused', async (ctx) => {
  const result = await call(ctx.base, authToken(ctx), 'tools/call', {
    name: 'xyte_api_call',
    arguments: {
      key: 'organization.commands.sendCommand',
      path: { device_id: 'smoke-test-no-such-device' },
      body: { name: 'reboot' }
    }
  });
  const text = result.content?.[0]?.text ?? '';
  if (!result.isError || !text.includes('read-only')) {
    throw new Error('write was NOT refused — the server is not in read-only mode');
  }
  return 'refused';
});

check(
  'OAuth: a read under the minted token succeeds',
  async (ctx) => {
    const result = await call(ctx.base, ctx.minted.access, 'tools/call', {
      name: 'xyte_api_call',
      arguments: { key: 'organization.devices.getDevices', query: { page: 1, per_page: 1 } }
    });
    if (result.isError) throw new Error(result.content?.[0]?.text ?? 'tool returned isError');
    const status = result.structuredContent?.status;
    if (status !== 200) throw new Error(`hub returned ${status ?? 'no status'}`);
    return 'hub 200 as the logged-in user';
  },
  (ctx) => Boolean(ctx.minted)
);

check(
  'OAuth: revocation kills the token',
  async ({ base, minted }) => {
    const revoked = await request(`${base}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: minted.refresh, client_id: minted.clientId }).toString()
    });
    if (revoked.status !== 200) throw new Error(`revoke: ${revoked.status}`);
    const after = await post(base, minted.access, { jsonrpc: '2.0', id: 0, method: 'tools/list' });
    if (after.status !== 401) throw new Error(`expected 401 after revoke, got ${after.status}`);
    return 'revoked → 401';
  },
  (ctx) => Boolean(ctx.minted)
);

async function main() {
  const argv = process.argv.slice(2);
  const base = resolveBase(argv);
  const token = await resolveToken(argv);
  const oauth = await detectOAuth(base);
  const email = process.env.XYTE_SMOKE_EMAIL?.trim();
  const password = process.env.XYTE_SMOKE_PASSWORD?.trim();
  const login = email && password ? { email, password } : undefined;

  if (!token && !(oauth && login)) {
    throw new Error(
      'No way to authenticate. Set XYTE_MCP_HTTP_TOKEN (or --token-stdin) for the static\n' +
        'bearer, and/or XYTE_SMOKE_EMAIL + XYTE_SMOKE_PASSWORD for the OAuth flow.'
    );
  }

  const ctx = { base, token, oauth, login };
  process.stderr.write(
    `smoking ${base} — static bearer: ${token ? 'yes' : 'no'}, oauth: ${oauth ? 'served' : 'off'}${
      oauth && !login ? ' (no XYTE_SMOKE_EMAIL/PASSWORD — dance skipped)' : ''
    }\n\n`
  );

  const secrets = () => [token, ctx.minted?.access, ctx.minted?.refresh, password].filter(Boolean);
  let failed = 0;
  let skipped = 0;
  for (const { name, fn, when } of checks) {
    if (when && !when(ctx)) {
      skipped += 1;
      process.stderr.write(`  SKIP  ${name}\n`);
      continue;
    }
    try {
      const detail = await fn(ctx);
      process.stderr.write(`  PASS  ${name}${detail ? ` — ${detail}` : ''}\n`);
    } catch (error) {
      failed += 1;
      // Redact defensively: an error body could quote the request headers back.
      let message = String(error.message ?? error);
      for (const secret of secrets()) message = message.split(secret).join('[redacted]');
      process.stderr.write(`  FAIL  ${name} — ${message}\n`);
    }
  }

  process.stderr.write(
    `\n${checks.length - failed - skipped}/${checks.length - skipped} passed` +
      `${skipped ? ` (${skipped} skipped)` : ''}\n`
  );
  process.exitCode = failed ? 1 : 0;
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(2);
});
