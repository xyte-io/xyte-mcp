#!/usr/bin/env node
/**
 * Acceptance check for a deployed `--http` server. A deployment runs one of two
 * modes, and the script smokes whichever it is given:
 *
 *   npm run smoke:remote -- https://<app>.herokuapp.com              (OAuth, no token)
 *   XYTE_MCP_HTTP_TOKEN=<token> npm run smoke:remote -- https://<app>.herokuapp.com
 *   npm run smoke:remote -- https://<app>.herokuapp.com --token-stdin
 *
 * Static-bearer mode asserts the positives (health, handshake, tool list, a
 * real read with the configured key) *and* the denials that fail silently
 * otherwise: no token, wrong token, unknown path, and a mutating endpoint on a
 * read-only server. Pass `--expect-writes` for a deploy that opted into writes
 * (`XYTE_MCP_ALLOW_WRITES=1`); the write probe then never runs.
 *
 * OAuth mode needs no token and smokes the browser-free part of the flow:
 * discovery metadata, the 401 challenge pointing at it, dynamic registration,
 * the consent page for a valid PKCE request, refusal of an unregistered
 * redirect_uri, a junk bearer, health and unknown paths. Signing in happens at
 * hub in a browser, so the rest is verified by connecting a real client.
 *
 * The denials are the point — a server that answers everything with 200
 * passes a happy-path check and is still wide open.
 *
 * Nothing here mutates hub state: a write is only sent to a server that
 * reported itself read-only, and its success is a failed test. (OAuth mode
 * does register a client on the MCP server itself.)
 *
 * No token is ever printed, not even on failure.
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
const JUNK_TOKEN = 'xmcp_not_a_token_0123456789abcdef';

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
/** `mode`: 'static', 'oauth', or both when omitted; `when` gates on earlier results. */
const check = (name, fn, { mode, when } = {}) => checks.push({ name, fn, mode, when });

const REDIRECT_URI = 'http://127.0.0.1:9/smoke-callback';

function authorizeUrl(base, clientId, redirectUri) {
  const url = new URL(`${base}/authorize`);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: createHash('sha256').update(randomBytes(32)).digest('base64url'),
    code_challenge_method: 'S256',
    state: 'smoke'
  }).toString();
  return url.toString();
}

check('GET /healthz answers without a token', async ({ base }) => {
  const response = await request(`${base}/healthz`, { method: 'GET' });
  if (response.status !== 200) throw new Error(`expected 200, got ${response.status}`);
  return 'ok';
});

check(
  'OAuth: discovery metadata names this server',
  async ({ base }) => {
    const as = await (await request(`${base}/.well-known/oauth-authorization-server`)).json();
    if (as.issuer?.replace(/\/+$/, '') !== base) throw new Error(`issuer is ${as.issuer}`);
    if (!as.registration_endpoint) throw new Error('no registration_endpoint');
    if (!as.code_challenge_methods_supported?.includes('S256')) throw new Error('no S256 PKCE');
    const rs = await request(`${base}/.well-known/oauth-protected-resource/mcp`);
    if (rs.status !== 200) throw new Error(`protected-resource metadata: ${rs.status}`);
    const { resource } = await rs.json();
    if (resource !== `${base}/mcp`) throw new Error(`resource is ${resource}`);
    return 'authorization server + protected resource';
  },
  { mode: 'oauth' }
);

check('POST with no token is 401', async ({ base, oauth }) => {
  const response = await post(base, null, { jsonrpc: '2.0', id: 0, method: 'tools/list' });
  if (response.status !== 401) throw new Error(`expected 401, got ${response.status}`);
  const challenge = response.headers.get('www-authenticate');
  if (oauth && challenge !== `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"`) {
    // RFC 9728: without this pointer, claude.ai cannot discover the flow.
    throw new Error(`OAuth is on but the 401 challenge is ${challenge ?? 'missing'}`);
  }
  if (!oauth && challenge) {
    // A challenge sends mcp-remote off to a browser OAuth flow that does not exist.
    throw new Error('unexpected WWW-Authenticate challenge on 401');
  }
  return oauth ? '401 with resource-metadata challenge' : '401, no challenge';
});

check('POST with a token that is not ours is 401', async ({ base }) => {
  const response = await post(base, JUNK_TOKEN, { jsonrpc: '2.0', id: 0, method: 'tools/list' });
  if (response.status !== 401) throw new Error(`expected 401, got ${response.status}`);
  return '401';
});

check(
  'OAuth: dynamic client registration',
  async (ctx) => {
    const registered = await request(`${ctx.base}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'remote-smoke',
        redirect_uris: [REDIRECT_URI],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code']
      })
    });
    if (registered.status !== 201) throw new Error(`register: ${registered.status}`);
    ctx.clientId = (await registered.json()).client_id;
    if (!ctx.clientId) throw new Error('no client_id');
    return 'registered';
  },
  { mode: 'oauth' }
);

check(
  'OAuth: /authorize with valid PKCE shows the consent page (never a redirect)',
  async ({ base, clientId }) => {
    const page = await request(authorizeUrl(base, clientId, REDIRECT_URI), {
      method: 'GET',
      redirect: 'manual'
    });
    if (page.status !== 200) throw new Error(`expected 200, got ${page.status}`);
    if (page.headers.get('x-frame-options') !== 'DENY') throw new Error('consent page is framable');
    if (!(await page.text()).includes('action="/oauth/consent"')) throw new Error('no consent form');
    return 'consent page served';
  },
  { mode: 'oauth', when: (ctx) => ctx.clientId }
);

check(
  'OAuth: /authorize refuses an unregistered redirect_uri',
  async ({ base, clientId }) => {
    const page = await request(authorizeUrl(base, clientId, 'https://attacker.invalid/cb'), {
      method: 'GET',
      redirect: 'manual'
    });
    if (page.status !== 400) throw new Error(`expected 400, got ${page.status}`);
    if (page.headers.get('location')) throw new Error('redirected to an unregistered URI');
    return '400, no redirect';
  },
  { mode: 'oauth', when: (ctx) => ctx.clientId }
);

check(
  'an unknown path is 404',
  async ({ base }) => {
    const response = await request(`${base}/no-such-path`, { method: 'GET' });
    if (response.status !== 404) throw new Error(`expected 404, got ${response.status}`);
    return '404';
  },
  { mode: 'oauth' }
);

check(
  'an authenticated request to another path is 404',
  async (ctx) => {
    const response = await post(
      ctx.base,
      ctx.token,
      { jsonrpc: '2.0', id: 0, method: 'tools/list' },
      '/'
    );
    if (response.status !== 404) throw new Error(`expected 404, got ${response.status}`);
    return '404';
  },
  { mode: 'static' }
);

check(
  'GET and DELETE on /mcp are 405',
  async (ctx) => {
    for (const method of ['GET', 'DELETE']) {
      const response = await request(`${ctx.base}/mcp`, {
        method,
        headers: { ...MCP_HEADERS, Authorization: `Bearer ${ctx.token}` }
      });
      if (response.status !== 405) throw new Error(`${method}: expected 405, got ${response.status}`);
    }
    return '405 on both';
  },
  { mode: 'static' }
);

check(
  'initialize handshake, in the expected write mode',
  async (ctx) => {
    const result = await call(ctx.base, ctx.token, 'initialize', {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'xyte-mcp-remote-smoke', version: '0.0.0' }
    });
    if (result.serverInfo?.name !== 'xyte-mcp') {
      throw new Error(`unexpected serverInfo: ${JSON.stringify(result.serverInfo)}`);
    }
    ctx.readOnly = Boolean(result.instructions?.includes('READ-ONLY'));
    if (ctx.readOnly === ctx.expectWrites) {
      throw new Error(
        ctx.readOnly
          ? 'server is read-only, but --expect-writes was passed'
          : 'server has writes ENABLED — unset XYTE_MCP_ALLOW_WRITES, or pass --expect-writes'
      );
    }
    return `${result.serverInfo.name} ${result.serverInfo.version}, ${ctx.readOnly ? 'read-only' : 'writes enabled'}`;
  },
  { mode: 'static' }
);

check(
  'tools/list returns the three tools',
  async (ctx) => {
    const { tools } = await call(ctx.base, ctx.token, 'tools/list');
    const names = tools.map((tool) => tool.name).sort();
    const expected = ['xyte_api_call', 'xyte_endpoint_describe', 'xyte_endpoints_list'];
    if (names.join(',') !== expected.join(',')) throw new Error(`got ${names.join(', ')}`);
    return names.join(', ');
  },
  { mode: 'static' }
);

check(
  'a real read reaches the hub with the configured key',
  async (ctx) => {
    // Organization first; a partner-only deploy has no org key, so fall back.
    let scope = 'organization';
    let result = await call(ctx.base, ctx.token, 'tools/call', {
      name: 'xyte_api_call',
      arguments: { key: 'organization.devices.getDevices', query: { page: 1, per_page: 1 } }
    });
    if (result.isError && /needs a organization API key/.test(result.content?.[0]?.text ?? '')) {
      scope = 'partner';
      result = await call(ctx.base, ctx.token, 'tools/call', {
        name: 'xyte_api_call',
        arguments: { key: 'partner.devices.getDevices' }
      });
    }
    if (result.isError) throw new Error(result.content?.[0]?.text ?? 'tool returned isError');
    const status = result.structuredContent?.status;
    if (status !== 200) throw new Error(`hub returned ${status ?? 'no status'}`);
    return `${scope} read, hub 200`;
  },
  { mode: 'static' }
);

check(
  'a mutating endpoint is refused',
  async (ctx) => {
    const result = await call(ctx.base, ctx.token, 'tools/call', {
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
  },
  // Never sent to a server that did not just report itself read-only.
  { mode: 'static', when: (ctx) => ctx.readOnly === true }
);

async function main() {
  const argv = process.argv.slice(2);
  const base = resolveBase(argv);
  const token = await resolveToken(argv);
  const oauth = await detectOAuth(base);

  if (token && oauth) {
    throw new Error('This deploy serves OAuth, so it has no static token; run without one.');
  }
  if (!token && !oauth) {
    throw new Error(
      'No OAuth metadata at this URL, so it is a static-bearer deploy: ' +
        'set XYTE_MCP_HTTP_TOKEN (or --token-stdin).'
    );
  }

  const mode = oauth ? 'oauth' : 'static';
  const ctx = { base, token, oauth, expectWrites: argv.includes('--expect-writes') };
  process.stderr.write(`smoking ${base} — mode: ${mode}\n\n`);

  const secrets = () => (token ? [token] : []);
  let failed = 0;
  let skipped = 0;
  const run = checks.filter((entry) => !entry.mode || entry.mode === mode);
  for (const { name, fn, when } of run) {
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
    `\n${run.length - failed - skipped}/${run.length - skipped} passed` +
      `${skipped ? ` (${skipped} skipped)` : ''}\n`
  );
  process.exitCode = failed ? 1 : 0;
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(2);
});
