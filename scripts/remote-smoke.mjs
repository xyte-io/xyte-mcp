#!/usr/bin/env node
/**
 * Acceptance check for a deployed `--http` server.
 *
 *   XYTE_MCP_HTTP_TOKEN=<token> npm run smoke:remote -- https://<app>.herokuapp.com
 *   npm run smoke:remote -- https://<app>.herokuapp.com --token-stdin
 *
 * Asserts the positives (health, handshake, tool list, a real read against the
 * configured org) *and* the denials that fail silently otherwise: no token,
 * wrong token, unknown path, and a mutating endpoint on a read-only server. The
 * denials are the point — a server that answers everything with 200 passes a
 * happy-path check and is still wide open.
 *
 * Read-only by construction: nothing here can mutate. The write check expects a
 * refusal, and treats a success as a failed test.
 *
 * The token is never printed, not even on failure.
 */

import process from 'node:process';

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
  throw new Error(
    'No token. Set XYTE_MCP_HTTP_TOKEN, or pass --token-stdin and paste it.\n' +
      'Example: npm run smoke:remote -- https://<app>.herokuapp.com --token-stdin'
  );
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
const check = (name, fn) => checks.push({ name, fn });

check('GET /healthz answers without a token', async ({ base }) => {
  const response = await request(`${base}/healthz`, { method: 'GET' });
  if (response.status !== 200) throw new Error(`expected 200, got ${response.status}`);
  return 'ok';
});

check('POST with no token is 401', async ({ base }) => {
  const response = await post(base, null, { jsonrpc: '2.0', id: 0, method: 'tools/list' });
  if (response.status !== 401) throw new Error(`expected 401, got ${response.status}`);
  if (response.headers.get('www-authenticate')) {
    // A challenge sends mcp-remote off to a browser OAuth flow that does not exist.
    throw new Error('unexpected WWW-Authenticate challenge on 401');
  }
  return '401, no challenge';
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

check('an authenticated request to another path is 404', async ({ base, token }) => {
  const response = await post(base, token, { jsonrpc: '2.0', id: 0, method: 'tools/list' }, '/');
  if (response.status !== 404) throw new Error(`expected 404, got ${response.status}`);
  return '404';
});

check('initialize handshake', async ({ base, token }) => {
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

check('tools/list returns the three tools', async ({ base, token }) => {
  const { tools } = await call(base, token, 'tools/list');
  const names = tools.map((tool) => tool.name).sort();
  const expected = ['xyte_api_call', 'xyte_endpoint_describe', 'xyte_endpoints_list'];
  if (names.join(',') !== expected.join(',')) throw new Error(`got ${names.join(', ')}`);
  return names.join(', ');
});

check('a real read reaches the configured org', async ({ base, token }) => {
  const result = await call(base, token, 'tools/call', {
    name: 'xyte_api_call',
    arguments: { key: 'organization.devices.getDevices', query: { page: 1, per_page: 1 } }
  });
  if (result.isError) throw new Error(result.content?.[0]?.text ?? 'tool returned isError');
  const status = result.structuredContent?.status;
  if (status !== 200) throw new Error(`hub returned ${status ?? 'no status'}`);
  return 'hub 200';
});

check('a mutating endpoint is refused', async ({ base, token }) => {
  const result = await call(base, token, 'tools/call', {
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

async function main() {
  const argv = process.argv.slice(2);
  const base = resolveBase(argv);
  const token = await resolveToken(argv);

  process.stderr.write(`smoking ${base}\n\n`);
  let failed = 0;
  for (const { name, fn } of checks) {
    try {
      const detail = await fn({ base, token });
      process.stderr.write(`  PASS  ${name}${detail ? ` — ${detail}` : ''}\n`);
    } catch (error) {
      failed += 1;
      // Redact defensively: an error body could quote the request headers back.
      const message = String(error.message ?? error).split(token).join('[redacted]');
      process.stderr.write(`  FAIL  ${name} — ${message}\n`);
    }
  }

  process.stderr.write(`\n${checks.length - failed}/${checks.length} passed\n`);
  process.exitCode = failed ? 1 : 0;
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(2);
});
