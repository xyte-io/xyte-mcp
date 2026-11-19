import { createServer as createHttpServer, type Server } from 'node:http';
import { createServer } from 'node:net';
import { gzipSync } from 'node:zlib';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { XyteOAuthProvider } from '../src/oauth/provider.js';
import { startHttpServer } from '../src/transports/http.js';

/**
 * The limits on /mcp and /oauth/callback, and the /mcp body cap. In-process with
 * a fresh server per test, so a burst never leaks into another test's buckets;
 * token verification is stubbed so each `grant-*` bearer is its own grant.
 */

const STATIC_TOKEN = 'xmcp_test_token_0123456789abcdef';
const MCP_HEADERS = {
  'Content-Type': 'application/json',
  Accept: 'application/json, text/event-stream'
};
const TOOLS_LIST = { jsonrpc: '2.0', id: 1, method: 'tools/list' };
const MIB = 1024 * 1024;

async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address() as { port: number };
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

let listener: Server | undefined;
let base = '';

async function start(mode: 'oauth' | 'static', hubUrl = 'http://127.0.0.1:9'): Promise<void> {
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  listener = await startHttpServer({
    PORT: String(port),
    DATABASE_URL: '',
    XYTE_HUB_URL: hubUrl,
    ...(mode === 'oauth'
      ? {
          XYTE_MCP_ISSUER_URL: base,
          XYTE_MCP_HUB_OAUTH_CLIENT_ID: 'mcp-client',
          XYTE_MCP_HUB_OAUTH_CLIENT_SECRET: 'mcp-secret'
        }
      : { XYTE_MCP_HTTP_TOKEN: STATIC_TOKEN, XYTE_ORG_API_KEY: 'org-key-abcdef123456' })
  });
}

function mcp(token: string | null, body: unknown = TOOLS_LIST): Promise<Response> {
  return fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { ...MCP_HEADERS, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: typeof body === 'string' ? body : JSON.stringify(body)
  });
}

/** Sends `count` calls and returns their statuses, draining each body. */
async function burst(count: number, send: (index: number) => Promise<Response>): Promise<number[]> {
  const statuses: number[] = [];
  for (let i = 0; i < count; i += 1) {
    const response = await send(i);
    await response.arrayBuffer();
    statuses.push(response.status);
  }
  return statuses;
}

beforeEach(() => {
  // Every denial logs a line; hundreds of them would bury the test output.
  vi.spyOn(process.stderr, 'write').mockReturnValue(true);
  vi.spyOn(XyteOAuthProvider.prototype, 'verifyAccessToken').mockImplementation(
    async (token: string) => {
      if (!token.startsWith('grant-')) throw new InvalidTokenError('unknown token');
      return {
        token,
        clientId: 'client',
        scopes: [],
        extra: { hub: { grantId: token, accessToken: 'hub-token' } }
      };
    }
  );
});

afterEach(async () => {
  vi.restoreAllMocks();
  await new Promise<void>((resolve) => listener?.close(() => resolve()) ?? resolve());
  listener = undefined;
});

async function expectRateLimited(response: Response): Promise<void> {
  expect(response.status).toBe(429);
  expect(Number(response.headers.get('retry-after'))).toBeGreaterThan(0);
  expect(response.headers.get('content-type')).toContain('application/json');
  expect(await response.json()).toMatchObject({ jsonrpc: '2.0', id: null, error: { code: -32000 } });
}

describe('/mcp rate limit', () => {
  it('allows 60 calls a minute per grant, then 429s that grant only', async () => {
    await start('oauth');

    const first = await mcp('grant-a');
    expect(first.status).toBe(200);
    expect(first.headers.get('ratelimit-policy')).toContain('q=60; w=60');
    expect(await burst(59, () => mcp('grant-a'))).toEqual(Array(59).fill(200));

    await expectRateLimited(await mcp('grant-a'));
    expect(process.stderr.write).toHaveBeenCalledWith(
      expect.stringContaining('429 POST /mcp — rate limited (grant grant-a)')
    );
    // A second sign-in from the same IP has its own budget.
    expect((await mcp('grant-b')).status).toBe(200);
  });

  it('allows 300 calls a minute per IP without a valid token, then 429s instead of 401', async () => {
    await start('oauth');

    const statuses = await burst(300, (i) => mcp(i % 2 ? 'junk-token' : null));
    expect(statuses).toEqual(Array(300).fill(401));

    await expectRateLimited(await mcp('junk-token'));
    // The IP bucket does not block a valid grant from the same IP, on any method.
    expect((await mcp('grant-a')).status).toBe(200);
    const get = await fetch(`${base}/mcp`, { headers: { Authorization: 'Bearer grant-a' } });
    expect(get.status).toBe(405);
  });

  it('applies the per-IP limit to non-POST methods too', async () => {
    await start('oauth');

    expect(await burst(300, () => fetch(`${base}/mcp`, { method: 'GET' }))).toEqual(
      Array(300).fill(401)
    );
    await expectRateLimited(await fetch(`${base}/mcp`, { method: 'DELETE' }));
  });

  it('never limits the static token (dev/CI), but still limits token-less calls', async () => {
    await start('static');

    const statuses = await burst(70, () => mcp(STATIC_TOKEN));
    expect(statuses).toEqual(Array(70).fill(200));

    const anonymous = await mcp(null);
    expect(anonymous.status).toBe(401);
    expect(anonymous.headers.get('ratelimit-policy')).toContain('q=300; w=60');
  });
});

describe('/mcp body cap', () => {
  /** A valid tools/list padded with an unused param to exactly `bytes`. */
  function paddedToolsList(bytes: number): string {
    const empty = JSON.stringify({ ...TOOLS_LIST, params: { _meta: { pad: '' } } });
    return JSON.stringify({ ...TOOLS_LIST, params: { _meta: { pad: 'x'.repeat(bytes - empty.length) } } });
  }

  it('answers a body over 1 MiB with 413, and serves one just under', async () => {
    await start('static');

    const over = await mcp(STATIC_TOKEN, paddedToolsList(MIB + 1));
    expect(over.status).toBe(413);
    expect(await over.json()).toMatchObject({ jsonrpc: '2.0', error: { code: -32000 } });

    const under = await mcp(STATIC_TOKEN, paddedToolsList(MIB - 1));
    expect(under.status).toBe(200);
  });

  it('answers a chunked body over 1 MiB (no Content-Length) with 413', async () => {
    await start('static');
    const body = new TextEncoder().encode(paddedToolsList(MIB + 1));
    const chunked = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let i = 0; i < body.length; i += 64 * 1024) {
          controller.enqueue(body.slice(i, i + 64 * 1024));
        }
        controller.close();
      }
    });

    const over = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { ...MCP_HEADERS, Authorization: `Bearer ${STATIC_TOKEN}` },
      body: chunked,
      duplex: 'half'
    } as RequestInit);
    expect(over.status).toBe(413);
    expect(await over.json()).toMatchObject({ jsonrpc: '2.0', error: { code: -32000 } });
  });

  it('keeps the JSON-RPC parse error, 415 and 406 for a malformed request', async () => {
    await start('static');
    const post = (headers: Record<string, string>, body: string) =>
      fetch(`${base}/mcp`, {
        method: 'POST',
        headers: { ...MCP_HEADERS, Authorization: `Bearer ${STATIC_TOKEN}`, ...headers },
        body
      });
    const valid = JSON.stringify(TOOLS_LIST);

    const invalid = await post({}, '{not json');
    expect(invalid.status).toBe(400);
    expect(await invalid.json()).toMatchObject({ jsonrpc: '2.0', error: { code: -32700 } });
    expect((await post({ 'Content-Type': 'text/plain' }, valid)).status).toBe(415);
    expect((await post({ Accept: 'application/json' }, valid)).status).toBe(406);
  });

  it('answers a Content-Encoding body with 415, not a parse error', async () => {
    await start('static');
    const gzipped = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { ...MCP_HEADERS, Authorization: `Bearer ${STATIC_TOKEN}`, 'Content-Encoding': 'gzip' },
      body: gzipSync(JSON.stringify(TOOLS_LIST))
    });
    expect(gzipped.status).toBe(415);
    expect(await gzipped.json()).toMatchObject({
      jsonrpc: '2.0',
      error: { code: -32000, message: expect.stringContaining('Unsupported Media Type') }
    });
  });
});

describe('/mcp JSON-RPC batches', () => {
  let hub: Server | undefined;
  afterEach(async () => {
    await new Promise<void>((resolve) => hub?.close(() => resolve()) ?? resolve());
    hub = undefined;
  });

  it('refuses a batch with 400 before any message runs, so one request is one hub call', async () => {
    let hubCalls = 0;
    hub = createHttpServer((_req, res) => {
      hubCalls += 1;
      res.setHeader('Content-Type', 'application/json');
      res.end('[]');
    });
    await new Promise<void>((resolve) => hub!.listen(0, '127.0.0.1', resolve));
    // Static mode sends the process key straight to the hub; the POST path is the same.
    await start('static', `http://127.0.0.1:${(hub.address() as { port: number }).port}`);
    const getDevices = (id: number) => ({
      jsonrpc: '2.0',
      id,
      method: 'tools/call',
      params: { name: 'xyte_api_call', arguments: { key: 'organization.devices.getDevices' } }
    });

    const batch = await mcp(STATIC_TOKEN, [getDevices(1), getDevices(2)]);
    expect(batch.status).toBe(400);
    expect(await batch.json()).toMatchObject({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32600, message: expect.stringContaining('batch') }
    });
    expect(hubCalls).toBe(0);

    // The same call on its own reaches the hub once.
    expect((await mcp(STATIC_TOKEN, getDevices(3))).status).toBe(200);
    expect(hubCalls).toBe(1);
  });

  it('never parses a body without a valid token', async () => {
    await start('oauth');
    // A pre-auth parse would answer this with 400.
    expect((await mcp(null, '{not json')).status).toBe(401);
  });
});

describe('/oauth/callback rate limit', () => {
  it('allows 30 callbacks a minute per IP, then 429s', async () => {
    await start('oauth');
    const callback = () => fetch(`${base}/oauth/callback?state=nope&code=x`, { redirect: 'manual' });

    expect(await burst(30, callback)).toEqual(Array(30).fill(400));
    const limited = await callback();
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get('retry-after'))).toBeGreaterThan(0);
  });
});
