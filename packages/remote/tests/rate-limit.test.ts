import type { Server } from 'node:http';
import { createServer } from 'node:net';
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

async function start(mode: 'oauth' | 'static'): Promise<void> {
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  listener = await startHttpServer({
    PORT: String(port),
    DATABASE_URL: '',
    XYTE_HUB_URL: 'http://127.0.0.1:9',
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
