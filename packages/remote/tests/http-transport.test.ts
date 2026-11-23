import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { connect, createServer } from 'node:net';
import path from 'node:path';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { XyteOAuthProvider } from '../src/oauth/provider.js';
import { PgOAuthStore } from '../src/oauth/pg-store.js';
import { MemoryOAuthStore } from '../src/oauth/store.js';
import { startHttpServer } from '../src/transports/http.js';
import { createTestSchema, listDevices, newTokenKey, serverEnv, signIn, startFakeHub } from './support/two-process.js';

/**
 * Drives a real HTTP server process over the network, so this covers the
 * transport selection, the auth boundary and the JSON-RPC framing together —
 * the same reasoning as `protocol-smoke.test.ts` does for stdio.
 */

const PG_URL = process.env.TEST_DATABASE_URL;
const DIST_ENTRY = path.resolve(import.meta.dirname, '..', 'dist', 'index.js');
// The hosted server reports @xyteai/mcp's version.
const MCP_PACKAGE_VERSION = (
  JSON.parse(
    readFileSync(path.resolve(import.meta.dirname, '..', '..', 'mcp', 'package.json'), 'utf8')
  ) as { version: string }
).version;
const TOKEN = 'xmcp_test_token_0123456789abcdef';
const ORG_KEY = 'org-key-abcdef123456';
const MCP_HEADERS = {
  'Content-Type': 'application/json',
  // The MCP spec requires both, whatever the server chooses to return.
  Accept: 'application/json, text/event-stream'
};

interface JsonRpcResponse {
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
}

/** Ask the OS for a free port, then hand it to the child. */
async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address() as { port: number };
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

class HttpHarness {
  readonly stderr: string[] = [];
  private constructor(
    private readonly child: ChildProcess,
    readonly base: string
  ) {}

  static async start(env: Record<string, string> = {}): Promise<HttpHarness> {
    const port = await freePort();
    const child = spawn(process.execPath, [DIST_ENTRY], {
      env: {
        ...process.env,
        PORT: String(port),
        XYTE_MCP_HTTP_TOKEN: TOKEN,
        XYTE_ORG_API_KEY: ORG_KEY,
        ...env
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    const harness = new HttpHarness(child, `http://127.0.0.1:${port}`);
    child.stderr?.setEncoding('utf8');
    child.stderr?.on('data', (chunk: string) => harness.stderr.push(chunk));
    await harness.awaitReady();
    return harness;
  }

  /**
   * Poll /healthz rather than sleeping: a fixed delay is either slow or flaky.
   * Then wait for the ready line naming *our* port: stderr is a different pipe
   * from the HTTP response, and freePort's port could in theory have been taken
   * by another process whose /healthz answered instead.
   */
  private async awaitReady(): Promise<void> {
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      if (this.child.exitCode !== null) {
        throw new Error(`server exited (${this.child.exitCode})\n${this.stderr.join('')}`);
      }
      try {
        if ((await fetch(`${this.base}/healthz`)).ok) break;
      } catch {
        // Not listening yet.
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    await this.waitForStderr(`ready over http on :${new URL(this.base).port}/mcp`);
  }

  async waitForStderr(text: string): Promise<void> {
    const deadline = Date.now() + 10_000;
    while (!this.stderr.join('').includes(text)) {
      if (Date.now() > deadline) {
        throw new Error(`stderr never contained "${text}"\n${this.stderr.join('')}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }

  post(body: unknown, init: { token?: string | null; path?: string } = {}): Promise<Response> {
    const { token = TOKEN, path: route = '/mcp' } = init;
    return fetch(`${this.base}${route}`, {
      method: 'POST',
      headers: { ...MCP_HEADERS, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body)
    });
  }

  async call(id: number, method: string, params?: Record<string, unknown>): Promise<JsonRpcResponse> {
    const response = await this.post({ jsonrpc: '2.0', id, method, ...(params ? { params } : {}) });
    expect(response.status, `${method} -> ${response.status}`).toBe(200);
    return (await response.json()) as JsonRpcResponse;
  }

  stop(): void {
    this.child.kill('SIGKILL');
  }

  /** Send a signal and resolve with the exit code. */
  signal(name: NodeJS.Signals): Promise<number | null> {
    const exited = new Promise<number | null>((resolve) => this.child.once('exit', resolve));
    this.child.kill(name);
    return exited;
  }
}

let harness: HttpHarness | undefined;
let bareChild: ChildProcess | undefined;

/** Run the binary to exit; killed in afterEach and bounded, so a regression fails fast instead of hanging. */
async function runToExit(
  args: string[],
  env: Record<string, string>
): Promise<{ code: number | null; stderr: string }> {
  const child = spawn(process.execPath, [DIST_ENTRY, ...args], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  bareChild = child;
  let stderr = '';
  child.stderr?.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
  const code = await new Promise<number | null>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`still running\n${stderr}`)), 5_000);
    child.on('exit', (exitCode) => {
      clearTimeout(timer);
      resolve(exitCode);
    });
  });
  return { code, stderr };
}

async function start(env: Record<string, string> = {}): Promise<HttpHarness> {
  harness = await HttpHarness.start(env);
  return harness;
}

beforeAll(() => {
  if (!existsSync(DIST_ENTRY)) {
    throw new Error(`Build first: ${DIST_ENTRY} is missing (npm run build).`);
  }
});

afterEach(() => {
  harness?.stop();
  harness = undefined;
  bareChild?.kill('SIGKILL');
  bareChild = undefined;
});

describe('http transport', () => {
  it('answers the health probe without a token', async () => {
    const server = await start();
    const response = await fetch(`${server.base}/healthz`);

    expect(response.status).toBe(200);
    expect(await response.text()).toBe('ok');
  });

  it('refuses a request with no Authorization header', async () => {
    const server = await start();
    const response = await server.post({ jsonrpc: '2.0', id: 1, method: 'tools/list' }, { token: null });

    expect(response.status).toBe(401);
    expect((await response.json()) as JsonRpcResponse).toMatchObject({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32001, message: 'unauthorized' }
    });
  });

  it('refuses a wrong token, and a right token of the wrong length', async () => {
    const server = await start();

    expect((await server.post({}, { token: 'nope' })).status).toBe(401);
    // A prefix of the real token must not pass — the length check is not the
    // whole comparison.
    expect((await server.post({}, { token: TOKEN.slice(0, -1) })).status).toBe(401);
    expect((await server.post({}, { token: `${TOKEN}x` })).status).toBe(401);
  });

  it('accepts the Bearer scheme in any case (RFC 7235)', async () => {
    const server = await start();
    const response = await fetch(`${server.base}/mcp`, {
      method: 'POST',
      headers: { ...MCP_HEADERS, Authorization: `bearer  ${TOKEN}` },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
    });

    expect(response.status).toBe(200);
  });

  it('never echoes the bearer token or the API key, to the caller or the log', async () => {
    const server = await start();
    const wrong = 'xmcp_wrong_token_fedcba9876543210';
    const body = await (await server.post({}, { token: wrong })).text();

    expect(body).not.toContain(TOKEN);
    expect(body).not.toContain(ORG_KEY);
    // The denial log is the real leak surface: it names the request, never the bearer.
    await server.waitForStderr('401 POST /mcp');
    const stderr = server.stderr.join('');
    expect(stderr).not.toContain(wrong);
    expect(stderr).not.toContain(TOKEN);
  });

  // A challenge makes mcp-remote open a browser for an OAuth flow that does not
  // exist yet, which reads as "the server is broken".
  it('sends no WWW-Authenticate challenge on a 401', async () => {
    const server = await start();
    const response = await server.post({}, { token: null });

    expect(response.headers.get('www-authenticate')).toBeNull();
  });

  it('404s an authenticated request to another path', async () => {
    const server = await start();
    const response = await server.post({ jsonrpc: '2.0', id: 1, method: 'tools/list' }, { path: '/' });

    expect(response.status).toBe(404);
    expect(await response.json()).toMatchObject({ jsonrpc: '2.0', id: null, error: { code: -32601 } });
  });

  // Otherwise the SDK opens an SSE stream a stateless server can never write to,
  // and every client parks an idle connection until the platform times it out.
  it('405s GET and DELETE on /mcp rather than opening a dead stream', async () => {
    const server = await start();

    for (const method of ['GET', 'DELETE']) {
      const response = await fetch(`${server.base}/mcp`, {
        method,
        headers: { Authorization: `Bearer ${TOKEN}`, ...MCP_HEADERS }
      });
      expect(response.status, method).toBe(405);
      expect(response.headers.get('allow'), method).toBe('POST');
      expect(response.headers.get('content-type'), method).toContain('application/json');
      expect(await response.json(), method).toMatchObject({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32000 }
      });
    }
  });

  it('still requires a token for a non-POST method', async () => {
    const server = await start();
    const response = await fetch(`${server.base}/mcp`, { method: 'GET', headers: MCP_HEADERS });

    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ jsonrpc: '2.0', id: null, error: { code: -32001 } });
  });

  // `new URL` throws on an absolute-form target with a bad port; unguarded, that
  // rejection killed the process before the auth check.
  it('answers a malformed request target with a 4xx and stays up', async () => {
    const server = await start();
    const { port } = new URL(server.base);
    const raw = await new Promise<string>((resolve, reject) => {
      const socket = connect(Number(port), '127.0.0.1', () => {
        socket.end('GET http://x:99999/mcp HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n');
      });
      let data = '';
      socket.setEncoding('utf8');
      socket.on('data', (chunk: string) => (data += chunk));
      socket.on('end', () => resolve(data));
      socket.on('error', reject);
    });

    expect(raw).toMatch(/^HTTP\/1\.1 4\d\d/);
    expect((await fetch(`${server.base}/healthz`)).status).toBe(200);
  });

  // Stateless means a fresh server/transport pair per request: concurrent calls
  // on one process must neither cross-talk nor break the teardown.
  it('answers concurrent requests on one process, each with its own id', async () => {
    const server = await start();
    const ids = Array.from({ length: 20 }, (_, index) => index + 1);
    const responses = await Promise.all(
      ids.map(async (id) => {
        const response = await server.post({ jsonrpc: '2.0', id, method: 'tools/list' });
        return (await response.json()) as JsonRpcResponse & { id: number };
      })
    );

    expect(responses.map((response) => response.id)).toEqual(ids);
    for (const response of responses) expect(response.result?.tools).toHaveLength(3);
  });

  it('completes the initialize handshake', async () => {
    const server = await start();
    const response = await server.call(1, 'initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'xyte-mcp-test', version: '0.0.0' }
    });

    expect(response.error).toBeUndefined();
    expect(response.result?.serverInfo).toMatchObject({ name: 'xyte-mcp' });
  });

  // Stateless: there is no session to establish, so a bare tools/list works.
  it('lists the three tools without a prior handshake, and sets no session id', async () => {
    const server = await start();
    const raw = await server.post({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    expect(raw.headers.get('mcp-session-id')).toBeNull();

    const tools = ((await raw.json()) as JsonRpcResponse).result?.tools as Array<{ name: string }>;
    expect(tools.map((tool) => tool.name).sort()).toEqual([
      'xyte_api_call',
      'xyte_endpoint_describe',
      'xyte_endpoints_list'
    ]);
  });

  it('runs a discovery tool end to end', async () => {
    const server = await start();
    const response = await server.call(2, 'tools/call', {
      name: 'xyte_endpoints_list',
      arguments: { namespace: 'organization' }
    });

    const result = response.result as { isError?: boolean; structuredContent?: { count: number } };
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent?.count).toBeGreaterThan(0);

    // One shared identity in this mode, so the line carries none.
    await server.waitForStderr('"event":"tool_call"');
    const line = server.stderr
      .join('')
      .split('\n')
      .find((entry) => entry.includes('"event":"tool_call"'))!;
    expect(JSON.parse(line)).toEqual({
      event: 'tool_call',
      tool: 'xyte_endpoints_list',
      outcome: 'ok',
      duration_ms: expect.any(Number)
    });
  });

  // Hosted is read-only unless writes are asked for; stdio keeps writes on.
  it('refuses a mutating endpoint by default', async () => {
    const server = await start();
    const response = await server.call(3, 'tools/call', {
      name: 'xyte_api_call',
      arguments: {
        key: 'organization.commands.sendCommand',
        path: { device_id: 'd1' },
        body: { name: 'reboot' }
      }
    });

    const result = response.result as { isError?: boolean; content: Array<{ text: string }> };
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain('read-only');
  });

  it('enables writes only on an explicit XYTE_MCP_ALLOW_WRITES=1, and warns', async () => {
    const server = await start({ XYTE_MCP_ALLOW_WRITES: '1' });
    expect(server.stderr.join('')).toContain('writes: ENABLED');
    expect(server.stderr.join('')).toContain('WARNING: writes are enabled');
  });

  it('lets an explicit read-only win over XYTE_MCP_ALLOW_WRITES=1', async () => {
    const server = await start({ XYTE_MCP_ALLOW_WRITES: '1', XYTE_MCP_READ_ONLY: '1' });
    expect(server.stderr.join('')).toContain('writes: disabled');
  });

  it('does not warn when read-only, the default', async () => {
    const server = await start();
    expect(server.stderr.join('')).toContain('writes: disabled');
    expect(server.stderr.join('')).not.toContain('WARNING');
  });

  it('refuses to start with both the static token and OAuth configured', async () => {
    const { code, stderr } = await runToExit([], {
      PORT: String(await freePort()),
      XYTE_ORG_API_KEY: ORG_KEY,
      XYTE_MCP_HTTP_TOKEN: TOKEN,
      XYTE_MCP_ISSUER_URL: 'https://mcp.example.com',
      XYTE_MCP_HUB_OAUTH_CLIENT_ID: 'mcp-client',
      XYTE_MCP_HUB_OAUTH_CLIENT_SECRET: 'mcp-secret'
    });

    expect(code).toBe(1);
    expect(stderr).toContain('are both set');
    expect(stderr).toContain('  - Unset XYTE_MCP_HTTP_TOKEN for OAuth');
  });

  it('refuses to start OAuth on Postgres without a token key, saying how to make one', async () => {
    const { code, stderr } = await runToExit([], {
      PORT: String(await freePort()),
      XYTE_MCP_ISSUER_URL: 'https://mcp.example.com',
      XYTE_MCP_HUB_OAUTH_CLIENT_ID: 'mcp-client',
      XYTE_MCP_HUB_OAUTH_CLIENT_SECRET: 'mcp-secret',
      // Never reached: config fails first.
      DATABASE_URL: 'postgres://localhost:9/none',
      XYTE_MCP_TOKEN_KEY: ''
    });

    expect(code).toBe(1);
    expect(stderr).toContain('XYTE_MCP_TOKEN_KEY must be the base64 of exactly 32 random bytes');
    expect(stderr).toContain("  - Generate one: node -e \"console.log(require('crypto').randomBytes(32).toString('base64'))\"");
  });

  it('refuses to start without a bearer token, naming the variable', async () => {
    const { code, stderr } = await runToExit([], {
      PORT: String(await freePort()),
      XYTE_ORG_API_KEY: ORG_KEY,
      XYTE_MCP_HTTP_TOKEN: ''
    });

    expect(code).toBe(1);
    expect(stderr).toContain('XYTE_MCP_HTTP_TOKEN');
  });
});

// In-process, so the token store can be made to fail.
describe('http transport: token store outage', () => {
  it('answers 503 without a challenge, not a 401, when the token check cannot run', async () => {
    const port = await freePort();
    const getToken = vi
      .spyOn(MemoryOAuthStore.prototype, 'getToken')
      .mockRejectedValue(Object.assign(new Error('db down at db.internal'), { code: '57P01' }));
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const listener = await startHttpServer({
      PORT: String(port),
      XYTE_MCP_ISSUER_URL: `http://127.0.0.1:${port}`,
      XYTE_MCP_HUB_OAUTH_CLIENT_ID: 'mcp-client',
      XYTE_MCP_HUB_OAUTH_CLIENT_SECRET: 'mcp-secret'
    });
    try {
      for (const method of ['POST', 'GET']) {
        const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
          method,
          headers: { ...MCP_HEADERS, Authorization: 'Bearer xmcp_at_whatever' },
          ...(method === 'POST' ? { body: '{}' } : {})
        });
        expect(response.status, method).toBe(503);
        expect(response.headers.get('www-authenticate'), method).toBeNull();
      }
      const logged = stderr.mock.calls.map(([line]) => String(line)).join('');
      expect(logged).toContain('token check failed: 57P01');
      expect(logged).not.toContain('db.internal');
    } finally {
      getToken.mockRestore();
      stderr.mockRestore();
      await new Promise<void>((resolve) => listener.close(() => resolve()));
    }
  });

  // The uptime check on /healthz is the "server down" alert, so a dead database must fail it.
  it('checks the database on /healthz: ok while it answers, a generic 503 when it does not', async () => {
    const port = await freePort();
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const listener = await startHttpServer({
      PORT: String(port),
      XYTE_MCP_ISSUER_URL: `http://127.0.0.1:${port}`,
      XYTE_MCP_HUB_OAUTH_CLIENT_ID: 'mcp-client',
      XYTE_MCP_HUB_OAUTH_CLIENT_SECRET: 'mcp-secret'
    });
    const getClient = vi.spyOn(MemoryOAuthStore.prototype, 'getClient');
    // Only Date is faked: the probe answer is kept for a couple of seconds.
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      const healthy = await fetch(`http://127.0.0.1:${port}/healthz`);
      expect(healthy.status).toBe(200);
      expect(await healthy.text()).toBe('ok');
      expect(getClient).toHaveBeenCalledTimes(1);

      vi.setSystemTime(Date.now() + 3_000);
      getClient.mockRejectedValue(
        Object.assign(new Error('connect ECONNREFUSED db.internal:5432'), { code: 'ECONNREFUSED' })
      );
      const down = await fetch(`http://127.0.0.1:${port}/healthz`);
      expect(down.status).toBe(503);
      expect(await down.text()).toBe('unavailable');
      const logged = stderr.mock.calls.map(([line]) => String(line)).join('');
      expect(logged).toContain('healthz: token store check failed: ECONNREFUSED');
      expect(logged).not.toContain('db.internal');
    } finally {
      vi.useRealTimers();
      getClient.mockRestore();
      stderr.mockRestore();
      await new Promise<void>((resolve) => listener.close(() => resolve()));
    }
  });

  // An unauthenticated flood of probes must not turn into a flood of database queries.
  it('runs at most one database check per couple of seconds on /healthz, however many probes', async () => {
    const port = await freePort();
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const listener = await startHttpServer({
      PORT: String(port),
      XYTE_MCP_ISSUER_URL: `http://127.0.0.1:${port}`,
      XYTE_MCP_HUB_OAUTH_CLIENT_ID: 'mcp-client',
      XYTE_MCP_HUB_OAUTH_CLIENT_SECRET: 'mcp-secret'
    });
    const getClient = vi.spyOn(MemoryOAuthStore.prototype, 'getClient');
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      const probe = () => fetch(`http://127.0.0.1:${port}/healthz`).then((response) => response.status);
      expect(await Promise.all([probe(), probe(), probe()])).toEqual([200, 200, 200]);
      expect(await probe()).toBe(200);
      expect(getClient).toHaveBeenCalledTimes(1);

      vi.setSystemTime(Date.now() + 3_000);
      expect(await probe()).toBe(200);
      expect(getClient).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
      getClient.mockRestore();
      stderr.mockRestore();
      await new Promise<void>((resolve) => listener.close(() => resolve()));
    }
  });

  // Same answer as a failed token check: a client retries instead of reporting a hard error.
  it.skipIf(!PG_URL)('answers a POST and a GET 503 retryable, not a 429 or 500, when the shared rate-limit counter fails', async () => {
    const schema = await createTestSchema(PG_URL!);
    const hub = await startFakeHub();
    const port = await freePort();
    const base = `http://127.0.0.1:${port}`;
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const listener = await startHttpServer(
      serverEnv({ port, issuerUrl: base, hubUrl: hub.url, databaseUrl: schema.databaseUrl, tokenKey: newTokenKey() })
    );
    try {
      const { accessToken } = await signIn(base);
      const count = vi
        .spyOn(PgOAuthStore.prototype, 'countRateLimitHit')
        .mockRejectedValue(Object.assign(new Error('db down at db.internal'), { code: '57P01' }));
      const hubCallsBefore = hub.apiAuth.length;
      const response = await listDevices(base, accessToken);
      expect(response.status).toBe(503);
      expect(await response.json()).toMatchObject({
        error: { code: -32603, message: 'temporarily unavailable, retry' }
      });
      expect(count).toHaveBeenCalledOnce();
      // The 503 stops the request: the tool never runs, so hub sees no call.
      expect(hub.apiAuth.length).toBe(hubCallsBefore);
      const failures = stderr.mock.calls
        .flatMap(([chunk]) => String(chunk).split('\n'))
        .filter((line) => line.includes('rate limit check failed'));
      expect(failures).toHaveLength(1);
      expect(failures[0]).toMatch(/rate limit check failed: 57P01$/);
      expect(failures[0]).not.toContain('db.internal');

      // The GET (app.all) path goes through the same limiter.
      const get = await fetch(`${base}/mcp`, { headers: { Authorization: `Bearer ${accessToken}` } });
      expect(get.status).toBe(503);
      expect(await get.json()).toMatchObject({
        error: { code: -32603, message: 'temporarily unavailable, retry' }
      });
      expect(count).toHaveBeenCalledTimes(2);
    } finally {
      vi.restoreAllMocks();
      await new Promise<void>((resolve) => listener.close(() => resolve()));
      await hub.close();
      await schema.drop();
    }
  });

  it('answers an unexpected throw in the consent flow with a generic 500 page', async () => {
    const port = await freePort();
    const consent = vi
      .spyOn(XyteOAuthProvider.prototype, 'consent')
      .mockRejectedValue(new Error('secret-ish internal detail'));
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const listener = await startHttpServer({
      PORT: String(port),
      XYTE_MCP_ISSUER_URL: `http://127.0.0.1:${port}`,
      XYTE_MCP_HUB_OAUTH_CLIENT_ID: 'mcp-client',
      XYTE_MCP_HUB_OAUTH_CLIENT_SECRET: 'mcp-secret'
    });
    try {
      const response = await fetch(`http://127.0.0.1:${port}/oauth/consent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'pending=x'
      });
      expect(response.status).toBe(500);
      const html = await response.text();
      expect(html).toContain('Sign-in failed');
      expect(html).not.toContain('secret-ish');
      const logged = stderr.mock.calls.map(([line]) => String(line)).join('');
      expect(logged).toContain('{"event":"sign_in","outcome":"failed","reason":"error"}');
    } finally {
      consent.mockRestore();
      stderr.mockRestore();
      await new Promise<void>((resolve) => listener.close(() => resolve()));
    }
  });

  // Windows has no SIGINT delivery via kill(): the child ends at once.
  it.skipIf(process.platform === 'win32')('drains and exits cleanly on SIGINT (local Ctrl+C)', async () => {
    const server = await start();
    expect(await server.signal('SIGINT')).toBe(0);
    expect(server.stderr.join('')).toContain('SIGINT: finishing in-flight requests');
  });
});

describe('http transport: rate bucket secret', () => {
  // The value checks themselves are resolveHttpConfig's (config.test.ts).
  it('refuses to boot on a secret that is not visible ASCII, without naming the value', async () => {
    const secret = 'leaky-secret\nx';
    const port = await freePort();
    const booted = startHttpServer({
      PORT: String(port),
      XYTE_MCP_ISSUER_URL: `http://127.0.0.1:${port}`,
      XYTE_MCP_HUB_OAUTH_CLIENT_ID: 'mcp-client',
      XYTE_MCP_HUB_OAUTH_CLIENT_SECRET: 'mcp-secret',
      XYTE_MCP_RATE_BUCKET_SECRET: secret
    });
    const error = await booted.then(
      (listener) => {
        listener.close();
        throw new Error('booted');
      },
      (rejection: unknown) => rejection as { kind: string; message: string; hints: string[] }
    );
    expect(error.kind).toBe('config');
    expect(error.message).toContain('XYTE_MCP_RATE_BUCKET_SECRET');
    expect(JSON.stringify([error.message, error.hints])).not.toContain('leaky');
  });
});

describe('cli', () => {
  it('rejects an unknown argument with exit code 2', async () => {
    const { code, stderr } = await runToExit(['--bogus'], {});

    expect(code).toBe(2);
    expect(stderr).toContain('unknown argument');
  });

  it('has no --help: it is an unknown argument, exit code 2', async () => {
    const { code, stderr } = await runToExit(['--help'], {});

    expect(code).toBe(2);
    expect(stderr).toContain('unknown argument(s): --help');
  });

  it('prints the version and exits for --version, without listening', async () => {
    const { code, stderr } = await runToExit(['--version'], {});

    expect(code).toBe(0);
    expect(stderr.trim()).toBe(MCP_PACKAGE_VERSION);
  });

  it('prints the version even next to an unknown argument, as --version wins', async () => {
    const { code, stderr } = await runToExit(['--version', '-x'], {});

    expect(code).toBe(0);
    expect(stderr.trim()).toBe(MCP_PACKAGE_VERSION);
  });
});
