import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createServer } from 'node:net';
import path from 'node:path';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

/**
 * Drives a real `--http` server process over the network, so this covers the
 * transport selection, the auth boundary and the JSON-RPC framing together —
 * the same reasoning as `protocol-smoke.test.ts` does for stdio.
 */

const DIST_ENTRY = path.resolve(import.meta.dirname, '..', 'dist', 'index.js');
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
    const child = spawn(process.execPath, [DIST_ENTRY, '--http'], {
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

  /** Poll /healthz rather than sleeping: a fixed delay is either slow or flaky. */
  private async awaitReady(): Promise<void> {
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      if (this.child.exitCode !== null) {
        throw new Error(`server exited (${this.child.exitCode})\n${this.stderr.join('')}`);
      }
      try {
        if ((await fetch(`${this.base}/healthz`)).ok) return;
      } catch {
        // Not listening yet.
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error(`server never became ready\n${this.stderr.join('')}`);
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
}

let harness: HttpHarness | undefined;

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
      error: { message: 'unauthorized' }
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

  it('never echoes the bearer token or the API key back to the caller', async () => {
    const server = await start();
    const body = await (await server.post({}, { token: 'nope' })).text();

    expect(body).not.toContain(TOKEN);
    expect(body).not.toContain(ORG_KEY);
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
    }
  });

  it('still requires a token for a non-POST method', async () => {
    const server = await start();
    const response = await fetch(`${server.base}/mcp`, { method: 'GET', headers: MCP_HEADERS });

    expect(response.status).toBe(401);
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
  });

  it('refuses a mutating endpoint when started read-only', async () => {
    const server = await start({ XYTE_MCP_READ_ONLY: '1' });
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

  it('warns on stderr when writes are enabled on a network transport', async () => {
    const server = await start();
    expect(server.stderr.join('')).toContain('WARNING: writes are enabled');
  });

  it('refuses to start without a bearer token, naming the variable', async () => {
    const child = spawn(process.execPath, [DIST_ENTRY, '--http'], {
      env: { ...process.env, PORT: '0', XYTE_ORG_API_KEY: ORG_KEY, XYTE_MCP_HTTP_TOKEN: '' },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stderr = '';
    child.stderr?.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
    const code = await new Promise<number | null>((resolve) => child.on('exit', resolve));

    expect(code).toBe(1);
    expect(stderr).toContain('XYTE_MCP_HTTP_TOKEN');
  });
});
