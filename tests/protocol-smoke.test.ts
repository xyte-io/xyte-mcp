import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

/**
 * Drives a real server process over stdio, exercising the actual protocol
 * framing rather than calling handlers directly.
 *
 * Also asserts the property that is easy to break and fatal in production: only
 * JSON-RPC ever reaches stdout.
 */

const DIST_ENTRY = path.resolve(import.meta.dirname, '..', 'dist', 'index.js');
const PROTOCOL_VERSION = '2025-06-18';

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: number;
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
}

class ServerHarness {
  private readonly child: ChildProcessWithoutNullStreams;
  private buffer = '';
  readonly stdoutLines: string[] = [];
  readonly stderr: string[] = [];
  private readonly waiters = new Map<number, (response: JsonRpcResponse) => void>();

  constructor(env: Record<string, string>) {
    this.child = spawn(process.execPath, [DIST_ENTRY], {
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe']
    }) as ChildProcessWithoutNullStreams;

    this.child.stdout.setEncoding('utf8');
    this.child.stdout.on('data', (chunk: string) => {
      this.buffer += chunk;
      let index = this.buffer.indexOf('\n');
      while (index !== -1) {
        const line = this.buffer.slice(0, index).trim();
        this.buffer = this.buffer.slice(index + 1);
        if (line) this.handleLine(line);
        index = this.buffer.indexOf('\n');
      }
    });

    this.child.stderr.setEncoding('utf8');
    this.child.stderr.on('data', (chunk: string) => this.stderr.push(chunk));
  }

  private handleLine(line: string): void {
    this.stdoutLines.push(line);
    let parsed: JsonRpcResponse;
    try {
      parsed = JSON.parse(line) as JsonRpcResponse;
    } catch {
      return; // Non-JSON on stdout is asserted against separately.
    }
    const waiter = this.waiters.get(parsed.id);
    if (waiter) {
      this.waiters.delete(parsed.id);
      waiter(parsed);
    }
  }

  send(message: Record<string, unknown>): void {
    this.child.stdin.write(`${JSON.stringify(message)}\n`);
  }

  request(id: number, method: string, params?: Record<string, unknown>): Promise<JsonRpcResponse> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`timed out waiting for ${method}\nstderr: ${this.stderr.join('')}`)),
        10_000
      );
      this.waiters.set(id, (response) => {
        clearTimeout(timer);
        resolve(response);
      });
      this.send({ jsonrpc: '2.0', id, method, ...(params ? { params } : {}) });
    });
  }

  async handshake(): Promise<JsonRpcResponse> {
    const response = await this.request(1, 'initialize', {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'xyte-mcp-test', version: '0.0.0' }
    });
    this.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    return response;
  }

  kill(): void {
    this.child.kill('SIGKILL');
  }
}

let harness: ServerHarness | undefined;

function start(env: Record<string, string> = {}): ServerHarness {
  harness = new ServerHarness({
    XYTE_ORG_API_KEY: 'org-key-abcdef123456',
    ...env
  });
  return harness;
}

beforeAll(() => {
  if (!existsSync(DIST_ENTRY)) {
    throw new Error(`Build first: ${DIST_ENTRY} is missing (npm run build).`);
  }
});

afterEach(() => {
  harness?.kill();
  harness = undefined;
});

describe('stdio protocol', () => {
  it('completes the initialize handshake', async () => {
    const server = start();
    const response = await server.handshake();

    expect(response.error).toBeUndefined();
    expect(response.result?.protocolVersion).toBeDefined();
    expect(response.result?.serverInfo).toMatchObject({ name: 'xyte-mcp' });
    expect(response.result?.instructions).toContain('READ-ONLY');
  });

  it('advertises exactly the three tools, with schemas', async () => {
    const server = start();
    await server.handshake();
    const response = await server.request(2, 'tools/list');

    const tools = response.result?.tools as Array<{
      name: string;
      inputSchema: { type: string; properties?: Record<string, unknown> };
      annotations?: Record<string, unknown>;
    }>;
    expect(tools.map((tool) => tool.name).sort()).toEqual([
      'xyte_api_call',
      'xyte_endpoint_describe',
      'xyte_endpoints_list'
    ]);

    for (const tool of tools) {
      expect(tool.inputSchema.type, tool.name).toBe('object');
    }

    const apiCall = tools.find((tool) => tool.name === 'xyte_api_call');
    expect(apiCall?.inputSchema.properties).toHaveProperty('key');
    // Read-only server: the host should be told the tool cannot mutate.
    expect(apiCall?.annotations?.readOnlyHint).toBe(true);
  });

  it('runs a discovery tool end to end', async () => {
    const server = start();
    await server.handshake();
    const response = await server.request(3, 'tools/call', {
      name: 'xyte_endpoints_list',
      arguments: { namespace: 'partner' }
    });

    const result = response.result as {
      isError?: boolean;
      structuredContent?: { count: number };
      content: Array<{ type: string; text: string }>;
    };
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent?.count).toBeGreaterThan(0);
    expect(result.content[0]?.text).toContain('partner.');
  });

  it('rejects a mutating call through the real protocol path', async () => {
    const server = start();
    await server.handshake();
    const response = await server.request(4, 'tools/call', {
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

  it('reports invalid tool arguments as an error result', async () => {
    const server = start();
    await server.handshake();
    const response = await server.request(5, 'tools/call', {
      name: 'xyte_endpoint_describe',
      arguments: {} // `key` is required
    });

    const failed =
      response.error !== undefined || (response.result as { isError?: boolean }).isError === true;
    expect(failed).toBe(true);
  });

  it('advertises writes in its instructions when enabled', async () => {
    const server = start({ XYTE_MCP_ALLOW_WRITES: '1' });
    const response = await server.handshake();
    expect(response.result?.instructions).toContain('ENABLED');
  });

  it('writes only JSON-RPC to stdout and diagnostics to stderr', async () => {
    const server = start();
    await server.handshake();
    await server.request(6, 'tools/list');

    expect(server.stdoutLines.length).toBeGreaterThan(0);
    for (const line of server.stdoutLines) {
      expect(() => JSON.parse(line) as unknown, `stdout line: ${line}`).not.toThrow();
    }
    // The readiness banner must not have gone to stdout.
    expect(server.stderr.join('')).toContain('xyte-mcp ready over stdio');
  });

  it('never leaks the API key over the wire', async () => {
    const server = start();
    await server.handshake();
    await server.request(7, 'tools/call', {
      name: 'xyte_endpoint_describe',
      arguments: { key: 'organization.devices.getDevices' }
    });

    expect(server.stdoutLines.join('\n')).not.toContain('org-key-abcdef123456');
    expect(server.stderr.join('')).not.toContain('org-key-abcdef123456');
  });
});
