import { describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { XyteError, XyteHttpError } from '../src/http/errors.js';
import { createServer, TOOLS, type ToolCallRecord } from '../src/server.js';
import { textResult, type AnyToolDefinition } from '../src/tools/types.js';
import { stubHttp, testContext } from './support/context.js';
import type { ToolContext } from '../src/context.js';
import type { HttpRequest } from '../src/http/client.js';

/** One tool call over an in-memory MCP connection. */
async function callTool(server: McpServer, name: string, args: Record<string, unknown>): Promise<void> {
  const client = new Client({ name: 'test', version: '0.0.0' });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
  try {
    await client.callTool({ name, arguments: args });
  } finally {
    await client.close();
  }
}

/** One tool call; returns what the hook saw. */
async function callWithHook(
  context: ToolContext,
  name: string,
  args: Record<string, unknown>
): Promise<ToolCallRecord[]> {
  const records: ToolCallRecord[] = [];
  await callTool(createServer(context, { onToolCall: (record) => records.push(record) }), name, args);
  return records;
}

/** Runs `run` with an extra test-only tool registered next to the real ones. */
async function withTestTool<T>(
  handler: AnyToolDefinition['handler'],
  run: () => Promise<T>
): Promise<T> {
  TOOLS.push({
    name: 'test_tool',
    title: 'Test tool',
    description: 'test only',
    inputSchema: {},
    annotations: () => ({}),
    handler
  });
  try {
    return await run();
  } finally {
    TOOLS.pop();
  }
}

function hubRequest(endpointKey: string): HttpRequest {
  return { method: 'GET', url: 'https://hub.invalid/x', headers: {}, endpointKey };
}

describe('createServer onToolCall', () => {
  it('reports the tool, the hub endpoint and its status for a successful call', async () => {
    const records = await callWithHook(testContext(), 'xyte_api_call', {
      key: 'organization.devices.getDevices'
    });
    expect(records).toEqual([
      {
        tool: 'xyte_api_call',
        endpoint: 'organization.devices.getDevices',
        status: 200,
        isError: false,
        durationMs: expect.any(Number)
      }
    ]);
  });

  it('reports the hub status of a failed call as an error', async () => {
    const http = stubHttp(() => new XyteHttpError(429, 'Too Many Requests', {}, 'k'));
    const records = await callWithHook(testContext({ http }), 'xyte_api_call', {
      key: 'organization.devices.getDevices'
    });
    expect(records).toMatchObject([
      { tool: 'xyte_api_call', endpoint: 'organization.devices.getDevices', status: 429, isError: true }
    ]);
  });

  it('reports no endpoint or status when the tool makes no hub call', async () => {
    const records = await callWithHook(testContext(), 'xyte_endpoints_list', {});
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ tool: 'xyte_endpoints_list', isError: false });
    expect(records[0]!.endpoint).toBeUndefined();
    expect(records[0]!.status).toBeUndefined();
  });

  it('reports a network error as an error with the endpoint and no status', async () => {
    const http = stubHttp(() => new XyteError('network', 'connection reset'));
    const records = await callWithHook(testContext({ http }), 'xyte_api_call', {
      key: 'organization.devices.getDevices'
    });
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      tool: 'xyte_api_call',
      endpoint: 'organization.devices.getDevices',
      isError: true
    });
    expect(records[0]!.status).toBeUndefined();
  });

  it('reports the last of several hub requests, with its status', async () => {
    const http = stubHttp((request) => ({ status: request.endpointKey === 'first' ? 200 : 204 }));
    const records = await withTestTool(
      async (_args, context) => {
        await context.http.request(hubRequest('first'));
        await context.http.request(hubRequest('second'));
        return textResult('done');
      },
      () => callWithHook(testContext({ http }), 'test_tool', {})
    );
    expect(records).toMatchObject([{ endpoint: 'second', status: 204, isError: false }]);
  });

  it('drops the earlier status when the last hub request gets no answer', async () => {
    const http = stubHttp((request) =>
      request.endpointKey === 'first' ? { status: 200 } : new XyteError('timeout', 'timed out')
    );
    const records = await withTestTool(
      async (_args, context) => {
        await context.http.request(hubRequest('first'));
        await context.http.request(hubRequest('second')).catch(() => undefined);
        return textResult('done');
      },
      () => callWithHook(testContext({ http }), 'test_tool', {})
    );
    expect(records).toHaveLength(1);
    expect(records[0]!.endpoint).toBe('second');
    expect(records[0]!.status).toBeUndefined();
  });

  it('still reports a call whose handler throws, as an error', async () => {
    const records = await withTestTool(
      async (_args, context) => {
        await context.http.request(hubRequest('first'));
        throw new Error('handler bug');
      },
      () => callWithHook(testContext(), 'test_tool', {})
    );
    expect(records).toMatchObject([{ tool: 'test_tool', endpoint: 'first', status: 200, isError: true }]);
  });
});

describe('createServer without hooks', () => {
  it('hands the handler the original hub client', async () => {
    const context = testContext();
    let seen: unknown;
    await withTestTool(
      (_args, handlerContext) => {
        seen = handlerContext.http;
        return textResult('done');
      },
      () => callTool(createServer(context), 'test_tool', {})
    );
    expect(seen).toBe(context.http);
  });
});
