import { describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { XyteHttpError } from '../src/http/errors.js';
import { createServer, type ToolCallRecord } from '../src/server.js';
import { stubHttp, testContext } from './support/context.js';
import type { ToolContext } from '../src/context.js';

/** One tool call over an in-memory MCP connection; returns what the hook saw. */
async function callWithHook(
  context: ToolContext,
  name: string,
  args: Record<string, unknown>
): Promise<ToolCallRecord[]> {
  const records: ToolCallRecord[] = [];
  const server = createServer(context, { onToolCall: (record) => records.push(record) });
  const client = new Client({ name: 'test', version: '0.0.0' });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
  try {
    await client.callTool({ name, arguments: args });
  } finally {
    await client.close();
  }
  return records;
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
});
