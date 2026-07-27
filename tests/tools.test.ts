import { describe, expect, it } from 'vitest';
import { apiCallTool } from '../src/tools/api-call.js';
import { endpointDescribeTool } from '../src/tools/endpoint-describe.js';
import { endpointsListTool } from '../src/tools/endpoints-list.js';
import { XyteHttpError } from '../src/http/errors.js';
import { REDACTED } from '../src/redact.js';
import { stubHttp, testContext } from './support/context.js';

const READ_KEY = 'organization.devices.getDevices';
const WRITE_KEY = 'organization.commands.sendCommand';

describe('xyte_endpoints_list', () => {
  it('returns compact rows and a total', async () => {
    // Handlers may be sync or async; awaiting covers both.
    const result = await endpointsListTool.handler({}, testContext());
    const structured = result.structuredContent as { count: number; endpoints: unknown[] };
    expect(structured.count).toBeGreaterThan(50);
    expect(structured.endpoints).toHaveLength(structured.count);
    expect(result.isError).toBeUndefined();
  });

  it('narrows by search', async () => {
    const result = await endpointsListTool.handler({ search: 'incident' }, testContext());
    const structured = result.structuredContent as { count: number };
    const all = (await endpointsListTool.handler({}, testContext())).structuredContent as {
      count: number;
    };
    expect(structured.count).toBeGreaterThan(0);
    expect(structured.count).toBeLessThan(all.count);
  });

  it('reports no matches without erroring, and names the groups', async () => {
    const result = await endpointsListTool.handler({ search: 'zzzznope' }, testContext());
    expect(result.isError).toBeUndefined();
    expect(result.content[0]?.text).toContain('No endpoints matched');
    expect(result.content[0]?.text).toContain('devices');
  });

  it('is annotated read-only', () => {
    expect(endpointsListTool.annotations(testContext()).readOnlyHint).toBe(true);
  });
});

describe('xyte_endpoint_describe', () => {
  it('describes a known endpoint', async () => {
    const result = await endpointDescribeTool.handler({ key: READ_KEY }, testContext());
    const structured = result.structuredContent as Record<string, unknown>;
    expect(structured.key).toBe(READ_KEY);
    expect(structured.method).toBe('GET');
    expect(structured.mutating).toBe(false);
    expect(structured.url).toContain('https://hub.xyte.io');
  });

  it('errors with suggestions on a near-miss key', async () => {
    // `getDevice` (singular) is a real endpoint, so use a name that truly is not.
    const result = await endpointDescribeTool.handler(
      { key: 'organization.devices.listDevices' },
      testContext()
    );
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain('Did you mean');
    expect(result.content[0]?.text).toContain('organization.devices.');
  });

  it('says a mutating endpoint will be refused when read-only', async () => {
    const result = await endpointDescribeTool.handler(
      { key: WRITE_KEY },
      testContext({ allowWrites: false })
    );
    expect(result.content[0]?.text).toContain('running read-only');
  });

  it('says writes are enabled for a mutating endpoint under the default posture', async () => {
    const result = await endpointDescribeTool.handler({ key: WRITE_KEY }, testContext());
    expect(result.content[0]?.text).toContain('Writes are enabled');
  });

  it('tells the caller to pass confirm for a DELETE when writes are on', async () => {
    const context = testContext({ allowWrites: true });
    const result = await endpointDescribeTool.handler(
      { key: 'organization.devices.deleteDevice' },
      context
    );
    const structured = result.structuredContent as { requiresConfirm: boolean };
    expect(structured.requiresConfirm).toBe(true);
    expect(result.content[0]?.text).toContain('confirm:');
  });
});

describe('xyte_api_call', () => {
  it('calls a read endpoint and returns the payload', async () => {
    const http = stubHttp(() => ({ status: 200, data: { devices: [{ id: 'd1' }] } }));
    const result = await apiCallTool.handler({ key: READ_KEY }, testContext({ http }));

    expect(result.isError).toBeUndefined();
    expect(http.calls).toHaveLength(1);
    expect(http.calls[0]?.method).toBe('GET');
    const structured = result.structuredContent as { status: number; data: unknown };
    expect(structured.status).toBe(200);
    expect(structured.data).toEqual({ devices: [{ id: 'd1' }] });
  });

  it('refuses a mutating endpoint in read-only mode, without calling out', async () => {
    const http = stubHttp(() => ({ data: {} }));
    const result = await apiCallTool.handler(
      { key: WRITE_KEY, path: { device_id: 'd1' }, body: { name: 'reboot' } },
      testContext({ http, allowWrites: false })
    );

    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain('read-only');
    expect(http.calls).toHaveLength(0);
  });

  it('performs the mutating call under the default write posture', async () => {
    const http = stubHttp(() => ({ status: 201, data: { id: 'cmd1' } }));
    const result = await apiCallTool.handler(
      { key: WRITE_KEY, path: { device_id: 'd1' }, body: { name: 'reboot' } },
      testContext({ http })
    );

    expect(result.isError).toBeUndefined();
    expect(http.calls).toHaveLength(1);
    expect(http.calls[0]?.method).toBe('POST');
    expect(http.calls[0]?.body).toBe('{"name":"reboot"}');
  });

  it('refuses an unknown endpoint with suggestions', async () => {
    const result = await apiCallTool.handler({ key: 'organization.devices.list' }, testContext());
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain('Unknown endpoint key');
  });

  it('surfaces a validation failure without calling out', async () => {
    const http = stubHttp(() => ({ data: {} }));
    const result = await apiCallTool.handler(
      { key: READ_KEY, query: { not_a_param: 1 } },
      testContext({ http })
    );
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain('does not accept query parameter');
    expect(http.calls).toHaveLength(0);
  });

  it('turns an HTTP error into a readable result with a hint', async () => {
    const http = stubHttp(
      () => new XyteHttpError(401, 'Unauthorized', { error: 'bad key' }, READ_KEY)
    );
    const result = await apiCallTool.handler({ key: READ_KEY }, testContext({ http }));
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain('401');
    expect(result.content[0]?.text).toContain('revoked');
  });

  it('never echoes the API key back, even if the API returns it', async () => {
    const secret = 'org-key-abcdef123456';
    const http = stubHttp(() => ({ data: { echoed: secret, api_key: 'something' } }));
    const result = await apiCallTool.handler({ key: READ_KEY }, testContext({ http }));

    const text = JSON.stringify(result);
    expect(text).not.toContain(secret);
    const structured = result.structuredContent as { data: Record<string, unknown> };
    expect(structured.data.echoed).toBe(REDACTED);
    expect(structured.data.api_key).toBe(REDACTED);
  });

  it('flips its annotations with the write policy', () => {
    expect(apiCallTool.annotations(testContext({ allowWrites: false }))).toMatchObject({
      readOnlyHint: true,
      destructiveHint: false
    });
    expect(apiCallTool.annotations(testContext({ allowWrites: true }))).toMatchObject({
      readOnlyHint: false,
      destructiveHint: true
    });
  });
});
