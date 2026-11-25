import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { apiCallTool } from '../src/tools/api-call.js';
import { endpointDescribeTool } from '../src/tools/endpoint-describe.js';
import { endpointsListTool } from '../src/tools/endpoints-list.js';
import { APPLICATION_PAUSED_HINT, RATE_LIMITED_HINT, XyteError, XyteHttpError } from '../src/http/errors.js';
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

  it.each([
    [undefined, 'auth: organization key'],
    [{ organization: { accessToken: 'xoat_abcdef123456' } }, 'auth: organization, signed-in user'],
  ])('names the credential in use (%j)', async (credentials, line) => {
    const result = await endpointDescribeTool.handler(
      { key: READ_KEY },
      testContext(credentials ? { credentials } : {})
    );
    expect(result.content[0]?.text).toContain(line);
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

  it('returns data: null for a 204 with no body, so the result matches the output schema', async () => {
    const http = stubHttp(() => ({ status: 204, statusText: 'No Content', data: undefined }));
    const result = await apiCallTool.handler(
      { key: 'partner.coupons.deleteCoupon', path: { id: 'c1' }, confirm: 'partner.coupons.deleteCoupon' },
      testContext({ http, credentials: { partner: 'partner-key-abcdef123456' } })
    );

    expect(result.isError).toBeUndefined();
    const structured = JSON.parse(JSON.stringify(result.structuredContent)) as Record<string, unknown>;
    expect(structured).toHaveProperty('data', null);
    expect(z.object(apiCallTool.outputSchema ?? {}).safeParse(structured).success).toBe(true);
  });

  it('hints that the endpoint is missing on this hub when the hub does not know the path', async () => {
    const http = stubHttp(
      () => new XyteHttpError(404, 'Not Found', { error: 'Requested path /core/v1/partner/coupons does not exist' }, 'partner.coupons.getCoupons')
    );
    const result = await apiCallTool.handler(
      { key: 'partner.coupons.getCoupons' },
      testContext({ http, credentials: { partner: 'partner-key-abcdef123456' } })
    );

    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain('not available on this hub');
    expect(result.content[0]?.text).not.toContain('the resource may not exist');
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

  const API_KEY_HINT = 'The API key may be invalid, revoked, or lack the required scope.';
  const IDS_HINT =
    'This is not a sign-in problem: check the ids in the request — the item may not be in this organization.';
  const ADMIN_HINT =
    'Only an organization administrator can do this. Ask an administrator of your organization.';
  const NO_ACCESS_HINT =
    'You have no access to this item. Ask an organization administrator for access.';
  const SIGN_IN_HINT =
    'The Xyte sign-in behind this connection has ended. Reconnect the Xyte connector to sign in again.';
  const SIGNED_IN_HINTS = [IDS_HINT, ADMIN_HINT, NO_ACCESS_HINT, SIGN_IN_HINT, APPLICATION_PAUSED_HINT];

  it.each([401, 403])('keeps the API-key hint on %i in API-key mode', async (status) => {
    const http = stubHttp(() => new XyteHttpError(status, 'Denied', { error: 'nope' }, READ_KEY));
    const result = await apiCallTool.handler({ key: READ_KEY }, testContext({ http }));
    expect(result.content[0]?.text).toContain(API_KEY_HINT);
  });

  it.each([
    [403, { error_code: 'organization_administrator_required', error: 'x' }, undefined],
    [403, { error_code: 'application_paused', error: 'x' }, undefined],
    [401, { error: 'x' }, 'Bearer error="invalid_token"']
  ])(
    'gives only the API-key hint on %i %j %s in API-key mode',
    async (status, body, wwwAuthenticate) => {
      const http = stubHttp(
        () => new XyteHttpError(status, 'Denied', body, READ_KEY, wwwAuthenticate)
      );
      const result = await apiCallTool.handler({ key: READ_KEY }, testContext({ http }));
      const text = result.content[0]?.text;
      expect(text).toContain(API_KEY_HINT);
      for (const hint of SIGNED_IN_HINTS) expect(text).not.toContain(hint);
    }
  );

  it.each([
    ['API key', undefined],
    ['signed in', { organization: { accessToken: 'xoat_abcdef123456' } }]
  ])('tells the model to wait on a hub 429 (%s)', async (_mode, credentials) => {
    const http = stubHttp(() => new XyteHttpError(429, 'Too Many Requests', {}, READ_KEY));
    const result = await apiCallTool.handler(
      { key: READ_KEY },
      testContext({ http, ...(credentials ? { credentials } : {}) })
    );
    expect(result.isError).toBe(true);
    // Exactly one hint, the rate limit one: no API-key or sign-in hint.
    expect(result.content[0]?.text).toBe(
      `${READ_KEY} failed: 429 Too Many Requests\n\n{}\n\n- ${RATE_LIMITED_HINT}`
    );
  });

  // A hub redirect (the secret set, XYTE_HUB_URL not the final address) is not an auth or rate problem.
  it.each([
    ['API key', undefined],
    ['signed in', { organization: { accessToken: 'xoat_abcdef123456' } }]
  ])('gives a hub 302 no hint (%s)', async (_mode, credentials) => {
    const http = stubHttp(() => new XyteHttpError(302, 'Found', {}, READ_KEY));
    const result = await apiCallTool.handler(
      { key: READ_KEY },
      testContext({ http, ...(credentials ? { credentials } : {}) })
    );
    expect(result.isError).toBe(true);
    const text = result.content[0]?.text;
    expect(text).toContain('302');
    for (const hint of [RATE_LIMITED_HINT, API_KEY_HINT, ...SIGNED_IN_HINTS]) expect(text).not.toContain(hint);
  });

  describe('signed in with Xyte', () => {
    const signedIn = (error: XyteHttpError) =>
      testContext({
        http: stubHttp(() => error),
        credentials: { organization: { accessToken: 'xoat_abcdef123456' } }
      });
    const expectNoHint = (text: string | undefined) => {
      expect(text).not.toContain('\n- ');
      for (const hint of [API_KEY_HINT, ...SIGNED_IN_HINTS]) expect(text).not.toContain(hint);
    };

    it.each([
      [403, { error_code: 'organization_administrator_required', error: 'x' }, undefined, ADMIN_HINT],
      [403, { error_code: 'no_access_to_resource', error: 'x' }, undefined, NO_ACCESS_HINT],
      [403, { error_code: 'application_paused', error: 'x' }, undefined, APPLICATION_PAUSED_HINT],
      [
        401,
        { error: 'x' },
        'Bearer error="invalid_token", error_description="expired"',
        SIGN_IN_HINT
      ],
      [401, { error: 'x' }, 'Bearer realm="xyte", error="invalid_token"', SIGN_IN_HINT],
      [401, { error: 'x' }, undefined, IDS_HINT],
      [401, { error: 'x' }, '', IDS_HINT]
    ])('%i %j %s gives its own hint', async (status, body, wwwAuthenticate, hint) => {
      const error = new XyteHttpError(status, 'Denied', body, READ_KEY, wwwAuthenticate);
      const result = await apiCallTool.handler({ key: READ_KEY }, signedIn(error));
      const text = result.content[0]?.text;
      expect(text).toContain(hint);
      expect(text).toContain(JSON.stringify(body, null, 2));
      expect(text).not.toContain(API_KEY_HINT);
    });

    it('gives no hint on a 401 with another challenge', async () => {
      const error = new XyteHttpError(
        401,
        'Unauthorized',
        { error: 'x' },
        READ_KEY,
        'Bearer error="insufficient_scope"'
      );
      const result = await apiCallTool.handler({ key: READ_KEY }, signedIn(error));
      expect(result.isError).toBe(true);
      expectNoHint(result.content[0]?.text);
    });

    it('gives no hint on another 403', async () => {
      const error = new XyteHttpError(403, 'Forbidden', { error_code: 'other' }, READ_KEY);
      const result = await apiCallTool.handler({ key: READ_KEY }, signedIn(error));
      expect(result.isError).toBe(true);
      expectNoHint(result.content[0]?.text);
    });

    it.each(['Forbidden', null])('gives no hint on a 403 with body %j', async (body) => {
      const error = new XyteHttpError(403, 'Forbidden', body, READ_KEY);
      const result = await apiCallTool.handler({ key: READ_KEY }, signedIn(error));
      expect(result.isError).toBe(true);
      expectNoHint(result.content[0]?.text);
    });

    it('keeps the endpoint-describe hint on 422', async () => {
      const error = new XyteHttpError(422, 'Unprocessable', { error: 'x' }, READ_KEY);
      const result = await apiCallTool.handler({ key: READ_KEY }, signedIn(error));
      const text = result.content[0]?.text;
      expect(text).toContain(`Run xyte_endpoint_describe on ${READ_KEY} to check the expected arguments.`);
      expect(text).not.toContain(API_KEY_HINT);
    });

    it('keeps the path-parameter hint on 404', async () => {
      const error = new XyteHttpError(404, 'Not Found', { error: 'x' }, READ_KEY);
      const result = await apiCallTool.handler({ key: READ_KEY }, signedIn(error));
      expect(result.content[0]?.text).toContain(
        'Check the path parameter values — the resource may not exist.'
      );
    });
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

describe('xyte_api_call write log line', () => {
  const SECRET = 'org-key-abcdef123456';
  let stderr: string[];

  beforeEach(() => {
    stderr = [];
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stderr.push(String(chunk));
      return true;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('writes one line with key, method, status and duration for a successful write', async () => {
    const http = stubHttp(() => ({ status: 201, data: { id: 'cmd1', secret_note: 'body-xyz' } }));
    await apiCallTool.handler(
      { key: WRITE_KEY, path: { device_id: 'd1' }, body: { name: 'reboot-body-abc' } },
      testContext({ http })
    );

    expect(stderr).toHaveLength(1);
    expect(stderr[0]).toMatch(
      new RegExp(`^\\[xyte-mcp\\] write ${WRITE_KEY} POST status=201 duration_ms=\\d+\\n$`)
    );
    expect(stderr[0]).not.toContain(SECRET);
    expect(stderr[0]).not.toContain('reboot-body-abc');
    expect(stderr[0]).not.toContain('body-xyz');
  });

  it('logs the HTTP status of a failed write, without the error body', async () => {
    const http = stubHttp(
      () => new XyteHttpError(422, 'Unprocessable', { error: 'body-xyz', key: SECRET }, WRITE_KEY)
    );
    await apiCallTool.handler(
      { key: WRITE_KEY, path: { device_id: 'd1' }, body: { name: 'reboot' } },
      testContext({ http })
    );

    expect(stderr).toHaveLength(1);
    expect(stderr[0]).toMatch(/ POST status=422 duration_ms=\d+\n$/);
    expect(stderr[0]).not.toContain('body-xyz');
    expect(stderr[0]).not.toContain(SECRET);
  });

  it('logs status=error when a write fails without an HTTP status (it may have landed)', async () => {
    const http = stubHttp(() => new XyteError('timeout', 'request timed out'));
    await apiCallTool.handler(
      { key: WRITE_KEY, path: { device_id: 'd1' }, body: { name: 'reboot' } },
      testContext({ http })
    );

    expect(stderr).toHaveLength(1);
    expect(stderr[0]).toMatch(/ POST status=error duration_ms=\d+\n$/);
  });

  it('logs a 204 DELETE with its status', async () => {
    const http = stubHttp(() => ({ status: 204, statusText: 'No Content', data: undefined }));
    await apiCallTool.handler(
      { key: 'partner.coupons.deleteCoupon', path: { id: 'c1' }, confirm: 'partner.coupons.deleteCoupon' },
      testContext({ http, credentials: { partner: 'partner-key-abcdef123456' } })
    );

    expect(stderr).toHaveLength(1);
    expect(stderr[0]).toMatch(/ write partner\.coupons\.deleteCoupon DELETE status=204 duration_ms=\d+\n$/);
  });

  it('writes nothing for a read, a refused write or a write that fails validation', async () => {
    const read = await apiCallTool.handler({ key: READ_KEY }, testContext());
    const readOnlyRefusal = await apiCallTool.handler(
      { key: WRITE_KEY, path: { device_id: 'd1' }, body: {} },
      testContext({ allowWrites: false })
    );
    const deleteWithoutConfirm = await apiCallTool.handler(
      { key: 'partner.coupons.deleteCoupon', path: { id: 'c1' } },
      testContext({ credentials: { partner: 'partner-key-abcdef123456' } })
    );
    const invalid = await apiCallTool.handler({ key: WRITE_KEY, body: {} }, testContext());

    expect(read.isError).toBeUndefined();
    expect(readOnlyRefusal.isError).toBe(true);
    expect(readOnlyRefusal.content[0]?.text).toContain('read-only');
    expect(deleteWithoutConfirm.isError).toBe(true);
    expect(deleteWithoutConfirm.content[0]?.text).toContain('confirm');
    expect(invalid.isError).toBe(true);
    expect(invalid.content[0]?.text).toContain('device_id');
    expect(stderr).toEqual([]);
  });
});
