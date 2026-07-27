import { describe, expect, it } from 'vitest';
import { buildRequest } from '../src/http/build-request.js';
import { XyteError } from '../src/http/errors.js';
import { getEndpoint } from '../src/catalog/catalog.js';
import { testContext } from './support/context.js';
import type { EndpointSpec } from '../src/catalog/types.js';

function spec(overrides: Partial<EndpointSpec> = {}): EndpointSpec {
  return {
    key: 'organization.devices.getDevice',
    namespace: 'organization',
    group: 'devices',
    action: 'getDevice',
    title: 'Get Device',
    method: 'GET',
    base: 'hub',
    pathTemplate: '/core/v1/organization/devices/:device_id',
    pathParams: ['device_id'],
    queryParams: ['page', 'per_page'],
    authScope: 'organization',
    bodyType: 'none',
    mutating: false,
    sourceFile: 'fixture.bru',
    ...overrides
  };
}

describe('buildRequest', () => {
  it('substitutes path parameters', () => {
    const request = buildRequest(spec(), { path: { device_id: 'abc' } }, testContext());
    expect(request.url).toBe('https://hub.xyte.io/core/v1/organization/devices/abc');
    expect(request.method).toBe('GET');
  });

  it('percent-encodes path parameter values', () => {
    const request = buildRequest(spec(), { path: { device_id: 'a/b c' } }, testContext());
    expect(request.url).toBe('https://hub.xyte.io/core/v1/organization/devices/a%2Fb%20c');
  });

  it('accepts numeric path parameters', () => {
    const request = buildRequest(spec(), { path: { device_id: 42 } }, testContext());
    expect(request.url).toMatch(/\/devices\/42$/);
  });

  it('sends the bare API key with no Bearer scheme', () => {
    // The hub rejects a "Bearer <key>" Authorization header.
    const request = buildRequest(spec(), { path: { device_id: 'abc' } }, testContext());
    expect(request.headers.Authorization).toBe('org-key-abcdef123456');
  });

  it('appends query parameters', () => {
    const request = buildRequest(
      spec(),
      { path: { device_id: 'abc' }, query: { page: 2, per_page: 50 } },
      testContext()
    );
    expect(request.url).toContain('page=2');
    expect(request.url).toContain('per_page=50');
  });

  it('honours a base URL override', () => {
    const context = testContext({
      baseUrls: { hub: 'http://localhost:3001', entry: 'http://localhost:3002' }
    });
    const request = buildRequest(spec(), { path: { device_id: 'abc' } }, context);
    expect(request.url).toBe('http://localhost:3001/core/v1/organization/devices/abc');
  });

  it('rejects a missing path parameter', () => {
    expect(() => buildRequest(spec(), {}, testContext())).toThrow(/missing required path/i);
  });

  it('rejects an empty path parameter', () => {
    expect(() => buildRequest(spec(), { path: { device_id: '  ' } }, testContext())).toThrow(
      /is empty/i
    );
  });

  it('rejects an unknown path parameter', () => {
    expect(() =>
      buildRequest(spec(), { path: { device_id: 'a', bogus: 'b' } }, testContext())
    ).toThrow(/does not accept path parameter/i);
  });

  it('rejects an unknown query parameter before hitting the network', () => {
    expect(() =>
      buildRequest(spec(), { path: { device_id: 'a' }, query: { nope: 1 } }, testContext())
    ).toThrow(/does not accept query parameter/i);
  });

  it('rejects a body on a GET endpoint', () => {
    // Some Bruno files declare body:json on GETs as a copy-paste artifact; a GET
    // must still never carry one.
    expect(() =>
      buildRequest(
        spec({ bodyType: 'json' }),
        { path: { device_id: 'a' }, body: { x: 1 } },
        testContext()
      )
    ).toThrow(/does not take a request body/i);
  });

  it('serialises a JSON body on POST and sets Content-Type', () => {
    const request = buildRequest(
      spec({ method: 'POST', mutating: true, bodyType: 'json', pathParams: [], pathTemplate: '/core/v1/organization/devices', queryParams: [] }),
      { body: { name: 'reboot' } },
      testContext()
    );
    expect(request.headers['Content-Type']).toBe('application/json');
    expect(request.body).toBe('{"name":"reboot"}');
  });

  it('omits Content-Type when a mutating call has no body', () => {
    const request = buildRequest(
      spec({ method: 'POST', mutating: true, pathParams: [], pathTemplate: '/core/v1/x', queryParams: [] }),
      {},
      testContext()
    );
    expect(request.headers['Content-Type']).toBeUndefined();
    expect(request.body).toBeUndefined();
  });

  it('fails with an actionable message when the needed scope has no key', () => {
    const context = testContext({ credentials: { organization: 'org-key-abcdef123456' } });
    const partnerEndpoint = spec({
      key: 'partner.devices.getDevices',
      namespace: 'partner',
      authScope: 'partner',
      pathParams: [],
      pathTemplate: '/core/v1/partner/devices',
      queryParams: []
    });
    let caught: unknown;
    try {
      buildRequest(partnerEndpoint, {}, context);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(XyteError);
    expect((caught as XyteError).kind).toBe('config');
    expect((caught as XyteError).hints.join(' ')).toContain('XYTE_PARTNER_API_KEY');
  });

  it('builds a request for every catalog endpoint without throwing', () => {
    // Catches any generated spec whose template and pathParams disagree.
    const context = testContext({
      credentials: { organization: 'org-key-abcdef123456', partner: 'partner-key-abcdef' }
    });
    for (const key of [
      'organization.devices.getDevices',
      'organization.commands.sendCommand',
      'organization.spaces.getSpaces'
    ]) {
      const endpoint = getEndpoint(key);
      expect(endpoint, key).toBeDefined();
      if (!endpoint) continue;
      const path = Object.fromEntries(endpoint.pathParams.map((name) => [name, 'x']));
      expect(() => buildRequest(endpoint, { path }, context), key).not.toThrow();
    }
  });
});
