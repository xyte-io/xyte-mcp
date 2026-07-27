import { describe, expect, it } from 'vitest';
import {
  allEndpoints,
  endpointCount,
  getEndpoint,
  listEndpoints,
  listGroups,
  suggestKeys
} from '../src/catalog/catalog.js';

describe('generated catalog', () => {
  it('loads a non-trivial number of endpoints', () => {
    expect(endpointCount()).toBeGreaterThan(50);
  });

  it('has unique keys', () => {
    const keys = allEndpoints().map((endpoint) => endpoint.key);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('contains only operator-usable auth scopes', () => {
    // Device-scoped endpoints authenticate as a device, not an operator, and
    // must never reach the catalog.
    const scopes = new Set(allEndpoints().map((endpoint) => endpoint.authScope));
    expect([...scopes].sort()).toEqual(['organization', 'partner']);
  });

  it('is sorted by key, so regenerating produces a reviewable diff', () => {
    const keys = allEndpoints().map((endpoint) => endpoint.key);
    expect(keys).toEqual([...keys].sort((a, b) => a.localeCompare(b)));
  });

  it('declares every path template placeholder in pathParams', () => {
    for (const endpoint of allEndpoints()) {
      const fromTemplate = [...endpoint.pathTemplate.matchAll(/:(\w+)/g)].map((m) => m[1]);
      expect(endpoint.pathParams, `${endpoint.key} path params`).toEqual(fromTemplate);
    }
  });

  it('marks non-GET endpoints as mutating', () => {
    for (const endpoint of allEndpoints()) {
      expect(endpoint.mutating, `${endpoint.key}`).toBe(
        !['GET', 'HEAD'].includes(endpoint.method)
      );
    }
  });

  it('uses absolute, placeholder-free base paths', () => {
    for (const endpoint of allEndpoints()) {
      expect(endpoint.pathTemplate.startsWith('/'), endpoint.key).toBe(true);
      expect(endpoint.pathTemplate).not.toContain('{{');
    }
  });

  it('resolves a known endpoint by key', () => {
    const endpoint = getEndpoint('organization.devices.getDevices');
    expect(endpoint).toBeDefined();
    expect(endpoint?.method).toBe('GET');
    expect(endpoint?.authScope).toBe('organization');
    expect(endpoint?.mutating).toBe(false);
  });

  it('returns undefined for an unknown key', () => {
    expect(getEndpoint('organization.nope.nope')).toBeUndefined();
  });
});

describe('listEndpoints', () => {
  it('filters by namespace', () => {
    const partner = listEndpoints({ namespace: 'partner' });
    expect(partner.length).toBeGreaterThan(0);
    expect(partner.every((endpoint) => endpoint.namespace === 'partner')).toBe(true);
  });

  it('filters by method', () => {
    const deletes = listEndpoints({ method: 'DELETE' });
    expect(deletes.length).toBeGreaterThan(0);
    expect(deletes.every((endpoint) => endpoint.method === 'DELETE')).toBe(true);
  });

  it('excludes mutating endpoints when asked', () => {
    const reads = listEndpoints({ includeMutating: false });
    expect(reads.length).toBeGreaterThan(0);
    expect(reads.some((endpoint) => endpoint.mutating)).toBe(false);
  });

  it('searches case-insensitively across key, title and path', () => {
    const results = listEndpoints({ search: 'INCIDENT' });
    expect(results.length).toBeGreaterThan(0);
    expect(
      results.every((endpoint) =>
        `${endpoint.key} ${endpoint.title} ${endpoint.pathTemplate}`
          .toLowerCase()
          .includes('incident')
      )
    ).toBe(true);
  });

  it('combines filters conjunctively', () => {
    const results = listEndpoints({ namespace: 'organization', method: 'GET', group: 'devices' });
    expect(results.length).toBeGreaterThan(0);
    for (const endpoint of results) {
      expect(endpoint.namespace).toBe('organization');
      expect(endpoint.method).toBe('GET');
      expect(endpoint.group).toBe('devices');
    }
  });

  it('returns everything when unfiltered', () => {
    expect(listEndpoints()).toHaveLength(endpointCount());
  });
});

describe('discovery helpers', () => {
  it('lists groups', () => {
    expect(listGroups('organization')).toContain('devices');
  });

  it('suggests near-miss keys', () => {
    expect(suggestKeys('organization.devices.getDevice')).toContain(
      'organization.devices.getDevices'
    );
  });

  it('returns no suggestions for nonsense', () => {
    expect(suggestKeys('zzzzzzzz')).toEqual([]);
  });
});
