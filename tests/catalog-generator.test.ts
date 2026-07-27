import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { EndpointSpec, GeneratedCatalog } from '../src/catalog/types.js';

const GENERATOR = path.resolve(import.meta.dirname, '..', 'scripts', 'generate-catalog.mjs');
const FAKE_HUB = path.resolve(import.meta.dirname, 'fixtures', 'fake-hub');

let workDir: string;
let catalog: GeneratedCatalog;
let byKey: Map<string, EndpointSpec>;

beforeAll(() => {
  workDir = mkdtempSync(path.join(tmpdir(), 'xyte-mcp-catalog-'));
  const outPath = path.join(workDir, 'endpoints.json');

  execFileSync(process.execPath, [GENERATOR, '--hub-path', FAKE_HUB, '--out', outPath], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe']
  });

  catalog = JSON.parse(readFileSync(outPath, 'utf8')) as GeneratedCatalog;
  byKey = new Map(catalog.endpoints.map((endpoint) => [endpoint.key, endpoint]));
});

afterAll(() => {
  rmSync(workDir, { recursive: true, force: true });
});

describe('generate-catalog', () => {
  it('generates only the operator-scoped endpoints', () => {
    // 4 organization + 1 partner. The Device API request is excluded.
    expect([...byKey.keys()].sort()).toEqual([
      'organization.commands.sendCommand',
      'organization.devices.deleteDevice',
      'organization.devices.getDevices',
      'organization.getOrganizationInfo',
      'partner.organizations.createOrganization'
    ]);
  });

  it('never emits a device-scoped endpoint', () => {
    const scopes = new Set(catalog.endpoints.map((endpoint) => endpoint.authScope));
    expect([...scopes].sort()).toEqual(['organization', 'partner']);
    expect([...byKey.keys()].some((key) => key.includes('registerDevice'))).toBe(false);
  });

  it('never reads the environments directory, which holds real credentials', () => {
    expect(JSON.stringify(catalog)).not.toContain('FIXTURE_MUST_NEVER_BE_READ');
  });

  it('derives namespace, group and action from the folder path and request name', () => {
    const endpoint = byKey.get('organization.devices.getDevices');
    expect(endpoint).toMatchObject({
      namespace: 'organization',
      group: 'devices',
      action: 'getDevices',
      title: 'Get Devices',
      method: 'GET',
      base: 'hub',
      pathTemplate: '/core/v1/organization/devices',
      authScope: 'organization',
      mutating: false
    });
  });

  it('leaves the group empty for a request at the namespace root', () => {
    const endpoint = byKey.get('organization.getOrganizationInfo');
    expect(endpoint?.group).toBe('');
  });

  it('captures query parameters including Bruno-disabled ones', () => {
    // A leading `~` only means "not sent by default" in the Bruno GUI; the
    // parameter is still valid and worth advertising.
    expect(byKey.get('organization.devices.getDevices')?.queryParams).toEqual([
      'page',
      'per_page',
      'name'
    ]);
  });

  it('captures docs blocks as the description', () => {
    expect(byKey.get('organization.devices.getDevices')?.description).toBe(
      'Returns every device in the organization.'
    );
  });

  it('omits the description when there is no docs block', () => {
    expect(byKey.get('organization.commands.sendCommand')?.description).toBeUndefined();
  });

  it('extracts path parameters and the body example', () => {
    const endpoint = byKey.get('organization.commands.sendCommand');
    expect(endpoint?.pathTemplate).toBe('/core/v1/organization/devices/:device_id/commands');
    expect(endpoint?.pathParams).toEqual(['device_id']);
    expect(endpoint?.bodyType).toBe('json');
    expect(endpoint?.bodyExample).toContain('"name": "reboot"');
    expect(endpoint?.mutating).toBe(true);
  });

  it('normalises {{var}} path params and {{hub_url}} bases', () => {
    const endpoint = byKey.get('organization.devices.deleteDevice');
    expect(endpoint?.base).toBe('hub');
    expect(endpoint?.pathTemplate).toBe('/core/v1/organization/devices/:device_id');
    expect(endpoint?.pathParams).toEqual(['device_id']);
    expect(endpoint?.method).toBe('DELETE');
  });

  it('routes the partner key to the partner scope', () => {
    expect(byKey.get('partner.organizations.createOrganization')?.authScope).toBe('partner');
  });

  it('does not treat a GET body:json artifact as a required body', () => {
    // "Get Organization Info" declares body:json in Bruno; it is still a GET.
    const endpoint = byKey.get('organization.getOrganizationInfo');
    expect(endpoint?.method).toBe('GET');
    expect(endpoint?.mutating).toBe(false);
  });

  it('sorts output by key so regeneration diffs are reviewable', () => {
    const keys = catalog.endpoints.map((endpoint) => endpoint.key);
    expect(keys).toEqual([...keys].sort((a, b) => a.localeCompare(b)));
  });

  it('stamps a catalog version', () => {
    expect(catalog.catalogVersion).toBe(1);
  });

  it('--check passes against a freshly generated file', () => {
    const outPath = path.join(workDir, 'endpoints.json');
    expect(() =>
      execFileSync(
        process.execPath,
        [GENERATOR, '--hub-path', FAKE_HUB, '--out', outPath, '--check'],
        { stdio: ['ignore', 'pipe', 'pipe'] }
      )
    ).not.toThrow();
  });

  it('--check fails when the committed file is stale', () => {
    expect(() =>
      execFileSync(
        process.execPath,
        [GENERATOR, '--hub-path', FAKE_HUB, '--out', path.join(workDir, 'missing.json'), '--check'],
        { stdio: ['ignore', 'pipe', 'pipe'] }
      )
    ).toThrow();
  });

  it('fails loudly when the hub path is wrong', () => {
    expect(() =>
      execFileSync(process.execPath, [GENERATOR, '--hub-path', path.join(workDir, 'nope')], {
        stdio: ['ignore', 'pipe', 'pipe']
      })
    ).toThrow();
  });
});
