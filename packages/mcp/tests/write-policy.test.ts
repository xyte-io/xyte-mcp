import { describe, expect, it } from 'vitest';
import { evaluateWritePolicy } from '../src/write-policy.js';
import type { EndpointSpec } from '../src/catalog/types.js';

function endpoint(overrides: Partial<EndpointSpec> = {}): EndpointSpec {
  return {
    key: 'organization.devices.getDevices',
    namespace: 'organization',
    group: 'devices',
    action: 'getDevices',
    title: 'Get Devices',
    method: 'GET',
    base: 'hub',
    pathTemplate: '/core/v1/organization/devices',
    pathParams: [],
    queryParams: [],
    authScope: 'organization',
    bodyType: 'none',
    mutating: false,
    sourceFile: 'fixture.bru',
    ...overrides
  };
}

const write = (method: EndpointSpec['method'], key: string): EndpointSpec =>
  endpoint({ method, key, mutating: true });

describe('evaluateWritePolicy', () => {
  it('always allows read endpoints, writes off', () => {
    expect(evaluateWritePolicy(endpoint(), undefined, false)).toEqual({ allowed: true });
  });

  it('always allows read endpoints, writes on', () => {
    expect(evaluateWritePolicy(endpoint(), undefined, true)).toEqual({ allowed: true });
  });

  it.each(['POST', 'PUT', 'PATCH', 'DELETE'] as const)(
    'blocks %s when writes are disabled',
    (method) => {
      const decision = evaluateWritePolicy(write(method, 'organization.x.y'), undefined, false);
      expect(decision.allowed).toBe(false);
      if (decision.allowed) return;
      expect(decision.reason).toContain('read-only');
      expect(decision.hints.join(' ')).toContain('XYTE_MCP_READ_ONLY=1');
    }
  );

  it.each(['POST', 'PUT', 'PATCH'] as const)(
    'allows %s when writes are enabled, without confirm',
    (method) => {
      expect(evaluateWritePolicy(write(method, 'organization.x.y'), undefined, true)).toEqual({
        allowed: true
      });
    }
  );

  it('blocks DELETE without confirm even when writes are enabled', () => {
    const decision = evaluateWritePolicy(
      write('DELETE', 'organization.devices.deleteDevice'),
      undefined,
      true
    );
    expect(decision.allowed).toBe(false);
    if (decision.allowed) return;
    expect(decision.reason).toContain('explicit confirmation');
    expect(decision.hints[0]).toContain('confirm: "organization.devices.deleteDevice"');
  });

  it('blocks DELETE when confirm names a different endpoint', () => {
    // Guards against a blanket confirm value being reused across calls.
    const decision = evaluateWritePolicy(
      write('DELETE', 'organization.devices.deleteDevice'),
      'organization.notes.deleteDeviceNote',
      true
    );
    expect(decision.allowed).toBe(false);
  });

  it('allows DELETE with a matching confirm and writes enabled', () => {
    expect(
      evaluateWritePolicy(
        write('DELETE', 'organization.devices.deleteDevice'),
        'organization.devices.deleteDevice',
        true
      )
    ).toEqual({ allowed: true });
  });

  it('still blocks DELETE with a matching confirm when writes are disabled', () => {
    // Confirm is an additional gate, never a way around the read-only posture.
    const decision = evaluateWritePolicy(
      write('DELETE', 'organization.devices.deleteDevice'),
      'organization.devices.deleteDevice',
      false
    );
    expect(decision.allowed).toBe(false);
    if (decision.allowed) return;
    expect(decision.reason).toContain('read-only');
  });
});
