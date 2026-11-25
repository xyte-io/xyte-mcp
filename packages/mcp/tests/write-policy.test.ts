import { describe, expect, it } from 'vitest';
import { getEndpoint } from '../src/catalog/catalog.js';
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
      // The model repeats hints to the user, so no variable names (D4).
      expect(decision.hints.join(' ')).not.toContain('XYTE_');
      expect(decision.hints.join(' ')).toContain('set up to look only');
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
    expect(decision.hints.join(' ')).toContain('explicit yes');
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

describe('evaluateWritePolicy on the Partner coupon and tag endpoints', () => {
  const real = (key: string): EndpointSpec => {
    const spec = getEndpoint(key);
    if (!spec) throw new Error(`missing from the catalog: ${key}`);
    return spec;
  };

  const reads = [
    'partner.organizations.getOrganizations',
    'partner.organizationTags.getOrganizationTags',
    'partner.coupons.getCoupons',
    'partner.storeListings.getStoreListings',
    'partner.orders.getOrders',
    'partner.orders.getOrder',
    'partner.payments.getPayments',
    'partner.payments.getPayment',
    'partner.products.getProducts',
    'partner.products.getProduct',
    'partner.soldProducts.getSoldProducts',
    'partner.soldProducts.getSoldProduct',
    'partner.storeListings.getStoreListing',
    'partner.storeSettings.getStoreSettings',
    'partner.subscriptions.getSubscriptions',
    'partner.subscriptions.getSubscription',
    'partner.subscriptions.getSubscriptionInvoiceItems'
  ];
  const writesWithoutConfirm = ['partner.orders.approveOrder', 'partner.organizationTags.updateOrganizationTag'];
  const writes = [
    'partner.organizationTags.addOrganizationTag',
    'partner.organizationTags.removeOrganizationTag',
    'partner.coupons.createCoupon',
    'partner.coupons.updateCoupon',
    'partner.coupons.deleteCoupon',
    'partner.orders.approveOrder',
    'partner.organizationTags.updateOrganizationTag'
  ];
  const deletes = ['partner.coupons.deleteCoupon', 'partner.organizationTags.removeOrganizationTag'];

  it.each(reads)('allows the read %s when read-only', (key) => {
    expect(evaluateWritePolicy(real(key), undefined, false)).toEqual({ allowed: true });
  });

  it.each(writes)('refuses the write %s when read-only', (key) => {
    expect(evaluateWritePolicy(real(key), key, false).allowed).toBe(false);
  });

  it.each(writesWithoutConfirm)('allows %s with writes on and no confirm', (key) => {
    expect(evaluateWritePolicy(real(key), undefined, true)).toEqual({ allowed: true });
  });

  it.each(deletes)('requires confirm for %s', (key) => {
    expect(evaluateWritePolicy(real(key), undefined, true).allowed).toBe(false);
    expect(evaluateWritePolicy(real(key), key, true)).toEqual({ allowed: true });
  });
});
