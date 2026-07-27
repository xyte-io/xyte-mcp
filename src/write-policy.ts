import { ENV } from './config.js';
import type { EndpointSpec } from './catalog/types.js';

export type WriteDecision =
  | { allowed: true }
  | { allowed: false; reason: string; hints: string[] };

/**
 * Decide whether a call may proceed.
 *
 * The caller here is a model, which may be acting on content it read from the
 * fleet (device names, ticket bodies, notes) and which a third party can
 * influence. So mutations are off unless an operator turned them on out of
 * band, and deletes need a deliberate, endpoint-specific acknowledgement on top.
 */
export function evaluateWritePolicy(
  endpoint: EndpointSpec,
  confirm: string | undefined,
  allowWrites: boolean
): WriteDecision {
  if (!endpoint.mutating) return { allowed: true };

  if (!allowWrites) {
    return {
      allowed: false,
      reason:
        `Refusing to call ${endpoint.key}: it is a ${endpoint.method} (mutating) endpoint ` +
        'and this server is running read-only.',
      hints: [
        `An operator must restart the server with ${ENV.allowWrites}=1 to enable writes.`,
        'Read-only endpoints remain available — use xyte_endpoints_list with readOnly: true.'
      ]
    };
  }

  if (endpoint.method === 'DELETE' && confirm !== endpoint.key) {
    return {
      allowed: false,
      reason: `Refusing to call ${endpoint.key}: deletes require explicit confirmation.`,
      hints: [
        `Pass confirm: "${endpoint.key}" to proceed.`,
        'Confirm you have the right target — this cannot be undone.'
      ]
    };
  }

  return { allowed: true };
}
