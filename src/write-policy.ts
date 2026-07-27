import { ENV } from './config.js';
import type { EndpointSpec } from './catalog/types.js';

export type WriteDecision =
  | { allowed: true }
  | { allowed: false; reason: string; hints: string[] };

/**
 * Decide whether a call may proceed.
 *
 * Mutations are permitted by default, so this is the layer that still holds when
 * they are: a DELETE needs a deliberate, endpoint-specific acknowledgement,
 * because the caller is a model that may be acting on fleet content a third
 * party can influence (device names, ticket bodies, notes) and an irreversible
 * call is the one that cannot be walked back. An operator who wants nothing
 * mutating at all sets `XYTE_MCP_READ_ONLY=1`.
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
        `Read-only was requested explicitly (${ENV.readOnly}=1, or the legacy ` +
          `${ENV.allowWrites}=0). Only an operator can lift it, by restarting the server ` +
          'without it — do not ask for the same call again.',
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
