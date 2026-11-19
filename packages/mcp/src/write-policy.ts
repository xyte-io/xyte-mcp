import { ENV } from './config.js';
import type { EndpointSpec } from './catalog/types.js';

export type WriteDecision =
  | { allowed: true }
  | { allowed: false; reason: string; hints: string[] };

/**
 * Decide whether a call may proceed.
 *
 * Mutations are permitted by default over stdio (over --http only on an explicit
 * opt-in), so this is the layer that still holds when they are: a DELETE needs a deliberate, endpoint-specific acknowledgement,
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
        `Read-only is the operator's configuration (${ENV.readOnly}=1, ${ENV.allowWrites}=0, ` +
          `or a hosted --http server without ${ENV.allowWrites}=1). Only an operator can ` +
          'lift it, by changing that and restarting the server — do not ask for the same call again.',
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
