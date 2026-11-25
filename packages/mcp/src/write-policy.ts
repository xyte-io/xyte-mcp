import type { EndpointSpec } from './catalog/types.js';

export type WriteDecision =
  | { allowed: true }
  | { allowed: false; reason: string; hints: string[] };

/**
 * Decide whether a call may proceed.
 *
 * Mutations are permitted by default over stdio (on the hosted server only on an
 * explicit opt-in), so this is the layer that still holds when they are: a DELETE needs a deliberate, endpoint-specific acknowledgement,
 * because the caller is a model that may be acting on fleet content a third
 * party can influence (device names, ticket bodies, notes) and an irreversible
 * call is the one that cannot be walked back. An operator who wants nothing
 * mutating at all sets `XYTE_MCP_READ_ONLY=1`. The model-facing wording here is guidance;
 * the user's agent host and its write-approval prompt are the real stop.
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
        // The model repeats hints to the user, so no setting names here.
        'Tell the user that this connection is set up to look only and cannot make changes, ' +
          'without naming any setting or variable. Only whoever set up the connection can ' +
          'change that — do not ask for the same call again.',
        'Read-only endpoints remain available — use xyte_endpoints_list with readOnly: true.'
      ]
    };
  }

  if (endpoint.method === 'DELETE' && confirm !== endpoint.key) {
    return {
      allowed: false,
      reason: `Refusing to call ${endpoint.key}: deletes require explicit confirmation.`,
      hints: [
        `Pass confirm: "${endpoint.key}" only after the user gave an explicit yes in the ` +
          'conversation to deleting this exact item.',
        'First tell the user in plain words what will be deleted and what they lose — this ' +
          'cannot be undone.'
      ]
    };
  }

  return { allowed: true };
}
