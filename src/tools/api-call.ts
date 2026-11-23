import { z } from 'zod';
import { getEndpoint, suggestKeys } from '../catalog/catalog.js';
import type { EndpointSpec } from '../catalog/types.js';
import type { ToolContext } from '../context.js';
import { buildRequest } from '../http/build-request.js';
import type { HttpRequest, HttpResponse } from '../http/client.js';
import { XyteHttpError, isXyteError } from '../http/errors.js';
import { log } from '../log.js';
import { redactValue } from '../redact.js';
import { evaluateWritePolicy } from '../write-policy.js';
import { defineTool, errorResult, textResult } from './types.js';

const inputSchema = {
  key: z
    .string()
    .describe('Endpoint key from xyte_endpoints_list, e.g. "organization.devices.getDevices".'),
  path: z
    .record(z.string(), z.union([z.string(), z.number()]))
    .optional()
    .describe('Path parameter values, e.g. { "device_id": "abc" }. All are required.'),
  query: z
    .record(z.string(), z.union([z.string(), z.number(), z.boolean()]))
    .optional()
    .describe('Query parameters. Only names listed by xyte_endpoint_describe are accepted.'),
  body: z
    .unknown()
    .optional()
    .describe('JSON request body. Only for non-GET endpoints.'),
  confirm: z
    .string()
    .optional()
    .describe(
      'DELETE only: the endpoint key verbatim. Set it only after you told the user what will be ' +
        "lost and the user gave an explicit yes in the conversation to this exact item — never " +
        'on your own. A yes for one item does not cover others.'
    )
};

const outputSchema = {
  key: z.string(),
  method: z.string(),
  status: z.number(),
  durationMs: z.number(),
  data: z.unknown()
};

export const apiCallTool = defineTool({
  name: 'xyte_api_call',
  title: 'Call a Xyte API endpoint',
  description:
    'Invoke a Xyte platform API endpoint by key. Use xyte_endpoint_describe first if ' +
    'you are unsure of the parameters. Mutating endpoints run unless the server was ' +
    'started read-only. Before a DELETE, a removal, or a change to something active or ' +
    "scheduled, tell the user what changes and wait for the user's explicit yes; DELETE " +
    'additionally requires confirm.',
  inputSchema,
  outputSchema,
  annotations: (context) => ({
    // Flipped by configuration so the host prompts appropriately.
    readOnlyHint: !context.allowWrites,
    destructiveHint: context.allowWrites,
    idempotentHint: false,
    openWorldHint: true
  }),
  handler: async (args, context) => {
    const endpoint = getEndpoint(args.key);
    if (!endpoint) {
      const suggestions = suggestKeys(args.key);
      return errorResult(
        `Unknown endpoint key: ${args.key}`,
        suggestions.length
          ? [`Did you mean: ${suggestions.join(', ')}`]
          : ['Use xyte_endpoints_list to see available endpoints.']
      );
    }

    const decision = evaluateWritePolicy(endpoint, args.confirm, context.allowWrites);
    if (!decision.allowed) {
      return errorResult(decision.reason, decision.hints);
    }

    try {
      const request = buildRequest(
        endpoint,
        {
          ...(args.path ? { path: args.path } : {}),
          ...(args.query ? { query: args.query } : {}),
          ...(args.body === undefined ? {} : { body: args.body })
        },
        context
      );
      const response = await sendRequest(endpoint, request, context);
      // A 204 has no body; null keeps `data` in the structured result, which the output schema requires.
      const data = redactValue(response.data ?? null, context.secrets);

      const structured = {
        key: endpoint.key,
        method: endpoint.method,
        status: response.status,
        durationMs: response.durationMs,
        data
      };

      return textResult(
        `${endpoint.method} ${endpoint.key} -> ${response.status} (${response.durationMs}ms)\n\n` +
          `${JSON.stringify(data, null, 2)}`,
        structured
      );
    } catch (error) {
      return toErrorResult(error, endpoint.key, context.secrets);
    }
  }
});

/**
 * Sends the request; a mutating call also writes one line to stderr, so an operator can tell
 * later what the agent changed. The line holds the key, method, status and duration only —
 * never the API key, the request body or the response body. `status=error` means no HTTP
 * status came back (timeout, network), so the write may still have landed.
 */
async function sendRequest(
  endpoint: EndpointSpec,
  request: HttpRequest,
  context: ToolContext
): Promise<HttpResponse> {
  if (!endpoint.mutating) return context.http.request(request);

  const startedAt = performance.now();
  let status: number | 'error' = 'error';
  try {
    const response = await context.http.request(request);
    status = response.status;
    return response;
  } catch (error) {
    if (error instanceof XyteHttpError) status = error.status;
    throw error;
  } finally {
    const durationMs = Math.round(performance.now() - startedAt);
    log(`write ${endpoint.key} ${endpoint.method} status=${status} duration_ms=${durationMs}`);
  }
}

function toErrorResult(
  error: unknown,
  endpointKey: string,
  secrets: readonly string[]
): ReturnType<typeof errorResult> {
  if (error instanceof XyteHttpError) {
    const body = redactValue(error.body, secrets);
    const hints: string[] = [];
    if (error.status === 401 || error.status === 403) {
      hints.push('The API key may be invalid, revoked, or lack the required scope.');
    }
    if (error.status === 404 && /Requested path .* does not exist/.test(JSON.stringify(error.body))) {
      // Hub's catch-all route: the hub is older than this catalog, not a missing record.
      hints.push('This endpoint is not available on this hub yet. Tell the user; do not retry with other ids.');
    } else if (error.status === 404) {
      hints.push('Check the path parameter values — the resource may not exist.');
    }
    if (error.status === 422 || error.status === 400) {
      hints.push(`Run xyte_endpoint_describe on ${endpointKey} to check the expected body.`);
    }
    return errorResult(
      `${endpointKey} failed: ${error.status} ${error.statusText}\n\n${JSON.stringify(body, null, 2)}`,
      hints
    );
  }

  if (isXyteError(error)) {
    return errorResult(error.message, error.hints);
  }

  const message = error instanceof Error ? error.message : String(error);
  return errorResult(`${endpointKey} failed: ${redactValue(message, secrets) as string}`);
}
