import { z } from 'zod';
import { getEndpoint, suggestKeys } from '../catalog/catalog.js';
import { buildRequest } from '../http/build-request.js';
import { XyteHttpError, isXyteError } from '../http/errors.js';
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
    .describe('Required for DELETE endpoints: pass the endpoint key verbatim to acknowledge.')
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
    'started read-only; DELETE additionally requires confirm.',
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
      const response = await context.http.request(request);
      const data = redactValue(response.data, context.secrets);

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
      return toErrorResult(
        error,
        endpoint.key,
        context.secrets,
        typeof context.credentials.organization === 'object'
      );
    }
  }
});

function toErrorResult(
  error: unknown,
  endpointKey: string,
  secrets: readonly string[],
  signedIn: boolean
): ReturnType<typeof errorResult> {
  if (error instanceof XyteHttpError) {
    const body = redactValue(error.body, secrets);
    const hints: string[] = [];
    if (signedIn) {
      const hint = signedInAccessHint(error);
      if (hint) hints.push(hint);
    } else if (error.status === 401 || error.status === 403) {
      hints.push('The API key may be invalid, revoked, or lack the required scope.');
    }
    if (error.status === 404) {
      hints.push('Check the path parameter values — the resource may not exist.');
    }
    if (error.status === 422 || error.status === 400) {
      hints.push(`Run xyte_endpoint_describe on ${endpointKey} to check the expected arguments.`);
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

/**
 * Hub applies the signed-in user's own access when the app's hub setting is on;
 * match its error_code, never its text.
 */
function signedInAccessHint(error: XyteHttpError): string | undefined {
  const errorCode =
    typeof error.body === 'object' && error.body !== null
      ? (error.body as { error_code?: unknown }).error_code
      : undefined;
  if (error.status === 403) {
    if (errorCode === 'organization_administrator_required') {
      return 'Only an organization administrator can do this. Ask an administrator of your organization.';
    }
    if (errorCode === 'no_access_to_resource') {
      return 'You have no access to this item. Ask an organization administrator for access.';
    }
    return undefined;
  }
  if (error.status === 401) {
    if (/error="invalid_token"/.test(error.wwwAuthenticate ?? '')) {
      return 'The Xyte sign-in behind this connection has ended. Reconnect the Xyte connector to sign in again.';
    }
    if (!error.wwwAuthenticate) {
      return 'This is not a sign-in problem: check the ids in the request — the item may not be in this organization.';
    }
    return undefined;
  }
  return undefined;
}
