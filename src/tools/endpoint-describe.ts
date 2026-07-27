import { z } from 'zod';
import { getEndpoint, suggestKeys } from '../catalog/catalog.js';
import { defineTool, errorResult, textResult } from './types.js';

const inputSchema = {
  key: z
    .string()
    .describe('Endpoint key from xyte_endpoints_list, e.g. "organization.devices.getDevices".')
};

const outputSchema = {
  key: z.string(),
  title: z.string(),
  description: z.string().optional(),
  method: z.string(),
  pathTemplate: z.string(),
  url: z.string(),
  authScope: z.string(),
  pathParams: z.array(z.string()),
  queryParams: z.array(z.string()),
  bodyType: z.string(),
  bodyExample: z.string().optional(),
  mutating: z.boolean(),
  requiresConfirm: z.boolean()
};

export const endpointDescribeTool = defineTool({
  name: 'xyte_endpoint_describe',
  title: 'Describe a Xyte API endpoint',
  description:
    'Show the full contract for one endpoint: required path parameters, accepted ' +
    'query parameters, body shape and which credential it needs. Call this before ' +
    'xyte_api_call when you are unsure of an endpoint\'s arguments.',
  inputSchema,
  outputSchema,
  annotations: () => ({
    readOnlyHint: true,
    idempotentHint: true,
    openWorldHint: false
  }),
  handler: (args, context) => {
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

    const base = context.baseUrls[endpoint.base];
    const requiresConfirm = endpoint.method === 'DELETE';

    const structured = {
      key: endpoint.key,
      title: endpoint.title,
      ...(endpoint.description ? { description: endpoint.description } : {}),
      method: endpoint.method,
      pathTemplate: endpoint.pathTemplate,
      url: `${base}${endpoint.pathTemplate}`,
      authScope: endpoint.authScope,
      pathParams: endpoint.pathParams,
      queryParams: endpoint.queryParams,
      bodyType: endpoint.bodyType,
      ...(endpoint.bodyExample ? { bodyExample: endpoint.bodyExample } : {}),
      mutating: endpoint.mutating,
      requiresConfirm
    };

    const lines = [
      `${endpoint.key} — ${endpoint.title}`,
      `${endpoint.method} ${base}${endpoint.pathTemplate}`,
      `auth: ${endpoint.authScope} key`,
      endpoint.description ? `\n${endpoint.description}` : '',
      endpoint.pathParams.length
        ? `\npath params (all required): ${endpoint.pathParams.join(', ')}`
        : '',
      endpoint.queryParams.length
        ? `query params (all optional): ${endpoint.queryParams.join(', ')}`
        : '',
      endpoint.bodyExample ? `\nexample body:\n${endpoint.bodyExample}` : '',
      endpoint.mutating
        ? `\nThis endpoint mutates data.${
            context.allowWrites
              ? requiresConfirm
                ? ` Writes are enabled; pass confirm: "${endpoint.key}" to run it.`
                : ' Writes are enabled.'
              : ' This server is running read-only, so the call will be refused.'
          }`
        : ''
    ].filter(Boolean);

    return textResult(lines.join('\n'), structured);
  }
});
