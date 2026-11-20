import { z } from 'zod';
import { listEndpoints, listGroups } from '../catalog/catalog.js';
import { defineTool, textResult } from './types.js';

const inputSchema = {
  namespace: z
    .enum(['organization', 'partner'])
    .optional()
    .describe('Restrict to one credential scope.'),
  group: z
    .string()
    .optional()
    .describe('Restrict to one resource group, e.g. "devices" or "spaces".'),
  method: z
    .enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
    .optional()
    .describe('Restrict to one HTTP method.'),
  search: z
    .string()
    .optional()
    .describe('Case-insensitive substring match over key, title and path.'),
  readOnly: z
    .boolean()
    .optional()
    .describe('When true, list only non-mutating (GET) endpoints.')
};

const outputSchema = {
  count: z.number(),
  totalAvailable: z.number(),
  endpoints: z.array(
    z.object({
      key: z.string(),
      method: z.string(),
      pathTemplate: z.string(),
      title: z.string(),
      mutating: z.boolean()
    })
  )
};

export const endpointsListTool = defineTool({
  name: 'xyte_endpoints_list',
  title: 'List Xyte API endpoints',
  description:
    'Discover Xyte platform API endpoints. Returns compact rows; call ' +
    'xyte_endpoint_describe for a specific endpoint\'s parameters before calling it. ' +
    'Filter with namespace/group/method/search to keep results small.',
  inputSchema,
  outputSchema,
  annotations: () => ({
    readOnlyHint: true,
    idempotentHint: true,
    openWorldHint: false
  }),
  handler: (args) => {
    const matches = listEndpoints({
      ...(args.namespace ? { namespace: args.namespace } : {}),
      ...(args.group ? { group: args.group } : {}),
      ...(args.method ? { method: args.method } : {}),
      ...(args.search ? { search: args.search } : {}),
      ...(args.readOnly ? { includeMutating: false } : {})
    });

    const rows = matches.map((endpoint) => ({
      key: endpoint.key,
      method: endpoint.method,
      pathTemplate: endpoint.pathTemplate,
      title: endpoint.title,
      mutating: endpoint.mutating
    }));

    const structured = {
      count: rows.length,
      totalAvailable: listEndpoints().length,
      endpoints: rows
    };

    if (rows.length === 0) {
      return textResult(
        `No endpoints matched.\n\nAvailable groups: ${listGroups().join(', ')}`,
        structured
      );
    }

    const lines = rows.map(
      (row) => `${row.key}  [${row.method}${row.mutating ? ' write' : ''}]  ${row.pathTemplate}`
    );
    return textResult(
      `${rows.length} endpoint(s):\n${lines.join('\n')}`,
      structured
    );
  }
});
