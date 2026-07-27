import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { resolveConfig } from '../config.js';
import { createToolContext } from '../context.js';
import { createServer } from '../server.js';
import { endpointCount } from '../catalog/catalog.js';
import { log } from '../log.js';

/**
 * Local stdio transport: credentials come from the process environment, which
 * is what the MCP specification prescribes for stdio servers (its OAuth flow is
 * defined for HTTP transports only).
 *
 * A future `transports/http.ts` would resolve a per-request credential from a
 * validated bearer token instead, build a context from it, and reuse
 * `createServer` unchanged.
 */
export async function startStdioServer(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const config = resolveConfig(env);
  const context = createToolContext(config);
  const server = createServer(context);

  const scopes = Object.keys(config.credentials).join(', ');
  log(
    `xyte-mcp ready over stdio — ${endpointCount()} endpoints, ` +
      `credentials: ${scopes}, writes: ${config.allowWrites ? 'ENABLED' : 'disabled'}`
  );
  if (config.baseUrls.hub !== 'https://hub.xyte.io') {
    log(`hub base URL overridden: ${config.baseUrls.hub}`);
  }

  await server.connect(new StdioServerTransport());
}
