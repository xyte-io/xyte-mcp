import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { DEFAULT_HUB_URL, resolveConfig } from '../config.js';
import { createToolContext } from '../context.js';
import { createServer } from '../server.js';
import { endpointCount } from '../catalog/catalog.js';
import { log } from '../log.js';

/**
 * Local stdio transport: credentials come from the process environment, which
 * is what the MCP specification prescribes for stdio servers (its OAuth flow is
 * defined for HTTP transports only).
 *
 * `transports/http.ts` instead resolves a per-request credential from a
 * validated OAuth token (or, in its static-bearer mode, one process-wide
 * context), and reuses `createServer` unchanged.
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
  if (config.baseUrls.hub !== DEFAULT_HUB_URL) {
    log(`hub base URL overridden: ${config.baseUrls.hub}`);
  }

  await server.connect(new StdioServerTransport());
}
