import { timingSafeEqual } from 'node:crypto';
import {
  createServer as createHttpListener,
  type IncomingMessage,
  type Server,
  type ServerResponse
} from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { endpointCount } from '../catalog/catalog.js';
import { DEFAULT_HUB_URL, resolveConfig, resolveHttpConfig } from '../config.js';
import { createToolContext, type ToolContext } from '../context.js';
import { redactText } from '../redact.js';
import { createServer } from '../server.js';
import { log, logError } from '../log.js';

/**
 * Remote Streamable HTTP transport.
 *
 * The counterpart to `stdio.ts`, and deliberately the smallest thing that can
 * serve MCP over the network: the catalog, argument validation, write policy and
 * redaction are `createServer`'s job and are reused untouched.
 *
 * **Stateless.** `sessionIdGenerator: undefined` means no session ids, no
 * session table to expire, and no SSE resumability — every POST is a complete
 * request/response. That costs a fresh `McpServer` per request (three tool
 * registrations over an already-parsed catalog, microseconds) and buys us not
 * having to reason about a session store on a dyno that restarts on every config
 * change. `enableJsonResponse` then returns plain JSON instead of a one-event
 * SSE stream, which is simpler to read and simpler to curl. Note that the MCP
 * spec still requires the *client* to send
 * `Accept: application/json, text/event-stream`.
 *
 * **Auth is a single static bearer** (`XYTE_MCP_HTTP_TOKEN`), and the API key it
 * fronts is per-process. So every caller shares one identity and one blast
 * radius — that is the deliberate ceiling of this phase, and the reason to run
 * it read-only (`XYTE_MCP_READ_ONLY=1`) against a dev hub. OAuth 2.1 and
 * per-user credentials are what replace this, and they replace only this file:
 * a per-request context built from a validated token is the same
 * `createToolContext` call.
 */

/** The MCP endpoint. `/healthz` is the only other route, and takes no token. */
export const MCP_PATH = '/mcp';
const HEALTH_PATH = '/healthz';

/** Caller-controlled strings are capped before they reach the log stream. */
const MAX_LOGGED_PATH = 64;

export async function startHttpServer(env: NodeJS.ProcessEnv = process.env): Promise<Server> {
  const { token, port } = resolveHttpConfig(env);
  const config = resolveConfig(env);

  // One context for the whole process: it holds the shared HTTP client (and so
  // its keep-alive pool) and the single set of credentials. Per-request state
  // lives in the per-request McpServer, not here.
  const context = createToolContext(config);

  const listener = createHttpListener((req, res) => {
    void handle(req, res, token, context);
  });
  await new Promise<void>((resolve, reject) => {
    listener.once('error', reject);
    listener.listen(port, () => {
      listener.off('error', reject);
      resolve();
    });
  });

  const scopes = Object.keys(config.credentials).join(', ');
  log(
    `xyte-mcp ready over http on :${port}${MCP_PATH} — ${endpointCount()} endpoints, ` +
      `credentials: ${scopes}, writes: ${config.allowWrites ? 'ENABLED' : 'disabled'}`
  );
  if (config.baseUrls.hub !== DEFAULT_HUB_URL) {
    log(`hub base URL overridden: ${config.baseUrls.hub}`);
  }
  if (config.allowWrites) {
    // Worth shouting about: on stdio the blast radius is one laptop, here it is
    // whoever holds the bearer token.
    log('WARNING: writes are enabled on a network-reachable server. Set XYTE_MCP_READ_ONLY=1.');
  }

  return listener;
}

async function handle(
  req: IncomingMessage,
  res: ServerResponse,
  token: string,
  context: ToolContext
): Promise<void> {
  // `req.url` is a path, not an absolute URL; the base is only there to parse it.
  const path = new URL(req.url ?? '/', 'http://localhost').pathname;

  // Before the auth check: a platform health probe carries no credentials, and
  // it reveals nothing a port scan would not.
  if (path === HEALTH_PATH) {
    res.writeHead(200, { 'Content-Type': 'text/plain' }).end('ok');
    return;
  }

  if (!authorized(req, token)) {
    // No `WWW-Authenticate` challenge on purpose: `mcp-remote` reads one as
    // "this server does OAuth" and opens a browser for a flow that does not
    // exist yet. Log the denial — path and method only, both capped, never the
    // presented token.
    logError(
      `401 ${req.method ?? '-'} ${path.slice(0, MAX_LOGGED_PATH)} — missing or wrong bearer token`
    );
    respondJsonRpcError(res, 401, -32001, 'unauthorized');
    return;
  }

  if (path !== MCP_PATH) {
    respondJsonRpcError(res, 404, -32601, `no such path — MCP is served at ${MCP_PATH}`);
    return;
  }

  const server = createServer(context);
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true
  });
  // Stateless means this pair is per-request, so it has to be torn down with the
  // response — otherwise every call leaks a transport and its listeners.
  res.on('close', () => {
    void transport.close();
    void server.close();
  });

  try {
    await server.connect(transport);
    // With no `parsedBody` the transport reads and parses the body itself, and
    // rejects a bad Accept/Content-Type per spec before we see it.
    await transport.handleRequest(req, res);
  } catch (error) {
    // The message could carry a credential (an upstream URL, a header dump), so
    // it goes through redactText before the log stream, and never to the client.
    const detail = error instanceof Error ? (error.stack ?? error.message) : String(error);
    logError(redactText(detail, context.secrets));
    if (!res.headersSent) respondJsonRpcError(res, 500, -32603, 'internal error');
    else res.end();
  }
}

/**
 * Constant-time bearer comparison.
 *
 * `timingSafeEqual` throws on a length mismatch, so the lengths are compared
 * first — that leaks the token's length, which is not a secret, and is the
 * standard trade.
 */
function authorized(req: IncomingMessage, expected: string): boolean {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return false;

  const presented = Buffer.from(header.slice('Bearer '.length).trim(), 'utf8');
  const secret = Buffer.from(expected, 'utf8');
  return presented.length === secret.length && timingSafeEqual(presented, secret);
}

function respondJsonRpcError(
  res: ServerResponse,
  status: number,
  code: number,
  message: string
): void {
  // Shaped as JSON-RPC even on a transport-level rejection, so an MCP client
  // surfaces the reason instead of "unexpected response".
  res
    .writeHead(status, { 'Content-Type': 'application/json' })
    .end(JSON.stringify({ jsonrpc: '2.0', error: { code, message }, id: null }));
}
