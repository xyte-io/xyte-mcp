import { timingSafeEqual } from 'node:crypto';
import type { Server } from 'node:http';
import express, { type Request, type Response } from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { endpointCount } from '../catalog/catalog.js';
import {
  DEFAULT_HUB_URL,
  resolveConfig,
  resolveHttpConfig,
  type ServerConfig
} from '../config.js';
import { createToolContext, type ToolContext } from '../context.js';
import { createHttpClient } from '../http/client.js';
import { createHubSignIn } from '../oauth/hub-login.js';
import { hubCredentialOf, XyteOAuthProvider, type LoginForm } from '../oauth/provider.js';
import { PgOAuthStore } from '../oauth/pg-store.js';
import { MemoryOAuthStore, type OAuthStore } from '../oauth/store.js';
import { redactText } from '../redact.js';
import { createServer } from '../server.js';
import { log, logError } from '../log.js';

/**
 * Remote Streamable HTTP transport.
 *
 * The counterpart to `stdio.ts`. The catalog, argument validation, write policy
 * and redaction are `createServer`'s job and are reused untouched; this file is
 * the network boundary and the authentication in front of it.
 *
 * **Stateless MCP.** `sessionIdGenerator: undefined` means no session ids, no
 * session table to expire, and no SSE resumability — every POST is a complete
 * request/response, so `/mcp` answers only POST (see the 405 below for what
 * goes wrong otherwise) and `enableJsonResponse` returns plain JSON.
 *
 * **Two credentials can open the door, each mapping to its own upstream
 * identity:**
 *
 * - A static bearer (`XYTE_MCP_HTTP_TOKEN`) fronting the process-level API
 *   key — the phase-1 mode, kept for dev/CI. Every caller shares one identity,
 *   so it belongs behind a dev hub with `XYTE_MCP_READ_ONLY=1`.
 * - An OAuth 2.1 access token (enabled by `XYTE_MCP_ISSUER_URL`). The SDK's
 *   `mcpAuthRouter` serves discovery metadata, dynamic client registration and
 *   the authorize/token/revoke endpoints; `XyteOAuthProvider` renders a login
 *   page that checks credentials against the hub, and every verified token
 *   resolves to that user's stored hub credential — built into a per-request
 *   `createToolContext`, exactly as `context.ts` promised. Client tokens are
 *   never forwarded to the hub (confused-deputy). Tokens live in Postgres
 *   (`DATABASE_URL`) so they survive a dyno restart; without it, an in-memory
 *   store that loudly warns.
 */

export const MCP_PATH = '/mcp';
const HEALTH_PATH = '/healthz';
const LOGIN_PATH = '/login';

/** Caller-controlled strings are capped before they reach the log stream. */
const MAX_LOGGED_PATH = 64;

export async function startHttpServer(env: NodeJS.ProcessEnv = process.env): Promise<Server> {
  const { staticToken, oauth, port } = resolveHttpConfig(env);
  // OAuth requests carry their own hub credential, so only the static-bearer
  // mode needs a process-level API key (resolveHttpConfig enforces that pair).
  const config = resolveConfig(env, { requireCredentials: !oauth });

  // One HTTP client for every context: it holds the keep-alive pool and no
  // credentials, so sharing it across identities is safe and cheap.
  const upstream = createHttpClient({ timeoutMs: config.timeoutMs });
  const staticContext = staticToken ? createToolContext(config, upstream) : undefined;

  const app = express();
  app.disable('x-powered-by');
  // Heroku's router terminates TLS; without this, express-rate-limit inside the
  // SDK's auth router refuses the X-Forwarded-For it sees on every request.
  app.set('trust proxy', 1);

  // Before the auth check: a platform health probe carries no credentials, and
  // it reveals nothing a port scan would not.
  app.get(HEALTH_PATH, (_req, res) => {
    res.type('text/plain').send('ok');
  });

  let store: OAuthStore | undefined;
  let provider: XyteOAuthProvider | undefined;
  if (oauth) {
    if (oauth.databaseUrl) {
      store = await PgOAuthStore.connect(oauth.databaseUrl);
    } else {
      store = new MemoryOAuthStore();
      logError(
        'WARNING: no DATABASE_URL — OAuth tokens are held in memory and every restart logs all users out.'
      );
    }
    provider = new XyteOAuthProvider(store, createHubSignIn(config.baseUrls.hub), oauth.issuerUrl);

    app.use(
      mcpAuthRouter({
        provider,
        issuerUrl: new URL(oauth.issuerUrl),
        resourceServerUrl: new URL(`${oauth.issuerUrl}${MCP_PATH}`),
        resourceName: 'Xyte MCP'
      })
    );

    const loginProvider = provider;
    app.post(LOGIN_PATH, express.urlencoded({ extended: false }), (req, res) => {
      void handleLogin(loginProvider, req, res);
    });
  }

  app.post(MCP_PATH, (req, res) => {
    void handleMcp(req, res, { staticToken, staticContext, provider, config, upstream, oauth });
  });

  // POST is the whole protocol here, and the spec lets a server say so.
  //
  // Without this the SDK answers GET with an SSE stream that can never emit —
  // a stateless server has no session to push to — so every connected client
  // parks an idle stream on the dyno until Heroku's 55s router timeout kills
  // it, and reconnects. DELETE is the same kind of lie: it reports 200 for
  // terminating a session that was never created.
  app.all(MCP_PATH, (req, res) => {
    void (async () => {
      // Auth first, as on POST: an unauthenticated caller learns nothing about
      // the endpoint, not even which methods it supports.
      const auth = { staticToken, staticContext, provider, config, upstream, oauth };
      if (!(await resolveIdentity(req, auth))) {
        respondUnauthorized(req, res, auth);
        return;
      }
      res.setHeader('Allow', 'POST');
      respondJsonRpcError(res, 405, -32000, `only POST is supported at ${MCP_PATH}`);
    })();
  });

  app.use((_req, res) => {
    respondJsonRpcError(res, 404, -32601, `no such path — MCP is served at ${MCP_PATH}`);
  });

  const listener = await new Promise<Server>((resolve, reject) => {
    const server = app.listen(port, () => {
      server.off('error', reject);
      resolve(server);
    });
    server.once('error', reject);
  });
  listener.once('close', () => void store?.close());

  const auth = [staticToken ? 'static bearer' : '', oauth ? `oauth (${oauth.issuerUrl})` : '']
    .filter(Boolean)
    .join(' + ');
  log(
    `xyte-mcp ready over http on :${port}${MCP_PATH} — ${endpointCount()} endpoints, ` +
      `auth: ${auth}, writes: ${config.allowWrites ? 'ENABLED' : 'disabled'}`
  );
  if (config.baseUrls.hub !== DEFAULT_HUB_URL) {
    log(`hub base URL overridden: ${config.baseUrls.hub}`);
  }
  if (config.allowWrites) {
    // Worth shouting about: on stdio the blast radius is one laptop, here it is
    // whoever holds a token.
    log('WARNING: writes are enabled on a network-reachable server. Set XYTE_MCP_READ_ONLY=1.');
  }

  return listener;
}

interface McpAuth {
  staticToken?: string;
  staticContext?: ToolContext;
  provider?: XyteOAuthProvider;
  config: ServerConfig;
  upstream: ReturnType<typeof createHttpClient>;
  oauth?: { issuerUrl: string };
}

async function handleMcp(req: Request, res: Response, auth: McpAuth): Promise<void> {
  const context = await resolveIdentity(req, auth);
  if (!context) {
    respondUnauthorized(req, res, auth);
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

function respondUnauthorized(req: Request, res: Response, auth: McpAuth): void {
  // In OAuth mode the challenge tells the client where to start the flow
  // (RFC 9728). In static-only mode it is deliberately absent — a challenge
  // makes `mcp-remote` open a browser for an OAuth flow that does not exist.
  if (auth.oauth) {
    res.setHeader(
      'WWW-Authenticate',
      `Bearer resource_metadata="${auth.oauth.issuerUrl}/.well-known/oauth-protected-resource${MCP_PATH}"`
    );
  }
  logError(
    `401 ${req.method} ${req.path.slice(0, MAX_LOGGED_PATH)} — missing or invalid bearer token`
  );
  respondJsonRpcError(res, 401, -32001, 'unauthorized');
}

/**
 * Map the presented bearer to an identity: the static token to the shared
 * process context, an OAuth token to a per-request context carrying that
 * user's hub credential. Order matters only for the static token's
 * constant-time comparison; OAuth tokens are random lookups by hash.
 */
async function resolveIdentity(req: Request, auth: McpAuth): Promise<ToolContext | undefined> {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return undefined;
  const presented = header.slice('Bearer '.length).trim();

  if (auth.staticToken && auth.staticContext && matches(presented, auth.staticToken)) {
    return auth.staticContext;
  }

  if (!auth.provider) return undefined;
  try {
    const info = await auth.provider.verifyAccessToken(presented);
    return createToolContext(
      { ...auth.config, credentials: { organization: hubCredentialOf(info) } },
      auth.upstream
    );
  } catch {
    return undefined;
  }
}

async function handleLogin(provider: XyteOAuthProvider, req: Request, res: Response): Promise<void> {
  try {
    const result = await provider.completeLogin(req.body as LoginForm);
    if ('redirectTo' in result) res.redirect(302, result.redirectTo);
    else res.status(result.status).type('html').send(result.html);
  } catch (error) {
    // Likely the hub being unreachable; the message never reaches the browser.
    logError(error instanceof Error ? (error.stack ?? error.message) : String(error));
    res.status(502).type('html').send('<p>Sign-in is unavailable right now. Try again shortly.</p>');
  }
}

/**
 * Constant-time comparison for the static bearer. `timingSafeEqual` throws on
 * a length mismatch, so the lengths are compared first — that leaks the
 * token's length, which is not a secret, and is the standard trade.
 */
function matches(presented: string, expected: string): boolean {
  const a = Buffer.from(presented, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

function respondJsonRpcError(res: Response, status: number, code: number, message: string): void {
  // Shaped as JSON-RPC even on a transport-level rejection, so an MCP client
  // surfaces the reason instead of "unexpected response".
  res
    .status(status)
    .type('application/json')
    .send(JSON.stringify({ jsonrpc: '2.0', error: { code, message }, id: null }));
}
