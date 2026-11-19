import { timingSafeEqual } from 'node:crypto';
import type { Server } from 'node:http';
import express, { type Request, type Response } from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
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
import { createHubOAuth } from '../oauth/hub-oauth.js';
import { hubIdentityOf, XyteOAuthProvider } from '../oauth/provider.js';
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
 * **One of two authentication modes per deployment** (config refuses both):
 *
 * - A static bearer (`XYTE_MCP_HTTP_TOKEN`) fronting the process-level API
 *   key — the phase-1 mode, kept for dev/CI. Every caller shares one identity,
 *   so it belongs behind a dev hub, read-only.
 * - OAuth 2.1 (enabled by `XYTE_MCP_ISSUER_URL`). The SDK's
 *   `mcpAuthRouter` serves discovery metadata, dynamic client registration and
 *   the authorize/token/revoke endpoints; `XyteOAuthProvider` renders a
 *   consent page, delegates sign-in to hub's OAuth server, and every verified
 *   token resolves to its grant's hub token — built into a per-request
 *   `createToolContext`, exactly as `context.ts` promised. Client tokens are
 *   never forwarded to the hub (confused-deputy). Tokens live in Postgres
 *   (`DATABASE_URL`) so they survive a dyno restart; without it, an in-memory
 *   store that loudly warns.
 *
 * Read-only unless `XYTE_MCP_ALLOW_WRITES=1`: unlike stdio, writes are opt-in.
 */

const MCP_PATH = '/mcp';
const HEALTH_PATH = '/healthz';
const CONSENT_PATH = '/oauth/consent';
/** Registered at hub as `<issuer>/oauth/callback`. */
const CALLBACK_PATH = '/oauth/callback';

/** Caller-controlled strings are capped before they reach the log stream. */
const MAX_LOGGED_PATH = 64;

/** Under Heroku's 30 s SIGTERM-to-SIGKILL window. */
const SHUTDOWN_DEADLINE_MS = 28_000;
/** In-flight requests get this long before the provider drain starts regardless. */
const REQUEST_GRACE_MS = 10_000;

export async function startHttpServer(env: NodeJS.ProcessEnv = process.env): Promise<Server> {
  const { staticToken, oauth, port } = resolveHttpConfig(env);
  // OAuth requests carry their own hub token, so only the static-bearer
  // mode needs a process-level API key (resolveHttpConfig enforces that pair).
  const config = resolveConfig(env, { requireCredentials: !oauth, writesByDefault: false });

  // One HTTP client for every context: it holds the keep-alive pool and no
  // credentials, so sharing it across identities is safe and cheap.
  const upstream = createHttpClient({ timeoutMs: config.timeoutMs });
  const staticContext = staticToken
    ? withSecret(createToolContext(config, upstream), staticToken)
    : undefined;

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
    provider = new XyteOAuthProvider(
      store,
      createHubOAuth({
        hubUrl: config.baseUrls.hub,
        clientId: oauth.hubClient.id,
        clientSecret: oauth.hubClient.secret,
        redirectUri: `${oauth.issuerUrl}${CALLBACK_PATH}`,
        timeoutMs: config.timeoutMs
      }),
      oauth.issuerUrl
    );

    app.use(
      mcpAuthRouter({
        provider,
        issuerUrl: new URL(oauth.issuerUrl),
        resourceServerUrl: new URL(`${oauth.issuerUrl}${MCP_PATH}`),
        resourceName: 'Xyte MCP',
        // The SDK limits per IP (register 20/h, token and revoke 50/15 min), but
        // claude.ai and ChatGPT register, exchange and refresh from their own
        // backend egress IPs, so one IP is all their users. Sized for a few
        // thousand users behind one IP (a refresh per user per hour, the access
        // TTL); tokens are 256-bit random, so the limit is load control, not
        // brute-force defence. `/authorize` is a browser, so it keeps the default.
        clientRegistrationOptions: { rateLimit: { windowMs: 60 * 60 * 1000, max: 1000 } },
        tokenOptions: { rateLimit: { windowMs: 15 * 60 * 1000, max: 2000 } },
        revocationOptions: { rateLimit: { windowMs: 15 * 60 * 1000, max: 500 } }
      })
    );

    const flow = provider;
    app.post(CONSENT_PATH, express.urlencoded({ extended: false }), (req, res) => {
      void flow.consent(req, res).catch((error: unknown) => failFlow(res, error));
    });
    app.get(CALLBACK_PATH, (req, res) => {
      void flow.callback(req, res).catch((error: unknown) => failFlow(res, error));
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
      if (!(await authenticate(req, res, auth))) return;
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
  // Once listening, a server error (EMFILE on accept, …) is fatal; say so
  // rather than crash on an unhandled 'error' event, and let the platform restart us.
  listener.on('error', (error) => {
    logError(`http listener failed: ${error.message}`);
    process.exit(1);
  });
  // Drain before the pool goes: a rotated hub pair that never reaches the store
  // is replayed on the next refresh, and hub then ends the user's sign-in.
  let stopping: Promise<void> | undefined;
  const stop = () =>
    (stopping ??= (async () => {
      await provider?.drain();
      await store?.close().catch(() => undefined);
    })());
  listener.once('close', () => void stop());

  // Heroku sends SIGTERM on every deploy and daily restart, and SIGKILL 30 s later;
  // a local Ctrl+C (SIGINT) drains the same way. A second, different signal during
  // the drain is ignored; repeating the same one falls back to the default exit.
  let shuttingDown = false;
  const shutdown = (signal: NodeJS.Signals) => {
    if (shuttingDown) return;
    shuttingDown = true;
    log(`${signal}: finishing in-flight requests and hub refreshes`);
    setTimeout(() => {
      logError('shutdown deadline reached; exiting with work unfinished');
      process.exit(1);
    }, SHUTDOWN_DEADLINE_MS).unref();
    void (async () => {
      await new Promise<void>((resolve) => {
        listener.close(() => resolve());
        // A kept-alive connection would hold close() open past the deadline.
        setTimeout(resolve, REQUEST_GRACE_MS).unref();
      });
      await stop();
      process.exit(0);
    })();
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);

  const auth = oauth ? `oauth (${oauth.issuerUrl}, sign-in: hub oauth)` : 'static bearer';
  log(
    `xyte-mcp ready over http on :${port}${MCP_PATH} — ${endpointCount()} endpoints, ` +
      `auth: ${auth}, writes: ${config.allowWrites ? 'ENABLED' : 'disabled'}`
  );
  if (config.baseUrls.hub !== DEFAULT_HUB_URL) {
    log(`hub base URL overridden: ${config.baseUrls.hub}`);
  }
  if (config.allowWrites) {
    // Worth shouting about even when asked for: on stdio the blast radius is
    // one laptop, here it is whoever holds a token.
    log('WARNING: writes are enabled on a network-reachable server (XYTE_MCP_ALLOW_WRITES).');
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
  const context = await authenticate(req, res, auth);
  if (!context) return;

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
 * The caller's identity, or undefined once a rejection is sent. Only a bad
 * token is a 401: a store outage is a retryable 503, or every connected client
 * would drop its tokens and restart the OAuth flow.
 */
async function authenticate(
  req: Request,
  res: Response,
  auth: McpAuth
): Promise<ToolContext | undefined> {
  let context: ToolContext | undefined;
  try {
    context = await resolveIdentity(req, auth);
  } catch (error) {
    logError(`token check failed: ${error instanceof Error ? error.message : String(error)}`);
    respondJsonRpcError(res, 503, -32603, 'temporarily unavailable, retry');
    return undefined;
  }
  if (!context) respondUnauthorized(req, res, auth);
  return context;
}

/**
 * Map the presented bearer to an identity: in static mode the token to the
 * shared process context (constant-time compare), in OAuth mode a token to a
 * per-request context carrying its grant's hub token (refreshed on demand by
 * the provider's hub client).
 */
async function resolveIdentity(req: Request, auth: McpAuth): Promise<ToolContext | undefined> {
  // The auth scheme is case-insensitive (RFC 7235 2.1).
  const header = req.headers.authorization ?? '';
  if (!/^bearer\s+/i.test(header)) return undefined;
  const presented = header.replace(/^bearer\s+/i, '').trim();

  if (auth.staticToken && auth.staticContext) {
    return matches(presented, auth.staticToken) ? auth.staticContext : undefined;
  }

  if (!auth.provider) return undefined;
  try {
    const hub = hubIdentityOf(await auth.provider.verifyAccessToken(presented));
    // hubHttp replaces this token with the grant's current one, and adds every
    // token it sends here, so a refreshed one is redacted like the original.
    const secrets = [hub.accessToken];
    const context = createToolContext(
      { ...auth.config, credentials: { organization: { accessToken: hub.accessToken } } },
      auth.provider.hubHttp(hub.grantId, auth.upstream, secrets)
    );
    return { ...context, secrets };
  } catch (error) {
    if (error instanceof InvalidTokenError) return undefined;
    throw error;
  }
}

/** The bearer joins the redaction set, so no logged error can carry it either. */
function withSecret(context: ToolContext, secret: string): ToolContext {
  return { ...context, secrets: [...context.secrets, secret] };
}

/** An unexpected throw in the consent/callback flow; the message never reaches the browser. */
function failFlow(res: Response, error: unknown): void {
  logError(error instanceof Error ? (error.stack ?? error.message) : String(error));
  if (res.headersSent) return;
  res.status(500).type('html').send('<p>Sign-in failed. Restart the connection.</p>');
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
