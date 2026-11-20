import { timingSafeEqual } from 'node:crypto';
import type { Server } from 'node:http';
import express, { type NextFunction, type Request, type Response } from 'express';
import { ipKeyGenerator, rateLimit, type RateLimitInfo } from 'express-rate-limit';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { isJsonContentType } from '@modelcontextprotocol/sdk/shared/mediaType.js';
import { endpointCount } from '@xyteai/mcp/catalog/catalog.js';
import {
  DEFAULT_HUB_URL,
  resolveConfig,
  resolveHttpConfig,
  type ServerConfig
} from '@xyteai/mcp/config.js';
import { createToolContext, type ToolContext } from '@xyteai/mcp/context.js';
import { createHttpClient } from '@xyteai/mcp/http/client.js';
import { createHubOAuth } from '../oauth/hub-oauth.js';
import { hubIdentityOf, XyteOAuthProvider } from '../oauth/provider.js';
import { PgOAuthStore } from '../oauth/pg-store.js';
import { MemoryOAuthStore, type OAuthStore } from '../oauth/store.js';
import { TokenCipher } from '../oauth/token-cipher.js';
import { redactText } from '@xyteai/mcp/redact.js';
import { createServer } from '@xyteai/mcp/server.js';
import { log, logError } from '@xyteai/mcp/log.js';
import { errorCodeOf, logEvent } from '../log-event.js';

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

// In-memory limits: one dyno today; a shared store comes with the multi-dyno work.
const RATE_LIMIT_WINDOW_MS = 60_000;
/** Per OAuth grant (one connection), not per IP: claude.ai and ChatGPT call from shared backend IPs. */
const MCP_CALLS_PER_GRANT_PER_MINUTE = 60;
/** Requests without a valid token, per IP: room for one 401 per connection per hour on a shared IP. */
const MCP_UNAUTHENTICATED_CALLS_PER_IP_PER_MINUTE = 300;
/** Per IP; a real sign-in hits the callback once. */
const CALLBACK_CALLS_PER_IP_PER_MINUTE = 30;
/** No catalog endpoint takes a file or base64 body; the SDK default is 4 MiB. */
const MAX_MCP_BODY_BYTES = 1024 * 1024;

/** Heroku's router gives up after 30 s, so a slower request is a dead socket. */
const REQUEST_TIMEOUT_MS = 30_000;
/** For the headers alone; Node requires it not to exceed REQUEST_TIMEOUT_MS. */
const HEADERS_TIMEOUT_MS = 20_000;

/** Under Heroku's 30 s SIGTERM-to-SIGKILL window. */
const SHUTDOWN_DEADLINE_MS = 28_000;
/** In-flight requests get this long before the provider drain starts regardless. */
const REQUEST_GRACE_MS = 10_000;
/** A health probe answer is reused this long after its database check ends. */
const HEALTH_CHECK_REUSE_MS = 2_000;

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

  let store: OAuthStore | undefined;
  let provider: XyteOAuthProvider | undefined;

  // Before the auth check: a platform health probe carries no credentials, and
  // it reveals nothing a port scan would not. In OAuth mode every request needs
  // the token store, so a dead database fails the probe (and the uptime alert).
  // ponytail: probes share one check while it runs and reuse its answer for 2 s,
  // so an unauthenticated flood costs at most one query per interval.
  const checkStore = async (): Promise<boolean> => {
    try {
      // ponytail: a primary-key lookup through the existing interface stands in
      // for a ping(); add one to OAuthStore if this lookup ever stops being cheap.
      await store?.getClient('healthz');
      return true;
    } catch (error) {
      logError(`healthz: token store check failed: ${errorCodeOf(error)}`);
      return false;
    }
  };
  let storeCheck: { answers: Promise<boolean>; reuseUntil: number } | undefined;
  const storeAnswers = (): Promise<boolean> => {
    if (!storeCheck || Date.now() >= storeCheck.reuseUntil) {
      const check = { answers: checkStore(), reuseUntil: Infinity };
      void check.answers.then(() => {
        check.reuseUntil = Date.now() + HEALTH_CHECK_REUSE_MS;
      });
      storeCheck = check;
    }
    return storeCheck.answers;
  };
  app.get(HEALTH_PATH, (_req, res) => {
    void storeAnswers()
      .then((up) => {
        if (up) res.type('text/plain').send('ok');
        else res.status(503).type('text/plain').send('unavailable');
      })
      .catch((error: unknown) => logError(`healthz: ${errorCodeOf(error)}`));
  });
  if (oauth) {
    if (oauth.databaseUrl) {
      store = await PgOAuthStore.connect(
        oauth.databaseUrl,
        // resolveHttpConfig refuses a database without a key.
        new TokenCipher(oauth.tokenKey!, oauth.previousTokenKey)
      );
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
    const callbackRateLimit = rateLimit({
      windowMs: RATE_LIMIT_WINDOW_MS,
      limit: CALLBACK_CALLS_PER_IP_PER_MINUTE,
      standardHeaders: 'draft-8',
      legacyHeaders: false,
      // A browser lands here, so the same page as any other sign-in failure.
      handler: (req, res) => {
        logError(`429 ${req.method} ${CALLBACK_PATH} — rate limited (per IP)`);
        sendSignInFailedPage(res, 429, 'Too many attempts. Wait a minute, then restart the connection.');
      }
    });
    app.get(CALLBACK_PATH, callbackRateLimit, (req, res) => {
      void flow.callback(req, res).catch((error: unknown) => failFlow(res, error));
    });
  }

  const mcpAuth: McpAuth = { staticToken, staticContext, provider, config, upstream, oauth };
  // Identify the caller before limiting, so the budget follows the grant, not the IP.
  // Trade-off, on purpose: a throttled request still costs its token lookup, because a
  // per-IP limit in front would also throttle valid users on a shared claude.ai or
  // ChatGPT egress IP. Add a pre-auth IP guard if production shows store floods.
  const resolveCaller = (req: Request, res: Response, next: NextFunction) => {
    resolveIdentity(req, mcpAuth).then(
      (identity) => {
        res.locals.identity = identity;
        next();
      },
      (error: unknown) => {
        // Only a bad token is a 401: a store outage is a retryable 503, or every
        // connected client would drop its tokens and restart the OAuth flow.
        logError(`token check failed: ${errorCodeOf(error)}`);
        respondJsonRpcError(res, 503, -32603, 'temporarily unavailable, retry');
      }
    );
  };
  const identityOf = (res: Response) => res.locals.identity as Caller | undefined;
  const mcpRateLimit = rateLimit({
    windowMs: RATE_LIMIT_WINDOW_MS,
    limit: (_req, res) =>
      identityOf(res)
        ? MCP_CALLS_PER_GRANT_PER_MINUTE
        : MCP_UNAUTHENTICATED_CALLS_PER_IP_PER_MINUTE,
    keyGenerator: (req, res) => {
      const identity = identityOf(res);
      return identity ? `grant:${identity.who.connection}` : ipKeyGenerator(req.ip ?? '');
    },
    // The static bearer is one shared dev/CI identity, so it is not limited.
    skip: (_req, res) => {
      const identity = identityOf(res);
      return identity !== undefined && identity.who.connection === undefined;
    },
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    // A flooded IP sees this instead of the 401 until its window ends.
    handler: (req, res) => {
      const { used, limit, resetTime } = (req as Request & { rateLimit: RateLimitInfo }).rateLimit;
      // Only the first refusal per key per window: a flood would otherwise log every call.
      if (used === limit + 1) {
        const grantId = identityOf(res)?.who.connection;
        logError(`429 ${req.method} ${MCP_PATH} — rate limited (${grantId ? `grant ${grantId}` : 'per IP'})`);
      }
      // Clients surface the message, not Retry-After, so the wait goes in the text too.
      const resetMs = resetTime ? resetTime.getTime() - Date.now() : RATE_LIMIT_WINDOW_MS;
      const waitSeconds = Math.max(1, Math.ceil(resetMs / 1000));
      respondJsonRpcError(res, 429, -32000, `rate limit exceeded, retry in ${waitSeconds} s`);
    }
  });

  // Parsed here, after auth, only to refuse JSON-RPC batches: the SDK runs up to 100
  // messages of one POST in parallel, which would multiply the per-grant limit (and
  // protocol 2025-06-18 has no batching). Parsed exactly when the SDK accepts the
  // Content-Type; anything else gets the SDK's 415 before a body is read.
  const parseMcpBody = express.json({
    limit: MAX_MCP_BODY_BYTES,
    inflate: false,
    type: (req) => isJsonContentType(req.headers['content-type'])
  });
  app.post(MCP_PATH, resolveCaller, mcpRateLimit, (req, res) => {
    const identity = identityOf(res);
    if (!identity) return respondUnauthorized(req, res, mcpAuth);
    parseMcpBody(req, res, (error?: unknown) => {
      // body-parser's errors, in the JSON-RPC shape the SDK used for them.
      const { status, type } = (error ?? {}) as { status?: number; type?: string };
      if (error && status === 413) {
        // ponytail: body-parser drains the whole body before this 413; only authenticated, under-limit callers get here and REQUEST_TIMEOUT_MS (30 s) bounds it.
        const message = `Payload Too Large: Request body must not exceed ${MAX_MCP_BODY_BYTES} bytes`;
        return respondJsonRpcError(res, 413, -32000, message);
      }
      // A non-UTF charset, or any Content-Encoding (inflate: false).
      if (error && status === 415) {
        // Fixed text: body-parser's message quotes the caller's charset / encoding back.
        return respondJsonRpcError(res, 415, -32000, 'Unsupported Media Type: send uncompressed UTF-8 JSON');
      }
      if (error && type === 'entity.parse.failed') {
        return respondJsonRpcError(res, 400, -32700, 'Parse error: Invalid JSON');
      }
      // Aborted or short reads, stream errors: not the caller's JSON, so not -32700.
      if (error) {
        // Type and status only, never body content; a client hanging up is not worth a line.
        if (type !== 'request.aborted') {
          logError(`${status ?? 400} ${req.method} ${MCP_PATH} — could not read the request body (${type ?? 'unknown'})`);
        }
        return respondJsonRpcError(res, status ?? 400, -32603, 'Internal error: could not read the request body');
      }
      if (Array.isArray(req.body)) {
        const message = 'Invalid Request: JSON-RPC batching is not supported, send one message per request';
        return respondJsonRpcError(res, 400, -32600, message);
      }
      void handleMcp(req, res, identity, req.body);
    });
  });

  // POST is the whole protocol here, and the spec lets a server say so.
  //
  // Without this the SDK answers GET with an SSE stream that can never emit —
  // a stateless server has no session to push to — so every connected client
  // parks an idle stream on the dyno until Heroku's 55s router timeout kills
  // it, and reconnects. DELETE is the same kind of lie: it reports 200 for
  // terminating a session that was never created.
  app.all(MCP_PATH, resolveCaller, mcpRateLimit, (req, res) => {
    // Auth first, as on POST: an unauthenticated caller learns nothing about
    // the endpoint, not even which methods it supports.
    if (!identityOf(res)) return respondUnauthorized(req, res, mcpAuth);
    res.setHeader('Allow', 'POST');
    respondJsonRpcError(res, 405, -32000, `only POST is supported at ${MCP_PATH}`);
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
  listener.requestTimeout = REQUEST_TIMEOUT_MS;
  listener.headersTimeout = HEADERS_TIMEOUT_MS;
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

async function handleMcp(
  req: Request,
  res: Response,
  caller: Caller,
  parsedBody: unknown
): Promise<void> {
  const { context, who } = caller;
  const server = createServer(context, {
    onToolCall: (call) =>
      logEvent('tool_call', {
        ...who,
        tool: call.tool,
        endpoint: call.endpoint,
        status: call.status,
        outcome: call.isError ? 'error' : 'ok',
        duration_ms: call.durationMs
      })
  });
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
    // The transport still rejects a bad Accept/Content-Type per spec, and reads
    // the body itself when none was parsed.
    await transport.handleRequest(req, res, parsedBody);
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

/** An authenticated caller: its tool context, and who it is for the logs (nobody in static mode). */
interface Caller {
  context: ToolContext;
  who: { connection?: string; organization?: string; user?: string };
}

/**
 * Map the presented bearer to an identity: in static mode the token to the
 * shared process context (constant-time compare), in OAuth mode a token to a
 * per-request context carrying its grant's hub token (refreshed on demand by
 * the provider's hub client).
 */
async function resolveIdentity(req: Request, auth: McpAuth): Promise<Caller | undefined> {
  // The auth scheme is case-insensitive (RFC 7235 2.1).
  const header = req.headers.authorization ?? '';
  if (!/^bearer\s+/i.test(header)) return undefined;
  const presented = header.replace(/^bearer\s+/i, '').trim();

  if (auth.staticToken && auth.staticContext) {
    return matches(presented, auth.staticToken) ? { context: auth.staticContext, who: {} } : undefined;
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
    return {
      context: { ...context, secrets },
      who: { connection: hub.grantId, organization: hub.tenantId, user: hub.sub }
    };
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
  logEvent('sign_in', { outcome: 'failed', reason: 'error' });
  if (res.headersSent) return;
  sendSignInFailedPage(res, 500, 'Restart the connection.');
}

function sendSignInFailedPage(res: Response, status: number, nextStep: string): void {
  res.status(status).type('html').send(`<p>Sign-in failed. ${nextStep}</p>`);
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
