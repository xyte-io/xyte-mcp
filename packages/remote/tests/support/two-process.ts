import { spawn } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import {
  createServer,
  request as httpRequest,
  type IncomingMessage,
  type ServerResponse
} from 'node:http';
import path from 'node:path';
import pg from 'pg';

/**
 * Pieces for running several server processes against one Postgres database,
 * as behind a load balancer: a schema of their own, a fake hub that behaves
 * like hub's OAuth server where it matters (single-use refresh tokens), the
 * built server as a child process, and a proxy that alternates between them.
 *
 * Later multi-instance tests (shared sign-in state, rate limits, deploys)
 * reuse it: `createTestSchema` → `startFakeHub` → `startServer` per process
 * (with `serverEnv`, all on one issuer: the proxy's URL) → `startAlternatingProxy`
 * → `signIn` against one process → calls through the proxy.
 *
 * `startServer` spawns the built dist: run `npm run build` first.
 */

const DIST_ENTRY = path.resolve(import.meta.dirname, '..', '..', 'dist', 'index.js');

export async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address() as { port: number };
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

export interface TestSchema {
  /** The test database, with search_path and application_name set to this schema. */
  databaseUrl: string;
  /** A pool on `databaseUrl`, for assertions. */
  admin: pg.Pool;
  drop(): Promise<void>;
}

/**
 * A schema of its own: other test files truncate the shared tables in public.
 * application_name lets lockWaiters count only this schema's connections.
 */
export async function createTestSchema(baseUrl: string): Promise<TestSchema> {
  const schema = `multi_test_${randomUUID().replaceAll('-', '')}`;
  const root = new pg.Pool({ connectionString: baseUrl, max: 1 });
  await root.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(baseUrl);
  url.searchParams.set('options', `-c search_path=${schema}`);
  url.searchParams.set('application_name', schema);
  const admin = new pg.Pool({ connectionString: url.toString(), max: 2 });
  return {
    databaseUrl: url.toString(),
    admin,
    drop: async () => {
      await admin.end();
      await root.query(`DROP SCHEMA ${schema} CASCADE`);
      await root.end();
    }
  };
}

/** Connections of this schema waiting on a grant row lock (another holds it). */
export async function lockWaiters(admin: pg.Pool): Promise<number> {
  const { rows } = await admin.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM pg_stat_activity
      WHERE wait_event_type = 'Lock' AND application_name = current_setting('application_name')
        AND query LIKE '%FOR NO KEY UPDATE%'`
  );
  return rows[0]!.n;
}

/** Connections of this schema holding a grant row lock while idle (a holder awaiting the hub). */
export async function lockHolders(admin: pg.Pool): Promise<number> {
  const { rows } = await admin.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM pg_stat_activity
      WHERE state = 'idle in transaction' AND application_name = current_setting('application_name')
        AND query LIKE '%FOR NO KEY UPDATE%'`
  );
  return rows[0]!.n;
}

export interface FakeHub {
  url: string;
  /** The refresh token of every refresh POST, in arrival order. */
  refreshes: string[];
  /** The refresh token each answered refresh handed out, in order. */
  rotatedTo: string[];
  /** The token of every revoke POST. */
  revokes: string[];
  /** Authorization headers of the API calls. */
  apiAuth: string[];
  /** Lifetime, in seconds, of the next pair handed out. */
  expiresIn: number;
  /** While true, refresh POSTs are parked until releaseHeld or dropHeld. */
  holdRefreshes: boolean;
  held(): number;
  /** Answers the parked refreshes: each rotates now, or gets invalid_grant if its token is burned. */
  releaseHeld(): void;
  /** Hangs up on the parked refreshes without processing them: nothing rotates. */
  dropHeld(): void;
  close(): Promise<void>;
}

/**
 * Hub's /oauth/token, /oauth/revoke and one org API read. Refresh tokens are
 * single-use as at hub: a used one answers invalid_grant. Each sign-in gets its
 * own user (`user-<n>`), so two sign-ins are never sibling grants.
 */
export async function startFakeHub(): Promise<FakeHub> {
  let minted = 0;
  const burned = new Set<string>();
  const parked: Array<{ token: string; res: ServerResponse }> = [];
  const json = (res: ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  const pair = (res: ServerResponse) => {
    minted += 1;
    const idToken = `h.${Buffer.from(
      JSON.stringify({ sub: `user-${minted}`, xyte_tenant_id: 'org-1' })
    ).toString('base64url')}.s`;
    json(res, 200, {
      access_token: `xoat_${minted}`,
      refresh_token: `xort_${minted}`,
      expires_in: hub.expiresIn,
      token_type: 'Bearer',
      id_token: idToken
    });
  };
  const answerRefresh = (token: string, res: ServerResponse) => {
    if (burned.has(token)) return json(res, 400, { error: 'invalid_grant' });
    burned.add(token);
    pair(res);
    hub.rotatedTo.push(`xort_${minted}`);
  };
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let body = '';
    req.on('data', (chunk: Buffer) => (body += chunk.toString()));
    req.on('end', () => {
      const form = new URLSearchParams(body);
      if (req.method === 'POST' && req.url === '/oauth/token') {
        if (form.get('grant_type') !== 'refresh_token') return pair(res);
        const token = form.get('refresh_token') ?? '';
        hub.refreshes.push(token);
        if (hub.holdRefreshes) parked.push({ token, res });
        else answerRefresh(token, res);
        return;
      }
      if (req.method === 'POST' && req.url === '/oauth/revoke') {
        hub.revokes.push(form.get('token') ?? '');
        res.writeHead(200);
        res.end();
        return;
      }
      hub.apiAuth.push(req.headers.authorization ?? '');
      json(res, 200, { devices: [] });
    });
  });
  const port = await freePort();
  await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve));
  const hub: FakeHub = {
    url: `http://127.0.0.1:${port}`,
    refreshes: [],
    rotatedTo: [],
    revokes: [],
    apiAuth: [],
    expiresIn: 3600,
    holdRefreshes: false,
    held: () => parked.length,
    releaseHeld: () => {
      for (const { token, res } of parked.splice(0)) answerRefresh(token, res);
    },
    dropHeld: () => {
      for (const { res } of parked.splice(0)) res.destroy();
    },
    close: () => {
      server.closeAllConnections();
      return new Promise<void>((resolve) => server.close(() => resolve()));
    }
  };
  return hub;
}

/** Env for one server process in OAuth mode on Postgres. All processes share `issuerUrl` and `tokenKey`. */
export function serverEnv(options: {
  port: number;
  issuerUrl: string;
  hubUrl: string;
  databaseUrl: string;
  tokenKey: string;
}): NodeJS.ProcessEnv {
  return {
    ...process.env,
    PORT: String(options.port),
    XYTE_MCP_ISSUER_URL: options.issuerUrl,
    XYTE_MCP_HUB_OAUTH_CLIENT_ID: 'mcp-client',
    XYTE_MCP_HUB_OAUTH_CLIENT_SECRET: 'mcp-secret',
    XYTE_HUB_URL: options.hubUrl,
    XYTE_MCP_READ_ONLY: '1',
    // Grant lock waits are this plus 5 s: short enough to fail a hung lock inside a test.
    XYTE_MCP_TIMEOUT_MS: '5000',
    DATABASE_URL: options.databaseUrl,
    XYTE_MCP_TOKEN_KEY: options.tokenKey
  };
}

export function newTokenKey(): string {
  return randomBytes(32).toString('base64');
}

export interface ServerProcess {
  base: string;
  /** SIGKILL (or `signal`), and wait for the exit. */
  kill(signal?: NodeJS.Signals): Promise<void>;
}

/** Spawns the built server and waits until /healthz answers. */
export async function startServer(env: NodeJS.ProcessEnv): Promise<ServerProcess> {
  if (!existsSync(DIST_ENTRY)) throw new Error(`Build first: ${DIST_ENTRY} is missing (npm run build).`);
  const base = `http://127.0.0.1:${env.PORT}`;
  const output: string[] = [];
  const child = spawn(process.execPath, [DIST_ENTRY], { env, stdio: ['ignore', 'ignore', 'pipe'] });
  child.stderr!.setEncoding('utf8');
  child.stderr!.on('data', (chunk: string) => output.push(chunk));
  const stderr = () => output.join('');
  const server: ServerProcess = {
    base,
    kill: async (signal = 'SIGKILL') => {
      if (child.exitCode !== null || child.signalCode !== null) return;
      const exited = new Promise((resolve) => child.once('exit', resolve));
      child.kill(signal);
      await exited;
    }
  };
  const deadline = Date.now() + 10_000;
  for (;;) {
    if (child.exitCode !== null) throw new Error(`server exited\n${stderr()}`);
    try {
      if ((await fetch(`${base}/healthz`)).ok) return server;
    } catch {
      // Not listening yet.
    }
    if (Date.now() > deadline) {
      await server.kill();
      throw new Error(`server never became ready\n${stderr()}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

/** A load balancer in front of `backends`: request n goes to backend n mod count. */
export async function startAlternatingProxy(
  port: number,
  backends: string[]
): Promise<{ base: string; routed: Array<{ path: string; backend: string }>; close(): Promise<void> }> {
  let next = 0;
  // Which backend served each request, in arrival order.
  const routed: Array<{ path: string; backend: string }> = [];
  const server = createServer((req, res) => {
    const backend = backends[next++ % backends.length]!;
    const target = new URL(req.url ?? '/', backend);
    routed.push({ path: target.pathname, backend });
    const upstream = httpRequest(target, { method: req.method, headers: req.headers }, (answer) => {
      res.writeHead(answer.statusCode ?? 502, answer.headers);
      answer.pipe(res);
    });
    upstream.on('error', () => {
      if (!res.headersSent) res.writeHead(502);
      res.end();
    });
    req.pipe(upstream);
  });
  await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve));
  return {
    base: `http://127.0.0.1:${port}`,
    routed,
    close: () => {
      server.closeAllConnections();
      return new Promise<void>((resolve) => server.close(() => resolve()));
    }
  };
}

export interface SignedIn {
  clientId: string;
  accessToken: string;
  refreshToken: string;
}

const REDIRECT = 'http://127.0.0.1:9/callback';

/**
 * Registration, consent, hub callback and code exchange on `base`. `afterConsent`
 * runs between consent and the hub callback and names the base the sign-in
 * finishes on (another process: the pending sign-in is in Postgres).
 */
export async function signIn(base: string, afterConsent?: () => Promise<string>): Promise<SignedIn> {
  const registered = await fetch(`${base}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' })
  });
  const { client_id: clientId } = (await registered.json()) as { client_id: string };
  const verifier = randomBytes(32).toString('base64url');
  const authorize = new URL(`${base}/authorize`);
  authorize.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256'
  }).toString();
  const page = await fetch(authorize);
  const html = await page.text();
  const field = (name: string) => new RegExp(`name="${name}" value="([^"]+)"`).exec(html)![1]!;
  const cookieOf = (response: Response) => response.headers.getSetCookie()[0]!.split(';')[0]!;
  const consent = await fetch(`${base}/oauth/consent`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookieOf(page) },
    body: new URLSearchParams({ pending: field('pending'), csrf: field('csrf'), decision: 'approve' })
  });
  const state = new URL(consent.headers.get('location')!).searchParams.get('state')!;
  if (afterConsent) base = await afterConsent();
  const callback = await fetch(`${base}/oauth/callback?state=${state}&code=hub-code`, {
    redirect: 'manual',
    headers: { Cookie: cookieOf(consent) }
  });
  const code = new URL(callback.headers.get('location')!).searchParams.get('code')!;
  const exchange = await fetch(`${base}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      code_verifier: verifier,
      client_id: clientId,
      redirect_uri: REDIRECT
    })
  });
  const tokens = (await exchange.json()) as { access_token: string; refresh_token: string };
  return { clientId, accessToken: tokens.access_token, refreshToken: tokens.refresh_token };
}

/** One tool call that reaches the hub: what makes a server refresh an expiring hub token. */
export function listDevices(base: string, accessToken: string): Promise<Response> {
  return fetch(`${base}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      Authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'xyte_api_call', arguments: { key: 'organization.devices.getDevices' } }
    })
  });
}
