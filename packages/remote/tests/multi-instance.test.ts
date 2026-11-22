import { createHash } from 'node:crypto';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  createTestSchema,
  freePort,
  listDevices,
  lockHolders,
  lockWaiters,
  newTokenKey,
  serverEnv,
  signIn,
  startAlternatingProxy,
  startFakeHub,
  startServer,
  type FakeHub,
  type ServerProcess,
  type TestSchema
} from './support/two-process.js';

/**
 * Two built server processes on one Postgres database behind an alternating
 * proxy, as behind a load balancer: a single-use hub refresh token is sent
 * once between them, a killed refresher frees its lock, and a revoke on one
 * waits for the other's refresh. Run `npm run build` first.
 */

const PG_URL = process.env.TEST_DATABASE_URL;

describe.skipIf(!PG_URL)('two server processes on one database', () => {
  let schema: TestSchema;
  let hub: FakeHub;
  let proxy: Awaited<ReturnType<typeof startAlternatingProxy>>;
  const servers: ServerProcess[] = [];
  const envs: NodeJS.ProcessEnv[] = [];

  beforeAll(async () => {
    schema = await createTestSchema(PG_URL!);
    hub = await startFakeHub();
    const proxyPort = await freePort();
    const tokenKey = newTokenKey();
    for (let i = 0; i < 2; i += 1) {
      const env = serverEnv({
        port: await freePort(),
        issuerUrl: `http://127.0.0.1:${proxyPort}`,
        hubUrl: hub.url,
        databaseUrl: schema.databaseUrl,
        tokenKey
      });
      envs.push(env);
      // One at a time: the second boot finds the schema migrated.
      servers.push(await startServer(env));
    }
    proxy = await startAlternatingProxy(proxyPort, servers.map((server) => server.base));
  }, 30_000);
  afterEach(() => {
    hub.holdRefreshes = false;
    hub.releaseHeld();
  });
  afterAll(async () => {
    await Promise.all(servers.map((server) => server.kill()));
    await proxy?.close();
    await hub?.close();
    await schema?.drop();
  });

  /** A sign-in whose hub token is already inside the refresh window. */
  async function expiringSignIn() {
    hub.expiresIn = 30;
    try {
      return await signIn(servers[0]!.base);
    } finally {
      hub.expiresIn = 3600;
    }
  }

  const liveGrants = async () =>
    (await schema.admin.query('SELECT 1 FROM oauth_grants WHERE revoked_at IS NULL')).rowCount;

  it('20 parallel calls over both processes send exactly one hub refresh, and the grant stays', async () => {
    const { accessToken } = await expiringSignIn();
    const grantsBefore = await liveGrants();
    const before = hub.refreshes.length;
    hub.holdRefreshes = true;

    const calls = Array.from({ length: 20 }, () => listDevices(proxy.base, accessToken));
    await vi.waitFor(() => expect(hub.held()).toBe(1), { timeout: 5_000 });
    await vi.waitFor(async () => expect(await lockWaiters(schema.admin)).toBe(1), { timeout: 5_000 });
    hub.holdRefreshes = false;
    hub.releaseHeld();
    const answers = await Promise.all(calls);

    for (const answer of answers) {
      expect(answer.status).toBe(200);
      expect(((await answer.json()) as { result?: { isError?: boolean } }).result?.isError).toBeFalsy();
    }
    expect(hub.refreshes).toHaveLength(before + 1);
    expect(hub.apiAuth.slice(-20)).toEqual(Array(20).fill(`Bearer ${hub.rotatedTo.at(-1)!.replace('xort_', 'xoat_')}`));
    expect(await liveGrants()).toBe(grantsBefore);
  });

  it('a revoke on one process waits for the refresh on the other, then revokes the new hub token', async () => {
    const { clientId, accessToken, refreshToken } = await expiringSignIn();
    const before = hub.refreshes.length;
    hub.holdRefreshes = true;

    const call = listDevices(servers[0]!.base, accessToken);
    await vi.waitFor(() => expect(hub.held()).toBe(1), { timeout: 5_000 });
    let revoked = false;
    const revoke = fetch(`${servers[1]!.base}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: refreshToken, client_id: clientId })
    }).then((answer) => ((revoked = true), answer));
    await vi.waitFor(async () => expect(await lockWaiters(schema.admin)).toBe(1), { timeout: 5_000 });
    expect(revoked).toBe(false);
    hub.holdRefreshes = false;
    hub.releaseHeld();

    expect((await call).status).toBe(200);
    expect((await revoke).status).toBe(200);
    expect(hub.revokes.at(-1)).toBe(hub.rotatedTo.at(-1));
    // No token is minted after the revoke, on either process.
    for (const server of servers) expect((await listDevices(server.base, accessToken)).status).toBe(401);
    expect(hub.refreshes).toHaveLength(before + 1);
  });

  it('a sign-in alternates over both processes at every step, and its connection works on either', async () => {
    const from = proxy.routed.length;
    const { accessToken } = await signIn(proxy.base);
    const servedBy = (path: string) => proxy.routed.slice(from).find((request) => request.path === path)!.backend;
    expect(servedBy('/authorize')).not.toBe(servedBy('/oauth/consent'));
    expect(servedBy('/oauth/consent')).not.toBe(servedBy('/oauth/callback'));
    for (const server of servers) expect((await listDevices(server.base, accessToken)).status).toBe(200);
  });

  it('a sign-in whose process gets SIGTERM after consent finishes on the other process', async () => {
    try {
      const { accessToken } = await signIn(servers[0]!.base, async () => {
        await servers[0]!.kill('SIGTERM');
        return servers[1]!.base;
      });
      expect((await listDevices(servers[1]!.base, accessToken)).status).toBe(200);
    } finally {
      // Else the next test runs with a dead servers[0] and hides this failure.
      await servers[0]!.kill();
      servers[0] = await startServer(envs[0]!);
    }
  });

  it('limits one connection to 60 calls a minute over both processes, and answers 503 when the counter fails', async () => {
    const { accessToken } = await signIn(proxy.base);
    const from = proxy.routed.length;
    const statuses: number[] = [];
    for (let i = 0; i < 60; i += 1) {
      const answer = await listDevices(proxy.base, accessToken);
      await answer.arrayBuffer();
      statuses.push(answer.status);
    }
    expect(statuses).toEqual(Array(60).fill(200));
    const limited = await listDevices(proxy.base, accessToken);
    expect(limited.status).toBe(429);
    expect(await limited.json()).toMatchObject({
      error: { code: -32000, message: expect.stringMatching(/^rate limit exceeded, retry in ([1-9]|[1-5]\d|60) s$/) }
    });
    expect(new Set(proxy.routed.slice(from).map((request) => request.backend)).size).toBe(2);

    await schema.admin.query('ALTER TABLE mcp_rate_limit_counters RENAME TO mcp_rate_limit_counters_away');
    try {
      const answer = await listDevices(proxy.base, accessToken);
      expect(answer.status).toBe(503);
      expect(await answer.json()).toMatchObject({ error: { code: -32603, message: 'temporarily unavailable, retry' } });
    } finally {
      await schema.admin.query('ALTER TABLE mcp_rate_limit_counters_away RENAME TO mcp_rate_limit_counters');
    }
  });

  it('counts 405 GETs over both processes against the same connection budget as POSTs', async () => {
    const { accessToken } = await signIn(proxy.base);
    const from = proxy.routed.length;
    for (let i = 0; i < 60; i += 1) {
      const answer = await fetch(`${proxy.base}/mcp`, { headers: { Authorization: `Bearer ${accessToken}` } });
      await answer.arrayBuffer();
      expect(answer.status).toBe(405);
    }
    expect(new Set(proxy.routed.slice(from).map((request) => request.backend)).size).toBe(2);
    expect((await listDevices(proxy.base, accessToken)).status).toBe(429);
  });

  it('answers a POST with no token 401 and writes no rate-limit counter', async () => {
    const counters = async () =>
      (await schema.admin.query<{ n: string }>('SELECT count(*) AS n FROM mcp_rate_limit_counters')).rows[0]!.n;
    const before = await counters();
    const answer = await fetch(`${proxy.base}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
    });
    expect(answer.status).toBe(401);
    expect(await counters()).toBe(before);
  });

  // Last: it kills a process and starts it again.
  it('kill -9 of the refreshing process frees the lock and keeps the stored pair; the next call refreshes', async () => {
    const { accessToken } = await expiringSignIn();
    const stored = async () =>
      (
        await schema.admin.query<{ hash: string }>(
          'SELECT hub_refresh_token_hash AS hash FROM oauth_grants WHERE revoked_at IS NULL ORDER BY id DESC LIMIT 1'
        )
      ).rows[0]!.hash;
    const pairBefore = await stored();
    const before = hub.refreshes.length;
    hub.holdRefreshes = true;

    void listDevices(servers[0]!.base, accessToken).catch(() => undefined);
    await vi.waitFor(() => expect(hub.held()).toBe(1), { timeout: 5_000 });
    const sent = hub.refreshes.at(-1)!;
    expect(await lockHolders(schema.admin)).toBe(1); // the refreshing process holds the row
    await servers[0]!.kill();
    hub.holdRefreshes = false;
    hub.dropHeld(); // hub never processed it: the token is not burned

    expect(await stored()).toBe(pairBefore);
    expect(pairBefore).toBe(createHash('sha256').update(sent).digest('hex'));
    const answer = await listDevices(servers[1]!.base, accessToken);
    expect(answer.status).toBe(200);
    expect(((await answer.json()) as { result?: { isError?: boolean } }).result?.isError).toBeFalsy();
    expect(hub.refreshes.slice(before)).toEqual([sent, sent]);
    expect(await stored()).toBe(createHash('sha256').update(hub.rotatedTo.at(-1)!).digest('hex'));

    servers[0] = await startServer(envs[0]!);
  });
});
