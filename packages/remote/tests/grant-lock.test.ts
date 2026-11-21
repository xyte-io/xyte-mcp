import { randomBytes } from 'node:crypto';
import type pg from 'pg';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { createHubOAuth } from '../src/oauth/hub-oauth.js';
import { PgOAuthStore } from '../src/oauth/pg-store.js';
import { XyteOAuthProvider } from '../src/oauth/provider.js';
import { TokenCipher } from '../src/oauth/token-cipher.js';
import { stubHttp } from '../../mcp/tests/support/context.js';
import { createTestSchema, lockWaiters, startFakeHub, type FakeHub, type TestSchema } from './support/two-process.js';

/**
 * Two providers, each on its own store, over one Postgres database: two server
 * processes in one test process. The hub refresh of a grant is serialized by a
 * row lock, so they never send one single-use hub refresh token twice.
 */

const PG_URL = process.env.TEST_DATABASE_URL;
const ISSUER = 'https://mcp.test';
const KEY = randomBytes(32);
const NOW = () => Math.floor(Date.now() / 1000);

describe.skipIf(!PG_URL)('XyteOAuthProvider: two instances on one database', () => {
  let schema: TestSchema;
  let hub: FakeHub;
  const stores: PgOAuthStore[] = [];

  beforeAll(async () => {
    schema = await createTestSchema(PG_URL!);
    hub = await startFakeHub();
  });
  afterEach(async () => {
    hub.releaseHeld();
    hub.holdRefreshes = false;
    await Promise.all(stores.splice(0).map((store) => store.close()));
  });
  afterAll(async () => {
    await hub.close();
    await schema.drop();
  });

  async function instances(hubTimeoutMs?: number) {
    const pair = [];
    for (let i = 0; i < 2; i += 1) {
      const store = await PgOAuthStore.connect(schema.databaseUrl, new TokenCipher(KEY), {
        ...(hubTimeoutMs === undefined ? {} : { hubTimeoutMs })
      });
      stores.push(store);
      const provider = new XyteOAuthProvider(
        store,
        createHubOAuth({
          hubUrl: hub.url,
          clientId: 'mcp-client',
          clientSecret: 's3cret',
          redirectUri: `${ISSUER}/oauth/callback`,
          timeoutMs: 10_000
        }),
        ISSUER
      );
      pair.push({ store, provider });
    }
    return pair as [(typeof pair)[0], (typeof pair)[0]];
  }

  /** A grant whose hub token is inside the refresh window, with a live access token. */
  async function expiringGrant(store: PgOAuthStore) {
    const refreshToken = `xort_seed_${randomBytes(4).toString('hex')}`;
    const client = { client_id: 'c1', redirect_uris: ['https://a/cb'] } as OAuthClientInformationFull;
    await store.saveClient(client);
    const grantId = await store.createGrant('c1', {
      accessToken: 'xoat_seed',
      refreshToken,
      expiresAt: NOW() + 30,
      sub: `user-${refreshToken}`,
      tenantId: 'org-1'
    });
    const accessToken = `xmcp_at_${randomBytes(8).toString('hex')}`;
    await store.saveToken({ token: accessToken, kind: 'access', grantId, expiresAt: NOW() + 600 });
    return { client, grantId, accessToken, refreshToken };
  }

  const get = (provider: XyteOAuthProvider, grantId: string, upstream = stubHttp(() => ({ data: {} }))) =>
    provider.hubHttp(grantId, upstream).request({ method: 'GET', url: `${hub.url}/x`, headers: {}, endpointKey: 'k' });

  type Run = (sql: string, values?: unknown[]) => Promise<unknown>;
  /** The next grant lock connection of `store` sends every statement through `intercept`. */
  function interceptLockStatements(
    store: PgOAuthStore,
    intercept: (sql: string, run: Run, values?: unknown[]) => Promise<unknown>
  ) {
    const lockPool = (store as unknown as { lockPool: pg.Pool }).lockPool;
    const connect = lockPool.connect.bind(lockPool) as () => Promise<pg.PoolClient>;
    vi.spyOn(lockPool, 'connect').mockImplementationOnce((async () => {
      const client = await connect();
      const run = client.query.bind(client) as Run;
      client.query = ((sql: string, values?: unknown[]) => intercept(sql, run, values)) as never;
      return client;
    }) as never);
  }
  /** The commit is lost: the transaction rolls back. */
  const failCommit = async (sql: string, run: Run, values?: unknown[]) => {
    if (sql !== 'COMMIT') return run(sql, values);
    await run('ROLLBACK');
    throw Object.assign(new Error('connection lost'), { code: '08006' });
  };
  /** Every save of a rotated pair fails at the server, aborting the transaction. */
  const failRotate = (sql: string, run: Run, values?: unknown[]) =>
    sql.includes('SET hub_access_token') ? run('SELECT 1 / 0') : run(sql, values);
  /** Used at hub already, as by an earlier lost refresh: the next refresh gets invalid_grant. */
  const burn = (refreshToken: string) =>
    fetch(`${hub.url}/oauth/token`, {
      method: 'POST',
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken })
    });
  /** Runs `fn` with stderr captured; returns what was written. */
  async function captureStderr(fn: () => Promise<unknown>): Promise<string> {
    const write = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    try {
      await fn();
      return write.mock.calls.map(([line]) => String(line)).join('');
    } finally {
      write.mockRestore();
    }
  }

  it('sends one hub refresh between both instances for parallel calls on an expiring token', async () => {
    const [a, b] = await instances();
    const { grantId, refreshToken } = await expiringGrant(a.store);
    const before = hub.refreshes.length;
    hub.holdRefreshes = true;
    const upstream = stubHttp(() => ({ data: {} }));

    const calls = [a, b].flatMap(({ provider }) =>
      Array.from({ length: 5 }, () => get(provider, grantId, upstream))
    );
    await vi.waitFor(() => expect(hub.held()).toBe(1), { timeout: 5_000 });
    // The other instance is queued on the grant's row, not refreshing on its own.
    await vi.waitFor(async () => expect(await lockWaiters(schema.admin)).toBe(1), { timeout: 5_000 });
    hub.holdRefreshes = false;
    hub.releaseHeld();
    await Promise.all(calls);

    expect(hub.refreshes.slice(before)).toEqual([refreshToken]);
    const fresh = (await a.store.getGrant(grantId))!.hub!.accessToken;
    expect(upstream.calls.map((call) => call.headers.Authorization)).toEqual(Array(10).fill(`Bearer ${fresh}`));
    expect((await b.store.getGrant(grantId))?.revoked).toBe(false);
  });

  it('a revoke on one instance waits for the other one\'s refresh, then revokes the new hub token', async () => {
    const [a, b] = await instances();
    const { client, grantId, accessToken } = await expiringGrant(a.store);
    const before = hub.refreshes.length;
    hub.holdRefreshes = true;

    const call = get(a.provider, grantId);
    await vi.waitFor(() => expect(hub.held()).toBe(1), { timeout: 5_000 });
    let revoked = false;
    const revoke = b.provider.revokeToken(client, { token: accessToken }).then(() => (revoked = true));
    await vi.waitFor(async () => expect(await lockWaiters(schema.admin)).toBe(1), { timeout: 5_000 });
    expect(revoked).toBe(false);
    hub.holdRefreshes = false;
    hub.releaseHeld();
    await call;
    await revoke;

    expect(hub.refreshes).toHaveLength(before + 1);
    expect(hub.revokes.at(-1)).toBe(hub.rotatedTo.at(-1));
    // Nothing is minted after the revoke.
    await expect(get(a.provider, grantId)).rejects.toMatchObject({ kind: 'auth' });
    await expect(get(b.provider, grantId)).rejects.toMatchObject({ kind: 'auth' });
    expect(hub.refreshes).toHaveLength(before + 1);
  });

  const revokedInDb = async (grantId: string) =>
    (
      await schema.admin.query(
        `SELECT 1 FROM oauth_grants
          WHERE id = $1 AND revoked_at IS NOT NULL AND hub_access_token IS NULL AND hub_refresh_token IS NULL`,
        [grantId]
      )
    ).rowCount === 1;

  // A revoke inside the lock commits with it: rolled back, the grant would keep a burned token.
  it.each([
    [
      'invalid_grant',
      async (refreshToken: string) => {
        // Burn the token at hub first, as an earlier lost refresh would have.
        await fetch(`${hub.url}/oauth/token`, {
          method: 'POST',
          body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken })
        });
      },
      () => undefined
    ],
    [
      'an unknown outcome (hub hung up)',
      async () => {
        hub.holdRefreshes = true;
      },
      async () => {
        await vi.waitFor(() => expect(hub.held()).toBe(1), { timeout: 5_000 });
        hub.holdRefreshes = false;
        hub.dropHeld();
      }
    ]
  ])('%s on refresh revokes the grant in the database, and the next call sends no refresh', async (_name, before, during) => {
    const [a, b] = await instances();
    const { grantId, refreshToken } = await expiringGrant(a.store);
    await before(refreshToken);
    const sent = hub.refreshes.length;

    const call = get(a.provider, grantId);
    await during();
    await expect(call).rejects.toMatchObject({ kind: 'auth' });
    expect(await revokedInDb(grantId)).toBe(true);
    await expect(get(b.provider, grantId)).rejects.toMatchObject({ kind: 'auth' });
    expect(hub.refreshes).toHaveLength(sent + 1);
  });

  // The revoke rolled back with the failed commit: it is redone on the main pool.
  it('invalid_grant whose revoke fails to commit still revokes the grant, and the next call sends no refresh', async () => {
    const [a, b] = await instances();
    const { grantId, refreshToken } = await expiringGrant(a.store);
    await burn(refreshToken);
    interceptLockStatements(a.store, failCommit);
    const sent = hub.refreshes.length;

    await expect(get(a.provider, grantId)).rejects.toMatchObject({ kind: 'auth' });
    vi.restoreAllMocks();
    expect(await revokedInDb(grantId)).toBe(true);
    await expect(get(b.provider, grantId)).rejects.toMatchObject({ kind: 'auth' });
    expect(hub.refreshes).toHaveLength(sent + 1);
  });

  it('when that revoke cannot be redone either, logs it and still signs the call out, with no revoke event', async () => {
    const [a] = await instances();
    const { grantId, refreshToken } = await expiringGrant(a.store);
    await burn(refreshToken);
    interceptLockStatements(a.store, failCommit);
    vi.spyOn(a.store, 'revokeGrant').mockRejectedValue(Object.assign(new Error('db down'), { code: '57P01' }));

    const stderr = await captureStderr(() =>
      expect(get(a.provider, grantId)).rejects.toMatchObject({ kind: 'auth' })
    );
    vi.restoreAllMocks();
    expect(stderr).toContain(`ERROR grant ${grantId}: could not revoke the grant after a failed hub refresh`);
    expect(stderr).not.toContain('"event":"revoke"');
  });

  // Fail closed under the lock: the stored token is burned at hub.
  it('a save of the new pair that fails on every try revokes the grant under the lock; neither instance refreshes again', async () => {
    const [a, b] = await instances();
    const { grantId } = await expiringGrant(a.store);
    interceptLockStatements(a.store, failRotate);
    const sent = hub.refreshes.length;

    const stderr = await captureStderr(() =>
      expect(get(a.provider, grantId)).rejects.toMatchObject({ kind: 'auth' })
    );
    vi.restoreAllMocks();
    expect(stderr).toContain('"reason":"hub_save_failed"');
    expect(await revokedInDb(grantId)).toBe(true);
    await expect(get(b.provider, grantId)).rejects.toMatchObject({ kind: 'auth' });
    expect(hub.refreshes).toHaveLength(sent + 1);
  });

  // The documented window: the lock is released before the pair is safe, and it
  // is saved on the main pool. (A waiter queued meanwhile could replay; not tested.)
  it('a commit lost after a successful refresh saves the new pair outside the lock; the other instance then sends nothing', async () => {
    const [a, b] = await instances();
    const { grantId } = await expiringGrant(a.store);
    interceptLockStatements(a.store, failCommit);
    const sent = hub.refreshes.length;

    await get(a.provider, grantId);
    vi.restoreAllMocks();
    expect((await b.store.getGrant(grantId))?.hub?.refreshToken).toBe(hub.rotatedTo.at(-1));
    await get(b.provider, grantId);
    expect(hub.refreshes).toHaveLength(sent + 1);
  });

  // pg-pool drops its idle 'error' listener on checkout: unhandled, the server
  // ending the session mid hub refresh would crash the whole process.
  it('a lock connection the server ends during the hub refresh does not crash the process: the pair is saved outside the lock', async () => {
    const [a, b] = await instances();
    const { grantId } = await expiringGrant(a.store);
    const sent = hub.refreshes.length;
    hub.holdRefreshes = true;

    const call = get(a.provider, grantId);
    await vi.waitFor(() => expect(hub.held()).toBe(1), { timeout: 5_000 });
    const { rows } = await schema.admin.query(
      `SELECT pg_terminate_backend(pid) AS ended FROM pg_stat_activity
        WHERE application_name = current_setting('application_name')
          AND state = 'idle in transaction' AND query LIKE '%FOR NO KEY UPDATE%'`
    );
    expect(rows).toEqual([{ ended: true }]);
    await new Promise((resolve) => setTimeout(resolve, 300)); // the session's end reaches the client
    hub.holdRefreshes = false;
    hub.releaseHeld();
    await captureStderr(() => call);

    expect((await b.store.getGrant(grantId))?.hub?.refreshToken).toBe(hub.rotatedTo.at(-1));
    await get(b.provider, grantId); // the lock is free, and the saved pair is fresh
    expect(hub.refreshes).toHaveLength(sent + 1);
  });

  // Retried inside the lock: released between tries, a waiter elsewhere would read
  // the stored, now burned token and send it to hub.
  it('a failed save of the new pair is retried under the lock: a waiter on the other instance sends nothing', async () => {
    const [a, b] = await instances();
    const { grantId, refreshToken } = await expiringGrant(a.store);
    let failed = false;
    interceptLockStatements(a.store, (sql, run, values) => {
      if (failed) return run(sql, values);
      failed = sql.includes('SET hub_access_token');
      return failRotate(sql, run, values);
    });
    const before = hub.refreshes.length;
    hub.holdRefreshes = true;

    const first = get(a.provider, grantId);
    await vi.waitFor(() => expect(hub.held()).toBe(1), { timeout: 5_000 });
    const waiter = get(b.provider, grantId);
    await vi.waitFor(async () => expect(await lockWaiters(schema.admin)).toBe(1), { timeout: 5_000 });
    hub.holdRefreshes = false;
    hub.releaseHeld();
    await first;
    await waiter;
    vi.restoreAllMocks();

    expect(failed).toBe(true);
    expect(hub.refreshes.slice(before)).toEqual([refreshToken]);
    expect((await a.store.getGrant(grantId))?.hub?.refreshToken).toBe(hub.rotatedTo.at(-1));
  });

  it('an unreadable hub token read under the lock stays revoked', async () => {
    const [a] = await instances();
    const { grantId } = await expiringGrant(a.store);
    await schema.admin.query(
      `UPDATE oauth_grants SET hub_access_token = 'xoat_plain', hub_refresh_token = 'xort_plain' WHERE id = $1`,
      [grantId]
    );
    const sent = hub.refreshes.length;
    // Straight to the locked read, as a refresh after a hub 401 does.
    await expect(
      (a.provider as unknown as { refreshHub(id: string, stale: string): Promise<string> }).refreshHub(grantId, 'xoat_seed')
    ).rejects.toMatchObject({ kind: 'auth' });
    expect(await revokedInDb(grantId)).toBe(true);
    expect(hub.refreshes).toHaveLength(sent);
  });

  it('a waiter past the lock timeout gets a retryable error and never sends the refresh token', async () => {
    const [, b] = await instances(0); // lock_timeout: 5 s
    const { grantId } = await expiringGrant(b.store);
    const before = hub.refreshes.length;
    const holder = await schema.admin.connect();
    try {
      await holder.query('BEGIN');
      await holder.query('SELECT 1 FROM oauth_grants WHERE id = $1 FOR NO KEY UPDATE', [grantId]);
      await expect(get(b.provider, grantId)).rejects.toMatchObject({
        kind: 'network',
        message: 'This connection is busy.'
      });
    } finally {
      await holder.query('ROLLBACK');
      holder.release();
    }
    expect(hub.refreshes).toHaveLength(before);
    expect((await b.store.getGrant(grantId))?.revoked).toBe(false);
  }, 15_000);
});
