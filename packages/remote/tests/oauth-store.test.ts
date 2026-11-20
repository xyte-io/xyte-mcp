import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { HubSignIn } from '../src/oauth/hub-oauth.js';
import { PgOAuthStore } from '../src/oauth/pg-store.js';
import {
  hashToken,
  MemoryOAuthStore,
  ABANDONED_GRANT_RETENTION_SECONDS,
  REVOKED_GRANT_RETENTION_SECONDS,
  UNUSED_CLIENT_RETENTION_SECONDS,
  type OAuthStore
} from '../src/oauth/store.js';
import { TokenCipher } from '../src/oauth/token-cipher.js';

/**
 * The store guarantees the provider relies on, run against both stores: always
 * the in-memory one, and Postgres when TEST_DATABASE_URL names a throwaway
 * database (its three tables are truncated before every test).
 */

const PG_URL = process.env.TEST_DATABASE_URL;
const KEY_A = randomBytes(32);
const KEY_B = randomBytes(32);
const NOW = () => Math.floor(Date.now() / 1000);

function signIn(overrides: Partial<HubSignIn> = {}): HubSignIn {
  return {
    accessToken: 'xoat_1',
    refreshToken: 'xort_1',
    expiresAt: NOW() + 3600,
    sub: 'user-1',
    tenantId: 'org-1',
    email: 'user@example.com',
    ...overrides
  };
}

interface Harness {
  store: OAuthStore;
  reset(): Promise<void>;
  close(): Promise<void>;
}

const harnesses: Array<[string, () => Promise<Harness>]> = [
  [
    'memory',
    async () => {
      const harness: Harness = {
        store: new MemoryOAuthStore(),
        reset: async () => {
          harness.store = new MemoryOAuthStore();
        },
        close: async () => {}
      };
      return harness;
    }
  ]
];
if (PG_URL) {
  harnesses.push([
    'postgres',
    async () => {
      const store = await PgOAuthStore.connect(PG_URL, new TokenCipher(KEY_A));
      const admin = new pg.Pool({ connectionString: PG_URL, max: 1 });
      return {
        store,
        reset: async () => {
          await admin.query('TRUNCATE oauth_tokens, oauth_grants, oauth_clients RESTART IDENTITY');
        },
        close: async () => {
          await store.close();
          await admin.end();
        }
      };
    }
  ]);
}

describe.each(harnesses)('OAuthStore contract: %s', (_name, make) => {
  let harness: Harness;
  const store = () => harness.store;

  beforeAll(async () => {
    harness = await make();
  });
  beforeEach(async () => {
    await harness.reset();
  });
  afterAll(async () => {
    await harness.close();
  });

  it('saves, overwrites and reads clients', async () => {
    const client = { client_id: 'c1', redirect_uris: ['https://a/cb'] } as OAuthClientInformationFull;
    await store().saveClient(client);
    await store().saveClient({ ...client, client_name: 'renamed' });
    expect(await store().getClient('c1')).toEqual({ ...client, client_name: 'renamed' });
    expect(await store().getClient('nope')).toBeUndefined();
  });

  it('round-trips a grant, its hub sign-in to the second', async () => {
    const hub = signIn();
    const id = await store().createGrant('c1', hub);
    expect(typeof id).toBe('string');
    expect(await store().getGrant(id)).toEqual({ id, clientId: 'c1', hub, revoked: false });
    expect(await store().getGrant('999999')).toBeUndefined();
  });

  it('revokeGrant marks the grant revoked and drops its hub tokens', async () => {
    const id = await store().createGrant('c1', signIn());
    await store().revokeGrant(id);
    const grant = await store().getGrant(id);
    expect(grant?.revoked).toBe(true);
    expect(grant?.hub).toBeUndefined();
  });

  it('rotates hub tokens only from the current refresh token, never after a revoke', async () => {
    const id = await store().createGrant('c1', signIn());
    const next = { accessToken: 'xoat_2', refreshToken: 'xort_2', expiresAt: NOW() + 7200 };

    expect(await store().rotateHubTokens(id, 'xort_stale', next)).toBe(false);
    expect(await store().rotateHubTokens(id, 'xort_1', next)).toBe(true);
    expect((await store().getGrant(id))?.hub).toEqual(signIn(next));
    expect(await store().rotateHubTokens(id, 'xort_1', { ...next, refreshToken: 'xort_3' })).toBe(
      false
    );

    await store().revokeGrant(id);
    expect(await store().rotateHubTokens(id, 'xort_2', next)).toBe(false);
    expect((await store().getGrant(id))?.hub).toBeUndefined();
  });

  it('round-trips tokens by kind, with their optional fields', async () => {
    const id = await store().createGrant('c1', signIn());
    const expiresAt = NOW() + 600;
    await store().saveToken({
      token: 't1',
      kind: 'code',
      grantId: id,
      codeChallenge: 'ch',
      redirectUri: 'https://a/cb',
      resource: 'https://mcp/mcp',
      expiresAt
    });
    await store().saveToken({ token: 't1', kind: 'access', grantId: id, expiresAt });

    expect(await store().getToken('t1', 'code')).toEqual({
      kind: 'code',
      grantId: id,
      codeChallenge: 'ch',
      redirectUri: 'https://a/cb',
      resource: 'https://mcp/mcp',
      expiresAt
    });
    expect(await store().getToken('t1', 'access')).toEqual({
      kind: 'access',
      grantId: id,
      expiresAt
    });
    expect(await store().getToken('t1', 'refresh')).toBeUndefined();
  });

  it('lets exactly one of two concurrent deletes take a token', async () => {
    const id = await store().createGrant('c1', signIn());
    for (const kind of ['code', 'refresh'] as const) {
      await store().saveToken({ token: 'once', kind, grantId: id, expiresAt: NOW() + 600 });
      const results = await Promise.all([
        store().deleteToken('once', kind),
        store().deleteToken('once', kind)
      ]);
      expect(results.sort()).toEqual([false, true]);
      expect(await store().getToken('once', kind)).toBeUndefined();
    }
  });

  it('finds a live sibling only on the same sign-in, unrevoked, with a live access/refresh token', async () => {
    const self = await store().createGrant('c1', signIn());
    const sibling = await store().createGrant('c2', signIn({ refreshToken: 'xort_s' }));
    const live = (grantId: string, kind: 'access' | 'refresh' | 'code', ttl = 600) =>
      store().saveToken({ token: `${grantId}-${kind}-${ttl}`, kind, grantId, expiresAt: NOW() + ttl });
    await live(self, 'access');

    // No tokens, a code only, or expired tokens: not in use.
    expect(await store().hasLiveHubSibling('user-1', 'org-1', self)).toBe(false);
    await live(sibling, 'code');
    await live(sibling, 'access', -10);
    expect(await store().hasLiveHubSibling('user-1', 'org-1', self)).toBe(false);

    await live(sibling, 'refresh');
    expect(await store().hasLiveHubSibling('user-1', 'org-1', self)).toBe(true);
    expect(await store().hasLiveHubSibling('user-1', 'org-2', self)).toBe(false);
    expect(await store().hasLiveHubSibling('user-2', 'org-1', self)).toBe(false);
    expect(await store().hasLiveHubSibling('user-1', 'org-1', sibling)).toBe(true); // self has a live token too

    await store().revokeGrant(sibling);
    expect(await store().hasLiveHubSibling('user-1', 'org-1', self)).toBe(false);
  });

  it('refuses a rotation on a revoked grant', async () => {
    const id = await store().createGrant('c1', signIn());
    await store().revokeGrant(id);
    const next = { accessToken: 'xoat_2', refreshToken: 'xort_2', expiresAt: NOW() + 7200 };
    expect(await store().rotateHubTokens(id, 'xort_1', next)).toBe(false);
    expect((await store().getGrant(id))?.hub).toBeUndefined();
  });

  describe('sweepExpiredOAuthRows', () => {
    const DAY = 24 * 60 * 60;
    const client = (id: string) =>
      ({ client_id: id, redirect_uris: ['https://a/cb'] }) as OAuthClientInformationFull;
    const token = (grantId: string, kind: 'code' | 'access' | 'refresh', expiresAt: number) =>
      store().saveToken({ token: `${grantId}-${kind}-${expiresAt}`, kind, grantId, expiresAt });
    const hasToken = async (grantId: string, kind: 'code' | 'access' | 'refresh', expiresAt: number) =>
      (await store().getToken(`${grantId}-${kind}-${expiresAt}`, kind)) !== undefined;

    it('deletes expired codes, access and refresh tokens, and keeps live ones', async () => {
      const id = await store().createGrant('c1', signIn());
      const now = NOW();
      for (const kind of ['code', 'access', 'refresh'] as const) {
        await token(id, kind, now - 1);
        await token(id, kind, now + 600);
      }
      await token(id, 'access', now); // expires at `now`: already unusable

      expect(await store().sweepExpiredOAuthRows(now)).toEqual({ tokens: 4, grants: 0, clients: 0 });
      for (const kind of ['code', 'access', 'refresh'] as const) {
        expect(await hasToken(id, kind, now - 1)).toBe(false);
        expect(await hasToken(id, kind, now + 600)).toBe(true);
      }
      expect(await store().getGrant(id)).toBeDefined();
    });

    // No client saved: the orphan branch must not take a revoked grant before its retention.
    it('keeps a revoked grant without tokens or client until the retention has passed', async () => {
      const id = await store().createGrant('c1', signIn());
      await store().revokeGrant(id);
      const due = NOW() + REVOKED_GRANT_RETENTION_SECONDS;

      expect(await store().sweepExpiredOAuthRows(due - 60)).toEqual({ tokens: 0, grants: 0, clients: 0 });
      expect(await store().getGrant(id)).toBeDefined();
      expect(await store().sweepExpiredOAuthRows(due + 60)).toEqual({ tokens: 0, grants: 1, clients: 0 });
      expect(await store().getGrant(id)).toBeUndefined();
    });

    it('deletes a revoked grant without tokens once the retention has passed, keeping its client', async () => {
      await store().saveClient(client('c1'));
      const id = await store().createGrant('c1', signIn());
      await store().revokeGrant(id);
      const due = NOW() + REVOKED_GRANT_RETENTION_SECONDS;

      expect(await store().sweepExpiredOAuthRows(due - 60)).toEqual({ tokens: 0, grants: 0, clients: 0 });
      expect(await store().getGrant(id)).toBeDefined();
      expect(await store().sweepExpiredOAuthRows(due + 60)).toEqual({ tokens: 0, grants: 1, clients: 0 });
      expect(await store().getGrant(id)).toBeUndefined();
      expect(await store().getClient('c1')).toBeDefined();
    });

    it('keeps a revoked grant that still has a live token, and any unrevoked grant', async () => {
      await store().saveClient(client('c1'));
      const revoked = await store().createGrant('c1', signIn());
      const unrevoked = await store().createGrant('c1', signIn());
      await store().revokeGrant(revoked);
      const later = NOW() + 96 * DAY; // below ABANDONED_GRANT_RETENTION_SECONDS
      await token(revoked, 'refresh', later + 600);

      expect(await store().sweepExpiredOAuthRows(later)).toEqual({ tokens: 0, grants: 0, clients: 0 });
      expect(await store().getGrant(revoked)).toBeDefined();
      expect(await store().getGrant(unrevoked)).toBeDefined();
    });

    // A sign-in whose client the sweep deleted while it was at the hub.
    it('deletes an unrevoked grant without tokens whose client is gone', async () => {
      const id = await store().createGrant('gone', signIn());
      await token(id, 'code', NOW() + 600);

      expect(await store().sweepExpiredOAuthRows(NOW())).toEqual({ tokens: 0, grants: 0, clients: 0 });
      expect(await store().getGrant(id)).toBeDefined();
      expect(await store().sweepExpiredOAuthRows(NOW() + 601)).toEqual({ tokens: 1, grants: 1, clients: 0 });
      expect(await store().getGrant(id)).toBeUndefined();
    });

    // The real path to that orphan: the client is swept, then the hub callback creates the grant.
    it('deletes the grant a callback created for a client swept during the sign-in, once its code expires', async () => {
      await store().saveClient(client('c1'));
      expect(await store().sweepExpiredOAuthRows(NOW() + 31 * DAY)).toEqual({ tokens: 0, grants: 0, clients: 1 });
      const id = await store().createGrant('c1', signIn());
      const codeExpiresAt = NOW() + 600;
      await token(id, 'code', codeExpiresAt);

      expect(await store().sweepExpiredOAuthRows(NOW())).toEqual({ tokens: 0, grants: 0, clients: 0 });
      expect(await store().sweepExpiredOAuthRows(codeExpiresAt + 1)).toEqual({ tokens: 1, grants: 1, clients: 0 });
      expect(await store().getGrant(id)).toBeUndefined();
    });

    // A code never exchanged, or a user idle past the refresh lifetime: hub ended the chain.
    it('deletes an unrevoked grant without tokens whose client exists once the retention has passed', async () => {
      expect(ABANDONED_GRANT_RETENTION_SECONDS).toBe(97 * DAY);
      await store().saveClient(client('c1'));
      const id = await store().createGrant('c1', signIn());

      expect(await store().sweepExpiredOAuthRows(NOW() + 96 * DAY)).toEqual({ tokens: 0, grants: 0, clients: 0 });
      expect(await store().getGrant(id)).toBeDefined();
      // The client, past its own retention, loses its last grant and goes in the same run.
      expect(await store().sweepExpiredOAuthRows(NOW() + 98 * DAY)).toEqual({ tokens: 0, grants: 1, clients: 1 });
      expect(await store().getGrant(id)).toBeUndefined();
      expect(await store().getClient('c1')).toBeUndefined();
    });

    it('deletes a client without grants once the retention has passed, never one with a grant', async () => {
      await store().saveClient(client('unused'));
      await store().saveClient(client('revoked'));
      await store().saveClient(client('live'));
      const revoked = await store().createGrant('revoked', signIn());
      await store().revokeGrant(revoked);
      await store().createGrant('live', signIn());
      const due = NOW() + UNUSED_CLIENT_RETENTION_SECONDS;
      // Keeps the revoked grant (and so its client) past both retentions.
      await token(revoked, 'refresh', due + 600);

      expect(await store().sweepExpiredOAuthRows(due - 60)).toEqual({ tokens: 0, grants: 0, clients: 0 });
      expect(await store().getClient('unused')).toBeDefined();
      expect(await store().sweepExpiredOAuthRows(due + 60)).toEqual({ tokens: 0, grants: 0, clients: 1 });
      expect(await store().getClient('unused')).toBeUndefined();
      expect(await store().getClient('revoked')).toBeDefined();
      expect(await store().getClient('live')).toBeDefined();
    });

    it('deletes a client in the same run that deletes its last grant', async () => {
      await store().saveClient(client('c1'));
      const id = await store().createGrant('c1', signIn());
      await token(id, 'access', NOW() + 600);
      await store().revokeGrant(id);

      expect(await store().sweepExpiredOAuthRows(NOW() + 365 * DAY)).toEqual({
        tokens: 1,
        grants: 1,
        clients: 1
      });
      expect(await store().getClient('c1')).toBeUndefined();
    });

    // A refresh exchange deletes the old refresh token before saving the new pair.
    it('never deletes a live grant caught between a refresh delete and the save of the new pair', async () => {
      await store().saveClient(client('c1'));
      const id = await store().createGrant('c1', signIn());
      const expiresAt = NOW() + 600;
      await token(id, 'refresh', expiresAt);
      expect(await store().deleteToken(`${id}-refresh-${expiresAt}`, 'refresh')).toBe(true);

      // A young grant, and the latest run before ABANDONED_GRANT_RETENTION_SECONDS: both keep it.
      expect(await store().sweepExpiredOAuthRows(NOW())).toEqual({ tokens: 0, grants: 0, clients: 0 });
      expect(await store().sweepExpiredOAuthRows(NOW() + 96 * DAY)).toEqual({ tokens: 0, grants: 0, clients: 0 });
      await token(id, 'refresh', expiresAt + 600);
      expect((await store().getGrant(id))?.revoked).toBe(false);
      expect(await store().getClient('c1')).toBeDefined();
    });

    it('returns zeros on a second run over the same rows', async () => {
      await store().saveClient(client('c1'));
      const id = await store().createGrant('c2', signIn());
      await token(id, 'access', NOW() - 1);
      await store().revokeGrant(id);
      const later = NOW() + 365 * DAY;

      expect(await store().sweepExpiredOAuthRows(later)).toEqual({ tokens: 1, grants: 1, clients: 1 });
      expect(await store().sweepExpiredOAuthRows(later)).toEqual({ tokens: 0, grants: 0, clients: 0 });
    });

    // A second save or revoke must not restart a retention, or a junk client or ended grant lives on.
    it('counts the retentions from the first save of a client and the first revoke of a grant', async () => {
      await store().saveClient(client('c1'));
      const id = await store().createGrant('c1', signIn());
      await store().revokeGrant(id);
      const first = NOW();
      // Both clocks (this one, and Postgres now()) must move past `first + 1`.
      await vi.waitFor(() => expect(NOW()).toBeGreaterThanOrEqual(first + 2), { timeout: 3000 });
      await store().saveClient(client('c1'));
      await store().revokeGrant(id);

      expect(await store().sweepExpiredOAuthRows(first + 1 + REVOKED_GRANT_RETENTION_SECONDS)).toEqual({
        tokens: 0,
        grants: 1,
        clients: 0
      });
      expect(await store().sweepExpiredOAuthRows(first + 1 + UNUSED_CLIENT_RETENTION_SECONDS)).toEqual({
        tokens: 0,
        grants: 0,
        clients: 1
      });
    });
  });
});

// A failing cleanup step names itself and its code only (a pg message can name the host and
// role), and the steps after it are not issued.
describe.skipIf(!PG_URL)('PgOAuthStore: a failing cleanup step', () => {
  it('throws "the <step> step failed: <code>" with the cause, and issues no later step', async () => {
    const store = await PgOAuthStore.connect(PG_URL!, new TokenCipher(KEY_A));
    const pool = (store as unknown as { pool: pg.Pool }).pool;
    const query = pool.query.bind(pool) as (sql: string, values?: unknown[]) => Promise<unknown>;
    const issued: string[] = [];
    const failure = Object.assign(new Error('canceling statement, host=secret-host role=secret'), {
      code: '57014'
    });
    vi.spyOn(pool, 'query').mockImplementation(((sql: string, values?: unknown[]) => {
      issued.push(sql);
      return sql.includes('DELETE FROM oauth_grants') ? Promise.reject(failure) : query(sql, values);
    }) as never);
    try {
      const error = await store.sweepExpiredOAuthRows(NOW()).then(
        () => undefined,
        (rejected: unknown) => rejected as Error
      );
      expect(error?.message).toBe('the grants step failed: 57014');
      expect(error?.message).not.toContain('secret');
      expect(error?.cause).toBe(failure);
      expect(issued.some((sql) => sql.includes('DELETE FROM oauth_tokens'))).toBe(true);
      expect(issued.some((sql) => sql.includes('DELETE FROM oauth_clients'))).toBe(false);
    } finally {
      vi.restoreAllMocks();
      await store.close();
    }
  });
});

describe.skipIf(!PG_URL)('PgOAuthStore: cleanup runs and shutdown', () => {
  let admin: pg.Pool;
  beforeAll(() => {
    admin = new pg.Pool({ connectionString: PG_URL, max: 1 });
  });
  beforeEach(async () => {
    await admin.query('TRUNCATE oauth_tokens, oauth_grants, oauth_clients RESTART IDENTITY');
  });
  afterAll(async () => {
    await admin.end();
  });

  // Every dyno runs its own cleanup: a concurrent run deletes nothing the other one did.
  it('two concurrent runs on two pools delete each row once between them', async () => {
    const a = await PgOAuthStore.connect(PG_URL!, new TokenCipher(KEY_A));
    const b = await PgOAuthStore.connect(PG_URL!, new TokenCipher(KEY_A));
    try {
      for (let i = 0; i < 3; i += 1) {
        await a.saveClient({ client_id: `c${i}`, redirect_uris: ['https://a/cb'] } as OAuthClientInformationFull);
        const id = await a.createGrant(`c${i}`, signIn());
        await a.saveToken({ token: `t${i}`, kind: 'access', grantId: id, expiresAt: NOW() + 600 });
        await a.revokeGrant(id);
      }
      const later = NOW() + 365 * 24 * 60 * 60;
      const [fromA, fromB] = await Promise.all([a.sweepExpiredOAuthRows(later), b.sweepExpiredOAuthRows(later)]);
      expect({
        tokens: fromA.tokens + fromB.tokens,
        grants: fromA.grants + fromB.grants,
        clients: fromA.clients + fromB.clients
      }).toEqual({ tokens: 3, grants: 3, clients: 3 });
    } finally {
      await Promise.all([a.close(), b.close()]);
    }
  });

  // Else the next step would query an ended pool and the run would fail at shutdown.
  it('close() during a run lets the step in flight finish and issues no later step', async () => {
    const store = await PgOAuthStore.connect(PG_URL!, new TokenCipher(KEY_A));
    const pool = (store as unknown as { pool: pg.Pool }).pool;
    const query = pool.query.bind(pool) as (sql: string, values?: unknown[]) => Promise<unknown>;
    const issued: string[] = [];
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    vi.spyOn(pool, 'query').mockImplementation((async (sql: string, values?: unknown[]) => {
      issued.push(sql);
      const result = await query(sql, values);
      if (sql.includes('DELETE FROM oauth_tokens')) await held;
      return result;
    }) as never);
    try {
      const run = store.sweepExpiredOAuthRows(NOW());
      await vi.waitFor(() => expect(issued.some((sql) => sql.includes('DELETE FROM oauth_tokens'))).toBe(true));
      const closed = store.close();
      release();
      await expect(run).resolves.toEqual({ tokens: 0, grants: 0, clients: 0 });
      await closed;
      expect(issued.some((sql) => /DELETE FROM oauth_(grants|clients)/.test(sql))).toBe(false);
    } finally {
      vi.restoreAllMocks();
    }
  });
});

/** What only the Postgres store does: the hub tokens are encrypted at rest. */
describe.skipIf(!PG_URL)('PgOAuthStore: hub tokens at rest', () => {
  let admin: pg.Pool;
  const stores: PgOAuthStore[] = [];
  const open = async (current: Buffer, previous?: Buffer) => {
    const store = await PgOAuthStore.connect(PG_URL!, new TokenCipher(current, previous));
    stores.push(store);
    return store;
  };
  const row = async (id: string) =>
    (
      await admin.query<{
        hub_access_token: string | null;
        hub_refresh_token: string | null;
        hub_refresh_token_hash: string | null;
      }>(
        'SELECT hub_access_token, hub_refresh_token, hub_refresh_token_hash FROM oauth_grants WHERE id = $1',
        [id]
      )
    ).rows[0]!;
  /** Silences log() and returns a reader for what it wrote since. */
  const captureLog = (): (() => string) => {
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    return () => write.mock.calls.map((call) => String(call[0])).join('');
  };

  beforeAll(() => {
    admin = new pg.Pool({ connectionString: PG_URL, max: 1 });
  });
  beforeEach(async () => {
    await admin.query('TRUNCATE oauth_tokens, oauth_grants, oauth_clients RESTART IDENTITY');
  });
  afterAll(async () => {
    vi.restoreAllMocks();
    await Promise.all(stores.map((store) => store.close()));
    // Live rows under this run's random keys would stop the next run's boots.
    await admin.query('TRUNCATE oauth_tokens, oauth_grants, oauth_clients RESTART IDENTITY');
    await admin.end();
  });

  it('logs the key ids at boot, and never a key', async () => {
    const logText = captureLog();
    await open(KEY_B, KEY_A);
    vi.restoreAllMocks();
    const ids = [new TokenCipher(KEY_B).currentKeyId, new TokenCipher(KEY_A).currentKeyId];
    expect(logText()).toContain(`hub token key id ${ids[0]} (previous: ${ids[1]})`);
    expect(logText()).not.toContain(KEY_A.toString('base64'));
    expect(logText()).not.toContain(KEY_B.toString('base64'));
  });

  it('stores no plaintext hub token, and the refresh token hash for compare-and-swap', async () => {
    const store = await open(KEY_A);
    const id = await store.createGrant('c1', signIn());
    const stored = await row(id);
    expect(stored.hub_access_token).toMatch(/^v1\./);
    expect(stored.hub_refresh_token).toMatch(/^v1\./);
    expect(JSON.stringify(stored)).not.toContain('xoat_1');
    expect(JSON.stringify(stored)).not.toContain('xort_1');
    expect(stored.hub_refresh_token_hash).toBe(hashToken('xort_1'));

    const next = { accessToken: 'xoat_2', refreshToken: 'xort_2', expiresAt: NOW() + 7200 };
    expect(await store.rotateHubTokens(id, 'xort_1', next)).toBe(true);
    const rotated = await row(id);
    expect(rotated.hub_access_token).toMatch(/^v1\./);
    expect(JSON.stringify(rotated)).not.toContain('xoat_2');
    expect(rotated.hub_refresh_token_hash).toBe(hashToken('xort_2'));

    await store.revokeGrant(id);
    expect(await row(id)).toEqual({
      hub_access_token: null,
      hub_refresh_token: null,
      hub_refresh_token_hash: null
    });
  });

  // The contract checks revokeGrant; here revoked_at is set while the tokens stay on the row.
  it('refuses a rotation on a revoked grant even while its tokens are still on the row', async () => {
    const store = await open(KEY_A);
    const id = await store.createGrant('c1', signIn());
    await admin.query('UPDATE oauth_grants SET revoked_at = now() WHERE id = $1', [id]);
    const next = { accessToken: 'xoat_2', refreshToken: 'xort_2', expiresAt: NOW() + 7200 };
    expect(await store.rotateHubTokens(id, 'xort_1', next)).toBe(false);
  });

  it('reads rows under the previous key, rewrites them under the current one on rotation', async () => {
    // All booted before any grant exists: a store booting with KEY_A grants live
    // and no KEY_A refuses to start (tested below); one already running revokes.
    const underA = await open(KEY_A);
    const rotating = await open(KEY_B, KEY_A);
    const onlyB = await open(KEY_B);
    const first = signIn(); // once: signIn() reads the clock
    const idle = await underA.createGrant('c1', first);
    const active = await underA.createGrant('c1', first);

    expect((await rotating.getGrant(idle))?.hub).toEqual(first);
    const next = { accessToken: 'xoat_2', refreshToken: 'xort_2', expiresAt: NOW() + 7200 };
    expect(await rotating.rotateHubTokens(active, 'xort_1', next)).toBe(true);
    const idB = new TokenCipher(KEY_B).currentKeyId;
    expect((await row(active)).hub_access_token).toMatch(new RegExp(`^v1\\.${idB}\\.`));
    expect((await row(active)).hub_refresh_token).toMatch(new RegExp(`^v1\\.${idB}\\.`));

    // PREVIOUS dropped: the row never rewritten is revoked, the rotated one is not.
    const storedIdle = await row(idle);
    const logText = captureLog();
    const lost = await onlyB.getGrant(idle);
    vi.restoreAllMocks();
    expect(lost).toEqual({ id: idle, clientId: 'c1', revoked: true });
    expect((await onlyB.getGrant(active))?.hub).toEqual(signIn(next));
    const idA = new TokenCipher(KEY_A).currentKeyId;
    expect(logText()).toContain(`grant ${idle}`);
    expect(logText()).toContain(`unknown key id (key id ${idA})`);
    expect(logText()).toContain('revoking the grant');
    expect(logText()).not.toContain(storedIdle.hub_access_token!);
    expect(logText()).not.toContain(storedIdle.hub_refresh_token!);
  });

  // A wrong key would otherwise revoke every grant on first read.
  it('refuses to boot while live grants use a key it does not have, naming only the key id', async () => {
    const KEY_C = randomBytes(32);
    const store = await open(KEY_A);
    const id = await store.createGrant('c1', signIn());
    const idA = new TokenCipher(KEY_A).currentKeyId;

    const refused = open(KEY_B);
    await expect(refused).rejects.toThrow(
      // Not wrapped as a connection failure: the operator sees the key text first.
      new RegExp(`^OAuth store: live grants use hub token key id\\(s\\) ${idA}, which .*XYTE_MCP_TOKEN_KEY_PREVIOUS`)
    );
    await expect(refused).rejects.not.toThrow(KEY_A.toString('base64'));
    await expect(open(KEY_C, KEY_B)).rejects.toThrow(idA);

    // The two-step rotation passes at each step: new key as PREVIOUS, then swapped.
    await open(KEY_A, KEY_B);
    await open(KEY_B, KEY_A);
    // The grant revoked (its tokens dropped): nothing left to read.
    await store.revokeGrant(id);
    await open(KEY_C);
  });

  it('boots with a new key over revoked rows that still hold tokens', async () => {
    const store = await open(KEY_A);
    const id = await store.createGrant('c1', signIn());
    await admin.query('UPDATE oauth_grants SET revoked_at = now() WHERE id = $1', [id]);
    await open(KEY_B);
  });

  // Else it would count as a live sibling, and a disconnect of the user's next
  // sign-in would skip the hub revoke.
  it('revokes an unreadable grant on read: no longer a live sibling, and logged once', async () => {
    const store = await open(KEY_A);
    const unreadable = await store.createGrant('c1', signIn());
    const next = await store.createGrant('c1', signIn({ refreshToken: 'xort_n' }));
    for (const id of [unreadable, next]) {
      await store.saveToken({ token: `${id}-refresh`, kind: 'refresh', grantId: id, expiresAt: NOW() + 600 });
    }
    await admin.query(
      `UPDATE oauth_grants SET hub_access_token = 'xoat_plain', hub_refresh_token = 'xort_plain' WHERE id = $1`,
      [unreadable]
    );
    expect(await store.hasLiveHubSibling('user-1', 'org-1', next)).toBe(true);

    const logText = captureLog();
    expect(await store.getGrant(unreadable)).toEqual({ id: unreadable, clientId: 'c1', revoked: true });
    const firstLog = logText();
    expect(await store.getGrant(unreadable)).toEqual({ id: unreadable, clientId: 'c1', revoked: true });
    vi.restoreAllMocks();
    expect(firstLog).toContain(`grant ${unreadable}`);
    expect(logText()).toBe(firstLog);

    expect(await row(unreadable)).toEqual({
      hub_access_token: null,
      hub_refresh_token: null,
      hub_refresh_token_hash: null
    });
    expect(
      (await admin.query('SELECT 1 FROM oauth_grants WHERE id = $1 AND revoked_at IS NOT NULL', [unreadable]))
        .rowCount
    ).toBe(1);
    expect(await store.hasLiveHubSibling('user-1', 'org-1', next)).toBe(false);
  });

  // An old dyno still serving during the deploy writes plain text.
  it('revokes a plaintext row on read, without logging the token', async () => {
    const store = await open(KEY_A);
    const id = await store.createGrant('c1', signIn());
    await admin.query(
      `UPDATE oauth_grants SET hub_access_token = 'xoat_plain', hub_refresh_token = 'xort_plain' WHERE id = $1`,
      [id]
    );
    const logText = captureLog();
    expect(await store.getGrant(id)).toEqual({ id, clientId: 'c1', revoked: true });
    vi.restoreAllMocks();
    expect(logText()).toContain('not encrypted');
    expect(logText()).toContain(
      `${JSON.stringify({ event: 'revoke', connection: id, organization: 'org-1', user: 'user-1', reason: 'unreadable_token' })}\n`
    );
    expect(logText()).not.toContain('xoat_plain');
    expect(logText()).not.toContain('xort_plain');
  });

  it('revokes a grant whose refresh token alone fails to authenticate, dropping both tokens', async () => {
    const store = await open(KEY_A);
    const id = await store.createGrant('c1', signIn());
    const stored = (await row(id)).hub_refresh_token!;
    const bytes = Buffer.from(stored.split('.')[2]!, 'base64url');
    bytes[12]! ^= 1; // the GCM tag
    await admin.query('UPDATE oauth_grants SET hub_refresh_token = $2 WHERE id = $1', [
      id,
      `${stored.split('.').slice(0, 2).join('.')}.${bytes.toString('base64url')}`
    ]);
    const logText = captureLog();
    expect(await store.getGrant(id)).toEqual({ id, clientId: 'c1', revoked: true });
    vi.restoreAllMocks();
    expect(logText()).toContain('authentication failed');
    expect(await row(id)).toEqual({
      hub_access_token: null,
      hub_refresh_token: null,
      hub_refresh_token_hash: null
    });
  });

  // Only a TokenDecryptError means "unreadable": any other failure is a bug, not a reason to sign out.
  it('rejects, and revokes nothing, when decrypting fails with a plain error', async () => {
    const cipher = new TokenCipher(KEY_A);
    const store = await PgOAuthStore.connect(PG_URL!, cipher);
    stores.push(store);
    const id = await store.createGrant('c1', signIn());
    vi.spyOn(cipher, 'decrypt').mockImplementation(() => {
      throw new Error('boom');
    });
    await expect(store.getGrant(id)).rejects.toThrow('boom');
    vi.restoreAllMocks();
    expect(
      (await admin.query('SELECT 1 FROM oauth_grants WHERE id = $1 AND revoked_at IS NULL', [id])).rowCount
    ).toBe(1);
  });

  // An old dyno still serving during the deploy writes plain text; the next boot clears it.
  it('revokes live plaintext grants at boot, logging only their count, and still boots', async () => {
    const store = await open(KEY_A);
    const plain = await store.createGrant('c1', signIn());
    const kept = await store.createGrant('c1', signIn());
    await admin.query(
      `UPDATE oauth_grants SET hub_access_token = 'xoat_plain', hub_refresh_token = 'xort_plain' WHERE id = $1`,
      [plain]
    );
    const logText = captureLog();
    await open(KEY_A);
    vi.restoreAllMocks();
    expect(await row(plain)).toEqual({
      hub_access_token: null,
      hub_refresh_token: null,
      hub_refresh_token_hash: null
    });
    expect((await store.getGrant(plain))?.revoked).toBe(true);
    expect((await store.getGrant(kept))?.revoked).toBe(false);
    expect(logText()).toContain('revoked 1 live grant(s) holding unencrypted hub tokens');
    expect(logText()).not.toContain('xort_plain');
  });

  // Either column, and a plain value that happens to start with 'v1.'.
  it('revokes at boot a live grant with either token not in the encrypted shape', async () => {
    const store = await open(KEY_A);
    const ids = [
      await store.createGrant('c1', signIn()),
      await store.createGrant('c1', signIn()),
      await store.createGrant('c1', signIn())
    ];
    await admin.query(`UPDATE oauth_grants SET hub_access_token = 'v1.xoat_plain' WHERE id = $1`, [ids[0]]);
    await admin.query(`UPDATE oauth_grants SET hub_refresh_token = 'v1.xort_secret.AAAA' WHERE id = $1`, [
      ids[1]
    ]);
    const logText = captureLog();
    await open(KEY_A);
    vi.restoreAllMocks();
    expect(logText()).toContain('revoked 2 live grant(s) holding unencrypted hub tokens');
    expect((await row(ids[0]!)).hub_access_token).toBeNull();
    expect((await row(ids[1]!)).hub_refresh_token).toBeNull();
    expect((await store.getGrant(ids[2]!))?.revoked).toBe(false);
  });

  it('names only well-formed key ids in the boot refusal, and boots over malformed values alone', async () => {
    const store = await open(KEY_A);
    const ids = [await store.createGrant('c1', signIn()), await store.createGrant('c1', signIn())];
    await admin.query(`UPDATE oauth_grants SET hub_refresh_token = 'v1.xort_secret.AAAA' WHERE id = $1`, [
      ids[0]
    ]);
    const idA = new TokenCipher(KEY_A).currentKeyId;
    const refused = open(KEY_B);
    await expect(refused).rejects.toThrow(new RegExp(`key id\\(s\\) ${idA}, which`));
    await expect(refused).rejects.not.toThrow('xort_secret');
    // Malformed alone is no key problem: it boots, and the boot sweep revokes that grant.
    await store.revokeGrant(ids[1]!);
    await open(KEY_B);
    expect((await row(ids[0]!)).hub_refresh_token).toBeNull();
  });

  it('refuses to boot while a live grant holds an access token under a key it does not have', async () => {
    const KEY_C = randomBytes(32);
    const store = await open(KEY_A);
    const id = await store.createGrant('c1', signIn());
    await admin.query('UPDATE oauth_grants SET hub_access_token = $2 WHERE id = $1', [
      id,
      new TokenCipher(KEY_C).encrypt('xoat_1', 'hub_access_token')
    ]);
    await expect(open(KEY_A)).rejects.toThrow(
      new RegExp(`key id\\(s\\) ${new TokenCipher(KEY_C).currentKeyId}, which`)
    );
  });
});
