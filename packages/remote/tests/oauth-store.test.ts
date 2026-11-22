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
  type OAuthStore,
  type PendingSignIn
} from '../src/oauth/store.js';
import { TokenCipher } from '../src/oauth/token-cipher.js';
import { lockWaiters } from './support/two-process.js';

/**
 * The store guarantees the provider relies on, run against both stores: always
 * the in-memory one, and Postgres when TEST_DATABASE_URL names a throwaway
 * database (its tables are truncated before every test).
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

function pendingSignIn(overrides: Partial<PendingSignIn> = {}): PendingSignIn {
  return {
    clientId: 'c1',
    redirectUri: 'https://a/cb',
    codeChallenge: 'client-challenge',
    state: 'st4te',
    resource: 'https://mcp/mcp',
    csrfHash: hashToken('csrf'),
    browserKeyHash: hashToken('browser-key'),
    approved: false,
    hubVerifier: 'v'.repeat(43),
    expiresAt: NOW() + 600,
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
      const store = await PgOAuthStore.connect(PG_URL, new TokenCipher(KEY_A), 15_000);
      const admin = new pg.Pool({ connectionString: PG_URL, max: 1 });
      return {
        store,
        reset: async () => {
          await admin.query('TRUNCATE oauth_tokens, oauth_grants, oauth_clients, oauth_pending_sign_ins RESTART IDENTITY');
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

  describe('pending sign-ins', () => {
    const MAX = 10_000;

    it('round-trips a pending sign-in, with and without its optional fields, until it expires', async () => {
      const now = NOW();
      const full = pendingSignIn({ expiresAt: now + 600 });
      const bare = pendingSignIn({ expiresAt: now + 600 });
      delete bare.state;
      delete bare.resource;
      expect(await store().createPendingSignIn('p1', full, MAX, now)).toBe(true);
      expect(await store().createPendingSignIn('p2', bare, MAX, now)).toBe(true);

      expect(await store().getPendingSignIn('p1', now)).toEqual(full);
      expect(await store().getPendingSignIn('p2', now)).toEqual(bare);
      expect(await store().getPendingSignIn('nope', now)).toBeUndefined();
      expect(await store().getPendingSignIn('p1', now + 600)).toBeUndefined();
    });

    it('approves only a live one, and a second approve (a double click) still succeeds', async () => {
      const now = NOW();
      // Starts unapproved whatever the caller passed: only Approve sets it.
      await store().createPendingSignIn('p1', pendingSignIn({ expiresAt: now + 600, approved: true }), MAX, now);
      expect((await store().getPendingSignIn('p1', now))?.approved).toBe(false);

      expect(await store().approvePendingSignIn('p1', now)).toBe(true);
      expect(await store().approvePendingSignIn('p1', now)).toBe(true);
      expect((await store().getPendingSignIn('p1', now))?.approved).toBe(true);
      expect(await store().approvePendingSignIn('nope', now)).toBe(false);
      expect(await store().approvePendingSignIn('p1', now + 600)).toBe(false);
    });

    it('lets exactly one of two concurrent takes have it, approved flag included', async () => {
      const now = NOW();
      await store().createPendingSignIn('p1', pendingSignIn({ expiresAt: now + 600 }), MAX, now);
      await store().approvePendingSignIn('p1', now);

      const taken = await Promise.all([
        store().takePendingSignIn('p1', now),
        store().takePendingSignIn('p1', now)
      ]);
      expect(taken.filter(Boolean)).toEqual([pendingSignIn({ expiresAt: now + 600, approved: true })]);
      expect(await store().getPendingSignIn('p1', now)).toBeUndefined();
    });

    it('takes no expired one', async () => {
      const now = NOW();
      await store().createPendingSignIn('p1', pendingSignIn({ expiresAt: now + 600 }), MAX, now);
      expect(await store().takePendingSignIn('p1', now + 600)).toBeUndefined();
    });

    it('refuses a new one at the cap, counting only live ones, and deletes expired ones on insert', async () => {
      const now = NOW();
      await store().createPendingSignIn('old', pendingSignIn({ expiresAt: now + 10 }), 2, now);
      await store().createPendingSignIn('p1', pendingSignIn({ expiresAt: now + 600 }), 2, now);
      expect(await store().createPendingSignIn('p2', pendingSignIn({ expiresAt: now + 600 }), 2, now)).toBe(false);

      // `old` has expired by now + 10: it no longer counts, and goes with the insert.
      expect(await store().createPendingSignIn('p2', pendingSignIn({ expiresAt: now + 610 }), 2, now + 10)).toBe(true);
      expect(await store().getPendingSignIn('old', now)).toBeUndefined();
      expect(await store().getPendingSignIn('p1', now)).toBeDefined();
      expect(await store().createPendingSignIn('p3', pendingSignIn({ expiresAt: now + 610 }), 2, now + 10)).toBe(false);
    });

    it('names which of the given ids are still live', async () => {
      const now = NOW();
      await store().createPendingSignIn('live', pendingSignIn({ expiresAt: now + 600 }), MAX, now);
      await store().createPendingSignIn('expired', pendingSignIn({ expiresAt: now + 5 }), MAX, now);

      expect(await store().livePendingSignInIds(['live', 'expired', 'unknown'], now + 5)).toEqual(
        new Set(['live'])
      );
      expect(await store().livePendingSignInIds([], now)).toEqual(new Set());
    });

    it('the cleanup deletes expired ones and counts them', async () => {
      const now = NOW();
      await store().createPendingSignIn('expired', pendingSignIn({ expiresAt: now + 5 }), MAX, now);
      await store().createPendingSignIn('live', pendingSignIn({ expiresAt: now + 600 }), MAX, now);

      expect(await store().sweepExpiredOAuthRows(now + 5)).toEqual({
        tokens: 0,
        grants: 0,
        clients: 0,
        pendingSignIns: 1
      });
      expect(await store().getPendingSignIn('expired', now)).toBeUndefined();
      expect(await store().getPendingSignIn('live', now)).toBeDefined();
    });
  });

  // The hub refresh single-flight across processes: one holder per grant, each
  // reading what the previous holder saved.
  it('runs grant lock holders one at a time, each reading the last one\'s save under the lock', async () => {
    const id = await store().createGrant('c1', signIn());
    const other = await store().createGrant('c1', signIn());
    const next = { accessToken: 'xoat_2', refreshToken: 'xort_2', expiresAt: NOW() + 7200 };
    const order: string[] = [];
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));

    const first = store().withGrantLock(id, async (locked) => {
      order.push('first');
      expect(await locked.rotate('xort_1', next)).toBe(true);
      await held;
    });
    await vi.waitFor(() => expect(order).toEqual(['first']));
    const second = store().withGrantLock(id, async (locked) => {
      order.push('second');
      return locked.grant?.hub?.refreshToken;
    });
    // Another grant is not queued behind this one.
    expect(await store().withGrantLock(other, async (locked) => locked.grant?.id)).toBe(other);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(order).toEqual(['first']);

    release();
    await first;
    expect(await second).toBe('xort_2');
    expect(order).toEqual(['first', 'second']);
  });

  it('frees the grant lock when the holder throws, and revokes through it', async () => {
    const id = await store().createGrant('c1', signIn());
    await expect(
      store().withGrantLock(id, async () => {
        throw new Error('boom');
      })
    ).rejects.toThrow('boom');
    await store().withGrantLock(id, (locked) => locked.revoke());
    expect(await store().withGrantLock(id, async (locked) => locked.grant)).toEqual({
      id,
      clientId: 'c1',
      revoked: true
    });
    expect(await store().withGrantLock('999999', async (locked) => locked.grant)).toBeUndefined();
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

      expect(await store().sweepExpiredOAuthRows(now)).toEqual({ tokens: 4, grants: 0, clients: 0, pendingSignIns: 0 });
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

      expect(await store().sweepExpiredOAuthRows(due - 60)).toEqual({ tokens: 0, grants: 0, clients: 0, pendingSignIns: 0 });
      expect(await store().getGrant(id)).toBeDefined();
      expect(await store().sweepExpiredOAuthRows(due + 60)).toEqual({ tokens: 0, grants: 1, clients: 0, pendingSignIns: 0 });
      expect(await store().getGrant(id)).toBeUndefined();
    });

    it('deletes a revoked grant without tokens once the retention has passed, keeping its client', async () => {
      await store().saveClient(client('c1'));
      const id = await store().createGrant('c1', signIn());
      await store().revokeGrant(id);
      const due = NOW() + REVOKED_GRANT_RETENTION_SECONDS;

      expect(await store().sweepExpiredOAuthRows(due - 60)).toEqual({ tokens: 0, grants: 0, clients: 0, pendingSignIns: 0 });
      expect(await store().getGrant(id)).toBeDefined();
      expect(await store().sweepExpiredOAuthRows(due + 60)).toEqual({ tokens: 0, grants: 1, clients: 0, pendingSignIns: 0 });
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

      expect(await store().sweepExpiredOAuthRows(later)).toEqual({ tokens: 0, grants: 0, clients: 0, pendingSignIns: 0 });
      expect(await store().getGrant(revoked)).toBeDefined();
      expect(await store().getGrant(unrevoked)).toBeDefined();
    });

    // A sign-in whose client the sweep deleted while it was at the hub.
    it('deletes an unrevoked grant without tokens whose client is gone', async () => {
      const id = await store().createGrant('gone', signIn());
      await token(id, 'code', NOW() + 600);

      expect(await store().sweepExpiredOAuthRows(NOW())).toEqual({ tokens: 0, grants: 0, clients: 0, pendingSignIns: 0 });
      expect(await store().getGrant(id)).toBeDefined();
      expect(await store().sweepExpiredOAuthRows(NOW() + 601)).toEqual({ tokens: 1, grants: 1, clients: 0, pendingSignIns: 0 });
      expect(await store().getGrant(id)).toBeUndefined();
    });

    // The real path to that orphan: the client is swept, then the hub callback creates the grant.
    it('deletes the grant a callback created for a client swept during the sign-in, once its code expires', async () => {
      await store().saveClient(client('c1'));
      expect(await store().sweepExpiredOAuthRows(NOW() + 31 * DAY)).toEqual({ tokens: 0, grants: 0, clients: 1, pendingSignIns: 0 });
      const id = await store().createGrant('c1', signIn());
      const codeExpiresAt = NOW() + 600;
      await token(id, 'code', codeExpiresAt);

      expect(await store().sweepExpiredOAuthRows(NOW())).toEqual({ tokens: 0, grants: 0, clients: 0, pendingSignIns: 0 });
      expect(await store().sweepExpiredOAuthRows(codeExpiresAt + 1)).toEqual({ tokens: 1, grants: 1, clients: 0, pendingSignIns: 0 });
      expect(await store().getGrant(id)).toBeUndefined();
    });

    // A code never exchanged, or a user idle past the refresh lifetime: hub ended the chain.
    it('deletes an unrevoked grant without tokens whose client exists once the retention has passed', async () => {
      expect(ABANDONED_GRANT_RETENTION_SECONDS).toBe(97 * DAY);
      await store().saveClient(client('c1'));
      const id = await store().createGrant('c1', signIn());

      expect(await store().sweepExpiredOAuthRows(NOW() + 96 * DAY)).toEqual({ tokens: 0, grants: 0, clients: 0, pendingSignIns: 0 });
      expect(await store().getGrant(id)).toBeDefined();
      // The client, past its own retention, loses its last grant and goes in the same run.
      expect(await store().sweepExpiredOAuthRows(NOW() + 98 * DAY)).toEqual({ tokens: 0, grants: 1, clients: 1, pendingSignIns: 0 });
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

      expect(await store().sweepExpiredOAuthRows(due - 60)).toEqual({ tokens: 0, grants: 0, clients: 0, pendingSignIns: 0 });
      expect(await store().getClient('unused')).toBeDefined();
      expect(await store().sweepExpiredOAuthRows(due + 60)).toEqual({ tokens: 0, grants: 0, clients: 1, pendingSignIns: 0 });
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
        clients: 1,
        pendingSignIns: 0
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
      expect(await store().sweepExpiredOAuthRows(NOW())).toEqual({ tokens: 0, grants: 0, clients: 0, pendingSignIns: 0 });
      expect(await store().sweepExpiredOAuthRows(NOW() + 96 * DAY)).toEqual({ tokens: 0, grants: 0, clients: 0, pendingSignIns: 0 });
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

      expect(await store().sweepExpiredOAuthRows(later)).toEqual({ tokens: 1, grants: 1, clients: 1, pendingSignIns: 0 });
      expect(await store().sweepExpiredOAuthRows(later)).toEqual({ tokens: 0, grants: 0, clients: 0, pendingSignIns: 0 });
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
        clients: 0,
        pendingSignIns: 0
      });
      expect(await store().sweepExpiredOAuthRows(first + 1 + UNUSED_CLIENT_RETENTION_SECONDS)).toEqual({
        tokens: 0,
        grants: 0,
        clients: 1,
        pendingSignIns: 0
      });
    });
  });
});

// A failing cleanup step names itself and its code only (a pg message can name the host and
// role), the steps after it are not issued, and the run returns what the earlier steps deleted.
describe.skipIf(!PG_URL)('PgOAuthStore: a failing cleanup step', () => {
  it('logs "the <step> step failed … <code>", issues no later step and returns the earlier counts', async () => {
    const store = await PgOAuthStore.connect(PG_URL!, new TokenCipher(KEY_A), 15_000);
    const pool = (store as unknown as { pool: pg.Pool }).pool;
    const query = pool.query.bind(pool) as (sql: string, values?: unknown[]) => Promise<unknown>;
    const issued: string[] = [];
    const failure = Object.assign(new Error('canceling statement, host=secret-host role=secret'), {
      code: '57014'
    });
    vi.spyOn(pool, 'query').mockImplementation(((sql: string, values?: unknown[]) => {
      issued.push(sql);
      if (sql.includes('DELETE FROM oauth_grants')) return Promise.reject(failure);
      if (sql.includes('DELETE FROM oauth_tokens')) return Promise.resolve({ rowCount: 3 });
      if (sql.includes('DELETE FROM oauth_pending_sign_ins')) return Promise.resolve({ rowCount: 2 });
      return query(sql, values);
    }) as never);
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      expect(await store.sweepExpiredOAuthRows(NOW())).toEqual({
        tokens: 3,
        grants: 0,
        clients: 0,
        pendingSignIns: 2
      });
      const logged = write.mock.calls.map((call) => String(call[0])).join('');
      expect(logged).toContain(
        '[xyte-mcp] error: OAuth store cleanup: the grants step failed, retried within an hour: 57014'
      );
      expect(logged).not.toContain('secret');
      expect(
        issued.filter((sql) => sql.startsWith('DELETE FROM')).map((sql) => sql.split(/\s+/)[2])
      ).toEqual(['oauth_pending_sign_ins', 'oauth_tokens', 'oauth_grants']);
      expect(issued.some((sql) => sql.includes('DELETE FROM oauth_clients'))).toBe(false);
      expect(issued.some((sql) => sql.includes('DELETE FROM mcp_rate_limit_counters'))).toBe(false);
    } finally {
      vi.restoreAllMocks();
      await store.close();
    }
  });

  // pg's client-side errors carry no code; these two messages name no host, so a fixed label stands in.
  it.each([
    ['Query read timeout', 'query timeout'],
    ['Connection terminated unexpectedly', 'connection terminated']
  ])('logs a code-less pg %j as %j', async (message, label) => {
    const store = await PgOAuthStore.connect(PG_URL!, new TokenCipher(KEY_A), 15_000);
    const pool = (store as unknown as { pool: pg.Pool }).pool;
    vi.spyOn(pool, 'query').mockRejectedValue(new Error(message));
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      await store.sweepExpiredOAuthRows(NOW());
      expect(write.mock.calls.map((call) => String(call[0])).join('')).toContain(
        `[xyte-mcp] error: OAuth store cleanup: the pendingSignIns step failed, retried within an hour: ${label}\n`
      );
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
    await admin.query('TRUNCATE oauth_tokens, oauth_grants, oauth_clients, oauth_pending_sign_ins RESTART IDENTITY');
  });
  afterAll(async () => {
    await admin.end();
  });

  // A grant held by a hub refresh (the grant lock) is skipped, not waited on: with
  // the main pool's 9 s lock_timeout the step would fail and skip the clients step.
  it('skips a grant held by the grant lock, and still deletes the rest and runs the clients step', async () => {
    const store = await PgOAuthStore.connect(PG_URL!, new TokenCipher(KEY_A), 15_000);
    const held = await store.createGrant('c1', signIn());
    const free = await store.createGrant('c1', signIn());
    await store.revokeGrant(held);
    await store.revokeGrant(free);
    await store.saveClient({ client_id: 'unused', redirect_uris: ['https://a/cb'] } as OAuthClientInformationFull);
    const holder = await admin.connect();
    try {
      await holder.query('BEGIN');
      await holder.query('SELECT 1 FROM oauth_grants WHERE id = $1 FOR NO KEY UPDATE', [held]);
      const started = Date.now();
      expect(await store.sweepExpiredOAuthRows(NOW() + 365 * 24 * 60 * 60)).toEqual({ tokens: 0, grants: 1, clients: 1, pendingSignIns: 0 });
      expect(Date.now() - started).toBeLessThan(5_000);
    } finally {
      await holder.query('ROLLBACK');
      holder.release();
      await store.close();
    }
  });

  // Another deleter (a concurrent /authorize or the cleanup) holding an expired
  // row must not make a sign-in start wait on the main pool's 9 s lock_timeout.
  it('starts a pending sign-in without waiting on an expired row another deleter holds', async () => {
    const store = await PgOAuthStore.connect(PG_URL!, new TokenCipher(KEY_A), 15_000);
    const now = NOW();
    await store.createPendingSignIn('old', pendingSignIn({ expiresAt: now + 5 }), 10_000, now);
    const holder = await admin.connect();
    try {
      await holder.query('BEGIN');
      await holder.query('SELECT 1 FROM oauth_pending_sign_ins WHERE id_hash = $1 FOR UPDATE', [hashToken('old')]);
      const started = Date.now();
      expect(await store.createPendingSignIn('p1', pendingSignIn({ expiresAt: now + 610 }), 10_000, now + 10)).toBe(true);
      expect(Date.now() - started).toBeLessThan(5_000);
    } finally {
      await holder.query('ROLLBACK');
      holder.release();
      await store.close();
    }
  });

  // Every dyno runs its own cleanup: a concurrent run deletes nothing the other one did.
  it('two concurrent runs on two pools delete each row once between them', async () => {
    const a = await PgOAuthStore.connect(PG_URL!, new TokenCipher(KEY_A), 15_000);
    const b = await PgOAuthStore.connect(PG_URL!, new TokenCipher(KEY_A), 15_000);
    try {
      for (let i = 0; i < 3; i += 1) {
        await a.saveClient({ client_id: `c${i}`, redirect_uris: ['https://a/cb'] } as OAuthClientInformationFull);
        const id = await a.createGrant(`c${i}`, signIn());
        await a.saveToken({ token: `t${i}`, kind: 'access', grantId: id, expiresAt: NOW() + 600 });
        await a.revokeGrant(id);
        await a.createPendingSignIn(`p${i}`, pendingSignIn(), 10_000, NOW());
      }
      const later = NOW() + 365 * 24 * 60 * 60;
      const [fromA, fromB] = await Promise.all([a.sweepExpiredOAuthRows(later), b.sweepExpiredOAuthRows(later)]);
      expect({
        tokens: fromA.tokens + fromB.tokens,
        grants: fromA.grants + fromB.grants,
        clients: fromA.clients + fromB.clients,
        pendingSignIns: fromA.pendingSignIns + fromB.pendingSignIns
      }).toEqual({ tokens: 3, grants: 3, clients: 3, pendingSignIns: 3 });
    } finally {
      await Promise.all([a.close(), b.close()]);
    }
  });

  // Else the next step would query an ended pool and the run would fail at shutdown.
  it('close() during a run lets the step in flight finish and issues no later step', async () => {
    const store = await PgOAuthStore.connect(PG_URL!, new TokenCipher(KEY_A), 15_000);
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
      await expect(run).resolves.toEqual({ tokens: 0, grants: 0, clients: 0, pendingSignIns: 0 });
      await closed;
      expect(issued.some((sql) => /DELETE FROM oauth_(grants|clients)/.test(sql))).toBe(false);
    } finally {
      vi.restoreAllMocks();
    }
  });
});

// The per-grant /mcp limit is shared by every process through this counter.
describe.skipIf(!PG_URL)('PgOAuthStore: rate-limit counters', () => {
  let admin: pg.Pool;
  let a: PgOAuthStore;
  let b: PgOAuthStore;
  beforeAll(async () => {
    admin = new pg.Pool({ connectionString: PG_URL, max: 1 });
    a = await PgOAuthStore.connect(PG_URL!, new TokenCipher(KEY_A), 15_000);
    b = await PgOAuthStore.connect(PG_URL!, new TokenCipher(KEY_A), 15_000);
  });
  beforeEach(async () => {
    await admin.query('TRUNCATE mcp_rate_limit_counters');
  });
  afterAll(async () => {
    await Promise.all([a.close(), b.close()]);
    await admin.end();
  });
  const backdate = (key: string) =>
    admin.query(`UPDATE mcp_rate_limit_counters SET reset_at = now() - interval '1 second' WHERE key = $1`, [key]);

  it('counts hits in a fixed window, and starts again at 1 once the window has ended', async () => {
    const first = await a.countRateLimitHit('grant:1', 60_000);
    expect(first.totalHits).toBe(1);
    expect(first.resetTime.getTime()).toBeGreaterThan(Date.now() + 55_000);
    expect(first.resetTime.getTime()).toBeLessThan(Date.now() + 65_000);
    expect((await a.countRateLimitHit('grant:1', 60_000)).totalHits).toBe(2);
    const third = await a.countRateLimitHit('grant:1', 60_000);
    expect(third.totalHits).toBe(3);
    // Same window end; rebuilt on the process clock per call, so within the calls' gap.
    expect(Math.abs(third.resetTime.getTime() - first.resetTime.getTime())).toBeLessThan(1_000);
    expect((await a.countRateLimitHit('grant:2', 60_000)).totalHits).toBe(1);

    await backdate('grant:1');
    const restarted = await a.countRateLimitHit('grant:1', 60_000);
    expect(restarted.totalHits).toBe(1);
    expect(restarted.resetTime.getTime()).toBeGreaterThan(Date.now() + 55_000);
  });

  it('restarts a window that ends more than one window ahead (the database clock stepped back)', async () => {
    await a.countRateLimitHit('grant:1', 60_000);
    await a.countRateLimitHit('grant:1', 60_000);
    await admin.query(`UPDATE mcp_rate_limit_counters SET reset_at = now() + interval '1 hour' WHERE key = 'grant:1'`);
    const restarted = await a.countRateLimitHit('grant:1', 60_000);
    expect(restarted.totalHits).toBe(1);
    expect(restarted.resetTime.getTime()).toBeLessThan(Date.now() + 65_000);
  });

  it('builds resetTime on the process clock from the time left, so a skewed database clock does not shift it', async () => {
    await a.countRateLimitHit('grant:1', 60_000);
    await admin.query(`UPDATE mcp_rate_limit_counters SET reset_at = now() + interval '30 seconds' WHERE key = 'grant:1'`);
    const processNow = Date.now() + 3_600_000;
    vi.useFakeTimers({ toFake: ['Date'], now: processNow });
    try {
      const { resetTime } = await a.countRateLimitHit('grant:1', 60_000);
      expect(resetTime.getTime()).toBeGreaterThan(processNow + 25_000);
      expect(resetTime.getTime()).toBeLessThanOrEqual(processNow + 30_000);
    } finally {
      vi.useRealTimers();
    }
  });

  it('shares one count between two stores on one database', async () => {
    await a.countRateLimitHit('grant:1', 60_000);
    await b.countRateLimitHit('grant:1', 60_000);
    const hits = await Promise.all(
      Array.from({ length: 10 }, (_, i) => (i % 2 ? a : b).countRateLimitHit('grant:1', 60_000))
    );
    expect(hits.map((hit) => hit.totalHits).sort((x, y) => x - y)).toEqual([3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
  });

  it('the cleanup deletes a counter whose window has ended and keeps a live one, reporting no count', async () => {
    await a.countRateLimitHit('grant:stale', 60_000);
    await a.countRateLimitHit('grant:live', 60_000);
    await backdate('grant:stale');

    expect(await a.sweepExpiredOAuthRows(NOW())).toEqual({ tokens: 0, grants: 0, clients: 0, pendingSignIns: 0 });
    const keys = (await admin.query<{ key: string }>('SELECT key FROM mcp_rate_limit_counters')).rows;
    expect(keys).toEqual([{ key: 'grant:live' }]);
  });

  it('the cleanup logs the rateLimitCounters step and its code only when that step fails, and still returns the counts', async () => {
    await admin.query('TRUNCATE oauth_pending_sign_ins');
    const now = NOW();
    await a.createPendingSignIn('expired', pendingSignIn({ expiresAt: now + 5 }), 10_000, now);
    await admin.query('ALTER TABLE mcp_rate_limit_counters RENAME TO mcp_rate_limit_counters_away');
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      expect(await a.sweepExpiredOAuthRows(now + 10)).toEqual({ tokens: 0, grants: 0, clients: 0, pendingSignIns: 1 });
      expect(write.mock.calls.map((call) => String(call[0])).join('')).toContain(
        '[xyte-mcp] error: OAuth store cleanup: the rateLimitCounters step failed, retried within an hour: 42P01'
      );
    } finally {
      write.mockRestore();
      await admin.query('ALTER TABLE mcp_rate_limit_counters_away RENAME TO mcp_rate_limit_counters');
    }
  });
});

/** What only the Postgres store does: the hub tokens are encrypted at rest. */
describe.skipIf(!PG_URL)('PgOAuthStore: hub tokens at rest', () => {
  let admin: pg.Pool;
  const stores: PgOAuthStore[] = [];
  const open = async (current: Buffer, previous?: Buffer) => {
    const store = await PgOAuthStore.connect(PG_URL!, new TokenCipher(current, previous), 15_000);
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
    await admin.query('TRUNCATE oauth_tokens, oauth_grants, oauth_clients, oauth_pending_sign_ins RESTART IDENTITY');
  });
  afterAll(async () => {
    vi.restoreAllMocks();
    await Promise.all(stores.map((store) => store.close()));
    // Live rows under this run's random keys would stop the next run's boots.
    await admin.query('TRUNCATE oauth_tokens, oauth_grants, oauth_clients, oauth_pending_sign_ins RESTART IDENTITY');
    await admin.end();
  });

  it('stores a pending sign-in with its id, csrf and browser key hashed and its hub verifier encrypted', async () => {
    const store = await open(KEY_A);
    await store.createPendingSignIn('pending-id', pendingSignIn(), 10_000, NOW());

    const { rows } = await admin.query('SELECT * FROM oauth_pending_sign_ins');
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      id_hash: hashToken('pending-id'),
      csrf_hash: hashToken('csrf'),
      browser_key_hash: hashToken('browser-key'),
      hub_pkce_verifier: expect.stringMatching(new RegExp(`^v1\\.${new TokenCipher(KEY_A).currentKeyId}\\.`))
    });
    expect(JSON.stringify(rows)).not.toContain('pending-id');
    expect(JSON.stringify(rows)).not.toContain('v'.repeat(43));
  });

  // A pending sign-in written under a key this instance lacks (a rotation
  // without the previous key) cannot finish; it reads as gone, never a crash.
  it('reads a pending sign-in whose verifier it cannot decrypt as gone, logging the reason', async () => {
    const writer = await open(KEY_A);
    const reader = await open(KEY_B);
    await writer.createPendingSignIn('p1', pendingSignIn(), 10_000, NOW());

    const logText = captureLog();
    expect(await reader.getPendingSignIn('p1', NOW())).toBeUndefined();
    expect(await reader.takePendingSignIn('p1', NOW())).toBeUndefined();
    // The take deleted the row before its decrypt failed: gone for every instance.
    expect(await writer.getPendingSignIn('p1', NOW())).toBeUndefined();
    expect(logText()).toContain('pending sign-in unreadable: unknown key id');
    expect(logText()).not.toContain('v'.repeat(43));
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

  // getGrant's revoke runs on the main pool and would wait on the row the lock holds.
  it('revokes an unreadable grant read under the grant lock on the locked connection', async () => {
    const store = await open(KEY_A);
    const id = await store.createGrant('c1', signIn());
    await admin.query(
      `UPDATE oauth_grants SET hub_access_token = 'xoat_plain', hub_refresh_token = 'xort_plain' WHERE id = $1`,
      [id]
    );
    const logText = captureLog();
    expect(await store.withGrantLock(id, async (locked) => locked.grant)).toEqual({
      id,
      clientId: 'c1',
      revoked: true
    });
    vi.restoreAllMocks();
    expect(logText()).toContain('"reason":"unreadable_token"');
    expect((await row(id)).hub_refresh_token).toBeNull();
  });

  // A token INSERT takes FOR KEY SHARE on its grant (the foreign key): a /token
  // exchange during a hub refresh must not wait for the refresh.
  it('saves a token for a grant while another holds that grant\'s lock', async () => {
    const store = await open(KEY_A);
    const id = await store.createGrant('c1', signIn());
    let release!: () => void;
    let locked!: () => void;
    const inside = new Promise<void>((resolve) => (locked = resolve));
    const holder = store.withGrantLock(id, () => {
      locked();
      return new Promise<void>((resolve) => (release = resolve));
    });
    await inside;
    try {
      const saved = store.saveToken({ token: 'during', kind: 'access', grantId: id, expiresAt: NOW() + 600 });
      const outcome = await Promise.race([
        saved.then(() => 'saved'),
        new Promise((resolve) => setTimeout(() => resolve('blocked'), 2_000))
      ]);
      expect(outcome).toBe('saved');
    } finally {
      release();
      await holder;
    }
  });

  // Without a client timeout, a statement on a half-open connection hangs for
  // minutes, and the refresh flight with every call joined to it.
  it('bounds each grant lock statement client-side above the lock wait, with TCP keepalive', async () => {
    const store = await open(KEY_A);
    const { options } = (store as unknown as { lockPool: pg.Pool & { options: Record<string, unknown> } }).lockPool;
    expect(options).toMatchObject({ query_timeout: 25_000, keepAlive: true });
  });

  // The revoke of an unreadable grant read under the lock commits with the lock:
  // rolled back, it did not happen, so it must not be logged.
  it('logs the unreadable-token revoke under the grant lock only once it has committed', async () => {
    const store = await open(KEY_A);
    const id = await store.createGrant('c1', signIn());
    await admin.query(
      `UPDATE oauth_grants SET hub_access_token = 'xoat_plain', hub_refresh_token = 'xort_plain' WHERE id = $1`,
      [id]
    );
    const logText = captureLog();
    await expect(
      store.withGrantLock(id, async () => {
        throw new Error('boom');
      })
    ).rejects.toThrow('boom');
    vi.restoreAllMocks();
    expect(logText()).not.toContain('"event":"revoke"');
    expect((await row(id)).hub_refresh_token).toBe('xort_plain'); // rolled back
  });

  // close() between the closing check and the checkout: the pool is already ended.
  it('answers a grant lock attempt that meets an ended pool as restarting', async () => {
    const store = await PgOAuthStore.connect(PG_URL!, new TokenCipher(KEY_A), 15_000);
    const id = await store.createGrant('c1', signIn());
    const lockPool = (store as unknown as { lockPool: pg.Pool }).lockPool;
    const connect = lockPool.connect.bind(lockPool) as () => Promise<pg.PoolClient>;
    vi.spyOn(lockPool, 'connect').mockImplementationOnce((async () => {
      await store.close();
      return connect();
    }) as never);
    await expect(store.withGrantLock(id, async () => undefined)).rejects.toMatchObject({
      kind: 'network',
      message: 'The server is restarting.'
    });
    vi.restoreAllMocks();
  });

  // Shutdown: a waiter queued on another process's lock sends nothing, so it must
  // not hold close() until its lock_timeout.
  it('close() does not wait for a grant lock waiter, and refuses new lock attempts', async () => {
    const store = await PgOAuthStore.connect(PG_URL!, new TokenCipher(KEY_A), 15_000);
    const id = await store.createGrant('c1', signIn());
    const holder = await admin.connect();
    await holder.query('BEGIN');
    await holder.query('SELECT 1 FROM oauth_grants WHERE id = $1 FOR NO KEY UPDATE', [id]);
    const waiter = store.withGrantLock(id, async () => undefined).catch(() => undefined);
    const pool = (store as unknown as { pool: pg.Pool }).pool;
    try {
      await vi.waitFor(async () => expect(await lockWaiters(pool)).toBe(1), { timeout: 5_000 });
      const started = Date.now();
      await store.close();
      expect(Date.now() - started).toBeLessThan(5_000);
      await expect(store.withGrantLock(id, async () => undefined)).rejects.toMatchObject({
        kind: 'network',
        message: 'The server is restarting.'
      });
    } finally {
      await holder.query('ROLLBACK');
      holder.release();
      await waiter;
    }
  });

  // Server-side, under the pool's 10 s query_timeout: a statement the client gave
  // up on must not wait on, then apply, an UPDATE later.
  it('bounds the main pool\'s lock waits server-side below its query timeout', async () => {
    const store = await open(KEY_A);
    const pool = (store as unknown as { pool: pg.Pool }).pool;
    expect((await pool.query<{ lock_timeout: string }>('SHOW lock_timeout')).rows[0]!.lock_timeout).toBe('9s');
  });

  it('clamps an out-of-range hub timeout, so the grant lock still sets valid limits', async () => {
    const store = await PgOAuthStore.connect(PG_URL!, new TokenCipher(KEY_A), 1e21);
    stores.push(store);
    const id = await store.createGrant('c1', signIn());
    expect(await store.withGrantLock(id, async (locked) => locked.grant?.id)).toBe(id);
  });

  it('rolls back what the grant lock holder wrote when it throws', async () => {
    const store = await open(KEY_A);
    const id = await store.createGrant('c1', signIn());
    const next = { accessToken: 'xoat_2', refreshToken: 'xort_2', expiresAt: NOW() + 7200 };
    await expect(
      store.withGrantLock(id, async (locked) => {
        await locked.rotate('xort_1', next);
        throw new Error('boom');
      })
    ).rejects.toThrow('boom');
    expect((await row(id)).hub_refresh_token_hash).toBe(hashToken('xort_1'));
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
    const store = await PgOAuthStore.connect(PG_URL!, cipher, 15_000);
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
