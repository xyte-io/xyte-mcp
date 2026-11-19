import pg from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { HubSignIn } from '../src/oauth/hub-oauth.js';
import { PgOAuthStore } from '../src/oauth/pg-store.js';
import { MemoryOAuthStore, type OAuthStore } from '../src/oauth/store.js';

/**
 * The store guarantees the provider relies on, run against both stores: always
 * the in-memory one, and Postgres when TEST_DATABASE_URL names a throwaway
 * database (its three tables are truncated before every test).
 */

const PG_URL = process.env.TEST_DATABASE_URL;
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
      const store = await PgOAuthStore.connect(PG_URL);
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
});
