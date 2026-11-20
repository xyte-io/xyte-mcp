import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { HubSignIn } from '../src/oauth/hub-oauth.js';
import { PgOAuthStore } from '../src/oauth/pg-store.js';
import { hashToken, MemoryOAuthStore, type OAuthStore } from '../src/oauth/store.js';
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

  it('refuses a rotation on a revoked grant even while its tokens are still on the row', async () => {
    const store = await open(KEY_A);
    const id = await store.createGrant('c1', signIn());
    await admin.query('UPDATE oauth_grants SET revoked_at = now() WHERE id = $1', [id]);
    const next = { accessToken: 'xoat_2', refreshToken: 'xort_2', expiresAt: NOW() + 7200 };
    expect(await store.rotateHubTokens(id, 'xort_1', next)).toBe(false);
  });

  it('reads rows under the previous key, rewrites them under the current one on rotation', async () => {
    const underA = await open(KEY_A);
    const first = signIn(); // once: signIn() reads the clock
    const idle = await underA.createGrant('c1', first);
    const active = await underA.createGrant('c1', first);

    const rotating = await open(KEY_B, KEY_A);
    expect((await rotating.getGrant(idle))?.hub).toEqual(first);
    const next = { accessToken: 'xoat_2', refreshToken: 'xort_2', expiresAt: NOW() + 7200 };
    expect(await rotating.rotateHubTokens(active, 'xort_1', next)).toBe(true);
    const idB = new TokenCipher(KEY_B).currentKeyId;
    expect((await row(active)).hub_access_token).toMatch(new RegExp(`^v1\\.${idB}\\.`));
    expect((await row(active)).hub_refresh_token).toMatch(new RegExp(`^v1\\.${idB}\\.`));

    // PREVIOUS dropped: the row never rewritten is revoked, the rotated one is not.
    const onlyB = await open(KEY_B);
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
    expect(logText()).not.toContain('xoat_plain');
    expect(logText()).not.toContain('xort_plain');
  });
});
