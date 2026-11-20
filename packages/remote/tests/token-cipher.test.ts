import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { TokenCipher, TokenDecryptError } from '../src/oauth/token-cipher.js';

const KEY_A = randomBytes(32);
const KEY_B = randomBytes(32);

function decryptFailure(cipher: TokenCipher, stored: string, column = 'hub_access_token' as const) {
  try {
    cipher.decrypt(stored, column);
  } catch (error) {
    expect(error).toBeInstanceOf(TokenDecryptError);
    return error as TokenDecryptError;
  }
  throw new Error('decrypt did not fail');
}

describe('TokenCipher', () => {
  it('round-trips under the current key, as v1.<key id>.<payload>, never the same twice', () => {
    const cipher = new TokenCipher(KEY_A);
    const stored = cipher.encrypt('xoat_1', 'hub_access_token');
    expect(stored).toMatch(new RegExp(`^v1\\.${cipher.currentKeyId}\\.[A-Za-z0-9_-]+$`));
    expect(cipher.currentKeyId).toMatch(/^[0-9a-f]{8}$/);
    expect(stored).not.toContain('xoat_1');
    expect(cipher.encrypt('xoat_1', 'hub_access_token')).not.toBe(stored);
    expect(cipher.decrypt(stored, 'hub_access_token')).toBe('xoat_1');
  });

  it('refuses a tampered payload', () => {
    const cipher = new TokenCipher(KEY_A);
    const stored = cipher.encrypt('xoat_1', 'hub_access_token');
    const payload = Buffer.from(stored.split('.')[2]!, 'base64url');
    payload[payload.length - 1]! ^= 1;
    const tampered = `v1.${cipher.currentKeyId}.${payload.toString('base64url')}`;
    expect(decryptFailure(cipher, tampered)).toMatchObject({
      reason: 'authentication failed',
      keyId: cipher.currentKeyId
    });
  });

  it('refuses a value moved to the other column', () => {
    const cipher = new TokenCipher(KEY_A);
    const stored = cipher.encrypt('xort_1', 'hub_refresh_token');
    expect(decryptFailure(cipher, stored, 'hub_access_token').reason).toBe('authentication failed');
  });

  it('refuses a value under a key it does not hold, naming the key id', () => {
    const stored = new TokenCipher(KEY_A).encrypt('xoat_1', 'hub_access_token');
    const other = new TokenCipher(KEY_B);
    expect(decryptFailure(other, stored)).toMatchObject({
      reason: 'unknown key id',
      keyId: new TokenCipher(KEY_A).currentKeyId
    });
  });

  it('decrypts with the previous key, and encrypts with the current one', () => {
    const stored = new TokenCipher(KEY_A).encrypt('xoat_1', 'hub_access_token');
    const rotated = new TokenCipher(KEY_B, KEY_A);
    expect(rotated.previousKeyId).toBe(new TokenCipher(KEY_A).currentKeyId);
    expect(rotated.decrypt(stored, 'hub_access_token')).toBe('xoat_1');
    expect(rotated.encrypt('xoat_1', 'hub_access_token')).toMatch(
      new RegExp(`^v1\\.${rotated.currentKeyId}\\.`)
    );
  });

  it('refuses a plaintext or malformed value, without echoing it', () => {
    const cipher = new TokenCipher(KEY_A);
    const plaintext = decryptFailure(cipher, 'xoat_plain');
    expect(plaintext.reason).toBe('not encrypted');
    expect(plaintext.keyId).toBeUndefined();
    expect(plaintext.message).not.toContain('xoat_plain');
    expect(decryptFailure(cipher, `v1.${cipher.currentKeyId}.AAAA`).reason).toBe('malformed');
    expect(decryptFailure(cipher, `v1.${cipher.currentKeyId}`).reason).toBe('malformed');
  });
});
