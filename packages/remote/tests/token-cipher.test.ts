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

  // IV and tag only (28 bytes) is a valid empty token; one byte short is not.
  it('round-trips an empty token, and calls a payload shorter than IV + tag malformed', () => {
    const cipher = new TokenCipher(KEY_A);
    expect(cipher.decrypt(cipher.encrypt('', 'hub_access_token'), 'hub_access_token')).toBe('');
    const short = `v1.${cipher.currentKeyId}.${randomBytes(27).toString('base64url')}`;
    expect(decryptFailure(cipher, short)).toMatchObject({ reason: 'malformed', keyId: cipher.currentKeyId });
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

  // Only v1.<8 lowercase hex>.<base64url> is read; anything else is malformed, and a
  // key id is echoed only in that exact shape (a stray value could hold a token).
  it('refuses any other shape as malformed, echoing no key id that is not 8 hex', () => {
    const cipher = new TokenCipher(KEY_A);
    const stored = cipher.encrypt('xoat_1', 'hub_access_token');
    const [, keyId, payload] = stored.split('.') as [string, string, string];
    for (const bad of [
      `${stored}.extra`, // a fourth segment
      `v1..${payload}`, // empty key id
      `v1.ABCDEF12.${payload}`, // not lowercase (a random key id may have no letters to raise)
      `v1.xoat_secret.${payload}`, // not hex, and could be anything
      `v1.${keyId}0.${payload}`, // 9 hex
      `v1.${keyId}.${payload}+`, // standard base64, not base64url
      `v1.${keyId}.${payload.slice(0, 20)}=`, // padding
      `v1.${keyId}.${payload.slice(0, 20)}!${payload.slice(20)}` // a character Buffer.from would skip
    ]) {
      const failure = decryptFailure(cipher, bad);
      expect(failure.reason, bad).toBe('malformed');
      expect(failure.message).not.toContain('xoat_secret');
      if (failure.keyId !== undefined) expect(failure.keyId).toMatch(/^[0-9a-f]{8}$/);
    }
    expect(decryptFailure(cipher, `v1.xoat_secret.${payload}`).keyId).toBeUndefined();
  });

  it('refuses a tampered IV or tag, and a key id swapped to the other key it holds', () => {
    const cipher = new TokenCipher(KEY_B, KEY_A);
    const stored = cipher.encrypt('xoat_1', 'hub_access_token');
    const [, , payload] = stored.split('.') as [string, string, string];
    const flipped = (index: number) => {
      const bytes = Buffer.from(payload, 'base64url');
      bytes[index]! ^= 1;
      return `v1.${cipher.currentKeyId}.${bytes.toString('base64url')}`;
    };
    expect(decryptFailure(cipher, flipped(0)).reason).toBe('authentication failed'); // IV byte 0
    expect(decryptFailure(cipher, flipped(12)).reason).toBe('authentication failed'); // tag byte 0
    const swapped = `v1.${cipher.previousKeyId}.${payload}`;
    expect(decryptFailure(cipher, swapped)).toMatchObject({
      reason: 'authentication failed',
      keyId: cipher.previousKeyId
    });
  });
});
