import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

/**
 * At-rest encryption of the hub tokens in oauth_grants, and of the hub PKCE
 * verifier of a pending sign-in: AES-256-GCM, stored as
 * `v1.<key id>.<base64url(iv | tag | ciphertext)>`. The key id (first 8 hex of
 * the key's SHA-256) picks the key on read, so a rotation can keep the
 * previous key for decryption while every write uses the current one. The
 * column name is the additional authenticated data: a value copied into the
 * other column fails to decrypt.
 */

export type TokenColumn = 'hub_access_token' | 'hub_refresh_token' | 'hub_pkce_verifier';

const VERSION = 'v1';
const IV_BYTES = 12;
const TAG_BYTES = 16;
/** The only key id shape ever read or echoed: anything else may be a token, not an id. */
export const KEY_ID_PATTERN = /^[0-9a-f]{8}$/;
const PAYLOAD_PATTERN = /^[A-Za-z0-9_-]+$/;

/** A stored value this cipher cannot read; the reason and key id are safe to log, the value is not. */
export class TokenDecryptError extends Error {
  constructor(
    readonly reason: 'not encrypted' | 'malformed' | 'unknown key id' | 'authentication failed',
    readonly keyId?: string
  ) {
    super(`hub token unreadable: ${reason}${keyId ? ` (key id ${keyId})` : ''}`);
  }
}

function tokenKeyId(key: Buffer): string {
  return createHash('sha256').update(key).digest('hex').slice(0, 8);
}

export class TokenCipher {
  readonly currentKeyId: string;
  readonly previousKeyId?: string;
  private readonly keys = new Map<string, Buffer>();

  constructor(
    private readonly currentKey: Buffer,
    previousKey?: Buffer
  ) {
    this.currentKeyId = tokenKeyId(currentKey);
    if (previousKey) {
      this.previousKeyId = tokenKeyId(previousKey);
      this.keys.set(this.previousKeyId, previousKey);
    }
    this.keys.set(this.currentKeyId, currentKey);
  }

  encrypt(plaintext: string, column: TokenColumn): string {
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', this.currentKey, iv).setAAD(Buffer.from(column));
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const payload = Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64url');
    return `${VERSION}.${this.currentKeyId}.${payload}`;
  }

  /** Throws TokenDecryptError for anything it cannot authenticate. */
  decrypt(stored: string, column: TokenColumn): string {
    if (!stored.startsWith(`${VERSION}.`)) throw new TokenDecryptError('not encrypted');
    const segments = stored.split('.');
    const [, keyId = '', payload = ''] = segments;
    if (segments.length !== 3 || !KEY_ID_PATTERN.test(keyId)) throw new TokenDecryptError('malformed');
    if (!PAYLOAD_PATTERN.test(payload)) throw new TokenDecryptError('malformed', keyId);
    const key = this.keys.get(keyId);
    if (!key) throw new TokenDecryptError('unknown key id', keyId);
    const bytes = Buffer.from(payload, 'base64url');
    if (bytes.length < IV_BYTES + TAG_BYTES) throw new TokenDecryptError('malformed', keyId);
    const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, IV_BYTES), {
      authTagLength: TAG_BYTES
    })
      .setAAD(Buffer.from(column))
      .setAuthTag(bytes.subarray(IV_BYTES, IV_BYTES + TAG_BYTES));
    try {
      return Buffer.concat([
        decipher.update(bytes.subarray(IV_BYTES + TAG_BYTES)),
        decipher.final()
      ]).toString('utf8');
    } catch {
      throw new TokenDecryptError('authentication failed', keyId);
    }
  }
}
