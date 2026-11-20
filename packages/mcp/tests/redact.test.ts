import { describe, expect, it } from 'vitest';
import { REDACTED, redactText, redactValue } from '../src/redact.js';

const SECRET = 'org-key-abcdef123456';

describe('redactText', () => {
  it('masks a known secret', () => {
    expect(redactText(`key=${SECRET} ok`, [SECRET])).toBe(`key=${REDACTED} ok`);
  });

  it('masks every occurrence', () => {
    expect(redactText(`${SECRET} ${SECRET}`, [SECRET])).toBe(`${REDACTED} ${REDACTED}`);
  });

  it('ignores short secrets that would match too much', () => {
    expect(redactText('a short a', ['a'])).toBe('a short a');
  });

  it('leaves unrelated text alone', () => {
    expect(redactText('nothing here', [SECRET])).toBe('nothing here');
  });
});

describe('redactValue', () => {
  it('masks sensitive keys regardless of value', () => {
    const output = redactValue(
      { api_key: 'zzz', Authorization: 'zzz', token: 'zzz', name: 'keep' },
      []
    ) as Record<string, unknown>;
    expect(output.api_key).toBe(REDACTED);
    expect(output.Authorization).toBe(REDACTED);
    expect(output.token).toBe(REDACTED);
    expect(output.name).toBe('keep');
  });

  it('masks secret values found under innocuous keys', () => {
    const output = redactValue({ notes: `saved ${SECRET}` }, [SECRET]) as Record<string, unknown>;
    expect(output.notes).toBe(`saved ${REDACTED}`);
  });

  it('recurses through arrays and nested objects', () => {
    const output = redactValue(
      { devices: [{ meta: { password: 'p' }, label: SECRET } ] },
      [SECRET]
    ) as { devices: Array<{ meta: { password: string }; label: string }> };
    expect(output.devices[0]?.meta.password).toBe(REDACTED);
    expect(output.devices[0]?.label).toBe(REDACTED);
  });

  it('survives cycles', () => {
    const cyclic: Record<string, unknown> = { name: 'x' };
    cyclic.self = cyclic;
    const output = redactValue(cyclic, []) as Record<string, unknown>;
    expect(output.self).toBe('[circular]');
    expect(() => JSON.stringify(output)).not.toThrow();
  });

  it('stringifies bigints so results stay serialisable', () => {
    expect(redactValue({ n: 1n }, [])).toEqual({ n: '1' });
  });

  it('passes through primitives', () => {
    expect(redactValue(null, [])).toBeNull();
    expect(redactValue(5, [])).toBe(5);
    expect(redactValue(true, [])).toBe(true);
  });
});
