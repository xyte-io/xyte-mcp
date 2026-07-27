import { describe, expect, it } from 'vitest';
import { DEFAULT_ENTRY_URL, DEFAULT_HUB_URL, ENV, resolveConfig } from '../src/config.js';
import { XyteError } from '../src/http/errors.js';

const withOrgKey = { [ENV.orgKey]: 'org-key-abcdef123456' };

describe('resolveConfig', () => {
  it('requires at least one key and says which to set', () => {
    const error = (() => {
      try {
        resolveConfig({});
        return undefined;
      } catch (e) {
        return e;
      }
    })();
    expect(error).toBeInstanceOf(XyteError);
    expect((error as XyteError).kind).toBe('config');
    expect((error as XyteError).message).toContain(ENV.orgKey);
    expect((error as XyteError).message).toContain(ENV.partnerKey);
  });

  it('accepts an organization key alone', () => {
    const config = resolveConfig(withOrgKey);
    expect(config.credentials).toEqual({ organization: 'org-key-abcdef123456' });
  });

  it('accepts a partner key alone', () => {
    const config = resolveConfig({ [ENV.partnerKey]: 'partner-key-abcdef' });
    expect(config.credentials).toEqual({ partner: 'partner-key-abcdef' });
  });

  it('accepts both', () => {
    const config = resolveConfig({ ...withOrgKey, [ENV.partnerKey]: 'partner-key-abcdef' });
    expect(Object.keys(config.credentials).sort()).toEqual(['organization', 'partner']);
  });

  it('ignores whitespace-only keys', () => {
    expect(() => resolveConfig({ [ENV.orgKey]: '   ' })).toThrow(XyteError);
  });

  it('defaults to production hosts', () => {
    const config = resolveConfig(withOrgKey);
    expect(config.baseUrls.hub).toBe(DEFAULT_HUB_URL);
    expect(config.baseUrls.entry).toBe(DEFAULT_ENTRY_URL);
  });

  it('overrides and normalises base URLs', () => {
    const config = resolveConfig({ ...withOrgKey, [ENV.hubUrl]: 'http://localhost:3001/' });
    expect(config.baseUrls.hub).toBe('http://localhost:3001');
  });

  it('defaults writes to off', () => {
    expect(resolveConfig(withOrgKey).allowWrites).toBe(false);
  });

  it.each(['1', 'true', 'TRUE', 'yes'])('enables writes for %s', (value) => {
    expect(resolveConfig({ ...withOrgKey, [ENV.allowWrites]: value }).allowWrites).toBe(true);
  });

  it.each(['0', 'false', 'no', '', 'maybe', 'on'])(
    'leaves writes off for %s',
    (value) => {
      expect(resolveConfig({ ...withOrgKey, [ENV.allowWrites]: value }).allowWrites).toBe(false);
    }
  );

  it('defaults and validates the timeout', () => {
    expect(resolveConfig(withOrgKey).timeoutMs).toBe(15_000);
    expect(resolveConfig({ ...withOrgKey, [ENV.timeoutMs]: '5000' }).timeoutMs).toBe(5000);
    expect(resolveConfig({ ...withOrgKey, [ENV.timeoutMs]: '-1' }).timeoutMs).toBe(15_000);
    expect(resolveConfig({ ...withOrgKey, [ENV.timeoutMs]: 'abc' }).timeoutMs).toBe(15_000);
  });
});
