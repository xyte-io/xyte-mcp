import { describe, expect, it } from 'vitest';
import {
  DEFAULT_ENTRY_URL,
  DEFAULT_HTTP_PORT,
  DEFAULT_HUB_URL,
  ENV,
  resolveConfig,
  resolveHttpConfig
} from '../src/config.js';
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

  it('defaults writes to on', () => {
    expect(resolveConfig(withOrgKey).allowWrites).toBe(true);
  });

  it.each(['1', 'true', 'TRUE', 'yes'])('goes read-only for %s', (value) => {
    expect(resolveConfig({ ...withOrgKey, [ENV.readOnly]: value }).allowWrites).toBe(false);
  });

  it.each(['0', 'false', 'no', '', 'maybe', 'on'])(
    'keeps writes on when read-only is %s',
    (value) => {
      expect(resolveConfig({ ...withOrgKey, [ENV.readOnly]: value }).allowWrites).toBe(true);
    }
  );

  // 0.1.x was read-only by default and this was the only switch, so anyone who
  // set it decided deliberately. Upgrading must not widen their posture.
  describe('the legacy allow-writes variable', () => {
    it.each(['0', 'false', 'no', '', 'maybe'])('still forces read-only for %s', (value) => {
      expect(resolveConfig({ ...withOrgKey, [ENV.allowWrites]: value }).allowWrites).toBe(false);
    });

    it.each(['1', 'true', 'yes'])('still permits writes for %s', (value) => {
      expect(resolveConfig({ ...withOrgKey, [ENV.allowWrites]: value }).allowWrites).toBe(true);
    });

    it('loses to an explicit read-only request', () => {
      const config = resolveConfig({
        ...withOrgKey,
        [ENV.allowWrites]: '1',
        [ENV.readOnly]: '1'
      });
      expect(config.allowWrites).toBe(false);
    });
  });

  // The HTTP transport: read-only unless writes are asked for explicitly.
  describe('with writesByDefault: false', () => {
    const http = (env: Record<string, string>) =>
      resolveConfig({ ...withOrgKey, ...env }, { writesByDefault: false }).allowWrites;

    it('defaults writes to off, and read-only=0 alone does not turn them on', () => {
      expect(http({})).toBe(false);
      expect(http({ [ENV.readOnly]: '0' })).toBe(false);
    });

    it('turns writes on only for an explicit allow-writes', () => {
      expect(http({ [ENV.allowWrites]: '1' })).toBe(true);
      expect(http({ [ENV.allowWrites]: '0' })).toBe(false);
    });

    it('still lets an explicit read-only win over allow-writes', () => {
      expect(http({ [ENV.allowWrites]: '1', [ENV.readOnly]: '1' })).toBe(false);
    });
  });

  it('defaults and validates the timeout', () => {
    expect(resolveConfig(withOrgKey).timeoutMs).toBe(15_000);
    expect(resolveConfig({ ...withOrgKey, [ENV.timeoutMs]: '5000' }).timeoutMs).toBe(5000);
    expect(resolveConfig({ ...withOrgKey, [ENV.timeoutMs]: '-1' }).timeoutMs).toBe(15_000);
    expect(resolveConfig({ ...withOrgKey, [ENV.timeoutMs]: 'abc' }).timeoutMs).toBe(15_000);
  });
});

describe('resolveHttpConfig', () => {
  const token = 'xmcp_test_token_0123456789abcdef';
  const staticEnv = { [ENV.httpToken]: token, [ENV.orgKey]: 'org-key' };

  it('reads the static token and the platform port', () => {
    expect(resolveHttpConfig({ ...staticEnv, [ENV.httpPort]: '5001' })).toEqual({
      staticToken: token,
      port: 5001
    });
  });

  it('defaults the port', () => {
    expect(resolveHttpConfig(staticEnv).port).toBe(DEFAULT_HTTP_PORT);
  });

  // Serving with auth disabled would publish a live API key to anyone with the
  // URL, so missing auth must stop the boot rather than widen the server.
  it('refuses a config with no auth at all, naming both options', () => {
    const error = (() => {
      try {
        resolveHttpConfig({});
        return undefined;
      } catch (e) {
        return e;
      }
    })();
    expect(error).toBeInstanceOf(XyteError);
    expect((error as XyteError).kind).toBe('config');
    expect((error as XyteError).message).toContain(ENV.httpToken);
    expect((error as XyteError).message).toContain(ENV.issuerUrl);
  });

  it('refuses a whitespace-only token', () => {
    expect(() => resolveHttpConfig({ [ENV.httpToken]: '   ' })).toThrow(XyteError);
  });

  it('refuses a guessably short token', () => {
    expect(() => resolveHttpConfig({ [ENV.httpToken]: 'short', [ENV.orgKey]: 'k' })).toThrow(
      /too short/
    );
  });

  it('refuses a static token with no API key behind it', () => {
    expect(() => resolveHttpConfig({ [ENV.httpToken]: token })).toThrow(/no API key/);
  });

  const hubClientEnv = {
    [ENV.hubOAuthClientId]: 'hub-id',
    [ENV.hubOAuthClientSecret]: 'hub-secret'
  };
  const hubClient = { id: 'hub-id', secret: 'hub-secret' };

  it('enables OAuth from the issuer URL, with and without a database', () => {
    const issuer = 'https://mcp.example.com';
    // Normalized as the SDK normalizes the resource clients send back.
    expect(
      resolveHttpConfig({ ...hubClientEnv, [ENV.issuerUrl]: 'https://MCP.example.com:443' }).oauth
        ?.issuerUrl
    ).toBe(issuer);
    expect(resolveHttpConfig({ ...hubClientEnv, [ENV.issuerUrl]: `${issuer}/` }).oauth).toEqual({
      issuerUrl: issuer,
      hubClient
    });
    expect(
      resolveHttpConfig({
        ...hubClientEnv,
        [ENV.issuerUrl]: issuer,
        [ENV.databaseUrl]: 'postgres://x'
      }).oauth
    ).toEqual({ issuerUrl: issuer, databaseUrl: 'postgres://x', hubClient });
  });

  it('refuses OAuth without the hub client credentials', () => {
    expect(() =>
      resolveHttpConfig({ [ENV.issuerUrl]: 'https://mcp.example.com', [ENV.hubOAuthClientId]: 'x' })
    ).toThrow(new RegExp(ENV.hubOAuthClientSecret));
  });

  // A shared static bearer next to the per-user sign-in on one public URL.
  it('refuses static + OAuth together, naming both variables', () => {
    expect(() =>
      resolveHttpConfig({ ...staticEnv, ...hubClientEnv, [ENV.issuerUrl]: 'https://mcp.example.com' })
    ).toThrow(new RegExp(`${ENV.httpToken} and ${ENV.issuerUrl} are both set`));
  });

  // Tokens minted under a plain-http issuer are readable by every hop; only
  // localhost (tests, local runs) is exempt, mirroring the SDK's rule.
  it('refuses a non-https issuer except localhost', () => {
    expect(() => resolveHttpConfig({ [ENV.issuerUrl]: 'http://mcp.example.com' })).toThrow(
      /https/
    );
    expect(
      resolveHttpConfig({ ...hubClientEnv, [ENV.issuerUrl]: 'http://127.0.0.1:8080' }).oauth
        ?.issuerUrl
    ).toBe('http://127.0.0.1:8080');
  });

  it('refuses an issuer with a query or fragment', () => {
    expect(() => resolveHttpConfig({ [ENV.issuerUrl]: 'https://a.example?x=1' })).toThrow(
      XyteError
    );
  });

  // Routes are mounted at the root: a path would send every sign-in to a 404.
  it('refuses an issuer with a path', () => {
    expect(() => resolveHttpConfig({ [ENV.issuerUrl]: 'https://a.example/xyte' })).toThrow(
      /must not have a path/
    );
  });

  // An org key alongside the token keeps these valid once OAuth lands.
  const withKey = { [ENV.orgKey]: 'org-key' };

  it('puts the length floor at 24 characters, after trimming', () => {
    expect(() => resolveHttpConfig({ ...withKey, [ENV.httpToken]: 'a'.repeat(23) })).toThrow(
      /too short/
    );
    expect(() => resolveHttpConfig({ ...withKey, [ENV.httpToken]: ` ${'a'.repeat(23)} ` })).toThrow(
      /too short/
    );
    // Field-name agnostic, so it survives the token field's rename for OAuth.
    expect(Object.values(resolveHttpConfig({ ...withKey, [ENV.httpToken]: ` ${token} ` }))).toContain(
      token
    );
    expect(() => resolveHttpConfig({ ...withKey, [ENV.httpToken]: 'a'.repeat(24) })).not.toThrow();
  });

  // The xmcp_ prefix is a scanner marker; it adds nothing to guess.
  it('does not count the xmcp_ prefix toward the floor', () => {
    expect(() =>
      resolveHttpConfig({ ...withKey, [ENV.httpToken]: `xmcp_${'a'.repeat(23)}` })
    ).toThrow(/too short/);
    expect(() =>
      resolveHttpConfig({ ...withKey, [ENV.httpToken]: `xmcp_${'a'.repeat(24)}` })
    ).not.toThrow();
  });

  it.each(['abc', '0', '-1', '3000.5', '70000'])('refuses PORT=%s', (port) => {
    expect(() =>
      resolveHttpConfig({ ...withKey, [ENV.httpToken]: token, [ENV.httpPort]: port })
    ).toThrow(/PORT must be an integer/);
  });
});
