import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The partner coupon loop creates, changes and deletes real coupons, so it must
 * refuse to start anywhere but a hub the operator named explicitly — never the
 * production default.
 */

const SCRIPT = path.resolve(import.meta.dirname, '..', 'scripts', 'partner-coupon-loop.mjs');

function run(env: Record<string, string>) {
  const clean = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.startsWith('XYTE_'))
  );
  return spawnSync(process.execPath, [SCRIPT], {
    env: { ...clean, ...env },
    encoding: 'utf8',
    timeout: 10_000
  });
}

describe('partner coupon loop guard', () => {
  it('refuses to run without an explicit hub URL', () => {
    const result = run({ XYTE_PARTNER_API_KEY: 'k' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('XYTE_HUB_URL');
  });

  it('refuses to run against production', () => {
    const result = run({ XYTE_HUB_URL: 'https://hub.xyte.io/', XYTE_PARTNER_API_KEY: 'k' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('production');
  });

  it('refuses production written with a trailing dot or in capitals', () => {
    for (const url of ['https://hub.xyte.io./', 'https://HUB.XYTE.IO']) {
      const result = run({ XYTE_HUB_URL: url, XYTE_PARTNER_API_KEY: 'k' });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('production');
    }
  });

  it('fails cleanly on a hub URL that is not a URL', () => {
    const result = run({ XYTE_HUB_URL: 'not a url', XYTE_PARTNER_API_KEY: 'k' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('XYTE_HUB_URL is not a valid URL');
  });

  it('refuses an unknown flow name in XYTE_LOOP_FLOWS', () => {
    const result = run({ XYTE_HUB_URL: 'http://localhost:3000', XYTE_PARTNER_API_KEY: 'k', XYTE_LOOP_FLOWS: '1, 2,9' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('unknown flow 9');
  });

  it('refuses to run without the partner key', () => {
    const result = run({ XYTE_HUB_URL: 'http://localhost:3000' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('XYTE_PARTNER_API_KEY');
  });
});
