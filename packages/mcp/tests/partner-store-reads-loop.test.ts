import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The store reads loop can approve an order, so it shares the coupon loop's
 * guard: an explicit hub URL, never production, and a partner key.
 */

const SCRIPT = path.resolve(import.meta.dirname, '..', 'scripts', 'partner-store-reads-loop.mjs');

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

describe('partner store reads loop guard', () => {
  it('refuses to run without an explicit hub URL', () => {
    const result = run({ XYTE_PARTNER_API_KEY: 'k' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('partner store reads loop: set XYTE_HUB_URL');
  });

  it('refuses to run against production', () => {
    const result = run({ XYTE_HUB_URL: 'https://hub.xyte.io/', XYTE_PARTNER_API_KEY: 'k' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('partner store reads loop: refusing to run against production.');
  });

  it('refuses to run without the partner key', () => {
    const result = run({ XYTE_HUB_URL: 'http://localhost:3000' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('partner store reads loop: set XYTE_PARTNER_API_KEY');
  });
});
