import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const DIST_ENTRY = path.resolve(import.meta.dirname, '..', 'dist', 'index.js');

function runBin(args: string[]) {
  return spawnSync(process.execPath, [DIST_ENTRY, ...args], {
    env: { PATH: process.env.PATH, XYTE_ORG_API_KEY: 'org-key-abcdef123456' },
    encoding: 'utf8',
    input: '',
    timeout: 10_000
  });
}

describe('xyte-mcp bin', () => {
  it('refuses --http: the hosted server is not part of this package', () => {
    const result = runBin(['--http']);

    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--http');
    expect(result.stderr).toContain('hosted server is not part of @xyteai/mcp');
    expect(result.stdout).toBe('');
  });

  it('no longer advertises --http in its usage', () => {
    const result = runBin(['--help']);

    expect(result.status).toBe(0);
    expect(result.stderr).not.toContain('--http');
  });
});
