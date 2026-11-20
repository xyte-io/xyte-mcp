import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';

const DIST_ENTRY = path.resolve(import.meta.dirname, '..', 'dist', 'index.js');
const PACKAGE_VERSION = (
  JSON.parse(
    readFileSync(path.resolve(import.meta.dirname, '..', 'package.json'), 'utf8')
  ) as { version: string }
).version;

// The parent's environment minus any XYTE_* settings, so a developer's own config cannot leak
// in. Keeping the rest matters on Windows, where node needs SYSTEMROOT and friends.
function childEnv(): NodeJS.ProcessEnv {
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !key.startsWith('XYTE_'))
  );
  return { ...env, XYTE_ORG_API_KEY: 'org-key-abcdef123456' };
}

function runBin(args: string[]) {
  return spawnSync(process.execPath, [DIST_ENTRY, ...args], {
    env: childEnv(),
    encoding: 'utf8',
    input: '',
    timeout: 10_000
  });
}

beforeAll(() => {
  if (!existsSync(DIST_ENTRY)) {
    throw new Error(`Build first: ${DIST_ENTRY} is missing (npm run build).`);
  }
});

describe('xyte-mcp bin', () => {
  it('refuses --http: the hosted server is not part of this package', () => {
    const result = runBin(['--http']);

    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--http');
    expect(result.stderr).toContain('hosted server is not part of @xyteai/mcp');
    expect(result.stdout).toBe('');
  });

  it('refuses --http before complaining about other unknown arguments', () => {
    const result = runBin(['--http', '--bogus']);

    expect(result.status).toBe(2);
    expect(result.stderr).toContain('hosted server is not part of @xyteai/mcp');
    expect(result.stdout).toBe('');
  });

  it('no longer advertises --http in its usage', () => {
    const result = runBin(['--help']);

    expect(result.status).toBe(0);
    expect(result.stderr).toContain('Usage:');
    expect(result.stderr).not.toContain('--http');
  });

  it('rejects an unknown argument with exit 2 and the usage', () => {
    const result = runBin(['--bogus']);

    expect(result.status).toBe(2);
    expect(result.stderr).toContain('unknown argument(s): --bogus');
    expect(result.stderr).toContain('Usage:');
    expect(result.stdout).toBe('');
  });

  it('prints the package version for --version', () => {
    const result = runBin(['--version']);

    expect(result.status).toBe(0);
    expect(result.stderr.trim()).toBe(PACKAGE_VERSION);
    expect(result.stdout).toBe('');
  });

  it('answers --version before refusing --http', () => {
    const result = runBin(['--http', '--version']);

    expect(result.status).toBe(0);
    expect(result.stderr.trim()).toBe(PACKAGE_VERSION);
    expect(result.stdout).toBe('');
  });
});
