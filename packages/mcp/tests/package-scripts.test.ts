import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = path.resolve(import.meta.dirname, '..', '..', '..');

type Manifest = { workspaces?: string[]; scripts?: Record<string, string> };

function manifest(dir: string): Manifest {
  return JSON.parse(readFileSync(path.join(ROOT, dir, 'package.json'), 'utf8')) as Manifest;
}

// npm 11 runs these hooks while pruning dev dependencies (the Heroku Node buildpack does that
// after the build), and the dev tools are already gone by then, so the deploy fails.
const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare'];
const MANIFESTS = ['.', ...(manifest('.').workspaces ?? [])];

describe('package scripts', () => {
  it.each(MANIFESTS)('%s has no install-time hook', (dir) => {
    const scripts = manifest(dir).scripts ?? {};
    expect(INSTALL_HOOKS.filter((hook) => hook in scripts)).toEqual([]);
  });

  it('@xyteai/mcp builds on pack and publish', () => {
    expect(manifest('packages/mcp').scripts?.prepack).toMatch(/\bbuild\b|\btsc\b/);
  });
});
