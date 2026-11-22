import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const scripts = (
  JSON.parse(
    readFileSync(path.resolve(import.meta.dirname, '..', 'package.json'), 'utf8')
  ) as { scripts: Record<string, string> }
).scripts;

describe('package scripts', () => {
  // npm 11 runs a workspace's `prepare` while pruning dev dependencies (the Heroku Node
  // buildpack does that after the build), and `tsc` is already gone by then, so the deploy
  // fails. `prepack` runs only on `npm pack` / `npm publish`.
  it('builds on pack, not on install or prune', () => {
    expect(scripts.prepare).toBeUndefined();
    expect(scripts.prepack).toBe('npm run build');
  });
});
