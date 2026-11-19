#!/usr/bin/env node
// Packs @xyteai/mcp as `npm publish` would and fails if the remote server's dependencies
// (pg, express), the remote package itself, or its code leaked into the public package.
// `--ignore-scripts` does not stop npm 10 from running `prepare` on pack, so this builds dist
// first; it only skips the other lifecycle scripts.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const PKG_DIR = path.resolve(import.meta.dirname, '..');
const FORBIDDEN = ['pg', 'express', '@types/pg', '@types/express', '@xyteai/mcp-remote'];
const IMPORT_RE = /(?:from\s*|import\s*\(\s*|import\s+|require\s*\(\s*)['"](pg|express)(?:\/[^'"]*)?['"]/;

const tmp = mkdtempSync(path.join(tmpdir(), 'xyte-mcp-pack-'));
const failures = [];
try {
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const [{ filename }] = JSON.parse(
    execFileSync(npm, ['pack', '--json', '--ignore-scripts', '--pack-destination', tmp], {
      cwd: PKG_DIR,
      encoding: 'utf8',
      shell: process.platform === 'win32'
    })
  );
  execFileSync('tar', ['-xzf', path.join(tmp, filename), '-C', tmp]);
  const root = path.join(tmp, 'package');

  const manifest = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const name of FORBIDDEN) {
      if (manifest[field]?.[name]) failures.push(`package.json ${field} has ${name}`);
    }
  }
  if (manifest.bundleDependencies?.length || manifest.bundledDependencies?.length) {
    failures.push('package.json bundles dependencies');
  }

  const files = readdirSync(root, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => path.relative(root, path.join(entry.parentPath, entry.name)).split(path.sep).join('/'));
  for (const file of files) {
    if (/^dist\/(oauth\/|transports\/http\.)/.test(file)) failures.push(`remote-only file packed: ${file}`);
    if (/\.(m|c)?js$|\.d\.(m|c)?ts$/.test(file) && IMPORT_RE.test(readFileSync(path.join(root, file), 'utf8'))) {
      failures.push(`imports pg/express: ${file}`);
    }
  }
  for (const required of ['README.md', 'LICENSE', 'dist/index.js', 'dist/server.js']) {
    if (!files.includes(required)) failures.push(`missing from tarball: ${required}`);
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

if (failures.length) {
  for (const failure of failures) console.error(`FAIL ${failure}`);
  process.exit(1);
}
console.error('OK packed @xyteai/mcp has no pg/express and no remote-only code');
