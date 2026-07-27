#!/usr/bin/env node
/**
 * Secretless packaged-install smoke test — the pre-publish gate.
 *
 *   npm run smoke:pack-install
 *
 * Packs the tarball npm would publish, installs it into a throwaway project,
 * and drives the installed binary over stdio. This is the `npx -y @xyteai/mcp`
 * path an operator takes, exercised before anything reaches the registry.
 *
 * It catches what unit tests structurally cannot: a `files` entry that drops a
 * needed artifact (the generated catalog is the standing risk — it is a
 * non-.ts file that only lands in dist/ because tsc copies it), a broken `bin`
 * mapping, and an entrypoint that only works from a repo checkout.
 *
 * No credentials, no network: a placeholder key satisfies config resolution,
 * and every request exercised here is served from the committed catalog.
 */

import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { mkdtemp, rm, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';

const ROOT = path.resolve(import.meta.dirname, '..');
const PKG = JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const PROTOCOL_VERSION = '2025-06-18';
const IS_WINDOWS = process.platform === 'win32';
const NPM = IS_WINDOWS ? 'npm.cmd' : 'npm';

// Every file the published package must carry. `files` is a whitelist, so an
// omission here is silent until a user installs it.
const REQUIRED_TARBALL_FILES = [
  'package.json',
  'README.md',
  'dist/index.js',
  'dist/server.js',
  'dist/catalog/endpoints.generated.json'
];

const results = [];

function check(name, pass, detail = '') {
  results.push({ name, pass });
  const suffix = detail ? `  (${detail})` : '';
  console.log(`${pass ? ' PASS ' : ' FAIL '} ${name}${suffix}`);
}

function step(index, total, label) {
  console.log(`\n[${index}/${total}] ${label}`);
}

/** Spawn a command, capturing output. Rejects only on spawn failure. */
function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    // On Windows a .cmd shim cannot be spawned directly (Node refuses since
    // CVE-2024-27980), so it goes through the shell — which then needs the
    // arguments quoted itself.
    const useShell = IS_WINDOWS;
    const child = spawn(
      command,
      useShell ? args.map((arg) => (/\s/.test(arg) ? `"${arg}"` : arg)) : args,
      { cwd: options.cwd ?? ROOT, env: { ...process.env, ...options.env }, shell: useShell }
    );

    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

function assertSuccess(result, label) {
  if (result.code !== 0) {
    throw new Error(`${label} exited ${result.code}\n${result.stdout}\n${result.stderr}`);
  }
}

/** `npm pack --json` may prefix lifecycle output, so start at the payload. */
function parsePackPayload(stdout) {
  const start = stdout.indexOf('[');
  if (start === -1) throw new Error(`npm pack produced no JSON payload:\n${stdout}`);
  const payload = JSON.parse(stdout.slice(start));
  const entry = Array.isArray(payload) ? payload[0] : payload;
  if (!entry?.filename) throw new Error(`npm pack payload has no filename:\n${stdout}`);
  return entry;
}

/** Minimal MCP client over the installed server's stdio. */
class StdioClient {
  #child;
  #buffer = '';
  #waiters = new Map();
  stdoutLines = [];
  stderr = '';

  constructor(entry, cwd) {
    this.#child = spawn(process.execPath, [entry], {
      cwd,
      env: {
        ...process.env,
        // Enough to satisfy config resolution; nothing here reaches the network.
        XYTE_ORG_API_KEY: 'pack-install-smoke-placeholder-key',
        XYTE_MCP_ALLOW_WRITES: '0'
      },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    this.#child.stdout.setEncoding('utf8');
    this.#child.stdout.on('data', (chunk) => {
      this.#buffer += chunk;
      let index = this.#buffer.indexOf('\n');
      while (index !== -1) {
        const line = this.#buffer.slice(0, index).trim();
        this.#buffer = this.#buffer.slice(index + 1);
        if (line) {
          this.stdoutLines.push(line);
          try {
            const message = JSON.parse(line);
            const waiter = this.#waiters.get(message.id);
            if (waiter) {
              this.#waiters.delete(message.id);
              waiter(message);
            }
          } catch {
            // stdout purity is asserted separately.
          }
        }
        index = this.#buffer.indexOf('\n');
      }
    });

    this.#child.stderr.setEncoding('utf8');
    this.#child.stderr.on('data', (chunk) => {
      this.stderr += chunk;
    });
  }

  rpc(id, method, params) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`timed out on ${method}\n${this.stderr}`)),
        30_000
      );
      this.#waiters.set(id, (message) => {
        clearTimeout(timer);
        resolve(message);
      });
      this.#child.stdin.write(
        `${JSON.stringify({ jsonrpc: '2.0', id, method, ...(params ? { params } : {}) })}\n`
      );
    });
  }

  notify(method) {
    this.#child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method })}\n`);
  }

  call(id, name, args) {
    return this.rpc(id, 'tools/call', { name, arguments: args ?? {} });
  }

  kill() {
    this.#child.kill('SIGKILL');
  }
}

async function main() {
  console.log(`xyte-mcp packaged-install smoke — ${PKG.name}@${PKG.version}, ${process.platform}`);

  const total = 5;
  let tarballPath;
  let tempRoot;
  let client;

  try {
    step(1, total, 'Building');
    assertSuccess(await run(NPM, ['run', 'build']), 'npm run build');

    step(2, total, 'Packing the publishable tarball');
    // --ignore-scripts: the build above is the artifact under test; re-running
    // `prepare` here would only add lifecycle noise to the --json payload.
    const pack = parsePackPayload(await runPack());
    tarballPath = path.join(ROOT, pack.filename);
    const packed = new Set((pack.files ?? []).map((file) => file.path));
    for (const required of REQUIRED_TARBALL_FILES) {
      check(`tarball contains ${required}`, packed.has(required));
    }
    // Declarations (.d.ts) are the published type surface; TypeScript sources are not.
    check(
      'tarball ships no TypeScript sources',
      ![...packed].some(
        (file) => file.startsWith('src/') || (file.endsWith('.ts') && !file.endsWith('.d.ts'))
      ),
      `${packed.size} files, ${Math.round((pack.unpackedSize ?? 0) / 1024)} kB unpacked`
    );

    step(3, total, 'Installing the tarball into a scratch project');
    tempRoot = await mkdtemp(path.join(tmpdir(), 'xyte-mcp-pack-install-'));
    await writeFile(
      path.join(tempRoot, 'package.json'),
      `${JSON.stringify({ name: 'xyte-mcp-pack-install-smoke', private: true, version: '0.0.0' }, null, 2)}\n`
    );
    assertSuccess(
      await run(NPM, ['install', tarballPath, '--no-audit', '--no-fund'], { cwd: tempRoot }),
      'npm install <tarball>'
    );

    const installed = path.join(tempRoot, 'node_modules', '@xyteai', 'mcp');
    const entry = path.join(installed, 'dist', 'index.js');
    check('installed entrypoint exists', existsSync(entry));
    check(
      'installed catalog exists',
      existsSync(path.join(installed, 'dist', 'catalog', 'endpoints.generated.json'))
    );

    step(4, total, 'Running the installed binary');
    const shim = path.join(tempRoot, 'node_modules', '.bin', IS_WINDOWS ? 'xyte-mcp.cmd' : 'xyte-mcp');
    const version = await run(shim, ['--version'], { cwd: tempRoot });
    check(
      'bin shim reports the package version',
      version.code === 0 && `${version.stdout}${version.stderr}`.trim() === PKG.version,
      `${version.stdout}${version.stderr}`.trim()
    );

    step(5, total, 'Driving the installed server over stdio');
    client = new StdioClient(entry, tempRoot);
    const init = await client.rpc(1, 'initialize', {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'xyte-mcp-pack-install-smoke', version: '0' }
    });
    client.notify('notifications/initialized');
    check('handshake', init.result?.serverInfo?.name === 'xyte-mcp');
    check(
      'server reports the package version',
      init.result?.serverInfo?.version === PKG.version,
      String(init.result?.serverInfo?.version)
    );

    const tools = await client.rpc(2, 'tools/list');
    const names = (tools.result?.tools ?? []).map((tool) => tool.name).sort();
    check('three tools advertised', names.length === 3, names.join(', '));

    const list = await client.call(3, 'xyte_endpoints_list', { readOnly: true });
    check(
      'catalog served from the installed package',
      (list.result?.structuredContent?.count ?? 0) > 0,
      `${list.result?.structuredContent?.count} read endpoints`
    );

    const blocked = await client.call(4, 'xyte_api_call', {
      key: 'organization.commands.sendCommand',
      path: { device_id: 'pack-install-smoke-never-real' },
      body: { name: 'reboot' }
    });
    check(
      'write refused by default',
      blocked.result?.isError === true &&
        String(blocked.result?.content?.[0]?.text).includes('read-only')
    );

    check(
      'stdout carried only JSON-RPC',
      client.stdoutLines.every((line) => {
        try {
          JSON.parse(line);
          return true;
        } catch {
          return false;
        }
      })
    );
  } finally {
    client?.kill();
    if (tempRoot) await rm(tempRoot, { recursive: true, force: true });
    if (tarballPath) await unlink(tarballPath).catch(() => {});
  }

  const failed = results.filter((result) => !result.pass);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length) {
    console.log(`\nFailed: ${failed.map((result) => result.name).join(', ')}`);
    process.exitCode = 1;
  }
}

async function runPack() {
  const result = await run(NPM, ['pack', '--json', '--ignore-scripts']);
  assertSuccess(result, 'npm pack');
  return result.stdout;
}

main().catch((error) => {
  console.error(`\npackaged-install smoke failed: ${error.message}`);
  process.exit(1);
});
