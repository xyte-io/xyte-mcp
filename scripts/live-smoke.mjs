#!/usr/bin/env node
/**
 * Live read-only smoke test against the real Xyte API.
 *
 *   XYTE_ORG_API_KEY=<key> npm run smoke:live
 *   npm run smoke:live -- --key-stdin        # paste the key, keeps it out of shell history
 *
 * Spawns the actual built server over stdio and drives real MCP requests, so a
 * pass means "server + credential + production reachable" — the same path an MCP
 * host takes.
 *
 * Read-only by construction: writes are force-disabled for the child process
 * regardless of the ambient environment, and only GET endpoints are exercised.
 * The key is never printed.
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const ROOT = path.resolve(import.meta.dirname, '..');
const ENTRY = path.join(ROOT, 'dist', 'index.js');
const PROTOCOL_VERSION = '2025-06-18';

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8').trim();
}

async function resolveKey(argv) {
  if (argv.includes('--key-stdin')) {
    if (process.stdin.isTTY) {
      process.stderr.write('Paste the organization API key, then press Ctrl-D:\n');
    }
    const key = await readStdin();
    if (!key) throw new Error('No key received on stdin.');
    return key;
  }
  const fromEnv = process.env.XYTE_ORG_API_KEY?.trim();
  if (fromEnv) return fromEnv;
  throw new Error(
    'No key. Set XYTE_ORG_API_KEY, or pass --key-stdin and paste it.\n' +
      'Example: npm run smoke:live -- --key-stdin'
  );
}

class Client {
  #child;
  #buffer = '';
  #waiters = new Map();
  stdoutLines = [];
  stderr = '';

  constructor(key) {
    this.#child = spawn(process.execPath, [ENTRY], {
      cwd: ROOT,
      env: {
        ...process.env,
        XYTE_ORG_API_KEY: key,
        // Never let an ambient setting turn this into a mutating run.
        XYTE_MCP_ALLOW_WRITES: '0'
      },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    this.#child.stdout.setEncoding('utf8');
    this.#child.stdout.on('data', (chunk) => {
      this.#buffer += chunk;
      let index;
      while ((index = this.#buffer.indexOf('\n')) !== -1) {
        const line = this.#buffer.slice(0, index).trim();
        this.#buffer = this.#buffer.slice(index + 1);
        if (!line) continue;
        this.stdoutLines.push(line);
        try {
          const message = JSON.parse(line);
          const waiter = this.#waiters.get(message.id);
          if (waiter) {
            this.#waiters.delete(message.id);
            waiter(message);
          }
        } catch {
          /* purity is asserted separately */
        }
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

const results = [];
function check(name, pass, detail = '') {
  results.push({ name, pass });
  const suffix = detail && !pass ? `\n        ${detail}` : detail ? `  (${detail})` : '';
  console.log(`${pass ? ' PASS ' : ' FAIL '} ${name}${suffix}`);
}

function summarize(value, limit = 160) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  if (!text) return '';
  return text.length > limit ? `${text.slice(0, limit)}…` : text;
}

async function main() {
  const argv = process.argv.slice(2);

  if (!existsSync(ENTRY)) {
    throw new Error(`Not built. Run: npm run build\n  (missing ${ENTRY})`);
  }
  const key = await resolveKey(argv);

  console.log('xyte-mcp live smoke — read-only, against production\n');
  const client = new Client(key);

  try {
    const init = await client.rpc(1, 'initialize', {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'xyte-mcp-live-smoke', version: '0' }
    });
    client.notify('notifications/initialized');
    check('server handshake', init.result?.serverInfo?.name === 'xyte-mcp');
    check(
      'running read-only',
      String(init.result?.instructions ?? '').includes('READ-ONLY'),
      'writes are force-disabled for this run'
    );

    const tools = await client.rpc(2, 'tools/list');
    const names = (tools.result?.tools ?? []).map((tool) => tool.name).sort();
    check('three tools advertised', names.length === 3, names.join(', '));

    // Catalog only — no network yet. Isolates wiring from connectivity.
    const list = await client.call(3, 'xyte_endpoints_list', { readOnly: true });
    check(
      'catalog loaded',
      (list.result?.structuredContent?.count ?? 0) > 0,
      `${list.result?.structuredContent?.count} read endpoints`
    );

    // The real test: cheapest authenticated production read.
    const info = await client.call(4, 'xyte_api_call', {
      key: 'organization.getOrganizationInfo'
    });
    const infoOk = info.result?.isError !== true;
    check(
      'authenticated read: organization.getOrganizationInfo',
      infoOk,
      infoOk
        ? summarize(info.result?.structuredContent?.data)
        : summarize(info.result?.content?.[0]?.text, 400)
    );

    if (infoOk) {
      const devices = await client.call(5, 'xyte_api_call', {
        key: 'organization.devices.getDevices',
        query: { per_page: 3 }
      });
      const devicesOk = devices.result?.isError !== true;
      const payload = devices.result?.structuredContent?.data;
      const count = Array.isArray(payload?.devices)
        ? payload.devices.length
        : Array.isArray(payload)
          ? payload.length
          : undefined;
      check(
        'authenticated read: organization.devices.getDevices',
        devicesOk,
        devicesOk
          ? `returned ${count ?? '?'} device(s)`
          : summarize(devices.result?.content?.[0]?.text, 400)
      );
    }

    // Guard still holds against production.
    const blocked = await client.call(6, 'xyte_api_call', {
      key: 'organization.commands.sendCommand',
      path: { device_id: 'smoke-test-never-real' },
      body: { name: 'reboot' }
    });
    check(
      'write refused (guard holds)',
      blocked.result?.isError === true &&
        String(blocked.result?.content?.[0]?.text).includes('read-only')
    );

    check(
      'key never appeared on stdout',
      !client.stdoutLines.join('\n').includes(key)
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
    client.kill();
  }

  const failed = results.filter((result) => !result.pass);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length) {
    console.log('\nFailed: ' + failed.map((f) => f.name).join(', '));
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(`\nlive smoke failed: ${error.message}`);
  process.exit(1);
});
