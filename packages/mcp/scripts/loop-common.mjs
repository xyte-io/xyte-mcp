/**
 * Shared by the partner loops: the env guard, an MCP client on the built server,
 * and the PASS/FAIL/SKIP bookkeeping. `loopName` prefixes every error line.
 */

import { existsSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { URL } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const ENTRY = path.join(path.resolve(import.meta.dirname, '..'), 'dist', 'index.js');
const PRODUCTION_HOST = 'hub.xyte.io';

export function startLoop(loopName) {
  function fail(message) {
    process.stderr.write(`${loopName}: ${message}\n`);
    process.exit(1);
  }

  const env = process.env;
  const hubUrl = env.XYTE_HUB_URL?.trim();
  if (!hubUrl) fail('set XYTE_HUB_URL to the hub to test; this loop can write, so it never uses the default.');
  let hubHost;
  try {
    hubHost = new URL(hubUrl).hostname.replace(/\.$/, '');
  } catch {
    fail(`XYTE_HUB_URL is not a valid URL: ${hubUrl}`);
  }
  // ponytail: exact production host only; add other prod hostnames here if any appear.
  if (hubHost === PRODUCTION_HOST) fail('refusing to run against production.');
  const key = env.XYTE_PARTNER_API_KEY?.trim();
  if (!key) fail('set XYTE_PARTNER_API_KEY to the partner key under test.');

  const results = [];
  const servers = [];
  // Every line check/skip/print wrote, so a loop can assert no secret reached its own output.
  const printed = [];

  function print(line) {
    printed.push(line);
    console.log(line);
  }

  function check(name, pass, detail = '') {
    results.push({ name, pass });
    print(`${pass ? ' PASS ' : ' FAIL '} ${name}${detail ? `  (${detail})` : ''}`);
    return pass;
  }

  function skip(name, why) {
    print(` SKIP ${name}  (${why})`);
  }

  // Summary line; exit code 1 when any check failed.
  function finish() {
    const failed = results.filter((result) => !result.pass);
    print(`\n${results.length - failed.length}/${results.length} checks passed`);
    if (failed.length) {
      print(`\nFailed: ${failed.map((result) => result.name).join(', ')}`);
      process.exitCode = 1;
    }
  }

  // Checks the write log of every server the loop started; returns their joined stderr.
  function checkWriteLog() {
    const stderr = servers.map((server) => server.stderr.join('')).join('');
    const writeLines = stderr.split('\n').filter((line) => /\] write .* status=\d/.test(line));
    const writes = servers.reduce((sum, server) => sum + server.writes, 0);
    check('write log: one line per write that got an HTTP status', writeLines.length === writes, `${writeLines.length} lines, ${writes} writes`);
    return stderr;
  }

  // Checked here, after the caller's own env checks, so those run without a build.
  async function startMcpServerClient(partnerApiKey, extraEnv = {}) {
    if (!existsSync(ENTRY)) fail(`not built; run npm run build (missing ${ENTRY}).`);
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [ENTRY],
      env: { PATH: env.PATH ?? '', XYTE_HUB_URL: hubUrl, XYTE_PARTNER_API_KEY: partnerApiKey, ...extraEnv },
      stderr: 'pipe'
    });
    const stderr = [];
    transport.stderr?.on('data', (chunk) => stderr.push(String(chunk)));
    const client = new Client({ name: `xyte-mcp-${loopName.replaceAll(' ', '-')}`, version: '0' });
    await client.connect(transport);
    const server = { client, stderr, call, writes: 0 };
    servers.push(server);

    async function call(endpointKey, args = {}) {
      const isWrite = !endpointKey.split('.').pop().startsWith('get');
      const result = await client.callTool({ name: 'xyte_api_call', arguments: { key: endpointKey, ...args } });
      const text = result.content?.[0]?.text ?? '';
      const status = result.isError ? Number(/failed: (\d{3})/.exec(text)?.[1] ?? 0) : result.structuredContent?.status;
      // Status 0 = no HTTP status: refused, invalid or a network failure (logged as status=error, not counted).
      if (isWrite && status) server.writes += 1;
      return { ok: !result.isError, status, data: result.structuredContent?.data, text };
    }

    return server;
  }

  return { env, hubUrl, key, fail, print, printed, check, skip, finish, checkWriteLog, startMcpServerClient };
}

export const rows = (response) => response.data?.data ?? [];
