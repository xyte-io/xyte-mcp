#!/usr/bin/env node
/**
 * Generate the endpoint catalog from hub's Bruno collection.
 *
 *   node scripts/generate-catalog.mjs --hub-path ../hub [--out <path>] [--check]
 *
 * The Bruno collection under `hub/docs/api/Xyte Public/` is the upstream source
 * the public API reference is built from, so it — not any other tool's catalog —
 * is what we derive from. Output is committed; this script is run by a
 * maintainer when the API changes.
 *
 * `--check` exits non-zero if the committed file differs from a fresh
 * generation, without writing.
 *
 * Never reads `environments/` — those files contain real credentials.
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { bruToJsonV2 } from '@usebruno/lang';

const COLLECTION_SUBPATH = path.join(
  'docs',
  'api',
  'Xyte Public',
  'Xyte Platform API - Documentation'
);

/** Top-level Bruno folders we generate from, and the namespace each maps to. */
const NAMESPACE_FOLDERS = {
  'Organization API': 'organization',
  'Partner API': 'partner'
};

/**
 * Bruno template variable in the `Authorization` header -> credential scope.
 * `{{authorization}}` is a device access token: the Device API authenticates as
 * a device, not as an operator, so those endpoints are deliberately excluded.
 */
const AUTH_SCOPE_BY_HEADER = {
  '{{org_api}}': 'organization',
  '{{partner_api}}': 'partner',
  '{{authorization}}': null
};

const BASE_BY_URL_PREFIX = [
  ['https://hub.xyte.io', 'hub'],
  ['{{hub_url}}', 'hub'],
  ['https://entry.xyte.io', 'entry'],
  ['{{entry_url}}', 'entry']
];

const SKIP_FILENAMES = new Set(['collection.bru', 'folder.bru']);
const SKIP_DIRNAMES = new Set(['environments']);

function parseArgs(argv) {
  const args = { hubPath: '../hub', out: null, check: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--hub-path') args.hubPath = argv[++i];
    else if (arg === '--out') args.out = argv[++i];
    else if (arg === '--check') args.check = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!args.hubPath) throw new Error('--hub-path requires a value');
  return args;
}

function walkBruFiles(dir) {
  const found = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) {
      if (SKIP_DIRNAMES.has(entry)) continue;
      found.push(...walkBruFiles(full));
    } else if (entry.endsWith('.bru') && !SKIP_FILENAMES.has(entry)) {
      found.push(full);
    }
  }
  return found;
}

function camelCase(text) {
  const words = text
    .replace(/[^0-9a-zA-Z]+/g, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  if (words.length === 0) return '';
  return words
    .map((word, index) => {
      const lower = word.toLowerCase();
      if (index === 0) return lower;
      return lower.charAt(0).toUpperCase() + lower.slice(1);
    })
    .join('');
}

/** Split a Bruno URL into { base, pathTemplate }, normalising `{{x}}` to `:x`. */
function splitUrl(url, sourceFile) {
  const match = BASE_BY_URL_PREFIX.find(([prefix]) => url.startsWith(prefix));
  if (!match) {
    throw new Error(`${sourceFile}: unrecognised URL base in "${url}"`);
  }
  const [prefix, base] = match;
  let rest = url.slice(prefix.length);

  // Strip any query string Bruno kept in the URL — query params come from the
  // params block, which is authoritative.
  const queryIndex = rest.indexOf('?');
  if (queryIndex !== -1) rest = rest.slice(0, queryIndex);

  // Some files write path params as {{device_id}} rather than :device_id.
  const pathTemplate = rest.replace(/\{\{(\w+)\}\}/g, ':$1');
  if (!pathTemplate.startsWith('/')) {
    throw new Error(`${sourceFile}: path does not start with "/": "${pathTemplate}"`);
  }
  return { base, pathTemplate };
}

function pathParamsFromTemplate(pathTemplate) {
  return [...pathTemplate.matchAll(/:(\w+)/g)].map((m) => m[1]);
}

function headerValue(headers, name) {
  const found = (headers ?? []).find(
    (header) => header.name?.toLowerCase() === name.toLowerCase()
  );
  return found?.value?.trim();
}

function buildEndpoint(file, collectionRoot) {
  const sourceFile = path.relative(collectionRoot, file);
  const parsed = bruToJsonV2(readFileSync(file, 'utf8'));

  if (parsed.meta?.type !== 'http') return null;

  const segments = sourceFile.split(path.sep);
  const namespace = NAMESPACE_FOLDERS[segments[0]];
  if (!namespace) return null;

  const authHeader = headerValue(parsed.headers, 'Authorization');
  if (!(authHeader in AUTH_SCOPE_BY_HEADER)) {
    throw new Error(
      `${sourceFile}: unrecognised Authorization header "${authHeader}". ` +
        `Add it to AUTH_SCOPE_BY_HEADER or fix the Bruno file.`
    );
  }
  const authScope = AUTH_SCOPE_BY_HEADER[authHeader];
  // Device-scoped endpoint: out of scope for an operator server.
  if (authScope === null) return null;

  const http = parsed.http;
  if (!http?.method || !http?.url) {
    throw new Error(`${sourceFile}: missing method or url`);
  }
  const method = http.method.toUpperCase();
  const { base, pathTemplate } = splitUrl(http.url.trim(), sourceFile);

  // `params:path` is explicit in most files, but the URL is the thing actually
  // substituted at call time, so treat it as authoritative and cross-check.
  const fromTemplate = pathParamsFromTemplate(pathTemplate);
  const declaredPath = (parsed.params ?? [])
    .filter((param) => param.type === 'path')
    .map((param) => param.name);
  const undeclared = fromTemplate.filter((name) => !declaredPath.includes(name));
  const unused = declaredPath.filter((name) => !fromTemplate.includes(name));
  if (undeclared.length || unused.length) {
    const parts = [];
    if (undeclared.length) parts.push(`in URL but not declared: ${undeclared.join(', ')}`);
    if (unused.length) parts.push(`declared but not in URL: ${unused.join(', ')}`);
    console.warn(`  warn ${sourceFile}: path param mismatch (${parts.join('; ')})`);
  }

  // Disabled (`~name`) query params are still documented, valid params — Bruno's
  // tilde only means "not sent by default in the GUI".
  const queryParams = (parsed.params ?? [])
    .filter((param) => param.type === 'query')
    .map((param) => param.name);

  const group = segments.slice(1, -1).map(camelCase).join('.');
  const action = camelCase(parsed.meta.name);
  const key = [namespace, group, action].filter(Boolean).join('.');

  const bodyExample = parsed.body?.json?.trim();
  const declaredBody = (http.body ?? 'none').toLowerCase();
  const bodyType = declaredBody === 'json' ? 'json' : 'none';

  return {
    key,
    namespace,
    group,
    action,
    title: parsed.meta.name,
    ...(parsed.docs?.trim() ? { description: parsed.docs.trim() } : {}),
    method,
    base,
    pathTemplate,
    pathParams: fromTemplate,
    queryParams,
    authScope,
    bodyType,
    ...(bodyType === 'json' && bodyExample ? { bodyExample } : {}),
    mutating: !['GET', 'HEAD'].includes(method),
    sourceFile
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const collectionRoot = path.resolve(args.hubPath, COLLECTION_SUBPATH);
  const outPath = args.out
    ? path.resolve(args.out)
    : path.resolve(import.meta.dirname, '..', 'src', 'catalog', 'endpoints.generated.json');

  try {
    statSync(collectionRoot);
  } catch {
    throw new Error(
      `Bruno collection not found at ${collectionRoot}\n` +
        `Pass --hub-path pointing at a hub checkout (e.g. --hub-path ../hub).`
    );
  }

  const endpoints = [];
  let skipped = 0;
  for (const folder of Object.keys(NAMESPACE_FOLDERS)) {
    const dir = path.join(collectionRoot, folder);
    try {
      statSync(dir);
    } catch {
      console.warn(`  warn missing namespace folder: ${folder}`);
      continue;
    }
    for (const file of walkBruFiles(dir)) {
      const endpoint = buildEndpoint(file, collectionRoot);
      if (endpoint) endpoints.push(endpoint);
      else skipped += 1;
    }
  }

  const byKey = new Map();
  for (const endpoint of endpoints) {
    const existing = byKey.get(endpoint.key);
    if (existing) {
      throw new Error(
        `Duplicate endpoint key "${endpoint.key}"\n` +
          `  ${existing.sourceFile}\n  ${endpoint.sourceFile}\n` +
          `Rename one of the Bruno requests so the generated keys are unique.`
      );
    }
    byKey.set(endpoint.key, endpoint);
  }

  endpoints.sort((a, b) => a.key.localeCompare(b.key));

  const catalog = {
    catalogVersion: 1,
    generatedFrom: `hub:${COLLECTION_SUBPATH}`,
    endpoints
  };
  const serialized = `${JSON.stringify(catalog, null, 2)}\n`;

  if (args.check) {
    let current = null;
    try {
      current = readFileSync(outPath, 'utf8');
    } catch {
      console.error(`FAIL committed catalog missing at ${outPath}`);
      process.exit(1);
    }
    if (current !== serialized) {
      console.error(
        'FAIL committed catalog is stale.\n' +
          'Run: npm run catalog:generate -- --hub-path <hub> and commit the result.'
      );
      process.exit(1);
    }
    console.error(`OK catalog up to date (${endpoints.length} endpoints)`);
    return;
  }

  writeFileSync(outPath, serialized);

  const counts = endpoints.reduce((acc, endpoint) => {
    acc[endpoint.authScope] = (acc[endpoint.authScope] ?? 0) + 1;
    return acc;
  }, {});
  console.error(
    `wrote ${endpoints.length} endpoints to ${path.relative(process.cwd(), outPath)}\n` +
      `  organization: ${counts.organization ?? 0}, partner: ${counts.partner ?? 0}\n` +
      `  mutating: ${endpoints.filter((e) => e.mutating).length}\n` +
      `  skipped (device-scoped / non-http): ${skipped}`
  );
}

main();
