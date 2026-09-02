import { XyteError } from './http/errors.js';

export const ENV = {
  orgKey: 'XYTE_ORG_API_KEY',
  partnerKey: 'XYTE_PARTNER_API_KEY',
  readOnly: 'XYTE_MCP_READ_ONLY',
  /** Superseded by `readOnly`, still honoured — see `resolveWrites`. */
  allowWrites: 'XYTE_MCP_ALLOW_WRITES',
  hubUrl: 'XYTE_HUB_URL',
  entryUrl: 'XYTE_ENTRY_URL',
  timeoutMs: 'XYTE_MCP_TIMEOUT_MS',
  httpToken: 'XYTE_MCP_HTTP_TOKEN',
  /** Set by the platform (Heroku, Fly, …); the transport only reads it. */
  httpPort: 'PORT'
} as const;

export const DEFAULT_HUB_URL = 'https://hub.xyte.io';
export const DEFAULT_ENTRY_URL = 'https://entry.xyte.io';
export const DEFAULT_HTTP_PORT = 3000;

/** Short enough to fit any sane generator, long enough not to be guessed. */
const MIN_TOKEN_LENGTH = 24;

export interface Credentials {
  organization?: string;
  partner?: string;
}

/** Configuration of the HTTP listener itself, as opposed to of a tool call. */
export interface HttpConfig {
  /** The single static bearer every request must present. */
  token: string;
  port: number;
}

export interface ServerConfig {
  credentials: Credentials;
  baseUrls: { hub: string; entry: string };
  /** When false, only GET/HEAD endpoints may be called. On by default. */
  allowWrites: boolean;
  timeoutMs: number;
}

/**
 * Read configuration from the environment.
 *
 * This is the ONLY place that touches `env` — tools receive an already-resolved
 * context. That separation is what lets a future HTTP/OAuth transport supply
 * per-request credentials without any tool changes.
 */
export function resolveConfig(env: NodeJS.ProcessEnv = process.env): ServerConfig {
  const organization = trimmed(env[ENV.orgKey]);
  const partner = trimmed(env[ENV.partnerKey]);

  if (!organization && !partner) {
    throw new XyteError(
      'config',
      `No Xyte API key configured. Set ${ENV.orgKey} and/or ${ENV.partnerKey}.`,
      [
        `Add to your MCP host config: "env": { "${ENV.orgKey}": "<key>" }`,
        'Organization and partner keys are separate; set whichever scopes you need.'
      ]
    );
  }

  return {
    credentials: {
      ...(organization ? { organization } : {}),
      ...(partner ? { partner } : {})
    },
    baseUrls: {
      hub: stripTrailingSlash(trimmed(env[ENV.hubUrl]) ?? DEFAULT_HUB_URL),
      entry: stripTrailingSlash(trimmed(env[ENV.entryUrl]) ?? DEFAULT_ENTRY_URL)
    },
    allowWrites: resolveWrites(env),
    timeoutMs: parsePositiveInt(env[ENV.timeoutMs]) ?? 15_000
  };
}

/**
 * Read the HTTP transport's configuration.
 *
 * Separate from `resolveConfig` because a bearer token and a port are properties
 * of the listener, not of a tool call — and keeping every environment read in
 * this module is what lets `src/transports/` stay free of `process.env`.
 *
 * A missing token is fatal rather than "auth off". This transport is reachable
 * from the internet and holds a live API key, so defaulting open would publish
 * that key to anyone who found the URL. Same reason for the length floor: a
 * two-character token is a typo, not a credential, and it would be brute-forced
 * before anyone noticed.
 */
export function resolveHttpConfig(env: NodeJS.ProcessEnv = process.env): HttpConfig {
  const token = trimmed(env[ENV.httpToken]);
  if (!token) {
    throw new XyteError(
      'config',
      `No bearer token configured. Set ${ENV.httpToken} to serve over HTTP.`,
      [
        `Mint one: node -e "console.log('xmcp_' + require('crypto').randomBytes(32).toString('base64url'))"`,
        'Every request must then send: Authorization: Bearer <token>'
      ]
    );
  }
  if (token.length < MIN_TOKEN_LENGTH) {
    throw new XyteError(
      'config',
      `${ENV.httpToken} is too short — ${MIN_TOKEN_LENGTH} characters minimum.`,
      ['A guessable bearer token is the same as no authentication at all.']
    );
  }

  return { token, port: parsePositiveInt(env[ENV.httpPort]) ?? DEFAULT_HTTP_PORT };
}

function trimmed(value: string | undefined): string | undefined {
  const text = value?.trim();
  return text ? text : undefined;
}

function stripTrailingSlash(url: string): string {
  return url.replace(/\/+$/, '');
}

/**
 * Writes are permitted by default; read-only is the opt-in.
 *
 * `XYTE_MCP_READ_ONLY=1` is the switch. `XYTE_MCP_ALLOW_WRITES` predates it and
 * keeps its original meaning whenever it is present at all: 0.1.x was read-only
 * by default, so anyone who set that variable made a deliberate choice, and
 * quietly widening their server's posture on upgrade would be the worst kind of
 * surprise. Where the two disagree, the restrictive one wins.
 */
function resolveWrites(env: NodeJS.ProcessEnv): boolean {
  if (parseBooleanFlag(env[ENV.readOnly])) return false;
  const legacy = env[ENV.allowWrites];
  if (legacy !== undefined) return parseBooleanFlag(legacy);
  return true;
}

/** Only an explicit affirmative counts as true; anything else is false. */
function parseBooleanFlag(value: string | undefined): boolean {
  const normalized = value?.trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes';
}

function parsePositiveInt(value: string | undefined): number | undefined {
  if (!value?.trim()) return undefined;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}
