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
  /** Public base URL of this deployment; setting it turns OAuth on. */
  issuerUrl: 'XYTE_MCP_ISSUER_URL',
  /** Set by Heroku Postgres; the OAuth token store. Absent → in-memory store. */
  databaseUrl: 'DATABASE_URL',
  /** Set by the platform (Heroku, Fly, …); the transport only reads it. */
  httpPort: 'PORT'
} as const;

export const DEFAULT_HUB_URL = 'https://hub.xyte.io';
export const DEFAULT_ENTRY_URL = 'https://entry.xyte.io';
export const DEFAULT_HTTP_PORT = 3000;

/** Short enough to fit any sane generator, long enough not to be guessed. */
const MIN_TOKEN_LENGTH = 24;

/**
 * A hub user session, as returned by hub's devise_token_auth `POST /auth/sign_in`.
 * The alternative to an org API key: hub resolves the user and enforces their
 * role. `tenant` selects the organization when the user belongs to several.
 */
export interface HubUserCredential {
  accessToken: string;
  client: string;
  uid: string;
  tenant?: string;
}

export interface Credentials {
  organization?: string | HubUserCredential;
  partner?: string;
}

export interface OAuthConfig {
  /** Public https base URL of this deployment (RFC 8414 issuer). */
  issuerUrl: string;
  /** Postgres DSN for the token store; absent → in-memory (dev only). */
  databaseUrl?: string;
}

/** Configuration of the HTTP listener itself, as opposed to of a tool call. */
export interface HttpConfig {
  /** Static bearer for dev/CI; optional once OAuth is configured. */
  staticToken?: string;
  oauth?: OAuthConfig;
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
export function resolveConfig(
  env: NodeJS.ProcessEnv = process.env,
  options: { requireCredentials?: boolean } = {}
): ServerConfig {
  const organization = trimmed(env[ENV.orgKey]);
  const partner = trimmed(env[ENV.partnerKey]);

  // An OAuth-only HTTP server has no process-level key: every request brings
  // its own hub user credential, so an empty credential set is valid there.
  if (!organization && !partner && (options.requireCredentials ?? true)) {
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
 * No auth at all is fatal rather than "auth off". This transport is reachable
 * from the internet, so defaulting open would publish whatever credentials the
 * process holds to anyone who found the URL. Same reason for the length floor
 * on the static token: a two-character token is a typo, not a credential, and
 * it would be brute-forced before anyone noticed.
 */
export function resolveHttpConfig(env: NodeJS.ProcessEnv = process.env): HttpConfig {
  const staticToken = trimmed(env[ENV.httpToken]);
  const issuerUrl = trimmed(env[ENV.issuerUrl]);

  if (!staticToken && !issuerUrl) {
    throw new XyteError(
      'config',
      `No authentication configured. Set ${ENV.httpToken} (static bearer) and/or ${ENV.issuerUrl} (OAuth) to serve over HTTP.`,
      [
        `Mint a static token: node -e "console.log('xmcp_' + require('crypto').randomBytes(32).toString('base64url'))"`,
        `Or set ${ENV.issuerUrl} to this deployment's public https URL to enable OAuth 2.1.`
      ]
    );
  }
  if (staticToken && staticToken.length < MIN_TOKEN_LENGTH) {
    throw new XyteError(
      'config',
      `${ENV.httpToken} is too short — ${MIN_TOKEN_LENGTH} characters minimum.`,
      ['A guessable bearer token is the same as no authentication at all.']
    );
  }
  // The static bearer fronts the process-level org/partner key, so one without
  // the other is a misconfiguration, not a mode.
  if (staticToken && !trimmed(env[ENV.orgKey]) && !trimmed(env[ENV.partnerKey])) {
    throw new XyteError(
      'config',
      `${ENV.httpToken} is set but no API key is configured for it to front.`,
      [`Set ${ENV.orgKey} and/or ${ENV.partnerKey}, or unset ${ENV.httpToken} and use OAuth only.`]
    );
  }

  let oauth: OAuthConfig | undefined;
  if (issuerUrl) {
    validateIssuerUrl(issuerUrl);
    oauth = {
      issuerUrl: stripTrailingSlash(issuerUrl),
      ...(trimmed(env[ENV.databaseUrl]) ? { databaseUrl: trimmed(env[ENV.databaseUrl]) } : {})
    };
  }

  return {
    ...(staticToken ? { staticToken } : {}),
    ...(oauth ? { oauth } : {}),
    port: parsePositiveInt(env[ENV.httpPort]) ?? DEFAULT_HTTP_PORT
  };
}

/**
 * Fail at boot, not on the first /authorize: tokens minted under an http or
 * malformed issuer would be rejected by clients after a working-looking start.
 * Localhost is exempt so tests and local runs don't need TLS (the SDK's
 * metadata router applies the same exemption).
 */
function validateIssuerUrl(value: string): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new XyteError('config', `${ENV.issuerUrl} is not a valid URL: ${value}`);
  }
  const localhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !localhost) {
    throw new XyteError('config', `${ENV.issuerUrl} must be https (got ${url.protocol}//).`, [
      'OAuth tokens over plain http are readable by every hop on the path.'
    ]);
  }
  if (url.search || url.hash) {
    throw new XyteError('config', `${ENV.issuerUrl} must not have a query string or fragment.`);
  }
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
