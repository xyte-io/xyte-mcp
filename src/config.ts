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
  /** This server's confidential-client credentials at hub's OAuth server; required with OAuth. */
  hubOAuthClientId: 'XYTE_MCP_HUB_OAUTH_CLIENT_ID',
  hubOAuthClientSecret: 'XYTE_MCP_HUB_OAUTH_CLIENT_SECRET',
  /** Set by the platform (Heroku, Fly, …); the transport only reads it. */
  httpPort: 'PORT'
} as const;

export const DEFAULT_HUB_URL = 'https://hub.xyte.io';
export const DEFAULT_ENTRY_URL = 'https://entry.xyte.io';
export const DEFAULT_HTTP_PORT = 3000;

/**
 * Short enough to fit any sane generator, long enough not to be guessed.
 * Counted after the optional `xmcp_` prefix, which is only a grep-able marker
 * for secret scanners and adds nothing to guess.
 */
const MIN_TOKEN_LENGTH = 24;
const TOKEN_MARKER = 'xmcp_';

/**
 * A hub OAuth access token (`xoat_…`), bound to the one organization picked on
 * hub's consent screen. It carries that organization's full authority, like an
 * org API key; the user who signed in for it is attribution only.
 */
export interface HubOAuthCredential {
  accessToken: string;
}

export interface Credentials {
  organization?: string | HubOAuthCredential;
  partner?: string;
}

export interface OAuthConfig {
  /** Public https base URL of this deployment (RFC 8414 issuer). */
  issuerUrl: string;
  /** Postgres DSN for the token store; absent → in-memory (dev only). */
  databaseUrl?: string;
  /** xyte-mcp's own client registration at hub's OAuth server (client_secret_basic). */
  hubClient: { id: string; secret: string };
}

/** Configuration of the HTTP listener itself, as opposed to of a tool call. */
export interface HttpConfig {
  /** Static bearer for dev/CI. Exactly one of this and `oauth` is set. */
  staticToken?: string;
  oauth?: OAuthConfig;
  port: number;
}

export interface ServerConfig {
  credentials: Credentials;
  baseUrls: { hub: string; entry: string };
  /** When false, only GET/HEAD endpoints may be called. On by default over stdio, off over HTTP. */
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
  options: { requireCredentials?: boolean; writesByDefault?: boolean } = {}
): ServerConfig {
  const organization = trimmed(env[ENV.orgKey]);
  const partner = trimmed(env[ENV.partnerKey]);

  // An OAuth-only HTTP server has no process-level key: every request brings
  // its own hub OAuth token, so an empty credential set is valid there.
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
    allowWrites: resolveWrites(env, options.writesByDefault ?? true),
    timeoutMs: parsePositiveInt(env[ENV.timeoutMs]) ?? 15_000
  };
}

/**
 * Read the HTTP transport's configuration.
 *
 * Separate from `resolveConfig` because a bearer token and a port are properties
 * of the listener, not of a tool call — and keeping every environment read in
 * this module means transports only pass `env` through; they never read
 * individual variables.
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
      `No authentication configured. Set ${ENV.httpToken} (static bearer) or ${ENV.issuerUrl} (OAuth) to serve over HTTP.`,
      [
        `Mint a static token: node -e "console.log('${TOKEN_MARKER}' + require('crypto').randomBytes(32).toString('base64url'))"`,
        `Or set ${ENV.issuerUrl} to this deployment's public https URL to enable OAuth 2.1.`
      ]
    );
  }
  // One mode per deployment: a static bearer on a public OAuth issuer is a
  // shared identity (with the process keys, partner scope included) sitting
  // next to the per-user sign-in, on the same URL.
  if (staticToken && issuerUrl) {
    throw new XyteError(
      'config',
      `${ENV.httpToken} and ${ENV.issuerUrl} are both set; a deployment serves one or the other.`,
      [`Unset ${ENV.httpToken} for OAuth, or ${ENV.issuerUrl} for the static-bearer mode.`]
    );
  }
  const secretPart = staticToken?.startsWith(TOKEN_MARKER)
    ? staticToken.slice(TOKEN_MARKER.length)
    : staticToken;
  if (secretPart !== undefined && secretPart.length < MIN_TOKEN_LENGTH) {
    throw new XyteError(
      'config',
      `${ENV.httpToken} is too short — ${MIN_TOKEN_LENGTH} characters minimum, not counting a ${TOKEN_MARKER} prefix.`,
      ['A guessable bearer token is the same as no authentication at all.']
    );
  }
  // The static bearer fronts the process-level org/partner key, so one without
  // the other is a misconfiguration, not a mode.
  if (staticToken && !trimmed(env[ENV.orgKey]) && !trimmed(env[ENV.partnerKey])) {
    throw new XyteError(
      'config',
      `${ENV.httpToken} is set but no API key is configured for it to front.`,
      [`Set ${ENV.orgKey} and/or ${ENV.partnerKey}, or unset ${ENV.httpToken} and use OAuth.`]
    );
  }

  let oauth: OAuthConfig | undefined;
  if (issuerUrl) {
    validateIssuerUrl(issuerUrl);
    const id = trimmed(env[ENV.hubOAuthClientId]);
    const secret = trimmed(env[ENV.hubOAuthClientSecret]);
    if (!id || !secret) {
      throw new XyteError(
        'config',
        `${ENV.issuerUrl} is set but ${ENV.hubOAuthClientId} / ${ENV.hubOAuthClientSecret} ` +
          'are not.',
        [
          'Register this server at hub: GLOBAL=true rake ' +
            `"oauth:register_application[Xyte MCP,,${stripTrailingSlash(issuerUrl)}/oauth/callback]"`
        ]
      );
    }
    oauth = {
      // The origin, as the SDK normalizes it (lowercase host, no default port),
      // so the RFC 8707 resource compares equal to what clients send back.
      issuerUrl: new URL(issuerUrl).origin,
      ...(trimmed(env[ENV.databaseUrl]) ? { databaseUrl: trimmed(env[ENV.databaseUrl]) } : {}),
      hubClient: { id, secret }
    };
  }

  return {
    ...(staticToken ? { staticToken } : {}),
    ...(oauth ? { oauth } : {}),
    port: parsePort(env[ENV.httpPort])
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
  // Routes are mounted at the root, so a path would send every sign-in to a 404.
  if (url.pathname !== '/') {
    throw new XyteError('config', `${ENV.issuerUrl} must not have a path (got ${url.pathname}).`);
  }
}

/** An unset PORT defaults; a set-but-invalid one is a misconfiguration, not a default. */
function parsePort(value: string | undefined): number {
  if (!value?.trim()) return DEFAULT_HTTP_PORT;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new XyteError('config', `${ENV.httpPort} must be an integer in 1..65535 (got "${value}").`);
  }
  return port;
}

function trimmed(value: string | undefined): string | undefined {
  const text = value?.trim();
  return text ? text : undefined;
}

function stripTrailingSlash(url: string): string {
  return url.replace(/\/+$/, '');
}

/**
 * Over stdio writes are permitted by default and read-only is the opt-in; over
 * HTTP (`writesByDefault: false`) it is the other way round, because there the
 * blast radius is whoever holds a token, not one laptop.
 *
 * `XYTE_MCP_READ_ONLY=1` always wins. `XYTE_MCP_ALLOW_WRITES` predates it and
 * keeps its original meaning whenever it is present at all: 0.1.x was read-only
 * by default, so anyone who set that variable made a deliberate choice, and
 * quietly widening their server's posture on upgrade would be the worst kind of
 * surprise. It is also the explicit opt-in to writes over HTTP. Where the two
 * disagree, the restrictive one wins.
 */
function resolveWrites(env: NodeJS.ProcessEnv, writesByDefault: boolean): boolean {
  if (parseBooleanFlag(env[ENV.readOnly])) return false;
  const legacy = env[ENV.allowWrites];
  if (legacy !== undefined) return parseBooleanFlag(legacy);
  return writesByDefault;
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
