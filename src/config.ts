import { XyteError } from './http/errors.js';

export const ENV = {
  orgKey: 'XYTE_ORG_API_KEY',
  partnerKey: 'XYTE_PARTNER_API_KEY',
  allowWrites: 'XYTE_MCP_ALLOW_WRITES',
  hubUrl: 'XYTE_HUB_URL',
  entryUrl: 'XYTE_ENTRY_URL',
  timeoutMs: 'XYTE_MCP_TIMEOUT_MS'
} as const;

export const DEFAULT_HUB_URL = 'https://hub.xyte.io';
export const DEFAULT_ENTRY_URL = 'https://entry.xyte.io';

export interface Credentials {
  organization?: string;
  partner?: string;
}

export interface ServerConfig {
  credentials: Credentials;
  baseUrls: { hub: string; entry: string };
  /** When false, only GET/HEAD endpoints may be called. */
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
    allowWrites: parseBooleanFlag(env[ENV.allowWrites]),
    timeoutMs: parsePositiveInt(env[ENV.timeoutMs]) ?? 15_000
  };
}

function trimmed(value: string | undefined): string | undefined {
  const text = value?.trim();
  return text ? text : undefined;
}

function stripTrailingSlash(url: string): string {
  return url.replace(/\/+$/, '');
}

/** Only an explicit affirmative enables writes; anything else is off. */
function parseBooleanFlag(value: string | undefined): boolean {
  const normalized = value?.trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes';
}

function parsePositiveInt(value: string | undefined): number | undefined {
  if (!value?.trim()) return undefined;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}
