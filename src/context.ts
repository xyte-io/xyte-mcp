import { createHttpClient, type HttpClient } from './http/client.js';
import type { Credentials, ServerConfig } from './config.js';

/**
 * Everything a tool is allowed to depend on.
 *
 * Tools receive this and nothing else — no `process.env`, no transport, no
 * global state. Swapping stdio for an HTTP/OAuth transport means building this
 * object differently (per-request credentials instead of per-process ones),
 * with no change to any tool.
 */
export interface ToolContext {
  readonly http: HttpClient;
  readonly credentials: Credentials;
  readonly baseUrls: { readonly hub: string; readonly entry: string };
  /** When false, only GET/HEAD endpoints may be called. */
  readonly allowWrites: boolean;
  /** Literal secret values to strip from anything returned to the caller. */
  readonly secrets: readonly string[];
}

export function createToolContext(config: ServerConfig, http?: HttpClient): ToolContext {
  return {
    http: http ?? createHttpClient({ timeoutMs: config.timeoutMs }),
    credentials: config.credentials,
    baseUrls: config.baseUrls,
    allowWrites: config.allowWrites,
    secrets: Object.values(config.credentials).filter(
      (value): value is string => typeof value === 'string' && value.length > 0
    )
  };
}
