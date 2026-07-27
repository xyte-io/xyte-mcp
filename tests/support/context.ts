import { DEFAULT_ENTRY_URL, DEFAULT_HUB_URL } from '../../src/catalog/../config.js';
import type { HttpClient, HttpRequest, HttpResponse } from '../../src/http/client.js';
import type { ToolContext } from '../../src/context.js';

export interface StubHttp extends HttpClient {
  calls: HttpRequest[];
}

/** Records requests and replays a queued response (or throws a queued error). */
export function stubHttp(
  responder: (request: HttpRequest) => Partial<HttpResponse> | Error
): StubHttp {
  const calls: HttpRequest[] = [];
  return {
    calls,
    async request(request: HttpRequest): Promise<HttpResponse> {
      calls.push(request);
      const outcome = responder(request);
      if (outcome instanceof Error) throw outcome;
      return {
        status: 200,
        statusText: 'OK',
        durationMs: 1,
        attempts: 1,
        data: undefined,
        ...outcome
      };
    }
  };
}

export function testContext(overrides: Partial<ToolContext> = {}): ToolContext {
  const credentials = overrides.credentials ?? { organization: 'org-key-abcdef123456' };
  return {
    http: overrides.http ?? stubHttp(() => ({ data: {} })),
    credentials,
    baseUrls: overrides.baseUrls ?? { hub: DEFAULT_HUB_URL, entry: DEFAULT_ENTRY_URL },
    allowWrites: overrides.allowWrites ?? false,
    secrets:
      overrides.secrets ??
      Object.values(credentials).filter((value): value is string => typeof value === 'string')
  };
}
