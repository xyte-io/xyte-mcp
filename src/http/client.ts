import { XyteError, XyteHttpError } from './errors.js';

export interface HttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  /** Only used to label errors. */
  endpointKey: string;
}

export interface HttpResponse {
  status: number;
  statusText: string;
  durationMs: number;
  attempts: number;
  data: unknown;
}

export interface HttpClient {
  request(request: HttpRequest): Promise<HttpResponse>;
}

export interface HttpClientOptions {
  timeoutMs?: number;
  retryAttempts?: number;
  retryBackoffMs?: number;
  /** Injectable for tests. */
  fetchImpl?: typeof fetch;
  sleepImpl?: (ms: number) => Promise<void>;
}

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_RETRY_ATTEMPTS = 2;
const DEFAULT_RETRY_BACKOFF_MS = 250;

/**
 * Retrying a non-idempotent method can duplicate a side effect — send a command
 * twice, create two records. Only methods that are safe to repeat get retries.
 */
const IDEMPOTENT_METHODS = new Set(['GET', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']);

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

export function createHttpClient(options: HttpClientOptions = {}): HttpClient {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const retryAttempts = options.retryAttempts ?? DEFAULT_RETRY_ATTEMPTS;
  const retryBackoffMs = options.retryBackoffMs ?? DEFAULT_RETRY_BACKOFF_MS;
  const fetchImpl = options.fetchImpl ?? fetch;
  const sleepImpl = options.sleepImpl ?? sleep;

  return {
    async request(request: HttpRequest): Promise<HttpResponse> {
      const maxAttempts = IDEMPOTENT_METHODS.has(request.method.toUpperCase())
        ? retryAttempts + 1
        : 1;
      const startedAt = performance.now();
      let lastError: unknown;

      for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
        try {
          const response = await attemptOnce(fetchImpl, request, timeoutMs);
          return { ...response, durationMs: elapsed(startedAt), attempts: attempt };
        } catch (error) {
          lastError = error;
          const retriable =
            (error instanceof XyteHttpError && error.retriable) ||
            (error instanceof XyteError &&
              (error.kind === 'network' || error.kind === 'timeout'));
          if (!retriable || attempt === maxAttempts) break;
          await sleepImpl(retryBackoffMs * attempt);
        }
      }

      throw lastError;
    }
  };
}

function elapsed(startedAt: number): number {
  return Math.round(performance.now() - startedAt);
}

async function attemptOnce(
  fetchImpl: typeof fetch,
  request: HttpRequest,
  timeoutMs: number
): Promise<Omit<HttpResponse, 'durationMs' | 'attempts'>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetchImpl(request.url, {
      method: request.method,
      headers: request.headers,
      ...(request.body === undefined ? {} : { body: request.body }),
      signal: controller.signal
    });
  } catch (error) {
    if (controller.signal.aborted) {
      throw new XyteError('timeout', `Request to ${request.endpointKey} timed out after ${timeoutMs}ms`);
    }
    throw new XyteError(
      'network',
      `Network error calling ${request.endpointKey}: ${error instanceof Error ? error.message : String(error)}`
    );
  } finally {
    clearTimeout(timer);
  }

  const data = await parseBody(response);

  if (!response.ok) {
    throw new XyteHttpError(response.status, response.statusText, data, request.endpointKey);
  }

  return { status: response.status, statusText: response.statusText, data };
}

async function parseBody(response: Response): Promise<unknown> {
  if (response.status === 204 || response.status === 205) return undefined;

  const text = await response.text();
  if (!text) return undefined;

  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('json')) {
    try {
      return JSON.parse(text) as unknown;
    } catch {
      // Server claimed JSON and sent something else; surface it verbatim
      // rather than throwing, so the caller can see what arrived.
      return { raw: text };
    }
  }
  return { raw: text };
}
