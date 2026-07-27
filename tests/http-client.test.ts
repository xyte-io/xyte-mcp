import { describe, expect, it, vi } from 'vitest';
import { createHttpClient } from '../src/http/client.js';
import { XyteError, XyteHttpError } from '../src/http/errors.js';

const request = (method = 'GET') => ({
  method,
  url: 'https://hub.xyte.io/core/v1/organization/devices',
  headers: { Authorization: 'k' },
  endpointKey: 'organization.devices.getDevices'
});

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' }
  });
}

describe('createHttpClient', () => {
  it('returns parsed JSON with timing metadata', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(200, { ok: true }));
    const client = createHttpClient({ fetchImpl: fetchImpl as unknown as typeof fetch });

    const response = await client.request(request());
    expect(response.status).toBe(200);
    expect(response.data).toEqual({ ok: true });
    expect(response.attempts).toBe(1);
    expect(response.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('treats 204 as an empty body', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    const client = createHttpClient({ fetchImpl: fetchImpl as unknown as typeof fetch });
    const response = await client.request(request());
    expect(response.data).toBeUndefined();
  });

  it('wraps a non-JSON body rather than throwing', async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(new Response('plain words', { status: 200, headers: {} }));
    const client = createHttpClient({ fetchImpl: fetchImpl as unknown as typeof fetch });
    const response = await client.request(request());
    expect(response.data).toEqual({ raw: 'plain words' });
  });

  it('throws XyteHttpError on 4xx and does not retry', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(404, { error: 'nope' }));
    const client = createHttpClient({ fetchImpl: fetchImpl as unknown as typeof fetch });

    await expect(client.request(request())).rejects.toBeInstanceOf(XyteHttpError);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('retries a GET on 5xx and succeeds', async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(503, { error: 'busy' }))
      .mockResolvedValueOnce(jsonResponse(200, { ok: true }));
    const client = createHttpClient({
      fetchImpl: fetchImpl as unknown as typeof fetch,
      sleepImpl: async () => undefined
    });

    const response = await client.request(request());
    expect(response.data).toEqual({ ok: true });
    expect(response.attempts).toBe(2);
  });

  it('never retries a POST, so a side effect cannot be duplicated', async () => {
    const fetchImpl = vi.fn().mockImplementation(() => jsonResponse(503, { error: 'busy' }));
    const client = createHttpClient({
      fetchImpl: fetchImpl as unknown as typeof fetch,
      sleepImpl: async () => undefined
    });

    await expect(client.request(request('POST'))).rejects.toBeInstanceOf(XyteHttpError);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('gives up after the retry budget and reports the last error', async () => {
    // A fresh Response per call: a body can only be read once.
    const fetchImpl = vi.fn().mockImplementation(() => jsonResponse(500, { error: 'boom' }));
    const client = createHttpClient({
      fetchImpl: fetchImpl as unknown as typeof fetch,
      retryAttempts: 2,
      sleepImpl: async () => undefined
    });

    await expect(client.request(request())).rejects.toBeInstanceOf(XyteHttpError);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it('classifies a network failure', async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new TypeError('fetch failed'));
    const client = createHttpClient({
      fetchImpl: fetchImpl as unknown as typeof fetch,
      retryAttempts: 0
    });

    const error = await client.request(request()).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(XyteError);
    expect((error as XyteError).kind).toBe('network');
  });

  it('classifies a timeout when the request is aborted', async () => {
    const fetchImpl = vi.fn(
      (_url: string, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            reject(new DOMException('Aborted', 'AbortError'));
          });
        })
    );
    const client = createHttpClient({
      fetchImpl: fetchImpl as unknown as typeof fetch,
      timeoutMs: 10,
      retryAttempts: 0
    });

    const error = await client.request(request()).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(XyteError);
    expect((error as XyteError).kind).toBe('timeout');
  });
});
