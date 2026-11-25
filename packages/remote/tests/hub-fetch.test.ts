import { createServer, type IncomingHttpHeaders } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, expect, it, vi } from 'vitest';
import { createHttpClient } from '@xyteai/mcp/http/client.js';
import { XyteError, XyteHttpError } from '@xyteai/mcp/http/errors.js';
import { RATE_BUCKET_SECRET_HEADER, withRateBucketSecret } from '../src/hub-fetch.js';
import { createHubOAuth, HubRefreshError } from '../src/oauth/hub-oauth.js';

const HUB = 'http://127.0.0.1:4100';
const SECRET = 'bucket-secret-123';

function stubFetch() {
  return vi.fn<typeof fetch>(async () => new Response('{}'));
}

/** The headers and redirect mode of the stub's only call. */
function sent(fetchImpl: ReturnType<typeof stubFetch>) {
  const [, init] = fetchImpl.mock.calls[0]!;
  return { headers: new Headers(init?.headers), redirect: init?.redirect };
}

describe('withRateBucketSecret', () => {
  it('sends the secret header to the hub origin, without following redirects', async () => {
    const fetchImpl = stubFetch();
    await withRateBucketSecret(HUB, SECRET, fetchImpl)(`${HUB}/core/v1/organization/devices`);
    const { headers, redirect } = sent(fetchImpl);
    expect(headers.get(RATE_BUCKET_SECRET_HEADER)).toBe(SECRET);
    expect(redirect).toBe('manual');
  });

  it('returns the fetch unchanged when no secret is configured', () => {
    const fetchImpl = stubFetch();
    expect(withRateBucketSecret(HUB, undefined, fetchImpl)).toBe(fetchImpl);
  });

  it.each([
    'http://127.0.0.1:4101/x',
    'http://localhost:4100/x',
    'https://127.0.0.1:4100/x',
    'https://example.com/x'
  ])(
    'passes a request to another origin (%s) through untouched',
    async (url) => {
      const fetchImpl = stubFetch();
      const init = { method: 'GET', headers: { Accept: 'application/json' } };
      await withRateBucketSecret(HUB, SECRET, fetchImpl)(url, init);
      expect(fetchImpl).toHaveBeenCalledWith(url, init);
    }
  );

  it('matches the hub origin with its default port spelled out', async () => {
    const fetchImpl = stubFetch();
    await withRateBucketSecret('https://hub.example:443/base', SECRET, fetchImpl)(
      'https://hub.example/core/v1/organization/devices'
    );
    expect(sent(fetchImpl).headers.get(RATE_BUCKET_SECRET_HEADER)).toBe(SECRET);
  });

  it('refuses a malformed hub URL as a config error naming XYTE_HUB_URL', () => {
    let error: unknown;
    try {
      withRateBucketSecret('not a url', SECRET, stubFetch());
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(XyteError);
    expect((error as XyteError).kind).toBe('config');
    expect((error as XyteError).message).toContain('XYTE_HUB_URL');
    expect((error as XyteError).message).not.toContain(SECRET);
  });

  it('keeps the caller headers and the rest of the init', async () => {
    const fetchImpl = stubFetch();
    await withRateBucketSecret(`${HUB}/`, SECRET, fetchImpl)(`${HUB}/oauth/token`, {
      method: 'POST',
      headers: { Authorization: 'Basic abc', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'a=b'
    });
    const [, init] = fetchImpl.mock.calls[0]!;
    const { headers } = sent(fetchImpl);
    expect(init?.method).toBe('POST');
    expect(init?.body).toBe('a=b');
    expect(headers.get('authorization')).toBe('Basic abc');
    expect(headers.get('content-type')).toBe('application/x-www-form-urlencoded');
    expect(headers.get(RATE_BUCKET_SECRET_HEADER)).toBe(SECRET);
  });

  // Node's fetch keeps custom headers on a cross-origin redirect; hub never redirects these calls.
  it('never carries the secret across a hub redirect', async () => {
    const received = await withRedirectingHub(async (hubUrl) => {
      const response = await withRateBucketSecret(hubUrl, SECRET)(`${hubUrl}/oauth/token`, { method: 'POST' });
      expect(response.status).toBe(302);
    });
    // Not followed at all, so the other server never sees the request (or the secret).
    expect(received).toEqual([]);
  });

  it('turns a hub redirect into an HTTP error for an API call, without the secret in it', async () => {
    const received = await withRedirectingHub(async (hubUrl) => {
      const http = createHttpClient({ fetchImpl: withRateBucketSecret(hubUrl, SECRET) });
      const error: unknown = await http
        .request({ method: 'GET', url: `${hubUrl}/core/v1/organization/devices`, headers: {}, endpointKey: 'k' })
        .then(() => undefined, (rejection: unknown) => rejection);
      expect(error).toBeInstanceOf(XyteHttpError);
      expect((error as XyteHttpError).status).toBe(302);
      expect(JSON.stringify([(error as XyteHttpError).message, (error as XyteHttpError).body])).not.toContain(SECRET);
    });
    expect(received).toEqual([]);
  });

  it('turns a hub redirect on the OAuth calls into a rejection, without the secret in it', async () => {
    const received = await withRedirectingHub(async (hubUrl) => {
      const hubOAuth = createHubOAuth({
        hubUrl,
        clientId: 'mcp-client',
        clientSecret: 'mcp-secret',
        redirectUri: 'https://mcp.example/oauth/callback',
        timeoutMs: 5_000,
        fetchImpl: withRateBucketSecret(hubUrl, SECRET)
      });
      const refreshError: unknown = await hubOAuth.refresh('xort_1').then(
        (result) => result,
        (rejection: unknown) => rejection
      );
      // Not invalid_grant: a 4xx 'auth' rejection, so the provider keeps the grant.
      expect(refreshError).toBeInstanceOf(HubRefreshError);
      expect((refreshError as HubRefreshError).status).toBe(302);
      expect((refreshError as HubRefreshError).kind).toBe('auth');
      expect((refreshError as HubRefreshError).message).not.toContain(SECRET);

      const exchangeError: unknown = await hubOAuth.exchangeCode('code', 'verifier').then(
        () => undefined,
        (rejection: unknown) => rejection
      );
      expect(exchangeError).toBeInstanceOf(Error);
      expect((exchangeError as Error).message).toContain('302');
      expect((exchangeError as Error).message).not.toContain(SECRET);
    });
    expect(received).toEqual([]);
  });
});

/** Runs `use` against a hub that 302s everything to a second server; returns what that server received. */
async function withRedirectingHub(use: (hubUrl: string) => Promise<void>): Promise<IncomingHttpHeaders[]> {
  const received: IncomingHttpHeaders[] = [];
  const other = createServer((req, res) => {
    received.push(req.headers);
    res.end('elsewhere');
  });
  const hub = createServer((_req, res) => {
    res.writeHead(302, { Location: `http://127.0.0.1:${(other.address() as AddressInfo).port}/landing` });
    res.end();
  });
  await new Promise<void>((resolve) => other.listen(0, '127.0.0.1', resolve));
  await new Promise<void>((resolve) => hub.listen(0, '127.0.0.1', resolve));
  try {
    await use(`http://127.0.0.1:${(hub.address() as AddressInfo).port}`);
  } finally {
    await new Promise<void>((resolve) => hub.close(() => resolve()));
    await new Promise<void>((resolve) => other.close(() => resolve()));
  }
  return received;
}
