import { createServer, type IncomingHttpHeaders } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, expect, it, vi } from 'vitest';
import { RATE_BUCKET_SECRET_HEADER, withRateBucketSecret } from '../src/hub-fetch.js';

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

  it.each(['http://127.0.0.1:4101/x', 'http://localhost:4100/x', 'https://example.com/x'])(
    'passes a request to another origin (%s) through untouched',
    async (url) => {
      const fetchImpl = stubFetch();
      const init = { method: 'GET', headers: { Accept: 'application/json' } };
      await withRateBucketSecret(HUB, SECRET, fetchImpl)(url, init);
      expect(fetchImpl).toHaveBeenCalledWith(url, init);
    }
  );

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
      const hubUrl = `http://127.0.0.1:${(hub.address() as AddressInfo).port}`;
      const response = await withRateBucketSecret(hubUrl, SECRET)(`${hubUrl}/oauth/token`, { method: 'POST' });
      expect(response.status).toBe(302);
      // Not followed at all, so the other server never sees the request (or the secret).
      expect(received).toEqual([]);
    } finally {
      await new Promise<void>((resolve) => hub.close(() => resolve()));
      await new Promise<void>((resolve) => other.close(() => resolve()));
    }
  });
});
