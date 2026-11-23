/** Hub counts every request carrying the shared secret in one rate bucket for this server. */
export const RATE_BUCKET_SECRET_HEADER = 'X-MCP-Rate-Bucket-Secret';

/**
 * A fetch that adds the rate bucket secret to requests for the hub's origin
 * only. Those requests do not follow redirects: Node's fetch keeps custom
 * headers on a cross-origin redirect, and the hub API and its OAuth
 * token/revoke endpoints never redirect. Callers pass string URLs.
 */
export function withRateBucketSecret(
  hubUrl: string,
  secret: string | undefined,
  fetchImpl: typeof fetch = fetch
): typeof fetch {
  if (!secret) return fetchImpl;
  const hubOrigin = new URL(hubUrl).origin;
  return (input, init) => {
    if (new URL(String(input)).origin !== hubOrigin) return fetchImpl(input, init);
    const headers = new Headers(init?.headers);
    headers.set(RATE_BUCKET_SECRET_HEADER, secret);
    return fetchImpl(input, { ...init, headers, redirect: 'manual' });
  };
}
