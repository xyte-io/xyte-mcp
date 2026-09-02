import type { HubUserCredential } from '../config.js';
import { log, logError } from '../log.js';

/**
 * Login delegation: the consent page's credentials are checked against the hub
 * itself via devise_token_auth's `POST /auth/sign_in`. A success returns the
 * token triplet from the response headers — that becomes the grant's stored
 * hub credential — plus the user's last-used tenant from the body, so calls
 * land on the organization they actually work in.
 *
 * A wrong password is `undefined`, not an exception: the login form retries.
 * Anything else (hub down, unexpected shape) throws, because telling a user
 * "wrong password" when the hub is unreachable would send them to reset it.
 */
export function createHubSignIn(
  hubUrl: string,
  fetchImpl: typeof fetch = fetch
): (email: string, password: string) => Promise<HubUserCredential | undefined> {
  return async (email, password) => {
    const response = await fetchImpl(`${hubUrl}/auth/sign_in`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ email, password })
    });

    if (response.status === 401) {
      log(`hub sign-in refused for ${redactEmail(email)}`);
      return undefined;
    }
    if (!response.ok) {
      logError(`hub sign-in failed: ${response.status} ${response.statusText}`);
      throw new Error(`hub sign-in failed with status ${response.status}`);
    }

    const accessToken = response.headers.get('access-token');
    const client = response.headers.get('client');
    const uid = response.headers.get('uid');
    if (!accessToken || !client || !uid) {
      throw new Error('hub sign-in succeeded but returned no token headers');
    }

    return { accessToken, client, uid, ...(await tenantOf(response)) };
  };
}

/** Best-effort: a missing tenant just falls back to hub-side resolution. */
async function tenantOf(response: Response): Promise<{ tenant?: string }> {
  try {
    const body = (await response.json()) as { data?: { last_tenant_id?: unknown } };
    const tenant = body.data?.last_tenant_id;
    return typeof tenant === 'string' && tenant ? { tenant } : {};
  } catch {
    return {};
  }
}

/** Enough to correlate log lines, not enough to be an address book. */
function redactEmail(email: string): string {
  const [user, domain] = email.split('@');
  return `${(user ?? '').slice(0, 2)}…@${domain ?? '?'}`;
}
