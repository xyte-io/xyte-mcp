import { XyteError } from '../http/errors.js';
import { logError } from '../log.js';

/**
 * xyte-mcp as a confidential client of hub's own OAuth 2 server
 * (`/oauth/authorize`, `/oauth/token`, `/oauth/revoke`): authorization code
 * with S256 PKCE, `client_secret_basic`, exact-match redirect URI.
 *
 * Hub refresh tokens are single-use and rotate, and replaying one more than
 * 60 s after its use revokes the user's whole sign-in on that organization —
 * so every token POST here is sent exactly once, never retried.
 */

/** Requesting `openid` is what makes hub return an id_token naming user + org. */
const SCOPE = 'openid email profile';

export interface HubTokens {
  accessToken: string;
  refreshToken: string;
  /** Seconds since epoch. */
  expiresAt: number;
}

/** A completed hub sign-in: the tokens plus who signed in, for which organization. */
export interface HubSignIn extends HubTokens {
  sub: string;
  tenantId: string;
  email?: string;
}

export type HubOAuth = ReturnType<typeof createHubOAuth>;

export function createHubOAuth(options: {
  hubUrl: string;
  clientId: string;
  clientSecret: string;
  /** e.g. https://<this server>/oauth/callback — registered verbatim at hub. */
  redirectUri: string;
  timeoutMs: number;
  fetchImpl?: typeof fetch;
}) {
  const { hubUrl, clientId, clientSecret, redirectUri, timeoutMs } = options;
  const fetchImpl = options.fetchImpl ?? fetch;
  // RFC 6749 2.3.1: each half is form-encoded before the join.
  const basic = `Basic ${Buffer.from(
    `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`
  ).toString('base64')}`;

  /** One POST, no retry. Network failure and timeout surface as XyteErrors. */
  async function post(path: string, form: Record<string, string>): Promise<Response> {
    try {
      return await fetchImpl(`${hubUrl}${path}`, {
        method: 'POST',
        headers: {
          Authorization: basic,
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json'
        },
        body: new URLSearchParams(form),
        signal: AbortSignal.timeout(timeoutMs)
      });
    } catch (error) {
      const timedOut = error instanceof Error && error.name === 'TimeoutError';
      throw new XyteError(
        timedOut ? 'timeout' : 'network',
        timedOut ? `hub ${path} timed out after ${timeoutMs}ms` : `hub ${path} unreachable`
      );
    }
  }

  async function tokens(response: Response): Promise<HubTokens & { idToken?: string }> {
    const body = (await response.json()) as Record<string, unknown>;
    const { access_token, refresh_token, expires_in, id_token } = body;
    if (typeof access_token !== 'string' || typeof refresh_token !== 'string') {
      throw new Error('hub token response has no access/refresh token');
    }
    return {
      accessToken: access_token,
      refreshToken: refresh_token,
      expiresAt: nowSeconds() + (typeof expires_in === 'number' ? expires_in : 3600),
      ...(typeof id_token === 'string' ? { idToken: id_token } : {})
    };
  }

  return {
    authorizeUrl(params: { state: string; codeChallenge: string }): string {
      const url = new URL(`${hubUrl}/oauth/authorize`);
      url.search = new URLSearchParams({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: SCOPE,
        state: params.state,
        code_challenge: params.codeChallenge,
        code_challenge_method: 'S256'
      }).toString();
      return url.toString();
    },

    async exchangeCode(code: string, codeVerifier: string): Promise<HubSignIn> {
      const response = await post('/oauth/token', {
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier
      });
      if (!response.ok) {
        throw new Error(`hub code exchange failed: ${response.status} ${await errorOf(response)}`);
      }
      const { idToken, ...rest } = await tokens(response);
      if (!idToken) throw new Error('hub token response has no id_token');
      // Straight from hub's token endpoint over TLS, so the payload is read
      // without a JWKS check (OIDC Core 3.1.3.7 allows this for the code flow).
      const claims = JSON.parse(
        Buffer.from(idToken.split('.')[1] ?? '', 'base64url').toString('utf8')
      ) as Record<string, unknown>;
      const { sub, xyte_tenant_id, email } = claims;
      if (typeof sub !== 'string' || typeof xyte_tenant_id !== 'string') {
        throw new Error('hub id_token has no sub / xyte_tenant_id');
      }
      return { ...rest, sub, tenantId: xyte_tenant_id, ...(typeof email === 'string' ? { email } : {}) };
    },

    /**
     * `invalid_grant` is the one answer that means the chain is dead (or was
     * already rotated by someone else); everything else throws. A 4xx throws as
     * 'auth' (nothing rotated); a timeout, network error or 5xx leaves it
     * unknown whether hub rotated — the caller must not send the token again.
     */
    async refresh(refreshToken: string): Promise<HubTokens | 'invalid_grant'> {
      const response = await post('/oauth/token', {
        grant_type: 'refresh_token',
        refresh_token: refreshToken
      });
      if (response.ok) {
        // The id_token names the same user + org as at sign-in; nothing to update.
        const { accessToken, refreshToken: next, expiresAt } = await tokens(response);
        return { accessToken, refreshToken: next, expiresAt };
      }
      const error = await errorOf(response);
      if (response.status === 400 && error === 'invalid_grant') return 'invalid_grant';
      throw new XyteError(
        response.status >= 500 ? 'network' : 'auth',
        `hub token refresh failed: ${response.status} ${error}`
      );
    },

    /** Best effort: a failure is logged, never surfaced to the disconnecting client. */
    async revoke(refreshToken: string): Promise<void> {
      try {
        const response = await post('/oauth/revoke', {
          token: refreshToken,
          token_type_hint: 'refresh_token'
        });
        if (!response.ok) logError(`hub revoke failed: ${response.status} ${await errorOf(response)}`);
      } catch (error) {
        logError(`hub revoke failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  };
}

/** The RFC 6749 5.2 `error` code only — never the body, which could echo a credential. */
async function errorOf(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { error?: unknown };
    return typeof body.error === 'string' ? body.error : '';
  } catch {
    return '';
  }
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
