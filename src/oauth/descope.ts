import { log, logError } from '../log.js';
import type { HubUserCredential } from '../config.js';

/**
 * Login delegation via Descope's OIDC federated app: `/authorize` redirects
 * the browser to Descope's hosted flow (the same "Sign Up or In" flow the
 * portal uses), and the callback exchanges the returned code for a Descope
 * session JWT, which hub's own `POST /auth/descope/login` swaps for a devise
 * token triplet. We never see a password; MFA/SSO stay Descope's problem.
 *
 * The OIDC app is a public client (no secret): both legs are secured with
 * PKCE — ours toward Descope here, and the MCP client's toward us in the
 * provider.
 */
export interface DescopeLogin {
  /** Where to send the user's browser from /authorize. */
  authorizeRedirect(params: { state: string; codeChallenge: string }): string;
  /** Callback leg: code -> Descope JWT -> hub devise triplet. undefined = hub refused the user. */
  exchange(code: string, codeVerifier: string): Promise<HubUserCredential | undefined>;
}

export interface DescopeOptions {
  projectId: string;
  /** e.g. https://auth.xyte.io */
  baseUrl: string;
  /** e.g. https://<this server>/oauth/callback */
  callbackUrl: string;
  hubUrl: string;
  fetchImpl?: typeof fetch;
}

export function createDescopeLogin(options: DescopeOptions): DescopeLogin {
  const { projectId, baseUrl, callbackUrl, hubUrl } = options;
  const fetchImpl = options.fetchImpl ?? fetch;
  // Descope quirk: a public OIDC client's client_id is the base64 of the project id.
  const clientId = Buffer.from(projectId, 'utf8').toString('base64');
  const oauthBase = `${baseUrl}/oauth2/v1/${projectId}`;

  return {
    authorizeRedirect({ state, codeChallenge }) {
      const url = new URL(`${oauthBase}/authorize`);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('client_id', clientId);
      url.searchParams.set('redirect_uri', callbackUrl);
      url.searchParams.set('scope', 'openid email');
      url.searchParams.set('state', state);
      url.searchParams.set('code_challenge', codeChallenge);
      url.searchParams.set('code_challenge_method', 'S256');
      return url.toString();
    },

    async exchange(code, codeVerifier) {
      const response = await fetchImpl(`${oauthBase}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: clientId,
          code,
          code_verifier: codeVerifier,
          redirect_uri: callbackUrl
        })
      });
      if (!response.ok) {
        logError(`descope token exchange failed: ${response.status} ${await safeBody(response)}`);
        throw new Error(`Descope token exchange failed with status ${response.status}`);
      }
      const tokens = (await response.json()) as { access_token?: string; id_token?: string };

      // Hub validates via Descope's /v1/auth/validate, which wants a session
      // JWT. The access_token should be one; the id_token is the fallback.
      const candidates = [tokens.access_token, tokens.id_token].filter(
        (value): value is string => typeof value === 'string' && value.length > 0
      );
      if (!candidates.length) throw new Error('Descope token exchange returned no tokens');

      for (const candidate of candidates) {
        const hub = await hubDescopeLogin(hubUrl, candidate, fetchImpl);
        if (hub) return hub;
      }
      return undefined;
    }
  };
}

/** Swap a Descope JWT for hub's devise token triplet. undefined on a 401. */
async function hubDescopeLogin(
  hubUrl: string,
  descopeToken: string,
  fetchImpl: typeof fetch
): Promise<HubUserCredential | undefined> {
  const response = await fetchImpl(`${hubUrl}/auth/descope/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      // Hub resolves the partner from HTTP_ORIGIN and falls back to the Xyte
      // partner without it; sending the hub's own origin keeps that explicit.
      Origin: hubUrl
    },
    body: JSON.stringify({ token: descopeToken, tenant_type: 'organization' })
  });

  if (response.status === 401) {
    log('hub descope login refused the token');
    return undefined;
  }
  if (!response.ok) {
    logError(`hub descope login failed: ${response.status} ${await safeBody(response)}`);
    throw new Error(`hub descope login failed with status ${response.status}`);
  }

  const body = (await response.json()) as {
    token?: string;
    client?: string;
    uid?: string;
    tenant?: { id?: string } | null;
  };
  if (!body.token || !body.client || !body.uid) {
    throw new Error('hub descope login succeeded but returned no token triplet');
  }
  return {
    accessToken: body.token,
    client: body.client,
    uid: body.uid,
    ...(body.tenant?.id ? { tenant: body.tenant.id } : {})
  };
}

async function safeBody(response: Response): Promise<string> {
  try {
    return (await response.text()).slice(0, 300);
  } catch {
    return '<unreadable>';
  }
}
