import { ENV } from '../config.js';
import { XyteError } from './errors.js';
import type { EndpointSpec } from '../catalog/types.js';
import type { ToolContext } from '../context.js';
import type { HttpRequest } from './client.js';

export type PathArgs = Record<string, string | number>;
export type QueryArgs = Record<string, string | number | boolean>;

export interface CallArgs {
  path?: PathArgs;
  query?: QueryArgs;
  body?: unknown;
}

const KEY_ENV_BY_SCOPE = {
  organization: ENV.orgKey,
  partner: ENV.partnerKey
} as const;

/**
 * Turn an endpoint spec plus caller arguments into a concrete request.
 *
 * Arguments are validated against the spec here rather than being forwarded
 * blindly, so a typo comes back as a precise message instead of a hub 4xx.
 */
export function buildRequest(
  endpoint: EndpointSpec,
  args: CallArgs,
  context: ToolContext
): HttpRequest {
  const credential = context.credentials[endpoint.authScope];
  if (!credential) {
    throw new XyteError(
      'config',
      `${endpoint.key} needs a ${endpoint.authScope} API key, which is not configured.`,
      [`Set ${KEY_ENV_BY_SCOPE[endpoint.authScope]} in the server environment and restart.`]
    );
  }

  const pathArgs = args.path ?? {};
  const queryArgs = args.query ?? {};

  const missing = endpoint.pathParams.filter((name) => !(name in pathArgs));
  if (missing.length) {
    throw new XyteError(
      'validation',
      `${endpoint.key} is missing required path parameter(s): ${missing.join(', ')}`,
      [`Required: ${endpoint.pathParams.join(', ') || '(none)'}`]
    );
  }

  const unexpectedPath = Object.keys(pathArgs).filter(
    (name) => !endpoint.pathParams.includes(name)
  );
  if (unexpectedPath.length) {
    throw new XyteError(
      'validation',
      `${endpoint.key} does not accept path parameter(s): ${unexpectedPath.join(', ')}`,
      [`Accepted: ${endpoint.pathParams.join(', ') || '(none)'}`]
    );
  }

  const unexpectedQuery = Object.keys(queryArgs).filter(
    (name) => !endpoint.queryParams.includes(name)
  );
  if (unexpectedQuery.length) {
    throw new XyteError(
      'validation',
      `${endpoint.key} does not accept query parameter(s): ${unexpectedQuery.join(', ')}`,
      [`Accepted: ${endpoint.queryParams.join(', ') || '(none)'}`]
    );
  }

  const sendsBody = !['GET', 'HEAD'].includes(endpoint.method);
  if (args.body !== undefined && !sendsBody) {
    throw new XyteError(
      'validation',
      `${endpoint.key} is a ${endpoint.method} and does not take a request body.`,
      ['Use query parameters instead.']
    );
  }

  const url = new URL(`${context.baseUrls[endpoint.base]}${substitutePath(endpoint, pathArgs)}`);
  for (const [name, value] of Object.entries(queryArgs)) {
    if (value === undefined || value === null) continue;
    url.searchParams.set(name, String(value));
  }

  const hasBody = sendsBody && args.body !== undefined;

  return {
    method: endpoint.method,
    url: url.toString(),
    headers: {
      Accept: 'application/json',
      // The hub expects the bare key — no "Bearer" scheme.
      Authorization: credential,
      ...(hasBody ? { 'Content-Type': 'application/json' } : {})
    },
    ...(hasBody ? { body: JSON.stringify(args.body) } : {}),
    endpointKey: endpoint.key
  };
}

function substitutePath(endpoint: EndpointSpec, pathArgs: PathArgs): string {
  return endpoint.pathTemplate.replace(/:(\w+)/g, (_match, name: string) => {
    const value = pathArgs[name];
    const text = String(value).trim();
    if (!text) {
      throw new XyteError(
        'validation',
        `${endpoint.key}: path parameter "${name}" is empty.`
      );
    }
    return encodeURIComponent(text);
  });
}
