/**
 * Error taxonomy. Every one of these is turned into an `isError` tool result
 * rather than a JSON-RPC protocol error, so the model can read the reason and
 * correct itself.
 */

export type ErrorKind =
  | 'config'
  | 'validation'
  | 'write-blocked'
  | 'unknown-endpoint'
  | 'http'
  /** The hub sign-in behind an OAuth grant is gone; the client has to reconnect. */
  | 'auth'
  | 'network'
  | 'timeout';

/** Hub paused the OAuth application: temporary, and the sign-in is kept (403 `application_paused`). */
export const APPLICATION_PAUSED_HINT =
  'This connection is temporarily paused. You are still signed in, so there is no need to reconnect. Try again later.';

export class XyteError extends Error {
  constructor(
    readonly kind: ErrorKind,
    message: string,
    /** Commands or arguments that would resolve this, shown to the model. */
    readonly hints: readonly string[] = []
  ) {
    super(message);
    this.name = 'XyteError';
  }
}

export class XyteHttpError extends XyteError {
  constructor(
    readonly status: number,
    readonly statusText: string,
    readonly body: unknown,
    readonly endpointKey: string,
    /** RFC 6750 3: hub sets it only when it rejects the bearer token itself. */
    readonly wwwAuthenticate?: string
  ) {
    super('http', `${status} ${statusText} from ${endpointKey}`);
    this.name = 'XyteHttpError';
  }

  /** 5xx and 408 are worth another attempt; 4xx are the caller's problem. */
  get retriable(): boolean {
    return this.status >= 500 || this.status === 408;
  }
}

export function isXyteError(error: unknown): error is XyteError {
  return error instanceof XyteError;
}
