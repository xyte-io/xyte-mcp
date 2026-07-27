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
  | 'network'
  | 'timeout';

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
    readonly endpointKey: string
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
