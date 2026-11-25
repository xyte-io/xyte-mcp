/**
 * Secret hygiene for everything that leaves this process.
 *
 * Two independent passes, because either alone leaks:
 *  - by key name, so `{ api_key: "..." }` in a response body is masked;
 *  - by literal value, so a configured credential can never be echoed back
 *    even if it turns up somewhere we did not anticipate.
 */

export const REDACTED = '[redacted]';

const SENSITIVE_KEY = /^(authorization|api[_-]?key|x[_-]api[_-]key|token|access[_-]?token|refresh[_-]?token|password|passwd|secret|client[_-]?secret|private[_-]?key)$/i;

/** Replace every occurrence of each known secret with a placeholder. */
export function redactText(text: string, secrets: readonly string[]): string {
  let output = text;
  for (const secret of secrets) {
    // Short strings would match far too much; a real key is never this short.
    if (!secret || secret.length < 8) continue;
    output = output.split(secret).join(REDACTED);
  }
  return output;
}

/**
 * Deep-copy `value`, masking sensitive object keys and any literal secret.
 * Cycles are replaced with `[circular]` so this is always safe to stringify.
 */
export function redactValue(value: unknown, secrets: readonly string[]): unknown {
  return walk(value, secrets, new WeakSet());
}

function walk(value: unknown, secrets: readonly string[], seen: WeakSet<object>): unknown {
  if (typeof value === 'string') return redactText(value, secrets);
  if (value === null || typeof value !== 'object') {
    return typeof value === 'bigint' ? value.toString() : value;
  }

  if (seen.has(value)) return '[circular]';
  seen.add(value);

  if (Array.isArray(value)) {
    return value.map((item) => walk(item, secrets, seen));
  }

  const output: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    output[key] = SENSITIVE_KEY.test(key) ? REDACTED : walk(item, secrets, seen);
  }
  return output;
}
