/**
 * One JSON line on stderr per operational event (tool_call, sign_in,
 * hub_refresh, revoke), for log queries and alerts — see OPERATIONS.md.
 * No `[xyte-mcp]` prefix, so the line parses as JSON on its own.
 *
 * Ids, outcomes and numbers only: never a token, a body, an email or a tool
 * argument. Undefined fields are left out.
 */
export function logEvent(
  event: string,
  fields: Record<string, string | number | boolean | undefined>
): void {
  process.stderr.write(`${JSON.stringify({ event, ...fields })}\n`);
}
