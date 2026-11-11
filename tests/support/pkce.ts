import { createHash } from 'node:crypto';

/** Hub's code_verifier rule (lib/oauth/token_request.rb) plus the S256 match. */
export function hubAcceptsPkce(verifier: string | null, challenge: string | undefined): boolean {
  return (
    /^[A-Za-z0-9._~-]{43,128}$/.test(verifier ?? '') &&
    createHash('sha256').update(verifier!).digest('base64url') === challenge
  );
}
