import jwt from 'jsonwebtoken';
import { getConfig } from '../config.js';

// Signed, short-lived payload for the OIDC state cookie. It binds the browser's callback to
// the login attempt: state (CSRF), nonce (replay), and the PKCE code verifier. Signed with
// the same secret as session tokens, so no extra key management.
export type SsoStatePayload = {
  state: string;
  nonce: string;
  verifier: string;
};

const STATE_PURPOSE = 'sso-state';
const DEFAULT_TTL_MS = 10 * 60_000;

export function signSsoState(payload: SsoStatePayload): string {
  // No `expiresIn`: expiry is checked against `iat` in verifySsoState so tests can inject a
  // clock (jsonwebtoken only supports second-granularity expiresIn). The purpose claim
  // prevents a state token from ever being replayed as (or built from) a session token.
  return jwt.sign({ ...payload, purpose: STATE_PURPOSE }, getConfig().jwtSecret, {
    algorithm: 'HS256',
  });
}

export function verifySsoState(
  token: string,
  ttlMs: number = DEFAULT_TTL_MS,
  nowMs: number = Date.now()
): SsoStatePayload | null {
  try {
    const decoded = jwt.verify(token, getConfig().jwtSecret, { algorithms: ['HS256'] });
    if (typeof decoded !== 'object' || decoded === null) return null;

    const { state, nonce, verifier, iat, purpose } = decoded as Record<string, unknown>;
    if (purpose !== STATE_PURPOSE) return null;
    if (typeof state !== 'string' || typeof nonce !== 'string' || typeof verifier !== 'string') {
      return null;
    }
    if (typeof iat !== 'number' || iat * 1000 + ttlMs <= nowMs) {
      return null;
    }

    return { state, nonce, verifier };
  } catch {
    return null;
  }
}
