import { describe, expect, it } from 'vitest';
import { signSsoState, verifySsoState } from './ssoState.js';

const payload = { state: 'state-1', nonce: 'nonce-1', verifier: 'verifier-1' };

describe('sso state cookie token', () => {
  it('round-trips state, nonce and PKCE verifier', () => {
    const token = signSsoState(payload);
    expect(verifySsoState(token)).toEqual(payload);
  });

  it('rejects a tampered token', () => {
    const token = signSsoState(payload);
    const [head, body] = token.split('.');
    const tampered = `${head}.${Buffer.from(JSON.stringify({ ...payload, state: 'evil' })).toString('base64url')}.x`;

    expect(tampered).not.toEqual(token);
    expect(body.length).toBeGreaterThan(0);
    expect(verifySsoState(tampered)).toBeNull();
  });

  it('rejects an expired token', () => {
    const token = signSsoState(payload);
    const tenMinutesMs = 10 * 60_000;

    expect(verifySsoState(token, tenMinutesMs, Date.now())).toEqual(payload);
    expect(verifySsoState(token, tenMinutesMs, Date.now() + tenMinutesMs + 1)).toBeNull();
  });

  it('rejects garbage', () => {
    expect(verifySsoState('not-a-jwt')).toBeNull();
  });
});
