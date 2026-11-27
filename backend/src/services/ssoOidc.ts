import * as oidc from 'openid-client';
import crypto from 'node:crypto';
import bcrypt from 'bcrypt';
import { getConfig } from '../config.js';
import { userRepository, roleRepository, ssoLoginCodeRepository } from '../database/index.js';
import { deriveSsoUsername, selectRolesForGroups } from '../utils/ssoHelpers.js';
import { logError } from '../utils/logger.js';
import type { SsoStatePayload } from '../utils/ssoState.js';

const SSO_PROVIDER_ID = 'oidc';
const MAX_USERNAME_LENGTH = 12;

export class SsoLoginError extends Error {
  constructor(
    // Stable machine-readable reason surfaced to the frontend via ?sso-error=.
    readonly reason: string,
    readonly status: number
  ) {
    super(`SSO login failed: ${reason}`);
  }
}

type OidcRuntime = {
  config: oidc.Configuration;
  sso: NonNullable<ReturnType<typeof getConfig>['sso']>;
};

let cachedRuntime: OidcRuntime | null = null;

function requireSsoConfig(): OidcRuntime['sso'] {
  const sso = getConfig().sso;
  if (!sso?.enabled) throw new SsoLoginError('sso_disabled', 404);
  return sso;
}

async function getRuntime(): Promise<OidcRuntime> {
  const sso = requireSsoConfig();
  cachedRuntime ??= {
    config: await oidc.discovery(new URL(sso.issuerUrl), sso.clientId, sso.clientSecret ?? undefined),
    sso,
  };
  return cachedRuntime;
}

function timingSafeEqualStrings(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

// Builds the redirect to the IdP's authorization endpoint (Authorization Code + PKCE).
// The returned values go into the signed state cookie; nothing sensitive travels in the URL.
export async function buildSsoLoginRedirect(
  redirectBase: string
): Promise<{ authorizeUrl: URL; state: string; nonce: string; verifier: string }> {
  const { config, sso } = await getRuntime();

  const state = oidc.randomState();
  const nonce = oidc.randomNonce();
  const verifier = oidc.randomPKCECodeVerifier();
  const challenge = await oidc.calculatePKCECodeChallenge(verifier);

  const parameters = new URLSearchParams({
    redirect_uri: `${redirectBase}/api/auth/sso/callback`,
    scope: sso.scopes,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });

  return { authorizeUrl: oidc.buildAuthorizationUrl(config, parameters), state, nonce, verifier };
}

function readGroupsClaim(claims: Record<string, unknown>, claimName: string): string[] {
  const raw = claims[claimName];
  if (Array.isArray(raw)) return raw.filter((item): item is string => typeof item === 'string');
  if (typeof raw === 'string' && raw.trim()) return [raw.trim()];
  return [];
}

async function uniqueSsoUsername(base: string): Promise<string> {
  if (!(await userRepository.findByUsername(base))) return base;

  for (let suffix = 2; suffix < 1000; suffix += 1) {
    const suffixText = String(suffix);
    const candidate = `${base.slice(0, MAX_USERNAME_LENGTH - suffixText.length - 1)}-${suffixText}`;
    if (!(await userRepository.findByUsername(candidate))) return candidate;
  }

  throw new SsoLoginError('unknown', 500);
}

// Replaces the user's SSO-managed role assignments with the ones implied by their IdP
// groups. Admin-managed assignments (roles without ssoGroups) are never touched.
async function syncSsoManagedRoles(userId: number, groups: string[]): Promise<void> {
  const allRoles = await roleRepository.list();
  const managed = allRoles.filter((role) => role.scope === 'global' && role.ssoGroups.length > 0);
  const selected = selectRolesForGroups(groups, managed);

  const currentIds = await roleRepository.listGlobalRoleIdsByUser(userId);
  const managedIds = new Set(managed.map((role) => role.id));
  const adminManagedIds = currentIds.filter((id) => !managedIds.has(id));
  const nextIds = [...adminManagedIds, ...selected.map((role) => role.id)];

  const currentSet = new Set(currentIds);
  const nextSet = new Set(nextIds);
  const unchanged =
    currentSet.size === nextSet.size && [...nextSet].every((id) => currentSet.has(id));
  if (unchanged) return;

  await roleRepository.setGlobalRoles(userId, nextIds);
}

export type SsoCallbackOutcome = { loginCode: string };

// Validates the callback (state/nonce/PKCE), resolves or provisions the user, resyncs
// SSO-managed roles, and mints a one-time login code for the frontend to exchange.
export async function completeSsoLogin(input: {
  query: URLSearchParams;
  statePayload: SsoStatePayload | null;
  redirectBase: string;
}): Promise<SsoCallbackOutcome> {
  const { config } = await getRuntime();

  if (!input.statePayload) throw new SsoLoginError('state_mismatch', 400);

  const queryState = input.query.get('state');
  if (!queryState || !timingSafeEqualStrings(input.statePayload.state, queryState)) {
    throw new SsoLoginError('state_mismatch', 400);
  }

  const currentUrl = new URL(
    `${input.redirectBase}/api/auth/sso/callback?${input.query.toString()}`
  );

  let tokens: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers;
  try {
    tokens = await oidc.authorizationCodeGrant(config, currentUrl, {
      expectedState: input.statePayload.state,
      expectedNonce: input.statePayload.nonce,
      pkceCodeVerifier: input.statePayload.verifier,
    });
  } catch (error) {
    logError('SSO:TOKEN_EXCHANGE', error);
    throw new SsoLoginError('token_exchange_failed', 401);
  }

  const claims = tokens.claims();
  if (!claims || typeof claims.sub !== 'string') {
    throw new SsoLoginError('token_exchange_failed', 401);
  }

  const subject = claims.sub;
  const email = typeof claims.email === 'string' ? claims.email : null;
  const preferredUsername =
    typeof claims.preferred_username === 'string' ? claims.preferred_username : null;
  const nickname = typeof claims.nickname === 'string' ? claims.nickname : null;

  let user = await userRepository.findBySsoIdentity(SSO_PROVIDER_ID, subject);
  let created = false;

  if (!user) {
    const sso = requireSsoConfig();
    if (!sso.autoProvision) throw new SsoLoginError('provisioning_disabled', 403);

    const username = await uniqueSsoUsername(
      deriveSsoUsername({ preferredUsername, nickname, email })
    );
    // SSO accounts never authenticate with a password; this hash is unusable garbage.
    const passwordHash = await bcrypt.hash(crypto.randomBytes(32).toString('base64url'), 10);
    const userId = await userRepository.createSsoUser({
      username,
      passwordHash,
      email,
      provider: SSO_PROVIDER_ID,
      subject,
    });
    if (!userId) throw new SsoLoginError('unknown', 500);

    user = await userRepository.findById(userId);
    created = true;
  }

  if (!user) throw new SsoLoginError('unknown', 500);
  if (!user.is_enabled) throw new SsoLoginError('account_disabled', 403);

  if (!created) {
    await userRepository.touchSsoLogin(user.id, email);
  }

  const groups = readGroupsClaim(claims as Record<string, unknown>, requireSsoConfig().groupsClaim);
  await syncSsoManagedRoles(user.id, groups);

  const loginCode = await ssoLoginCodeRepository.issue(user.id);
  return { loginCode };
}
