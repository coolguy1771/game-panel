import type { Role } from '../database/repositories/roleRepository.js';

const MAX_USERNAME_LENGTH = 12;

function sanitizeUsernameCandidate(candidate: string): string {
  const cleaned = candidate.trim().replace(/\s+/g, '-');
  if (!cleaned) return '';
  return cleaned.slice(0, MAX_USERNAME_LENGTH);
}

// Derives a panel username from OIDC claims, following the claim precedence
// preferred_username → nickname → email local-part. Panel usernames are limited to 12
// characters (same rule as local accounts); collisions are resolved by the caller.
export function deriveSsoUsername(claims: {
  preferredUsername?: string | null;
  nickname?: string | null;
  email?: string | null;
}): string {
  const candidates = [
    claims.preferredUsername,
    claims.nickname,
    claims.email ? claims.email.split('@')[0] : null,
  ];

  for (const candidate of candidates) {
    if (!candidate) continue;
    const sanitized = sanitizeUsernameCandidate(candidate);
    if (sanitized) return sanitized;
  }

  return 'user';
}

// SSO-managed roles are those with a non-empty ssoGroups list: the user holds exactly the
// ones whose IdP groups intersect theirs (union semantics, recomputed at every login).
export function selectRolesForGroups<
  T extends Pick<Role, 'id' | 'ssoGroups'>
>(groups: string[], roles: T[]): T[] {
  const userGroups = new Set(groups);
  return roles.filter((role) => role.ssoGroups.some((group) => userGroups.has(group)));
}
