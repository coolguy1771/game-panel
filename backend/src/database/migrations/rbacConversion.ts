import { SYSTEM_ROLE_KEYS, SYSTEM_ROLES, type RoleScope } from '../systemRoles.js';

export type ParsedUserRow = {
  id: number;
  isRoot: boolean;
  globalPermissions: string[];
};

export type ParsedMembershipRow = {
  serverId: number;
  userId: number;
  permissions: string[];
};

export type PlannedRole = {
  key: string;
  name: string;
  scope: RoleScope;
  permissions: string[];
  isSystem: boolean;
};

export type RbacConversionPlan = {
  roles: PlannedRole[];
  userRoleAssignments: Array<{ userId: number; roleKey: string }>;
  memberRoleAssignments: Array<{ serverId: number; userId: number; roleKey: string }>;
};

function signatureOf(permissions: string[]): string {
  const unique = Array.from(new Set(permissions)).filter((p) => typeof p === 'string' && p.length > 0);
  if (unique.length === 0) return '';
  return unique.sort().join('\u0000');
}

function systemRoleKeyByName(name: string): string {
  switch (name) {
    case 'Administrator': return SYSTEM_ROLE_KEYS.administrator;
    case 'Viewer': return SYSTEM_ROLE_KEYS.viewer;
    case 'Operator': return SYSTEM_ROLE_KEYS.operator;
    case 'Full access': return SYSTEM_ROLE_KEYS.fullAccess;
    default: throw new Error(`Unknown system role: ${name}`);
  }
}

// Converts legacy per-user/per-membership permission lists into a role plan. Only roles that
// are actually needed are planned. Exact matches to the seeded system roles reuse them;
// everything else becomes a deterministic "Imported ..." role shared by every row with the
// same permission set. Imported roles are numbered in sorted-signature order so the plan does
// not depend on input row order.
export function planRbacConversion(
  users: ParsedUserRow[],
  memberships: ParsedMembershipRow[]
): RbacConversionPlan {
  const rolesByKey = new Map<string, PlannedRole>();
  const keyByGlobalSignature = new Map<string, string>();
  const keyByServerSignature = new Map<string, string>();

  const registerRole = (key: string, name: string, scope: RoleScope, permissions: string[], isSystem: boolean): void => {
    rolesByKey.set(key, {
      key,
      name,
      scope,
      permissions: [...new Set(permissions)].sort(),
      isSystem,
    });
  };

  const allocateForScope = (scope: RoleScope, signatures: Set<string>): void => {
    const keyBySignature = scope === 'global' ? keyByGlobalSignature : keyByServerSignature;
    const sorted = [...signatures].sort();

    // System roles first so exact preset matches never consume an "imported" number.
    for (const signature of sorted) {
      const systemMatch = SYSTEM_ROLES.find(
        (role) => role.scope === scope && signatureOf(role.permissions) === signature
      );
      if (!systemMatch || keyBySignature.has(signature)) continue;

      const key = systemRoleKeyByName(systemMatch.name);
      registerRole(key, systemMatch.name, scope, systemMatch.permissions, true);
      keyBySignature.set(signature, key);
    }

    // Imported roles: one per remaining distinct signature, numbered in sorted order.
    let number = 0;
    for (const signature of sorted) {
      if (keyBySignature.has(signature)) continue;

      number += 1;
      const key = scope === 'global' ? `imported:global:${number}` : `imported:server:${number}`;
      const name = scope === 'global' ? `Imported role ${number}` : `Imported server role ${number}`;
      registerRole(key, name, scope, signature.split('\u0000'), false);
      keyBySignature.set(signature, key);
    }
  };

  const globalSignatures = new Set<string>();
  for (const user of users) {
    if (user.isRoot) continue;
    const signature = signatureOf(user.globalPermissions);
    if (signature) globalSignatures.add(signature);
  }

  const serverSignatures = new Set<string>();
  for (const membership of memberships) {
    const signature = signatureOf(membership.permissions);
    if (signature) serverSignatures.add(signature);
  }

  allocateForScope('global', globalSignatures);
  allocateForScope('server', serverSignatures);

  const userRoleAssignments: Array<{ userId: number; roleKey: string }> = [];
  for (const user of users) {
    if (user.isRoot) continue;

    const roleKey = keyByGlobalSignature.get(signatureOf(user.globalPermissions));
    if (roleKey) userRoleAssignments.push({ userId: user.id, roleKey });
  }

  const memberRoleAssignments: Array<{ serverId: number; userId: number; roleKey: string }> = [];
  for (const membership of memberships) {
    const roleKey = keyByServerSignature.get(signatureOf(membership.permissions));
    if (roleKey) {
      memberRoleAssignments.push({
        serverId: membership.serverId,
        userId: membership.userId,
        roleKey,
      });
    }
  }

  const roles = [...rolesByKey.values()].sort((a, b) => {
    if (a.isSystem !== b.isSystem) return a.isSystem ? -1 : 1;
    return a.key.localeCompare(b.key);
  });

  return { roles, userRoleAssignments, memberRoleAssignments };
}
