import { roleRepository } from '../database/index.js';
import type { Role, RoleScope } from '../database/repositories/roleRepository.js';

function httpError(statusCode: number, message: string): Error {
  return Object.assign(new Error(message), { statusCode });
}

// Resolves and validates role ids for a manual assignment. Every id must exist, match the
// expected scope, and not be SSO-managed (roles with ssoGroups are assigned exclusively by
// the SSO login sync).
export async function resolveAssignableRoles(roleIds: number[], scope: RoleScope): Promise<Role[]> {
  const roles: Role[] = [];

  for (const roleId of [...new Set(roleIds)]) {
    const role = await roleRepository.findById(roleId);

    if (!role || role.scope !== scope) {
      throw httpError(400, `Role ${roleId} does not exist or is not a ${scope} role`);
    }

    if (role.ssoGroups.length > 0) {
      throw httpError(400, `Role "${role.name}" is managed by SSO and cannot be assigned manually`);
    }

    roles.push(role);
  }

  return roles;
}
