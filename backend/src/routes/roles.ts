import { Router, type Request, type Response } from 'express';
import { requireGlobalPermission } from '../middleware/auth.js';
import { roleRepository } from '../database/index.js';
import { sendRouteError } from '../utils/routeErrors.js';
import { ASSIGNABLE_SERVER_PERMISSIONS, GLOBAL_ONLY_PERMISSIONS, PERMISSIONS } from '../permissions.js';
import {
  requireBodyObject,
  requirePositiveInt,
  requireTrimmedString,
} from '../utils/httpValidation.js';
import type { RoleScope } from '../database/repositories/roleRepository.js';

const router = Router();

function asScope(value: unknown): RoleScope | null {
  return value === 'global' || value === 'server' ? value : null;
}

function asStringList(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  const values: string[] = [];
  for (const item of value) {
    if (typeof item !== 'string') return null;
    const trimmed = item.trim();
    if (!trimmed) return null;
    values.push(trimmed);
  }
  return [...new Set(values)];
}

function asPermissionList(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  const values: string[] = [];
  for (const item of value) {
    if (typeof item !== 'string') return null;
    const trimmed = item.trim();
    if (!trimmed) return null;
    values.push(trimmed);
  }
  return [...new Set(values)];
}

function validateRolePermissions(scope: RoleScope, permissions: string[]): string | null {
  const allowed = scope === 'global' ? GLOBAL_ONLY_PERMISSIONS : ASSIGNABLE_SERVER_PERMISSIONS;
  const invalid = permissions.filter((permission) => !allowed.has(permission));

  if (invalid.length > 0) {
    return `Unknown or non-assignable permissions for a ${scope} role: ${invalid.join(', ')}`;
  }

  return null;
}

function validateRoleName(name: string): string | null {
  if (name.length === 0 || name.length > 64) {
    return 'Role name must be between 1 and 64 characters';
  }

  return null;
}

// GET /api/roles
router.get(
  '/',
  requireGlobalPermission(PERMISSIONS.users.manage),
  async (_req: Request, res: Response) => {
    try {
      const roles = await roleRepository.list();
      const withCounts = await Promise.all(
        roles.map(async (role) => ({
          ...role,
          assignmentCounts: await roleRepository.countAssignments(role.id),
        }))
      );

      return res.json({ roles: withCounts });
    } catch (error) {
      return sendRouteError(res, error, {
        route: 'ROUTE:ROLES:LIST',
        fallbackMessage: 'Failed to list roles',
      });
    }
  }
);

// POST /api/roles
router.post(
  '/',
  requireGlobalPermission(PERMISSIONS.users.manage),
  async (req: Request, res: Response) => {
    try {
      const body = requireBodyObject(req.body);
      const name = requireTrimmedString(body.name, 'Missing or invalid role name');
      const scope = asScope(body.scope);
      if (!scope) {
        return res.status(400).json({ error: 'scope must be "global" or "server"' });
      }

      const nameError = validateRoleName(name);
      if (nameError) return res.status(400).json({ error: nameError });

      const permissions = asPermissionList(body.permissions);
      if (permissions === null) {
        return res.status(400).json({ error: 'permissions must be an array of non-empty strings' });
      }

      const permissionError = validateRolePermissions(scope, permissions);
      if (permissionError) return res.status(400).json({ error: permissionError });

      let ssoGroups: string[] = [];
      if (body.ssoGroups !== undefined) {
        if (scope !== 'global') {
          return res.status(400).json({ error: 'ssoGroups is only supported on global roles' });
        }
        const parsed = asStringList(body.ssoGroups);
        if (parsed === null) {
          return res.status(400).json({ error: 'ssoGroups must be an array of non-empty strings' });
        }
        ssoGroups = parsed;
      }

      const existing = await roleRepository.findByScopeAndName(scope, name);
      if (existing) {
        return res.status(409).json({ error: 'A role with this name already exists' });
      }

      const roleId = await roleRepository.create({ name, scope, permissions, ssoGroups });
      const role = roleId ? await roleRepository.findById(roleId) : undefined;
      if (!role) {
        throw new Error('Created role could not be loaded');
      }

      return res.status(201).json({ success: true, role });
    } catch (error) {
      return sendRouteError(res, error, {
        route: 'ROUTE:ROLES:CREATE',
        fallbackMessage: 'Failed to create role',
      });
    }
  }
);

// PATCH /api/roles/:id
router.patch(
  '/:id',
  requireGlobalPermission(PERMISSIONS.users.manage),
  async (req: Request, res: Response) => {
    try {
      const id = requirePositiveInt(req.params.id, 'Invalid role id');
      const body = requireBodyObject(req.body);

      const role = await roleRepository.findById(id);
      if (!role) return res.status(404).json({ error: 'Role not found' });

      if (body.scope !== undefined && asScope(body.scope) !== role.scope) {
        return res.status(400).json({ error: 'Role scope cannot be changed' });
      }

      let name: string | undefined = undefined;
      if (body.name !== undefined) {
        name = requireTrimmedString(body.name, 'Invalid role name');
        const nameError = validateRoleName(name);
        if (nameError) return res.status(400).json({ error: nameError });

        // System role names are load-bearing (e.g. the installer grants "Full access" to
        // server creators); renaming them must not be possible.
        if (role.isSystem && name !== role.name) {
          return res.status(403).json({ error: 'System roles cannot be renamed' });
        }

        const conflict = await roleRepository.findByScopeAndName(role.scope, name);
        if (conflict && conflict.id !== id) {
          return res.status(409).json({ error: 'A role with this name already exists' });
        }
      }

      let permissions: string[] | undefined = undefined;
      if (body.permissions !== undefined) {
        const parsed = asPermissionList(body.permissions);
        if (parsed === null) {
          return res.status(400).json({ error: 'permissions must be an array of non-empty strings' });
        }
        permissions = parsed;

        const permissionError = validateRolePermissions(role.scope, permissions);
        if (permissionError) return res.status(400).json({ error: permissionError });
      }

      let ssoGroups: string[] | undefined = undefined;
      if (body.ssoGroups !== undefined) {
        if (role.scope !== 'global') {
          return res.status(400).json({ error: 'ssoGroups is only supported on global roles' });
        }
        const parsed = asStringList(body.ssoGroups);
        if (parsed === null) {
          return res.status(400).json({ error: 'ssoGroups must be an array of non-empty strings' });
        }
        ssoGroups = parsed;

        // Turning a role into SSO-managed while it still has manual assignments would leave
        // those assignments frozen (the SSO resync only manages SSO-mapped roles).
        if (role.ssoGroups.length === 0 && ssoGroups.length > 0) {
          const counts = await roleRepository.countAssignments(id);
          if (counts.users + counts.memberships > 0) {
            return res.status(409).json({
              error: 'Unassign this role from users and servers before making it SSO-managed',
            });
          }
        }
      }

      await roleRepository.update(id, { name, permissions, ssoGroups });

      return res.json({ success: true, role: await roleRepository.findById(id) });
    } catch (error) {
      return sendRouteError(res, error, {
        route: 'ROUTE:ROLES:UPDATE',
        fallbackMessage: 'Failed to update role',
        logContext: { roleId: req.params.id },
      });
    }
  }
);

// DELETE /api/roles/:id
router.delete(
  '/:id',
  requireGlobalPermission(PERMISSIONS.users.manage),
  async (req: Request, res: Response) => {
    try {
      const id = requirePositiveInt(req.params.id, 'Invalid role id');

      const role = await roleRepository.findById(id);
      if (!role) return res.status(404).json({ error: 'Role not found' });

      if (role.isSystem) {
        return res.status(403).json({ error: 'System roles cannot be deleted' });
      }

      await roleRepository.delete(id);

      return res.json({ success: true });
    } catch (error) {
      return sendRouteError(res, error, {
        route: 'ROUTE:ROLES:DELETE',
        fallbackMessage: 'Failed to delete role',
        logContext: { roleId: req.params.id },
      });
    }
  }
);

export default router;
