import { Router, type Request, type Response } from 'express';
import { requireGlobalPermission } from '../middleware/auth.js';
import { roleRepository, userRepository } from '../database/index.js';
import { hashPassword } from '../utils/auth.js';
import { sendRouteError } from '../utils/routeErrors.js';
import { PERMISSIONS } from '../permissions.js';
import { toIsoTimestamp } from '../utils/time.js';
import { optionalBoolean, requireBodyObject, requirePositiveInt, idArray } from '../utils/httpValidation.js';
import { resolveAssignableRoles } from '../services/roleAssignment.js';

const router = Router();

export function asNonEmptyString(value: unknown): string | null {
    if (typeof value !== 'string') return null;
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : null;
}

function normalizeUsername(value: string): string {
    return value.trim();
}

function isValidUsername(value: string): boolean {
    return value.length > 0 && value.length <= 12;
}

// GET /api/users
router.get(
    '/',
    requireGlobalPermission(PERMISSIONS.users.manage),
    async (_req: Request, res: Response) => {
        try {
            const users = await userRepository.list();
            const assignments = await roleRepository.listGlobalAssignments();

            const rolesByUser = new Map<number, Array<{ id: number; name: string }>>();
            for (const assignment of assignments) {
                const list = rolesByUser.get(assignment.userId) ?? [];
                list.push({ id: assignment.roleId, name: assignment.roleName });
                rolesByUser.set(assignment.userId, list);
            }

            const normalized = users.map((u) => ({
                id: u.id,
                username: u.username,
                isRoot: Boolean(u.is_root),
                isEnabled: Boolean(u.is_enabled),
                roles: rolesByUser.get(u.id) ?? [],
                createdAt: toIsoTimestamp(u.created_at),
                updatedAt: toIsoTimestamp(u.updated_at),
            }));

            return res.json({ users: normalized });
        } catch (error) {
            return sendRouteError(res, error, {
                route: 'ROUTE:USERS:LIST',
                fallbackMessage: 'Failed to list users',
            });
        }
    }
);

// PATCH /api/users/:id
router.patch(
    '/:id',
    requireGlobalPermission(PERMISSIONS.users.manage),
    async (req: Request, res: Response) => {
        try {
            const id = requirePositiveInt(req.params.id, 'Invalid user id');
            const body = requireBodyObject(req.body);

            const user = await userRepository.findById(id);
            if (!user) return res.status(404).json({ error: 'User not found' });

            if (user.is_root) {
                return res.status(403).json({ error: 'Root user cannot be modified' });
            }

            const usernameRaw = asNonEmptyString(body.username);

            const normalizedUsername = usernameRaw ? normalizeUsername(usernameRaw) : undefined;
            if (normalizedUsername !== undefined) {
                if (!isValidUsername(normalizedUsername)) {
                    return res.status(400).json({ error: 'Username must be between 1 and 12 characters' });
                }

                const existing = await userRepository.findByUsername(normalizedUsername);
                if (existing && existing.id !== id) {
                    return res.status(409).json({ error: 'Username already exists' });
                }
            }

            let roleIds: number[] | undefined = undefined;
            if (body.roleIds !== undefined) {
                roleIds = idArray(body.roleIds, 'roleIds must be an array of role ids');
                await resolveAssignableRoles(roleIds, 'global');
            }

            const isEnabled = optionalBoolean(body.isEnabled, 'isEnabled must be a boolean');

            await userRepository.updateUser(id, {
                username: normalizedUsername ?? undefined,
                is_enabled: isEnabled,
            });

            if (roleIds !== undefined) {
                await roleRepository.setGlobalRoles(id, roleIds);
            }

            return res.json({ success: true });
        } catch (error) {
            return sendRouteError(res, error, {
                route: 'ROUTE:USERS:UPDATE',
                fallbackMessage: 'Failed to update user',
                logContext: { userId: req.params.id },
            });
        }
    }
);

// DELETE /api/users/:id
router.delete(
    '/:id',
    requireGlobalPermission(PERMISSIONS.users.manage),
    async (req: Request, res: Response) => {
        try {
            const id = requirePositiveInt(req.params.id, 'Invalid user id');

            const user = await userRepository.findById(id);
            if (!user) return res.status(404).json({ error: 'User not found' });

            if (user.is_root) {
                return res.status(403).json({ error: 'Root user cannot be deleted' });
            }

            await userRepository.deleteUser(id);

            return res.json({ success: true });
        } catch (error) {
            return sendRouteError(res, error, {
                route: 'ROUTE:USERS:DELETE',
                fallbackMessage: 'Failed to delete user',
                logContext: { userId: req.params.id },
            });
        }
    }
);

// POST /api/users/:id/reset-password
router.post(
    '/:id/reset-password',
    requireGlobalPermission(PERMISSIONS.users.manage),
    async (req: Request, res: Response) => {
        try {
            const id = requirePositiveInt(req.params.id, 'Invalid user id');
            const body = requireBodyObject(req.body);

            const newPassword = asNonEmptyString(body.newPassword);
            if (!newPassword || newPassword.length < 8) {
                return res.status(400).json({ error: 'Password must be at least 8 characters' });
            }

            const user = await userRepository.findById(id);
            if (!user) return res.status(404).json({ error: 'User not found' });

            if (user.is_root) {
                return res.status(403).json({ error: 'Root user password should be changed via /auth route' });
            }

            if (user.auth_type === 'sso') {
                return res.status(400).json({ error: 'SSO accounts do not use passwords' });
            }

            const passwordHash = await hashPassword(newPassword);
            await userRepository.updatePassword(id, passwordHash);

            return res.json({ success: true });
        } catch (error) {
            return sendRouteError(res, error, {
                route: 'ROUTE:USERS:RESET_PASSWORD',
                fallbackMessage: 'Failed to reset password',
                logContext: { userId: req.params.id },
            });
        }
    }
);

export default router;
