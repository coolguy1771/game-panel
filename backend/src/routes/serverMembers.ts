import { Router, type Request, type Response } from 'express';
import { requireGlobalPermission } from '../middleware/auth.js';
import { roleRepository, serverMemberRepository, serverRepository, userRepository } from '../database/index.js';
import { withDatabaseTransaction } from '../database/transaction.js';
import { sendRouteError } from '../utils/routeErrors.js';
import { PERMISSIONS } from '../permissions.js';
import { toIsoTimestamp } from '../utils/time.js';
import { requireBodyObject, requirePositiveInt, idArray } from '../utils/httpValidation.js';
import { resolveAssignableRoles } from '../services/roleAssignment.js';

const router = Router();

// GET /api/servers/:id/members
router.get(
    '/:id/members',
    requireGlobalPermission(PERMISSIONS.users.manage),
    async (req: Request, res: Response) => {
        try {
            const serverId = requirePositiveInt(req.params.id, 'Invalid server id');

            const server = await serverRepository.findById(serverId);
            if (!server) return res.status(404).json({ error: 'Server not found' });

            const members = await serverMemberRepository.listByServer(serverId);

            // Return normalized members: roles resolved, timestamps as ISO strings.
            const normalized = members.map((m) => ({
                id: m.id,
                serverId: m.server_id,
                userId: m.user_id,
                username: m.username,
                roles: m.roles,
                createdAt: toIsoTimestamp(m.created_at),
                updatedAt: toIsoTimestamp(m.updated_at),
            }));

            return res.json({ members: normalized });
        } catch (error) {
            return sendRouteError(res, error, {
                route: 'ROUTE:SERVER_MEMBERS:LIST',
                fallbackMessage: 'Failed to list server members',
                logContext: { serverId: req.params.id },
            });
        }
    }
);

// POST /api/servers/:id/members
router.post(
    '/:id/members',
    requireGlobalPermission(PERMISSIONS.users.manage),
    async (req: Request, res: Response) => {
        try {
            const serverId = requirePositiveInt(req.params.id, 'Invalid server id');
            const body = requireBodyObject(req.body);

            const userId = requirePositiveInt(body.userId, 'Missing or invalid userId/roleIds');
            const roleIds = idArray(body.roleIds ?? [], 'roleIds must be an array of role ids');
            await resolveAssignableRoles(roleIds, 'server');

            const server = await serverRepository.findById(serverId);
            if (!server) return res.status(404).json({ error: 'Server not found' });

            const user = await userRepository.findById(userId);
            if (!user) return res.status(404).json({ error: 'User not found' });

            const existing = await serverMemberRepository.find(serverId, userId);
            if (existing) return res.status(409).json({ error: 'User already assigned to server' });

            await withDatabaseTransaction(async () => {
              await serverMemberRepository.create(serverId, userId);
              await roleRepository.setServerMemberRoles(serverId, userId, roleIds);
            });

            return res.status(201).json({ success: true });
        } catch (error) {
            return sendRouteError(res, error, {
                route: 'ROUTE:SERVER_MEMBERS:CREATE',
                fallbackMessage: 'Failed to add server member',
                logContext: { serverId: req.params.id },
            });
        }
    }
);

// PATCH /api/servers/:id/members/:userId
router.patch(
    '/:id/members/:userId',
    requireGlobalPermission(PERMISSIONS.users.manage),
    async (req: Request, res: Response) => {
        try {
            const serverId = requirePositiveInt(req.params.id, 'Invalid server id');

            const userId = requirePositiveInt(req.params.userId, 'Invalid user id');
            const body = requireBodyObject(req.body);

            const roleIds = idArray(body.roleIds, 'roleIds must be an array of role ids');
            await resolveAssignableRoles(roleIds, 'server');

            const existing = await serverMemberRepository.find(serverId, userId);
            if (!existing) return res.status(404).json({ error: 'Membership not found' });

            await withDatabaseTransaction(async () => {
              await serverMemberRepository.update(serverId, userId);
              await roleRepository.setServerMemberRoles(serverId, userId, roleIds);
            });

            return res.json({ success: true });
        } catch (error) {
            return sendRouteError(res, error, {
                route: 'ROUTE:SERVER_MEMBERS:UPDATE',
                fallbackMessage: 'Failed to update server member',
                logContext: {
                    serverId: req.params.id,
                    userId: req.params.userId,
                },
            });
        }
    }
);

// DELETE /api/servers/:id/members/:userId
router.delete(
    '/:id/members/:userId',
    requireGlobalPermission(PERMISSIONS.users.manage),
    async (req: Request, res: Response) => {
        try {
            const serverId = requirePositiveInt(req.params.id, 'Invalid server id');

            const userId = requirePositiveInt(req.params.userId, 'Invalid user id');

            const existing = await serverMemberRepository.find(serverId, userId);
            if (!existing) return res.status(404).json({ error: 'Membership not found' });

            await serverMemberRepository.delete(serverId, userId);

            return res.json({ success: true });
        } catch (error) {
            return sendRouteError(res, error, {
                route: 'ROUTE:SERVER_MEMBERS:DELETE',
                fallbackMessage: 'Failed to remove server member',
                logContext: {
                    serverId: req.params.id,
                    userId: req.params.userId,
                },
            });
        }
    }
);

export default router;
