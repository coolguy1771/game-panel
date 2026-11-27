import { Router, type Request, type Response } from 'express';
import { type AuthenticatedRequest, authMiddleware, requireGlobalPermission } from '../middleware/auth.js';
import { comparePasswords, generateToken, hashPassword } from '../utils/auth.js';
import { userRepository, serverMemberRepository, roleRepository } from '../database/index.js';
import { getDatabase } from '../database/init.js';
import { withDatabaseTransaction } from '../database/transaction.js';
import { asNonEmptyString } from './users.js';
import { sendRouteError } from '../utils/routeErrors.js';
import { PERMISSIONS } from '../permissions.js';
import { requireBodyObject, idArray } from '../utils/httpValidation.js';
import { resolveAssignableRoles } from '../services/roleAssignment.js';
import { createRateLimiter, LOGIN_RATE_LIMITS } from '../utils/rateLimit.js';

const router = Router();

function isStrongEnoughPassword(password: string): boolean {
  return password.length >= 8;
}

function isValidUsername(value: string): boolean {
  return value.length > 0 && value.length <= 12;
}

function normalizeUsername(value: string): string {
  return value.trim();
}

const loginRateLimiter = createRateLimiter(LOGIN_RATE_LIMITS);

// POST /api/auth/register
router.post(
  '/register',
  authMiddleware,
  requireGlobalPermission(PERMISSIONS.users.manage),
  async (req: Request, res: Response) => {
    try {
      const body = requireBodyObject(req.body);
      const username = asNonEmptyString(body.username);
      const password = asNonEmptyString(body.password);
      const confirmPassword = asNonEmptyString(body.confirmPassword);

      let globalRoleIds: number[] = [];
      if (body.roleIds !== undefined) {
        globalRoleIds = idArray(body.roleIds, 'roleIds must be an array of role ids');
        await resolveAssignableRoles(globalRoleIds, 'global');
      }

      if (!username || !password || !confirmPassword) {
        return res.status(400).json({ error: 'Missing required fields' });
      }

      const normalizedUsername = normalizeUsername(username);
      if (!isValidUsername(normalizedUsername)) {
        return res.status(400).json({ error: 'Username must be between 1 and 12 characters' });
      }

      if (password !== confirmPassword) {
        return res.status(400).json({ error: 'Passwords do not match' });
      }

      if (!isStrongEnoughPassword(password)) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
      }

      const existingByUsername = await userRepository.findByUsername(normalizedUsername);
      if (existingByUsername) {
        return res.status(409).json({ error: 'Username already exists' });
      }

      const passwordHash = await hashPassword(password);

      // Create user (enabled by default) with its initial global roles atomically.
      const userId = await withDatabaseTransaction(await getDatabase(), async () => {
        const newUserId = await userRepository.create(normalizedUsername, passwordHash, {});
        if (!newUserId) throw new Error('Failed to create user');
        await roleRepository.setGlobalRoles(newUserId, globalRoleIds);
        return newUserId;
      });

      const user = await userRepository.findById(userId);
      if (!user) {
        throw new Error('Created user could not be loaded');
      }

      const assignedRoles = await roleRepository.listGlobalRoleIdsByUser(user.id);
      const roleObjects = await Promise.all(
        assignedRoles.map(async (roleId) => {
          const role = await roleRepository.findById(roleId);
          return role ? { id: role.id, name: role.name } : null;
        })
      );

      return res.status(201).json({
        success: true,
        user: {
          id: user.id,
          username: user.username,
          isRoot: Boolean(user.is_root),
          isEnabled: Boolean(user.is_enabled),
          roles: roleObjects.filter((role): role is { id: number; name: string } => role !== null),
        },
      });
    } catch (error) {
      return sendRouteError(res, error, {
        route: 'ROUTE:AUTH:REGISTER',
        fallbackMessage: 'Registration failed',
      });
    }
  }
);

// POST /api/auth/login
router.post('/login', async (req: Request, res: Response) => {
  try {
    const body = requireBodyObject(req.body);
    const identifier = asNonEmptyString(body.username);
    const password = asNonEmptyString(body.password);

    if (!identifier || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const normalizedIdentifier = normalizeUsername(identifier);
    if (!isValidUsername(normalizedIdentifier)) {
      return res.status(400).json({ error: 'Username must be between 1 and 12 characters' });
    }

    if (!loginRateLimiter.ensureAllowed(req, res, normalizedIdentifier)) {
      return;
    }

    const user = await userRepository.findByUsername(normalizedIdentifier);
    if (!user) {
      loginRateLimiter.noteFailure(req, normalizedIdentifier);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.auth_type === 'sso') {
      return res.status(400).json({ error: 'This account signs in with SSO' });
    }

    if (!user.is_enabled) {
      loginRateLimiter.noteFailure(req, normalizedIdentifier);
      return res.status(403).json({ error: 'Account disabled' });
    }

    const validPassword = await comparePasswords(password, user.password_hash);
    if (!validPassword) {
      loginRateLimiter.noteFailure(req, normalizedIdentifier);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    loginRateLimiter.clear(req, normalizedIdentifier);

    const token = generateToken({
      userId: user.id,
      username: user.username,
      isRoot: Boolean(user.is_root),
      tokenVersion: user.token_version,
    });

    return res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        isRoot: Boolean(user.is_root),
        isEnabled: Boolean(user.is_enabled),
      },
      token,
    });
  } catch (error) {
    return sendRouteError(res, error, {
      route: 'ROUTE:AUTH:LOGIN',
      fallbackMessage: 'Login failed',
    });
  }
});

// GET /api/auth/me
router.get('/me', authMiddleware, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userId = req.user!.userId;

    const user = await userRepository.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const isRoot = Boolean(user.is_root);

    const globalPermissions = isRoot
      ? ['*']
      : await userRepository.getGlobalPermissions(userId);

    const serverRows = await serverMemberRepository.listByUser(userId);

    const serverPermissions = serverRows.map((r) => ({
      serverId: r.server_id,
      // Effective permissions are resolved from the member's roles server-side.
      permissions: r.permissions,
    }));

    return res.json({
      user: {
        id: user.id,
        username: user.username,
        isRoot,
        isEnabled: Boolean(user.is_enabled),
      },
      permissions: {
        global: globalPermissions,
        servers: serverPermissions,
      },
    });
  } catch (error) {
    return sendRouteError(res, error, {
      route: 'ROUTE:AUTH:ME',
      fallbackMessage: 'Failed to fetch user',
    });
  }
});

// POST /api/auth/change-password
router.post('/change-password', authMiddleware, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const body = requireBodyObject(req.body);
    const currentPassword = asNonEmptyString(body.currentPassword);
    const newPassword = asNonEmptyString(body.newPassword);
    const confirmPassword = asNonEmptyString(body.confirmPassword);

    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'New passwords do not match' });
    }

    if (!isStrongEnoughPassword(newPassword)) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    if (currentPassword === newPassword) {
      return res.status(400).json({ error: 'New password must be different from current password' });
    }

    const user = await userRepository.findById(req.user!.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.auth_type === 'sso') {
      return res.status(400).json({ error: 'SSO accounts do not use passwords' });
    }

    const validPassword = await comparePasswords(currentPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const newPasswordHash = await hashPassword(newPassword);
    await userRepository.updatePassword(req.user!.userId, newPasswordHash);

    const refreshed = await userRepository.findById(req.user!.userId);
    const token = refreshed
      ? generateToken({
          userId: refreshed.id,
          username: refreshed.username,
          isRoot: Boolean(refreshed.is_root),
          tokenVersion: refreshed.token_version,
        })
      : undefined;

    return res.json({ success: true, message: 'Password changed successfully', token });
  } catch (error) {
    return sendRouteError(res, error, {
      route: 'ROUTE:AUTH:CHANGE_PASSWORD',
      fallbackMessage: 'Failed to change password',
    });
  }
});

export default router;
