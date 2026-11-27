import { getDatabase } from './init.js';
import { hashPassword } from '../utils/auth.js';
import { getConfig } from '../config.js';
import { SYSTEM_ROLES } from './systemRoles.js';
import { PERMISSIONS } from '../permissions.js';
import { logInfo } from '../utils/logger.js';
import { nowIso } from '../utils/time.js';

// Boot-time env is read at call time (like ADMIN_PASSWORD), not through the cached config,
// so behavior is testable and independent of config load order.
function ssoAdminGroupsFromEnv(): string[] {
  const raw = process.env.SSO_OIDC_ADMIN_GROUPS?.trim();
  if (!raw) return [];
  return [...new Set(raw.split(',').map((group) => group.trim()).filter(Boolean))];
}

export async function ensureRootUserExists(): Promise<void> {
  const db = await getDatabase();
  const { adminUsername } = getConfig();

  const existingRoot = await db.get<{ id: number }>('SELECT id FROM users WHERE is_root = 1');
  if (existingRoot?.id) return;

  const adminPassword = process.env.ADMIN_PASSWORD?.trim();
  if (!adminPassword) {
    if (ssoAdminGroupsFromEnv().length > 0) {
      logInfo(
        'DATABASE',
        'No ADMIN_PASSWORD set; skipping local root creation (SSO admin groups are configured).'
      );
      return;
    }

    throw new Error(
      'Missing env var: ADMIN_PASSWORD. It is required to create the first root user unless SSO_OIDC_ADMIN_GROUPS is configured.'
    );
  }

  const passwordHash = await hashPassword(adminPassword);
  const globalPermsJson = JSON.stringify(['*']);
  const timestamp = nowIso();

  await db.run(
    `INSERT INTO users (username, password_hash, global_permissions_json, is_root, is_enabled, created_at, updated_at)
     VALUES (?, ?, ?, 1, 1, ?, ?)`,
    [adminUsername.trim(), passwordHash, globalPermsJson, timestamp, timestamp]
  );
}

// Declares the SSO → panel-admin binding from env: the named global role gets its SSO
// groups (and the canonical admin permissions) reconciled to the environment on every
// boot. Env is the source of truth for this role while SSO_OIDC_ADMIN_GROUPS is set, so
// UI edits to its groups do not survive a restart. The role is marked system so it cannot
// be deleted from the UI.
export async function ensureSsoAdminRoleFromEnv(): Promise<void> {
  const adminGroups = ssoAdminGroupsFromEnv();
  if (adminGroups.length === 0) return;

  const roleName = process.env.SSO_OIDC_ADMIN_ROLE_NAME?.trim() || 'Administrator';
  const permissions = [
    PERMISSIONS.users.manage,
    PERMISSIONS.server.install,
  ];
  const timestamp = nowIso();

  const db = await getDatabase();
  const existing = await db.get<{ id: number }>(
    "SELECT id FROM roles WHERE scope = 'global' AND LOWER(name) = LOWER(?)",
    [roleName]
  );

  if (existing?.id) {
    await db.run(
      'UPDATE roles SET permissions_json = ?, sso_groups_json = ?, is_system = 1, updated_at = ? WHERE id = ?',
      [JSON.stringify(permissions), JSON.stringify(adminGroups), timestamp, existing.id]
    );
    return;
  }

  await db.run(
    `INSERT INTO roles (name, scope, permissions_json, sso_groups_json, is_system, created_at, updated_at)
     VALUES (?, 'global', ?, ?, 1, ?, ?)`,
    [roleName, JSON.stringify(permissions), JSON.stringify(adminGroups), timestamp, timestamp]
  );

  logInfo(
    'DATABASE',
    `SSO admin groups bound to global role "${roleName}": ${adminGroups.join(', ')}`
  );
}

// Seeds the built-in roles. Idempotent and matched by (scope, case-insensitive name) so it is
// safe on fresh databases (where migrations never ran) and on upgraded ones alike.
export async function ensureSystemRolesExist(): Promise<void> {
  const db = await getDatabase();
  const timestamp = nowIso();

  for (const role of SYSTEM_ROLES) {
    const existing = await db.get<{ id: number }>(
      'SELECT id FROM roles WHERE scope = ? AND LOWER(name) = LOWER(?)',
      [role.scope, role.name]
    );
    if (existing?.id) continue;

    await db.run(
      `INSERT INTO roles (name, scope, permissions_json, sso_groups_json, is_system, created_at, updated_at)
       VALUES (?, ?, ?, '[]', 1, ?, ?)`,
      [role.name, role.scope, JSON.stringify(role.permissions), timestamp, timestamp]
    );
  }
}
