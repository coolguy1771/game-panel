import { getDatabase } from './init.js';
import { hashPassword } from '../utils/auth.js';
import { getConfig, requireAdminBootstrapPassword } from '../config.js';
import { SYSTEM_ROLES } from './systemRoles.js';
import { nowIso } from '../utils/time.js';

export async function ensureRootUserExists(): Promise<void> {
  const db = await getDatabase();
  const { adminUsername } = getConfig();

  const existingRoot = await db.get<{ id: number }>('SELECT id FROM users WHERE is_root = 1');
  if (existingRoot?.id) return;

  const adminPassword = requireAdminBootstrapPassword();
  const passwordHash = await hashPassword(adminPassword.trim());
  const globalPermsJson = JSON.stringify(['*']);
  const timestamp = nowIso();

  await db.run(
    `INSERT INTO users (username, password_hash, global_permissions_json, is_root, is_enabled, created_at, updated_at)
     VALUES (?, ?, ?, 1, 1, ?, ?)`,
    [adminUsername.trim(), passwordHash, globalPermsJson, timestamp, timestamp]
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
