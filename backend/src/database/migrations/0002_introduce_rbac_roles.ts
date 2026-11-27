import type { DatabaseMigration } from './types.js';
import { checksumSql } from './checksum.js';
import { planRbacConversion, type ParsedMembershipRow, type ParsedUserRow } from './rbacConversion.js';
import { nowIso } from '../../utils/time.js';

const SCHEMA_SQL = `
  CREATE TABLE roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    scope TEXT NOT NULL CHECK(scope IN ('global','server')),
    permissions_json TEXT NOT NULL DEFAULT '[]',
    sso_groups_json TEXT NOT NULL DEFAULT '[]',
    is_system INTEGER NOT NULL DEFAULT 0 CHECK(is_system IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE UNIQUE INDEX idx_roles_name_scope ON roles(LOWER(name), scope);

  CREATE TABLE user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    UNIQUE(user_id, role_id)
  );

  CREATE INDEX idx_user_roles_user ON user_roles(user_id);
  CREATE INDEX idx_user_roles_role ON user_roles(role_id);

  -- Assignment implies membership: the composite FK targets the UNIQUE(server_id, user_id)
  -- pair on server_members, so deleting a membership (or its user/server) removes the rows.
  CREATE TABLE server_member_roles (
    server_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    UNIQUE(server_id, user_id, role_id),
    FOREIGN KEY (server_id, user_id) REFERENCES server_members(server_id, user_id) ON DELETE CASCADE
  );

  CREATE INDEX idx_server_member_roles_user ON server_member_roles(user_id);
  CREATE INDEX idx_server_member_roles_role ON server_member_roles(role_id);

  CREATE TABLE sso_login_codes (
    code_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    used_at TEXT
  );

  ALTER TABLE users ADD COLUMN auth_type TEXT NOT NULL DEFAULT 'local' CHECK(auth_type IN ('local','sso'));
  ALTER TABLE users ADD COLUMN sso_provider TEXT;
  ALTER TABLE users ADD COLUMN sso_subject TEXT;
  ALTER TABLE users ADD COLUMN sso_email TEXT;

  CREATE UNIQUE INDEX idx_users_sso_identity ON users(sso_provider, sso_subject) WHERE sso_subject IS NOT NULL;
`;

function parsePermsJson(raw: unknown): string[] {
  if (typeof raw !== 'string' || raw.trim() === '') return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((x) => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

export const migration: DatabaseMigration = {
  id: '0002_introduce_rbac_roles',
  appVersion: '1.7.0',
  checksum: checksumSql(SCHEMA_SQL + 'rbac-conversion-v1'),
  async up(database) {
    await database.exec(SCHEMA_SQL);

    const userRows = await database.all<Array<{ id: number; is_root: number; global_permissions_json: string }>>(
      'SELECT id, is_root, global_permissions_json FROM users ORDER BY id'
    );
    const membershipRows = await database.all<
      Array<{ server_id: number; user_id: number; permissions_json: string }>
    >('SELECT server_id, user_id, permissions_json FROM server_members ORDER BY server_id, user_id');

    const users: ParsedUserRow[] = userRows.map((row) => ({
      id: row.id,
      isRoot: Boolean(row.is_root),
      globalPermissions: parsePermsJson(row.global_permissions_json),
    }));
    const memberships: ParsedMembershipRow[] = membershipRows.map((row) => ({
      serverId: row.server_id,
      userId: row.user_id,
      permissions: parsePermsJson(row.permissions_json),
    }));

    const plan = planRbacConversion(users, memberships);

    // Find-or-create every planned role (system roles included) and remember its id.
    const roleIdByKey = new Map<string, number>();
    for (const planned of plan.roles) {
      const existing = await database.get<{ id: number }>(
        'SELECT id FROM roles WHERE scope = ? AND LOWER(name) = LOWER(?)',
        [planned.scope, planned.name]
      );

      if (existing?.id) {
        roleIdByKey.set(planned.key, existing.id);
        continue;
      }

      const timestamp = nowIso();
      const result = await database.run(
        `INSERT INTO roles (name, scope, permissions_json, sso_groups_json, is_system, created_at, updated_at)
         VALUES (?, ?, ?, '[]', ?, ?, ?)`,
        [planned.name, planned.scope, JSON.stringify(planned.permissions), planned.isSystem ? 1 : 0, timestamp, timestamp]
      );
      roleIdByKey.set(planned.key, Number(result.lastID));
    }

    for (const assignment of plan.userRoleAssignments) {
      const roleId = roleIdByKey.get(assignment.roleKey);
      if (!roleId) throw new Error(`Migration planned an unknown role key: ${assignment.roleKey}`);

      await database.run(
        'INSERT OR IGNORE INTO user_roles (user_id, role_id, created_at) VALUES (?, ?, ?)',
        [assignment.userId, roleId, nowIso()]
      );
    }

    for (const assignment of plan.memberRoleAssignments) {
      const roleId = roleIdByKey.get(assignment.roleKey);
      if (!roleId) throw new Error(`Migration planned an unknown role key: ${assignment.roleKey}`);

      await database.run(
        'INSERT OR IGNORE INTO server_member_roles (server_id, user_id, role_id, created_at) VALUES (?, ?, ?, ?)',
        [assignment.serverId, assignment.userId, roleId, nowIso()]
      );
    }

    // Roles are now the only assignment mechanism; freeze the legacy lists.
    await database.exec("UPDATE users SET global_permissions_json = '[]' WHERE global_permissions_json != '[]'");
    await database.exec("UPDATE server_members SET permissions_json = '[]' WHERE permissions_json != '[]'");
  },
};
