import { BaseRepository } from './base.js';
import { nowIso } from '../../utils/time.js';
import { parsePermissionsJson } from '../../utils/permissionList.js';

export type RoleScope = 'global' | 'server';

export type DbRoleRow = {
  id: number;
  name: string;
  scope: RoleScope;
  permissions_json: string;
  sso_groups_json: string;
  is_system: number;
};

export type Role = {
  id: number;
  name: string;
  scope: RoleScope;
  permissions: string[];
  ssoGroups: string[];
  isSystem: boolean;
};

export type RoleInput = {
  name: string;
  scope: RoleScope;
  permissions: string[];
  ssoGroups?: string[];
  isSystem?: boolean;
};

function toRole(row: DbRoleRow): Role {
  return {
    id: row.id,
    name: row.name,
    scope: row.scope,
    permissions: parsePermissionsJson(row.permissions_json),
    ssoGroups: parsePermissionsJson(row.sso_groups_json),
    isSystem: Boolean(row.is_system),
  };
}

const ROLE_COLUMNS = 'id, name, scope, permissions_json, sso_groups_json, is_system';

export class RoleRepository extends BaseRepository {
  async list(): Promise<Role[]> {
    const db = await this.ensureDb();
    const rows = await db.all<DbRoleRow[]>(
      `SELECT ${ROLE_COLUMNS} FROM roles ORDER BY scope ASC, LOWER(name) ASC`
    );
    return rows.map(toRole);
  }

  async findById(id: number): Promise<Role | undefined> {
    const db = await this.ensureDb();
    const row = await db.get<DbRoleRow>(
      `SELECT ${ROLE_COLUMNS} FROM roles WHERE id = ?`,
      [id]
    );
    return row ? toRole(row) : undefined;
  }

  async findByScopeAndName(scope: RoleScope, name: string): Promise<Role | undefined> {
    const db = await this.ensureDb();
    const row = await db.get<DbRoleRow>(
      `SELECT ${ROLE_COLUMNS} FROM roles WHERE scope = ? AND LOWER(name) = LOWER(?)`,
      [scope, name]
    );
    return row ? toRole(row) : undefined;
  }

  async create(input: RoleInput): Promise<number | undefined> {
    const db = await this.ensureDb();
    const timestamp = nowIso();
    const result = await db.run(
      `INSERT INTO roles (name, scope, permissions_json, sso_groups_json, is_system, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        input.name,
        input.scope,
        JSON.stringify(input.permissions),
        JSON.stringify(input.ssoGroups ?? []),
        input.isSystem ? 1 : 0,
        timestamp,
        timestamp,
      ]
    );
    return result.lastID;
  }

  async update(
    id: number,
    data: { name?: string; permissions?: string[]; ssoGroups?: string[] }
  ): Promise<void> {
    const db = await this.ensureDb();

    const fields: string[] = [];
    const values: unknown[] = [];

    if (data.name !== undefined) {
      fields.push('name = ?');
      values.push(data.name);
    }
    if (data.permissions !== undefined) {
      fields.push('permissions_json = ?');
      values.push(JSON.stringify(data.permissions));
    }
    if (data.ssoGroups !== undefined) {
      fields.push('sso_groups_json = ?');
      values.push(JSON.stringify(data.ssoGroups));
    }

    if (fields.length === 0) return;

    await db.run(
      `UPDATE roles SET ${fields.join(', ')}, updated_at = ? WHERE id = ?`,
      [...values, nowIso(), id]
    );
  }

  async delete(id: number): Promise<void> {
    const db = await this.ensureDb();
    await db.run('DELETE FROM roles WHERE id = ?', [id]);
  }

  // Assignment counts for the admin UI: how many users hold the role globally and how many
  // server memberships include it.
  async countAssignments(roleId: number): Promise<{ users: number; memberships: number }> {
    const db = await this.ensureDb();
    const users = await db.get<{ count: number }>(
      'SELECT COUNT(*) AS count FROM user_roles WHERE role_id = ?',
      [roleId]
    );
    const memberships = await db.get<{ count: number }>(
      'SELECT COUNT(*) AS count FROM server_member_roles WHERE role_id = ?',
      [roleId]
    );
    return { users: users?.count ?? 0, memberships: memberships?.count ?? 0 };
  }

  async listGlobalRoleIdsByUser(userId: number): Promise<number[]> {
    const db = await this.ensureDb();
    const rows = await db.all<Array<{ role_id: number }>>(
      'SELECT role_id FROM user_roles WHERE user_id = ? ORDER BY role_id ASC',
      [userId]
    );
    return rows.map((row) => row.role_id);
  }

  // All global assignments with role names, for user listings.
  async listGlobalAssignments(): Promise<Array<{ userId: number; roleId: number; roleName: string }>> {
    const db = await this.ensureDb();
    const rows = await db.all<Array<{ userId: number; roleId: number; roleName: string }>>(
      `SELECT ur.user_id AS userId, r.id AS roleId, r.name AS roleName
       FROM user_roles ur
       JOIN roles r ON r.id = ur.role_id
       ORDER BY ur.user_id ASC, LOWER(r.name) ASC`
    );
    return rows;
  }

  // Replaces the user's global role assignments. Statements run on the caller's
  // transaction connection when inside withDatabaseTransaction, else on the shared one;
  // multi-statement callers must wrap this together with their other writes.
  async setGlobalRoles(userId: number, roleIds: number[]): Promise<void> {
    const db = await this.ensureDb();
    const unique = [...new Set(roleIds)];

    await db.run('DELETE FROM user_roles WHERE user_id = ?', [userId]);
    for (const roleId of unique) {
      await db.run(
        'INSERT INTO user_roles (user_id, role_id, created_at) VALUES (?, ?, ?)',
        [userId, roleId, nowIso()]
      );
    }
  }

  async listServerRoleIds(serverId: number, userId: number): Promise<number[]> {
    const db = await this.ensureDb();
    const rows = await db.all<Array<{ role_id: number }>>(
      'SELECT role_id FROM server_member_roles WHERE server_id = ? AND user_id = ? ORDER BY role_id ASC',
      [serverId, userId]
    );
    return rows.map((row) => row.role_id);
  }

  // Replaces a membership's role assignments. Caller must ensure the membership exists
  // (the composite FK enforces it) and wrap multi-statement sequences in
  // withDatabaseTransaction.
  async setServerMemberRoles(serverId: number, userId: number, roleIds: number[]): Promise<void> {
    const db = await this.ensureDb();
    const unique = [...new Set(roleIds)];

    await db.run('DELETE FROM server_member_roles WHERE server_id = ? AND user_id = ?', [
      serverId,
      userId,
    ]);
    for (const roleId of unique) {
      await db.run(
        'INSERT INTO server_member_roles (server_id, user_id, role_id, created_at) VALUES (?, ?, ?, ?)',
        [serverId, userId, roleId, nowIso()]
      );
    }
  }
}
