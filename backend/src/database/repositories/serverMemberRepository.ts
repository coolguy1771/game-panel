import { BaseRepository } from './base.js';
import { nowIso } from '../../utils/time.js';
import { parsePermissionsJson } from '../../utils/permissionList.js';

export type ServerMemberWithUserRow = {
  id: number;
  server_id: number;
  user_id: number;
  permissions_json: string;
  created_at: string;
  updated_at: string;
  username: string;
};

export type ServerMembershipRow = {
  server_id: number;
  permissions: string[];
  created_at: string;
  updated_at: string;
};

export class ServerMemberRepository extends BaseRepository {
  async listByServer(serverId: number) {
    const db = await this.ensureDb();
    return db.all<ServerMemberWithUserRow[]>(
      `SELECT sm.id,
              sm.server_id,
              sm.user_id,
              sm.permissions_json,
              sm.created_at,
              sm.updated_at,
              u.username
       FROM server_members sm
       JOIN users u ON u.id = sm.user_id
       WHERE sm.server_id = ?
       ORDER BY u.username ASC`,
      [serverId]
    );
  }

  async listByUser(userId: number) {
    const db = await this.ensureDb();

    // Membership rows plus the effective permissions of the roles assigned to each
    // membership (union across roles; roles are the only assignment mechanism since
    // migration 0002).
    const membershipRows = await db.all<
      Array<{ server_id: number; created_at: string; updated_at: string }>
    >(
      `SELECT sm.server_id, sm.created_at, sm.updated_at
       FROM server_members sm
       WHERE sm.user_id = ?
       ORDER BY sm.server_id ASC`,
      [userId]
    );

    const permissionRows = await db.all<
      Array<{ server_id: number; permissions_json: string }>
    >(
      `SELECT smr.server_id, r.permissions_json
       FROM server_member_roles smr
       JOIN roles r ON r.id = smr.role_id
       WHERE smr.user_id = ?`,
      [userId]
    );

    const permissionsByServer = new Map<number, Set<string>>();
    for (const row of permissionRows) {
      const acc = permissionsByServer.get(row.server_id) ?? new Set<string>();
      for (const permission of parsePermissionsJson(row.permissions_json)) {
        acc.add(permission);
      }
      permissionsByServer.set(row.server_id, acc);
    }

    return membershipRows.map((row) => ({
      server_id: row.server_id,
      permissions: [...(permissionsByServer.get(row.server_id) ?? [])],
      created_at: row.created_at,
      updated_at: row.updated_at,
    }));
  }

  async find(serverId: number, userId: number) {
    const db = await this.ensureDb();
    return db.get(
      `SELECT *
       FROM server_members
       WHERE server_id = ? AND user_id = ?`,
      [serverId, userId]
    );
  }

  async create(serverId: number, userId: number, _legacyPermissions?: string[]) {
    const db = await this.ensureDb();
    const timestamp = nowIso();
    // `_legacyPermissions` is accepted for call-site compatibility and ignored: access is
    // owned by server_member_roles since migration 0002. Routes pass roleIds instead.
    await db.run(
      `INSERT INTO server_members (server_id, user_id, permissions_json, created_at, updated_at)
       VALUES (?, ?, '[]', ?, ?)`,
      [serverId, userId, timestamp, timestamp]
    );
  }

  async update(serverId: number, userId: number, _legacyPermissions?: string[]) {
    const db = await this.ensureDb();
    // `_legacyPermissions` is accepted for call-site compatibility and ignored; role
    // assignments are written through RoleRepository.setServerMemberRoles.
    await db.run(
      `UPDATE server_members
       SET updated_at = ?
       WHERE server_id = ? AND user_id = ?`,
      [nowIso(), serverId, userId]
    );
  }

  async delete(serverId: number, userId: number) {
    const db = await this.ensureDb();
    await db.run(
      `DELETE FROM server_members
       WHERE server_id = ? AND user_id = ?`,
      [serverId, userId]
    );
  }

  async getUserServerPermissions(serverId: number, userId: number): Promise<string[]> {
    const db = await this.ensureDb();

    // Effective per-server permissions are the union of the membership's roles' permissions.
    const rows = await db.all<Array<{ permissions_json: string }>>(
      `SELECT r.permissions_json
       FROM server_member_roles smr
       JOIN roles r ON r.id = smr.role_id
       WHERE smr.server_id = ? AND smr.user_id = ?`,
      [serverId, userId]
    );

    const acc = new Set<string>();
    for (const row of rows) {
      for (const permission of parsePermissionsJson(row.permissions_json)) {
        acc.add(permission);
      }
    }
    return [...acc];
  }
}
