import { open } from 'sqlite';
import sqlite3 from 'sqlite3';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { migration as introduceRbacRoles } from './0002_introduce_rbac_roles.js';
import { parsePermissionsJson } from '../../utils/permissionList.js';

// Proves migration 0002 preserves every user's effective permissions exactly: the legacy
// per-user/per-membership lists are converted into roles, and pre/post resolution must match
// for every account (except root, which bypasses authorization and gets no roles).

describe('migration 0002 conversion', () => {
  it('preserves effective global and per-server permissions for every user', async () => {
    const dbPath = path.join(process.env.GAMEPANEL_DATA_DIR ?? '.', 'rbac-migration-test.db');
    const db = await open({ filename: dbPath, driver: sqlite3.Database });
    await db.exec('PRAGMA foreign_keys = ON');

    // Legacy (pre-0002) schema: the parts the migration reads or needs for FKs.
    await db.exec(`
      CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        global_permissions_json TEXT NOT NULL DEFAULT '[]',
        is_root INTEGER NOT NULL DEFAULT 0 CHECK(is_root IN (0, 1)),
        is_enabled INTEGER NOT NULL DEFAULT 1 CHECK(is_enabled IN (0, 1)),
        token_version INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE UNIQUE INDEX idx_users_username_ci_unique ON users(LOWER(username));

      CREATE TABLE game_servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        provider TEXT NOT NULL CHECK(provider IN ('ovhcloud','linuxgsm','external')),
        docker_image TEXT NOT NULL,
        ports_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE server_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        permissions_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (server_id) REFERENCES game_servers(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(server_id, user_id)
      );

      CREATE TABLE schema_migrations (
        id TEXT PRIMARY KEY,
        app_version TEXT NOT NULL,
        checksum TEXT NOT NULL,
        applied_at TEXT NOT NULL
      );
      INSERT INTO schema_migrations (id, app_version, checksum, applied_at)
        VALUES ('0001_file_transfer_jobs_add_extract_kind', '1.2.0', 'x', '2026-01-01T00:00:00.000Z');
    `);

    const timestamp = '2026-01-01T00:00:00.000Z';
    const insertUser = async (username: string, perms: string[], isRoot = false): Promise<number> => {
      const result = await db.run(
        `INSERT INTO users (username, password_hash, global_permissions_json, is_root, is_enabled, created_at, updated_at)
         VALUES (?, 'x', ?, ?, 1, ?, ?)`,
        [username, JSON.stringify(perms), isRoot ? 1 : 0, timestamp, timestamp]
      );
      return Number(result.lastID);
    };

    const adminId = await insertUser('admin', ['*'], true);
    const managerId = await insertUser('manager', ['users.manage']);
    const superId = await insertUser('super', ['users.manage', 'server.install']);
    const emptyId = await insertUser('empty', []);
    const oddId = await insertUser('odd', ['users.manage', 'unknown.legacy.perm']);

    const serverResult = await db.run(
      `INSERT INTO game_servers (name, provider, docker_image, ports_json, created_at, updated_at)
       VALUES ('srv1', 'external', 'img:1', '[]', ?, ?)`,
      [timestamp, timestamp]
    );
    const serverId = Number(serverResult.lastID);

    const viewerSet = ['server.command.send', 'container.logs.read', 'fs.read', 'backups.read', 'scheduledtasks.read'];
    const operatorSet = [
      'server.edit', 'server.command.send', 'container.logs.read', 'server.power', 'server.env',
      'fs.read', 'fs.write', 'container.terminal', 'backups.read', 'backups.download',
      'backups.create', 'scheduledtasks.read',
    ];
    const customSet = ['server.power', 'backups.delete'];

    const insertMember = async (userId: number, perms: string[]): Promise<void> => {
      await db.run(
        `INSERT INTO server_members (server_id, user_id, permissions_json, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)`,
        [serverId, userId, JSON.stringify(perms), timestamp, timestamp]
      );
    };

    await insertMember(managerId, viewerSet);
    await insertMember(superId, operatorSet);
    await insertMember(oddId, customSet);
    await insertMember(emptyId, []);

    // Snapshot legacy effective permissions.
    const legacyUsers = await db.all<Array<{ id: number; is_root: number; global_permissions_json: string }>>(
      'SELECT id, is_root, global_permissions_json FROM users'
    );
    const legacyMembers = await db.all<
      Array<{ server_id: number; user_id: number; permissions_json: string }>
    >('SELECT server_id, user_id, permissions_json FROM server_members');

    const legacyGlobal = new Map(legacyUsers.map((u) => [u.id, parsePermissionsJson(u.global_permissions_json)]));
    const legacyServer = new Map(
      legacyMembers.map((m) => [`${m.server_id}:${m.user_id}`, parsePermissionsJson(m.permissions_json)])
    );

    await introduceRbacRoles.up(db);

    // Recompute effective permissions through the role tables.
    const rolePerms = await db.all<Array<{ role_id: number; permissions_json: string }>>(
      'SELECT id AS role_id, permissions_json FROM roles'
    );
    const permsByRole = new Map(rolePerms.map((row) => [row.role_id, parsePermissionsJson(row.permissions_json)]));

    const globalAssignments = await db.all<Array<{ user_id: number; role_id: number }>>(
      'SELECT user_id, role_id FROM user_roles'
    );
    const memberAssignments = await db.all<
      Array<{ server_id: number; user_id: number; role_id: number }>
    >('SELECT server_id, user_id, role_id FROM server_member_roles');

    const migratedGlobal = new Map<number, string[]>();
    for (const row of globalAssignments) {
      const acc = migratedGlobal.get(row.user_id) ?? [];
      acc.push(...(permsByRole.get(row.role_id) ?? []));
      migratedGlobal.set(row.user_id, acc);
    }

    const migratedServer = new Map<string, string[]>();
    for (const row of memberAssignments) {
      const key = `${row.server_id}:${row.user_id}`;
      const acc = migratedServer.get(key) ?? [];
      acc.push(...(permsByRole.get(row.role_id) ?? []));
      migratedServer.set(key, acc);
    }

    // Every non-root user keeps exactly the same effective permissions.
    for (const user of legacyUsers) {
      if (user.is_root) {
        expect(migratedGlobal.get(user.id) ?? []).toEqual([]);
        continue;
      }

      const legacy = [...new Set(legacyGlobal.get(user.id) ?? [])].sort();
      const migrated = [...new Set(migratedGlobal.get(user.id) ?? [])].sort();
      expect(migrated, `global permissions of user ${user.id}`).toEqual(legacy);
    }

    for (const membership of legacyMembers) {
      const key = `${membership.server_id}:${membership.user_id}`;
      const legacy = [...new Set(legacyServer.get(key) ?? [])].sort();
      const migrated = [...new Set(migratedServer.get(key) ?? [])].sort();
      expect(migrated, `server permissions of ${key}`).toEqual(legacy);
    }

    // Root got no roles; the system roles the conversion needed exist and are flagged
    // system (the full set of four is seeded at bootstrap, not by the migration).
    expect(await db.get<{ count: number }>('SELECT COUNT(*) AS count FROM user_roles WHERE user_id = ?', [adminId])).toMatchObject({ count: 0 });
    const allSystemRoleNames = ['Administrator', 'Full access', 'Operator', 'Viewer'];
    const systemRoles = await db.all<Array<{ name: string; is_system: number }>>(
      'SELECT name, is_system FROM roles WHERE is_system = 1'
    );
    expect(systemRoles.length).toBeGreaterThan(0);
    for (const role of systemRoles) {
      expect(allSystemRoleNames).toContain(role.name);
    }
    const systemRoleNames = systemRoles.map((r) => r.name);
    expect(systemRoleNames).toContain('Administrator');
    expect(systemRoleNames).toContain('Viewer');
    expect(systemRoleNames).toContain('Operator');
    expect(await db.get<{ count: number }>("SELECT COUNT(*) AS count FROM users WHERE global_permissions_json != '[]'")).toMatchObject({ count: 0 });
    expect(await db.get<{ count: number }>("SELECT COUNT(*) AS count FROM server_members WHERE permissions_json != '[]'")).toMatchObject({ count: 0 });

    await db.close();
  });
});
