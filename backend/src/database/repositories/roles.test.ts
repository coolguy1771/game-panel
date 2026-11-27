import { PERMISSIONS } from '../../permissions.js';
import type { Database } from 'sqlite';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { closeDatabase, initializeDatabase } from '../init.js';
import { roleRepository, serverMemberRepository, userRepository } from '../index.js';

// Integration tests against the real SQLite stack (temp data dir via vitest.setup.ts).

async function seedRole(name: string, scope: 'global' | 'server', permissions: string[]): Promise<number> {
  return (await roleRepository.create({ name, scope, permissions }))!;
}

beforeAll(async () => {
  await initializeDatabase();
});

afterAll(async () => {
  await closeDatabase();
});

beforeEach(async () => {
  const db = await initializeDatabase();
  await db.run('DELETE FROM user_roles');
  await db.run('DELETE FROM server_member_roles');
  await db.run('DELETE FROM server_members');
  await db.run('DELETE FROM roles WHERE is_system = 0');
  await db.run('DELETE FROM users WHERE is_root = 0');
  await db.run('DELETE FROM game_servers');
});

describe('effective permission resolution through roles', () => {
  it('returns the union of a user\'s global role permissions', async () => {
    const userId = (await userRepository.create('alice', 'x'))!;
    const admins = await seedRole('Admins', 'global', [PERMISSIONS.users.manage]);
    const installers = await seedRole('Installers', 'global', [PERMISSIONS.server.install, PERMISSIONS.users.manage]);

    await roleRepository.setGlobalRoles(userId, [admins, installers]);

    expect(await userRepository.getGlobalPermissions(userId)).toEqual(
      expect.arrayContaining([PERMISSIONS.users.manage, PERMISSIONS.server.install])
    );
    expect(await userRepository.getGlobalPermissions(userId)).toHaveLength(2);
  });

  it('returns empty global permissions for users without roles', async () => {
    const userId = (await userRepository.create('bob', 'x'))!;

    expect(await userRepository.getGlobalPermissions(userId)).toEqual([]);
  });

  it('returns the union of a membership\'s server role permissions', async () => {
    const db = await initializeDatabase();
    const userId = (await userRepository.create('carol', 'x'))!;
    const timestamp = '2026-01-01T00:00:00Z';
    const serverResult = await db.run(
      `INSERT INTO game_servers (name, provider, docker_image, ports_json, created_at, updated_at)
       VALUES ('srv', 'external', 'img:1', '[]', ?, ?)`,
      [timestamp, timestamp]
    );
    const serverId = Number(serverResult.lastID);

    await serverMemberRepository.create(serverId, userId);
    const viewers = await seedRole('Viewers', 'server', [PERMISSIONS.fs.read]);
    const wipers = await seedRole('Wipers', 'server', [PERMISSIONS.fs.write, PERMISSIONS.fs.read]);
    await roleRepository.setServerMemberRoles(serverId, userId, [viewers, wipers]);

    expect(await serverMemberRepository.getUserServerPermissions(serverId, userId)).toEqual(
      expect.arrayContaining([PERMISSIONS.fs.read, PERMISSIONS.fs.write])
    );
    expect(await serverMemberRepository.getUserServerPermissions(serverId, userId)).toHaveLength(2);
  });

  it('listByUser returns effective permissions per membership', async () => {
    const db = await initializeDatabase();
    const userId = (await userRepository.create('dave', 'x'))!;
    const timestamp = '2026-01-01T00:00:00Z';
    const serverResult = await db.run(
      `INSERT INTO game_servers (name, provider, docker_image, ports_json, created_at, updated_at)
       VALUES ('srv2', 'external', 'img:1', '[]', ?, ?)`,
      [timestamp, timestamp]
    );
    const serverId = Number(serverResult.lastID);

    await serverMemberRepository.create(serverId, userId);
    const roleId = await seedRole('Ops', 'server', [PERMISSIONS.server.power]);
    await roleRepository.setServerMemberRoles(serverId, userId, [roleId]);

    const memberships = await serverMemberRepository.listByUser(userId);
    expect(memberships).toHaveLength(1);
    expect(memberships[0].server_id).toBe(serverId);
    expect(memberships[0].permissions).toEqual([PERMISSIONS.server.power]);
  });

  it('rejects duplicate role names within a scope, case-insensitively', async () => {
    await seedRole('Viewer', 'server', [PERMISSIONS.fs.read]);

    await expect(seedRole('viewer', 'server', [PERMISSIONS.fs.write])).rejects.toThrow();
  });

  it('allows the same role name across scopes', async () => {
    await seedRole('Operator', 'server', [PERMISSIONS.server.power]);

    await expect(seedRole('Operator', 'global', [PERMISSIONS.users.manage])).resolves.toBeDefined();
  });
});
