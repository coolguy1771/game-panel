import { describe, expect, it } from 'vitest';
import {
  planRbacConversion,
  type ParsedMembershipRow,
  type ParsedUserRow,
} from './rbacConversion.js';
import { SYSTEM_ROLE_KEYS } from '../systemRoles.js';

function user(id: number, globalPermissions: string[], isRoot = false): ParsedUserRow {
  return { id, isRoot, globalPermissions };
}

function membership(serverId: number, userId: number, permissions: string[]): ParsedMembershipRow {
  return { serverId, userId, permissions };
}

describe('planRbacConversion', () => {
  it('creates no roles and no assignments when everything is empty', () => {
    const plan = planRbacConversion([user(1, [])], [membership(10, 1, [])]);

    expect(plan.roles).toEqual([]);
    expect(plan.userRoleAssignments).toEqual([]);
    expect(plan.memberRoleAssignments).toEqual([]);
  });

  it('maps the full global set to the system Administrator role', () => {
    const plan = planRbacConversion(
      [user(1, ['server.install', 'users.manage'])],
      []
    );

    expect(plan.roles).toHaveLength(1);
    expect(plan.roles[0]).toMatchObject({
      key: SYSTEM_ROLE_KEYS.administrator,
      name: 'Administrator',
      scope: 'global',
      isSystem: true,
    });
    expect(plan.userRoleAssignments).toEqual([{ userId: 1, roleKey: SYSTEM_ROLE_KEYS.administrator }]);
  });

  it('shares one imported global role between users with identical sets', () => {
    const plan = planRbacConversion(
      [user(1, ['users.manage']), user(2, ['users.manage'])],
      []
    );

    expect(plan.roles).toHaveLength(1);
    expect(plan.roles[0]).toMatchObject({ name: 'Imported role 1', scope: 'global', isSystem: false });
    expect(plan.userRoleAssignments).toEqual([
      { userId: 1, roleKey: plan.roles[0].key },
      { userId: 2, roleKey: plan.roles[0].key },
    ]);
  });

  it('maps membership presets to system server roles and custom sets to imported ones', () => {
    const viewerSet = ['container.logs.read', 'fs.read', 'scheduledtasks.read', 'backups.read', 'server.command.send'];
    const customSet = ['server.power', 'fs.write'];

    const plan = planRbacConversion(
      [],
      [
        membership(10, 1, viewerSet),
        membership(11, 2, viewerSet),
        membership(12, 3, customSet),
      ]
    );

    const byKey = new Map(plan.roles.map((role) => [role.key, role]));
    expect(byKey.get(SYSTEM_ROLE_KEYS.viewer)).toMatchObject({ scope: 'server', isSystem: true });
    expect(byKey.get('imported:server:1')).toMatchObject({ name: 'Imported server role 1', scope: 'server' });
    expect(plan.memberRoleAssignments).toEqual([
      { serverId: 10, userId: 1, roleKey: SYSTEM_ROLE_KEYS.viewer },
      { serverId: 11, userId: 2, roleKey: SYSTEM_ROLE_KEYS.viewer },
      { serverId: 12, userId: 3, roleKey: 'imported:server:1' },
    ]);
  });

  it('skips root users entirely', () => {
    const plan = planRbacConversion([user(1, ['users.manage'], true)], []);

    expect(plan.roles).toEqual([]);
    expect(plan.userRoleAssignments).toEqual([]);
  });

  it('numbers imported roles deterministically regardless of input order', () => {
    const a = planRbacConversion(
      [user(1, ['users.manage']), user(2, ['server.install'])],
      []
    );
    const b = planRbacConversion(
      [user(2, ['server.install']), user(1, ['users.manage'])],
      []
    );

    const aNames = a.roles.map((role) => `${role.name}:${role.permissions.slice().sort().join(',')}`);
    const bNames = b.roles.map((role) => `${role.name}:${role.permissions.slice().sort().join(',')}`);
    expect(aNames).toEqual(bNames);
  });
});
