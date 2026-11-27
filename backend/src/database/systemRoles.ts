import { ASSIGNABLE_SERVER_PERMISSIONS, PERMISSIONS } from '../permissions.js';

export type RoleScope = 'global' | 'server';

export type SystemRoleDefinition = {
  name: string;
  scope: RoleScope;
  permissions: string[];
};

export const SYSTEM_ROLE_KEYS = {
  administrator: 'system:global:Administrator',
  viewer: 'system:server:Viewer',
  operator: 'system:server:Operator',
  fullAccess: 'system:server:Full access',
} as const;

// Mirrors the permission sets of the frontend presets in
// frontend/components/userAdministration/utils.ts (SERVER_PRESETS). The two files must stay
// in sync: these roles are seeded at bootstrap and used by migration 0002 to convert
// existing grants into roles.
export const SYSTEM_ROLES: SystemRoleDefinition[] = [
  {
    name: 'Administrator',
    scope: 'global',
    permissions: [PERMISSIONS.users.manage, PERMISSIONS.server.install],
  },
  {
    name: 'Viewer',
    scope: 'server',
    permissions: [
      PERMISSIONS.server.commandSend,
      PERMISSIONS.container.logsRead,
      PERMISSIONS.fs.read,
      PERMISSIONS.backups.read,
      PERMISSIONS.scheduledTasks.read,
    ],
  },
  {
    name: 'Operator',
    scope: 'server',
    permissions: [
      PERMISSIONS.server.edit,
      PERMISSIONS.server.commandSend,
      PERMISSIONS.container.logsRead,
      PERMISSIONS.server.power,
      PERMISSIONS.server.env,
      PERMISSIONS.fs.read,
      PERMISSIONS.fs.write,
      PERMISSIONS.container.terminal,
      PERMISSIONS.backups.read,
      PERMISSIONS.backups.download,
      PERMISSIONS.backups.create,
      PERMISSIONS.scheduledTasks.read,
    ],
  },
  {
    name: 'Full access',
    scope: 'server',
    permissions: [...ASSIGNABLE_SERVER_PERMISSIONS],
  },
];
