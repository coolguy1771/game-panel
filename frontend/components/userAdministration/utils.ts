// Permission option groups for the role editor. Labels mirror the backend permission
// catalog (backend/src/permissions.ts); the two files must stay in sync.
export const GLOBAL_OPTIONS = [
  { value: 'users.manage', label: 'Manage users' },
  { value: 'server.install', label: 'Install servers' },
];

export const SERVER_CORE_OPTIONS = [
  { value: 'server.power', label: 'Start/Stop/Restart' },
  { value: 'container.logs.read', label: 'Read server logs' },
  { value: 'server.command.send', label: 'Access server console' },
  { value: 'server.edit', label: 'Edit container properties' },
  { value: 'server.env', label: 'Manage environment variables' },
  { value: 'container.terminal', label: 'Access container terminal' },
  { value: 'server.delete', label: 'Delete server' },
  { value: 'scheduledtasks.read', label: 'View scheduled tasks' },
  { value: 'scheduledtasks.write', label: 'Manage scheduled tasks' },
  { value: 'fs.read', label: 'Read files' },
  { value: 'fs.write', label: 'Write files' },
];

export const SERVER_GENERAL_OPTIONS = SERVER_CORE_OPTIONS.filter((o) =>
  !['fs.read', 'fs.write', 'scheduledtasks.read', 'scheduledtasks.write'].includes(o.value)
);

export const FILE_MANAGER_OPTIONS = [
  { value: 'fs.read', label: 'Read files' },
  { value: 'fs.write', label: 'Write files' },
];

export const SCHEDULED_TASKS_OPTIONS = [
  { value: 'scheduledtasks.read', label: 'View scheduled tasks' },
  { value: 'scheduledtasks.write', label: 'Manage scheduled tasks' },
];

export const BACKUP_OPTIONS = [
  { value: 'backups.read', label: 'View backups' },
  { value: 'backups.create', label: 'Create backups' },
  { value: 'backups.restore', label: 'Restore backups' },
  { value: 'backups.download', label: 'Download backups' },
  { value: 'backups.delete', label: 'Delete backups' },
  { value: 'backups.rename', label: 'Rename backups' },
  { value: 'backups.settings.write', label: 'Edit backup settings' },
];

export const WIPE_OPTIONS = [
  { value: 'server.wipe.soft', label: 'Soft wipe' },
  { value: 'server.wipe.hard', label: 'Hard wipe' },
];

export const CS2_OVHCLOUD_OPTIONS = [
  { value: 'cs2.frameworks.write', label: 'Manage frameworks' },
];

export const MINECRAFT_OVHCLOUD_OPTIONS = [
  { value: 'minecraft.settings.read', label: 'View game config' },
  { value: 'minecraft.settings.write', label: 'Edit game config' },
  { value: 'minecraft.operators.read', label: 'View operators' },
  { value: 'minecraft.operators.write', label: 'Manage operators' },
  { value: 'minecraft.whitelist.read', label: 'View whitelist' },
  { value: 'minecraft.whitelist.write', label: 'Manage whitelist' },
  { value: 'minecraft.bans.read', label: 'View player bans' },
  { value: 'minecraft.bans.write', label: 'Manage player bans' },
  { value: 'minecraft.ip-bans.read', label: 'View IP bans' },
  { value: 'minecraft.ip-bans.write', label: 'Manage IP bans' },
  { value: 'minecraft.addons.read', label: 'View mods / plugins' },
  { value: 'minecraft.addons.write', label: 'Manage mods / plugins' },
];

export const HYTALE_OVHCLOUD_OPTIONS = [
  { value: 'hytale.settings.read', label: 'View game config' },
  { value: 'hytale.settings.write', label: 'Edit game config' },
  { value: 'hytale.mods.read', label: 'View mods' },
  { value: 'hytale.mods.write', label: 'Manage mods' },
];

export const PALWORLD_OVHCLOUD_OPTIONS = [
  { value: 'palworld.settings.read', label: 'View game config' },
  { value: 'palworld.settings.write', label: 'Edit game config' },
];

export const PROJECT_ZOMBOID_OVHCLOUD_OPTIONS = [
  { value: 'project-zomboid.settings.read', label: 'View game config' },
  { value: 'project-zomboid.settings.write', label: 'Edit game config' },
  { value: 'project-zomboid.mods.read', label: 'View mods' },
  { value: 'project-zomboid.mods.write', label: 'Manage mods' },
];

export const RUST_OVHCLOUD_OPTIONS = [
  { value: 'rust.settings.read', label: 'View game config' },
  { value: 'rust.settings.write', label: 'Edit game config' },
  { value: 'rust.mods.read', label: 'View mods' },
  { value: 'rust.mods.write', label: 'Manage mods' },
  { value: 'rust.frameworks.write', label: 'Manage frameworks' },
];

// Valheim is configured through env vars, so it has no valheim.settings.* pair — the
// settings screen is guarded by the generic server.env / server.edit permissions.
export const VALHEIM_OVHCLOUD_OPTIONS = [
  { value: 'valheim.mods.read', label: 'View mods' },
  { value: 'valheim.mods.write', label: 'Manage mods' },
  { value: 'valheim.frameworks.write', label: 'Manage frameworks' },
];

export const MAX_USERS = 10;
