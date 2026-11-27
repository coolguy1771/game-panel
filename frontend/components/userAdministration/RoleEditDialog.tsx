import { AlertCircle, Save, Trash2 } from 'lucide-react';import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '../ui/dialog';
import { AppButton, AppInput, AppSelect, AppToggle } from '../../src/ui/components';
import {
  BACKUP_OPTIONS,
  CS2_OVHCLOUD_OPTIONS,
  FILE_MANAGER_OPTIONS,
  GLOBAL_OPTIONS,
  HYTALE_OVHCLOUD_OPTIONS,
  MINECRAFT_OVHCLOUD_OPTIONS,
  PALWORLD_OVHCLOUD_OPTIONS,
  PROJECT_ZOMBOID_OVHCLOUD_OPTIONS,
  RUST_OVHCLOUD_OPTIONS,
  SCHEDULED_TASKS_OPTIONS,
  SERVER_GENERAL_OPTIONS,
  VALHEIM_OVHCLOUD_OPTIONS,
  WIPE_OPTIONS,
} from './utils';
import type { PanelRole } from '../../utils/api';

const SERVER_PERMISSION_GROUPS = [
  { label: 'General', options: SERVER_GENERAL_OPTIONS },
  { label: 'File Manager', options: FILE_MANAGER_OPTIONS },
  { label: 'Scheduled Tasks', options: SCHEDULED_TASKS_OPTIONS },
  { label: 'Backups', options: BACKUP_OPTIONS },
  { label: 'Wipe', options: WIPE_OPTIONS },
  { label: 'Minecraft', options: MINECRAFT_OVHCLOUD_OPTIONS },
  { label: 'Hytale', options: HYTALE_OVHCLOUD_OPTIONS },
  { label: 'Palworld', options: PALWORLD_OVHCLOUD_OPTIONS },
  { label: 'Project Zomboid', options: PROJECT_ZOMBOID_OVHCLOUD_OPTIONS },
  { label: 'Rust', options: RUST_OVHCLOUD_OPTIONS },
  { label: 'Valheim', options: VALHEIM_OVHCLOUD_OPTIONS },
  { label: 'Counter-Strike 2', options: CS2_OVHCLOUD_OPTIONS },
];

interface RoleEditDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  // null = create mode
  editingRole: PanelRole | null;
  initialName: string;
  initialScope: 'global' | 'server';
  initialPermissions: string[];
  ssoGroupsEnabled: boolean;
  setSsoGroupsEnabled: (enabled: boolean) => void;
  setName: (value: string) => void;
  setScope: (scope: 'global' | 'server') => void;
  togglePermission: (permission: string) => void;
  setSsoGroupsText: (value: string) => void;
  ssoGroupsText: string;
  onSave: () => void;
  onDelete: () => void;
  saveLoading: boolean;
  deleteLoading: boolean;
  error?: string | null;
}

export function RoleEditDialog({
  open,
  onOpenChange,
  editingRole,
  initialName,
  initialScope,
  initialPermissions,
  ssoGroupsEnabled,
  setSsoGroupsEnabled,
  setName,
  setScope,
  togglePermission,
  setSsoGroupsText,
  ssoGroupsText,
  onSave,
  onDelete,
  saveLoading,
  deleteLoading,
  error,
}: RoleEditDialogProps) {
  const isEdit = Boolean(editingRole);
  const isSystem = Boolean(editingRole?.isSystem);

  const permissionGroups =
    initialScope === 'global'
      ? [{ label: 'Panel permissions', options: GLOBAL_OPTIONS.filter((opt) => opt.value !== '*') }]
      : SERVER_PERMISSION_GROUPS;

  // One group per line: identifiers may contain commas (LDAP DNs) and must round-trip
  // exactly as the claim carries them.
  const parsedSsoGroups = ssoGroupsText
    .split('\n')
    .map((group) => group.trim())
    .filter(Boolean);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent dismissible={false} className="w-[94vw] sm:w-[86vw] lg:w-[62vw] max-h-[90vh] sm:max-w-[860px] overflow-hidden border border-gray-700/80 bg-[#0f172a] p-0 text-white">
        <div className="max-h-[90vh] overflow-y-auto hide-scrollbar modal-scrollbar-dark p-6 md:p-7">
          <DialogHeader className="border-b border-gray-800 pb-5 pr-8">
            <DialogTitle className="text-xl text-white">
              {isEdit ? `Edit role: ${editingRole?.name}` : 'Create role'}
            </DialogTitle>
            <DialogDescription className="leading-relaxed text-gray-400">
              A role bundles permissions that can be assigned to users (panel roles) or to server
              memberships (server roles).
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-5 pt-6">
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <label className="block">
                <span className="mb-1.5 block text-sm font-medium text-gray-200">Role name</span>
                <AppInput
                  value={initialName}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="e.g. Operator"
                  name="role-name"
                  autoComplete="off"
                  maxLength={64}
                  className="w-full rounded border border-gray-700 bg-[#1f2937] px-3 py-2 text-sm text-white focus:border-[var(--color-cyan-400)] focus:outline-none"
                />
              </label>
              <label className="block">
                <span className="mb-1.5 block text-sm font-medium text-gray-200">Scope</span>
                <AppSelect
                  value={initialScope}
                  onChange={(next) => setScope(next === 'global' ? 'global' : 'server')}
                  disabled={isEdit}
                  options={[
                    { label: 'Server role (per-server access)', value: 'server' },
                    { label: 'Panel role (global access)', value: 'global' },
                  ]}
                  className="w-full rounded-lg border border-gray-700 bg-[#0b1220] px-3 py-2 text-sm text-white"
                />
                {isEdit && (
                  <span className="mt-1 block text-xs text-gray-500">Scope cannot be changed after creation.</span>
                )}
              </label>
            </div>

            <div className="space-y-4">
              <span className="block text-sm font-medium text-gray-200">Permissions in this role</span>
              {permissionGroups.map(({ label, options }) => (
                <div key={label}>
                  <span className="mb-2 block text-xs font-medium text-gray-400">{label}</span>
                  <div className="grid grid-cols-1 gap-2 md:grid-cols-2 lg:grid-cols-3">
                    {options.map((opt) => {
                      const checked = initialPermissions.includes(opt.value);
                      return (
                        <AppToggle
                          key={`${initialScope}-${opt.value}`}
                          ariaLabel={opt.label}
                          checked={checked}
                          size="compact"
                          onChange={() => togglePermission(opt.value)}
                          label={opt.label}
                          className={`w-full flex-row-reverse justify-between rounded border px-3 py-2 transition-colors ${
                            checked
                              ? 'border-[var(--color-cyan-400)]/50 bg-[#0050D7]/10'
                              : 'border-gray-700 bg-[#111827]'
                          }`}
                        />
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>

            {initialScope === 'global' && (
              <div className="rounded-lg border border-gray-700 bg-[#111827] p-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-medium text-gray-200">Managed by SSO</p>
                    <p className="mt-0.5 text-xs text-gray-500">
                      Map identity-provider groups to this role. Members are synced at every SSO
                      login and cannot be assigned manually.
                    </p>
                  </div>
                  <AppToggle
                    ariaLabel="Managed by SSO"
                    checked={ssoGroupsEnabled}
                    size="compact"
                    onChange={() => setSsoGroupsEnabled(!ssoGroupsEnabled)}
                  />
                </div>
                {ssoGroupsEnabled && (
                  <div className="mt-3">
                    <label htmlFor="role-sso-groups" className="mb-1 block text-xs font-medium text-gray-300">
                      Identity provider groups
                    </label>
                    <textarea
                      id="role-sso-groups"
                      value={ssoGroupsText}
                      onChange={(event) => setSsoGroupsText(event.target.value)}
                      placeholder={'group-a\ngroup-b'}
                      name="role-sso-groups"
                      autoComplete="off"
                      rows={3}
                      className="w-full rounded border border-gray-700 bg-[#0f172a] px-3 py-2 text-sm text-white focus:border-[var(--color-cyan-400)] focus:outline-none"
                    />
                    <p className="mt-1 text-xs text-gray-500">
                      One group per line, exactly as the identity provider sends it.
                    </p>
                    {parsedSsoGroups.length > 0 && (
                      <p className="mt-1 text-xs text-gray-500">
                        Claims group value must match exactly: {parsedSsoGroups.join(', ')}
                      </p>
                    )}
                  </div>
                )}
              </div>
            )}

            {error && (
              <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">
                <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <div className="flex flex-col gap-2 border-t border-gray-800 pt-4 sm:flex-row sm:items-center">
              {isEdit && !isSystem && (
                <AppButton
                  type="button"
                  onClick={onDelete}
                  disabled={saveLoading || deleteLoading}
                  className="inline-flex items-center gap-2 rounded border border-red-500/45 bg-[#2a1219] px-3 py-2 text-sm text-red-200 hover:border-red-400 hover:text-red-100 disabled:opacity-60 sm:mr-auto"
                >
                  <Trash2 className="h-4 w-4" />
                  {deleteLoading ? 'Deleting…' : 'Delete role'}
                </AppButton>
              )}
              {isEdit && isSystem && (
                <span className="text-xs text-gray-500 sm:mr-auto">Built-in roles cannot be deleted.</span>
              )}
              <div className="flex flex-1 flex-col-reverse gap-2 sm:flex-row sm:justify-end">
                <AppButton
                  type="button"
                  onClick={() => onOpenChange(false)}
                  disabled={saveLoading || deleteLoading}
                  className="rounded bg-gray-700 px-4 py-2 text-sm text-white hover:bg-gray-600 disabled:opacity-60"
                >
                  Cancel
                </AppButton>
                <AppButton
                  type="button"
                  tone="primary"
                  onClick={onSave}
                  disabled={saveLoading || deleteLoading}
                  className="inline-flex items-center justify-center gap-2 rounded px-4 py-2 text-sm font-medium disabled:opacity-60"
                >
                  <Save className="h-4 w-4" />
                  {saveLoading ? 'Saving…' : isEdit ? 'Save role' : 'Create role'}
                </AppButton>
              </div>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
