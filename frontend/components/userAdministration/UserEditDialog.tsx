import { useState } from 'react';
import { AlertCircle, Eye, EyeOff, Save, ShieldCheck } from 'lucide-react';
import { X } from 'lucide-react';
import { Dialog, DialogContent } from '../ui/dialog';
import { AppButton, AppInput, AppSelect, AppToggle } from '../../src/ui/components';
import type { PanelRole } from '../../utils/api';

interface SelectedUserRef {
  id: number;
  isRoot: boolean;
}

interface UserEditDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  selectedUser: SelectedUserRef | null;
  username: string;
  setUsername: (value: string) => void;
  enabled: boolean;
  setEnabled: (value: boolean) => void;
  newPassword: string;
  setNewPassword: (value: string) => void;
  newPasswordConfirm: string;
  setNewPasswordConfirm: (value: string) => void;
  globalRoles: PanelRole[];
  selectedGlobalRoleIds: number[];
  onToggleGlobalRole: (roleId: number) => void;
  serverRoles: PanelRole[];
  selectedServerRoleIds: number[];
  onToggleServerRole: (roleId: number) => void;
  selectedServerId: string;
  setSelectedServerId: (serverId: string) => void;
  servers: Array<{ id: string; name: string; provider?: string; catalogId?: string }>;
  membersError: string | null;
  onSaveChanges: () => void;
  saveLoading: boolean;
  saveError?: string | null;
}

function RoleToggle({
  role,
  checked,
  onChange,
}: {
  role: PanelRole;
  checked: boolean;
  onChange: () => void;
}) {
  const ssoManaged = role.ssoGroups.length > 0;

  return (
    <AppToggle
      ariaLabel={role.name}
      checked={checked}
      size="compact"
      disabled={ssoManaged}
      onChange={onChange}
      label={ssoManaged ? `${role.name} (managed by SSO)` : role.name}
      className={`w-full flex-row-reverse justify-between rounded border px-3 py-2 transition-colors ${
        ssoManaged
          ? 'cursor-not-allowed border-gray-700/60 bg-[#111827]/60 text-gray-500'
          : checked
            ? 'border-[var(--color-cyan-400)]/50 bg-[#0050D7]/10'
            : 'border-gray-700 bg-[#111827]'
      }`}
    />
  );
}

export function UserEditDialog({
  open,
  onOpenChange,
  selectedUser,
  username,
  setUsername,
  enabled,
  setEnabled,
  newPassword,
  setNewPassword,
  newPasswordConfirm,
  setNewPasswordConfirm,
  globalRoles,
  selectedGlobalRoleIds,
  onToggleGlobalRole,
  serverRoles,
  selectedServerRoleIds,
  onToggleServerRole,
  selectedServerId,
  setSelectedServerId,
  servers,
  membersError,
  onSaveChanges,
  saveLoading,
  saveError,
}: UserEditDialogProps) {
  const [showPassword, setShowPassword] = useState(false);
  const [showPasswordConfirm, setShowPasswordConfirm] = useState(false);

  const selectedServer = servers.find((server) => server.id === selectedServerId);
  const selectedServerName = selectedServer?.name || 'this server';
  const isBusy = saveLoading;

  const accessSummary =
    selectedServerRoleIds.length === 0
      ? 'No access'
      : serverRoles
          .filter((role) => selectedServerRoleIds.includes(role.id))
          .map((role) => role.name)
          .join(', ');

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent dismissible={false} className="w-[94vw] sm:w-[86vw] lg:w-[68vw] xl:w-[62vw] max-h-[90vh] sm:max-w-[920px] xl:max-w-[980px] overflow-hidden border border-gray-700/80 bg-[#0f172a] p-0 text-white">
        <div className="flex justify-end border-b border-gray-800 px-4 py-2">
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            className="rounded p-1.5 text-gray-400 hover:bg-gray-700 hover:text-white transition-colors"
            aria-label="Close"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="max-h-[calc(90vh-44px)] overflow-y-auto hide-scrollbar modal-scrollbar-dark p-4 md:p-5">

          {!selectedUser && <p className="pt-0 text-sm text-gray-400">No user selected.</p>}
          {selectedUser &&
            (selectedUser.isRoot ? (
              <div className="pt-0">
                <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
                  Super Admin account cannot be edited or deleted here.
                </div>
              </div>
            ) : (
              <div className="space-y-5 pt-0">
                <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                  <section className="rounded-lg border border-gray-700 bg-[#1f2937] p-4">
                    <h3 className="text-lg font-semibold text-white">User configuration</h3>
                    <div className="mt-3 space-y-4">
                      <div className="inline-flex items-center gap-3 rounded-lg border border-gray-700 bg-[#111827] px-3 py-2 text-sm text-gray-200">
                        <AppToggle
                          ariaLabel="Account enabled"
                          checked={enabled}
                          size="compact"
                          onChange={setEnabled}
                        />
                        <span>Account enabled</span>
                      </div>

                      <label className="block">
                        <span className="mb-1.5 block text-sm font-medium text-gray-200">User name</span>
                        <AppInput
                          name="edit-user-username"
                          autoComplete="off"
                          value={username}
                          onChange={(event) => setUsername(event.target.value)}
                          placeholder="Username"
                          className="prevent-autofill w-full rounded border border-gray-700 bg-[#0f172a] px-3 py-2 text-sm text-white"
                        />
                      </label>

                      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                        <label className="block">
                          <span className="mb-1.5 block text-sm font-medium text-gray-200">
                            New password
                          </span>
                          <div className="relative">
                            <AppInput
                              type={showPassword ? 'text' : 'password'}
                              name={`reset-password-${selectedUser.id}`}
                              autoComplete="new-password"
                              data-lpignore="true"
                              data-1p-ignore="true"
                              value={newPassword}
                              onChange={(event) => setNewPassword(event.target.value)}
                              placeholder="New password"
                              className="prevent-autofill w-full rounded border border-gray-700 bg-[#0f172a] px-3 py-2 pr-10 text-sm text-white"
                            />
                            <button type="button" tabIndex={-1} onClick={() => setShowPassword(s => !s)}
                              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200 transition-colors">
                              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                          </div>
                        </label>
                        <label className="block">
                          <span className="mb-1.5 block text-sm font-medium text-gray-200">
                            Retype new password
                          </span>
                          <div className="relative">
                            <AppInput
                              type={showPasswordConfirm ? 'text' : 'password'}
                              name={`reset-password-confirm-${selectedUser.id}`}
                              autoComplete="new-password"
                              data-lpignore="true"
                              data-1p-ignore="true"
                              value={newPasswordConfirm}
                              onChange={(event) => setNewPasswordConfirm(event.target.value)}
                              placeholder="Retype password"
                              className="prevent-autofill w-full rounded border border-gray-700 bg-[#0f172a] px-3 py-2 pr-10 text-sm text-white"
                            />
                            <button type="button" tabIndex={-1} onClick={() => setShowPasswordConfirm(s => !s)}
                              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200 transition-colors">
                              {showPasswordConfirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                          </div>
                        </label>
                      </div>
                    </div>
                  </section>

                  <section className="rounded-lg border border-gray-700 bg-[#1f2937] p-4">
                    <h3 className="text-lg font-semibold text-white">Panel roles</h3>
                    <p className="mt-1 text-sm text-gray-400">
                      Roles bundle permissions; they apply across the whole panel.
                    </p>
                    <div className="mt-3 space-y-2">
                      {globalRoles.map((role) => (
                        <RoleToggle
                          key={`global-role-${role.id}`}
                          role={role}
                          checked={selectedGlobalRoleIds.includes(role.id)}
                          onChange={() => onToggleGlobalRole(role.id)}
                        />
                      ))}
                      {globalRoles.length === 0 && (
                        <p className="text-sm text-gray-400">No panel roles defined yet.</p>
                      )}
                    </div>
                  </section>
                </div>

                <section className="rounded-lg border border-gray-700 bg-[#1f2937] p-4">
                  <h3 className="text-lg font-semibold text-white">Server access for this user</h3>
                  <p className="mt-1 text-sm text-gray-400">
                    Pick the roles this user holds on the selected server.
                  </p>

                  {membersError && (
                    <div className="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
                      {membersError}
                    </div>
                  )}

                  <div className="mt-4 space-y-4">
                    <div>
                      <label className="mb-1.5 block text-sm font-medium text-gray-200">
                        Select server
                      </label>
                      <AppSelect
                        value={selectedServerId}
                        onChange={(nextValue) => setSelectedServerId(nextValue)}
                        options={servers.map((server) => ({
                          label: server.name,
                          value: server.id,
                        }))}
                        className="w-full rounded-lg border border-gray-700 bg-[#0b1220] px-3 py-2 text-sm text-white"
                      />
                    </div>

                    <div className="rounded-lg border border-gray-700/70 bg-[#111827] px-3 py-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs text-gray-400">Current access</span>
                        <span
                          className={`truncate rounded-full border px-2 py-0.5 text-xs ${
                            selectedServerRoleIds.length > 0
                              ? 'border-[var(--color-cyan-400)]/40 bg-[#0050D7]/10 text-[var(--color-cyan-400)]'
                              : 'border-gray-600 bg-[#0f172a] text-gray-300'
                          }`}
                        >
                          {accessSummary}
                        </span>
                      </div>
                    </div>

                    <div>
                      <p className="text-sm font-medium text-gray-200">
                        Roles on <span className="text-white">{selectedServerName}</span>
                      </p>
                      <div className="mt-2 space-y-2">
                        {serverRoles.map((role) => (
                          <RoleToggle
                            key={`server-role-${role.id}`}
                            role={role}
                            checked={selectedServerRoleIds.includes(role.id)}
                            onChange={() => onToggleServerRole(role.id)}
                          />
                        ))}
                        {serverRoles.length === 0 && (
                          <p className="text-sm text-gray-400">No server roles defined yet.</p>
                        )}
                      </div>
                      <p className="mt-3 flex items-center gap-2 text-xs text-gray-500">
                        <ShieldCheck className="h-3.5 w-3.5" />
                        Roles marked “managed by SSO” are granted automatically from your identity provider and cannot be assigned here.
                      </p>
                    </div>
                  </div>
                </section>

                <div className="flex flex-col gap-3 border-t border-gray-800 pt-4 sm:flex-row sm:items-center sm:justify-end">
                  {saveError && (
                    <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300 sm:mr-auto">
                      <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0" />
                      <span>{saveError}</span>
                    </div>
                  )}
                  <div className="flex items-center justify-end gap-2">
                  <AppButton
                    type="button"
                    onClick={() => onOpenChange(false)}
                    disabled={isBusy}
                    className="rounded bg-gray-700 px-4 py-2 text-sm text-white hover:bg-gray-600 disabled:opacity-60"
                  >
                    Cancel
                  </AppButton>
                  <AppButton
                    type="button"
                    tone="primary"
                    onClick={onSaveChanges}
                    disabled={isBusy}
                    className="inline-flex items-center gap-2 rounded px-4 py-2 text-sm font-medium disabled:opacity-60"
                  >
                    <Save className="h-4 w-4" />
                    {saveLoading ? 'Saving...' : 'Save changes'}
                  </AppButton>
                  </div>
                </div>
              </div>
            ))}
        </div>
      </DialogContent>
    </Dialog>
  );
}
