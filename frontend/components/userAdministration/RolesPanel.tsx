import { KeyRound, Plus, Settings2 } from 'lucide-react';
import { AppButton, AppCard } from '../../src/ui/components';
import type { PanelRole } from '../../utils/api';

interface RolesPanelProps {
  roles: PanelRole[];
  rolesLoading: boolean;
  setCreateModalOpen: (open: boolean) => void;
  openRoleEdit: (role: PanelRole) => void;
  requestDeleteRole: (role: PanelRole) => void;
  deleteRoleLoading: boolean;
}

const SCOPE_LABELS: Record<PanelRole['scope'], string> = {
  global: 'Panel role',
  server: 'Server role',
};

export function RolesPanel({
  roles,
  rolesLoading,
  setCreateModalOpen,
  openRoleEdit,
  requestDeleteRole,
  deleteRoleLoading,
}: RolesPanelProps) {
  return (
    <AppCard className="p-5 md:p-6">
      <div className="mb-5 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <h2 className="flex items-center gap-2 text-xl font-semibold text-white">
          <KeyRound className="h-5 w-5 text-[var(--color-cyan-400)]" />
          Roles
        </h2>
        <AppButton
          onClick={() => setCreateModalOpen(true)}
          className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-[var(--color-cyan-400)]/55 bg-[#0b1728] px-4 text-sm font-semibold text-[var(--color-cyan-400)] transition-colors hover:border-[var(--color-cyan-400)] hover:text-[var(--color-cyan-400)]"
        >
          <Plus className="h-4 w-4" />
          Create role
        </AppButton>
      </div>

      <div className="space-y-3">
        {roles.length === 0 && !rolesLoading && (
          <p className="text-sm text-gray-400">No roles defined yet.</p>
        )}

        {roles.map((role) => (
          <AppCard key={role.id} className="w-full px-4 py-4">
            <div className="flex items-center justify-between gap-4">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-semibold text-white">{role.name}</span>
                  <span className="rounded border border-gray-600 bg-[#111827] px-2 py-0.5 text-xs text-gray-300">
                    {SCOPE_LABELS[role.scope]}
                  </span>
                  {role.isSystem && (
                    <span className="rounded border border-amber-500/60 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-300">
                      Built-in
                    </span>
                  )}
                  {role.ssoGroups.length > 0 && (
                    <span
                      className="rounded border border-[var(--color-cyan-400)]/40 bg-[#0050D7]/10 px-2 py-0.5 text-xs text-[var(--color-cyan-400)]"
                      title={`SSO groups: ${role.ssoGroups.join(', ')}`}
                    >
                      SSO: {role.ssoGroups.join(', ')}
                    </span>
                  )}
                </div>
                <p className="mt-1 text-sm text-gray-400">
                  {role.permissions.length} permission{role.permissions.length === 1 ? '' : 's'}
                  {role.assignmentCounts
                    ? ` · ${role.assignmentCounts.users} user${role.assignmentCounts.users === 1 ? '' : 's'} · ${role.assignmentCounts.memberships} membership${role.assignmentCounts.memberships === 1 ? '' : 's'}`
                    : ''}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <AppButton
                  type="button"
                  onClick={() => openRoleEdit(role)}
                  className="inline-flex h-10 shrink-0 items-center gap-2 rounded-md border border-gray-600 bg-[#111827] px-3.5 text-sm text-gray-200 hover:border-[var(--color-cyan-400)] hover:text-[var(--color-cyan-400)]"
                >
                  <Settings2 className="h-4 w-4" />
                  Edit
                </AppButton>
                {!role.isSystem && (
                  <AppButton
                    type="button"
                    onClick={() => requestDeleteRole(role)}
                    disabled={deleteRoleLoading}
                    aria-label={`Delete role ${role.name}`}
                    title={`Delete role ${role.name}`}
                    className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-md border border-red-500/45 bg-[#2a1219] text-sm text-red-200 hover:border-red-400 hover:text-red-100 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    ✕
                  </AppButton>
                )}
              </div>
            </div>
          </AppCard>
        ))}
      </div>
    </AppCard>
  );
}
