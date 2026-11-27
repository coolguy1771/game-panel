import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  RefreshCw,
} from 'lucide-react';
import { apiClient, type PanelRole } from '../utils/api';
import { CreateUserDialog } from './userAdministration/CreateUserDialog';
import { UserEditDialog } from './userAdministration/UserEditDialog';
import { RoleEditDialog } from './userAdministration/RoleEditDialog';
import { RolesPanel } from './userAdministration/RolesPanel';
import { ConfirmationModal } from './ConfirmationModal';
import { UsersPanel } from './userAdministration/UsersPanel';
import { AppButton } from '../src/ui/components';
import { MAX_USERS } from './userAdministration/utils';

interface UserAdministrationProps {
  servers: Array<{ id: string; name: string; provider?: string; catalogId?: string }>;
  currentUserId?: number | null;
  canManageUsers?: boolean;
}

interface PanelUser {
  id: number;
  username: string;
  isRoot: boolean;
  isEnabled: boolean;
  roles: Array<{ id: number; name: string }>;
}

interface ServerMember {
  id: number;
  serverId: number;
  userId: number;
  username: string;
  roles: Array<{ id: number; name: string }>;
}

function apiError(error: unknown, fallback: string): string {
  const responseError = (error as { response?: { data?: { error?: string } } })?.response?.data?.error;
  return responseError || fallback;
}

function sameIdSet(a: number[], b: number[]): boolean {
  const left = [...new Set(a)].sort((x, y) => x - y);
  const right = [...new Set(b)].sort((x, y) => x - y);
  return left.length === right.length && left.every((id, index) => id === right[index]);
}

export function UserAdministration({
  servers,
  currentUserId = null,
  canManageUsers = true,
}: UserAdministrationProps) {
  const [users, setUsers] = useState<PanelUser[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [usersError, setUsersError] = useState<string | null>(null);

  const [roles, setRoles] = useState<PanelRole[]>([]);
  const [rolesLoading, setRolesLoading] = useState(false);
  const [rolesError, setRolesError] = useState<string | null>(null);

  const [createUsername, setCreateUsername] = useState('');
  const [createPassword, setCreatePassword] = useState('');
  const [createPasswordConfirm, setCreatePasswordConfirm] = useState('');
  const [createLoading, setCreateLoading] = useState(false);
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [editModalOpen, setEditModalOpen] = useState(false);

  const [selectedUserId, setSelectedUserId] = useState<number | null>(null);
  const [username, setUsername] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [selectedGlobalRoleIds, setSelectedGlobalRoleIds] = useState<number[]>([]);
  const [saveEditLoading, setSaveEditLoading] = useState(false);
  const [deleteUserLoading, setDeleteUserLoading] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [newPasswordConfirm, setNewPasswordConfirm] = useState('');

  const [selectedServerId, setSelectedServerId] = useState('');
  const [members, setMembers] = useState<ServerMember[]>([]);
  const [membersLoading, setMembersLoading] = useState(false);
  const [membersError, setMembersError] = useState<string | null>(null);
  // Member responses are scoped to the server that was selected when they were requested;
  // late responses for a previous server never replace the current list.
  const selectedServerIdRef = useRef('');

  const [addMemberUserId, setAddMemberUserId] = useState('');
  const [selectedServerRoleIds, setSelectedServerRoleIds] = useState<number[]>([]);

  const [roleModalOpen, setRoleModalOpen] = useState(false);
  const [editingRole, setEditingRole] = useState<PanelRole | null>(null);
  const [roleName, setRoleName] = useState('');
  const [roleScope, setRoleScope] = useState<'global' | 'server'>('server');
  const [rolePermissions, setRolePermissions] = useState<string[]>([]);
  const [ssoGroupsEnabled, setSsoGroupsEnabled] = useState(false);
  const [ssoGroupsText, setSsoGroupsText] = useState('');
  const [roleSaveLoading, setRoleSaveLoading] = useState(false);
  const [roleDeleteLoading, setRoleDeleteLoading] = useState(false);
  const [roleError, setRoleError] = useState<string | null>(null);
  const [roleDeleteConfirm, setRoleDeleteConfirm] = useState<
    | { open: false }
    | { open: true; roleId: number; roleName: string }
  >({ open: false });

  const [deleteUserConfirm, setDeleteUserConfirm] = useState<
    | { open: false }
    | {
        open: true;
        userId: number;
        username: string;
      }
  >({ open: false });

  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string } | null>(
    null
  );
  const [createError, setCreateError] = useState<string | null>(null);
  const [editError, setEditError] = useState<string | null>(null);

  const selectedUser = useMemo(
    () => users.find((u) => u.id === selectedUserId) ?? null,
    [users, selectedUserId]
  );
  const highlightedUserId = currentUserId ?? selectedUserId;
  const accessDenied = Boolean(usersError?.includes('users.manage'));

  const userLimitReached = users.length >= MAX_USERS;

  const globalRoles = useMemo(() => roles.filter((role) => role.scope === 'global'), [roles]);
  const serverRoles = useMemo(() => roles.filter((role) => role.scope === 'server'), [roles]);

  const loadUsers = useCallback(async () => {
    setUsersLoading(true);
    setUsersError(null);
    try {
      const res = await apiClient.listUsers();
      setUsers(res.users);
      setSelectedUserId((current) =>
        res.users.some((u) => u.id === current) ? current : (res.users[0]?.id ?? null)
      );
    } catch (error) {
      setUsers([]);
      setUsersError(apiError(error, 'Failed to load users.'));
    } finally {
      setUsersLoading(false);
    }
  }, []);

  const loadRoles = useCallback(async () => {
    setRolesLoading(true);
    setRolesError(null);
    try {
      const res = await apiClient.listRoles();
      setRoles(res.roles);
    } catch (error) {
      setRoles([]);
      setRolesError(apiError(error, 'Failed to load roles.'));
    } finally {
      setRolesLoading(false);
    }
  }, []);

  const loadMembers = useCallback(async (serverId: string) => {
    if (!serverId) return;
    selectedServerIdRef.current = serverId;
    setMembersLoading(true);
    setMembersError(null);
    setMembers([]);
    try {
      const res = await apiClient.getServerMembers(Number(serverId));
      if (selectedServerIdRef.current !== serverId) return; // stale response for a previous server
      setMembers(res.members);
    } catch (error) {
      if (selectedServerIdRef.current !== serverId) return;
      setMembers([]);
      setMembersError(apiError(error, 'Failed to load server access.'));
    } finally {
      if (selectedServerIdRef.current === serverId) {
        setMembersLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    loadUsers();
    loadRoles();
  }, [loadUsers, loadRoles]);

  useEffect(() => {
    if (servers.length === 0) return;
    setSelectedServerId((current) =>
      current && servers.some((s) => s.id === current) ? current : servers[0].id
    );
  }, [servers]);

  useEffect(() => {
    if (!selectedServerId || accessDenied) return;
    loadMembers(selectedServerId);
  }, [selectedServerId, accessDenied, loadMembers]);

  useEffect(() => {
    if (!selectedUser) return;
    setUsername(selectedUser.username);
    setEnabled(selectedUser.isEnabled);
    setSelectedGlobalRoleIds(selectedUser.roles.map((role) => role.id));
    setNewPassword('');
    setNewPasswordConfirm('');
  }, [selectedUser]);

  useEffect(() => {
    if (!addMemberUserId) {
      setSelectedServerRoleIds([]);
      return;
    }
    const existing = members.find((m) => String(m.userId) === addMemberUserId);
    setSelectedServerRoleIds(existing ? existing.roles.map((role) => role.id) : []);
  }, [addMemberUserId, members, selectedServerId]);

  const resetCreateForm = useCallback(() => {
    setCreateUsername('');
    setCreatePassword('');
    setCreatePasswordConfirm('');
  }, []);

  const handleCreateUser = async () => {
    if (userLimitReached) {
      setCreateError(`User limit reached (${MAX_USERS} max).`);
      return;
    }
    const usernameValue = createUsername.trim();
    if (!usernameValue || !createPassword || !createPasswordConfirm) {
      setCreateError('Username and password are required.');
      return;
    }
    if (createPassword.length < 8) {
      setCreateError('Password must be at least 8 characters.');
      return;
    }
    if (createPassword !== createPasswordConfirm) {
      setCreateError('Password confirmation does not match.');
      return;
    }
    setCreateLoading(true);
    setCreateError(null);
    try {
      const res = await apiClient.createUser(
        usernameValue,
        createPassword,
        createPasswordConfirm
      );
      resetCreateForm();
      setCreateModalOpen(false);
      await loadUsers();
      if (typeof res.user?.id === 'number') {
        setSelectedUserId(res.user.id);
      }
      setFeedback({
        type: 'success',
        text: `User ${res.user?.username || usernameValue} created successfully.`,
      });
    } catch (error) {
      setCreateError(apiError(error, 'Failed to create user.'));
    } finally {
      setCreateLoading(false);
    }
  };

  useEffect(() => {
    if (!createModalOpen) return;
    setCreateError(null);
    resetCreateForm();
  }, [createModalOpen, resetCreateForm]);

  const handleSaveEdit = async () => {
    if (!selectedUser) return;
    if (selectedUser.isRoot) {
      setEditError('Super Admin account cannot be edited here.');
      return;
    }
    // The membership draft is only trustworthy once the selected server's list has loaded.
    if (membersLoading) return;

    const trimmedUsername = username.trim();
    if (!trimmedUsername) {
      setEditError('Username is required.');
      return;
    }

    const shouldResetPassword = newPassword.length > 0 || newPasswordConfirm.length > 0;
    if (shouldResetPassword) {
      if (newPassword.length < 8) {
        setEditError('Password must be at least 8 characters.');
        return;
      }
      if (!newPasswordConfirm) {
        setEditError('Please confirm the new password.');
        return;
      }
      if (newPassword !== newPasswordConfirm) {
        setEditError('Password confirmation does not match.');
        return;
      }
    }

    setSaveEditLoading(true);
    setEditError(null);
    try {
      await apiClient.updateUser(selectedUser.id, {
        username: trimmedUsername,
        isEnabled: enabled,
        roleIds: selectedGlobalRoleIds,
      });

      if (shouldResetPassword) {
        await apiClient.resetUserPassword(selectedUser.id, newPassword);
      }

      if (selectedServerId) {
        const selectedUserMember =
          members.find((member) => String(member.userId) === String(selectedUser.id)) ?? null;

        if (selectedServerRoleIds.length === 0) {
          if (selectedUserMember) {
            await apiClient.removeServerMember(Number(selectedServerId), selectedUser.id);
          }
        } else if (!selectedUserMember) {
          await apiClient.addServerMember(Number(selectedServerId), selectedUser.id, selectedServerRoleIds);
        } else if (!sameIdSet(selectedUserMember.roles.map((role) => role.id), selectedServerRoleIds)) {
          await apiClient.updateServerMember(
            Number(selectedServerId),
            selectedUser.id,
            selectedServerRoleIds
          );
        }
      }

      await loadUsers();
      if (selectedServerId) {
        await loadMembers(selectedServerId);
      }
      setNewPassword('');
      setNewPasswordConfirm('');
      setEditModalOpen(false);
      setFeedback({ type: 'success', text: 'User changes saved successfully.' });
    } catch (error) {
      setEditError(apiError(error, 'Failed to save user changes.'));
    } finally {
      setSaveEditLoading(false);
    }
  };

  const requestDeleteUser = (user: PanelUser) => {
    if (user.isRoot) {
      setFeedback({ type: 'error', text: 'Super Admin account cannot be deleted.' });
      return;
    }
    setSelectedUserId(user.id);
    setDeleteUserConfirm({
      open: true,
      userId: user.id,
      username: user.username,
    });
  };

  const confirmDeleteUser = async () => {
    if (!deleteUserConfirm.open) return;
    const userId = deleteUserConfirm.userId;
    const usernameToDelete = deleteUserConfirm.username;

    setDeleteUserLoading(true);
    setFeedback(null);
    try {
      await apiClient.deleteUser(userId);
      await loadUsers();
      if (selectedServerId) await loadMembers(selectedServerId);
      setEditModalOpen(false);
      setFeedback({ type: 'success', text: `User ${usernameToDelete} deleted.` });
    } catch (error) {
      setFeedback({ type: 'error', text: apiError(error, 'Failed to delete user.') });
    } finally {
      setDeleteUserLoading(false);
      setDeleteUserConfirm({ open: false });
    }
  };

  const openRoleCreate = () => {
    setEditingRole(null);
    setRoleName('');
    setRoleScope('server');
    setRolePermissions([]);
    setSsoGroupsEnabled(false);
    setSsoGroupsText('');
    setRoleError(null);
    setRoleModalOpen(true);
  };

  const openRoleEdit = (role: PanelRole) => {
    setEditingRole(role);
    setRoleName(role.name);
    setRoleScope(role.scope);
    setRolePermissions([...role.permissions]);
    setSsoGroupsEnabled(role.ssoGroups.length > 0);
    setSsoGroupsText(role.ssoGroups.join('\n'));
    setRoleError(null);
    setRoleModalOpen(true);
  };

  // One group per line: group identifiers may legitimately contain commas (LDAP DNs), so
  // commas are never treated as separators.
  const parseSsoGroups = (): string[] =>
    [...new Set(
      ssoGroupsText
        .split('\n')
        .map((group) => group.trim())
        .filter(Boolean)
    )];

  const handleSaveRole = async () => {
    const trimmedName = roleName.trim();
    if (!trimmedName) {
      setRoleError('Role name is required.');
      return;
    }
    if (trimmedName.length > 64) {
      setRoleError('Role name must be 64 characters or fewer.');
      return;
    }
    const nextSsoGroups = roleScope === 'global' && ssoGroupsEnabled ? parseSsoGroups() : [];
    if (roleScope === 'global' && rolePermissions.length === 0 && nextSsoGroups.length === 0) {
      setRoleError('A role needs at least one permission or SSO group.');
      return;
    }
    if (roleScope === 'server' && rolePermissions.length === 0) {
      setRoleError('A server role needs at least one permission.');
      return;
    }

    setRoleSaveLoading(true);
    setRoleError(null);
    try {
      if (editingRole) {
        await apiClient.updateRole(editingRole.id, {
          name: trimmedName,
          permissions: rolePermissions,
          ssoGroups: roleScope === 'global' ? nextSsoGroups : undefined,
        });
      } else {
        await apiClient.createRole({
          name: trimmedName,
          scope: roleScope,
          permissions: rolePermissions,
          ssoGroups: roleScope === 'global' ? nextSsoGroups : undefined,
        });
      }

      setRoleModalOpen(false);
      await loadRoles();
      setFeedback({
        type: 'success',
        text: editingRole ? `Role ${trimmedName} updated.` : `Role ${trimmedName} created.`,
      });
    } catch (error) {
      setRoleError(apiError(error, 'Failed to save the role.'));
    } finally {
      setRoleSaveLoading(false);
    }
  };

  const requestDeleteRole = (role: PanelRole) => {
    setRoleDeleteConfirm({ open: true, roleId: role.id, roleName: role.name });
  };

  const confirmDeleteRole = async () => {
    if (!roleDeleteConfirm.open) return;
    const { roleId, roleName: name } = roleDeleteConfirm;

    setRoleDeleteLoading(true);
    try {
      await apiClient.deleteRole(roleId);
      // Users still carry the deleted role id in their cached assignments; reload both so
      // the next edit does not submit a deleted id.
      await Promise.all([loadRoles(), loadUsers()]);
      setFeedback({ type: 'success', text: `Role ${name} deleted.` });
      setRoleModalOpen(false);
    } catch (error) {
      setFeedback({ type: 'error', text: apiError(error, 'Failed to delete the role.') });
    } finally {
      setRoleDeleteLoading(false);
      setRoleDeleteConfirm({ open: false });
    }
  };

  const openUserEdit = (user: PanelUser) => {
    if (user.isRoot) {
      setFeedback({ type: 'error', text: 'Super Admin account cannot be edited here.' });
      return;
    }
    setEditError(null);
    setSelectedUserId(user.id);
    setAddMemberUserId(String(user.id));
    setUsername(user.username);
    setEnabled(user.isEnabled);
    setSelectedGlobalRoleIds(user.roles.map((role) => role.id));
    setNewPassword('');
    setNewPasswordConfirm('');
    const existingMember = members.find((m) => String(m.userId) === String(user.id));
    setSelectedServerRoleIds(existingMember ? existingMember.roles.map((role) => role.id) : []);
    setEditModalOpen(true);
  };

  if (!canManageUsers) {
    return null;
  }

  return (
    <div className="mx-auto w-full max-w-[1140px] space-y-6">
      {feedback && (
        <div
          className={`rounded-lg border px-4 py-3 text-sm ${feedback.type === 'success' ? 'border-green-600/40 bg-green-500/10 text-green-700 dark:text-green-300' : 'border-red-600/40 bg-red-500/10 text-red-700 dark:text-red-300'}`}
        >
          <div className="flex items-center gap-2">
            {feedback.type === 'success' ? (
              <CheckCircle2 className="h-4 w-4" />
            ) : (
              <AlertCircle className="h-4 w-4" />
            )}
            <span>{feedback.text}</span>
          </div>
        </div>
      )}

      {usersError && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-red-300">
          <div className="flex items-start gap-3">
            <AlertCircle className="mt-0.5 h-5 w-5" />
            <div className="space-y-2">
              <p className="text-sm">{usersError}</p>
              <AppButton
                onClick={loadUsers}
                className="inline-flex items-center gap-2 rounded bg-red-600 px-3 py-2 text-sm text-white hover:bg-red-500"
              >
                <RefreshCw className="h-4 w-4" />
                Retry
              </AppButton>
            </div>
          </div>
        </div>
      )}

      {!accessDenied && (
        <>
          <CreateUserDialog
            open={createModalOpen}
            onOpenChange={(open) => {
              setCreateModalOpen(open);
              if (!open) {
                setCreateError(null);
                if (!createLoading) {
                  resetCreateForm();
                }
              }
            }}
            createLoading={createLoading}
            userLimitReached={userLimitReached}
            createUsername={createUsername}
            setCreateUsername={setCreateUsername}
            createPassword={createPassword}
            setCreatePassword={setCreatePassword}
            createPasswordConfirm={createPasswordConfirm}
            setCreatePasswordConfirm={setCreatePasswordConfirm}
            onCreateUser={handleCreateUser}
            error={createError}
          />

          <UserEditDialog
            open={editModalOpen}
            onOpenChange={(open) => {
              setEditModalOpen(open);
              if (!open) {
                setNewPassword('');
                setNewPasswordConfirm('');
                setEditError(null);
                if (!deleteUserLoading) {
                  setDeleteUserConfirm({ open: false });
                }
              }
            }}
            selectedUser={
              selectedUser ? { id: selectedUser.id, isRoot: selectedUser.isRoot } : null
            }
            username={username}
            setUsername={setUsername}
            enabled={enabled}
            setEnabled={setEnabled}
            newPassword={newPassword}
            setNewPassword={setNewPassword}
            newPasswordConfirm={newPasswordConfirm}
            setNewPasswordConfirm={setNewPasswordConfirm}
            globalRoles={globalRoles}
            selectedGlobalRoleIds={selectedGlobalRoleIds}
            onToggleGlobalRole={(roleId) =>
              setSelectedGlobalRoleIds((current) =>
                current.includes(roleId)
                  ? current.filter((id) => id !== roleId)
                  : [...current, roleId]
              )
            }
            serverRoles={serverRoles}
            selectedServerRoleIds={selectedServerRoleIds}
            onToggleServerRole={(roleId) =>
              setSelectedServerRoleIds((current) =>
                current.includes(roleId)
                  ? current.filter((id) => id !== roleId)
                  : [...current, roleId]
              )
            }
            selectedServerId={selectedServerId}
            setSelectedServerId={setSelectedServerId}
            servers={servers}
            membersLoading={membersLoading}
            membersError={membersError}
            onSaveChanges={handleSaveEdit}
            saveLoading={saveEditLoading}
            saveError={editError}
          />

          <ConfirmationModal
            isOpen={deleteUserConfirm.open}
            onClose={() => {
              if (deleteUserLoading) return;
              setDeleteUserConfirm({ open: false });
            }}
            onConfirm={confirmDeleteUser}
            title="Delete User"
            message={
              deleteUserConfirm.open
                ? `Delete "${deleteUserConfirm.username}" now? This action permanently deletes the account and cannot be undone.`
                : 'This action permanently deletes the account and cannot be undone.'
            }
            confirmText="Delete"
            confirmButtonClass="bg-red-600 hover:bg-red-700"
            requiredText={deleteUserConfirm.open ? deleteUserConfirm.username : undefined}
          />

          <RoleEditDialog
            open={roleModalOpen}
            onOpenChange={(open) => {
              setRoleModalOpen(open);
              if (!open) {
                setRoleError(null);
              }
            }}
            editingRole={editingRole}
            initialName={roleName}
            initialScope={roleScope}
            initialPermissions={rolePermissions}
            ssoGroupsEnabled={ssoGroupsEnabled}
            setSsoGroupsEnabled={setSsoGroupsEnabled}
            setName={setRoleName}
            setScope={setRoleScope}
            togglePermission={(permission) =>
              setRolePermissions((current) =>
                current.includes(permission)
                  ? current.filter((value) => value !== permission)
                  : [...current, permission]
              )
            }
            ssoGroupsText={ssoGroupsText}
            setSsoGroupsText={setSsoGroupsText}
            onSave={handleSaveRole}
            onDelete={() => {
              if (editingRole) requestDeleteRole(editingRole);
            }}
            saveLoading={roleSaveLoading}
            deleteLoading={roleDeleteLoading}
            error={roleError}
          />

          <ConfirmationModal
            isOpen={roleDeleteConfirm.open}
            onClose={() => {
              if (roleDeleteLoading) return;
              setRoleDeleteConfirm({ open: false });
            }}
            onConfirm={confirmDeleteRole}
            title="Delete Role"
            message={
              roleDeleteConfirm.open
                ? `Delete the role "${roleDeleteConfirm.roleName}"? Users and servers currently holding it lose its permissions.`
                : 'This action cannot be undone.'
            }
            confirmText="Delete"
            confirmButtonClass="bg-red-600 hover:bg-red-700"
          />

          <UsersPanel
            users={users}
            usersLoading={usersLoading}
            userLimitReached={userLimitReached}
            highlightedUserId={highlightedUserId}
            maxUsers={MAX_USERS}
            setFeedback={setFeedback}
            setCreateModalOpen={setCreateModalOpen}
            openUserEdit={openUserEdit}
            requestDeleteUser={requestDeleteUser}
            deleteUserLoading={deleteUserLoading}
          />

          <RolesPanel
            roles={roles}
            rolesLoading={rolesLoading}
            rolesError={rolesError}
            onRetry={loadRoles}
            setCreateModalOpen={openRoleCreate}
            openRoleEdit={openRoleEdit}
            requestDeleteRole={requestDeleteRole}
            deleteRoleLoading={roleDeleteLoading}
          />
        </>
      )}
    </div>
  );
}
