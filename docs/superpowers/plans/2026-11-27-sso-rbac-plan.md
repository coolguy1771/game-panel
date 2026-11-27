# SSO (OIDC) + RBAC implementation plan

Date: 2026-11-27 · Spec: `docs/superpowers/specs/2026-11-27-sso-rbac-design.md` (binding authority) · Branch: `feat/sso-rbac`

## Context

Backend: Node 20 + Express 4 + sqlite, migrations in `backend/src/database/migrations/`,
repositories in `backend/src/database/repositories/`, routes mounted in `backend/src/index.ts`.
Frontend: React + Vite SPA, no router (tab state in `frontend/App.tsx`, shell in
`frontend/components/app/AppShell.tsx`). No test framework exists; this plan adds a minimal
vitest harness in `backend` for pure/integration logic. HTTP behavior is verified by boot + curl.

## Global constraints

- `/api/auth/me` response shape and all frontend permission helpers stay byte-identical.
- `*` wildcard: root only, never accepted in roles or role assignments.
- Global roles: permissions ⊆ `{users.manage, server.install}`. Server roles: ⊆
  `ASSIGNABLE_SERVER_PERMISSIONS`.
- Migration `0002` must preserve every user's effective permissions exactly and must run inside
  its own transaction (the runner already wraps `up()` in BEGIN/COMMIT).
- Fresh-DB path: `createSchema()` must produce the same end state as migrations; system-role
  seeding happens in `bootstrap.ts` (idempotent, by name+scope).
- No secrets in code or docs; SSO config comes from env only.

## Tasks

### Task 1 — RBAC schema, migration 0002, system-role seeding

Files: `backend/src/database/migrations/0002_introduce_rbac_roles.ts`,
`backend/src/database/migrations/rbacConversion.ts` (pure conversion logic),
`backend/src/database/migrations/index.ts`, `backend/src/database/init.ts` (`createSchema`),
`backend/src/database/bootstrap.ts` (`ensureSystemRolesExist`).

- Tables `roles`, `user_roles`, `server_member_roles` (composite FK to the existing
  `UNIQUE(server_id, user_id)` pair), `sso_login_codes`; `roles` unique index on
  `(LOWER(name), scope)`; `users` gains `auth_type/sso_provider/sso_subject/sso_email` + partial
  unique index on `(sso_provider, sso_subject)`; mirror everything in `createSchema()`.
- Conversion (pure, unit-tested): global users grouped by exact permission-set signature →
  `{users.manage, server.install}` ⇒ role `Administrator` (system), else `Imported role N`;
  memberships grouped by signature → exact preset match ⇒ `Viewer`/`Operator`/`Full access`
  (system), else `Imported server role N`. Root users skipped. Old JSON columns set to `'[]'`.
- Seeded system roles: Administrator (global), Viewer / Operator / Full access (server),
  `is_system=1`.

Test (vitest): conversion function on synthetic rows — exact matches reuse system roles, custom
sets get imported roles, empty signatures create nothing, root skipped, output is idempotent.
Expected: red first (module missing), then green. Command: `npm test -- --run` (backend).
Commit: `feat(db): RBAC roles schema, migration 0002, system role seeding`.

### Task 2 — roleRepository + effective-permission resolution

Files: `backend/src/database/repositories/roleRepository.ts`, `repositories.ts`, `index.ts`,
`userRepository.ts`, `serverMemberRepository.ts`, `backend/src/middleware/auth.ts`.

- `roleRepository`: CRUD, `findByScopeAndName`, assignment helpers
  (`setGlobalRoles(userId, ids)`, `setServerMemberRoles(serverId, userId, ids)`,
  `listGlobalRoleIdsByUser`, `listServerRoleIds(serverId, userId)`), `pruneOrphans` not needed
  (CASCADE).
- `userRepository.getGlobalPermissions(userId)` — same name/signature — now returns the union of
  the user's global roles' permissions. `serverMemberRepository.getUserServerPermissions`
  likewise unions membership roles; `listByUser` gains effective `permissions` per membership
  (drives `/me` and `buildServerPermissionVisibility`, which drops its own JSON parsing).
- Tests: role unions for global and per-server resolution; `/me`-shape data via repo calls.
Commit: `feat(auth): resolve permissions through RBAC roles`.

### Task 3 — Roles API + roleIds on users/members endpoints

Files: new `backend/src/routes/roles.ts`; `backend/src/routes/users.ts`,
`backend/src/routes/serverMembers.ts`, `backend/src/routes/auth.ts` (register),
`backend/src/index.ts` (mount under `/api/roles`).

- `GET/POST /api/roles`, `PATCH/DELETE /api/roles/:id`, gated by `users.manage`; validation
  helper `assertRolePermissions(scope, perms)`; DELETE → 403 for `is_system`.
- `POST /api/auth/register` and `PATCH /api/users/:id` take `roleIds` (global scope, must exist);
  `GET /api/users` returns `roles: [{id, name}]`. Members POST/PATCH take `roleIds` (server
  scope); member list returns `roles`. SSO-managed roles (non-empty `sso_groups`): manual
  assignment → 400.
- HTTP verification: boot backend with temp data dir and curl the endpoints (status codes
  recorded in ledger).
Commit: `feat(api): roles CRUD and role-based user/member assignment`.

### Task 4 — SSO: config, OIDC service, routes, one-time codes

Files: `backend/src/config.ts` (sso block), new `backend/src/services/ssoOidc.ts`,
`backend/src/routes/authSso.ts`, new `backend/src/database/repositories/ssoLoginCodeRepository.ts`,
`backend/src/utils/rateLimit.ts` (extract IP-bucket limiter from `routes/auth.ts`, reused),
`backend/package.json` (+`openid-client`).

- Env: `SSO_OIDC_ISSUER_URL/CLIENT_ID/CLIENT_SECRET/SCOPES/GROUPS_CLAIM/AUTO_PROVISION/BUTTON_LABEL`.
- `GET /api/auth/sso/status|login|callback` + `POST /api/auth/sso/exchange` per spec (state
  cookie = 10-min JWT signed with `JWT_SECRET`; exchange code = 32-byte random, SHA-256 at rest,
  60 s TTL, single-use; redirect `/?sso-code=…` or `/?sso-error=…`).
- JIT: `auth_type='sso'`, unusable random password hash, username sanitized ≤ 12 + uniquify,
  never root. Role sync: assignments to roles with non-empty `sso_groups` fully replaced at each
  login; admin-managed assignments untouched.
- Unit tests: state JWT roundtrip/rejection, username sanitize/uniquify, group→role selection.
Commit: `feat(sso): OIDC login with JIT provisioning and group-to-role mapping`.

### Task 5 — SSO account rules on password paths

Files: `backend/src/routes/auth.ts` (login, change-password), `backend/src/routes/users.ts`
(reset-password).

- `auth_type='sso'` users: login → 400 `This account signs in with SSO`, change-password and
  admin reset-password → 400. Local accounts unchanged.
- Verified via curl in Task 6's boot; unit test for the shared guard helper.
Commit: `feat(auth): block password flows for SSO accounts`.

### Task 6 — Backend integration verification

- `npm run build` + `npm test -- --run` green.
- Migration equivalence test: build a populated temp DB (users/memberships with assorted
  permission lists), snapshot each user's effective permissions via pre-migration resolution
  logic, run the real migration runner, recompute via post-migration logic, assert equality.
- Boot + curl script against a stub OIDC provider (`backend/scripts/mockOidc.ts`, vite-free,
  plain node/express — runs with tsx): full status→login→callback→exchange→`/me` flow, disabled
  account, provisioning_disabled, replayed code.
- Ledger records command outputs. Commit: `test(backend): migration equivalence and SSO flow verification`.

### Task 7 — Frontend: api client, login SSO, session exchange

Files: `frontend/utils/api.ts`, `frontend/components/Login.tsx`, `frontend/components/app/useAuthSession.ts`
(if needed).

- `getSsoStatus()`, `exchangeSsoCode(code)`; Login shows button when enabled; on mount, `?sso-code=`
  → exchange → existing session path; `?sso-error=` → alert. URL params cleaned via
  `history.replaceState`.
- Verify: `npm run build` (frontend), manual dev-proxy boot check.
Commit: `feat(ui): SSO sign-in button and code exchange`.

### Task 8 — Frontend: Roles admin UI

Files: new `frontend/components/userAdministration/RolesPanel.tsx` + `RoleEditDialog.tsx`,
`frontend/components/app/AppShell.tsx`/`Sidebar.tsx` (new tab `admin-roles`, gated
`canManageUsers`), `frontend/App.tsx` wiring, `frontend/utils/permissions.ts` untouched.

- Role list (name, scope, permission count, SSO groups, assignment counts), create/edit dialog
  (scope fixed at creation; permission checkboxes reuse the option groups in
  `userAdministration/utils.ts`; SSO groups editor for global roles), delete non-system roles.
Commit: `feat(ui): roles management screen`.

### Task 9 — Frontend: role assignment in user + member editors

Files: `frontend/components/userAdministration/UserEditDialog.tsx`, `UsersPanel.tsx`,
`frontend/components/userAdministration/utils.ts` (assignment payload helpers),
`frontend/components/serverSettings/access.ts` + members modal.

- User editor: global role multi-select replaces global permission checkboxes. Member editor:
  server role multi-select replaces permission checkboxes. SSO-managed roles disabled for manual
  assignment with an explanatory hint.
Commit: `feat(ui): assign roles to users and server members`.

### Task 10 — Deploy wiring + final build

Files: `deploy/install.sh` (optional SSO prompt block writing env), compose/env passthrough
verified.

- `npm run build` both packages green; `git diff --stat` sanity.
Commit: `chore(deploy): optional OIDC SSO configuration in installer`.

## Review focus (for the final review pass)

- Migration correctness on non-trivial data (duplicate signatures, root users, memberships
  with empty lists, users with `*`-free unknown permission strings).
- SSO security: state/nonce validation, open-redirect surface, code single-use, rate limiting,
  JIT privilege ceiling (never root, never `*`).
- The manual-assignment block on SSO-managed roles and the resync-at-login semantics.
- Frontend regression risk: nothing outside admin/login screens changed.
