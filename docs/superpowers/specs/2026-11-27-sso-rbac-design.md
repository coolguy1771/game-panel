# SSO (OIDC) + RBAC rework — design

Date: 2026-11-27 · Status: draft for approval

## Why

Today every permission is a raw string list stored directly on the user
(`users.global_permissions_json`) and on every server membership
(`server_members.permissions_json`). Admins tick individual permissions per user
and again per server; the frontend softens this with hardcoded "presets"
(Viewer / Operator / Full access + per-game variants in
`frontend/components/userAdministration/utils.ts`), but nothing reusable exists
server-side. There is no SSO: every account is a hand-created username/password.

This design introduces proper RBAC — roles as reusable permission bundles — and
OIDC single sign-on with just-in-time provisioning, while keeping the panel's
self-hosted, single-box, SQLite deployment model intact.

## Goals

- Roles bundle the existing permission strings from `backend/src/permissions.ts`;
  assignable to users globally and to server memberships.
- Existing access survives the upgrade exactly.
- OIDC Authorization Code + PKCE login, JIT user creation, IdP group → global
  role mapping.
- Local password login unchanged; root stays local and keeps bypassing checks.
- The frontend permission contract (the `/api/auth/me` response shape and
  `frontend/utils/permissions.ts` helpers) stays unchanged.

## Non-goals and anti-goals

- No ABAC policy engine, no ReBAC graph service — both were considered and
  rejected (see Approaches).
- No SAML or LDAP in this pass.
- One generic OIDC provider for v1 (env-configured); no multi-provider admin UI.
- No automatic IdP → server-membership mapping in v1: SSO maps groups to
  *global* roles; per-server access stays admin-assigned.
- Anti-goal: two parallel ways to grant permissions. After migration, roles are
  the only assignment mechanism.
- Anti-goal: any new stateful service (breaks the one-box install story).

## Constraints

- SQLite via `sqlite`/`sqlite3`; migrations via `DATABASE_MIGRATIONS`
  (`id`, `appVersion`, `checksum`, `up(db)`); fresh databases run
  `createSchema()` and mark all bundled migrations applied *without running
  them* — so anything a migration creates must also exist in `createSchema()`
  and seeding must live in `bootstrap.ts` (idempotent).
- Express 4, JWT HS256 with `token_version` invalidation, bcrypt passwords,
  WebSocket auth re-validates the account per socket.
- Node >= 20.17. No test framework in the repo today.
- Username ≤ 12 chars, case-insensitive unique; `*` reserved for root;
  `GLOBAL_ONLY_PERMISSIONS = {users.manage, server.install}`.
- Config is env-driven; `deploy/install.sh` writes `deploy/.env` for compose.

## Approaches considered

- **ABAC** — rules over user/resource attributes (e.g. CASL). Rejected: the
  panel has almost no attribute sources; its real access structure (user ↔
  server membership) is a relationship, and there is no natural admin UI for
  policies.
- **ReBAC** — Zanzibar-style relationship tuples in OpenFGA/SpiceDB with graph
  traversal. Rejected for v1: a second stateful service conflicts with the
  single-box install; no team/org hierarchy exists yet to exploit inheritance.
- **RBAC with relationship-scoped assignment** — chosen: roles globally, roles
  on server memberships. Subsumes what ReBAC would buy at this scale, no new
  services, and gives SSO the simplest mapping.

## Design

### 1. Data model — migration `0002_introduce_rbac_roles` (appVersion 1.7.0)

New tables (mirrored in `createSchema()`):

```sql
CREATE TABLE roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  scope TEXT NOT NULL CHECK(scope IN ('global','server')),
  permissions_json TEXT NOT NULL DEFAULT '[]',
  sso_groups_json TEXT NOT NULL DEFAULT '[]',
  is_system INTEGER NOT NULL DEFAULT 0 CHECK(is_system IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_roles_name_scope ON roles(LOWER(name), scope);

CREATE TABLE user_roles (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  UNIQUE(user_id, role_id)
);

-- Assignment implies membership via the composite FK; server_members already
-- has UNIQUE(server_id, user_id).
CREATE TABLE server_member_roles (
  server_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  UNIQUE(server_id, user_id, role_id),
  FOREIGN KEY (server_id, user_id) REFERENCES server_members(server_id, user_id) ON DELETE CASCADE
);

CREATE TABLE sso_login_codes (
  code_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  used_at TEXT
);
```

`users` gains columns (plain `ALTER TABLE ADD COLUMN`, no table rebuild):
`auth_type TEXT NOT NULL DEFAULT 'local' CHECK(auth_type IN ('local','sso'))`,
`sso_provider TEXT`, `sso_subject TEXT`, `sso_email TEXT`, plus a partial unique
index on `(sso_provider, sso_subject) WHERE sso_subject IS NOT NULL`.

`users.global_permissions_json` and `server_members.permissions_json` become
unused: reads stop, migration rewrites both to `'[]'`. Keeping the columns
avoids rebuilding the two most sensitive tables in this migration; a later
cleanup migration can drop them.

**Seeded system roles** (`is_system = 1`, created idempotently in
`bootstrap.ts` so fresh databases get them too): `Administrator` (global:
`users.manage`, `server.install`), and server-scope `Viewer`, `Operator`,
`Full access` matching the frontend presets. System roles can be edited but not
deleted.

**Data conversion** (inside the migration):

- Global: group users by exact permission-set signature; for each non-empty
  signature, find-or-create a global role (`Administrator` when the set is
  exactly `{users.manage, server.install}`, otherwise `Imported role N`) and
  assign it to those users.
- Per-server: group *all* memberships by signature; exact matches to the
  Viewer/Operator/Full-access sets reuse those system roles, otherwise
  find-or-create `Imported server role N`; write `server_member_roles` rows.
- Root users are skipped (they bypass authorization anyway).

### 2. One resolution mechanism

- New `roleRepository`; `userRepository.getGlobalPermissions(userId)` keeps its
  name and signature but now returns the **union of the user's global roles'
  permissions**; `serverMemberRepository.getUserServerPermissions` likewise
  unions the membership's roles. Every existing check site —
  `requireGlobalPermission`, `requireServerPermission`, `userHasServerPermission`,
  `buildServerPermissionVisibility`, and the WebSocket `hasServerPermission` —
  keeps calling the same helpers, so authorization semantics are unchanged and
  role edits apply immediately (permissions are read from the DB per request;
  no token invalidation needed).
- `GET /api/auth/me` keeps today's exact response shape (resolved flat string
  lists), so `useAuthSession` and all client-side checks are untouched.
- Validation on writes: global roles may contain only
  `GLOBAL_ONLY_PERMISSIONS`; server roles only `ASSIGNABLE_SERVER_PERMISSIONS`;
  `*` is never accepted in a role; name ≤ 64 chars, unique per scope
  (case-insensitive).
- Roles with a non-empty `sso_groups_json` are **SSO-managed**: the API rejects
  manual assignment to them (400); their assignments are recomputed at each SSO
  login. Roles with empty `sso_groups_json` are admin-managed only.

### 3. Roles API (gated by `users.manage`, like the rest of user admin)

- `GET /api/roles` — list with `id, name, scope, permissions, ssoGroups,
  isSystem` plus assignment counts for the UI.
- `POST /api/roles` · `PATCH /api/roles/:id` (name, permissions, ssoGroups;
  scope immutable) · `DELETE /api/roles/:id` (403 for system roles).
- `POST /api/auth/register` and `PATCH /api/users/:id` accept `roleIds`
  (global scope) instead of `globalPermissions`; the frontend ships in the same
  release, so no compat shim.
- `POST /api/servers/:id/members` and its PATCH accept `roleIds` (server scope)
  instead of `permissions`.

### 4. SSO — OIDC

New dependency: `openid-client` (v6). Config via env, following the existing
`config.ts` pattern (provider enabled iff issuer + client ID are set):

```
SSO_OIDC_ISSUER_URL, SSO_OIDC_CLIENT_ID, SSO_OIDC_CLIENT_SECRET,
SSO_OIDC_SCOPES           # default "openid profile email"
SSO_OIDC_GROUPS_CLAIM     # default "groups"
SSO_OIDC_AUTO_PROVISION   # default true
SSO_OIDC_BUTTON_LABEL     # default "Sign in with SSO"
```

Flow (all endpoints under `/api/auth`):

1. `GET /api/auth/sso/status` (public) → `{ enabled, buttonLabel }`.
2. `GET /api/auth/sso/login` (public, IP rate-limited) → redirect to the IdP's
   authorization endpoint (PKCE). Sets cookie `gp_sso_state`: a short-lived
   (10 min) JWT signed with the existing `JWT_SECRET` containing `state` and
   `nonce`; HttpOnly, SameSite=Lax, Secure when the request is HTTPS.
3. `GET /api/auth/sso/callback` (public) → verify state cookie against the
   `state` query param, exchange the code, validate the ID token
   (iss/aud/exp/nonce). Resolve `sub`, username
   (`preferred_username` → `nickname` → email local-part), email, and the
   groups claim. Find the user by `(sso_provider='oidc', sso_subject)`;
   JIT-create when enabled (`auth_type='sso'`, unusable random password hash,
   username sanitized to the ≤ 12-char rule with a uniquifying suffix on
   collision); replace the user's SSO-managed role assignments with the roles
   whose `sso_groups` intersect the user's groups. Create a one-time login code
   (SHA-256 hash stored, 60 s TTL, single use) and redirect to
   `https://<DOMAIN>/?sso-code=<code>`, or `/?sso-error=<reason>` on failure.
4. `POST /api/auth/sso/exchange` (public, rate-limited) `{ code }` → same
   response shape as `/api/auth/login` (`{ success, user, token }`). The panel's
   existing bearer-token session model is unchanged; no token ever appears in a
   URL.

Error reasons: `state_mismatch`, `token_exchange_failed`,
`provisioning_disabled`, `account_disabled`, `unknown`.

Account rules:

- SSO accounts cannot use password login and cannot change/reset passwords
  (clear 400s); they are identified by `(provider, subject)`, never by email.
- JIT users are never root and can never hold `*`; users with no mapped roles
  log in with zero permissions.
- An SSO identity never links to an existing local account — it provisions its
  own (no account-takeover surface in v1; linking is a possible follow-up).
- `is_enabled = 0` blocks SSO login exactly as it blocks password login.
- `MAX_USERS = 10` is a frontend guard for manual creation only; SSO-provisioned
  users bypass it (the backend has no cap today).

### 5. Frontend

- `Login.tsx`: fetch `sso/status`; render the SSO button when enabled; on load,
  detect `?sso-code=` (exchange → normal session) and `?sso-error=` (alert).
  `App.tsx` already normalizes the pathname to `/`, so no router work.
- New **Roles** admin area (sidebar item, gated by `canManageUsers`): role list,
  create/edit (name, scope fixed at creation, permission checkboxes reusing the
  option groups in `userAdministration/utils.ts`, SSO groups field for global
  roles), delete for non-system roles.
- `UserEditDialog`: global role multi-select instead of global permission
  checkboxes; user list shows role names.
- Server access UI (`serverSettings/access.ts` + members modal): server role
  multi-select instead of permission checkboxes.
- No changes to `useAuthSession`, `utils/permissions.ts`, or any
  permission-gated view.

### 6. Deploy

- `deploy/install.sh`: optional "SSO (OIDC)" prompt block (issuer URL, client
  ID, client secret); skipped → SSO disabled. `update.sh` preserves the env
  file untouched.
- Verify at implementation time that compose passes the new vars through to the
  backend container and that nginx routes `/api/auth/sso/*` to the backend.

### 7. Verification

- Builds: `tsc` (backend) and `vite build` (frontend).
- Migration test on a copy of a populated database: for every user,
  `/api/auth/me` effective permissions must be identical before and after;
  system roles undeletable; empty-signature edge cases produce no roles.
- SSO end-to-end against a lightweight local OIDC provider (stub with
  discovery + token endpoints, or `oidc-provider`): status → login redirect →
  callback → exchange → `/me` reflects the mapped role; JIT user created;
  disabled account rejected; group change adds/removes mapped roles on next
  login; replayed/expired one-time codes rejected.
- Manual UI pass: role CRUD, user role assignment, membership role assignment,
  SSO button on the login screen.

## Builder-check outcomes (self-review)

Answered during the check: composite FK needs the existing
`UNIQUE(server_id, user_id)` on `server_members` (present); fresh databases get
system roles via `bootstrap.ts` because migrations don't run on fresh DBs; JIT
usernames must satisfy the 12-char rule; redirect URI derives from `DOMAIN`;
state cookie works with SameSite=Lax because the IdP redirect is a top-level
GET navigation.

## Decisions I made (builder's calls — correct me on any)

1. Roles are the *only* assignment mechanism after migration; the old JSON
   permission columns are cleared and left in place for a later drop.
2. Multiple roles per membership, union semantics (matches how global
   assignment already works).
3. Four seeded system roles only (Administrator / Viewer / Operator / Full
   access); per-game presets are not pre-created as roles.
4. SSO config lives in env (not a new settings table), matching how
   `ADMIN_PASSWORD`/`JWT_SECRET` are handled.
5. SSO-managed vs admin-managed is determined by whether the role has
   `sso_groups`; assignments to SSO-managed roles are fully resynced at login
   (lost group ⇒ role removed).
6. One-time exchange code rather than cookies/tokens in URLs.

## For the owner to settle

1. **Migration is one-way**: after upgrading, downgrading to ≤ 1.6 leaves users
   without permissions (except root) because the old columns are cleared.
   Acceptable? (Secure-by-default says clear them; keeping stale copies would
   preserve over-grants.)
2. **SSO v1 maps groups → global roles only**; server memberships stay
   admin-assigned. Acceptable, or is auto-granting server access per group a
   launch requirement?
3. **Single OIDC provider** via env for v1. Acceptable?
