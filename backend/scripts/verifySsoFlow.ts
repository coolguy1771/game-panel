/* eslint-disable no-console */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// End-to-end verification for RBAC + SSO against the real routes. Run with:
//   cd backend && npx tsx scripts/verifySsoFlow.ts
// Exits 0 when every check passes; prints one line per check.

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gp-verify-'));
const BACKEND_PORT = 4620;
const BACKEND = `http://127.0.0.1:${BACKEND_PORT}`;
const ADMIN_PASSWORD = 'verify-root-password';

process.env.DOMAIN = '127.0.0.1';
process.env.PORT = String(BACKEND_PORT);
process.env.JWT_SECRET = 'verify-jwt-secret';
process.env.ADMIN_PASSWORD = ADMIN_PASSWORD;
process.env.GAMEPANEL_DATA_DIR = dataDir;
process.env.SSO_OIDC_ISSUER_URL = 'placeholder-set-after-mock-starts';
process.env.SSO_OIDC_CLIENT_ID = 'game-panel-verify';
process.env.SSO_OIDC_CLIENT_SECRET = 'verify-client-secret';
process.env.SSO_OIDC_ALLOW_INSECURE = 'true';
process.env.TELEMETRY_ENABLED = 'false';

let failures = 0;
function check(name: string, ok: boolean, detail?: unknown): void {
  if (ok) {
    console.log(`PASS ${name}`);
  } else {
    failures += 1;
    console.log(`FAIL ${name}${detail !== undefined ? ` -> ${JSON.stringify(detail)}` : ''}`);
  }
}

async function main(): Promise<void> {
  const { startMockOidc } = await import('./mockOidc.js');
  const mock = await startMockOidc({
    sub: 'idp-user-1',
    username: 'idp.alice.longusername.here',
    email: 'alice@example.com',
    groups: ['panel-admins'],
    clientId: process.env.SSO_OIDC_CLIENT_ID!,
    clientSecret: process.env.SSO_OIDC_CLIENT_SECRET!,
  });
  process.env.SSO_OIDC_ISSUER_URL = mock.issuerBaseUrl;

  const { startVerifyHarness } = await import('./verifyHarness.js');
  const harness = await startVerifyHarness(BACKEND_PORT);

  const { roleRepository } = await import('../src/database/index.js');
  const { PERMISSIONS } = await import('../src/permissions.js');

  // Seed: an SSO-mapped global role and a plain server role.
  const ssoRoleId = (await roleRepository.create({
    name: 'SSO Admins',
    scope: 'global',
    permissions: [PERMISSIONS.users.manage],
    ssoGroups: ['panel-admins'],
  }))!;
  const operatorRoleId = (await roleRepository.create({
    name: 'Server Operators',
    scope: 'server',
    permissions: [PERMISSIONS.server.power, PERMISSIONS.fs.read],
  }))!;

  const post = async (pathName: string, body?: unknown, token?: string, headers: Record<string, string> = {}) =>
    fetch(`${BACKEND}${pathName}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'manual',
    });

  const get = async (pathName: string, token?: string, headers: Record<string, string> = {}) =>
    fetch(`${BACKEND}${pathName}`, {
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
      redirect: 'manual',
    });

  // 1. SSO status
  const status = await (await get('/api/auth/sso/status')).json();
  check('sso status enabled', status.enabled === true);

  // 2. Root login
  const loginRes = await post('/api/auth/login', { username: 'admin', password: ADMIN_PASSWORD });
  check('root login', loginRes.status === 200);
  const rootToken = ((await loginRes.json()) as { token: string }).token;

  // 3. Roles API behavior
  const rolesList = await (await get('/api/roles', rootToken)).json();
  check(
    'system roles seeded',
    Array.isArray(rolesList.roles) &&
      rolesList.roles.filter((r: { isSystem: boolean }) => r.isSystem).length === 4,
    rolesList.roles?.map((r: { name: string }) => r.name),
  );

  const badRoleRes = await post(
    '/api/roles',
    { name: 'Bad', scope: 'server', permissions: ['users.manage'] },
    rootToken
  );
  check('global-only permission rejected in server role', badRoleRes.status === 400);

  const viewerSystem = rolesList.roles.find((r: { name: string }) => r.name === 'Viewer');
  const deleteSystemRes = await post(`/api/roles-nonexistent`, null, rootToken).catch(() => null);
  void deleteSystemRes;
  const delRes = await fetch(`${BACKEND}/api/roles/${viewerSystem.id}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${rootToken}` },
  });
  check('system role delete forbidden', delRes.status === 403);

  const ssoAssignRes = await post(
    '/api/auth/register',
    { username: 'manualsso', password: 'longpassword1', confirmPassword: 'longpassword1', roleIds: [ssoRoleId] },
    rootToken
  );
  check('SSO-managed role cannot be assigned manually', ssoAssignRes.status === 400);

  // 4. RBAC user + membership assignment
  const registerRes = await post(
    '/api/auth/register',
    { username: 'bob', password: 'longpassword1', confirmPassword: 'longpassword1', roleIds: [] },
    rootToken
  );
  check('register user with empty roles', registerRes.status === 201);
  const bobId = ((await registerRes.json()) as { user: { id: number } }).user.id;

  const seedRes = await post('/api/test/seed-server', {}, rootToken);
  const serverId = ((await seedRes.json()) as { serverId: number }).serverId;

  const memberRes = await post(
    `/api/servers/${serverId}/members`,
    { userId: bobId, roleIds: [operatorRoleId] },
    rootToken
  );
  check('assign server role to member', memberRes.status === 201);

  const bobLogin = await post('/api/auth/login', { username: 'bob', password: 'longpassword1' });
  const bobToken = ((await bobLogin.json()) as { token: string }).token;
  const bobMe = await (await get('/api/auth/me', bobToken)).json();
  const bobServerPerms = bobMe.permissions.servers.find(
    (s: { serverId: number }) => s.serverId === serverId
  )?.permissions ?? [];
  check(
    'member effective permissions from role',
    bobServerPerms.includes(PERMISSIONS.server.power) && bobServerPerms.includes(PERMISSIONS.fs.read),
    bobServerPerms,
  );

  // 5. SSO flow: status -> login -> authorize -> callback -> exchange -> /me
  const ssoLoginRes = await get('/api/auth/sso/login');
  check('sso login redirects to IdP', ssoLoginRes.status === 302, ssoLoginRes.status);
  const authorizeUrl = new URL(ssoLoginRes.headers.get('location') ?? '');
  check('authorize targets the mock IdP', authorizeUrl.origin === mock.issuerBaseUrl);
  const setCookie = ssoLoginRes.headers.get('set-cookie') ?? '';
  check('state cookie issued', setCookie.includes('gp_sso_state='));
  const stateCookie = setCookie.split(';').find((part) => part.trim().startsWith('gp_sso_state='))?.split('=')[1] ?? '';

  const authorizeRes = await fetch(authorizeUrl, { redirect: 'manual' });
  check('IdP returns to callback with code', authorizeRes.status === 302);
  const callbackUrl = new URL(authorizeRes.headers.get('location') ?? '');
  check('callback has code and state', callbackUrl.searchParams.has('code') && callbackUrl.searchParams.has('state'));

  const callbackQuery = callbackUrl.searchParams.toString();
  const callbackRes = await fetch(
    `${BACKEND}/api/auth/sso/callback?${callbackQuery}`,
    { headers: { Cookie: `gp_sso_state=${stateCookie}` }, redirect: 'manual' }
  );
  check('callback redirects to frontend with code', callbackRes.status === 302);
  const callbackLocation = callbackRes.headers.get('location') ?? '';
  const finalUrl = new URL(callbackLocation, BACKEND);
  check('frontend redirect carries sso-code', finalUrl.searchParams.has('sso-code'));

  const loginCode = finalUrl.searchParams.get('sso-code') ?? '';
  const exchangeRes = await post('/api/auth/sso/exchange', { code: loginCode });
  check('exchange code for token', exchangeRes.status === 200);
  const ssoUser = (await exchangeRes.json()) as { token: string; user: { username: string } };

  const ssoMe = await (await get('/api/auth/me', ssoUser.token)).json();
  check('SSO user provisioned with mapped role', (ssoMe.permissions.global as string[]).includes(PERMISSIONS.users.manage), ssoMe.permissions.global);
  check('SSO username derived and truncated', ssoUser.user.username.length <= 12, ssoUser.user.username);

  // 6. One-time code semantics
  const replayRes = await post('/api/auth/sso/exchange', { code: loginCode });
  check('exchange code is single-use', replayRes.status === 401);
  const bogusRes = await post('/api/auth/sso/exchange', { code: 'bogus-code' });
  check('bogus code rejected', bogusRes.status === 401);

  // 7. SSO accounts cannot use passwords
  const ssoPasswordLogin = await post('/api/auth/login', { username: ssoUser.user.username, password: 'whatever123' });
  check('SSO account password login blocked', ssoPasswordLogin.status === 400);

  await harness.close();
  await mock.close();

  if (failures > 0) {
    console.log(`\n${failures} check(s) failed`);
    process.exitCode = 1;
  } else {
    console.log('\nAll checks passed');
  }
}

void main();
