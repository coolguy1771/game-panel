import express, { type Application } from 'express';
import { initializeDatabase, getDatabase } from '../src/database/init.js';
import { ensureRootUserExists, ensureSystemRolesExist, ensureSsoAdminRoleFromEnv } from '../src/database/bootstrap.js';
import { authMiddleware } from '../src/middleware/auth.js';
import authRoutes from '../src/routes/auth.js';
import authSsoRoutes from '../src/routes/authSso.js';
import userRoutes from '../src/routes/users.js';
import roleRoutes from '../src/routes/roles.js';
import serverMembersRoutes from '../src/routes/serverMembers.js';
import { nowIso } from '../src/utils/time.js';

// Boots the real HTTP surface (routes, middleware, SQLite) without the Docker-touching
// startup steps of index.ts, so the API can be exercised on machines without Docker.
export async function startVerifyHarness(port: number): Promise<{ close: () => Promise<void> }> {
  await initializeDatabase();
  await ensureRootUserExists();
  await ensureSystemRolesExist();
  await ensureSsoAdminRoleFromEnv();

  const app: Application = express();
  app.use(express.json());

  // Test helper: create a game server row for membership tests.
  app.post('/api/test/seed-server', async (_req, res) => {
    const db = await getDatabase();
    const timestamp = nowIso();
    const result = await db.run(
      `INSERT INTO game_servers (name, provider, docker_image, ports_json, created_at, updated_at)
       VALUES (?, 'external', 'verify:latest', '[]', ?, ?)`,
      [`verify-${Date.now()}`, timestamp, timestamp]
    );
    res.json({ serverId: Number(result.lastID) });
  });

  app.use('/api/auth/sso', authSsoRoutes);
  app.use('/api/auth', authRoutes);
  app.use('/api/users', authMiddleware, userRoutes);
  app.use('/api/roles', authMiddleware, roleRoutes);
  app.use('/api/servers', authMiddleware, serverMembersRoutes);

  await new Promise<void>((resolve, reject) => {
    const server = app.listen(port, '127.0.0.1', () => resolve());
    server.on('error', reject);
  });

  return { close: () => Promise.resolve() };
}
