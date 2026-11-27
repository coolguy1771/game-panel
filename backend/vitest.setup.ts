import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// The backend normally keeps its SQLite file under /data (container path). Tests get a
// disposable directory per vitest worker so they never touch real data.
const dataDir = fs.mkdtempSync(
  path.join(os.tmpdir(), `gp-test-${process.pid}-${process.env.VITEST_WORKER_ID ?? '0'}-`)
);

process.env.DOMAIN = 'test.local';
process.env.PORT = '3999';
process.env.JWT_SECRET = 'test-jwt-secret';
process.env.GAMEPANEL_DATA_DIR = dataDir;
