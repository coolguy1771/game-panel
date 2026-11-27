import crypto from 'node:crypto';
import { BaseRepository } from './base.js';

function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

// Short-lived, single-use codes that hand a browser session its panel JWT after an SSO
// redirect. Only the SHA-256 hash of a code is stored, so a database leak cannot mint logins.
export class SsoLoginCodeRepository extends BaseRepository {
  async issue(userId: number, ttlMs = 60_000): Promise<string> {
    const db = await this.ensureDb();

    // Opportunistic cleanup of expired/consumed codes.
    const cutoff = new Date(Date.now() - 3_600_000).toISOString();
    await db.run('DELETE FROM sso_login_codes WHERE expires_at < ?', [cutoff]);

    const code = crypto.randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + ttlMs).toISOString();
    await db.run(
      'INSERT INTO sso_login_codes (code_hash, user_id, expires_at) VALUES (?, ?, ?)',
      [sha256Hex(code), userId, expiresAt]
    );

    return code;
  }

  // Marks the code used and returns its user id, or null when unknown/expired/already used.
  // The conditional UPDATE makes consumption atomic even for racing requests.
  async consume(code: string): Promise<number | null> {
    const db = await this.ensureDb();
    const codeHash = sha256Hex(code);
    const now = new Date().toISOString();

    const result = await db.run(
      'UPDATE sso_login_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?',
      [now, codeHash, now]
    );
    if (!result.changes) return null;

    const row = await db.get<{ user_id: number }>(
      'SELECT user_id FROM sso_login_codes WHERE code_hash = ?',
      [codeHash]
    );
    return row?.user_id ?? null;
  }
}