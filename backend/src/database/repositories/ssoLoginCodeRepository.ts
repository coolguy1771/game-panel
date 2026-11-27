import crypto from 'node:crypto';
import { BaseRepository } from './base.js';

function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

// Short-lived, single-use codes that hand a browser session its panel JWT after an SSO
// redirect. A code is only valid together with its handoff secret - an HttpOnly cookie set
// to the browser that completed the callback - so a code leaked to another browser (login
// CSRF / session fixation) cannot be redeemed there. Only SHA-256 hashes are stored.
export class SsoLoginCodeRepository extends BaseRepository {
  async issue(userId: number, handoffSecret: string, ttlMs = 60_000): Promise<string> {
    const db = await this.ensureDb();

    // Opportunistic cleanup of expired/consumed codes.
    const cutoff = new Date(Date.now() - 3_600_000).toISOString();
    await db.run('DELETE FROM sso_login_codes WHERE expires_at < ?', [cutoff]);

    const code = crypto.randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + ttlMs).toISOString();
    await db.run(
      'INSERT INTO sso_login_codes (code_hash, handoff_hash, user_id, expires_at) VALUES (?, ?, ?, ?)',
      [sha256Hex(code), sha256Hex(handoffSecret), userId, expiresAt]
    );

    return code;
  }

  // Marks the code used and returns its user id, or null when unknown/expired/already used/
  // presented without the matching handoff proof. The conditional UPDATE makes consumption
  // atomic even for racing requests.
  async consume(code: string, handoffSecret: string): Promise<number | null> {
    const db = await this.ensureDb();
    const now = new Date().toISOString();

    const result = await db.run(
      'UPDATE sso_login_codes SET used_at = ? WHERE code_hash = ? AND handoff_hash = ? AND used_at IS NULL AND expires_at > ?',
      [now, sha256Hex(code), sha256Hex(handoffSecret), now]
    );
    if (!result.changes) return null;

    const row = await db.get<{ user_id: number }>(
      'SELECT user_id FROM sso_login_codes WHERE code_hash = ?',
      [sha256Hex(code)]
    );
    return row?.user_id ?? null;
  }
}