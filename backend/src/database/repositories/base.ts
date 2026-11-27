import type { Database } from 'sqlite';
import { getDatabase } from '../init.js';
import { currentTransactionConnection } from '../transaction.js';

export abstract class BaseRepository {
  private db: Database | null = null;

  protected async ensureDb(): Promise<Database> {
    // Inside withDatabaseTransaction every statement - reads included - must run on the
    // transaction's own connection so it shares the transaction's isolation.
    const transactionDb = currentTransactionConnection();
    if (transactionDb) return transactionDb;

    if (!this.db) {
      this.db = await getDatabase();
    }

    return this.db;
  }
}

