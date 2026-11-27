import { AsyncLocalStorage } from 'node:async_hooks';
import type { Database } from 'sqlite';
import { openDatabaseConnection } from './init.js';

const transactionConnection = new AsyncLocalStorage<Database>();

// The connection to use for database work on the current async chain: the open
// transaction's dedicated connection when inside withDatabaseTransaction, otherwise the
// shared application connection.
export function currentTransactionConnection(): Database | undefined {
  return transactionConnection.getStore();
}

// Runs work on a dedicated connection inside one transaction. Repositories resolve their
// handle through currentTransactionConnection(), so every statement issued inside the
// callback - reads included - shares the transaction, and concurrent requests on the main
// connection can never interleave with it. SQLite serializes the two connections at the
// file level; busy_timeout turns contention into a short wait instead of an error.
export async function withDatabaseTransaction<T>(work: (db: Database) => Promise<T>): Promise<T> {
  const existing = transactionConnection.getStore();
  if (existing) return work(existing);

  const db = await openDatabaseConnection();
  try {
    await db.exec('BEGIN');
    try {
      const result = await transactionConnection.run(db, () => work(db));
      await db.exec('COMMIT');
      return result;
    } catch (error) {
      await db.exec('ROLLBACK').catch(() => undefined);
      throw error;
    }
  } finally {
    await db.close();
  }
}
