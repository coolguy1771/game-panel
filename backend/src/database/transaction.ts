import { AsyncLocalStorage } from 'node:async_hooks';
import type { Database } from 'sqlite';

const inTransaction = new AsyncLocalStorage<true>();

// The backend uses a single SQLite connection, so concurrent requests must not interleave
// BEGIN/COMMIT. Outermost transaction wins a queue slot; nested calls (same async chain)
// join the open transaction instead of starting a new one.
let queue: Promise<unknown> = Promise.resolve();

export function withDatabaseTransaction<T>(db: Database, work: () => Promise<T>): Promise<T> {
  if (inTransaction.getStore()) return work();

  const run = queue.then(() =>
    inTransaction.run(true, async () => {
      await db.exec('BEGIN');
      try {
        const result = await work();
        await db.exec('COMMIT');
        return result;
      } catch (error) {
        await db.exec('ROLLBACK');
        throw error;
      }
    })
  );

  // Keep the queue alive regardless of individual failures.
  queue = run.catch(() => undefined);
  return run;
}
