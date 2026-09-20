import { chmodSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

// A separate rollback-journal database coordinates the whole data directory.
// An app holds a reserved lock, backups hold shared locks, and restore requires
// an exclusive lock. WAL mode would not provide these reader/writer semantics.
export function acquireStateLock(directory, role = 'app') {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
  const path = join(directory, '.state-lock.db');
  const lock = new DatabaseSync(path);
  try {
    chmodSync(path, 0o600);
    lock.exec('PRAGMA busy_timeout = 0');
    lock.exec('CREATE TABLE IF NOT EXISTS state_lock (id INTEGER PRIMARY KEY)');
    if (role === 'backup') {
      lock.exec('BEGIN');
      lock.prepare('SELECT id FROM state_lock').all();
    } else {
      lock.exec(role === 'restore' ? 'BEGIN EXCLUSIVE' : 'BEGIN IMMEDIATE');
    }
    return lock;
  } catch (error) {
    lock.close();
    const lockError = new Error(
      role === 'restore'
        ? `Uygulama çalışırken veya yedek alırken geri yükleme yapılamaz. Önce HostCanvas süreçlerini durdurun: ${error.message}`
        : `HostCanvas veri dizini başka bir uygulama veya geri yükleme süreci tarafından kullanılıyor: ${error.message}`,
      { cause: error },
    );
    lockError.code = 'STATE_DIRECTORY_LOCKED';
    throw lockError;
  }
}

export function releaseStateLock(lock) {
  if (!lock) return;
  try {
    lock.exec('ROLLBACK');
  } finally {
    lock.close();
  }
}
