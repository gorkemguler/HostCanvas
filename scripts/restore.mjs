import { randomUUID } from 'node:crypto';
import { chmod, copyFile, mkdir, rename, stat, unlink } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import { backup, DatabaseSync } from 'node:sqlite';

import {
  BACKUP_DIRECTORY,
  DATA_DIRECTORY,
  DATABASE_PATH,
} from '../server/config.mjs';
import { acquireStateLock, releaseStateLock } from '../server/state-lock.mjs';

process.umask(0o077);

const args = process.argv.slice(2);
const sourceArgument = args.find((argument) => argument !== '--confirm');

if (!sourceArgument || !args.includes('--confirm')) {
  console.error('Kullanım: npm run restore -- /tam/yol/yedek.db --confirm');
  console.error('Geri yüklemeden önce HostCanvas süreçlerini durdurun.');
  process.exit(2);
}

const source = resolve(sourceArgument);
const target = resolve(DATABASE_PATH);
if (source === target) {
  console.error('Kaynak yedek, çalışan veritabanıyla aynı dosya olamaz.');
  process.exit(2);
}

function verifyDatabase(path) {
  const candidate = new DatabaseSync(path, { readOnly: true });
  try {
    const integrity = candidate.prepare('PRAGMA quick_check').get();
    if (!integrity || Object.values(integrity)[0] !== 'ok') {
      throw new Error('SQLite quick_check başarısız.');
    }
    const required = new Set([
      'assets',
      'scans',
      'incidents',
      'app_settings',
      'users',
    ]);
    const tables = candidate
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
      .all()
      .map((row) => row.name);
    for (const name of required) {
      if (!tables.includes(name))
        throw new Error(`Gerekli tablo bulunamadı: ${name}`);
    }
  } finally {
    candidate.close();
  }
}

async function ensurePrivateDirectory(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  await chmod(path, 0o700);
}

async function unlinkIfPresent(path) {
  await unlink(path).catch((error) => {
    if (error.code !== 'ENOENT') throw error;
  });
}

async function removeSidecars(path) {
  await Promise.all([
    unlinkIfPresent(`${path}-wal`),
    unlinkIfPresent(`${path}-shm`),
  ]);
}

let temporary = null;
let restoreLock = null;
try {
  await ensurePrivateDirectory(DATA_DIRECTORY);
  await ensurePrivateDirectory(BACKUP_DIRECTORY);
  restoreLock = acquireStateLock(DATA_DIRECTORY, 'restore');

  const sourceDetails = await stat(source);
  if (!sourceDetails.isFile()) throw new Error('Kaynak bir dosya değil.');
  verifyDatabase(source);

  const targetExists = await stat(target)
    .then((details) => details.isFile())
    .catch(() => false);
  if (targetExists) {
    let active;
    try {
      active = new DatabaseSync(target);
      active.exec('PRAGMA busy_timeout = 250');
      const checkpoint = active
        .prepare('PRAGMA wal_checkpoint(TRUNCATE)')
        .get();
      if (checkpoint.busy) throw new Error('WAL checkpoint tamamlanamadı.');
      active.exec('BEGIN EXCLUSIVE');
      active.exec('ROLLBACK');
    } catch (error) {
      throw new Error(
        `Çalışan veritabanı kilitli. Önce uygulamayı durdurun: ${error.message}`,
      );
    } finally {
      active?.close();
    }
  }

  const stamp = new Date()
    .toISOString()
    .replaceAll(':', '')
    .replaceAll('-', '');
  const emergency = resolve(
    BACKUP_DIRECTORY,
    `pre-restore-${stamp}-${basename(target)}`,
  );
  if (targetExists) {
    await copyFile(target, emergency);
    await chmod(emergency, 0o600);
  }

  temporary = resolve(dirname(target), `.restore-${randomUUID()}.db`);
  // SQLite's backup API also captures committed data in a source WAL file.
  // A raw copy of the .db alone could silently restore an older snapshot.
  const sourceDatabase = new DatabaseSync(source, { readOnly: true });
  try {
    await backup(sourceDatabase, temporary);
  } finally {
    sourceDatabase.close();
  }
  await chmod(temporary, 0o600);
  verifyDatabase(temporary);
  await removeSidecars(temporary);
  await removeSidecars(target);
  await rename(temporary, target);
  temporary = null;
  await chmod(target, 0o600);
  console.log(`Geri yükleme tamamlandı: ${target}`);
  if (targetExists)
    console.log(`Önceki veritabanının acil durum kopyası: ${emergency}`);
} catch (error) {
  console.error(`Geri yükleme başarısız: ${error.message}`);
  process.exitCode = 1;
} finally {
  if (temporary) {
    await unlinkIfPresent(temporary).catch(() => {});
    await removeSidecars(temporary).catch(() => {});
  }
  releaseStateLock(restoreLock);
}
