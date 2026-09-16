import { randomUUID } from 'node:crypto';
import { copyFile, mkdir, rename, stat, unlink } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { BACKUP_DIRECTORY, DATABASE_PATH } from '../server/config.mjs';

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

let temporary = null;
try {
  const sourceDetails = await stat(source);
  if (!sourceDetails.isFile()) throw new Error('Kaynak bir dosya değil.');
  verifyDatabase(source);

  await mkdir(dirname(target), { recursive: true });
  await mkdir(BACKUP_DIRECTORY, { recursive: true });
  const targetExists = await stat(target)
    .then((details) => details.isFile())
    .catch(() => false);
  if (targetExists) {
    let active;
    try {
      active = new DatabaseSync(target);
      active.exec('PRAGMA busy_timeout = 250');
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
  if (targetExists) await copyFile(target, emergency);

  temporary = resolve(dirname(target), `.restore-${randomUUID()}.db`);
  await copyFile(source, temporary);
  verifyDatabase(temporary);
  await unlink(`${target}-wal`).catch((error) => {
    if (error.code !== 'ENOENT') throw error;
  });
  await unlink(`${target}-shm`).catch((error) => {
    if (error.code !== 'ENOENT') throw error;
  });
  await rename(temporary, target);
  temporary = null;
  console.log(`Geri yükleme tamamlandı: ${target}`);
  if (targetExists)
    console.log(`Önceki veritabanının acil durum kopyası: ${emergency}`);
} catch (error) {
  console.error(`Geri yükleme başarısız: ${error.message}`);
  process.exitCode = 1;
} finally {
  if (temporary) await unlink(temporary).catch(() => {});
}
