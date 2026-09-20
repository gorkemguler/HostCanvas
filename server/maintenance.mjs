import { randomUUID } from 'node:crypto';
import {
  chmod,
  mkdir,
  open,
  readdir,
  rename,
  stat,
  unlink,
} from 'node:fs/promises';
import { join } from 'node:path';
import { backup, DatabaseSync } from 'node:sqlite';

import { ARTIFACT_DIRECTORY, BACKUP_DIRECTORY } from './config.mjs';
import {
  database,
  getMaintenanceSettings,
  pruneExpiredSessions,
  pruneScanHistory,
} from './db.mjs';

let maintenanceTimer;
let runningPromise = null;

function backupName(date = new Date()) {
  return `tlsentinel-${date.toISOString().replaceAll(':', '').replaceAll('-', '').replace('.000Z', 'Z')}.db`;
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

async function removeBackupSidecars(path) {
  await Promise.all([
    unlinkIfPresent(`${path}-wal`),
    unlinkIfPresent(`${path}-shm`),
  ]);
}

export async function listBackups() {
  await ensurePrivateDirectory(BACKUP_DIRECTORY);
  const names = await readdir(BACKUP_DIRECTORY);
  const backups = [];
  for (const name of names) {
    if (!/^tlsentinel-\d{8}T\d{6}(?:\.\d{3})?Z\.db$/.test(name)) continue;
    const path = join(BACKUP_DIRECTORY, name);
    const details = await stat(path);
    backups.push({
      name,
      size: details.size,
      createdAt: details.mtime.toISOString(),
    });
  }
  return backups.sort((first, second) =>
    second.createdAt.localeCompare(first.createdAt),
  );
}

async function pruneBackups(retentionCount) {
  const backups = await listBackups();
  for (const item of backups.slice(retentionCount)) {
    const path = join(BACKUP_DIRECTORY, item.name);
    await unlink(path);
    await removeBackupSidecars(path);
  }
  return Math.max(0, backups.length - retentionCount);
}

export async function createDatabaseBackup() {
  await ensurePrivateDirectory(BACKUP_DIRECTORY);
  const temporary = join(BACKUP_DIRECTORY, `.backup-${randomUUID()}.db`);
  let backupDatabase;
  let destination;
  let name;
  try {
    await backup(database, temporary);
    await chmod(temporary, 0o600);
    backupDatabase = new DatabaseSync(temporary);
    backupDatabase.exec('PRAGMA journal_mode = DELETE');
    const integrity = backupDatabase.prepare('PRAGMA quick_check').get();
    if (integrity.quick_check !== 'ok') {
      throw new Error(
        'Veritabanı bütünlük kontrolü başarısız olduğu için yedek oluşturulmadı.',
      );
    }
    backupDatabase.close();
    backupDatabase = null;
    // Reserve a unique timestamp even when CLI and scheduled backups overlap.
    for (let timestamp = Date.now(); ; timestamp += 1) {
      name = backupName(new Date(timestamp));
      const candidate = join(BACKUP_DIRECTORY, name);
      try {
        const reservation = await open(candidate, 'wx', 0o600);
        await reservation.close();
        destination = candidate;
        break;
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
      }
    }
    await rename(temporary, destination);
  } catch (error) {
    if (destination) await unlinkIfPresent(destination);
    throw error;
  } finally {
    backupDatabase?.close();
    await unlinkIfPresent(temporary);
    await removeBackupSidecars(temporary);
  }
  const details = await stat(destination);
  await pruneBackups(getMaintenanceSettings().backupRetentionCount);
  return { name, size: details.size, createdAt: details.mtime.toISOString() };
}

export function resolveBackupPath(name) {
  if (!/^tlsentinel-\d{8}T\d{6}(?:\.\d{3})?Z\.db$/.test(String(name || ''))) {
    return null;
  }
  return join(BACKUP_DIRECTORY, name);
}

async function cleanupArtifacts(retentionDays) {
  await ensurePrivateDirectory(ARTIFACT_DIRECTORY);
  const cutoff = Date.now() - retentionDays * 86_400_000;
  let removed = 0;
  for (const name of await readdir(ARTIFACT_DIRECTORY)) {
    if (!/^[a-f0-9-]{36}\.json$/i.test(name)) continue;
    const path = join(ARTIFACT_DIRECTORY, name);
    const details = await stat(path);
    if (details.mtimeMs >= cutoff) continue;
    await unlink(path);
    removed += 1;
  }
  return removed;
}

export async function runMaintenance({ forceBackup = false } = {}) {
  if (runningPromise) {
    await runningPromise;
    if (!forceBackup) return { skipped: true };
  }
  runningPromise = (async () => {
    const settings = getMaintenanceSettings();
    pruneExpiredSessions();
    const removedScans = pruneScanHistory(settings.scanRetentionDays);
    const removedArtifacts = await cleanupArtifacts(
      settings.artifactRetentionDays,
    );
    const backups = await listBackups();
    const newestBackupAt = backups[0] ? Date.parse(backups[0].createdAt) : 0;
    const backupDue =
      Date.now() - newestBackupAt >= settings.backupIntervalHours * 3_600_000;
    const createdBackup =
      forceBackup || backupDue ? await createDatabaseBackup() : null;
    const removedBackups = await pruneBackups(settings.backupRetentionCount);
    return {
      skipped: false,
      removedScans: removedScans.length,
      removedArtifacts,
      removedBackups,
      createdBackup,
    };
  })();
  try {
    return await runningPromise;
  } finally {
    runningPromise = null;
  }
}

export function startMaintenance() {
  void runMaintenance().catch((error) =>
    console.error('[maintenance]', error.message),
  );
  maintenanceTimer = setInterval(() => {
    void runMaintenance().catch((error) =>
      console.error('[maintenance]', error.message),
    );
  }, 60 * 60_000);
  maintenanceTimer.unref();
}

export async function stopMaintenance() {
  if (maintenanceTimer) clearInterval(maintenanceTimer);
  maintenanceTimer = undefined;
  await runningPromise;
}
