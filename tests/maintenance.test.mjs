import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test, { after } from 'node:test';

const sourceDirectory = mkdtempSync(
  join(tmpdir(), 'tls-sentinel-backup-source-'),
);
process.env.TLS_SENTINEL_DATA_DIR = sourceDirectory;

const [db, maintenance] = await Promise.all([
  import('../server/db.mjs'),
  import('../server/maintenance.mjs'),
]);

after(() => db.closeDatabase());

test('SQLite yedeği doğrulanır ve restore aracı kurtarma kopyası oluşturur', async () => {
  const backup = await maintenance.createDatabaseBackup();
  assert.match(backup.name, /^tlsentinel-\d{8}T\d{6}(?:\.\d{3})?Z\.db$/);
  assert.ok(backup.size > 0);

  const targetDirectory = mkdtempSync(
    join(tmpdir(), 'tls-sentinel-backup-target-'),
  );
  const environment = {
    ...process.env,
    TLS_SENTINEL_DATA_DIR: targetDirectory,
  };
  const initialize = spawnSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      "import('./server/db.mjs').then((db) => db.closeDatabase())",
    ],
    { cwd: process.cwd(), env: environment, encoding: 'utf8' },
  );
  assert.equal(initialize.status, 0, initialize.stderr);

  const restore = spawnSync(
    process.execPath,
    [
      'scripts/restore.mjs',
      join(sourceDirectory, 'backups', backup.name),
      '--confirm',
    ],
    { cwd: process.cwd(), env: environment, encoding: 'utf8' },
  );
  assert.equal(restore.status, 0, restore.stderr);
  assert.match(restore.stdout, /Geri yükleme tamamlandı/);
  assert.ok(
    readdirSync(join(targetDirectory, 'backups')).some((name) =>
      name.startsWith('pre-restore-'),
    ),
  );
});
