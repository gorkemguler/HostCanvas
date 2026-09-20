import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
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

function permissionBits(path) {
  return statSync(path).mode & 0o777;
}

function waitUntilReady(child) {
  return new Promise((resolve, reject) => {
    let stderr = '';
    const timer = setTimeout(() => {
      reject(new Error(`Kilit süreci hazır olmadı: ${stderr}`));
    }, 5_000);
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.stdout.on('data', (chunk) => {
      if (!String(chunk).includes('ready')) return;
      clearTimeout(timer);
      resolve();
    });
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`Kilit süreci erken kapandı (${code}): ${stderr}`));
    });
  });
}

function waitForExit(child) {
  return new Promise((resolve) => child.once('exit', resolve));
}

test('SQLite yedeği doğrulanır ve restore aracı kurtarma kopyası oluşturur', async () => {
  const backup = await maintenance.createDatabaseBackup();
  assert.match(backup.name, /^tlsentinel-\d{8}T\d{6}(?:\.\d{3})?Z\.db$/);
  assert.ok(backup.size > 0);
  const backupPath = join(sourceDirectory, 'backups', backup.name);
  assert.equal(existsSync(`${backupPath}-wal`), false);
  assert.equal(existsSync(`${backupPath}-shm`), false);
  if (process.platform !== 'win32') {
    assert.equal(permissionBits(sourceDirectory), 0o700);
    assert.equal(permissionBits(join(sourceDirectory, 'backups')), 0o700);
    assert.equal(permissionBits(backupPath), 0o600);
  }

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

  const holder = spawn(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      [
        "const db = await import('./server/db.mjs');",
        'const stop = () => { db.closeDatabase(); process.exit(0); };',
        "process.on('SIGINT', stop);",
        "process.on('SIGTERM', stop);",
        "console.log('ready');",
        'setInterval(() => {}, 1_000);',
      ].join(' '),
    ],
    {
      cwd: process.cwd(),
      env: environment,
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  await waitUntilReady(holder);
  try {
    const liveBackup = spawnSync(process.execPath, ['scripts/backup.mjs'], {
      cwd: process.cwd(),
      env: environment,
      encoding: 'utf8',
    });
    assert.equal(liveBackup.status, 0, liveBackup.stderr);
    assert.match(liveBackup.stdout, /Yedek oluşturuldu/);
    const duplicateApp = spawnSync(
      process.execPath,
      ['--input-type=module', '-e', "await import('./server/db.mjs')"],
      {
        cwd: process.cwd(),
        env: environment,
        encoding: 'utf8',
      },
    );
    assert.notEqual(duplicateApp.status, 0);
    assert.match(duplicateApp.stderr, /STATE_DIRECTORY_LOCKED/);
    const rejectedRestore = spawnSync(
      process.execPath,
      ['scripts/restore.mjs', backupPath, '--confirm'],
      { cwd: process.cwd(), env: environment, encoding: 'utf8' },
    );
    assert.notEqual(rejectedRestore.status, 0);
    assert.match(rejectedRestore.stderr, /uygulama çalışırken/i);
  } finally {
    holder.kill('SIGTERM');
    await waitForExit(holder);
  }

  const restore = spawnSync(
    process.execPath,
    ['scripts/restore.mjs', backupPath, '--confirm'],
    { cwd: process.cwd(), env: environment, encoding: 'utf8' },
  );
  assert.equal(restore.status, 0, restore.stderr);
  assert.match(restore.stdout, /Geri yükleme tamamlandı/);
  assert.ok(
    readdirSync(join(targetDirectory, 'backups')).some((name) =>
      name.startsWith('pre-restore-'),
    ),
  );
  if (process.platform !== 'win32') {
    assert.equal(permissionBits(targetDirectory), 0o700);
    assert.equal(permissionBits(join(targetDirectory, 'backups')), 0o700);
    assert.equal(permissionBits(join(targetDirectory, 'tlsentinel.db')), 0o600);
    assert.equal(
      permissionBits(join(targetDirectory, '.state-lock.db')),
      0o600,
    );
  }
});
