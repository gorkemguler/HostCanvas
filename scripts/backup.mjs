globalThis[Symbol.for('hostcanvas.database.role')] = 'backup';

const [{ closeDatabase }, { createDatabaseBackup }] = await Promise.all([
  import('../server/db.mjs'),
  import('../server/maintenance.mjs'),
]);

try {
  const result = await createDatabaseBackup();
  console.log(`Yedek oluşturuldu: ${result.name} (${result.size} bayt)`);
} catch (error) {
  console.error(`Yedekleme başarısız: ${error.message}`);
  process.exitCode = 1;
} finally {
  closeDatabase();
}
