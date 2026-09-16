import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { after } from 'node:test';

process.env.TLS_SENTINEL_DATA_DIR = mkdtempSync(
  join(tmpdir(), 'tls-sentinel-notifications-'),
);

const [secrets, notifications, db] = await Promise.all([
  import('../server/secrets.mjs'),
  import('../server/notifications.mjs'),
  import('../server/db.mjs'),
]);

after(() => db.closeDatabase());

test('webhook secret AES-GCM ile round-trip olur ve plaintext saklanmaz', () => {
  const plaintext = 'https://example.com/hooks/super-secret';
  const encrypted = secrets.encryptSecret(plaintext);
  assert.notEqual(encrypted, plaintext);
  assert.equal(encrypted.includes('super-secret'), false);
  assert.equal(secrets.decryptSecret(encrypted), plaintext);
});

test('webhook URL politikası HTTPS/443 ve credentials zorunluluğunu uygular', () => {
  assert.equal(
    notifications.validateWebhookUrl('https://hooks.example.com/path#fragment'),
    'https://hooks.example.com/path',
  );
  for (const value of [
    'http://hooks.example.com/path',
    'https://user:pass@hooks.example.com/path',
    'https://hooks.example.com:8443/path',
    'https://127.0.0.1/path',
  ]) {
    assert.throws(() => notifications.validateWebhookUrl(value));
  }
});

test('webhook teslimatı private DNS hedefine bağlantı kurmadan engellenir ve kaydedilir', async () => {
  const channel = db.createNotificationChannel({
    name: 'Private target test',
    kind: 'generic',
    minSeverity: 'high',
    urlEncrypted: secrets.encryptSecret('https://localhost/hook'),
  });
  const result = await notifications.testNotificationChannel(channel.id);
  assert.equal(result.ok, false);
  assert.match(result.error, /public olmayan IP/);
  const deliveries = db.listNotificationDeliveries();
  assert.equal(deliveries[0].status, 'failed');
  assert.equal(deliveries[0].channelName, 'Private target test');
});
