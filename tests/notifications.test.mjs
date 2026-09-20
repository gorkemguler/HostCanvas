import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
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
  assert.equal(result.attempts, 1);
});

function fakeRequest(responseAction) {
  return (_options, callback) => {
    const request = new EventEmitter();
    request.destroy = () => undefined;
    request.end = () => {
      if (!responseAction) return;
      const response = new EventEmitter();
      response.statusCode = 200;
      response.destroy = () => undefined;
      callback(response);
      queueMicrotask(() => responseAction(response));
    };
    return request;
  };
}

test('webhook oversized, aborted ve premature-close yanıtlarında kesin olarak reject olur', async () => {
  const url = new URL('https://hooks.example.com/path');
  await assert.rejects(
    notifications.requestWebhook(
      url,
      '203.0.113.10',
      4,
      {},
      {
        requestImpl: fakeRequest((response) =>
          response.emit('data', Buffer.alloc(65)),
        ),
        maximumResponseBytes: 64,
        deadlineMs: 100,
      },
    ),
    (error) => error.code === 'WEBHOOK_RESPONSE_TOO_LARGE',
  );
  await assert.rejects(
    notifications.requestWebhook(
      url,
      '203.0.113.10',
      4,
      {},
      {
        requestImpl: fakeRequest((response) => response.emit('aborted')),
        deadlineMs: 100,
      },
    ),
    (error) => error.code === 'WEBHOOK_RESPONSE_ABORTED',
  );
  await assert.rejects(
    notifications.requestWebhook(
      url,
      '203.0.113.10',
      4,
      {},
      {
        requestImpl: fakeRequest((response) =>
          response.emit(
            'error',
            Object.assign(new Error('reset'), { code: 'ECONNRESET' }),
          ),
        ),
        deadlineMs: 100,
      },
    ),
    (error) => error.code === 'ECONNRESET',
  );
  await assert.rejects(
    notifications.requestWebhook(
      url,
      '203.0.113.10',
      4,
      {},
      {
        requestImpl: fakeRequest((response) => response.emit('close')),
        deadlineMs: 100,
      },
    ),
    (error) => error.code === 'WEBHOOK_RESPONSE_PREMATURE_CLOSE',
  );
});

test('webhook mutlak deadline yavaş veya yanıtsız bağlantıyı sonlandırır', async () => {
  await assert.rejects(
    notifications.requestWebhook(
      new URL('https://hooks.example.com/path'),
      '203.0.113.10',
      4,
      {},
      {
        requestImpl: fakeRequest(null),
        deadlineMs: 10,
      },
    ),
    (error) => error.code === 'WEBHOOK_DEADLINE_EXCEEDED',
  );
});

test('webhook geçici hataları bounded retry ile yeniden dener', async () => {
  const channel = db.createNotificationChannel({
    name: 'Retry test',
    kind: 'generic',
    minSeverity: 'high',
    urlEncrypted: secrets.encryptSecret('https://retry.example.com/hook'),
  });
  let attempts = 0;
  const result = await notifications.testNotificationChannel(channel.id, {
    resolveTarget: async () => ({
      address: '93.184.216.34',
      family: 4,
    }),
    sendRequest: async () => {
      attempts += 1;
      if (attempts < 3) {
        throw Object.assign(new Error('temporary failure'), {
          code: 'ECONNRESET',
        });
      }
      return 204;
    },
    wait: async () => undefined,
    random: () => 0.5,
  });
  assert.equal(result.ok, true);
  assert.equal(result.attempts, 3);
  assert.equal(attempts, 3);
  const deliveries = db
    .listNotificationDeliveries(100)
    .filter((delivery) => delivery.channelId === channel.id);
  assert.equal(deliveries.length, 3);
  assert.equal(
    deliveries.filter((delivery) => delivery.status === 'succeeded').length,
    1,
  );
});

test('webhook deadline DNS aşamasını kapsar ve geç DNS sonucu bağlantı açmaz', async () => {
  const channel = db.createNotificationChannel({
    name: 'DNS deadline',
    kind: 'generic',
    minSeverity: 'high',
    urlEncrypted: secrets.encryptSecret('https://slow.example/hook'),
  });
  let completeDns;
  let requests = 0;
  const result = await notifications.testNotificationChannel(channel.id, {
    maximumAttempts: 1,
    deadlineMs: 10,
    resolveTarget: () =>
      new Promise((resolve) => {
        completeDns = resolve;
      }),
    sendRequest: async () => {
      requests += 1;
      return 200;
    },
  });
  assert.equal(result.ok, false);
  assert.match(result.error, /süre sınırını/);
  completeDns({ address: '8.8.8.8', family: 4 });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(requests, 0);
});

test('webhook permanent HTTP hatalarını tekrar denemez', async () => {
  const channel = db.createNotificationChannel({
    name: 'No retry',
    kind: 'generic',
    minSeverity: 'high',
    urlEncrypted: secrets.encryptSecret('https://hooks.example/hook'),
  });
  const result = await notifications.testNotificationChannel(channel.id, {
    resolveTarget: async () => ({ address: '8.8.8.8', family: 4 }),
    sendRequest: async () => {
      throw Object.assign(new Error('HTTP 400'), { status: 400 });
    },
    wait: async () => assert.fail('permanent failure must not retry'),
  });
  assert.equal(result.attempts, 1);
});

test('webhook global paralellik sınırı eşzamanlı çağrılarda korunur', async () => {
  const channel = db.createNotificationChannel({
    name: 'Concurrency',
    kind: 'generic',
    minSeverity: 'high',
    urlEncrypted: secrets.encryptSecret('https://hooks.example/hook'),
  });
  let active = 0;
  let peak = 0;
  const options = {
    resolveTarget: async () => ({ address: '8.8.8.8', family: 4 }),
    sendRequest: async () => {
      active += 1;
      peak = Math.max(active, peak);
      await new Promise((resolve) => setTimeout(resolve, 10));
      active -= 1;
      return 204;
    },
  };
  const results = await Promise.all(
    Array.from({ length: 12 }, () =>
      notifications.testNotificationChannel(channel.id, options),
    ),
  );
  assert.equal(peak, 4);
  assert.ok(results.every((result) => result.ok));
});

test('webhook shutdown aktif ve bekleyen işleri bekletmeden bitirir', async () => {
  const channel = db.createNotificationChannel({
    name: 'Shutdown',
    kind: 'generic',
    minSeverity: 'high',
    urlEncrypted: secrets.encryptSecret('https://hooks.example/hook'),
  });
  const tasks = Array.from({ length: 8 }, () =>
    notifications.testNotificationChannel(channel.id, {
      resolveTarget: () => new Promise(() => {}),
    }),
  );
  notifications.stopNotificationDeliveries();
  const results = await Promise.all(tasks);
  assert.ok(results.every((result) => !result.ok));
  notifications.startNotificationDeliveries();
  const recovered = await notifications.testNotificationChannel(channel.id, {
    resolveTarget: async () => ({ address: '8.8.8.8', family: 4 }),
    sendRequest: async () => 204,
  });
  assert.equal(recovered.ok, true);
});
