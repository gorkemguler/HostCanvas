import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.TLS_SENTINEL_DATA_DIR = mkdtempSync(
  join(tmpdir(), 'tls-sentinel-auth-'),
);

const db = await import('../server/db.mjs');
const auth = await import('../server/auth.mjs');
after(() => db.closeDatabase());

test('ilk kurulum, parola doğrulama ve hashlenmiş oturum akışı çalışır', async () => {
  assert.equal(db.getAppSettings().setupCompleted, false);
  const password = await auth.hashPassword('CokGuclu-Test-Parolasi-2026');
  const result = db.completeSetup({
    username: auth.validateUsername('soc.admin'),
    displayName: 'SOC Admin',
    ...password,
    language: 'tr',
    organization: 'Example SOC',
    lanEnabled: false,
    authEnabled: true,
    allowedOrigins: ['http://localhost:3000'],
    sessionTtlHours: 12,
    defaultScanProfile: 'native',
    defaultExpiryWarningDays: 30,
    defaultScanIntervalMinutes: 720,
  });

  assert.equal(result.settings.setupCompleted, true);
  assert.equal(
    await auth.verifyPassword('CokGuclu-Test-Parolasi-2026', result.user),
    true,
  );
  assert.equal(await auth.verifyPassword('yanlis-parola', result.user), false);

  const session = auth.createAuthenticatedSession(result.user.id, 12);
  const cookie = auth.sessionCookie(session.token, 12).split(';')[0];
  const authenticated = auth.authenticateRequest({ headers: { cookie } });
  assert.equal(authenticated.username, 'soc.admin');
  assert.notEqual(authenticated.tokenHash, session.token);
});

test('LAN ve dil ayarları kalıcı olarak güncellenir', () => {
  const settings = db.updateAppSettings({
    language: 'en',
    lanEnabled: true,
    authEnabled: true,
    allowedOrigins: ['http://192.168.1.20:3000'],
  });
  assert.equal(settings.language, 'en');
  assert.equal(settings.lanEnabled, true);
  assert.deepEqual(settings.allowedOrigins, ['http://192.168.1.20:3000']);
});

test('RBAC son yöneticiyi korur ve rol değişikliğinde oturumları sonlandırır', async () => {
  const password = await auth.hashPassword('Operator-Test-Password-2026');
  const operator = db.createUser({
    username: 'operator',
    displayName: 'SOC Operator',
    role: 'operator',
    ...password,
  });
  assert.equal(operator.role, 'operator');
  const session = auth.createAuthenticatedSession(operator.id, 12);
  const request = {
    headers: { cookie: auth.sessionCookie(session.token, 12).split(';')[0] },
  };
  assert.ok(auth.authenticateRequest(request));
  db.updateUserAccess(operator.id, { role: 'viewer' });
  assert.equal(auth.authenticateRequest(request), null);

  const admin = db.listUsers().find((user) => user.role === 'admin');
  assert.throws(
    () => db.updateUserAccess(admin.id, { enabled: false }),
    (error) => error.code === 'LAST_ADMIN_REQUIRED',
  );
});

test('audit kayıtları yapılandırılmış metadata ile kalıcıdır', () => {
  db.addAuditEvent({
    actor: 'test-runner',
    action: 'test.audit',
    targetType: 'test',
    summary: 'Audit testi',
    metadata: { safe: true },
  });
  const audit = db.listAuditEvents({ limit: 10 });
  assert.ok(
    audit.events.some(
      (event) => event.action === 'test.audit' && event.metadata.safe,
    ),
  );
});
