import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { after } from 'node:test';

process.env.TLS_SENTINEL_DATA_DIR = mkdtempSync(
  join(tmpdir(), 'tls-sentinel-api-auth-'),
);
process.env.TLS_SENTINEL_API_HOST = '127.0.0.1';
process.env.TLS_SENTINEL_CRT_NAME_ENABLED = 'false';

const [{ createApiServer }, db] = await Promise.all([
  import('../server/api.mjs'),
  import('../server/db.mjs'),
]);

const server = createApiServer();
await new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', resolve);
});
const address = server.address();
assert.equal(typeof address, 'object');
const base = `http://127.0.0.1:${address.port}`;
const origin = 'http://localhost:3000';

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  db.closeDatabase();
});

async function call(path, { cookie, ...init } = {}) {
  const response = await fetch(`${base}${path}`, {
    ...init,
    headers: {
      Origin: origin,
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      ...(cookie ? { Cookie: cookie } : {}),
      ...init.headers,
    },
  });
  const body = await response.json();
  return { response, body };
}

test('kurulum, oturum, CORS ve LAN ayarları API sınırında korunur', async () => {
  const bootstrapBefore = await call('/api/bootstrap');
  assert.equal(bootstrapBefore.response.status, 200);
  assert.equal(bootstrapBefore.body.setupRequired, true);
  assert.equal(
    bootstrapBefore.response.headers.get('access-control-allow-origin'),
    origin,
  );

  const invalidSetup = await call('/api/setup', {
    method: 'POST',
    body: JSON.stringify({
      organization: 'Test SOC',
      username: 'admin',
      password: 'short',
    }),
  });
  assert.equal(invalidSetup.response.status, 422);
  assert.equal(invalidSetup.body.error.code, 'INVALID_PASSWORD');

  const setup = await call('/api/setup', {
    method: 'POST',
    body: JSON.stringify({
      language: 'en',
      organization: 'Test SOC',
      username: 'admin',
      displayName: 'Test Admin',
      password: 'Strong-Local-Password-2026',
      authEnabled: true,
      lanEnabled: false,
      allowedOrigins: [origin, 'http://127.0.0.1:3000'],
      sessionTtlHours: 12,
      defaultScanProfile: 'native',
      defaultExpiryWarningDays: 21,
      defaultScanIntervalMinutes: 360,
    }),
  });
  assert.equal(setup.response.status, 201);
  assert.equal(setup.body.settings.setupCompleted, true);
  assert.equal(setup.body.settings.language, 'en');
  const setupCookie = setup.response.headers.get('set-cookie')?.split(';')[0];
  assert.ok(setupCookie?.startsWith('tls_sentinel_session='));

  const anonymousDashboard = await call('/api/dashboard');
  assert.equal(anonymousDashboard.response.status, 401);
  assert.equal(anonymousDashboard.body.error.code, 'AUTHENTICATION_REQUIRED');

  const protectedDashboard = await call('/api/dashboard', {
    cookie: setupCookie,
  });
  assert.equal(protectedDashboard.response.status, 200);
  assert.equal(protectedDashboard.body.summary.totalAssets, 0);
  const health = await call('/api/health', { cookie: setupCookie });
  assert.equal(health.response.status, 200);
  assert.equal(health.body.name, 'HostCanvas');
  assert.equal(health.body.version, '0.3.0');
  assert.equal(health.body.subdomainDiscovery.provider, 'crt.name');
  assert.equal(health.body.subdomainDiscovery.enabled, false);

  const oversizedPassword = await call('/api/session', {
    method: 'POST',
    body: JSON.stringify({ username: 'admin', password: 'x'.repeat(500) }),
  });
  assert.equal(oversizedPassword.response.status, 401);

  const login = await call('/api/session', {
    method: 'POST',
    body: JSON.stringify({
      username: 'admin',
      password: 'Strong-Local-Password-2026',
    }),
  });
  assert.equal(login.response.status, 200);
  const loginCookie = login.response.headers.get('set-cookie')?.split(';')[0];
  assert.ok(loginCookie);

  const viewerCreated = await call('/api/users', {
    method: 'POST',
    cookie: loginCookie,
    body: JSON.stringify({
      username: 'audit.viewer',
      displayName: 'Audit Viewer',
      password: 'Viewer-Strong-Password-2026',
      role: 'viewer',
    }),
  });
  assert.equal(viewerCreated.response.status, 201);
  assert.equal(viewerCreated.body.user.role, 'viewer');

  const operatorCreated = await call('/api/users', {
    method: 'POST',
    cookie: loginCookie,
    body: JSON.stringify({
      username: 'scan.operator',
      displayName: 'Scan Operator',
      password: 'Operator-Strong-Password-2026',
      role: 'operator',
    }),
  });
  assert.equal(operatorCreated.response.status, 201);

  const viewerLogin = await call('/api/session', {
    method: 'POST',
    body: JSON.stringify({
      username: 'audit.viewer',
      password: 'Viewer-Strong-Password-2026',
    }),
  });
  const viewerCookie = viewerLogin.response.headers
    .get('set-cookie')
    ?.split(';')[0];
  assert.equal(viewerLogin.response.status, 200);
  assert.ok(viewerCookie);

  const viewerMutation = await call('/api/assets', {
    method: 'POST',
    cookie: viewerCookie,
    body: JSON.stringify({
      hostname: 'example.com',
      port: 443,
      authorized: true,
    }),
  });
  assert.equal(viewerMutation.response.status, 403);
  assert.equal(viewerMutation.body.error.code, 'INSUFFICIENT_ROLE');
  const viewerRead = await call('/api/dashboard', { cookie: viewerCookie });
  assert.equal(viewerRead.response.status, 200);

  const operatorLogin = await call('/api/session', {
    method: 'POST',
    body: JSON.stringify({
      username: 'scan.operator',
      password: 'Operator-Strong-Password-2026',
    }),
  });
  const operatorCookie = operatorLogin.response.headers
    .get('set-cookie')
    ?.split(';')[0];
  assert.equal(operatorLogin.response.status, 200);
  assert.ok(operatorCookie);
  const operatorSettings = await call('/api/settings', {
    method: 'PATCH',
    cookie: operatorCookie,
    body: JSON.stringify({ organization: 'Not allowed' }),
  });
  assert.equal(operatorSettings.response.status, 403);
  const operatorAsset = await call('/api/assets', {
    method: 'POST',
    cookie: operatorCookie,
    body: JSON.stringify({
      hostname: 'example.com',
      port: 443,
      label: 'Operator asset',
      authorized: true,
      scanNow: false,
      discoverSubdomains: true,
    }),
  });
  assert.equal(operatorAsset.response.status, 201);
  assert.equal(operatorAsset.body.discovery.status, 'disabled');
  assert.equal(operatorAsset.body.discovery.createdCount, 0);

  const users = await call('/api/users', { cookie: loginCookie });
  assert.equal(users.response.status, 200);
  assert.equal(users.body.users.length, 3);

  const lastAdmin = await call(`/api/users/${setup.body.user.id}`, {
    method: 'PATCH',
    cookie: loginCookie,
    body: JSON.stringify({ role: 'viewer' }),
  });
  assert.equal(lastAdmin.response.status, 409);
  assert.equal(lastAdmin.body.error.code, 'LAST_ADMIN_REQUIRED');

  const webhook = await call('/api/notifications/channels', {
    method: 'POST',
    cookie: loginCookie,
    body: JSON.stringify({
      name: 'SOC webhook',
      kind: 'generic',
      webhookUrl: 'https://example.com/secret/path?token=hidden',
      minSeverity: 'high',
    }),
  });
  assert.equal(webhook.response.status, 201);
  assert.equal(webhook.body.channel.endpoint, 'example.com');
  assert.equal(JSON.stringify(webhook.body).includes('secret/path'), false);
  assert.equal(JSON.stringify(webhook.body).includes('token=hidden'), false);

  const maintenance = await call('/api/backups', {
    method: 'POST',
    cookie: loginCookie,
    body: '{}',
  });
  assert.equal(maintenance.response.status, 201);
  assert.match(maintenance.body.backup.name, /^tlsentinel-.*\.db$/);

  const audit = await call('/api/audit?limit=100', { cookie: loginCookie });
  assert.equal(audit.response.status, 200);
  assert.ok(audit.body.events.some((event) => event.action === 'user.created'));
  assert.ok(
    audit.body.events.some((event) => event.action === 'backup.created'),
  );

  const lanSettings = await call('/api/settings', {
    method: 'PATCH',
    cookie: loginCookie,
    body: JSON.stringify({
      lanEnabled: true,
      authEnabled: false,
      allowedOrigins: [origin, 'http://192.168.1.20:3000'],
    }),
  });
  assert.equal(lanSettings.response.status, 200);
  assert.equal(lanSettings.body.settings.lanEnabled, true);
  assert.equal(lanSettings.body.settings.authEnabled, true);
  assert.equal(
    lanSettings.response.headers.get('access-control-allow-origin'),
    origin,
  );

  const logout = await call('/api/session', {
    method: 'DELETE',
    cookie: loginCookie,
  });
  assert.equal(logout.response.status, 200);
  assert.match(logout.response.headers.get('set-cookie') || '', /Max-Age=0/);

  const expiredSession = await call('/api/dashboard', { cookie: loginCookie });
  assert.equal(expiredSession.response.status, 401);
});
