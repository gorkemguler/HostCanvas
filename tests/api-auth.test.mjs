import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as httpRequest } from 'node:http';
import test, { after } from 'node:test';

process.env.TLS_SENTINEL_DATA_DIR = mkdtempSync(
  join(tmpdir(), 'tls-sentinel-api-auth-'),
);
process.env.TLS_SENTINEL_API_HOST = '127.0.0.1';
process.env.TLS_SENTINEL_CRT_NAME_ENABLED = 'false';
process.env.TLS_SENTINEL_TRUST_PROXY = 'true';
process.env.TLS_SENTINEL_UI_ORIGINS =
  'http://localhost:3000,http://127.0.0.1:3000,https://console.example.test:3443';

const [{ createApiServer, getSetupCodeForConsole }, db] = await Promise.all([
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
const proxyOrigin = 'https://console.example.test:3443';
const proxyHeaders = {
  Host: 'console.example.test:3443',
  'X-Forwarded-For': '192.0.2.10',
  'X-Forwarded-Proto': 'https',
};

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  db.closeDatabase();
});

async function call(
  path,
  { cookie, origin: requestOrigin = origin, ...init } = {},
) {
  const response = await new Promise((resolve, reject) => {
    const request = httpRequest(
      `${base}${path}`,
      {
        method: init.method || 'GET',
        headers: {
          ...(requestOrigin ? { Origin: requestOrigin } : {}),
          ...(init.body ? { 'Content-Type': 'application/json' } : {}),
          ...(cookie ? { Cookie: cookie } : {}),
          ...init.headers,
        },
      },
      (incoming) => {
        const chunks = [];
        incoming.on('data', (chunk) => chunks.push(chunk));
        incoming.on('error', reject);
        incoming.on('end', () => {
          const headers = new Headers();
          for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
            headers.append(
              incoming.rawHeaders[index],
              incoming.rawHeaders[index + 1],
            );
          }
          resolve(
            new Response(Buffer.concat(chunks), {
              status: incoming.statusCode,
              headers,
            }),
          );
        });
      },
    );
    request.on('error', reject);
    request.end(init.body);
  });
  const body = await response.json();
  return { response, body };
}

test('kurulum, oturum, CORS ve LAN ayarları API sınırında korunur', async () => {
  const setupCode = getSetupCodeForConsole();
  assert.match(setupCode, /^[A-F0-9]{12}$/);
  const invalidSetupCode =
    setupCode === '000000000000' ? '111111111111' : '000000000000';

  const bootstrapBefore = await call('/api/bootstrap');
  assert.equal(bootstrapBefore.response.status, 200);
  assert.equal(bootstrapBefore.body.setupRequired, true);
  assert.equal(bootstrapBefore.body.setupCodeRequired, true);
  assert.equal('setupCode' in bootstrapBefore.body, false);
  assert.ok(bootstrapBefore.body.suggestedOrigins.length >= 2);
  assert.equal(
    bootstrapBefore.response.headers.get('access-control-allow-origin'),
    origin,
  );

  const liveBeforeSetup = await call('/api/health/live', { origin: null });
  assert.equal(liveBeforeSetup.response.status, 200);
  assert.deepEqual(Object.keys(liveBeforeSetup.body).sort(), [
    'name',
    'now',
    'ok',
    'version',
  ]);

  const deniedBootstrapOrigin = await call('/api/bootstrap', {
    origin: 'https://evil.example.test',
  });
  assert.equal(deniedBootstrapOrigin.response.status, 403);
  assert.equal(deniedBootstrapOrigin.body.error.code, 'ORIGIN_DENIED');
  assert.equal(
    deniedBootstrapOrigin.response.headers.get('access-control-allow-origin'),
    null,
  );

  const remoteBootstrap = await call('/api/bootstrap', {
    origin: proxyOrigin,
    headers: proxyHeaders,
  });
  assert.equal(remoteBootstrap.response.status, 200);
  assert.equal(remoteBootstrap.body.setupCodeRequired, true);
  assert.deepEqual(remoteBootstrap.body.suggestedOrigins, []);
  assert.equal('setupCode' in remoteBootstrap.body, false);

  const forwardedRebinding = await call('/api/bootstrap', {
    origin: 'https://rebind.attacker.test:3443',
    headers: { ...proxyHeaders, Host: 'rebind.attacker.test:3443' },
  });
  assert.equal(forwardedRebinding.response.status, 421);
  assert.equal(forwardedRebinding.body.error.code, 'HOST_NOT_ALLOWED');

  for (const malformedHeaders of [
    { 'X-Forwarded-For': 'not-an-ip' },
    { 'X-Forwarded-For': '192.0.2.10, 127.0.0.1' },
    { 'X-Forwarded-Proto': 'https, http' },
    { 'X-Forwarded-Proto': '' },
  ]) {
    const malformedProxy = await call('/api/bootstrap', {
      origin: proxyOrigin,
      headers: { ...proxyHeaders, ...malformedHeaders },
    });
    assert.equal(malformedProxy.response.status, 400);
    assert.equal(malformedProxy.body.error.code, 'INVALID_PROXY_HEADERS');
  }

  const rebindingSetup = await call('/api/setup', {
    method: 'POST',
    origin: `http://rebind.attacker.test:${address.port}`,
    headers: { Host: `rebind.attacker.test:${address.port}` },
    body: JSON.stringify({
      setupCode,
      username: 'attacker',
      password: 'Attacker-Strong-Password-2026',
    }),
  });
  assert.equal(rebindingSetup.response.status, 421);
  assert.equal(rebindingSetup.body.error.code, 'HOST_NOT_ALLOWED');
  assert.equal(
    rebindingSetup.response.headers.get('access-control-allow-origin'),
    null,
  );

  const arbitraryOriginSetup = await call('/api/setup', {
    method: 'POST',
    origin: 'https://evil.example.test',
    body: JSON.stringify({
      setupCode,
      username: 'attacker',
      password: 'Attacker-Strong-Password-2026',
    }),
  });
  assert.equal(arbitraryOriginSetup.response.status, 403);
  assert.equal(arbitraryOriginSetup.body.error.code, 'ORIGIN_DENIED');
  assert.equal(
    arbitraryOriginSetup.response.headers.get('access-control-allow-origin'),
    null,
  );

  const insecureRemoteSetup = await call('/api/setup', {
    method: 'POST',
    origin: 'http://console.example.test:3443',
    headers: {
      ...proxyHeaders,
      'X-Forwarded-Proto': 'http',
    },
    body: JSON.stringify({
      setupCode,
      username: 'admin',
      password: 'Strong-Local-Password-2026',
    }),
  });
  assert.equal(insecureRemoteSetup.response.status, 426);
  assert.equal(insecureRemoteSetup.body.error.code, 'HTTPS_REQUIRED');

  for (const body of ['null', '[]', '"text"', '{invalid']) {
    const invalidJson = await call('/api/setup', { method: 'POST', body });
    assert.equal(invalidJson.response.status, 400);
    assert.equal(invalidJson.body.error.code, 'INVALID_JSON');
  }

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const invalidCode = await call('/api/setup', {
      method: 'POST',
      body: JSON.stringify({
        setupCode: invalidSetupCode,
        username: 'admin',
        password: 'Strong-Local-Password-2026',
      }),
    });
    assert.equal(invalidCode.response.status, 403);
    assert.equal(invalidCode.body.error.code, 'INVALID_SETUP_CODE');
  }
  const limitedLoopbackSetup = await call('/api/setup', {
    method: 'POST',
    body: JSON.stringify({
      setupCode,
      username: 'admin',
      password: 'Strong-Local-Password-2026',
    }),
  });
  assert.equal(limitedLoopbackSetup.response.status, 429);
  assert.equal(limitedLoopbackSetup.body.error.code, 'LOGIN_RATE_LIMITED');

  const invalidSetup = await call('/api/setup', {
    method: 'POST',
    origin: proxyOrigin,
    headers: {
      ...proxyHeaders,
      'X-Forwarded-For': '192.0.2.11',
    },
    body: JSON.stringify({
      setupCode,
      organization: 'Test SOC',
      username: 'admin',
      password: 'short',
    }),
  });
  assert.equal(invalidSetup.response.status, 422);
  assert.equal(invalidSetup.body.error.code, 'INVALID_PASSWORD');

  const setup = await call('/api/setup', {
    method: 'POST',
    origin: proxyOrigin,
    headers: proxyHeaders,
    body: JSON.stringify({
      setupCode,
      language: 'en',
      organization: 'Test SOC',
      username: 'admin',
      displayName: 'Test Admin',
      password: 'Strong-Local-Password-2026',
      authEnabled: true,
      lanEnabled: false,
      allowedOrigins: [origin, 'http://127.0.0.1:3000', proxyOrigin],
      sessionTtlHours: 12,
      defaultScanProfile: 'native',
      defaultExpiryWarningDays: 21,
      defaultScanIntervalMinutes: 360,
    }),
  });
  assert.equal(setup.response.status, 201);
  assert.equal(setup.body.settings.setupCompleted, true);
  assert.equal(setup.body.settings.language, 'en');
  const setupSetCookie = setup.response.headers.get('set-cookie') || '';
  const setupCookie = setupSetCookie.split(';')[0];
  assert.ok(setupCookie?.startsWith('tls_sentinel_session='));
  assert.match(setupSetCookie, /; Secure(?:;|$)/);
  assert.equal(getSetupCodeForConsole(), null);

  const remoteBootstrapAfterSetup = await call('/api/bootstrap', {
    origin: proxyOrigin,
    headers: proxyHeaders,
  });
  assert.equal(remoteBootstrapAfterSetup.response.status, 200);
  assert.equal(remoteBootstrapAfterSetup.body.setupCodeRequired, false);
  assert.deepEqual(remoteBootstrapAfterSetup.body.suggestedOrigins, []);
  assert.equal(remoteBootstrapAfterSetup.body.organization, '');
  assert.equal(remoteBootstrapAfterSetup.body.defaultExpiryWarningDays, 30);

  const remoteAdminBootstrap = await call('/api/bootstrap', {
    origin: proxyOrigin,
    headers: proxyHeaders,
    cookie: setupCookie,
  });
  assert.equal(remoteAdminBootstrap.response.status, 200);
  assert.ok(remoteAdminBootstrap.body.suggestedOrigins.length >= 2);

  const forgedLocalOrigin = await call('/api/session', {
    method: 'POST',
    origin,
    headers: {
      ...proxyHeaders,
      'X-Forwarded-For': '192.0.2.12',
    },
    body: JSON.stringify({
      username: 'admin',
      password: 'Strong-Local-Password-2026',
    }),
  });
  assert.equal(forgedLocalOrigin.response.status, 403);
  assert.equal(forgedLocalOrigin.body.error.code, 'LAN_ACCESS_DISABLED');

  const anonymousDashboard = await call('/api/dashboard');
  assert.equal(anonymousDashboard.response.status, 401);
  assert.equal(anonymousDashboard.body.error.code, 'AUTHENTICATION_REQUIRED');

  const anonymousDetailedHealth = await call('/api/health');
  assert.equal(anonymousDetailedHealth.response.status, 401);
  const publicLiveHealth = await call('/api/health/live', { origin: null });
  assert.equal(publicLiveHealth.response.status, 200);
  assert.equal('engines' in publicLiveHealth.body, false);
  assert.equal('bind' in publicLiveHealth.body, false);

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

  const policyBefore = await call('/api/check-policy', { cookie: loginCookie });
  assert.equal(policyBefore.response.status, 200);
  assert.equal(policyBefore.body.policy.scanFailureThreshold, 3);
  const policySaved = await call('/api/check-policy', {
    cookie: loginCookie,
    method: 'PATCH',
    body: JSON.stringify({
      scanFailureThreshold: 2,
      sessionCookieNames: ['session'],
      caaRequired: true,
    }),
  });
  assert.equal(policySaved.response.status, 200);
  assert.equal(policySaved.body.policy.scanFailureThreshold, 2);
  const badPolicy = await call('/api/check-policy', {
    cookie: loginCookie,
    method: 'PATCH',
    body: JSON.stringify({ scanFailureThreshold: '2' }),
  });
  assert.equal(badPolicy.response.status, 422);
  assert.equal(badPolicy.body.error.code, 'INVALID_CHECK_POLICY');
  const anonymousPolicy = await call('/api/check-policy');
  assert.equal(anonymousPolicy.response.status, 401);

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
  assert.equal(
    (await call('/api/check-policy', { cookie: viewerCookie })).response.status,
    200,
  );
  assert.equal(
    (
      await call('/api/check-policy', {
        cookie: viewerCookie,
        method: 'PATCH',
        body: JSON.stringify({ caaRequired: false }),
      })
    ).response.status,
    403,
  );

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
  assert.equal(
    (
      await call('/api/check-policy', {
        cookie: operatorCookie,
        method: 'PATCH',
        body: JSON.stringify({ caaRequired: false }),
      })
    ).response.status,
    403,
  );
  assert.equal(db.getCheckPolicy().policy.caaRequired, true);
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

  const insecureLanSettings = await call('/api/settings', {
    method: 'PATCH',
    cookie: loginCookie,
    body: JSON.stringify({
      lanEnabled: true,
      authEnabled: false,
      allowedOrigins: [origin, 'http://192.168.1.20:3000'],
    }),
  });
  assert.equal(insecureLanSettings.response.status, 422);
  assert.equal(insecureLanSettings.body.error.code, 'LAN_HTTPS_REQUIRED');

  const lanSettings = await call('/api/settings', {
    method: 'PATCH',
    cookie: loginCookie,
    body: JSON.stringify({
      lanEnabled: true,
      authEnabled: false,
      allowedOrigins: [origin, proxyOrigin],
    }),
  });
  assert.equal(lanSettings.response.status, 200);
  assert.equal(lanSettings.body.settings.lanEnabled, true);
  assert.equal(lanSettings.body.settings.authEnabled, true);
  assert.equal(
    lanSettings.response.headers.get('access-control-allow-origin'),
    origin,
  );

  const insecureRemoteLogin = await call('/api/session', {
    method: 'POST',
    origin: proxyOrigin,
    headers: {
      ...proxyHeaders,
      'X-Forwarded-Proto': 'http',
      'X-Forwarded-For': '192.0.2.20',
    },
    body: JSON.stringify({
      username: 'admin',
      password: 'Strong-Local-Password-2026',
    }),
  });
  assert.equal(insecureRemoteLogin.response.status, 426);
  assert.equal(insecureRemoteLogin.body.error.code, 'HTTPS_REQUIRED');

  const secureRemoteLogin = await call('/api/session', {
    method: 'POST',
    origin: proxyOrigin,
    headers: {
      ...proxyHeaders,
      'X-Forwarded-For': '192.0.2.20',
    },
    body: JSON.stringify({
      username: 'admin',
      password: 'Strong-Local-Password-2026',
    }),
  });
  assert.equal(secureRemoteLogin.response.status, 200);
  assert.match(
    secureRemoteLogin.response.headers.get('set-cookie') || '',
    /; Secure(?:;|$)/,
  );

  const parallelLoginAttempts = await Promise.all(
    Array.from({ length: 10 }, () =>
      call('/api/session', {
        method: 'POST',
        origin: proxyOrigin,
        headers: { ...proxyHeaders, 'X-Forwarded-For': '192.0.2.30' },
        body: JSON.stringify({
          username: 'admin',
          password: 'incorrect-password',
        }),
      }),
    ),
  );
  assert.ok(
    parallelLoginAttempts.some(({ response }) => response.status === 429),
  );
  assert.ok(
    parallelLoginAttempts.every(({ response }) =>
      [401, 429].includes(response.status),
    ),
  );
  const blockedAfterParallelFailures = await call('/api/session', {
    method: 'POST',
    origin: proxyOrigin,
    headers: { ...proxyHeaders, 'X-Forwarded-For': '192.0.2.30' },
    body: JSON.stringify({
      username: 'admin',
      password: 'Strong-Local-Password-2026',
    }),
  });
  assert.equal(blockedAfterParallelFailures.response.status, 429);

  const logout = await call('/api/session', {
    method: 'DELETE',
    cookie: loginCookie,
  });
  assert.equal(logout.response.status, 200);
  assert.match(logout.response.headers.get('set-cookie') || '', /Max-Age=0/);

  const expiredSession = await call('/api/dashboard', { cookie: loginCookie });
  assert.equal(expiredSession.response.status, 401);
});
