import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import tls from 'node:tls';

const temporaryDirectory = mkdtempSync(join(tmpdir(), 'tls-sentinel-e2e-'));
const deepScan = process.env.TLS_SENTINEL_E2E_DEEP === '1';
const keyPath = join(temporaryDirectory, 'key.pem');
const certificatePath = join(temporaryDirectory, 'certificate.pem');
const openssl = spawnSync(
  'openssl',
  [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    keyPath,
    '-out',
    certificatePath,
    '-days',
    '2',
    '-subj',
    '/CN=localhost',
    '-addext',
    'subjectAltName=DNS:localhost',
  ],
  { encoding: 'utf8' },
);
assert.equal(openssl.status, 0, openssl.stderr);

const fixture = tls.createServer(
  {
    key: readFileSync(keyPath),
    cert: readFileSync(certificatePath),
    minVersion: 'TLSv1.2',
  },
  (socket) => {
    socket.once('data', () => {
      socket.end(
        'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nStrict-Transport-Security: max-age=31536000\r\nConnection: close\r\n\r\n',
      );
    });
  },
);
await new Promise((resolve, reject) => {
  fixture.once('error', reject);
  fixture.listen(0, '::', resolve);
});
const fixtureAddress = fixture.address();
assert.equal(typeof fixtureAddress, 'object');

process.env.TLS_SENTINEL_DATA_DIR = join(temporaryDirectory, 'data');
process.env.TLS_SENTINEL_ALLOW_PRIVATE_TARGETS = 'true';
process.env.TLS_SENTINEL_API_PORT = '8877';

const [{ createApiServer }, scanner, db] = await Promise.all([
  import('../server/api.mjs'),
  import('../server/scanner.mjs'),
  import('../server/db.mjs'),
]);
const apiServer = createApiServer();
scanner.startScanner();
await new Promise((resolve, reject) => {
  apiServer.once('error', reject);
  apiServer.listen(0, '127.0.0.1', resolve);
});
const apiAddress = apiServer.address();
assert.equal(typeof apiAddress, 'object');
const apiBase = `http://127.0.0.1:${apiAddress.port}`;

async function request(path, init = {}) {
  const response = await fetch(`${apiBase}${path}`, {
    ...init,
    headers: {
      Origin: 'http://localhost:3000',
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
    },
  });
  const body = await response.json();
  assert.equal(response.ok, true, JSON.stringify(body));
  return body;
}

try {
  await request('/api/setup', {
    method: 'POST',
    body: JSON.stringify({
      language: 'tr',
      organization: 'HostCanvas E2E',
      username: 'e2e.admin',
      displayName: 'E2E Admin',
      password: 'E2E-Guclu-Parola-2026',
      authEnabled: false,
      lanEnabled: false,
      allowedOrigins: ['http://localhost:3000'],
      sessionTtlHours: 12,
      defaultScanProfile: deepScan ? 'deep' : 'native',
      defaultExpiryWarningDays: 30,
      defaultScanIntervalMinutes: 720,
    }),
  });

  const created = await request('/api/assets', {
    method: 'POST',
    body: JSON.stringify({
      hostname: 'localhost',
      port: fixtureAddress.port,
      label: 'Yerel TLS fixture',
      owner: 'Test',
      environment: 'development',
      scanProfile: deepScan ? 'deep' : 'native',
      allowPrivate: true,
      authorized: true,
      scanNow: true,
    }),
  });
  assert.ok(created.asset.id);
  assert.ok(created.scan.id);

  let scan;
  for (let attempt = 0; attempt < (deepScan ? 2_600 : 80); attempt += 1) {
    scan = (await request(`/api/scans/${created.scan.id}`)).scan;
    if (!['queued', 'running'].includes(scan.status)) break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.equal(scan.status, 'succeeded', scan.errorMessage);
  assert.equal(scan.observations.tls.certificate.hostnameMatches, true);
  assert.equal(scan.observations.tls.authorized, false);
  if (deepScan) {
    assert.equal(scan.observations.testssl.status, 'complete');
    assert.equal(scan.observations.testssl.exitCode, 0);
    assert.ok(Array.isArray(scan.observations.testssl.findings));
    assert.ok(scan.observations.testssl.engineVersion);
    assert.ok(
      scan.observations.testssl.findings.some(
        (finding) =>
          !['engine_problem', 'scanproblem', 'scantime'].includes(finding.id),
      ),
      'testssl yalnızca başlangıç/fatal metadata üretti; gerçek test bölümü çalışmadı.',
    );
  }

  const dashboard = await request('/api/dashboard');
  assert.equal(dashboard.summary.totalAssets, 1);
  assert.ok(
    dashboard.incidents.some(
      (incident) => incident.ruleKey === 'cert.chain_untrusted',
    ),
  );
  assert.ok(
    dashboard.incidents.some(
      (incident) => incident.ruleKey === 'cert.expiry_window',
    ),
  );
  console.log(
    `E2E başarılı (${deepScan ? 'deep' : 'native'}): ${scan.observations.tls.protocol}, skor ${scan.grade}, ${dashboard.summary.openIncidents} incident`,
  );
} finally {
  await new Promise((resolve) => apiServer.close(resolve));
  await scanner.stopScanner();
  db.closeDatabase();
  await new Promise((resolve) => fixture.close(resolve));
}
