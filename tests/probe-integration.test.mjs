import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import tls from 'node:tls';
import test, { after } from 'node:test';

const temporaryDirectory = mkdtempSync(join(tmpdir(), 'hostcanvas-probes-'));
process.env.TLS_SENTINEL_DATA_DIR = join(temporaryDirectory, 'data');
process.env.TLS_SENTINEL_ALLOW_PRIVATE_TARGETS = 'true';
process.env.TLS_SENTINEL_PUBLIC_DNS_RESOLVER = '';
process.env.TLS_SENTINEL_DNSSEC_RESOLVER = '';
process.env.TLS_SENTINEL_TESTSSL_PATH = join(
  temporaryDirectory,
  'missing-testssl',
);
const keyPath = join(temporaryDirectory, 'key.pem');
const certificatePath = join(temporaryDirectory, 'cert.pem');
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

const [probes, scanner, db] = await Promise.all([
  import('../server/probes/tls.mjs'),
  import('../server/scanner.mjs'),
  import('../server/db.mjs'),
]);
let seenProtocol;
let seenRequest;
const sockets = new Set();
const fixture = tls.createServer(
  {
    key: readFileSync(keyPath),
    cert: readFileSync(certificatePath),
    minVersion: 'TLSv1.2',
    ALPNProtocols: ['h2', 'http/1.1'],
  },
  (socket) => {
    sockets.add(socket);
    socket.on('error', () => undefined);
    socket.once('close', () => sockets.delete(socket));
    socket.once('data', (data) => {
      seenProtocol = socket.alpnProtocol;
      seenRequest = data.toString();
      if (socket.alpnProtocol === 'h2') return socket.destroy();
      socket.end(
        'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nStrict-Transport-Security: max-age=31536000\r\nSet-Cookie: session=not-retained; Secure; HttpOnly; SameSite=Lax\r\nConnection: close\r\n\r\n',
      );
    });
  },
);
await new Promise((resolve, reject) => {
  fixture.once('error', reject);
  fixture.listen(0, '::', resolve);
});
const target = {
  hostname: 'localhost',
  address: '::1',
  family: 6,
  port: fixture.address().port,
};

after(async () => {
  await scanner.stopScanner();
  for (const socket of sockets) socket.destroy();
  await new Promise((resolve) => fixture.close(resolve));
  db.closeDatabase();
  rmSync(temporaryDirectory, { recursive: true, force: true });
});

test('HTTP header probe h2 sunan TLS sunucusunda HTTP/1.1 müzakere eder', async () => {
  const result = await probes.probeHttpHeaders(target);
  assert.equal(seenProtocol, 'http/1.1');
  assert.match(seenRequest, new RegExp(`Host: localhost:${target.port}`));
  assert.equal(result.status, 'complete');
  assert.equal(result.hsts, 'max-age=31536000');
  assert.deepEqual(result.cookies, [
    { name: 'session', sameSite: 'lax', secure: true, httpOnly: true },
  ]);
  assert.equal(JSON.stringify(result).includes('not-retained'), false);
});

test('deep failures preserve findings, open a coverage incident at threshold, and native recovery resolves only coverage', async () => {
  db.updateCheckPolicy({ scanFailureThreshold: 2 });
  const asset = db.createAsset({
    hostname: 'localhost',
    port: target.port,
    label: 'Partial scan fixture',
    owner: 'Test',
    environment: 'development',
    scanProfile: 'deep',
    allowPrivate: true,
    expiryWarningDays: 30,
    scanIntervalMinutes: 720,
  });
  const previous = db.createScan(asset.id, 'deep', 'manual').scan;
  db.finishScan(previous.id, { status: 'succeeded' });
  db.reconcileIncidents(asset.id, previous.id, [
    {
      ruleKey: 'testssl.heartbleed',
      status: 'fail',
      severity: 'critical',
      title: 'Prior deep finding',
      description: 'Must remain open until a complete deep scan.',
    },
  ]);
  const runScan = async (profile = 'deep') => {
    const { scan: queued } = scanner.queueAssetScan(asset.id, { profile });
    for (let attempt = 0; attempt < 200; attempt += 1) {
      const result = db.getScan(queued.id);
      if (!['queued', 'running'].includes(result.status)) return result;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.fail('Fixture scan did not finish within five seconds');
  };
  const scan = await runScan();
  assert.equal(scan.status, 'partial', scan.errorMessage);
  assert.equal(scan.observations.testssl.status, 'failed');
  assert.equal(scan.observations.testssl.error.code, 'TESTSSL_UNAVAILABLE');
  assert.equal(scan.observations.tls.certificate.hostnameMatches, true);
  const incidents = db.listIncidents({ status: 'active' });
  assert.ok(
    incidents.some((incident) => incident.ruleKey === 'cert.chain_untrusted'),
  );
  assert.ok(
    incidents.some((incident) => incident.ruleKey === 'testssl.heartbleed'),
  );
  assert.equal(
    incidents.some((item) => item.ruleKey === 'monitor.scan_unhealthy'),
    false,
  );
  assert.equal((await runScan()).status, 'partial');
  const coverage = db
    .listIncidents({ status: 'active' })
    .find((item) => item.ruleKey === 'monitor.scan_unhealthy');
  assert.ok(coverage);
  assert.equal(coverage.evidence.consecutiveFailures, 2);
  assert.equal(coverage.evidence.threshold, 2);
  const recovered = await runScan('native');
  assert.equal(recovered.status, 'succeeded');
  assert.equal(db.getIncident(coverage.id).status, 'resolved');
  assert.ok(
    db
      .listIncidents({ status: 'active' })
      .some((item) => item.ruleKey === 'testssl.heartbleed'),
  );
});
