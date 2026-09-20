import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

process.env.TLS_SENTINEL_DATA_DIR = mkdtempSync(
  join(tmpdir(), 'tls-sentinel-db-'),
);

const db = await import('../server/db.mjs');
after(() => db.closeDatabase());

test('incident fail ile açılır, unknown ile kapanmaz, pass ile çözülür ve tekrar açılır', () => {
  const asset = db.createAsset({
    hostname: 'api.example.com',
    port: 443,
    label: 'API',
    owner: 'Platform',
    environment: 'production',
    scanProfile: 'native',
    expiryWarningDays: 30,
    scanIntervalMinutes: 720,
  });
  const scan = db.createScan(asset.id, 'native', 'manual').scan;
  const failing = {
    ruleKey: 'cert.expiry_window',
    status: 'fail',
    severity: 'high',
    title: 'Sertifika 7 gün içinde sona eriyor',
    description: 'Yenileme gerekli.',
    evidence: { daysRemaining: 7 },
  };

  db.reconcileIncidents(asset.id, scan.id, [failing]);
  let incident = db.listIncidents({ status: 'active' })[0];
  assert.equal(incident.status, 'open');
  assert.equal(incident.occurrenceCount, 1);

  db.updateIncidentStatus(incident.id, 'acknowledged');
  db.reconcileIncidents(asset.id, scan.id, [
    { ruleKey: 'cert.expiry_window', status: 'unknown' },
  ]);
  incident = db.listIncidents({ status: 'active' })[0];
  assert.equal(incident.status, 'acknowledged');

  db.reconcileIncidents(asset.id, scan.id, [
    { ruleKey: 'cert.expiry_window', status: 'pass' },
  ]);
  assert.equal(db.listIncidents({ status: 'active' }).length, 0);
  assert.equal(db.listIncidents({ status: 'resolved' })[0].status, 'resolved');

  db.reconcileIncidents(asset.id, scan.id, [failing]);
  incident = db.listIncidents({ status: 'active' })[0];
  assert.equal(incident.status, 'open');
  assert.equal(incident.occurrenceCount, 2);
});

test('dashboard sayaçları önizleme limitinden bağımsız olarak tüm incidentları sayar', () => {
  const asset = db.createAsset({
    hostname: 'bulk.example.com',
    port: 443,
    label: 'Toplu test',
    owner: 'SOC',
    environment: 'production',
    scanProfile: 'native',
    expiryWarningDays: 30,
    scanIntervalMinutes: 720,
  });
  const scan = db.createScan(asset.id, 'native', 'manual').scan;
  const evaluations = Array.from({ length: 55 }, (_, index) => ({
    ruleKey: `test.bulk.${index}`,
    status: 'fail',
    severity: 'critical',
    title: `Toplu bulgu ${index}`,
    description: 'Sayaç regresyon testi.',
    evidence: { index },
  }));
  db.reconcileIncidents(asset.id, scan.id, evaluations);

  const dashboard = db.getDashboard();
  const allActive = db.listIncidents({ status: 'active', limit: 200 });
  assert.equal(dashboard.summary.openIncidents, allActive.length);
  assert.equal(
    dashboard.summary.criticalIncidents,
    allActive.filter((incident) => incident.severity === 'critical').length,
  );
  assert.ok(dashboard.summary.openIncidents > dashboard.incidents.length);
  const firstPage = db.listIncidentsPage({ status: 'active', limit: 50 });
  const secondPage = db.listIncidentsPage({
    status: 'active',
    limit: 50,
    offset: 50,
  });
  assert.equal(firstPage.total, allActive.length);
  assert.equal(firstPage.incidents.length, 50);
  assert.equal(secondPage.incidents.length, allActive.length - 50);
  assert.equal(
    firstPage.counts.critical,
    allActive.filter((incident) => incident.severity === 'critical').length,
  );
});

test('varlık arşivlenince aktif incidentlar geçmişi korunarak kapanır', () => {
  const asset = db.createAsset({
    hostname: 'archive.example.com',
    port: 443,
    label: 'Arşiv testi',
    owner: 'SOC',
    environment: 'production',
    scanProfile: 'native',
    expiryWarningDays: 30,
    scanIntervalMinutes: 720,
  });
  const scan = db.createScan(asset.id, 'native', 'manual').scan;
  db.reconcileIncidents(asset.id, scan.id, [
    {
      ruleKey: 'cert.hostname_mismatch',
      status: 'fail',
      severity: 'high',
      title: 'Hostname eşleşmiyor',
      description: 'Arşiv davranışı testi.',
    },
  ]);

  const before = db.getDashboard().summary.openIncidents;
  db.archiveAsset(asset.id);
  assert.equal(db.getDashboard().summary.openIncidents, before - 1);
  assert.equal(
    db
      .listIncidents({ status: 'resolved', limit: 200 })
      .some((incident) => incident.assetId === asset.id),
    true,
  );
});

test('başarısız tarama son güvenilir TLS snapshotını korur ve kısa retry planlar', () => {
  const asset = db.createAsset({
    hostname: 'retry.example.com',
    port: 443,
    label: 'Retry testi',
    owner: 'SOC',
    environment: 'production',
    scanProfile: 'native',
    expiryWarningDays: 30,
    scanIntervalMinutes: 720,
  });
  const validTo = '2030-01-01T00:00:00.000Z';
  const first = db.createScan(asset.id, 'native', 'manual').scan;
  db.finishScan(first.id, {
    status: 'succeeded',
    grade: 'A',
    observations: {
      target: { address: '93.184.216.34' },
      tls: { certificate: { validTo } },
    },
  });

  const second = db.createScan(asset.id, 'native', 'manual').scan;
  const beforeFailure = Date.now();
  db.finishScan(second.id, {
    status: 'failed',
    errorCode: 'TLS_TIMEOUT',
    errorMessage: 'Geçici ağ hatası.',
  });

  const updated = db.getAsset(asset.id);
  assert.equal(updated.latestStatus, 'failed');
  assert.equal(updated.latestGrade, 'A');
  assert.equal(updated.certificateExpiresAt, validTo);
  assert.equal(updated.latestIp, '93.184.216.34');
  const retryDelay = Date.parse(updated.nextScanAt) - beforeFailure;
  assert.ok(retryDelay >= 14 * 60_000 && retryDelay <= 16 * 60_000);
});
