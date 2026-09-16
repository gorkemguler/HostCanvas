import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.TLS_SENTINEL_DATA_DIR = mkdtempSync(
  join(tmpdir(), 'host-canvas-discovery-db-'),
);

const {
  archiveAsset,
  createAsset,
  createDiscoveredAssets,
  getAsset,
  getDueAssets,
  listAssets,
  listScans,
} = await import('../server/db.mjs');

test('keşfedilen subdomainleri kök asset ile ilişkilendirir ve taramaları kademeler', () => {
  const parent = createAsset({
    hostname: 'example.com',
    port: 8443,
    label: 'Example estate',
    owner: 'Platform',
    environment: 'production',
    tags: ['external'],
    allowPrivate: false,
    scanProfile: 'native',
    expiryWarningDays: 30,
    scanIntervalMinutes: 720,
  });
  const records = [
    { hostname: 'api.example.com', firstSeenAt: '2024-01-01T00:00:00.000Z' },
    { hostname: 'www.example.com', firstSeenAt: '2024-02-01T00:00:00.000Z' },
  ];

  const created = createDiscoveredAssets(parent.id, records);
  assert.equal(created.createdCount, 2);
  assert.equal(created.existingCount, 0);
  assert.equal(listAssets().length, 3);
  assert.equal(getAsset(parent.id).discoveredAssetCount, 2);

  const api = created.assets.find(
    (asset) => asset.hostname === 'api.example.com',
  );
  assert.equal(api.port, 8443);
  assert.equal(api.owner, 'Platform');
  assert.equal(api.source, 'crt.name');
  assert.equal(api.parentAssetId, parent.id);
  assert.equal(api.firstSeenAt, '2024-01-01T00:00:00.000Z');
  assert.ok(api.tags.includes('crt.name'));
  assert.ok(Date.parse(api.nextScanAt) > Date.now() + 11 * 60 * 60 * 1000);
  assert.equal(listScans().length, 0);
  assert.deepEqual(
    getDueAssets().map((asset) => asset.hostname),
    ['example.com'],
  );

  const duplicate = createDiscoveredAssets(parent.id, records);
  assert.equal(duplicate.createdCount, 0);
  assert.equal(duplicate.existingCount, 2);
  assert.equal(getAsset(parent.id).discoveredAssetCount, 2);

  archiveAsset(api.id);
  assert.equal(getAsset(parent.id).discoveredAssetCount, 1);
});
