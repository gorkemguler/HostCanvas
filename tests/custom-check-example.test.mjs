import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  certificateValidityRuleKey,
  evaluateCertificateValidity,
} from '../examples/custom-check/certificate-validity.mjs';

process.env.TLS_SENTINEL_DATA_DIR = mkdtempSync(
  join(tmpdir(), 'hostcanvas-custom-rule-'),
);
const db = await import('../server/db.mjs');
after(() => db.closeDatabase());

function observation(days) {
  const from = Date.UTC(2026, 0, 1);
  return {
    tls: {
      certificate: {
        validFrom: new Date(from).toISOString(),
        validTo: new Date(from + days * 86_400_000).toISOString(),
      },
    },
  };
}

test('documented custom rule fails above the exact policy boundary, not at it', () => {
  const failed = evaluateCertificateValidity(observation(91));
  assert.equal(failed.ruleKey, certificateValidityRuleKey);
  assert.equal(failed.status, 'fail');
  assert.equal(failed.severity, 'low');
  assert.equal(failed.evidence.lifetimeDays, 91);
  assert.equal(failed.evidence.maxDays, 90);
  assert.equal(evaluateCertificateValidity(observation(90)).status, 'pass');
  assert.equal(
    evaluateCertificateValidity(observation(90 + 1 / 86400)).status,
    'fail',
  );
  assert.equal(
    evaluateCertificateValidity(observation(91), { maxDays: 120 }).status,
    'pass',
  );
});

test('documented custom rule treats missing, malformed and inverted dates as unknown', () => {
  for (const input of [
    undefined,
    {},
    { tls: { status: 'failed' } },
    observation(0),
    observation(-1),
  ]) {
    assert.equal(evaluateCertificateValidity(input).status, 'unknown');
  }
  for (const value of [null, 1, '', 'invalid', 'x'.repeat(65)]) {
    for (const field of ['validFrom', 'validTo']) {
      const input = observation(91);
      input.tls.certificate[field] = value;
      assert.equal(evaluateCertificateValidity(input).status, 'unknown');
    }
  }
  for (const maxDays of [0, -1, 1.5, '90', NaN, Infinity, 36501]) {
    assert.equal(
      evaluateCertificateValidity(observation(91), { maxDays }).status,
      'unknown',
    );
  }
});

test('documented custom rule preserves, resolves and reopens one incident identity', () => {
  const asset = db.createAsset({
    hostname: 'policy.example.com',
    port: 443,
    label: 'Policy example',
    owner: 'Platform',
    environment: 'test',
    scanProfile: 'native',
    expiryWarningDays: 30,
    scanIntervalMinutes: 720,
  });
  const scan = db.createScan(asset.id, 'native', 'manual').scan;
  const apply = (input) =>
    db.reconcileIncidents(asset.id, scan.id, [
      evaluateCertificateValidity(input),
    ]);
  assert.equal(apply(observation(91))[0].type, 'opened');
  const original = db.listIncidents({ status: 'active' })[0];
  db.updateIncidentStatus(original.id, 'acknowledged');
  assert.deepEqual(apply({}), []);
  assert.equal(db.getIncident(original.id).status, 'acknowledged');
  assert.deepEqual(apply(observation(120)), []);
  assert.equal(db.getIncident(original.id).status, 'acknowledged');
  assert.equal(db.getIncident(original.id).occurrenceCount, 2);
  assert.deepEqual(apply(observation(90)), []);
  assert.equal(db.getIncident(original.id).status, 'resolved');
  const reopened = apply(observation(100));
  assert.equal(reopened[0].type, 'reopened');
  assert.equal(reopened[0].incident.id, original.id);
  assert.equal(db.getIncident(original.id).occurrenceCount, 3);
});
