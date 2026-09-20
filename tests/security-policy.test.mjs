import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  defaultCheckPolicy,
  validateCheckPolicy,
} from '../server/rules/policy.mjs';
import {
  analyzeHsts,
  analyzeCaa,
  evaluateSecurityPolicy,
} from '../server/rules/security-policy.mjs';
import { evaluateObservations, ruleCatalog } from '../server/rules/index.mjs';

const temporaryDirectory = mkdtempSync(join(tmpdir(), 'hostcanvas-policy-'));
process.env.TLS_SENTINEL_DATA_DIR = temporaryDirectory;
const db = await import('../server/db.mjs');
after(() => {
  db.closeDatabase();
  rmSync(temporaryDirectory, { recursive: true, force: true });
});

test('policy validates types, bounds, names and unknown fields without coercion', () => {
  assert.deepEqual(validateCheckPolicy({}), defaultCheckPolicy);
  for (const input of [
    null,
    [],
    { unknown: true },
    { cookieSecureRequired: 'false' },
    { scanFailureThreshold: 0 },
    { scanFailureThreshold: 1.5 },
    { hstsMinMaxAgeSeconds: -1 },
    { hstsMinMaxAgeSeconds: Infinity },
    { sessionCookieNames: ['session=secret'] },
    { caaAllowedIssuers: ['https://example.com'] },
    { sessionCookieNames: Array(21).fill('a') },
  ]) {
    assert.throws(() => validateCheckPolicy(input), {
      code: 'INVALID_CHECK_POLICY',
    });
  }
  const policy = validateCheckPolicy({
    caaAllowedIssuers: ['LETSENCRYPT.ORG', 'letsencrypt.org'],
    sessionCookieNames: ['__Host-session'],
  });
  assert.deepEqual(policy.caaAllowedIssuers, ['letsencrypt.org']);
  assert.deepEqual(policy.sessionCookieNames, ['__Host-session']);
});

test('HSTS handles zero, duplicate/malformed directives, exact boundary and optional subdomains', () => {
  const issues = (value, extra = {}) =>
    analyzeHsts(value, { ...defaultCheckPolicy, ...extra }).issues;
  for (const value of [
    'max-age=0',
    'max-age=abc',
    'max-age=-1',
    'max-age=31536000, max-age=0',
    'max-age=31536000; max-age=100',
    'max-age=31536000; includeSubDomains=true',
  ])
    assert.ok(issues(value).length, value);
  assert.deepEqual(issues('max-age=15552000'), []);
  assert.deepEqual(
    issues('MAX-AGE="31536000"; includeSubDomains; preload'),
    [],
  );
  assert.deepEqual(issues('max-age=15551999'), ['max_age_below_policy']);
  assert.deepEqual(
    issues('max-age=31536000', { hstsRequireSubdomains: true }),
    ['include_subdomains_required'],
  );
  assert.deepEqual(issues('max-age=0', { hstsMinMaxAgeSeconds: 0 }), [
    'hsts_disabled',
  ]);
});

test('cookie checks are scoped, never store values, and unobserved sessions stay unknown', () => {
  const policy = {
    ...defaultCheckPolicy,
    sessionCookieNames: ['session', '__Host-auth'],
  };
  const evaluate = (cookies, status = 'complete') =>
    evaluateSecurityPolicy(
      { http: { status, cookies, hsts: 'max-age=31536000' } },
      policy,
    );
  const find = (results, key) => results.find((item) => item.ruleKey === key);
  const cookies = [
    {
      name: 'session',
      value: 'must-not-be-stored',
      secure: false,
      httpOnly: false,
    },
    { name: 'analytics', secure: true, httpOnly: false },
  ];
  const failed = evaluate(cookies);
  assert.equal(find(failed, 'http.cookie_secure_missing').status, 'fail');
  assert.deepEqual(
    find(failed, 'http.session_cookie_httponly_missing').evidence.cookieNames,
    ['session'],
  );
  assert.equal(JSON.stringify(failed).includes('must-not-be-stored'), false);
  assert.equal(
    find(
      evaluate([{ name: 'session', secure: true, httpOnly: true }]),
      'http.session_cookie_httponly_missing',
    ).status,
    'unknown',
  );
  const complete = evaluate(
    policy.sessionCookieNames.map((name) => ({
      name,
      secure: true,
      httpOnly: true,
    })),
  );
  assert.equal(
    find(complete, 'http.session_cookie_httponly_missing').status,
    'pass',
  );
  assert.equal(
    find(evaluate([]), 'http.cookie_secure_missing').status,
    'unknown',
  );
  assert.equal(
    find(evaluate(cookies, 'unknown'), 'http.cookie_secure_missing').status,
    'unknown',
  );
});

test('CAA is optional, honors effective issuance restrictions and flags invalid critical properties', () => {
  const analyze = (records, policy = {}) =>
    analyzeCaa(records, { ...defaultCheckPolicy, ...policy });
  assert.deepEqual(analyze([]).issues, []);
  assert.deepEqual(analyze([], { caaRequired: true }).issues, [
    'issuance_policy_missing',
  ]);
  assert.deepEqual(
    analyze([{ critical: 0, issue: ';' }], { caaRequired: true }).issues,
    [],
  );
  assert.deepEqual(
    analyze(
      [{ critical: 0, issue: 'letsencrypt.org; validationmethods=dns-01' }],
      { caaAllowedIssuers: ['letsencrypt.org'] },
    ).issues,
    [],
  );
  assert.ok(
    analyze([{ critical: 0, issue: 'other.example' }], {
      caaAllowedIssuers: ['letsencrypt.org'],
    }).issues.includes('issuer_not_allowed'),
  );
  assert.ok(
    analyze([{ critical: 128, unknown: 'x' }]).issues.includes(
      'unsupported_critical_property',
    ),
  );
  assert.deepEqual(analyze([{ critical: 0, unknown: 'x' }]).issues, []);
  assert.deepEqual(
    analyze([{ critical: 128, ISSUE: 'LetsEncrypt.org' }], {
      caaRequired: true,
      caaAllowedIssuers: ['letsencrypt.org'],
    }).issues,
    [],
  );
  assert.ok(
    analyze([{ critical: 0, 'bad-tag': 'x' }]).issues.includes('invalid_tag'),
  );
  assert.ok(
    analyze([{ critical: 0, issuewild: 'letsencrypt.org' }], {
      caaRequired: true,
    }).issues.includes('issuance_policy_missing'),
  );
});

test('new rules are integrated exactly once and DNSSEC works independently of public-DNS state', () => {
  assert.equal(
    new Set(ruleCatalog.map((rule) => rule.key)).size,
    ruleCatalog.length,
  );
  const results = evaluateObservations({
    publicDns: {
      status: 'disabled',
      dnssec: { status: 'bogus', extendedErrors: [6] },
    },
  });
  assert.equal(
    new Set(results.map((rule) => rule.ruleKey)).size,
    results.length,
  );
  assert.equal(
    results.find((item) => item.ruleKey === 'dns.dnssec_bogus').status,
    'fail',
  );
  assert.equal(
    results.find((item) => item.ruleKey === 'dns.dnssec_missing').status,
    'unknown',
  );
  assert.equal(
    results.find((item) => item.ruleKey === 'dns.caa_policy').status,
    'unknown',
  );
});

test('check policy persists, validates updates and keeps omitted settings', () => {
  assert.ok(
    db.database
      .prepare('SELECT version FROM schema_migrations WHERE version = 4')
      .get(),
  );
  assert.deepEqual(db.getCheckPolicy().policy, defaultCheckPolicy);
  db.updateCheckPolicy({
    scanFailureThreshold: 2,
    sessionCookieNames: ['session'],
  });
  db.updateCheckPolicy({ caaRequired: true });
  assert.equal(db.getCheckPolicy().policy.scanFailureThreshold, 2);
  assert.equal(db.getCheckPolicy().policy.caaRequired, true);
  assert.throws(() => db.updateCheckPolicy({ scanFailureThreshold: 0 }), {
    code: 'INVALID_CHECK_POLICY',
  });
  assert.equal(db.getCheckPolicy().policy.scanFailureThreshold, 2);
});

test('persistent scan health opens at threshold, counts once, resolves and reopens the same incident', () => {
  const asset = db.createAsset({ hostname: 'health.example.com', port: 443 });
  const policy = { ...defaultCheckPolicy, scanFailureThreshold: 2 };
  const record = (healthy) => {
    const scan = db.createScan(asset.id, 'native').scan;
    db.finishScan(scan.id, { status: healthy ? 'succeeded' : 'failed' });
    return {
      id: scan.id,
      events: db.recordScanHealth(
        asset.id,
        scan.id,
        healthy,
        'TEST_TIMEOUT',
        policy,
      ),
    };
  };
  assert.deepEqual(record(false).events, []);
  const second = record(false);
  const incident = second.events[0].incident;
  assert.equal(second.events[0].type, 'opened');
  assert.equal(incident.evidence.consecutiveFailures, 2);
  assert.deepEqual(
    db.recordScanHealth(asset.id, second.id, false, 'TEST_TIMEOUT', policy),
    [],
  );
  assert.equal(db.getIncident(incident.id).occurrenceCount, 1);
  db.updateIncidentStatus(incident.id, 'acknowledged');
  assert.deepEqual(record(false).events, []);
  assert.equal(db.getIncident(incident.id).status, 'acknowledged');
  // History retention does not erase the persisted failure streak.
  db.database.prepare('DELETE FROM scans WHERE asset_id = ?').run(asset.id);
  assert.deepEqual(record(false).events, []);
  assert.equal(db.getIncident(incident.id).evidence.consecutiveFailures, 4);
  record(true);
  assert.equal(db.getIncident(incident.id).status, 'resolved');
  assert.deepEqual(record(false).events, []);
  const reopened = record(false).events[0];
  assert.equal(reopened.type, 'reopened');
  assert.equal(reopened.incident.id, incident.id);
  const last = db.createScan(asset.id, 'native').scan;
  db.finishScan(last.id, { status: 'failed' });
  db.archiveAsset(asset.id);
  assert.deepEqual(
    db.recordScanHealth(asset.id, last.id, false, 'TEST_TIMEOUT', policy),
    [],
  );
});

test('disabled scan-health policy tracks outcomes without opening or resolving incidents', () => {
  const asset = db.createAsset({
    hostname: 'disabled-health.example.com',
    port: 443,
  });
  const active = { ...defaultCheckPolicy, scanFailureThreshold: 1 };
  const disabled = { ...active, scanHealthEnabled: false };
  const record = (healthy, policy) => {
    const scan = db.createScan(asset.id, 'native').scan;
    // Queued scans and scans belonging to another asset must not affect health.
    assert.deepEqual(
      db.recordScanHealth(asset.id, scan.id, healthy, '', policy),
      [],
    );
    assert.deepEqual(
      db.recordScanHealth('not-this-asset', scan.id, healthy, '', policy),
      [],
    );
    db.finishScan(scan.id, { status: healthy ? 'succeeded' : 'partial' });
    return db.recordScanHealth(
      asset.id,
      scan.id,
      healthy,
      'TEST_INCOMPLETE',
      policy,
    );
  };
  assert.deepEqual(record(false, disabled), []);
  const opened = record(false, active)[0].incident;
  assert.equal(opened.evidence.consecutiveFailures, 2);
  assert.deepEqual(record(true, disabled), []);
  assert.equal(db.getIncident(opened.id).status, 'open');
  record(true, active);
  assert.equal(db.getIncident(opened.id).status, 'resolved');
});
