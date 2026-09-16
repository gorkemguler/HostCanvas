import test from 'node:test';
import assert from 'node:assert/strict';

import {
  evaluateObservations,
  gradeEvaluations,
} from '../server/rules/index.mjs';
import { classifyProtocolProbeError } from '../server/probes/tls.mjs';

function observations(overrides = {}) {
  const now = Date.now();
  return {
    tls: {
      authorized: true,
      authorizationError: null,
      certificate: {
        subject: 'CN=api.example.com',
        issuer: 'CN=Example CA',
        subjectAltName: 'DNS:api.example.com',
        fingerprint256: 'AA:BB',
        validFrom: new Date(now - 86_400_000).toISOString(),
        validTo: new Date(now + 10 * 86_400_000).toISOString(),
        hostnameMatches: true,
        hostnameError: null,
        chainDepth: 2,
        publicKey: { type: 'rsa', bits: 2048 },
        signatureAlgorithm: 'sha256WithRSAEncryption',
      },
      protocols: {
        TLSv1: { supported: false },
        'TLSv1.1': { supported: false },
        'TLSv1.2': { supported: true },
        'TLSv1.3': { supported: true },
      },
    },
    http: {
      status: 'complete',
      statusLine: 'HTTP/1.1 200 OK',
      hsts: 'max-age=31536000',
      headers: {
        'strict-transport-security': 'max-age=31536000',
        'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'x-frame-options': null,
        'x-xss-protection': '0',
        server: null,
      },
      cookies: [],
    },
    publicDns: { status: 'disabled', records: [] },
    testssl: null,
    ...overrides,
  };
}

test('yaklaşan sertifika bitişini tek eşik incidentına dönüştürür', () => {
  const result = evaluateObservations(observations(), {
    expiryWarningDays: 30,
  });
  const expiry = result.find((item) => item.ruleKey === 'cert.expiry_window');
  assert.equal(expiry.status, 'fail');
  assert.equal(expiry.severity, 'high');
  assert.match(expiry.title, /gün içinde/);
  assert.equal(gradeEvaluations(result), 'C');
});

test('legacy protokol, HSTS eksikliği ve public DNS ifşasını bulur', () => {
  const input = observations();
  input.tls.protocols.TLSv1.supported = true;
  input.http.hsts = null;
  input.publicDns = {
    status: 'complete',
    resolver: '1.1.1.1',
    records: [{ type: 'A', address: '10.0.0.4', public: false }],
  };
  const result = evaluateObservations(input, { expiryWarningDays: 1 });
  assert.equal(
    result.find((item) => item.ruleKey === 'tls.legacy_protocol').status,
    'fail',
  );
  assert.equal(
    result.find((item) => item.ruleKey === 'http.hsts_missing').status,
    'fail',
  );
  assert.equal(
    result.find((item) => item.ruleKey === 'dns.public_private_ip').status,
    'fail',
  );
});

test('imza algoritması runtime tarafından sağlanmıyorsa yanlış pass yerine unknown üretir', () => {
  const input = observations();
  input.tls.certificate.signatureAlgorithm = null;
  const result = evaluateObservations(input, { expiryWarningDays: 1 });
  assert.equal(
    result.find((item) => item.ruleKey === 'cert.weak_signature').status,
    'unknown',
  );
});

test('HTTP başlık, teknoloji ifşası ve cookie sorunlarını güvenli kanıtla üretir', () => {
  const input = observations();
  input.http.headers['content-security-policy'] = null;
  input.http.headers['x-content-type-options'] = null;
  input.http.headers['referrer-policy'] = null;
  input.http.headers.server = 'nginx/1.27.0';
  input.http.headers['x-xss-protection'] = '1; mode=block';
  input.http.cookies = [
    { name: 'session', sameSite: null, secure: true, httpOnly: true },
    { name: 'tracking', sameSite: 'none', secure: false, httpOnly: false },
  ];

  const result = evaluateObservations(input, { expiryWarningDays: 1 });
  assert.equal(
    result.find((item) => item.ruleKey === 'http.security_headers_missing')
      .status,
    'fail',
  );
  assert.equal(
    result.find((item) => item.ruleKey === 'http.server_header_disclosure')
      .status,
    'fail',
  );
  assert.equal(
    result.find((item) => item.ruleKey === 'http.deprecated_xss_protection')
      .status,
    'fail',
  );
  const cookies = result.find(
    (item) => item.ruleKey === 'http.cookie_samesite_missing',
  );
  assert.equal(cookies.status, 'fail');
  assert.deepEqual(cookies.evidence.cookies, [
    { name: 'session', issue: 'samesite_missing' },
    { name: 'tracking', issue: 'samesite_none_without_secure' },
  ]);
  assert.equal(
    JSON.stringify(cookies.evidence).includes('cookie-value'),
    false,
  );
});

test('DNSSEC, DMARC ve SPF gözlemlerini incident kurallarına dönüştürür', () => {
  const input = observations({
    publicDns: {
      status: 'complete',
      resolver: '1.1.1.1',
      records: [{ type: 'A', address: '203.0.113.10', public: true }],
      addressStatus: 'complete',
      dnssec: {
        status: 'missing',
        domain: 'example.com',
        dnskeyRecords: [],
        dsRecords: [],
      },
      dmarc: {
        status: 'warning',
        domain: 'example.com',
        policy: 'none',
        issues: ['monitoring_only'],
      },
      spf: {
        status: 'warning',
        records: ['v=spf1 +all'],
        issues: ['permissive_all'],
      },
    },
  });
  const result = evaluateObservations(input, { expiryWarningDays: 1 });
  assert.equal(
    result.find((item) => item.ruleKey === 'dns.dnssec_missing').status,
    'fail',
  );
  assert.equal(
    result.find((item) => item.ruleKey === 'email.dmarc_missing').status,
    'pass',
  );
  assert.equal(
    result.find((item) => item.ruleKey === 'email.dmarc_policy_weak').status,
    'fail',
  );
  const spf = result.find(
    (item) => item.ruleKey === 'email.spf_misconfiguration',
  );
  assert.equal(spf.status, 'fail');
  assert.equal(spf.severity, 'high');
});

test('geçici transport hatasını protokol reddi olarak yorumlamaz', () => {
  assert.equal(
    classifyProtocolProbeError({ code: 'TLS_TIMEOUT' }).supported,
    null,
  );
  assert.equal(
    classifyProtocolProbeError({ code: 'ECONNRESET' }).supported,
    null,
  );
  assert.equal(
    classifyProtocolProbeError({ code: 'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION' })
      .supported,
    false,
  );
});

test('eksik gözlem unknown üretir ve testssl severity bulgularını normalize eder', () => {
  const result = evaluateObservations(
    {
      http: { status: 'unknown' },
      publicDns: { status: 'disabled' },
      testssl: {
        findings: [
          {
            id: 'heartbleed',
            severity: 'CRITICAL',
            finding: 'vulnerable',
            cve: 'CVE-2014-0160',
          },
          { id: 'service', severity: 'INFO', finding: 'ok' },
        ],
      },
    },
    { expiryWarningDays: 30 },
  );
  assert.equal(
    result.find((item) => item.ruleKey === 'cert.expired').status,
    'unknown',
  );
  assert.equal(
    result.find((item) => item.ruleKey === 'testssl.heartbleed').severity,
    'critical',
  );
  assert.equal(
    result.some((item) => item.ruleKey === 'testssl.service'),
    false,
  );
});
