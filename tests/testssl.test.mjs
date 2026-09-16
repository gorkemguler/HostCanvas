import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildTestsslArguments,
  normalizeTestsslOutput,
} from '../server/probes/testssl.mjs';

test('testssl pretty ve nested çıktısından güvenli bulguları çıkarır', () => {
  const document = {
    scanResult: [
      {
        vulnerabilities: [
          {
            id: 'heartbleed',
            severity: 'CRITICAL',
            finding: '\u001b[31mVULNERABLE\u001b[0m',
            cve: 'CVE-2014-0160',
            ip: '203.0.113.1',
            port: '443',
          },
          { id: 'service', severity: 'INFO', finding: 'TLS service detected' },
        ],
      },
    ],
  };
  const result = normalizeTestsslOutput(document);
  assert.equal(result.length, 2);
  assert.equal(result[0].id, 'heartbleed');
  assert.equal(result[0].finding, 'VULNERABLE');
  assert.equal(result[0].port, 443);
});

test('testssl IPv6 hedefini sabitler ve macOS dış watchdog ile uyumlu argv üretir', () => {
  const args = buildTestsslArguments(
    { hostname: 'localhost', address: '::1', family: 6, port: 443 },
    '/tmp/scan.json',
  );

  assert.ok(args.includes('-6'));
  assert.equal(args[args.indexOf('--ip') + 1], '::1');
  assert.equal(args[args.indexOf('--jsonfile') + 1], '/tmp/scan.json');
  assert.equal(args.includes('--overwrite'), true);
  assert.equal(args.includes('--connect-timeout'), false);
  assert.equal(args.includes('--openssl-timeout'), false);
});
