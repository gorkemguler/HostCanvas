import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { after } from 'node:test';

import {
  buildScannerEnvironment,
  buildTestsslArguments,
  normalizeTestsslOutput,
  readBoundedTestsslArtifact,
  spawnWithLimits,
} from '../server/probes/testssl.mjs';

const artifactDirectory = mkdtempSync(join(tmpdir(), 'tls-sentinel-testssl-'));
after(() => rmSync(artifactDirectory, { recursive: true, force: true }));

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

test('scanner timeout bir sonraki işi başlatmadan child sürecini sonlandırır', async () => {
  await assert.rejects(
    spawnWithLimits(
      process.execPath,
      ['-e', 'process.on("SIGTERM", () => {}); setInterval(() => {}, 1000)'],
      { timeoutMs: 100 },
    ),
    (error) => error.code === 'TESTSSL_TIMEOUT',
  );
});

test('scanner stdout ve stderr toplam byte limitini uygular', async () => {
  await assert.rejects(
    spawnWithLimits(
      process.execPath,
      [
        '-e',
        'process.stdout.write("a".repeat(300000)); process.stderr.write("b".repeat(300000)); setInterval(() => {}, 1000)',
      ],
      { timeoutMs: 2_000 },
    ),
    (error) => error.code === 'TESTSSL_OUTPUT_LIMIT',
  );
});

test('scanner artifact büyümesini süreç çalışırken durdurur', async () => {
  const path = join(artifactDirectory, 'growing.json');
  await assert.rejects(
    spawnWithLimits(
      process.execPath,
      [
        '-e',
        'require("node:fs").writeFileSync(process.argv[1], "x".repeat(1024)); setInterval(() => {}, 1000)',
        path,
      ],
      { artifactPath: path, maximumArtifactBytes: 64, timeoutMs: 2_000 },
    ),
    (error) => error.code === 'TESTSSL_ARTIFACT_LIMIT',
  );
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
  assert.equal(args.includes('-h'), false);
  assert.equal(args.includes('--connect-timeout'), false);
  assert.equal(args.includes('--openssl-timeout'), false);
});

test('testssl child ortamı allowlist uygular ve tehlikeli ayarları sıfırlar', () => {
  const environment = buildScannerEnvironment({
    PATH: '/usr/bin:/bin',
    LANG: 'C.UTF-8',
    TLS_SENTINEL_SECRET_KEY: 'must-not-leak',
    NODE_OPTIONS: '--require=/tmp/untrusted.cjs',
    BASICAUTH: 'user:password',
    REQHEADER: 'Authorization: secret',
    PHONE_OUT: 'true',
    DEBUG: '6',
  });

  assert.equal(environment.PATH, '/usr/bin:/bin');
  assert.equal(environment.LANG, 'C.UTF-8');
  assert.equal(environment.TLS_SENTINEL_SECRET_KEY, undefined);
  assert.equal(environment.NODE_OPTIONS, undefined);
  assert.equal(environment.BASICAUTH, '');
  assert.equal(environment.REQHEADER, '');
  assert.equal(environment.PHONE_OUT, 'false');
  assert.equal(environment.DEBUG, '0');
  assert.equal(environment.HEADER_MAXSLEEP, '1');
});

test('testssl artifact dosyası okunmadan önce byte limiti uygular', async () => {
  const validPath = join(artifactDirectory, 'valid.json');
  const oversizedPath = join(artifactDirectory, 'oversized.json');
  writeFileSync(validPath, JSON.stringify([{ id: 'ok' }]));
  writeFileSync(oversizedPath, JSON.stringify({ finding: 'x'.repeat(128) }));

  assert.deepEqual(await readBoundedTestsslArtifact(validPath, 1_024), [
    { id: 'ok' },
  ]);
  await assert.rejects(
    () => readBoundedTestsslArtifact(oversizedPath, 64),
    (error) => error.code === 'TESTSSL_ARTIFACT_LIMIT',
  );
});
