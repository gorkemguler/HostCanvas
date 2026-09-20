import test from 'node:test';
import assert from 'node:assert/strict';

import {
  isPublicAddress,
  normalizeHostname,
  normalizePort,
  resolveAndValidateTarget,
} from '../server/security/targets.mjs';

test('hostname girdisini IDNA ASCII biçimine normalleştirir', () => {
  assert.equal(normalizeHostname('  BÜCHER.DE. '), 'xn--bcher-kva.de');
  assert.equal(
    normalizeHostname('api.example.internal'),
    'api.example.internal',
  );
  assert.equal(normalizePort('8443'), 8443);
});

test('URL, wildcard ve doğrudan IP girdilerini reddeder', () => {
  for (const input of [
    'https://example.com',
    '*.example.com',
    'example.com/path',
    '127.0.0.1',
    'example.com:443',
  ]) {
    assert.throws(() => normalizeHostname(input));
  }
  assert.throws(() => normalizePort(0));
  assert.throws(() => normalizePort(65536));
});

test('public olmayan IPv4 ve IPv6 aralıklarını bloklar', () => {
  for (const address of [
    '127.0.0.1',
    '10.0.0.1',
    '100.64.1.1',
    '169.254.169.254',
    '192.168.1.10',
    '203.0.113.9',
    '::1',
    'fd12::1',
    'fe80::1',
    '2001:db8::1',
    '::ffff:127.0.0.1',
    '::ffff:7f00:1',
    '::ffff:8.8.8.8',
    '::7f00:1',
    '64:ff9b::7f00:1',
    '64:ff9b::a9fe:a9fe',
    '64:ff9b:1::1',
    '100::1',
    '2001:2::1',
    '2002:7f00:1::1',
    '3ffe::1',
    '3fff::1',
    'fec0::1',
  ]) {
    assert.equal(isPublicAddress(address), false, `${address} public olmamalı`);
  }
  for (const address of [
    '1.1.1.1',
    '8.8.8.8',
    '2001:4860:4860::8888',
    '2404:6800:4001::200e',
    '2606:4700:4700::1111',
  ]) {
    assert.equal(isPublicAddress(address), true, `${address} public olmalı`);
  }
});

test('DNS rebinding savunması private cevapları açık izin olmadan reddeder', async () => {
  const privateLookup = async () => [{ address: '127.0.0.1', family: 4 }];
  await assert.rejects(
    () =>
      resolveAndValidateTarget('service.example', { lookup: privateLookup }),
    (error) => error.code === 'PRIVATE_TARGET_BLOCKED',
  );
  const allowed = await resolveAndValidateTarget('service.example', {
    lookup: privateLookup,
    allowPrivate: true,
  });
  assert.equal(allowed.address, '127.0.0.1');
});

test('DNS deadline takılan resolver için worker serbest bırakır', async () => {
  await assert.rejects(
    resolveAndValidateTarget('slow.example', {
      timeoutMs: 10,
      lookup: () => new Promise(() => {}),
    }),
    (error) =>
      error.code === 'DNS_RESOLUTION_FAILED' &&
      error.cause.code === 'DNS_TIMEOUT',
  );
});

test('DNS güvenlik kontrolü gösterim sınırından sonraki private cevabı da reddeder', async () => {
  await assert.rejects(
    resolveAndValidateTarget('mixed.example', {
      lookup: async () => [
        ...Array.from({ length: 17 }, (_, index) => ({
          address: `8.8.8.${index + 1}`,
          family: 4,
        })),
        { address: '127.0.0.1', family: 4 },
      ],
    }),
    (error) => error.code === 'PRIVATE_TARGET_BLOCKED',
  );
});
