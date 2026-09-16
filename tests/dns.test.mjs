import test from 'node:test';
import assert from 'node:assert/strict';

import { probePublicDns } from '../server/probes/dns.mjs';

function dnsError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function resolver(overrides = {}) {
  return {
    async resolve4() {
      return [{ address: '203.0.113.10', ttl: 300 }];
    },
    async resolve6() {
      return [];
    },
    async resolveTxt(name) {
      if (name === 'api.example.com') return [['v=spf1', ' -all']];
      if (name === '_dmarc.example.com')
        return [['v=DMARC1; p=reject; pct=100']];
      throw dnsError('ENODATA');
    },
    async resolve(name, type) {
      if (name === 'example.com' && type === 'DNSKEY') {
        return [
          { flags: 257, protocol: 3, algorithm: 13, key: 'redacted-by-rules' },
        ];
      }
      if (name === 'example.com' && type === 'DS') {
        return [{ keyTag: 12345, algorithm: 13, digestType: 2, digest: 'abc' }];
      }
      throw dnsError('ENODATA');
    },
    ...overrides,
  };
}

test('public DNS probu SPF, üst domain DMARC ve DNSSEC zincirini toplar', async () => {
  const result = await probePublicDns('api.example.com', {
    resolver: resolver(),
    publicDnsResolver: '1.1.1.1',
  });

  assert.equal(result.status, 'complete');
  assert.equal(result.addressStatus, 'complete');
  assert.equal(result.spf.status, 'present');
  assert.deepEqual(result.spf.records, ['v=spf1 -all']);
  assert.equal(result.dmarc.status, 'present');
  assert.equal(result.dmarc.domain, 'example.com');
  assert.equal(result.dmarc.policy, 'reject');
  assert.equal(result.dnssec.status, 'present');
  assert.equal(result.dnssec.domain, 'example.com');
});

test('tek DNS sorgusu zaman aşımına uğrarsa mevcut sonuçları partial olarak korur', async () => {
  const result = await probePublicDns('api.example.com', {
    resolver: resolver({
      async resolve6() {
        throw dnsError('ETIMEOUT');
      },
    }),
    publicDnsResolver: '1.1.1.1',
  });

  assert.equal(result.status, 'partial');
  assert.equal(result.addressStatus, 'partial');
  assert.equal(result.records[0].address, '203.0.113.10');
  assert.deepEqual(result.addressErrors, ['ETIMEOUT']);
  assert.equal(result.spf.status, 'present');
});

test('resolver yapılandırılmamışsa public DNS kontrollerini açıkça devre dışı bırakır', async () => {
  const result = await probePublicDns('example.com', {
    publicDnsResolver: null,
  });
  assert.equal(result.status, 'disabled');
  assert.match(result.reason, /PUBLIC_DNS_RESOLVER/);
});
