import test from 'node:test';
import assert from 'node:assert/strict';

import { probePublicDns, probeCaa } from '../server/probes/dns.mjs';

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
    async resolveCaa(name) {
      if (name === 'example.com')
        return [{ critical: 0, issue: 'letsencrypt.org' }];
      throw dnsError('ENODATA');
    },
    ...overrides,
  };
}

test('public DNS SPF, üst domain DMARC ve effective CAA toplar; DNSSEC ayrı adaptördür', async () => {
  const result = await probePublicDns('api.example.com', {
    resolver: resolver(),
    publicDnsResolver: '1.1.1.1',
    dnssecProbe: async () => ({
      status: 'present',
      domain: 'api.example.com',
      transport: 'dns-over-tls',
    }),
  });

  assert.equal(result.status, 'complete');
  assert.equal(result.addressStatus, 'complete');
  assert.equal(result.spf.status, 'present');
  assert.deepEqual(result.spf.records, ['v=spf1 -all']);
  assert.equal(result.dmarc.status, 'present');
  assert.equal(result.dmarc.domain, 'example.com');
  assert.equal(result.dmarc.policy, 'reject');
  assert.equal(result.dnssec.status, 'present');
  assert.equal(result.dnssec.domain, 'api.example.com');
  assert.equal(result.caa.domain, 'example.com');
  assert.equal(result.caa.records[0].issue, 'letsencrypt.org');
});

test('tek DNS sorgusu zaman aşımına uğrarsa mevcut sonuçları partial olarak korur', async () => {
  const result = await probePublicDns('api.example.com', {
    resolver: resolver({
      async resolve6() {
        throw dnsError('ETIMEOUT');
      },
    }),
    publicDnsResolver: '1.1.1.1',
    dnssecProbe: async () => ({ status: 'disabled' }),
  });

  assert.equal(result.status, 'partial');
  assert.equal(result.addressStatus, 'partial');
  assert.equal(result.records[0].address, '203.0.113.10');
  assert.deepEqual(result.addressErrors, ['ETIMEOUT']);
  assert.equal(result.spf.status, 'present');
});

test('resolver yapılandırılmamışsa public DNS kontrollerini açıkça devre dışı bırakır', async () => {
  const result = await probePublicDns('example.com', {
    publicDnsResolver: '',
    dnssecProbe: async () => ({ status: 'disabled' }),
  });
  assert.equal(result.status, 'disabled');
  assert.match(result.reason, /PUBLIC_DNS_RESOLVER/);
});

test('CAA child RRset wins, failures never fall back, and depth is bounded', async () => {
  let calls = 0;
  const child = await probeCaa(
    resolver({
      async resolveCaa() {
        calls++;
        return [{ critical: 0, issue: ';' }];
      },
    }),
    'api.example.com',
  );
  assert.equal(calls, 1);
  assert.equal(child.domain, 'api.example.com');
  calls = 0;
  const incomplete = await probeCaa(
    resolver({
      async resolveCaa() {
        calls++;
        throw dnsError('ETIMEOUT');
      },
    }),
    'api.example.com',
  );
  assert.equal(incomplete.status, 'unknown');
  assert.equal(calls, 1);
  calls = 0;
  const limit = await probeCaa(
    resolver({
      async resolveCaa() {
        calls++;
        return [];
      },
    }),
    'a.'.repeat(18) + 'example.com',
  );
  assert.equal(limit.status, 'unknown');
  assert.equal(calls, 16);
  const oversized = await probeCaa(
    resolver({
      async resolveCaa() {
        return Array(65).fill({ critical: 0, issue: 'example.com' });
      },
    }),
    'example.com',
  );
  assert.equal(oversized.error, 'CAA_RECORD_LIMIT');
});

test('DNSSEC remains independently available when plaintext public DNS checks are disabled', async () => {
  const result = await probePublicDns('example.com', {
    publicDnsResolver: null,
    dnssecProbe: async () => ({ status: 'bogus', extendedErrors: [6] }),
  });
  assert.equal(result.status, 'disabled');
  assert.equal(result.dnssec.status, 'bogus');
});
