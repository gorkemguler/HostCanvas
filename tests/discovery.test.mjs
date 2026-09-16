import test from 'node:test';
import assert from 'node:assert/strict';

import { discoverSubdomains } from '../server/discovery/crt-name.mjs';

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

test('crt.name sonuçlarını normalize eder, scope dışını ve wildcards kayıtlarını reddeder', async () => {
  let requestedUrl;
  const result = await discoverSubdomains('Example.COM', {
    limit: 1,
    fetch: async (url, init) => {
      requestedUrl = url;
      assert.equal(init.redirect, 'error');
      assert.match(init.headers['User-Agent'], /^HostCanvas\/0\.3\.0$/);
      return jsonResponse([
        { sub: 'EXAMPLE.COM', first_seen: '2025-01-01T00:00:00Z' },
        { sub: '*.example.com', first_seen: '2025-01-01T00:00:00Z' },
        { sub: 'API.example.com', first_seen: '2025-02-01T00:00:00Z' },
        { sub: 'api.example.com', first_seen: '2025-03-01T00:00:00Z' },
        { sub: 'dev.example.com', first_seen: '2025-04-01T00:00:00Z' },
        { sub: 'outside.example.net', first_seen: '2025-01-01T00:00:00Z' },
        { sub: 'probe.example.com', first_seen: null },
      ]);
    },
  });

  assert.equal(requestedUrl.hostname, 'crt.name');
  assert.equal(requestedUrl.searchParams.get('apex'), 'example.com');
  assert.equal(result.totalFound, 2);
  assert.equal(result.truncated, true);
  assert.deepEqual(result.records, [
    {
      hostname: 'api.example.com',
      firstSeenAt: '2025-02-01T00:00:00.000Z',
    },
  ]);
});

test('crt.name kota hatasını kullanıcıya güvenli kodla döndürür', async () => {
  await assert.rejects(
    discoverSubdomains('example.com', {
      fetch: async () => jsonResponse({}, 429),
    }),
    (error) => error.code === 'DISCOVERY_RATE_LIMITED',
  );
});

test('çok büyük discovery yanıtını belleğe sınırsız almadan reddeder', async () => {
  await assert.rejects(
    discoverSubdomains('example.com', {
      maximumResponseBytes: 16,
      fetch: async () =>
        jsonResponse([
          {
            sub: 'very-long-subdomain.example.com',
            first_seen: '2025-01-01T00:00:00Z',
          },
        ]),
    }),
    (error) => error.code === 'DISCOVERY_RESPONSE_TOO_LARGE',
  );
});
