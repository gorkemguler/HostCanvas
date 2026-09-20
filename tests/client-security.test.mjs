import assert from 'node:assert/strict';
import test from 'node:test';
import { QueryClient } from '@tanstack/react-query';
import {
  clearWorkspaceCache,
  isLocalPanelOrigin,
  isSecureLanOrigin,
  panelOrigin,
} from '../app/client-security.ts';

test('LAN origin validation requires HTTPS and parses hostnames rather than substrings', () => {
  assert.equal(isLocalPanelOrigin('http://localhost:3000'), true);
  assert.equal(isLocalPanelOrigin('http://[::1]:3000'), true);
  assert.equal(isLocalPanelOrigin('https://localhost.attacker.example'), false);
  assert.equal(isLocalPanelOrigin('https://team.example/127.0.0.1'), false);
  assert.equal(isSecureLanOrigin('https://192.168.1.20:3443'), true);
  assert.equal(isSecureLanOrigin('http://192.168.1.20:3000'), false);
  assert.equal(isSecureLanOrigin('https://localhost:3443'), false);
  for (const origin of [
    'javascript:alert(1)',
    'https://user:password@example.com',
    'https://example.com/path',
    'https://example.com?query=1',
    'https://example.com#fragment',
  ]) {
    assert.equal(panelOrigin(origin), null);
  }
});

test('session cleanup removes all private caches and rejects late query results', async () => {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity } },
  });
  client.setQueryData(['bootstrap'], { authenticated: true });
  for (const key of [
    'dashboard',
    'incidents',
    'scans',
    'settings',
    'users',
    'audit',
    'backups',
    'notifications',
  ]) {
    client.setQueryData([key], { privateData: true });
  }
  let release;
  const pending = client
    .fetchQuery({
      queryKey: ['late-inventory'],
      queryFn: () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    })
    .catch(() => undefined);
  clearWorkspaceCache(client);
  release({ previousUserData: true });
  await pending;
  assert.deepEqual(
    client
      .getQueryCache()
      .getAll()
      .map((query) => query.queryKey),
    [['bootstrap']],
  );
  client.clear();
});
