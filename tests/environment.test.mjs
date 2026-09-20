import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  environmentForWeb,
  loadApplicationEnvironment,
} from '../scripts/environment.mjs';

test('API config loads local dotenv values without overriding explicit environment', () => {
  const directory = mkdtempSync(join(tmpdir(), 'hostcanvas-env-'));
  writeFileSync(
    join(directory, '.env'),
    'TLS_SENTINEL_API_PORT=8787\nTLS_SENTINEL_CRT_NAME_ENABLED=false\n',
  );
  writeFileSync(
    join(directory, '.env.local'),
    'TLS_SENTINEL_API_PORT=8888\nTLS_SENTINEL_SECRET_KEY="test-only-secret"\nNEXT_PUBLIC_SITE_URL=https://example.test\n',
  );
  const environment = { TLS_SENTINEL_API_PORT: '9999' };
  loadApplicationEnvironment(directory, environment);
  assert.equal(environment.TLS_SENTINEL_API_PORT, '9999');
  assert.equal(environment.TLS_SENTINEL_CRT_NAME_ENABLED, 'false');
  assert.equal(environment.TLS_SENTINEL_SECRET_KEY, 'test-only-secret');
  assert.equal(environment.NEXT_PUBLIC_SITE_URL, undefined);
  assert.equal(
    loadApplicationEnvironment(directory, {}).TLS_SENTINEL_API_PORT,
    '8888',
  );
});

test('web processes cannot inherit or reload API secrets from dotenv', () => {
  const directory = mkdtempSync(join(tmpdir(), 'hostcanvas-web-env-'));
  writeFileSync(
    join(directory, '.env.local'),
    'TLS_SENTINEL_SECRET_KEY=test-secret-from-file\nTLS_SENTINEL_SETUP_CODE=test-setup-from-file\n',
  );
  const source = {
    TLS_SENTINEL_WEB_PORT: '3001',
    TLS_SENTINEL_SECRET_KEY: 'test-secret-from-shell',
    PATH: '/bin',
  };
  const environment = environmentForWeb(source, directory);
  assert.equal(environment.TLS_SENTINEL_SECRET_KEY, '');
  assert.equal(environment.TLS_SENTINEL_SETUP_CODE, '');
  assert.equal(environment.TLS_SENTINEL_WEB_PORT, '3001');
  assert.equal(environment.PATH, '/bin');
  assert.equal(source.TLS_SENTINEL_SECRET_KEY, 'test-secret-from-shell');
});
