import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

process.env.TLS_SENTINEL_DATA_DIR = mkdtempSync(
  join(tmpdir(), 'host-canvas-secrets-'),
);
process.env.TLS_SENTINEL_SECRET_KEY = 'test-only-configured-secret';

const secrets = await import('../server/secrets.mjs');

test('configured encryption key is removed from the process environment', () => {
  assert.equal(process.env.TLS_SENTINEL_SECRET_KEY, undefined);
  const encrypted = secrets.encryptSecret('https://example.test/webhook');
  assert.equal(
    secrets.decryptSecret(encrypted),
    'https://example.test/webhook',
  );
});
