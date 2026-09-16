import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { DATA_DIRECTORY } from './config.mjs';

const keyPath = join(DATA_DIRECTORY, '.secret-key');

function loadKey() {
  const configured = process.env.TLS_SENTINEL_SECRET_KEY?.trim();
  if (configured) return createHash('sha256').update(configured).digest();
  mkdirSync(DATA_DIRECTORY, { recursive: true });
  if (!existsSync(keyPath)) {
    writeFileSync(keyPath, randomBytes(32).toString('base64url'), {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    });
  }
  chmodSync(keyPath, 0o600);
  return createHash('sha256').update(readFileSync(keyPath, 'utf8').trim()).digest();
}

const key = loadKey();

export function encryptSecret(value) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  return [
    'v1',
    iv.toString('base64url'),
    cipher.getAuthTag().toString('base64url'),
    encrypted.toString('base64url'),
  ].join('.');
}

export function decryptSecret(value) {
  const [version, iv, tag, encrypted] = String(value || '').split('.');
  if (version !== 'v1' || !iv || !tag || !encrypted) {
    const error = new Error('Şifreli secret biçimi geçersiz.');
    error.code = 'INVALID_ENCRYPTED_SECRET';
    throw error;
  }
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(encrypted, 'base64url')),
    decipher.final(),
  ]).toString('utf8');
}
