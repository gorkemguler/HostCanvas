import {
  createHash,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
} from 'node:crypto';
import { promisify } from 'node:util';

import {
  createSession,
  deleteSession,
  getSession,
  pruneExpiredSessions,
} from './db.mjs';

const scrypt = promisify(scryptCallback);
const COOKIE_NAME = 'tls_sentinel_session';
const SCRYPT_OPTIONS = { N: 32_768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const HASH_LENGTH = 64;

function sessionTokenHash(token) {
  return createHash('sha256').update(token).digest('base64url');
}

function parseCookies(header = '') {
  return Object.fromEntries(
    header
      .split(';')
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const separator = part.indexOf('=');
        if (separator < 1) return [part, ''];
        return [part.slice(0, separator), part.slice(separator + 1)];
      }),
  );
}

export function validateUsername(value) {
  const username = String(value || '')
    .trim()
    .toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{2,47}$/.test(username)) {
    const error = new Error(
      'Kullanıcı adı 3–48 karakter olmalı; yalnızca harf, sayı, nokta, tire ve alt çizgi içerebilir.',
    );
    error.code = 'INVALID_USERNAME';
    throw error;
  }
  return username;
}

export function validatePassword(value) {
  const password = String(value || '');
  if (password.length < 12 || password.length > 256) {
    const error = new Error('Parola 12 ile 256 karakter arasında olmalıdır.');
    error.code = 'INVALID_PASSWORD';
    throw error;
  }
  return password;
}

export async function hashPassword(value) {
  const password = validatePassword(value);
  const salt = randomBytes(16);
  const hash = await scrypt(password, salt, HASH_LENGTH, SCRYPT_OPTIONS);
  return {
    passwordHash: Buffer.from(hash).toString('base64'),
    passwordSalt: salt.toString('base64'),
  };
}

export async function verifyPassword(value, user) {
  const password = String(value || '');
  const passwordWithinLimit = password.length <= 256;
  const candidate = passwordWithinLimit ? password : password.slice(0, 256);
  const salt = user?.passwordSalt
    ? Buffer.from(user.passwordSalt, 'base64')
    : Buffer.alloc(16, 0);
  const expected = user?.passwordHash
    ? Buffer.from(user.passwordHash, 'base64')
    : Buffer.alloc(HASH_LENGTH, 0);
  const actual = Buffer.from(
    await scrypt(candidate, salt, HASH_LENGTH, SCRYPT_OPTIONS),
  );
  return (
    Boolean(user) &&
    passwordWithinLimit &&
    expected.length === actual.length &&
    timingSafeEqual(expected, actual)
  );
}

export function createAuthenticatedSession(userId, ttlHours) {
  pruneExpiredSessions();
  const token = randomBytes(32).toString('base64url');
  const tokenHash = sessionTokenHash(token);
  const expiresAt = new Date(Date.now() + ttlHours * 3_600_000).toISOString();
  createSession(tokenHash, userId, expiresAt);
  return { token, expiresAt };
}

export function authenticateRequest(request) {
  const token = parseCookies(request.headers.cookie)[COOKIE_NAME];
  if (!token || token.length > 128) return null;
  return getSession(sessionTokenHash(token));
}

export function destroyRequestSession(request) {
  const token = parseCookies(request.headers.cookie)[COOKIE_NAME];
  if (!token || token.length > 128) return;
  deleteSession(sessionTokenHash(token));
}

export function sessionCookie(token, ttlHours, secure = false) {
  return [
    `${COOKIE_NAME}=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.floor(ttlHours * 3_600)}`,
    secure ? 'Secure' : null,
  ]
    .filter(Boolean)
    .join('; ');
}

export function clearSessionCookie(secure = false) {
  return [
    `${COOKIE_NAME}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    'Max-Age=0',
    secure ? 'Secure' : null,
  ]
    .filter(Boolean)
    .join('; ');
}
