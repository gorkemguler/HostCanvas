import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const serverDirectory = dirname(fileURLToPath(import.meta.url));

function integerFromEnvironment(name, fallback, minimum, maximum) {
  const value = Number.parseInt(process.env[name] ?? '', 10);
  if (!Number.isFinite(value)) return fallback;
  return Math.min(maximum, Math.max(minimum, value));
}

function booleanFromEnvironment(name, fallback = false) {
  const value = process.env[name];
  if (value === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
}

export const PROJECT_ROOT = resolve(serverDirectory, '..');
export const DATA_DIRECTORY = resolve(
  process.env.TLS_SENTINEL_DATA_DIR || resolve(PROJECT_ROOT, 'data'),
);
export const DATABASE_PATH = resolve(DATA_DIRECTORY, 'tlsentinel.db');
export const ARTIFACT_DIRECTORY = resolve(DATA_DIRECTORY, 'artifacts');
export const BACKUP_DIRECTORY = resolve(DATA_DIRECTORY, 'backups');

export const API_HOST = process.env.TLS_SENTINEL_API_HOST || '0.0.0.0';
export const API_PORT = integerFromEnvironment(
  'TLS_SENTINEL_API_PORT',
  8787,
  1024,
  65535,
);
export const UI_ORIGINS = new Set(
  (
    process.env.TLS_SENTINEL_UI_ORIGINS ||
    'http://localhost:3000,http://127.0.0.1:3000'
  )
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean),
);

export const ALLOW_PRIVATE_TARGETS = booleanFromEnvironment(
  'TLS_SENTINEL_ALLOW_PRIVATE_TARGETS',
);
export const PUBLIC_DNS_RESOLVER =
  process.env.TLS_SENTINEL_PUBLIC_DNS_RESOLVER?.trim() || null;
export const SUBDOMAIN_DISCOVERY_ENABLED = booleanFromEnvironment(
  'TLS_SENTINEL_CRT_NAME_ENABLED',
  true,
);
export const SUBDOMAIN_DISCOVERY_LIMIT = integerFromEnvironment(
  'TLS_SENTINEL_CRT_NAME_LIMIT',
  200,
  1,
  500,
);
export const SUBDOMAIN_DISCOVERY_TIMEOUT_MS = integerFromEnvironment(
  'TLS_SENTINEL_CRT_NAME_TIMEOUT_MS',
  10_000,
  1_000,
  30_000,
);
export const TRUST_PROXY = booleanFromEnvironment('TLS_SENTINEL_TRUST_PROXY');
export const TESTSSL_PATH =
  process.env.TLS_SENTINEL_TESTSSL_PATH?.trim() || 'testssl.sh';
export const NATIVE_SCAN_TIMEOUT_MS = integerFromEnvironment(
  'TLS_SENTINEL_NATIVE_TIMEOUT_MS',
  7_000,
  1_000,
  30_000,
);
export const TESTSSL_TIMEOUT_MS = integerFromEnvironment(
  'TLS_SENTINEL_TESTSSL_TIMEOUT_MS',
  240_000,
  30_000,
  900_000,
);
export const MAX_CONCURRENT_SCANS = integerFromEnvironment(
  'TLS_SENTINEL_MAX_CONCURRENT_SCANS',
  2,
  1,
  8,
);
export const SCHEDULER_INTERVAL_MS = integerFromEnvironment(
  'TLS_SENTINEL_SCHEDULER_INTERVAL_MS',
  30_000,
  5_000,
  300_000,
);
export const MAX_REQUEST_BYTES = 64 * 1024;
export const MAX_SCANNER_OUTPUT_BYTES = 512 * 1024;

export const APP_NAME = 'HostCanvas';
export const APP_VERSION = '0.3.0';
