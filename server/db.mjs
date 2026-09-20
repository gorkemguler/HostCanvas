import { randomUUID } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { acquireStateLock, releaseStateLock } from './state-lock.mjs';
import { defaultCheckPolicy, validateCheckPolicy } from './rules/policy.mjs';

import {
  ARTIFACT_DIRECTORY,
  BACKUP_DIRECTORY,
  DATA_DIRECTORY,
  DATABASE_PATH,
} from './config.mjs';

process.umask(0o077);

const STATE_LOCK_PATH = join(DATA_DIRECTORY, '.state-lock.db');
const databaseRole = globalThis[Symbol.for('hostcanvas.database.role')];
let stateLockDatabase = null;
let databaseClosed = false;

function secureDirectory(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
}

function secureRegularFile(path) {
  try {
    if (lstatSync(path).isFile()) chmodSync(path, 0o600);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

function migrateStatePermissions() {
  for (const path of [DATA_DIRECTORY, BACKUP_DIRECTORY, ARTIFACT_DIRECTORY]) {
    secureDirectory(path);
  }
  for (const path of [
    DATABASE_PATH,
    `${DATABASE_PATH}-wal`,
    `${DATABASE_PATH}-shm`,
    STATE_LOCK_PATH,
    `${STATE_LOCK_PATH}-journal`,
    join(DATA_DIRECTORY, '.secret-key'),
  ]) {
    secureRegularFile(path);
  }
  for (const directory of [BACKUP_DIRECTORY, ARTIFACT_DIRECTORY]) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isFile()) secureRegularFile(join(directory, entry.name));
    }
  }
}

migrateStatePermissions();
stateLockDatabase = acquireStateLock(DATA_DIRECTORY, databaseRole);

export const database = new DatabaseSync(DATABASE_PATH);
database.exec('PRAGMA journal_mode = WAL');
database.exec('PRAGMA foreign_keys = ON');
database.exec('PRAGMA busy_timeout = 5000');
secureRegularFile(DATABASE_PATH);
secureRegularFile(`${DATABASE_PATH}-wal`);
secureRegularFile(`${DATABASE_PATH}-shm`);

database.exec(`
  CREATE TABLE IF NOT EXISTS check_policy (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    policy_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS scan_health_state (
    asset_id TEXT PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_scan_id TEXT,
    last_success_at TEXT,
    updated_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL COLLATE NOCASE,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    label TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT 'production',
    tags_json TEXT NOT NULL DEFAULT '[]',
    authorized INTEGER NOT NULL DEFAULT 1 CHECK (authorized IN (0, 1)),
    allow_private INTEGER NOT NULL DEFAULT 0 CHECK (allow_private IN (0, 1)),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    scan_profile TEXT NOT NULL DEFAULT 'native' CHECK (scan_profile IN ('native', 'deep')),
    expiry_warning_days INTEGER NOT NULL DEFAULT 30 CHECK (expiry_warning_days BETWEEN 1 AND 365),
    scan_interval_minutes INTEGER NOT NULL DEFAULT 720 CHECK (scan_interval_minutes BETWEEN 15 AND 10080),
    last_scan_at TEXT,
    next_scan_at TEXT,
    latest_grade TEXT,
    latest_status TEXT NOT NULL DEFAULT 'never_scanned',
    latest_certificate_expires_at TEXT,
    latest_ip TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(hostname, port)
  );

  CREATE TABLE IF NOT EXISTS asset_discovery_links (
    asset_id TEXT PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    parent_asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider IN ('crt.name')),
    first_seen_at TEXT,
    discovered_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    profile TEXT NOT NULL CHECK (profile IN ('native', 'deep')),
    trigger_kind TEXT NOT NULL DEFAULT 'manual' CHECK (trigger_kind IN ('manual', 'scheduled', 'initial')),
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'partial', 'failed')),
    started_at TEXT,
    finished_at TEXT,
    duration_ms INTEGER,
    grade TEXT,
    scanner_version TEXT,
    error_code TEXT,
    error_message TEXT,
    observations_json TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    identity_key TEXT NOT NULL UNIQUE,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    rule_key TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status TEXT NOT NULL CHECK (status IN ('open', 'acknowledged', 'resolved')),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    resolved_at TEXT,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS incident_events (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'system',
    note TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS app_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    setup_completed INTEGER NOT NULL DEFAULT 0 CHECK (setup_completed IN (0, 1)),
    language TEXT NOT NULL DEFAULT 'tr' CHECK (language IN ('tr', 'en')),
    organization TEXT NOT NULL DEFAULT '',
    lan_enabled INTEGER NOT NULL DEFAULT 0 CHECK (lan_enabled IN (0, 1)),
    auth_enabled INTEGER NOT NULL DEFAULT 1 CHECK (auth_enabled IN (0, 1)),
    allowed_origins_json TEXT NOT NULL DEFAULT '[]',
    session_ttl_hours INTEGER NOT NULL DEFAULT 12 CHECK (session_ttl_hours BETWEEN 1 AND 168),
    default_scan_profile TEXT NOT NULL DEFAULT 'native' CHECK (default_scan_profile IN ('native', 'deep')),
    default_expiry_warning_days INTEGER NOT NULL DEFAULT 30 CHECK (default_expiry_warning_days BETWEEN 1 AND 365),
    default_scan_interval_minutes INTEGER NOT NULL DEFAULT 720 CHECK (default_scan_interval_minutes BETWEEN 15 AND 10080),
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin')),
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS user_access (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'operator', 'viewer')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    summary TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    source_ip TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS notification_channels (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'generic' CHECK (kind IN ('generic', 'slack')),
    url_encrypted TEXT NOT NULL,
    min_severity TEXT NOT NULL DEFAULT 'high' CHECK (min_severity IN ('critical', 'high', 'medium', 'low', 'info')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS notification_deliveries (
    id TEXT PRIMARY KEY,
    channel_id TEXT REFERENCES notification_channels(id) ON DELETE SET NULL,
    channel_name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    incident_id TEXT REFERENCES incidents(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK (status IN ('succeeded', 'failed')),
    response_code INTEGER,
    error_message TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS maintenance_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    scan_retention_days INTEGER NOT NULL DEFAULT 180 CHECK (scan_retention_days BETWEEN 7 AND 3650),
    artifact_retention_days INTEGER NOT NULL DEFAULT 30 CHECK (artifact_retention_days BETWEEN 1 AND 3650),
    backup_retention_count INTEGER NOT NULL DEFAULT 14 CHECK (backup_retention_count BETWEEN 1 AND 100),
    backup_interval_hours INTEGER NOT NULL DEFAULT 24 CHECK (backup_interval_hours BETWEEN 1 AND 168),
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_assets_next_scan_at
    ON assets(next_scan_at) WHERE enabled = 1;
  CREATE INDEX IF NOT EXISTS idx_asset_discovery_parent
    ON asset_discovery_links(parent_asset_id, discovered_at DESC);
  CREATE INDEX IF NOT EXISTS idx_scans_asset_created_at
    ON scans(asset_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_scans_status
    ON scans(status, created_at);
  CREATE INDEX IF NOT EXISTS idx_incidents_asset_status
    ON incidents(asset_id, status);
  CREATE INDEX IF NOT EXISTS idx_incidents_status_severity
    ON incidents(status, severity, last_seen_at DESC);
  CREATE INDEX IF NOT EXISTS idx_incident_events_incident
    ON incident_events(incident_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
    ON sessions(expires_at);
  CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
    ON audit_events(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_audit_events_actor_created_at
    ON audit_events(actor_user_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_notification_deliveries_created_at
    ON notification_deliveries(created_at DESC);
`);
database
  .prepare(
    `INSERT OR IGNORE INTO app_settings (id, updated_at)
     VALUES (1, ?)`,
  )
  .run(new Date().toISOString());
database
  .prepare(
    `INSERT OR IGNORE INTO maintenance_settings (id, updated_at)
     VALUES (1, ?)`,
  )
  .run(new Date().toISOString());
database
  .prepare(
    `INSERT OR IGNORE INTO user_access (user_id, role, enabled, created_at, updated_at)
     SELECT id, 'admin', 1, created_at, updated_at FROM users`,
  )
  .run();
database
  .prepare(
    `INSERT OR IGNORE INTO schema_migrations (version, name, applied_at)
     VALUES (2, 'team-access-audit-notifications-maintenance', ?)`,
  )
  .run(new Date().toISOString());
database
  .prepare(
    `INSERT OR IGNORE INTO schema_migrations (version, name, applied_at)
     VALUES (3, 'asset-subdomain-discovery-links', ?)`,
  )
  .run(new Date().toISOString());
database
  .prepare(
    `INSERT OR IGNORE INTO schema_migrations (version, name, applied_at)
     VALUES (4, 'check-policy-and-persistent-scan-health', ?)`,
  )
  .run(new Date().toISOString());
database
  .prepare('DELETE FROM sessions WHERE expires_at <= ?')
  .run(new Date().toISOString());
database.exec('PRAGMA optimize');

const parseJson = (value, fallback) => {
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
};

const booleanFields = (record) => ({
  ...record,
  authorized: Boolean(record.authorized),
  allowPrivate: Boolean(record.allow_private),
  enabled: Boolean(record.enabled),
});

function shapeAsset(record) {
  if (!record) return null;
  const normalized = booleanFields(record);
  return {
    id: normalized.id,
    hostname: normalized.hostname,
    port: normalized.port,
    label: normalized.label,
    owner: normalized.owner,
    environment: normalized.environment,
    tags: parseJson(normalized.tags_json, []),
    authorized: normalized.authorized,
    allowPrivate: normalized.allowPrivate,
    enabled: normalized.enabled,
    scanProfile: normalized.scan_profile,
    expiryWarningDays: normalized.expiry_warning_days,
    scanIntervalMinutes: normalized.scan_interval_minutes,
    lastScanAt: normalized.last_scan_at,
    nextScanAt: normalized.next_scan_at,
    latestGrade: normalized.latest_grade,
    latestStatus: normalized.latest_status,
    certificateExpiresAt: normalized.latest_certificate_expires_at,
    latestIp: normalized.latest_ip,
    source: normalized.discovery_provider || 'manual',
    parentAssetId: normalized.parent_asset_id || null,
    discoveredAt: normalized.discovered_at || null,
    firstSeenAt: normalized.first_seen_at || null,
    discoveredAssetCount: Number(normalized.discovered_asset_count || 0),
    openIncidentCount: Number(normalized.open_incident_count || 0),
    criticalIncidentCount: Number(normalized.critical_incident_count || 0),
    createdAt: normalized.created_at,
    updatedAt: normalized.updated_at,
  };
}

function shapeScan(record) {
  if (!record) return null;
  return {
    id: record.id,
    assetId: record.asset_id,
    hostname: record.hostname,
    port: record.port,
    profile: record.profile,
    trigger: record.trigger_kind,
    status: record.status,
    startedAt: record.started_at,
    finishedAt: record.finished_at,
    durationMs: record.duration_ms,
    grade: record.grade,
    scannerVersion: record.scanner_version,
    errorCode: record.error_code,
    errorMessage: record.error_message,
    observations: parseJson(record.observations_json, null),
    createdAt: record.created_at,
  };
}

function shapeIncident(record) {
  if (!record) return null;
  return {
    id: record.id,
    assetId: record.asset_id,
    hostname: record.hostname,
    port: record.port,
    owner: record.owner,
    ruleKey: record.rule_key,
    severity: record.severity,
    status: record.status,
    title: record.title,
    description: record.description,
    evidence: parseJson(record.evidence_json, {}),
    firstSeenAt: record.first_seen_at,
    lastSeenAt: record.last_seen_at,
    resolvedAt: record.resolved_at,
    occurrenceCount: record.occurrence_count,
    scanId: record.scan_id,
    createdAt: record.created_at,
    updatedAt: record.updated_at,
  };
}

function shapeAppSettings(record) {
  if (!record) return null;
  return {
    setupCompleted: Boolean(record.setup_completed),
    language: record.language,
    organization: record.organization,
    lanEnabled: Boolean(record.lan_enabled),
    authEnabled: Boolean(record.auth_enabled),
    allowedOrigins: parseJson(record.allowed_origins_json, []),
    sessionTtlHours: record.session_ttl_hours,
    defaultScanProfile: record.default_scan_profile,
    defaultExpiryWarningDays: record.default_expiry_warning_days,
    defaultScanIntervalMinutes: record.default_scan_interval_minutes,
    updatedAt: record.updated_at,
  };
}

function shapeUser(record) {
  if (!record) return null;
  return {
    id: record.id,
    username: record.username,
    displayName: record.display_name,
    role: record.access_role || record.role,
    enabled:
      record.access_enabled == null ? true : Boolean(record.access_enabled),
    passwordHash: record.password_hash,
    passwordSalt: record.password_salt,
    createdAt: record.created_at,
    updatedAt: record.updated_at,
  };
}

export function getAppSettings() {
  return shapeAppSettings(
    database.prepare('SELECT * FROM app_settings WHERE id = 1').get(),
  );
}

export function getCheckPolicy() {
  const row = database.prepare('SELECT * FROM check_policy WHERE id = 1').get();
  return {
    policy: validateCheckPolicy(parseJson(row?.policy_json, {})),
    updatedAt: row?.updated_at || null,
  };
}

export function updateCheckPolicy(input) {
  const policy = validateCheckPolicy(input, getCheckPolicy().policy);
  database
    .prepare(`INSERT INTO check_policy (id, policy_json, updated_at) VALUES (1, ?, ?)
    ON CONFLICT(id) DO UPDATE SET policy_json = excluded.policy_json, updated_at = excluded.updated_at`)
    .run(JSON.stringify(policy), new Date().toISOString());
  return getCheckPolicy();
}

// Persistent streaks survive scan retention and restarts. One scan counts once.
export function recordScanHealth(
  assetId,
  scanId,
  healthy,
  reason,
  policy = defaultCheckPolicy,
) {
  const asset = getAsset(assetId);
  const scan = getScan(scanId);
  if (
    !asset?.enabled ||
    scan?.assetId !== assetId ||
    !['succeeded', 'partial', 'failed'].includes(scan.status)
  )
    return [];
  const previous = database
    .prepare('SELECT * FROM scan_health_state WHERE asset_id = ?')
    .get(assetId);
  if (previous?.last_scan_id === scanId) return [];
  const now = new Date().toISOString();
  const count = healthy ? 0 : (previous?.consecutive_failures || 0) + 1;
  database
    .prepare(`INSERT INTO scan_health_state (asset_id, consecutive_failures, last_scan_id, last_success_at, updated_at)
    VALUES (?, ?, ?, ?, ?) ON CONFLICT(asset_id) DO UPDATE SET consecutive_failures = excluded.consecutive_failures,
    last_scan_id = excluded.last_scan_id, last_success_at = excluded.last_success_at, updated_at = excluded.updated_at`)
    .run(
      assetId,
      count,
      scanId,
      healthy ? now : previous?.last_success_at || null,
      now,
    );
  if (!policy.scanHealthEnabled) return [];
  const ruleKey = 'monitor.scan_unhealthy';
  const evaluation = healthy
    ? { ruleKey, status: 'pass' }
    : count >= policy.scanFailureThreshold
      ? {
          ruleKey,
          status: 'fail',
          severity: 'medium',
          title: 'Tarama güvenilirliği kayboldu / Scan coverage degraded',
          description: `${count} ardışık taramada zorunlu kapsam tamamlanamadı / consecutive scans could not complete required coverage.`,
          evidence: {
            consecutiveFailures: count,
            threshold: policy.scanFailureThreshold,
            lastSuccessAt: previous?.last_success_at || null,
            reason: String(reason || 'SCAN_INCOMPLETE').slice(0, 200),
          },
        }
      : { ruleKey, status: 'unknown' };
  return reconcileIncidents(assetId, scanId, [evaluation]);
}

export function completeSetup(input) {
  const now = new Date().toISOString();
  database.exec('BEGIN IMMEDIATE');
  try {
    const current = database
      .prepare('SELECT setup_completed FROM app_settings WHERE id = 1')
      .get();
    if (current?.setup_completed) {
      const error = new Error('İlk kurulum daha önce tamamlanmış.');
      error.code = 'SETUP_ALREADY_COMPLETED';
      throw error;
    }

    const userId = randomUUID();
    database
      .prepare(
        `INSERT INTO users (
          id, username, display_name, role, password_hash, password_salt,
          created_at, updated_at
        ) VALUES (?, ?, ?, 'admin', ?, ?, ?, ?)`,
      )
      .run(
        userId,
        input.username,
        input.displayName,
        input.passwordHash,
        input.passwordSalt,
        now,
        now,
      );
    database
      .prepare(
        `INSERT INTO user_access (user_id, role, enabled, created_at, updated_at)
         VALUES (?, 'admin', 1, ?, ?)`,
      )
      .run(userId, now, now);
    database
      .prepare(
        `UPDATE app_settings SET
          setup_completed = 1, language = ?, organization = ?, lan_enabled = ?,
          auth_enabled = ?, allowed_origins_json = ?, session_ttl_hours = ?,
          default_scan_profile = ?, default_expiry_warning_days = ?,
          default_scan_interval_minutes = ?, updated_at = ?
         WHERE id = 1`,
      )
      .run(
        input.language,
        input.organization,
        input.lanEnabled ? 1 : 0,
        input.authEnabled ? 1 : 0,
        JSON.stringify(input.allowedOrigins),
        input.sessionTtlHours,
        input.defaultScanProfile,
        input.defaultExpiryWarningDays,
        input.defaultScanIntervalMinutes,
        now,
      );
    database.exec('COMMIT');
    return { settings: getAppSettings(), user: getUserById(userId) };
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
}

export function updateAppSettings(input) {
  const current = getAppSettings();
  const now = new Date().toISOString();
  database
    .prepare(
      `UPDATE app_settings SET
        language = ?, organization = ?, lan_enabled = ?, auth_enabled = ?,
        allowed_origins_json = ?, session_ttl_hours = ?, default_scan_profile = ?,
        default_expiry_warning_days = ?, default_scan_interval_minutes = ?,
        updated_at = ? WHERE id = 1`,
    )
    .run(
      input.language ?? current.language,
      input.organization ?? current.organization,
      (input.lanEnabled ?? current.lanEnabled) ? 1 : 0,
      (input.authEnabled ?? current.authEnabled) ? 1 : 0,
      JSON.stringify(input.allowedOrigins ?? current.allowedOrigins),
      input.sessionTtlHours ?? current.sessionTtlHours,
      input.defaultScanProfile ?? current.defaultScanProfile,
      input.defaultExpiryWarningDays ?? current.defaultExpiryWarningDays,
      input.defaultScanIntervalMinutes ?? current.defaultScanIntervalMinutes,
      now,
    );
  return getAppSettings();
}

export function getUserById(id) {
  return shapeUser(
    database
      .prepare(
        `SELECT u.*, ua.role AS access_role, ua.enabled AS access_enabled
         FROM users u JOIN user_access ua ON ua.user_id = u.id WHERE u.id = ?`,
      )
      .get(id),
  );
}

export function getUserByUsername(username) {
  return shapeUser(
    database
      .prepare(
        `SELECT u.*, ua.role AS access_role, ua.enabled AS access_enabled
         FROM users u JOIN user_access ua ON ua.user_id = u.id
         WHERE u.username = ? COLLATE NOCASE AND ua.enabled = 1`,
      )
      .get(username),
  );
}

export function updateUserPassword(id, passwordHash, passwordSalt) {
  const now = new Date().toISOString();
  database
    .prepare(
      `UPDATE users SET password_hash = ?, password_salt = ?, updated_at = ?
       WHERE id = ?`,
    )
    .run(passwordHash, passwordSalt, now, id);
  database.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
  return getUserById(id);
}

export function listUsers() {
  return database
    .prepare(
      `SELECT u.*, ua.role AS access_role, ua.enabled AS access_enabled
       FROM users u JOIN user_access ua ON ua.user_id = u.id
       ORDER BY ua.enabled DESC, u.created_at ASC`,
    )
    .all()
    .map(shapeUser);
}

export function createUser(input) {
  const id = randomUUID();
  const now = new Date().toISOString();
  database.exec('BEGIN IMMEDIATE');
  try {
    database
      .prepare(
        `INSERT INTO users (
          id, username, display_name, role, password_hash, password_salt,
          created_at, updated_at
        ) VALUES (?, ?, ?, 'admin', ?, ?, ?, ?)`,
      )
      .run(
        id,
        input.username,
        input.displayName,
        input.passwordHash,
        input.passwordSalt,
        now,
        now,
      );
    database
      .prepare(
        `INSERT INTO user_access (user_id, role, enabled, created_at, updated_at)
         VALUES (?, ?, 1, ?, ?)`,
      )
      .run(id, input.role, now, now);
    database.exec('COMMIT');
    return getUserById(id);
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
}

export function updateUserAccess(id, input) {
  const current = getUserById(id);
  if (!current) return null;
  const role = input.role ?? current.role;
  const enabled = input.enabled ?? current.enabled;
  if (
    current.role === 'admin' &&
    current.enabled &&
    (role !== 'admin' || !enabled) &&
    countEnabledAdmins() <= 1
  ) {
    const error = new Error(
      'Son etkin yönetici hesabı devre dışı bırakılamaz.',
    );
    error.code = 'LAST_ADMIN_REQUIRED';
    throw error;
  }
  const now = new Date().toISOString();
  database.exec('BEGIN IMMEDIATE');
  try {
    if (input.displayName !== undefined) {
      database
        .prepare(
          'UPDATE users SET display_name = ?, updated_at = ? WHERE id = ?',
        )
        .run(input.displayName, now, id);
    }
    database
      .prepare(
        'UPDATE user_access SET role = ?, enabled = ?, updated_at = ? WHERE user_id = ?',
      )
      .run(role, enabled ? 1 : 0, now, id);
    if (!enabled || role !== current.role) {
      database.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
    }
    database.exec('COMMIT');
    return getUserById(id);
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
}

export function countEnabledAdmins() {
  return Number(
    database
      .prepare(
        "SELECT COUNT(*) AS count FROM user_access WHERE role = 'admin' AND enabled = 1",
      )
      .get().count,
  );
}

export function addAuditEvent(input) {
  const id = randomUUID();
  database
    .prepare(
      `INSERT INTO audit_events (
        id, actor_user_id, actor, action, target_type, target_id,
        summary, metadata_json, source_ip, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      id,
      input.actorUserId || null,
      input.actor || 'system',
      input.action,
      input.targetType,
      input.targetId || null,
      input.summary,
      JSON.stringify(input.metadata || {}),
      input.sourceIp || null,
      new Date().toISOString(),
    );
  return id;
}

export function listAuditEvents({ limit = 100, offset = 0 } = {}) {
  const safeLimit = Math.min(200, Math.max(1, Number(limit) || 100));
  const safeOffset = Math.max(0, Number(offset) || 0);
  const total = Number(
    database.prepare('SELECT COUNT(*) AS count FROM audit_events').get().count,
  );
  const events = database
    .prepare(
      `SELECT * FROM audit_events ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    )
    .all(safeLimit, safeOffset)
    .map((record) => ({
      id: record.id,
      actorUserId: record.actor_user_id,
      actor: record.actor,
      action: record.action,
      targetType: record.target_type,
      targetId: record.target_id,
      summary: record.summary,
      metadata: parseJson(record.metadata_json, {}),
      sourceIp: record.source_ip,
      createdAt: record.created_at,
    }));
  return { events, total, limit: safeLimit, offset: safeOffset };
}

export function createSession(tokenHash, userId, expiresAt) {
  const now = new Date().toISOString();
  database
    .prepare(
      `INSERT INTO sessions (token_hash, user_id, expires_at, last_seen_at, created_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .run(tokenHash, userId, expiresAt, now, now);
}

export function getSession(tokenHash) {
  const now = new Date().toISOString();
  const record = database
    .prepare(
      `SELECT s.token_hash, s.user_id, s.expires_at, s.last_seen_at,
              u.username, u.display_name, ua.role
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       JOIN user_access ua ON ua.user_id = u.id
       WHERE s.token_hash = ? AND s.expires_at > ? AND ua.enabled = 1`,
    )
    .get(tokenHash, now);
  if (!record) {
    database
      .prepare('DELETE FROM sessions WHERE token_hash = ?')
      .run(tokenHash);
    return null;
  }
  database
    .prepare('UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?')
    .run(now, tokenHash);
  return {
    tokenHash: record.token_hash,
    userId: record.user_id,
    username: record.username,
    displayName: record.display_name,
    role: record.role,
    expiresAt: record.expires_at,
  };
}

export function deleteSession(tokenHash) {
  return database
    .prepare('DELETE FROM sessions WHERE token_hash = ?')
    .run(tokenHash).changes;
}

export function pruneExpiredSessions() {
  return database
    .prepare('DELETE FROM sessions WHERE expires_at <= ?')
    .run(new Date().toISOString()).changes;
}

function shapeNotificationChannel(record) {
  if (!record) return null;
  return {
    id: record.id,
    name: record.name,
    kind: record.kind,
    urlEncrypted: record.url_encrypted,
    minSeverity: record.min_severity,
    enabled: Boolean(record.enabled),
    createdAt: record.created_at,
    updatedAt: record.updated_at,
  };
}

export function listNotificationChannels({ enabledOnly = false } = {}) {
  const rows = enabledOnly
    ? database
        .prepare(
          'SELECT * FROM notification_channels WHERE enabled = 1 ORDER BY created_at ASC',
        )
        .all()
    : database
        .prepare('SELECT * FROM notification_channels ORDER BY created_at ASC')
        .all();
  return rows.map(shapeNotificationChannel);
}

export function getNotificationChannel(id) {
  return shapeNotificationChannel(
    database
      .prepare('SELECT * FROM notification_channels WHERE id = ?')
      .get(id),
  );
}

export function createNotificationChannel(input) {
  const id = randomUUID();
  const now = new Date().toISOString();
  database
    .prepare(
      `INSERT INTO notification_channels (
        id, name, kind, url_encrypted, min_severity, enabled, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)`,
    )
    .run(
      id,
      input.name,
      input.kind,
      input.urlEncrypted,
      input.minSeverity,
      now,
      now,
    );
  return getNotificationChannel(id);
}

export function updateNotificationChannel(id, input) {
  const current = getNotificationChannel(id);
  if (!current) return null;
  const now = new Date().toISOString();
  database
    .prepare(
      `UPDATE notification_channels SET
        name = ?, kind = ?, url_encrypted = ?, min_severity = ?, enabled = ?, updated_at = ?
       WHERE id = ?`,
    )
    .run(
      input.name ?? current.name,
      input.kind ?? current.kind,
      input.urlEncrypted ?? current.urlEncrypted,
      input.minSeverity ?? current.minSeverity,
      (input.enabled ?? current.enabled) ? 1 : 0,
      now,
      id,
    );
  return getNotificationChannel(id);
}

export function deleteNotificationChannel(id) {
  return database
    .prepare('DELETE FROM notification_channels WHERE id = ?')
    .run(id).changes;
}

export function addNotificationDelivery(input) {
  database
    .prepare(
      `INSERT INTO notification_deliveries (
        id, channel_id, channel_name, event_type, incident_id, status,
        response_code, error_message, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      randomUUID(),
      input.channelId || null,
      input.channelName,
      input.eventType,
      input.incidentId || null,
      input.status,
      input.responseCode || null,
      input.errorMessage || null,
      new Date().toISOString(),
    );
}

export function listNotificationDeliveries(limit = 50) {
  return database
    .prepare(
      `SELECT * FROM notification_deliveries ORDER BY created_at DESC LIMIT ?`,
    )
    .all(Math.min(100, Math.max(1, Number(limit) || 50)))
    .map((record) => ({
      id: record.id,
      channelId: record.channel_id,
      channelName: record.channel_name,
      eventType: record.event_type,
      incidentId: record.incident_id,
      status: record.status,
      responseCode: record.response_code,
      errorMessage: record.error_message,
      createdAt: record.created_at,
    }));
}

export function getMaintenanceSettings() {
  const record = database
    .prepare('SELECT * FROM maintenance_settings WHERE id = 1')
    .get();
  return {
    scanRetentionDays: record.scan_retention_days,
    artifactRetentionDays: record.artifact_retention_days,
    backupRetentionCount: record.backup_retention_count,
    backupIntervalHours: record.backup_interval_hours,
    updatedAt: record.updated_at,
  };
}

export function updateMaintenanceSettings(input) {
  const current = getMaintenanceSettings();
  const now = new Date().toISOString();
  database
    .prepare(
      `UPDATE maintenance_settings SET
        scan_retention_days = ?, artifact_retention_days = ?,
        backup_retention_count = ?, backup_interval_hours = ?, updated_at = ?
       WHERE id = 1`,
    )
    .run(
      input.scanRetentionDays ?? current.scanRetentionDays,
      input.artifactRetentionDays ?? current.artifactRetentionDays,
      input.backupRetentionCount ?? current.backupRetentionCount,
      input.backupIntervalHours ?? current.backupIntervalHours,
      now,
    );
  return getMaintenanceSettings();
}

export function pruneScanHistory(retentionDays) {
  const cutoff = new Date(
    Date.now() - retentionDays * 86_400_000,
  ).toISOString();
  const records = database
    .prepare(
      `SELECT id FROM scans
       WHERE status NOT IN ('queued', 'running')
         AND COALESCE(finished_at, created_at) < ?`,
    )
    .all(cutoff);
  if (!records.length) return [];
  const remove = database.prepare('DELETE FROM scans WHERE id = ?');
  database.exec('BEGIN IMMEDIATE');
  try {
    for (const record of records) remove.run(record.id);
    database
      .prepare('DELETE FROM notification_deliveries WHERE created_at < ?')
      .run(cutoff);
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
  return records.map((record) => record.id);
}

const assetSelect = `
  SELECT a.*,
    (SELECT d.provider FROM asset_discovery_links d WHERE d.asset_id = a.id) AS discovery_provider,
    (SELECT d.parent_asset_id FROM asset_discovery_links d WHERE d.asset_id = a.id) AS parent_asset_id,
    (SELECT d.first_seen_at FROM asset_discovery_links d WHERE d.asset_id = a.id) AS first_seen_at,
    (SELECT d.discovered_at FROM asset_discovery_links d WHERE d.asset_id = a.id) AS discovered_at,
    (SELECT COUNT(*) FROM asset_discovery_links d
      JOIN assets child ON child.id = d.asset_id
      WHERE d.parent_asset_id = a.id AND child.enabled = 1) AS discovered_asset_count,
    (SELECT COUNT(*) FROM incidents i WHERE i.asset_id = a.id AND i.status != 'resolved') AS open_incident_count,
    (SELECT COUNT(*) FROM incidents i WHERE i.asset_id = a.id AND i.status != 'resolved' AND i.severity = 'critical') AS critical_incident_count
  FROM assets a
`;

export function listAssets({ includeDisabled = false } = {}) {
  const statement = includeDisabled
    ? `${assetSelect} ORDER BY a.created_at DESC`
    : `${assetSelect} WHERE a.enabled = 1 ORDER BY a.created_at DESC`;
  return database.prepare(statement).all().map(shapeAsset);
}

export function getAsset(id) {
  return shapeAsset(database.prepare(`${assetSelect} WHERE a.id = ?`).get(id));
}

export function createAsset(input) {
  const id = randomUUID();
  const now = new Date().toISOString();
  database
    .prepare(
      `INSERT INTO assets (
        id, hostname, port, label, owner, environment, tags_json, authorized,
        allow_private, enabled, scan_profile, expiry_warning_days,
        scan_interval_minutes, next_scan_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 1, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      id,
      input.hostname,
      input.port,
      input.label || input.hostname,
      input.owner || '',
      input.environment || 'production',
      JSON.stringify(input.tags || []),
      input.allowPrivate ? 1 : 0,
      input.scanProfile || 'native',
      input.expiryWarningDays || 30,
      input.scanIntervalMinutes || 720,
      now,
      now,
      now,
    );
  return getAsset(id);
}

export function createDiscoveredAssets(parentAssetId, records) {
  const parent = getAsset(parentAssetId);
  if (!parent) return null;

  const now = new Date();
  const nowIso = now.toISOString();
  const tags = [...new Set([...parent.tags, 'crt.name'])].slice(0, 12);
  const insertAsset = database.prepare(
    `INSERT OR IGNORE INTO assets (
      id, hostname, port, label, owner, environment, tags_json, authorized,
      allow_private, enabled, scan_profile, expiry_warning_days,
      scan_interval_minutes, next_scan_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 1, ?, ?, ?, ?, ?, ?)`,
  );
  const insertLink = database.prepare(
    `INSERT INTO asset_discovery_links (
      asset_id, parent_asset_id, provider, first_seen_at, discovered_at
    ) VALUES (?, ?, 'crt.name', ?, ?)`,
  );
  const createdAssetIds = [];
  let existingCount = 0;

  database.exec('BEGIN IMMEDIATE');
  try {
    for (const [index, record] of records.entries()) {
      const id = randomUUID();
      const nextScanAt = new Date(
        now.getTime() + parent.scanIntervalMinutes * 60_000 + index * 60_000,
      ).toISOString();
      const result = insertAsset.run(
        id,
        record.hostname,
        parent.port,
        record.hostname,
        parent.owner,
        parent.environment,
        JSON.stringify(tags),
        parent.allowPrivate ? 1 : 0,
        parent.scanProfile,
        parent.expiryWarningDays,
        parent.scanIntervalMinutes,
        nextScanAt,
        nowIso,
        nowIso,
      );
      if (result.changes !== 1) {
        existingCount += 1;
        continue;
      }
      insertLink.run(id, parent.id, record.firstSeenAt || null, nowIso);
      createdAssetIds.push(id);
    }
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }

  return {
    createdCount: createdAssetIds.length,
    existingCount,
    assets: createdAssetIds.map((id) => getAsset(id)),
  };
}

export function updateAsset(id, input) {
  const current = getAsset(id);
  if (!current) return null;
  const now = new Date().toISOString();
  const next = {
    label: input.label ?? current.label,
    owner: input.owner ?? current.owner,
    environment: input.environment ?? current.environment,
    tags: input.tags ?? current.tags,
    allowPrivate: input.allowPrivate ?? current.allowPrivate,
    enabled: input.enabled ?? current.enabled,
    scanProfile: input.scanProfile ?? current.scanProfile,
    expiryWarningDays: input.expiryWarningDays ?? current.expiryWarningDays,
    scanIntervalMinutes:
      input.scanIntervalMinutes ?? current.scanIntervalMinutes,
  };
  database
    .prepare(
      `UPDATE assets SET
        label = ?, owner = ?, environment = ?, tags_json = ?, allow_private = ?,
        enabled = ?, scan_profile = ?, expiry_warning_days = ?,
        scan_interval_minutes = ?, updated_at = ?
      WHERE id = ?`,
    )
    .run(
      next.label,
      next.owner,
      next.environment,
      JSON.stringify(next.tags),
      next.allowPrivate ? 1 : 0,
      next.enabled ? 1 : 0,
      next.scanProfile,
      next.expiryWarningDays,
      next.scanIntervalMinutes,
      now,
      id,
    );
  return getAsset(id);
}

export function archiveAsset(id) {
  const current = getAsset(id);
  if (!current) return null;
  const now = new Date().toISOString();

  database.exec('BEGIN IMMEDIATE');
  try {
    database
      .prepare('UPDATE assets SET enabled = 0, updated_at = ? WHERE id = ?')
      .run(now, id);
    const activeIncidents = database
      .prepare(
        "SELECT id FROM incidents WHERE asset_id = ? AND status != 'resolved'",
      )
      .all(id);
    for (const incident of activeIncidents) {
      database
        .prepare(
          `UPDATE incidents SET status = 'resolved', resolved_at = ?, updated_at = ?
           WHERE id = ?`,
        )
        .run(now, now, incident.id);
      addIncidentEvent(
        incident.id,
        'resolved_asset_archived',
        'local-user',
        'Varlık arşivlendiği için aktif incident kapatıldı.',
      );
    }
    database
      .prepare(
        `UPDATE scans SET status = 'failed', finished_at = ?, error_code = 'ASSET_ARCHIVED',
         error_message = 'Varlık tarama başlamadan önce arşivlendi.'
         WHERE asset_id = ? AND status = 'queued'`,
      )
      .run(now, id);
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
  return getAsset(id);
}

export function findActiveScan(assetId) {
  return shapeScan(
    database
      .prepare(
        `SELECT s.*, a.hostname, a.port
         FROM scans s JOIN assets a ON a.id = s.asset_id
         WHERE s.asset_id = ? AND s.status IN ('queued', 'running')
         ORDER BY s.created_at DESC LIMIT 1`,
      )
      .get(assetId),
  );
}

export function createScan(assetId, profile, trigger = 'manual') {
  const active = findActiveScan(assetId);
  if (active) return { scan: active, created: false };

  const id = randomUUID();
  const now = new Date().toISOString();
  database
    .prepare(
      `INSERT INTO scans (id, asset_id, profile, trigger_kind, status, created_at)
       VALUES (?, ?, ?, ?, 'queued', ?)`,
    )
    .run(id, assetId, profile, trigger, now);
  return { scan: getScan(id), created: true };
}

export function getScan(id) {
  return shapeScan(
    database
      .prepare(
        `SELECT s.*, a.hostname, a.port
         FROM scans s JOIN assets a ON a.id = s.asset_id WHERE s.id = ?`,
      )
      .get(id),
  );
}

export function listQueuedScans(limit = 10) {
  return database
    .prepare(
      `SELECT s.*, a.hostname, a.port
       FROM scans s JOIN assets a ON a.id = s.asset_id
       WHERE s.status = 'queued' ORDER BY s.created_at ASC LIMIT ?`,
    )
    .all(limit)
    .map(shapeScan);
}

export function markScanRunning(id) {
  const now = new Date().toISOString();
  const result = database
    .prepare(
      `UPDATE scans SET status = 'running', started_at = ?
       WHERE id = ? AND status = 'queued'`,
    )
    .run(now, id);
  return result.changes === 1 ? getScan(id) : null;
}

export function finishScan(id, result) {
  const scan = getScan(id);
  if (!scan) return null;
  const asset = getAsset(scan.assetId);
  const finishedAt = new Date().toISOString();
  const startedAt = scan.startedAt ? Date.parse(scan.startedAt) : Date.now();
  const durationMs = Math.max(0, Date.now() - startedAt);
  const status = result.status || 'succeeded';

  database
    .prepare(
      `UPDATE scans SET
        status = ?, finished_at = ?, duration_ms = ?, grade = ?, scanner_version = ?,
        error_code = ?, error_message = ?, observations_json = ?
      WHERE id = ?`,
    )
    .run(
      status,
      finishedAt,
      durationMs,
      result.grade || null,
      result.scannerVersion || null,
      result.errorCode || null,
      result.errorMessage || null,
      result.observations ? JSON.stringify(result.observations) : null,
      id,
    );

  const intervalMinutes =
    status === 'failed'
      ? Math.min(asset?.scanIntervalMinutes || 720, 15)
      : asset?.scanIntervalMinutes || 720;
  const interval = intervalMinutes * 60_000;
  const nextScanAt = new Date(Date.now() + interval).toISOString();
  const preserveLastReliableSnapshot = status === 'failed';
  const latestGrade = preserveLastReliableSnapshot
    ? asset?.latestGrade
    : result.grade || asset?.latestGrade;
  const certificateExpiresAt = preserveLastReliableSnapshot
    ? asset?.certificateExpiresAt
    : result.observations?.tls?.certificate?.validTo ||
      asset?.certificateExpiresAt;
  const latestIp = preserveLastReliableSnapshot
    ? asset?.latestIp
    : result.observations?.target?.address || asset?.latestIp;
  database
    .prepare(
      `UPDATE assets SET
        last_scan_at = ?, next_scan_at = ?, latest_grade = ?, latest_status = ?,
        latest_certificate_expires_at = ?, latest_ip = ?, updated_at = ?
      WHERE id = ?`,
    )
    .run(
      finishedAt,
      nextScanAt,
      latestGrade || null,
      status,
      certificateExpiresAt || null,
      latestIp || null,
      finishedAt,
      scan.assetId,
    );

  return getScan(id);
}

export function recoverInterruptedScans() {
  return database
    .prepare(
      `UPDATE scans SET status = 'queued', started_at = NULL,
       error_code = NULL, error_message = NULL WHERE status = 'running'`,
    )
    .run().changes;
}

export function getDueAssets(limit = 20) {
  const now = new Date().toISOString();
  return database
    .prepare(
      `${assetSelect}
       WHERE a.enabled = 1
         AND (a.next_scan_at IS NULL OR a.next_scan_at <= ?)
         AND NOT EXISTS (
           SELECT 1 FROM scans s
           WHERE s.asset_id = a.id AND s.status IN ('queued', 'running')
         )
       ORDER BY COALESCE(a.next_scan_at, a.created_at) ASC LIMIT ?`,
    )
    .all(now, limit)
    .map(shapeAsset);
}

export function listScans({ assetId = null, limit = 50 } = {}) {
  const rows = assetId
    ? database
        .prepare(
          `SELECT s.*, a.hostname, a.port
           FROM scans s JOIN assets a ON a.id = s.asset_id
           WHERE s.asset_id = ? ORDER BY s.created_at DESC LIMIT ?`,
        )
        .all(assetId, limit)
    : database
        .prepare(
          `SELECT s.*, a.hostname, a.port
           FROM scans s JOIN assets a ON a.id = s.asset_id
           ORDER BY s.created_at DESC LIMIT ?`,
        )
        .all(limit);
  return rows.map(shapeScan);
}

function incidentPredicate(status, severity = null) {
  if (!['active', 'resolved', 'all'].includes(status)) {
    throw new RangeError('Incident status filtresi geçersiz.');
  }
  if (
    severity &&
    !['critical', 'high', 'medium', 'low', 'info'].includes(severity)
  ) {
    throw new RangeError('Incident önem filtresi geçersiz.');
  }
  const clauses = [];
  const parameters = [];
  if (status === 'active') clauses.push("i.status != 'resolved'");
  if (status === 'resolved') clauses.push("i.status = 'resolved'");
  if (severity) {
    clauses.push('i.severity = ?');
    parameters.push(severity);
  }
  return {
    sql: clauses.length ? `WHERE ${clauses.join(' AND ')}` : '',
    parameters,
  };
}

export function listIncidentsPage({
  status = 'active',
  severity = null,
  limit = 50,
  offset = 0,
} = {}) {
  const predicate = incidentPredicate(status, severity);
  const pageLimit = Math.min(100, Math.max(1, Number(limit) || 50));
  const requestedOffset = Math.max(0, Number(offset) || 0);
  const total = Number(
    database
      .prepare(
        `SELECT COUNT(*) AS count
         FROM incidents i JOIN assets a ON a.id = i.asset_id ${predicate.sql}`,
      )
      .get(...predicate.parameters).count,
  );
  const maximumOffset = total
    ? Math.floor((total - 1) / pageLimit) * pageLimit
    : 0;
  const pageOffset = Math.min(requestedOffset, maximumOffset);
  const rows = database
    .prepare(
      `SELECT i.*, a.hostname, a.port, a.owner
       FROM incidents i JOIN assets a ON a.id = i.asset_id
       ${predicate.sql}
       ORDER BY
         CASE i.severity
           WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
           WHEN 'low' THEN 4 ELSE 5 END,
         i.last_seen_at DESC
       LIMIT ? OFFSET ?`,
    )
    .all(...predicate.parameters, pageLimit, pageOffset);

  const countPredicate = incidentPredicate(status);
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const grouped = database
    .prepare(
      `SELECT i.severity, COUNT(*) AS count
       FROM incidents i JOIN assets a ON a.id = i.asset_id
       ${countPredicate.sql} GROUP BY i.severity`,
    )
    .all(...countPredicate.parameters);
  for (const row of grouped) counts[row.severity] = Number(row.count);

  return {
    incidents: rows.map(shapeIncident),
    total,
    counts,
    limit: pageLimit,
    offset: pageOffset,
  };
}

export function listIncidents({
  status = 'active',
  limit = 100,
  offset = 0,
} = {}) {
  return listIncidentsPage({ status, limit, offset }).incidents;
}

export function getIncident(id) {
  return shapeIncident(
    database
      .prepare(
        `SELECT i.*, a.hostname, a.port, a.owner
         FROM incidents i JOIN assets a ON a.id = i.asset_id WHERE i.id = ?`,
      )
      .get(id),
  );
}

function addIncidentEvent(
  incidentId,
  eventType,
  actor = 'system',
  note = null,
) {
  database
    .prepare(
      `INSERT INTO incident_events (id, incident_id, event_type, actor, note, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .run(
      randomUUID(),
      incidentId,
      eventType,
      actor,
      note,
      new Date().toISOString(),
    );
}

export function reconcileIncidents(assetId, scanId, evaluations, options = {}) {
  const now = new Date().toISOString();
  const failedIdentityKeys = new Set();
  const notificationEvents = [];

  for (const evaluation of evaluations) {
    const discriminator = evaluation.discriminator || 'default';
    const identityKey = `${assetId}:${evaluation.ruleKey}:${discriminator}`;

    if (evaluation.status === 'fail') {
      failedIdentityKeys.add(identityKey);
      const existing = database
        .prepare('SELECT * FROM incidents WHERE identity_key = ?')
        .get(identityKey);

      if (!existing) {
        const incidentId = randomUUID();
        database
          .prepare(
            `INSERT INTO incidents (
              id, identity_key, asset_id, rule_key, severity, status, title,
              description, evidence_json, first_seen_at, last_seen_at,
              occurrence_count, scan_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
          )
          .run(
            incidentId,
            identityKey,
            assetId,
            evaluation.ruleKey,
            evaluation.severity,
            evaluation.title,
            evaluation.description,
            JSON.stringify(evaluation.evidence || {}),
            now,
            now,
            scanId,
            now,
            now,
          );
        addIncidentEvent(incidentId, 'opened');
        notificationEvents.push({
          type: 'opened',
          incident: getIncident(incidentId),
        });
      } else {
        const wasResolved = existing.status === 'resolved';
        const nextStatus = wasResolved ? 'open' : existing.status;
        database
          .prepare(
            `UPDATE incidents SET
              severity = ?, status = ?, title = ?, description = ?, evidence_json = ?,
              last_seen_at = ?, resolved_at = NULL, occurrence_count = occurrence_count + 1,
              scan_id = ?, updated_at = ? WHERE id = ?`,
          )
          .run(
            evaluation.severity,
            nextStatus,
            evaluation.title,
            evaluation.description,
            JSON.stringify(evaluation.evidence || {}),
            now,
            scanId,
            now,
            existing.id,
          );
        if (wasResolved) {
          addIncidentEvent(existing.id, 'reopened');
          notificationEvents.push({
            type: 'reopened',
            incident: getIncident(existing.id),
          });
        }
      }
      continue;
    }

    if (evaluation.status === 'pass') {
      const active = database
        .prepare(
          `SELECT id FROM incidents
           WHERE asset_id = ? AND rule_key = ? AND status != 'resolved'`,
        )
        .all(assetId, evaluation.ruleKey);
      for (const incident of active) {
        database
          .prepare(
            `UPDATE incidents SET status = 'resolved', resolved_at = ?, updated_at = ?
             WHERE id = ?`,
          )
          .run(now, now, incident.id);
        addIncidentEvent(incident.id, 'resolved');
      }
    }
  }

  for (const prefix of options.completePrefixes || []) {
    const active = database
      .prepare(
        `SELECT id, identity_key FROM incidents
         WHERE asset_id = ? AND rule_key LIKE ? AND status != 'resolved'`,
      )
      .all(assetId, `${prefix}%`);
    for (const incident of active) {
      if (failedIdentityKeys.has(incident.identity_key)) continue;
      database
        .prepare(
          `UPDATE incidents SET status = 'resolved', resolved_at = ?, updated_at = ?
           WHERE id = ?`,
        )
        .run(now, now, incident.id);
      addIncidentEvent(incident.id, 'resolved');
    }
  }
  return notificationEvents;
}

export function updateIncidentStatus(
  id,
  status,
  actor = 'local-user',
  note = null,
) {
  const existing = database
    .prepare('SELECT * FROM incidents WHERE id = ?')
    .get(id);
  if (!existing) return null;
  const now = new Date().toISOString();
  const resolvedAt = status === 'resolved' ? now : null;
  database
    .prepare(
      `UPDATE incidents SET status = ?, resolved_at = ?, updated_at = ? WHERE id = ?`,
    )
    .run(status, resolvedAt, now, id);
  addIncidentEvent(id, status, actor, note);
  return shapeIncident(
    database
      .prepare(
        `SELECT i.*, a.hostname, a.port, a.owner
         FROM incidents i JOIN assets a ON a.id = i.asset_id WHERE i.id = ?`,
      )
      .get(id),
  );
}

export function getDashboard() {
  const assets = listAssets();
  const incidents = listIncidents({ status: 'active', limit: 50 });
  const recentScans = listScans({ limit: 25 });
  const counts = database
    .prepare(
      `SELECT
        (SELECT COUNT(*) FROM incidents WHERE status != 'resolved') AS open_incidents,
        (SELECT COUNT(*) FROM incidents WHERE status != 'resolved' AND severity = 'critical') AS critical_incidents,
        (SELECT COUNT(*) FROM scans WHERE status = 'running') AS running_scans,
        (SELECT COUNT(*) FROM scans WHERE status = 'queued') AS queued_scans`,
    )
    .get();
  const now = Date.now();
  const expiringSoon = assets.filter((asset) => {
    if (!asset.certificateExpiresAt) return false;
    const days = (Date.parse(asset.certificateExpiresAt) - now) / 86_400_000;
    return days >= 0 && days <= 30;
  }).length;
  const healthy = assets.filter(
    (asset) =>
      asset.latestStatus === 'succeeded' && asset.openIncidentCount === 0,
  ).length;

  return {
    summary: {
      totalAssets: assets.length,
      openIncidents: Number(counts.open_incidents),
      criticalIncidents: Number(counts.critical_incidents),
      expiringSoon,
      healthyPercentage: assets.length
        ? Math.round((healthy / assets.length) * 100)
        : 0,
      runningScans: Number(counts.running_scans),
      queuedScans: Number(counts.queued_scans),
    },
    assets,
    incidents,
    recentScans,
    generatedAt: new Date().toISOString(),
  };
}

export function closeDatabase() {
  if (databaseClosed) return;
  databaseClosed = true;
  try {
    database.close();
  } finally {
    if (stateLockDatabase) {
      releaseStateLock(stateLockDatabase);
      stateLockDatabase = null;
    }
  }
}
