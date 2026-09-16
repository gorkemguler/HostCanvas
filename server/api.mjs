import { createServer } from 'node:http';
import { createReadStream, statSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { randomBytes } from 'node:crypto';

import {
  ALLOW_PRIVATE_TARGETS,
  API_HOST,
  API_PORT,
  APP_NAME,
  APP_VERSION,
  MAX_REQUEST_BYTES,
  PUBLIC_DNS_RESOLVER,
  SUBDOMAIN_DISCOVERY_ENABLED,
  SUBDOMAIN_DISCOVERY_LIMIT,
  TRUST_PROXY,
  UI_ORIGINS,
} from './config.mjs';
import {
  archiveAsset,
  addAuditEvent,
  completeSetup,
  createAsset,
  createDiscoveredAssets,
  createNotificationChannel,
  createUser,
  deleteNotificationChannel,
  getAppSettings,
  getAsset,
  getDashboard,
  getMaintenanceSettings,
  getNotificationChannel,
  getScan,
  listAuditEvents,
  listAssets,
  listIncidentsPage,
  listNotificationChannels,
  listNotificationDeliveries,
  listScans,
  listUsers,
  getUserByUsername,
  updateAppSettings,
  updateAsset,
  updateIncidentStatus,
  updateMaintenanceSettings,
  updateNotificationChannel,
  updateUserAccess,
  updateUserPassword,
} from './db.mjs';
import {
  authenticateRequest,
  clearSessionCookie,
  createAuthenticatedSession,
  destroyRequestSession,
  hashPassword,
  sessionCookie,
  validateUsername,
  verifyPassword,
} from './auth.mjs';
import { decryptSecret, encryptSecret } from './secrets.mjs';
import {
  testNotificationChannel,
  validateWebhookUrl,
} from './notifications.mjs';
import {
  listBackups,
  resolveBackupPath,
  runMaintenance,
} from './maintenance.mjs';
import { queueAllAssets, queueAssetScan, scannerHealth } from './scanner.mjs';
import { ruleCatalog } from './rules/index.mjs';
import {
  normalizeHostname,
  normalizePort,
  TargetValidationError,
} from './security/targets.mjs';
import { discoverSubdomains } from './discovery/crt-name.mjs';

class ApiError extends Error {
  constructor(status, message, code = 'BAD_REQUEST') {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const setupCode = randomBytes(6).toString('hex').toUpperCase();
const loginAttempts = new Map();

export function getSetupCodeForConsole() {
  return getAppSettings().setupCompleted ? null : setupCode;
}

function requestAddress(request) {
  if (TRUST_PROXY) {
    const forwarded = Array.isArray(request.headers['x-forwarded-for'])
      ? request.headers['x-forwarded-for'][0]
      : request.headers['x-forwarded-for'];
    const address = String(forwarded || '')
      .split(',')[0]
      .trim();
    if (address)
      return address.startsWith('::ffff:') ? address.slice(7) : address;
  }
  const address = request.socket.remoteAddress || '';
  return address.startsWith('::ffff:') ? address.slice(7) : address;
}

function isLoopbackRequest(request) {
  const address = requestAddress(request);
  return address === '127.0.0.1' || address === '::1';
}

function isSecureRequest(request) {
  return Boolean(
    request.socket.encrypted ||
    safeOrigin(request.headers.origin)?.startsWith('https://'),
  );
}

function safeOrigin(value) {
  try {
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    if (
      parsed.username ||
      parsed.password ||
      parsed.pathname !== '/' ||
      parsed.search ||
      parsed.hash
    ) {
      return null;
    }
    return parsed.origin;
  } catch {
    return null;
  }
}

function configuredOrigins() {
  return new Set([...UI_ORIGINS, ...(getAppSettings()?.allowedOrigins || [])]);
}

function originIsAllowed(origin) {
  return Boolean(
    origin && safeOrigin(origin) && configuredOrigins().has(safeOrigin(origin)),
  );
}

function normalizeOrigins(value) {
  const source = Array.isArray(value)
    ? value
    : String(value || '').split(/[\s,]+/);
  const origins = [...new Set(source.map(safeOrigin).filter(Boolean))].slice(
    0,
    12,
  );
  if (source.some((origin) => String(origin).trim()) && origins.length === 0) {
    throw new ApiError(
      422,
      'En az bir geçerli http(s) panel adresi girin.',
      'INVALID_ORIGIN',
    );
  }
  return origins;
}

function suggestedOrigins() {
  const origins = new Set(['http://localhost:3000', 'http://127.0.0.1:3000']);
  const ipv4Origins = [];
  const ipv6Origins = [];
  for (const addresses of Object.values(networkInterfaces())) {
    for (const address of addresses || []) {
      if (address.internal) continue;
      if (
        address.family === 'IPv6' &&
        address.address.toLowerCase().startsWith('fe80:')
      ) {
        continue;
      }
      const host =
        address.family === 'IPv6'
          ? `[${address.address.split('%')[0]}]`
          : address.address;
      const origin = `http://${host}:3000`;
      if (address.family === 'IPv6') ipv6Origins.push(origin);
      else ipv4Origins.push(origin);
    }
  }
  for (const origin of [...ipv4Origins, ...ipv6Origins]) origins.add(origin);
  return [...origins];
}

function securityHeaders(origin = null, reflectSafeOrigin = false) {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Resource-Policy': 'cross-origin',
  };
  const normalizedOrigin = safeOrigin(origin);
  if (
    normalizedOrigin &&
    (reflectSafeOrigin || originIsAllowed(normalizedOrigin))
  ) {
    headers['Access-Control-Allow-Origin'] = normalizedOrigin;
    headers['Access-Control-Allow-Credentials'] = 'true';
    headers.Vary = 'Origin';
  }
  return headers;
}

function sendJson(
  response,
  status,
  body,
  origin = null,
  extraHeaders = {},
  reflectSafeOrigin = false,
) {
  response.writeHead(status, {
    ...securityHeaders(origin, reflectSafeOrigin),
    ...extraHeaders,
  });
  response.end(JSON.stringify(body));
}

async function readJson(request) {
  const contentType = request.headers['content-type'] || '';
  if (!contentType.toLowerCase().startsWith('application/json')) {
    throw new ApiError(
      415,
      'Content-Type application/json olmalıdır.',
      'UNSUPPORTED_MEDIA_TYPE',
    );
  }
  let bytes = 0;
  const chunks = [];
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > MAX_REQUEST_BYTES) {
      throw new ApiError(413, 'İstek gövdesi çok büyük.', 'PAYLOAD_TOO_LARGE');
    }
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new ApiError(400, 'JSON gövdesi geçersiz.', 'INVALID_JSON');
  }
}

function text(value, maximum = 120) {
  if (value == null) return '';
  if (typeof value !== 'string')
    throw new ApiError(422, 'Metin alanı geçersiz.', 'VALIDATION_ERROR');
  return value.trim().slice(0, maximum);
}

function integer(value, fallback, minimum, maximum, label) {
  if (value == null || value === '') return fallback;
  const result = Number(value);
  if (!Number.isInteger(result) || result < minimum || result > maximum) {
    throw new ApiError(
      422,
      `${label} ${minimum} ile ${maximum} arasında olmalıdır.`,
      'VALIDATION_ERROR',
    );
  }
  return result;
}

function normalizeTags(value) {
  if (value == null) return [];
  const source = Array.isArray(value) ? value : String(value).split(',');
  return [
    ...new Set(source.map((item) => text(String(item), 32)).filter(Boolean)),
  ].slice(0, 12);
}

function validateProfile(value, fallback = 'native') {
  const profile = value || fallback;
  if (!['native', 'deep'].includes(profile)) {
    throw new ApiError(
      422,
      'Tarama profili native veya deep olmalıdır.',
      'VALIDATION_ERROR',
    );
  }
  return profile;
}

function validateEnvironment(value, fallback = 'production') {
  const environment = value || fallback;
  if (
    !['production', 'staging', 'development', 'other'].includes(environment)
  ) {
    throw new ApiError(422, 'Ortam değeri geçersiz.', 'VALIDATION_ERROR');
  }
  return environment;
}

function assetInput(body, current = null) {
  const defaults = getAppSettings();
  const allowPrivate = body.allowPrivate ?? current?.allowPrivate ?? false;
  if (allowPrivate && !ALLOW_PRIVATE_TARGETS) {
    throw new ApiError(
      422,
      'İç ağ hedefleri sunucu yapılandırmasında kapalı. TLS_SENTINEL_ALLOW_PRIVATE_TARGETS=true ile açıkça etkinleştirin.',
      'PRIVATE_TARGETS_DISABLED',
    );
  }
  return {
    hostname: current?.hostname || normalizeHostname(body.hostname),
    port: current?.port || normalizePort(body.port),
    label:
      text(body.label ?? current?.label, 80) ||
      current?.hostname ||
      body.hostname,
    owner: text(body.owner ?? current?.owner, 80),
    environment: validateEnvironment(body.environment, current?.environment),
    tags:
      body.tags === undefined && current
        ? current.tags
        : normalizeTags(body.tags),
    allowPrivate: Boolean(allowPrivate),
    enabled:
      body.enabled === undefined
        ? (current?.enabled ?? true)
        : Boolean(body.enabled),
    scanProfile: validateProfile(
      body.scanProfile,
      current?.scanProfile || defaults.defaultScanProfile,
    ),
    expiryWarningDays: integer(
      body.expiryWarningDays,
      current?.expiryWarningDays || defaults.defaultExpiryWarningDays,
      1,
      365,
      'Sertifika uyarı eşiği',
    ),
    scanIntervalMinutes: integer(
      body.scanIntervalMinutes,
      current?.scanIntervalMinutes || defaults.defaultScanIntervalMinutes,
      15,
      10080,
      'Tarama aralığı',
    ),
  };
}

function publicUser(session) {
  if (!session) return null;
  return {
    id: session.userId,
    username: session.username,
    displayName: session.displayName,
    role: session.role,
    enabled: session.enabled ?? true,
  };
}

function validateRole(value, fallback = 'viewer') {
  const role = value || fallback;
  if (!['admin', 'operator', 'viewer'].includes(role)) {
    throw new ApiError(422, 'Kullanıcı rolü geçersiz.', 'VALIDATION_ERROR');
  }
  return role;
}

function validateNotificationKind(value, fallback = 'generic') {
  const kind = value || fallback;
  if (!['generic', 'slack'].includes(kind)) {
    throw new ApiError(
      422,
      'Bildirim kanalı türü geçersiz.',
      'VALIDATION_ERROR',
    );
  }
  return kind;
}

function validateSeverity(value, fallback = 'high') {
  const severity = value || fallback;
  if (!['critical', 'high', 'medium', 'low', 'info'].includes(severity)) {
    throw new ApiError(422, 'Önem seviyesi geçersiz.', 'VALIDATION_ERROR');
  }
  return severity;
}

function requireRole(role, allowed) {
  if (!role || !allowed.includes(role)) {
    throw new ApiError(
      403,
      'Bu işlem için yetkiniz bulunmuyor.',
      'INSUFFICIENT_ROLE',
    );
  }
}

function audit(request, session, input) {
  addAuditEvent({
    actorUserId: session?.userId || null,
    actor: session?.username || 'local-admin',
    sourceIp: requestAddress(request) || null,
    ...input,
  });
}

function publicNotificationChannel(channel) {
  let endpoint = 'encrypted';
  try {
    endpoint = new URL(decryptSecret(channel.urlEncrypted)).hostname;
  } catch {
    endpoint = 'unavailable';
  }
  return {
    id: channel.id,
    name: channel.name,
    kind: channel.kind,
    minSeverity: channel.minSeverity,
    enabled: channel.enabled,
    endpoint,
    hasSecret: true,
    createdAt: channel.createdAt,
    updatedAt: channel.updatedAt,
  };
}

function validateLanguage(value, fallback = 'tr') {
  const language = value || fallback;
  if (!['tr', 'en'].includes(language)) {
    throw new ApiError(422, 'Dil seçimi geçersiz.', 'VALIDATION_ERROR');
  }
  return language;
}

function settingsInput(body, current = getAppSettings()) {
  const lanEnabled = Boolean(body.lanEnabled ?? current.lanEnabled);
  const authEnabled = lanEnabled
    ? true
    : Boolean(body.authEnabled ?? current.authEnabled);
  const allowedOrigins =
    body.allowedOrigins === undefined
      ? current.allowedOrigins
      : normalizeOrigins(body.allowedOrigins);
  if (lanEnabled && !allowedOrigins.some((origin) => !UI_ORIGINS.has(origin))) {
    throw new ApiError(
      422,
      'LAN erişimi için bu cihazın LAN panel adresini izinli adreslere ekleyin.',
      'LAN_ORIGIN_REQUIRED',
    );
  }
  return {
    language: validateLanguage(body.language, current.language),
    organization: text(body.organization ?? current.organization, 100),
    lanEnabled,
    authEnabled,
    allowedOrigins,
    sessionTtlHours: integer(
      body.sessionTtlHours,
      current.sessionTtlHours,
      1,
      168,
      'Oturum süresi',
    ),
    defaultScanProfile: validateProfile(
      body.defaultScanProfile,
      current.defaultScanProfile,
    ),
    defaultExpiryWarningDays: integer(
      body.defaultExpiryWarningDays,
      current.defaultExpiryWarningDays,
      1,
      365,
      'Varsayılan sertifika eşiği',
    ),
    defaultScanIntervalMinutes: integer(
      body.defaultScanIntervalMinutes,
      current.defaultScanIntervalMinutes,
      15,
      10080,
      'Varsayılan tarama aralığı',
    ),
  };
}

function assertLoginRate(request) {
  const key = requestAddress(request) || 'unknown';
  const now = Date.now();
  const attempt = loginAttempts.get(key);
  if (attempt?.blockedUntil > now) {
    throw new ApiError(
      429,
      'Çok fazla başarısız giriş. Birkaç dakika sonra tekrar deneyin.',
      'LOGIN_RATE_LIMITED',
    );
  }
  return key;
}

function recordLoginFailure(key) {
  const now = Date.now();
  const current = loginAttempts.get(key);
  const reset = !current || current.windowStarted + 5 * 60_000 < now;
  const failures = reset ? 1 : current.failures + 1;
  loginAttempts.set(key, {
    failures,
    windowStarted: reset ? now : current.windowStarted,
    blockedUntil: failures >= 5 ? now + 5 * 60_000 : 0,
  });
}

function csvCell(value) {
  let string = value == null ? '' : String(value);
  if (/^[=+\-@]/.test(string)) string = `'${string}`;
  return `"${string.replaceAll('"', '""')}"`;
}

function assetCsv(assets) {
  const columns = [
    'hostname',
    'port',
    'label',
    'owner',
    'environment',
    'scanProfile',
    'latestGrade',
    'latestStatus',
    'certificateExpiresAt',
    'lastScanAt',
    'openIncidentCount',
    'source',
    'parentAssetId',
    'firstSeenAt',
  ];
  return [
    columns.join(','),
    ...assets.map((asset) =>
      columns.map((column) => csvCell(asset[column])).join(','),
    ),
  ].join('\n');
}

function ensureAllowedOrigin(request, options = {}) {
  const origin = request.headers.origin;
  const allowed =
    options.allowUnconfigured === true
      ? Boolean(safeOrigin(origin))
      : originIsAllowed(origin);
  if (origin === 'null' || (origin && !allowed)) {
    throw new ApiError(
      403,
      'İstek kaynağına izin verilmiyor.',
      'ORIGIN_DENIED',
    );
  }
  return safeOrigin(origin) || null;
}

async function route(request, response) {
  const url = new URL(request.url, `http://${API_HOST}:${API_PORT}`);
  const path = url.pathname.replace(/\/$/, '') || '/';
  const settings = getAppSettings();
  const bootstrapRoute = request.method === 'GET' && path === '/api/bootstrap';
  const setupRoute = request.method === 'POST' && path === '/api/setup';
  const allowUnconfiguredOrigin =
    bootstrapRoute || (!settings.setupCompleted && setupRoute);
  const origin = ensureAllowedOrigin(request, {
    allowUnconfigured: allowUnconfiguredOrigin,
  });

  if (request.method === 'OPTIONS') {
    const reflectSafeOrigin = !settings.setupCompleted && path === '/api/setup';
    response.writeHead(204, {
      ...securityHeaders(origin, reflectSafeOrigin),
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '600',
    });
    response.end();
    return;
  }

  if (bootstrapRoute) {
    const session = authenticateRequest(request);
    const socketLocal = isLoopbackRequest(request);
    const configuredLocalOrigin = Boolean(origin && UI_ORIGINS.has(origin));
    const localAccess = socketLocal || configuredLocalOrigin;
    const originAllowed = !origin || originIsAllowed(origin);
    sendJson(
      response,
      200,
      {
        setupRequired: !settings.setupCompleted,
        setupCodeRequired: !socketLocal,
        language: settings.language,
        organization: settings.organization,
        lanEnabled: settings.lanEnabled,
        authEnabled: settings.authEnabled,
        defaultScanProfile: settings.defaultScanProfile,
        defaultExpiryWarningDays: settings.defaultExpiryWarningDays,
        defaultScanIntervalMinutes: settings.defaultScanIntervalMinutes,
        authenticated: Boolean(session),
        authenticationRequired:
          settings.setupCompleted && (settings.authEnabled || !socketLocal),
        lanAccessBlocked:
          settings.setupCompleted &&
          !localAccess &&
          (!settings.lanEnabled || !originAllowed),
        originAllowed,
        user: publicUser(session),
        suggestedOrigins: suggestedOrigins(),
      },
      origin,
      {},
      true,
    );
    return;
  }

  if (setupRoute) {
    if (settings.setupCompleted) {
      throw new ApiError(
        409,
        'İlk kurulum daha önce tamamlanmış.',
        'SETUP_ALREADY_COMPLETED',
      );
    }
    const body = await readJson(request);
    if (!isLoopbackRequest(request)) {
      const attemptKey = assertLoginRate(request);
      if (String(body.setupCode || '').toUpperCase() !== setupCode) {
        recordLoginFailure(attemptKey);
        throw new ApiError(
          403,
          'Kurulum kodu geçersiz. Sunucu konsolundaki tek kullanımlık kodu girin.',
          'INVALID_SETUP_CODE',
        );
      }
      loginAttempts.delete(attemptKey);
    }
    const username = validateUsername(body.username);
    const password = await hashPassword(body.password);
    const nextSettings = settingsInput(body, settings);
    const result = completeSetup({
      ...nextSettings,
      username,
      displayName: text(body.displayName, 80) || username,
      ...password,
    });
    const created = createAuthenticatedSession(
      result.user.id,
      result.settings.sessionTtlHours,
    );
    addAuditEvent({
      actorUserId: result.user.id,
      actor: result.user.username,
      action: 'setup.completed',
      targetType: 'workspace',
      summary: 'İlk kurulum tamamlandı.',
      sourceIp: requestAddress(request) || null,
      metadata: {
        lanEnabled: result.settings.lanEnabled,
        authEnabled: result.settings.authEnabled,
      },
    });
    sendJson(
      response,
      201,
      {
        settings: result.settings,
        user: publicUser({ ...result.user, userId: result.user.id }),
      },
      origin,
      {
        'Set-Cookie': sessionCookie(
          created.token,
          result.settings.sessionTtlHours,
          isSecureRequest(request),
        ),
      },
      true,
    );
    return;
  }

  const configuredLocalOrigin = Boolean(origin && UI_ORIGINS.has(origin));
  const logicalLocal = isLoopbackRequest(request) || configuredLocalOrigin;
  if (!settings.setupCompleted) {
    throw new ApiError(428, 'Önce ilk kurulumu tamamlayın.', 'SETUP_REQUIRED');
  }
  if (!logicalLocal && !settings.lanEnabled) {
    throw new ApiError(
      403,
      'LAN erişimi bu kurulumda kapalı.',
      'LAN_ACCESS_DISABLED',
    );
  }

  if (request.method === 'POST' && path === '/api/session') {
    const attemptKey = assertLoginRate(request);
    const body = await readJson(request);
    const username = String(body.username || '')
      .trim()
      .toLowerCase()
      .slice(0, 48);
    const user = getUserByUsername(username);
    const passwordValid = await verifyPassword(body.password, user);
    if (!passwordValid) {
      recordLoginFailure(attemptKey);
      addAuditEvent({
        actor: username || 'unknown',
        action: 'auth.login_failed',
        targetType: 'session',
        summary: 'Başarısız giriş denemesi.',
        sourceIp: requestAddress(request) || null,
      });
      throw new ApiError(
        401,
        'Kullanıcı adı veya parola hatalı.',
        'INVALID_CREDENTIALS',
      );
    }
    loginAttempts.delete(attemptKey);
    const created = createAuthenticatedSession(
      user.id,
      settings.sessionTtlHours,
    );
    addAuditEvent({
      actorUserId: user.id,
      actor: user.username,
      action: 'auth.login',
      targetType: 'session',
      summary: 'Kullanıcı giriş yaptı.',
      sourceIp: requestAddress(request) || null,
    });
    sendJson(
      response,
      200,
      {
        user: publicUser({ ...user, userId: user.id }),
        expiresAt: created.expiresAt,
      },
      origin,
      {
        'Set-Cookie': sessionCookie(
          created.token,
          settings.sessionTtlHours,
          isSecureRequest(request),
        ),
      },
    );
    return;
  }

  if (request.method === 'DELETE' && path === '/api/session') {
    const logoutSession = authenticateRequest(request);
    if (logoutSession) {
      audit(request, logoutSession, {
        action: 'auth.logout',
        targetType: 'session',
        summary: 'Kullanıcı çıkış yaptı.',
      });
    }
    destroyRequestSession(request);
    sendJson(response, 200, { ok: true }, origin, {
      'Set-Cookie': clearSessionCookie(isSecureRequest(request)),
    });
    return;
  }

  const session = authenticateRequest(request);
  const authenticationRequired =
    settings.authEnabled || !isLoopbackRequest(request);
  if (authenticationRequired && !session) {
    throw new ApiError(
      401,
      'Devam etmek için giriş yapın.',
      'AUTHENTICATION_REQUIRED',
    );
  }
  const effectiveRole =
    session?.role ||
    (!settings.authEnabled && isLoopbackRequest(request) ? 'admin' : null);
  const adminOnlyPath =
    path.startsWith('/api/users') ||
    path.startsWith('/api/audit') ||
    path.startsWith('/api/notifications') ||
    path.startsWith('/api/maintenance') ||
    path.startsWith('/api/backups');
  if (
    adminOnlyPath ||
    (path === '/api/settings' && request.method === 'PATCH')
  ) {
    requireRole(effectiveRole, ['admin']);
  }
  const operationalMutation =
    !['GET', 'HEAD', 'OPTIONS'].includes(request.method) &&
    (path === '/api/scan-all' ||
      path.startsWith('/api/assets') ||
      path.startsWith('/api/incidents'));
  if (operationalMutation) requireRole(effectiveRole, ['admin', 'operator']);

  if (request.method === 'GET' && path === '/api/settings') {
    sendJson(
      response,
      200,
      {
        settings,
        user: publicUser(session),
        suggestedOrigins: suggestedOrigins(),
      },
      origin,
    );
    return;
  }

  if (request.method === 'PATCH' && path === '/api/settings') {
    const body = await readJson(request);
    const updated = updateAppSettings(settingsInput(body, settings));
    audit(request, session, {
      action: 'settings.updated',
      targetType: 'workspace',
      summary: 'Çalışma alanı ayarları güncellendi.',
      metadata: {
        lanEnabled: updated.lanEnabled,
        authEnabled: updated.authEnabled,
        language: updated.language,
      },
    });
    sendJson(response, 200, { settings: updated }, origin, {}, true);
    return;
  }

  if (request.method === 'POST' && path === '/api/account/password') {
    const body = await readJson(request);
    const username = session?.username || validateUsername(body.username);
    const user = getUserByUsername(username);
    if (!(await verifyPassword(body.currentPassword, user))) {
      throw new ApiError(
        401,
        'Mevcut parola hatalı.',
        'INVALID_CURRENT_PASSWORD',
      );
    }
    const password = await hashPassword(body.newPassword);
    updateUserPassword(user.id, password.passwordHash, password.passwordSalt);
    const created = createAuthenticatedSession(
      user.id,
      settings.sessionTtlHours,
    );
    audit(
      request,
      { ...user, userId: user.id },
      {
        action: 'account.password_changed',
        targetType: 'user',
        targetId: user.id,
        summary: 'Kullanıcı kendi parolasını değiştirdi.',
      },
    );
    sendJson(response, 200, { ok: true }, origin, {
      'Set-Cookie': sessionCookie(
        created.token,
        settings.sessionTtlHours,
        isSecureRequest(request),
      ),
    });
    return;
  }

  if (request.method === 'GET' && path === '/api/users') {
    sendJson(
      response,
      200,
      {
        users: listUsers().map((user) =>
          publicUser({ ...user, userId: user.id }),
        ),
      },
      origin,
    );
    return;
  }

  if (request.method === 'POST' && path === '/api/users') {
    const body = await readJson(request);
    const username = validateUsername(body.username);
    const password = await hashPassword(body.password);
    let user;
    try {
      user = createUser({
        username,
        displayName: text(body.displayName, 80) || username,
        role: validateRole(body.role),
        ...password,
      });
    } catch (error) {
      if (String(error.code).includes('SQLITE_CONSTRAINT')) {
        throw new ApiError(
          409,
          'Bu kullanıcı adı zaten kullanılıyor.',
          'USER_EXISTS',
        );
      }
      throw error;
    }
    audit(request, session, {
      action: 'user.created',
      targetType: 'user',
      targetId: user.id,
      summary: `${user.username} hesabı oluşturuldu.`,
      metadata: { role: user.role },
    });
    sendJson(
      response,
      201,
      { user: publicUser({ ...user, userId: user.id }) },
      origin,
    );
    return;
  }

  const userPasswordMatch = path.match(
    /^\/api\/users\/([a-f0-9-]+)\/password$/i,
  );
  if (userPasswordMatch && request.method === 'POST') {
    const body = await readJson(request);
    const password = await hashPassword(body.password);
    const user = updateUserPassword(
      userPasswordMatch[1],
      password.passwordHash,
      password.passwordSalt,
    );
    if (!user)
      throw new ApiError(404, 'Kullanıcı bulunamadı.', 'USER_NOT_FOUND');
    audit(request, session, {
      action: 'user.password_reset',
      targetType: 'user',
      targetId: user.id,
      summary: `${user.username} hesabının parolası yönetici tarafından sıfırlandı.`,
    });
    sendJson(
      response,
      200,
      { user: publicUser({ ...user, userId: user.id }) },
      origin,
    );
    return;
  }

  const userMatch = path.match(/^\/api\/users\/([a-f0-9-]+)$/i);
  if (userMatch && request.method === 'PATCH') {
    const body = await readJson(request);
    let user;
    try {
      user = updateUserAccess(userMatch[1], {
        displayName:
          body.displayName === undefined
            ? undefined
            : text(body.displayName, 80),
        role: body.role === undefined ? undefined : validateRole(body.role),
        enabled: body.enabled === undefined ? undefined : Boolean(body.enabled),
      });
    } catch (error) {
      if (error.code === 'LAST_ADMIN_REQUIRED') {
        throw new ApiError(409, error.message, error.code);
      }
      throw error;
    }
    if (!user)
      throw new ApiError(404, 'Kullanıcı bulunamadı.', 'USER_NOT_FOUND');
    audit(request, session, {
      action: 'user.updated',
      targetType: 'user',
      targetId: user.id,
      summary: `${user.username} hesabı güncellendi.`,
      metadata: { role: user.role, enabled: user.enabled },
    });
    sendJson(
      response,
      200,
      { user: publicUser({ ...user, userId: user.id }) },
      origin,
    );
    return;
  }

  if (request.method === 'GET' && path === '/api/audit') {
    const limit = integer(
      url.searchParams.get('limit'),
      100,
      1,
      200,
      'Audit sayfa boyutu',
    );
    const offset = integer(
      url.searchParams.get('offset'),
      0,
      0,
      1_000_000,
      'Audit sayfa başlangıcı',
    );
    sendJson(response, 200, listAuditEvents({ limit, offset }), origin);
    return;
  }

  if (request.method === 'GET' && path === '/api/notifications/channels') {
    sendJson(
      response,
      200,
      {
        channels: listNotificationChannels().map(publicNotificationChannel),
        deliveries: listNotificationDeliveries(30),
      },
      origin,
    );
    return;
  }

  if (request.method === 'POST' && path === '/api/notifications/channels') {
    const body = await readJson(request);
    const webhookUrl = validateWebhookUrl(body.webhookUrl);
    const channel = createNotificationChannel({
      name: text(body.name, 80) || 'Webhook',
      kind: validateNotificationKind(body.kind),
      minSeverity: validateSeverity(body.minSeverity),
      urlEncrypted: encryptSecret(webhookUrl),
    });
    audit(request, session, {
      action: 'notification_channel.created',
      targetType: 'notification_channel',
      targetId: channel.id,
      summary: `${channel.name} bildirim kanalı oluşturuldu.`,
      metadata: { kind: channel.kind, minSeverity: channel.minSeverity },
    });
    sendJson(
      response,
      201,
      { channel: publicNotificationChannel(channel) },
      origin,
    );
    return;
  }

  const notificationTestMatch = path.match(
    /^\/api\/notifications\/channels\/([a-f0-9-]+)\/test$/i,
  );
  if (notificationTestMatch && request.method === 'POST') {
    const channel = getNotificationChannel(notificationTestMatch[1]);
    if (!channel)
      throw new ApiError(
        404,
        'Bildirim kanalı bulunamadı.',
        'CHANNEL_NOT_FOUND',
      );
    const result = await testNotificationChannel(channel.id);
    audit(request, session, {
      action: 'notification_channel.tested',
      targetType: 'notification_channel',
      targetId: channel.id,
      summary: `${channel.name} bildirim kanalı test edildi.`,
      metadata: { ok: result.ok },
    });
    sendJson(response, result.ok ? 200 : 502, { result }, origin);
    return;
  }

  const notificationMatch = path.match(
    /^\/api\/notifications\/channels\/([a-f0-9-]+)$/i,
  );
  if (notificationMatch && request.method === 'PATCH') {
    const current = getNotificationChannel(notificationMatch[1]);
    if (!current)
      throw new ApiError(
        404,
        'Bildirim kanalı bulunamadı.',
        'CHANNEL_NOT_FOUND',
      );
    const body = await readJson(request);
    const channel = updateNotificationChannel(current.id, {
      name: body.name === undefined ? undefined : text(body.name, 80),
      kind:
        body.kind === undefined
          ? undefined
          : validateNotificationKind(body.kind),
      minSeverity:
        body.minSeverity === undefined
          ? undefined
          : validateSeverity(body.minSeverity),
      enabled: body.enabled === undefined ? undefined : Boolean(body.enabled),
      urlEncrypted: body.webhookUrl
        ? encryptSecret(validateWebhookUrl(body.webhookUrl))
        : undefined,
    });
    audit(request, session, {
      action: 'notification_channel.updated',
      targetType: 'notification_channel',
      targetId: channel.id,
      summary: `${channel.name} bildirim kanalı güncellendi.`,
      metadata: { enabled: channel.enabled, minSeverity: channel.minSeverity },
    });
    sendJson(
      response,
      200,
      { channel: publicNotificationChannel(channel) },
      origin,
    );
    return;
  }
  if (notificationMatch && request.method === 'DELETE') {
    const current = getNotificationChannel(notificationMatch[1]);
    if (!current)
      throw new ApiError(
        404,
        'Bildirim kanalı bulunamadı.',
        'CHANNEL_NOT_FOUND',
      );
    deleteNotificationChannel(current.id);
    audit(request, session, {
      action: 'notification_channel.deleted',
      targetType: 'notification_channel',
      targetId: current.id,
      summary: `${current.name} bildirim kanalı silindi.`,
    });
    sendJson(response, 200, { ok: true }, origin);
    return;
  }

  if (request.method === 'GET' && path === '/api/maintenance') {
    sendJson(
      response,
      200,
      {
        settings: getMaintenanceSettings(),
        backups: await listBackups(),
      },
      origin,
    );
    return;
  }

  if (request.method === 'PATCH' && path === '/api/maintenance') {
    const body = await readJson(request);
    const maintenance = updateMaintenanceSettings({
      scanRetentionDays: integer(
        body.scanRetentionDays,
        undefined,
        7,
        3650,
        'Tarama saklama süresi',
      ),
      artifactRetentionDays: integer(
        body.artifactRetentionDays,
        undefined,
        1,
        3650,
        'Artifact saklama süresi',
      ),
      backupRetentionCount: integer(
        body.backupRetentionCount,
        undefined,
        1,
        100,
        'Yedek sayısı',
      ),
      backupIntervalHours: integer(
        body.backupIntervalHours,
        undefined,
        1,
        168,
        'Yedekleme aralığı',
      ),
    });
    audit(request, session, {
      action: 'maintenance.settings_updated',
      targetType: 'workspace',
      summary: 'Veri saklama ve yedekleme ayarları güncellendi.',
      metadata: maintenance,
    });
    sendJson(response, 200, { settings: maintenance }, origin);
    return;
  }

  if (request.method === 'POST' && path === '/api/maintenance/run') {
    const result = await runMaintenance();
    audit(request, session, {
      action: 'maintenance.executed',
      targetType: 'workspace',
      summary: 'Bakım işi manuel olarak çalıştırıldı.',
      metadata: result,
    });
    sendJson(response, 200, { result, backups: await listBackups() }, origin);
    return;
  }

  if (request.method === 'POST' && path === '/api/backups') {
    const result = await runMaintenance({ forceBackup: true });
    audit(request, session, {
      action: 'backup.created',
      targetType: 'backup',
      targetId: result.createdBackup?.name,
      summary: 'Manuel veritabanı yedeği oluşturuldu.',
      metadata: result.createdBackup || {},
    });
    sendJson(
      response,
      201,
      { backup: result.createdBackup, backups: await listBackups() },
      origin,
    );
    return;
  }

  const backupDownloadMatch = path.match(
    /^\/api\/backups\/(tlsentinel-\d{8}T\d{6}(?:\.\d{3})?Z\.db)$/,
  );
  if (backupDownloadMatch && request.method === 'GET') {
    const backupPath = resolveBackupPath(backupDownloadMatch[1]);
    let details;
    try {
      details = statSync(backupPath);
    } catch {
      throw new ApiError(404, 'Yedek bulunamadı.', 'BACKUP_NOT_FOUND');
    }
    response.writeHead(200, {
      ...securityHeaders(origin),
      'Content-Type': 'application/vnd.sqlite3',
      'Content-Length': details.size,
      'Content-Disposition': `attachment; filename="${backupDownloadMatch[1]}"`,
    });
    createReadStream(backupPath).pipe(response);
    return;
  }

  if (request.method === 'GET' && path === '/api/health') {
    sendJson(
      response,
      200,
      {
        ok: true,
        name: APP_NAME,
        version: APP_VERSION,
        bind: `${API_HOST}:${API_PORT}`,
        privateTargetsAllowed: ALLOW_PRIVATE_TARGETS,
        publicDnsResolver: PUBLIC_DNS_RESOLVER,
        subdomainDiscovery: {
          enabled: SUBDOMAIN_DISCOVERY_ENABLED,
          provider: 'crt.name',
          limit: SUBDOMAIN_DISCOVERY_LIMIT,
        },
        engines: await scannerHealth(),
        now: new Date().toISOString(),
      },
      origin,
    );
    return;
  }

  if (request.method === 'GET' && path === '/api/dashboard') {
    sendJson(response, 200, getDashboard(), origin);
    return;
  }

  if (request.method === 'GET' && path === '/api/assets') {
    sendJson(
      response,
      200,
      {
        assets: listAssets({
          includeDisabled: url.searchParams.get('all') === '1',
        }),
      },
      origin,
    );
    return;
  }

  if (request.method === 'POST' && path === '/api/assets') {
    const body = await readJson(request);
    if (body.authorized !== true) {
      throw new ApiError(
        422,
        'Bu hedefi tarama yetkiniz olduğunu onaylamalısınız.',
        'AUTHORIZATION_REQUIRED',
      );
    }
    let asset;
    try {
      asset = createAsset(assetInput(body));
    } catch (error) {
      if (String(error.code).includes('SQLITE_CONSTRAINT')) {
        throw new ApiError(
          409,
          'Bu domain ve port zaten envanterde.',
          'ASSET_EXISTS',
        );
      }
      throw error;
    }
    const queued =
      body.scanNow === false
        ? null
        : queueAssetScan(asset.id, { trigger: 'initial' }).scan;
    const discovery = {
      requested: body.discoverSubdomains === true,
      provider: 'crt.name',
      status: 'skipped',
      totalFound: 0,
      createdCount: 0,
      existingCount: 0,
      truncated: false,
      error: null,
    };
    if (discovery.requested && !SUBDOMAIN_DISCOVERY_ENABLED) {
      discovery.status = 'disabled';
      discovery.error = 'Subdomain keşfi sunucu yapılandırmasında kapalı.';
    } else if (discovery.requested) {
      try {
        const found = await discoverSubdomains(asset.hostname);
        const created = createDiscoveredAssets(asset.id, found.records);
        discovery.status = 'completed';
        discovery.totalFound = found.totalFound;
        discovery.createdCount = created?.createdCount || 0;
        discovery.existingCount = created?.existingCount || 0;
        discovery.truncated = found.truncated;
      } catch (error) {
        discovery.status = 'failed';
        discovery.error = String(
          error.message || 'Subdomain keşfi başarısız oldu.',
        ).slice(0, 300);
      }
    }
    audit(request, session, {
      action: 'asset.created',
      targetType: 'asset',
      targetId: asset.id,
      summary: `${asset.hostname}:${asset.port} envantere eklendi.`,
      metadata: {
        profile: asset.scanProfile,
        environment: asset.environment,
        discovery: {
          requested: discovery.requested,
          provider: discovery.provider,
          status: discovery.status,
          totalFound: discovery.totalFound,
          createdCount: discovery.createdCount,
          existingCount: discovery.existingCount,
          truncated: discovery.truncated,
        },
      },
    });
    sendJson(response, 201, { asset, scan: queued, discovery }, origin);
    return;
  }

  const assetMatch = path.match(/^\/api\/assets\/([a-f0-9-]+)$/i);
  if (assetMatch && request.method === 'PATCH') {
    const current = getAsset(assetMatch[1]);
    if (!current)
      throw new ApiError(404, 'Varlık bulunamadı.', 'ASSET_NOT_FOUND');
    const body = await readJson(request);
    const asset = updateAsset(current.id, assetInput(body, current));
    audit(request, session, {
      action: 'asset.updated',
      targetType: 'asset',
      targetId: asset.id,
      summary: `${asset.hostname}:${asset.port} ayarları güncellendi.`,
    });
    sendJson(response, 200, { asset }, origin);
    return;
  }
  if (assetMatch && request.method === 'DELETE') {
    const asset = archiveAsset(assetMatch[1]);
    if (!asset)
      throw new ApiError(404, 'Varlık bulunamadı.', 'ASSET_NOT_FOUND');
    audit(request, session, {
      action: 'asset.archived',
      targetType: 'asset',
      targetId: asset.id,
      summary: `${asset.hostname}:${asset.port} arşivlendi.`,
    });
    sendJson(response, 200, { asset }, origin);
    return;
  }

  const scanAssetMatch = path.match(/^\/api\/assets\/([a-f0-9-]+)\/scan$/i);
  if (scanAssetMatch && request.method === 'POST') {
    const body = await readJson(request);
    const result = queueAssetScan(scanAssetMatch[1], {
      profile: body.profile ? validateProfile(body.profile) : undefined,
      trigger: 'manual',
    });
    audit(request, session, {
      action: 'scan.queued',
      targetType: 'asset',
      targetId: scanAssetMatch[1],
      summary: 'Manuel tarama kuyruğa alındı.',
      metadata: { profile: result.scan.profile, created: result.created },
    });
    sendJson(response, result.created ? 202 : 200, result, origin);
    return;
  }

  const historyMatch = path.match(/^\/api\/assets\/([a-f0-9-]+)\/scans$/i);
  if (historyMatch && request.method === 'GET') {
    if (!getAsset(historyMatch[1])) {
      throw new ApiError(404, 'Varlık bulunamadı.', 'ASSET_NOT_FOUND');
    }
    sendJson(
      response,
      200,
      { scans: listScans({ assetId: historyMatch[1], limit: 100 }) },
      origin,
    );
    return;
  }

  if (request.method === 'POST' && path === '/api/scan-all') {
    const body = await readJson(request);
    const profile = body.profile ? validateProfile(body.profile) : undefined;
    const queued = queueAllAssets({ profile, trigger: 'manual' });
    audit(request, session, {
      action: 'scan.all_queued',
      targetType: 'workspace',
      summary: 'Tüm etkin varlıklar için tarama istendi.',
      metadata: {
        queued: queued.filter((item) => item.created).length,
        profile: profile || 'asset-default',
      },
    });
    sendJson(
      response,
      202,
      {
        queued: queued.filter((item) => item.created).length,
        existing: queued.filter((item) => !item.created).length,
        scans: queued.map((item) => item.scan),
      },
      origin,
    );
    return;
  }

  const scanMatch = path.match(/^\/api\/scans\/([a-f0-9-]+)$/i);
  if (scanMatch && request.method === 'GET') {
    const scan = getScan(scanMatch[1]);
    if (!scan) throw new ApiError(404, 'Tarama bulunamadı.', 'SCAN_NOT_FOUND');
    sendJson(response, 200, { scan }, origin);
    return;
  }

  if (request.method === 'GET' && path === '/api/scans') {
    sendJson(response, 200, { scans: listScans({ limit: 100 }) }, origin);
    return;
  }

  if (request.method === 'GET' && path === '/api/incidents') {
    const status = url.searchParams.get('status') || 'active';
    if (!['active', 'resolved', 'all'].includes(status)) {
      throw new ApiError(
        422,
        'Incident filtresi geçersiz.',
        'VALIDATION_ERROR',
      );
    }
    const severity = url.searchParams.get('severity');
    if (
      severity &&
      !['critical', 'high', 'medium', 'low', 'info'].includes(severity)
    ) {
      throw new ApiError(
        422,
        'Incident önem filtresi geçersiz.',
        'VALIDATION_ERROR',
      );
    }
    const limit = integer(
      url.searchParams.get('limit'),
      50,
      1,
      100,
      'Sayfa boyutu',
    );
    const offset = integer(
      url.searchParams.get('offset'),
      0,
      0,
      1_000_000,
      'Sayfa başlangıcı',
    );
    sendJson(
      response,
      200,
      listIncidentsPage({ status, severity, limit, offset }),
      origin,
    );
    return;
  }

  const incidentMatch = path.match(/^\/api\/incidents\/([a-f0-9-]+)$/i);
  if (incidentMatch && request.method === 'PATCH') {
    const body = await readJson(request);
    if (!['open', 'acknowledged', 'resolved'].includes(body.status)) {
      throw new ApiError(422, 'Incident durumu geçersiz.', 'VALIDATION_ERROR');
    }
    const incident = updateIncidentStatus(
      incidentMatch[1],
      body.status,
      session?.username || 'local-user',
      text(body.note, 500) || null,
    );
    if (!incident)
      throw new ApiError(404, 'Incident bulunamadı.', 'INCIDENT_NOT_FOUND');
    audit(request, session, {
      action: `incident.${body.status}`,
      targetType: 'incident',
      targetId: incident.id,
      summary: `${incident.title} durumu ${body.status} olarak değiştirildi.`,
    });
    sendJson(response, 200, { incident }, origin);
    return;
  }

  if (request.method === 'GET' && path === '/api/checks') {
    sendJson(
      response,
      200,
      {
        checks: ruleCatalog.map((rule) => ({
          ...rule,
          enabled:
            rule.requires === 'TLS_SENTINEL_PUBLIC_DNS_RESOLVER'
              ? Boolean(PUBLIC_DNS_RESOLVER)
              : rule.enabled,
        })),
      },
      origin,
    );
    return;
  }

  if (request.method === 'GET' && path === '/api/export/assets.csv') {
    response.writeHead(200, {
      ...securityHeaders(origin),
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="host-canvas-assets.csv"',
    });
    response.end(`\ufeff${assetCsv(listAssets({ includeDisabled: true }))}`);
    return;
  }

  throw new ApiError(404, 'Endpoint bulunamadı.', 'NOT_FOUND');
}

export function createApiServer() {
  return createServer((request, response) => {
    route(request, response).catch((error) => {
      const origin = request.headers.origin || null;
      const validationCodes = new Set(['INVALID_USERNAME', 'INVALID_PASSWORD']);
      const known =
        error instanceof ApiError ||
        error instanceof TargetValidationError ||
        validationCodes.has(error.code);
      const status =
        error.status ||
        (error instanceof TargetValidationError ||
        validationCodes.has(error.code)
          ? 422
          : 500);
      if (!known) console.error('[api]', error);
      sendJson(
        response,
        status,
        {
          error: {
            code: error.code || 'INTERNAL_ERROR',
            message: known
              ? error.message
              : 'Beklenmeyen bir sunucu hatası oluştu.',
          },
        },
        origin,
        {},
        !getAppSettings().setupCompleted,
      );
    });
  });
}
