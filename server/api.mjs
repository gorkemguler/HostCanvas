import { createServer } from 'node:http';
import { createReadStream, statSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { isIP } from 'node:net';
import { randomBytes, timingSafeEqual } from 'node:crypto';

import {
  ALLOW_PRIVATE_TARGETS,
  API_HOST,
  API_PORT,
  APP_NAME,
  APP_VERSION,
  MAX_REQUEST_BYTES,
  PUBLIC_DNS_RESOLVER,
  DNSSEC_RESOLVER,
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
  getCheckPolicy,
  updateCheckPolicy,
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

const SETUP_CODE_TTL_MS = 15 * 60_000;
const LOGIN_WINDOW_MS = 5 * 60_000;
const LOGIN_BLOCK_MS = 5 * 60_000;
const LOGIN_MAX_FAILURES = 5;
const LOGIN_ATTEMPT_LIMIT = 4_096;
const PASSWORD_WORK_LIMIT = 8;
const PASSWORD_WORK_PER_ADDRESS = 4;

let setupCodeState = createSetupCode();
const loginAttempts = new Map();
const passwordWork = new Map();
let activePasswordWork = 0;

function createSetupCode() {
  return {
    value: randomBytes(6).toString('hex').toUpperCase(),
    expiresAt: Date.now() + SETUP_CODE_TTL_MS,
  };
}

function currentSetupCode({ announceRotation = false } = {}) {
  if (setupCodeState.expiresAt <= Date.now()) {
    setupCodeState = createSetupCode();
    if (announceRotation) {
      console.log(`İlk kurulum kodu yenilendi: ${setupCodeState.value}`);
    }
  }
  return setupCodeState.value;
}

export function getSetupCodeForConsole() {
  return getAppSettings().setupCompleted ? null : currentSetupCode();
}

function requestAddress(request) {
  const proxy = trustedProxyContext(request);
  if (proxy) return normalizeRemoteAddress(proxy.address);
  const address = request.socket.remoteAddress || '';
  return normalizeRemoteAddress(address);
}

function isLoopbackRequest(request) {
  const address = requestAddress(request);
  return address === '127.0.0.1' || address === '::1';
}

function isSecureRequest(request) {
  return requestScheme(request) === 'https';
}

function headerValue(request, name) {
  const value = request.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function normalizeRemoteAddress(value) {
  const address = String(value || '').trim();
  return address.startsWith('::ffff:') ? address.slice(7) : address;
}

function trustedProxyContext(request) {
  if (!TRUST_PROXY) return null;
  const forwardedAddress = headerValue(request, 'x-forwarded-for');
  const forwardedScheme = headerValue(request, 'x-forwarded-proto');
  if (forwardedAddress === undefined && forwardedScheme === undefined)
    return null;
  const address = String(forwardedAddress || '').trim();
  const scheme = String(forwardedScheme || '')
    .trim()
    .toLowerCase();
  // A trusted, directly connected proxy must replace these fields, not append
  // a client-controlled chain. Reject partial/malformed context fail-closed.
  if (!isIP(address) || !['http', 'https'].includes(scheme)) {
    throw new ApiError(
      400,
      'Proxy başlıkları geçersiz.',
      'INVALID_PROXY_HEADERS',
    );
  }
  return { address, scheme };
}

function requestScheme(request) {
  if (request.socket.encrypted) return 'https';
  return trustedProxyContext(request)?.scheme || 'http';
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

function parseRequestHost(request) {
  const value = String(headerValue(request, 'host') || '').trim();
  if (!value || value.length > 255 || /[\s/@?#\\]/.test(value)) return null;
  try {
    const parsed = new URL(`http://${value}`);
    if (
      parsed.username ||
      parsed.password ||
      parsed.pathname !== '/' ||
      parsed.search ||
      parsed.hash
    ) {
      return null;
    }
    return {
      authority: parsed.host.toLowerCase(),
      hostname: parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase(),
    };
  } catch {
    return null;
  }
}

function isLoopbackHostname(hostname) {
  return (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname === '::1' ||
    /^127(?:\.\d{1,3}){3}$/.test(hostname)
  );
}

function originHostname(origin) {
  try {
    return new URL(origin).hostname.replace(/^\[|\]$/g, '').toLowerCase();
  } catch {
    return null;
  }
}

function requestOrigin(request, host = parseRequestHost(request)) {
  if (!host) return null;
  try {
    return new URL(`${requestScheme(request)}://${host.authority}`).origin;
  } catch {
    return null;
  }
}

function isSameOriginRequest(request, origin) {
  const normalized = safeOrigin(origin);
  return Boolean(normalized && normalized === requestOrigin(request));
}

function allowedRawHostnames(settings) {
  const hostnames = new Set(
    [...UI_ORIGINS, ...(settings?.allowedOrigins || [])]
      .map(originHostname)
      .filter(Boolean),
  );
  const configuredHost = String(API_HOST || '')
    .replace(/^\[|\]$/g, '')
    .toLowerCase();
  if (configuredHost && !['0.0.0.0', '::'].includes(configuredHost)) {
    hostnames.add(configuredHost);
  }
  return hostnames;
}

function ensureAllowedHost(request, settings) {
  const host = parseRequestHost(request);
  if (!host) {
    throw new ApiError(400, 'Host başlığı geçersiz.', 'INVALID_HOST');
  }
  if (
    isLoopbackHostname(host.hostname) ||
    allowedRawHostnames(settings).has(host.hostname)
  ) {
    return host;
  }
  throw new ApiError(
    421,
    'Raw API isteğinin Host başlığına izin verilmiyor.',
    'HOST_NOT_ALLOWED',
  );
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
      const origin = `https://${host}:3443`;
      if (address.family === 'IPv6') ipv6Origins.push(origin);
      else ipv4Origins.push(origin);
    }
  }
  for (const origin of [...ipv4Origins, ...ipv6Origins]) origins.add(origin);
  return [...origins];
}

function securityHeaders(origin = null) {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Resource-Policy': 'cross-origin',
  };
  const normalizedOrigin = safeOrigin(origin);
  if (normalizedOrigin && originIsAllowed(normalizedOrigin)) {
    headers['Access-Control-Allow-Origin'] = normalizedOrigin;
    headers['Access-Control-Allow-Credentials'] = 'true';
    headers.Vary = 'Origin';
  }
  return headers;
}

function sendJson(response, status, body, origin = null, extraHeaders = {}) {
  response.writeHead(status, {
    ...securityHeaders(origin),
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
  let body;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new ApiError(400, 'JSON gövdesi geçersiz.', 'INVALID_JSON');
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ApiError(
      400,
      'JSON gövdesi bir nesne olmalıdır.',
      'INVALID_JSON',
    );
  }
  return body;
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
  const lanOrigins = allowedOrigins.filter(
    (origin) => !isLoopbackHostname(originHostname(origin)),
  );
  if (lanEnabled && lanOrigins.length === 0) {
    throw new ApiError(
      422,
      'LAN erişimi için bu cihazın LAN panel adresini izinli adreslere ekleyin.',
      'LAN_ORIGIN_REQUIRED',
    );
  }
  if (
    lanEnabled &&
    lanOrigins.some((origin) => new URL(origin).protocol !== 'https:')
  ) {
    throw new ApiError(
      422,
      'LAN erişimi için panel adresi HTTPS kullanmalıdır.',
      'LAN_HTTPS_REQUIRED',
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

function pruneLoginAttempts(now = Date.now()) {
  for (const [key, attempt] of loginAttempts) {
    if (
      attempt.blockedUntil <= now &&
      attempt.windowStarted + LOGIN_WINDOW_MS <= now
    ) {
      loginAttempts.delete(key);
    }
  }
  while (loginAttempts.size > LOGIN_ATTEMPT_LIMIT) {
    const oldest = loginAttempts.keys().next().value;
    if (oldest === undefined) break;
    loginAttempts.delete(oldest);
  }
}

function loginAttemptKeys(request, operation, subject = '') {
  const address = requestAddress(request) || 'unknown';
  const normalizedSubject = String(subject || '-')
    .trim()
    .toLowerCase()
    .slice(0, 64);
  const prefix = `${operation}:${address}`;
  return [`${prefix}:*`, `${prefix}:${normalizedSubject}`];
}

function assertLoginRate(request, operation, subject = '') {
  const now = Date.now();
  pruneLoginAttempts(now);
  const keys = loginAttemptKeys(request, operation, subject);
  if (keys.some((key) => loginAttempts.get(key)?.blockedUntil > now)) {
    throw new ApiError(
      429,
      'Çok fazla başarısız giriş. Birkaç dakika sonra tekrar deneyin.',
      'LOGIN_RATE_LIMITED',
    );
  }
  return keys;
}

function recordLoginFailure(keys) {
  const now = Date.now();
  pruneLoginAttempts(now);
  for (const key of keys) {
    const current = loginAttempts.get(key);
    const reset = !current || current.windowStarted + LOGIN_WINDOW_MS < now;
    const failures = reset ? 1 : current.failures + 1;
    loginAttempts.delete(key);
    loginAttempts.set(key, {
      failures,
      windowStarted: reset ? now : current.windowStarted,
      blockedUntil: failures >= LOGIN_MAX_FAILURES ? now + LOGIN_BLOCK_MS : 0,
    });
  }
  pruneLoginAttempts(now);
}

function clearLoginFailures(keys) {
  for (const key of keys) loginAttempts.delete(key);
}

async function runPasswordWork(request, work) {
  const address = requestAddress(request) || 'unknown';
  const activeForAddress = passwordWork.get(address) || 0;
  if (
    activePasswordWork >= PASSWORD_WORK_LIMIT ||
    activeForAddress >= PASSWORD_WORK_PER_ADDRESS
  ) {
    throw new ApiError(
      429,
      'Çok fazla eşzamanlı giriş denemesi. Biraz sonra tekrar deneyin.',
      'LOGIN_RATE_LIMITED',
    );
  }
  activePasswordWork += 1;
  passwordWork.set(address, activeForAddress + 1);
  try {
    return await work();
  } finally {
    activePasswordWork -= 1;
    const remaining = (passwordWork.get(address) || 1) - 1;
    if (remaining) passwordWork.set(address, remaining);
    else passwordWork.delete(address);
  }
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

function ensureAllowedOrigin(request) {
  const origin = request.headers.origin;
  const normalized = safeOrigin(origin);
  const allowed =
    originIsAllowed(normalized) || isSameOriginRequest(request, normalized);
  if (origin === 'null' || (origin && !allowed)) {
    throw new ApiError(
      403,
      'İstek kaynağına izin verilmiyor.',
      'ORIGIN_DENIED',
    );
  }
  return normalized || null;
}

async function route(request, response) {
  const url = new URL(request.url, 'http://localhost');
  const path = url.pathname.replace(/\/$/, '') || '/';
  const settings = getAppSettings();
  ensureAllowedHost(request, settings);
  const bootstrapRoute = request.method === 'GET' && path === '/api/bootstrap';
  const setupRoute = request.method === 'POST' && path === '/api/setup';
  const liveRoute = request.method === 'GET' && path === '/api/health/live';
  const origin = ensureAllowedOrigin(request);

  if (request.method === 'OPTIONS') {
    response.writeHead(204, {
      ...securityHeaders(origin),
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '600',
    });
    response.end();
    return;
  }

  if (liveRoute) {
    sendJson(
      response,
      200,
      {
        ok: true,
        name: APP_NAME,
        version: APP_VERSION,
        now: new Date().toISOString(),
      },
      origin,
    );
    return;
  }

  if (bootstrapRoute) {
    if (!settings.setupCompleted) currentSetupCode({ announceRotation: true });
    const session = authenticateRequest(request);
    const socketLocal = isLoopbackRequest(request);
    const originAllowed =
      !origin ||
      originIsAllowed(origin) ||
      isSameOriginRequest(request, origin);
    const interfaceMetadataAllowed = socketLocal || session?.role === 'admin';
    const workspaceMetadataAllowed = socketLocal || Boolean(session);
    sendJson(
      response,
      200,
      {
        setupRequired: !settings.setupCompleted,
        setupCodeRequired: !settings.setupCompleted,
        language: settings.language,
        organization: workspaceMetadataAllowed ? settings.organization : '',
        lanEnabled: settings.lanEnabled,
        authEnabled: settings.authEnabled,
        defaultScanProfile: workspaceMetadataAllowed
          ? settings.defaultScanProfile
          : 'native',
        defaultExpiryWarningDays: workspaceMetadataAllowed
          ? settings.defaultExpiryWarningDays
          : 30,
        defaultScanIntervalMinutes: workspaceMetadataAllowed
          ? settings.defaultScanIntervalMinutes
          : 720,
        authenticated: Boolean(session),
        authenticationRequired:
          settings.setupCompleted && (settings.authEnabled || !socketLocal),
        lanAccessBlocked:
          settings.setupCompleted &&
          !socketLocal &&
          (!settings.lanEnabled || !originAllowed || !isSecureRequest(request)),
        originAllowed,
        user: publicUser(session),
        suggestedOrigins: interfaceMetadataAllowed ? suggestedOrigins() : [],
      },
      origin,
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
    if (!isLoopbackRequest(request) && !isSecureRequest(request)) {
      throw new ApiError(
        426,
        'LAN üzerinden ilk kurulum HTTPS kullanmalıdır.',
        'HTTPS_REQUIRED',
      );
    }
    const body = await readJson(request);
    const attemptKeys = assertLoginRate(request, 'setup', body.username);
    const suppliedSetupCode = Buffer.from(
      String(body.setupCode || '').toUpperCase(),
    );
    const expectedSetupCode = Buffer.from(
      currentSetupCode({ announceRotation: true }),
    );
    if (
      suppliedSetupCode.length !== expectedSetupCode.length ||
      !timingSafeEqual(suppliedSetupCode, expectedSetupCode)
    ) {
      recordLoginFailure(attemptKeys);
      throw new ApiError(
        403,
        'Kurulum kodu geçersiz. Sunucu konsolundaki tek kullanımlık kodu girin.',
        'INVALID_SETUP_CODE',
      );
    }
    clearLoginFailures(attemptKeys);
    const username = validateUsername(body.username);
    const password = await runPasswordWork(request, () =>
      hashPassword(body.password),
    );
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
    );
    return;
  }

  const socketLocal = isLoopbackRequest(request);
  if (!settings.setupCompleted) {
    throw new ApiError(428, 'Önce ilk kurulumu tamamlayın.', 'SETUP_REQUIRED');
  }
  if (!socketLocal && !settings.lanEnabled) {
    throw new ApiError(
      403,
      'LAN erişimi bu kurulumda kapalı.',
      'LAN_ACCESS_DISABLED',
    );
  }
  if (!socketLocal && !isSecureRequest(request)) {
    throw new ApiError(
      426,
      'LAN API erişimi HTTPS kullanmalıdır.',
      'HTTPS_REQUIRED',
    );
  }

  if (request.method === 'POST' && path === '/api/session') {
    const body = await readJson(request);
    const username = String(body.username || '')
      .trim()
      .toLowerCase()
      .slice(0, 48);
    const attemptKeys = assertLoginRate(request, 'login', username);
    const user = getUserByUsername(username);
    // Reserve the attempt before expensive asynchronous password verification;
    // parallel invalid requests cannot all pass an empty failure counter.
    recordLoginFailure(attemptKeys);
    const passwordValid = await runPasswordWork(request, () =>
      verifyPassword(body.password, user),
    );
    if (!passwordValid) {
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
    clearLoginFailures(attemptKeys);
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
  const authenticationRequired = settings.authEnabled || !socketLocal;
  if (authenticationRequired && !session) {
    throw new ApiError(
      401,
      'Devam etmek için giriş yapın.',
      'AUTHENTICATION_REQUIRED',
    );
  }
  const effectiveRole =
    session?.role || (!settings.authEnabled && socketLocal ? 'admin' : null);
  const adminOnlyPath =
    path.startsWith('/api/users') ||
    path.startsWith('/api/audit') ||
    path.startsWith('/api/notifications') ||
    path.startsWith('/api/maintenance') ||
    path.startsWith('/api/backups');
  if (
    adminOnlyPath ||
    (['/api/settings', '/api/check-policy'].includes(path) &&
      request.method === 'PATCH')
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

  if (request.method === 'GET' && path === '/api/check-policy') {
    sendJson(
      response,
      200,
      {
        ...getCheckPolicy(),
        dnssecResolver: DNSSEC_RESOLVER,
        publicDnsResolver: PUBLIC_DNS_RESOLVER,
      },
      origin,
    );
    return;
  }
  if (request.method === 'PATCH' && path === '/api/check-policy') {
    const updated = updateCheckPolicy(await readJson(request));
    audit(request, session, {
      action: 'check_policy.updated',
      targetType: 'workspace',
      summary: 'Kontrol politikası güncellendi / Check policy updated.',
      metadata: updated.policy,
    });
    sendJson(response, 200, updated, origin);
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
    sendJson(response, 200, { settings: updated }, origin);
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
        dnssecResolver: DNSSEC_RESOLVER,
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
    const { policy } = getCheckPolicy();
    sendJson(
      response,
      200,
      {
        checks: ruleCatalog.map((rule) => ({
          ...rule,
          enabled:
            rule.requires === 'TLS_SENTINEL_PUBLIC_DNS_RESOLVER'
              ? Boolean(PUBLIC_DNS_RESOLVER)
              : rule.requires === 'TLS_SENTINEL_DNSSEC_RESOLVER'
                ? Boolean(DNSSEC_RESOLVER)
                : rule.key === 'http.cookie_secure_missing'
                  ? policy.cookieSecureRequired
                  : rule.key === 'http.session_cookie_httponly_missing'
                    ? policy.sessionCookieNames.length > 0
                    : rule.key === 'monitor.scan_unhealthy'
                      ? policy.scanHealthEnabled
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
  const pendingRequests = new Set();
  const server = createServer(
    {
      headersTimeout: 15_000,
      requestTimeout: 30_000,
      keepAliveTimeout: 5_000,
      maxHeaderSize: 16 * 1024,
    },
    (request, response) => {
      const pending = route(request, response)
        .catch((error) => {
          const origin = request.headers.origin || null;
          const validationCodes = new Set([
            'INVALID_USERNAME',
            'INVALID_PASSWORD',
            'INVALID_CHECK_POLICY',
          ]);
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
          );
        })
        .finally(() => pendingRequests.delete(pending));
      pendingRequests.add(pending);
    },
  );
  server.waitForRequests = () => Promise.allSettled(pendingRequests);
  return server;
}
