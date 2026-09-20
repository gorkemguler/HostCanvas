import https from 'node:https';
import { setTimeout as delay } from 'node:timers/promises';

import { APP_NAME, APP_VERSION } from './config.mjs';

import {
  addNotificationDelivery,
  getNotificationChannel,
  listNotificationChannels,
} from './db.mjs';
import { decryptSecret } from './secrets.mjs';
import {
  normalizeHostname,
  resolveAndValidateTarget,
} from './security/targets.mjs';

const severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const WEBHOOK_DEADLINE_MS = 8_000;
const WEBHOOK_MAX_RESPONSE_BYTES = 64 * 1024;
const WEBHOOK_MAX_ATTEMPTS = 3;
const WEBHOOK_RETRY_BASE_MS = 250;
const WEBHOOK_RETRY_MAX_MS = 2_000;
const WEBHOOK_MAX_CONCURRENCY = 4;
const WEBHOOK_MAX_PENDING = 256;
let activeDeliveries = 0;
const pendingDeliveries = [];
let shutdownController = new AbortController();

export function startNotificationDeliveries() {
  if (shutdownController.signal.aborted)
    shutdownController = new AbortController();
}

export function stopNotificationDeliveries() {
  shutdownController.abort(
    webhookError('Webhook teslimatı durduruldu.', 'WEBHOOK_STOPPED'),
  );
  while (pendingDeliveries.length)
    pendingDeliveries.shift().reject(shutdownController.signal.reason);
}

async function withDeliverySlot(callback) {
  if (shutdownController.signal.aborted) throw shutdownController.signal.reason;
  if (activeDeliveries >= WEBHOOK_MAX_CONCURRENCY) {
    if (pendingDeliveries.length >= WEBHOOK_MAX_PENDING) {
      throw webhookError('Webhook bekleme kuyruğu dolu.', 'WEBHOOK_QUEUE_FULL');
    }
    await new Promise((resolve, reject) =>
      pendingDeliveries.push({ resolve, reject }),
    );
  } else {
    activeDeliveries += 1;
  }
  try {
    if (shutdownController.signal.aborted)
      throw shutdownController.signal.reason;
    return await callback();
  } finally {
    const next = pendingDeliveries.shift();
    if (next) next.resolve();
    else activeDeliveries -= 1;
  }
}

export function validateWebhookUrl(value) {
  let url;
  try {
    url = new URL(String(value || '').trim());
  } catch {
    const error = new Error('Webhook adresi geçersiz.');
    error.code = 'INVALID_WEBHOOK_URL';
    throw error;
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    (url.port && url.port !== '443')
  ) {
    const error = new Error(
      'Webhook yalnızca kullanıcı bilgisi içermeyen HTTPS/443 adresi olabilir.',
    );
    error.code = 'INVALID_WEBHOOK_URL';
    throw error;
  }
  normalizeHostname(url.hostname);
  url.hash = '';
  return url.toString();
}

function webhookError(message, code, details = {}) {
  return Object.assign(new Error(message), { code, ...details });
}

export function requestWebhook(url, address, family, body, options = {}) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(body));
    const deadlineMs = Math.max(
      1,
      Number(options.deadlineMs) || WEBHOOK_DEADLINE_MS,
    );
    const maximumResponseBytes = Math.max(
      0,
      Number(options.maximumResponseBytes) || WEBHOOK_MAX_RESPONSE_BYTES,
    );
    const requestImpl = options.requestImpl || https.request;
    let request;
    let response;
    let responseEnded = false;
    let settled = false;

    const finish = (error, status = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      options.signal?.removeEventListener('abort', onAbort);
      if (error) reject(error);
      else resolve(status);
    };
    const abort = (error) => {
      if (settled) return;
      finish(error);
      response?.destroy();
      request?.destroy();
    };
    const onAbort = () => abort(options.signal.reason);
    const deadline = setTimeout(
      () =>
        abort(
          webhookError(
            'Webhook toplam süre sınırını aştı.',
            'WEBHOOK_DEADLINE_EXCEEDED',
          ),
        ),
      deadlineMs,
    );

    if (options.signal?.aborted) {
      abort(options.signal.reason);
      return;
    }
    options.signal?.addEventListener('abort', onAbort, { once: true });

    try {
      request = requestImpl(
        {
          protocol: 'https:',
          hostname: url.hostname,
          servername: url.hostname,
          port: 443,
          path: `${url.pathname}${url.search}`,
          method: 'POST',
          lookup: (_hostname, _options, callback) =>
            callback(null, address, family),
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': payload.length,
            'User-Agent': `${APP_NAME}/${APP_VERSION}`,
          },
          rejectUnauthorized: true,
        },
        (incoming) => {
          response = incoming;
          if (settled) {
            response.on('error', () => undefined);
            response.destroy();
            return;
          }
          let responseBytes = 0;
          response.on('data', (chunk) => {
            responseBytes += chunk.length;
            if (responseBytes > maximumResponseBytes) {
              abort(
                webhookError(
                  'Webhook yanıtı güvenli boyut sınırını aştı.',
                  'WEBHOOK_RESPONSE_TOO_LARGE',
                ),
              );
            }
          });
          response.once('aborted', () =>
            abort(
              webhookError(
                'Webhook yanıtı tamamlanmadan kesildi.',
                'WEBHOOK_RESPONSE_ABORTED',
              ),
            ),
          );
          response.once('error', (error) =>
            abort(
              webhookError(
                `Webhook yanıtı okunamadı: ${error.message}`,
                error.code || 'WEBHOOK_RESPONSE_ERROR',
              ),
            ),
          );
          response.once('end', () => {
            responseEnded = true;
            const status = response.statusCode || 0;
            if (status >= 200 && status < 300) finish(null, status);
            else
              finish(
                webhookError(
                  `Webhook HTTP ${status} döndürdü.`,
                  'WEBHOOK_HTTP_ERROR',
                  {
                    status,
                  },
                ),
              );
          });
          response.once('close', () => {
            if (!responseEnded) {
              abort(
                webhookError(
                  'Webhook yanıt bağlantısı tamamlanmadan kapandı.',
                  'WEBHOOK_RESPONSE_PREMATURE_CLOSE',
                ),
              );
            }
          });
        },
      );
    } catch (error) {
      abort(error);
      return;
    }

    request.once('error', (error) => abort(error));
    try {
      request.end(payload);
    } catch (error) {
      abort(error);
    }
  });
}

function payloadFor(channel, event) {
  const incident = event.incident;
  const text =
    event.type === 'test'
      ? `${APP_NAME} webhook testi başarılı.`
      : `[${incident.severity.toUpperCase()}] ${incident.title} — ${incident.hostname}:${incident.port}`;
  if (channel.kind === 'slack') return { text };
  return {
    event: `incident.${event.type}`,
    sentAt: new Date().toISOString(),
    message: text,
    incident: incident
      ? {
          id: incident.id,
          severity: incident.severity,
          status: incident.status,
          title: incident.title,
          description: incident.description,
          hostname: incident.hostname,
          port: incident.port,
          owner: incident.owner,
          ruleKey: incident.ruleKey,
          firstSeenAt: incident.firstSeenAt,
          lastSeenAt: incident.lastSeenAt,
        }
      : null,
  };
}

function retryableWebhookError(error) {
  if (
    [
      'INVALID_WEBHOOK_URL',
      'INVALID_TARGET',
      'PRIVATE_TARGET_BLOCKED',
      'DNS_EMPTY',
      'WEBHOOK_STOPPED',
      'WEBHOOK_QUEUE_FULL',
      'WEBHOOK_RESPONSE_TOO_LARGE',
    ].includes(error?.code)
  ) {
    return false;
  }
  if (error?.status) {
    return (
      error.status === 408 ||
      error.status === 425 ||
      error.status === 429 ||
      error.status >= 500
    );
  }
  return true;
}

const wait = (milliseconds) =>
  delay(milliseconds, undefined, { signal: shutdownController.signal });

async function sendAttempt(url, body, options) {
  const controller = new AbortController();
  const deadlineMs = Math.max(
    1,
    Math.min(
      WEBHOOK_DEADLINE_MS,
      Number(options.deadlineMs) || WEBHOOK_DEADLINE_MS,
    ),
  );
  const signal = AbortSignal.any([
    controller.signal,
    shutdownController.signal,
  ]);
  const timer = setTimeout(
    () =>
      controller.abort(
        webhookError(
          'Webhook toplam süre sınırını aştı.',
          'WEBHOOK_DEADLINE_EXCEEDED',
        ),
      ),
    deadlineMs,
  );
  let onAbort;
  try {
    return await Promise.race([
      (async () => {
        signal.throwIfAborted();
        const resolved = await (
          options.resolveTarget || resolveAndValidateTarget
        )(url.hostname, { allowPrivate: false, timeoutMs: deadlineMs });
        // A late DNS result after cancellation must never start a connection.
        signal.throwIfAborted();
        return (options.sendRequest || requestWebhook)(
          url,
          resolved.address,
          resolved.family,
          body,
          { ...options.requestOptions, signal, deadlineMs },
        );
      })(),
      new Promise((_, reject) => {
        onAbort = () => reject(signal.reason);
        if (signal.aborted) onAbort();
        else signal.addEventListener('abort', onAbort, { once: true });
      }),
    ]);
  } finally {
    clearTimeout(timer);
    if (onAbort) signal.removeEventListener('abort', onAbort);
  }
}

function retryDelay(attempt, random = Math.random) {
  const exponential = Math.min(
    WEBHOOK_RETRY_MAX_MS,
    WEBHOOK_RETRY_BASE_MS * 2 ** Math.max(0, attempt - 1),
  );
  return Math.max(1, Math.round(exponential * (0.75 + random() * 0.5)));
}

async function deliver(channel, event, options = {}) {
  const waitForRetry = options.wait || wait;
  const maximumAttempts = Math.floor(
    Math.max(
      1,
      Math.min(
        WEBHOOK_MAX_ATTEMPTS,
        Number(options.maximumAttempts) || WEBHOOK_MAX_ATTEMPTS,
      ),
    ),
  );
  let url;
  let body;
  let lastError;
  let attempts = 0;

  try {
    const webhookUrl = validateWebhookUrl(decryptSecret(channel.urlEncrypted));
    url = new URL(webhookUrl);
    body = payloadFor(channel, event);
  } catch (error) {
    addNotificationDelivery({
      channelId: channel.id,
      channelName: channel.name,
      eventType: event.type,
      incidentId: event.incident?.id,
      status: 'failed',
      errorMessage: String(error.message || error).slice(0, 500),
    });
    return {
      ok: false,
      attempts: 1,
      error: String(error.message || error).slice(0, 500),
    };
  }

  for (let attempt = 1; attempt <= maximumAttempts; attempt += 1) {
    attempts = attempt;
    let responseCode = null;
    try {
      responseCode = await sendAttempt(url, body, options);
      addNotificationDelivery({
        channelId: channel.id,
        channelName: channel.name,
        eventType: event.type,
        incidentId: event.incident?.id,
        status: 'succeeded',
        responseCode,
      });
      return { ok: true, responseCode, attempts: attempt };
    } catch (error) {
      lastError = error;
      addNotificationDelivery({
        channelId: channel.id,
        channelName: channel.name,
        eventType: event.type,
        incidentId: event.incident?.id,
        status: 'failed',
        responseCode: error.status || responseCode,
        errorMessage: String(error.message || error).slice(0, 500),
      });
      if (attempt >= maximumAttempts || !retryableWebhookError(error)) break;
      try {
        await waitForRetry(retryDelay(attempt, options.random));
      } catch {
        break;
      }
    }
  }

  return {
    ok: false,
    attempts,
    error: String(
      lastError?.message || lastError || 'Webhook teslimatı başarısız.',
    ).slice(0, 500),
  };
}

async function queuedDeliver(channel, event, options) {
  try {
    return await withDeliverySlot(() => deliver(channel, event, options));
  } catch (error) {
    addNotificationDelivery({
      channelId: channel.id,
      channelName: channel.name,
      eventType: event.type,
      incidentId: event.incident?.id,
      status: 'failed',
      errorMessage: String(error.message || error).slice(0, 500),
    });
    return {
      ok: false,
      attempts: 0,
      error: String(error.message || error).slice(0, 500),
    };
  }
}

export async function dispatchIncidentNotifications(events, options = {}) {
  const channels = listNotificationChannels({ enabledOnly: true });
  const deliveries = [];
  for (const event of events || []) {
    if (!event.incident) continue;
    for (const channel of channels) {
      if (
        severityRank[event.incident.severity] <
        severityRank[channel.minSeverity]
      )
        continue;
      deliveries.push(() => queuedDeliver(channel, event, options));
    }
  }
  const results = Array.from({ length: deliveries.length });
  let cursor = 0;
  const workers = Array.from(
    { length: Math.min(WEBHOOK_MAX_CONCURRENCY, deliveries.length) },
    async () => {
      while (cursor < deliveries.length) {
        const index = cursor;
        cursor += 1;
        results[index] = await deliveries[index]();
      }
    },
  );
  await Promise.all(workers);
  return results;
}

export async function testNotificationChannel(id, options = {}) {
  const channel = getNotificationChannel(id);
  if (!channel) return null;
  return queuedDeliver(channel, { type: 'test', incident: null }, options);
}
