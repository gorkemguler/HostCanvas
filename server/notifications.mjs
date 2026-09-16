import https from 'node:https';

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

function requestWebhook(url, address, family, body) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(body));
    const request = https.request(
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
        timeout: 8_000,
        rejectUnauthorized: true,
      },
      (response) => {
        let responseBytes = 0;
        response.on('data', (chunk) => {
          responseBytes += chunk.length;
          if (responseBytes > 64 * 1024) response.destroy();
        });
        response.once('end', () => {
          const status = response.statusCode || 0;
          if (status >= 200 && status < 300) resolve(status);
          else
            reject(
              Object.assign(new Error(`Webhook HTTP ${status} döndürdü.`), {
                status,
              }),
            );
        });
      },
    );
    request.once('timeout', () =>
      request.destroy(
        Object.assign(new Error('Webhook zaman aşımına uğradı.'), {
          code: 'WEBHOOK_TIMEOUT',
        }),
      ),
    );
    request.once('error', reject);
    request.end(payload);
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

async function deliver(channel, event) {
  let responseCode = null;
  try {
    const webhookUrl = validateWebhookUrl(decryptSecret(channel.urlEncrypted));
    const url = new URL(webhookUrl);
    const resolved = await resolveAndValidateTarget(url.hostname, {
      allowPrivate: false,
    });
    responseCode = await requestWebhook(
      url,
      resolved.address,
      resolved.family,
      payloadFor(channel, event),
    );
    addNotificationDelivery({
      channelId: channel.id,
      channelName: channel.name,
      eventType: event.type,
      incidentId: event.incident?.id,
      status: 'succeeded',
      responseCode,
    });
    return { ok: true, responseCode };
  } catch (error) {
    addNotificationDelivery({
      channelId: channel.id,
      channelName: channel.name,
      eventType: event.type,
      incidentId: event.incident?.id,
      status: 'failed',
      responseCode: error.status || responseCode,
      errorMessage: String(error.message || error).slice(0, 500),
    });
    return { ok: false, error: String(error.message || error).slice(0, 500) };
  }
}

export async function dispatchIncidentNotifications(events) {
  const channels = listNotificationChannels({ enabledOnly: true });
  const tasks = [];
  for (const event of events || []) {
    if (!event.incident) continue;
    for (const channel of channels) {
      if (
        severityRank[event.incident.severity] <
        severityRank[channel.minSeverity]
      )
        continue;
      tasks.push(deliver(channel, event));
    }
  }
  return Promise.all(tasks);
}

export async function testNotificationChannel(id) {
  const channel = getNotificationChannel(id);
  if (!channel) return null;
  return deliver(channel, { type: 'test', incident: null });
}
