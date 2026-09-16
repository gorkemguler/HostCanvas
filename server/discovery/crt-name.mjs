import {
  APP_NAME,
  APP_VERSION,
  SUBDOMAIN_DISCOVERY_LIMIT,
  SUBDOMAIN_DISCOVERY_TIMEOUT_MS,
} from '../config.mjs';
import { normalizeHostname } from '../security/targets.mjs';

const endpoint = 'https://crt.name/v1/search';
const maximumResponseBytes = 2 * 1024 * 1024;

async function readBoundedJson(response, maximumBytes = maximumResponseBytes) {
  const reader = response.body?.getReader();
  if (!reader) return response.json();

  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maximumBytes) {
      await reader.cancel();
      const error = new Error('crt.name yanıtı güvenli boyut sınırını aştı.');
      error.code = 'DISCOVERY_RESPONSE_TOO_LARGE';
      throw error;
    }
    chunks.push(value);
  }
  const buffer = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)));
  return JSON.parse(buffer.toString('utf8'));
}

function normalizeResults(apex, payload, limit) {
  if (!Array.isArray(payload)) {
    const error = new Error('crt.name beklenmeyen bir yanıt döndürdü.');
    error.code = 'DISCOVERY_INVALID_RESPONSE';
    throw error;
  }

  const unique = new Map();
  for (const item of payload) {
    if (!item || typeof item.sub !== 'string' || !item.first_seen) continue;
    let hostname;
    try {
      hostname = normalizeHostname(item.sub);
    } catch {
      continue;
    }
    if (hostname === apex || !hostname.endsWith(`.${apex}`)) continue;
    const firstSeen = new Date(item.first_seen);
    if (!Number.isFinite(firstSeen.getTime())) continue;
    const current = unique.get(hostname);
    if (!current || firstSeen < current.firstSeen) {
      unique.set(hostname, { hostname, firstSeen });
    }
  }

  const sorted = [...unique.values()].sort(
    (left, right) => left.firstSeen - right.firstSeen,
  );
  return {
    records: sorted.slice(0, limit).map((record) => ({
      hostname: record.hostname,
      firstSeenAt: record.firstSeen.toISOString(),
    })),
    totalFound: sorted.length,
    truncated: sorted.length > limit,
  };
}

export async function discoverSubdomains(apexInput, options = {}) {
  const apex = normalizeHostname(apexInput);
  if (!apex.includes('.')) {
    const error = new Error(
      'Subdomain keşfi için bir kök domain girilmelidir.',
    );
    error.code = 'DISCOVERY_APEX_REQUIRED';
    throw error;
  }

  const limit = Math.min(
    SUBDOMAIN_DISCOVERY_LIMIT,
    Math.max(1, Number(options.limit) || SUBDOMAIN_DISCOVERY_LIMIT),
  );
  const request = options.fetch || fetch;
  const url = new URL(endpoint);
  url.searchParams.set('apex', apex);
  url.searchParams.set('format', 'json');
  url.searchParams.set('dates', '1');

  let response;
  try {
    response = await request(url, {
      headers: {
        Accept: 'application/json',
        'User-Agent': `${APP_NAME}/${APP_VERSION}`,
      },
      redirect: 'error',
      signal:
        options.signal || AbortSignal.timeout(SUBDOMAIN_DISCOVERY_TIMEOUT_MS),
    });
  } catch (error) {
    const wrapped = new Error(
      error.name === 'TimeoutError'
        ? 'crt.name isteği zaman aşımına uğradı.'
        : 'crt.name servisine ulaşılamadı.',
    );
    wrapped.code =
      error.name === 'TimeoutError'
        ? 'DISCOVERY_TIMEOUT'
        : 'DISCOVERY_UNAVAILABLE';
    throw wrapped;
  }

  if (!response.ok) {
    const error = new Error(
      response.status === 429
        ? 'crt.name ücretsiz sorgu kotası doldu.'
        : `crt.name isteği ${response.status} durumuyla başarısız oldu.`,
    );
    error.code =
      response.status === 429 ? 'DISCOVERY_RATE_LIMITED' : 'DISCOVERY_FAILED';
    throw error;
  }

  const payload = await readBoundedJson(
    response,
    options.maximumResponseBytes || maximumResponseBytes,
  );
  return {
    provider: 'crt.name',
    apex,
    ...normalizeResults(apex, payload, limit),
  };
}
