import dns from 'node:dns/promises';
import net from 'node:net';
import { domainToASCII } from 'node:url';

export class TargetValidationError extends Error {
  constructor(message, code = 'INVALID_TARGET') {
    super(message);
    this.name = 'TargetValidationError';
    this.code = code;
  }
}

export function normalizeHostname(input) {
  if (typeof input !== 'string') {
    throw new TargetValidationError('Domain metin olarak gönderilmelidir.');
  }

  const raw = input.trim().replace(/\.$/, '').toLowerCase();
  if (!raw || raw.length > 253) {
    throw new TargetValidationError('Domain uzunluğu geçersiz.');
  }
  if (
    raw.includes('://') ||
    /[\s/@?#\\]/.test(raw) ||
    raw.includes('*') ||
    raw.includes(':')
  ) {
    throw new TargetValidationError(
      'Yalnızca hostname girin; protokol, port, yol ve wildcard kullanmayın.',
    );
  }
  if (net.isIP(raw)) {
    throw new TargetValidationError(
      'MVP yalnızca hostname envanterini kabul eder; doğrudan IP eklenemez.',
    );
  }

  const ascii = domainToASCII(raw);
  if (!ascii || ascii.length > 253) {
    throw new TargetValidationError('Domain IDNA dönüşümünden geçemedi.');
  }

  const labels = ascii.split('.');
  if (
    labels.some(
      (label) =>
        label.length < 1 ||
        label.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    )
  ) {
    throw new TargetValidationError('Domain etiketlerinden biri geçersiz.');
  }

  return ascii;
}

export function normalizePort(input) {
  const port = Number(input ?? 443);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TargetValidationError('Port 1 ile 65535 arasında olmalıdır.');
  }
  return port;
}

function ipv4ToInteger(address) {
  return (
    address
      .split('.')
      .map(Number)
      .reduce((total, octet) => (total << 8) + octet, 0) >>> 0
  );
}

function ipv4InCidr(address, base, prefix) {
  const value = ipv4ToInteger(address);
  const baseValue = ipv4ToInteger(base);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (baseValue & mask);
}

const nonPublicIpv4Ranges = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

export function isPublicAddress(address) {
  const family = net.isIP(address);
  if (family === 4) {
    return !nonPublicIpv4Ranges.some(([base, prefix]) =>
      ipv4InCidr(address, base, prefix),
    );
  }
  if (family !== 6) return false;

  const value = ipv6ToBigInt(address);
  if (value == null) return false;

  // IPv4-mapped IPv6 records are unnecessary for hostname scanning and can
  // otherwise disguise an IPv4 special-use destination.
  const mappedPrefix = 0xffffn;
  if (value >> 32n === mappedPrefix) {
    return false;
  }

  // Currently allocated globally routable unicast space is within 2000::/3.
  // This also rejects IPv4-compatible, translated/NAT64, site-local, ULA,
  // link-local and multicast forms before the narrower exclusions below.
  if (!bigIntInCidr(value, globalUnicastIpv6Base, 3)) return false;

  return !nonPublicIpv6Ranges.some(([base, prefix]) =>
    bigIntInCidr(value, base, prefix),
  );
}

function ipv6ToBigInt(address) {
  const normalized = address.toLowerCase().split('%')[0];
  const halves = normalized.split('::');
  if (halves.length > 2) return null;

  const parsePart = (part) => {
    if (!part) return [];
    const segments = part.split(':');
    const result = [];
    for (const segment of segments) {
      if (segment.includes('.')) {
        if (net.isIP(segment) !== 4) return null;
        const ipv4 = ipv4ToInteger(segment);
        result.push((ipv4 >>> 16).toString(16), (ipv4 & 0xffff).toString(16));
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(segment)) return null;
        result.push(segment);
      }
    }
    return result;
  };

  const left = parsePart(halves[0]);
  const right = parsePart(halves[1] || '');
  if (!left || !right) return null;
  const omitted = halves.length === 2 ? 8 - left.length - right.length : 0;
  if (omitted < 0 || (halves.length === 1 && left.length !== 8)) return null;
  const segments = [...left, ...Array(omitted).fill('0'), ...right];
  if (segments.length !== 8) return null;
  return segments.reduce(
    (total, segment) => (total << 16n) | BigInt(`0x${segment}`),
    0n,
  );
}

function bigIntInCidr(value, base, prefix) {
  if (prefix === 0) return true;
  const shift = 128n - BigInt(prefix);
  return value >> shift === base >> shift;
}

const ipv6 = (address) => ipv6ToBigInt(address);
const globalUnicastIpv6Base = ipv6('2000::');
const nonPublicIpv6Ranges = [
  // IETF protocol assignments include transition/tunnelling technologies such
  // as Teredo and are not treated as ordinary public scan destinations.
  [ipv6('2001::'), 23],
  [ipv6('2001:db8::'), 32],
  [ipv6('2002::'), 16],
  [ipv6('3ffe::'), 16],
  [ipv6('3fff::'), 20],
];

export async function resolveAndValidateTarget(hostname, options = {}) {
  const normalized = normalizeHostname(hostname);
  const allowPrivate = options.allowPrivate === true;
  const lookup = options.lookup || dns.lookup;

  let records;
  let timer;
  try {
    // getaddrinfo cannot be cancelled, but a stalled resolver must not hold a
    // scan worker forever. Late lookup results are ignored by Promise.race.
    records = await Promise.race([
      Promise.resolve().then(() =>
        lookup(normalized, { all: true, verbatim: true }),
      ),
      new Promise((_, reject) => {
        timer = setTimeout(
          () =>
            reject(
              Object.assign(new Error('DNS deadline exceeded'), {
                code: 'DNS_TIMEOUT',
              }),
            ),
          Math.max(1, Math.min(30_000, Number(options.timeoutMs) || 7_000)),
        );
      }),
    ]);
  } catch (error) {
    const targetError = new TargetValidationError(
      `DNS çözümlemesi başarısız: ${error.code || error.message}`,
      'DNS_RESOLUTION_FAILED',
    );
    targetError.cause = error;
    throw targetError;
  } finally {
    clearTimeout(timer);
  }

  const uniqueRecords = [
    ...new Map(records.map((record) => [record.address, record])).values(),
  ];
  if (uniqueRecords.length === 0) {
    throw new TargetValidationError(
      'Domain hiçbir A/AAAA kaydına çözülmedi.',
      'DNS_EMPTY',
    );
  }

  const blocked = uniqueRecords.filter(
    (record) => !isPublicAddress(record.address),
  );
  if (blocked.length && !allowPrivate) {
    throw new TargetValidationError(
      `Hedef public olmayan IP adresine çözülüyor (${blocked
        .map((record) => record.address)
        .join(', ')}). İç ağ taraması varsayılan olarak kapalıdır.`,
      'PRIVATE_TARGET_BLOCKED',
    );
  }

  const preferred =
    uniqueRecords.find((record) => isPublicAddress(record.address)) ||
    uniqueRecords[0];
  return {
    hostname: normalized,
    address: preferred.address,
    family: preferred.family,
    records: uniqueRecords.slice(0, 16).map((record) => ({
      address: record.address,
      family: record.family,
      public: isPublicAddress(record.address),
    })),
  };
}
