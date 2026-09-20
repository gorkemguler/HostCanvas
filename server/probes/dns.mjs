import { Resolver } from 'node:dns/promises';

import { PUBLIC_DNS_RESOLVER } from '../config.mjs';
import { isPublicAddress } from '../security/targets.mjs';
import { probeDnssec } from './dnssec.mjs';

const notFoundCodes = new Set(['ENODATA', 'ENOTFOUND', 'ENODOMAIN', 'ENONAME']);
const commonSecondLevelSuffixes = new Set([
  'ac',
  'co',
  'com',
  'edu',
  'gov',
  'net',
  'org',
]);

async function safeResolve(callback) {
  try {
    return { status: 'complete', records: await callback() };
  } catch (error) {
    if (notFoundCodes.has(error.code))
      return { status: 'complete', records: [] };
    return {
      status: 'unknown',
      records: [],
      error: error.code || error.message || 'DNS_QUERY_FAILED',
    };
  }
}

function domainCandidates(hostname) {
  const labels = hostname
    .toLowerCase()
    .replace(/\.$/, '')
    .split('.')
    .filter(Boolean);
  const hasCompoundPublicSuffix =
    labels.at(-1)?.length === 2 && commonSecondLevelSuffixes.has(labels.at(-2));
  const minimumLabels = hasCompoundPublicSuffix ? 3 : 2;
  const candidates = [];
  for (let index = 0; labels.length - index >= minimumLabels; index += 1) {
    candidates.push(labels.slice(index).join('.'));
  }
  return candidates.slice(0, 6);
}

function flattenTxt(records) {
  return records.map((chunks) => chunks.join('').trim()).filter(Boolean);
}

function analyzeSpf(query) {
  if (query.status !== 'complete') {
    return { status: 'unknown', records: [], issues: [], error: query.error };
  }
  const records = flattenTxt(query.records).filter((record) =>
    /^v=spf1(?:\s|$)/i.test(record),
  );
  const issues = [];
  if (!records.length) issues.push('missing');
  if (records.length > 1) issues.push('multiple_records');
  if (records.some((record) => /(?:^|\s)\+?all(?:\s|$)/i.test(record))) {
    issues.push('permissive_all');
  }
  if (records.some((record) => !/(?:^|\s)[+?~-]?all(?:\s|$)/i.test(record))) {
    issues.push('all_mechanism_missing');
  }
  if (records.some((record) => /(?:^|\s)~all(?:\s|$)/i.test(record))) {
    issues.push('softfail');
  }
  return {
    status: records.length
      ? issues.length
        ? 'warning'
        : 'present'
      : 'missing',
    records,
    issues: [...new Set(issues)],
  };
}

function parseDmarcRecords(query, domain) {
  if (query.status !== 'complete') {
    return {
      status: 'unknown',
      domain,
      records: [],
      issues: [],
      error: query.error,
    };
  }
  const records = flattenTxt(query.records).filter((record) =>
    /^v=dmarc1(?:;|\s|$)/i.test(record),
  );
  if (!records.length)
    return { status: 'missing', domain, records: [], issues: ['missing'] };

  const issues = [];
  if (records.length > 1) issues.push('multiple_records');
  const tags = Object.fromEntries(
    records[0]
      .split(';')
      .map((part) => part.trim().split('=', 2))
      .filter(([key, value]) => key && value)
      .map(([key, value]) => [key.toLowerCase(), value.toLowerCase()]),
  );
  if (!['none', 'quarantine', 'reject'].includes(tags.p))
    issues.push('invalid_policy');
  if (tags.p === 'none') issues.push('monitoring_only');
  return {
    status: issues.length ? 'warning' : 'present',
    domain,
    records,
    policy: tags.p || null,
    subdomainPolicy: tags.sp || null,
    percentage: tags.pct || null,
    issues,
  };
}

async function probeDmarc(resolver, hostname) {
  for (const domain of domainCandidates(hostname)) {
    const query = await safeResolve(() =>
      resolver.resolveTxt(`_dmarc.${domain}`),
    );
    const result = parseDmarcRecords(query, domain);
    if (result.status === 'unknown' || result.records.length) return result;
  }
  return {
    status: 'missing',
    domain: domainCandidates(hostname).at(-1) || hostname,
    records: [],
    issues: ['missing'],
  };
}

export async function probeCaa(resolver, hostname) {
  const labels = hostname.split('.');
  // RFC 8659: look for the first effective RRset, climbing only when absent.
  // resolveCaa follows DNS aliases. A timeout must never fall through to parent.
  for (let index = 0; index < labels.length && index < 16; index += 1) {
    const domain = labels.slice(index).join('.');
    const query = await safeResolve(() => resolver.resolveCaa(domain));
    if (query.status !== 'complete') return { ...query, domain };
    if (query.records.length > 64)
      return {
        status: 'unknown',
        domain,
        records: [],
        error: 'CAA_RECORD_LIMIT',
      };
    if (query.records.length)
      return { status: 'complete', domain, records: query.records };
  }
  return {
    status: labels.length > 16 ? 'unknown' : 'complete',
    domain: hostname,
    records: [],
    ...(labels.length > 16 ? { error: 'CAA_DEPTH_LIMIT' } : {}),
  };
}

export async function probePublicDns(hostname, options = {}) {
  const publicDnsResolver = options.publicDnsResolver ?? PUBLIC_DNS_RESOLVER;
  const dnssecTask = (options.dnssecProbe || probeDnssec)(hostname);
  if (!publicDnsResolver && !options.resolver) {
    return {
      status: 'disabled',
      resolver: null,
      records: [],
      dnssec: await dnssecTask,
      reason: 'TLS_SENTINEL_PUBLIC_DNS_RESOLVER ayarlanmamış.',
    };
  }

  const resolver =
    options.resolver || new Resolver({ timeout: 2_000, tries: 2 });
  if (!options.resolver) resolver.setServers([publicDnsResolver]);

  const deadline = setTimeout(() => resolver.cancel?.(), 8_000);
  const [ipv4, ipv6, txt, dmarc, dnssec, caa] = await Promise.all([
    safeResolve(() => resolver.resolve4(hostname, { ttl: true })),
    safeResolve(() => resolver.resolve6(hostname, { ttl: true })),
    safeResolve(() => resolver.resolveTxt(hostname)),
    probeDmarc(resolver, hostname),
    dnssecTask,
    probeCaa(resolver, hostname),
  ]).finally(() => clearTimeout(deadline));
  const records = [
    ...ipv4.records.map((record) => ({ type: 'A', ...record })),
    ...ipv6.records.map((record) => ({ type: 'AAAA', ...record })),
  ].map((record) => ({ ...record, public: isPublicAddress(record.address) }));
  const statuses = [
    ipv4.status,
    ipv6.status,
    txt.status,
    dmarc.status,
    dnssec.status,
    caa.status,
  ];
  return {
    status: statuses.includes('unknown') ? 'partial' : 'complete',
    resolver: publicDnsResolver || 'injected',
    records,
    addressStatus:
      ipv4.status === 'complete' && ipv6.status === 'complete'
        ? 'complete'
        : 'partial',
    addressErrors: [ipv4.error, ipv6.error].filter(Boolean),
    spf: analyzeSpf(txt),
    dmarc,
    dnssec,
    caa,
  };
}
