import { defaultCheckPolicy } from './policy.mjs';

export const securityPolicyCatalog = [
  {
    key: 'http.hsts_weak_policy',
    title: 'HSTS politikası etkisiz / Ineffective HSTS policy',
    category: 'HTTP policy',
    severity: 'medium',
    source: 'Native HTTP',
    enabled: true,
  },
  {
    key: 'http.cookie_secure_missing',
    title: 'Cookie Secure eksik / Cookie Secure missing',
    category: 'HTTP policy',
    severity: 'low',
    source: 'Native HTTP',
    enabled: true,
  },
  {
    key: 'http.session_cookie_httponly_missing',
    title: 'Oturum cookie HttpOnly eksik / Session cookie HttpOnly missing',
    category: 'HTTP policy',
    severity: 'medium',
    source: 'Native HTTP',
    enabled: true,
  },
  {
    key: 'dns.caa_policy',
    title: 'CAA politikası uygun değil / CAA policy mismatch',
    category: 'DNS',
    severity: 'low',
    source: 'Public DNS',
    enabled: false,
    requires: 'TLS_SENTINEL_PUBLIC_DNS_RESOLVER',
  },
  {
    key: 'dns.dnssec_bogus',
    title: 'DNSSEC doğrulama hatası / DNSSEC validation failure',
    category: 'DNS',
    severity: 'high',
    source: 'DNS-over-TLS',
    enabled: false,
    requires: 'TLS_SENTINEL_DNSSEC_RESOLVER',
  },
  {
    key: 'monitor.scan_unhealthy',
    title: 'Tarama kapsamı kayboldu / Scan coverage degraded',
    category: 'Monitoring',
    severity: 'medium',
    source: 'Scan history',
    enabled: true,
  },
];

export function analyzeHsts(value, policy) {
  const parts = String(value)
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean);
  const directives = new Map();
  const issues = [];
  for (const part of parts) {
    const [rawName, ...rest] = part.split('=');
    const name = rawName.trim().toLowerCase();
    const setting = rest.join('=').trim();
    if (!/^[a-z][a-z0-9-]*$/.test(name) || directives.has(name))
      issues.push('malformed_or_duplicate_directive');
    directives.set(name, setting);
    if (name === 'includesubdomains' && rest.length)
      issues.push('invalid_include_subdomains');
  }
  const maxAge = directives.get('max-age');
  const seconds = /^(?:\d+|"\d+")$/.test(maxAge || '')
    ? Number(maxAge.replaceAll('"', ''))
    : NaN;
  if (!Number.isSafeInteger(seconds)) issues.push('invalid_max_age');
  else if (seconds === 0) issues.push('hsts_disabled');
  else if (seconds < policy.hstsMinMaxAgeSeconds)
    issues.push('max_age_below_policy');
  if (policy.hstsRequireSubdomains && !directives.has('includesubdomains'))
    issues.push('include_subdomains_required');
  return {
    issues: [...new Set(issues)],
    maxAgeSeconds: Number.isFinite(seconds) ? seconds : null,
  };
}

export function analyzeCaa(records, policy) {
  const issues = new Set();
  const issuers = [];
  let issueCount = 0;
  for (const record of records) {
    if (!record || typeof record !== 'object') {
      issues.add('malformed_record');
      continue;
    }
    const flags = record.critical;
    if (!Number.isInteger(flags) || flags < 0 || flags > 255 || flags & 127)
      issues.add('invalid_flags');
    const tags = Object.keys(record).filter((key) => key !== 'critical');
    if (tags.length !== 1) issues.add('malformed_record');
    for (const rawTag of tags) {
      const tag = rawTag.toLowerCase();
      const value = record[rawTag];
      if (!/^[a-z0-9]{1,255}$/.test(tag)) issues.add('invalid_tag');
      if (typeof value !== 'string' || value.length > 4096) {
        issues.add('invalid_value');
        continue;
      }
      if (!['issue', 'issuewild', 'iodef'].includes(tag)) {
        if (flags & 128) issues.add('unsupported_critical_property');
        continue;
      }
      if (tag === 'iodef') continue;
      if (tag === 'issue') issueCount += 1;
      const issuer = value.split(';', 1)[0].trim().toLowerCase();
      // Empty issuer is an intentional issuance prohibition, not a missing CA.
      if (!issuer) continue;
      if (
        !issuer
          .split('.')
          .every((part) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part))
      ) {
        issues.add('invalid_issuer');
        continue;
      }
      issuers.push(issuer);
      if (
        policy.caaAllowedIssuers.length &&
        !policy.caaAllowedIssuers.includes(issuer)
      )
        issues.add('issuer_not_allowed');
    }
  }
  if (
    (policy.caaRequired || policy.caaAllowedIssuers.length) &&
    issueCount === 0
  )
    issues.add('issuance_policy_missing');
  return { issues: [...issues], issuers: [...new Set(issuers)] };
}

export function evaluateSecurityPolicy(observations, inputPolicy = {}) {
  const policy = { ...defaultCheckPolicy, ...inputPolicy };
  const results = [];
  const add = (ruleKey, status, details = {}) =>
    results.push({ ruleKey, status, ...details });
  const http = observations.http;
  if (http?.status !== 'complete') {
    for (const key of [
      'http.hsts_weak_policy',
      'http.cookie_secure_missing',
      'http.session_cookie_httponly_missing',
    ])
      add(key, 'unknown');
  } else {
    if (!http.hsts)
      add('http.hsts_weak_policy', 'pass'); // Missing HSTS has its own existing rule.
    else {
      const hsts = analyzeHsts(http.hsts, policy);
      add(
        'http.hsts_weak_policy',
        hsts.issues.length ? 'fail' : 'pass',
        hsts.issues.length
          ? {
              severity: 'medium',
              title: 'HSTS politikası etkisiz / Ineffective HSTS policy',
              description: `HSTS: ${hsts.issues.join(', ')}.`,
              evidence: {
                ...hsts,
                requiredMaxAgeSeconds: policy.hstsMinMaxAgeSeconds,
                requireSubdomains: policy.hstsRequireSubdomains,
              },
            }
          : {},
      );
    }
    const cookies = Array.isArray(http.cookies) ? http.cookies : [];
    const insecure = cookies.filter((cookie) => cookie.secure === false);
    const cookieComplete =
      cookies.length > 0 &&
      cookies.every((cookie) => typeof cookie.secure === 'boolean');
    add(
      'http.cookie_secure_missing',
      !policy.cookieSecureRequired
        ? 'unknown'
        : insecure.length
          ? 'fail'
          : cookieComplete
            ? 'pass'
            : 'unknown',
      policy.cookieSecureRequired && insecure.length
        ? {
            severity: 'low',
            title: 'Cookie Secure bayrağı eksik / Cookie Secure flag missing',
            description:
              'HTTPS yanıtındaki cookie’ler Secure bayrağı taşımıyor / Cookies in the HTTPS response lack Secure.',
            evidence: {
              cookieNames: insecure.map((cookie) => cookie.name).slice(0, 64),
            },
          }
        : {},
    );
    const session = cookies.filter((cookie) =>
      policy.sessionCookieNames.includes(cookie.name),
    );
    const unsafe = session.filter((cookie) => cookie.httpOnly === false);
    const observedAll =
      policy.sessionCookieNames.length > 0 &&
      policy.sessionCookieNames.every((name) =>
        session.some(
          (cookie) =>
            cookie.name === name && typeof cookie.httpOnly === 'boolean',
        ),
      );
    add(
      'http.session_cookie_httponly_missing',
      unsafe.length ? 'fail' : observedAll ? 'pass' : 'unknown',
      unsafe.length
        ? {
            severity: 'medium',
            title:
              'Oturum cookie HttpOnly bayrağı eksik / Session cookie HttpOnly missing',
            description:
              'Tanımlanan oturum cookie’leri HttpOnly kullanmalı / Configured session cookies should use HttpOnly.',
            evidence: {
              cookieNames: unsafe.map((cookie) => cookie.name).slice(0, 64),
            },
          }
        : {},
    );
  }
  const caa = observations.publicDns?.caa;
  if (caa?.status !== 'complete' || !Array.isArray(caa.records))
    add('dns.caa_policy', 'unknown');
  else {
    const finding = analyzeCaa(caa.records, policy);
    add(
      'dns.caa_policy',
      finding.issues.length ? 'fail' : 'pass',
      finding.issues.length
        ? {
            severity: 'low',
            title: 'CAA politikası uygun değil / CAA policy mismatch',
            description: `CAA: ${finding.issues.join(', ')}.`,
            evidence: {
              ...finding,
              domain: caa.domain,
              resolver: observations.publicDns.resolver,
            },
          }
        : {},
    );
  }
  const dnssec = observations.publicDns?.dnssec;
  const evidence = {
    domain: dnssec?.domain,
    resolver: dnssec?.resolver,
    transport: dnssec?.transport,
    reason: dnssec?.reason,
  };
  add(
    'dns.dnssec_missing',
    dnssec?.status === 'missing'
      ? 'fail'
      : dnssec?.status === 'present'
        ? 'pass'
        : 'unknown',
    dnssec?.status === 'missing'
      ? {
          severity: 'medium',
          title: 'DNSSEC koruması bulunamadı / DNSSEC protection missing',
          description:
            'Doğrulayan resolver hedef yanıtını imzalı olarak doğrulamadı / The validating resolver returned an unsigned answer.',
          evidence,
        }
      : {},
  );
  add(
    'dns.dnssec_bogus',
    dnssec?.status === 'bogus'
      ? 'fail'
      : ['present', 'missing'].includes(dnssec?.status)
        ? 'pass'
        : 'unknown',
    dnssec?.status === 'bogus'
      ? {
          severity: 'high',
          title: 'DNSSEC doğrulaması başarısız / DNSSEC validation failed',
          description:
            'TLS ile doğrulanan resolver DNSSEC hata kanıtı bildirdi / The authenticated resolver reported a DNSSEC validation error.',
          evidence: { ...evidence, extendedErrors: dnssec.extendedErrors },
        }
      : {},
  );
  return results;
}
