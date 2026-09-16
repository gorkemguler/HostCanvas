const dayMs = 86_400_000;

export const ruleCatalog = [
  {
    key: 'cert.expired',
    title: 'Sertifika süresi dolmuş',
    category: 'Sertifika',
    severity: 'critical',
    source: 'Native TLS',
    enabled: true,
  },
  {
    key: 'cert.expiry_window',
    title: 'Sertifika yenileme penceresinde',
    category: 'Sertifika',
    severity: 'medium',
    source: 'Native TLS',
    enabled: true,
  },
  {
    key: 'cert.hostname_mismatch',
    title: 'Sertifika hostname ile eşleşmiyor',
    category: 'Sertifika',
    severity: 'high',
    source: 'Native TLS',
    enabled: true,
  },
  {
    key: 'cert.chain_untrusted',
    title: 'Sertifika zinciri güvenilir değil',
    category: 'Sertifika',
    severity: 'high',
    source: 'Native TLS',
    enabled: true,
  },
  {
    key: 'cert.not_yet_valid',
    title: 'Sertifika henüz geçerli değil',
    category: 'Sertifika',
    severity: 'high',
    source: 'Native TLS',
    enabled: true,
  },
  {
    key: 'cert.weak_public_key',
    title: 'Zayıf sertifika açık anahtarı',
    category: 'Sertifika',
    severity: 'high',
    source: 'Native TLS',
    enabled: true,
  },
  {
    key: 'cert.weak_signature',
    title: 'Zayıf sertifika imza algoritması',
    category: 'Sertifika',
    severity: 'high',
    source: 'Native TLS',
    enabled: true,
  },
  {
    key: 'tls.legacy_protocol',
    title: 'Legacy TLS protokolü destekleniyor',
    category: 'TLS yapılandırması',
    severity: 'high',
    source: 'Native TLS',
    enabled: true,
  },
  {
    key: 'tls.tls12_missing',
    title: 'TLS 1.2 desteği bulunamadı',
    category: 'TLS yapılandırması',
    severity: 'high',
    source: 'Native TLS',
    enabled: true,
  },
  {
    key: 'http.hsts_missing',
    title: 'HSTS başlığı eksik',
    category: 'HTTPS politikası',
    severity: 'medium',
    source: 'Native HTTP',
    enabled: true,
    recommendedCadence: 'daily',
  },
  {
    key: 'http.security_headers_missing',
    title: 'Temel HTTP güvenlik başlıkları eksik',
    category: 'HTTP güvenliği',
    severity: 'medium',
    source: 'Native HTTP',
    enabled: true,
    recommendedCadence: 'daily',
  },
  {
    key: 'http.server_header_disclosure',
    title: 'Server başlığı teknoloji bilgisi ifşa ediyor',
    category: 'Bilgi ifşası',
    severity: 'low',
    source: 'Native HTTP',
    enabled: true,
    recommendedCadence: 'weekly',
  },
  {
    key: 'http.deprecated_xss_protection',
    title: 'Eski X-XSS-Protection başlığı etkin',
    category: 'HTTP güvenliği',
    severity: 'low',
    source: 'Native HTTP',
    enabled: true,
    recommendedCadence: 'weekly',
  },
  {
    key: 'http.cookie_samesite_missing',
    title: 'Cookie SameSite koruması eksik',
    category: 'HTTP güvenliği',
    severity: 'low',
    source: 'Native HTTP',
    enabled: true,
    recommendedCadence: 'daily',
  },
  {
    key: 'dns.public_private_ip',
    title: 'Public DNS kaydında private IP ifşası',
    category: 'DNS',
    severity: 'high',
    source: 'Public DNS',
    enabled: false,
    requires: 'TLS_SENTINEL_PUBLIC_DNS_RESOLVER',
    recommendedCadence: 'daily',
  },
  {
    key: 'dns.dnssec_missing',
    title: 'DNSSEC koruması bulunamadı',
    category: 'DNS',
    severity: 'medium',
    source: 'Public DNS',
    enabled: false,
    requires: 'TLS_SENTINEL_PUBLIC_DNS_RESOLVER',
    recommendedCadence: 'weekly',
  },
  {
    key: 'email.dmarc_missing',
    title: 'DMARC kaydı eksik',
    category: 'E-posta güvenliği',
    severity: 'medium',
    source: 'Public DNS',
    enabled: false,
    requires: 'TLS_SENTINEL_PUBLIC_DNS_RESOLVER',
    recommendedCadence: 'daily',
  },
  {
    key: 'email.dmarc_policy_weak',
    title: 'DMARC politikası zayıf',
    category: 'E-posta güvenliği',
    severity: 'medium',
    source: 'Public DNS',
    enabled: false,
    requires: 'TLS_SENTINEL_PUBLIC_DNS_RESOLVER',
    recommendedCadence: 'daily',
  },
  {
    key: 'email.spf_misconfiguration',
    title: 'SPF kaydı eksik veya hatalı',
    category: 'E-posta güvenliği',
    severity: 'medium',
    source: 'Public DNS',
    enabled: false,
    requires: 'TLS_SENTINEL_PUBLIC_DNS_RESOLVER',
    recommendedCadence: 'daily',
  },
  {
    key: 'testssl.*',
    title: 'Derin TLS zafiyet kontrolleri',
    category: 'Derin tarama',
    severity: 'dynamic',
    source: 'testssl.sh',
    enabled: true,
  },
];

const evaluation = (ruleKey, status, details = {}) => ({
  ruleKey,
  status,
  ...details,
});

function expirySeverity(daysRemaining, warningDays) {
  if (daysRemaining <= 7) return 'high';
  if (daysRemaining <= Math.min(14, warningDays)) return 'high';
  if (daysRemaining <= 30) return 'medium';
  return 'low';
}

export function evaluateObservations(observations, policy) {
  const results = [];
  const certificate = observations.tls?.certificate;
  const now = Date.now();

  if (!certificate) {
    for (const key of [
      'cert.expired',
      'cert.expiry_window',
      'cert.hostname_mismatch',
      'cert.chain_untrusted',
      'cert.not_yet_valid',
      'cert.weak_public_key',
      'cert.weak_signature',
      'tls.legacy_protocol',
      'tls.tls12_missing',
    ]) {
      results.push(evaluation(key, 'unknown'));
    }
  } else {
    const validFrom = Date.parse(certificate.validFrom);
    const validTo = Date.parse(certificate.validTo);
    const daysRemaining = Math.ceil((validTo - now) / dayMs);
    const expired = Number.isFinite(validTo) && validTo <= now;

    results.push(
      expired
        ? evaluation('cert.expired', 'fail', {
            severity: 'critical',
            title: 'Sertifikanın süresi dolmuş',
            description: `Sertifika ${Math.abs(daysRemaining)} gün önce sona erdi.`,
            evidence: { validTo: certificate.validTo, daysRemaining },
          })
        : evaluation('cert.expired', 'pass'),
    );

    const warningDays = policy.expiryWarningDays || 30;
    results.push(
      !expired && daysRemaining <= warningDays
        ? evaluation('cert.expiry_window', 'fail', {
            severity: expirySeverity(daysRemaining, warningDays),
            title: `Sertifika ${daysRemaining} gün içinde sona eriyor`,
            description: `Yenileme eşiği ${warningDays} gün; sertifikanın bitiş tarihi ${certificate.validTo}.`,
            evidence: {
              validTo: certificate.validTo,
              daysRemaining,
              warningDays,
              fingerprint256: certificate.fingerprint256,
            },
          })
        : evaluation('cert.expiry_window', 'pass'),
    );

    results.push(
      certificate.hostnameMatches
        ? evaluation('cert.hostname_mismatch', 'pass')
        : evaluation('cert.hostname_mismatch', 'fail', {
            severity: 'high',
            title: 'Sertifika hostname ile eşleşmiyor',
            description:
              certificate.hostnameError ||
              'SAN/CN hedef hostname ile eşleşmedi.',
            evidence: {
              subjectAltName: certificate.subjectAltName,
              hostnameError: certificate.hostnameError,
            },
          }),
    );

    const authorizationError = String(
      observations.tls.authorizationError || '',
    );
    const onlyHostnameError = authorizationError.includes('ALTNAME');
    results.push(
      observations.tls.authorized || onlyHostnameError
        ? evaluation('cert.chain_untrusted', 'pass')
        : evaluation('cert.chain_untrusted', 'fail', {
            severity: 'high',
            title: 'Sertifika zinciri güvenilir değil',
            description:
              authorizationError ||
              'Sertifika zinciri sistem trust store ile doğrulanamadı.',
            evidence: {
              authorizationError,
              issuer: certificate.issuer,
              chainDepth: certificate.chainDepth,
            },
          }),
    );

    const notYetValid = Number.isFinite(validFrom) && validFrom > now;
    results.push(
      notYetValid
        ? evaluation('cert.not_yet_valid', 'fail', {
            severity: 'high',
            title: 'Sertifika henüz geçerli değil',
            description: `Geçerlilik başlangıcı ${certificate.validFrom}.`,
            evidence: { validFrom: certificate.validFrom },
          })
        : evaluation('cert.not_yet_valid', 'pass'),
    );

    const publicKey = certificate.publicKey || {};
    const weakRsa =
      ['rsa', 'rsa-pss'].includes(publicKey.type) &&
      typeof publicKey.bits === 'number' &&
      publicKey.bits < 2048;
    const weakDsa =
      publicKey.type === 'dsa' &&
      typeof publicKey.bits === 'number' &&
      publicKey.bits < 2048;
    results.push(
      weakRsa || weakDsa
        ? evaluation('cert.weak_public_key', 'fail', {
            severity: 'high',
            title: 'Sertifika açık anahtarı zayıf',
            description: `${publicKey.type} anahtar uzunluğu ${publicKey.bits} bit.`,
            evidence: publicKey,
          })
        : evaluation('cert.weak_public_key', 'pass'),
    );

    const signatureAlgorithm = String(certificate.signatureAlgorithm || '')
      .trim()
      .toLowerCase();
    const weakSignature = /(^|[^a-z])(md2|md4|md5|sha1)([^a-z]|$)/.test(
      signatureAlgorithm,
    );
    results.push(
      !signatureAlgorithm
        ? evaluation('cert.weak_signature', 'unknown')
        : weakSignature
          ? evaluation('cert.weak_signature', 'fail', {
              severity: 'high',
              title: 'Sertifika zayıf imza algoritması kullanıyor',
              description: `İmza algoritması: ${certificate.signatureAlgorithm}.`,
              evidence: { signatureAlgorithm: certificate.signatureAlgorithm },
            })
          : evaluation('cert.weak_signature', 'pass'),
    );

    const protocols = observations.tls.protocols || {};
    const legacySupported = ['TLSv1', 'TLSv1.1'].filter(
      (version) => protocols[version]?.supported === true,
    );
    const legacyUnknown = ['TLSv1', 'TLSv1.1'].some(
      (version) => protocols[version]?.supported == null,
    );
    results.push(
      legacySupported.length
        ? evaluation('tls.legacy_protocol', 'fail', {
            severity: 'high',
            title: 'Legacy TLS protokolü etkin',
            description: `${legacySupported.join(', ')} bağlantıları kabul ediliyor.`,
            evidence: { supported: legacySupported, protocols },
          })
        : evaluation('tls.legacy_protocol', legacyUnknown ? 'unknown' : 'pass'),
    );

    const tls12 = protocols['TLSv1.2']?.supported;
    results.push(
      tls12 === false
        ? evaluation('tls.tls12_missing', 'fail', {
            severity: 'high',
            title: 'TLS 1.2 desteği bulunamadı',
            description: 'Uyumluluk tabanı için TLS 1.2 desteği bekleniyor.',
            evidence: { protocols },
          })
        : evaluation('tls.tls12_missing', tls12 == null ? 'unknown' : 'pass'),
    );
  }

  const http = observations.http;
  if (http?.status === 'complete') {
    const headers = http.headers || {};
    results.push(
      http.hsts
        ? evaluation('http.hsts_missing', 'pass')
        : evaluation('http.hsts_missing', 'fail', {
            severity: 'medium',
            title: 'HSTS başlığı eksik',
            description:
              'HTTPS yanıtında Strict-Transport-Security başlığı bulunamadı.',
            evidence: { statusLine: http.statusLine },
          }),
    );

    const contentSecurityPolicy = headers['content-security-policy'];
    const missingSecurityHeaders = [];
    if (!contentSecurityPolicy)
      missingSecurityHeaders.push('Content-Security-Policy');
    if (
      String(headers['x-content-type-options'] || '').toLowerCase() !==
      'nosniff'
    ) {
      missingSecurityHeaders.push('X-Content-Type-Options: nosniff');
    }
    const frameProtected =
      /(?:^|;)\s*frame-ancestors\s+/i.test(
        String(contentSecurityPolicy || ''),
      ) ||
      /^(deny|sameorigin)$/i.test(
        String(headers['x-frame-options'] || '').trim(),
      );
    if (!frameProtected)
      missingSecurityHeaders.push('frame-ancestors veya X-Frame-Options');
    if (!headers['referrer-policy'])
      missingSecurityHeaders.push('Referrer-Policy');
    results.push(
      missingSecurityHeaders.length
        ? evaluation('http.security_headers_missing', 'fail', {
            severity: 'medium',
            title: 'Temel HTTP güvenlik başlıkları eksik',
            description: `${missingSecurityHeaders.join(', ')} koruması bulunamadı veya geçersiz.`,
            evidence: {
              missing: missingSecurityHeaders,
              statusLine: http.statusLine,
            },
          })
        : evaluation('http.security_headers_missing', 'pass'),
    );

    const serverHeader = String(headers.server || '').trim();
    results.push(
      serverHeader
        ? evaluation('http.server_header_disclosure', 'fail', {
            severity: 'low',
            title: 'Server başlığı teknoloji bilgisi ifşa ediyor',
            description:
              'HTTP yanıtı sunucu teknolojisini belirten bir Server başlığı içeriyor.',
            evidence: { server: serverHeader.slice(0, 200) },
          })
        : evaluation('http.server_header_disclosure', 'pass'),
    );

    const xssProtection = String(headers['x-xss-protection'] || '').trim();
    results.push(
      xssProtection && xssProtection !== '0'
        ? evaluation('http.deprecated_xss_protection', 'fail', {
            severity: 'low',
            title: 'Eski X-XSS-Protection başlığı etkin',
            description:
              'Eski tarayıcı XSS filtresi yerine modern Content-Security-Policy kullanılmalıdır.',
            evidence: { value: xssProtection.slice(0, 100) },
          })
        : evaluation('http.deprecated_xss_protection', 'pass'),
    );

    const unsafeCookies = (http.cookies || [])
      .filter(
        (cookie) =>
          !cookie.sameSite || (cookie.sameSite === 'none' && !cookie.secure),
      )
      .map((cookie) => ({
        name: cookie.name,
        issue: cookie.sameSite
          ? 'samesite_none_without_secure'
          : 'samesite_missing',
      }));
    results.push(
      unsafeCookies.length
        ? evaluation('http.cookie_samesite_missing', 'fail', {
            severity: 'low',
            title: 'Cookie SameSite koruması eksik',
            description: `${unsafeCookies.length} cookie güvenli bir SameSite politikası kullanmıyor.`,
            evidence: { cookies: unsafeCookies },
          })
        : evaluation('http.cookie_samesite_missing', 'pass'),
    );
  } else {
    for (const key of [
      'http.hsts_missing',
      'http.security_headers_missing',
      'http.server_header_disclosure',
      'http.deprecated_xss_protection',
      'http.cookie_samesite_missing',
    ]) {
      results.push(evaluation(key, 'unknown'));
    }
  }

  const publicDns = observations.publicDns;
  if (publicDns && ['complete', 'partial'].includes(publicDns.status)) {
    const leaked = (publicDns.records || []).filter((record) => !record.public);
    results.push(
      leaked.length
        ? evaluation('dns.public_private_ip', 'fail', {
            severity: 'high',
            title: 'Public DNS kaydında private IP ifşası',
            description: `${leaked.map((record) => record.address).join(', ')} public resolver üzerinden görünüyor.`,
            evidence: { resolver: publicDns.resolver, records: leaked },
          })
        : evaluation(
            'dns.public_private_ip',
            publicDns.addressStatus === 'complete' ? 'pass' : 'unknown',
          ),
    );

    const dnssec = publicDns.dnssec;
    results.push(
      dnssec?.status === 'missing'
        ? evaluation('dns.dnssec_missing', 'fail', {
            severity: 'medium',
            title: 'DNSSEC koruması bulunamadı',
            description: `${dnssec.domain || 'Hedef domain'} için doğrulanabilir DS/DNSKEY zinciri bulunamadı.`,
            evidence: {
              resolver: publicDns.resolver,
              domain: dnssec.domain,
              dnskeyCount: dnssec.dnskeyRecords?.length || 0,
              dsCount: dnssec.dsRecords?.length || 0,
            },
          })
        : evaluation(
            'dns.dnssec_missing',
            dnssec?.status === 'present' ? 'pass' : 'unknown',
          ),
    );

    const dmarc = publicDns.dmarc;
    results.push(
      dmarc?.status === 'missing'
        ? evaluation('email.dmarc_missing', 'fail', {
            severity: 'medium',
            title: 'DMARC kaydı eksik',
            description: `${dmarc.domain || 'Hedef domain'} için DMARC TXT kaydı bulunamadı.`,
            evidence: { resolver: publicDns.resolver, domain: dmarc.domain },
          })
        : evaluation(
            'email.dmarc_missing',
            ['present', 'warning'].includes(dmarc?.status) ? 'pass' : 'unknown',
          ),
    );
    const weakDmarc =
      dmarc?.status === 'warning' &&
      (dmarc.issues || []).some((issue) =>
        ['multiple_records', 'invalid_policy', 'monitoring_only'].includes(
          issue,
        ),
      );
    results.push(
      weakDmarc
        ? evaluation('email.dmarc_policy_weak', 'fail', {
            severity: dmarc.issues.includes('multiple_records')
              ? 'high'
              : 'medium',
            title: 'DMARC politikası zayıf veya geçersiz',
            description: `DMARC sorunları: ${dmarc.issues.join(', ')}.`,
            evidence: {
              domain: dmarc.domain,
              policy: dmarc.policy,
              subdomainPolicy: dmarc.subdomainPolicy,
              percentage: dmarc.percentage,
              issues: dmarc.issues,
            },
          })
        : evaluation(
            'email.dmarc_policy_weak',
            ['present', 'warning', 'missing'].includes(dmarc?.status)
              ? 'pass'
              : 'unknown',
          ),
    );

    const spf = publicDns.spf;
    const spfFailed = ['missing', 'warning'].includes(spf?.status);
    const highSpfRisk = (spf?.issues || []).some((issue) =>
      ['multiple_records', 'permissive_all'].includes(issue),
    );
    results.push(
      spfFailed
        ? evaluation('email.spf_misconfiguration', 'fail', {
            severity: highSpfRisk ? 'high' : 'medium',
            title: 'SPF kaydı eksik veya hatalı',
            description: `SPF sorunları: ${(spf.issues || []).join(', ')}.`,
            evidence: { issues: spf.issues, records: spf.records },
          })
        : evaluation(
            'email.spf_misconfiguration',
            spf?.status === 'present' ? 'pass' : 'unknown',
          ),
    );
  } else {
    for (const key of [
      'dns.public_private_ip',
      'dns.dnssec_missing',
      'email.dmarc_missing',
      'email.dmarc_policy_weak',
      'email.spf_misconfiguration',
    ]) {
      results.push(evaluation(key, 'unknown'));
    }
  }

  for (const finding of observations.testssl?.findings || []) {
    const severity = finding.severity.toLowerCase();
    if (!['critical', 'high', 'medium', 'low'].includes(severity)) continue;
    results.push(
      evaluation(`testssl.${finding.id}`, 'fail', {
        discriminator: finding.cve || finding.id,
        severity,
        title: `testssl.sh: ${finding.id}`,
        description: finding.finding || 'testssl.sh bir TLS bulgusu raporladı.',
        evidence: finding,
      }),
    );
  }

  return results;
}

export function gradeEvaluations(evaluations) {
  const failed = evaluations.filter((item) => item.status === 'fail');
  if (failed.some((item) => item.severity === 'critical')) return 'F';
  if (failed.some((item) => item.severity === 'high')) return 'C';
  if (failed.some((item) => item.severity === 'medium')) return 'B';
  if (failed.some((item) => item.severity === 'low')) return 'A-';
  return 'A';
}
