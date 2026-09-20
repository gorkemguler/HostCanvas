// Documentation example; not enabled by the production rule engine.
// 90 days is an example organization policy, not a claim about public CA rules.
export const certificateValidityRuleKey = 'custom.cert_validity_too_long';
const dayMs = 86_400_000;

export function evaluateCertificateValidity(
  observations,
  { maxDays = 90 } = {},
) {
  const result = (status, details = {}) => ({
    ruleKey: certificateValidityRuleKey,
    status,
    ...details,
  });
  if (!Number.isSafeInteger(maxDays) || maxDays < 1 || maxDays > 36500) {
    return result('unknown', { reason: 'invalid_policy' });
  }
  const certificate = observations?.tls?.certificate;
  const dates = [certificate?.validFrom, certificate?.validTo];
  if (dates.some((value) => typeof value !== 'string' || value.length > 64)) {
    return result('unknown', { reason: 'certificate_dates_unavailable' });
  }
  const [from, to] = dates.map((value) => Date.parse(value));
  if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) {
    return result('unknown', { reason: 'certificate_dates_invalid' });
  }
  if (to - from <= maxDays * dayMs) return result('pass');
  return result('fail', {
    severity: 'low',
    title: 'Certificate lifetime exceeds organization policy',
    description: `The certificate validity period exceeds the configured ${maxDays}-day policy. Review issuance and renewal settings.`,
    evidence: {
      validFrom: new Date(from).toISOString(),
      validTo: new Date(to).toISOString(),
      lifetimeDays: Math.round(((to - from) / dayMs) * 100) / 100,
      maxDays,
    },
  });
}
