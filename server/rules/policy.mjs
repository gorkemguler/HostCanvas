export const defaultCheckPolicy = Object.freeze({
  hstsMinMaxAgeSeconds: 15_552_000,
  hstsRequireSubdomains: false,
  cookieSecureRequired: true,
  sessionCookieNames: [],
  caaRequired: false,
  caaAllowedIssuers: [],
  scanHealthEnabled: true,
  scanFailureThreshold: 3,
});

export function validateCheckPolicy(input, current = defaultCheckPolicy) {
  const invalid = (field) => {
    throw Object.assign(
      new Error(`Geçersiz kontrol politikası / Invalid check policy: ${field}`),
      {
        code: 'INVALID_CHECK_POLICY',
        status: 422,
      },
    );
  };
  if (!input || typeof input !== 'object' || Array.isArray(input))
    invalid('object');
  for (const key of Object.keys(input)) {
    if (!Object.hasOwn(defaultCheckPolicy, key)) invalid(key);
  }
  const next = { ...defaultCheckPolicy, ...current, ...input };
  for (const key of [
    'hstsRequireSubdomains',
    'cookieSecureRequired',
    'caaRequired',
    'scanHealthEnabled',
  ]) {
    if (typeof next[key] !== 'boolean') invalid(key);
  }
  for (const [key, min, max] of [
    ['hstsMinMaxAgeSeconds', 0, 63_072_000],
    ['scanFailureThreshold', 1, 20],
  ]) {
    if (!Number.isSafeInteger(next[key]) || next[key] < min || next[key] > max)
      invalid(key);
  }
  for (const key of ['sessionCookieNames', 'caaAllowedIssuers']) {
    const values = next[key];
    if (!Array.isArray(values) || values.length > 20) invalid(key);
    next[key] = [
      ...new Set(
        values.map((value) => {
          if (
            typeof value !== 'string' ||
            !value ||
            value.length > (key === 'sessionCookieNames' ? 100 : 253)
          )
            invalid(key);
          if (key === 'sessionCookieNames') {
            if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(value)) invalid(key);
            return value;
          }
          const name = value.toLowerCase();
          if (
            !name.includes('.') ||
            !name
              .split('.')
              .every((label) =>
                /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label),
              )
          )
            invalid(key);
          return name;
        }),
      ),
    ];
  }
  return next;
}
