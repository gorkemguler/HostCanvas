# Incident check policies

[Türkçe](https://github.com/gorkemguler/HostCanvas/wiki/Kontrol-Politikalari) · [Home](https://github.com/gorkemguler/HostCanvas/wiki)

## Configure the workspace

Open **Settings → Incident check policy** with an administrator account. Operators and viewers can read the policy but cannot change it. These are workspace-wide settings, not per-asset overrides. Saving is audited and affects scans started afterwards; it does not rescan assets or rewrite earlier evidence. Resolver settings are deployment environment variables and require an API restart.

| Field | Default | Accepted values / effect |
| --- | --- | --- |
| `hstsMinMaxAgeSeconds` | `15552000` (180 days) | Integer `0–63072000`; zero disables only the minimum-duration requirement, not syntax/zero-max-age detection |
| `hstsRequireSubdomains` | `false` | Require `includeSubDomains` on observed HSTS headers |
| `cookieSecureRequired` | `true` | Check Secure on cookies observed in the HTTPS response |
| `sessionCookieNames` | `[]` | Up to 20 exact, case-sensitive cookie names, each at most 100 characters |
| `caaRequired` | `false` | Require an effective CAA `issue` policy |
| `caaAllowedIssuers` | `[]` | Up to 20 issuer domain names; nonempty also requires an `issue` policy |
| `scanHealthEnabled` | `true` | Generate a consecutive-incomplete-scan incident |
| `scanFailureThreshold` | `3` | Integer `1–20` |

Unknown fields and invalid types are rejected, not coerced. Lists in the UI accept one entry per line or comma-separated entries. Cookie names are not guessed from words such as `session`; explicitly enter the names your applications use. These global lists should suit every asset in the workspace.

## HSTS and cookies

- `http.hsts_weak_policy` (medium): observed HSTS has invalid/duplicate directives, zero `max-age`, too short a lifetime, or lacks required `includeSubDomains`. No header is handled by the existing `http.hsts_missing` rule, avoiding duplicate missing-header findings.
- `http.cookie_secure_missing` (low): at least one observed cookie lacks Secure. No observed cookies means `unknown`, not proof that the application has no insecure cookies.
- `http.session_cookie_httponly_missing` (medium): at least one configured session cookie is observed without HttpOnly. Passing requires every configured name to be observed with HttpOnly; absent names remain `unknown`. An empty list disables this check.

For example, `max-age=86400` fails the default HSTS duration policy; `max-age=31536000` passes unless `includeSubDomains` is required. `session=…; Secure` fails HttpOnly only when `session` is explicitly configured. Names and boolean attributes are retained, never cookie values. These checks observe one unauthenticated HTTPS response; they do not crawl login flows or establish that every application route is protected. Do not require subdomain HSTS until your HTTPS rollout supports it.

## CAA policy

Configure `TLS_SENTINEL_PUBLIC_DNS_RESOLVER` to collect CAA. `dns.caa_policy` is a low-severity policy finding, not a claim that certificate misissuance occurred. With default settings, absence alone is not a finding; malformed observed records and unsupported critical properties can still be flagged.

The probe follows the effective CAA lookup through aliases and parent labels, stopping at the first nonempty RRset. Query errors and safety limits produce `unknown`, not a fabricated empty policy. Tags are matched case-insensitively; an empty `issue` issuer intentionally prohibits issuance. These semantics follow [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659.html).

Examples for this implementation:

- `caaRequired: true` and no effective records → `issuance_policy_missing`.
- Allowed issuers `letsencrypt.org`, effective `issue "other.example"` → `issuer_not_allowed`.
- Effective `issue ";"` → no missing-policy finding.
- Only `issuewild` records → does not satisfy this tool's required ordinary-host `issue` policy.

The allowlist compares issuer domains in `issue` and `issuewild` records, not the current certificate's display-name/CN. It does not implement every CA-specific parameter or prove a CA's actual issuance decision. The probe is bounded to 16 queried labels and 64 records.

## DNSSEC: separate, explicit opt-in

The former Node `resolve(..., 'DNSKEY'/'DS')` approach is replaced: those record types are unsupported by that API. Merely setting `TLS_SENTINEL_PUBLIC_DNS_RESOLVER` no longer enables DNSSEC. Choose a trusted, validating DNS-over-TLS provider with a publicly resolvable hostname and permit outbound TCP 853. Example configuration, **not enabled automatically**:

```dotenv
TLS_SENTINEL_DNSSEC_RESOLVER=cloudflare-dns.com
```

Restart the API, then verify the resolver shown in Settings and scan an authorized asset. The selected provider receives each queried asset hostname (A lookup) and a root DNSKEY capability query. Do not enable this for names you are not permitted to disclose. The resolver hostname is resolved and public-IP-validated, then the address is pinned. TLS verifies the original hostname/certificate; there is no plaintext or unverified-TLS fallback.

| Observation | Result |
| --- | --- |
| Address/CNAME answer with authenticated-data indication | `present`; missing/bogus rules pass |
| Unsigned answer plus positive root validation capability | `missing`; `dns.dnssec_missing` fails (medium) |
| SERVFAIL plus a resolver-reported DNSSEC EDE code 6–12 | `bogus`; `dns.dnssec_bogus` fails (high) |
| Timeout, TLS failure, unconfirmed capability, malformed/stale/error response, NXDOMAIN or no A/CNAME evidence | `unknown`; existing DNSSEC incidents remain open |
| No configured resolver | `disabled`; no new DNSSEC finding |

This trusts an authenticated resolver's report; it is **not local cryptographic validation of the full signature chain**. EDE meanings are defined in [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914.html). A generic SERVFAIL alone is not called bogus. The initial probe uses A, so IPv6-only/no-A responses without CNAME evidence may stay unknown. DNSSEC uncertainty makes the scan partial even when other probes succeeded. An old missing-DNSSEC incident is not closed merely because the current result is bogus or unknown.

## Scan-health incident

`monitor.scan_unhealthy` (medium) opens after the configured number of consecutive completed scans with `failed` or `partial` status. Missing deep engine, incomplete required HTTP/DNS coverage and connection failures can contribute. A completed scan can contain security findings and still be healthy: healthy describes **collection coverage**, not a clean security grade.

The per-asset streak survives restarts and scan-history retention. Repeated failures update the same incident; acknowledged incidents stay acknowledged. A `succeeded` scan resets the counter and resolves only the health incident. A native scan can recover collection health without clearing older `testssl.*` findings: those still need complete deep coverage. Disabled/archived assets do not generate new health incidents.

This is not a stale-scan/watchdog alarm: a stopped scheduler with no completed scans cannot increment the counter. Health policy does not change the scan schedule. Disabling it stops incident evaluation but continues tracking completed-scan outcomes. Re-enabling applies on the next completed scan. Other disabled checks similarly do not resolve old findings; resolution requires adequate passing evidence or a deliberate manual decision.

## API, persistence and verification

Authenticated `GET /api/check-policy` returns `{ policy, updatedAt, publicDnsResolver, dnssecResolver }`. Admin-only `PATCH /api/check-policy` merges the supplied fields and returns the saved policy. Existing session, origin, Host and LAN restrictions apply. Example request body:

```json
{
  "hstsMinMaxAgeSeconds": 15552000,
  "hstsRequireSubdomains": false,
  "sessionCookieNames": ["session", "__Host-session"],
  "caaRequired": true,
  "caaAllowedIssuers": ["letsencrypt.org"],
  "scanHealthEnabled": true,
  "scanFailureThreshold": 3
}
```

The `check_policy` and `scan_health_state` SQLite tables are included in normal database backups; no separate policy file or secret is required. Additive schema initialization preserves existing assets and incidents. Old backups gain default policy and an empty health streak when opened by this version.

Tests in `tests/security-policy.test.mjs`, `tests/dnssec.test.mjs`, `tests/dns.test.mjs`, `tests/probe-integration.test.mjs` and `tests/api-auth.test.mjs` cover validation, incident lifecycle, role restrictions, effective CAA lookup and real local TLS-framed DNS fixtures. Tests do not need an external DNS provider. To add a different incident family rather than configure these rules, use [Creating custom incident types](https://github.com/gorkemguler/HostCanvas/wiki/Custom-Incident-Types).
