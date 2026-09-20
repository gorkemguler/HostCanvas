# Inventory, scanning and incidents

[Türkçe](https://github.com/gorkemguler/HostCanvas/wiki/Envanter-Tarama-ve-Incidentlar) · [Home](https://github.com/gorkemguler/HostCanvas/wiki)

## Add the right scope

An asset represents a hostname and port. Enter a hostname such as `api.example.com`, not `https://api.example.com/path`, an IP address, wildcard or command-line argument. Use only names you own or have explicit permission to assess.

Record a useful label, owner/team and environment, then choose a scan profile, interval and certificate-renewal warning threshold. The default interval is 720 minutes (12 hours). Editing the interval changes asset scheduling, not individual rule schedules.

The owner field provides operational context; it is not a separate access-control boundary. Admin/operator/viewer permissions apply to the workspace, not a per-asset tenant model. CSV export contains inventory information and should be handled as internal data.

### Internal targets

Private/loopback/link-local and other reserved targets are blocked by default. Internal scanning requires both:

1. Server setting `TLS_SENTINEL_ALLOW_PRIVATE_TARGETS=true`.
2. The asset's **Internal network target** option.

This is a deliberate expansion of what the scanning service can reach. Restrict who has operator/admin access and restrict the server's network reach. Do not enable it simply to suppress a validation error. DNS results are revalidated at scan time and the selected address is pinned while the original hostname remains the SNI/Host identity.

## Optional subdomain discovery

When adding an apex domain, explicitly select discovery with `crt.name` if desired. It sends the apex domain to an external certificate-transparency index. It is unchecked by default; global availability of the integration is not consent to query every asset.

Responses are normalized and filtered to in-scope hostnames, wildcards and duplicates are rejected, and by default up to 200 new subdomain assets are created. The limit is configurable from 1 to 500. Each discovered asset retains its parent/source relationship and its scan time is staggered to avoid a burst.

Discovery is passive: it does not prove a name is live, still owned, or safe to scan. Review the discovered inventory. It is not a continuous brute-force subdomain enumerator or complete internet asset discovery. Index coverage, provider availability and quotas can affect results. A discovery failure does not establish that the domain has no subdomains.

## Scan profiles and scheduling

| Profile | What it does | Operational use |
| --- | --- | --- |
| Native | TLS certificate/protocol observations, HTTP headers/cookie summaries, optional configured public DNS | Routine lightweight monitoring |
| Deep | Native observations plus testssl.sh's fixed IDS-friendly profile | More expensive TLS cipher/protocol/vulnerability assessment |

The application queues jobs and runs two concurrently by default (configurable 1–8). The scheduler checks due work every 30 seconds by default. Large inventories naturally take time to drain. Avoid triggering all deep scans before measuring duration and memory use.

Public DNS resolver configuration is required for disclosure, CAA, DMARC and SPF checks. DNSSEC separately requires an explicitly chosen validating DNS-over-TLS resolver. The system's internal split-horizon resolver is not public disclosure evidence. Native TLS support conclusions can be constrained by local Node/OpenSSL capabilities; use deep scans where stronger protocol validation is needed.

Workspace HSTS/cookie/CAA thresholds and consecutive-failure incidents are configured in Settings. See [Check policies](https://github.com/gorkemguler/HostCanvas/wiki/Check-Policies) for defaults, DNSSEC privacy/limitations and `monitor.scan_unhealthy`. An incomplete required probe produces partial/failed coverage; security findings alone do not make collection unhealthy.

A deep-engine failure can yield a `partial` scan while preserving native observations and existing deep incidents. A failed scan preserves the last useful snapshot and schedules a retry after the shorter of the configured interval and 15 minutes. Therefore an old grade or expiry date beside a failed scan is historical, not fresh proof.

Queued/running work is tracked in SQLite. Restart recovery handles interrupted work; it does not make every in-progress network call resumable. Inspect scan history after a restart.

## Interpret findings correctly

- `fail`: evidence supports the rule's condition; an incident is created or updated.
- `pass`: the rule has enough evidence to report no finding and may resolve matching incidents.
- `unknown`: data is missing, incomplete or unusable; it must not resolve an existing incident.

A successful job means the workflow finished, not that every probe supplied conclusive evidence. Inspect observations and evaluations, not just the job badge or grade. For example, an A grade can coexist with unknown checks because only confirmed failures contribute to the grade.

HostCanvas grades are operational summaries: critical F, high C, medium B, low A-, no failures A. They are not SSL Labs grades or certifications. A security-header or email-policy finding may be an operational hardening recommendation rather than an exploitable vulnerability in your specific environment.

## Incident workflow

1. Review the title, evidence, affected hostname/port, severity and scan time.
2. Acknowledge ownership of the investigation with `acknowledged`; the check remains active.
3. Fix the underlying certificate/DNS/HTTP configuration and run a fresh scan.
4. A reliable `pass` resolves the incident automatically. You can also manually choose `resolved` with context, but future failures reopen it.

The available statuses are `open`, `acknowledged` and `resolved`. Repeated failures update the same incident's evidence, severity, last-seen timestamp and occurrence count. A resolved issue that recurs reuses its incident ID and records a reopening. Automatic notifications currently occur only on opening/reopening, not every scan or resolution.

Archiving an asset disables future scanning and closes its active incidents while preserving historical records. This is not evidence that the remote system was fixed; distinguish archive-related closure from a passing check.

For custom rules and the important limitation around per-rule `pass` with multiple discriminators, read [Creating custom incident types](https://github.com/gorkemguler/HostCanvas/wiki/Custom-Incident-Types). For notification setup and retention, continue to [Operations](https://github.com/gorkemguler/HostCanvas/wiki/Operations-and-Troubleshooting).
