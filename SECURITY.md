# Security Policy

## Supported version

Security fixes are applied to the latest release on the `main` branch.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting flow from the repository's **Security** tab and include:

- the affected version or commit;
- a concise reproduction or proof of concept;
- the expected security impact;
- any suggested mitigation, if available.

Do not test against systems you do not own or lack explicit permission to scan. Avoid including real credentials, private inventories, or customer data in a report. Maintainers will acknowledge a complete report as soon as practical and coordinate disclosure after a fix is available.

## Scope notes

HostCanvas is intended for local or controlled-LAN deployment. Exposing it directly to the public internet without an authenticated access layer, trusted TLS termination, and a strict origin policy is outside the supported deployment model.
