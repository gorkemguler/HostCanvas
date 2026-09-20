# Installation and secure LAN access

[Türkçe](https://github.com/gorkemguler/HostCanvas/wiki/Kurulum-ve-LAN) · [Home](https://github.com/gorkemguler/HostCanvas/wiki)

## Choose a deployment

Use native development for local evaluation and development. Use a production build or the supplied Compose/Caddy deployment for a persistent service. The supported baseline is Node.js 24.21.0 or newer; `.node-version` and the Dockerfile pin the baseline. Native deep scans additionally require a supported testssl.sh 3.2.x executable. The Docker image includes testssl.sh 3.2.4.

### Native installation

```bash
git clone https://github.com/gorkemguler/HostCanvas.git
cd HostCanvas
npm ci
cp .env.example .env.local
npm run dev
```

Open `http://localhost:3000`. For a production run, stop the development processes, then:

```bash
npm run build
npm start
```

`npm start` runs the built console and the API, not the development server. Do not run a second API against the same data directory. The default API port is 8787 and the web port is 3000. For strictly local native access, set both `TLS_SENTINEL_API_HOST=127.0.0.1` and `TLS_SENTINEL_WEB_HOST=127.0.0.1` before starting.

### First-run wizard

1. Select English or Turkish and set the organization name.
2. Choose local access or authenticated LAN access. The latter requires HTTPS.
3. Read the one-time setup code printed in the API console. It is required even on localhost and expires after 15 minutes. If expired, reload the wizard and read the newly printed code.
4. Create the administrator account and set scan defaults.
5. Optionally add an asset. Confirm authorization to scan it. Leave subdomain discovery unchecked unless external CT lookup is intended.
6. Complete setup and verify sign-in, an authorized test scan, and incident display.

Language, organization, access policy and scan defaults remain editable from Settings. Asset-specific settings are editable in the inventory. The setup wizard is not an account-recovery mechanism; do not delete the live database to reset a password.

## Docker and HTTPS for LAN teams

From the cloned repository:

```bash
cp .env.example .env
# Edit .env before starting:
# TLS_SENTINEL_HTTPS_HOST=192.168.1.20
docker compose up --build -d
docker compose logs app
```

Use your server's actual hostname or IPv4 address, **without scheme, port or path**, for `TLS_SENTINEL_HTTPS_HOST`. Open `https://192.168.1.20:3443` (substitute your configured value). Use that same origin consistently. Enable LAN access in setup and supply the console code.

Caddy issues a certificate using its local CA. Export the **public root certificate**, not its private key:

```bash
docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt ./host-canvas-local-ca.crt
```

Verify the CA's provenance and install it only on managed client devices using your organization's trusted-root procedure. Do not treat browser certificate warnings as a production solution. With an organizational PKI, replace the `tls internal` configuration with your organization's certificate/key mounts and secure permissions.

Compose exposes only HTTPS port 3443 to the LAN; direct web/API ports 3000/8787 bind to host loopback. The app is non-root, capabilities are dropped, root filesystems are read-only, and data is persisted in named volumes. Keep backups outside those volumes as well.

## Origin allowlists and custom reverse proxies

The console and API should share one HTTPS origin. In Settings, allow the exact console origin, including a non-default port, for example `https://hostcanvas.example.internal:3443`. Origins do not include paths. Avoid broad allowlists.

For a custom reverse proxy, put its origin in `TLS_SENTINEL_UI_ORIGINS` **before first setup**, so Host validation allows it. Set `TLS_SENTINEL_TRUST_PROXY=true` only when untrusted clients cannot reach the API directly. The proxy must replace, not append or trust client-supplied, `X-Forwarded-For` and `X-Forwarded-Proto`. The supplied Caddy configuration does this. Otherwise a proxy may hide the real client or forwarded headers may undermine access decisions.

Leave `NEXT_PUBLIC_TLS_SENTINEL_API_URL` unset in normal deployments: HTTPS uses same-origin API access. Do not bake secrets into any `NEXT_PUBLIC_*` variable. Use a VPN or organizational access gateway for remote access; this is not a publicly exposed multi-tenant SaaS service.

## Configuration reference

Native API/launchers load `TLS_SENTINEL_*` settings in this precedence order: already exported environment, `.env.<mode>.local`, `.env.local` (except test mode), `.env.<mode>`, `.env`. Restart processes after changing server configuration. Compose reads `.env` by default; use `--env-file .env.local` explicitly if required. Copying `.env.local` alone does not configure Compose interpolation.

| Variable | Default / use |
| --- | --- |
| `TLS_SENTINEL_DATA_DIR` | Local `data/`; container `/data` |
| `TLS_SENTINEL_UI_ORIGINS` | Localhost console origins; add intended custom-proxy origins |
| `TLS_SENTINEL_TRUST_PROXY` | `false`; Compose sets it for its restricted proxy topology |
| `TLS_SENTINEL_HTTPS_HOST` | `localhost`; Compose/Caddy host or IPv4 address |
| `TLS_SENTINEL_ALLOW_PRIVATE_TARGETS` | `false`; also requires the asset-level internal-target opt-in |
| `TLS_SENTINEL_PUBLIC_DNS_RESOLVER` | Unset; public-DNS disclosure, CAA and email policy checks disabled until configured |
| `TLS_SENTINEL_DNSSEC_RESOLVER` | Unset; explicit trusted validating DNS-over-TLS hostname, TCP 853; queried asset names go to that provider |
| `TLS_SENTINEL_CRT_NAME_ENABLED` | `true`; discovery still requires per-asset opt-in |
| `TLS_SENTINEL_CRT_NAME_LIMIT` | 200 new subdomain assets maximum per discovery; allowed 1–500 |
| `TLS_SENTINEL_MAX_CONCURRENT_SCANS` | 2, clamped to 1–8 |
| `TLS_SENTINEL_TESTSSL_PATH` | `testssl.sh`; executable path, not a command with flags |
| `TLS_SENTINEL_TESTSSL_TIMEOUT_MS` | 240000; clamped to 30000–900000 |
| `TLS_SENTINEL_SECRET_KEY` | Optional persistent encryption secret; otherwise a protected `.secret-key` is generated |

Legacy `TLS_SENTINEL_*` names and `tlsentinel.db` are intentional compatibility names. See [.env.example](https://github.com/gorkemguler/HostCanvas/blob/main/.env.example) and [server/config.mjs](https://github.com/gorkemguler/HostCanvas/blob/main/server/config.mjs) for the source of truth. Do not commit `.env` files, databases, private keys, webhook secrets or real inventory exports.

## Before handing it to a team

Configure workspace HSTS/cookie/CAA thresholds and scan-health incidents in **Settings → Incident check policy**. DNSSEC has a separate opt-in; the public DNS setting alone does not enable it. Read [Check policies](https://github.com/gorkemguler/HostCanvas/wiki/Check-Policies) before selecting a resolver or enabling organization-wide requirements.

- Confirm HTTPS trust and LAN authentication from a second managed client.
- Create a second enabled admin; use operator/viewer accounts for routine work.
- Confirm a viewer cannot mutate inventory or settings.
- Test backup and restore against a separate data directory.
- Confirm firewall restrictions, origin allowlist and proxy header replacement.
- Test notification delivery and observe resource use with a small authorized inventory before increasing concurrency.
