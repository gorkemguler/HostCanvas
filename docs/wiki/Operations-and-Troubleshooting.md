# Operations and troubleshooting

[Türkçe](https://github.com/gorkemguler/HostCanvas/wiki/Operasyon-ve-Sorun-Giderme) · [Home](https://github.com/gorkemguler/HostCanvas/wiki)

## Roles and daily operations

| Role | Capabilities |
| --- | --- |
| Admin | Workspace/access settings, users, notifications, audit, retention/backups, all operational actions |
| Operator | Add/edit/archive/scan assets and manage incident status |
| Viewer | Read dashboards, assets, scans, checks and incidents |

Manage users in Settings → Administration center. Keep two enabled administrators and use least privilege for routine work. Last-admin protection prevents removing the final enabled admin through ordinary access management. Disabling a user invalidates their sessions. Keep the server, backups and logs accessible only to trusted administrators.

Each day inspect failed/partial scans, overdue assets, queue growth, delivery errors, latest backup age, unexpected audit events and available disk space. A green liveness endpoint alone is not proof that scans or backups are succeeding.

## Webhook channels

Create an enabled generic or Slack channel, select its minimum severity, and send a test notification before relying on it. Full webhook URLs are encrypted at rest and are not returned by the API. Protect the encryption key with backups.

Destinations must be public HTTPS URLs on port 443. DNS is validated and the connection is pinned to an allowed IP. Internal or custom-port endpoints are intentionally rejected; the internal-target scan flag does not relax webhook policy.

Generic payload outline:

```json
{
  "event": "incident.opened",
  "sentAt": "2026-01-01T00:00:00.000Z",
  "message": "Human-readable incident summary",
  "incident": {
    "id": "incident-id",
    "severity": "high",
    "status": "open",
    "title": "Finding title",
    "description": "Finding description",
    "hostname": "api.example.com",
    "port": 443,
    "owner": "Platform",
    "ruleKey": "cert.hostname_mismatch",
    "firstSeenAt": "2026-01-01T00:00:00.000Z",
    "lastSeenAt": "2026-01-01T00:00:00.000Z"
  }
}
```

Events are `incident.opened`, `incident.reopened` and the manual test `incident.test` (test incident is null). Slack uses a `text` payload. Raw evidence is not included in the generic incident payload. There is no automatic resolution or repeated-failure notification currently.

Each attempt has an eight-second total deadline, including DNS, with up to three attempts for transient failures. Response bodies are capped at 64 KiB, active deliveries at four and waiting deliveries at 256. Scans do not wait for delivery. Delivery history is persistent, but the waiting queue is **in memory**, not a durable outbox: interrupted pending work is not replayed after restart.

Timeout retries may deliver the same event twice. Consumers should be idempotent; incident ID + event kind + the event's `lastSeenAt` can help distinguish a retry from a later reopening. Using only incident ID forever would also suppress legitimate later reopenings. A durable outbox and explicit delivery/idempotency IDs are future work.

## Backup, retention and secrets

By default, hourly maintenance creates a verified SQLite backup every 24 hours, retains 14 backups, removes completed scan history older than 180 days and raw artifacts older than 30 days. Configure these in Settings → Administration center → Data. Retention is not a blanket deletion policy for all incident/audit history.

Native manual backup (the app may remain running):

```bash
npm run backup
```

Container backup:

```bash
docker compose exec app npm run backup
# Substitute the exact filename printed by the command:
docker compose cp app:/data/backups/tlsentinel-YYYYMMDDTHHMMSSZ.db ./
```

The UI also creates and downloads backups. Keep selected copies on separate encrypted storage and test them. Same-volume copies do not protect against volume loss. Back up the persistent `TLS_SENTINEL_SECRET_KEY` or generated `/data/.secret-key` separately and securely; without it restored webhook URLs cannot be decrypted. A SQLite backup is not an archive of every raw testssl artifact or Caddy's PKI state.

POSIX data directories use `0700` and database/backup/secret files use `0600`; startup also tightens existing permissions. Container volume ownership should be `10001:10001`. Do not solve permission errors with world-writable permissions.

## Controlled restore

Restoring replaces application state. Verify the source and take an off-volume recovery copy first. Use a compatible application version, stop all writers, and retain the original encryption key.

Native (stop the app first):

```bash
npm run restore -- /absolute/path/backup.db --confirm
```

Compose:

```bash
docker compose cp ./backup.db app:/data/backups/restore-source.db
docker compose stop app
docker compose run --rm app npm run restore -- /data/backups/restore-source.db --confirm
docker compose up -d app
```

The restore utility checks SQLite integrity/required tables, uses an exclusive data-directory lock, and creates a `pre-restore-*` recovery copy before replacing the database. It refuses to run against an active app/backup lock. Do not delete lock files or bypass the guard to force a live restore. Test this workflow in a separate environment before an incident.

After restoration verify login, users, asset counts, recent scans, incident history and webhook decryption/test delivery. Restarted instances may recover interrupted scans. Monitor the first maintenance cycle.

## Health and resource boundaries

- `/api/health/live` is the minimal pre-auth liveness route; `/api/health` is subject to workspace access controls and includes more detail.
- Compose defaults to 2 GiB application memory, 256 processes, a 128 MiB `/tmp`, rotating logs and graceful shutdown time. Measure before scaling scans.
- testssl stdout/stderr, JSON artifact and POSIX per-file output are capped. Some testssl versions use `/tmp` directly; native installations still need an OS quota or separate temporary filesystem for a total disk bound.
- Graceful shutdown stops new work and cleans up scanner children. It does not provide durable webhook replay.

## Common problems

| Symptom | Checks |
| --- | --- |
| Setup code rejected | Read the current API process's console; reload an expired wizard and use the new code. Do not publish setup codes in screenshots/issues. |
| LAN login fails | Check HTTPS, LAN enablement, exact origin/port, certificate trust, proxy replacement headers and firewall. |
| Invalid Host | Configure the intended hostname in `TLS_SENTINEL_UI_ORIGINS` / Compose HTTPS host before startup. |
| Deep engine unavailable | Check executable path, execution permission and supported version; do not put arbitrary flags in the executable setting. |
| DNS rules unknown | Configure a reachable public resolver and inspect its result; unknown is not a healthy conclusion. |
| Old grade after a failure | This is the preserved last useful snapshot; inspect scan timestamp/status and fix the underlying error. |
| Another API/restore cannot start | Check for an existing process using the data directory; stop it cleanly. Do not remove active lock files. |
| Webhook not received | Check severity, opened/reopened vs repeated failure, enabled channel, public HTTPS destination and delivery history. |
| Webhook fails after restore | Verify the original encryption secret was restored and matches the encrypted records. |

## Verification and current limitations

From the repository root:

```bash
npm ci
npm test
npm run lint
npx tsc --noEmit
npm run test:e2e
npm run build
npm run test:web
npm audit --audit-level=high
```

The automated tests include isolated local fixtures. Dependency audit results are time-sensitive and are not a complete security assessment. CI also validates Compose and Caddy syntax; that is not a full deployment/restore drill on your infrastructure.

Current omissions include visual rule authoring, durable webhook outbox, email delivery, SSO/OIDC, per-asset tenancy, snooze/maintenance windows and complete attack-surface discovery. Record these constraints in your operating procedure rather than assuming they exist.
