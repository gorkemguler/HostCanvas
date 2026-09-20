# Creating a custom incident type

[Türkçe](https://github.com/gorkemguler/HostCanvas/wiki/Ozel-Incident-Turu-Olusturma) · [Wiki home](https://github.com/gorkemguler/HostCanvas/wiki)

## What is supported today?

An incident type is a **code-defined rule**, not a manually inserted database record. HostCanvas does not currently include a visual rule builder, YAML/JSON template upload, or automatic plugin loading. The Checks screen displays a catalog; it does not execute user-supplied code. Adding a catalog entry alone does not activate a check.

To implement a rule you:

1. Reuse a collected observation, or implement a narrowly scoped probe if the necessary data is absent.
2. Write a pure evaluator returning `pass`, `fail`, or `unknown`.
3. Register its display metadata **and call its evaluator** in `server/rules/index.mjs`.
4. Test both evaluation and incident reconciliation.
5. Restart the API (rebuild the image for Docker) and scan an authorized test asset.

The examples below match the source in this repository. They are not enabled in the default application.

## Data flow and extension points

```text
validated hostname → DNS/IP policy → pinned target → probes
                                                     ↓
                                               observations
                                                     ↓
                                      evaluateObservations(observations, asset)
                                                     ↓
                                  pass / fail / unknown → reconcileIncidents
                                                     ↓
                                     incident history + opened/reopened events
```

| File | Responsibility |
| --- | --- |
| `server/security/targets.mjs` | Normalize hostnames, validate all resolved addresses, pin an allowed address |
| `server/probes/` | Collect bounded network observations |
| `server/scanner.mjs` | Orchestrate probes, evaluate, save scans, reconcile incidents, dispatch notifications |
| `server/rules/index.mjs` | Catalog and executable evaluation logic |
| `server/db.mjs` | Stable incident identity, history, automatic resolution and reopening |
| `server/notifications.mjs` | Generic/Slack delivery after incident opening or reopening |

The observation container has `schemaVersion: 1`. Existing sources include `tls.certificate`, `http.headers`, `http.cookies`, `publicDns`, and `testssl.findings`. Inspect the relevant probe before relying on a field: an HTTP probe error, a missing field, and a confirmed missing header are not equivalent.

The `policy` argument of `evaluateObservations` is the asset object, not an arbitrary user-defined policy document. For example, existing rules use its `expiryWarningDays`. New settings require API validation, persistence, UI and tests; inventing `policy.myThreshold` does not create a setting.

## Worked example: organization certificate-lifetime policy

Requirement: flag a certificate whose **total validity period** exceeds the organization's chosen limit. This is different from the existing renewal warning, which measures **time remaining**.

The example uses 90 days as an illustrative internal policy, **not as a claim about CA/Browser Forum requirements or a universal vulnerability threshold**. Adapt the limit and severity to your organization.

### 1. Start with the tested evaluator

The complete runnable module is [examples/custom-check/certificate-validity.mjs](https://github.com/gorkemguler/HostCanvas/blob/main/examples/custom-check/certificate-validity.mjs). Its tests are [tests/custom-check-example.test.mjs](https://github.com/gorkemguler/HostCanvas/blob/main/tests/custom-check-example.test.mjs).

From the repository root, copy it once to your new production module; do not overwrite an existing customization:

```bash
cp -n examples/custom-check/certificate-validity.mjs server/rules/certificate-validity.mjs
node --test tests/custom-check-example.test.mjs
```

Its interface is:

```js
evaluateCertificateValidity(observations, { maxDays: 90 });
```

It validates the policy, checks that both dates exist and parse correctly, rejects inverted/zero-length intervals, compares the exact duration, and emits one evaluation. Missing evidence or invalid policy produces `unknown`, not `pass`. It performs no network requests and reads no database or environment variables.

A failing result looks like:

```js
{
  ruleKey: 'custom.cert_validity_too_long',
  status: 'fail',
  severity: 'low',
  title: 'Certificate lifetime exceeds organization policy',
  description: 'The certificate validity period exceeds the configured 90-day policy. Review issuance and renewal settings.',
  evidence: {
    validFrom: '2026-01-01T00:00:00.000Z',
    validTo: '2026-04-02T00:00:00.000Z',
    lifetimeDays: 91,
    maxDays: 90,
  },
}
```

### 2. Import and register it

At the top of `server/rules/index.mjs`, add:

```js
import { evaluateCertificateValidity } from './certificate-validity.mjs';
```

Add this object to the existing `ruleCatalog` array:

```js
{
  key: 'custom.cert_validity_too_long',
  title: 'Certificate lifetime exceeds organization policy',
  category: 'Certificate policy',
  severity: 'low',
  source: 'Native TLS',
  enabled: true,
  recommendedCadence: 'daily',
},
```

Important: `enabled` is catalog metadata, **not a universal runtime switch**. `recommendedCadence` is a displayed recommendation, **not a per-rule scheduler**. The current scheduler runs an asset's selected scan profile at its configured interval. A disabled catalog flag alone will not prevent a directly called evaluator from running.

### 3. Wire the evaluator into the running engine

Inside `evaluateObservations(observations, policy, checkPolicy)`, immediately before its final `return results;`, add:

```js
results.push(evaluateCertificateValidity(observations, { maxDays: 90 }));
```

`policy` is the asset policy; the optional third argument `checkPolicy` is the saved workspace HSTS/cookie/CAA policy. Existing two-argument callers use workspace defaults. This example uses its own fixed `maxDays` setting. Adding editable custom settings requires extending validation, persistence and the admin UI; it is not enough to send arbitrary new keys to `/api/check-policy` (unknown keys are rejected). See [Check policies](https://github.com/gorkemguler/HostCanvas/wiki/Check-Policies).

Keep this outside branches belonging to unrelated HTTP, DNS or deep-scan checks. This example reuses native TLS observations, so it needs no change to `server/scanner.mjs`, no new network probe, and no database migration. It will run in both native and deep profiles because both collect native TLS data.

The example threshold is a code constant. To expose it in Settings or per asset, implement validated input, persistent storage/defaults, frontend controls, role checks and migration/backward-compatibility tests first.

### 4. Check integration as well as the example

After copying the evaluator, adapt the example tests to import your production module. Add an assertion in your rule tests that `evaluateObservations(...)` includes the new key; unit-testing only the standalone function will not catch a forgotten integration call.

```js
import assert from 'node:assert/strict';
import { evaluateObservations, ruleCatalog } from '../server/rules/index.mjs';

const key = 'custom.cert_validity_too_long';
const results = evaluateObservations({}, { expiryWarningDays: 30 });
assert.equal(results.find((item) => item.ruleKey === key)?.status, 'unknown');
assert.ok(ruleCatalog.some((item) => item.key === key));
```

This assertion intentionally fails before activation: the repository's example is not a default check. Also test a complete risky observation and a healthy one through the integrated function.

```bash
npm test
npm run lint
npx tsc --noEmit
npm run build
npm run test:web
```

Restart the API after a production edit. With Compose, rebuild and restart the app (`docker compose up --build -d app`). Run a scan against an authorized test hostname, inspect the scan's evaluations and the Checks/Incidents screens, then scan again to verify the same incident is updated rather than duplicated. Tests use synthetic observations and a temporary database; they do not scan third-party domains.

## Evaluation contract

| Field | Meaning |
| --- | --- |
| `ruleKey` | Stable, namespaced identifier; must match the catalog entry |
| `status` | Exactly `pass`, `fail`, or `unknown` |
| `severity` | Required for failures: `critical`, `high`, `medium`, or `low` |
| `title`, `description` | Required for failures; readable text, preferably with remediation context |
| `evidence` | Small JSON-serializable facts sufficient to explain the result |
| `discriminator` | Optional stable identifier for multiple independent findings under one asset/rule |
| `reason` | Optional diagnostic metadata for your evaluator/tests; not a guaranteed UI field |

Never put session tokens, passwords, full cookie values or unbounded raw responses in evidence. Evidence is stored with scans/incidents and becomes part of backups. UI text must remain escaped; do not render finding content using unsafe HTML.

Titles returned by custom rules are displayed as supplied. Adding a title does not automatically generate an English/Turkish translation. Plan explicit localization if your team needs it.

## Incident identity and lifecycle

Identity is:

```text
assetId : ruleKey : (discriminator || "default")
```

Keep the key stable after release. Changing it creates a new incident family; removing a rule does not automatically close its old incidents. Do not use timestamps, scan IDs, changing expiry dates or certificate fingerprints as discriminators for one ongoing operational problem.

| Evaluation / previous state | Result | Automatic webhook event |
| --- | --- | --- |
| `fail`, no prior incident | Create `open`, occurrence count 1 | `incident.opened` |
| `fail`, open/acknowledged | Update evidence, severity, last seen and count; preserve status | None |
| `unknown`, any state | Leave prior incident unchanged | None |
| `pass`, active matching rule | Resolve it and record history | None |
| `fail`, previously resolved | Reopen the same incident ID, increment count | `incident.reopened` |

Manual statuses are `open`, `acknowledged`, and `resolved`. Manual resolution is not permanent suppression: a later failing scan reopens the incident. Acknowledging it also does not disable the rule.

### Critical caveat for multiple findings

In the current implementation, a `pass` resolves **all active incidents for the same asset and rule key**, regardless of `discriminator`. Do not return a per-item `pass` together with per-item failures for the same rule. Result ordering could otherwise close a real finding.

For a simple multi-item rule, emit failures for each confirmed risky item and emit one aggregate `pass` only when the whole set was successfully checked and no failures remain. This conservative approach may keep a disappeared sibling incident open while another sibling is still failing.

For precise reconciliation of dynamic result sets, `reconcileIncidents` supports `completePrefixes`. The current scanner uses only `testssl.` after a **complete** deep scan. A custom adapter must deliberately supply its own narrowly owned namespace only after proving full coverage. Do not reuse broad prefixes like `cert.` or `http.`, and do not use SQL LIKE wildcard characters (`%`, `_`) in such a prefix: it is passed to a `LIKE` query. Partial scans, missing engines, timeouts and parser failures must never claim completeness. Avoid this advanced path for a single-result rule like the example.

## When a new probe is needed

Rules should not initiate I/O. Add a probe under `server/probes/` and wire its bounded result into `server/scanner.mjs` first. Reuse the target validation/pinning model; never call `fetch(userInput)` or interpolate a hostname into a shell command. If following another hostname or redirect, validate and pin that destination too.

Define a schema/version, timeout, response limit, parser-failure result and completeness semantics. Keep secret material out of observations. For subprocesses use fixed executable/arguments, a constrained environment, output/file limits, and process-group cleanup. Add private-IP, mapped IPv6, rebinding, malformed output, timeout and resource-limit tests as applicable.

A dangling CNAME or unexpected header is not automatically proof of takeover or exploitation. Define what your evidence actually proves and name the incident accordingly.

## Notifications and grading

Custom failures use the existing incident and notification pipeline; there is no need to send webhooks from a rule. Enabled channels apply their minimum severity to opening/reopening events. Therefore this example's `low` finding will not reach a channel configured for `high` or `critical` only. Repeated failures and automatic resolutions do not currently send webhook events.

The grade uses failed severities: critical → F, high → C, medium → B, low → A-, no failures → A. It is not an SSL Labs score. Unknown/unavailable checks can coexist with A; inspect coverage and scan status separately.

## Troubleshooting checklist

- Listed in Checks but never produces an evaluation: confirm the evaluator call, not just the catalog entry.
- Works in a unit test but not the running app: restart the API/rebuild the Docker image; inspect actual observation field names.
- Existing incident closes after incomplete scans: check that missing evidence returns `unknown` and no overly broad completeness prefix is supplied.
- Duplicate incidents: inspect changing keys/discriminators; do not key by scan ID or fingerprint.
- No webhook: check severity threshold, enabled channel, delivery history, and whether the incident was merely updated rather than opened/reopened.
- Policy change has no immediate effect: schedule a new scan. Existing incidents are reconciled on evaluation, not on a code edit alone.

Before rollout, back up the database and encryption key, test against fixtures and authorized assets, review the diff, and record the new rule's owner, evidence requirements and remediation procedure.
