# Contributing to HostCanvas

HostCanvas welcomes focused fixes, new checks, documentation improvements, and test coverage. Please keep every contribution local-first and safe for defensive use.

## Development setup

Requirements:

- Node.js 24.9 or newer
- npm
- Optional: `testssl.sh` 3.2.x for deep-scan development

```bash
npm ci
cp .env.example .env.local
npm run dev
```

Before opening a pull request, run:

```bash
npm run lint
npx tsc --noEmit
npm test
npm run build
```

## Adding security checks

Follow [docs/adding-a-check.md](docs/adding-a-check.md). Keep probes and rules separate, use the `pass / fail / unknown` model, and add tests for incident lifecycle behavior. An `unknown` result must never resolve an open incident.

## Safety requirements

- Never add hidden telemetry or upload inventory data by default.
- Never weaken hostname, IP-range, origin, authorization, or SSRF protections.
- Do not add arbitrary shell interpolation or user-controlled scanner flags.
- Use only assets you own or have explicit authorization to scan in examples and tests.
- Do not commit `.env` files, databases, backups, artifacts, credentials, or real domain inventories.

## Pull requests

Keep changes scoped, explain the operational impact, and include tests when behavior changes. By contributing, you agree that your contribution is licensed under the repository's MIT License.
