# Contributing

Thanks for helping improve ABL Data & Risk MCP. Changes should preserve its core boundary: models may propose intent, while trusted deterministic code owns authorization, data access, calculations, and audit.

## Before opening a change

1. Open an issue for material API, policy, persistence, or analytical-semantics changes.
2. Keep customer data, credentials, connection strings, and production configuration out of issues, fixtures, commits, and logs.
3. Review [SECURITY.md](./docs/SECURITY.md), [ARCHITECTURE.md](./docs/ARCHITECTURE.md), and the [release checklist](./docs/RELEASE_CHECKLIST.md) for the boundary you are changing.

## Development workflow

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm run verify
pnpm run audit:prod
```

Use exact decimal strings for financial values. Add deterministic golden tests for analytical changes and adversarial tests for identity, tenancy, persistence, parsing, or disclosure-boundary changes. Never add a generic SQL, raw-row export, source-write, or model-supplied credential path.

Pull requests should explain the user impact, trust-boundary impact, validation performed, and any remaining release gates. Keep commits focused and do not mix generated data or unrelated refactors into a functional change.

## Security reports

Do not disclose vulnerabilities in a public issue. Follow [.github/SECURITY.md](./.github/SECURITY.md).
