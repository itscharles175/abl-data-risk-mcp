# Platform console

The console is the React review and administration surface for Aegis Ledger. It renders role-filtered navigation, source onboarding previews, maker/checker journeys, and an optional single-facility surveillance panel. It contains no database credentials and never calls MCP directly.

## Run locally

Start the BFF first, then run from the repository root:

```sh
pnpm --filter @abl/platform-contracts build
pnpm --filter @abl/platform-console dev
```

Vite serves `http://127.0.0.1:4173` and proxies `/api` and `/health` to `http://127.0.0.1:4300`. The default experience is clearly labeled fixture data with demonstration identities.

For all three platform packages in watch mode, use:

```sh
pnpm run dev:platform
```

## Pilot workflow

The pilot panel discovers `/api/v1/pilot` before enabling the IDs-only submission form. Its default state is unavailable because the checked-in BFF launcher does not inject a governed job service. An authorized composition supplies tenant and facility scope server-side; the browser supplies only certification-manifest IDs, definition-version IDs, purpose, and an idempotency key.

## Verify

```sh
pnpm --filter @abl/platform-console check
pnpm --filter @abl/platform-console test
pnpm --filter @abl/platform-console build
```

Any UI change must also pass the repository's Vizier visual QA gate before it is reported complete.
