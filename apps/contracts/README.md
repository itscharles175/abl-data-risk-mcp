# Platform contracts

This package contains the browser-safe schemas and TypeScript types shared by the platform BFF and console. It is intentionally narrower than the root domain contract library.

Use it for:

- session, navigation, workbench, approval, and source-onboarding payloads;
- pilot capability, IDs-only start, opaque status/result, and cancellation payloads;
- strict validation at both sides of the browser/BFF boundary.

Do not add credentials, database locations, raw loan rows, trusted actor fields, or server-only authority documents to this package.

## Verify

From the repository root:

```sh
pnpm --filter @abl/platform-contracts check
pnpm --filter @abl/platform-contracts test
pnpm --filter @abl/platform-contracts build
```
