# Platform BFF

The BFF is the browser trust boundary for the Aegis Ledger console. It owns authentication flows, HTTP-only sessions, CSRF and Origin enforcement, role checks, step-up state, and server-side adaptation of browser requests. The browser does not call MCP or receive service credentials.

## Run locally

From the repository root:

```sh
pnpm --filter @abl/platform-contracts build
pnpm --filter @abl/platform-bff dev
```

The process binds to `127.0.0.1:4300` by default. The checked-in development launcher uses fixture authentication and the fixture platform adapter. Never expose fixture mode through a public bind, tunnel, or reverse proxy.

## Configuration

[`.env.example`](./.env.example) documents the variables. Configuration is read from the process environment; the BFF does not automatically load a `.env` file. Production mode fails closed unless `BFF_AUTH_MODE=oidc`; it also requires secure cookies and an OIDC Authorization Code + PKCE configuration. TLS termination, an approved session store, client registration, and production secrets are deployment responsibilities.

The optional governed pilot API is injected through `buildApp({ pilotJobs: ... })`. The normal `src/index.ts` launcher does not inject it. Without that dependency, `/api/v1/pilot` reports the capability unavailable and no surveillance job can be started from the browser.

## Verify

```sh
pnpm --filter @abl/platform-bff check
pnpm --filter @abl/platform-bff test
pnpm --filter @abl/platform-bff build
```

The BFF is not the portfolio authority. Any injected adapter or pilot service must independently reauthorize tenant, facility, principal, role, and purpose at its own boundary.
