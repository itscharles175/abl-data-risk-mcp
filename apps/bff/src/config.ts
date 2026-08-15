import { z } from "zod";

const UrlSchema = z.string().url();

export interface OidcConfiguration {
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scopes: readonly string[];
}

export interface BffConfiguration {
  readonly authMode: "fixture" | "oidc";
  readonly production: boolean;
  readonly port: number;
  readonly consoleUrl: string;
  readonly allowedOrigins: ReadonlySet<string>;
  readonly secureCookies: boolean;
  readonly sessionTtlMs: number;
  readonly stepUpTtlMs: number;
  readonly oidcTransactionTtlMs: number;
  readonly oidcTransactionMaxEntries: number;
  readonly oidcLoginWindowMs: number;
  readonly oidcLoginMaxAttempts: number;
  readonly oidcLoginMaxKeys: number;
  readonly oidc?: OidcConfiguration;
}

function normalizedOrigin(value: string): string {
  return new URL(UrlSchema.parse(value)).origin;
}

export function loadBffConfiguration(
  env: Readonly<Record<string, string | undefined>> = process.env,
): BffConfiguration {
  const production = env.NODE_ENV === "production";
  const requestedAuthMode = env.BFF_AUTH_MODE;
  if (
    requestedAuthMode !== undefined &&
    requestedAuthMode !== "fixture" &&
    requestedAuthMode !== "oidc"
  ) {
    throw new Error("BFF_AUTH_MODE must be either 'fixture' or 'oidc'");
  }
  const authMode = requestedAuthMode ?? "fixture";
  if (production && authMode !== "oidc") {
    throw new Error("BFF_AUTH_MODE=oidc is required in production");
  }
  const consoleUrl = normalizedOrigin(env.BFF_CONSOLE_URL ?? "http://127.0.0.1:4173");
  const allowedOrigins = new Set(
    (env.BFF_ALLOWED_ORIGINS ?? consoleUrl)
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean)
      .map(normalizedOrigin),
  );
  const secureCookies = env.BFF_SECURE_COOKIES
    ? env.BFF_SECURE_COOKIES === "true"
    : env.NODE_ENV === "production";

  if (env.NODE_ENV === "production" && !secureCookies) {
    throw new Error("BFF_SECURE_COOKIES cannot be disabled in production");
  }

  const base: BffConfiguration = {
    authMode,
    production,
    port: z.coerce.number().int().min(1).max(65_535).parse(env.BFF_PORT ?? 4300),
    consoleUrl,
    allowedOrigins,
    secureCookies,
    sessionTtlMs: z.coerce.number().int().min(60_000).parse(env.BFF_SESSION_TTL_MS ?? 28_800_000),
    stepUpTtlMs: z.coerce.number().int().min(60_000).parse(env.BFF_STEP_UP_TTL_MS ?? 600_000),
    oidcTransactionTtlMs: z.coerce.number().int().min(60_000).max(900_000).parse(env.BFF_OIDC_TRANSACTION_TTL_MS ?? 600_000),
    oidcTransactionMaxEntries: z.coerce.number().int().min(16).max(100_000).parse(env.BFF_OIDC_TRANSACTION_MAX_ENTRIES ?? 4_096),
    oidcLoginWindowMs: z.coerce.number().int().min(1_000).max(3_600_000).parse(env.BFF_OIDC_LOGIN_WINDOW_MS ?? 60_000),
    oidcLoginMaxAttempts: z.coerce.number().int().min(1).max(1_000).parse(env.BFF_OIDC_LOGIN_MAX_ATTEMPTS ?? 20),
    oidcLoginMaxKeys: z.coerce.number().int().min(16).max(100_000).parse(env.BFF_OIDC_LOGIN_MAX_KEYS ?? 10_000),
  };

  if (authMode === "fixture") {
    return base;
  }

  return {
    ...base,
    oidc: {
      issuer: UrlSchema.parse(env.OIDC_ISSUER),
      clientId: z.string().min(1).parse(env.OIDC_CLIENT_ID),
      redirectUri: UrlSchema.parse(
        env.OIDC_REDIRECT_URI ?? "http://127.0.0.1:4300/api/auth/callback",
      ),
      scopes: (env.OIDC_SCOPES ?? "openid profile email roles")
        .split(/\s+/u)
        .filter(Boolean),
    },
  };
}
