import { createHash } from "node:crypto";

import { decodeJwt } from "jose/jwt/decode";
import { jwtVerify } from "jose/jwt/verify";
import {
  createRemoteJWKSet,
  customFetch,
  type FetchImplementation,
  type RemoteJWKSet,
} from "jose/jwks/remote";
import type { JWTPayload, JWSAlgorithm } from "jose";

import {
  createVerifiedPrincipalContext,
  type VerifiedPrincipalContext,
} from "./identity.js";

const DEFAULT_MAXIMUM_TOKEN_LENGTH = 16_384;
const DEFAULT_MAXIMUM_TOKEN_LIFETIME_SECONDS = 3_600;
const DEFAULT_JWKS_TIMEOUT_MS = 3_000;
const DEFAULT_JWKS_COOLDOWN_MS = 30_000;
const DEFAULT_JWKS_CACHE_MAX_AGE_MS = 600_000;

const REQUIRED_ACCESS_TOKEN_CLAIMS = Object.freeze([
  "iss",
  "sub",
  "aud",
  "exp",
  "iat",
  "resource",
]);

const ASYMMETRIC_JWS_ALGORITHMS = new Set<AllowedJwtAlgorithm>([
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "Ed25519",
  "EdDSA",
]);

export type AllowedJwtAlgorithm =
  | "RS256"
  | "RS384"
  | "RS512"
  | "PS256"
  | "PS384"
  | "PS512"
  | "ES256"
  | "ES384"
  | "ES512"
  | "Ed25519"
  | "EdDSA";

export type OAuthAuthenticationErrorCode =
  | "MISSING_BEARER_TOKEN"
  | "MALFORMED_AUTHORIZATION"
  | "TOKEN_TOO_LARGE"
  | "UNKNOWN_ISSUER"
  | "INVALID_TOKEN"
  | "MISSING_REQUIRED_CLAIM"
  | "INVALID_RESOURCE"
  | "TENANT_MEMBERSHIP_DENIED"
  | "TENANT_RESOLUTION_FAILED"
  | "INVALID_AUTHENTICATOR_CONFIGURATION";

export type BearerChallengeError = "invalid_request" | "invalid_token" | "insufficient_scope";

/**
 * A deliberately low-detail authentication error safe to serialize or log.
 * It never retains a credential, decoded claims, a JOSE error, or an exception
 * cause. Operators should aggregate `code` rather than logging request headers.
 */
export class OAuthAuthenticationError extends Error {
  readonly code: OAuthAuthenticationErrorCode;
  readonly httpStatus: number;
  readonly challengeError?: BearerChallengeError;

  constructor(
    code: OAuthAuthenticationErrorCode,
    message: string,
    httpStatus: number,
    challengeError?: BearerChallengeError,
  ) {
    super(message);
    this.name = "OAuthAuthenticationError";
    this.code = code;
    this.httpStatus = httpStatus;
    if (challengeError !== undefined) this.challengeError = challengeError;
  }

  toJSON(): Readonly<Record<string, string | number>> {
    return Object.freeze({
      name: this.name,
      code: this.code,
      message: this.message,
      httpStatus: this.httpStatus,
      ...(this.challengeError === undefined ? {} : { challengeError: this.challengeError }),
    });
  }
}

export interface RemoteJwksConfiguration {
  readonly timeoutDurationMs?: number;
  readonly cooldownDurationMs?: number;
  readonly cacheMaxAgeMs?: number;
}

export interface OAuthIssuerConfiguration {
  /** Exact, allowlisted `iss` value. It is never learned dynamically from a token. */
  readonly issuer: string;
  /** Explicit HTTPS endpoint used by jose's cached, rotation-aware remote JWKS resolver. */
  readonly jwksUri: string;
  /** At least one of these values must match the JWT `aud` claim. */
  readonly audiences: readonly string[];
  /** At least one of these values must match the JWT `resource` claim. */
  readonly resources: readonly string[];
  /** Only asymmetric algorithms are accepted; HMAC and `none` are prohibited. */
  readonly algorithms: readonly AllowedJwtAlgorithm[];
  /** Additive required claims. Core access-token claims cannot be disabled. */
  readonly requiredClaims?: readonly string[];
  /** Accepted JWT `typ` values, compared case-insensitively. Defaults to `at+jwt`. */
  readonly acceptedTokenTypes?: readonly string[];
  /** Alternative claims for OAuth client identity. Defaults to `client_id`, then `azp`. */
  readonly clientIdClaims?: readonly string[];
  /** Claim containing a space-delimited string or array of scopes. Defaults to `scope`. */
  readonly scopeClaim?: string;
  readonly maximumTokenLifetimeSeconds?: number;
  readonly remoteJwks?: RemoteJwksConfiguration;
}

/**
 * Minimal verified identity supplied to the server-owned membership resolver.
 * Arbitrary token claims and the bearer token are intentionally absent.
 */
export interface TenantMembershipLookup {
  readonly issuer: string;
  readonly subject: string;
  readonly clientId: string;
  readonly audiences: readonly string[];
  readonly resourceIndicators: readonly string[];
  readonly scopes: readonly string[];
  readonly credentialFingerprint: string;
}

export interface TenantMembership {
  readonly tenantId: string;
  readonly principalId: string;
}

/**
 * Implementations resolve an issuer/subject/client tuple against a server-side
 * directory. They must not accept a tenant chosen in MCP tool arguments.
 */
export interface TenantMembershipResolver {
  resolveTenantMembership(lookup: TenantMembershipLookup): Promise<TenantMembership | null>;
}

export interface JwtOAuthAuthenticatorConfiguration {
  readonly issuers: readonly OAuthIssuerConfiguration[];
  readonly tenantMembershipResolver: TenantMembershipResolver;
  readonly maximumTokenLength?: number;
}

export interface JwtOAuthAuthenticatorDependencies {
  /** Trusted fetch adapter for egress controls, proxies, and deterministic tests. */
  readonly jwksFetch?: FetchImplementation;
  readonly now?: () => Date;
}

export interface JwtOAuthAuthenticator {
  authenticateAuthorizationHeader(
    authorizationHeader: string | readonly string[] | undefined,
  ): Promise<VerifiedPrincipalContext>;
}

interface NormalizedIssuerConfiguration {
  readonly issuer: string;
  readonly audiences: readonly string[];
  readonly resources: readonly string[];
  readonly algorithms: readonly AllowedJwtAlgorithm[];
  readonly requiredClaims: readonly string[];
  readonly acceptedTokenTypes: ReadonlySet<string>;
  readonly clientIdClaims: readonly string[];
  readonly scopeClaim: string;
  readonly maximumTokenLifetimeSeconds: number;
  readonly jwks: RemoteJWKSet;
}

/**
 * Creates a fail-closed JWT bearer authenticator. Unverified `iss` is used only
 * as an exact lookup key into the configured allowlist; it cannot introduce a
 * JWKS URL. A separate jose remote resolver is created once per allowlisted
 * issuer and retains its in-memory key cache across requests.
 */
export function createJwtOAuthAuthenticator(
  configuration: JwtOAuthAuthenticatorConfiguration,
  dependencies: JwtOAuthAuthenticatorDependencies = {},
): JwtOAuthAuthenticator {
  if (
    !configuration ||
    !Array.isArray(configuration.issuers) ||
    configuration.issuers.length === 0 ||
    configuration.issuers.length > 64 ||
    !configuration.tenantMembershipResolver ||
    typeof configuration.tenantMembershipResolver.resolveTenantMembership !== "function"
  ) {
    configurationError("At least one issuer and a tenant membership resolver are required");
  }

  const maximumTokenLength = boundedInteger(
    configuration.maximumTokenLength ?? DEFAULT_MAXIMUM_TOKEN_LENGTH,
    "maximumTokenLength",
    1_024,
    65_536,
  );
  const now = dependencies.now ?? (() => new Date());
  const issuers = new Map<string, NormalizedIssuerConfiguration>();

  for (const issuer of configuration.issuers) {
    const normalized = normalizeIssuerConfiguration(issuer, dependencies.jwksFetch);
    if (issuers.has(normalized.issuer)) configurationError("Issuer allowlist contains a duplicate");
    issuers.set(normalized.issuer, normalized);
  }

  const resolver = configuration.tenantMembershipResolver;

  return Object.freeze({
    async authenticateAuthorizationHeader(
      authorizationHeader: string | readonly string[] | undefined,
    ): Promise<VerifiedPrincipalContext> {
      const token = parseBearerAuthorization(authorizationHeader, maximumTokenLength);
      let unverified: JWTPayload;
      try {
        unverified = decodeJwt(token);
      } catch {
        throw authenticationError("INVALID_TOKEN");
      }

      if (typeof unverified.iss !== "string") {
        throw authenticationError("MISSING_REQUIRED_CLAIM");
      }
      const issuer = issuers.get(unverified.iss);
      if (!issuer) throw authenticationError("UNKNOWN_ISSUER");

      const verificationDate = now();
      if (!(verificationDate instanceof Date) || !Number.isFinite(verificationDate.getTime())) {
        throw authenticationError("INVALID_TOKEN");
      }
      const verifiedAtEpochSeconds = Math.floor(verificationDate.getTime() / 1_000);

      let payload: JWTPayload;
      let protectedType: unknown;
      try {
        const verified = await jwtVerify(token, issuer.jwks, {
          issuer: issuer.issuer,
          audience: [...issuer.audiences],
          algorithms: issuer.algorithms as readonly JWSAlgorithm[] as JWSAlgorithm[],
          requiredClaims: [...issuer.requiredClaims],
          clockTolerance: 0,
          currentDate: verificationDate,
        });
        payload = verified.payload;
        protectedType = verified.protectedHeader.typ;
      } catch {
        throw authenticationError("INVALID_TOKEN");
      }

      if (
        typeof protectedType !== "string" ||
        !issuer.acceptedTokenTypes.has(protectedType.toLowerCase())
      ) {
        throw authenticationError("INVALID_TOKEN");
      }

      const tokenTimes = validatedTokenTimes(
        payload,
        verifiedAtEpochSeconds,
        issuer.maximumTokenLifetimeSeconds,
      );
      const subject = requiredTokenText(payload.sub);
      const audiences = tokenStringSet(payload.aud, "aud");
      const resourceIndicators = tokenStringSet(payload.resource, "resource");
      if (!hasIntersection(resourceIndicators, issuer.resources)) {
        throw authenticationError("INVALID_RESOURCE");
      }
      const clientId = resolveClientId(payload, issuer.clientIdClaims);
      const scopes = tokenScopes(payload[issuer.scopeClaim]);
      const authenticationMethods = tokenOptionalStringSet(payload.amr, "amr");
      const credentialFingerprint = createHash("sha256").update(token).digest("hex");

      const lookup = Object.freeze({
        issuer: issuer.issuer,
        subject,
        clientId,
        audiences: Object.freeze(audiences),
        resourceIndicators: Object.freeze(resourceIndicators),
        scopes: Object.freeze(scopes),
        credentialFingerprint,
      });

      let membership: TenantMembership | null;
      try {
        membership = await resolver.resolveTenantMembership(lookup);
      } catch {
        throw authenticationError("TENANT_RESOLUTION_FAILED");
      }
      if (!membership) throw authenticationError("TENANT_MEMBERSHIP_DENIED");

      try {
        return createVerifiedPrincipalContext({
          issuer: issuer.issuer,
          subject,
          principalId: membership.principalId,
          tenantId: membership.tenantId,
          clientId,
          audiences,
          resourceIndicators,
          scopes,
          credentialFingerprint,
          verifiedAtEpochSeconds,
          ...(tokenTimes.notBeforeEpochSeconds === undefined
            ? {}
            : { notBeforeEpochSeconds: tokenTimes.notBeforeEpochSeconds }),
          expiresAtEpochSeconds: tokenTimes.expiresAtEpochSeconds,
          authenticationMethods,
        });
      } catch {
        throw authenticationError("INVALID_TOKEN");
      }
    },
  });
}

/** Extracts one JWT bearer credential while rejecting combined or ambiguous headers. */
export function parseBearerAuthorization(
  authorizationHeader: string | readonly string[] | undefined,
  maximumTokenLength = DEFAULT_MAXIMUM_TOKEN_LENGTH,
): string {
  boundedInteger(maximumTokenLength, "maximumTokenLength", 1_024, 65_536);
  if (authorizationHeader === undefined) throw authenticationError("MISSING_BEARER_TOKEN");
  if (typeof authorizationHeader !== "string") {
    throw authenticationError("MALFORMED_AUTHORIZATION");
  }
  if (/[\u0000-\u001f\u007f]/.test(authorizationHeader)) {
    throw authenticationError("MALFORMED_AUTHORIZATION");
  }
  const match = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)$/i.exec(
    authorizationHeader,
  );
  if (!match) throw authenticationError("MALFORMED_AUTHORIZATION");
  const token = match[1]!;
  if (token.length > maximumTokenLength) throw authenticationError("TOKEN_TOO_LARGE");
  return token;
}

export interface ProtectedResourceMetadataConfiguration {
  readonly resource: string;
  readonly authorizationServers?: readonly string[];
  readonly scopesSupported?: readonly string[];
  readonly resourceName?: string;
  readonly resourceDocumentation?: string;
}

export interface ProtectedResourceMetadata {
  readonly resource: string;
  readonly authorization_servers?: readonly string[];
  readonly bearer_methods_supported: readonly ["header"];
  readonly scopes_supported?: readonly string[];
  readonly resource_name?: string;
  readonly resource_documentation?: string;
}

/** Builds the unsigned RFC 9728 metadata document served by the protected resource. */
export function createProtectedResourceMetadata(
  configuration: ProtectedResourceMetadataConfiguration,
): ProtectedResourceMetadata {
  const resource = validatedResourceIdentifier(configuration.resource, "resource");
  const authorizationServers = configuration.authorizationServers?.map((issuer) =>
    validatedIssuerIdentifier(issuer, "authorization server"),
  );
  if (authorizationServers && new Set(authorizationServers).size !== authorizationServers.length) {
    configurationError("authorizationServers contains a duplicate");
  }
  const scopes =
    configuration.scopesSupported === undefined
      ? undefined
      : normalizedIdentifiers(configuration.scopesSupported, "scopesSupported", true);
  const resourceName =
    configuration.resourceName === undefined
      ? undefined
      : boundedText(configuration.resourceName, "resourceName", 256);
  const resourceDocumentation =
    configuration.resourceDocumentation === undefined
      ? undefined
      : validatedHttpsUrl(configuration.resourceDocumentation, "resourceDocumentation", true);

  return Object.freeze({
    resource,
    ...(authorizationServers === undefined || authorizationServers.length === 0
      ? {}
      : { authorization_servers: Object.freeze(authorizationServers) }),
    bearer_methods_supported: Object.freeze(["header"] as const),
    ...(scopes === undefined || scopes.length === 0
      ? {}
      : { scopes_supported: Object.freeze(scopes) }),
    ...(resourceName === undefined ? {} : { resource_name: resourceName }),
    ...(resourceDocumentation === undefined
      ? {}
      : { resource_documentation: resourceDocumentation }),
  });
}

/** Derives the deterministic RFC 9728 well-known URL for a resource identifier. */
export function protectedResourceMetadataUrl(resourceIdentifier: string): string {
  const resource = new URL(validatedResourceIdentifier(resourceIdentifier, "resource"));
  const resourcePath = resource.pathname === "/" ? "" : resource.pathname;
  resource.pathname = `/.well-known/oauth-protected-resource${resourcePath}`;
  return resource.href;
}

export interface BearerWwwAuthenticateOptions {
  readonly resourceMetadataUrl: string;
  readonly realm?: string;
  readonly error?: BearerChallengeError;
  readonly scope?: readonly string[];
}

/** Creates an RFC 9728/RFC 6750 Bearer challenge without credential-derived text. */
export function createBearerWwwAuthenticate(
  options: BearerWwwAuthenticateOptions,
): string {
  const metadataUrl = validatedHttpsUrl(
    options.resourceMetadataUrl,
    "resourceMetadataUrl",
    true,
  );
  const parameters = [`resource_metadata=${quoted(metadataUrl)}`];
  if (options.realm !== undefined) {
    parameters.push(`realm=${quoted(boundedText(options.realm, "realm", 256))}`);
  }
  if (options.error !== undefined) parameters.push(`error=${quoted(options.error)}`);
  if (options.scope !== undefined) {
    const scopes = normalizedIdentifiers(options.scope, "scope", true);
    if (scopes.length > 0) parameters.push(`scope=${quoted(scopes.join(" "))}`);
  }
  return `Bearer ${parameters.join(", ")}`;
}

/** Maps a stable authentication error to a token-free Bearer challenge. */
export function createBearerChallengeForError(
  error: OAuthAuthenticationError,
  resourceMetadataUrlValue: string,
  options: Readonly<{ realm?: string; scope?: readonly string[] }> = {},
): string {
  if (!(error instanceof OAuthAuthenticationError)) {
    throw authenticationError("INVALID_AUTHENTICATOR_CONFIGURATION");
  }
  return createBearerWwwAuthenticate({
    resourceMetadataUrl: resourceMetadataUrlValue,
    ...(options.realm === undefined ? {} : { realm: options.realm }),
    ...(error.challengeError === undefined ? {} : { error: error.challengeError }),
    ...(options.scope === undefined ? {} : { scope: options.scope }),
  });
}

function normalizeIssuerConfiguration(
  configuration: OAuthIssuerConfiguration,
  fetcher: FetchImplementation | undefined,
): NormalizedIssuerConfiguration {
  const issuer = validatedIssuerIdentifier(configuration.issuer, "issuer");
  const jwksUri = validatedHttpsUrl(configuration.jwksUri, "jwksUri", true);
  const audiences = normalizedTextSet(configuration.audiences, "audiences", 512);
  const resources = configuration.resources.map((resource) =>
    validatedResourceIdentifier(resource, "resource"),
  );
  if (resources.length === 0 || resources.length > 32) {
    configurationError("resources must contain between 1 and 32 values");
  }
  if (new Set(resources).size !== resources.length) configurationError("resources contains a duplicate");
  if (
    !Array.isArray(configuration.algorithms) ||
    configuration.algorithms.length === 0 ||
    configuration.algorithms.length > ASYMMETRIC_JWS_ALGORITHMS.size ||
    configuration.algorithms.some((algorithm) => !ASYMMETRIC_JWS_ALGORITHMS.has(algorithm))
  ) {
    configurationError("algorithms must be a non-empty set of approved asymmetric algorithms");
  }
  const algorithms = [...new Set(configuration.algorithms)];
  const requiredClaims = [
    ...new Set([
      ...REQUIRED_ACCESS_TOKEN_CLAIMS,
      ...normalizedIdentifiers(configuration.requiredClaims ?? [], "requiredClaims", true),
    ]),
  ].sort();
  const acceptedTokenTypes = new Set(
    normalizedTextSet(configuration.acceptedTokenTypes ?? ["at+jwt"], "acceptedTokenTypes", 128).map(
      (value) => value.toLowerCase(),
    ),
  );
  const clientIdClaims = normalizedIdentifiers(
    configuration.clientIdClaims ?? ["client_id", "azp"],
    "clientIdClaims",
    false,
  );
  const scopeClaim = identifier(configuration.scopeClaim ?? "scope", "scopeClaim");
  const maximumTokenLifetimeSeconds = boundedInteger(
    configuration.maximumTokenLifetimeSeconds ?? DEFAULT_MAXIMUM_TOKEN_LIFETIME_SECONDS,
    "maximumTokenLifetimeSeconds",
    60,
    86_400,
  );
  const timeoutDuration = boundedInteger(
    configuration.remoteJwks?.timeoutDurationMs ?? DEFAULT_JWKS_TIMEOUT_MS,
    "remoteJwks.timeoutDurationMs",
    100,
    30_000,
  );
  const cooldownDuration = boundedInteger(
    configuration.remoteJwks?.cooldownDurationMs ?? DEFAULT_JWKS_COOLDOWN_MS,
    "remoteJwks.cooldownDurationMs",
    0,
    3_600_000,
  );
  const cacheMaxAge = boundedInteger(
    configuration.remoteJwks?.cacheMaxAgeMs ?? DEFAULT_JWKS_CACHE_MAX_AGE_MS,
    "remoteJwks.cacheMaxAgeMs",
    1_000,
    86_400_000,
  );
  const jwks = createRemoteJWKSet(new URL(jwksUri), {
    timeoutDuration,
    cooldownDuration,
    cacheMaxAge,
    ...(fetcher === undefined ? {} : { [customFetch]: fetcher }),
  });

  return Object.freeze({
    issuer,
    audiences: Object.freeze(audiences),
    resources: Object.freeze(resources),
    algorithms: Object.freeze(algorithms),
    requiredClaims: Object.freeze(requiredClaims),
    acceptedTokenTypes,
    clientIdClaims: Object.freeze(clientIdClaims),
    scopeClaim,
    maximumTokenLifetimeSeconds,
    jwks,
  });
}

function validatedTokenTimes(
  payload: JWTPayload,
  nowEpochSeconds: number,
  maximumLifetimeSeconds: number,
): Readonly<{ expiresAtEpochSeconds: number; notBeforeEpochSeconds?: number }> {
  const expiresAtEpochSeconds = tokenNumericDate(payload.exp, "exp");
  const issuedAtEpochSeconds = tokenNumericDate(payload.iat, "iat");
  const notBeforeEpochSeconds =
    payload.nbf === undefined ? undefined : tokenNumericDate(payload.nbf, "nbf");

  if (
    expiresAtEpochSeconds <= nowEpochSeconds ||
    issuedAtEpochSeconds > nowEpochSeconds ||
    expiresAtEpochSeconds <= issuedAtEpochSeconds ||
    expiresAtEpochSeconds - issuedAtEpochSeconds > maximumLifetimeSeconds ||
    (notBeforeEpochSeconds !== undefined &&
      (notBeforeEpochSeconds > nowEpochSeconds || notBeforeEpochSeconds >= expiresAtEpochSeconds))
  ) {
    throw authenticationError("INVALID_TOKEN");
  }
  return Object.freeze({
    expiresAtEpochSeconds,
    ...(notBeforeEpochSeconds === undefined ? {} : { notBeforeEpochSeconds }),
  });
}

function resolveClientId(payload: JWTPayload, claims: readonly string[]): string {
  const candidates = claims
    .filter((claim) => payload[claim] !== undefined)
    .map((claim) => requiredTokenText(payload[claim]));
  if (candidates.length === 0) throw authenticationError("MISSING_REQUIRED_CLAIM");
  if (new Set(candidates).size !== 1) throw authenticationError("INVALID_TOKEN");
  return candidates[0]!;
}

function tokenScopes(value: unknown): string[] {
  if (value === undefined) return [];
  const scopes =
    typeof value === "string"
      ? value.split(" ").filter(Boolean)
      : Array.isArray(value)
        ? value.map((scope) => requiredTokenText(scope))
        : failToken();
  if (scopes.length > 256) throw authenticationError("INVALID_TOKEN");
  const normalized = scopes.map((scope) => {
    const text = requiredTokenText(scope);
    if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(text)) {
      throw authenticationError("INVALID_TOKEN");
    }
    return text;
  });
  return [...new Set(normalized)].sort();
}

function tokenStringSet(value: unknown, claim: string): string[] {
  void claim;
  const values = Array.isArray(value) ? value : [value];
  if (values.length === 0 || values.length > 64) throw authenticationError("INVALID_TOKEN");
  const normalized = values.map((entry) => requiredTokenText(entry));
  if (new Set(normalized).size !== normalized.length) throw authenticationError("INVALID_TOKEN");
  return normalized.sort();
}

function tokenOptionalStringSet(value: unknown, claim: string): string[] {
  if (value === undefined) return [];
  try {
    return tokenStringSet(value, claim);
  } catch {
    throw authenticationError("INVALID_TOKEN");
  }
}

function requiredTokenText(value: unknown): string {
  if (typeof value !== "string") throw authenticationError("INVALID_TOKEN");
  const normalized = value.trim();
  if (!normalized || normalized.length > 2_048 || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw authenticationError("INVALID_TOKEN");
  }
  return normalized;
}

function tokenNumericDate(value: unknown, claim: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    void claim;
    throw authenticationError("INVALID_TOKEN");
  }
  return value as number;
}

function hasIntersection(left: readonly string[], right: readonly string[]): boolean {
  const accepted = new Set(right);
  return left.some((value) => accepted.has(value));
}

function validatedIssuerIdentifier(value: unknown, label: string): string {
  const issuer = validatedHttpsUrl(value, label, false);
  const parsed = new URL(issuer);
  if (parsed.search || parsed.hash) configurationError(`${label} must not contain query or fragment`);
  return issuer;
}

function validatedResourceIdentifier(value: unknown, label: string): string {
  const resource = validatedHttpsUrl(value, label, false);
  if (new URL(resource).hash) configurationError(`${label} must not contain a fragment`);
  return resource;
}

function validatedHttpsUrl(value: unknown, label: string, allowQuery: boolean): string {
  const text = boundedText(value, label, 2_048);
  let parsed: URL;
  try {
    parsed = new URL(text);
  } catch {
    configurationError(`${label} must be an absolute HTTPS URL`);
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.hash ||
    (!allowQuery && parsed.search)
  ) {
    configurationError(`${label} must be a credential-free HTTPS URL`);
  }
  return text;
}

function normalizedIdentifiers(
  values: readonly string[],
  label: string,
  allowEmpty: boolean,
): string[] {
  if (!Array.isArray(values) || values.length > 256 || (!allowEmpty && values.length === 0)) {
    configurationError(`${label} must be a bounded array`);
  }
  const normalized = values.map((value) => identifier(value, label));
  if (new Set(normalized).size !== normalized.length) configurationError(`${label} contains a duplicate`);
  return normalized.sort();
}

function normalizedTextSet(values: readonly string[], label: string, maximumLength: number): string[] {
  if (!Array.isArray(values) || values.length === 0 || values.length > 64) {
    configurationError(`${label} must be a bounded non-empty array`);
  }
  const normalized = values.map((value) => boundedText(value, label, maximumLength));
  if (new Set(normalized).size !== normalized.length) configurationError(`${label} contains a duplicate`);
  return normalized.sort();
}

function identifier(value: unknown, label: string): string {
  const normalized = boundedText(value, label, 256);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(normalized)) {
    configurationError(`${label} is invalid`);
  }
  return normalized;
}

function boundedText(value: unknown, label: string, maximumLength: number): string {
  if (typeof value !== "string") configurationError(`${label} must be a string`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maximumLength || /[\u0000-\u001f\u007f]/.test(normalized)) {
    configurationError(`${label} is invalid`);
  }
  return normalized;
}

function boundedInteger(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    configurationError(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return value as number;
}

function quoted(value: string): string {
  return `"${value.replace(/(["\\])/g, "\\$1")}"`;
}

function failToken(): never {
  throw authenticationError("INVALID_TOKEN");
}

function authenticationError(code: OAuthAuthenticationErrorCode): OAuthAuthenticationError {
  switch (code) {
    case "MISSING_BEARER_TOKEN":
      return new OAuthAuthenticationError(code, "Bearer access token is required", 401);
    case "MALFORMED_AUTHORIZATION":
      return new OAuthAuthenticationError(code, "Authorization header is invalid", 400, "invalid_request");
    case "TOKEN_TOO_LARGE":
      return new OAuthAuthenticationError(code, "Access token is not accepted", 401, "invalid_token");
    case "UNKNOWN_ISSUER":
    case "INVALID_TOKEN":
    case "MISSING_REQUIRED_CLAIM":
    case "INVALID_RESOURCE":
      return new OAuthAuthenticationError(code, "Access token is not accepted", 401, "invalid_token");
    case "TENANT_MEMBERSHIP_DENIED":
      return new OAuthAuthenticationError(code, "Access is not authorized", 403, "insufficient_scope");
    case "TENANT_RESOLUTION_FAILED":
      return new OAuthAuthenticationError(code, "Authentication service is unavailable", 503);
    case "INVALID_AUTHENTICATOR_CONFIGURATION":
      return new OAuthAuthenticationError(code, "OAuth authenticator configuration is invalid", 500);
  }
}

function configurationError(message: string): never {
  throw new OAuthAuthenticationError(
    "INVALID_AUTHENTICATOR_CONFIGURATION",
    message,
    500,
  );
}
