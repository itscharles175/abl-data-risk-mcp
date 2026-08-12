import { createHash } from "node:crypto";

const verifiedPrincipalBrand: unique symbol = Symbol("VerifiedPrincipalContext");
const VERIFIED_CONTEXTS = new WeakSet<object>();

export type IdentityContextErrorCode =
  | "INVALID_VERIFICATION_ATTESTATION"
  | "UNVERIFIED_IDENTITY_CONTEXT"
  | "IDENTITY_NOT_YET_VALID"
  | "IDENTITY_EXPIRED"
  | "MISSING_SCOPE";

export class IdentityContextError extends Error {
  readonly code: IdentityContextErrorCode;

  constructor(code: IdentityContextErrorCode, message: string) {
    super(message);
    this.name = "IdentityContextError";
    this.code = code;
  }
}

/**
 * Evidence produced by a trusted authentication edge after token validation.
 *
 * This type is deliberately not an OAuth token or an arbitrary claims bag. The
 * edge must validate signature, issuer, audience, expiry, and tenant membership
 * before calling {@link createVerifiedPrincipalContext}. Never populate it from
 * MCP tool arguments.
 */
export interface VerifiedIdentityAttestation {
  readonly issuer: string;
  readonly subject: string;
  readonly principalId: string;
  readonly tenantId: string;
  readonly clientId?: string;
  readonly audiences: readonly string[];
  /** Verified OAuth resource indicators carried by the access token. */
  readonly resourceIndicators: readonly string[];
  readonly scopes: readonly string[];
  /** SHA-256 of the credential/token; the credential itself must not be retained. */
  readonly credentialFingerprint: string;
  readonly verifiedAtEpochSeconds: number;
  readonly notBeforeEpochSeconds?: number;
  readonly expiresAtEpochSeconds: number;
  readonly authenticationMethods?: readonly string[];
}

/**
 * Nominal, runtime-attested identity context for server-side authorization.
 * The private brand and WeakSet membership do not survive JSON serialization.
 */
export interface VerifiedPrincipalContext {
  readonly [verifiedPrincipalBrand]: true;
  readonly issuer: string;
  readonly subject: string;
  readonly principalId: string;
  readonly tenantId: string;
  readonly clientId?: string;
  readonly audiences: readonly string[];
  readonly resourceIndicators: readonly string[];
  readonly scopes: readonly string[];
  readonly credentialFingerprint: string;
  readonly verifiedAtEpochSeconds: number;
  readonly notBeforeEpochSeconds?: number;
  readonly expiresAtEpochSeconds: number;
  readonly authenticationMethods: readonly string[];
}

/**
 * Converts already-verified claims into a context accepted by policy APIs.
 * Validation here checks shape and lifetime coherence; it does not verify JWTs,
 * introspect tokens, or establish tenant membership.
 */
export function createVerifiedPrincipalContext(
  attestation: VerifiedIdentityAttestation,
): VerifiedPrincipalContext {
  const issuer = requiredText(attestation.issuer, "issuer", 2_048);
  const subject = requiredText(attestation.subject, "subject", 512);
  const principalId = requiredIdentifier(attestation.principalId, "principalId");
  const tenantId = requiredIdentifier(attestation.tenantId, "tenantId");
  const clientId = optionalText(attestation.clientId, "clientId", 512);
  const audiences = normalizedTextSet(attestation.audiences, "audiences", 512, true);
  const resourceIndicators = normalizedTextSet(
    attestation.resourceIndicators,
    "resourceIndicators",
    2_048,
    true,
  );
  const scopes = normalizedIdentifierSet(attestation.scopes, "scopes");
  const authenticationMethods = normalizedIdentifierSet(
    attestation.authenticationMethods ?? [],
    "authenticationMethods",
  );
  const credentialFingerprint = requiredFingerprint(
    attestation.credentialFingerprint,
    "credentialFingerprint",
  );
  const verifiedAtEpochSeconds = epochSeconds(
    attestation.verifiedAtEpochSeconds,
    "verifiedAtEpochSeconds",
  );
  const expiresAtEpochSeconds = epochSeconds(
    attestation.expiresAtEpochSeconds,
    "expiresAtEpochSeconds",
  );
  const notBeforeEpochSeconds =
    attestation.notBeforeEpochSeconds === undefined
      ? undefined
      : epochSeconds(attestation.notBeforeEpochSeconds, "notBeforeEpochSeconds");

  if (expiresAtEpochSeconds <= verifiedAtEpochSeconds) {
    invalid("expiresAtEpochSeconds must be later than verifiedAtEpochSeconds");
  }
  if (notBeforeEpochSeconds !== undefined && notBeforeEpochSeconds >= expiresAtEpochSeconds) {
    invalid("notBeforeEpochSeconds must be earlier than expiresAtEpochSeconds");
  }

  const context = Object.freeze({
    [verifiedPrincipalBrand]: true as const,
    issuer,
    subject,
    principalId,
    tenantId,
    ...(clientId === undefined ? {} : { clientId }),
    audiences: Object.freeze(audiences),
    resourceIndicators: Object.freeze(resourceIndicators),
    scopes: Object.freeze(scopes),
    credentialFingerprint,
    verifiedAtEpochSeconds,
    ...(notBeforeEpochSeconds === undefined ? {} : { notBeforeEpochSeconds }),
    expiresAtEpochSeconds,
    authenticationMethods: Object.freeze(authenticationMethods),
  });

  VERIFIED_CONTEXTS.add(context);
  return context;
}

export function isVerifiedPrincipalContext(value: unknown): value is VerifiedPrincipalContext {
  return Boolean(value && typeof value === "object" && VERIFIED_CONTEXTS.has(value));
}

export function assertVerifiedPrincipalContext(
  value: unknown,
): asserts value is VerifiedPrincipalContext {
  if (!isVerifiedPrincipalContext(value)) {
    throw new IdentityContextError(
      "UNVERIFIED_IDENTITY_CONTEXT",
      "Authorization requires a runtime-issued verified principal context",
    );
  }
}

export function assertActivePrincipal(
  context: VerifiedPrincipalContext,
  nowEpochSeconds = currentEpochSeconds(),
  clockSkewSeconds = 0,
): void {
  assertVerifiedPrincipalContext(context);
  const now = epochSeconds(nowEpochSeconds, "nowEpochSeconds");
  const skew = nonNegativeInteger(clockSkewSeconds, "clockSkewSeconds");

  if (
    context.notBeforeEpochSeconds !== undefined &&
    now + skew < context.notBeforeEpochSeconds
  ) {
    throw new IdentityContextError("IDENTITY_NOT_YET_VALID", "Identity is not yet valid");
  }
  if (now - skew >= context.expiresAtEpochSeconds) {
    throw new IdentityContextError("IDENTITY_EXPIRED", "Identity has expired");
  }
}

export function hasAllScopes(
  context: VerifiedPrincipalContext,
  requiredScopes: readonly string[],
): boolean {
  assertVerifiedPrincipalContext(context);
  const required = normalizedIdentifierSet(requiredScopes, "requiredScopes");
  const available = new Set(context.scopes);
  return required.every((scope) => available.has(scope));
}

export function requireScopes(
  context: VerifiedPrincipalContext,
  requiredScopes: readonly string[],
): void {
  assertVerifiedPrincipalContext(context);
  const required = normalizedIdentifierSet(requiredScopes, "requiredScopes");
  const available = new Set(context.scopes);
  const missing = required.filter((scope) => !available.has(scope));
  if (missing.length > 0) {
    throw new IdentityContextError(
      "MISSING_SCOPE",
      `Identity is missing required scopes: ${missing.join(", ")}`,
    );
  }
}

/**
 * Stable pseudonymous binding for plans and handles. It intentionally excludes
 * the credential fingerprint and scopes so refreshed credentials for the same
 * issuer/subject/client identity retain the same binding.
 */
export function principalBinding(context: VerifiedPrincipalContext): string {
  assertVerifiedPrincipalContext(context);
  const canonicalIdentity = JSON.stringify({
    audiences: context.audiences,
    clientId: context.clientId ?? null,
    issuer: context.issuer,
    principalId: context.principalId,
    resourceIndicators: context.resourceIndicators,
    subject: context.subject,
    tenantId: context.tenantId,
  });
  return createHash("sha256").update(canonicalIdentity).digest("hex");
}

function requiredText(value: unknown, label: string, maximumLength: number): string {
  if (typeof value !== "string") invalid(`${label} must be a string`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maximumLength || hasControlCharacter(normalized)) {
    invalid(`${label} is invalid`);
  }
  return normalized;
}

function optionalText(
  value: unknown,
  label: string,
  maximumLength: number,
): string | undefined {
  if (value === undefined) return undefined;
  return requiredText(value, label, maximumLength);
}

function requiredIdentifier(value: unknown, label: string): string {
  const normalized = requiredText(value, label, 256);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(normalized)) invalid(`${label} is invalid`);
  return normalized;
}

function normalizedIdentifierSet(values: readonly string[], label: string): string[] {
  if (!Array.isArray(values) || values.length > 256) invalid(`${label} must be a bounded array`);
  return [...new Set(values.map((value) => requiredIdentifier(value, label)))].sort();
}

function normalizedTextSet(
  values: readonly string[],
  label: string,
  maximumLength: number,
  requireValue: boolean,
): string[] {
  if (!Array.isArray(values) || values.length > 64 || (requireValue && values.length === 0)) {
    invalid(`${label} must be a bounded non-empty array`);
  }
  return [...new Set(values.map((value) => requiredText(value, label, maximumLength)))].sort();
}

function requiredFingerprint(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    invalid(`${label} must be a lowercase SHA-256 fingerprint`);
  }
  return value;
}

function epochSeconds(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    invalid(`${label} must be non-negative integer epoch seconds`);
  }
  return value as number;
}

function nonNegativeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    invalid(`${label} must be a non-negative integer`);
  }
  return value as number;
}

function hasControlCharacter(value: string): boolean {
  return /[\u0000-\u001f\u007f]/.test(value);
}

function currentEpochSeconds(): number {
  return Math.floor(Date.now() / 1_000);
}

function invalid(message: string): never {
  throw new IdentityContextError("INVALID_VERIFICATION_ATTESTATION", message);
}
