import {
  accessSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  type Stats,
} from "node:fs";
import { isIP } from "node:net";
import { dirname, isAbsolute, resolve } from "node:path";

import * as z from "zod/v4";

import type { ArtifactKeyRing } from "../control/artifacts.js";
import {
  compileAuthorizationPolicy,
  type AuthorizationPolicyDocument,
  type CompiledAuthorizationPolicy,
} from "../security/policy.js";
import type {
  AllowedJwtAlgorithm,
  OAuthIssuerConfiguration,
  RemoteJwksConfiguration,
} from "../security/oauth.js";
import {
  createHmacKeyRing,
  type HmacKeyDefinition,
  type HmacKeyRing,
} from "../security/signed-plan.js";

const MAX_ENVIRONMENT_VALUE_LENGTH = 1_048_576;
const MAX_CONFIGURATION_FILE_BYTES = 1_048_576;
const MAX_SECRET_BYTES = 512;
const MIN_REMOTE_RESULT_BYTES = 1_024;
const SECRET_FILE_MODE_MASK = 0o077;
const STRUCTURAL_TENANT_FILTER_REF = "tenant-boundary";

const APPROVED_ALGORITHMS = [
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
] as const satisfies readonly AllowedJwtAlgorithm[];

const identifierSchema = z
  .string()
  .min(1)
  .max(512)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/);
const keyIdSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/);
const boundedTextSchema = z
  .string()
  .min(1)
  .max(2_048)
  .refine((value) => !/[\u0000-\u001f\u007f]/.test(value));

const remoteJwksSchema = z
  .object({
    timeoutDurationMs: z.number().int().min(100).max(30_000).optional(),
    cooldownDurationMs: z.number().int().min(0).max(3_600_000).optional(),
    cacheMaxAgeMs: z.number().int().min(1_000).max(86_400_000).optional(),
  })
  .strict();

const oauthIssuerSchema = z
  .object({
    issuer: boundedTextSchema,
    jwksUri: boundedTextSchema,
    audiences: z.array(boundedTextSchema).min(1).max(512),
    resources: z.array(boundedTextSchema).min(1).max(32),
    algorithms: z.array(z.enum(APPROVED_ALGORITHMS)).min(1).max(APPROVED_ALGORITHMS.length),
    requiredClaims: z.array(identifierSchema).max(256).optional(),
    acceptedTokenTypes: z.array(boundedTextSchema).min(1).max(32).optional(),
    clientIdClaims: z.array(identifierSchema).min(1).max(32).optional(),
    scopeClaim: identifierSchema.optional(),
    maximumTokenLifetimeSeconds: z.number().int().min(60).max(86_400).optional(),
    remoteJwks: remoteJwksSchema.optional(),
  })
  .strict();

const oauthIssuersSchema = z.array(oauthIssuerSchema).min(1).max(64);

const keyDefinitionSchema = z
  .object({
    id: keyIdSchema,
    secret: z.string().min(1).max(8_192),
    notBeforeEpochSeconds: z.number().int().min(0).optional(),
    notAfterEpochSeconds: z.number().int().min(0).optional(),
  })
  .strict();

const artifactKeyFileSchema = z
  .object({
    activeKeyId: keyIdSchema,
    keys: z.array(keyDefinitionSchema.omit({ notBeforeEpochSeconds: true, notAfterEpochSeconds: true })).min(1).max(32),
  })
  .strict();

const signingKeyFileSchema = z
  .object({
    currentKeyId: keyIdSchema,
    keys: z.array(keyDefinitionSchema).min(1).max(32),
  })
  .strict();

const fieldMaskSchema = z.enum(["partial", "hash", "tokenize", "redact"]);
const obligationShape = {
  maxResultRows: z.number().int().min(1),
  maxResultBytes: z.number().int().min(1),
  maxExecutionMs: z.number().int().min(1),
  minimumCohortSize: z.number().int().min(1),
  requireImmutableSnapshot: z.boolean(),
  allowRawRows: z.boolean(),
  allowExport: z.boolean(),
  rowFilterRefs: z.array(identifierSchema).max(10_000),
  fieldMasks: z.record(identifierSchema, fieldMaskSchema),
  auditTags: z.array(identifierSchema).max(10_000),
} as const;
const policyObligationsSchema = z.object(obligationShape).strict();
const policyObligationOverridesSchema = z
  .object({
    maxResultRows: obligationShape.maxResultRows.optional(),
    maxResultBytes: obligationShape.maxResultBytes.optional(),
    maxExecutionMs: obligationShape.maxExecutionMs.optional(),
    minimumCohortSize: obligationShape.minimumCohortSize.optional(),
    requireImmutableSnapshot: obligationShape.requireImmutableSnapshot.optional(),
    allowRawRows: obligationShape.allowRawRows.optional(),
    allowExport: obligationShape.allowExport.optional(),
    rowFilterRefs: obligationShape.rowFilterRefs.optional(),
    fieldMasks: obligationShape.fieldMasks.optional(),
    auditTags: obligationShape.auditTags.optional(),
  })
  .strict();
const policyRuleSchema = z
  .object({
    id: identifierSchema,
    effect: z.enum(["permit", "deny"]),
    tenantIds: z.array(z.union([identifierSchema, z.literal("*")])).min(1).max(10_000),
    principalIds: z.array(z.union([identifierSchema, z.literal("*")])).min(1).max(10_000).optional(),
    tools: z.array(z.union([identifierSchema, z.literal("*")])).min(1).max(10_000),
    datasets: z.array(z.union([identifierSchema, z.literal("*")])).min(1).max(10_000),
    purposes: z.array(z.union([identifierSchema, z.literal("*")])).min(1).max(10_000).optional(),
    fields: z.array(z.union([identifierSchema, z.literal("*")])).min(1).max(10_000).optional(),
    requiredScopes: z.array(identifierSchema).max(10_000).optional(),
    obligations: policyObligationOverridesSchema.optional(),
  })
  .strict();
const policyDocumentSchema = z
  .object({
    id: identifierSchema,
    version: boundedTextSchema.max(128),
    defaultObligations: policyObligationsSchema,
    rules: z.array(policyRuleSchema).min(1).max(10_000),
  })
  .strict();

export type RuntimeEnvironment = Readonly<Record<string, string | undefined>>;

export type RuntimeConfigurationErrorCode =
  | "MISSING_SETTING"
  | "INVALID_SETTING"
  | "INVALID_FILE"
  | "INSECURE_FILE"
  | "INVALID_TARGET_PATH";

/** A stable, redacted startup error. It never retains a rejected value or a cause. */
export class RuntimeConfigurationError extends Error {
  readonly code: RuntimeConfigurationErrorCode;
  readonly setting: string;

  constructor(code: RuntimeConfigurationErrorCode, setting: string) {
    super(`Runtime configuration rejected: ${setting}`);
    this.name = "RuntimeConfigurationError";
    this.code = code;
    this.setting = setting;
  }

  toJSON(): Readonly<{ name: string; code: RuntimeConfigurationErrorCode; setting: string; message: string }> {
    return Object.freeze({
      name: this.name,
      code: this.code,
      setting: this.setting,
      message: this.message,
    });
  }
}

export interface RuntimeHttpConfiguration {
  readonly host: string;
  readonly port: number;
  readonly publicUrl: string;
  readonly allowedHosts: readonly string[];
  readonly allowedOrigins: readonly string[];
}

export interface RuntimeOAuthConfiguration {
  readonly resource: string;
  readonly issuers: readonly OAuthIssuerConfiguration[];
  readonly maximumTokenLength: number;
  readonly scopesSupported: readonly string[];
  readonly resourceName: string;
  readonly resourceDocumentation?: string;
}

export interface RuntimeStorageConfiguration {
  readonly sourceConfigPath: string;
  readonly controlDatabasePath: string;
  readonly jobDatabasePath: string;
  readonly securityDatabasePath: string;
  readonly artifactRoot: string;
}

export interface RuntimeWorkerConfiguration {
  readonly id: string;
  readonly leaseSeconds: number;
  readonly pollIntervalMs: number;
}

export interface RuntimeLimitConfiguration {
  readonly rateLimitWindowMs: number;
  readonly rateLimitMaximumRequests: number;
  readonly maximumConcurrentRequests: number;
  readonly maximumConcurrentJobs: number;
}

export interface RuntimeConfiguration {
  readonly authMode: "oauth";
  readonly codeVersion: string;
  readonly http: RuntimeHttpConfiguration;
  readonly oauth: RuntimeOAuthConfiguration;
  readonly storage: RuntimeStorageConfiguration;
  readonly worker: RuntimeWorkerConfiguration;
  readonly limits: RuntimeLimitConfiguration;
  readonly policy: CompiledAuthorizationPolicy;
  readonly signingKeyRing: HmacKeyRing;
  readonly artifactKeyRing: ArtifactKeyRing;
}

/** Loads and validates the complete remote-runtime configuration without creating any path. */
export function loadRuntimeConfiguration(
  environment: RuntimeEnvironment = process.env,
): RuntimeConfiguration {
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) {
    invalid("INVALID_SETTING", "environment");
  }
  const authMode = requiredSetting(environment, "ABL_AUTH_MODE", 32);
  if (authMode !== "oauth") invalid("INVALID_SETTING", "ABL_AUTH_MODE");

  const publicUrl = httpsUrl(
    "ABL_MCP_PUBLIC_URL",
    requiredSetting(environment, "ABL_MCP_PUBLIC_URL", 2_048),
    { originOnly: true, allowQuery: false },
  );
  const publicHost = new URL(publicUrl).host.toLowerCase();
  const allowedHosts = hostList(
    "ABL_MCP_ALLOWED_HOSTS",
    requiredSetting(environment, "ABL_MCP_ALLOWED_HOSTS", 32_768),
  );
  if (!allowedHosts.includes(publicHost)) invalid("INVALID_SETTING", "ABL_MCP_ALLOWED_HOSTS");

  const allowedOrigins = originList(
    "ABL_MCP_ALLOWED_ORIGINS",
    requiredSetting(environment, "ABL_MCP_ALLOWED_ORIGINS", 32_768),
  );
  const resource = httpsUrl(
    "ABL_OAUTH_RESOURCE",
    requiredSetting(environment, "ABL_OAUTH_RESOURCE", 2_048),
    { originOnly: false, allowQuery: false },
  );
  const issuers = oauthIssuers(
    requiredSetting(environment, "ABL_OAUTH_ISSUERS_JSON", MAX_ENVIRONMENT_VALUE_LENGTH),
    resource,
  );
  const resourceDocumentationRaw = optionalSetting(
    environment,
    "ABL_OAUTH_RESOURCE_DOCUMENTATION",
    2_048,
  );

  const sourceConfigPath = readableFilePath(
    "ABL_MCP_CONFIG",
    requiredSetting(environment, "ABL_MCP_CONFIG", 4_096),
    false,
  );
  const controlDatabasePath = writableFileTarget(
    "ABL_MCP_CONTROL_DB_PATH",
    requiredSetting(environment, "ABL_MCP_CONTROL_DB_PATH", 4_096),
  );
  const jobDatabasePath = writableFileTarget(
    "ABL_MCP_JOB_DB_PATH",
    requiredSetting(environment, "ABL_MCP_JOB_DB_PATH", 4_096),
  );
  const securityDatabasePath = writableFileTarget(
    "ABL_MCP_SECURITY_DB_PATH",
    requiredSetting(environment, "ABL_MCP_SECURITY_DB_PATH", 4_096),
  );
  const artifactRoot = writableDirectoryTarget(
    "ABL_MCP_ARTIFACT_ROOT",
    requiredSetting(environment, "ABL_MCP_ARTIFACT_ROOT", 4_096),
  );
  distinctTargets([
    ["ABL_MCP_CONTROL_DB_PATH", controlDatabasePath],
    ["ABL_MCP_JOB_DB_PATH", jobDatabasePath],
    ["ABL_MCP_SECURITY_DB_PATH", securityDatabasePath],
    ["ABL_MCP_ARTIFACT_ROOT", artifactRoot],
  ]);

  const policy = compiledPolicy(
    requiredSetting(environment, "ABL_MCP_POLICY_FILE", 4_096),
  );
  assertRemotePolicySupport(policy);
  const signingKeyRing = signingKeys(
    requiredSetting(environment, "ABL_MCP_SIGNING_KEYS_FILE", 4_096),
  );
  const artifactKeyRing = artifactKeys(
    requiredSetting(environment, "ABL_MCP_ARTIFACT_KEYS_FILE", 4_096),
  );

  return Object.freeze({
    authMode: "oauth" as const,
    codeVersion: runtimeIdentifier(
      "ABL_MCP_CODE_VERSION",
      requiredSetting(environment, "ABL_MCP_CODE_VERSION", 128),
    ),
    http: Object.freeze({
      host: bindHost(requiredSetting(environment, "ABL_MCP_HOST", 253)),
      port: boundedInteger(environment, "ABL_MCP_PORT", 1, 65_535),
      publicUrl,
      allowedHosts,
      allowedOrigins,
    }),
    oauth: Object.freeze({
      resource,
      issuers,
      maximumTokenLength: boundedInteger(
        environment,
        "ABL_OAUTH_MAX_TOKEN_LENGTH",
        1_024,
        65_536,
      ),
      scopesSupported: scopeList(
        "ABL_OAUTH_SCOPES_SUPPORTED",
        requiredSetting(environment, "ABL_OAUTH_SCOPES_SUPPORTED", 32_768),
      ),
      resourceName: boundedText(
        "ABL_OAUTH_RESOURCE_NAME",
        requiredSetting(environment, "ABL_OAUTH_RESOURCE_NAME", 128),
        128,
      ),
      ...(resourceDocumentationRaw === undefined
        ? {}
        : {
            resourceDocumentation: httpsUrl(
              "ABL_OAUTH_RESOURCE_DOCUMENTATION",
              resourceDocumentationRaw,
              { originOnly: false, allowQuery: true },
            ),
          }),
    }),
    storage: Object.freeze({
      sourceConfigPath,
      controlDatabasePath,
      jobDatabasePath,
      securityDatabasePath,
      artifactRoot,
    }),
    worker: Object.freeze({
      id: runtimeIdentifier(
        "ABL_MCP_WORKER_ID",
        requiredSetting(environment, "ABL_MCP_WORKER_ID", 128),
      ),
      leaseSeconds: boundedInteger(environment, "ABL_MCP_WORKER_LEASE_SECONDS", 5, 3_600),
      pollIntervalMs: boundedInteger(
        environment,
        "ABL_MCP_WORKER_POLL_INTERVAL_MS",
        50,
        60_000,
      ),
    }),
    limits: Object.freeze({
      rateLimitWindowMs: boundedInteger(
        environment,
        "ABL_MCP_RATE_LIMIT_WINDOW_MS",
        1_000,
        3_600_000,
      ),
      rateLimitMaximumRequests: boundedInteger(
        environment,
        "ABL_MCP_RATE_LIMIT_MAX_REQUESTS",
        1,
        100_000,
      ),
      maximumConcurrentRequests: boundedInteger(
        environment,
        "ABL_MCP_MAX_CONCURRENT_REQUESTS",
        1,
        10_000,
      ),
      maximumConcurrentJobs: boundedInteger(
        environment,
        "ABL_MCP_MAX_CONCURRENT_JOBS",
        1,
        1_000,
      ),
    }),
    policy,
    signingKeyRing,
    artifactKeyRing,
  });
}

/**
 * The remote runtime only accepts obligations that it can enforce completely.
 * Tenant isolation is structural in every durable store, so the sole supported
 * row-filter marker records that boundary without delegating filtering to data.
 */
function assertRemotePolicySupport(policy: CompiledAuthorizationPolicy): void {
  const obligations = [
    policy.defaultObligations,
    ...policy.rules.flatMap((rule) => (rule.obligations === undefined ? [] : [rule.obligations])),
  ];
  for (const obligation of obligations) {
    if (
      obligation.maxResultBytes !== undefined &&
      obligation.maxResultBytes < MIN_REMOTE_RESULT_BYTES
    ) {
      invalid("INVALID_FILE", "ABL_MCP_POLICY_FILE");
    }
    if (obligation.allowRawRows === true || obligation.allowExport === true) {
      invalid("INVALID_FILE", "ABL_MCP_POLICY_FILE");
    }
    if (obligation.fieldMasks !== undefined && Object.keys(obligation.fieldMasks).length > 0) {
      invalid("INVALID_FILE", "ABL_MCP_POLICY_FILE");
    }
    if (
      obligation.rowFilterRefs !== undefined &&
      obligation.rowFilterRefs.some((reference) => reference !== STRUCTURAL_TENANT_FILTER_REF)
    ) {
      invalid("INVALID_FILE", "ABL_MCP_POLICY_FILE");
    }
  }
}

function oauthIssuers(rawJson: string, resource: string): readonly OAuthIssuerConfiguration[] {
  const parsed = parseEnvironmentJson(rawJson, "ABL_OAUTH_ISSUERS_JSON");
  const result = oauthIssuersSchema.safeParse(parsed);
  if (!result.success) invalid("INVALID_SETTING", "ABL_OAUTH_ISSUERS_JSON");

  const seenIssuers = new Set<string>();
  const normalized = result.data.map((raw): OAuthIssuerConfiguration => {
    const issuer = httpsUrl("ABL_OAUTH_ISSUERS_JSON", raw.issuer, {
      originOnly: false,
      allowQuery: false,
    });
    const jwksUri = httpsUrl("ABL_OAUTH_ISSUERS_JSON", raw.jwksUri, {
      originOnly: false,
      allowQuery: true,
    });
    if (seenIssuers.has(issuer)) invalid("INVALID_SETTING", "ABL_OAUTH_ISSUERS_JSON");
    seenIssuers.add(issuer);
    const audiences = uniqueTextSet(raw.audiences, "ABL_OAUTH_ISSUERS_JSON");
    const resources = uniqueTextSet(raw.resources, "ABL_OAUTH_ISSUERS_JSON").map((entry) =>
      httpsUrl("ABL_OAUTH_ISSUERS_JSON", entry, { originOnly: false, allowQuery: false }),
    );
    if (!resources.includes(resource)) invalid("INVALID_SETTING", "ABL_OAUTH_ISSUERS_JSON");
    const algorithms = uniqueTextSet(raw.algorithms, "ABL_OAUTH_ISSUERS_JSON") as AllowedJwtAlgorithm[];
    const requiredClaims =
      raw.requiredClaims === undefined
        ? undefined
        : uniqueTextSet(raw.requiredClaims, "ABL_OAUTH_ISSUERS_JSON");
    const acceptedTokenTypes =
      raw.acceptedTokenTypes === undefined
        ? undefined
        : uniqueTextSet(raw.acceptedTokenTypes, "ABL_OAUTH_ISSUERS_JSON");
    const clientIdClaims =
      raw.clientIdClaims === undefined
        ? undefined
        : uniqueTextSet(raw.clientIdClaims, "ABL_OAUTH_ISSUERS_JSON");
    const remoteJwks = raw.remoteJwks === undefined ? undefined : Object.freeze({ ...raw.remoteJwks });

    return Object.freeze({
      issuer,
      jwksUri,
      audiences: Object.freeze(audiences),
      resources: Object.freeze(resources),
      algorithms: Object.freeze(algorithms),
      ...(requiredClaims === undefined ? {} : { requiredClaims: Object.freeze(requiredClaims) }),
      ...(acceptedTokenTypes === undefined
        ? {}
        : { acceptedTokenTypes: Object.freeze(acceptedTokenTypes) }),
      ...(clientIdClaims === undefined ? {} : { clientIdClaims: Object.freeze(clientIdClaims) }),
      ...(raw.scopeClaim === undefined ? {} : { scopeClaim: raw.scopeClaim }),
      ...(raw.maximumTokenLifetimeSeconds === undefined
        ? {}
        : { maximumTokenLifetimeSeconds: raw.maximumTokenLifetimeSeconds }),
      ...(remoteJwks === undefined
        ? {}
        : { remoteJwks: remoteJwks as RemoteJwksConfiguration }),
    });
  });
  return Object.freeze(normalized.sort((left, right) => left.issuer.localeCompare(right.issuer)));
}

function compiledPolicy(pathValue: string): CompiledAuthorizationPolicy {
  const parsed = readJsonFile("ABL_MCP_POLICY_FILE", pathValue, false);
  const result = policyDocumentSchema.safeParse(parsed);
  if (!result.success) invalid("INVALID_FILE", "ABL_MCP_POLICY_FILE");
  try {
    return compileAuthorizationPolicy(result.data as AuthorizationPolicyDocument);
  } catch {
    invalid("INVALID_FILE", "ABL_MCP_POLICY_FILE");
  }
}

function signingKeys(pathValue: string): HmacKeyRing {
  const parsed = readJsonFile("ABL_MCP_SIGNING_KEYS_FILE", pathValue, true);
  const result = signingKeyFileSchema.safeParse(parsed);
  if (!result.success) invalid("INVALID_FILE", "ABL_MCP_SIGNING_KEYS_FILE");
  const definitions: HmacKeyDefinition[] = [];
  try {
    for (const definition of result.data.keys) {
      definitions.push({
        id: definition.id,
        secret: decodedSecret(
          definition.secret,
          "ABL_MCP_SIGNING_KEYS_FILE",
          32,
          MAX_SECRET_BYTES,
        ),
        ...(definition.notBeforeEpochSeconds === undefined
          ? {}
          : { notBeforeEpochSeconds: definition.notBeforeEpochSeconds }),
        ...(definition.notAfterEpochSeconds === undefined
          ? {}
          : { notAfterEpochSeconds: definition.notAfterEpochSeconds }),
      });
    }
    return createHmacKeyRing(definitions, result.data.currentKeyId);
  } catch {
    invalid("INVALID_FILE", "ABL_MCP_SIGNING_KEYS_FILE");
  } finally {
    for (const definition of definitions) definition.secret.fill(0);
  }
  return invalid("INVALID_FILE", "ABL_MCP_SIGNING_KEYS_FILE");
}

function artifactKeys(pathValue: string): ArtifactKeyRing {
  const parsed = readJsonFile("ABL_MCP_ARTIFACT_KEYS_FILE", pathValue, true);
  const result = artifactKeyFileSchema.safeParse(parsed);
  if (!result.success) invalid("INVALID_FILE", "ABL_MCP_ARTIFACT_KEYS_FILE");
  const keys: Record<string, Uint8Array> = {};
  try {
    for (const definition of result.data.keys) {
      if (keys[definition.id] !== undefined) invalid("INVALID_FILE", "ABL_MCP_ARTIFACT_KEYS_FILE");
      keys[definition.id] = decodedSecret(
        definition.secret,
        "ABL_MCP_ARTIFACT_KEYS_FILE",
        32,
        32,
      );
    }
    if (keys[result.data.activeKeyId] === undefined) {
      invalid("INVALID_FILE", "ABL_MCP_ARTIFACT_KEYS_FILE");
    }
    return Object.freeze({
      activeKeyId: result.data.activeKeyId,
      keys: Object.freeze(keys),
    });
  } catch (error) {
    for (const material of Object.values(keys)) material.fill(0);
    if (error instanceof RuntimeConfigurationError) throw error;
    invalid("INVALID_FILE", "ABL_MCP_ARTIFACT_KEYS_FILE");
  }
}

function decodedSecret(
  encoded: string,
  setting: string,
  minimumBytes: number,
  maximumBytes: number,
): Uint8Array {
  if (
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)
  ) {
    invalid("INVALID_FILE", setting);
  }
  const decoded = Buffer.from(encoded, "base64");
  if (
    decoded.byteLength < minimumBytes ||
    decoded.byteLength > maximumBytes ||
    decoded.toString("base64") !== encoded
  ) {
    decoded.fill(0);
    invalid("INVALID_FILE", setting);
  }
  const material = Uint8Array.from(decoded);
  decoded.fill(0);
  return material;
}

function readJsonFile(setting: string, pathValue: string, privateFile: boolean): unknown {
  const path = absolutePath(setting, pathValue, "INVALID_FILE");
  let descriptor: number | undefined;
  try {
    const before = lstatSync(path);
    if (!before.isFile()) invalid("INVALID_FILE", setting);
    const noFollow = process.platform === "win32" ? 0 : constants.O_NOFOLLOW;
    descriptor = openSync(path, constants.O_RDONLY | noFollow);
    const stats = fstatSync(descriptor);
    if (before.dev !== stats.dev || before.ino !== stats.ino) invalid("INVALID_FILE", setting);
    validateReadableFileStats(stats, setting, privateFile);
    if (stats.size < 1 || stats.size > MAX_CONFIGURATION_FILE_BYTES) invalid("INVALID_FILE", setting);
    const bytes = readFileSync(descriptor);
    if (bytes.byteLength < 1 || bytes.byteLength > MAX_CONFIGURATION_FILE_BYTES) {
      invalid("INVALID_FILE", setting);
    }
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      invalid("INVALID_FILE", setting);
    }
    try {
      return JSON.parse(text) as unknown;
    } catch {
      invalid("INVALID_FILE", setting);
    }
  } catch (error) {
    if (error instanceof RuntimeConfigurationError) throw error;
    invalid("INVALID_FILE", setting);
  } finally {
    closeFile(descriptor, setting);
  }
  return invalid("INVALID_FILE", setting);
}

function readableFilePath(setting: string, pathValue: string, privateFile: boolean): string {
  const path = absolutePath(setting, pathValue, "INVALID_FILE");
  let descriptor: number | undefined;
  try {
    const before = lstatSync(path);
    if (!before.isFile()) invalid("INVALID_FILE", setting);
    const noFollow = process.platform === "win32" ? 0 : constants.O_NOFOLLOW;
    descriptor = openSync(path, constants.O_RDONLY | noFollow);
    const stats = fstatSync(descriptor);
    if (before.dev !== stats.dev || before.ino !== stats.ino) invalid("INVALID_FILE", setting);
    validateReadableFileStats(stats, setting, privateFile);
    return path;
  } catch (error) {
    if (error instanceof RuntimeConfigurationError) throw error;
    invalid("INVALID_FILE", setting);
  } finally {
    closeFile(descriptor, setting);
  }
  return invalid("INVALID_FILE", setting);
}

function validateReadableFileStats(stats: Stats, setting: string, privateFile: boolean): void {
  if (!stats.isFile()) invalid("INVALID_FILE", setting);
  if (process.platform === "win32" || !privateFile) return;
  const effectiveUserId = typeof process.geteuid === "function" ? process.geteuid() : undefined;
  if (
    (stats.mode & 0o400) === 0 ||
    (stats.mode & SECRET_FILE_MODE_MASK) !== 0 ||
    (effectiveUserId !== undefined && stats.uid !== effectiveUserId)
  ) {
    invalid("INSECURE_FILE", setting);
  }
}

function closeFile(descriptor: number | undefined, setting: string): void {
  if (descriptor === undefined) return;
  try {
    closeSync(descriptor);
  } catch {
    invalid("INVALID_FILE", setting);
  }
}

function writableFileTarget(setting: string, value: string): string {
  const path = absolutePath(setting, value, "INVALID_TARGET_PATH");
  try {
    let targetStats: Stats | undefined;
    try {
      targetStats = lstatSync(path);
    } catch (error) {
      if (!isMissingPathError(error)) throw error;
    }
    if (targetStats !== undefined) {
      if (!targetStats.isFile()) invalid("INVALID_TARGET_PATH", setting);
      accessSync(path, constants.R_OK | constants.W_OK);
    }
    writableAncestor(dirname(path), setting);
    return path;
  } catch (error) {
    if (error instanceof RuntimeConfigurationError) throw error;
    invalid("INVALID_TARGET_PATH", setting);
  }
}

function writableDirectoryTarget(setting: string, value: string): string {
  const path = absolutePath(setting, value, "INVALID_TARGET_PATH");
  try {
    let targetStats: Stats | undefined;
    try {
      targetStats = lstatSync(path);
    } catch (error) {
      if (!isMissingPathError(error)) throw error;
    }
    if (targetStats !== undefined) {
      if (!targetStats.isDirectory()) invalid("INVALID_TARGET_PATH", setting);
      accessSync(path, constants.W_OK | constants.X_OK);
    } else {
      writableAncestor(dirname(path), setting);
    }
    return path;
  } catch (error) {
    if (error instanceof RuntimeConfigurationError) throw error;
    invalid("INVALID_TARGET_PATH", setting);
  }
}

function writableAncestor(start: string, setting: string): void {
  let candidate = start;
  while (true) {
    try {
      const stats = lstatSync(candidate);
      if (!stats.isDirectory()) invalid("INVALID_TARGET_PATH", setting);
      accessSync(candidate, constants.W_OK | constants.X_OK);
      return;
    } catch (error) {
      if (!isMissingPathError(error)) throw error;
      const parent = dirname(candidate);
      if (parent === candidate) invalid("INVALID_TARGET_PATH", setting);
      candidate = parent;
    }
  }
}

function distinctTargets(targets: readonly (readonly [string, string])[]): void {
  const seen = new Set<string>();
  for (const [setting, path] of targets) {
    if (seen.has(path)) invalid("INVALID_TARGET_PATH", setting);
    seen.add(path);
  }
}

function parseEnvironmentJson(rawJson: string, setting: string): unknown {
  try {
    return JSON.parse(rawJson) as unknown;
  } catch {
    invalid("INVALID_SETTING", setting);
  }
}

function requiredSetting(environment: RuntimeEnvironment, setting: string, maximumLength: number): string {
  const value = environment[setting];
  if (value === undefined || value.trim() === "") invalid("MISSING_SETTING", setting);
  const normalized = value.trim();
  if (normalized.length > maximumLength || /[\u0000\u007f]/.test(normalized)) {
    invalid("INVALID_SETTING", setting);
  }
  return normalized;
}

function optionalSetting(
  environment: RuntimeEnvironment,
  setting: string,
  maximumLength: number,
): string | undefined {
  const value = environment[setting];
  if (value === undefined || value.trim() === "") return undefined;
  const normalized = value.trim();
  if (normalized.length > maximumLength || /[\u0000\u007f]/.test(normalized)) {
    invalid("INVALID_SETTING", setting);
  }
  return normalized;
}

function boundedInteger(
  environment: RuntimeEnvironment,
  setting: string,
  minimum: number,
  maximum: number,
): number {
  const raw = requiredSetting(environment, setting, 32);
  if (!/^(?:0|[1-9][0-9]*)$/.test(raw)) invalid("INVALID_SETTING", setting);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalid("INVALID_SETTING", setting);
  }
  return value;
}

function boundedText(setting: string, value: string, maximumLength: number): string {
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > maximumLength ||
    /[\u0000-\u001f\u007f]/.test(normalized)
  ) {
    invalid("INVALID_SETTING", setting);
  }
  return normalized;
}

function runtimeIdentifier(setting: string, value: string): string {
  const normalized = boundedText(setting, value, 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._+/-]*$/.test(normalized)) {
    invalid("INVALID_SETTING", setting);
  }
  return normalized;
}

function bindHost(value: string): string {
  const host = boundedText("ABL_MCP_HOST", value, 253).toLowerCase();
  if (isIP(host) !== 0) return host;
  if (
    host === "localhost" ||
    (host.length <= 253 &&
      host.split(".").every(
        (label) =>
          label.length > 0 &&
          label.length <= 63 &&
          /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
      ))
  ) {
    return host;
  }
  invalid("INVALID_SETTING", "ABL_MCP_HOST");
}

function httpsUrl(
  setting: string,
  value: string,
  options: Readonly<{ originOnly: boolean; allowQuery: boolean }>,
): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    invalid("INVALID_SETTING", setting);
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    (!options.allowQuery && parsed.search !== "") ||
    (options.originOnly && (parsed.pathname !== "/" || parsed.search !== ""))
  ) {
    invalid("INVALID_SETTING", setting);
  }
  return options.originOnly ? parsed.origin : value;
}

function hostList(setting: string, raw: string): readonly string[] {
  const entries = genericList(setting, raw, /,/);
  const hosts = entries.map((entry) => {
    if (entry.includes("*")) invalid("INVALID_SETTING", setting);
    let parsed: URL;
    try {
      parsed = new URL(`https://${entry}`);
    } catch {
      invalid("INVALID_SETTING", setting);
    }
    if (
      parsed.username ||
      parsed.password ||
      parsed.pathname !== "/" ||
      parsed.search ||
      parsed.hash ||
      !parsed.host
    ) {
      invalid("INVALID_SETTING", setting);
    }
    return parsed.host.toLowerCase();
  });
  return Object.freeze(uniqueStrings(hosts, setting));
}

function originList(setting: string, raw: string): readonly string[] {
  const entries = genericList(setting, raw, /,/);
  const origins = entries.map((entry) => {
    const origin = httpsUrl(setting, entry, { originOnly: true, allowQuery: false });
    if (origin !== entry.replace(/\/$/, "")) invalid("INVALID_SETTING", setting);
    return origin;
  });
  return Object.freeze(uniqueStrings(origins, setting));
}

function scopeList(setting: string, raw: string): readonly string[] {
  const entries = genericList(setting, raw, /[\s,]+/);
  for (const scope of entries) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(scope)) invalid("INVALID_SETTING", setting);
  }
  return Object.freeze(uniqueStrings(entries, setting));
}

function genericList(setting: string, raw: string, separator: RegExp): string[] {
  let entries: unknown;
  if (raw.startsWith("[")) {
    entries = parseEnvironmentJson(raw, setting);
  } else {
    entries = raw.split(separator).filter(Boolean);
  }
  const result = z.array(boundedTextSchema).min(1).max(256).safeParse(entries);
  if (!result.success) invalid("INVALID_SETTING", setting);
  const normalized = result.data.map((entry) => entry.trim());
  if (normalized.some((entry) => entry.length === 0)) invalid("INVALID_SETTING", setting);
  return normalized;
}

function uniqueTextSet(values: readonly string[], setting: string): string[] {
  const normalized = values.map((value) => boundedText(setting, value, 2_048));
  return uniqueStrings(normalized, setting);
}

function uniqueStrings(values: readonly string[], setting: string): string[] {
  const unique = new Set(values);
  if (unique.size !== values.length) invalid("INVALID_SETTING", setting);
  return [...unique].sort();
}

function absolutePath(
  setting: string,
  value: string,
  code: "INVALID_FILE" | "INVALID_TARGET_PATH",
): string {
  if (!isAbsolute(value)) invalid(code, setting);
  const normalized = resolve(value);
  if (normalized.length > 4_096) invalid(code, setting);
  return normalized;
}

function isMissingPathError(error: unknown): boolean {
  return Boolean(
    error &&
      typeof error === "object" &&
      "code" in error &&
      (error as Readonly<{ code?: unknown }>).code === "ENOENT",
  );
}

function invalid(code: RuntimeConfigurationErrorCode, setting: string): never {
  throw new RuntimeConfigurationError(code, setting);
}
