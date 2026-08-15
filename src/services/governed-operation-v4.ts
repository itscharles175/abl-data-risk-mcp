import { Buffer } from "node:buffer";

import { z } from "zod/v4";

import {
  ContractValidationError,
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  canonicalJson,
  deepFreeze,
  parseWithSchema,
  type CanonicalJsonValue,
  type Sha256Hash
} from "../contracts/canonical.js";
import { artifactJsonContentHash } from "../control/artifacts.js";
import { PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR } from "./operations/portfolio-surveillance-v1.js";
import {
  accountPlanBoundPortfolioSurveillanceResultEvidenceV1,
  accountPortfolioSurveillanceOperationResultV1,
  parsePortfolioSurveillanceExecutionPlanV1,
  type PortfolioSurveillanceExecutionPlanV1,
  type PortfolioSurveillanceOperationResultV1
} from "./operations/portfolio-surveillance-v1.js";

const OPERATION = "portfolio_surveillance_v1" as const;
const MAXIMUM_PLAN_ARTIFACT_BYTES = 10_000_000;
const BareHashSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const PurposeSchema = IdentifierSchema;

const CanonicalJsonSchema = z.custom<CanonicalJsonValue>((value) => {
  try {
    canonicalHash(value);
    return true;
  } catch {
    return false;
  }
}, "must be canonical JSON");

function sortedUniqueStrings(
  item: z.ZodType<string>,
  minimum: number,
  maximum: number,
  label: string
) {
  return z
    .array(item)
    .min(minimum)
    .max(maximum)
    .superRefine((values, context) => {
      if (
        new Set(values).size !== values.length ||
        canonicalJson([...values].sort(compare)) !== canonicalJson(values)
      ) {
        context.addIssue({
          code: "custom",
          message: `${label} must be unique and sorted`
        });
      }
    });
}

const IdentityAttestationSchema = z
  .object({
    issuer: z.string().min(1).max(2_048),
    subject: z.string().min(1).max(512),
    principalId: IdentifierSchema,
    tenantId: IdentifierSchema,
    clientId: z.string().min(1).max(512).optional(),
    audiences: sortedUniqueStrings(z.string().min(1).max(512), 1, 64, "audiences"),
    resourceIndicators: sortedUniqueStrings(
      z.string().url().min(1).max(2_048),
      1,
      64,
      "resource indicators"
    ),
    scopes: sortedUniqueStrings(IdentifierSchema, 0, 256, "scopes"),
    credentialFingerprint: BareHashSchema,
    verifiedAtEpochSeconds: z.number().int().nonnegative(),
    notBeforeEpochSeconds: z.number().int().nonnegative().optional(),
    expiresAtEpochSeconds: z.number().int().nonnegative(),
    authenticationMethods: sortedUniqueStrings(
      IdentifierSchema,
      0,
      256,
      "authentication methods"
    ).optional()
  })
  .strict()
  .superRefine((value, context) => {
    rejectExplicitUndefined(
      value,
      ["clientId", "notBeforeEpochSeconds", "authenticationMethods"],
      context
    );
    if (value.verifiedAtEpochSeconds >= value.expiresAtEpochSeconds) {
      context.addIssue({
        code: "custom",
        path: ["expiresAtEpochSeconds"],
        message: "must be after verifiedAtEpochSeconds"
      });
    }
    if (
      value.notBeforeEpochSeconds !== undefined &&
      value.notBeforeEpochSeconds >= value.expiresAtEpochSeconds
    ) {
      context.addIssue({
        code: "custom",
        path: ["notBeforeEpochSeconds"],
        message: "must be before expiresAtEpochSeconds"
      });
    }
  });

const PolicyObligationsSchema = z
  .object({
    maxResultRows: z.number().int().positive(),
    maxResultBytes: z.number().int().positive(),
    maxExecutionMs: z.number().int().positive(),
    minimumCohortSize: z.number().int().positive(),
    requireImmutableSnapshot: z.boolean(),
    allowRawRows: z.boolean(),
    allowExport: z.boolean(),
    rowFilterRefs: sortedUniqueStrings(IdentifierSchema, 0, 10_000, "row filter references"),
    fieldMasks: z.record(
      IdentifierSchema,
      z.enum(["partial", "hash", "tokenize", "redact"])
    ),
    auditTags: sortedUniqueStrings(IdentifierSchema, 0, 256, "audit tags")
  })
  .strict();

const AuthorizationDecisionSchema = z
  .object({
    decisionId: BareHashSchema,
    policyFingerprint: BareHashSchema,
    tenantId: IdentifierSchema,
    principalId: IdentifierSchema,
    requestedFields: sortedUniqueStrings(IdentifierSchema, 1, 2_000, "requested fields"),
    purpose: PurposeSchema,
    obligations: PolicyObligationsSchema
  })
  .strict();

const ExecutionAuthorizationSchema = AuthorizationDecisionSchema.extend({
  authorizedAt: IsoTimestampSchema,
  startedAt: IsoTimestampSchema,
  completedAt: IsoTimestampSchema
}).strict();

export type GovernedExecutionAuthorizationV4 = Readonly<
  z.infer<typeof ExecutionAuthorizationSchema>
>;

const DescriptorBindingSchema = z
  .object({
    descriptorHash: Sha256HashSchema,
    requestSchemaHash: Sha256HashSchema,
    executionSchemaHash: Sha256HashSchema,
    resultSchemaHash: Sha256HashSchema
  })
  .strict()
  .superRefine((value, context) => {
    const expected = descriptorBinding();
    for (const key of [
      "descriptorHash",
      "requestSchemaHash",
      "executionSchemaHash",
      "resultSchemaHash"
    ] as const) {
      if (value[key] !== expected[key]) {
        context.addIssue({
          code: "custom",
          path: [key],
          message: "must match the registered portfolio surveillance descriptor"
        });
      }
    }
  });

const PlanArtifactReferenceSchema = z
  .object({
    artifactId: BareHashSchema,
    kind: z.literal("governed_portfolio_surveillance_plan_v4"),
    mediaType: z.literal("application/json"),
    contentHash: BareHashSchema,
    byteLength: z.number().int().positive().max(MAXIMUM_PLAN_ARTIFACT_BYTES)
  })
  .strict();

export type GovernedPlanArtifactReferenceV4 = Readonly<
  z.infer<typeof PlanArtifactReferenceSchema>
>;

const PortfolioSurveillanceAuthorizationPreflightV4BodySchema = z
  .object({
    contractVersion: z.literal(1),
    operation: z.literal(OPERATION),
    tenantId: IdentifierSchema,
    purpose: PurposeSchema,
    descriptor: DescriptorBindingSchema,
    requestHash: Sha256HashSchema,
    datasetId: IdentifierSchema,
    scopeHash: Sha256HashSchema,
    sourceIdentityHash: Sha256HashSchema,
    sourceSelectionHash: Sha256HashSchema,
    sourceAccessPolicySetHash: Sha256HashSchema,
    datasetScopeBindingSetHash: Sha256HashSchema,
    definitionSetHash: Sha256HashSchema,
    requestedFields: sortedUniqueStrings(IdentifierSchema, 1, 2_000, "requested fields"),
    requestedFieldsHash: Sha256HashSchema,
    planningCutoff: IsoTimestampSchema,
    maximumPlannedCells: z.number().int().positive().max(1_000_000),
    minimumMetricCellCount: z.number().int().positive().max(1_000_000)
  })
  .strict();

export const PortfolioSurveillanceAuthorizationPreflightV4Schema =
  PortfolioSurveillanceAuthorizationPreflightV4BodySchema.extend({
    preflightHash: Sha256HashSchema
  }).strict();

export type PortfolioSurveillanceAuthorizationPreflightV4 = Readonly<
  z.infer<typeof PortfolioSurveillanceAuthorizationPreflightV4Schema>
>;

export type PortfolioSurveillanceAuthorizationPreflightV4Input = Readonly<
  z.input<typeof PortfolioSurveillanceAuthorizationPreflightV4BodySchema>
>;

export function createPortfolioSurveillanceAuthorizationPreflightV4(
  input: PortfolioSurveillanceAuthorizationPreflightV4Input
): PortfolioSurveillanceAuthorizationPreflightV4 {
  const body = parseWithSchema(
    PortfolioSurveillanceAuthorizationPreflightV4BodySchema,
    input,
    "PortfolioSurveillanceAuthorizationPreflightV4"
  );
  assertRequestedFieldsHash(body.requestedFields, body.requestedFieldsHash, "preflight");
  return parsePortfolioSurveillanceAuthorizationPreflightV4({
    ...body,
    preflightHash: canonicalHash(body)
  });
}

export function parsePortfolioSurveillanceAuthorizationPreflightV4(
  value: unknown
): PortfolioSurveillanceAuthorizationPreflightV4 {
  const parsed = parseWithSchema(
    PortfolioSurveillanceAuthorizationPreflightV4Schema,
    value,
    "PortfolioSurveillanceAuthorizationPreflightV4"
  );
  const { preflightHash, ...body } = parsed;
  assertCanonicalHash(body, preflightHash, "PortfolioSurveillanceAuthorizationPreflightV4");
  assertRequestedFieldsHash(parsed.requestedFields, parsed.requestedFieldsHash, "preflight");
  return parsed;
}

const GovernedExecutionEnvelopeV4BodySchema = z
  .object({
    version: z.literal(4),
    operation: z.literal(OPERATION),
    tenantId: IdentifierSchema,
    purpose: PurposeSchema,
    identity: IdentityAttestationSchema,
    descriptor: DescriptorBindingSchema,
    preflight: PortfolioSurveillanceAuthorizationPreflightV4Schema,
    planArtifact: PlanArtifactReferenceSchema,
    requestHash: Sha256HashSchema,
    planHash: Sha256HashSchema,
    sourceSelectionHash: Sha256HashSchema,
    sourceIdentityHash: Sha256HashSchema,
    sourceAccessPolicySetHash: Sha256HashSchema,
    datasetScopeBindingSetHash: Sha256HashSchema,
    sourceSetHash: Sha256HashSchema,
    definitionSetHash: Sha256HashSchema,
    requestedFields: sortedUniqueStrings(IdentifierSchema, 1, 2_000, "requested fields"),
    requestedFieldsHash: Sha256HashSchema,
    datasetId: IdentifierSchema,
    scopeHash: Sha256HashSchema,
    planningCutoff: IsoTimestampSchema,
    planTtlSeconds: z.number().int().min(1).max(900),
    startAuthorization: AuthorizationDecisionSchema,
    parameterFingerprint: BareHashSchema,
    idempotencyFingerprint: BareHashSchema,
    startFingerprint: BareHashSchema
  })
  .strict();

export const GovernedExecutionEnvelopeV4Schema =
  GovernedExecutionEnvelopeV4BodySchema.extend({
    envelopeHash: Sha256HashSchema
  }).strict();

export type GovernedExecutionEnvelopeV4 = Readonly<
  z.infer<typeof GovernedExecutionEnvelopeV4Schema>
>;

export type GovernedExecutionEnvelopeV4Input = Readonly<
  z.input<typeof GovernedExecutionEnvelopeV4BodySchema>
>;

export function createGovernedExecutionEnvelopeV4(
  input: GovernedExecutionEnvelopeV4Input
): GovernedExecutionEnvelopeV4 {
  const body = parseWithSchema(
    GovernedExecutionEnvelopeV4BodySchema,
    input,
    "GovernedExecutionEnvelopeV4"
  );
  assertEnvelopeBindings(body);
  return parseGovernedExecutionEnvelopeV4({
    ...body,
    envelopeHash: canonicalHash(body)
  });
}

export function parseGovernedExecutionEnvelopeV4(
  value: unknown
): GovernedExecutionEnvelopeV4 {
  const parsed = parseWithSchema(
    GovernedExecutionEnvelopeV4Schema,
    value,
    "GovernedExecutionEnvelopeV4"
  );
  const { envelopeHash, ...body } = parsed;
  assertCanonicalHash(body, envelopeHash, "GovernedExecutionEnvelopeV4");
  assertEnvelopeBindings(parsed);
  return parsed;
}

const ResultAccountingSchema = z
  .object({
    aggregateRows: z.number().int().nonnegative(),
    cellCount: z.number().int().nonnegative(),
    warningCount: z.number().int().nonnegative(),
    metricHeaderCount: z.number().int().nonnegative(),
    disclosedItemCount: z.number().int().nonnegative(),
    bytes: z.number().int().nonnegative(),
    metricCount: z.number().int().nonnegative(),
    suppressedCellCount: z.number().int().nonnegative(),
    unavailableCellCount: z.number().int().nonnegative(),
    populationHashes: sortedUniqueStrings(
      Sha256HashSchema,
      0,
      3_000_000,
      "population hashes"
    ),
    disclosureClasses: sortedUniqueStrings(
      IdentifierSchema,
      0,
      64,
      "disclosure classes"
    )
  })
  .strict()
  .superRefine((value, context) => {
    if (
      value.aggregateRows !== value.cellCount ||
      value.disclosedItemCount !==
        value.cellCount + value.warningCount + value.metricHeaderCount
    ) {
      context.addIssue({
        code: "custom",
        message: "disclosed item accounting must exactly reconcile"
      });
    }
    if (
      value.suppressedCellCount > value.aggregateRows ||
      value.unavailableCellCount > value.aggregateRows
    ) {
      context.addIssue({
        code: "custom",
        message: "suppressed and unavailable cell counts cannot exceed aggregate rows"
      });
    }
  });

export type GovernedResultAccountingV4 = Readonly<
  z.infer<typeof ResultAccountingSchema>
>;

const ResultLineageSchema = z
  .object({
    tenantId: IdentifierSchema,
    purpose: PurposeSchema,
    envelopeHash: Sha256HashSchema,
    descriptor: DescriptorBindingSchema,
    preflightHash: Sha256HashSchema,
    planningCutoff: IsoTimestampSchema,
    planArtifact: PlanArtifactReferenceSchema,
    requestHash: Sha256HashSchema,
    planHash: Sha256HashSchema,
    sourceIdentityHash: Sha256HashSchema,
    sourceSelectionHash: Sha256HashSchema,
    sourceAccessPolicySetHash: Sha256HashSchema,
    datasetScopeBindingSetHash: Sha256HashSchema,
    sourceSetHash: Sha256HashSchema,
    definitionSetHash: Sha256HashSchema,
    requestedFieldsHash: Sha256HashSchema,
    datasetId: IdentifierSchema,
    scopeHash: Sha256HashSchema
  })
  .strict();

export type GovernedResultLineageV4 = Readonly<z.infer<typeof ResultLineageSchema>>;

const ResultAuthorizationSchema = ExecutionAuthorizationSchema;

const GovernedResultArtifactV4SeedSchema = z
  .object({
    version: z.literal(4),
    jobId: IdentifierSchema,
    manifestId: IdentifierSchema,
    operation: z.literal(OPERATION),
    tenantId: IdentifierSchema,
    purpose: PurposeSchema,
    result: CanonicalJsonSchema
  })
  .strict();

const GovernedResultArtifactV4CoreSchema = GovernedResultArtifactV4SeedSchema.extend({
  authorization: ResultAuthorizationSchema,
  lineage: ResultLineageSchema,
  accounting: ResultAccountingSchema
}).strict();

export const GovernedResultArtifactV4Schema = GovernedResultArtifactV4CoreSchema.extend({
  lineageHash: Sha256HashSchema,
  accountingHash: Sha256HashSchema,
  resultHash: Sha256HashSchema
}).strict();

export type GovernedResultArtifactV4 = Readonly<
  z.infer<typeof GovernedResultArtifactV4Schema>
>;

export type GovernedResultArtifactV4Input = Readonly<
  z.input<typeof GovernedResultArtifactV4SeedSchema>
>;

export interface GovernedResultFinalizationInstrumentationV4 {
  /** Test/telemetry hook; it cannot replace or alter deterministic validation. */
  readonly onDeterministicReplay?: () => void;
}

/**
 * The only artifact-minting path. It validates the exact frozen execution plan,
 * reruns deterministic disclosure validation, derives accounting, and enforces
 * every result obligation before hashing the durable artifact.
 */
export function finalizeGovernedResultArtifactV4(
  input: GovernedResultArtifactV4Input,
  envelopeValue: unknown,
  planValue: PortfolioSurveillanceExecutionPlanV1,
  executionAuthorizationValue: GovernedExecutionAuthorizationV4,
  instrumentation?: GovernedResultFinalizationInstrumentationV4
): GovernedResultArtifactV4 {
  const seed = parseWithSchema(
    GovernedResultArtifactV4SeedSchema,
    input,
    "GovernedResultArtifactV4"
  );
  const envelope = parseGovernedExecutionEnvelopeV4(envelopeValue);
  const plan = parseAndBindPlan(planValue, envelope);
  const executionAuthorization = parseWithSchema(
    ExecutionAuthorizationSchema,
    executionAuthorizationValue,
    "GovernedExecutionAuthorizationV4"
  );
  assertExecutionAuthorization(executionAuthorization, envelope);
  const accounting = validatedAccounting(
    seed.result,
    plan,
    instrumentation?.onDeterministicReplay
  );
  const core = parseWithSchema(GovernedResultArtifactV4CoreSchema, {
    ...seed,
    authorization: executionAuthorization,
    lineage: governedV4LineageFromEnvelope(envelope),
    accounting
  }, "GovernedResultArtifactV4");
  const artifact = parseGovernedResultArtifactV4Structure({
    ...core,
    lineageHash: canonicalHash(core.lineage),
    accountingHash: canonicalHash(core.accounting),
    resultHash: canonicalHash(core.result)
  });
  assertGovernedResultArtifactV4MatchesEnvelopeUsingAccounting(
    artifact,
    envelope,
    plan,
    executionAuthorization,
    accounting
  );
  return artifact;
}

/** Structural/self-hash validation only; it does not authorize disclosure. */
export function parseGovernedResultArtifactV4Structure(
  value: unknown
): GovernedResultArtifactV4 {
  const parsed = parseWithSchema(
    GovernedResultArtifactV4Schema,
    value,
    "GovernedResultArtifactV4"
  );
  if (parsed.jobId !== parsed.manifestId) {
    invariant("GovernedResultArtifactV4 jobId must equal manifestId");
  }
  assertCanonicalHash(parsed.lineage, parsed.lineageHash, "GovernedResultArtifactV4 lineage");
  assertCanonicalHash(
    parsed.accounting,
    parsed.accountingHash,
    "GovernedResultArtifactV4 accounting"
  );
  assertCanonicalHash(parsed.result, parsed.resultHash, "GovernedResultArtifactV4 result");
  assertRequestedFieldsHash(
    parsed.authorization.requestedFields,
    parsed.lineage.requestedFieldsHash,
    "result authorization"
  );
  if (
    parsed.tenantId !== parsed.lineage.tenantId ||
    parsed.purpose !== parsed.lineage.purpose ||
    parsed.authorization.purpose !== parsed.purpose
  ) {
    invariant("GovernedResultArtifactV4 tenant or purpose lineage did not verify");
  }
  if (Buffer.byteLength(canonicalJson(parsed.result), "utf8") !== parsed.accounting.bytes) {
    invariant("GovernedResultArtifactV4 accounting bytes did not match the canonical result");
  }
  assertOperationResultLineage(parsed);
  return parsed;
}

export function governedV4LineageFromEnvelope(
  envelopeValue: GovernedExecutionEnvelopeV4
): GovernedResultLineageV4 {
  const envelope = parseGovernedExecutionEnvelopeV4(envelopeValue);
  return deepFreeze({
    tenantId: envelope.tenantId,
    purpose: envelope.purpose,
    envelopeHash: envelope.envelopeHash,
    descriptor: envelope.descriptor,
    preflightHash: envelope.preflight.preflightHash,
    planningCutoff: envelope.planningCutoff,
    planArtifact: envelope.planArtifact,
    requestHash: envelope.requestHash,
    planHash: envelope.planHash,
    sourceIdentityHash: envelope.sourceIdentityHash,
    sourceSelectionHash: envelope.sourceSelectionHash,
    sourceAccessPolicySetHash: envelope.sourceAccessPolicySetHash,
    datasetScopeBindingSetHash: envelope.datasetScopeBindingSetHash,
    sourceSetHash: envelope.sourceSetHash,
    definitionSetHash: envelope.definitionSetHash,
    requestedFieldsHash: envelope.requestedFieldsHash,
    datasetId: envelope.datasetId,
    scopeHash: envelope.scopeHash
  });
}

export function assertGovernedResultArtifactV4MatchesEnvelope(
  resultValue: unknown,
  envelopeValue: unknown,
  planValue: PortfolioSurveillanceExecutionPlanV1,
  executionAuthorizationValue: GovernedExecutionAuthorizationV4
): void {
  const result = parseGovernedResultArtifactV4Structure(resultValue);
  const envelope = parseGovernedExecutionEnvelopeV4(envelopeValue);
  const plan = parseAndBindPlan(planValue, envelope);
  const executionAuthorization = parseWithSchema(
    ExecutionAuthorizationSchema,
    executionAuthorizationValue,
    "GovernedExecutionAuthorizationV4"
  );
  assertExecutionAuthorization(executionAuthorization, envelope);
  const expectedAccounting = validatedAccounting(result.result, plan);
  assertGovernedResultArtifactV4MatchesEnvelopeUsingAccounting(
    result,
    envelope,
    plan,
    executionAuthorization,
    expectedAccounting
  );
}

/**
 * Verifies immutable result evidence on recovery/read paths without replaying
 * the full analytics engine. Deterministic replay remains mandatory before
 * the artifact is minted; subsequent reads verify its exact bytes, hashes,
 * accounting, authorization, and frozen-plan lineage.
 */
export function assertGovernedResultArtifactV4EvidenceMatchesEnvelope(
  resultValue: unknown,
  envelopeValue: unknown,
  planValue: PortfolioSurveillanceExecutionPlanV1,
  executionAuthorizationValue: GovernedExecutionAuthorizationV4
): void {
  const result = parseGovernedResultArtifactV4Structure(resultValue);
  const envelope = parseGovernedExecutionEnvelopeV4(envelopeValue);
  const plan = parseAndBindPlan(planValue, envelope);
  const executionAuthorization = parseWithSchema(
    ExecutionAuthorizationSchema,
    executionAuthorizationValue,
    "GovernedExecutionAuthorizationV4"
  );
  assertExecutionAuthorization(executionAuthorization, envelope);
  const expectedAccounting = evidencedAccounting(result.result, plan);
  assertGovernedResultArtifactV4MatchesEnvelopeUsingAccounting(
    result,
    envelope,
    plan,
    executionAuthorization,
    expectedAccounting
  );
}

function assertGovernedResultArtifactV4MatchesEnvelopeUsingAccounting(
  result: GovernedResultArtifactV4,
  envelope: GovernedExecutionEnvelopeV4,
  plan: PortfolioSurveillanceExecutionPlanV1,
  executionAuthorization: GovernedExecutionAuthorizationV4,
  expectedAccounting: GovernedResultAccountingV4
): void {
  const expectedLineage = governedV4LineageFromEnvelope(envelope);
  if (
    result.tenantId !== envelope.tenantId ||
    result.purpose !== envelope.purpose ||
    canonicalJson(result.authorization) !== canonicalJson(executionAuthorization) ||
    canonicalJson(result.lineage) !== canonicalJson(expectedLineage) ||
    canonicalJson(result.accounting) !== canonicalJson(expectedAccounting)
  ) {
    invariant("GovernedResultArtifactV4 did not match its frozen execution envelope");
  }
  enforceResultObligations(result, plan, envelope);
}

const StoredResultArtifactReferenceSchema = z
  .object({
    artifactId: BareHashSchema,
    kind: z.literal("governed_analysis_result_v4"),
    mediaType: z.literal("application/json"),
    contentHash: BareHashSchema,
    byteLength: z.number().int().positive().max(MAXIMUM_PLAN_ARTIFACT_BYTES)
  })
  .strict();

export type GovernedStoredResultArtifactReferenceV4 = Readonly<
  z.infer<typeof StoredResultArtifactReferenceSchema>
>;

const GovernedResultManifestV4SeedSchema = z
  .object({
    version: z.literal(4),
    createdAt: IsoTimestampSchema,
    codeVersion: IdentifierSchema,
    planId: BareHashSchema
  })
  .strict();

const GovernedResultManifestV4CoreSchema = z
  .object({
    version: z.literal(4),
    manifestId: IdentifierSchema,
    jobId: IdentifierSchema,
    operation: z.literal(OPERATION),
    tenantId: IdentifierSchema,
    purpose: PurposeSchema,
    createdBy: z.string().min(1).max(2_048),
    createdAt: IsoTimestampSchema,
    codeVersion: IdentifierSchema,
    planId: BareHashSchema,
    lineage: ResultLineageSchema,
    resultArtifact: StoredResultArtifactReferenceSchema,
    resultHash: Sha256HashSchema,
    accounting: ResultAccountingSchema
  })
  .strict();

export const GovernedResultManifestV4Schema = GovernedResultManifestV4CoreSchema.extend({
  lineageHash: Sha256HashSchema,
  accountingHash: Sha256HashSchema,
  manifestHash: Sha256HashSchema
}).strict();

export type GovernedResultManifestV4 = Readonly<
  z.infer<typeof GovernedResultManifestV4Schema>
>;

export type GovernedResultManifestV4Input = Readonly<
  z.input<typeof GovernedResultManifestV4SeedSchema>
>;

export function finalizeGovernedResultManifestV4(
  input: GovernedResultManifestV4Input,
  resultValue: unknown,
  storedResultArtifactValue: GovernedStoredResultArtifactReferenceV4
): GovernedResultManifestV4 {
  const seed = parseWithSchema(
    GovernedResultManifestV4SeedSchema,
    input,
    "GovernedResultManifestV4"
  );
  const result = parseGovernedResultArtifactV4Structure(resultValue);
  const resultArtifact = parseWithSchema(
    StoredResultArtifactReferenceSchema,
    storedResultArtifactValue,
    "GovernedStoredResultArtifactReferenceV4"
  );
  assertStoredResultArtifact(result, resultArtifact);
  const core = parseWithSchema(GovernedResultManifestV4CoreSchema, {
    ...seed,
    manifestId: result.manifestId,
    jobId: result.jobId,
    operation: OPERATION,
    tenantId: result.tenantId,
    purpose: result.purpose,
    createdBy: result.authorization.principalId,
    lineage: result.lineage,
    resultArtifact,
    resultHash: result.resultHash,
    accounting: result.accounting
  }, "GovernedResultManifestV4");
  if (Date.parse(core.createdAt) < Date.parse(result.authorization.completedAt)) {
    invariant("GovernedResultManifestV4 cannot predate completed execution");
  }
  const body = {
    ...core,
    lineageHash: canonicalHash(core.lineage),
    accountingHash: canonicalHash(core.accounting)
  };
  const manifest = parseGovernedResultManifestV4Structure({
    ...body,
    manifestHash: canonicalHash(body)
  });
  assertGovernedResultManifestV4MatchesResult(manifest, result);
  return manifest;
}

/** Structural/self-hash validation only; it does not verify stored bytes. */
export function parseGovernedResultManifestV4Structure(value: unknown): GovernedResultManifestV4 {
  const parsed = parseWithSchema(
    GovernedResultManifestV4Schema,
    value,
    "GovernedResultManifestV4"
  );
  if (parsed.jobId !== parsed.manifestId) {
    invariant("GovernedResultManifestV4 jobId must equal manifestId");
  }
  assertCanonicalHash(parsed.lineage, parsed.lineageHash, "GovernedResultManifestV4 lineage");
  assertCanonicalHash(
    parsed.accounting,
    parsed.accountingHash,
    "GovernedResultManifestV4 accounting"
  );
  const { manifestHash, ...body } = parsed;
  assertCanonicalHash(body, manifestHash, "GovernedResultManifestV4");
  if (
    parsed.tenantId !== parsed.lineage.tenantId ||
    parsed.purpose !== parsed.lineage.purpose
  ) {
    invariant("GovernedResultManifestV4 tenant or purpose lineage did not verify");
  }
  if (Date.parse(parsed.createdAt) < Date.parse(parsed.lineage.planningCutoff)) {
    invariant("GovernedResultManifestV4 cannot predate its frozen planning cutoff");
  }
  if (
    parsed.lineage.planArtifact.artifactId.length !== 64 ||
    parsed.lineage.planArtifact.contentHash.length !== 64 ||
    !parsed.lineage.planHash.startsWith("sha256:")
  ) {
    invariant("GovernedResultManifestV4 plan artifact lineage did not verify");
  }
  return parsed;
}

export function assertGovernedResultManifestV4MatchesResult(
  manifestValue: unknown,
  resultValue: unknown
): void {
  const manifest = parseGovernedResultManifestV4Structure(manifestValue);
  const result = parseGovernedResultArtifactV4Structure(resultValue);
  if (
    manifest.jobId !== result.jobId ||
    manifest.manifestId !== result.manifestId ||
    manifest.tenantId !== result.tenantId ||
    manifest.purpose !== result.purpose ||
    manifest.resultHash !== result.resultHash ||
    manifest.lineageHash !== result.lineageHash ||
    manifest.accountingHash !== result.accountingHash ||
    canonicalJson(manifest.lineage) !== canonicalJson(result.lineage) ||
    canonicalJson(manifest.accounting) !== canonicalJson(result.accounting) ||
    manifest.createdBy !== result.authorization.principalId ||
    Date.parse(manifest.createdAt) < Date.parse(result.authorization.completedAt)
  ) {
    invariant("GovernedResultManifestV4 did not match its frozen result artifact");
  }
  assertStoredResultArtifact(result, manifest.resultArtifact);
}

/**
 * Finalization-time principal binding. The manifest is independently durable,
 * so its creator must be checked against the verified principal binding that
 * signed the execution plan; that binding is intentionally not caller text in
 * either the analytical result or its lineage.
 */
export function assertGovernedResultManifestV4Creator(
  manifestValue: unknown,
  verifiedPrincipalBinding: string
): void {
  const manifest = parseGovernedResultManifestV4Structure(manifestValue);
  if (
    typeof verifiedPrincipalBinding !== "string" ||
    verifiedPrincipalBinding.length < 1 ||
    verifiedPrincipalBinding.length > 2_048 ||
    manifest.createdBy !== verifiedPrincipalBinding
  ) {
    invariant("GovernedResultManifestV4 creator did not match the verified principal binding");
  }
}

export function portfolioSurveillanceDescriptorBindingV4(): Readonly<{
  descriptorHash: Sha256Hash;
  requestSchemaHash: Sha256Hash;
  executionSchemaHash: Sha256Hash;
  resultSchemaHash: Sha256Hash;
}> {
  return deepFreeze(descriptorBinding());
}

function descriptorBinding() {
  return {
    descriptorHash: PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR.descriptorHash,
    requestSchemaHash: PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR.requestSchemaHash,
    executionSchemaHash: PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR.executionSchemaHash,
    resultSchemaHash: PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR.resultSchemaHash
  };
}

function assertEnvelopeBindings(
  envelope: Readonly<z.infer<typeof GovernedExecutionEnvelopeV4BodySchema>>
): void {
  const preflight = parsePortfolioSurveillanceAuthorizationPreflightV4(envelope.preflight);
  const planningCutoffEpochSeconds = Math.floor(Date.parse(envelope.planningCutoff) / 1_000);
  assertRequestedFieldsHash(envelope.requestedFields, envelope.requestedFieldsHash, "envelope");
  if (
    envelope.identity.tenantId !== envelope.tenantId ||
    envelope.startAuthorization.tenantId !== envelope.tenantId ||
    envelope.startAuthorization.principalId !== envelope.identity.principalId ||
    envelope.startAuthorization.purpose !== envelope.purpose ||
    canonicalJson(envelope.startAuthorization.requestedFields) !==
      canonicalJson(envelope.requestedFields) ||
    preflight.tenantId !== envelope.tenantId ||
    preflight.purpose !== envelope.purpose ||
    preflight.requestHash !== envelope.requestHash ||
    canonicalJson(preflight.descriptor) !== canonicalJson(envelope.descriptor) ||
    preflight.sourceSelectionHash !== envelope.sourceSelectionHash ||
    preflight.sourceIdentityHash !== envelope.sourceIdentityHash ||
    preflight.sourceAccessPolicySetHash !== envelope.sourceAccessPolicySetHash ||
    preflight.datasetScopeBindingSetHash !== envelope.datasetScopeBindingSetHash ||
    preflight.definitionSetHash !== envelope.definitionSetHash ||
    canonicalJson(preflight.requestedFields) !== canonicalJson(envelope.requestedFields) ||
    preflight.requestedFieldsHash !== envelope.requestedFieldsHash ||
    preflight.datasetId !== envelope.datasetId ||
    preflight.scopeHash !== envelope.scopeHash ||
    preflight.planningCutoff !== envelope.planningCutoff
  ) {
    invariant("GovernedExecutionEnvelopeV4 did not match its authorization preflight");
  }
  if (envelope.parameterFingerprint !== bareHash(envelope.planHash)) {
    invariant("GovernedExecutionEnvelopeV4 parameter fingerprint must bind planHash");
  }
  const startObligations = envelope.startAuthorization.obligations;
  if (
    !startObligations.requireImmutableSnapshot ||
    startObligations.allowRawRows ||
    startObligations.allowExport ||
    startObligations.rowFilterRefs.length !== 0 ||
    Object.keys(startObligations.fieldMasks).length !== 0 ||
    preflight.maximumPlannedCells > startObligations.maxResultRows ||
    preflight.minimumMetricCellCount < startObligations.minimumCohortSize
  ) {
    invariant("GovernedExecutionEnvelopeV4 start authorization cannot satisfy the plan");
  }
  if (
    envelope.identity.verifiedAtEpochSeconds > planningCutoffEpochSeconds ||
    (envelope.identity.notBeforeEpochSeconds !== undefined &&
      envelope.identity.notBeforeEpochSeconds > planningCutoffEpochSeconds) ||
    envelope.identity.expiresAtEpochSeconds <= planningCutoffEpochSeconds
  ) {
    invariant("GovernedExecutionEnvelopeV4 planning cutoff must be inside the identity validity window");
  }
}

function parseAndBindPlan(
  planValue: PortfolioSurveillanceExecutionPlanV1,
  envelope: GovernedExecutionEnvelopeV4
): PortfolioSurveillanceExecutionPlanV1 {
  let plan: PortfolioSurveillanceExecutionPlanV1;
  try {
    plan = parsePortfolioSurveillanceExecutionPlanV1(planValue);
  } catch {
    invariant("GovernedExecutionEnvelopeV4 execution plan did not validate");
  }
  const canonicalPlan = canonicalJson(plan);
  const sourceDatasetAndScopeMatch = plan.sourceLineage.every(
    (source) =>
      source.datasetId === envelope.datasetId &&
      canonicalHash(source.scope) === envelope.scopeHash
  );
  const sourceIdentityHash = canonicalHash(
    plan.sourceLineage.map(({ datasetId, source, scope }) => ({ datasetId, source, scope }))
  );
  const governanceBindings = plan.governanceBindings;
  if (governanceBindings === undefined) {
    invariant("GovernedExecutionEnvelopeV4 requires authority-bound plan governance");
  }
  const maximumPlannedCells = plan.engineInput.metricDefinitions.reduce(
    (sum, metric) => sum + metric.maximumCells,
    0
  );
  const minimumMetricCellCount = Math.min(
    ...plan.engineInput.metricDefinitions.map((metric) => metric.privacy.minimumCellCount)
  );
  if (
    plan.tenantId !== envelope.tenantId ||
    plan.purpose !== envelope.purpose ||
    plan.descriptorHash !== envelope.descriptor.descriptorHash ||
    plan.requestHash !== envelope.requestHash ||
    plan.planHash !== envelope.planHash ||
    plan.sourceSetHash !== envelope.sourceSetHash ||
    sourceIdentityHash !== envelope.sourceIdentityHash ||
    governanceBindings.preflightHash !== envelope.preflight.preflightHash ||
    governanceBindings.sourceSelectionHash !== envelope.sourceSelectionHash ||
    governanceBindings.sourceIdentityHash !== envelope.sourceIdentityHash ||
    canonicalHash(governanceBindings.sourceAccessPolicies) !==
      envelope.sourceAccessPolicySetHash ||
    governanceBindings.sourceAccessPolicySetHash !== envelope.sourceAccessPolicySetHash ||
    canonicalHash(governanceBindings.datasetScopeBindings) !==
      envelope.datasetScopeBindingSetHash ||
    governanceBindings.datasetScopeBindingSetHash !==
      envelope.datasetScopeBindingSetHash ||
    plan.definitionSetHash !== envelope.definitionSetHash ||
    plan.requestedFieldsHash !== envelope.requestedFieldsHash ||
    canonicalJson(plan.requestedFields) !== canonicalJson(envelope.requestedFields) ||
    envelope.planArtifact.contentHash !== artifactJsonContentHash(plan) ||
    envelope.planArtifact.byteLength !== Buffer.byteLength(canonicalPlan, "utf8") ||
    !sourceDatasetAndScopeMatch ||
    maximumPlannedCells > envelope.preflight.maximumPlannedCells ||
    minimumMetricCellCount < envelope.preflight.minimumMetricCellCount
  ) {
    invariant("GovernedExecutionEnvelopeV4 did not bind the exact execution plan");
  }
  return plan;
}

function validatedAccounting(
  resultValue: CanonicalJsonValue,
  plan: PortfolioSurveillanceExecutionPlanV1,
  onDeterministicReplay?: () => void
): GovernedResultAccountingV4 {
  try {
    onDeterministicReplay?.();
    const operationResult = resultValue as unknown as PortfolioSurveillanceOperationResultV1;
    const accounting = accountPortfolioSurveillanceOperationResultV1(operationResult, plan);
    const warningCount = operationResult.aggregate.metrics.reduce(
      (sum, metric) => sum + metric.warnings.length,
      0
    );
    const metricHeaderCount = operationResult.aggregate.metrics.length;
    return parseWithSchema(
      ResultAccountingSchema,
      {
        ...accounting,
        cellCount: accounting.aggregateRows,
        warningCount,
        metricHeaderCount,
        disclosedItemCount: accounting.aggregateRows + warningCount + metricHeaderCount
      },
      "GovernedResultAccountingV4"
    );
  } catch {
    invariant("GovernedResultArtifactV4 result failed deterministic disclosure validation");
  }
}

function evidencedAccounting(
  resultValue: CanonicalJsonValue,
  plan: PortfolioSurveillanceExecutionPlanV1
): GovernedResultAccountingV4 {
  try {
    const operationResult = resultValue as unknown as PortfolioSurveillanceOperationResultV1;
    const accounting = accountPlanBoundPortfolioSurveillanceResultEvidenceV1(
      operationResult,
      plan
    );
    const warningCount = operationResult.aggregate.metrics.reduce(
      (sum, metric) => sum + metric.warnings.length,
      0
    );
    const metricHeaderCount = operationResult.aggregate.metrics.length;
    return parseWithSchema(
      ResultAccountingSchema,
      {
        ...accounting,
        cellCount: accounting.aggregateRows,
        warningCount,
        metricHeaderCount,
        disclosedItemCount: accounting.aggregateRows + warningCount + metricHeaderCount
      },
      "GovernedResultAccountingV4"
    );
  } catch {
    invariant("GovernedResultArtifactV4 persisted evidence validation failed");
  }
}

function enforceResultObligations(
  result: GovernedResultArtifactV4,
  plan: PortfolioSurveillanceExecutionPlanV1,
  envelope: GovernedExecutionEnvelopeV4
): void {
  for (const obligations of [
    envelope.startAuthorization.obligations,
    result.authorization.obligations
  ]) {
    const metricMinimumsMeetPolicy = plan.engineInput.metricDefinitions.every(
      (metric) => metric.privacy.minimumCellCount >= obligations.minimumCohortSize
    );
    if (
      !obligations.requireImmutableSnapshot ||
      obligations.allowRawRows ||
      obligations.allowExport ||
      obligations.rowFilterRefs.length !== 0 ||
      Object.keys(obligations.fieldMasks).length !== 0 ||
      !metricMinimumsMeetPolicy ||
      result.accounting.disclosedItemCount > obligations.maxResultRows ||
      result.accounting.bytes > obligations.maxResultBytes ||
      Buffer.byteLength(canonicalJson(result), "utf8") > obligations.maxResultBytes
    ) {
      invariant("GovernedResultArtifactV4 violated its authorization obligations");
    }
  }
}

function assertExecutionAuthorization(
  authorization: GovernedExecutionAuthorizationV4,
  envelope: GovernedExecutionEnvelopeV4
): void {
  const cutoffMs = Date.parse(envelope.planningCutoff);
  const authorizedMs = Date.parse(authorization.authorizedAt);
  const startedMs = Date.parse(authorization.startedAt);
  const completedMs = Date.parse(authorization.completedAt);
  const expiresMs = envelope.identity.expiresAtEpochSeconds * 1_000;
  if (
    authorization.tenantId !== envelope.tenantId ||
    authorization.principalId !== envelope.identity.principalId ||
    authorization.purpose !== envelope.purpose ||
    canonicalJson(authorization.requestedFields) !== canonicalJson(envelope.requestedFields) ||
    canonicalJson(authorization.obligations.auditTags) !==
      canonicalJson(envelope.startAuthorization.obligations.auditTags) ||
    authorizedMs < cutoffMs ||
    startedMs < authorizedMs ||
    completedMs < startedMs ||
    completedMs > cutoffMs + envelope.planTtlSeconds * 1_000 ||
    completedMs > expiresMs ||
    completedMs - startedMs > authorization.obligations.maxExecutionMs ||
    completedMs - startedMs > envelope.startAuthorization.obligations.maxExecutionMs
  ) {
    invariant("GovernedExecutionAuthorizationV4 did not match the frozen execution authority");
  }
}

function assertStoredResultArtifact(
  result: GovernedResultArtifactV4,
  reference: GovernedStoredResultArtifactReferenceV4
): void {
  if (
    reference.contentHash !== artifactJsonContentHash(result) ||
    reference.byteLength !== Buffer.byteLength(canonicalJson(result), "utf8")
  ) {
    invariant("GovernedResultManifestV4 stored artifact evidence did not match result bytes");
  }
}

function assertOperationResultLineage(result: GovernedResultArtifactV4): void {
  const operationResult = recordValue(result.result, "portfolio surveillance result");
  if (
    operationResult.operation !== OPERATION ||
    operationResult.tenantId !== result.tenantId ||
    operationResult.purpose !== result.purpose ||
    operationResult.requestHash !== result.lineage.requestHash ||
    operationResult.planHash !== result.lineage.planHash ||
    operationResult.sourceSetHash !== result.lineage.sourceSetHash ||
    operationResult.definitionSetHash !== result.lineage.definitionSetHash ||
    operationResult.requestedFieldsHash !== result.lineage.requestedFieldsHash
  ) {
    invariant("GovernedResultArtifactV4 operation result lineage did not verify");
  }
  const innerResultHash = operationResult.resultHash;
  if (typeof innerResultHash !== "string") {
    invariant("GovernedResultArtifactV4 operation result hash is missing");
  }
  const { resultHash: _resultHash, ...innerBody } = operationResult;
  assertCanonicalHash(innerBody, innerResultHash, "PortfolioSurveillanceOperationResultV1");
}

function assertRequestedFieldsHash(
  fields: readonly string[],
  expected: string,
  label: string
): void {
  if (canonicalHash(fields) !== expected) {
    throw new ContractValidationError(
      "HASH_MISMATCH",
      `${label} requestedFieldsHash did not match requested fields`
    );
  }
}

function rejectExplicitUndefined(
  value: Readonly<Record<string, unknown>>,
  keys: readonly string[],
  context: z.core.$RefinementCtx<Record<string, unknown>>
): void {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(value, key) && value[key] === undefined) {
      context.addIssue({
        code: "custom",
        path: [key],
        message: "must be omitted rather than explicitly undefined"
      });
    }
  }
}

function recordValue(value: unknown, label: string): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    invariant(`${label} must be an object`);
  }
  return value as Readonly<Record<string, unknown>>;
}

function bareHash(hash: string): string {
  if (!hash.startsWith("sha256:")) invariant("Expected a canonical sha256 hash");
  return hash.slice("sha256:".length);
}

function invariant(message: string): never {
  throw new ContractValidationError("INVARIANT_VIOLATION", message);
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
