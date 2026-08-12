import { createHash, randomBytes, randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { Worker } from "node:worker_threads";

import * as z from "zod/v4";

import type { MonitoringAlertStore } from "../control/alerts.js";
import type { ArtifactStore, StoredArtifact } from "../control/artifacts.js";
import type { DefinitionKind, DefinitionStore, GovernedDefinition } from "../control/definitions.js";
import type { InputCertificationStore } from "../control/input-certifications.js";
import { JobStoreError, type JobRecord, type JobStore } from "../control/jobs.js";
import type {
  AnalysisManifest,
  ControlStore,
  DataQualityRun,
  DatasetSnapshot,
  JsonValue,
  MappingVersion,
  Reconciliation
} from "../control/store.js";
import { DICTIONARY_VERSION } from "../domain/dictionary.js";
import { CANONICAL_DICTIONARY_HASH } from "../domain/dictionary-fingerprint.js";
import {
  calculateArBorrowingBase,
  type ArBorrowingBasePolicyVersion,
  type ArBorrowingBaseResult
} from "../domain/borrowing-base.js";
import {
  evaluateMonitoring,
  type DataQualityGate,
  type MetricObservation,
  type MonitorDefinition,
  type MonitoringResult,
  type MonitoringScope
} from "../domain/monitoring.js";
import {
  assertActivePrincipal,
  assertVerifiedPrincipalContext,
  createVerifiedPrincipalContext,
  principalBinding,
  type VerifiedIdentityAttestation,
  type VerifiedPrincipalContext
} from "../security/identity.js";
import type { TenantMembershipResolver } from "../security/oauth.js";
import {
  assertPermitDecision,
  evaluatePolicy,
  type CompiledAuthorizationPolicy,
  type PermitPolicyDecision,
  type PolicyObligations
} from "../security/policy.js";
import {
  issueExecutionPlan,
  issuePrincipalBoundHandle,
  SignedArtifactError,
  verifyExecutionPlan,
  verifyPrincipalBoundHandle,
  type HmacKeyRing
} from "../security/signed-plan.js";
import { SecurityStateStoreError, type SecurityStateStore } from "../security/state-store.js";
import { MCP_SERVER_NAME, MCP_SERVER_VERSION } from "../product.js";
import { modernMcpSuccessResultByteLength } from "../transports/mcp-result-envelope.js";
import {
  runSnapshotStratification,
  runSnapshotVintageAnalysis,
  type CanonicalSnapshotRecord,
  type ImmutableSnapshotLineage,
  type SnapshotStratificationResult,
  type SnapshotVintageResult
} from "./snapshot-analysis.js";
import { InputCertificationService } from "./input-certification.js";

export type GovernedWorkflowOperation =
  | "snapshot_stratification"
  | "snapshot_vintage"
  | "ar_borrowing_base"
  | "monitoring";

export interface StartGovernedJobInput {
  readonly operation: GovernedWorkflowOperation;
  readonly certificationManifestId: string;
  readonly definitionIds: readonly string[];
  readonly inputArtifactId?: string;
  readonly idempotencyKey: string;
  readonly purpose?: string;
  readonly planTtlSeconds?: number;
  readonly handleTtlSeconds?: number;
}

export interface StartedGovernedJob {
  readonly jobHandle: string;
  readonly status: JobRecord["status"];
  readonly operation: GovernedWorkflowOperation;
}

export interface GovernedMutationRequestContext {
  /** Trusted same-process monotonic start time for the enclosing request. */
  readonly requestStartedAtMonotonicMs: number;
}

export interface GovernedJobStatusView {
  readonly operation: GovernedWorkflowOperation;
  readonly status: JobRecord["status"];
  readonly attemptCount: number;
  readonly maxAttempts: number;
  readonly cancellationRequested: boolean;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly errorCode: string | null;
  readonly resultAvailable: boolean;
}

export interface GovernedJobResultView {
  readonly operation: GovernedWorkflowOperation;
  readonly manifestId: string;
  readonly artifactId: string;
  readonly resultHash: string;
  readonly result: unknown;
}

export interface GovernedAuthorizedResponse<T> {
  readonly value: T;
  readonly obligations: readonly PolicyObligations[];
}

export interface ProcessedGovernedJob {
  readonly operation: GovernedWorkflowOperation;
  readonly status: "succeeded" | "failed" | "cancelled";
  readonly errorCode: string | null;
}

export interface GovernedWorkflowServices {
  readonly control: ControlStore;
  readonly definitions: DefinitionStore;
  readonly artifacts: ArtifactStore;
  readonly jobs: JobStore;
  readonly monitoringAlerts: MonitoringAlertStore;
  readonly inputCertifications: InputCertificationStore;
  readonly securityState: SecurityStateStore;
  readonly tenantMembershipResolver: TenantMembershipResolver;
  readonly policy: CompiledAuthorizationPolicy;
  readonly keyRing: HmacKeyRing;
}

export interface GovernedWorkflowOptions {
  readonly codeVersion: string;
  readonly clock?: () => Date;
  readonly defaultPlanTtlSeconds?: number;
  readonly defaultHandleTtlSeconds?: number;
  readonly workerLeaseSeconds?: number;
}

export type GovernedWorkflowErrorCode =
  | "INVALID_INPUT"
  | "CERTIFICATION_REQUIRED"
  | "DEFINITION_NOT_EFFECTIVE"
  | "POLICY_DENIED"
  | "AUTHORIZATION_UNAVAILABLE"
  | "AUDIT_REQUIRED"
  | "RESULT_NOT_READY"
  | "RESULT_TOO_LARGE"
  | "EXECUTION_TIMEOUT"
  | "CANCELLED"
  | "EXECUTION_FAILED";

export class GovernedWorkflowError extends Error {
  constructor(readonly code: GovernedWorkflowErrorCode, message: string) {
    super(message);
    this.name = "GovernedWorkflowError";
  }
}

export interface CertificationChain {
  readonly manifest: AnalysisManifest;
  readonly snapshot: DatasetSnapshot;
  readonly mapping: MappingVersion;
  readonly dataQuality: DataQualityRun;
  readonly reconciliation: Reconciliation;
  readonly normalizedArtifact: StoredArtifact;
  readonly records: readonly CanonicalSnapshotRecord[];
  readonly dataQualityFingerprint: string;
  readonly reconciliationFingerprint: string;
}

export interface DefinitionBundle {
  readonly definitions: readonly GovernedDefinition[];
  readonly recipeHash: string;
}

interface InputArtifactReference {
  readonly artifactId: string;
  readonly contentHash: string;
  readonly kind: string;
  readonly certification?: CertifiedInputLineageSummary;
}

interface CertifiedInputLineageSummary {
  readonly inputId: string;
  readonly envelopeHash: string;
  readonly lineageHash: string;
  readonly derivationHash: string;
  readonly primaryCertificationHash: string;
  readonly primaryPopulationHash: string;
  readonly sidecarCertificationHash: string;
  readonly sidecarPopulationHash: string;
  readonly dataQualityRunId: string;
  readonly dataQualityResultHash: string;
  readonly reconciliationId: string;
  readonly reconciliationResultHash: string;
  readonly certifiedAt: string;
}

export interface LoadedInputArtifact {
  readonly reference: InputArtifactReference;
  readonly value: unknown;
}

/** Structured-clone-safe payload executed inside the bounded analysis worker. */
export interface GovernedAnalysisExecutionPayload {
  readonly operation: GovernedWorkflowOperation;
  readonly certification: CertificationChain;
  readonly definitions: DefinitionBundle;
  readonly inputArtifact: LoadedInputArtifact | null;
  readonly obligations: PolicyObligations;
}

interface ExecutionEnvelope {
  readonly version: 2 | 3;
  readonly operation: GovernedWorkflowOperation;
  readonly certificationManifestId: string;
  readonly definitionIds: readonly string[];
  readonly inputArtifact: InputArtifactReference | null;
  readonly identity: VerifiedIdentityAttestation;
  readonly requestedFields: readonly string[];
  readonly purpose: string | null;
  readonly planTtlSeconds: number;
  readonly authorizationReceiptId: string;
  readonly parameterFingerprint: string;
  readonly schemaFingerprint: string;
  readonly snapshotFingerprint: string;
  readonly mappingFingerprint: string;
  readonly mappingDigest: string;
  readonly recipeFingerprint: string;
  readonly policyFingerprint: string;
  readonly idempotencyFingerprint: string;
  readonly startFingerprint: string;
  readonly auditTags: readonly string[];
}

interface ResultArtifactPayload {
  readonly version: 2 | 3;
  readonly jobId: string;
  readonly manifestId: string;
  readonly operation: GovernedWorkflowOperation;
  readonly certificationManifestId: string;
  readonly definitionIds: readonly string[];
  readonly resultHash: string;
  readonly authorization: {
    readonly decisionId: string;
    readonly policyFingerprint: string;
    readonly requestedFields: readonly string[];
    readonly purpose: string | null;
    readonly obligations: PolicyObligations;
  };
  readonly lineage: {
    readonly snapshotHash: string;
    readonly mappingHash: string;
    readonly mappingDigest: string;
    readonly dictionaryHash: string;
    readonly recipeHash: string;
    readonly inputArtifactHash: string | null;
    readonly inputCertification?: CertifiedInputLineageSummary | null;
  };
  readonly result: unknown;
}

const identifierSchema = z.string().min(1).max(256).refine((value) => !/[\u0000-\u001f\u007f]/.test(value));
const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const controlDigestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const isoDateSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}$/).refine(isRealIsoDate);
const isoDateTimeSchema = z.string().min(1).refine((value) => Number.isFinite(Date.parse(value)));
const decimalSchema = z.string().regex(/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/);
const operationSchema = z.enum([
  "snapshot_stratification",
  "snapshot_vintage",
  "ar_borrowing_base",
  "monitoring"
]);

const startInputSchema = z
  .object({
    operation: operationSchema,
    certificationManifestId: identifierSchema,
    definitionIds: z.array(identifierSchema).min(1).max(100),
    inputArtifactId: hashSchema.optional(),
    idempotencyKey: identifierSchema,
    purpose: identifierSchema.optional(),
    planTtlSeconds: z.number().int().min(1).max(900).optional(),
    handleTtlSeconds: z.number().int().min(1).max(604_800).optional()
  })
  .strict();

const identityAttestationSchema = z
  .object({
    issuer: z.string().min(1).max(2_048),
    subject: z.string().min(1).max(512),
    principalId: identifierSchema,
    tenantId: identifierSchema,
    clientId: z.string().min(1).max(512).optional(),
    audiences: z.array(z.string().min(1).max(512)).min(1).max(64),
    resourceIndicators: z.array(z.string().url().min(1).max(2_048)).min(1).max(64),
    scopes: z.array(identifierSchema).max(256),
    credentialFingerprint: hashSchema,
    verifiedAtEpochSeconds: z.number().int().nonnegative(),
    notBeforeEpochSeconds: z.number().int().nonnegative().optional(),
    expiresAtEpochSeconds: z.number().int().nonnegative(),
    authenticationMethods: z.array(identifierSchema).max(256).optional()
  })
  .strict();

const legacyInputArtifactReferenceSchema = z
  .object({ artifactId: hashSchema, contentHash: hashSchema, kind: identifierSchema })
  .strict();

const certifiedInputLineageSummarySchema = z
  .object({
    inputId: identifierSchema,
    envelopeHash: controlDigestSchema,
    lineageHash: controlDigestSchema,
    derivationHash: controlDigestSchema,
    primaryCertificationHash: controlDigestSchema,
    primaryPopulationHash: controlDigestSchema,
    sidecarCertificationHash: controlDigestSchema,
    sidecarPopulationHash: controlDigestSchema,
    dataQualityRunId: identifierSchema,
    dataQualityResultHash: controlDigestSchema,
    reconciliationId: identifierSchema,
    reconciliationResultHash: controlDigestSchema,
    certifiedAt: isoDateTimeSchema
  })
  .strict();

const certifiedInputArtifactReferenceSchema = z
  .object({
    artifactId: hashSchema,
    contentHash: hashSchema,
    kind: z.enum(["certified_borrowing_base_input", "certified_monitoring_input"]),
    certification: certifiedInputLineageSummarySchema
  })
  .strict();

const executionEnvelopeBaseShape = {
  operation: operationSchema,
  certificationManifestId: identifierSchema,
  definitionIds: z.array(identifierSchema).min(1).max(100),
  identity: identityAttestationSchema,
  requestedFields: z.array(identifierSchema).max(2_000),
  purpose: identifierSchema.nullable(),
  planTtlSeconds: z.number().int().min(1).max(900),
  authorizationReceiptId: hashSchema,
  parameterFingerprint: hashSchema,
  schemaFingerprint: hashSchema,
  snapshotFingerprint: hashSchema,
  mappingFingerprint: hashSchema,
  mappingDigest: controlDigestSchema,
  recipeFingerprint: hashSchema,
  policyFingerprint: hashSchema,
  idempotencyFingerprint: hashSchema,
  startFingerprint: hashSchema,
  auditTags: z.array(identifierSchema).max(256)
} as const;

const executionEnvelopeSchema = z
  .discriminatedUnion("version", [
    z
      .object({
        version: z.literal(2),
        ...executionEnvelopeBaseShape,
        inputArtifact: legacyInputArtifactReferenceSchema.nullable()
      })
      .strict(),
    z
      .object({
        version: z.literal(3),
        ...executionEnvelopeBaseShape,
        inputArtifact: certifiedInputArtifactReferenceSchema.nullable()
      })
      .strict()
  ]);

const certificationParametersSchema = z
  .object({
    dataQualityProfileId: identifierSchema,
    dataQualityProfileVersion: identifierSchema,
    dataQualityRunId: identifierSchema,
    reconciliationId: identifierSchema,
    evaluatedAt: isoDateTimeSchema,
    certified: z.boolean(),
    blockerCodes: z.array(identifierSchema).max(10_000)
  })
  .strict();

const canonicalRecordSchema = z.record(z.string().min(1).max(128), z.unknown());
const normalizedSnapshotSchema = z
  .object({
    snapshotId: identifierSchema,
    mappingVersionId: identifierSchema,
    records: z.array(canonicalRecordSchema).max(1_000_000),
    dataQualityFingerprint: hashSchema
  })
  .strict();

const bucketSchema = z
  .object({
    label: z.string().min(1).max(128),
    lower: decimalSchema.optional(),
    upper: decimalSchema.optional(),
    includeLower: z.boolean().optional(),
    includeUpper: z.boolean().optional()
  })
  .strict();

const stratificationRecipeSchema = z
  .object({
    dimension: identifierSchema,
    balanceField: identifierSchema.optional(),
    buckets: z.array(bucketSchema).min(1).max(100).optional(),
    weightedAverageFields: z.array(identifierSchema).max(5).optional(),
    minimumCohortSize: z.number().int().min(1).max(1_000_000).optional(),
    maxRecords: z.number().int().min(1).max(1_000_000),
    maxGroups: z.number().int().min(1).max(10_000)
  })
  .strict();

const vintageRecipeSchema = z
  .object({
    cohortGrain: z.enum(["month", "quarter", "year"]),
    maxMonthsOnBook: z.number().int().min(0).max(600),
    delinquencyThresholdDays: z.number().int().min(0).max(100_000),
    minimumCohortSize: z.number().int().min(1).max(1_000_000).optional(),
    maxRecords: z.number().int().min(1).max(1_000_000),
    maxPoints: z.number().int().min(1).max(1_000_000)
  })
  .strict();

const receivableFlagSchema = z.enum([
  "affiliate",
  "contra",
  "disputed",
  "duplicate",
  "foreign",
  "government",
  "insolvent_debtor",
  "lien_not_perfected",
  "reaged",
  "unbilled"
]);

const eligibilityConditionSchema: z.ZodType = z.lazy(() =>
  z.discriminatedUnion("kind", [
    z.object({ kind: z.literal("days_past_due_at_least"), days: z.number().int().nonnegative() }).strict(),
    z.object({ kind: z.literal("flag_present"), flag: receivableFlagSchema }).strict(),
    z.object({ kind: z.literal("debtor_id_in"), debtorIds: z.array(identifierSchema).min(1).max(100_000) }).strict(),
    z.object({ kind: z.literal("all"), conditions: z.array(eligibilityConditionSchema).min(1).max(100) }).strict(),
    z.object({ kind: z.literal("any"), conditions: z.array(eligibilityConditionSchema).min(1).max(100) }).strict(),
    z.object({ kind: z.literal("not"), condition: eligibilityConditionSchema }).strict()
  ])
);

const eligibilityRuleSchema = z
  .object({
    ruleId: identifierSchema,
    version: identifierSchema,
    effectiveFrom: isoDateSchema,
    effectiveTo: isoDateSchema.optional(),
    priority: z.number().int().nonnegative(),
    reasonCode: identifierSchema,
    description: z.string().min(1).max(2_000),
    condition: eligibilityConditionSchema
  })
  .strict();

const borrowingBasePolicySchema = z
  .object({
    policyId: identifierSchema,
    version: identifierSchema,
    effectiveFrom: isoDateSchema,
    effectiveTo: isoDateSchema.optional(),
    currencyCode: z.string().regex(/^[A-Z]{3}$/),
    eligibilityRules: z.array(eligibilityRuleSchema).max(10_000),
    crossAging: z
      .object({
        ruleId: identifierSchema,
        reasonCode: identifierSchema,
        daysPastDueAtLeast: z.number().int().nonnegative(),
        triggerRatio: decimalSchema
      })
      .strict()
      .optional(),
    concentration: z
      .object({
        ruleId: identifierSchema,
        reasonCode: identifierSchema,
        maxDebtorShare: decimalSchema,
        allocation: z.enum(["invoice_id", "largest_first", "oldest_first"])
      })
      .strict()
      .optional(),
    advanceRate: decimalSchema,
    componentSublimit: decimalSchema.optional(),
    reserves: z
      .array(
        z
          .object({
            reserveId: identifierSchema,
            reasonCode: identifierSchema,
            description: z.string().min(1).max(2_000),
            amount: decimalSchema
          })
          .strict()
      )
      .max(10_000),
    commitmentAmount: decimalSchema
  })
  .strict();

const receivableSchema = z
  .object({
    receivableId: identifierSchema,
    debtorId: identifierSchema,
    outstandingAmount: decimalSchema,
    daysPastDue: z.number().int().nonnegative(),
    flags: z.array(receivableFlagSchema).max(20)
  })
  .strict();

const usageSchema = z
  .object({
    usageId: identifierSchema,
    kind: z.enum(["revolver", "letters_of_credit", "swingline", "other"]),
    amount: decimalSchema
  })
  .strict();

const borrowingBaseInputSchema = z
  .object({
    snapshotId: identifierSchema,
    asOfDate: isoDateSchema,
    receivables: z.array(receivableSchema).max(1_000_000),
    usage: z.array(usageSchema).max(100_000)
  })
  .strict();

const evidenceKindSchema = z.enum([
  "borrowing_base_run",
  "mapping",
  "metric_run",
  "policy",
  "reconciliation",
  "source_artifact"
]);
const evidenceSchema = z.object({ kind: evidenceKindSchema, id: identifierSchema }).strict();
const decimalUnitSchema = z.enum(["basis_points", "count", "currency", "days", "percent", "ratio"]);
const monitorBaseShape = {
  monitorId: identifierSchema,
  version: identifierSchema,
  effectiveFrom: isoDateSchema,
  effectiveTo: isoDateSchema.optional(),
  metricId: identifierSchema,
  title: z.string().min(1).max(512),
  message: z.string().min(1).max(2_000),
  severity: z.enum(["info", "warning", "high", "critical"])
};
const decimalMonitorSchema = z
  .object({
    ...monitorBaseShape,
    threshold: z
      .object({
        type: z.literal("decimal"),
        operator: z.enum(["eq", "gte", "gt", "lte", "lt", "neq"]),
        value: decimalSchema,
        unit: decimalUnitSchema
      })
      .strict()
  })
  .strict();
const booleanMonitorSchema = z
  .object({
    ...monitorBaseShape,
    threshold: z
      .object({
        type: z.literal("boolean"),
        operator: z.enum(["eq", "neq"]),
        value: z.boolean(),
        unit: z.literal("boolean")
      })
      .strict()
  })
  .strict();
const monitorDefinitionSchema = z.union([decimalMonitorSchema, booleanMonitorSchema]);
const observationBaseShape = {
  observationId: identifierSchema,
  metricId: identifierSchema,
  snapshotId: identifierSchema,
  asOfDate: isoDateSchema,
  evidence: z.array(evidenceSchema).max(10_000)
};
const metricObservationSchema = z.union([
  z
    .object({
      ...observationBaseShape,
      type: z.literal("decimal"),
      value: decimalSchema,
      unit: decimalUnitSchema
    })
    .strict(),
  z
    .object({
      ...observationBaseShape,
      type: z.literal("boolean"),
      value: z.boolean(),
      unit: z.literal("boolean")
    })
    .strict()
]);
const monitoringInputSchema = z
  .object({
    snapshotId: identifierSchema,
    asOfDate: isoDateSchema,
    scope: z.object({ type: z.enum(["facility", "portfolio", "source"]), id: identifierSchema }).strict(),
    observations: z.array(metricObservationSchema).max(1_000_000)
  })
  .strict();

const resultAuthorizationSchema = z
  .object({
    decisionId: hashSchema,
    policyFingerprint: hashSchema,
    requestedFields: z.array(identifierSchema).max(2_000),
    purpose: identifierSchema.nullable(),
    obligations: z
      .object({
        maxResultRows: z.number().int().positive(),
        maxResultBytes: z.number().int().positive(),
        maxExecutionMs: z.number().int().positive(),
        minimumCohortSize: z.number().int().positive(),
        requireImmutableSnapshot: z.boolean(),
        allowRawRows: z.boolean(),
        allowExport: z.boolean(),
        rowFilterRefs: z.array(identifierSchema).max(10_000),
        fieldMasks: z.record(identifierSchema, z.enum(["partial", "hash", "tokenize", "redact"])),
        auditTags: z.array(identifierSchema).max(256)
      })
      .strict()
  })
  .strict();

const resultLineageBaseShape = {
  snapshotHash: hashSchema,
  mappingHash: hashSchema,
  mappingDigest: controlDigestSchema,
  dictionaryHash: hashSchema,
  recipeHash: hashSchema,
  inputArtifactHash: hashSchema.nullable()
} as const;

const resultArtifactBaseShape = {
    jobId: identifierSchema,
    manifestId: identifierSchema,
    operation: operationSchema,
    certificationManifestId: identifierSchema,
    definitionIds: z.array(identifierSchema).min(1).max(100),
    resultHash: hashSchema,
    authorization: resultAuthorizationSchema,
    result: z.unknown()
} as const;

const resultArtifactSchema = z.discriminatedUnion("version", [
  z
    .object({
      version: z.literal(2),
      ...resultArtifactBaseShape,
      lineage: z.object(resultLineageBaseShape).strict()
    })
    .strict(),
  z
    .object({
      version: z.literal(3),
      ...resultArtifactBaseShape,
      lineage: z
        .object({
          ...resultLineageBaseShape,
          inputCertification: certifiedInputLineageSummarySchema.nullable()
        })
        .strict()
    })
    .strict()
]);

const TOOL_NAMES: Readonly<Record<GovernedWorkflowOperation, string>> = {
  snapshot_stratification: "abl_run_snapshot_stratification",
  snapshot_vintage: "abl_run_snapshot_vintage",
  ar_borrowing_base: "abl_run_ar_borrowing_base",
  monitoring: "abl_run_monitoring"
};

const EXPECTED_DEFINITION_KIND: Readonly<Record<GovernedWorkflowOperation, DefinitionKind>> = {
  snapshot_stratification: "stratification_recipe",
  snapshot_vintage: "vintage_recipe",
  ar_borrowing_base: "borrowing_base_policy",
  monitoring: "monitor_definition"
};

const EXPECTED_INPUT_KIND: Readonly<Partial<Record<GovernedWorkflowOperation, string>>> = {
  ar_borrowing_base: "certified_borrowing_base_input",
  monitoring: "certified_monitoring_input"
};

const DICTIONARY_HASH = CANONICAL_DICTIONARY_HASH;

/** Durable orchestration boundary for authenticated, governed analysis jobs. */
export class GovernedWorkflow {
  readonly #services: GovernedWorkflowServices;
  readonly #codeVersion: string;
  readonly #clock: () => Date;
  readonly #defaultPlanTtlSeconds: number;
  readonly #defaultHandleTtlSeconds: number;
  readonly #workerLeaseSeconds: number;

  constructor(services: GovernedWorkflowServices, options: GovernedWorkflowOptions) {
    if (!services.tenantMembershipResolver || typeof services.tenantMembershipResolver.resolveTenantMembership !== "function") {
      throw workflowError("INVALID_INPUT", "A trusted tenant membership resolver is required");
    }
    this.#services = services;
    this.#codeVersion = parse(identifierSchema, options.codeVersion, "codeVersion");
    this.#clock = options.clock ?? (() => new Date());
    this.#defaultPlanTtlSeconds = boundedInteger(options.defaultPlanTtlSeconds ?? 300, "defaultPlanTtlSeconds", 1, 900);
    this.#defaultHandleTtlSeconds = boundedInteger(
      options.defaultHandleTtlSeconds ?? 3_600,
      "defaultHandleTtlSeconds",
      1,
      604_800
    );
    this.#workerLeaseSeconds = boundedInteger(options.workerLeaseSeconds ?? 300, "workerLeaseSeconds", 5, 3_600);
    if (this.#workerLeaseSeconds * 1_000 <= services.policy.defaultObligations.maxExecutionMs + 5_000) {
      throw workflowError("INVALID_INPUT", "Worker lease must exceed the maximum policy execution time plus finalization margin");
    }
  }

  start(principal: VerifiedPrincipalContext, input: StartGovernedJobInput): StartedGovernedJob {
    return this.startAuthorized(principal, input).value;
  }

  startAuthorized(
    principal: VerifiedPrincipalContext,
    input: StartGovernedJobInput,
    requestContext?: GovernedMutationRequestContext
  ): GovernedAuthorizedResponse<StartedGovernedJob> {
    const requestStartedAt = mutationRequestStartedAt(requestContext);
    assertVerifiedPrincipalContext(principal);
    const request = parse(startInputSchema, input, "start request");
    const now = this.#nowEpochSeconds();
    const definitionIds = sortedUnique(request.definitionIds);
    if (definitionIds.length !== request.definitionIds.length) {
      throw workflowError("INVALID_INPUT", "definitionIds must not contain duplicates");
    }
    const requester = principalBinding(principal);
    const idempotencyFingerprint = hashText(request.idempotencyKey);
    const startFingerprint = hashJson({
      operation: request.operation,
      certificationManifestId: request.certificationManifestId,
      definitionIds,
      inputArtifactId: request.inputArtifactId ?? null,
      purpose: request.purpose ?? null,
      planTtlSeconds: request.planTtlSeconds ?? this.#defaultPlanTtlSeconds,
      handleTtlSeconds: request.handleTtlSeconds ?? this.#defaultHandleTtlSeconds
    });
    const replay = this.#findIdempotentJob(
      principal.tenantId,
      requester,
      idempotencyFingerprint,
      startFingerprint
    );
    const certification = this.#loadCertification(principal.tenantId, request.certificationManifestId);
    const definitions = this.#loadDefinitions(
      principal.tenantId,
      request.operation,
      definitionIds,
      certification.snapshot.asOfDate
    );
    if (EXPECTED_INPUT_KIND[request.operation] !== undefined && request.purpose === undefined) {
      throw workflowError("INVALID_INPUT", `${request.operation} requires an explicit governed purpose`);
    }
    const loadedInput = this.#loadInputArtifact(
      principal.tenantId,
      request.operation,
      request.inputArtifactId,
      certification,
      definitions,
      request.purpose ?? null
    );
    const fields = requestedFields(request.operation, definitions);
    const decision = evaluatePolicy(this.#services.policy, {
      principal,
      toolName: TOOL_NAMES[request.operation],
      dataset: { id: certification.snapshot.snapshotId, tenantId: certification.snapshot.tenantId },
      fields,
      ...(request.purpose === undefined ? {} : { purpose: request.purpose }),
      nowEpochSeconds: now
    });
    const authorizationReceiptId = hashJson({
      requester,
      startFingerprint,
      policyFingerprint: decision.policyFingerprint,
      toolName: decision.toolName,
      datasetId: decision.datasetId,
      requestedFields: decision.requestedFields,
      purpose: decision.purpose ?? null,
      effect: decision.effect
    });
    this.#recordAuthorizationDecision(
      principal,
      decision,
      authorizationReceiptId
    );
    try {
      assertPermitDecision(decision);
    } catch {
      throw workflowError(
        "POLICY_DENIED",
        decision.effect === "deny"
          ? `Policy denied the operation: ${decision.reasons.map((reason) => reason.code).join(",")}`
          : "Policy did not issue a permit"
      );
    }
    assertSupportedObligations(decision.obligations);
    if (replay) {
      assertPreCommitDeadline(requestStartedAt, decision.obligations.maxExecutionMs);
      this.#recordStartAudit(replay.job, replay.envelope);
      return authorizedResponse(
        this.#issueJobHandle(
          principal,
          replay.job,
          request.handleTtlSeconds ?? this.#defaultHandleTtlSeconds,
          now
        ),
        decision.obligations
      );
    }

    const inputReference = loadedInput?.reference ?? null;
    const parameterFingerprint = operationFingerprint(
      request.operation,
      request.certificationManifestId,
      definitions,
      inputReference
    );
    const mappingFingerprint = controlDigestFingerprint(certification.mapping.mappingHash, "mapping hash");
    const schemaFingerprint = hashJson({ dictionaryHash: DICTIONARY_HASH, operation: request.operation, version: 1 });
    const envelope: ExecutionEnvelope = {
      version: 3,
      operation: request.operation,
      certificationManifestId: request.certificationManifestId,
      definitionIds,
      inputArtifact: inputReference,
      identity: persistedIdentity(principal),
      requestedFields: fields,
      purpose: request.purpose ?? null,
      planTtlSeconds: request.planTtlSeconds ?? this.#defaultPlanTtlSeconds,
      authorizationReceiptId,
      parameterFingerprint,
      schemaFingerprint,
      snapshotFingerprint: certification.normalizedArtifact.contentHash,
      mappingFingerprint,
      mappingDigest: certification.mapping.mappingHash,
      recipeFingerprint: definitions.recipeHash,
      policyFingerprint: this.#services.policy.fingerprint,
      idempotencyFingerprint,
      startFingerprint,
      auditTags: decision.obligations.auditTags
    };
    parse(executionEnvelopeSchema, envelope, "execution envelope");

    let job: JobRecord;
    const proposedJobId = randomUUID();
    this.#recordSubmissionAuthorization(
      principal.tenantId,
      proposedJobId,
      requester,
      envelope
    );
    assertPreCommitDeadline(requestStartedAt, decision.obligations.maxExecutionMs);
    try {
      job = this.#services.jobs.submit({
        tenantId: principal.tenantId,
        jobId: proposedJobId,
        requestedBy: requester,
        idempotencyKey: request.idempotencyKey,
        toolName: TOOL_NAMES[request.operation],
        datasetId: certification.snapshot.snapshotId,
        request: asRecord(envelope),
        // Claim-time plans are fresh, so deterministic crash recovery is safe.
        maxAttempts: 3
      });
    } catch (error) {
      if (!(error instanceof JobStoreError) || error.code !== "IDEMPOTENCY_CONFLICT") throw error;
      const concurrentReplay = this.#findIdempotentJob(
        principal.tenantId,
        requester,
        idempotencyFingerprint,
        startFingerprint
      );
      if (!concurrentReplay) {
        throw workflowError("INVALID_INPUT", "Idempotency key was already used for another request");
      }
      this.#recordSubmissionAuthorization(
        principal.tenantId,
        concurrentReplay.job.jobId,
        requester,
        concurrentReplay.envelope
      );
      this.#recordStartAudit(concurrentReplay.job, concurrentReplay.envelope);
      return authorizedResponse(
        this.#issueJobHandle(
          principal,
          concurrentReplay.job,
          request.handleTtlSeconds ?? this.#defaultHandleTtlSeconds,
          now
        ),
        decision.obligations
      );
    }
    this.#recordSubmissionAuthorization(principal.tenantId, job.jobId, requester, envelope);
    this.#recordStartAudit(job, envelope);
    return authorizedResponse(
      this.#issueJobHandle(
        principal,
        job,
        request.handleTtlSeconds ?? this.#defaultHandleTtlSeconds,
        now
      ),
      decision.obligations
    );
  }

  async getJobStatus(principal: VerifiedPrincipalContext, jobHandle: string): Promise<GovernedJobStatusView> {
    return (await this.getJobStatusAuthorized(principal, jobHandle)).value;
  }

  async getJobStatusAuthorized(
    principal: VerifiedPrincipalContext,
    jobHandle: string
  ): Promise<GovernedAuthorizedResponse<GovernedJobStatusView>> {
    const authorized = await this.#resolveAuthorizedJob(principal, jobHandle, "job.status");
    return authorizedResponse(
      publicJobStatus(authorized.job),
      authorized.analysisDecision.obligations,
      authorized.actionDecision.obligations
    );
  }

  async getJobResult(principal: VerifiedPrincipalContext, jobHandle: string): Promise<GovernedJobResultView> {
    return (await this.getJobResultAuthorized(principal, jobHandle)).value;
  }

  async getJobResultAuthorized(
    principal: VerifiedPrincipalContext,
    jobHandle: string
  ): Promise<GovernedAuthorizedResponse<GovernedJobResultView>> {
    const authorized = await this.#resolveAuthorizedJob(principal, jobHandle, "job.result");
    const { job, envelope } = authorized;
    if (job.status !== "succeeded" || !job.resultHandle) {
      throw workflowError("RESULT_NOT_READY", "Job result is not available");
    }
    let resultArtifactId: string;
    try {
      const resultRecord = verifyPrincipalBoundHandle(this.#services.keyRing, job.resultHandle, principal, {
        expectedKind: "result",
        nowEpochSeconds: this.#nowEpochSeconds(),
        clockSkewSeconds: 0
      });
      resultArtifactId = this.#services.securityState.resolveHandle(resultRecord).resourceId;
    } catch (error) {
      const expired =
        (error instanceof SignedArtifactError && error.code === "ARTIFACT_EXPIRED") ||
        (error instanceof SecurityStateStoreError && error.code === "HANDLE_EXPIRED");
      if (!expired) throw error;
      const durableManifest = this.#services.control.getAnalysisManifest(principal.tenantId, job.jobId);
      const candidates = durableManifest?.artifacts.filter(
        (artifact) => artifact.kind === "governed_analysis_result"
      );
      if (!durableManifest || durableManifest.createdBy !== job.requestedBy || candidates?.length !== 1) {
        throw workflowError("EXECUTION_FAILED", "Expired result handle could not be recovered from its manifest");
      }
      resultArtifactId = candidates[0]!.artifactId;
    }
    const stored = this.#services.artifacts.getJson(principal.tenantId, resultArtifactId);
    if (stored.metadata.kind !== "governed_analysis_result") {
      throw workflowError("EXECUTION_FAILED", "Bound result artifact has an invalid kind");
    }
    const payload = parse(resultArtifactSchema, stored.value, "result artifact") as ResultArtifactPayload;
    if (
      payload.jobId !== job.jobId ||
      payload.manifestId !== job.jobId ||
      payload.operation !== envelope.operation ||
      payload.operation !== operationForTool(job.toolName) ||
      payload.certificationManifestId !== envelope.certificationManifestId ||
      stableJson(payload.definitionIds) !== stableJson(envelope.definitionIds) ||
      payload.resultHash !== hashJson(payload.result) ||
      stableJson(payload.authorization.requestedFields) !== stableJson(envelope.requestedFields) ||
      payload.authorization.purpose !== envelope.purpose ||
      payload.lineage.snapshotHash !== envelope.snapshotFingerprint ||
      payload.lineage.mappingHash !== envelope.mappingFingerprint ||
      payload.lineage.mappingDigest !== envelope.mappingDigest ||
      payload.lineage.dictionaryHash !== DICTIONARY_HASH ||
      payload.lineage.recipeHash !== envelope.recipeFingerprint ||
      payload.lineage.inputArtifactHash !== (envelope.inputArtifact?.contentHash ?? null) ||
      !resultInputCertificationMatches(payload, envelope)
    ) {
      throw workflowError("EXECUTION_FAILED", "Result artifact lineage did not verify");
    }
    const manifest = this.#services.control.getAnalysisManifest(principal.tenantId, payload.manifestId);
    if (
      !manifest ||
      manifest.manifestId !== payload.manifestId ||
      manifest.analysisType !== payload.operation ||
      manifest.queryHash !== payload.resultHash ||
      manifest.createdBy !== job.requestedBy ||
      !manifest.artifacts.some(
        (artifact) => artifact.artifactId === stored.metadata.artifactId && artifact.contentHash === stored.metadata.contentHash
      ) ||
      !manifestInputCertificationMatches(manifest, envelope)
    ) {
      throw workflowError("EXECUTION_FAILED", "Result manifest did not verify");
    }
    const view: GovernedJobResultView = {
      operation: payload.operation,
      manifestId: payload.manifestId,
      artifactId: stored.metadata.artifactId,
      resultHash: payload.resultHash,
      result: payload.result
    };
    assertResultAllowedByCurrentPolicy(
      payload,
      view,
      authorized.analysisDecision,
      authorized.actionDecision
    );
    return authorizedResponse(
      view,
      authorized.analysisDecision.obligations,
      authorized.actionDecision.obligations
    );
  }

  async cancelJob(principal: VerifiedPrincipalContext, jobHandle: string): Promise<GovernedJobStatusView> {
    return (await this.cancelJobAuthorized(principal, jobHandle)).value;
  }

  async cancelJobAuthorized(
    principal: VerifiedPrincipalContext,
    jobHandle: string,
    requestContext?: GovernedMutationRequestContext
  ): Promise<GovernedAuthorizedResponse<GovernedJobStatusView>> {
    const requestStartedAt = mutationRequestStartedAt(requestContext);
    const authorized = await this.#resolveAuthorizedJob(principal, jobHandle, "job.cancel");
    const { job } = authorized;
    const requester = principalBinding(principal);
    assertPreCommitDeadline(
      requestStartedAt,
      Math.min(
        authorized.analysisDecision.obligations.maxExecutionMs,
        authorized.actionDecision.obligations.maxExecutionMs
      )
    );
    const cancelled = this.#services.jobs.requestCancellation(principal.tenantId, job.jobId, requester);
    this.#services.control.appendAuditEvent({
      tenantId: principal.tenantId,
      eventType: "governed_job.cancellation_requested",
      entityType: "job",
      entityId: job.jobId,
      actor: requester,
      details: asJsonValue({ requestReceived: true }),
      idempotencyKey: auditIdempotencyKey("cancel", job.jobId)
    });
    return authorizedResponse(
      publicJobStatus(cancelled),
      authorized.analysisDecision.obligations,
      authorized.actionDecision.obligations
    );
  }

  async processNext(tenantId: string, workerId: string): Promise<ProcessedGovernedJob | null> {
    parse(identifierSchema, tenantId, "tenantId");
    parse(identifierSchema, workerId, "workerId");
    const claimed = this.#services.jobs.claimNext({
      tenantId,
      workerId,
      leaseSeconds: this.#workerLeaseSeconds
    });
    if (!claimed) return null;

    let operation: GovernedWorkflowOperation = "snapshot_stratification";
    let verifiedDurableResultExists = false;
    try {
      const envelope = parse(executionEnvelopeSchema, claimed.request, "persisted execution envelope") as ExecutionEnvelope;
      operation = envelope.operation;
      const principal = createVerifiedPrincipalContext(envelope.identity);
      assertActivePrincipal(principal, this.#nowEpochSeconds(), 0);
      await this.#assertCurrentMembership(principal);
      this.#assertSubmissionAuthorization(claimed, envelope);
      if (
        claimed.datasetId === null ||
        operationForTool(claimed.toolName) !== operation
      ) {
        throw workflowError("EXECUTION_FAILED", "Persisted job identity did not match its execution envelope");
      }
      const currentDecision = evaluatePolicy(this.#services.policy, {
        principal,
        toolName: TOOL_NAMES[operation],
        dataset: { id: claimed.datasetId, tenantId },
        fields: envelope.requestedFields,
        ...(envelope.purpose === null ? {} : { purpose: envelope.purpose }),
        nowEpochSeconds: this.#nowEpochSeconds()
      });
      this.#recordWorkerAuthorization(claimed, currentDecision);
      try {
        assertPermitDecision(currentDecision);
      } catch {
        throw workflowError("POLICY_DENIED", "Current policy denied queued execution");
      }
      assertSupportedObligations(currentDecision.obligations);
      this.#throwIfCancelled(tenantId, claimed.jobId);

      // A result manifest is a frozen, self-contained execution authority. Recover it
      // after current identity/policy checks but before consulting mutable definitions
      // or input-certification state, which may legitimately be superseded later.
      const recovered = this.#recoverDurableResult(claimed, envelope, currentDecision);
      if (recovered) {
        verifiedDurableResultExists = true;
        this.#persistMonitoringResultIfNeeded(tenantId, claimed, principal, recovered.payload);
        const resultHandle = this.#bindResultHandle(principal, recovered.artifactId);
        this.#services.jobs.heartbeat(
          tenantId,
          claimed.jobId,
          workerId,
          claimed.claimToken,
          this.#workerLeaseSeconds
        );
        const completed = this.#services.jobs.complete(
          tenantId,
          claimed.jobId,
          workerId,
          claimed.claimToken,
          resultHandle
        );
        return { operation, status: "succeeded", errorCode: completed.errorCode };
      }
      if (claimed.recoveryOnly) {
        throw workflowError(
          "EXECUTION_FAILED",
          "The exhausted claim had no verified durable result to recover"
        );
      }

      const certification = this.#loadCertification(tenantId, envelope.certificationManifestId);
      const definitions = this.#loadDefinitions(
        tenantId,
        operation,
        envelope.definitionIds,
        certification.snapshot.asOfDate
      );
      const inputArtifact = this.#reloadInputArtifact(
        tenantId,
        operation,
        envelope.inputArtifact,
        certification,
        definitions,
        envelope.purpose
      );
      const parameterFingerprint = operationFingerprint(
        operation,
        envelope.certificationManifestId,
        definitions,
        envelope.inputArtifact
      );
      const mappingFingerprint = controlDigestFingerprint(certification.mapping.mappingHash, "mapping hash");
      const schemaFingerprint = hashJson({ dictionaryHash: DICTIONARY_HASH, operation, version: 1 });
      const currentFields = requestedFields(operation, definitions);
      if (
        envelope.schemaFingerprint !== schemaFingerprint ||
        envelope.snapshotFingerprint !== certification.normalizedArtifact.contentHash ||
        envelope.mappingFingerprint !== mappingFingerprint ||
        envelope.mappingDigest !== certification.mapping.mappingHash ||
        envelope.recipeFingerprint !== definitions.recipeHash ||
        envelope.parameterFingerprint !== parameterFingerprint ||
        stableJson(envelope.requestedFields) !== stableJson(currentFields)
      ) {
        throw workflowError("EXECUTION_FAILED", "Execution envelope no longer matches governed inputs");
      }
      const nowEpochSeconds = this.#nowEpochSeconds();
      const remainingCredentialSeconds = principal.expiresAtEpochSeconds - nowEpochSeconds;
      if (remainingCredentialSeconds < 1) {
        throw workflowError("POLICY_DENIED", "Queued identity is no longer active");
      }
      const claimPlan = issueExecutionPlan(this.#services.keyRing, {
        principal,
        authorization: currentDecision,
        spec: {
          operation,
          parameterFingerprint,
          schemaFingerprint,
          snapshotFingerprint: certification.normalizedArtifact.contentHash,
          mappingFingerprint,
          recipeFingerprint: definitions.recipeHash
        },
        nonce: stateCompatibleOpaqueId(),
        ttlSeconds: Math.min(envelope.planTtlSeconds, this.#defaultPlanTtlSeconds, remainingCredentialSeconds),
        nowEpochSeconds
      });
      const verified = await verifyExecutionPlan(
        this.#services.keyRing,
        claimPlan.token,
        principal,
        this.#services.securityState,
        {
          nowEpochSeconds: this.#nowEpochSeconds(),
          clockSkewSeconds: 0,
          expected: {
            toolName: TOOL_NAMES[operation],
            datasetId: certification.snapshot.snapshotId,
            operation,
            parameterFingerprint,
            schemaFingerprint,
            policyFingerprint: this.#services.policy.fingerprint,
            snapshotFingerprint: certification.normalizedArtifact.contentHash
          }
        }
      );
      if (
        verified.claims.mappingFingerprint !== mappingFingerprint ||
        verified.claims.recipeFingerprint !== definitions.recipeHash
      ) {
        throw workflowError("EXECUTION_FAILED", "Signed execution lineage no longer matches governed inputs");
      }
      this.#throwIfCancelled(tenantId, claimed.jobId);

      const result = await this.#executeIsolated(
        {
          operation,
          certification,
          definitions,
          inputArtifact,
          obligations: verified.claims.obligations
        },
        claimed,
        workerId
      );
      this.#throwIfCancelled(tenantId, claimed.jobId);
      const rowCount = resultRows(operation, result);
      if (rowCount > verified.claims.obligations.maxResultRows) {
        throw workflowError("RESULT_TOO_LARGE", "Result exceeded the authorized row bound");
      }
      const resultHash = hashJson(result);
      const payloadBase = {
        jobId: claimed.jobId,
        manifestId: claimed.jobId,
        operation,
        certificationManifestId: envelope.certificationManifestId,
        definitionIds: envelope.definitionIds,
        resultHash,
        authorization: {
          decisionId: verified.claims.authorizationDecisionId,
          policyFingerprint: verified.claims.policyFingerprint,
          requestedFields: verified.claims.requestedFields,
          purpose: envelope.purpose,
          obligations: verified.claims.obligations
        },
        result
      };
      const lineage = {
        snapshotHash: certification.normalizedArtifact.contentHash,
        mappingHash: mappingFingerprint,
        mappingDigest: certification.mapping.mappingHash,
        dictionaryHash: DICTIONARY_HASH,
        recipeHash: definitions.recipeHash,
        inputArtifactHash: envelope.inputArtifact?.contentHash ?? null
      };
      const payload: ResultArtifactPayload = envelope.version === 2
        ? { ...payloadBase, version: 2, lineage }
        : {
            ...payloadBase,
            version: 3,
            lineage: {
              ...lineage,
              inputCertification: envelope.inputArtifact?.certification ?? null
            }
          };
      const serialized = stableJson(payload);
      const prospectiveView: GovernedJobResultView = {
        operation,
        manifestId: claimed.jobId,
        artifactId: "0".repeat(64),
        resultHash,
        result
      };
      if (
        Buffer.byteLength(serialized, "utf8") > verified.claims.obligations.maxResultBytes ||
        governedMcpResultByteLength(prospectiveView) > verified.claims.obligations.maxResultBytes
      ) {
        throw workflowError("RESULT_TOO_LARGE", "Result exceeded the authorized byte bound");
      }
      const resultArtifact = this.#services.artifacts.putJson({
        tenantId,
        kind: "governed_analysis_result",
        mediaType: "application/json",
        value: payload
      });
      this.#services.control.recordAnalysisManifest({
        tenantId,
        manifestId: claimed.jobId,
        snapshotId: certification.snapshot.snapshotId,
        mappingVersionId: certification.mapping.mappingVersionId,
        analysisType: operation,
        parameters: asJsonValue({
          certificationManifestId: envelope.certificationManifestId,
          definitionIds: envelope.definitionIds,
          definitionHashes: definitions.definitions.map((definition) => definition.documentHash),
          inputArtifactHash: envelope.inputArtifact?.contentHash ?? null,
          inputCertification: envelope.inputArtifact?.certification ?? null,
          mappingDigest: certification.mapping.mappingHash,
          planId: verified.planId,
          policyFingerprint: verified.claims.policyFingerprint,
          resultHash
        }),
        queryHash: resultHash,
        codeVersion: this.#codeVersion,
        artifacts: [
          {
            artifactId: resultArtifact.artifactId,
            kind: resultArtifact.kind,
            mediaType: resultArtifact.mediaType,
            contentHash: resultArtifact.contentHash,
            uri: resultArtifact.uri,
            metadata: asJsonValue({
              byteLength: resultArtifact.byteLength,
              keyId: resultArtifact.keyId,
              planId: verified.planId,
              auditTags: verified.claims.obligations.auditTags
            })
          }
        ],
        createdBy: verified.claims.principalBinding,
        idempotencyKey: `workflow-manifest:${claimed.jobId}`
      });
      verifiedDurableResultExists = true;
      this.#persistMonitoringResultIfNeeded(tenantId, claimed, principal, payload);
      const resultHandle = this.#bindResultHandle(principal, resultArtifact.artifactId);
      this.#services.jobs.heartbeat(
        tenantId,
        claimed.jobId,
        workerId,
        claimed.claimToken,
        this.#workerLeaseSeconds
      );
      const completed = this.#services.jobs.complete(
        tenantId,
        claimed.jobId,
        workerId,
        claimed.claimToken,
        resultHandle
      );
      return { operation, status: "succeeded", errorCode: completed.errorCode };
    } catch (error) {
      const code = executionErrorCode(error);
      // Once an immutable result and its manifest have verified, never replace
      // recoverable evidence with a terminal queue failure. Leave the fenced
      // claim running until lease expiry so a later recovery-only claim can
      // reauthorize, adopt, and complete it without recomputation.
      if (verifiedDurableResultExists || (claimed.recoveryOnly && isRetryableExecutionError(code))) {
        throw error;
      }
      let failed: JobRecord;
      try {
        failed = this.#services.jobs.fail(
          tenantId,
          claimed.jobId,
          workerId,
          claimed.claimToken,
          code,
          isRetryableExecutionError(code),
          isRetryableExecutionError(code)
            ? new Date(this.#clock().getTime() + 30_000).toISOString()
            : undefined
        );
      } catch (failure) {
        if (failure instanceof JobStoreError && failure.code === "CLAIM_REJECTED") {
          return { operation, status: "failed", errorCode: "LEASE_EXPIRED" };
        }
        throw failure;
      }
      try {
        this.#services.control.appendAuditEvent({
          tenantId,
          eventType: "governed_job.failed",
          entityType: "job",
          entityId: claimed.jobId,
          actor: workerId,
          details: asJsonValue({
            errorCode: code,
            operation,
            attemptCount: claimed.attemptCount,
            outcomeStatus: failed.status
          }),
          idempotencyKey: auditIdempotencyKey("failure", {
            jobId: claimed.jobId,
            attemptCount: claimed.attemptCount
          })
        });
      } catch {
        // Job state is authoritative even if supplemental failure audit is unavailable.
      }
      return {
        operation,
        status: failed.status === "cancelled" ? "cancelled" : failed.status === "queued" ? "failed" : "failed",
        errorCode: failed.errorCode
      };
    }
  }

  #recordAuthorizationDecision(
    principal: VerifiedPrincipalContext,
    decision: ReturnType<typeof evaluatePolicy>,
    receiptId: string
  ): void {
    this.#services.control.appendAuditEvent({
      tenantId: principal.tenantId,
      eventType: decision.effect === "permit" ? "authorization.permitted" : "authorization.denied",
      entityType: "policy_decision",
      entityId: receiptId,
      actor: principalBinding(principal),
      details: asJsonValue({
        decisionId: decision.decisionId,
        effect: decision.effect,
        matchedRuleIds: decision.matchedRuleIds,
        policyFingerprint: decision.policyFingerprint,
        policyId: decision.policyId,
        policyVersion: decision.policyVersion,
        toolName: decision.toolName,
        datasetId: decision.datasetId,
        requestedFields: decision.requestedFields,
        purpose: decision.purpose ?? null,
        ...(decision.effect === "permit"
          ? { auditTags: decision.obligations.auditTags }
          : { reasonCodes: decision.reasons.map((reason) => reason.code) })
      }),
      idempotencyKey: auditIdempotencyKey("authorization", receiptId)
    });
  }

  #recordSubmissionAuthorization(
    tenantId: string,
    jobId: string,
    requester: string,
    envelope: ExecutionEnvelope
  ): void {
    this.#services.control.appendAuditEvent({
      tenantId,
      eventType: "governed_job.submission_authorized",
      entityType: "job",
      entityId: jobId,
      actor: requester,
      details: asJsonValue({
        authorizationReceiptId: envelope.authorizationReceiptId,
        operation: envelope.operation,
        parameterFingerprint: envelope.parameterFingerprint,
        startFingerprint: envelope.startFingerprint
      }),
      idempotencyKey: `workflow-submission-authorization:${jobId}`
    });
  }

  #recordWorkerAuthorization(
    job: JobRecord & { readonly recoveryOnly?: boolean },
    decision: ReturnType<typeof evaluatePolicy>
  ): void {
    try {
      this.#services.control.appendAuditEvent({
        tenantId: job.tenantId,
        eventType: decision.effect === "permit" ? "authorization.permitted" : "authorization.denied",
        entityType: "policy_decision",
        entityId: decision.decisionId,
        actor: job.requestedBy,
        details: asJsonValue({
          phase: "worker_claim",
          jobId: job.jobId,
          attemptCount: job.attemptCount,
          claimMode: job.recoveryOnly ? "manifest_recovery" : "execution",
          effect: decision.effect,
          matchedRuleIds: decision.matchedRuleIds,
          policyFingerprint: decision.policyFingerprint,
          policyId: decision.policyId,
          policyVersion: decision.policyVersion,
          toolName: decision.toolName,
          datasetId: decision.datasetId,
          requestedFields: decision.requestedFields,
          purpose: decision.purpose ?? null,
          ...(decision.effect === "permit"
            ? { auditTags: decision.obligations.auditTags }
            : { reasonCodes: decision.reasons.map((reason) => reason.code) })
        }),
        idempotencyKey: auditIdempotencyKey("worker-authorization", {
          jobId: job.jobId,
          attemptCount: job.attemptCount,
          claimMode: job.recoveryOnly ? "manifest_recovery" : "execution",
          decisionId: decision.decisionId
        })
      });
    } catch {
      throw workflowError("AUDIT_REQUIRED", "Worker authorization audit could not be recorded");
    }
  }

  #assertSubmissionAuthorization(job: JobRecord, envelope: ExecutionEnvelope): void {
    const permit = this.#findAuditEvent(
      job.tenantId,
      "authorization.permitted",
      "policy_decision",
      envelope.authorizationReceiptId
    );
    const submission = this.#findAuditEvent(
      job.tenantId,
      "governed_job.submission_authorized",
      "job",
      job.jobId
    );
    if (!permit || permit.actor !== job.requestedBy || !submission || submission.actor !== job.requestedBy) {
      throw workflowError("AUDIT_REQUIRED", "Durable submission authorization evidence was not found");
    }
    const details = objectValue(submission.details, "submission authorization audit");
    if (
      details.authorizationReceiptId !== envelope.authorizationReceiptId ||
      details.parameterFingerprint !== envelope.parameterFingerprint ||
      details.startFingerprint !== envelope.startFingerprint
    ) {
      throw workflowError("AUDIT_REQUIRED", "Submission authorization evidence did not match the job");
    }
  }

  #findAuditEvent(
    tenantId: string,
    eventType: string,
    entityType: string,
    entityId: string
  ): ReturnType<ControlStore["listAuditEvents"]>[number] | null {
    let afterSequence = 0;
    for (;;) {
      const events = this.#services.control.listAuditEvents(tenantId, { afterSequence, limit: 1_000 });
      const found = events.find(
        (event) => event.eventType === eventType && event.entityType === entityType && event.entityId === entityId
      );
      if (found) return found;
      if (events.length < 1_000) return null;
      afterSequence = events[events.length - 1]!.sequence;
    }
  }

  async #assertCurrentMembership(principal: VerifiedPrincipalContext): Promise<void> {
    assertActivePrincipal(principal, this.#nowEpochSeconds(), 0);
    if (!principal.clientId) throw workflowError("POLICY_DENIED", "Current client membership is required");
    let membership: Awaited<ReturnType<TenantMembershipResolver["resolveTenantMembership"]>>;
    try {
      membership = await this.#services.tenantMembershipResolver.resolveTenantMembership({
        issuer: principal.issuer,
        subject: principal.subject,
        clientId: principal.clientId,
        audiences: principal.audiences,
        resourceIndicators: principal.resourceIndicators,
        scopes: principal.scopes,
        credentialFingerprint: principal.credentialFingerprint
      });
    } catch {
      throw workflowError("AUTHORIZATION_UNAVAILABLE", "Current membership could not be verified");
    }
    if (
      !membership ||
      membership.tenantId !== principal.tenantId ||
      membership.principalId !== principal.principalId
    ) {
      throw workflowError("POLICY_DENIED", "Current tenant membership denied the operation");
    }
  }

  async #resolveAuthorizedJob(
    principal: VerifiedPrincipalContext,
    jobHandle: string,
    actionToolName: "job.status" | "job.result" | "job.cancel"
  ): Promise<{
    readonly job: JobRecord;
    readonly envelope: ExecutionEnvelope;
    readonly analysisDecision: PermitPolicyDecision;
    readonly actionDecision: PermitPolicyDecision;
  }> {
    const job = this.#resolveJob(principal, jobHandle);
    const envelope = parse(executionEnvelopeSchema, job.request, "persisted execution envelope") as ExecutionEnvelope;
    if (
      job.datasetId === null ||
      operationForTool(job.toolName) !== envelope.operation ||
      principalBinding(principal) !== job.requestedBy
    ) {
      throw workflowError("EXECUTION_FAILED", "Job authorization lineage did not verify");
    }
    await this.#assertCurrentMembership(principal);
    const common = {
      principal,
      dataset: { id: job.datasetId, tenantId: job.tenantId },
      fields: envelope.requestedFields,
      ...(envelope.purpose === null ? {} : { purpose: envelope.purpose }),
      nowEpochSeconds: this.#nowEpochSeconds()
    } as const;
    const analysis = evaluatePolicy(this.#services.policy, { ...common, toolName: job.toolName });
    const action = evaluatePolicy(this.#services.policy, { ...common, toolName: actionToolName });
    const accessId = hashJson({
      jobId: job.jobId,
      actionToolName,
      credentialFingerprint: principal.credentialFingerprint,
      analysisDecisionId: analysis.decisionId,
      actionDecisionId: action.decisionId
    });
    this.#services.control.appendAuditEvent({
      tenantId: job.tenantId,
      eventType: analysis.effect === "permit" && action.effect === "permit"
        ? "authorization.permitted"
        : "authorization.denied",
      entityType: "job_access",
      entityId: accessId,
      actor: job.requestedBy,
      details: asJsonValue({
        jobId: job.jobId,
        actionToolName,
        datasetId: job.datasetId,
        requestedFields: envelope.requestedFields,
        purpose: envelope.purpose,
        analysis: policyDecisionAuditDetails(analysis),
        action: policyDecisionAuditDetails(action)
      }),
      idempotencyKey: `workflow-job-access:${accessId}`
    });
    try {
      assertPermitDecision(analysis);
      assertPermitDecision(action);
    } catch {
      throw workflowError("POLICY_DENIED", "Current policy denied job access");
    }
    assertSupportedObligations(analysis.obligations);
    assertSupportedObligations(action.obligations);
    return { job, envelope, analysisDecision: analysis, actionDecision: action };
  }

  async #executeIsolated(
    payload: GovernedAnalysisExecutionPayload,
    claimed: JobRecord & { readonly claimToken: string },
    workerId: string
  ): Promise<unknown> {
    this.#services.jobs.heartbeat(
      claimed.tenantId,
      claimed.jobId,
      workerId,
      claimed.claimToken,
      this.#workerLeaseSeconds
    );
    const entry = new URL(import.meta.url.endsWith(".ts") ? "./analysis-worker.ts" : "./analysis-worker.js", import.meta.url);
    const worker = new Worker(entry, {
      workerData: payload,
      resourceLimits: {
        maxOldGenerationSizeMb: 256,
        maxYoungGenerationSizeMb: 64,
        stackSizeMb: 8
      }
    });
    return await new Promise<unknown>((resolveExecution, rejectExecution) => {
      let settled = false;
      const settle = (error: GovernedWorkflowError | null, result?: unknown): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        clearInterval(supervisor);
        worker.removeAllListeners();
        void worker.terminate();
        if (error) rejectExecution(error);
        else resolveExecution(result);
      };
      const timeout = setTimeout(
        () => settle(workflowError("EXECUTION_TIMEOUT", "Execution exceeded the authorized time bound")),
        payload.obligations.maxExecutionMs
      );
      const supervisor = setInterval(() => {
        try {
          if (this.#services.jobs.get(claimed.tenantId, claimed.jobId).cancellationRequested) {
            settle(workflowError("CANCELLED", "Job cancellation was requested"));
            return;
          }
          this.#services.jobs.heartbeat(
            claimed.tenantId,
            claimed.jobId,
            workerId,
            claimed.claimToken,
            this.#workerLeaseSeconds
          );
        } catch {
          settle(workflowError("EXECUTION_FAILED", "Execution supervisor lost its job lease"));
        }
      }, Math.max(250, Math.floor((this.#workerLeaseSeconds * 1_000) / 3)));
      worker.once("message", (message: unknown) => {
        if (!message || typeof message !== "object" || Array.isArray(message)) {
          settle(workflowError("EXECUTION_FAILED", "Analysis worker returned an invalid response"));
          return;
        }
        const record = message as { readonly ok?: unknown; readonly result?: unknown; readonly code?: unknown };
        if (record.ok === true) {
          settle(null, record.result);
          return;
        }
        const code = record.code === "INVALID_INPUT" ? "INVALID_INPUT" : "EXECUTION_FAILED";
        settle(workflowError(code, "Analysis worker rejected the governed input"));
      });
      worker.once("error", () => settle(workflowError("EXECUTION_FAILED", "Analysis worker failed")));
      worker.once("exit", (code) => {
        if (!settled && code !== 0) settle(workflowError("EXECUTION_FAILED", "Analysis worker exited unexpectedly"));
      });
    });
  }

  #recoverDurableResult(
    job: JobRecord,
    envelope: ExecutionEnvelope,
    currentDecision: PermitPolicyDecision
  ): { readonly artifactId: string; readonly payload: ResultArtifactPayload } | null {
    const manifest = this.#services.control.getAnalysisManifest(job.tenantId, job.jobId);
    if (!manifest) return null;
    const candidates = manifest.artifacts.filter((artifact) => artifact.kind === "governed_analysis_result");
    if (
      manifest.analysisType !== envelope.operation ||
      manifest.createdBy !== job.requestedBy ||
      manifest.snapshotId !== job.datasetId ||
      candidates.length !== 1
    ) {
      throw workflowError("EXECUTION_FAILED", "Existing result manifest did not match the retried job");
    }
    const stored = this.#services.artifacts.getJson(job.tenantId, candidates[0]!.artifactId);
    const payload = parse(resultArtifactSchema, stored.value, "result artifact") as ResultArtifactPayload;
    if (
      stored.metadata.kind !== "governed_analysis_result" ||
      stored.metadata.contentHash !== candidates[0]!.contentHash ||
      payload.jobId !== job.jobId ||
      payload.manifestId !== job.jobId ||
      payload.operation !== envelope.operation ||
      payload.certificationManifestId !== envelope.certificationManifestId ||
      stableJson(payload.definitionIds) !== stableJson(envelope.definitionIds) ||
      payload.resultHash !== hashJson(payload.result) ||
      payload.lineage.snapshotHash !== envelope.snapshotFingerprint ||
      payload.lineage.mappingHash !== envelope.mappingFingerprint ||
      payload.lineage.mappingDigest !== envelope.mappingDigest ||
      payload.lineage.dictionaryHash !== DICTIONARY_HASH ||
      payload.lineage.recipeHash !== envelope.recipeFingerprint ||
      payload.lineage.inputArtifactHash !== (envelope.inputArtifact?.contentHash ?? null) ||
      !resultInputCertificationMatches(payload, envelope) ||
      manifest.queryHash !== payload.resultHash ||
      !manifestInputCertificationMatches(manifest, envelope)
    ) {
      throw workflowError("EXECUTION_FAILED", "Existing result artifact lineage did not verify");
    }
    assertResultAllowedByCurrentPolicy(
      payload,
      {
        operation: payload.operation,
        manifestId: payload.manifestId,
        artifactId: stored.metadata.artifactId,
        resultHash: payload.resultHash,
        result: payload.result
      },
      currentDecision,
      currentDecision
    );
    return { artifactId: stored.metadata.artifactId, payload };
  }

  #persistMonitoringResultIfNeeded(
    tenantId: string,
    job: JobRecord,
    principal: VerifiedPrincipalContext,
    payload: ResultArtifactPayload
  ): void {
    if (payload.operation !== "monitoring") return;
    this.#services.monitoringAlerts.recordRun({
      tenantId,
      runId: job.jobId,
      result: payload.result as MonitoringResult,
      recordedBy: principalBinding(principal),
      idempotencyKey: `workflow-monitoring:${job.jobId}`
    });
  }

  #bindResultHandle(principal: VerifiedPrincipalContext, artifactId: string): string {
    const issued = issuePrincipalBoundHandle(this.#services.keyRing, {
      kind: "result",
      principal,
      handleId: stateCompatibleOpaqueId(),
      ttlSeconds: this.#defaultHandleTtlSeconds,
      nowEpochSeconds: this.#nowEpochSeconds()
    });
    this.#services.securityState.bindHandle(issued.record, artifactId);
    return issued.handle;
  }

  #findIdempotentJob(
    tenantId: string,
    requester: string,
    idempotencyFingerprint: string,
    startFingerprint: string
  ): { readonly job: JobRecord; readonly envelope: ExecutionEnvelope } | null {
    for (const job of this.#services.jobs.list(tenantId, requester, 500)) {
      const candidate = this.#matchIdempotentJob(job, idempotencyFingerprint, startFingerprint);
      if (candidate) return candidate;
    }

    let afterSequence = 0;
    for (;;) {
      const events = this.#services.control.listAuditEvents(tenantId, { afterSequence, limit: 1_000 });
      for (const event of events) {
        if (
          event.eventType !== "governed_job.started" ||
          event.entityType !== "job" ||
          event.actor !== requester
        ) {
          continue;
        }
        const details = objectValue(event.details, "governed job start audit details");
        if (details.idempotencyFingerprint !== idempotencyFingerprint) continue;
        const job = this.#services.jobs.get(tenantId, event.entityId, requester);
        const candidate = this.#matchIdempotentJob(job, idempotencyFingerprint, startFingerprint);
        if (candidate) return candidate;
      }
      if (events.length < 1_000) return null;
      afterSequence = events[events.length - 1]!.sequence;
    }
  }

  #matchIdempotentJob(
    job: JobRecord,
    idempotencyFingerprint: string,
    startFingerprint: string
  ): { readonly job: JobRecord; readonly envelope: ExecutionEnvelope } | null {
    const raw = objectValue(job.request, "persisted execution envelope");
    if (raw.idempotencyFingerprint !== idempotencyFingerprint) return null;
    const envelope = parse(executionEnvelopeSchema, raw, "persisted execution envelope") as ExecutionEnvelope;
    if (envelope.startFingerprint !== startFingerprint) {
      throw workflowError("INVALID_INPUT", "Idempotency key was already used for another request");
    }
    if (operationForTool(job.toolName) !== envelope.operation) {
      throw workflowError("EXECUTION_FAILED", "Idempotent job operation did not verify");
    }
    return { job, envelope };
  }

  #recordStartAudit(job: JobRecord, envelope: ExecutionEnvelope): void {
    this.#services.control.appendAuditEvent({
      tenantId: job.tenantId,
      eventType: "governed_job.started",
      entityType: "job",
      entityId: job.jobId,
      actor: job.requestedBy,
      details: asJsonValue({
        operation: envelope.operation,
        certificationManifestId: envelope.certificationManifestId,
        definitionIds: envelope.definitionIds,
        requestedFields: envelope.requestedFields,
        purpose: envelope.purpose,
        authorizationReceiptId: envelope.authorizationReceiptId,
        policyFingerprint: envelope.policyFingerprint,
        idempotencyFingerprint: envelope.idempotencyFingerprint,
        startFingerprint: envelope.startFingerprint,
        auditTags: envelope.auditTags
      }),
      idempotencyKey: auditIdempotencyKey("start", job.jobId)
    });
  }

  #issueJobHandle(
    principal: VerifiedPrincipalContext,
    job: JobRecord,
    ttlSeconds: number,
    nowEpochSeconds: number
  ): StartedGovernedJob {
    if (job.tenantId !== principal.tenantId || job.requestedBy !== principalBinding(principal)) {
      throw workflowError("EXECUTION_FAILED", "Job ownership did not verify before handle issuance");
    }
    const issued = issuePrincipalBoundHandle(this.#services.keyRing, {
      kind: "job",
      principal,
      handleId: stateCompatibleOpaqueId(),
      ttlSeconds,
      nowEpochSeconds
    });
    this.#services.securityState.bindHandle(issued.record, job.jobId);
    return { jobHandle: issued.handle, status: job.status, operation: operationForTool(job.toolName) };
  }

  #resolveJob(principal: VerifiedPrincipalContext, jobHandle: string): JobRecord {
    assertVerifiedPrincipalContext(principal);
    const record = verifyPrincipalBoundHandle(this.#services.keyRing, jobHandle, principal, {
      expectedKind: "job",
      nowEpochSeconds: this.#nowEpochSeconds(),
      clockSkewSeconds: 0
    });
    const binding = this.#services.securityState.resolveHandle(record);
    return this.#services.jobs.get(principal.tenantId, binding.resourceId, principalBinding(principal));
  }

  #loadCertification(tenantId: string, manifestId: string): CertificationChain {
    const manifest = this.#services.control.getAnalysisManifest(tenantId, manifestId);
    if (!manifest) throw workflowError("CERTIFICATION_REQUIRED", "Certification manifest was not found");
    const parameters = parse(certificationParametersSchema, manifest.parameters, "certification parameters");
    if (
      manifest.analysisType !== "snapshot_certification" ||
      parameters.certified !== true ||
      parameters.blockerCodes.length !== 0
    ) {
      throw workflowError("CERTIFICATION_REQUIRED", "Snapshot certification did not pass");
    }
    const snapshot = this.#services.control.getDatasetSnapshot(tenantId, manifest.snapshotId);
    const mapping = this.#services.control.getMappingVersion(tenantId, manifest.mappingVersionId);
    const dataQuality = this.#services.control.getDataQualityRun(tenantId, parameters.dataQualityRunId);
    const reconciliation = this.#services.control.getReconciliation(tenantId, parameters.reconciliationId);
    if (!snapshot || !mapping || !dataQuality || !reconciliation) {
      throw workflowError("CERTIFICATION_REQUIRED", "Certification evidence chain is incomplete");
    }
    if (
      mapping.status !== "active" ||
      mapping.snapshotId !== snapshot.snapshotId ||
      mapping.dictionaryVersion !== DICTIONARY_VERSION ||
      dataQuality.snapshotId !== snapshot.snapshotId ||
      dataQuality.rulesetId !== parameters.dataQualityProfileId ||
      !dataQuality.passed ||
      dataQuality.failedFindingCount !== 0 ||
      reconciliation.snapshotId !== snapshot.snapshotId ||
      !reconciliation.passed
    ) {
      throw workflowError("CERTIFICATION_REQUIRED", "Certification evidence chain is not currently valid");
    }
    const artifactManifest = manifest.artifacts.filter((artifact) => artifact.kind === "normalized_snapshot");
    if (artifactManifest.length !== 1) {
      throw workflowError("CERTIFICATION_REQUIRED", "Certification must bind one normalized snapshot artifact");
    }
    const artifactEntry = artifactManifest[0]!;
    const loaded = this.#services.artifacts.getJson(tenantId, artifactEntry.artifactId);
    if (
      loaded.metadata.kind !== "normalized_snapshot" ||
      loaded.metadata.contentHash !== artifactEntry.contentHash ||
      artifactEntry.uri !== loaded.metadata.uri
    ) {
      throw workflowError("CERTIFICATION_REQUIRED", "Normalized snapshot artifact did not match its manifest");
    }
    const normalized = parse(normalizedSnapshotSchema, loaded.value, "normalized snapshot");
    if (
      normalized.snapshotId !== snapshot.snapshotId ||
      normalized.mappingVersionId !== mapping.mappingVersionId ||
      normalized.records.length !== snapshot.rowCount
    ) {
      throw workflowError("CERTIFICATION_REQUIRED", "Normalized snapshot artifact lineage did not match");
    }
    const reconciliationDetails = objectValue(reconciliation.details, "reconciliation details");
    const reconciliationFingerprint = parse(
      hashSchema,
      reconciliationDetails.fingerprint,
      "reconciliation fingerprint"
    );
    const expectedQueryHash = hashJson({
      snapshotHash: snapshot.contentHash,
      mappingHash: mapping.mappingHash,
      dataQualityFingerprint: normalized.dataQualityFingerprint,
      reconciliationFingerprint
    });
    if (manifest.queryHash !== expectedQueryHash) {
      throw workflowError("CERTIFICATION_REQUIRED", "Certification fingerprint did not verify");
    }
    return {
      manifest,
      snapshot,
      mapping,
      dataQuality,
      reconciliation,
      normalizedArtifact: loaded.metadata,
      records: normalized.records,
      dataQualityFingerprint: normalized.dataQualityFingerprint,
      reconciliationFingerprint
    };
  }

  #loadDefinitions(
    tenantId: string,
    operation: GovernedWorkflowOperation,
    definitionIds: readonly string[],
    asOfDate: string
  ): DefinitionBundle {
    const expectedKind = EXPECTED_DEFINITION_KIND[operation];
    if (operation !== "monitoring" && definitionIds.length !== 1) {
      throw workflowError("INVALID_INPUT", `${operation} requires exactly one governed definition`);
    }
    const definitions = definitionIds.map((definitionId) => {
      const definition = this.#services.definitions.get(tenantId, definitionId);
      if (!definition || definition.kind !== expectedKind) {
        throw workflowError("DEFINITION_NOT_EFFECTIVE", "Governed definition was not found with the required kind");
      }
      let effective: GovernedDefinition;
      try {
        effective = this.#services.definitions.selectEffective(
          tenantId,
          expectedKind,
          definition.definitionKey,
          asOfDate
        );
      } catch {
        throw workflowError("DEFINITION_NOT_EFFECTIVE", "Governed definition is not effective for the snapshot date");
      }
      if (effective.definitionId !== definition.definitionId) {
        throw workflowError("DEFINITION_NOT_EFFECTIVE", "A different governed definition is effective for the snapshot date");
      }
      validateDefinitionDocument(operation, definition);
      return definition;
    });
    const sorted = [...definitions].sort((left, right) => compareText(left.definitionId, right.definitionId));
    return { definitions: sorted, recipeHash: hashJson(sorted.map((item) => [item.definitionId, item.documentHash])) };
  }

  #loadInputArtifact(
    tenantId: string,
    operation: GovernedWorkflowOperation,
    artifactId: string | undefined,
    certification: CertificationChain,
    definitions: DefinitionBundle,
    purpose: string | null
  ): LoadedInputArtifact | null {
    const expectedKind = EXPECTED_INPUT_KIND[operation];
    if (!expectedKind) {
      if (artifactId !== undefined) {
        throw workflowError("INVALID_INPUT", `${operation} does not accept a separate input artifact`);
      }
      return null;
    }
    if (!artifactId) throw workflowError("INVALID_INPUT", `${operation} requires an encrypted input artifact`);
    if (purpose === null) throw workflowError("INVALID_INPUT", `${operation} requires an explicit governed purpose`);
    const loaded = this.#services.artifacts.getJson(tenantId, artifactId);
    if (loaded.metadata.kind !== expectedKind) {
      throw workflowError("INVALID_INPUT", `Input artifact must have kind ${expectedKind}`);
    }
    if (operation !== "ar_borrowing_base" && operation !== "monitoring") {
      throw workflowError("INVALID_INPUT", "Certified operation input is unsupported for this operation");
    }
    const verifier = new InputCertificationService({
      control: this.#services.control,
      definitions: this.#services.definitions,
      artifacts: this.#services.artifacts,
      inputCertifications: this.#services.inputCertifications
    }, this.#clock);
    let verified;
    try {
      verified = verifier.verify({
        tenantId,
        operation,
        purpose,
        artifact: loaded.metadata,
        value: loaded.value,
        chain: certification,
        definitions: definitions.definitions,
        now: this.#clock()
      });
    } catch {
      throw workflowError("CERTIFICATION_REQUIRED", "Input population certification did not verify");
    }
    validateOperationInput(operation, verified.payload, certification.snapshot);
    return {
      reference: {
        artifactId: loaded.metadata.artifactId,
        contentHash: loaded.metadata.contentHash,
        kind: loaded.metadata.kind,
        certification: verified.summary
      },
      value: verified.payload
    };
  }

  #reloadInputArtifact(
    tenantId: string,
    operation: GovernedWorkflowOperation,
    reference: InputArtifactReference | null,
    certification: CertificationChain,
    definitions: DefinitionBundle,
    purpose: string | null
  ): LoadedInputArtifact | null {
    if (!reference) return this.#loadInputArtifact(tenantId, operation, undefined, certification, definitions, purpose);
    const loaded = this.#loadInputArtifact(
      tenantId,
      operation,
      reference.artifactId,
      certification,
      definitions,
      purpose
    );
    if (
      !loaded ||
      loaded.reference.contentHash !== reference.contentHash ||
      loaded.reference.kind !== reference.kind ||
      stableJson(loaded.reference.certification ?? null) !== stableJson(reference.certification ?? null)
    ) {
      throw workflowError("EXECUTION_FAILED", "Input artifact no longer matches the signed execution envelope");
    }
    return loaded;
  }

  #throwIfCancelled(tenantId: string, jobId: string): void {
    if (this.#services.jobs.get(tenantId, jobId).cancellationRequested) {
      throw workflowError("CANCELLED", "Job cancellation was requested");
    }
  }

  #nowEpochSeconds(): number {
    const time = this.#clock().getTime();
    if (!Number.isFinite(time)) throw workflowError("INVALID_INPUT", "Workflow clock is invalid");
    return Math.floor(time / 1_000);
  }
}

/** Pure deterministic worker entry; callers must supply already-governed inputs and obligations. */
export function executeGovernedAnalysis(
  payload: GovernedAnalysisExecutionPayload
): SnapshotStratificationResult | SnapshotVintageResult | ArBorrowingBaseResult | MonitoringResult | unknown {
  const { operation, certification, definitions, inputArtifact, obligations } = payload;
  assertSupportedObligations(obligations);
  const mappingFingerprint = controlDigestFingerprint(certification.mapping.mappingHash, "mapping hash");
  const lineage: ImmutableSnapshotLineage = {
    snapshotHash: certification.normalizedArtifact.contentHash,
    mappingHash: mappingFingerprint,
    dictionaryHash: DICTIONARY_HASH,
    recipeHash: definitions.recipeHash
  };
  if (operation === "snapshot_stratification") {
    const recipe = parse(stratificationRecipeSchema, definitions.definitions[0]!.document, "stratification recipe");
    return runSnapshotStratification({
      records: certification.records,
      lineage,
      asOfDate: certification.snapshot.asOfDate,
      dimension: recipe.dimension,
      ...(recipe.balanceField === undefined ? {} : { balanceField: recipe.balanceField }),
      ...(recipe.buckets === undefined
        ? {}
        : {
            buckets: recipe.buckets.map((bucket) => ({
              label: bucket.label,
              ...(bucket.lower === undefined ? {} : { lower: bucket.lower }),
              ...(bucket.upper === undefined ? {} : { upper: bucket.upper }),
              ...(bucket.includeLower === undefined ? {} : { includeLower: bucket.includeLower }),
              ...(bucket.includeUpper === undefined ? {} : { includeUpper: bucket.includeUpper })
            }))
          }),
      ...(recipe.weightedAverageFields === undefined
        ? {}
        : { weightedAverageFields: recipe.weightedAverageFields }),
      minimumCohortSize: Math.max(recipe.minimumCohortSize ?? 1, obligations.minimumCohortSize),
      maxRecords: recipe.maxRecords,
      maxGroups: Math.min(recipe.maxGroups, obligations.maxResultRows)
    });
  }
  if (operation === "snapshot_vintage") {
    const recipe = parse(vintageRecipeSchema, definitions.definitions[0]!.document, "vintage recipe");
    return runSnapshotVintageAnalysis({
      records: certification.records,
      lineage,
      cohortGrain: recipe.cohortGrain,
      asOfDate: certification.snapshot.asOfDate,
      maxMonthsOnBook: recipe.maxMonthsOnBook,
      delinquencyThresholdDays: recipe.delinquencyThresholdDays,
      minimumCohortSize: Math.max(recipe.minimumCohortSize ?? 1, obligations.minimumCohortSize),
      maxRecords: recipe.maxRecords,
      maxPoints: Math.min(recipe.maxPoints, obligations.maxResultRows)
    });
  }
  if (operation === "ar_borrowing_base") {
    if (!inputArtifact?.reference.certification) {
      throw workflowError("CERTIFICATION_REQUIRED", "Borrowing-base input population is not certified");
    }
    const policy = parseBorrowingBasePolicy(definitions.definitions[0]!);
    const input = parse(borrowingBaseInputSchema, inputArtifact?.value, "borrowing-base input");
    return sanitizeBorrowingBase(
      calculateArBorrowingBase({
        asOfDate: input.asOfDate,
        policyVersions: [policy],
        receivables: input.receivables,
        usage: input.usage
      }),
      obligations
    );
  }
  const monitorDefinitions = definitions.definitions.map(parseMonitorDefinition);
  if (!inputArtifact?.reference.certification) {
    throw workflowError("CERTIFICATION_REQUIRED", "Monitoring input population is not certified");
  }
  const input = parse(monitoringInputSchema, inputArtifact?.value, "monitoring input");
  return evaluateMonitoring({
    asOfDate: input.asOfDate,
    scope: input.scope as MonitoringScope,
    dataQualityGate: certifiedMonitoringGate(certification, definitions, inputArtifact),
    monitorDefinitions,
    observations: input.observations as readonly MetricObservation[]
  });
}

function validateDefinitionDocument(
  operation: GovernedWorkflowOperation,
  definition: GovernedDefinition
): void {
  if (operation === "snapshot_stratification") {
    parse(stratificationRecipeSchema, definition.document, "stratification recipe");
    return;
  }
  if (operation === "snapshot_vintage") {
    parse(vintageRecipeSchema, definition.document, "vintage recipe");
    return;
  }
  if (operation === "ar_borrowing_base") {
    parseBorrowingBasePolicy(definition);
    return;
  }
  parseMonitorDefinition(definition);
}

function parseBorrowingBasePolicy(definition: GovernedDefinition): ArBorrowingBasePolicyVersion {
  const policy = parse(borrowingBasePolicySchema, definition.document, "borrowing-base policy");
  if (
    policy.policyId !== definition.definitionKey ||
    policy.version !== definition.version ||
    policy.effectiveFrom !== definition.effectiveFrom ||
    (policy.effectiveTo ?? null) !== definition.effectiveTo
  ) {
    throw workflowError("INVALID_INPUT", "Borrowing-base policy identity does not match definition governance");
  }
  return policy as ArBorrowingBasePolicyVersion;
}

function parseMonitorDefinition(definition: GovernedDefinition): MonitorDefinition {
  const monitor = parse(monitorDefinitionSchema, definition.document, "monitor definition");
  if (
    monitor.monitorId !== definition.definitionKey ||
    monitor.version !== definition.version ||
    monitor.effectiveFrom !== definition.effectiveFrom ||
    (monitor.effectiveTo ?? null) !== definition.effectiveTo
  ) {
    throw workflowError("INVALID_INPUT", "Monitor identity does not match definition governance");
  }
  return monitor as MonitorDefinition;
}

function validateOperationInput(
  operation: GovernedWorkflowOperation,
  value: unknown,
  snapshot: DatasetSnapshot
): void {
  if (operation === "ar_borrowing_base") {
    const input = parse(borrowingBaseInputSchema, value, "borrowing-base input");
    if (input.snapshotId !== snapshot.snapshotId || input.asOfDate !== snapshot.asOfDate) {
      throw workflowError("INVALID_INPUT", "Borrowing-base input does not belong to the certified snapshot");
    }
    return;
  }
  if (operation === "monitoring") {
    const input = parse(monitoringInputSchema, value, "monitoring input");
    if (
      input.snapshotId !== snapshot.snapshotId ||
      input.asOfDate !== snapshot.asOfDate ||
      input.observations.some(
        (observation) => observation.snapshotId !== snapshot.snapshotId || observation.asOfDate > snapshot.asOfDate
      )
    ) {
      throw workflowError("INVALID_INPUT", "Monitoring input does not belong to the certified snapshot");
    }
  }
}

function requestedFields(
  operation: GovernedWorkflowOperation,
  definitions: DefinitionBundle
): readonly string[] {
  if (operation === "snapshot_stratification") {
    const recipe = parse(
      stratificationRecipeSchema,
      definitions.definitions[0]!.document,
      "stratification recipe"
    );
    return sortedUnique([
      "as_of_date",
      recipe.balanceField ?? "outstanding_balance",
      recipe.dimension,
      ...(recipe.weightedAverageFields ?? [])
    ]);
  }
  if (operation === "snapshot_vintage") {
    return [
      "as_of_date",
      "charge_off_amount",
      "days_past_due",
      "loan_id",
      "original_balance",
      "origination_date",
      "outstanding_balance",
      "recovery_amount"
    ];
  }
  if (operation === "ar_borrowing_base") {
    return ["days_past_due", "debtor_id", "facility_usage", "flags", "outstanding_amount", "receivable_id"];
  }
  return ["metric_observations", "monitor_thresholds"];
}

function operationFingerprint(
  operation: GovernedWorkflowOperation,
  certificationManifestId: string,
  definitions: DefinitionBundle,
  inputArtifact: InputArtifactReference | null
): string {
  return hashJson({
    operation,
    certificationManifestId,
    definitions: definitions.definitions.map((definition) => ({
      definitionId: definition.definitionId,
      documentHash: definition.documentHash
    })),
    inputArtifact
  });
}

function resultInputCertificationMatches(
  payload: ResultArtifactPayload,
  envelope: ExecutionEnvelope
): boolean {
  if (payload.version === 2) {
    return envelope.version === 2 && envelope.inputArtifact?.certification === undefined;
  }
  return (
    envelope.version === 3 &&
    stableJson(payload.lineage.inputCertification) ===
      stableJson(envelope.inputArtifact?.certification ?? null)
  );
}

function manifestInputCertificationMatches(
  manifest: AnalysisManifest,
  envelope: ExecutionEnvelope
): boolean {
  const parameters = objectValue(manifest.parameters, "result manifest parameters");
  const stored = parameters.inputCertification ?? null;
  return stableJson(stored) === stableJson(envelope.inputArtifact?.certification ?? null);
}

function certifiedMonitoringGate(
  certification: CertificationChain,
  definitions: DefinitionBundle,
  inputArtifact: LoadedInputArtifact | null
): DataQualityGate {
  const certifiedInput = inputArtifact?.reference.certification;
  return {
    status: "certified",
    gateId: certifiedInput?.lineageHash ?? certification.manifest.manifestId,
    snapshotId: certification.snapshot.snapshotId,
    certifiedAt: certifiedInput?.certifiedAt ?? certification.manifest.createdAt,
    blockingFindingCount: certification.dataQuality.failedFindingCount,
    evidence: [
      { kind: "mapping", id: certification.mapping.mappingVersionId },
      { kind: "reconciliation", id: certification.reconciliation.reconciliationId },
      { kind: "source_artifact", id: certification.normalizedArtifact.artifactId },
      ...(inputArtifact === null
        ? []
        : [
            { kind: "source_artifact" as const, id: inputArtifact.reference.artifactId },
            {
              kind: "reconciliation" as const,
              id: certifiedInput?.reconciliationId ?? certification.reconciliation.reconciliationId
            }
          ]),
      ...definitions.definitions.map((definition) => ({ kind: "policy" as const, id: definition.definitionId }))
    ]
  };
}

function sanitizeBorrowingBase(
  result: ArBorrowingBaseResult,
  _obligations: PolicyObligations
): ArBorrowingBaseResult | unknown {
  return {
    ...result,
    receivables: [],
    usage: [],
    waterfall: result.waterfall.map((step) => ({
      ...step,
      affectedReceivableIds: [],
      evidence: step.evidence.filter((item) => !item.key.startsWith("debtor:") && !item.key.startsWith("usage:"))
    }))
  };
}

function assertSupportedObligations(obligations: PolicyObligations): void {
  if (!obligations.requireImmutableSnapshot) {
    throw workflowError("POLICY_DENIED", "Governed analysis requires an immutable snapshot obligation");
  }
  if (obligations.allowRawRows || obligations.allowExport) {
    throw workflowError("POLICY_DENIED", "Raw rows and exports are unavailable in the governed analysis plane");
  }
  if (Object.keys(obligations.fieldMasks).length !== 0) {
    throw workflowError("POLICY_DENIED", "Field-mask obligations are not supported by this analysis release");
  }
  if (
    obligations.rowFilterRefs.some((reference) => reference !== "tenant-boundary") ||
    new Set(obligations.rowFilterRefs).size !== obligations.rowFilterRefs.length
  ) {
    throw workflowError("POLICY_DENIED", "Unsupported row-filter obligation");
  }
}

function assertResultAllowedByCurrentPolicy(
  payload: ResultArtifactPayload,
  view: GovernedJobResultView,
  analysisDecision: PermitPolicyDecision,
  actionDecision: PermitPolicyDecision
): void {
  for (const decision of [analysisDecision, actionDecision]) {
    assertSupportedObligations(decision.obligations);
    if (decision.obligations.minimumCohortSize > payload.authorization.obligations.minimumCohortSize) {
      throw workflowError("POLICY_DENIED", "Stored result does not satisfy the current cohort minimum");
    }
    if (resultRows(payload.operation, payload.result) > decision.obligations.maxResultRows) {
      throw workflowError("POLICY_DENIED", "Stored result exceeds the current row disclosure bound");
    }
    if (governedMcpResultByteLength(view) > decision.obligations.maxResultBytes) {
      throw workflowError("POLICY_DENIED", "Stored result exceeds the current byte disclosure bound");
    }
  }
}

function governedMcpResultByteLength(view: GovernedJobResultView): number {
  return modernMcpSuccessResultByteLength(
    { result: view },
    { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION }
  );
}

function authorizedResponse<T>(
  value: T,
  ...obligations: readonly PolicyObligations[]
): GovernedAuthorizedResponse<T> {
  return Object.freeze({ value, obligations: Object.freeze([...obligations]) });
}

function policyDecisionAuditDetails(decision: ReturnType<typeof evaluatePolicy>): JsonValue {
  return {
    decisionId: decision.decisionId,
    effect: decision.effect,
    matchedRuleIds: [...decision.matchedRuleIds],
    policyId: decision.policyId,
    policyVersion: decision.policyVersion,
    policyFingerprint: decision.policyFingerprint,
    toolName: decision.toolName,
    datasetId: decision.datasetId,
    requestedFields: [...decision.requestedFields],
    purpose: decision.purpose ?? null,
    ...(decision.effect === "permit"
      ? { auditTags: [...decision.obligations.auditTags] }
      : { reasonCodes: decision.reasons.map((reason) => reason.code) })
  };
}

function isRetryableExecutionError(code: string): boolean {
  return code === "AUTHORIZATION_UNAVAILABLE";
}

function resultRows(operation: GovernedWorkflowOperation, result: unknown): number {
  const value = objectValue(result, "result");
  if (operation === "snapshot_stratification") return arrayValue(value.rows, "stratification rows").length;
  if (operation === "snapshot_vintage") return arrayValue(value.points, "vintage points").length;
  // Raw receivables are deliberately stripped before publication. Count the
  // reason-coded waterfall that is actually disclosed so maxResultRows cannot
  // be bypassed by the sanitizer emptying the source-record array.
  if (operation === "ar_borrowing_base") return arrayValue(value.waterfall, "borrowing-base waterfall").length;
  return arrayValue(value.evaluations, "monitoring evaluations").length;
}

function persistedIdentity(principal: VerifiedPrincipalContext): VerifiedIdentityAttestation {
  return {
    issuer: principal.issuer,
    subject: principal.subject,
    principalId: principal.principalId,
    tenantId: principal.tenantId,
    ...(principal.clientId === undefined ? {} : { clientId: principal.clientId }),
    audiences: principal.audiences,
    resourceIndicators: principal.resourceIndicators,
    scopes: principal.scopes,
    credentialFingerprint: principal.credentialFingerprint,
    verifiedAtEpochSeconds: principal.verifiedAtEpochSeconds,
    ...(principal.notBeforeEpochSeconds === undefined
      ? {}
      : { notBeforeEpochSeconds: principal.notBeforeEpochSeconds }),
    expiresAtEpochSeconds: principal.expiresAtEpochSeconds,
    authenticationMethods: principal.authenticationMethods
  };
}

function publicJobStatus(job: JobRecord): GovernedJobStatusView {
  return {
    operation: operationForTool(job.toolName),
    status: job.status,
    attemptCount: job.attemptCount,
    maxAttempts: job.maxAttempts,
    cancellationRequested: job.cancellationRequested,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    errorCode: job.errorCode,
    resultAvailable: job.status === "succeeded" && job.resultHandle !== null
  };
}

function operationForTool(toolName: string): GovernedWorkflowOperation {
  const found = (Object.entries(TOOL_NAMES) as [GovernedWorkflowOperation, string][]).find(
    ([, candidate]) => candidate === toolName
  );
  if (!found) throw workflowError("EXECUTION_FAILED", "Job tool is not a governed workflow operation");
  return found[0];
}

function executionErrorCode(error: unknown): string {
  if (error instanceof SignedArtifactError) return error.code;
  if (error instanceof GovernedWorkflowError) return error.code;
  if (error instanceof z.ZodError) return "INVALID_INPUT";
  return "EXECUTION_FAILED";
}

function parse<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  const result = schema.safeParse(value);
  if (!result.success) throw workflowError("INVALID_INPUT", `${label} failed strict validation`);
  return result.data;
}

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw workflowError("INVALID_INPUT", `${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function arrayValue(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) throw workflowError("EXECUTION_FAILED", `${label} must be an array`);
  return value;
}

function asRecord(value: unknown): Readonly<Record<string, unknown>> {
  return objectValue(JSON.parse(stableJson(value)) as unknown, "job request");
}

function asJsonValue(value: unknown): JsonValue {
  return JSON.parse(stableJson(value)) as JsonValue;
}

function stableJson(value: unknown): string {
  const normalized = canonicalize(value);
  const serialized = JSON.stringify(normalized);
  if (serialized === undefined) throw workflowError("INVALID_INPUT", "Value is not canonical JSON");
  return serialized;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, nested]) => nested !== undefined)
        .sort(([left], [right]) => compareText(left, right))
        .map(([key, nested]) => [key, canonicalize(nested)])
    );
  }
  if (typeof value === "bigint" || (typeof value === "number" && !Number.isFinite(value))) {
    throw workflowError("INVALID_INPUT", "Value contains a non-JSON scalar");
  }
  return value;
}

function hashJson(value: unknown): string {
  return hashText(stableJson(value));
}

function hashText(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function auditIdempotencyKey(scope: string, identity: unknown): string {
  return `workflow-${scope}:${hashJson(identity)}`;
}

function stateCompatibleOpaqueId(): string {
  return `h${randomBytes(24).toString("base64url")}`;
}

function controlDigestFingerprint(value: string, label: string): string {
  const digest = parse(controlDigestSchema, value, label);
  return digest.slice("sha256:".length);
}

function sortedUnique(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort(compareText);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function boundedInteger(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw workflowError("INVALID_INPUT", `${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function mutationRequestStartedAt(
  requestContext: GovernedMutationRequestContext | undefined
): number | undefined {
  if (requestContext === undefined) return undefined;
  const now = performance.now();
  const startedAt = requestContext.requestStartedAtMonotonicMs;
  if (!Number.isFinite(startedAt) || startedAt < 0 || startedAt > now) {
    throw workflowError("INVALID_INPUT", "Mutation request start time is invalid");
  }
  return startedAt;
}

function assertPreCommitDeadline(startedAt: number | undefined, maximumExecutionMs: number): void {
  if (startedAt === undefined) return;
  if (performance.now() - startedAt > maximumExecutionMs) {
    throw workflowError("EXECUTION_TIMEOUT", "Mutation validation exceeded the authorized time bound");
  }
}

function isRealIsoDate(value: string): boolean {
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

function workflowError(code: GovernedWorkflowErrorCode, message: string): GovernedWorkflowError {
  return new GovernedWorkflowError(code, message);
}
