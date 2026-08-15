import * as z from "zod/v4";

import {
  GovernedDefinitionKindV2Schema,
  GovernedDefinitionTransitionV2Schema,
  SemanticVersionV2Schema,
  Sha256HashSchema
} from "../contracts/index.js";
import type { JsonValue } from "../control/store.js";

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const CONTROL_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DECIMAL = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/;
const SHA256 = /^(?:sha256:)?[a-f0-9]{64}$/;

export const operatorIdentifierSchema = z.string().regex(CONTROL_IDENTIFIER);
export const documentIdentifierSchema = z.string().regex(IDENTIFIER);
export const isoDateSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/)
  .refine(isRealIsoDate);
export const isoDateTimeSchema = z
  .string()
  .min(1)
  .max(128)
  .refine((value) => Number.isFinite(Date.parse(value)));
export const decimalSchema = z.string().regex(DECIMAL).max(1_000);

const boundedTextSchema = z
  .string()
  .min(1)
  .max(2_048)
  .refine((value) => !/[\u0000-\u001f\u007f]/.test(value));
const sourceColumnSchema = z
  .object({
    name: z.string().min(1).max(128),
    type: z.string().min(1).max(512).optional(),
    description: z.string().max(4_096).optional(),
    nullable: z.boolean().optional()
  })
  .strict();
const fieldMappingSchema = z
  .object({
    sourceColumn: z.string().min(1).max(128),
    canonicalField: z.string().min(1).max(128)
  })
  .strict();
const profileSchema = z.enum(["base", "stratification", "vintage", "borrowing_base"]);
const jsonFileLimitsSchema = z
  .object({
    maximumBytes: z.number().int().min(1_024).max(100_000_000).optional(),
    maximumRecords: z.number().int().min(1).max(1_000_000).optional(),
    maximumColumns: z.number().int().min(1).max(2_000).optional(),
    maximumCellCharacters: z.number().int().min(1).max(1_000_000).optional()
  })
  .strict();

export const fileIngestInputSchema = z
  .object({
    tenantId: operatorIdentifierSchema,
    snapshotId: operatorIdentifierSchema,
    sourceId: operatorIdentifierSchema,
    asOfDate: isoDateSchema,
    filePath: z.string().min(1).max(4_096),
    format: z.enum(["csv", "json", "ndjson"]).optional(),
    limits: jsonFileLimitsSchema.optional(),
    idempotencyKey: operatorIdentifierSchema,
    expectedCanonicalContentHash: z.string().regex(SHA256).optional()
  })
  .strict();

export const sqlExtractInputSchema = z
  .object({
    sourceId: operatorIdentifierSchema,
    tenantId: operatorIdentifierSchema,
    datasetId: operatorIdentifierSchema,
    snapshotId: operatorIdentifierSchema,
    relationId: operatorIdentifierSchema,
    columnIds: z.array(operatorIdentifierSchema).min(1).max(2_000),
    watermark: z
      .object({ upperBound: z.union([z.string().max(4_096), z.number().safe()]) })
      .strict()
      .optional(),
    asOfDate: isoDateSchema,
    idempotencyKey: operatorIdentifierSchema,
    expectedCanonicalContentHash: z.string().regex(SHA256).optional()
  })
  .strict();

/**
 * Trusted modern capture accepts identity references only. Source location,
 * SQL, credentials, limits, hashes and actor identity are runtime authority.
 */
export const extractSqlV2InputSchema = z
  .object({
    sourceContractId: operatorIdentifierSchema,
    deliveryId: operatorIdentifierSchema
  })
  .strict();

export const mappingProposeInputSchema = z
  .object({
    tenantId: operatorIdentifierSchema,
    mappingVersionId: operatorIdentifierSchema,
    mappingKey: operatorIdentifierSchema,
    snapshotId: operatorIdentifierSchema,
    sourceColumns: z.array(sourceColumnSchema).min(1).max(2_000),
    mappings: z.array(fieldMappingSchema).min(1).max(2_000),
    profile: profileSchema,
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();

const mappingValidatedTransitionSchema = z
  .object({
    tenantId: operatorIdentifierSchema,
    mappingVersionId: operatorIdentifierSchema,
    toStatus: z.literal("validated"),
    sourceColumns: z.array(sourceColumnSchema).min(1).max(2_000),
    profile: profileSchema,
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();
const mappingApprovalTransitionSchema = z
  .object({
    tenantId: operatorIdentifierSchema,
    mappingVersionId: operatorIdentifierSchema,
    toStatus: z.enum(["approved", "active"]),
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();
export const mappingTransitionInputSchema = z.discriminatedUnion("toStatus", [
  mappingValidatedTransitionSchema,
  mappingApprovalTransitionSchema
]);

export const definitionProposeInputSchema = z
  .object({
    tenantId: operatorIdentifierSchema,
    definitionId: documentIdentifierSchema,
    definitionKey: documentIdentifierSchema,
    kind: z.enum([
      "data_quality_profile",
      "stratification_recipe",
      "vintage_recipe",
      "borrowing_base_policy",
      "monitor_definition"
    ]),
    version: documentIdentifierSchema,
    effectiveFrom: isoDateSchema,
    effectiveTo: isoDateSchema.optional(),
    document: z.unknown(),
    idempotencyKey: documentIdentifierSchema
  })
  .strict();

export const definitionTransitionInputSchema = z
  .object({
    tenantId: documentIdentifierSchema,
    definitionId: documentIdentifierSchema,
    toStatus: z.enum(["validated", "approved", "active", "retired"]),
    evidence: z.unknown().optional(),
    idempotencyKey: documentIdentifierSchema
  })
  .strict();

export const governedDefinitionV2ProposeInputSchema = z
  .object({
    tenantId: operatorIdentifierSchema,
    definitionVersionId: operatorIdentifierSchema,
    definitionKey: operatorIdentifierSchema,
    kind: GovernedDefinitionKindV2Schema,
    semanticVersion: SemanticVersionV2Schema,
    effectiveFrom: isoDateSchema,
    effectiveTo: isoDateSchema.optional(),
    predecessorDefinitionVersionId: operatorIdentifierSchema.optional(),
    rollbackTargetDefinitionVersionId: operatorIdentifierSchema.optional(),
    document: z.unknown(),
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();

export const governedDefinitionV2TransitionInputSchema = z
  .object({
    tenantId: operatorIdentifierSchema,
    definitionVersionId: operatorIdentifierSchema,
    toStatus: GovernedDefinitionTransitionV2Schema,
    expectedRevision: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    evidence: z.unknown().optional(),
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();

export const governedDefinitionV2GetInputSchema = z
  .object({
    tenantId: operatorIdentifierSchema,
    definitionVersionId: operatorIdentifierSchema
  })
  .strict();

export const governedDefinitionV2ListInputSchema = z
  .object({
    tenantId: operatorIdentifierSchema,
    kind: GovernedDefinitionKindV2Schema.optional(),
    definitionKey: operatorIdentifierSchema.optional(),
    limit: z.number().int().min(1).max(1_000).optional()
  })
  .strict();

export const governedDefinitionV2SelectEffectiveInputSchema = z
  .object({
    tenantId: operatorIdentifierSchema,
    kind: GovernedDefinitionKindV2Schema,
    definitionKey: operatorIdentifierSchema,
    asOfDate: isoDateSchema
  })
  .strict();

export const governedDefinitionV2AuditListInputSchema = z
  .object({
    tenantId: operatorIdentifierSchema,
    afterSequence: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
    limit: z.number().int().min(1).max(1_000).optional()
  })
  .strict();

const controlTotalsSchema = z
  .object({
    rowCount: z.number().int().nonnegative(),
    balance: decimalSchema,
    currency: z.string().regex(/^[A-Z]{3}$/).optional()
  })
  .strict();
const reconciliationToleranceSchema = z
  .object({
    rowCount: z.number().int().nonnegative(),
    balance: decimalSchema
  })
  .strict();
export const certifySnapshotInputSchema = z
  .object({
    tenantId: operatorIdentifierSchema,
    snapshotId: operatorIdentifierSchema,
    mappingVersionId: operatorIdentifierSchema,
    dataQualityDefinitionKey: documentIdentifierSchema,
    dataQualityRunId: operatorIdentifierSchema,
    reconciliationId: operatorIdentifierSchema,
    certificationManifestId: operatorIdentifierSchema,
    declaredControlTotals: controlTotalsSchema,
    reconciliationTolerance: reconciliationToleranceSchema.optional(),
    evaluatedAt: isoDateTimeSchema,
    codeVersion: operatorIdentifierSchema,
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();

/**
 * Trusted modern certification reloads every definition and evidence payload
 * by immutable identifier; callers cannot submit rows, totals or actor data.
 */
export const certifySnapshotV2InputSchema = z
  .object({
    snapshotId: operatorIdentifierSchema
  })
  .strict();

export const sourceDeliveryRegisterInputSchema = z
  .object({
    deliveryId: operatorIdentifierSchema,
    sourceContractDefinitionVersionId: operatorIdentifierSchema,
    datasetScopeBindingDefinitionVersionId: operatorIdentifierSchema,
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();

export const sourceDeliveryDisableInputSchema = z
  .object({
    deliveryId: operatorIdentifierSchema,
    reasonCode: operatorIdentifierSchema,
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();

export const sourceDeliveryGetInputSchema = z
  .object({ deliveryId: operatorIdentifierSchema })
  .strict();

export const sourceDeliveryAuditListInputSchema = z
  .object({
    afterSequence: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
    limit: z.number().int().min(1).max(1_000).optional()
  })
  .strict();

const historicalBundleBaseShape = {
  bundleId: operatorIdentifierSchema,
  version: operatorIdentifierSchema,
  mediaType: z.literal("application/json"),
  createdAt: isoDateTimeSchema,
  filePath: z.string().min(1).max(4_096),
  idempotencyKey: operatorIdentifierSchema
} as const;

export const historicalBundleRegisterInputSchema = z.discriminatedUnion("bundleKind", [
  z
    .object({
      ...historicalBundleBaseShape,
      bundleKind: z.literal("dictionary"),
      dictionaryVersion: operatorIdentifierSchema,
      dictionaryHash: Sha256HashSchema,
      fieldPolicyVersion: operatorIdentifierSchema,
      fieldPolicyHash: Sha256HashSchema
    })
    .strict(),
  z
    .object({
      ...historicalBundleBaseShape,
      bundleKind: z.enum(["field_policy", "mapping_compiler", "methodology"])
    })
    .strict()
]);

export const historicalRuntimeRegisterInputSchema = z
  .object({
    runtimeBundleId: operatorIdentifierSchema,
    runtimeVersion: operatorIdentifierSchema,
    dictionary: z
      .object({
        bundleId: operatorIdentifierSchema,
        version: operatorIdentifierSchema
      })
      .strict(),
    mappingCompiler: z
      .object({
        bundleId: operatorIdentifierSchema,
        version: operatorIdentifierSchema
      })
      .strict(),
    methodologies: z
      .array(
        z
          .object({
            bundleId: operatorIdentifierSchema,
            version: operatorIdentifierSchema
          })
          .strict()
      )
      .max(128),
    assembledAt: isoDateTimeSchema,
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();

export const historicalRuntimeActivateInputSchema = z
  .object({
    runtimeBundleId: operatorIdentifierSchema,
    runtimeBundleHash: Sha256HashSchema,
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();

export const historicalRuntimeAuditListInputSchema = sourceDeliveryAuditListInputSchema;

export const publishSnapshotV2InputSchema = z
  .object({
    linkId: operatorIdentifierSchema,
    certificationManifestId: operatorIdentifierSchema,
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();

export const disablePublicationV2InputSchema = z
  .object({
    linkId: operatorIdentifierSchema,
    expectedLinkHash: Sha256HashSchema,
    reasonCode: operatorIdentifierSchema,
    reason: boundedTextSchema.max(1_024),
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();

export const publicationV2GetInputSchema = z
  .object({ linkId: operatorIdentifierSchema })
  .strict();

export const publicationV2AuditListInputSchema = sourceDeliveryAuditListInputSchema;

export const putInputArtifactInputSchema = z
  .object({
    tenantId: operatorIdentifierSchema,
    inputId: operatorIdentifierSchema,
    kind: z.enum(["borrowing_base_input", "monitoring_input"]),
    filePath: z.string().min(1).max(4_096),
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();

const inputDeclaredControlsSchema = z
  .object({
    rowCount: z.number().int().nonnegative(),
    balance: decimalSchema.optional(),
    currency: z.string().regex(/^[A-Z]{3}$/).optional()
  })
  .strict()
  .refine((value) => value.balance === undefined || value.currency !== undefined);

export const inputCertificationProposeSchema = z
  .object({
    tenantId: operatorIdentifierSchema,
    inputId: operatorIdentifierSchema,
    inputKind: z.enum(["borrowing_base", "monitoring"]),
    candidateArtifactId: z.string().regex(/^[a-f0-9]{64}$/),
    primaryCertificationManifestId: operatorIdentifierSchema,
    definitionIds: z.array(documentIdentifierSchema).min(1).max(128),
    purpose: boundedTextSchema.max(512),
    declaredControls: inputDeclaredControlsSchema,
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();

export const inputCertificationCertifySchema = z
  .object({
    tenantId: operatorIdentifierSchema,
    inputId: operatorIdentifierSchema,
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();

export const membershipProposeInputSchema = z
  .object({
    membershipId: operatorIdentifierSchema,
    issuer: z.string().url().max(2_048),
    subject: boundedTextSchema.max(512),
    clientId: boundedTextSchema.max(512),
    tenantId: operatorIdentifierSchema,
    principalId: operatorIdentifierSchema,
    notBefore: isoDateTimeSchema.optional(),
    expiresAt: isoDateTimeSchema.optional(),
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();
export const membershipChangeInputSchema = z
  .object({
    membershipId: operatorIdentifierSchema,
    idempotencyKey: operatorIdentifierSchema
  })
  .strict();

export const alertListInputSchema = z
  .object({
    tenantId: operatorIdentifierSchema,
    status: z.enum(["open", "acknowledged", "escalated", "resolved", "suppressed"]).optional(),
    limit: z.number().int().min(1).max(500).optional()
  })
  .strict();
const alertTransitionBase = {
  tenantId: operatorIdentifierSchema,
  alertId: operatorIdentifierSchema,
  idempotencyKey: operatorIdentifierSchema
} as const;
export const alertTransitionInputSchema = z.discriminatedUnion("action", [
  z.object({ ...alertTransitionBase, action: z.literal("acknowledge"), note: boundedTextSchema.optional() }).strict(),
  z.object({ ...alertTransitionBase, action: z.literal("escalate"), reason: boundedTextSchema }).strict(),
  z.object({ ...alertTransitionBase, action: z.literal("resolve"), resolution: boundedTextSchema }).strict(),
  z.object({ ...alertTransitionBase, action: z.literal("suppress"), reason: boundedTextSchema }).strict(),
  z.object({ ...alertTransitionBase, action: z.literal("reopen"), reason: boundedTextSchema }).strict()
]);

export const auditListInputSchema = z
  .object({
    tenantId: documentIdentifierSchema,
    stream: z.enum(["control", "definitions", "monitoring"]),
    afterSequence: z.number().int().nonnegative().optional(),
    limit: z.number().int().min(1).max(1_000).optional()
  })
  .strict();

const dateOrderRuleSchema = z
  .object({
    earlierField: documentIdentifierSchema,
    laterField: documentIdentifierSchema,
    allowEqual: z.boolean().optional()
  })
  .strict();
const statusConsistencySchema = z
  .object({
    statusField: documentIdentifierSchema,
    daysPastDueField: documentIdentifierSchema,
    currentStatuses: z.array(boundedTextSchema).min(1).max(10_000),
    delinquentStatuses: z.array(boundedTextSchema).min(1).max(10_000),
    delinquentThresholdDays: z.number().int().nonnegative()
  })
  .strict();
const dataQualityProfileSchema = z
  .object({
    id: documentIdentifierSchema,
    version: documentIdentifierSchema,
    entity: z.enum(["loan_snapshot", "loan_history", "receivable_snapshot", "collateral_snapshot"]),
    asOfMode: z.enum(["exact", "through"]).optional(),
    keyFields: z.array(documentIdentifierSchema).min(1).max(100),
    requiredFields: z.array(documentIdentifierSchema).min(1).max(2_000),
    balanceField: documentIdentifierSchema,
    asOfField: documentIdentifierSchema,
    expectedAsOfDate: isoDateSchema,
    currencyField: documentIdentifierSchema.optional(),
    expectedCurrency: z.string().regex(/^[A-Z]{3}$/).optional(),
    exactDecimalFields: z.array(documentIdentifierSchema).max(2_000).optional(),
    nonNegativeFields: z.array(documentIdentifierSchema).max(2_000).optional(),
    dateFields: z.array(documentIdentifierSchema).max(2_000).optional(),
    dateOrderRules: z.array(dateOrderRuleSchema).max(100).optional(),
    allowedValues: z.record(documentIdentifierSchema, z.array(boundedTextSchema).max(100_000)).optional(),
    maximumNullRates: z.record(documentIdentifierSchema, z.number().min(0).max(1)).optional(),
    statusConsistency: statusConsistencySchema.optional(),
    maximumSnapshotAgeDays: z.number().int().nonnegative().max(100_000).optional()
  })
  .strict();

const bucketSchema = z
  .object({
    label: boundedTextSchema.max(128),
    lower: decimalSchema.optional(),
    upper: decimalSchema.optional(),
    includeLower: z.boolean().optional(),
    includeUpper: z.boolean().optional()
  })
  .strict();
const stratificationRecipeSchema = z
  .object({
    dimension: documentIdentifierSchema,
    balanceField: documentIdentifierSchema.optional(),
    buckets: z.array(bucketSchema).min(1).max(100).optional(),
    weightedAverageFields: z.array(documentIdentifierSchema).max(5).optional(),
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
    z.object({ kind: z.literal("debtor_id_in"), debtorIds: z.array(documentIdentifierSchema).min(1).max(100_000) }).strict(),
    z.object({ kind: z.literal("all"), conditions: z.array(eligibilityConditionSchema).min(1).max(100) }).strict(),
    z.object({ kind: z.literal("any"), conditions: z.array(eligibilityConditionSchema).min(1).max(100) }).strict(),
    z.object({ kind: z.literal("not"), condition: eligibilityConditionSchema }).strict()
  ])
);
const eligibilityRuleSchema = z
  .object({
    ruleId: documentIdentifierSchema,
    version: documentIdentifierSchema,
    effectiveFrom: isoDateSchema,
    effectiveTo: isoDateSchema.optional(),
    priority: z.number().int().nonnegative(),
    reasonCode: documentIdentifierSchema,
    description: boundedTextSchema,
    condition: eligibilityConditionSchema
  })
  .strict();
const borrowingBasePolicySchema = z
  .object({
    policyId: documentIdentifierSchema,
    version: documentIdentifierSchema,
    effectiveFrom: isoDateSchema,
    effectiveTo: isoDateSchema.optional(),
    currencyCode: z.string().regex(/^[A-Z]{3}$/),
    eligibilityRules: z.array(eligibilityRuleSchema).max(10_000),
    crossAging: z
      .object({
        ruleId: documentIdentifierSchema,
        reasonCode: documentIdentifierSchema,
        daysPastDueAtLeast: z.number().int().nonnegative(),
        triggerRatio: decimalSchema
      })
      .strict()
      .optional(),
    concentration: z
      .object({
        ruleId: documentIdentifierSchema,
        reasonCode: documentIdentifierSchema,
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
            reserveId: documentIdentifierSchema,
            reasonCode: documentIdentifierSchema,
            description: boundedTextSchema,
            amount: decimalSchema
          })
          .strict()
      )
      .max(10_000),
    commitmentAmount: decimalSchema
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
const evidenceSchema = z
  .object({ kind: evidenceKindSchema, id: documentIdentifierSchema })
  .strict();
const decimalUnitSchema = z.enum(["basis_points", "count", "currency", "days", "percent", "ratio"]);
const monitorBaseShape = {
  monitorId: documentIdentifierSchema,
  version: documentIdentifierSchema,
  effectiveFrom: isoDateSchema,
  effectiveTo: isoDateSchema.optional(),
  metricId: documentIdentifierSchema,
  title: boundedTextSchema.max(512),
  message: boundedTextSchema,
  severity: z.enum(["info", "warning", "high", "critical"])
} as const;
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

const receivableSchema = z
  .object({
    receivableId: documentIdentifierSchema,
    debtorId: documentIdentifierSchema,
    outstandingAmount: decimalSchema,
    daysPastDue: z.number().int().nonnegative(),
    flags: z.array(receivableFlagSchema).max(20)
  })
  .strict();
const usageSchema = z
  .object({
    usageId: documentIdentifierSchema,
    kind: z.enum(["revolver", "letters_of_credit", "swingline", "other"]),
    amount: decimalSchema
  })
  .strict();
const borrowingBaseInputSchema = z
  .object({
    snapshotId: documentIdentifierSchema,
    asOfDate: isoDateSchema,
    receivables: z.array(receivableSchema).max(1_000_000),
    usage: z.array(usageSchema).max(100_000)
  })
  .strict();
const observationBaseShape = {
  observationId: documentIdentifierSchema,
  metricId: documentIdentifierSchema,
  snapshotId: documentIdentifierSchema,
  asOfDate: isoDateSchema,
  evidence: z.array(evidenceSchema).max(10_000)
} as const;
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
    snapshotId: documentIdentifierSchema,
    asOfDate: isoDateSchema,
    scope: z
      .object({ type: z.enum(["facility", "portfolio", "source"]), id: documentIdentifierSchema })
      .strict(),
    observations: z.array(metricObservationSchema).max(1_000_000)
  })
  .strict();

export type FileIngestInput = z.infer<typeof fileIngestInputSchema>;
export type SqlExtractInput = z.infer<typeof sqlExtractInputSchema>;
export type ExtractSqlV2Input = z.infer<typeof extractSqlV2InputSchema>;
export type MappingProposeInput = z.infer<typeof mappingProposeInputSchema>;
export type MappingTransitionInput = z.infer<typeof mappingTransitionInputSchema>;
export type DefinitionProposeInput = z.infer<typeof definitionProposeInputSchema>;
export type DefinitionTransitionInput = z.infer<typeof definitionTransitionInputSchema>;
export type GovernedDefinitionV2ProposeInput = z.infer<typeof governedDefinitionV2ProposeInputSchema>;
export type GovernedDefinitionV2TransitionInput = z.infer<typeof governedDefinitionV2TransitionInputSchema>;
export type GovernedDefinitionV2GetInput = z.infer<typeof governedDefinitionV2GetInputSchema>;
export type GovernedDefinitionV2ListInput = z.infer<typeof governedDefinitionV2ListInputSchema>;
export type GovernedDefinitionV2SelectEffectiveInput = z.infer<
  typeof governedDefinitionV2SelectEffectiveInputSchema
>;
export type GovernedDefinitionV2AuditListInput = z.infer<
  typeof governedDefinitionV2AuditListInputSchema
>;
export type CertifySnapshotInput = z.infer<typeof certifySnapshotInputSchema>;
export type CertifySnapshotV2Input = z.infer<typeof certifySnapshotV2InputSchema>;
export type SourceDeliveryRegisterInput = z.infer<typeof sourceDeliveryRegisterInputSchema>;
export type SourceDeliveryDisableInput = z.infer<typeof sourceDeliveryDisableInputSchema>;
export type SourceDeliveryGetInput = z.infer<typeof sourceDeliveryGetInputSchema>;
export type SourceDeliveryAuditListInput = z.infer<typeof sourceDeliveryAuditListInputSchema>;
export type HistoricalBundleRegisterInput = z.infer<typeof historicalBundleRegisterInputSchema>;
export type HistoricalRuntimeRegisterInput = z.infer<typeof historicalRuntimeRegisterInputSchema>;
export type HistoricalRuntimeActivateInput = z.infer<typeof historicalRuntimeActivateInputSchema>;
export type HistoricalRuntimeAuditListInput = z.infer<typeof historicalRuntimeAuditListInputSchema>;
export type PublishSnapshotV2Input = z.infer<typeof publishSnapshotV2InputSchema>;
export type DisablePublicationV2Input = z.infer<typeof disablePublicationV2InputSchema>;
export type PublicationV2GetInput = z.infer<typeof publicationV2GetInputSchema>;
export type PublicationV2AuditListInput = z.infer<typeof publicationV2AuditListInputSchema>;
export type PutInputArtifactInput = z.infer<typeof putInputArtifactInputSchema>;
export type InputCertificationProposeRequest = z.infer<typeof inputCertificationProposeSchema>;
export type InputCertificationCertifyRequest = z.infer<typeof inputCertificationCertifySchema>;
export type MembershipProposeInput = z.infer<typeof membershipProposeInputSchema>;
export type MembershipChangeInput = z.infer<typeof membershipChangeInputSchema>;
export type AlertListInput = z.infer<typeof alertListInputSchema>;
export type AlertTransitionInput = z.infer<typeof alertTransitionInputSchema>;
export type AuditListInput = z.infer<typeof auditListInputSchema>;

export type DefinitionDocumentKind = DefinitionProposeInput["kind"];
export type InputArtifactKind = PutInputArtifactInput["kind"];

export function parseStrict<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new OperatorInputError(`${label} is invalid`);
  return parsed.data;
}

export function validateDefinitionDocument(kind: DefinitionDocumentKind, value: unknown): JsonValue {
  const schema = {
    data_quality_profile: dataQualityProfileSchema,
    stratification_recipe: stratificationRecipeSchema,
    vintage_recipe: vintageRecipeSchema,
    borrowing_base_policy: borrowingBasePolicySchema,
    monitor_definition: monitorDefinitionSchema
  }[kind];
  return boundedJson(
    parseStrict(schema as z.ZodType<unknown>, value, `${kind} document`),
    `${kind} document`,
    1_000_000
  );
}

export function validateInputArtifact(kind: InputArtifactKind, value: unknown): JsonValue {
  const schema = kind === "borrowing_base_input" ? borrowingBaseInputSchema : monitoringInputSchema;
  return boundedJson(parseStrict(schema as z.ZodType<unknown>, value, kind), kind, 8_000_000);
}

export function boundedJson(value: unknown, label: string, maximumBytes: number): JsonValue {
  let nodes = 0;
  const visit = (nested: unknown, depth: number): JsonValue => {
    nodes += 1;
    if (nodes > 1_000_000 || depth > 32) throw new OperatorInputError(`${label} exceeds structural limits`);
    if (nested === null || typeof nested === "boolean" || typeof nested === "string") return nested;
    if (typeof nested === "number") {
      if (!Number.isFinite(nested)) throw new OperatorInputError(`${label} contains a non-JSON number`);
      return nested;
    }
    if (Array.isArray(nested)) return nested.map((entry) => visit(entry, depth + 1));
    if (nested && typeof nested === "object" && !ArrayBuffer.isView(nested)) {
      const output = Object.create(null) as Record<string, JsonValue>;
      for (const key of Object.keys(nested as Record<string, unknown>).sort()) {
        output[key] = visit((nested as Record<string, unknown>)[key], depth + 1);
      }
      return output;
    }
    throw new OperatorInputError(`${label} contains a non-JSON value`);
  };
  const normalized = visit(value, 0);
  if (Buffer.byteLength(JSON.stringify(normalized), "utf8") > maximumBytes) {
    throw new OperatorInputError(`${label} exceeds its byte limit`);
  }
  return normalized;
}

export class OperatorInputError extends Error {
  readonly code = "INVALID_INPUT" as const;

  constructor(message: string) {
    super(message);
    this.name = "OperatorInputError";
  }
}

function isRealIsoDate(value: string): boolean {
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}
