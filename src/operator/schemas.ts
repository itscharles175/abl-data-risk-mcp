import * as z from "zod/v4";

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
export type MappingProposeInput = z.infer<typeof mappingProposeInputSchema>;
export type MappingTransitionInput = z.infer<typeof mappingTransitionInputSchema>;
export type DefinitionProposeInput = z.infer<typeof definitionProposeInputSchema>;
export type DefinitionTransitionInput = z.infer<typeof definitionTransitionInputSchema>;
export type CertifySnapshotInput = z.infer<typeof certifySnapshotInputSchema>;
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
