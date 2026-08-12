import { z } from "zod";

import {
  ContractValidationError,
  IdentifierSchema,
  IsoDateSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  assertTimestampOrder,
  canonicalHash,
  parseWithSchema,
  type Sha256Hash
} from "./canonical.js";
import {
  GovernedSemanticVersionReferenceV1Schema,
  MetricProjectionReferenceV1Schema,
  type MetricProjectionReferenceV1
} from "./metric-projection-v1.js";

const CanonicalExactDecimalSchema = z
  .string()
  .max(256)
  .regex(
    /^-?(?:0|[1-9]\d*)(?:\.\d*[1-9])?$/,
    "must be a canonical exact decimal string"
  )
  .refine((value) => value !== "-0", "must encode zero as 0");

export const MetricRunDecimalUnitV1Schema = z.enum([
  "basis_points",
  "count",
  "currency",
  "days",
  "percent",
  "ratio"
]);

const MetricRunDecimalValueV1Schema = z
  .object({
    type: z.literal("decimal"),
    value: CanonicalExactDecimalSchema,
    unit: MetricRunDecimalUnitV1Schema
  })
  .strict();

const MetricRunBooleanValueV1Schema = z
  .object({
    type: z.literal("boolean"),
    value: z.boolean(),
    unit: z.literal("boolean")
  })
  .strict();

export const MetricRunValueV1Schema = z.discriminatedUnion("type", [
  MetricRunDecimalValueV1Schema,
  MetricRunBooleanValueV1Schema
]);

export const MetricRunScopeV1Schema = z
  .object({
    type: z.enum(["facility", "portfolio", "source"]),
    id: IdentifierSchema
  })
  .strict();

export const MetricDefinitionReferenceV1Schema = z
  .object({
    definitionKind: z.literal("metric_definition"),
    definitionVersionId: IdentifierSchema,
    definitionId: IdentifierSchema,
    version: GovernedSemanticVersionReferenceV1Schema,
    definitionHash: Sha256HashSchema,
    documentHash: Sha256HashSchema,
    versionHash: Sha256HashSchema,
    approvalEventHash: Sha256HashSchema,
    approvedAt: IsoTimestampSchema
  })
  .strict();

export const MetricRunMethodologyReferenceV1Schema = z
  .object({
    definitionKind: z.literal("methodology_bundle"),
    definitionVersionId: IdentifierSchema,
    definitionId: IdentifierSchema,
    version: GovernedSemanticVersionReferenceV1Schema,
    definitionHash: Sha256HashSchema,
    documentHash: Sha256HashSchema,
    versionHash: Sha256HashSchema,
    approvalEventHash: Sha256HashSchema,
    approvedAt: IsoTimestampSchema
  })
  .strict();

const MetricRunResultCellEvidenceV1Schema = z
  .object({
    certificationStatus: z.literal("certified"),
    resultRecordedAt: IsoTimestampSchema,
    resultArtifactId: IdentifierSchema,
    resultArtifactHash: Sha256HashSchema,
    resultManifestId: IdentifierSchema,
    resultManifestHash: Sha256HashSchema,
    cellId: IdentifierSchema,
    cellHash: Sha256HashSchema,
    populationHash: Sha256HashSchema,
    populationRowCount: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)
  })
  .strict();

const PointInTimeMetricRunSourceBodyV1Schema = MetricRunResultCellEvidenceV1Schema.extend({
  sourceType: z.literal("point_in_time"),
  snapshotId: IdentifierSchema,
  snapshotAsOfDate: IsoDateSchema,
  snapshotCertificationManifestId: IdentifierSchema,
  snapshotCertificationHash: Sha256HashSchema,
  snapshotCertifiedAt: IsoTimestampSchema,
  inputArtifactId: IdentifierSchema,
  inputArtifactHash: Sha256HashSchema,
  inputArtifactKind: IdentifierSchema
}).strict();

const LongitudinalMetricRunSourceBodyV1Schema = MetricRunResultCellEvidenceV1Schema.extend({
  sourceType: z.literal("longitudinal"),
  longitudinalBundleId: IdentifierSchema,
  longitudinalBundleHash: Sha256HashSchema,
  bundleCreatedAt: IsoTimestampSchema,
  firstAsOfDate: IsoDateSchema,
  lastAsOfDate: IsoDateSchema,
  periodCount: z.number().int().min(2).max(120)
}).strict().superRefine((source, context) => {
  if (source.firstAsOfDate >= source.lastAsOfDate) {
    context.addIssue({
      code: "custom",
      path: ["lastAsOfDate"],
      message: "must follow firstAsOfDate"
    });
  }
});

export const MetricRunSourceV1Schema = z.discriminatedUnion("sourceType", [
  PointInTimeMetricRunSourceBodyV1Schema.extend({ sourceHash: Sha256HashSchema }).strict(),
  LongitudinalMetricRunSourceBodyV1Schema.extend({ sourceHash: Sha256HashSchema }).strict()
]);

const MetricRunQuantityV1Schema = z
  .object({
    value: CanonicalExactDecimalSchema,
    unit: MetricRunDecimalUnitV1Schema
  })
  .strict();

const MetricRunCoverageV1Schema = z
  .object({
    includedCount: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    eligibleCount: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)
  })
  .strict()
  .superRefine((coverage, context) => {
    if (coverage.includedCount > coverage.eligibleCount) {
      context.addIssue({
        code: "custom",
        path: ["includedCount"],
        message: "must not exceed eligibleCount"
      });
    }
  });

const MetricRunObservationInputV1Shape = {
  asOfDate: IsoDateSchema,
  scope: MetricRunScopeV1Schema,
  measurement: MetricRunValueV1Schema,
  numerator: MetricRunQuantityV1Schema.optional(),
  denominator: MetricRunQuantityV1Schema.optional(),
  coverage: MetricRunCoverageV1Schema.optional()
} as const;

export const MetricRunObservationInputV1Schema = z
  .object(MetricRunObservationInputV1Shape)
  .strict()
  .superRefine(assertCompleteRatio);

export const MetricRunObservationV1Schema = z
  .object({ ...MetricRunObservationInputV1Shape, scopeHash: Sha256HashSchema })
  .strict()
  .superRefine(assertCompleteRatio);

const MetricRunDerivationBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    runId: IdentifierSchema,
    tenantId: IdentifierSchema,
    metricId: IdentifierSchema,
    projection: MetricProjectionReferenceV1Schema,
    metricDefinition: MetricDefinitionReferenceV1Schema,
    methodology: MetricRunMethodologyReferenceV1Schema,
    source: MetricRunSourceV1Schema,
    observation: MetricRunObservationV1Schema
  })
  .strict();

export const MetricRunBodyV1Schema = MetricRunDerivationBodyV1Schema.extend({
  derivationHash: Sha256HashSchema
}).strict();

export const MetricRunCreatedV1Schema = MetricRunBodyV1Schema.extend({
  status: z.literal("created"),
  createdBy: IdentifierSchema,
  createdAt: IsoTimestampSchema,
  runHash: Sha256HashSchema
}).strict();

export const MetricRunV1Schema = MetricRunBodyV1Schema.extend({
  status: z.literal("certified"),
  createdBy: IdentifierSchema,
  createdAt: IsoTimestampSchema,
  runHash: Sha256HashSchema,
  approvedBy: IdentifierSchema,
  approvedAt: IsoTimestampSchema,
  certificationHash: Sha256HashSchema
}).strict();

export type MetricRunDecimalUnitV1 = z.infer<typeof MetricRunDecimalUnitV1Schema>;
export type MetricRunValueV1 = z.infer<typeof MetricRunValueV1Schema>;
export type MetricRunScopeV1 = z.infer<typeof MetricRunScopeV1Schema>;
export type MetricProjectionReference = MetricProjectionReferenceV1;
export type MetricDefinitionReferenceV1 = z.infer<typeof MetricDefinitionReferenceV1Schema>;
export type MetricRunMethodologyReferenceV1 = z.infer<typeof MetricRunMethodologyReferenceV1Schema>;
export type MetricRunSourceV1 = z.infer<typeof MetricRunSourceV1Schema>;
export type MetricRunBodyV1 = z.infer<typeof MetricRunBodyV1Schema>;
export type MetricRunCreatedV1 = z.infer<typeof MetricRunCreatedV1Schema>;
export type MetricRunV1 = z.infer<typeof MetricRunV1Schema>;
export type MetricRunViewV1 = MetricRunCreatedV1 | MetricRunV1;

export interface CreateMetricRunV1Input
  extends Omit<z.input<typeof MetricRunDerivationBodyV1Schema>, "observation"> {
  readonly observation: Omit<z.input<typeof MetricRunObservationV1Schema>, "scopeHash">;
  readonly createdBy: string;
  readonly createdAt: string;
}

export interface CertifyMetricRunV1Input {
  readonly approvedBy: string;
  readonly approvedAt: string;
}

export function createMetricRunV1(input: CreateMetricRunV1Input): MetricRunCreatedV1 {
  const scope = parseWithSchema(MetricRunScopeV1Schema, input.observation.scope, "MetricRunV1 scope");
  const derivationBody = parseWithSchema(
    MetricRunDerivationBodyV1Schema,
    {
      contractVersion: input.contractVersion,
      runId: input.runId,
      tenantId: input.tenantId,
      metricId: input.metricId,
      projection: input.projection,
      metricDefinition: input.metricDefinition,
      methodology: input.methodology,
      source: input.source,
      observation: {
        ...input.observation,
        scope,
        scopeHash: canonicalHash(scope)
      }
    },
    "MetricRunV1 derivation body"
  );
  const body = parseWithSchema(
    MetricRunBodyV1Schema,
    { ...derivationBody, derivationHash: canonicalHash(derivationBody) },
    "MetricRunV1 body"
  );
  const createdBody = {
    ...body,
    status: "created" as const,
    createdBy: input.createdBy,
    createdAt: input.createdAt
  };
  return parseMetricRunCreatedV1({ ...createdBody, runHash: canonicalHash(createdBody) });
}

export function certifyMetricRunV1(
  createdValue: unknown,
  input: CertifyMetricRunV1Input
): MetricRunV1 {
  const created = parseMetricRunCreatedV1(createdValue);
  if (created.createdBy === input.approvedBy) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "MetricRunV1 creator and approver must be different principals"
    );
  }
  assertTimestampOrder(created.createdAt, input.approvedAt, "createdAt", "approvedAt");
  const { status: _createdStatus, ...createdWithoutStatus } = created;
  const certifiedBody = {
    ...createdWithoutStatus,
    status: "certified" as const,
    approvedBy: input.approvedBy,
    approvedAt: input.approvedAt
  };
  return parseMetricRunV1({
    ...certifiedBody,
    certificationHash: canonicalHash(certifiedBody)
  });
}

export function parseMetricRunCreatedV1(value: unknown): MetricRunCreatedV1 {
  const parsed = parseWithSchema(MetricRunCreatedV1Schema, value, "MetricRunV1 created record");
  assertMetricRunBody(parsed);
  assertTimestampOrder(parsed.source.resultRecordedAt, parsed.createdAt, "resultRecordedAt", "createdAt");
  const { runHash, ...body } = parsed;
  assertCanonicalHash(body, runHash, "MetricRunV1 run");
  return parsed;
}

export function parseMetricRunV1(value: unknown): MetricRunV1 {
  const parsed = parseWithSchema(MetricRunV1Schema, value, "MetricRunV1 certification");
  assertMetricRunBody(parsed);
  assertTimestampOrder(parsed.source.resultRecordedAt, parsed.createdAt, "resultRecordedAt", "createdAt");
  if (parsed.createdBy === parsed.approvedBy) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "MetricRunV1 creator and approver must be different principals"
    );
  }
  assertTimestampOrder(parsed.createdAt, parsed.approvedAt, "createdAt", "approvedAt");
  const {
    approvedAt,
    approvedBy,
    certificationHash,
    runHash,
    status: _certifiedStatus,
    ...createdBodyWithoutHash
  } = parsed;
  const createdBody = { ...createdBodyWithoutHash, status: "created" as const };
  assertCanonicalHash(createdBody, runHash, "MetricRunV1 run");
  const certificationBody = {
    ...createdBodyWithoutHash,
    runHash,
    status: "certified" as const,
    approvedBy,
    approvedAt
  };
  assertCanonicalHash(certificationBody, certificationHash, "MetricRunV1 certification");
  return parsed;
}

export function parseMetricRunViewV1(value: unknown): MetricRunViewV1 {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return parseMetricRunCreatedV1(value);
  }
  return (value as Readonly<Record<string, unknown>>).status === "certified"
    ? parseMetricRunV1(value)
    : parseMetricRunCreatedV1(value);
}

function assertMetricRunBody(value: MetricRunBodyV1 & Readonly<Record<string, unknown>>): void {
  if (value.metricDefinition.definitionId !== value.projection.metricDefinitionId) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "MetricRunV1 metric definition must match its governed projection"
    );
  }
  if (value.metricId !== value.projection.metricName) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "MetricRunV1 metric id must match its governed projection metric name"
    );
  }
  if (
    value.observation.scope.type !== value.projection.scope.type ||
    (value.projection.scope.idSource === "fixed" &&
      value.observation.scope.id !== value.projection.scope.fixedId)
  ) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "MetricRunV1 observation scope must match its governed projection"
    );
  }
  if (
    value.observation.measurement.type !== value.projection.measurementType ||
    value.observation.measurement.unit !== value.projection.unit
  ) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "MetricRunV1 measurement type and unit must match its governed projection"
    );
  }
  if (
    value.observation.coverage !== undefined &&
    value.observation.coverage.eligibleCount > value.source.populationRowCount
  ) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "MetricRunV1 eligible coverage cannot exceed its certified population"
    );
  }
  const expectedScopeHash = canonicalHash(value.observation.scope);
  if (value.observation.scopeHash !== expectedScopeHash) {
    throw new ContractValidationError(
      "HASH_MISMATCH",
      "MetricRunV1 scope hash did not match its canonical scope"
    );
  }
  if (
    value.source.sourceType === "point_in_time" &&
    value.observation.asOfDate !== value.source.snapshotAsOfDate
  ) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "Point-in-time MetricRunV1 observation date must match its certified snapshot date"
    );
  }
  const sourceCutoff = value.source.sourceType === "point_in_time"
    ? value.source.snapshotCertifiedAt.slice(0, 10)
    : value.source.bundleCreatedAt.slice(0, 10);
  const sourceAsOfDate = value.source.sourceType === "point_in_time"
    ? value.source.snapshotAsOfDate
    : value.source.lastAsOfDate;
  if (sourceAsOfDate > sourceCutoff) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "MetricRunV1 source cannot be certified before its population as-of date"
    );
  }
  if (
    value.source.sourceType === "longitudinal" &&
    (value.observation.asOfDate < value.source.firstAsOfDate ||
      value.observation.asOfDate > value.source.lastAsOfDate)
  ) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "Longitudinal MetricRunV1 observation date must fall within its certified bundle"
    );
  }
  const { sourceHash, ...sourceBody } = value.source;
  assertCanonicalHash(sourceBody, sourceHash, "MetricRunV1 source");
  const expectedCellHash = metricRunCellHashV1({
    metricId: value.metricId,
    projection: value.projection,
    metricDefinition: value.metricDefinition,
    methodology: value.methodology,
    resultArtifactId: value.source.resultArtifactId,
    resultArtifactHash: value.source.resultArtifactHash,
    resultManifestId: value.source.resultManifestId,
    resultManifestHash: value.source.resultManifestHash,
    cellId: value.source.cellId,
    populationHash: value.source.populationHash,
    observation: value.observation
  });
  if (value.source.cellHash !== expectedCellHash) {
    throw new ContractValidationError(
      "HASH_MISMATCH",
      "MetricRunV1 result-cell hash did not match its projected observation"
    );
  }
  const sourceCertifiedAt = value.source.sourceType === "point_in_time"
    ? value.source.snapshotCertifiedAt
    : value.source.bundleCreatedAt;
  assertTimestampOrder(
    sourceCertifiedAt,
    value.source.resultRecordedAt,
    "source certification time",
    "resultRecordedAt"
  );
  for (const [label, approvedAt] of [
    ["metric projection approval", value.projection.approvedAt],
    ["metric definition approval", value.metricDefinition.approvedAt],
    ["methodology approval", value.methodology.approvedAt]
  ] as const) {
    assertTimestampOrder(approvedAt, value.source.resultRecordedAt, label, "resultRecordedAt");
  }
  const {
    approvedAt: _approvedAt,
    approvedBy: _approvedBy,
    certificationHash: _certificationHash,
    createdAt: _createdAt,
    createdBy: _createdBy,
    derivationHash,
    runHash: _runHash,
    status: _status,
    ...derivationBody
  } = value;
  assertCanonicalHash(derivationBody, derivationHash, "MetricRunV1 derivation");
}

export function metricRunObservationKey(value: {
  readonly metricId: string;
  readonly asOfDate: string;
  readonly scope: MetricRunScopeV1;
}): Readonly<{
  metricId: string;
  asOfDate: string;
  scopeHash: Sha256Hash;
}> {
  const metricId = parseWithSchema(IdentifierSchema, value.metricId, "MetricRunV1 metric id");
  const asOfDate = parseWithSchema(IsoDateSchema, value.asOfDate, "MetricRunV1 observation date");
  const scope = parseWithSchema(MetricRunScopeV1Schema, value.scope, "MetricRunV1 scope");
  return Object.freeze({ metricId, asOfDate, scopeHash: canonicalHash(scope) });
}

export function metricRunCellHashV1(input: {
  readonly metricId: string;
  readonly projection: MetricProjectionReferenceV1;
  readonly metricDefinition: MetricDefinitionReferenceV1;
  readonly methodology: MetricRunMethodologyReferenceV1;
  readonly resultArtifactId: string;
  readonly resultArtifactHash: Sha256Hash;
  readonly resultManifestId: string;
  readonly resultManifestHash: Sha256Hash;
  readonly cellId: string;
  readonly populationHash: Sha256Hash;
  readonly observation:
    | z.input<typeof MetricRunObservationV1Schema>
    | Omit<z.input<typeof MetricRunObservationV1Schema>, "scopeHash">;
}): Sha256Hash {
  const scope = parseWithSchema(MetricRunScopeV1Schema, input.observation.scope, "MetricRunV1 scope");
  const observation = parseWithSchema(
    MetricRunObservationV1Schema,
    { ...input.observation, scope, scopeHash: canonicalHash(scope) },
    "MetricRunV1 cell observation"
  );
  return canonicalHash({
    contractVersion: 1,
    metricId: input.metricId,
    projection: input.projection,
    metricDefinition: input.metricDefinition,
    methodology: input.methodology,
    resultArtifactId: input.resultArtifactId,
    resultArtifactHash: input.resultArtifactHash,
    resultManifestId: input.resultManifestId,
    resultManifestHash: input.resultManifestHash,
    cellId: input.cellId,
    populationHash: input.populationHash,
    observation
  });
}

function assertCompleteRatio(
  observation: {
    readonly measurement: { readonly type: "decimal" | "boolean"; readonly unit: string };
    readonly numerator?: { readonly value: string; readonly unit: string } | undefined;
    readonly denominator?: { readonly value: string; readonly unit: string } | undefined;
  },
  context: z.RefinementCtx
): void {
  if ((observation.numerator === undefined) !== (observation.denominator === undefined)) {
    context.addIssue({
      code: "custom",
      path: [observation.numerator === undefined ? "numerator" : "denominator"],
      message: "numerator and denominator must either both be present or both be absent"
    });
  }
  if (
    observation.measurement.type === "decimal" &&
    observation.measurement.unit === "ratio" &&
    (observation.numerator === undefined || observation.denominator === undefined)
  ) {
    context.addIssue({
      code: "custom",
      path: ["numerator"],
      message: "ratio measurements require numerator and denominator evidence"
    });
  }
  if (
    observation.measurement.type === "decimal" &&
    observation.measurement.unit === "ratio" &&
    observation.numerator !== undefined &&
    observation.denominator !== undefined &&
    observation.numerator.unit !== observation.denominator.unit
  ) {
    context.addIssue({
      code: "custom",
      path: ["denominator", "unit"],
      message: "ratio numerator and denominator must use the same unit"
    });
  }
  if (
    observation.measurement.type === "decimal" &&
    observation.measurement.unit === "ratio" &&
    observation.denominator?.value === "0"
  ) {
    context.addIssue({
      code: "custom",
      path: ["denominator", "value"],
      message: "ratio denominator must be nonzero"
    });
  }
}
