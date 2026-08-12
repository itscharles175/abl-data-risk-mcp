import { z } from "zod";

import {
  ContractValidationError,
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  parseWithSchema
} from "./canonical.js";

const ExactDimensionSelectorsV1Schema = z
  .record(IdentifierSchema, z.string().min(1).max(512))
  .superRefine((selectors, context) => {
    const entries = Object.entries(selectors);
    if (entries.length > 32) {
      context.addIssue({ code: "custom", message: "at most 32 exact dimension selectors are allowed" });
    }
  });

export const GovernedSemanticVersionReferenceV1Schema = z
  .string()
  .max(64)
  .regex(
    /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:0|[1-9A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/,
    "must be a semantic version"
  )
  .refine(
    (value) => {
      const prerelease = value.split("+", 1)[0]!.split("-", 2)[1];
      return prerelease === undefined || prerelease.split(".").every((part) => !/^0\d+$/.test(part));
    },
    "numeric prerelease identifiers must not contain leading zeroes"
  );

const FixedProjectionScopeV1Schema = z
  .object({
    type: z.enum(["facility", "portfolio", "source"]),
    idSource: z.literal("fixed"),
    fixedId: IdentifierSchema
  })
  .strict();

const DimensionProjectionScopeV1Schema = z
  .object({
    type: z.enum(["facility", "portfolio", "source"]),
    idSource: z.literal("dimension"),
    dimension: IdentifierSchema
  })
  .strict();

export const MetricProjectionReferenceV1Schema = z
  .object({
    definitionKind: z.literal("metric_projection"),
    definitionVersionId: IdentifierSchema,
    definitionId: IdentifierSchema,
    version: GovernedSemanticVersionReferenceV1Schema,
    definitionHash: Sha256HashSchema,
    documentHash: Sha256HashSchema,
    versionHash: Sha256HashSchema,
    approvalEventHash: Sha256HashSchema,
    approvedAt: IsoTimestampSchema,
    metricDefinitionId: IdentifierSchema,
    metricName: IdentifierSchema,
    scope: z.discriminatedUnion("idSource", [
      FixedProjectionScopeV1Schema,
      DimensionProjectionScopeV1Schema
    ]),
    measurementSource: z.literal("value"),
    measurementType: z.literal("decimal"),
    unit: z.enum(["count", "currency", "days", "ratio"])
  })
  .strict();

const MetricProjectionBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    definitionType: z.literal("metric_projection"),
    definitionId: IdentifierSchema,
    version: GovernedSemanticVersionReferenceV1Schema,
    metricDefinitionId: IdentifierSchema,
    metricName: IdentifierSchema,
    exactDimensionSelectors: ExactDimensionSelectorsV1Schema,
    observationDateDimension: IdentifierSchema,
    scope: z.discriminatedUnion("idSource", [
      FixedProjectionScopeV1Schema,
      DimensionProjectionScopeV1Schema
    ]),
    measurement: z
      .object({
        source: z.literal("value"),
        type: z.literal("decimal"),
        unit: z.enum(["count", "currency", "days", "ratio"])
      })
      .strict(),
    requireAvailable: z.literal(true),
    requireUnsuppressed: z.literal(true),
    approval: z
      .object({
        status: z.literal("pending_durable_approval"),
        authority: z.literal("governed_definition_v2_lifecycle")
      })
      .strict()
  })
  .strict()
  .superRefine((projection, context) => {
    if (projection.scope.idSource === "dimension") {
      if (projection.scope.dimension === projection.observationDateDimension) {
        context.addIssue({
          code: "custom",
          path: ["scope", "dimension"],
          message: "scope and observation date must use distinct dimensions"
        });
      }
    }
  });

export const MetricProjectionV1Schema = MetricProjectionBodyV1Schema.extend({
  projectionHash: Sha256HashSchema
}).strict();

export type MetricProjectionReferenceV1 = z.infer<typeof MetricProjectionReferenceV1Schema>;
export type MetricProjectionV1 = z.infer<typeof MetricProjectionV1Schema>;
export type MetricProjectionV1Input = z.input<typeof MetricProjectionBodyV1Schema>;

export function createMetricProjectionV1(input: MetricProjectionV1Input): MetricProjectionV1 {
  const body = parseWithSchema(MetricProjectionBodyV1Schema, input, "MetricProjectionV1");
  return parseMetricProjectionV1({ ...body, projectionHash: canonicalHash(body) });
}

export function parseMetricProjectionV1(value: unknown): MetricProjectionV1 {
  const parsed = parseWithSchema(MetricProjectionV1Schema, value, "MetricProjectionV1");
  const { projectionHash, ...body } = parsed;
  assertCanonicalHash(body, projectionHash, "MetricProjectionV1");
  return parsed;
}

export function metricProjectionReferenceV1(
  projectionValue: unknown,
  governance: Readonly<{
    definitionVersionId: string;
    documentHash: string;
    versionHash: string;
    approvalEventHash: string;
    approvedAt: string;
  }>
): MetricProjectionReferenceV1 {
  const projection = parseMetricProjectionV1(projectionValue);
  const expectedDocumentHash = canonicalHash(projection);
  if (governance.documentHash !== expectedDocumentHash) {
    throw new ContractValidationError(
      "HASH_MISMATCH",
      "MetricProjectionReferenceV1 governance document hash did not match the projection"
    );
  }
  return parseWithSchema(
    MetricProjectionReferenceV1Schema,
    {
      definitionKind: "metric_projection",
      definitionVersionId: governance.definitionVersionId,
      definitionId: projection.definitionId,
      version: projection.version,
      definitionHash: projection.projectionHash,
      documentHash: governance.documentHash,
      versionHash: governance.versionHash,
      approvalEventHash: governance.approvalEventHash,
      approvedAt: governance.approvedAt,
      metricDefinitionId: projection.metricDefinitionId,
      metricName: projection.metricName,
      scope: projection.scope,
      measurementSource: projection.measurement.source,
      measurementType: projection.measurement.type,
      unit: projection.measurement.unit
    },
    "MetricProjectionReferenceV1"
  );
}
