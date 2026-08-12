import * as z from "zod/v4";

import type {
  BinDefinitionV1,
  CohortDefinitionV1,
  EntityResolutionDefinitionV1,
  MetricDefinitionV1
} from "../domain/surveillance/contracts.js";
import type { BorrowingBasePolicyV2 } from "../domain/abl-v2/contracts.js";
import { validateBorrowingBasePolicyV2 } from "../domain/abl-v2/engine.js";
import {
  validateBinDefinitionV1,
  validateCohortDefinitionV1,
  validateEntityResolutionDefinitionV1,
  validateMetricDefinitionV1
} from "../domain/surveillance/definitions.js";
import {
  ContractValidationError,
  IdentifierSchema,
  IsoDateSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  canonicalJson,
  parseWithSchema,
  type CanonicalJsonValue
} from "./canonical.js";
import { parseMappingSpecV2 } from "./mapping-v2.js";
import { parseMetricProjectionV1 } from "./metric-projection-v1.js";
import { parseSourceAccessPolicyV1 } from "./source-access-policy-v1.js";
import { parseSourceContractV1 } from "./source-contract-v1.js";

export const GovernedDefinitionKindV2Schema = z.enum([
  "source_contract",
  "source_access_policy",
  "mapping_spec",
  "methodology_bundle",
  "borrowing_base_policy_v2",
  "metric_definition",
  "metric_projection",
  "cohort_definition",
  "bin_definition",
  "reconciliation_definition",
  "entity_resolution_definition",
  "report_definition",
  "scenario_definition",
  "covenant_definition"
]);

export type GovernedDefinitionKindV2 = z.infer<typeof GovernedDefinitionKindV2Schema>;

export const GovernedDefinitionStatusV2Schema = z.enum([
  "proposed",
  "validated",
  "approved",
  "active",
  "superseded",
  "retired",
  "withdrawn"
]);

export type GovernedDefinitionStatusV2 = z.infer<typeof GovernedDefinitionStatusV2Schema>;

export const GovernedDefinitionTransitionV2Schema = z.enum([
  "validated",
  "approved",
  "active",
  "retired",
  "withdrawn"
]);

export type GovernedDefinitionTransitionV2 = z.infer<typeof GovernedDefinitionTransitionV2Schema>;

export const SemanticVersionV2Schema = z
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

const DecimalStringSchema = z
  .string()
  .max(256)
  .regex(
    /^-?(?:0|[1-9]\d*)(?:\.\d*[1-9])?$/,
    "must be a canonical decimal string"
  )
  .refine((value) => value !== "-0", "must encode zero as 0");

const NonnegativeDecimalStringSchema = DecimalStringSchema.refine(
  (value) => !value.startsWith("-"),
  "must be nonnegative"
);

const NeutralDefinitionApprovalSchema = z
  .object({
    status: z.literal("pending_durable_approval"),
    authority: z.literal("governed_definition_v2_lifecycle")
  })
  .strict();

export const MethodologyBundleV1Schema = z
  .object({
    contractVersion: z.literal(1),
    bundleKind: z.literal("methodology"),
    bundleId: IdentifierSchema,
    version: SemanticVersionV2Schema,
    name: z.string().min(1).max(512),
    description: z.string().min(1).max(8_192),
    calculationEngine: z
      .object({
        engineId: IdentifierSchema,
        engineVersion: SemanticVersionV2Schema,
        runtimeBundleHash: Sha256HashSchema
      })
      .strict(),
    requiredDefinitionKinds: z.array(GovernedDefinitionKindV2Schema).max(64),
    deterministicParameters: z.record(IdentifierSchema, z.union([z.string(), z.boolean(), z.number().int().safe()])),
    approval: NeutralDefinitionApprovalSchema
  })
  .strict()
  .superRefine((value, context) => {
    unique(
      value.requiredDefinitionKinds,
      context,
      ["requiredDefinitionKinds"],
      "required definition kinds must be unique"
    );
  });

export type MethodologyBundleV1 = Readonly<z.infer<typeof MethodologyBundleV1Schema>>;

export const ReconciliationDefinitionV1Schema = z
  .object({
    schemaVersion: z.literal("1"),
    definitionType: z.literal("reconciliation_definition"),
    definitionId: IdentifierSchema,
    version: z.number().int().min(1).max(1_000_000),
    name: z.string().min(1).max(512),
    segments: z
      .array(z.enum(["facility", "legal_entity", "currency", "status", "collateral_class"]))
      .min(1)
      .max(5),
    controls: z
      .array(
        z
          .object({
            controlId: IdentifierSchema,
            measure: z.enum(["row_count", "balance", "eligible_balance", "usage"]),
            tolerance: NonnegativeDecimalStringSchema,
            materialityThreshold: NonnegativeDecimalStringSchema
          })
          .strict()
      )
      .min(1)
      .max(128),
    approval: NeutralDefinitionApprovalSchema
  })
  .strict()
  .superRefine((value, context) => {
    unique(value.segments, context, ["segments"], "segments must be unique");
    unique(
      value.controls.map((control) => control.controlId),
      context,
      ["controls"],
      "control ids must be unique"
    );
  });

export type ReconciliationDefinitionV1 = Readonly<z.infer<typeof ReconciliationDefinitionV1Schema>>;

export const ReportDefinitionV1Schema = z
  .object({
    schemaVersion: z.literal("1"),
    definitionType: z.literal("report_definition"),
    definitionId: IdentifierSchema,
    version: z.number().int().min(1).max(1_000_000),
    name: z.string().min(1).max(512),
    methodologyBundleId: IdentifierSchema,
    sections: z
      .array(
        z
          .object({
            sectionId: IdentifierSchema,
            title: z.string().min(1).max(512),
            metricDefinitionIds: z.array(IdentifierSchema).min(1).max(128),
            chartTypes: z.array(z.enum(["bar", "line", "stacked_bar", "heatmap"])).max(16)
          })
          .strict()
      )
      .min(1)
      .max(128),
    suppressionPolicyId: IdentifierSchema,
    approval: NeutralDefinitionApprovalSchema
  })
  .strict()
  .superRefine((value, context) => {
    unique(
      value.sections.map((section) => section.sectionId),
      context,
      ["sections"],
      "section ids must be unique"
    );
    for (const [index, section] of value.sections.entries()) {
      unique(
        section.metricDefinitionIds,
        context,
        ["sections", index, "metricDefinitionIds"],
        "metric definition ids must be unique within a section"
      );
      unique(
        section.chartTypes,
        context,
        ["sections", index, "chartTypes"],
        "chart types must be unique within a section"
      );
    }
  });

export type ReportDefinitionV1 = Readonly<z.infer<typeof ReportDefinitionV1Schema>>;

export const ScenarioDefinitionV1Schema = z
  .object({
    schemaVersion: z.literal("1"),
    definitionType: z.literal("scenario_definition"),
    definitionId: IdentifierSchema,
    version: z.number().int().min(1).max(1_000_000),
    name: z.string().min(1).max(512),
    analysisType: z.enum(["borrowing_base", "portfolio_surveillance"]),
    maximumScenarios: z.number().int().min(1).max(1_000),
    assumptions: z
      .array(
        z
          .object({
            assumptionId: IdentifierSchema,
            field: IdentifierSchema,
            minimum: DecimalStringSchema,
            maximum: DecimalStringSchema,
            unit: z.enum(["currency", "count", "ratio", "percentage", "days"])
          })
          .strict()
      )
      .min(1)
      .max(128),
    approval: NeutralDefinitionApprovalSchema
  })
  .strict()
  .superRefine((value, context) => {
    unique(
      value.assumptions.map((assumption) => assumption.assumptionId),
      context,
      ["assumptions"],
      "assumption ids must be unique"
    );
    for (const [index, assumption] of value.assumptions.entries()) {
      if (compareCanonicalDecimals(assumption.minimum, assumption.maximum) > 0) {
        context.addIssue({
          code: "custom",
          path: ["assumptions", index, "maximum"],
          message: "maximum must be greater than or equal to minimum"
        });
      }
    }
  });

export type ScenarioDefinitionV1 = Readonly<z.infer<typeof ScenarioDefinitionV1Schema>>;

export const CovenantDefinitionV1Schema = z
  .object({
    schemaVersion: z.literal("1"),
    definitionType: z.literal("covenant_definition"),
    definitionId: IdentifierSchema,
    version: z.number().int().min(1).max(1_000_000),
    name: z.string().min(1).max(512),
    metricDefinitionId: IdentifierSchema,
    comparator: z.enum(["gte", "lte"]),
    threshold: DecimalStringSchema,
    unit: z.enum(["currency", "count", "ratio", "percentage", "days"]),
    warningThreshold: DecimalStringSchema.optional(),
    approval: NeutralDefinitionApprovalSchema
  })
  .strict();

export type CovenantDefinitionV1 = Readonly<z.infer<typeof CovenantDefinitionV1Schema>>;

export const SemanticDiffV1Schema = z
  .object({
    contractVersion: z.literal(1),
    beforeHash: Sha256HashSchema.nullable(),
    afterHash: Sha256HashSchema,
    changeCount: z.number().int().min(0).max(1_000_000),
    changedPaths: z.array(z.string().min(1).max(2_048)).max(256),
    truncated: z.boolean()
  })
  .strict()
  .superRefine((value, context) => {
    unique(value.changedPaths, context, ["changedPaths"], "changed paths must be unique");
    const sorted = [...value.changedPaths].sort(compare);
    if (sorted.some((path, index) => path !== value.changedPaths[index])) {
      context.addIssue({ code: "custom", path: ["changedPaths"], message: "changed paths must be sorted" });
    }
    if (!value.truncated && value.changeCount !== value.changedPaths.length) {
      context.addIssue({
        code: "custom",
        path: ["changeCount"],
        message: "changeCount must match changedPaths when the diff is not truncated"
      });
    }
    if (value.truncated && value.changeCount <= value.changedPaths.length) {
      context.addIssue({
        code: "custom",
        path: ["changeCount"],
        message: "a truncated diff must omit at least one path"
      });
    }
  });

export type SemanticDiffV1 = Readonly<z.infer<typeof SemanticDiffV1Schema>>;

export const DefinitionImpactPreviewV1Schema = z
  .object({
    contractVersion: z.literal(1),
    impactLevel: z.enum(["initial", "patch", "minor", "major"]),
    affectedCapabilities: z.array(IdentifierSchema).min(1).max(16),
    changedPathCount: z.number().int().min(0).max(1_000_000),
    rollbackTargetRequired: z.boolean()
  })
  .strict()
  .superRefine((value, context) => {
    unique(
      value.affectedCapabilities,
      context,
      ["affectedCapabilities"],
      "affected capabilities must be unique"
    );
    const sorted = [...value.affectedCapabilities].sort(compare);
    if (sorted.some((capability, index) => capability !== value.affectedCapabilities[index])) {
      context.addIssue({
        code: "custom",
        path: ["affectedCapabilities"],
        message: "affected capabilities must be sorted"
      });
    }
  });

export type DefinitionImpactPreviewV1 = Readonly<z.infer<typeof DefinitionImpactPreviewV1Schema>>;

const CanonicalJsonSchema: z.ZodType<CanonicalJsonValue> = z.lazy(() =>
  z.union([
    z.null(),
    z.boolean(),
    z.string(),
    z.number().int().safe(),
    z.array(CanonicalJsonSchema),
    z.record(z.string(), CanonicalJsonSchema)
  ])
);

const GovernedDefinitionVersionBodyV2Schema = z
  .object({
    contractVersion: z.literal(2),
    tenantId: IdentifierSchema,
    definitionVersionId: IdentifierSchema,
    definitionKey: IdentifierSchema,
    kind: GovernedDefinitionKindV2Schema,
    semanticVersion: SemanticVersionV2Schema,
    effectiveFrom: IsoDateSchema,
    effectiveTo: IsoDateSchema.nullable(),
    predecessorDefinitionVersionId: IdentifierSchema.nullable(),
    rollbackTargetDefinitionVersionId: IdentifierSchema.nullable(),
    document: CanonicalJsonSchema,
    documentHash: Sha256HashSchema,
    semanticDiff: SemanticDiffV1Schema,
    semanticDiffHash: Sha256HashSchema,
    impactPreview: DefinitionImpactPreviewV1Schema,
    impactPreviewHash: Sha256HashSchema,
    proposedBy: IdentifierSchema,
    proposedAt: IsoTimestampSchema
  })
  .strict()
  .superRefine((value, context) => {
    if (value.effectiveTo !== null && value.effectiveTo <= value.effectiveFrom) {
      context.addIssue({ code: "custom", path: ["effectiveTo"], message: "must follow effectiveFrom" });
    }
    if (value.predecessorDefinitionVersionId === value.definitionVersionId) {
      context.addIssue({
        code: "custom",
        path: ["predecessorDefinitionVersionId"],
        message: "cannot reference the same definition version"
      });
    }
    if (value.rollbackTargetDefinitionVersionId === value.definitionVersionId) {
      context.addIssue({
        code: "custom",
        path: ["rollbackTargetDefinitionVersionId"],
        message: "cannot reference the same definition version"
      });
    }
  });

export const GovernedDefinitionVersionV2Schema = GovernedDefinitionVersionBodyV2Schema.extend({
  versionHash: Sha256HashSchema
}).strict();

export type GovernedDefinitionVersionV2 = Readonly<z.infer<typeof GovernedDefinitionVersionV2Schema>>;
export type GovernedDefinitionVersionV2Input = Readonly<
  Omit<
    z.input<typeof GovernedDefinitionVersionBodyV2Schema>,
    "documentHash" | "semanticDiffHash" | "impactPreviewHash"
  >
>;

export function createGovernedDefinitionVersionV2(
  input: GovernedDefinitionVersionV2Input
): GovernedDefinitionVersionV2 {
  const validatedDocument = validateGovernedDefinitionDocumentV2(
    input.kind,
    input.document,
    input.tenantId,
    input.definitionKey,
    input.semanticVersion,
    input.effectiveFrom,
    input.effectiveTo
  );
  const inputBody = {
    ...input,
    document: validatedDocument,
    documentHash: canonicalHash(validatedDocument),
    semanticDiffHash: canonicalHash(input.semanticDiff),
    impactPreviewHash: canonicalHash(input.impactPreview)
  };
  const body = parseWithSchema(
    GovernedDefinitionVersionBodyV2Schema,
    inputBody,
    "GovernedDefinitionVersionV2"
  );
  return parseGovernedDefinitionVersionV2({ ...body, versionHash: canonicalHash(body) });
}

export function parseGovernedDefinitionVersionV2(value: unknown): GovernedDefinitionVersionV2 {
  const parsed = parseWithSchema(
    GovernedDefinitionVersionV2Schema,
    value,
    "GovernedDefinitionVersionV2"
  );
  const { versionHash, ...body } = parsed;
  assertCanonicalHash(body, versionHash, "GovernedDefinitionVersionV2");
  assertCanonicalHash(parsed.document, parsed.documentHash, "governed definition document");
  assertCanonicalHash(parsed.semanticDiff, parsed.semanticDiffHash, "governed definition semantic diff");
  assertCanonicalHash(parsed.impactPreview, parsed.impactPreviewHash, "governed definition impact preview");
  if (parsed.semanticDiff.afterHash !== parsed.documentHash) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "Semantic diff afterHash must match the governed definition document hash"
    );
  }
  validateGovernedDefinitionDocumentV2(
    parsed.kind,
    parsed.document,
    parsed.tenantId,
    parsed.definitionKey,
    parsed.semanticVersion,
    parsed.effectiveFrom,
    parsed.effectiveTo
  );
  return parsed;
}

export function computeDefinitionImpactPreviewV1(
  kind: GovernedDefinitionKindV2,
  beforeSemanticVersion: string | null,
  afterSemanticVersion: string,
  semanticDiff: SemanticDiffV1,
  rollbackTargetRequired: boolean
): DefinitionImpactPreviewV1 {
  const after = semanticVersionParts(
    parseWithSchema(SemanticVersionV2Schema, afterSemanticVersion, "after semantic version")
  );
  let impactLevel: DefinitionImpactPreviewV1["impactLevel"] = "initial";
  if (beforeSemanticVersion !== null) {
    const before = semanticVersionParts(
      parseWithSchema(SemanticVersionV2Schema, beforeSemanticVersion, "before semantic version")
    );
    impactLevel =
      after.core[0] !== before.core[0]
        ? "major"
        : after.core[1] !== before.core[1]
          ? "minor"
          : "patch";
  }
  const capabilityMap: Record<GovernedDefinitionKindV2, readonly string[]> = {
    source_contract: ["certification", "ingestion"],
    source_access_policy: ["analytics", "authorization", "certification"],
    mapping_spec: ["certification", "mapping"],
    methodology_bundle: ["analytics", "replay"],
    borrowing_base_policy_v2: ["borrowing_base", "monitoring"],
    metric_definition: ["analytics", "monitoring"],
    metric_projection: ["analytics", "monitoring"],
    cohort_definition: ["analytics"],
    bin_definition: ["analytics", "stratification"],
    reconciliation_definition: ["certification", "reconciliation"],
    entity_resolution_definition: ["analytics", "concentration"],
    report_definition: ["reporting"],
    scenario_definition: ["analytics", "scenario"],
    covenant_definition: ["covenant", "monitoring"]
  };
  return parseWithSchema(
    DefinitionImpactPreviewV1Schema,
    {
      contractVersion: 1,
      impactLevel,
      affectedCapabilities: [...capabilityMap[kind]].sort(compare),
      changedPathCount: semanticDiff.changeCount,
      rollbackTargetRequired
    },
    "DefinitionImpactPreviewV1"
  );
}

export function validateGovernedDefinitionDocumentV2(
  kind: GovernedDefinitionKindV2,
  value: unknown,
  tenantId: string,
  definitionKey: string,
  semanticVersion: string,
  effectiveFrom: string,
  effectiveTo: string | null
): CanonicalJsonValue {
  const document = canonicalClone(value, `${kind} document`);
  try {
    switch (kind) {
      case "source_contract": {
        const parsed = parseSourceContractV1(document);
        tenantMatch(parsed.tenantId, tenantId, kind);
        logicalIdentity(parsed.sourceKey, definitionKey, kind);
        documentVersion(parsed.revision, semanticVersion, kind);
        effectivityMatch(parsed.effectiveFrom, parsed.effectiveTo, effectiveFrom, effectiveTo, kind);
        const normalizedBody = {
          ...parsed,
          status: "proposed" as const,
          approvedBy: undefined,
          approvedAt: undefined
        };
        const { sourceContractHash: _sourceContractHash, approvedBy: _approvedBy, approvedAt: _approvedAt, ...body } =
          normalizedBody;
        return canonicalClone(
          parseSourceContractV1({ ...body, sourceContractHash: canonicalHash(body) }),
          `${kind} document`
        );
      }
      case "source_access_policy": {
        const parsed = parseSourceAccessPolicyV1(document);
        tenantMatch(parsed.tenantId, tenantId, kind);
        logicalIdentity(parsed.policyId, definitionKey, kind);
        documentVersion(parsed.revision, semanticVersion, kind);
        effectivityMatch(parsed.effectiveFrom, parsed.effectiveTo, effectiveFrom, effectiveTo, kind);
        return canonicalClone(parsed, `${kind} document`);
      }
      case "mapping_spec": {
        const parsed = parseMappingSpecV2(document);
        tenantMatch(parsed.tenantId, tenantId, kind);
        logicalIdentity(parsed.mappingKey, definitionKey, kind);
        documentVersion(parsed.revision, semanticVersion, kind);
        const normalizedBody = {
          ...parsed,
          status: "proposed" as const,
          approvedBy: undefined,
          approvedAt: undefined
        };
        const { mappingSpecHash: _mappingSpecHash, approvedBy: _approvedBy, approvedAt: _approvedAt, ...body } =
          normalizedBody;
        return canonicalClone(
          parseMappingSpecV2({ ...body, mappingSpecHash: canonicalHash(body) }),
          `${kind} document`
        );
      }
      case "methodology_bundle": {
        const parsed = canonicalClone(
          parseWithSchema(MethodologyBundleV1Schema, document, "MethodologyBundleV1"),
          `${kind} document`
        );
        logicalIdentity((parsed as { bundleId: string }).bundleId, definitionKey, kind);
        documentVersion((parsed as { version: string }).version, semanticVersion, kind);
        return parsed;
      }
      case "borrowing_base_policy_v2": {
        const normalized = normalizeBorrowingBasePolicy(document);
        validateBorrowingBasePolicyV2(normalized.execution as unknown as BorrowingBasePolicyV2);
        tenantMatch((normalized.stored as { tenantId: string }).tenantId, tenantId, kind);
        logicalIdentity((normalized.stored as { policyId: string }).policyId, definitionKey, kind);
        documentVersion((normalized.stored as { version: string }).version, semanticVersion, kind);
        effectivityMatch(
          (normalized.stored as { effectiveFrom: string }).effectiveFrom,
          (normalized.stored as { effectiveTo?: string }).effectiveTo,
          effectiveFrom,
          effectiveTo,
          kind
        );
        return normalized.stored;
      }
      case "metric_definition": {
        const engineDocument = engineApproval(document);
        validateMetricDefinitionV1(engineDocument as unknown as MetricDefinitionV1);
        logicalIdentity((document as { definitionId: string }).definitionId, definitionKey, kind);
        documentVersion((document as { version: number }).version, semanticVersion, kind);
        return neutralizeApproval(document);
      }
      case "metric_projection": {
        const parsed = canonicalClone(
          parseMetricProjectionV1(neutralizeApproval(document)),
          `${kind} document`
        );
        logicalIdentity((parsed as { definitionId: string }).definitionId, definitionKey, kind);
        documentVersion((parsed as { version: string }).version, semanticVersion, kind);
        return parsed;
      }
      case "cohort_definition": {
        const engineDocument = engineApproval(document);
        validateCohortDefinitionV1(engineDocument as unknown as CohortDefinitionV1);
        logicalIdentity((document as { definitionId: string }).definitionId, definitionKey, kind);
        documentVersion((document as { version: number }).version, semanticVersion, kind);
        return neutralizeApproval(document);
      }
      case "bin_definition": {
        const engineDocument = engineApproval(document);
        validateBinDefinitionV1(engineDocument as unknown as BinDefinitionV1);
        logicalIdentity((document as { definitionId: string }).definitionId, definitionKey, kind);
        documentVersion((document as { version: number }).version, semanticVersion, kind);
        return neutralizeApproval(document);
      }
      case "entity_resolution_definition": {
        const engineDocument = engineApproval(document);
        validateEntityResolutionDefinitionV1(
          engineDocument as unknown as EntityResolutionDefinitionV1,
          tenantId
        );
        logicalIdentity((document as { definitionId: string }).definitionId, definitionKey, kind);
        documentVersion((document as { version: number }).version, semanticVersion, kind);
        return neutralizeApproval(document);
      }
      case "reconciliation_definition": {
        const parsed = canonicalClone(
          parseWithSchema(
            ReconciliationDefinitionV1Schema,
            neutralizeApproval(document),
            "ReconciliationDefinitionV1"
          ),
          `${kind} document`
        );
        logicalIdentity((parsed as { definitionId: string }).definitionId, definitionKey, kind);
        documentVersion((parsed as { version: number }).version, semanticVersion, kind);
        return parsed;
      }
      case "report_definition": {
        const parsed = canonicalClone(
          parseWithSchema(ReportDefinitionV1Schema, neutralizeApproval(document), "ReportDefinitionV1"),
          `${kind} document`
        );
        logicalIdentity((parsed as { definitionId: string }).definitionId, definitionKey, kind);
        documentVersion((parsed as { version: number }).version, semanticVersion, kind);
        return parsed;
      }
      case "scenario_definition": {
        const parsed = canonicalClone(
          parseWithSchema(ScenarioDefinitionV1Schema, neutralizeApproval(document), "ScenarioDefinitionV1"),
          `${kind} document`
        );
        logicalIdentity((parsed as { definitionId: string }).definitionId, definitionKey, kind);
        documentVersion((parsed as { version: number }).version, semanticVersion, kind);
        return parsed;
      }
      case "covenant_definition": {
        const parsed = canonicalClone(
          parseWithSchema(CovenantDefinitionV1Schema, neutralizeApproval(document), "CovenantDefinitionV1"),
          `${kind} document`
        );
        logicalIdentity((parsed as { definitionId: string }).definitionId, definitionKey, kind);
        documentVersion((parsed as { version: number }).version, semanticVersion, kind);
        return parsed;
      }
    }
  } catch (error) {
    if (error instanceof ContractValidationError) throw error;
    throw new ContractValidationError(
      "INVALID_CONTRACT",
      `${kind} document failed validation`,
      [error instanceof Error ? error.message : "unknown validation failure"]
    );
  }
}

export function computeSemanticDiffV1(
  before: CanonicalJsonValue | null,
  after: CanonicalJsonValue,
  maximumPaths = 256
): SemanticDiffV1 {
  if (!Number.isSafeInteger(maximumPaths) || maximumPaths < 1 || maximumPaths > 256) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "Semantic diff maximumPaths must be between 1 and 256"
    );
  }
  canonicalJson(before);
  canonicalJson(after);
  const paths: string[] = [];
  let changeCount = 0;
  const changed = (path: string): void => {
    changeCount += 1;
    if (paths.length < maximumPaths) paths.push(path || "/");
  };
  if (before === null) {
    changed("/");
  } else {
    diffValue(before, after, "", changed);
  }
  paths.sort(compare);
  return parseWithSchema(
    SemanticDiffV1Schema,
    {
      contractVersion: 1,
      beforeHash: before === null ? null : canonicalHash(before),
      afterHash: canonicalHash(after),
      changeCount,
      changedPaths: paths,
      truncated: changeCount > paths.length
    },
    "SemanticDiffV1"
  );
}

export function compareSemanticVersionsV2(left: string, right: string): number {
  const parsedLeft = parseWithSchema(SemanticVersionV2Schema, left, "left semantic version");
  const parsedRight = parseWithSchema(SemanticVersionV2Schema, right, "right semantic version");
  const leftParts = semanticVersionParts(parsedLeft);
  const rightParts = semanticVersionParts(parsedRight);
  for (let index = 0; index < 3; index += 1) {
    const leftCore = leftParts.core[index]!;
    const rightCore = rightParts.core[index]!;
    if (leftCore !== rightCore) return leftCore < rightCore ? -1 : 1;
  }
  if (leftParts.prerelease.length === 0 && rightParts.prerelease.length === 0) return 0;
  if (leftParts.prerelease.length === 0) return 1;
  if (rightParts.prerelease.length === 0) return -1;
  const length = Math.max(leftParts.prerelease.length, rightParts.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const leftPart = leftParts.prerelease[index];
    const rightPart = rightParts.prerelease[index];
    if (leftPart === undefined) return -1;
    if (rightPart === undefined) return 1;
    if (leftPart === rightPart) continue;
    const leftNumeric = /^\d+$/.test(leftPart);
    const rightNumeric = /^\d+$/.test(rightPart);
    if (leftNumeric && rightNumeric) {
      const leftNumber = BigInt(leftPart);
      const rightNumber = BigInt(rightPart);
      return leftNumber < rightNumber ? -1 : 1;
    }
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    return compare(leftPart, rightPart);
  }
  return 0;
}

function diffValue(
  before: CanonicalJsonValue | undefined,
  after: CanonicalJsonValue | undefined,
  path: string,
  changed: (path: string) => void
): void {
  if (before === undefined || after === undefined) {
    changed(path);
    return;
  }
  if (canonicalJson(before) === canonicalJson(after)) return;
  if (Array.isArray(before) && Array.isArray(after)) {
    const length = Math.max(before.length, after.length);
    for (let index = 0; index < length; index += 1) {
      diffValue(before[index], after[index], `${path}/${index}`, changed);
    }
    return;
  }
  if (isRecord(before) && isRecord(after)) {
    const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
    for (const key of [...keys].sort(compare)) {
      diffValue(before[key], after[key], `${path}/${escapeJsonPointer(key)}`, changed);
    }
    return;
  }
  changed(path);
}

function canonicalClone(value: unknown, label: string): CanonicalJsonValue {
  try {
    return JSON.parse(canonicalJson(value)) as CanonicalJsonValue;
  } catch (error) {
    if (error instanceof ContractValidationError) throw error;
    throw new ContractValidationError("INVALID_CONTRACT", `${label} is not canonical JSON`);
  }
}

function isRecord(value: CanonicalJsonValue): value is { readonly [key: string]: CanonicalJsonValue } {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function escapeJsonPointer(value: string): string {
  return value.replace(/~/g, "~0").replace(/\//g, "~1");
}

function semanticVersionParts(value: string): {
  readonly core: readonly [bigint, bigint, bigint];
  readonly prerelease: readonly string[];
} {
  const withoutBuild = value.split("+", 1)[0]!;
  const [core, prerelease = ""] = withoutBuild.split("-", 2);
  const parts = core!.split(".").map(BigInt) as [bigint, bigint, bigint];
  return { core: parts, prerelease: prerelease ? prerelease.split(".") : [] };
}

function tenantMatch(actual: string, expected: string, kind: string): void {
  if (actual !== expected) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      `${kind} document belongs to another tenant`
    );
  }
}

function logicalIdentity(actual: string, expected: string | undefined, kind: string): void {
  if (expected !== undefined && actual !== expected) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      `${kind} logical identity does not match the governed definition key`
    );
  }
}

function documentVersion(actual: string | number, expected: string, kind: string): void {
  const normalized =
    typeof actual === "number" || /^(?:0|[1-9]\d*)$/.test(actual)
      ? `${String(actual)}.0.0`
      : actual;
  if (normalized !== expected) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      `${kind} document version does not match the governed semantic version`
    );
  }
}

function effectivityMatch(
  actualFrom: string,
  actualTo: string | undefined,
  expectedFrom: string,
  expectedTo: string | null,
  kind: string
): void {
  if (actualFrom !== expectedFrom || (actualTo ?? null) !== expectedTo) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      `${kind} document effectivity must match its governed version`
    );
  }
}

const NEUTRAL_APPROVAL = Object.freeze({
  status: "pending_durable_approval" as const,
  authority: "governed_definition_v2_lifecycle" as const
});

const ENGINE_VALIDATION_APPROVAL = Object.freeze({
  status: "approved" as const,
  proposedBy: "definition-v2-validation-maker",
  approvedBy: "definition-v2-validation-checker",
  approvedAt: "1970-01-01T00:00:00.000Z"
});

function neutralizeApproval(document: CanonicalJsonValue): CanonicalJsonValue {
  if (!isRecord(document)) {
    throw new ContractValidationError("INVALID_CONTRACT", "Governed definition document must be an object");
  }
  return canonicalClone({ ...document, approval: NEUTRAL_APPROVAL }, "approval-neutral document");
}

function engineApproval(document: CanonicalJsonValue): CanonicalJsonValue {
  if (!isRecord(document)) {
    throw new ContractValidationError("INVALID_CONTRACT", "Governed definition document must be an object");
  }
  return canonicalClone({ ...document, approval: ENGINE_VALIDATION_APPROVAL }, "engine validation document");
}

function normalizeBorrowingBasePolicy(document: CanonicalJsonValue): Readonly<{
  execution: CanonicalJsonValue;
  stored: CanonicalJsonValue;
}> {
  if (!isRecord(document)) {
    throw new ContractValidationError("INVALID_CONTRACT", "Borrowing-base policy document must be an object");
  }
  const { policyHash: _callerPolicyHash, approval: _callerApproval, ...policyProjection } = document;
  const policyHash = canonicalHash(policyProjection).slice("sha256:".length);
  const engineEvidence = {
    ...ENGINE_VALIDATION_APPROVAL,
    authorityRef: "definition-v2-validation",
    rationale: "Structural validation only; durable lifecycle is authoritative"
  };
  return Object.freeze({
    execution: canonicalClone(
      { ...policyProjection, policyHash, approval: engineEvidence },
      "borrowing-base validation document"
    ),
    stored: canonicalClone(
      { ...policyProjection, policyHash, approval: NEUTRAL_APPROVAL },
      "approval-neutral borrowing-base document"
    )
  });
}

function unique(
  values: readonly string[],
  context: z.RefinementCtx,
  path: readonly PropertyKey[],
  message: string
): void {
  if (new Set(values).size !== values.length) context.addIssue({ code: "custom", path: [...path], message });
}

function compareCanonicalDecimals(left: string, right: string): number {
  const negativeLeft = left.startsWith("-");
  const negativeRight = right.startsWith("-");
  if (negativeLeft !== negativeRight) return negativeLeft ? -1 : 1;
  const normalized = (value: string): readonly [string, string] => {
    const positive = value.startsWith("-") ? value.slice(1) : value;
    const [integer, fraction = ""] = positive.split(".");
    return [integer!, fraction.replace(/0+$/, "")];
  };
  const [leftInteger, leftFraction] = normalized(left);
  const [rightInteger, rightFraction] = normalized(right);
  let result = leftInteger.length - rightInteger.length;
  if (result === 0) result = compare(leftInteger, rightInteger);
  if (result === 0) {
    const length = Math.max(leftFraction.length, rightFraction.length);
    result = compare(leftFraction.padEnd(length, "0"), rightFraction.padEnd(length, "0"));
  }
  return negativeLeft ? -result : result;
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
