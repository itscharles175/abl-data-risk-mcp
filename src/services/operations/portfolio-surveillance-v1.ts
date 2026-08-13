import { Buffer } from "node:buffer";

import { z } from "zod";

import {
  GovernedDatasetScopeV1Schema,
  LongitudinalSourceIdentityV1Schema,
  parseLongitudinalCertificationBundleV1,
  type LongitudinalCertificationBundleV1,
  type LongitudinalCertifiedRevisionV1
} from "../../contracts/longitudinal-certification-bundle-v1.js";
import {
  IdentifierSchema,
  IsoDateSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  canonicalJson,
  deepFreeze,
  parseWithSchema,
  type CanonicalJsonValue,
  type Sha256Hash
} from "../../contracts/canonical.js";
import {
  GovernedDefinitionKindV2Schema,
  MethodologyBundleV1Schema,
  SemanticVersionV2Schema
} from "../../contracts/governed-definition-v2.js";
import type {
  BinDefinitionV1,
  CanonicalSurveillanceRecord,
  CertifiedSurveillanceSnapshotV1,
  CohortDefinitionV1,
  EntityResolutionDefinitionV1,
  FilterExpressionV1,
  MetricDefinitionV1,
  PortfolioSurveillanceInputV1,
  PortfolioSurveillanceResultV1
} from "../../domain/surveillance/contracts.js";
import {
  validateBinDefinitionV1,
  validateCohortDefinitionV1,
  validateEntityResolutionDefinitionV1,
  validateMetricDefinitionV1
} from "../../domain/surveillance/definitions.js";
import { getCanonicalFieldPolicy } from "../../domain/field-policy.js";
import type { ResolvedGovernedDefinitionV2 } from "../governed-definition-v2-resolver.js";
import {
  createAnalysisOperationDescriptorV2,
  type AnalysisOperationDescriptorV2,
  type AnalysisOperationModuleV2,
  type AnalysisOperationPlanningContextV2,
  type AnalysisOperationResultAccountingV2,
  type FrozenDefinitionRequirementV2
} from "../operation-registry-v2.js";
import { runPortfolioSurveillance } from "../surveillance/engine.js";

const OPERATION = "portfolio_surveillance_v1" as const;
const MINIMUM_SOURCE_REFERENCES = 1;
const MINIMUM_EXPANDED_SNAPSHOTS = 2;
const MAXIMUM_SOURCE_REFERENCES = 120;
const MAXIMUM_DEFINITION_REFERENCES = 256;
const MAXIMUM_RECORDS = 5_000_000;
const MAXIMUM_METRICS = 1_000;
const MAXIMUM_CELLS = 1_000_000;

const REQUEST_SCHEMA_DESCRIPTION = {
  contract: "PortfolioSurveillanceOperationRequestV1",
  strict: true,
  fields: {
    contractVersion: "literal:1",
    operation: `literal:${OPERATION}`,
    sources: "array[1..120]<certification_manifest_id|longitudinal_bundle_id>",
    definitionVersionIds: "unique_array[2..256]<identifier>"
  }
} as const;

const EXECUTION_SCHEMA_DESCRIPTION = {
  contract: "PortfolioSurveillanceExecutionPlanV1",
  strict: true,
  sourceEvidence: "certified_snapshot_material_v1",
  definitionAuthority: "frozen_governed_definition_v2",
  requestedFields: "derived_only",
  engine: "portfolio_surveillance_v1"
} as const;

const RESULT_SCHEMA_DESCRIPTION = {
  contract: "PortfolioSurveillanceOperationResultV1",
  strict: true,
  disclosure: "aggregate_only",
  cellPopulationLineage: "required",
  suppressionState: "required"
} as const;

export const PORTFOLIO_SURVEILLANCE_V1_SCHEMA_METADATA = deepFreeze({
  request: {
    contract: "PortfolioSurveillanceOperationRequestV1",
    schemaHash: canonicalHash(REQUEST_SCHEMA_DESCRIPTION)
  },
  workerPayload: {
    contract: "PortfolioSurveillanceExecutionPlanV1",
    schemaHash: canonicalHash(EXECUTION_SCHEMA_DESCRIPTION)
  },
  result: {
    contract: "PortfolioSurveillanceOperationResultV1",
    schemaHash: canonicalHash(RESULT_SCHEMA_DESCRIPTION)
  }
});

/** Explicit v4 workflow handoff: parent resolves; worker only verifies and computes. */
export const PORTFOLIO_SURVEILLANCE_V1_INTEGRATION_PORTS = deepFreeze({
  parentProcess: {
    requestParser: "parsePortfolioSurveillanceOperationRequestV1",
    authorityPort: "PortfolioSurveillanceOperationAuthorityV1",
    planner: "preparePortfolioSurveillanceExecutionPlanV1",
    requiredOuterControls: [
      "tenant_and_purpose_policy_authorization",
      "signed_plan_with_replay_protection",
      "worker_memory_and_deadline_enforcement",
      "immutable_artifact_content_hash_verification"
    ]
  },
  workerProcess: {
    payload: "PortfolioSurveillanceWorkerPayloadV1",
    parser: "parsePortfolioSurveillanceExecutionPlanV1",
    executor: "executePortfolioSurveillanceOperationV1",
    output: "PortfolioSurveillanceOperationResultV1",
    accounting: "accountPortfolioSurveillanceOperationResultV1"
  },
  longitudinalConversion: {
    selection: "each_period.analyticsSelection_terminal_revision",
    records: "selected_normalized_artifact_to_certified_snapshot_material_v1",
    ordering: "as_of_date_then_certification_manifest_id",
    correctionPolicy: "terminal_certified_replacement_only"
  }
});

export const PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR: AnalysisOperationDescriptorV2 =
  createAnalysisOperationDescriptorV2({
    contractVersion: 2,
    operationId: OPERATION,
    kind: "analysis",
    requestMode: "ids_only",
    requestContract: "PortfolioSurveillanceOperationRequestV1",
    executionContract: "PortfolioSurveillanceExecutionPlanV1",
    resultContract: "PortfolioSurveillanceOperationResultV1",
    requestSchemaHash: PORTFOLIO_SURVEILLANCE_V1_SCHEMA_METADATA.request.schemaHash,
    executionSchemaHash: PORTFOLIO_SURVEILLANCE_V1_SCHEMA_METADATA.workerPayload.schemaHash,
    resultSchemaHash: PORTFOLIO_SURVEILLANCE_V1_SCHEMA_METADATA.result.schemaHash,
    limits: {
      minimumSourceReferences: MINIMUM_SOURCE_REFERENCES,
      minimumExpandedSnapshots: MINIMUM_EXPANDED_SNAPSHOTS,
      maximumSourceReferences: MAXIMUM_SOURCE_REFERENCES,
      maximumDefinitionReferences: MAXIMUM_DEFINITION_REFERENCES,
      maximumExpandedSnapshots: MAXIMUM_SOURCE_REFERENCES,
      maximumRecords: MAXIMUM_RECORDS,
      maximumMetrics: MAXIMUM_METRICS,
      maximumCells: MAXIMUM_CELLS
    },
    disclosurePolicy: {
      policyId: "portfolio_surveillance.aggregate_only.v1",
      mode: "aggregate_only",
      detailRowsAllowed: false,
      sourceRecordFieldsAllowed: false,
      populationHashRequiredPerCell: true,
      suppressionStateRequiredPerCell: true
    }
  });

const SourceReferenceSchema = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.literal("certification_manifest"),
      certificationManifestId: IdentifierSchema
    })
    .strict(),
  z
    .object({
      kind: z.literal("longitudinal_bundle"),
      longitudinalBundleId: IdentifierSchema
    })
    .strict()
]);

const PortfolioSurveillanceOperationRequestV1Schema = z
  .object({
    contractVersion: z.literal(1),
    operation: z.literal(OPERATION),
    sources: z.array(SourceReferenceSchema).min(MINIMUM_SOURCE_REFERENCES).max(MAXIMUM_SOURCE_REFERENCES),
    definitionVersionIds: z
      .array(IdentifierSchema)
      .min(2)
      .max(MAXIMUM_DEFINITION_REFERENCES)
  })
  .strict()
  .superRefine((value, context) => {
    const sourceKeys = value.sources.map(sourceReferenceKey);
    unique(sourceKeys, context, ["sources"], "source references must be unique");
    unique(
      value.definitionVersionIds,
      context,
      ["definitionVersionIds"],
      "definition version ids must be unique"
    );
  });

export type PortfolioSurveillanceSourceReferenceV1 = Readonly<
  z.infer<typeof SourceReferenceSchema>
>;
export type PortfolioSurveillanceOperationRequestV1 = Readonly<
  z.infer<typeof PortfolioSurveillanceOperationRequestV1Schema>
>;

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

const CanonicalRecordSchema = z.record(z.string().min(1).max(256), CanonicalJsonSchema);
const BareSha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);
const CanonicalDecimalSchema = z
  .string()
  .max(256)
  .regex(/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/u);
const CanonicalCountSchema = z.string().max(32).regex(/^(?:0|[1-9]\d*)$/u);

const CertifiedSurveillanceSnapshotSchema = z
  .object({
    schemaVersion: z.literal("1"),
    snapshotId: IdentifierSchema,
    tenantId: IdentifierSchema,
    asOfDate: IsoDateSchema,
    snapshotHash: Sha256HashSchema,
    certification: z
      .object({
        status: z.literal("certified"),
        certificationId: IdentifierSchema,
        certificationHash: Sha256HashSchema,
        certifiedAt: IsoTimestampSchema
      })
      .strict(),
    records: z.array(CanonicalRecordSchema).max(MAXIMUM_RECORDS)
  })
  .strict();

const EngineCertifiedSurveillanceSnapshotSchema = CertifiedSurveillanceSnapshotSchema.extend({
  snapshotHash: BareSha256Schema,
  certification: z
    .object({
      status: z.literal("certified"),
      certificationId: IdentifierSchema,
      certificationHash: BareSha256Schema,
      certifiedAt: IsoTimestampSchema
    })
    .strict()
}).strict();

const CertifiedSnapshotMaterialBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    datasetId: IdentifierSchema,
    source: LongitudinalSourceIdentityV1Schema,
    scope: GovernedDatasetScopeV1Schema,
    authorizedPurpose: z.string().trim().min(1).max(512),
    authorizedFields: z.array(IdentifierSchema).min(1).max(2_000),
    authorizedAggregateDimensionFields: z.array(IdentifierSchema).max(256),
    certificationManifestId: IdentifierSchema,
    certificationManifestHash: Sha256HashSchema,
    populationHash: Sha256HashSchema,
    normalizedArtifact: z
      .object({
        artifactId: IdentifierSchema,
        contentHash: Sha256HashSchema
      })
      .strict(),
    rowCount: z.number().int().min(0).max(MAXIMUM_RECORDS),
    snapshot: CertifiedSurveillanceSnapshotSchema
  })
  .strict()
  .superRefine((value, context) => {
    if (
      new Set(value.authorizedFields).size !== value.authorizedFields.length ||
      canonicalJson([...value.authorizedFields].sort(compare)) !== canonicalJson(value.authorizedFields) ||
      new Set(value.authorizedAggregateDimensionFields).size !==
        value.authorizedAggregateDimensionFields.length ||
      canonicalJson([...value.authorizedAggregateDimensionFields].sort(compare)) !==
        canonicalJson(value.authorizedAggregateDimensionFields)
    ) {
      context.addIssue({
        code: "custom",
        path: ["authorizedFields"],
        message: "must be unique and sorted"
      });
    }
    if (value.snapshot.tenantId !== value.tenantId) {
      context.addIssue({
        code: "custom",
        path: ["snapshot", "tenantId"],
        message: "must match the certified material tenant"
      });
    }
    if (value.snapshot.certification.certificationId !== value.certificationManifestId) {
      context.addIssue({
        code: "custom",
        path: ["snapshot", "certification", "certificationId"],
        message: "must match the certification manifest id"
      });
    }
    if (value.snapshot.certification.certificationHash !== value.certificationManifestHash) {
      context.addIssue({
        code: "custom",
        path: ["snapshot", "certification", "certificationHash"],
        message: "must match the certification manifest hash"
      });
    }
    if (value.rowCount !== value.snapshot.records.length) {
      context.addIssue({
        code: "custom",
        path: ["rowCount"],
        message: "must match the certified snapshot record count"
      });
    }
    if (value.populationHash !== canonicalHash(value.snapshot.records)) {
      context.addIssue({
        code: "custom",
        path: ["populationHash"],
        message: "must bind the exact canonical certified records"
      });
    }
    if (value.snapshot.asOfDate > value.snapshot.certification.certifiedAt.slice(0, 10)) {
      context.addIssue({
        code: "custom",
        path: ["snapshot", "asOfDate"],
        message: "cannot be after certification"
      });
    }
  });

export const CertifiedSnapshotMaterialV1Schema =
  CertifiedSnapshotMaterialBodyV1Schema.extend({ materialHash: Sha256HashSchema }).strict();

export type CertifiedSnapshotMaterialV1 = Readonly<
  z.infer<typeof CertifiedSnapshotMaterialV1Schema>
>;

export type CertifiedSnapshotMaterialV1Input = Readonly<
  z.input<typeof CertifiedSnapshotMaterialBodyV1Schema>
>;

export function createCertifiedSnapshotMaterialV1(
  input: CertifiedSnapshotMaterialV1Input
): CertifiedSnapshotMaterialV1 {
  const body = parseWithSchema(
    CertifiedSnapshotMaterialBodyV1Schema,
    input,
    "CertifiedSnapshotMaterialV1"
  );
  return parseCertifiedSnapshotMaterialV1({ ...body, materialHash: canonicalHash(body) });
}

export function parseCertifiedSnapshotMaterialV1(value: unknown): CertifiedSnapshotMaterialV1 {
  const parsed = parseWithSchema(
    CertifiedSnapshotMaterialV1Schema,
    value,
    "CertifiedSnapshotMaterialV1"
  );
  const { materialHash, ...body } = parsed;
  assertCanonicalHash(body, materialHash, "CertifiedSnapshotMaterialV1");
  return parsed;
}

export type PortfolioSurveillanceSnapshotLoadRequestV1 =
  | Readonly<{
      sourceKind: "certification_manifest";
      tenantId: string;
      certificationManifestId: string;
    }>
  | Readonly<{
      sourceKind: "longitudinal_bundle";
      tenantId: string;
      longitudinalBundleId: string;
      longitudinalBundleHash: Sha256Hash;
      certificationManifestId: string;
      certificationManifestHash: Sha256Hash;
      snapshotId: string;
      snapshotHash: Sha256Hash;
      normalizedArtifactId: string;
      normalizedArtifactContentHash: Sha256Hash;
      populationHash: Sha256Hash;
      rowCount: number;
    }>;

export interface PortfolioSurveillanceOperationAuthorityV1 {
  loadLongitudinalBundle(
    tenantId: string,
    longitudinalBundleId: string
  ): Promise<unknown | undefined> | unknown | undefined;
  loadCertifiedSnapshot(
    input: PortfolioSurveillanceSnapshotLoadRequestV1
  ): Promise<unknown | undefined> | unknown | undefined;
  resolveFrozenDefinition(
    tenantId: string,
    definitionVersionId: string
  ): Promise<ResolvedGovernedDefinitionV2 | undefined> | ResolvedGovernedDefinitionV2 | undefined;
}

const SourceLineageSchema = z
  .object({
    sourceReferenceKind: z.enum(["certification_manifest", "longitudinal_bundle"]),
    sourceReferenceId: IdentifierSchema,
    longitudinalBundleHash: Sha256HashSchema.nullable(),
    materialHash: Sha256HashSchema,
    datasetId: IdentifierSchema,
    source: LongitudinalSourceIdentityV1Schema,
    scope: GovernedDatasetScopeV1Schema,
    authorizedPurpose: z.string().trim().min(1).max(512),
    authorizedFields: z.array(IdentifierSchema).min(1).max(2_000),
    authorizedFieldsHash: Sha256HashSchema,
    authorizedAggregateDimensionFields: z.array(IdentifierSchema).max(256),
    authorizedAggregateDimensionFieldsHash: Sha256HashSchema,
    certificationManifestId: IdentifierSchema,
    certificationManifestHash: Sha256HashSchema,
    snapshotId: IdentifierSchema,
    snapshotHash: Sha256HashSchema,
    asOfDate: IsoDateSchema,
    normalizedArtifactId: IdentifierSchema,
    normalizedArtifactContentHash: Sha256HashSchema,
    populationHash: Sha256HashSchema,
    projectedPopulationHash: Sha256HashSchema,
    rowCount: z.number().int().min(0).max(MAXIMUM_RECORDS)
  })
  .strict()
  .superRefine((value, context) => {
    if (
      new Set(value.authorizedFields).size !== value.authorizedFields.length ||
      canonicalJson([...value.authorizedFields].sort(compare)) !== canonicalJson(value.authorizedFields) ||
      canonicalHash(value.authorizedFields) !== value.authorizedFieldsHash ||
      new Set(value.authorizedAggregateDimensionFields).size !==
        value.authorizedAggregateDimensionFields.length ||
      canonicalJson([...value.authorizedAggregateDimensionFields].sort(compare)) !==
        canonicalJson(value.authorizedAggregateDimensionFields) ||
      canonicalHash(value.authorizedAggregateDimensionFields) !==
        value.authorizedAggregateDimensionFieldsHash
    ) {
      context.addIssue({
        code: "custom",
        path: ["authorizedFields"],
        message: "must be unique, sorted, and hash-bound"
      });
    }
  });

const DefinitionLineageSchema = z
  .object({
    kind: z.enum([
      "methodology_bundle",
      "metric_definition",
      "cohort_definition",
      "bin_definition",
      "entity_resolution_definition"
    ]),
    definitionVersionId: IdentifierSchema,
    definitionKey: IdentifierSchema,
    semanticVersion: z.string().min(1).max(64),
    versionHash: Sha256HashSchema,
    documentHash: Sha256HashSchema,
    approvalEventHash: Sha256HashSchema,
    executionDocumentHash: Sha256HashSchema
  })
  .strict();

const ResolvedDefinitionSchema = z
  .object({
    reference: z
      .object({
        definitionVersionId: IdentifierSchema,
        definitionKey: IdentifierSchema,
        kind: GovernedDefinitionKindV2Schema,
        semanticVersion: SemanticVersionV2Schema,
        versionHash: Sha256HashSchema,
        documentHash: Sha256HashSchema,
        approvalEventHash: Sha256HashSchema
      })
      .strict(),
    approvalEvidence: z
      .object({
        status: z.literal("approved"),
        proposedBy: IdentifierSchema,
        approvedBy: IdentifierSchema,
        approvedAt: IsoTimestampSchema,
        approvalEventHash: Sha256HashSchema
      })
      .strict(),
    executionDocument: CanonicalJsonSchema
  })
  .strict()
  .superRefine((value, context) => {
    if (value.reference.approvalEventHash !== value.approvalEvidence.approvalEventHash) {
      context.addIssue({
        code: "custom",
        path: ["approvalEvidence", "approvalEventHash"],
        message: "must match the frozen definition reference"
      });
    }
    if (value.approvalEvidence.proposedBy === value.approvalEvidence.approvedBy) {
      context.addIssue({
        code: "custom",
        path: ["approvalEvidence", "approvedBy"],
        message: "must be different from the maker"
      });
    }
  });

const MetricCellLineageSchema = z
  .object({
    definitionHash: BareSha256Schema,
    supportingDefinitionHashes: z.array(BareSha256Schema).max(MAXIMUM_DEFINITION_REFERENCES),
    methodologyId: IdentifierSchema,
    methodologyVersion: z.number().int().min(1).max(1_000_000),
    methodologyHash: BareSha256Schema,
    snapshotHashes: z.array(BareSha256Schema).min(1).max(MAXIMUM_SOURCE_REFERENCES),
    populationHash: BareSha256Schema,
    numeratorPopulationHash: BareSha256Schema,
    denominatorPopulationHash: BareSha256Schema,
    entityResolutionHash: BareSha256Schema.nullable()
  })
  .strict()
  .superRefine((value, context) => {
    if (value.populationHash !== value.denominatorPopulationHash) {
      context.addIssue({
        code: "custom",
        path: ["populationHash"],
        message: "must equal the denominator/disclosure population hash"
      });
    }
  });

const MetricCellSchema = z
  .object({
    cellId: IdentifierSchema,
    metric: IdentifierSchema,
    unit: z.enum(["count", "currency", "ratio", "days"]),
    dimensions: z.record(z.string().min(1).max(128), z.string().max(256)),
    numerator: CanonicalDecimalSchema.nullable(),
    denominator: CanonicalDecimalSchema.nullable(),
    value: CanonicalDecimalSchema.nullable(),
    coverage: z
      .object({
        observedCount: CanonicalCountSchema.nullable(),
        eligibleCount: CanonicalCountSchema.nullable(),
        ratio: CanonicalDecimalSchema.nullable()
      })
      .strict(),
    available: z.boolean(),
    availabilityReason: z.enum([
      "available",
      "no_records",
      "missing_required_field",
      "insufficient_coverage",
      "unseasoned",
      "no_prior_period",
      "division_by_zero",
      "entity_resolution_unapproved",
      "suppressed"
    ]),
    suppressed: z.boolean(),
    lineage: MetricCellLineageSchema
  })
  .strict();

const SurveillanceMetricResultSchema = z
  .object({
    schemaVersion: z.literal("1"),
    metricDefinitionId: IdentifierSchema,
    metricDefinitionVersion: z.number().int().min(1).max(1_000_000),
    family: z.enum([
      "roll_cure",
      "default_ever",
      "loss_recovery",
      "paydown_prepayment",
      "rating_migration",
      "balance_utilization",
      "maturity_wall",
      "concentration",
      "period_comparison"
    ]),
    cells: z.array(MetricCellSchema).max(MAXIMUM_CELLS),
    warnings: z.array(z.string().max(512)).max(4),
    lineage: z
      .object({
        definitionHash: BareSha256Schema,
        supportingDefinitionHashes: z.array(BareSha256Schema).max(MAXIMUM_DEFINITION_REFERENCES),
        methodologyId: IdentifierSchema,
        methodologyVersion: z.number().int().min(1).max(1_000_000),
        methodologyHash: BareSha256Schema,
        analysisHash: BareSha256Schema
      })
      .strict()
  })
  .strict();

const AggregateSurveillanceResultSchema = z
  .object({
    schemaVersion: z.literal("1"),
    tenantId: IdentifierSchema,
    asOfDates: z.array(IsoDateSchema).min(2).max(MAXIMUM_SOURCE_REFERENCES),
    metrics: z.array(SurveillanceMetricResultSchema).min(1).max(MAXIMUM_METRICS),
    lineage: z
      .object({
        methodologyId: IdentifierSchema,
        methodologyVersion: z.number().int().min(1).max(1_000_000),
        methodologyHash: BareSha256Schema,
        snapshotHashes: z.array(BareSha256Schema).min(2).max(MAXIMUM_SOURCE_REFERENCES),
        analysisHash: BareSha256Schema
      })
      .strict()
  })
  .strict();

const PortfolioSurveillanceOperationResultSchema = z
  .object({
    contractVersion: z.literal(1),
    operation: z.literal(OPERATION),
    tenantId: IdentifierSchema,
    purpose: z.string().trim().min(1).max(512),
    requestHash: Sha256HashSchema,
    planHash: Sha256HashSchema,
    sourceLineage: z.array(SourceLineageSchema).min(2).max(MAXIMUM_SOURCE_REFERENCES),
    sourceSetHash: Sha256HashSchema,
    definitionLineage: z
      .array(DefinitionLineageSchema)
      .min(2)
      .max(MAXIMUM_DEFINITION_REFERENCES),
    definitionSetHash: Sha256HashSchema,
    requestedFieldsHash: Sha256HashSchema,
    aggregate: AggregateSurveillanceResultSchema,
    resultHash: Sha256HashSchema
  })
  .strict();

export type PortfolioSurveillanceSourceLineageV1 = Readonly<
  z.infer<typeof SourceLineageSchema>
>;
export type PortfolioSurveillanceDefinitionLineageV1 = Readonly<
  z.infer<typeof DefinitionLineageSchema>
>;

const SourceAccessPolicyAuthorityReferenceV1Schema = z
  .object({
    definitionVersionId: IdentifierSchema,
    definitionKey: IdentifierSchema,
    semanticVersion: SemanticVersionV2Schema,
    versionHash: Sha256HashSchema,
    documentHash: Sha256HashSchema,
    approvalEventHash: Sha256HashSchema,
    executionDocumentHash: Sha256HashSchema,
    policyId: IdentifierSchema,
    revision: z.number().int().positive().max(1_000_000),
    policyHash: Sha256HashSchema,
    effectiveFrom: IsoDateSchema,
    effectiveTo: IsoDateSchema.nullable()
  })
  .strict();

const DatasetScopeBindingAuthorityReferenceV1Schema = z
  .object({
    definitionVersionId: IdentifierSchema,
    definitionKey: IdentifierSchema,
    semanticVersion: SemanticVersionV2Schema,
    versionHash: Sha256HashSchema,
    documentHash: Sha256HashSchema,
    approvalEventHash: Sha256HashSchema,
    executionDocumentHash: Sha256HashSchema,
    bindingId: IdentifierSchema,
    revision: z.number().int().positive().max(1_000_000),
    bindingHash: Sha256HashSchema,
    effectiveFrom: IsoDateSchema,
    effectiveTo: IsoDateSchema.nullable()
  })
  .strict();

const PortfolioSurveillanceGovernanceBindingsV1Schema = z
  .object({
    metadataHash: Sha256HashSchema,
    preflightHash: Sha256HashSchema,
    sourceSelectionHash: Sha256HashSchema,
    sourceIdentityHash: Sha256HashSchema,
    sourceAccessPolicies: z
      .array(SourceAccessPolicyAuthorityReferenceV1Schema)
      .min(1)
      .max(1_000),
    sourceAccessPolicySetHash: Sha256HashSchema,
    datasetScopeBindings: z
      .array(DatasetScopeBindingAuthorityReferenceV1Schema)
      .min(1)
      .max(MAXIMUM_SOURCE_REFERENCES),
    datasetScopeBindingSetHash: Sha256HashSchema
  })
  .strict()
  .superRefine((value, context) => {
    for (const [field, values, expectedHash] of [
      ["sourceAccessPolicies", value.sourceAccessPolicies, value.sourceAccessPolicySetHash],
      ["datasetScopeBindings", value.datasetScopeBindings, value.datasetScopeBindingSetHash]
    ] as const) {
      const ids = values.map(({ definitionVersionId }) => definitionVersionId);
      if (
        new Set(ids).size !== ids.length ||
        canonicalJson([...ids].sort(compare)) !== canonicalJson(ids) ||
        canonicalHash(values) !== expectedHash
      ) {
        context.addIssue({
          code: "custom",
          path: [field],
          message: "must be uniquely ordered and exactly hash-bound"
        });
      }
    }
  });

export type PortfolioSurveillanceGovernanceBindingsV1 = Readonly<
  z.infer<typeof PortfolioSurveillanceGovernanceBindingsV1Schema>
>;

export interface PortfolioSurveillanceExecutionPlanV1 {
  readonly contractVersion: 1;
  readonly operation: typeof OPERATION;
  readonly descriptorHash: Sha256Hash;
  readonly tenantId: string;
  readonly purpose: string;
  readonly request: PortfolioSurveillanceOperationRequestV1;
  readonly requestHash: Sha256Hash;
  readonly sourceLineage: readonly PortfolioSurveillanceSourceLineageV1[];
  readonly sourceSetHash: Sha256Hash;
  readonly definitionLineage: readonly PortfolioSurveillanceDefinitionLineageV1[];
  readonly definitionSetHash: Sha256Hash;
  readonly requestedFields: readonly string[];
  readonly requestedFieldsHash: Sha256Hash;
  /** Required by governed v4 execution; absent only on legacy standalone v1 plans. */
  readonly governanceBindings?: PortfolioSurveillanceGovernanceBindingsV1;
  readonly engineInput: PortfolioSurveillanceInputV1;
  readonly planHash: Sha256Hash;
}

/** Exact payload the parent process may structured-clone into an analysis worker. */
export type PortfolioSurveillanceWorkerPayloadV1 = PortfolioSurveillanceExecutionPlanV1;

export interface PortfolioSurveillanceOperationResultV1 {
  readonly contractVersion: 1;
  readonly operation: typeof OPERATION;
  readonly tenantId: string;
  readonly purpose: string;
  readonly requestHash: Sha256Hash;
  readonly planHash: Sha256Hash;
  readonly sourceLineage: readonly PortfolioSurveillanceSourceLineageV1[];
  readonly sourceSetHash: Sha256Hash;
  readonly definitionLineage: readonly PortfolioSurveillanceDefinitionLineageV1[];
  readonly definitionSetHash: Sha256Hash;
  readonly requestedFieldsHash: Sha256Hash;
  readonly aggregate: PortfolioSurveillanceResultV1;
  readonly resultHash: Sha256Hash;
}

export type PortfolioSurveillanceOperationErrorCode =
  | "INVALID_REQUEST"
  | "SOURCE_NOT_FOUND"
  | "SOURCE_EVIDENCE_MISMATCH"
  | "DEFINITION_NOT_FOUND"
  | "DEFINITION_EVIDENCE_MISMATCH"
  | "UNSUPPORTED_DEFINITION"
  | "PLAN_INTEGRITY_FAILURE"
  | "DISCLOSURE_POLICY_VIOLATION";

export class PortfolioSurveillanceOperationError extends Error {
  constructor(readonly code: PortfolioSurveillanceOperationErrorCode, message: string) {
    super(message);
    this.name = "PortfolioSurveillanceOperationError";
  }
}

export function parsePortfolioSurveillanceOperationRequestV1(
  value: unknown
): PortfolioSurveillanceOperationRequestV1 {
  const parsed = parseWithSchema(
    PortfolioSurveillanceOperationRequestV1Schema,
    value,
    "PortfolioSurveillanceOperationRequestV1"
  );
  return deepFreeze({
    ...parsed,
    sources: [...parsed.sources].sort((left, right) =>
      compare(sourceReferenceKey(left), sourceReferenceKey(right))
    ),
    definitionVersionIds: [...parsed.definitionVersionIds].sort(compare)
  });
}

/** IDs the parent workflow must resolve through the frozen-definition authority. */
export function portfolioSurveillanceRequiredDefinitionVersionIdsV1(
  requestValue: unknown
): readonly string[] {
  return parsePortfolioSurveillanceOperationRequestV1(requestValue).definitionVersionIds;
}

/**
 * Resolves all mutable repository lookups before worker execution. The output
 * is a self-hashed, canonical, structured-clone-safe payload containing only
 * certified source data and frozen definition projections.
 */
export async function preparePortfolioSurveillanceExecutionPlanV1(
  requestValue: unknown,
  contextValue: AnalysisOperationPlanningContextV2,
  authority: PortfolioSurveillanceOperationAuthorityV1
): Promise<PortfolioSurveillanceExecutionPlanV1> {
  const request = parsePortfolioSurveillanceOperationRequestV1(requestValue);
  const context = planningContext(contextValue);
  const definitions = await resolveDefinitions(request, context.tenantId, authority);
  const requestedFields = derivePortfolioSurveillanceRequestedFieldsV1({
    metricDefinitions: definitions.metrics,
    cohortDefinitions: definitions.cohorts,
    binDefinitions: definitions.bins,
    entityResolutionDefinitions: definitions.entityResolutions
  });
  const disclosedSourceDimensionFields = deriveDisclosedSourceDimensionFields(
    definitions.metrics
  );
  const loadedSources: LoadedSource[] = [];
  let loadedRecordCount = 0;
  for (const reference of request.sources) {
    const next = await loadSource(reference, context, authority, {
      maximumSnapshots: MAXIMUM_SOURCE_REFERENCES - loadedSources.length,
      maximumRecords: MAXIMUM_RECORDS - loadedRecordCount
    });
    if (loadedSources.length + next.length > MAXIMUM_SOURCE_REFERENCES) {
      invalid(
        "INVALID_REQUEST",
        `Resolved surveillance history exceeds ${MAXIMUM_SOURCE_REFERENCES} certified snapshots`
      );
    }
    for (const source of next) {
      loadedRecordCount += source.material.rowCount;
      if (loadedRecordCount > MAXIMUM_RECORDS) {
        invalid("INVALID_REQUEST", `Certified surveillance records exceed ${MAXIMUM_RECORDS}`);
      }
      loadedSources.push(source);
    }
  }
  if (
    loadedSources.length < MINIMUM_EXPANDED_SNAPSHOTS ||
    loadedSources.length > MAXIMUM_SOURCE_REFERENCES
  ) {
    invalid(
      "INVALID_REQUEST",
      `Resolved surveillance history must contain ${MINIMUM_EXPANDED_SNAPSHOTS}..${MAXIMUM_SOURCE_REFERENCES} certified snapshots`
    );
  }

  const orderedSources = [...loadedSources].sort(
    (left, right) =>
      compare(left.material.snapshot.asOfDate, right.material.snapshot.asOfDate) ||
      compare(left.material.certificationManifestId, right.material.certificationManifestId)
  );
  validateSourceSet(orderedSources, context.tenantId);
  validateBundleMethodologyBindings(orderedSources, definitions.methodology);

  validateSourceFieldAuthorizations(
    orderedSources,
    context.purpose,
    requestedFields,
    disclosedSourceDimensionFields
  );
  const methodologyHash = methodologyHashForSources(orderedSources, definitions.methodology);
  const engineInput: PortfolioSurveillanceInputV1 = deepFreeze({
    tenantId: context.tenantId,
    snapshots: orderedSources.map(({ material }) =>
      toEngineSnapshot(material.snapshot, requestedFields)
    ),
    metricDefinitions: definitions.metrics,
    cohortDefinitions: definitions.cohorts,
    binDefinitions: definitions.bins,
    entityResolutionDefinitions: definitions.entityResolutions,
    methodology: {
      methodologyId: definitions.methodology.document.bundleId,
      methodologyVersion: legacyMethodologyVersion(definitions.methodology.document.version),
      methodologyHash: bareHash(methodologyHash)
    },
    bounds: {
      maxSnapshots: MAXIMUM_SOURCE_REFERENCES,
      maxRecords: MAXIMUM_RECORDS,
      maxMetrics: MAXIMUM_METRICS,
      maxCells: MAXIMUM_CELLS
    }
  });
  const sourceLineage = orderedSources.map((source) =>
    toSourceLineage(source, requestedFields)
  );
  const definitionLineage = definitions.lineage;
  const body = {
    contractVersion: 1 as const,
    operation: OPERATION,
    descriptorHash: PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR.descriptorHash,
    tenantId: context.tenantId,
    purpose: context.purpose,
    request,
    requestHash: canonicalHash(request),
    sourceLineage,
    sourceSetHash: canonicalHash(sourceLineage),
    definitionLineage,
    definitionSetHash: canonicalHash(definitionLineage),
    requestedFields,
    requestedFieldsHash: canonicalHash(requestedFields),
    engineInput
  };
  return parsePortfolioSurveillanceExecutionPlanV1({
    ...body,
    planHash: canonicalHash(body)
  });
}

export function parsePortfolioSurveillanceExecutionPlanV1(
  value: unknown
): PortfolioSurveillanceExecutionPlanV1 {
  const candidate = value as Readonly<Record<string, unknown>>;
  const hasGovernanceBindings =
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.prototype.hasOwnProperty.call(candidate, "governanceBindings");
  const record = strictRecord(value, [
    "contractVersion",
    "definitionLineage",
    "definitionSetHash",
    "descriptorHash",
    "engineInput",
    "operation",
    "planHash",
    "purpose",
    "request",
    "requestHash",
    "requestedFields",
    "requestedFieldsHash",
    "sourceLineage",
    "sourceSetHash",
    "tenantId",
    ...(hasGovernanceBindings ? ["governanceBindings"] : [])
  ], "PortfolioSurveillanceExecutionPlanV1");
  const planHash = hashValue(record.planHash, "planHash");
  const { planHash: _planHash, ...body } = record;
  try {
    assertCanonicalHash(body, planHash, "PortfolioSurveillanceExecutionPlanV1");
  } catch {
    invalid("PLAN_INTEGRITY_FAILURE", "Surveillance execution plan hash did not match its content");
  }
  if (
    record.contractVersion !== 1 ||
    record.operation !== OPERATION ||
    record.descriptorHash !== PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR.descriptorHash
  ) {
    invalid("PLAN_INTEGRITY_FAILURE", "Surveillance execution plan identity is invalid");
  }
  const tenantId = identifierValue(record.tenantId, "tenantId");
  const purpose = purposeValue(record.purpose);
  const request = parsePortfolioSurveillanceOperationRequestV1(record.request);
  if (hashValue(record.requestHash, "requestHash") !== canonicalHash(request)) {
    invalid("PLAN_INTEGRITY_FAILURE", "Surveillance request hash drifted inside the execution plan");
  }
  const sourceLineage = parseWithSchema(
    z.array(SourceLineageSchema).min(2).max(MAXIMUM_SOURCE_REFERENCES),
    record.sourceLineage,
    "portfolio surveillance source lineage"
  );
  const definitionLineage = parseWithSchema(
    z.array(DefinitionLineageSchema).min(2).max(MAXIMUM_DEFINITION_REFERENCES),
    record.definitionLineage,
    "portfolio surveillance definition lineage"
  );
  if (
    canonicalJson(request.definitionVersionIds) !==
    canonicalJson(definitionLineage.map(({ definitionVersionId }) => definitionVersionId).sort(compare))
  ) {
    invalid("PLAN_INTEGRITY_FAILURE", "Request definition ids do not match frozen lineage");
  }
  const lineageSourceReferenceKeys = sortedUniqueText(
    sourceLineage.map((source) => `${source.sourceReferenceKind}:${source.sourceReferenceId}`)
  );
  if (
    canonicalJson(request.sources.map(sourceReferenceKey).sort(compare)) !==
    canonicalJson(lineageSourceReferenceKeys)
  ) {
    invalid("PLAN_INTEGRITY_FAILURE", "Request source ids do not match certified lineage");
  }
  const requestedFields = identifierArray(record.requestedFields, "requestedFields", 1, 2_000);
  for (const source of sourceLineage) {
    if (
      source.authorizedPurpose !== purpose ||
      canonicalHash(source.authorizedFields) !== source.authorizedFieldsHash ||
      requestedFields.some((field) => !source.authorizedFields.includes(field))
    ) {
      invalid(
        "PLAN_INTEGRITY_FAILURE",
        "Worker payload field or purpose authorization no longer matches source lineage"
      );
    }
  }
  if (
    hashValue(record.sourceSetHash, "sourceSetHash") !== canonicalHash(sourceLineage) ||
    hashValue(record.definitionSetHash, "definitionSetHash") !== canonicalHash(definitionLineage) ||
    hashValue(record.requestedFieldsHash, "requestedFieldsHash") !== canonicalHash(requestedFields)
  ) {
    invalid("PLAN_INTEGRITY_FAILURE", "Surveillance execution-plan lineage hashes drifted");
  }
  const engineInput = validatePreparedEngineInput(
    record.engineInput,
    tenantId,
    sourceLineage,
    definitionLineage,
    requestedFields
  );
  const governanceBindings = hasGovernanceBindings
    ? parseWithSchema(
        PortfolioSurveillanceGovernanceBindingsV1Schema,
        record.governanceBindings,
        "portfolio surveillance governance bindings"
      )
    : undefined;
  return deepFreeze({
    contractVersion: 1,
    operation: OPERATION,
    descriptorHash: PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR.descriptorHash,
    tenantId,
    purpose,
    request,
    requestHash: hashValue(record.requestHash, "requestHash"),
    sourceLineage,
    sourceSetHash: hashValue(record.sourceSetHash, "sourceSetHash"),
    definitionLineage,
    definitionSetHash: hashValue(record.definitionSetHash, "definitionSetHash"),
    requestedFields,
    requestedFieldsHash: hashValue(record.requestedFieldsHash, "requestedFieldsHash"),
    ...(governanceBindings === undefined ? {} : { governanceBindings }),
    engineInput,
    planHash
  });
}

/**
 * Adds the exact frozen policy and dataset-binding authority used by metadata
 * preflight. Legacy standalone v1 plans remain parseable, but governed v4
 * execution requires this extension and independently rebinds every hash.
 */
export function bindPortfolioSurveillanceGovernanceV1(
  planValue: PortfolioSurveillanceExecutionPlanV1,
  bindingsValue: PortfolioSurveillanceGovernanceBindingsV1
): PortfolioSurveillanceExecutionPlanV1 {
  const plan = parsePortfolioSurveillanceExecutionPlanV1(planValue);
  if (plan.governanceBindings !== undefined) {
    invalid("PLAN_INTEGRITY_FAILURE", "Surveillance plan governance is already bound");
  }
  const bindings = parseWithSchema(
    PortfolioSurveillanceGovernanceBindingsV1Schema,
    bindingsValue,
    "portfolio surveillance governance bindings"
  );
  const { planHash: _planHash, ...legacyBody } = plan;
  const body = { ...legacyBody, governanceBindings: bindings };
  return parsePortfolioSurveillanceExecutionPlanV1({
    ...body,
    planHash: canonicalHash(body)
  });
}

/** Executes only the deterministic engine; this function has no repository or network port. */
export function executePortfolioSurveillanceOperationV1(
  planValue: PortfolioSurveillanceExecutionPlanV1
): PortfolioSurveillanceOperationResultV1 {
  const plan = parsePortfolioSurveillanceExecutionPlanV1(planValue);
  const aggregate = runPortfolioSurveillance(plan.engineInput);
  const body = {
    contractVersion: 1 as const,
    operation: OPERATION,
    tenantId: plan.tenantId,
    purpose: plan.purpose,
    requestHash: plan.requestHash,
    planHash: plan.planHash,
    sourceLineage: plan.sourceLineage,
    sourceSetHash: plan.sourceSetHash,
    definitionLineage: plan.definitionLineage,
    definitionSetHash: plan.definitionSetHash,
    requestedFieldsHash: plan.requestedFieldsHash,
    aggregate
  };
  const result = deepFreeze({ ...body, resultHash: canonicalHash(body) });
  assertPortfolioSurveillanceResultMatchesPlan(result, plan, aggregate);
  return result;
}

export function assertAggregateOnlyPortfolioSurveillanceResultV1(
  result: PortfolioSurveillanceOperationResultV1,
  planValue: PortfolioSurveillanceExecutionPlanV1
): void {
  const plan = parsePortfolioSurveillanceExecutionPlanV1(planValue);
  const expectedAggregate = runPortfolioSurveillance(plan.engineInput);
  assertPortfolioSurveillanceResultMatchesPlan(result, plan, expectedAggregate);
}

function assertPortfolioSurveillanceResultMatchesPlan(
  result: PortfolioSurveillanceOperationResultV1,
  plan: PortfolioSurveillanceExecutionPlanV1,
  expectedAggregate: PortfolioSurveillanceResultV1
): void {
  let parsed: Readonly<z.infer<typeof PortfolioSurveillanceOperationResultSchema>>;
  try {
    parsed = parseWithSchema(
      PortfolioSurveillanceOperationResultSchema,
      result,
      "PortfolioSurveillanceOperationResultV1"
    );
  } catch {
    invalid(
      "DISCLOSURE_POLICY_VIOLATION",
      "Aggregate surveillance result contains invalid or non-aggregate fields"
    );
  }
  const { resultHash, ...body } = parsed;
  try {
    assertCanonicalHash(body, resultHash, "PortfolioSurveillanceOperationResultV1");
  } catch {
    invalid("DISCLOSURE_POLICY_VIOLATION", "Aggregate surveillance result hash is invalid");
  }
  if (
    parsed.contractVersion !== 1 ||
    parsed.operation !== OPERATION ||
    parsed.aggregate.tenantId !== parsed.tenantId ||
    parsed.tenantId !== plan.tenantId ||
    parsed.purpose !== plan.purpose ||
    parsed.requestHash !== plan.requestHash ||
    parsed.planHash !== plan.planHash ||
    parsed.sourceSetHash !== plan.sourceSetHash ||
    parsed.definitionSetHash !== plan.definitionSetHash ||
    parsed.requestedFieldsHash !== plan.requestedFieldsHash ||
    canonicalJson(parsed.sourceLineage) !== canonicalJson(plan.sourceLineage) ||
    canonicalJson(parsed.definitionLineage) !== canonicalJson(plan.definitionLineage)
  ) {
    invalid("DISCLOSURE_POLICY_VIOLATION", "Aggregate surveillance result identity is invalid");
  }
  if (canonicalJson(parsed.aggregate) !== canonicalJson(expectedAggregate)) {
    invalid(
      "DISCLOSURE_POLICY_VIOLATION",
      "Aggregate surveillance result does not match deterministic execution of the frozen plan"
    );
  }
}

export function accountPortfolioSurveillanceOperationResultV1(
  result: PortfolioSurveillanceOperationResultV1,
  plan: PortfolioSurveillanceExecutionPlanV1
): AnalysisOperationResultAccountingV2 {
  assertAggregateOnlyPortfolioSurveillanceResultV1(result, plan);
  const cells = result.aggregate.metrics.flatMap((metric) => metric.cells);
  const populationHashes = sortedUnique(
    cells.flatMap((cell) => cellPopulationHashes(cell.lineage))
  );
  return deepFreeze({
    aggregateRows: cells.length,
    bytes: Buffer.byteLength(canonicalJson(result), "utf8"),
    metricCount: result.aggregate.metrics.length,
    suppressedCellCount: cells.filter((cell) => cell.suppressed).length,
    unavailableCellCount: cells.filter((cell) => !cell.available).length,
    populationHashes,
    disclosureClasses: ["aggregate_metric_cell", "aggregate_warning", "governed_lineage"]
  });
}

/** Process-local module surface; all values crossing it are canonical JSON. */
export const PORTFOLIO_SURVEILLANCE_V1_OPERATION_MODULE = Object.freeze({
  descriptor: PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR,
  parseRequest: parsePortfolioSurveillanceOperationRequestV1,
  requiredDefinitionVersionIds: portfolioSurveillanceRequiredDefinitionVersionIdsV1,
  prepare: preparePortfolioSurveillanceExecutionPlanV1,
  parseWorkerPayload: parsePortfolioSurveillanceExecutionPlanV1,
  executeInWorker: executePortfolioSurveillanceOperationV1,
  accountResult: accountPortfolioSurveillanceOperationResultV1,
  assertDisclosure: assertAggregateOnlyPortfolioSurveillanceResultV1
});

/** Binds parent-process authorities into the generic v2 operation-module port. */
export function createPortfolioSurveillanceOperationModuleV1(
  authority: PortfolioSurveillanceOperationAuthorityV1
): AnalysisOperationModuleV2<
  PortfolioSurveillanceOperationRequestV1,
  PortfolioSurveillanceWorkerPayloadV1,
  PortfolioSurveillanceOperationResultV1
> {
  return Object.freeze({
    descriptor: PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR,
    parseRequest: parsePortfolioSurveillanceOperationRequestV1,
    prepare: (
      request: PortfolioSurveillanceOperationRequestV1,
      context: AnalysisOperationPlanningContextV2
    ) =>
      preparePortfolioSurveillanceExecutionPlanV1(request, context, authority),
    execute: executePortfolioSurveillanceOperationV1,
    accountResult: accountPortfolioSurveillanceOperationResultV1
  });
}

export function derivePortfolioSurveillanceRequestedFieldsV1(input: Readonly<{
  metricDefinitions: readonly MetricDefinitionV1[];
  cohortDefinitions: readonly CohortDefinitionV1[];
  binDefinitions: readonly BinDefinitionV1[];
  entityResolutionDefinitions: readonly EntityResolutionDefinitionV1[];
}>): readonly string[] {
  const fields = new Set<string>(["as_of_date", "facility_id", "loan_id", "source_system"]);
  const cohorts = new Map(input.cohortDefinitions.map((definition) => [definition.definitionId, definition]));
  const bins = new Map(input.binDefinitions.map((definition) => [definition.definitionId, definition]));
  const resolutions = new Map(
    input.entityResolutionDefinitions.map((definition) => [definition.definitionId, definition])
  );
  for (const definition of input.metricDefinitions) {
    if (definition.population !== null) collectFilterFields(fields, definition.population);
    const configuration = definition.configuration;
    switch (configuration.kind) {
      case "roll_cure":
        fields.add(configuration.delinquencyField);
        fields.add(configuration.balanceField);
        addSupportingBinField(fields, bins, configuration.binDefinitionId);
        break;
      case "default_ever":
        fields.add(configuration.defaultFlagField);
        fields.add(configuration.daysPastDueField);
        fields.add(configuration.balanceField);
        break;
      case "loss_recovery":
        fields.add(configuration.grossLossField);
        fields.add(configuration.recoveryField);
        fields.add(configuration.denominatorField);
        fields.add(configuration.defaultDateField);
        break;
      case "paydown_prepayment":
        fields.add(configuration.balanceField);
        if (configuration.scheduledPrincipalField !== undefined) {
          fields.add(configuration.scheduledPrincipalField);
        }
        break;
      case "rating_migration":
        fields.add(configuration.ratingField);
        fields.add(configuration.balanceField);
        break;
      case "balance_utilization": {
        fields.add(configuration.balanceField);
        fields.add(configuration.originalBalanceField);
        fields.add(configuration.commitmentField);
        if (configuration.cohortDefinitionId !== undefined) {
          const cohort = cohorts.get(configuration.cohortDefinitionId);
          if (cohort !== undefined) {
            fields.add(cohort.dateField);
            if (cohort.population !== undefined) collectFilterFields(fields, cohort.population);
          }
        }
        break;
      }
      case "maturity_wall":
        fields.add(configuration.maturityDateField);
        fields.add(configuration.balanceField);
        break;
      case "concentration": {
        fields.add(configuration.dimensionField);
        fields.add(configuration.balanceField);
        if (configuration.binDefinitionId !== undefined) {
          addSupportingBinField(fields, bins, configuration.binDefinitionId);
        }
        if (configuration.entityResolutionDefinitionId !== undefined) {
          const resolution = resolutions.get(configuration.entityResolutionDefinitionId);
          if (resolution !== undefined) fields.add(resolution.sourceField);
        }
        break;
      }
      case "period_comparison":
        fields.add(configuration.balanceField);
        if (configuration.dimensionField !== undefined) fields.add(configuration.dimensionField);
        break;
    }
  }
  return deepFreeze([...fields].sort(compare));
}

/** Deterministic methodology identity consumed by the v1 surveillance engine. */
export function portfolioSurveillanceMethodologyHashV1(
  documentValue: unknown
): Sha256Hash {
  const document = parseWithSchema(
    MethodologyBundleV1Schema,
    documentValue,
    "portfolio surveillance methodology"
  );
  return canonicalHash({
    contract: "portfolio_surveillance_methodology_v1",
    bundleId: document.bundleId,
    version: document.version,
    calculationEngine: document.calculationEngine,
    deterministicParameters: document.deterministicParameters,
    requiredDefinitionKinds: document.requiredDefinitionKinds
  });
}

function deriveDisclosedSourceDimensionFields(
  metrics: readonly MetricDefinitionV1[]
): readonly string[] {
  const fields = new Set<string>();
  for (const metric of metrics) {
    const config = metric.configuration;
    if (config.kind === "rating_migration") fields.add(config.ratingField);
    if (
      config.kind === "concentration" &&
      config.binDefinitionId === undefined &&
      config.entityResolutionDefinitionId === undefined
    ) {
      fields.add(config.dimensionField);
    }
    if (config.kind === "period_comparison" && config.dimensionField !== undefined) {
      fields.add(config.dimensionField);
    }
  }
  const result = [...fields].sort(compare);
  for (const field of result) {
    const policy = getCanonicalFieldPolicy(field);
    if (policy.aggregationEligibility !== "bucket_only" || policy.defaultMask !== "none") {
      invalid(
        "DISCLOSURE_POLICY_VIOLATION",
        `Source-backed aggregate dimension ${field} is not eligible for direct category disclosure`
      );
    }
  }
  return deepFreeze(result);
}

interface LoadedSource {
  readonly reference: PortfolioSurveillanceSourceReferenceV1;
  readonly bundle: LongitudinalCertificationBundleV1 | null;
  readonly material: CertifiedSnapshotMaterialV1;
}

interface ResolvedMethodology {
  readonly resolved: ResolvedGovernedDefinitionV2;
  readonly document: Readonly<z.infer<typeof MethodologyBundleV1Schema>>;
  readonly lineage: PortfolioSurveillanceDefinitionLineageV1;
}

interface ResolvedDefinitions {
  readonly methodology: ResolvedMethodology;
  readonly metrics: readonly MetricDefinitionV1[];
  readonly cohorts: readonly CohortDefinitionV1[];
  readonly bins: readonly BinDefinitionV1[];
  readonly entityResolutions: readonly EntityResolutionDefinitionV1[];
  readonly lineage: readonly PortfolioSurveillanceDefinitionLineageV1[];
}

async function resolveDefinitions(
  request: PortfolioSurveillanceOperationRequestV1,
  tenantId: string,
  authority: PortfolioSurveillanceOperationAuthorityV1
): Promise<ResolvedDefinitions> {
  const resolvedValues = await Promise.all(
    request.definitionVersionIds.map(async (definitionVersionId) => {
      const value = await authority.resolveFrozenDefinition(tenantId, definitionVersionId);
      if (value === undefined) {
        invalid("DEFINITION_NOT_FOUND", `Frozen definition ${definitionVersionId} was not found`);
      }
      let resolved: ResolvedGovernedDefinitionV2;
      try {
        resolved = parseWithSchema(
          ResolvedDefinitionSchema,
          value,
          `resolved governed definition ${definitionVersionId}`
        ) as ResolvedGovernedDefinitionV2;
      } catch {
        invalid(
          "DEFINITION_EVIDENCE_MISMATCH",
          `Frozen definition ${definitionVersionId} returned malformed authority evidence`
        );
      }
      if (resolved.reference.definitionVersionId !== definitionVersionId) {
        invalid(
          "DEFINITION_EVIDENCE_MISMATCH",
          `Frozen definition authority substituted ${definitionVersionId}`
        );
      }
      canonicalHash(resolved.executionDocument);
      return resolved;
    })
  );
  const allowedKinds = new Set([
    "methodology_bundle",
    "metric_definition",
    "cohort_definition",
    "bin_definition",
    "entity_resolution_definition"
  ]);
  for (const resolved of resolvedValues) {
    if (!allowedKinds.has(resolved.reference.kind)) {
      invalid(
        "UNSUPPORTED_DEFINITION",
        `Definition kind ${resolved.reference.kind} cannot execute in portfolio surveillance v1`
      );
    }
  }
  const methodologyValues = resolvedValues.filter(
    ({ reference }) => reference.kind === "methodology_bundle"
  );
  if (methodologyValues.length !== 1) {
    invalid("INVALID_REQUEST", "Portfolio surveillance requires exactly one frozen methodology bundle");
  }
  const methodologyResolved = methodologyValues[0]!;
  const methodologyDocument = parseWithSchema(
    MethodologyBundleV1Schema,
    methodologyResolved.executionDocument,
    "portfolio surveillance methodology"
  );
  if (methodologyDocument.bundleId !== methodologyResolved.reference.definitionKey) {
    invalid("DEFINITION_EVIDENCE_MISMATCH", "Methodology identity does not match its frozen reference");
  }

  const metrics = parseDefinitionDocuments<MetricDefinitionV1>(
    resolvedValues,
    "metric_definition",
    validateMetricDefinitionV1
  );
  if (metrics.length < 1 || metrics.length > MAXIMUM_METRICS) {
    invalid("INVALID_REQUEST", `Portfolio surveillance requires 1..${MAXIMUM_METRICS} metric definitions`);
  }
  const maximumPlannedCells = metrics.reduce((total, metric) => {
    const next = total + metric.maximumCells;
    if (!Number.isSafeInteger(next)) {
      invalid("INVALID_REQUEST", "Metric cell limits exceed the safe integer bound");
    }
    return next;
  }, 0);
  if (maximumPlannedCells > MAXIMUM_CELLS) {
    invalid(
      "INVALID_REQUEST",
      `Frozen metric cell limits exceed the ${MAXIMUM_CELLS} cell operation budget`
    );
  }
  for (const metric of metrics) assertPortfolioSurveillanceMetricCompatibilityV1(metric);
  const cohorts = parseDefinitionDocuments<CohortDefinitionV1>(
    resolvedValues,
    "cohort_definition",
    validateCohortDefinitionV1
  );
  const bins = parseDefinitionDocuments<BinDefinitionV1>(
    resolvedValues,
    "bin_definition",
    validateBinDefinitionV1
  );
  const entityResolutions = parseDefinitionDocuments<EntityResolutionDefinitionV1>(
    resolvedValues,
    "entity_resolution_definition",
    (value) => validateEntityResolutionDefinitionV1(value, tenantId)
  );
  validateSupportingDefinitions(metrics, cohorts, bins, entityResolutions);
  validateMethodologyRequirements(methodologyDocument.requiredDefinitionKinds, resolvedValues);

  const lineage = resolvedValues.map(toDefinitionLineage).sort(compareDefinitionLineage);
  return deepFreeze({
    methodology: {
      resolved: methodologyResolved,
      document: methodologyDocument,
      lineage: toDefinitionLineage(methodologyResolved)
    },
    metrics: [...metrics].sort(compareEngineDefinition),
    cohorts: [...cohorts].sort(compareEngineDefinition),
    bins: [...bins].sort(compareEngineDefinition),
    entityResolutions: [...entityResolutions].sort(compareEngineDefinition),
    lineage
  });
}

async function loadSource(
  reference: PortfolioSurveillanceSourceReferenceV1,
  context: Readonly<{ tenantId: string; purpose: string }>,
  authority: PortfolioSurveillanceOperationAuthorityV1,
  remaining: Readonly<{ maximumSnapshots: number; maximumRecords: number }>
): Promise<readonly LoadedSource[]> {
  if (reference.kind === "certification_manifest") {
    const value = await authority.loadCertifiedSnapshot({
      sourceKind: "certification_manifest",
      tenantId: context.tenantId,
      certificationManifestId: reference.certificationManifestId
    });
    if (value === undefined) {
      invalid(
        "SOURCE_NOT_FOUND",
        `Certification manifest ${reference.certificationManifestId} was not found`
      );
    }
    const material = parseCertifiedSnapshotMaterialV1(value);
    if (remaining.maximumSnapshots < 1 || material.rowCount > remaining.maximumRecords) {
      invalid("INVALID_REQUEST", "Certified surveillance source exceeds the remaining execution budget");
    }
    if (
      material.tenantId !== context.tenantId ||
      material.certificationManifestId !== reference.certificationManifestId
    ) {
      invalid("SOURCE_EVIDENCE_MISMATCH", "Certification-manifest authority substituted source evidence");
    }
    return deepFreeze([{ reference, bundle: null, material }]);
  }

  const bundleValue = await authority.loadLongitudinalBundle(
    context.tenantId,
    reference.longitudinalBundleId
  );
  if (bundleValue === undefined) {
    invalid("SOURCE_NOT_FOUND", `Longitudinal bundle ${reference.longitudinalBundleId} was not found`);
  }
  const bundle = parseLongitudinalCertificationBundleV1(bundleValue);
  if (
    bundle.tenantId !== context.tenantId ||
    bundle.bundleId !== reference.longitudinalBundleId ||
    bundle.purpose !== context.purpose
  ) {
    invalid(
      "SOURCE_EVIDENCE_MISMATCH",
      "Longitudinal bundle tenant, identity, or certified purpose did not match the operation"
    );
  }
  const selectedRevisions = bundle.periods.map((period) =>
    selectedRevision(bundle, period.analyticsSelection.revisionSequence, period.sequence)
  );
  const selectedRowCount = selectedRevisions.reduce((total, revision) => {
    const next = total + revision.rowCount;
    if (!Number.isSafeInteger(next)) {
      invalid("INVALID_REQUEST", "Longitudinal bundle row count exceeds the safe integer bound");
    }
    return next;
  }, 0);
  if (
    selectedRevisions.length > remaining.maximumSnapshots ||
    selectedRowCount > remaining.maximumRecords
  ) {
    invalid(
      "INVALID_REQUEST",
      "Longitudinal bundle exceeds the remaining snapshot or record execution budget"
    );
  }
  const sources: LoadedSource[] = [];
  let recordCount = 0;
  for (const selected of selectedRevisions) {
    recordCount += selected.rowCount;
    if (recordCount > MAXIMUM_RECORDS) {
      invalid("INVALID_REQUEST", `Certified surveillance records exceed ${MAXIMUM_RECORDS}`);
    }
    const value = await authority.loadCertifiedSnapshot({
        sourceKind: "longitudinal_bundle",
        tenantId: context.tenantId,
        longitudinalBundleId: bundle.bundleId,
        longitudinalBundleHash: bundle.bundleHash,
        certificationManifestId: selected.certification.certificationManifestId,
        certificationManifestHash: selected.certification.certificationManifestHash,
        snapshotId: selected.snapshot.snapshotId,
        snapshotHash: selected.snapshot.snapshotHash,
        normalizedArtifactId: selected.normalizedArtifact.artifactId,
        normalizedArtifactContentHash: selected.normalizedArtifact.contentHash,
        populationHash: selected.populationHash,
        rowCount: selected.rowCount
    });
    if (value === undefined) {
      invalid(
        "SOURCE_NOT_FOUND",
        `Certified normalized artifact ${selected.normalizedArtifact.artifactId} was not found`
      );
    }
    const material = parseCertifiedSnapshotMaterialV1(value);
    assertSelectedRevision(material, bundle, selected);
    sources.push(deepFreeze({ reference, bundle, material }));
  }
  return deepFreeze(sources);
}

function validateSourceSet(sources: readonly LoadedSource[], tenantId: string): void {
  const manifestIds = new Set<string>();
  const snapshotIds = new Set<string>();
  const dates = new Set<string>();
  let recordCount = 0;
  const first = sources[0]!.material;
  for (const { material } of sources) {
    if (material.tenantId !== tenantId) {
      invalid("SOURCE_EVIDENCE_MISMATCH", "Certified source crossed a tenant boundary");
    }
    if (
      material.datasetId !== first.datasetId ||
      canonicalJson(material.source) !== canonicalJson(first.source) ||
      canonicalJson(material.scope) !== canonicalJson(first.scope)
    ) {
      invalid(
        "SOURCE_EVIDENCE_MISMATCH",
        "Portfolio surveillance v1 requires one dataset, source-contract revision, and governed scope"
      );
    }
    if (
      manifestIds.has(material.certificationManifestId) ||
      snapshotIds.has(material.snapshot.snapshotId) ||
      dates.has(material.snapshot.asOfDate)
    ) {
      invalid(
        "SOURCE_EVIDENCE_MISMATCH",
        "Certified surveillance sources must have unique manifests, snapshots, and as-of dates"
      );
    }
    manifestIds.add(material.certificationManifestId);
    snapshotIds.add(material.snapshot.snapshotId);
    dates.add(material.snapshot.asOfDate);
    recordCount += material.rowCount;
    if (recordCount > MAXIMUM_RECORDS) {
      invalid("INVALID_REQUEST", `Certified surveillance records exceed ${MAXIMUM_RECORDS}`);
    }
  }
}

function validateBundleMethodologyBindings(
  sources: readonly LoadedSource[],
  methodology: ResolvedMethodology
): void {
  for (const { bundle } of sources) {
    if (bundle === null) continue;
    if (
      bundle.methodology.methodologyId !== methodology.document.bundleId ||
      bundle.methodology.definitionVersionId !== methodology.lineage.definitionVersionId ||
      bundle.methodology.version !== methodology.lineage.semanticVersion ||
      bundle.methodology.versionHash !== methodology.lineage.versionHash ||
      bundle.methodology.documentHash !== methodology.lineage.documentHash ||
      bundle.methodology.approvalEventHash !== methodology.lineage.approvalEventHash
    ) {
      invalid(
        "DEFINITION_EVIDENCE_MISMATCH",
        "Longitudinal source was certified under another frozen methodology"
      );
    }
  }
}

function methodologyHashForSources(
  sources: readonly LoadedSource[],
  methodology: ResolvedMethodology
): Sha256Hash {
  const hashes = sortedUnique(
    sources.flatMap(({ bundle }) => (bundle === null ? [] : [bundle.methodology.methodologyHash]))
  );
  if (hashes.length > 1) {
    invalid("DEFINITION_EVIDENCE_MISMATCH", "Longitudinal sources carry different methodology hashes");
  }
  const expected = portfolioSurveillanceMethodologyHashV1(methodology.document);
  if (hashes.length === 1 && hashes[0] !== expected) {
    invalid(
      "DEFINITION_EVIDENCE_MISMATCH",
      "Longitudinal bundle methodology hash does not match the frozen executable methodology"
    );
  }
  return expected;
}

function validatePreparedEngineInput(
  value: unknown,
  tenantId: string,
  sourceLineage: readonly PortfolioSurveillanceSourceLineageV1[],
  definitionLineage: readonly PortfolioSurveillanceDefinitionLineageV1[],
  requestedFields: readonly string[]
): PortfolioSurveillanceInputV1 {
  const record = strictRecord(value, [
    "binDefinitions",
    "bounds",
    "cohortDefinitions",
    "entityResolutionDefinitions",
    "methodology",
    "metricDefinitions",
    "snapshots",
    "tenantId"
  ], "portfolio surveillance engine input");
  if (record.tenantId !== tenantId || !Array.isArray(record.snapshots)) {
    invalid("PLAN_INTEGRITY_FAILURE", "Surveillance engine input tenant or snapshots are invalid");
  }
  const snapshotValues = record.snapshots;
  if (snapshotValues.length !== sourceLineage.length) {
    invalid("PLAN_INTEGRITY_FAILURE", "Surveillance snapshot lineage count drifted");
  }
  const snapshots = snapshotValues.map((snapshot, index) => {
    const parsed = parseWithSchema(
      EngineCertifiedSurveillanceSnapshotSchema,
      snapshot,
      `surveillance snapshot ${index}`
    ) as CertifiedSurveillanceSnapshotV1;
    const lineage = sourceLineage[index]!;
    const allowed = new Set(requestedFields);
    if (
      parsed.snapshotId !== lineage.snapshotId ||
      normalizeHash(parsed.snapshotHash) !== lineage.snapshotHash ||
      parsed.asOfDate !== lineage.asOfDate ||
      parsed.certification.certificationId !== lineage.certificationManifestId ||
      normalizeHash(parsed.certification.certificationHash) !== lineage.certificationManifestHash ||
      parsed.records.length !== lineage.rowCount ||
      canonicalHash(parsed.records) !== lineage.projectedPopulationHash
    ) {
      invalid("PLAN_INTEGRITY_FAILURE", "Surveillance snapshot no longer matches source lineage");
    }
    for (const recordValue of parsed.records) {
      if (Object.keys(recordValue).some((field) => !allowed.has(field))) {
        invalid(
          "PLAN_INTEGRITY_FAILURE",
          "Worker payload contains a source field outside the derived field allow-list"
        );
      }
    }
    return parsed;
  });
  if (
    !Array.isArray(record.metricDefinitions) ||
    !Array.isArray(record.cohortDefinitions) ||
    !Array.isArray(record.binDefinitions) ||
    !Array.isArray(record.entityResolutionDefinitions)
  ) {
    invalid("PLAN_INTEGRITY_FAILURE", "Surveillance definition arrays are invalid");
  }
  const metrics = validatePlanDefinitions<MetricDefinitionV1>(
    record.metricDefinitions,
    "metric_definition",
    definitionLineage,
    validateMetricDefinitionV1
  );
  const cohorts = validatePlanDefinitions<CohortDefinitionV1>(
    record.cohortDefinitions,
    "cohort_definition",
    definitionLineage,
    validateCohortDefinitionV1
  );
  const bins = validatePlanDefinitions<BinDefinitionV1>(
    record.binDefinitions,
    "bin_definition",
    definitionLineage,
    validateBinDefinitionV1
  );
  const entityResolutions = validatePlanDefinitions<EntityResolutionDefinitionV1>(
    record.entityResolutionDefinitions,
    "entity_resolution_definition",
    definitionLineage,
    (definition) => validateEntityResolutionDefinitionV1(definition, tenantId)
  );
  const derived = derivePortfolioSurveillanceRequestedFieldsV1({
    metricDefinitions: metrics,
    cohortDefinitions: cohorts,
    binDefinitions: bins,
      entityResolutionDefinitions: entityResolutions
  });
  if (canonicalJson(derived) !== canonicalJson(requestedFields)) {
    invalid("PLAN_INTEGRITY_FAILURE", "Requested fields no longer match frozen definitions");
  }
  const disclosedSourceDimensionFields = deriveDisclosedSourceDimensionFields(metrics);
  for (const source of sourceLineage) {
    if (
      canonicalHash(source.authorizedAggregateDimensionFields) !==
        source.authorizedAggregateDimensionFieldsHash ||
      disclosedSourceDimensionFields.some(
        (field) => !source.authorizedAggregateDimensionFields.includes(field)
      )
    ) {
      invalid(
        "PLAN_INTEGRITY_FAILURE",
        "Aggregate source-backed dimensions exceed certified disclosure authorization"
      );
    }
  }
  const methodology = strictRecord(
    record.methodology,
    ["methodologyHash", "methodologyId", "methodologyVersion"],
    "surveillance methodology"
  );
  identifierValue(methodology.methodologyId, "methodologyId");
  if (
    !Number.isSafeInteger(methodology.methodologyVersion) ||
    (methodology.methodologyVersion as number) < 1 ||
    !BareSha256Schema.safeParse(methodology.methodologyHash).success
  ) {
    invalid("PLAN_INTEGRITY_FAILURE", "Surveillance methodology projection is invalid");
  }
  const methodologyLineage = definitionLineage.filter(
    ({ kind }) => kind === "methodology_bundle"
  );
  if (methodologyLineage.length !== 1 || methodologyLineage[0]!.definitionKey !== methodology.methodologyId) {
    invalid("PLAN_INTEGRITY_FAILURE", "Surveillance methodology lineage drifted");
  }
  const bounds = strictRecord(
    record.bounds,
    ["maxCells", "maxMetrics", "maxRecords", "maxSnapshots"],
    "surveillance bounds"
  );
  if (
    bounds.maxSnapshots !== MAXIMUM_SOURCE_REFERENCES ||
    bounds.maxRecords !== MAXIMUM_RECORDS ||
    bounds.maxMetrics !== MAXIMUM_METRICS ||
    bounds.maxCells !== MAXIMUM_CELLS
  ) {
    invalid("PLAN_INTEGRITY_FAILURE", "Surveillance execution bounds were relaxed or changed");
  }
  return deepFreeze({
    tenantId,
    snapshots,
    metricDefinitions: metrics,
    cohortDefinitions: cohorts,
    binDefinitions: bins,
    entityResolutionDefinitions: entityResolutions,
    methodology: {
      methodologyId: methodology.methodologyId as string,
      methodologyVersion: methodology.methodologyVersion as number,
      methodologyHash: methodology.methodologyHash as string
    },
    bounds: {
      maxSnapshots: MAXIMUM_SOURCE_REFERENCES,
      maxRecords: MAXIMUM_RECORDS,
      maxMetrics: MAXIMUM_METRICS,
      maxCells: MAXIMUM_CELLS
    }
  });
}

function validatePlanDefinitions<T>(
  value: unknown,
  kind: PortfolioSurveillanceDefinitionLineageV1["kind"],
  lineage: readonly PortfolioSurveillanceDefinitionLineageV1[],
  validate: (definition: T) => unknown
): readonly T[] {
  if (!Array.isArray(value)) invalid("PLAN_INTEGRITY_FAILURE", `${kind} payload is not an array`);
  const expected = lineage.filter((entry) => entry.kind === kind);
  if (value.length !== expected.length) {
    invalid("PLAN_INTEGRITY_FAILURE", `${kind} payload count does not match frozen lineage`);
  }
  return value.map((candidate, index) => {
    try {
      validate(candidate as T);
    } catch {
      invalid("PLAN_INTEGRITY_FAILURE", `${kind} payload failed engine validation`);
    }
    const definition = candidate as T & { readonly definitionId: string };
    const matched = expected.find(({ definitionKey }) => definitionKey === definition.definitionId);
    if (matched === undefined || canonicalHash(candidate) !== matched.executionDocumentHash) {
      invalid("PLAN_INTEGRITY_FAILURE", `${kind} payload does not match frozen lineage at ${index}`);
    }
    return cloneCanonical(candidate as T);
  });
}

function parseDefinitionDocuments<T>(
  values: readonly ResolvedGovernedDefinitionV2[],
  kind: ResolvedGovernedDefinitionV2["reference"]["kind"],
  validate: (definition: T) => unknown
): readonly T[] {
  return values
    .filter(({ reference }) => reference.kind === kind)
    .map((resolved) => {
      try {
        validate(resolved.executionDocument as unknown as T);
      } catch {
        invalid(
          "DEFINITION_EVIDENCE_MISMATCH",
          `Frozen ${kind} ${resolved.reference.definitionVersionId} failed engine validation`
        );
      }
      return cloneCanonical(resolved.executionDocument as unknown as T);
    });
}

/**
 * Public preflight used by registry composition tests and future adapters.
 * It accepts only definitions whose declared grain and measure semantics are
 * exactly the ones implemented by the deterministic v1 family engine.
 */
export function assertPortfolioSurveillanceMetricCompatibilityV1(
  definition: MetricDefinitionV1
): void {
  try {
    validateMetricDefinitionV1(definition);
  } catch {
    invalid(
      "DEFINITION_EVIDENCE_MISMATCH",
      `Metric ${definition.definitionId} failed engine definition validation`
    );
  }
  validateMetricExecutionCompatibility(definition);
}

function validateMetricExecutionCompatibility(definition: MetricDefinitionV1): void {
  if (definition.unit !== "ratio") {
    invalid(
      "DEFINITION_EVIDENCE_MISMATCH",
      `Metric ${definition.definitionId} must declare ratio as its analytical family unit`
    );
  }
  if (definition.numerator.predicate !== undefined || definition.denominator?.predicate !== undefined) {
    invalid(
      "UNSUPPORTED_DEFINITION",
      `Metric ${definition.definitionId} uses measure predicates that the v1 engine does not execute`
    );
  }
  const config = definition.configuration;
  let allowedFields: readonly string[];
  let temporal: readonly MetricDefinitionV1["temporalSemantics"][];
  let windows: readonly MetricDefinitionV1["window"]["kind"][];
  let expectedNumeratorField: string | undefined;
  let expectedDenominatorField: string | undefined;
  let expectedGrain: MetricDefinitionV1["grain"] = "loan";
  let expectedAggregation: MetricDefinitionV1["numerator"]["aggregation"] = "sum";
  switch (config.kind) {
    case "roll_cure":
      allowedFields = [config.balanceField, config.delinquencyField];
      temporal = ["transition"];
      windows = ["adjacent_periods"];
      expectedNumeratorField = config.balanceField;
      expectedDenominatorField = config.balanceField;
      break;
    case "default_ever":
      allowedFields = [config.balanceField, config.daysPastDueField, config.defaultFlagField];
      temporal = ["cumulative", "transition"];
      windows = ["adjacent_periods", "ever_to_date"];
      if (config.incidenceBasis === "balance") {
        expectedNumeratorField = config.balanceField;
        expectedDenominatorField = config.balanceField;
      } else {
        expectedAggregation = "count";
      }
      break;
    case "loss_recovery":
      allowedFields = [
        config.defaultDateField,
        config.denominatorField,
        config.grossLossField,
        config.recoveryField
      ];
      temporal = [config.flowSemantics === "period" ? "period_flow" : "cumulative"];
      windows = ["event_lag", "ever_to_date"];
      expectedNumeratorField = config.grossLossField;
      expectedDenominatorField = config.denominatorField;
      break;
    case "paydown_prepayment":
      allowedFields = [
        config.balanceField,
        ...(config.scheduledPrincipalField === undefined ? [] : [config.scheduledPrincipalField])
      ];
      temporal = ["transition"];
      windows = ["adjacent_periods"];
      expectedNumeratorField = config.balanceField;
      expectedDenominatorField = config.balanceField;
      break;
    case "rating_migration":
      allowedFields = [config.balanceField, config.ratingField];
      temporal = ["transition"];
      windows = ["adjacent_periods"];
      expectedNumeratorField = config.balanceField;
      expectedDenominatorField = config.balanceField;
      break;
    case "balance_utilization":
      allowedFields = [config.balanceField, config.commitmentField, config.originalBalanceField];
      temporal = ["point_in_time"];
      windows = ["ever_to_date", "snapshot"];
      expectedNumeratorField = config.balanceField;
      expectedDenominatorField = config.commitmentField;
      break;
    case "maturity_wall":
      allowedFields = [config.balanceField, config.maturityDateField];
      temporal = ["point_in_time"];
      windows = ["ever_to_date", "snapshot"];
      expectedNumeratorField = config.balanceField;
      expectedDenominatorField = config.balanceField;
      break;
    case "concentration":
      expectedGrain = "entity";
      allowedFields = [config.balanceField, config.dimensionField];
      temporal = ["point_in_time"];
      windows = ["ever_to_date", "snapshot"];
      expectedNumeratorField = config.balanceField;
      expectedDenominatorField = config.balanceField;
      break;
    case "period_comparison":
      allowedFields = [
        config.balanceField,
        ...(config.dimensionField === undefined ? [] : [config.dimensionField])
      ];
      temporal = ["transition"];
      windows = ["adjacent_periods"];
      expectedNumeratorField = config.balanceField;
      expectedDenominatorField = config.balanceField;
      break;
  }
  if (!temporal.includes(definition.temporalSemantics) || !windows.includes(definition.window.kind)) {
    invalid(
      "DEFINITION_EVIDENCE_MISMATCH",
      `Metric ${definition.definitionId} temporal or window semantics do not match ${config.kind}`
    );
  }
  if (definition.grain !== expectedGrain) {
    invalid(
      "DEFINITION_EVIDENCE_MISMATCH",
      `Metric ${definition.definitionId} grain does not match ${config.kind} execution`
    );
  }
  if (
    definition.numerator.aggregation !== expectedAggregation ||
    definition.denominator?.aggregation !== expectedAggregation
  ) {
    invalid(
      "DEFINITION_EVIDENCE_MISMATCH",
      `Metric ${definition.definitionId} measure aggregations do not match ${config.kind} execution`
    );
  }
  const declaredFields = [definition.numerator.field, definition.denominator?.field].filter(
    (field): field is string => field !== undefined
  );
  if (declaredFields.some((field) => !allowedFields.includes(field))) {
    invalid(
      "UNSUPPORTED_DEFINITION",
      `Metric ${definition.definitionId} declares a measure field the v1 family does not execute`
    );
  }
  if (
    expectedNumeratorField !== undefined &&
    definition.numerator.field !== expectedNumeratorField
  ) {
    invalid(
      "DEFINITION_EVIDENCE_MISMATCH",
      `Metric ${definition.definitionId} numerator does not match the executed family field`
    );
  }
  if (
    expectedDenominatorField !== undefined &&
    definition.denominator?.field !== expectedDenominatorField
  ) {
    invalid(
      "DEFINITION_EVIDENCE_MISMATCH",
      `Metric ${definition.definitionId} denominator does not match the executed family field`
    );
  }
  if (
    config.kind === "default_ever" &&
    config.incidenceBasis === "count" &&
    (definition.numerator.field !== undefined ||
      definition.denominator?.field !== undefined)
  ) {
    invalid(
      "DEFINITION_EVIDENCE_MISMATCH",
      `Metric ${definition.definitionId} count incidence measures do not match execution`
    );
  }
}

function validateSupportingDefinitions(
  metrics: readonly MetricDefinitionV1[],
  cohorts: readonly CohortDefinitionV1[],
  bins: readonly BinDefinitionV1[],
  entityResolutions: readonly EntityResolutionDefinitionV1[]
): void {
  const requiredCohorts = new Set<string>();
  const requiredBins = new Set<string>();
  const requiredResolutions = new Set<string>();
  for (const metric of metrics) {
    const config = metric.configuration;
    if (config.kind === "roll_cure") requiredBins.add(config.binDefinitionId);
    if (config.kind === "balance_utilization" && config.cohortDefinitionId !== undefined) {
      requiredCohorts.add(config.cohortDefinitionId);
    }
    if (config.kind === "concentration") {
      if (config.binDefinitionId !== undefined) requiredBins.add(config.binDefinitionId);
      if (config.entityResolutionDefinitionId !== undefined) {
        requiredResolutions.add(config.entityResolutionDefinitionId);
      }
      const policy = getCanonicalFieldPolicy(config.dimensionField);
      if (
        policy.directIdentifier &&
        config.entityResolutionDefinitionId === undefined
      ) {
        invalid(
          "DISCLOSURE_POLICY_VIOLATION",
          `Identifier concentration dimension ${config.dimensionField} requires entity resolution`
        );
      }
      if (
        policy.aggregationEligibility === "allowed" &&
        config.binDefinitionId === undefined
      ) {
        invalid(
          "DISCLOSURE_POLICY_VIOLATION",
          `Numeric concentration dimension ${config.dimensionField} requires a governed bin definition`
        );
      }
    }
  }
  exactSupportingSet(requiredCohorts, cohorts.map(({ definitionId }) => definitionId), "cohort");
  exactSupportingSet(requiredBins, bins.map(({ definitionId }) => definitionId), "bin");
  exactSupportingSet(
    requiredResolutions,
    entityResolutions.map(({ definitionId }) => definitionId),
    "entity-resolution"
  );
}

function validateMethodologyRequirements(
  requiredKinds: readonly string[],
  definitions: readonly ResolvedGovernedDefinitionV2[]
): void {
  const executableKinds = new Set(definitions.map(({ reference }) => reference.kind));
  if (!requiredKinds.includes("metric_definition")) {
    invalid("DEFINITION_EVIDENCE_MISMATCH", "Methodology must require metric definitions");
  }
  const supported = new Set([
    "metric_definition",
    "cohort_definition",
    "bin_definition",
    "entity_resolution_definition"
  ]);
  for (const kind of requiredKinds) {
    if (!supported.has(kind) || !executableKinds.has(kind as ResolvedGovernedDefinitionV2["reference"]["kind"])) {
      invalid(
        "UNSUPPORTED_DEFINITION",
        `Methodology requires unavailable portfolio-surveillance definition kind ${kind}`
      );
    }
  }
  for (const kind of executableKinds) {
    if (kind !== "methodology_bundle" && !requiredKinds.includes(kind)) {
      invalid(
        "DEFINITION_EVIDENCE_MISMATCH",
        `Frozen ${kind} was not declared by the methodology bundle`
      );
    }
  }
}

function toDefinitionLineage(
  resolved: ResolvedGovernedDefinitionV2
): PortfolioSurveillanceDefinitionLineageV1 {
  const reference = resolved.reference;
  if (!DefinitionLineageSchema.shape.kind.safeParse(reference.kind).success) {
    invalid("UNSUPPORTED_DEFINITION", `Definition kind ${reference.kind} is unsupported`);
  }
  return parseWithSchema(
    DefinitionLineageSchema,
    {
      kind: reference.kind,
      definitionVersionId: reference.definitionVersionId,
      definitionKey: reference.definitionKey,
      semanticVersion: reference.semanticVersion,
      versionHash: reference.versionHash,
      documentHash: reference.documentHash,
      approvalEventHash: reference.approvalEventHash,
      executionDocumentHash: canonicalHash(resolved.executionDocument)
    },
    "portfolio surveillance definition lineage"
  );
}

function toSourceLineage(
  source: LoadedSource,
  requestedFields: readonly string[]
): PortfolioSurveillanceSourceLineageV1 {
  const material = source.material;
  return parseWithSchema(
    SourceLineageSchema,
    {
      sourceReferenceKind: source.reference.kind,
      sourceReferenceId:
        source.reference.kind === "certification_manifest"
          ? source.reference.certificationManifestId
          : source.reference.longitudinalBundleId,
      longitudinalBundleHash: source.bundle?.bundleHash ?? null,
      materialHash: material.materialHash,
      datasetId: material.datasetId,
      source: material.source,
      scope: material.scope,
      authorizedPurpose: material.authorizedPurpose,
      authorizedFields: material.authorizedFields,
      authorizedFieldsHash: canonicalHash(material.authorizedFields),
      authorizedAggregateDimensionFields: material.authorizedAggregateDimensionFields,
      authorizedAggregateDimensionFieldsHash: canonicalHash(
        material.authorizedAggregateDimensionFields
      ),
      certificationManifestId: material.certificationManifestId,
      certificationManifestHash: material.certificationManifestHash,
      snapshotId: material.snapshot.snapshotId,
      snapshotHash: material.snapshot.snapshotHash,
      asOfDate: material.snapshot.asOfDate,
      normalizedArtifactId: material.normalizedArtifact.artifactId,
      normalizedArtifactContentHash: material.normalizedArtifact.contentHash,
      populationHash: material.populationHash,
      projectedPopulationHash: canonicalHash(
        projectRecords(material.snapshot.records, requestedFields)
      ),
      rowCount: material.rowCount
    },
    "portfolio surveillance source lineage"
  );
}

function selectedRevision(
  bundle: LongitudinalCertificationBundleV1,
  revisionSequence: number,
  periodSequence: number
): LongitudinalCertifiedRevisionV1 {
  const period = bundle.periods.find(({ sequence }) => sequence === periodSequence)!;
  const selected = period.revisions.find((revision) => revision.revisionSequence === revisionSequence);
  if (selected === undefined) {
    invalid("SOURCE_EVIDENCE_MISMATCH", "Longitudinal analytics selection did not resolve");
  }
  return selected;
}

function validateSourceFieldAuthorizations(
  sources: readonly LoadedSource[],
  purpose: string,
  requestedFields: readonly string[],
  disclosedSourceDimensionFields: readonly string[]
): void {
  for (const { material } of sources) {
    if (material.authorizedPurpose !== purpose) {
      invalid(
        "SOURCE_EVIDENCE_MISMATCH",
        "Certified source purpose does not match the authorized operation purpose"
      );
    }
    const authorized = new Set(material.authorizedFields);
    const unauthorized = requestedFields.filter((field) => !authorized.has(field));
    if (unauthorized.length > 0) {
      invalid(
        "DISCLOSURE_POLICY_VIOLATION",
        `Certified source field authorization does not cover: ${unauthorized.join(", ")}`
      );
    }
    const authorizedDimensions = new Set(material.authorizedAggregateDimensionFields);
    const unauthorizedDimensions = disclosedSourceDimensionFields.filter(
      (field) => !authorizedDimensions.has(field)
    );
    if (unauthorizedDimensions.length > 0) {
      invalid(
        "DISCLOSURE_POLICY_VIOLATION",
        `Certified aggregate-dimension authorization does not cover: ${unauthorizedDimensions.join(", ")}`
      );
    }
  }
}

function assertSelectedRevision(
  material: CertifiedSnapshotMaterialV1,
  bundle: LongitudinalCertificationBundleV1,
  selected: LongitudinalCertifiedRevisionV1
): void {
  if (
    material.tenantId !== bundle.tenantId ||
    material.datasetId !== bundle.datasetId ||
    canonicalJson(material.source) !== canonicalJson(bundle.source) ||
    canonicalJson(material.scope) !== canonicalJson(bundle.scope) ||
    material.certificationManifestId !== selected.certification.certificationManifestId ||
    material.certificationManifestHash !== selected.certification.certificationManifestHash ||
    material.populationHash !== selected.populationHash ||
    material.normalizedArtifact.artifactId !== selected.normalizedArtifact.artifactId ||
    material.normalizedArtifact.contentHash !== selected.normalizedArtifact.contentHash ||
    material.rowCount !== selected.rowCount ||
    material.snapshot.snapshotId !== selected.snapshot.snapshotId ||
    material.snapshot.snapshotHash !== selected.snapshot.snapshotHash ||
    material.snapshot.asOfDate !== selected.snapshot.asOfDate ||
    material.snapshot.certification.certifiedAt !== selected.certification.certifiedAt
  ) {
    invalid(
      "SOURCE_EVIDENCE_MISMATCH",
      "Loaded normalized snapshot does not match the longitudinal analytics selection"
    );
  }
}

function exactSupportingSet(
  expected: ReadonlySet<string>,
  actualValues: readonly string[],
  label: string
): void {
  const actual = new Set(actualValues);
  if (
    actual.size !== actualValues.length ||
    expected.size !== actual.size ||
    [...expected].some((id) => !actual.has(id))
  ) {
    invalid(
      "DEFINITION_EVIDENCE_MISMATCH",
      `Frozen ${label} definitions must exactly match metric dependencies`
    );
  }
}

function legacyMethodologyVersion(version: string): number {
  const match = /^(0|[1-9]\d*)\.0\.0$/u.exec(version);
  if (match === null) {
    invalid(
      "UNSUPPORTED_DEFINITION",
      "The v1 surveillance engine can execute only methodology semantic versions with zero minor and patch components"
    );
  }
  const value = Number(match[1]);
  if (!Number.isSafeInteger(value) || value < 1 || value > 1_000_000) {
    invalid("UNSUPPORTED_DEFINITION", "Methodology major version is outside the v1 engine bound");
  }
  return value;
}

function collectFilterFields(fields: Set<string>, expression: FilterExpressionV1): void {
  if ("clauses" in expression) {
    for (const clause of expression.clauses) collectFilterFields(fields, clause);
    return;
  }
  fields.add(expression.field);
}

function addSupportingBinField(
  fields: Set<string>,
  definitions: ReadonlyMap<string, BinDefinitionV1>,
  definitionId: string
): void {
  const definition = definitions.get(definitionId);
  if (definition !== undefined) fields.add(definition.field);
}

function planningContext(
  value: AnalysisOperationPlanningContextV2
): Readonly<{ tenantId: string; purpose: string }> {
  return deepFreeze({
    tenantId: identifierValue(value.tenantId, "tenantId"),
    purpose: purposeValue(value.purpose)
  });
}

function sourceReferenceKey(reference: PortfolioSurveillanceSourceReferenceV1): string {
  return reference.kind === "certification_manifest"
    ? `${reference.kind}:${reference.certificationManifestId}`
    : `${reference.kind}:${reference.longitudinalBundleId}`;
}

function compareDefinitionLineage(
  left: PortfolioSurveillanceDefinitionLineageV1,
  right: PortfolioSurveillanceDefinitionLineageV1
): number {
  return compare(left.kind, right.kind) || compare(left.definitionVersionId, right.definitionVersionId);
}

function compareEngineDefinition(
  left: { readonly definitionId: string; readonly version: number },
  right: { readonly definitionId: string; readonly version: number }
): number {
  return compare(left.definitionId, right.definitionId) || left.version - right.version;
}

function identifierArray(value: unknown, label: string, minimum: number, maximum: number): readonly string[] {
  const parsed = parseWithSchema(
    z.array(IdentifierSchema).min(minimum).max(maximum),
    value,
    label
  );
  if (new Set(parsed).size !== parsed.length || canonicalJson([...parsed].sort(compare)) !== canonicalJson(parsed)) {
    invalid("PLAN_INTEGRITY_FAILURE", `${label} must be unique and sorted`);
  }
  return parsed;
}

function identifierValue(value: unknown, label: string): string {
  return parseWithSchema(IdentifierSchema, value, label);
}

function purposeValue(value: unknown): string {
  return parseWithSchema(z.string().trim().min(1).max(512), value, "purpose");
}

function hashValue(value: unknown, label: string): Sha256Hash {
  return parseWithSchema(Sha256HashSchema, value, label);
}

function strictRecord(
  value: unknown,
  keys: readonly string[],
  label: string
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    invalid("PLAN_INTEGRITY_FAILURE", `${label} must be an object`);
  }
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort(compare);
  const expected = [...keys].sort(compare);
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    invalid("PLAN_INTEGRITY_FAILURE", `${label} contains missing or unsupported fields`);
  }
  return record;
}

function normalizeHash(value: string): Sha256Hash {
  return (value.startsWith("sha256:") ? value : `sha256:${value}`) as Sha256Hash;
}

function cellPopulationHashes(
  lineage: PortfolioSurveillanceResultV1["metrics"][number]["cells"][number]["lineage"]
): readonly Sha256Hash[] {
  const expanded = lineage as typeof lineage & {
    readonly numeratorPopulationHash: string;
    readonly denominatorPopulationHash: string;
  };
  return [
    normalizeHash(lineage.populationHash),
    normalizeHash(expanded.numeratorPopulationHash),
    normalizeHash(expanded.denominatorPopulationHash)
  ];
}

function bareHash(value: Sha256Hash): string {
  return value.slice("sha256:".length);
}

function toEngineSnapshot(
  snapshot: CertifiedSnapshotMaterialV1["snapshot"],
  requestedFields: readonly string[]
): CertifiedSurveillanceSnapshotV1 {
  return deepFreeze({
    ...snapshot,
    snapshotHash: bareHash(snapshot.snapshotHash),
    certification: {
      ...snapshot.certification,
      certificationHash: bareHash(snapshot.certification.certificationHash)
    },
    records: projectRecords(snapshot.records, requestedFields)
  });
}

function projectRecords(
  records: readonly Readonly<Record<string, CanonicalJsonValue>>[],
  requestedFields: readonly string[]
): readonly Readonly<Record<string, CanonicalJsonValue>>[] {
  const allowed = new Set(requestedFields);
  return deepFreeze(
    records.map((record) =>
      Object.fromEntries(
        Object.entries(record)
          .filter(([field]) => allowed.has(field))
          .sort(([left], [right]) => compare(left, right))
      )
    )
  );
}

function sortedUnique(values: readonly Sha256Hash[]): readonly Sha256Hash[] {
  return deepFreeze([...new Set(values)].sort(compare));
}

function sortedUniqueText(values: readonly string[]): readonly string[] {
  return deepFreeze([...new Set(values)].sort(compare));
}

function cloneCanonical<T>(value: T): T {
  return JSON.parse(canonicalJson(value)) as T;
}

function unique(
  values: readonly string[],
  context: z.RefinementCtx,
  path: readonly (string | number)[],
  message: string
): void {
  if (new Set(values).size !== values.length) {
    context.addIssue({ code: "custom", path: [...path], message });
  }
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function invalid(code: PortfolioSurveillanceOperationErrorCode, message: string): never {
  throw new PortfolioSurveillanceOperationError(code, message);
}

export type PortfolioSurveillanceFrozenDefinitionRequirementV1 =
  FrozenDefinitionRequirementV2;
export type PortfolioSurveillanceCanonicalRecordV1 = CanonicalSurveillanceRecord;
