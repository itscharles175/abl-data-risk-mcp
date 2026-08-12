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

const SnapshotReferenceV2Schema = z
  .object({
    snapshotId: IdentifierSchema,
    snapshotHash: Sha256HashSchema,
    contentHash: Sha256HashSchema
  })
  .strict();

const MappingApplicationReferenceV1Schema = z
  .object({
    mappingApplicationId: IdentifierSchema,
    mappingApplicationHash: Sha256HashSchema,
    mappingSpecId: IdentifierSchema,
    mappingSpecHash: Sha256HashSchema
  })
  .strict();

const DataQualityEvidenceV1Schema = z
  .object({
    runId: IdentifierSchema,
    rulesetId: IdentifierSchema,
    rulesetHash: Sha256HashSchema,
    resultHash: Sha256HashSchema,
    publicationDecision: z.enum(["publish", "block"]),
    blockerCodes: z.array(IdentifierSchema).max(256)
  })
  .strict();

const ReconciliationEvidenceV1Schema = z
  .object({
    reconciliationId: IdentifierSchema,
    definitionHash: Sha256HashSchema,
    resultHash: Sha256HashSchema,
    passed: z.boolean(),
    populationHash: Sha256HashSchema
  })
  .strict();

const PopulationBodyShape = {
  contractVersion: z.literal(1),
  tenantId: IdentifierSchema,
  populationId: IdentifierSchema,
  populationKind: z.enum(["canonical_snapshot", "certified_sidecar"]),
  purpose: z.string().min(1).max(512),
  snapshot: SnapshotReferenceV2Schema,
  mappingApplication: MappingApplicationReferenceV1Schema,
  populationHash: Sha256HashSchema,
  fieldSetHash: Sha256HashSchema,
  rowCount: z.number().int().min(0),
  dataQuality: DataQualityEvidenceV1Schema,
  reconciliation: ReconciliationEvidenceV1Schema,
  certifiedBy: IdentifierSchema.optional(),
  certifiedAt: IsoTimestampSchema.optional(),
  blockedAt: IsoTimestampSchema.optional()
} as const;

const CertifiedPopulationBodyV1Schema = z
  .object({ ...PopulationBodyShape, certificationStatus: z.literal("certified") })
  .strict()
  .superRefine((value, context) => {
    if (value.dataQuality.publicationDecision !== "publish") {
      context.addIssue({ code: "custom", path: ["dataQuality"], message: "certified population requires publish decision" });
    }
    if (!value.reconciliation.passed) {
      context.addIssue({ code: "custom", path: ["reconciliation"], message: "certified population requires passing reconciliation" });
    }
    if (value.reconciliation.populationHash !== value.populationHash) {
      context.addIssue({ code: "custom", path: ["reconciliation", "populationHash"], message: "must match the certified population hash" });
    }
    if (value.certifiedBy === undefined || value.certifiedAt === undefined) {
      context.addIssue({ code: "custom", path: ["certifiedBy"], message: "certification evidence is required" });
    }
    if (value.blockedAt !== undefined) {
      context.addIssue({ code: "custom", path: ["blockedAt"], message: "certified population cannot be blocked" });
    }
  });

const BlockedPopulationBodyV1Schema = z
  .object({ ...PopulationBodyShape, certificationStatus: z.literal("blocked") })
  .strict()
  .superRefine((value, context) => {
    if (value.blockedAt === undefined) {
      context.addIssue({ code: "custom", path: ["blockedAt"], message: "blocked population requires blockedAt" });
    }
    if (value.certifiedBy !== undefined || value.certifiedAt !== undefined) {
      context.addIssue({ code: "custom", path: ["certifiedBy"], message: "blocked population cannot contain certification evidence" });
    }
  });

export const CertifiedInputPopulationV1Schema = CertifiedPopulationBodyV1Schema.extend({
  certificationHash: Sha256HashSchema
}).strict();

export const BlockedInputPopulationV1Schema = BlockedPopulationBodyV1Schema.extend({
  certificationHash: Sha256HashSchema
}).strict();

export const InputPopulationV1Schema = z.discriminatedUnion("certificationStatus", [
  CertifiedInputPopulationV1Schema,
  BlockedInputPopulationV1Schema
]);

export type CertifiedInputPopulationV1 = Readonly<
  z.infer<typeof CertifiedInputPopulationV1Schema>
>;
export type BlockedInputPopulationV1 = Readonly<z.infer<typeof BlockedInputPopulationV1Schema>>;
export type InputPopulationV1 = CertifiedInputPopulationV1 | BlockedInputPopulationV1;
export type CertifiedInputPopulationV1Input = Readonly<
  z.input<typeof CertifiedPopulationBodyV1Schema>
>;
export type BlockedInputPopulationV1Input = Readonly<z.input<typeof BlockedPopulationBodyV1Schema>>;

const DefinitionReferenceV1Schema = z
  .object({
    definitionId: IdentifierSchema,
    version: z.string().min(1).max(64),
    definitionHash: Sha256HashSchema
  })
  .strict();

const AnalysisInputLineageBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    analysisKind: z.enum(["monitoring", "borrowing_base", "portfolio_analysis"]),
    primary: InputPopulationV1Schema,
    sidecars: z.array(InputPopulationV1Schema).max(32),
    definitions: z.array(DefinitionReferenceV1Schema).min(1).max(128),
    derivationHash: Sha256HashSchema,
    assembledAt: IsoTimestampSchema
  })
  .strict()
  .superRefine((value, context) => {
    const populations = [value.primary, ...value.sidecars];
    if (populations.some((population) => population.tenantId !== value.tenantId)) {
      context.addIssue({ code: "custom", path: ["tenantId"], message: "all input populations must belong to the same tenant" });
    }
    if (value.primary.populationKind !== "canonical_snapshot") {
      context.addIssue({ code: "custom", path: ["primary", "populationKind"], message: "primary input must be canonical snapshot data" });
    }
    if (value.sidecars.some((population) => population.populationKind !== "certified_sidecar")) {
      context.addIssue({ code: "custom", path: ["sidecars"], message: "sidecar inputs must use certified_sidecar kind" });
    }
    const populationIds = populations.map((population) => population.populationId);
    if (new Set(populationIds).size !== populationIds.length) {
      context.addIssue({ code: "custom", path: ["sidecars"], message: "population ids must be unique" });
    }
    const definitionIds = value.definitions.map(
      (definition) => `${definition.definitionId}:${definition.version}:${definition.definitionHash}`
    );
    if (new Set(definitionIds).size !== definitionIds.length) {
      context.addIssue({ code: "custom", path: ["definitions"], message: "definition references must be unique" });
    }
  });

export const AnalysisInputLineageV1Schema = AnalysisInputLineageBodyV1Schema.extend({
  lineageHash: Sha256HashSchema
}).strict();

export type AnalysisInputLineageV1 = Readonly<z.infer<typeof AnalysisInputLineageV1Schema>>;
export type AnalysisInputLineageV1Input = Readonly<
  z.input<typeof AnalysisInputLineageBodyV1Schema>
>;

export type CertifiedAnalysisInputLineageV1 = AnalysisInputLineageV1 & {
  readonly primary: CertifiedInputPopulationV1;
  readonly sidecars: readonly CertifiedInputPopulationV1[];
};

export function createCertifiedInputPopulationV1(
  input: CertifiedInputPopulationV1Input
): CertifiedInputPopulationV1 {
  const body = parseWithSchema(
    CertifiedPopulationBodyV1Schema,
    input,
    "CertifiedInputPopulationV1"
  );
  return parseCertifiedInputPopulationV1({ ...body, certificationHash: canonicalHash(body) });
}

export function createBlockedInputPopulationV1(
  input: BlockedInputPopulationV1Input
): BlockedInputPopulationV1 {
  const body = parseWithSchema(BlockedPopulationBodyV1Schema, input, "BlockedInputPopulationV1");
  return parseBlockedInputPopulationV1({ ...body, certificationHash: canonicalHash(body) });
}

export function parseCertifiedInputPopulationV1(value: unknown): CertifiedInputPopulationV1 {
  const parsed = parseWithSchema(
    CertifiedInputPopulationV1Schema,
    value,
    "CertifiedInputPopulationV1"
  );
  const { certificationHash, ...body } = parsed;
  assertCanonicalHash(body, certificationHash, "CertifiedInputPopulationV1");
  return parsed;
}

export function parseBlockedInputPopulationV1(value: unknown): BlockedInputPopulationV1 {
  const parsed = parseWithSchema(
    BlockedInputPopulationV1Schema,
    value,
    "BlockedInputPopulationV1"
  );
  const { certificationHash, ...body } = parsed;
  assertCanonicalHash(body, certificationHash, "BlockedInputPopulationV1");
  return parsed;
}

export function createAnalysisInputLineageV1(
  input: AnalysisInputLineageV1Input
): AnalysisInputLineageV1 {
  const body = parseWithSchema(AnalysisInputLineageBodyV1Schema, input, "AnalysisInputLineageV1");
  for (const population of [body.primary, ...body.sidecars]) parseInputPopulation(population);
  return parseAnalysisInputLineageV1({ ...body, lineageHash: canonicalHash(body) });
}

export function parseAnalysisInputLineageV1(value: unknown): AnalysisInputLineageV1 {
  const parsed = parseWithSchema(AnalysisInputLineageV1Schema, value, "AnalysisInputLineageV1");
  for (const population of [parsed.primary, ...parsed.sidecars]) parseInputPopulation(population);
  const { lineageHash, ...body } = parsed;
  assertCanonicalHash(body, lineageHash, "AnalysisInputLineageV1");
  return parsed;
}

/** Mandatory gate for monitoring and borrowing-base engines. */
export function assertCertifiedAnalysisInputs(
  lineage: AnalysisInputLineageV1
): asserts lineage is CertifiedAnalysisInputLineageV1 {
  for (const population of [lineage.primary, ...lineage.sidecars]) {
    if (population.certificationStatus !== "certified") {
      throw new ContractValidationError(
        "INVARIANT_VIOLATION",
        `${lineage.analysisKind} cannot use uncertified population ${population.populationId}`
      );
    }
    parseCertifiedInputPopulationV1(population);
  }
}

function parseInputPopulation(population: InputPopulationV1): InputPopulationV1 {
  return population.certificationStatus === "certified"
    ? parseCertifiedInputPopulationV1(population)
    : parseBlockedInputPopulationV1(population);
}
