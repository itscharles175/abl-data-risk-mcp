import { z } from "zod";

import { DictionaryBundleReferenceV1Schema } from "./bundles.js";
import {
  IdentifierSchema,
  IsoDateSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  canonicalJson,
  parseWithSchema
} from "./canonical.js";
import { SemanticVersionV2Schema } from "./governed-definition-v2.js";
import { MappingApplicationV1Schema, parseMappingApplicationV1 } from "./mapping-v2.js";

const SourceContractIdentityV1Schema = z
  .object({
    sourceContractId: IdentifierSchema,
    revision: z.number().int().positive().max(1_000_000),
    sourceContractHash: Sha256HashSchema
  })
  .strict();

const FrozenSourceContractDefinitionReferenceV1Schema = z
  .object({
    definitionVersionId: IdentifierSchema,
    definitionKey: IdentifierSchema,
    kind: z.literal("source_contract"),
    semanticVersion: SemanticVersionV2Schema,
    versionHash: Sha256HashSchema,
    documentHash: Sha256HashSchema,
    approvalEventHash: Sha256HashSchema
  })
  .strict();

const PublishedSourceContractV1Schema = z
  .object({
    definition: FrozenSourceContractDefinitionReferenceV1Schema,
    sourceContractId: IdentifierSchema,
    sourceKey: IdentifierSchema,
    revision: z.number().int().positive().max(1_000_000),
    sourceContractHash: Sha256HashSchema
  })
  .strict();

const SnapshotCorrectionV1Schema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("original") }).strict(),
  z
    .object({
      kind: z.literal("correction"),
      correctsSnapshotId: IdentifierSchema,
      correctsSnapshotHash: Sha256HashSchema,
      correctionSequence: z.number().int().positive().max(1_000_000),
      reasonCode: IdentifierSchema,
      reason: z.string().min(1).max(2_000),
      detectedAt: IsoTimestampSchema
    })
    .strict()
]);

const PublishedDatasetSnapshotV2Schema = z
  .object({
    snapshotId: IdentifierSchema,
    snapshotHash: Sha256HashSchema,
    sourceContract: SourceContractIdentityV1Schema,
    delivery: z
      .object({
        mode: z.enum(["postgresql_pull", "managed_upload", "object_storage"]),
        deliveredContentHash: Sha256HashSchema,
        immutableSourceVersion: z.string().min(1).max(1_024).optional()
      })
      .strict(),
    asOfDate: IsoDateSchema,
    knowledge: z
      .object({
        sourceObservedAt: IsoTimestampSchema,
        extractedAt: IsoTimestampSchema,
        receivedAt: IsoTimestampSchema,
        persistedAt: IsoTimestampSchema
      })
      .strict(),
    hashes: z
      .object({
        contentHash: Sha256HashSchema,
        schemaHash: Sha256HashSchema,
        catalogHash: Sha256HashSchema,
        parserHash: Sha256HashSchema,
        extractionHash: Sha256HashSchema
      })
      .strict(),
    rowCount: z.number().int().min(0).max(1_000_000),
    byteCount: z.number().int().min(0).max(10_000_000_000),
    correction: SnapshotCorrectionV1Schema
  })
  .strict()
  .superRefine((value, context) => {
    if (value.delivery.deliveredContentHash !== value.hashes.contentHash) {
      issue(context, ["delivery", "deliveredContentHash"], "must match the snapshot content hash");
    }
    if (value.delivery.mode === "object_storage" && value.delivery.immutableSourceVersion === undefined) {
      issue(context, ["delivery", "immutableSourceVersion"], "is required for object storage");
    }
    if (value.delivery.mode !== "object_storage" && value.delivery.immutableSourceVersion !== undefined) {
      issue(context, ["delivery", "immutableSourceVersion"], "is only valid for object storage");
    }
    const knowledge = [
      value.knowledge.sourceObservedAt,
      value.knowledge.extractedAt,
      value.knowledge.receivedAt,
      value.knowledge.persistedAt
    ];
    if (knowledge.some((timestamp, index) => index > 0 && timestamp < knowledge[index - 1]!)) {
      issue(context, ["knowledge"], "timestamps must be chronological");
    }
  });

const PublishedMappingSpecV2Schema = z
  .object({
    mappingSpecId: IdentifierSchema,
    mappingKey: IdentifierSchema,
    revision: z.number().int().positive().max(1_000_000),
    mappingSpecHash: Sha256HashSchema,
    sourceContract: SourceContractIdentityV1Schema,
    dictionaryBundle: DictionaryBundleReferenceV1Schema
  })
  .strict();

const DatasetScopeBindingBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    bindingId: IdentifierSchema,
    tenantId: IdentifierSchema,
    datasetId: IdentifierSchema,
    sourceContract: SourceContractIdentityV1Schema,
    scope: z
      .object({
        scopeType: z.enum(["portfolio", "facility"]),
        scopeId: IdentifierSchema
      })
      .strict(),
    boundAt: IsoTimestampSchema
  })
  .strict();

export const DatasetScopeBindingV1Schema =
  DatasetScopeBindingBodyV1Schema.extend({ bindingHash: Sha256HashSchema }).strict();

export type DatasetScopeBindingV1 = Readonly<z.infer<typeof DatasetScopeBindingV1Schema>>;

const DataPopulationCertificationBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    populationId: IdentifierSchema,
    snapshotId: IdentifierSchema,
    snapshotHash: Sha256HashSchema,
    mappingApplicationId: IdentifierSchema,
    mappingApplicationHash: Sha256HashSchema,
    populationHash: Sha256HashSchema,
    fieldSetHash: Sha256HashSchema,
    rowCount: z.number().int().min(0).max(1_000_000),
    dataQuality: z
      .object({
        runId: IdentifierSchema,
        rulesetId: IdentifierSchema,
        rulesetHash: Sha256HashSchema,
        resultHash: Sha256HashSchema,
        publicationDecision: z.literal("publish"),
        blockerCodes: z.array(IdentifierSchema).max(256)
      })
      .strict(),
    reconciliation: z
      .object({
        reconciliationId: IdentifierSchema,
        definitionHash: Sha256HashSchema,
        resultHash: Sha256HashSchema,
        passed: z.literal(true),
        populationHash: Sha256HashSchema
      })
      .strict(),
    certifiedBy: IdentifierSchema,
    certifiedAt: IsoTimestampSchema
  })
  .strict()
  .superRefine((value, context) => {
    if (value.dataQuality.blockerCodes.length !== 0) {
      issue(context, ["dataQuality", "blockerCodes"], "published population cannot have blockers");
    }
    if (value.reconciliation.populationHash !== value.populationHash) {
      issue(context, ["reconciliation", "populationHash"], "must match the certified population hash");
    }
  });

export const DataPopulationCertificationV1Schema =
  DataPopulationCertificationBodyV1Schema.extend({ certificationHash: Sha256HashSchema }).strict();

export type DataPopulationCertificationV1 = Readonly<
  z.infer<typeof DataPopulationCertificationV1Schema>
>;

const CertificationManifestBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    certificationManifestId: IdentifierSchema,
    evidenceFormat: z.enum(["legacy_control_v1", "modern_snapshot_v2"]),
    snapshotId: IdentifierSchema,
    snapshotHash: Sha256HashSchema,
    populationId: IdentifierSchema,
    populationCertificationHash: Sha256HashSchema,
    mappingApplicationId: IdentifierSchema,
    mappingApplicationHash: Sha256HashSchema,
    normalizedArtifactId: IdentifierSchema,
    normalizedArtifactContentHash: Sha256HashSchema,
    dataQualityResultHash: Sha256HashSchema,
    reconciliationResultHash: Sha256HashSchema,
    populationHash: Sha256HashSchema,
    rowCount: z.number().int().min(0).max(1_000_000),
    certifiedBy: IdentifierSchema,
    certifiedAt: IsoTimestampSchema
  })
  .strict();

export const CertificationManifestPublicationV1Schema =
  CertificationManifestBodyV1Schema.extend({ certificationManifestHash: Sha256HashSchema }).strict();

export type CertificationManifestPublicationV1 = Readonly<
  z.infer<typeof CertificationManifestPublicationV1Schema>
>;

const NormalizedArtifactPublicationV1Schema = z
  .object({
    artifactId: IdentifierSchema,
    kind: z.literal("normalized_snapshot"),
    mediaType: z.literal("application/json"),
    contentHash: Sha256HashSchema,
    byteLength: z.number().int().min(0).max(100_000_000),
    uri: z.string().min(1).max(2_048),
    metadataHash: Sha256HashSchema,
    rowCount: z.number().int().min(0).max(1_000_000),
    populationHash: Sha256HashSchema,
    fieldSetHash: Sha256HashSchema
  })
  .strict();

const CertifiedSnapshotPublicationBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    publicationId: IdentifierSchema,
    tenantId: IdentifierSchema,
    datasetId: IdentifierSchema,
    scope: z
      .object({
        scopeType: z.enum(["portfolio", "facility"]),
        scopeId: IdentifierSchema
      })
      .strict(),
    datasetBinding: DatasetScopeBindingV1Schema,
    sourceContract: PublishedSourceContractV1Schema,
    snapshot: PublishedDatasetSnapshotV2Schema,
    certification: CertificationManifestPublicationV1Schema,
    population: DataPopulationCertificationV1Schema,
    mappingSpec: PublishedMappingSpecV2Schema,
    mappingApplication: MappingApplicationV1Schema,
    normalizedArtifact: NormalizedArtifactPublicationV1Schema,
    publishedBy: IdentifierSchema,
    publishedAt: IsoTimestampSchema
  })
  .strict()
  .superRefine((value, context) => {
    const population = value.population;
    const mapping = value.mappingApplication;
    const certification = value.certification;
    const normalized = value.normalizedArtifact;
    for (const [path, tenantId] of [
      [["certification", "tenantId"], certification.tenantId],
      [["population", "tenantId"], population.tenantId],
      [["mappingApplication", "tenantId"], mapping.tenantId]
    ] as const) {
      equal(tenantId, value.tenantId, context, path);
    }
    equal(value.sourceContract.definition.definitionKey, value.sourceContract.sourceKey, context, ["sourceContract", "definition", "definitionKey"]);
    const sourceIdentity = {
      sourceContractId: value.sourceContract.sourceContractId,
      revision: value.sourceContract.revision,
      sourceContractHash: value.sourceContract.sourceContractHash
    };
    if (canonicalJson(value.snapshot.sourceContract) !== canonicalJson(sourceIdentity)) {
      issue(context, ["snapshot", "sourceContract"], "must match the frozen source contract");
    }
    if (canonicalJson(value.mappingSpec.sourceContract) !== canonicalJson(sourceIdentity)) {
      issue(context, ["mappingSpec", "sourceContract"], "must match the frozen source contract");
    }
    equal(value.datasetBinding.tenantId, value.tenantId, context, ["datasetBinding", "tenantId"]);
    equal(value.datasetBinding.datasetId, value.datasetId, context, ["datasetBinding", "datasetId"]);
    if (canonicalJson(value.datasetBinding.scope) !== canonicalJson(value.scope)) {
      issue(context, ["datasetBinding", "scope"], "must match the published data scope");
    }
    if (canonicalJson(value.datasetBinding.sourceContract) !== canonicalJson(sourceIdentity)) {
      issue(context, ["datasetBinding", "sourceContract"], "must match the frozen source contract");
    }
    if (value.datasetBinding.boundAt > value.snapshot.knowledge.persistedAt) {
      issue(context, ["datasetBinding", "boundAt"], "cannot be after snapshot persistence");
    }

    equal(population.snapshotId, value.snapshot.snapshotId, context, ["population", "snapshotId"]);
    equal(population.snapshotHash, value.snapshot.snapshotHash, context, ["population", "snapshotHash"]);
    equal(population.rowCount, value.snapshot.rowCount, context, ["population", "rowCount"]);
    equal(population.populationId, certification.populationId, context, ["certification", "populationId"]);
    equal(population.certificationHash, certification.populationCertificationHash, context, ["certification", "populationCertificationHash"]);
    equal(population.populationHash, certification.populationHash, context, ["certification", "populationHash"]);
    equal(population.populationHash, normalized.populationHash, context, ["normalizedArtifact", "populationHash"]);
    equal(population.fieldSetHash, normalized.fieldSetHash, context, ["normalizedArtifact", "fieldSetHash"]);
    equal(population.dataQuality.resultHash, certification.dataQualityResultHash, context, ["certification", "dataQualityResultHash"]);
    equal(population.reconciliation.resultHash, certification.reconciliationResultHash, context, ["certification", "reconciliationResultHash"]);
    equal(population.certifiedBy, certification.certifiedBy, context, ["certification", "certifiedBy"]);
    equal(population.certifiedAt, certification.certifiedAt, context, ["certification", "certifiedAt"]);

    equal(mapping.mappingApplicationId, certification.mappingApplicationId, context, ["certification", "mappingApplicationId"]);
    equal(mapping.mappingApplicationHash, certification.mappingApplicationHash, context, ["certification", "mappingApplicationHash"]);
    equal(population.mappingApplicationId, mapping.mappingApplicationId, context, ["population", "mappingApplicationId"]);
    equal(population.mappingApplicationHash, mapping.mappingApplicationHash, context, ["population", "mappingApplicationHash"]);
    equal(mapping.mappingSpec.mappingSpecId, value.mappingSpec.mappingSpecId, context, ["mappingApplication", "mappingSpec", "mappingSpecId"]);
    equal(mapping.mappingSpec.revision, value.mappingSpec.revision, context, ["mappingApplication", "mappingSpec", "revision"]);
    equal(mapping.mappingSpec.mappingSpecHash, value.mappingSpec.mappingSpecHash, context, ["mappingApplication", "mappingSpec", "mappingSpecHash"]);
    if (canonicalJson(mapping.dictionaryBundle) !== canonicalJson(value.mappingSpec.dictionaryBundle)) {
      issue(context, ["mappingApplication", "dictionaryBundle"], "must match the frozen mapping dictionary bundle");
    }
    equal(mapping.snapshot.snapshotId, value.snapshot.snapshotId, context, ["mappingApplication", "snapshot", "snapshotId"]);
    equal(mapping.snapshot.snapshotHash, value.snapshot.snapshotHash, context, ["mappingApplication", "snapshot", "snapshotHash"]);
    equal(mapping.snapshot.contentHash, value.snapshot.hashes.contentHash, context, ["mappingApplication", "snapshot", "contentHash"]);
    equal(mapping.outputPopulationHash, population.populationHash, context, ["mappingApplication", "outputPopulationHash"]);
    equal(mapping.outputRowCount, population.rowCount, context, ["mappingApplication", "outputRowCount"]);

    equal(normalized.artifactId, certification.normalizedArtifactId, context, ["normalizedArtifact", "artifactId"]);
    equal(normalized.contentHash, certification.normalizedArtifactContentHash, context, ["normalizedArtifact", "contentHash"]);
    equal(normalized.rowCount, population.rowCount, context, ["normalizedArtifact", "rowCount"]);
    equal(certification.snapshotId, value.snapshot.snapshotId, context, ["certification", "snapshotId"]);
    equal(certification.snapshotHash, value.snapshot.snapshotHash, context, ["certification", "snapshotHash"]);
    equal(certification.rowCount, population.rowCount, context, ["certification", "rowCount"]);
    if (value.snapshot.asOfDate > certification.certifiedAt.slice(0, 10)) {
      issue(context, ["certification", "certifiedAt"], "cannot precede the snapshot as-of date");
    }
    if (value.snapshot.knowledge.persistedAt > certification.certifiedAt) {
      issue(context, ["certification", "certifiedAt"], "cannot precede snapshot persistence");
    }
    if (mapping.appliedAt > certification.certifiedAt) {
      issue(context, ["mappingApplication", "appliedAt"], "cannot follow certification");
    }
    if (
      value.snapshot.correction.kind === "correction" &&
      value.snapshot.correction.detectedAt > certification.certifiedAt
    ) {
      issue(context, ["snapshot", "correction", "detectedAt"], "cannot follow certification");
    }
    if (certification.certifiedAt > value.publishedAt) {
      issue(context, ["publishedAt"], "cannot precede certification");
    }
  });

export const CertifiedSnapshotPublicationV1Schema =
  CertifiedSnapshotPublicationBodyV1Schema.extend({ publicationHash: Sha256HashSchema }).strict();

export type CertifiedSnapshotPublicationV1 = Readonly<z.infer<typeof CertifiedSnapshotPublicationV1Schema>>;
export type CertifiedSnapshotPublicationV1Input = Readonly<z.input<typeof CertifiedSnapshotPublicationBodyV1Schema>>;

export function parseDatasetScopeBindingV1(value: unknown): DatasetScopeBindingV1 {
  const parsed = parseWithSchema(DatasetScopeBindingV1Schema, value, "DatasetScopeBindingV1");
  const { bindingHash, ...body } = parsed;
  assertCanonicalHash(body, bindingHash, "DatasetScopeBindingV1");
  return parsed;
}

export function parseDataPopulationCertificationV1(value: unknown): DataPopulationCertificationV1 {
  const parsed = parseWithSchema(DataPopulationCertificationV1Schema, value, "DataPopulationCertificationV1");
  const { certificationHash, ...body } = parsed;
  assertCanonicalHash(body, certificationHash, "DataPopulationCertificationV1");
  return parsed;
}

export function parseCertificationManifestPublicationV1(value: unknown): CertificationManifestPublicationV1 {
  const parsed = parseWithSchema(CertificationManifestPublicationV1Schema, value, "CertificationManifestPublicationV1");
  const { certificationManifestHash, ...body } = parsed;
  assertCanonicalHash(body, certificationManifestHash, "CertificationManifestPublicationV1");
  return parsed;
}

export function createCertifiedSnapshotPublicationV1(input: CertifiedSnapshotPublicationV1Input): CertifiedSnapshotPublicationV1 {
  const body = parseWithSchema(CertifiedSnapshotPublicationBodyV1Schema, input, "CertifiedSnapshotPublicationV1");
  return parseCertifiedSnapshotPublicationV1({ ...body, publicationHash: canonicalHash(body) });
}

export function parseCertifiedSnapshotPublicationV1(value: unknown): CertifiedSnapshotPublicationV1 {
  const parsed = parseWithSchema(CertifiedSnapshotPublicationV1Schema, value, "CertifiedSnapshotPublicationV1");
  parseDatasetScopeBindingV1(parsed.datasetBinding);
  parseCertificationManifestPublicationV1(parsed.certification);
  parseDataPopulationCertificationV1(parsed.population);
  parseMappingApplicationV1(parsed.mappingApplication);
  const { publicationHash, ...body } = parsed;
  assertCanonicalHash(body, publicationHash, "CertifiedSnapshotPublicationV1");
  return parsed;
}

function equal(actual: string | number, expected: string | number, context: z.RefinementCtx, path: readonly PropertyKey[]): void {
  if (actual !== expected) issue(context, path, "does not match its certified lineage");
}

function issue(context: z.RefinementCtx, path: readonly PropertyKey[], message: string): void {
  context.addIssue({ code: "custom", path: [...path], message });
}
