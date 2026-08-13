import { z } from "zod";

import {
  ContractValidationError,
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  assertTimestampOrder,
  canonicalHash,
  canonicalJson,
  parseWithSchema
} from "./canonical.js";
import {
  CertificationManifestPublicationV1Schema,
  DataPopulationCertificationV1Schema,
  parseCertificationManifestPublicationV1,
  parseDataPopulationCertificationV1
} from "./certified-snapshot-publication-v1.js";
import {
  MappingApplicationV1Schema,
  MappingSpecV2Schema,
  assertMappingApplicationBindings,
  parseMappingApplicationV1,
  parseMappingSpecV2
} from "./mapping-v2.js";
import {
  normalizedSnapshotArtifactByteLength,
  normalizedSnapshotArtifactContentHash,
  parseNormalizedSnapshotArtifactV2,
  type NormalizedSnapshotArtifactV2
} from "./normalized-snapshot-artifact-v2.js";
import type { StoredArtifact } from "../control/artifacts.js";

const ArtifactStorageReferenceV1Schema = z
  .object({
    tenantId: IdentifierSchema,
    artifactId: IdentifierSchema,
    kind: z.literal("normalized_snapshot"),
    mediaType: z.literal("application/json"),
    artifactContractVersion: z.literal(2),
    artifactHash: Sha256HashSchema,
    contentHash: Sha256HashSchema,
    byteLength: z.number().int().positive().max(1_000_000_000),
    keyId: IdentifierSchema,
    uri: z.string().regex(/^abl-artifact:\/\/[a-f0-9]{64}$/u),
    snapshotId: IdentifierSchema,
    snapshotHash: Sha256HashSchema,
    normalizedPopulationId: IdentifierSchema,
    mappingApplicationId: IdentifierSchema,
    mappingApplicationHash: Sha256HashSchema,
    populationHash: Sha256HashSchema,
    fieldSetHash: Sha256HashSchema,
    rowCount: z.number().int().min(0).max(1_000_000),
    createdAt: IsoTimestampSchema
  })
  .strict();

export const CertifiedSnapshotArtifactMetadataV1Schema = ArtifactStorageReferenceV1Schema;
export type CertifiedSnapshotArtifactMetadataV1 = Readonly<
  z.infer<typeof CertifiedSnapshotArtifactMetadataV1Schema>
>;

const CertifiedSnapshotEvidenceBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    certification: CertificationManifestPublicationV1Schema,
    population: DataPopulationCertificationV1Schema,
    mappingSpec: MappingSpecV2Schema,
    mappingApplication: MappingApplicationV1Schema,
    normalizedArtifact: CertifiedSnapshotArtifactMetadataV1Schema,
    dataQualityPopulation: z
      .object({
        populationHash: Sha256HashSchema,
        fieldSetHash: Sha256HashSchema,
        rowCount: z.number().int().min(0).max(1_000_000)
      })
      .strict(),
    recordedAt: IsoTimestampSchema
  })
  .strict()
  .superRefine((value, context) => {
    const certification = value.certification;
    const population = value.population;
    const mapping = value.mappingApplication;
    const artifact = value.normalizedArtifact;
    for (const [path, tenantId] of [
      [["certification", "tenantId"], certification.tenantId],
      [["population", "tenantId"], population.tenantId],
      [["mappingSpec", "tenantId"], value.mappingSpec.tenantId],
      [["mappingApplication", "tenantId"], mapping.tenantId]
    ] as const) {
      if (tenantId !== value.tenantId) issue(context, path, "must match the evidence tenant");
    }
    same(population.snapshotId, certification.snapshotId, context, ["population", "snapshotId"]);
    same(population.snapshotHash, certification.snapshotHash, context, ["population", "snapshotHash"]);
    same(population.populationId, certification.populationId, context, ["population", "populationId"]);
    same(population.certificationHash, certification.populationCertificationHash, context, ["population", "certificationHash"]);
    same(population.populationHash, certification.populationHash, context, ["population", "populationHash"]);
    same(population.rowCount, certification.rowCount, context, ["population", "rowCount"]);
    same(population.dataQuality.resultHash, certification.dataQualityResultHash, context, ["population", "dataQuality", "resultHash"]);
    same(population.reconciliation.resultHash, certification.reconciliationResultHash, context, ["population", "reconciliation", "resultHash"]);
    same(population.certifiedBy, certification.certifiedBy, context, ["population", "certifiedBy"]);
    same(population.certifiedAt, certification.certifiedAt, context, ["population", "certifiedAt"]);

    same(mapping.snapshot.snapshotId, certification.snapshotId, context, ["mappingApplication", "snapshot", "snapshotId"]);
    same(mapping.snapshot.snapshotHash, certification.snapshotHash, context, ["mappingApplication", "snapshot", "snapshotHash"]);
    same(mapping.mappingApplicationId, certification.mappingApplicationId, context, ["mappingApplication", "mappingApplicationId"]);
    same(mapping.mappingApplicationHash, certification.mappingApplicationHash, context, ["mappingApplication", "mappingApplicationHash"]);
    same(mapping.outputPopulationHash, population.populationHash, context, ["mappingApplication", "outputPopulationHash"]);
    same(mapping.outputRowCount, population.rowCount, context, ["mappingApplication", "outputRowCount"]);

    same(artifact.artifactId, certification.normalizedArtifactId, context, ["normalizedArtifact", "artifactId"]);
    same(artifact.tenantId, value.tenantId, context, ["normalizedArtifact", "tenantId"]);
    same(artifact.contentHash, certification.normalizedArtifactContentHash, context, ["normalizedArtifact", "contentHash"]);
    same(artifact.snapshotId, certification.snapshotId, context, ["normalizedArtifact", "snapshotId"]);
    same(artifact.snapshotHash, certification.snapshotHash, context, ["normalizedArtifact", "snapshotHash"]);
    same(artifact.normalizedPopulationId, population.populationId, context, ["normalizedArtifact", "normalizedPopulationId"]);
    same(artifact.mappingApplicationId, mapping.mappingApplicationId, context, ["normalizedArtifact", "mappingApplicationId"]);
    same(artifact.mappingApplicationHash, mapping.mappingApplicationHash, context, ["normalizedArtifact", "mappingApplicationHash"]);
    same(artifact.populationHash, population.populationHash, context, ["normalizedArtifact", "populationHash"]);
    same(artifact.fieldSetHash, population.fieldSetHash, context, ["normalizedArtifact", "fieldSetHash"]);
    same(artifact.rowCount, population.rowCount, context, ["normalizedArtifact", "rowCount"]);
    same(value.dataQualityPopulation.populationHash, population.populationHash, context, ["dataQualityPopulation", "populationHash"]);
    same(value.dataQualityPopulation.fieldSetHash, population.fieldSetHash, context, ["dataQualityPopulation", "fieldSetHash"]);
    same(value.dataQualityPopulation.rowCount, population.rowCount, context, ["dataQualityPopulation", "rowCount"]);
    if (certification.evidenceFormat !== "modern_snapshot_v2") {
      issue(context, ["certification", "evidenceFormat"], "must use modern_snapshot_v2 evidence");
    }
    if (mapping.appliedAt > artifact.createdAt) {
      issue(context, ["normalizedArtifact", "createdAt"], "cannot precede mapping application");
    }
    if (artifact.createdAt > certification.certifiedAt) {
      issue(context, ["normalizedArtifact", "createdAt"], "cannot follow certification");
    }
    if (certification.certifiedAt > value.recordedAt) {
      issue(context, ["recordedAt"], "cannot precede certification");
    }
  });

export const CertifiedSnapshotEvidenceRecordV1Schema =
  CertifiedSnapshotEvidenceBodyV1Schema.extend({ evidenceHash: Sha256HashSchema }).strict();

export type CertifiedSnapshotEvidenceRecordV1 = Readonly<
  z.infer<typeof CertifiedSnapshotEvidenceRecordV1Schema>
>;
export type CertifiedSnapshotEvidenceRecordV1Input = Readonly<
  z.input<typeof CertifiedSnapshotEvidenceBodyV1Schema>
>;

export interface CreateCertifiedSnapshotArtifactMetadataV1Input {
  readonly artifact: NormalizedSnapshotArtifactV2;
  /** Exact metadata returned by tenant-scoped ArtifactStore.getJson for this payload. */
  readonly loadedStoredArtifact: StoredArtifact;
}

export function createCertifiedSnapshotArtifactMetadataV1(
  input: CreateCertifiedSnapshotArtifactMetadataV1Input
): CertifiedSnapshotArtifactMetadataV1 {
  canonicalJson(input);
  const artifact = parseNormalizedSnapshotArtifactV2(input.artifact);
  const stored = input.loadedStoredArtifact;
  if (
    !stored ||
    typeof stored !== "object" ||
    Array.isArray(stored) ||
    canonicalJson(Object.keys(stored).sort()) !==
      canonicalJson([
        "artifactId",
        "byteLength",
        "contentHash",
        "keyId",
        "kind",
        "mediaType",
        "tenantBinding",
        "uri"
      ])
  ) {
    invariant("Normalized snapshot storage metadata has an unsupported shape");
  }
  const expectedContentHash = normalizedSnapshotArtifactContentHash(artifact).slice("sha256:".length);
  const expectedByteLength = normalizedSnapshotArtifactByteLength(artifact);
  if (
    !/^[a-f0-9]{64}$/u.test(stored.artifactId) ||
    !/^[a-f0-9]{64}$/u.test(stored.tenantBinding) ||
    !/^[a-f0-9]{64}$/u.test(stored.contentHash) ||
    stored.uri !== `abl-artifact://${stored.artifactId}` ||
    stored.kind !== "normalized_snapshot" ||
    stored.mediaType !== "application/json" ||
    stored.contentHash !== expectedContentHash ||
    stored.byteLength !== expectedByteLength
  ) {
    invariant("Normalized snapshot storage metadata does not match the exact canonical payload");
  }
  return parseWithSchema(
    CertifiedSnapshotArtifactMetadataV1Schema,
    {
      tenantId: artifact.tenantId,
      artifactId: stored.artifactId,
      kind: artifact.kind,
      mediaType: "application/json",
      artifactContractVersion: artifact.contractVersion,
      artifactHash: artifact.artifactHash,
      contentHash: `sha256:${stored.contentHash}`,
      byteLength: stored.byteLength,
      keyId: stored.keyId,
      uri: stored.uri,
      snapshotId: artifact.snapshot.snapshotId,
      snapshotHash: artifact.snapshot.snapshotHash,
      normalizedPopulationId: artifact.normalizedPopulationId,
      mappingApplicationId: artifact.mappingApplication.mappingApplicationId,
      mappingApplicationHash: artifact.mappingApplication.mappingApplicationHash,
      populationHash: artifact.populationHash,
      fieldSetHash: artifact.fieldSetHash,
      rowCount: artifact.rowCount,
      createdAt: artifact.createdAt
    },
    "CertifiedSnapshotArtifactMetadataV1"
  );
}

export function createCertifiedSnapshotEvidenceRecordV1(
  inputValue: CertifiedSnapshotEvidenceRecordV1Input
): CertifiedSnapshotEvidenceRecordV1 {
  canonicalJson(inputValue);
  const body = parseWithSchema(
    CertifiedSnapshotEvidenceBodyV1Schema,
    inputValue,
    "CertifiedSnapshotEvidenceRecordV1"
  );
  validateNestedEvidence(body);
  return parseCertifiedSnapshotEvidenceRecordV1({ ...body, evidenceHash: canonicalHash(body) });
}

export function parseCertifiedSnapshotEvidenceRecordV1(
  value: unknown
): CertifiedSnapshotEvidenceRecordV1 {
  canonicalJson(value);
  const parsed = parseWithSchema(
    CertifiedSnapshotEvidenceRecordV1Schema,
    value,
    "CertifiedSnapshotEvidenceRecordV1"
  );
  validateNestedEvidence(parsed);
  const { evidenceHash, ...body } = parsed;
  assertCanonicalHash(body, evidenceHash, "CertifiedSnapshotEvidenceRecordV1");
  return parsed;
}

function validateNestedEvidence(
  value: z.infer<typeof CertifiedSnapshotEvidenceBodyV1Schema>
): void {
  const certification = parseCertificationManifestPublicationV1(value.certification);
  const population = parseDataPopulationCertificationV1(value.population);
  const mappingSpec = parseMappingSpecV2(value.mappingSpec);
  const mappingApplication = parseMappingApplicationV1(value.mappingApplication);
  assertMappingApplicationBindings(mappingApplication, mappingSpec);
  if (mappingSpec.status !== "active") {
    invariant("Certified snapshot evidence requires an active mapping specification");
  }
  if (mappingSpec.approvedAt === undefined || mappingSpec.approvedAt > mappingApplication.appliedAt) {
    invariant("Mapping specification approval must precede its application");
  }
  assertTimestampOrder(
    mappingApplication.appliedAt,
    certification.certifiedAt,
    "mapping application time",
    "certification time"
  );
  if (population.dataQuality.blockerCodes.length !== 0) {
    invariant("Certified snapshot evidence cannot contain data-quality blockers");
  }
}

function same(
  actual: string | number | undefined,
  expected: string | number | undefined,
  context: z.RefinementCtx,
  path: readonly PropertyKey[]
): void {
  if (actual !== expected) issue(context, path, "does not match the authoritative evidence");
}

function issue(context: z.RefinementCtx, path: readonly PropertyKey[], message: string): void {
  context.addIssue({ code: "custom", path: [...path], message });
}

function invariant(message: string): never {
  throw new ContractValidationError("INVARIANT_VIOLATION", message);
}
