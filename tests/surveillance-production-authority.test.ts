import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import {
  canonicalHash,
  createCertifiedSnapshotArtifactMetadataV1,
  createCertifiedSnapshotEvidenceRecordV1,
  createDatasetSnapshotV2,
  createGovernedDatasetScopeBindingV1,
  createMappingApplicationV1,
  createMappingSpecV2,
  createNormalizedSnapshotArtifactV2,
  createSourceContractV1,
  parseSourceContractV1,
  type CertifiedSnapshotEvidenceRecordV1,
  type DatasetSnapshotV2,
  type Sha256Hash
} from "../src/contracts/index.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import {
  GovernedDefinitionV2Store,
  type GovernedDefinitionViewV2
} from "../src/control/governed-definitions-v2.js";
import { SurveillancePublicationCatalog } from "../src/control/surveillance-publications.js";
import { SqliteSurveillanceEvidenceRepositories } from "../src/repositories/sqlite-surveillance.js";
import { GovernedDefinitionV2Resolver } from "../src/services/governed-definition-v2-resolver.js";
import {
  RepositoryBackedSurveillanceSourcePublicationAuthorityV1,
  SurveillanceProductionAuthorityError
} from "../src/services/surveillance-production-authority.js";
import {
  SurveillanceSourcePublicationError,
  SurveillanceSourcePublicationService
} from "../src/services/surveillance-source-publication.js";

const directories: string[] = [];
const HASH = (label: string): Sha256Hash => canonicalHash(label);

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("repository-backed authority publishes only reloaded tenant evidence and governed scope", async () => {
  const fixture = await productionFixture();
  const service = new SurveillanceSourcePublicationService(fixture.authority, fixture.catalog, {
    clock: () => new Date("2026-08-02T10:06:00.000Z")
  });
  const request = publicationRequest(fixture.evidence);
  const publication = await service.publish(request, "publication-worker");

  assert.equal(publication.datasetId, "loan-tape-dataset");
  assert.deepEqual(publication.scope, { scopeType: "portfolio", scopeId: "portfolio-east" });
  assert.equal(publication.datasetBinding.boundAt, "2026-08-01T09:06:00.000Z");
  assert.equal(publication.datasetBinding.bindingId, "portfolio-east-loan-tape");
  assert.equal(
    publication.normalizedArtifact.artifactId,
    fixture.evidence.normalizedArtifact.artifactId
  );

  await assert.rejects(
    service.publish({ ...request, datasetBindingId: "caller-binding" } as never, "publication-worker"),
    (error: unknown) =>
      error instanceof SurveillanceSourcePublicationError && error.code === "INVALID_REQUEST"
  );
  fixture.close();
});

test("tenant-scoped artifact reload rejects evidence whose bytes exist only for another tenant", async () => {
  const fixture = await productionFixture();
  const crossTenantEvidence = buildEvidence(
    fixture.snapshot,
    fixture.mappingSpec,
    fixture.mappingApplication,
    fixture.normalized,
    fixture.artifacts,
    "tenant-b",
    "certification-cross-tenant"
  );
  await fixture.repositories.certifiedSnapshotEvidence.put(crossTenantEvidence, {
    tenantId: "tenant-a",
    actorId: "certification-worker",
    idempotencyKey: "cross-tenant-evidence"
  });

  await assert.rejects(
    fixture.authority.resolveCertifiedPublicationEvidence({
      tenantId: "tenant-a",
      certificationManifestId: crossTenantEvidence.certification.certificationManifestId
    }),
    (error: unknown) => authorityError(error, "INTEGRITY_FAILURE")
  );
  fixture.close();
});

test("repository-backed authority rejects forged metadata and wrong governed definition kinds", async () => {
  const fixture = await productionFixture();
  const forgedMetadata = {
    ...fixture.evidence.normalizedArtifact,
    artifactId: "f".repeat(64),
    uri: `abl-artifact://${"f".repeat(64)}`
  };
  const certificationBody = {
    ...withoutManifestHash(fixture.evidence.certification),
    certificationManifestId: "certification-forged-metadata",
    normalizedArtifactId: forgedMetadata.artifactId
  };
  const forgedEvidence = createCertifiedSnapshotEvidenceRecordV1({
    ...withoutEvidenceHash(fixture.evidence),
    certification: {
      ...certificationBody,
      certificationManifestHash: canonicalHash(certificationBody)
    },
    normalizedArtifact: forgedMetadata
  });
  await fixture.repositories.certifiedSnapshotEvidence.put(forgedEvidence, {
    tenantId: "tenant-a",
    actorId: "certification-worker",
    idempotencyKey: "forged-metadata"
  });
  await assert.rejects(
    fixture.authority.resolveCertifiedPublicationEvidence({
      tenantId: "tenant-a",
      certificationManifestId: forgedEvidence.certification.certificationManifestId
    }),
    (error: unknown) => authorityError(error, "INTEGRITY_FAILURE")
  );
  assert.throws(
    () =>
      fixture.authority.resolveFrozenDatasetBinding({
        tenantId: "tenant-a",
        datasetBindingDefinitionVersionId: "source-contract-definition-v1"
      }),
    (error: unknown) => authorityError(error, "INTEGRITY_FAILURE")
  );
  fixture.close();
});

test("authority will not select a certified snapshot after an immutable correction", async () => {
  const fixture = await productionFixture();
  const correction = createDatasetSnapshotV2({
    ...withoutSnapshotHash(fixture.snapshot),
    snapshotId: "snapshot-2026-07-correction",
    sourceLocator: "upload://snapshot-2026-07-correction",
    knowledge: {
      sourceObservedAt: "2026-08-03T10:00:00.000Z",
      extractedAt: "2026-08-03T10:01:00.000Z",
      receivedAt: "2026-08-03T10:02:00.000Z",
      persistedAt: "2026-08-03T10:03:00.000Z"
    },
    hashes: {
      ...fixture.snapshot.hashes,
      contentHash: HASH("corrected-content")
    },
    sections: [{
      ...fixture.snapshot.sections[0]!,
      contentHash: HASH("corrected-section")
    }],
    correction: {
      kind: "correction",
      correctsSnapshotId: fixture.snapshot.snapshotId,
      correctsSnapshotHash: fixture.snapshot.snapshotHash,
      correctionSequence: 1,
      reasonCode: "source_restatement",
      reason: "The source supplied a corrected period.",
      detectedAt: "2026-08-03T09:00:00.000Z"
    }
  });
  await fixture.repositories.datasetSnapshots.put(correction, {
    tenantId: "tenant-a",
    actorId: "snapshot-worker",
    idempotencyKey: "correction"
  });

  await assert.rejects(
    fixture.authority.resolveDatasetSnapshotV2({
      tenantId: "tenant-a",
      datasetSnapshotId: fixture.snapshot.snapshotId,
      certificationManifestId: fixture.evidence.certification.certificationManifestId
    }),
    (error: unknown) => authorityError(error, "NON_TERMINAL_SNAPSHOT")
  );
  fixture.close();
});

interface ProductionFixture {
  readonly databasePath: string;
  readonly definitions: GovernedDefinitionV2Store;
  readonly repositories: SqliteSurveillanceEvidenceRepositories;
  readonly artifacts: ArtifactStore;
  readonly catalog: SurveillancePublicationCatalog;
  readonly authority: RepositoryBackedSurveillanceSourcePublicationAuthorityV1;
  readonly snapshot: DatasetSnapshotV2;
  readonly mappingSpec: ReturnType<typeof createMappingSpecV2>;
  readonly mappingApplication: ReturnType<typeof createMappingApplicationV1>;
  readonly normalized: ReturnType<typeof createNormalizedSnapshotArtifactV2>;
  readonly evidence: CertifiedSnapshotEvidenceRecordV1;
  close(): void;
}

async function productionFixture(): Promise<ProductionFixture> {
  const directory = temporaryDirectory();
  const databasePath = join(directory, "control.sqlite");
  const definitions = new GovernedDefinitionV2Store(databasePath, {
    clock: sequentialClock([
      "2026-08-01T09:00:00.000Z",
      "2026-08-01T09:01:00.000Z",
      "2026-08-01T09:02:00.000Z",
      "2026-08-01T09:03:00.000Z",
      "2026-08-01T09:04:00.000Z",
      "2026-08-01T09:05:00.000Z",
      "2026-08-01T09:06:00.000Z",
      "2026-08-01T09:07:00.000Z"
    ])
  });
  const resolver = new GovernedDefinitionV2Resolver(definitions);
  activate(
    definitions,
    definitions.propose({
      tenantId: "tenant-a",
      definitionVersionId: "source-contract-definition-v1",
      definitionKey: "loan-tape-source",
      kind: "source_contract",
      semanticVersion: "1.0.0",
      effectiveFrom: "2026-01-01",
      document: sourceContractCandidate(),
      proposedBy: "source-maker",
      idempotencyKey: "source-propose"
    }),
    "source-checker",
    "source"
  );
  const source = parseSourceContractV1(
    resolver.resolveFrozen({
      tenantId: "tenant-a",
      definitionVersionId: "source-contract-definition-v1"
    }).executionDocument
  );
  activate(
    definitions,
    definitions.propose({
      tenantId: "tenant-a",
      definitionVersionId: "dataset-binding-definition-v1",
      definitionKey: "portfolio-east-loan-tape",
      kind: "dataset_scope_binding",
      semanticVersion: "1.0.0",
      effectiveFrom: "2026-01-01",
      document: createGovernedDatasetScopeBindingV1({
        contractVersion: 1,
        tenantId: "tenant-a",
        bindingId: "portfolio-east-loan-tape",
        revision: 1,
        datasetId: "loan-tape-dataset",
        sourceContract: sourceReference(source),
        scope: { scopeType: "portfolio", scopeId: "portfolio-east" },
        effectiveFrom: "2026-01-01"
      }),
      proposedBy: "binding-maker",
      idempotencyKey: "binding-propose"
    }),
    "binding-checker",
    "binding"
  );

  const snapshot = createDatasetSnapshotV2({
    contractVersion: 2,
    tenantId: "tenant-a",
    snapshotId: "snapshot-2026-07",
    sourceContract: sourceReference(source),
    delivery: source.delivery,
    sourceLocator: "upload://snapshot-2026-07",
    asOfDate: "2026-07-31",
    knowledge: {
      sourceObservedAt: "2026-08-02T10:00:00.000Z",
      extractedAt: "2026-08-02T10:01:00.000Z",
      receivedAt: "2026-08-02T10:02:00.000Z",
      persistedAt: "2026-08-02T10:03:00.000Z"
    },
    watermark: { mode: "none" },
    hashes: {
      contentHash: HASH("snapshot-content"),
      schemaHash: HASH("snapshot-schema"),
      catalogHash: HASH("snapshot-catalog"),
      parserHash: HASH("snapshot-parser"),
      extractionHash: HASH("snapshot-extraction")
    },
    rowCount: 2,
    byteCount: 512,
    sections: [{
      sectionId: "loans",
      required: true,
      present: true,
      rowCount: 2,
      contentHash: HASH("snapshot-section"),
      schemaHash: HASH("snapshot-section-schema")
    }],
    correction: { kind: "original" },
    createdBy: "snapshot-worker"
  });
  const mappingSpec = createMappingSpecV2({
    contractVersion: 2,
    tenantId: "tenant-a",
    mappingSpecId: "mapping-spec-1",
    mappingKey: "loan-tape-mapping",
    revision: 1,
    status: "active",
    sourceContract: sourceReference(source),
    dictionaryBundle: dictionaryBundle(),
    rules: [
      {
        ruleId: "loan-id",
        canonicalField: "loan_id",
        expression: { op: "source", column: "loan_id" },
        onError: "fail_application"
      },
      {
        ruleId: "balance",
        canonicalField: "current_balance",
        expression: { op: "source", column: "current_balance" },
        onError: "fail_application"
      }
    ],
    requiredCanonicalFields: ["loan_id", "current_balance"],
    createdBy: "mapping-maker",
    createdAt: "2026-08-01T09:08:00.000Z",
    approvedBy: "mapping-checker",
    approvedAt: "2026-08-01T09:09:00.000Z"
  });
  const records = [
    { current_balance: "100.00", loan_id: "loan-1" },
    { current_balance: "250.00", loan_id: "loan-2" }
  ] as const;
  const mappingApplication = createMappingApplicationV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    mappingApplicationId: "mapping-application-1",
    snapshot: {
      snapshotId: snapshot.snapshotId,
      snapshotHash: snapshot.snapshotHash,
      contentHash: snapshot.hashes.contentHash
    },
    mappingSpec: {
      mappingSpecId: mappingSpec.mappingSpecId,
      revision: mappingSpec.revision,
      mappingSpecHash: mappingSpec.mappingSpecHash
    },
    dictionaryBundle: mappingSpec.dictionaryBundle,
    runtimeBundle: {
      runtimeBundleId: "runtime-1",
      runtimeBundleHash: HASH("runtime"),
      runtimeVersion: "1.0.0"
    },
    inputPopulationHash: HASH("raw-population"),
    outputPopulationHash: canonicalHash(records),
    inputRowCount: 2,
    outputRowCount: 2,
    rejectedRowCount: 0,
    appliedBy: "mapping-worker",
    appliedAt: "2026-08-02T10:04:00.000Z"
  });
  const normalized = createNormalizedSnapshotArtifactV2({
    contractVersion: 2,
    kind: "normalized_snapshot",
    tenantId: "tenant-a",
    normalizedPopulationId: "population-1",
    snapshot: { snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash },
    mappingApplication: {
      mappingApplicationId: mappingApplication.mappingApplicationId,
      mappingApplicationHash: mappingApplication.mappingApplicationHash
    },
    records,
    createdAt: "2026-08-02T10:04:30.000Z"
  });
  const artifacts = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "key-1",
    keys: { "key-1": Buffer.alloc(32, 11) }
  });
  const evidence = buildEvidence(
    snapshot,
    mappingSpec,
    mappingApplication,
    normalized,
    artifacts,
    "tenant-a",
    "certification-manifest-1"
  );
  const repositories = new SqliteSurveillanceEvidenceRepositories(databasePath);
  await repositories.datasetSnapshots.put(snapshot, {
    tenantId: "tenant-a",
    actorId: "snapshot-worker",
    idempotencyKey: "snapshot"
  });
  await repositories.certifiedSnapshotEvidence.put(evidence, {
    tenantId: "tenant-a",
    actorId: "certification-worker",
    idempotencyKey: "evidence"
  });
  const catalog = new SurveillancePublicationCatalog(databasePath);
  const authority = new RepositoryBackedSurveillanceSourcePublicationAuthorityV1({
    datasetSnapshots: repositories.datasetSnapshots,
    certifiedSnapshotEvidence: repositories.certifiedSnapshotEvidence,
    artifacts,
    definitions: resolver
  });
  return {
    databasePath,
    definitions,
    repositories,
    artifacts,
    catalog,
    authority,
    snapshot,
    mappingSpec,
    mappingApplication,
    normalized,
    evidence,
    close: () => {
      catalog.close();
      repositories.close();
      definitions.close();
    }
  };
}

function buildEvidence(
  snapshot: DatasetSnapshotV2,
  mappingSpec: ReturnType<typeof createMappingSpecV2>,
  mappingApplication: ReturnType<typeof createMappingApplicationV1>,
  normalized: ReturnType<typeof createNormalizedSnapshotArtifactV2>,
  artifacts: ArtifactStore,
  artifactTenantId: string,
  certificationManifestId: string
): CertifiedSnapshotEvidenceRecordV1 {
  const stored = artifacts.putJson({
    tenantId: artifactTenantId,
    kind: "normalized_snapshot",
    mediaType: "application/json",
    value: normalized
  });
  const metadata = createCertifiedSnapshotArtifactMetadataV1({
    artifact: normalized,
    loadedStoredArtifact: stored
  });
  const populationBody = {
    contractVersion: 1 as const,
    tenantId: snapshot.tenantId,
    populationId: normalized.normalizedPopulationId,
    snapshotId: snapshot.snapshotId,
    snapshotHash: snapshot.snapshotHash,
    mappingApplicationId: mappingApplication.mappingApplicationId,
    mappingApplicationHash: mappingApplication.mappingApplicationHash,
    populationHash: normalized.populationHash,
    fieldSetHash: normalized.fieldSetHash,
    rowCount: normalized.rowCount,
    dataQuality: {
      runId: "dq-1",
      rulesetId: "dq-rules-1",
      rulesetHash: HASH("dq-rules"),
      resultHash: HASH("dq-result"),
      publicationDecision: "publish" as const,
      blockerCodes: []
    },
    reconciliation: {
      reconciliationId: "reconciliation-1",
      definitionHash: HASH("reconciliation-definition"),
      resultHash: HASH("reconciliation-result"),
      passed: true as const,
      populationHash: normalized.populationHash
    },
    certifiedBy: "certification-checker",
    certifiedAt: "2026-08-02T10:05:00.000Z"
  };
  const population = { ...populationBody, certificationHash: canonicalHash(populationBody) };
  const certificationBody = {
    contractVersion: 1 as const,
    tenantId: snapshot.tenantId,
    certificationManifestId,
    evidenceFormat: "modern_snapshot_v2" as const,
    snapshotId: snapshot.snapshotId,
    snapshotHash: snapshot.snapshotHash,
    populationId: population.populationId,
    populationCertificationHash: population.certificationHash,
    mappingApplicationId: mappingApplication.mappingApplicationId,
    mappingApplicationHash: mappingApplication.mappingApplicationHash,
    normalizedArtifactId: metadata.artifactId,
    normalizedArtifactContentHash: metadata.contentHash,
    dataQualityResultHash: population.dataQuality.resultHash,
    reconciliationResultHash: population.reconciliation.resultHash,
    populationHash: population.populationHash,
    rowCount: population.rowCount,
    certifiedBy: population.certifiedBy,
    certifiedAt: population.certifiedAt
  };
  return createCertifiedSnapshotEvidenceRecordV1({
    contractVersion: 1,
    tenantId: snapshot.tenantId,
    certification: {
      ...certificationBody,
      certificationManifestHash: canonicalHash(certificationBody)
    },
    population,
    mappingSpec,
    mappingApplication,
    normalizedArtifact: metadata,
    dataQualityPopulation: {
      populationHash: normalized.populationHash,
      fieldSetHash: normalized.fieldSetHash,
      rowCount: normalized.rowCount
    },
    recordedAt: "2026-08-02T10:05:30.000Z"
  });
}

function sourceContractCandidate() {
  return createSourceContractV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    sourceContractId: "loan-tape-source-v1",
    sourceKey: "loan-tape-source",
    revision: 1,
    status: "proposed",
    delivery: { mode: "managed_upload", format: "parquet", logicalName: "loans.parquet" },
    schemaPolicy: {
      columns: [
        { sourceName: "loan_id", ordinal: 0, nativeType: "string", nullable: false, required: true },
        { sourceName: "current_balance", ordinal: 1, nativeType: "decimal", nullable: false, required: true }
      ],
      allowUnknownColumns: false,
      requireStableOrdinals: true
    },
    parserPolicy: {
      format: "parquet",
      parserId: "parquet-v1",
      parserVersion: "1.0.0",
      optionsHash: HASH("parser-options"),
      exactDecimalMode: "string",
      timezone: "UTC",
      rejectSchemaMerging: true
    },
    extractionPolicy: {
      mode: "full",
      readOnly: true,
      maximumRows: 1_000,
      maximumColumns: 20,
      maximumBytes: 1_000_000,
      timeoutMs: 5_000,
      cursorRows: 100
    },
    sections: [{ sectionId: "loans", required: true, selector: "loans", keyFields: ["loan_id"] }],
    effectiveFrom: "2026-01-01",
    createdBy: "source-maker",
    createdAt: "2026-08-01T08:00:00.000Z"
  });
}

function dictionaryBundle() {
  return {
    contractVersion: 1 as const,
    bundleKind: "dictionary" as const,
    bundleId: "dictionary-1",
    version: "1.0.0",
    contentHash: HASH("dictionary-content"),
    artifactId: "dictionary-artifact-1",
    mediaType: "application/json",
    createdAt: "2026-08-01T08:00:00.000Z",
    dictionaryVersion: "1.0.0",
    dictionaryHash: HASH("dictionary"),
    fieldPolicyVersion: "1.0.0",
    fieldPolicyHash: HASH("field-policy")
  };
}

function sourceReference(source: ReturnType<typeof parseSourceContractV1>) {
  return {
    sourceContractId: source.sourceContractId,
    revision: source.revision,
    sourceContractHash: source.sourceContractHash
  };
}

function publicationRequest(evidence: CertifiedSnapshotEvidenceRecordV1) {
  return {
    tenantId: "tenant-a",
    publicationId: "publication-1",
    certificationManifestId: evidence.certification.certificationManifestId,
    datasetSnapshotId: evidence.certification.snapshotId,
    datasetBindingDefinitionVersionId: "dataset-binding-definition-v1",
    sourceContractDefinitionVersionId: "source-contract-definition-v1",
    idempotencyKey: "publication-1"
  } as const;
}

function activate(
  store: GovernedDefinitionV2Store,
  proposed: GovernedDefinitionViewV2,
  checker: string,
  prefix: string
): GovernedDefinitionViewV2 {
  let view = proposed;
  for (const toStatus of ["validated", "approved", "active"] as const) {
    view = store.transition({
      tenantId: view.version.tenantId,
      definitionVersionId: view.version.definitionVersionId,
      toStatus,
      expectedRevision: view.lifecycleRevision,
      actor: checker,
      idempotencyKey: `${prefix}-${toStatus}`
    });
  }
  return view;
}

function sequentialClock(timestamps: readonly string[]): () => Date {
  let index = 0;
  return () => new Date(timestamps[index++] ?? timestamps.at(-1)!);
}

function withoutSnapshotHash(value: DatasetSnapshotV2) {
  const { snapshotHash: _snapshotHash, ...body } = value;
  return body;
}

function withoutEvidenceHash(value: CertifiedSnapshotEvidenceRecordV1) {
  const { evidenceHash: _evidenceHash, ...body } = value;
  return body;
}

function withoutManifestHash<T extends { readonly certificationManifestHash: unknown }>(value: T) {
  const { certificationManifestHash: _certificationManifestHash, ...body } = value;
  return body;
}

function authorityError(
  error: unknown,
  code: SurveillanceProductionAuthorityError["code"]
): boolean {
  return error instanceof SurveillanceProductionAuthorityError && error.code === code;
}

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "surveillance-production-authority-"));
  directories.push(directory);
  return directory;
}
