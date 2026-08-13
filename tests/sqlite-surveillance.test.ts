import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, test } from "node:test";

import {
  canonicalHash,
  createDatasetSnapshotV2,
  createMappingApplicationV1,
  createMappingSpecV2,
  type DatasetSnapshotV2,
  type Sha256Hash
} from "../src/contracts/index.js";
import {
  createCertifiedSnapshotArtifactMetadataV1,
  createCertifiedSnapshotEvidenceRecordV1,
  type CertifiedSnapshotEvidenceRecordV1
} from "../src/contracts/certified-snapshot-evidence-v1.js";
import {
  createNormalizedSnapshotArtifactV2,
  parseNormalizedSnapshotArtifactV2
} from "../src/contracts/normalized-snapshot-artifact-v2.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import {
  SqliteCertifiedSnapshotEvidenceV1Repository,
  SqliteDatasetSnapshotV2Repository,
  SqliteSurveillanceEvidenceRepositories
} from "../src/repositories/sqlite-surveillance.js";
import { RepositoryError } from "../src/repositories/ports.js";
import { createGovernedSnapshotCommitLineageV1 } from "../src/repositories/governed-snapshot-commit.js";

const directories: string[] = [];
const HASH = (label: string): Sha256Hash => canonicalHash(label);

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("normalized artifact derives controls, rejects noncanonical values, and round-trips ArtifactStore", () => {
  const directory = temporaryDirectory();
  const artifact = normalizedArtifact();
  assert.equal(artifact.rowCount, 2);
  assert.equal(artifact.populationHash, canonicalHash(artifact.records));
  assert.equal("artifactId" in artifact, false);
  assert.equal(parseNormalizedSnapshotArtifactV2(artifact).artifactHash, artifact.artifactHash);

  const store = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "key-1",
    keys: { "key-1": Buffer.alloc(32, 7) }
  });
  const stored = store.putJson({
    tenantId: artifact.tenantId,
    kind: "normalized_snapshot",
    mediaType: "application/json",
    value: artifact
  });
  const loaded = store.getJson(artifact.tenantId, stored.artifactId);
  assert.deepEqual(loaded.value, artifact);
  const metadata = createCertifiedSnapshotArtifactMetadataV1({
    artifact: parseNormalizedSnapshotArtifactV2(loaded.value),
    loadedStoredArtifact: loaded.metadata
  });
  assert.equal(metadata.artifactId, stored.artifactId);
  assert.equal(metadata.normalizedPopulationId, artifact.normalizedPopulationId);
  assert.equal(metadata.createdAt, artifact.createdAt);

  assert.throws(
    () =>
      createNormalizedSnapshotArtifactV2({
        ...normalizedArtifactInput(),
        records: [{ loan_id: "loan-1", forbidden: undefined }]
      }),
    (error: unknown) => hasCode(error, "NON_CANONICAL_VALUE")
  );
  assert.throws(
    () => createNormalizedSnapshotArtifactV2({
      ...normalizedArtifactInput(),
      records: [{ "crédit": "1" }]
    }),
    (error: unknown) => hasCode(error, "INVALID_CONTRACT")
  );
  assert.throws(
    () => createNormalizedSnapshotArtifactV2({
      ...normalizedArtifactInput(),
      records: [{ loan_id: { nested: "value" } }]
    } as never),
    (error: unknown) => hasCode(error, "INVALID_CONTRACT")
  );
  assert.throws(
    () => createCertifiedSnapshotArtifactMetadataV1({ artifact, loadedStoredArtifact: { ...stored, byteLength: stored.byteLength + 1 } }),
    (error: unknown) => hasCode(error, "INVARIANT_VIOLATION")
  );
  assert.throws(
    () => createCertifiedSnapshotArtifactMetadataV1({ artifact, loadedStoredArtifact: { ...stored, uri: "https://user:secret@example.test/artifact" } }),
    (error: unknown) => hasCode(error, "INVARIANT_VIOLATION")
  );
});

test("dataset snapshot repository is tenant scoped, actor idempotent, paged, immutable, and reopen safe", async () => {
  const path = databasePath();
  const repository = new SqliteDatasetSnapshotV2Repository(path);
  const first = snapshot("snapshot-1", "2026-07-31");
  const second = snapshot("snapshot-2", "2026-08-31");
  const context = { tenantId: "tenant-a", actorId: "worker-1", idempotencyKey: "snapshot-1" };
  assert.equal((await repository.put(first, context)).replayed, false);
  assert.equal((await repository.put(first, context)).replayed, true);
  await repository.put(second, { ...context, idempotencyKey: "snapshot-2" });
  assert.equal(await repository.get("tenant-b", first.snapshotId), undefined);
  const page = await repository.list("tenant-a", { limit: 1 });
  assert.deepEqual(page.items.map((record) => record.snapshotId), ["snapshot-1"]);
  assert.ok(page.nextCursor);
  assert.deepEqual(
    (await repository.list("tenant-a", { cursor: page.nextCursor ?? undefined })).items.map(
      (record) => record.snapshotId
    ),
    ["snapshot-2"]
  );
  await assert.rejects(
    repository.put(first, { ...context, actorId: "worker-2", idempotencyKey: "same-record" }),
    (error: unknown) => repositoryCode(error, "ALREADY_EXISTS")
  );
  await assert.rejects(
    repository.put(second, context),
    (error: unknown) => repositoryCode(error, "IDEMPOTENCY_CONFLICT")
  );
  repository.close();
  const reopened = new SqliteDatasetSnapshotV2Repository(path);
  assert.equal((await reopened.get("tenant-a", first.snapshotId))?.snapshotHash, first.snapshotHash);
  reopened.close();
});

test("correction lineage requires an exact contiguous, non-forking predecessor", async () => {
  const path = databasePath();
  const repository = new SqliteDatasetSnapshotV2Repository(path);
  const original = snapshot("snapshot-original", "2026-07-31");
  await repository.put(original, context("original"));
  await assert.rejects(
    repository.put(
      snapshot("snapshot-duplicate-original", original.asOfDate),
      context("duplicate-original")
    ),
    (error: unknown) => repositoryCode(error, "ALREADY_EXISTS")
  );
  const correction = snapshot("snapshot-correction-1", original.asOfDate, {
    kind: "correction",
    correctsSnapshotId: original.snapshotId,
    correctsSnapshotHash: original.snapshotHash,
    correctionSequence: 1,
    reasonCode: "late_file",
    reason: "Late source correction",
    detectedAt: "2026-08-02T00:00:00.000Z"
  }, "2026-08-02T01:00:00.000Z");
  await repository.put(correction, context("correction-1"));

  await assert.rejects(
    repository.put(
      snapshot("snapshot-fork", original.asOfDate, {
        ...correction.correction,
        kind: "correction",
        reasonCode: "second_branch",
        detectedAt: "2026-08-02T00:30:00.000Z"
      }, "2026-08-02T02:00:00.000Z"),
      context("fork")
    ),
    (error: unknown) => repositoryCode(error, "CONCURRENCY_CONFLICT")
  );
  await assert.rejects(
    repository.put(
      snapshot("snapshot-skipped", original.asOfDate, {
        kind: "correction",
        correctsSnapshotId: correction.snapshotId,
        correctsSnapshotHash: correction.snapshotHash,
        correctionSequence: 3,
        reasonCode: "skip",
        reason: "Invalid sequence",
        detectedAt: "2026-08-03T00:00:00.000Z"
      }, "2026-08-03T01:00:00.000Z"),
      context("skip")
    ),
    (error: unknown) => repositoryCode(error, "INTEGRITY_FAILURE")
  );
  await assert.rejects(
    repository.put(
      snapshot("snapshot-missing", original.asOfDate, {
        kind: "correction",
        correctsSnapshotId: "not-found",
        correctsSnapshotHash: HASH("missing"),
        correctionSequence: 1,
        reasonCode: "missing",
        reason: "Missing predecessor",
        detectedAt: "2026-08-02T00:00:00.000Z"
      }),
      context("missing")
    ),
    (error: unknown) => repositoryCode(error, "NOT_FOUND")
  );
  repository.close();
});

test("governed capture CAS scopes originals by facility population and permits one concurrent child", async () => {
  const path = databasePath();
  const firstConnection = new SqliteDatasetSnapshotV2Repository(path);
  const secondConnection = new SqliteDatasetSnapshotV2Repository(path);
  const original = snapshot("governed-original", "2026-07-31");
  await firstConnection.commitGovernedCapture(
    original,
    governedLineage(original, "dataset-a", "facility-a", "binding-a", "delivery-original"),
    context("governed-original")
  );

  const otherFacility = snapshot("governed-other-facility", original.asOfDate);
  await secondConnection.commitGovernedCapture(
    otherFacility,
    governedLineage(
      otherFacility,
      "dataset-b",
      "facility-b",
      "binding-b",
      "delivery-other-facility"
    ),
    context("governed-other-facility")
  );

  const duplicatePopulation = snapshot("governed-duplicate", original.asOfDate);
  await assert.rejects(
    secondConnection.commitGovernedCapture(
      duplicatePopulation,
      governedLineage(
        duplicatePopulation,
        "dataset-a",
        "facility-a",
        "binding-a",
        "delivery-duplicate"
      ),
      context("governed-duplicate")
    ),
    (error: unknown) => repositoryCode(error, "ALREADY_EXISTS")
  );

  const correctionInput = {
    kind: "correction" as const,
    correctsSnapshotId: original.snapshotId,
    correctsSnapshotHash: original.snapshotHash,
    correctionSequence: 1,
    reasonCode: "restatement",
    reason: "Source restatement",
    detectedAt: "2026-08-02T00:00:00.000Z"
  };
  const correctionA = snapshot(
    "governed-correction-a",
    original.asOfDate,
    correctionInput,
    "2026-08-02T01:00:00.000Z"
  );
  const correctionB = snapshot(
    "governed-correction-b",
    original.asOfDate,
    correctionInput,
    "2026-08-02T01:01:00.000Z"
  );
  const results = await Promise.allSettled([
    firstConnection.commitGovernedCapture(
      correctionA,
      governedLineage(correctionA, "dataset-a", "facility-a", "binding-a", "delivery-correction-a"),
      context("governed-correction-a")
    ),
    secondConnection.commitGovernedCapture(
      correctionB,
      governedLineage(correctionB, "dataset-a", "facility-a", "binding-a", "delivery-correction-b"),
      context("governed-correction-b")
    )
  ]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  const rejected = results.find((result) => result.status === "rejected");
  assert.ok(rejected?.status === "rejected");
  assert.equal((rejected.reason as RepositoryError).code, "CONCURRENCY_CONFLICT");

  firstConnection.close();
  secondConnection.close();
});

test("governed capture lineage reads are tenant-fenced, verified, and reopen-safe", async () => {
  const path = databasePath();
  const repository = new SqliteDatasetSnapshotV2Repository(path);
  const governed = snapshot("governed-lineage-read", "2026-07-31");
  const lineage = governedLineage(
    governed,
    "dataset-lineage-read",
    "facility-lineage-read",
    "binding-lineage-read",
    "delivery-lineage-read"
  );
  await repository.commitGovernedCapture(governed, lineage, context("governed-lineage-read"));
  await repository.put(snapshot("legacy-lineage-read", "2026-08-31"), context("legacy-lineage-read"));

  assert.deepEqual(
    await repository.getGovernedCaptureLineage("tenant-a", governed.snapshotId),
    lineage
  );
  assert.equal(await repository.getGovernedCaptureLineage("tenant-b", governed.snapshotId), undefined);
  assert.equal(await repository.getGovernedCaptureLineage("tenant-a", "missing-lineage"), undefined);
  assert.equal(
    await repository.getGovernedCaptureLineage("tenant-a", "legacy-lineage-read"),
    undefined
  );
  repository.close();

  const reopened = new SqliteDatasetSnapshotV2Repository(path);
  assert.deepEqual(
    await reopened.getGovernedCaptureLineage("tenant-a", governed.snapshotId),
    lineage
  );
  reopened.close();
});

test("governed capture lineage reads reject tampered lineage indexes", async () => {
  const path = databasePath();
  const repository = new SqliteDatasetSnapshotV2Repository(path);
  const governed = snapshot("governed-lineage-tamper", "2026-07-31");
  await repository.commitGovernedCapture(
    governed,
    governedLineage(
      governed,
      "dataset-lineage-tamper",
      "facility-lineage-tamper",
      "binding-lineage-tamper",
      "delivery-lineage-tamper"
    ),
    context("governed-lineage-tamper")
  );
  repository.close();

  const database = new DatabaseSync(path);
  database.exec("DROP TRIGGER surveillance_dataset_snapshot_lineage_v1_no_update");
  database
    .prepare(
      `UPDATE surveillance_dataset_snapshot_lineage_v1
          SET delivery_id = ?
        WHERE tenant_id = ? AND record_id = ?`
    )
    .run("delivery-substituted", "tenant-a", governed.snapshotId);
  database.exec(`
    CREATE TRIGGER surveillance_dataset_snapshot_lineage_v1_no_update
    BEFORE UPDATE ON surveillance_dataset_snapshot_lineage_v1
    BEGIN
      SELECT RAISE(ABORT, 'surveillance dataset snapshot lineage is immutable');
    END;
  `);
  database.close();

  const reopened = new SqliteDatasetSnapshotV2Repository(path);
  await assert.rejects(
    reopened.getGovernedCaptureLineage("tenant-a", governed.snapshotId),
    (error: unknown) => repositoryCode(error, "INTEGRITY_FAILURE")
  );
  reopened.close();
});

test("certified evidence requires the persisted tenant snapshot and exact ArtifactStore metadata", async () => {
  const path = databasePath();
  const snapshots = new SqliteDatasetSnapshotV2Repository(path);
  const evidenceRepository = new SqliteCertifiedSnapshotEvidenceV1Repository(path);
  const snapshotValue = snapshot("snapshot-evidence", "2026-07-31");
  await snapshots.put(snapshotValue, context("snapshot-evidence"));
  const evidence = evidenceFixture(snapshotValue);
  const created = await evidenceRepository.put(evidence, context("evidence"));
  assert.equal(created.replayed, false);
  assert.equal((await evidenceRepository.put(evidence, context("evidence"))).replayed, true);
  assert.equal(
    (await evidenceRepository.get("tenant-a", evidence.certification.certificationManifestId))?.evidenceHash,
    evidence.evidenceHash
  );
  assert.equal(
    await evidenceRepository.get("tenant-b", evidence.certification.certificationManifestId),
    undefined
  );

  const unknown = evidenceFixture(snapshot("snapshot-unknown", "2026-07-31"));
  await assert.rejects(
    evidenceRepository.put(unknown, context("unknown")),
    (error: unknown) => repositoryCode(error, "NOT_FOUND")
  );
  assert.throws(
    () => createCertifiedSnapshotEvidenceRecordV1({
      ...withoutEvidenceHash(evidence),
      normalizedArtifact: {
        ...evidence.normalizedArtifact,
        normalizedPopulationId: "population-swapped"
      }
    }),
    (error: unknown) => hasCode(error, "INVALID_CONTRACT")
  );
  assert.throws(
    () => createCertifiedSnapshotEvidenceRecordV1({
      ...withoutEvidenceHash(evidence),
      normalizedArtifact: {
        ...evidence.normalizedArtifact,
        mappingApplicationId: "mapping-swapped"
      }
    }),
    (error: unknown) => hasCode(error, "INVALID_CONTRACT")
  );
  evidenceRepository.close();
  snapshots.close();
});

test("schema attestation rejects tampering and SQL immutability triggers reject mutation", async () => {
  const path = databasePath();
  const repository = new SqliteDatasetSnapshotV2Repository(path);
  await repository.put(snapshot("snapshot-1", "2026-07-31"), context("snapshot-1"));
  repository.close();

  const database = new DatabaseSync(path);
  assert.throws(() =>
    database.exec("UPDATE surveillance_dataset_snapshots_v2 SET as_of_date = '2020-01-01'")
  );
  database.exec("DROP TRIGGER surveillance_dataset_snapshots_v2_no_update");
  database.close();
  assert.throws(
    () => new SqliteDatasetSnapshotV2Repository(path),
    (error: unknown) => repositoryCode(error, "INTEGRITY_FAILURE")
  );
});

test("snapshot contracts reject credential-bearing source locators before persistence", () => {
  assert.throws(
    () => createDatasetSnapshotV2({
      ...withoutSnapshotHash(snapshot("unsafe-locator", "2026-07-31")),
      sourceLocator: "https://user:password@example.test/loans.parquet"
    }),
    (error: unknown) => hasCode(error, "INVALID_CONTRACT")
  );
});

test("shared file repositories coexist and the aggregate rejects split in-memory lineage", async () => {
  assert.throws(
    () => new SqliteSurveillanceEvidenceRepositories(":memory:"),
    (error: unknown) => repositoryCode(error, "INVALID_ARGUMENT")
  );
  const path = databasePath();
  const repositories = new SqliteSurveillanceEvidenceRepositories(path);
  const snapshotValue = snapshot("snapshot-shared", "2026-07-31");
  await repositories.datasetSnapshots.put(snapshotValue, context("shared-snapshot"));
  await repositories.certifiedSnapshotEvidence.put(
    evidenceFixture(snapshotValue),
    context("shared-evidence")
  );
  repositories.close();
});

function normalizedArtifactInput() {
  const records = [
    { current_balance: "100.00", loan_id: "loan-1" },
    { current_balance: "250.00", loan_id: "loan-2" }
  ] as const;
  return {
    contractVersion: 2 as const,
    kind: "normalized_snapshot" as const,
    tenantId: "tenant-a",
    normalizedPopulationId: "population-1",
    snapshot: { snapshotId: "snapshot-evidence", snapshotHash: HASH("snapshot-placeholder") },
    mappingApplication: {
      mappingApplicationId: "mapping-application-1",
      mappingApplicationHash: HASH("mapping-placeholder")
    },
    records,
    createdAt: "2026-08-01T10:04:30.000Z"
  };
}

function normalizedArtifact() {
  return createNormalizedSnapshotArtifactV2(normalizedArtifactInput());
}

function snapshot(
  snapshotId: string,
  asOfDate: string,
  correction: DatasetSnapshotV2["correction"] = { kind: "original" },
  persistedAt = "2026-08-01T10:03:00.000Z"
): DatasetSnapshotV2 {
  const sourceContract = sourceReference();
  return createDatasetSnapshotV2({
    contractVersion: 2,
    tenantId: "tenant-a",
    snapshotId,
    sourceContract,
    delivery: { mode: "managed_upload", format: "parquet", logicalName: "loans.parquet" },
    sourceLocator: `upload://${snapshotId}`,
    asOfDate,
    knowledge: {
      sourceObservedAt: "2026-08-01T10:00:00.000Z",
      extractedAt: "2026-08-01T10:01:00.000Z",
      receivedAt: "2026-08-01T10:02:00.000Z",
      persistedAt
    },
    watermark: { mode: "none" },
    hashes: {
      contentHash: HASH(`content:${snapshotId}`),
      schemaHash: HASH("schema"),
      catalogHash: HASH("catalog"),
      parserHash: HASH("parser"),
      extractionHash: HASH("extraction")
    },
    rowCount: 2,
    byteCount: 512,
    sections: [{
      sectionId: "loans",
      required: true,
      present: true,
      rowCount: 2,
      contentHash: HASH(`section:${snapshotId}`),
      schemaHash: HASH("section-schema")
    }],
    correction,
    createdBy: "snapshot-worker"
  });
}

function governedLineage(
  snapshotValue: DatasetSnapshotV2,
  datasetId: string,
  facilityId: string,
  bindingId: string,
  deliveryId: string
) {
  return createGovernedSnapshotCommitLineageV1({
    contractVersion: 1,
    tenantId: snapshotValue.tenantId,
    snapshotId: snapshotValue.snapshotId,
    snapshotHash: snapshotValue.snapshotHash,
    datasetId,
    facilityId,
    sourceContract: snapshotValue.sourceContract,
    scopeBinding: {
      bindingId,
      revision: 1,
      bindingHash: HASH(`binding:${bindingId}`)
    },
    sourceDelivery: {
      deliveryId,
      deliveryRevision: 1,
      deliveryHash: HASH(`delivery:${deliveryId}`),
      locatorHash: HASH(`locator:${deliveryId}`),
      sourceVersionHash: HASH(`source-version:${deliveryId}`)
    },
    extractionReceipt: {
      receiptId: `${snapshotValue.snapshotId}:extraction`,
      receiptHash: snapshotValue.hashes.extractionHash
    },
    asOfDate: snapshotValue.asOfDate
  });
}

function evidenceFixture(snapshotValue: DatasetSnapshotV2): CertifiedSnapshotEvidenceRecordV1 {
  const directory = temporaryDirectory();
  const dictionaryBundle = {
    contractVersion: 1 as const,
    bundleKind: "dictionary" as const,
    bundleId: "dictionary-1",
    version: "1.0.0",
    contentHash: HASH("dictionary-content"),
    artifactId: "dictionary-artifact-1",
    mediaType: "application/json",
    createdAt: "2026-01-01T00:00:00.000Z",
    dictionaryVersion: "1.0.0",
    dictionaryHash: HASH("dictionary"),
    fieldPolicyVersion: "1.0.0",
    fieldPolicyHash: HASH("field-policy")
  };
  const mappingSpec = createMappingSpecV2({
    contractVersion: 2,
    tenantId: snapshotValue.tenantId,
    mappingSpecId: "mapping-spec-1",
    mappingKey: "mapping-loans",
    revision: 1,
    status: "active",
    sourceContract: snapshotValue.sourceContract,
    dictionaryBundle,
    rules: [{
      ruleId: "loan-id",
      canonicalField: "loan_id",
      expression: { op: "source", column: "loan_id" },
      onError: "fail_application"
    }],
    requiredCanonicalFields: ["loan_id"],
    createdBy: "mapping-maker",
    createdAt: "2026-01-01T00:00:00.000Z",
    approvedBy: "mapping-checker",
    approvedAt: "2026-01-01T00:01:00.000Z"
  });
  const records = [
    { current_balance: "100.00", loan_id: "loan-1" },
    { current_balance: "250.00", loan_id: "loan-2" }
  ] as const;
  const populationHash = canonicalHash(records);
  const mappingApplication = createMappingApplicationV1({
    contractVersion: 1,
    tenantId: snapshotValue.tenantId,
    mappingApplicationId: "mapping-application-1",
    snapshot: {
      snapshotId: snapshotValue.snapshotId,
      snapshotHash: snapshotValue.snapshotHash,
      contentHash: snapshotValue.hashes.contentHash
    },
    mappingSpec: {
      mappingSpecId: mappingSpec.mappingSpecId,
      revision: mappingSpec.revision,
      mappingSpecHash: mappingSpec.mappingSpecHash
    },
    dictionaryBundle,
    runtimeBundle: {
      runtimeBundleId: "runtime-1",
      runtimeBundleHash: HASH("runtime"),
      runtimeVersion: "1.0.0"
    },
    inputPopulationHash: HASH("raw-population"),
    outputPopulationHash: populationHash,
    inputRowCount: 2,
    outputRowCount: 2,
    rejectedRowCount: 0,
    appliedBy: "mapping-worker",
    appliedAt: "2026-08-01T10:04:00.000Z"
  });
  const normalized = createNormalizedSnapshotArtifactV2({
    contractVersion: 2,
    kind: "normalized_snapshot",
    tenantId: snapshotValue.tenantId,
    normalizedPopulationId: "population-1",
    snapshot: { snapshotId: snapshotValue.snapshotId, snapshotHash: snapshotValue.snapshotHash },
    mappingApplication: {
      mappingApplicationId: mappingApplication.mappingApplicationId,
      mappingApplicationHash: mappingApplication.mappingApplicationHash
    },
    records,
    createdAt: "2026-08-01T10:04:30.000Z"
  });
  const store = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "key-1",
    keys: { "key-1": Buffer.alloc(32, 9) }
  });
  const storedArtifact = store.putJson({
    tenantId: snapshotValue.tenantId,
    kind: "normalized_snapshot",
    mediaType: "application/json",
    value: normalized
  });
  const artifactMetadata = createCertifiedSnapshotArtifactMetadataV1({
    artifact: normalized,
    loadedStoredArtifact: storedArtifact
  });
  const populationBody = {
    contractVersion: 1 as const,
    tenantId: snapshotValue.tenantId,
    populationId: normalized.normalizedPopulationId,
    snapshotId: snapshotValue.snapshotId,
    snapshotHash: snapshotValue.snapshotHash,
    mappingApplicationId: mappingApplication.mappingApplicationId,
    mappingApplicationHash: mappingApplication.mappingApplicationHash,
    populationHash,
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
      populationHash
    },
    certifiedBy: "certification-checker",
    certifiedAt: "2026-08-01T10:05:00.000Z"
  };
  const population = { ...populationBody, certificationHash: canonicalHash(populationBody) };
  const certificationBody = {
    contractVersion: 1 as const,
    tenantId: snapshotValue.tenantId,
    certificationManifestId: `certification-${snapshotValue.snapshotId}`,
    evidenceFormat: "modern_snapshot_v2" as const,
    snapshotId: snapshotValue.snapshotId,
    snapshotHash: snapshotValue.snapshotHash,
    populationId: population.populationId,
    populationCertificationHash: population.certificationHash,
    mappingApplicationId: mappingApplication.mappingApplicationId,
    mappingApplicationHash: mappingApplication.mappingApplicationHash,
    normalizedArtifactId: artifactMetadata.artifactId,
    normalizedArtifactContentHash: artifactMetadata.contentHash,
    dataQualityResultHash: population.dataQuality.resultHash,
    reconciliationResultHash: population.reconciliation.resultHash,
    populationHash,
    rowCount: population.rowCount,
    certifiedBy: population.certifiedBy,
    certifiedAt: population.certifiedAt
  };
  return createCertifiedSnapshotEvidenceRecordV1({
    contractVersion: 1,
    tenantId: snapshotValue.tenantId,
    certification: {
      ...certificationBody,
      certificationManifestHash: canonicalHash(certificationBody)
    },
    population,
    mappingSpec,
    mappingApplication,
    normalizedArtifact: artifactMetadata,
    dataQualityPopulation: {
      populationHash,
      fieldSetHash: normalized.fieldSetHash,
      rowCount: normalized.rowCount
    },
    recordedAt: "2026-08-01T10:06:00.000Z"
  });
}

function sourceReference() {
  return {
    sourceContractId: "source-contract-1",
    revision: 1,
    sourceContractHash: HASH("source-contract")
  } as const;
}

function context(idempotencyKey: string) {
  return { tenantId: "tenant-a", actorId: "worker-1", idempotencyKey };
}

function databasePath(): string {
  return join(temporaryDirectory(), "surveillance.sqlite");
}

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "sqlite-surveillance-"));
  directories.push(directory);
  return directory;
}

function repositoryCode(error: unknown, code: RepositoryError["code"]): boolean {
  return error instanceof RepositoryError && error.code === code;
}

function withoutSnapshotHash(value: DatasetSnapshotV2) {
  const { snapshotHash: _snapshotHash, ...body } = value;
  return body;
}

function withoutEvidenceHash(value: CertifiedSnapshotEvidenceRecordV1) {
  const { evidenceHash: _evidenceHash, ...body } = value;
  return body;
}

function hasCode(error: unknown, code: string): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === code);
}
