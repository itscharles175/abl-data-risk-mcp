import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, test } from "node:test";

import {
  canonicalHash,
  createGovernedDatasetScopeBindingV1,
  createMappingApplicationV1,
  createMappingSpecV2,
  type Sha256Hash
} from "../src/contracts/index.js";
import {
  createCertifiedSnapshotEvidenceRecordV1
} from "../src/contracts/certified-snapshot-evidence-v1.js";
import {
  createCertifiedSnapshotEvidenceRecordV2,
  type CertifiedSnapshotEvidenceRecordV2,
  type CertifiedSnapshotEvidenceRecordV2Input
} from "../src/contracts/certified-snapshot-evidence-v2.js";
import { createSnapshotCertificationAttemptV1 } from "../src/contracts/snapshot-certification-attempt-v1.js";
import { createSnapshotCertificationDefinitionV1 } from "../src/contracts/snapshot-certification-definition-v1.js";
import {
  SqliteCertifiedSnapshotEvidenceV2Repository
} from "../src/repositories/certified-snapshot-evidence-v2.js";
import { SqliteCertifiedSnapshotEvidenceV1Repository } from "../src/repositories/sqlite-surveillance.js";
import { RepositoryError } from "../src/repositories/ports.js";

const directories: string[] = [];
const HASH = (value: unknown): Sha256Hash => canonicalHash(value);

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("V2 evidence repository is tenant-scoped, actor-idempotent, immutable, paged, and reopen-safe", async () => {
  const path = databasePath();
  const repository = new SqliteCertifiedSnapshotEvidenceV2Repository(path);
  const first = evidence("a");
  const second = evidence("b");
  const context = { tenantId: "tenant-a", actorId: "certification-checker", idempotencyKey: "attempt-a" };

  assert.equal((await repository.put(first, context)).replayed, false);
  assert.equal((await repository.put(first, context)).replayed, true);
  await repository.put(second, { ...context, idempotencyKey: "attempt-b" });
  assert.equal(await repository.get("tenant-b", first.certificationAttempt.certificationManifestId), undefined);
  const page = await repository.list("tenant-a", { limit: 1 });
  assert.equal(page.items.length, 1);
  assert.ok(page.nextCursor);
  assert.equal((await repository.list("tenant-a", { cursor: page.nextCursor ?? undefined })).items.length, 1);

  await assert.rejects(
    repository.put(first, { ...context, actorId: "other-checker", idempotencyKey: "other" }),
    (error: unknown) => repositoryCode(error, "ALREADY_EXISTS")
  );
  await assert.rejects(
    repository.put(second, context),
    (error: unknown) => repositoryCode(error, "IDEMPOTENCY_CONFLICT")
  );

  const database = new DatabaseSync(path);
  assert.throws(
    () => database.prepare("UPDATE certified_snapshot_evidence_v2 SET recorded_at = ?").run("2026-01-03T00:00:00.000Z"),
    /immutable/u
  );
  database.close();
  repository.close();

  const reopened = new SqliteCertifiedSnapshotEvidenceV2Repository(path);
  assert.equal(
    (await reopened.get("tenant-a", first.certificationAttempt.certificationManifestId))?.evidenceHash,
    first.evidenceHash
  );
  reopened.close();
});

test("V2 evidence repository rejects tampered schema on reopen", async () => {
  const path = databasePath();
  const repository = new SqliteCertifiedSnapshotEvidenceV2Repository(path);
  repository.close();
  const database = new DatabaseSync(path);
  database.exec("PRAGMA writable_schema = ON");
  database
    .prepare(
      `UPDATE sqlite_master
          SET sql = replace(sql, 'record_json TEXT NOT NULL', 'record_json BLOB NOT NULL')
        WHERE type = 'table' AND name = 'certified_snapshot_evidence_v2'`
    )
    .run();
  database.exec("PRAGMA writable_schema = OFF");
  database.close();
  assert.throws(
    () => new SqliteCertifiedSnapshotEvidenceV2Repository(path),
    (error: unknown) => repositoryCode(error, "INTEGRITY_FAILURE")
  );
});

test("V2 evidence storage coexists with the independent V1 evidence component", async () => {
  const path = databasePath();
  const v1 = new SqliteCertifiedSnapshotEvidenceV1Repository(path);
  const v2 = new SqliteCertifiedSnapshotEvidenceV2Repository(path);
  const record = evidence("coexist");
  const stored = await v2.put(record, {
    tenantId: "tenant-a",
    actorId: "certification-checker",
    idempotencyKey: "coexist"
  });
  assert.equal(stored.record.evidenceHash, record.evidenceHash);
  v2.close();
  v1.close();
});

function evidence(suffix: string): CertifiedSnapshotEvidenceRecordV2 {
  const sourceContract = {
    sourceContractId: `loan-source-${suffix}`,
    revision: 1,
    sourceContractHash: HASH(`loan-source-${suffix}`)
  };
  const scopeBinding = createGovernedDatasetScopeBindingV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    bindingId: `facility-binding-${suffix}`,
    revision: 1,
    datasetId: `loan-dataset-${suffix}`,
    sourceContract,
    scope: { scopeType: "facility", scopeId: `facility-${suffix}` },
    effectiveFrom: "2026-01-01"
  });
  const dictionary = {
    contractVersion: 1 as const,
    bundleKind: "dictionary" as const,
    bundleId: `dictionary-${suffix}`,
    version: "1.0.0",
    contentHash: HASH(`dictionary-content-${suffix}`),
    artifactId: `dictionary-artifact-${suffix}`,
    mediaType: "application/json",
    createdAt: "2026-01-01T00:00:00.000Z",
    dictionaryVersion: "1.0.0",
    dictionaryHash: HASH(`dictionary-${suffix}`),
    fieldPolicyVersion: "1.0.0",
    fieldPolicyHash: HASH(`field-policy-${suffix}`)
  };
  const compiler = {
    contractVersion: 1 as const,
    bundleKind: "mapping_compiler" as const,
    bundleId: `compiler-${suffix}`,
    version: "1.0.0",
    contentHash: HASH(`compiler-content-${suffix}`),
    artifactId: `compiler-artifact-${suffix}`,
    mediaType: "application/json",
    createdAt: "2026-01-01T00:00:00.000Z"
  };
  const mappingSpec = createMappingSpecV2({
    contractVersion: 2,
    tenantId: "tenant-a",
    mappingSpecId: `mapping-spec-${suffix}`,
    mappingKey: `loan-tape-${suffix}`,
    revision: 1,
    status: "active",
    sourceContract,
    dictionaryBundle: dictionary,
    rules: [{ ruleId: "loan-id", canonicalField: "loan_id", expression: { op: "source", column: "loan_id" }, onError: "fail_application" }],
    requiredCanonicalFields: ["loan_id"],
    createdBy: "mapping-maker",
    createdAt: "2026-01-01T00:00:00.000Z",
    approvedBy: "mapping-checker",
    approvedAt: "2026-01-01T00:01:00.000Z"
  });
  const mappingExecution = {
    definitionVersionId: `mapping-version-${suffix}`,
    definitionKey: mappingSpec.mappingKey,
    kind: "mapping_spec" as const,
    semanticVersion: "1.0.0",
    versionHash: HASH(`mapping-version-${suffix}`),
    documentHash: HASH(`mapping-document-${suffix}`),
    approvalEventHash: HASH(`mapping-approval-${suffix}`),
    mappingSpecId: mappingSpec.mappingSpecId,
    mappingSpecRevision: mappingSpec.revision,
    mappingSpecHash: mappingSpec.mappingSpecHash,
    sourceContract,
    activation: { status: "active" as const, lifecycleRevision: 3, activatedBy: "mapping-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationEventHash: HASH(`mapping-activation-${suffix}`) },
    window: { effectiveFrom: "2026-01-01" }
  };
  const sourceExecution = {
    definitionVersionId: `source-version-${suffix}`,
    definitionKey: `loan-source-key-${suffix}`,
    kind: "source_contract" as const,
    semanticVersion: "1.0.0",
    versionHash: HASH(`source-version-${suffix}`),
    documentHash: HASH(`source-document-${suffix}`),
    approvalEventHash: HASH(`source-approval-${suffix}`),
    sourceContract
  };
  const scopeExecution = {
    definitionVersionId: `scope-version-${suffix}`,
    definitionKey: scopeBinding.bindingId,
    kind: "dataset_scope_binding" as const,
    semanticVersion: "1.0.0",
    versionHash: HASH(`scope-version-${suffix}`),
    documentHash: HASH(`scope-document-${suffix}`),
    approvalEventHash: HASH(`scope-approval-${suffix}`),
    bindingId: scopeBinding.bindingId,
    revision: scopeBinding.revision,
    bindingHash: scopeBinding.bindingHash,
    sourceContract
  };
  const definition = createSnapshotCertificationDefinitionV1({
    contractVersion: 1,
    definitionKind: "snapshot_certification_control",
    tenantId: "tenant-a",
    certificationDefinitionId: scopeBinding.bindingId,
    revision: 1,
    sourceContract,
    sourceContractExecution: sourceExecution,
    scopeBinding,
    scopeBindingExecution: scopeExecution,
    mappingExecution,
    runtime: { runtimeBundleId: `runtime-${suffix}`, runtimeVersion: "1.0.0", runtimeBundleHash: HASH(`runtime-${suffix}`), dictionary, mappingCompiler: compiler },
    dataQuality: { definitionId: `dq-${suffix}`, rulesetId: `dq-rules-${suffix}`, mappingSectionId: "loans", requiredSectionIds: ["loans"], rules: [{ ruleId: "loan-required", type: "required", field: "loan_id", severity: "critical", blocking: true }], balanceField: "current_balance", materialBalance: "1", window: { effectiveFrom: "2026-01-01" } },
    certificationReconciliation: { definitionId: `recon-${suffix}`, reconciliationId: `recon-${suffix}`, requiredSectionIds: ["loans"], controls: [{ controlId: "pool-balance", sectionId: "loans", recordSource: "normalized", dimensions: ["portfolio_id"], balanceField: "current_balance", currencyField: "currency", expected: [{ dimensions: { portfolio_id: `portfolio-${suffix}` }, rowCount: 1, balance: "100", currency: "USD" }], balanceTolerance: "0" }], window: { effectiveFrom: "2026-01-01" } },
    window: { effectiveFrom: "2026-01-01" },
    approval: { status: "pending_durable_approval", authority: "governed_definition_v2_lifecycle" }
  });
  const snapshot = { snapshotId: `snapshot-${suffix}`, snapshotHash: HASH(`snapshot-${suffix}`), contentHash: HASH(`snapshot-content-${suffix}`) };
  const mappingApplication = createMappingApplicationV1({
    contractVersion: 1, tenantId: "tenant-a", mappingApplicationId: `application-${suffix}`, snapshot,
    mappingSpec: { mappingSpecId: mappingSpec.mappingSpecId, revision: mappingSpec.revision, mappingSpecHash: mappingSpec.mappingSpecHash },
    dictionaryBundle: dictionary, runtimeBundle: { runtimeBundleId: `runtime-${suffix}`, runtimeBundleHash: HASH(`runtime-${suffix}`), runtimeVersion: "1.0.0" },
    inputPopulationHash: HASH(`input-population-${suffix}`), outputPopulationHash: HASH(`output-population-${suffix}`), inputRowCount: 1, outputRowCount: 1, rejectedRowCount: 0,
    appliedBy: "mapping-worker", appliedAt: "2026-01-02T00:01:00.000Z"
  });
  const populationBody = {
    contractVersion: 1 as const, tenantId: "tenant-a", populationId: `population-${suffix}`, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash,
    mappingApplicationId: mappingApplication.mappingApplicationId, mappingApplicationHash: mappingApplication.mappingApplicationHash,
    populationHash: mappingApplication.outputPopulationHash, fieldSetHash: HASH(`field-set-${suffix}`), rowCount: 1,
    dataQuality: { runId: `dq-run-${suffix}`, rulesetId: `dq-rules-${suffix}`, rulesetHash: HASH(`dq-rules-${suffix}`), resultHash: HASH(`dq-result-${suffix}`), publicationDecision: "publish" as const, blockerCodes: [] as string[] },
    reconciliation: { reconciliationId: `recon-${suffix}`, definitionHash: HASH(`recon-definition-${suffix}`), resultHash: HASH(`recon-result-${suffix}`), passed: true as const, populationHash: mappingApplication.outputPopulationHash },
    certifiedBy: "certification-checker", certifiedAt: "2026-01-02T01:00:00.000Z"
  };
  const population = { ...populationBody, certificationHash: HASH(populationBody) };
  const certificationBody = {
    contractVersion: 1 as const, tenantId: "tenant-a", certificationManifestId: `manifest-${suffix}`, evidenceFormat: "modern_snapshot_v2" as const,
    snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, populationId: population.populationId, populationCertificationHash: population.certificationHash,
    mappingApplicationId: mappingApplication.mappingApplicationId, mappingApplicationHash: mappingApplication.mappingApplicationHash,
    normalizedArtifactId: `artifact-${suffix}`, normalizedArtifactContentHash: HASH(`artifact-content-${suffix}`), dataQualityResultHash: population.dataQuality.resultHash,
    reconciliationResultHash: population.reconciliation.resultHash, populationHash: population.populationHash, rowCount: population.rowCount,
    certifiedBy: population.certifiedBy, certifiedAt: population.certifiedAt
  };
  const v1Evidence = createCertifiedSnapshotEvidenceRecordV1({
    contractVersion: 1, tenantId: "tenant-a", certification: { ...certificationBody, certificationManifestHash: HASH(certificationBody) }, population,
    mappingSpec, mappingApplication,
    normalizedArtifact: { tenantId: "tenant-a", artifactId: `artifact-${suffix}`, kind: "normalized_snapshot", mediaType: "application/json", artifactContractVersion: 2, artifactHash: HASH(`artifact-${suffix}`), contentHash: certificationBody.normalizedArtifactContentHash, byteLength: 100, keyId: "key-a", uri: `abl-artifact://${"a".repeat(64)}`, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, normalizedPopulationId: population.populationId, mappingApplicationId: mappingApplication.mappingApplicationId, mappingApplicationHash: mappingApplication.mappingApplicationHash, populationHash: population.populationHash, fieldSetHash: population.fieldSetHash, rowCount: 1, createdAt: "2026-01-02T00:30:00.000Z" },
    dataQualityPopulation: { populationHash: population.populationHash, fieldSetHash: population.fieldSetHash, rowCount: 1 }, recordedAt: "2026-01-02T01:00:00.000Z"
  });
  const controlReference = { definitionVersionId: `control-version-${suffix}`, definitionKey: definition.certificationDefinitionId, kind: "snapshot_certification_control" as const, semanticVersion: "1.0.0", versionHash: HASH(`control-version-${suffix}`), documentHash: HASH(definition), approvalEventHash: HASH(`control-approval-${suffix}`) };
  const input = {
    contractVersion: 2 as const, tenantId: "tenant-a", v1Evidence,
    certificationAttempt: createSnapshotCertificationAttemptV1({ contractVersion: 1, tenantId: "tenant-a", certificationManifestId: certificationBody.certificationManifestId, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, actorId: "certification-checker", requestHash: HASH(`certification-request-${suffix}`), certifiedAt: certificationBody.certifiedAt, createdAt: "2026-01-02T01:00:00.000Z" }),
    governance: {
      control: { definition, reference: controlReference, approval: { status: "approved" as const, proposedBy: "control-maker", approvedBy: "control-checker", approvedAt: "2026-01-01T00:01:00.000Z", approvalEventHash: controlReference.approvalEventHash }, activation: { status: "active" as const, lifecycleRevision: 3, activatedBy: "control-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationEventHash: HASH(`control-activation-${suffix}`) } },
      sourceContract: { raw: sourceContract, execution: sourceExecution }, scopeBinding: { raw: scopeBinding, execution: scopeExecution }, mapping: { execution: mappingExecution, activation: mappingExecution.activation },
      runtime: { runtimeBundleId: `runtime-${suffix}`, runtimeVersion: "1.0.0", runtimeBundleHash: HASH(`runtime-${suffix}`), activation: { tenantId: "tenant-a", runtimeBundleId: `runtime-${suffix}`, runtimeBundleHash: HASH(`runtime-${suffix}`), registeredBy: "runtime-maker", registeredAt: "2026-01-01T00:00:00.000Z", activatedBy: "runtime-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationHash: HASH(`runtime-activation-${suffix}`) }, dictionary, mappingCompiler: compiler }
    },
    recordedAt: "2026-01-02T01:00:00.000Z"
  } satisfies CertifiedSnapshotEvidenceRecordV2Input;
  return createCertifiedSnapshotEvidenceRecordV2(input);
}

function databasePath(): string {
  const directory = mkdtempSync(join(tmpdir(), "certified-snapshot-evidence-v2-"));
  directories.push(directory);
  return join(directory, "evidence.sqlite");
}

function repositoryCode(error: unknown, expected: RepositoryError["code"]): boolean {
  return error instanceof RepositoryError && error.code === expected;
}
