import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import {
  canonicalHash,
  createGovernedDatasetScopeBindingV1,
  createMappingSpecV2,
  createSnapshotCertificationDefinitionV1,
  createSourceContractV1,
  type MappingSpecV2,
  type SnapshotCertificationDefinitionV1
} from "../src/contracts/index.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import { CertificationRuntimeAuthorityFactoryV1 } from "../src/control/certification-runtime-authority-v1.js";
import { GovernedDefinitionV2Store } from "../src/control/governed-definitions-v2.js";
import { SqliteHistoricalRuntimeAuthorityV1 } from "../src/control/historical-runtime-authority-v1.js";
import { LifecycleSnapshotCertificationDefinitionAuthorityV1 } from "../src/control/lifecycle-snapshot-certification-definition-authority-v1.js";
import { SqliteSourceDeliveryAuthorityV1 } from "../src/control/source-delivery-authority-v1.js";
import { InMemoryImmutableRepository } from "../src/repositories/in-memory.js";
import { SqliteCapturedSourceMaterialStoreV1 } from "../src/repositories/captured-source-material-v1.js";
import { SqliteCertificationArtifactStagingStoreV1 } from "../src/repositories/certification-artifact-staging-v1.js";
import { SqliteCertifiedSnapshotEvidenceV2Repository } from "../src/repositories/certified-snapshot-evidence-v2.js";
import { SqliteSnapshotCertificationAttemptStoreV1 } from "../src/repositories/snapshot-certification-attempts-v1.js";
import { SqliteSurveillanceEvidenceRepositories } from "../src/repositories/sqlite-surveillance.js";
import { GovernedDefinitionV2Resolver } from "../src/services/governed-definition-v2-resolver.js";
import { HistoricalMappingExecutionAuthorityV1 } from "../src/services/historical-mapping-execution-authority-v1.js";
import {
  modernSnapshotExtractionReceiptIdV1,
  type ModernSnapshotExtractionReceiptV1,
  type TrustedModernSnapshotExtractionV1
} from "../src/services/modern-snapshot-capture.js";
import {
  ModernSnapshotRuntimeV1Error,
  composeModernSnapshotRuntimeV1,
  type ModernSnapshotRuntimeV1Dependencies
} from "../src/services/modern-snapshot-runtime-v1.js";

const directories: string[] = [];
const TENANT = "tenant-a";
const CAPTURE_AT = "2026-02-01T00:00:00.000Z";
const OPERATOR = {
  tenantId: TENANT,
  actorId: "operator-a",
  authority: "platform_operator" as const,
  identitySource: "server_derived" as const
};
const RUNTIME_MAKER = { ...OPERATOR, actorId: "runtime-maker" };
const RUNTIME_CHECKER = { ...OPERATOR, actorId: "runtime-checker" };

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("composed modern runtime captures immutable source material and certifies only lifecycle-governed V2 evidence", async () => {
  const fixture = createFixture();
  try {
    const runtime = composeModernSnapshotRuntimeV1(fixture.dependencies);
    const captured = await runtime.capture.capture(OPERATOR, {
      sourceContractId: fixture.source.sourceContractId,
      deliveryId: "delivery-a"
    });
    assert.equal(captured.receipt.receiptId, modernSnapshotExtractionReceiptIdV1(captured.snapshot.snapshotId));
    assert.ok(await fixture.sourceMaterial.get({
      tenantId: TENANT, snapshotId: captured.snapshot.snapshotId, sectionId: "loans"
    }));

    const certified = await runtime.certification.certify({ snapshotId: captured.snapshot.snapshotId }, OPERATOR);
    assert.equal(certified.replayed, false);
    assert.ok(certified.evidenceV2);
    assert.equal(certified.evidenceV2.governance.control.definition.certificationDefinitionId, fixture.binding.bindingId);
    assert.equal(certified.evidenceV2.v1Evidence.certification.snapshotHash, captured.snapshot.snapshotHash);
    assert.equal(
      await fixture.repositories.certifiedSnapshotEvidence.get(TENANT, certified.evidence.certification.certificationManifestId),
      undefined,
      "lifecycle mode must never write legacy V1 evidence"
    );
    assert.deepEqual(
      await fixture.evidenceV2.get(TENANT, certified.evidence.certification.certificationManifestId),
      certified.evidenceV2
    );

    const replay = await runtime.certification.certify({ snapshotId: captured.snapshot.snapshotId }, OPERATOR);
    assert.equal(replay.replayed, true);
    assert.equal(replay.evidenceV2?.evidenceHash, certified.evidenceV2.evidenceHash);
  } finally {
    fixture.close();
  }
});

test("modern runtime rejects an incomplete production composition before it can expose capture or certification", () => {
  const fixture = createFixture();
  try {
    assert.throws(
      () => composeModernSnapshotRuntimeV1({ ...fixture.dependencies, sourceMaterial: {} as never }),
      (error: unknown) => error instanceof ModernSnapshotRuntimeV1Error && error.code === "INVALID_CONFIGURATION"
    );
    assert.throws(
      () => composeModernSnapshotRuntimeV1({ ...fixture.dependencies, tenantId: "invalid tenant" }),
      (error: unknown) => error instanceof ModernSnapshotRuntimeV1Error && error.code === "INVALID_CONFIGURATION"
    );
    assert.throws(
      () => composeModernSnapshotRuntimeV1({ ...fixture.dependencies, sourceMaterialMaximumBytes: 100_000_001 }),
      (error: unknown) => error instanceof ModernSnapshotRuntimeV1Error && error.code === "INVALID_CONFIGURATION"
    );
  } finally {
    fixture.close();
  }
});

function createFixture() {
  const directory = mkdtempSync(join(tmpdir(), "modern-snapshot-runtime-"));
  directories.push(directory);
  const artifacts = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "test-key", keys: { "test-key": Buffer.alloc(32, 7) }
  }, { maximumArtifactBytes: 1_000_000 });
  const source = sourceContract();
  const binding = createGovernedDatasetScopeBindingV1({
    contractVersion: 1, tenantId: TENANT, bindingId: "facility-a-binding", revision: 1,
    datasetId: "loan-dataset", sourceContract: {
      sourceContractId: source.sourceContractId, revision: source.revision, sourceContractHash: source.sourceContractHash
    }, scope: { scopeType: "facility", scopeId: "facility-a" }, effectiveFrom: "2026-01-01"
  });
  const sourceDeliveries = new SqliteSourceDeliveryAuthorityV1(join(directory, "deliveries.sqlite"), {
    clock: () => new Date("2026-01-31T00:02:00.000Z"), eventId: () => "delivery-event-a"
  });
  sourceDeliveries.register(OPERATOR, {
    deliveryId: "delivery-a", sourceContract: source, scopeBinding: binding,
    locator: {
      mode: "object_storage", format: "parquet", connectorId: "source-connector", bucket: "governed-deliveries",
      objectKey: "facility-a/loan-tape.parquet", immutableVersionId: "version-a",
      immutableVersionHash: canonicalHash({ connectorId: "source-connector", bucket: "governed-deliveries", objectKey: "facility-a/loan-tape.parquet", immutableVersionId: "version-a" }), contentHash: canonicalHash("content-a"), byteCount: 128
    },
    sourceObservedAt: "2026-01-31T00:00:00.000Z", receivedAt: "2026-01-31T00:01:00.000Z", idempotencyKey: "register-delivery-a"
  });

  let governedTick = 0;
  const governedStore = new GovernedDefinitionV2Store(join(directory, "governed.sqlite"), {
    clock: () => new Date(Date.UTC(2026, 0, 10, 12, 0, governedTick++))
  });
  const governed = new GovernedDefinitionV2Resolver(governedStore);
  let runtimeEvent = 0;
  const historicalRuntime = new SqliteHistoricalRuntimeAuthorityV1(join(directory, "runtime.sqlite"), artifacts, {
    clock: () => new Date("2026-01-09T12:00:00.000Z"), eventId: () => `runtime-event-${++runtimeEvent}`
  });
  const runtimeEvidence = runtime(historicalRuntime);
  historicalRuntime.activateRuntime(RUNTIME_CHECKER, {
    runtimeBundleId: runtimeEvidence.runtime.runtimeBundleId, runtimeBundleHash: runtimeEvidence.runtime.runtimeBundleHash,
    idempotencyKey: "activate-runtime-a"
  });

  const sourceView = activate(governedStore, { definitionVersionId: "source-v1", definitionKey: source.sourceKey, kind: "source_contract", document: source });
  const bindingView = activate(governedStore, { definitionVersionId: "binding-v1", definitionKey: binding.bindingId, kind: "dataset_scope_binding", document: binding });
  const mappingDocument = mapping(source, runtimeEvidence.dictionary);
  const mappingView = activate(governedStore, { definitionVersionId: "mapping-v1", definitionKey: mappingDocument.mappingKey, kind: "mapping_spec", document: mappingDocument });
  const mappings = new HistoricalMappingExecutionAuthorityV1(governed);
  const historicalMapping = mappings.resolveFrozenAt({ tenantId: TENANT, definitionVersionId: mappingView.version.definitionVersionId, certificationAt: CAPTURE_AT });
  const sourceRef = governed.resolveFrozen({ tenantId: TENANT, definitionVersionId: sourceView.version.definitionVersionId }).reference;
  const scopeRef = governed.resolveFrozen({ tenantId: TENANT, definitionVersionId: bindingView.version.definitionVersionId }).reference;
  const control = controlDefinition({ source, binding, sourceRef, scopeRef, historicalMapping, runtime: runtimeEvidence.runtime });
  activate(governedStore, { definitionVersionId: "control-v1", definitionKey: binding.bindingId, kind: "snapshot_certification_control", document: control });

  const repositories = new SqliteSurveillanceEvidenceRepositories(join(directory, "surveillance.sqlite"));
  const receipts = new InMemoryImmutableRepository<ModernSnapshotExtractionReceiptV1>("modern-runtime-receipts", (record) => record.receiptId);
  const sourceMaterial = new SqliteCapturedSourceMaterialStoreV1(join(directory, "source-material.sqlite"));
  const evidenceV2 = new SqliteCertifiedSnapshotEvidenceV2Repository(join(directory, "evidence-v2.sqlite"));
  const attempts = new SqliteSnapshotCertificationAttemptStoreV1(join(directory, "attempts.sqlite"));
  const artifactStaging = new SqliteCertificationArtifactStagingStoreV1(join(directory, "staging.sqlite"));
  const lifecycleDefinitions = new LifecycleSnapshotCertificationDefinitionAuthorityV1({
    governed, mappings, runtime: new CertificationRuntimeAuthorityFactoryV1(historicalRuntime)
  });
  const records = [{ assetNumber: "loan-1", actualEndBalance: "100", pool: "a", currency: "USD" }] as const;
  const dependencies: ModernSnapshotRuntimeV1Dependencies = {
    tenantId: TENANT, sourceDeliveries,
    sourceMaterialMaximumBytes: 1_000_000,
    extraction: {
      async extract(input): Promise<TrustedModernSnapshotExtractionV1> {
        assert.equal(input.tenantId, TENANT);
        return {
          tenantId: TENANT, datasetId: binding.datasetId, facilityId: binding.scope.scopeId,
          snapshotId: input.snapshotId, deliveryId: input.deliveryId, asOfDate: "2026-01-31",
          knowledge: { sourceObservedAt: "2026-01-31T00:00:00.000Z", extractedAt: "2026-01-31T00:02:00.000Z", receivedAt: "2026-01-31T00:03:00.000Z" },
          watermark: { mode: "none" }, hashes: {
            contentHash: canonicalHash("content-a"), schemaHash: canonicalHash("schema-a"), profileHash: canonicalHash("profile-a"),
            catalogHash: canonicalHash("catalog-a"), parserHash: canonicalHash({ parserId: source.parserPolicy.parserId, parserVersion: source.parserPolicy.parserVersion, optionsHash: source.parserPolicy.optionsHash })
          }, rowCount: 1, columnCount: 4, byteCount: 128, elapsedMs: 1,
          sections: [{ sectionId: "loans", required: true, present: true, rowCount: 1, contentHash: canonicalHash("loans-content"), schemaHash: canonicalHash("loans-schema"), controlPopulationHash: canonicalHash(records) }],
          correction: { kind: "original" }, sourceSections: [{ sectionId: "loans", records }]
        };
      }
    },
    receipts, snapshots: repositories.datasetSnapshots,
    certifiedEvidenceV2: evidenceV2, attempts, artifactStaging, sourceMaterial, lifecycleDefinitions,
    certificationRuntime: new CertificationRuntimeAuthorityFactoryV1(historicalRuntime),
    dimensions: { async resolveForMapping() { return []; } }, artifacts, now: () => CAPTURE_AT
  };
  return {
    dependencies, source, binding, repositories, sourceMaterial, evidenceV2,
    close() {
      artifactStaging.close(); attempts.close(); evidenceV2.close(); sourceMaterial.close(); repositories.close();
      historicalRuntime.close(); governedStore.close(); sourceDeliveries.close();
    }
  };
}

function sourceContract() {
  return createSourceContractV1({
    contractVersion: 1, tenantId: TENANT, sourceContractId: "loan-source-a", sourceKey: "loan-tape", revision: 1, status: "active",
    delivery: { mode: "object_storage", format: "parquet", connectorId: "source-connector", credentialRef: "kms/source", bucket: "governed-deliveries", keyPattern: "facility-a/*.parquet", immutableVersionRequired: true },
    schemaPolicy: { columns: [
      { sourceName: "assetNumber", ordinal: 0, nativeType: "string", nullable: false, required: true },
      { sourceName: "actualEndBalance", ordinal: 1, nativeType: "decimal", nullable: false, required: true },
      { sourceName: "pool", ordinal: 2, nativeType: "string", nullable: false, required: true },
      { sourceName: "currency", ordinal: 3, nativeType: "string", nullable: false, required: true }
    ], allowUnknownColumns: false, requireStableOrdinals: true },
    parserPolicy: { format: "parquet", parserId: "parquet-v1", parserVersion: "1.0.0", optionsHash: canonicalHash("parser-options"), exactDecimalMode: "string", timezone: "UTC", rejectSchemaMerging: true },
    extractionPolicy: { mode: "full", readOnly: true, maximumRows: 1_000, maximumColumns: 100, maximumBytes: 1_000_000, timeoutMs: 1_000, cursorRows: 100 },
    sections: [{ sectionId: "loans", required: true, selector: "loans", keyFields: ["assetNumber"] }],
    effectiveFrom: "2026-01-01", createdBy: "source-maker", createdAt: "2026-01-01T00:00:00.000Z", approvedBy: "source-checker", approvedAt: "2026-01-01T00:01:00.000Z"
  });
}

function activate(store: GovernedDefinitionV2Store, input: { readonly definitionVersionId: string; readonly definitionKey: string; readonly kind: Parameters<GovernedDefinitionV2Store["propose"]>[0]["kind"]; readonly document: unknown }) {
  let view = store.propose({ tenantId: TENANT, ...input, semanticVersion: "1.0.0", effectiveFrom: "2026-01-01", proposedBy: "maker-a", idempotencyKey: `${input.definitionVersionId}-propose` });
  for (const toStatus of ["validated", "approved", "active"] as const) view = store.transition({ tenantId: TENANT, definitionVersionId: input.definitionVersionId, toStatus, expectedRevision: view.lifecycleRevision, actor: "checker-a", idempotencyKey: `${input.definitionVersionId}-${toStatus}` });
  return view;
}

function runtime(authority: SqliteHistoricalRuntimeAuthorityV1) {
  const dictionaryContent = { dictionary: { fields: ["loan_id", "current_balance", "pool", "currency"] }, fieldPolicy: { nulls: "preserve" } };
  const dictionary = authority.registerBundle(RUNTIME_MAKER, { bundleKind: "dictionary", bundleId: "dictionary-a", version: "1.0.0", mediaType: "application/json", createdAt: "2026-01-01T00:00:00.000Z", dictionaryVersion: "1.0.0", dictionaryHash: canonicalHash(dictionaryContent.dictionary), fieldPolicyVersion: "1.0.0", fieldPolicyHash: canonicalHash(dictionaryContent.fieldPolicy), content: dictionaryContent, idempotencyKey: "dictionary-a" }).value;
  if (dictionary.bundleKind !== "dictionary") throw new Error("Expected dictionary bundle");
  const compiler = authority.registerBundle(RUNTIME_MAKER, { bundleKind: "mapping_compiler", bundleId: "compiler-a", version: "1.0.0", mediaType: "application/json", createdAt: "2026-01-01T00:01:00.000Z", content: { compiler: "mapping-v2" }, idempotencyKey: "compiler-a" }).value;
  if (compiler.bundleKind !== "mapping_compiler") throw new Error("Expected compiler bundle");
  const assembly = authority.registerRuntime(RUNTIME_MAKER, { runtimeBundleId: "runtime-a", runtimeVersion: "1.0.0", dictionary, mappingCompiler: compiler, methodologies: [], assembledAt: "2026-01-01T00:02:00.000Z", idempotencyKey: "runtime-a" }).value;
  return { dictionary, compiler, runtime: assembly };
}

function mapping(source: ReturnType<typeof sourceContract>, dictionary: ReturnType<typeof runtime>["dictionary"]): MappingSpecV2 {
  return createMappingSpecV2({
    contractVersion: 2, tenantId: TENANT, mappingSpecId: "mapping-spec-a", mappingKey: "loan-tape", revision: 1, status: "active",
    sourceContract: { sourceContractId: source.sourceContractId, revision: source.revision, sourceContractHash: source.sourceContractHash }, dictionaryBundle: dictionary,
    rules: [
      { ruleId: "loan-id", canonicalField: "loan_id", expression: { op: "source", column: "assetNumber" }, onError: "fail_application" },
      { ruleId: "balance", canonicalField: "current_balance", expression: { op: "source", column: "actualEndBalance" }, onError: "fail_application" },
      { ruleId: "pool", canonicalField: "pool", expression: { op: "source", column: "pool" }, onError: "fail_application" },
      { ruleId: "currency", canonicalField: "currency", expression: { op: "source", column: "currency" }, onError: "fail_application" }
    ], requiredCanonicalFields: ["loan_id", "current_balance", "pool", "currency"],
    createdBy: "mapping-maker", createdAt: "2026-01-01T00:00:00.000Z", approvedBy: "mapping-checker", approvedAt: "2026-01-01T00:01:00.000Z"
  });
}

function controlDefinition(input: { readonly source: ReturnType<typeof sourceContract>; readonly binding: ReturnType<typeof createGovernedDatasetScopeBindingV1>; readonly sourceRef: ReturnType<GovernedDefinitionV2Resolver["resolveFrozen"]>["reference"]; readonly scopeRef: ReturnType<GovernedDefinitionV2Resolver["resolveFrozen"]>["reference"]; readonly historicalMapping: ReturnType<HistoricalMappingExecutionAuthorityV1["resolveFrozenAt"]>; readonly runtime: ReturnType<typeof runtime>["runtime"] }): SnapshotCertificationDefinitionV1 {
  return createSnapshotCertificationDefinitionV1({
    contractVersion: 1, definitionKind: "snapshot_certification_control", tenantId: TENANT, certificationDefinitionId: input.binding.bindingId, revision: 1,
    sourceContract: input.binding.sourceContract, sourceContractExecution: { ...input.sourceRef, sourceContract: input.binding.sourceContract },
    scopeBinding: input.binding, scopeBindingExecution: { ...input.scopeRef, bindingId: input.binding.bindingId, revision: input.binding.revision, bindingHash: input.binding.bindingHash, sourceContract: input.binding.sourceContract },
    mappingExecution: { ...input.historicalMapping.reference, mappingSpecId: input.historicalMapping.mappingSpec.mappingSpecId, mappingSpecRevision: input.historicalMapping.mappingSpec.revision, mappingSpecHash: input.historicalMapping.mappingSpec.mappingSpecHash, sourceContract: input.binding.sourceContract, activation: input.historicalMapping.activationEvidence, window: input.historicalMapping.window },
    runtime: { runtimeBundleId: input.runtime.runtimeBundleId, runtimeVersion: input.runtime.runtimeVersion, runtimeBundleHash: input.runtime.runtimeBundleHash, dictionary: input.runtime.dictionary, mappingCompiler: input.runtime.mappingCompiler },
    dataQuality: { definitionId: "dq-a", rulesetId: "dq-rules-a", mappingSectionId: "loans", requiredSectionIds: ["loans"], rules: [{ ruleId: "loan-id", type: "required", field: "loan_id", severity: "critical", blocking: true }], balanceField: "current_balance", materialBalance: "0", window: { effectiveFrom: "2026-01-01" } },
    certificationReconciliation: { definitionId: "reconciliation-a", reconciliationId: "pool-tie-out", requiredSectionIds: ["loans"], controls: [{ controlId: "loan-pool", sectionId: "loans", recordSource: "normalized", dimensions: ["pool"], balanceField: "current_balance", currencyField: "currency", expected: [{ dimensions: { pool: "a" }, rowCount: 1, balance: "100", currency: "USD" }], balanceTolerance: "0" }], window: { effectiveFrom: "2026-01-01" } },
    window: { effectiveFrom: "2026-01-01" }, approval: { status: "pending_durable_approval", authority: "governed_definition_v2_lifecycle" }
  });
}
