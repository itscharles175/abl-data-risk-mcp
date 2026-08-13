import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import {
  canonicalHash,
  createGovernedDatasetScopeBindingV1,
  createGovernedSourceDeliveryRecordV1,
  createMappingSpecV2,
  createSnapshotCertificationAttemptV1,
  createSnapshotCertificationDefinitionV1,
  createSourceContractV1,
  type MappingSpecV2,
  type SnapshotCertificationDefinitionV1
} from "../src/contracts/index.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import { CertificationRuntimeAuthorityFactoryV1 } from "../src/control/certification-runtime-authority-v1.js";
import { GovernedDefinitionV2Store } from "../src/control/governed-definitions-v2.js";
import { SqliteHistoricalRuntimeAuthorityV1 } from "../src/control/historical-runtime-authority-v1.js";
import {
  LifecycleSnapshotCertificationDefinitionAuthorityError,
  LifecycleSnapshotCertificationDefinitionAuthorityV1
} from "../src/control/lifecycle-snapshot-certification-definition-authority-v1.js";
import { HistoricalMappingExecutionAuthorityV1 } from "../src/services/historical-mapping-execution-authority-v1.js";
import { GovernedDefinitionV2Resolver } from "../src/services/governed-definition-v2-resolver.js";
import {
  modernSnapshotExtractionReceiptIdV1,
  parseModernSnapshotExtractionReceiptV1
} from "../src/services/modern-snapshot-capture.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("lifecycle certification authority selects one facility control and replays exact approved lineage", async () => {
  const fixture = fixtureForAuthority();
  try {
    const detailed = await fixture.authority.resolveForCertificationAttemptDetailed({
      evidence: fixture.evidence,
      attempt: fixture.attempt
    });
    assert.ok(detailed);
    const resolved = detailed.resolution;
    assert.ok(resolved);
    assert.equal(resolved.mappingSpec.mappingSpecId, "mapping-spec-a");
    assert.equal(resolved.mappingSpec.status, "active");
    assert.equal(resolved.runtime.runtimeBundleId, fixture.runtime.runtimeBundleId);
    assert.equal(resolved.dataQuality.definitionId, "dq-a");
    assert.equal(resolved.reconciliation.reconciliationId, "pool-tie-out");
    assert.equal(detailed.governance.control.definition.certificationDefinitionId, fixture.evidence.scopeBinding.bindingId);
    assert.equal(detailed.governance.control.reference.documentHash, canonicalHash(detailed.governance.control.definition));
    assert.equal(detailed.governance.control.activation.status, "active");
    assert.equal(detailed.governance.runtime.activation.runtimeBundleHash, fixture.runtime.runtimeBundleHash);

    const compatibility = await fixture.authority.resolveForCertificationAttempt({
      evidence: fixture.evidence,
      attempt: fixture.attempt
    });
    assert.deepEqual(compatibility, resolved);
  } finally {
    fixture.close();
  }
});

test("lifecycle certification authority rejects substituted immutable scope/delivery evidence", async () => {
  const fixture = fixtureForAuthority();
  try {
    await assert.rejects(
      fixture.authority.resolveForCertificationAttempt({
        evidence: { ...fixture.evidence, deliveryHash: canonicalHash("substituted-delivery") },
        attempt: fixture.attempt
      }),
      (error: unknown) => error instanceof LifecycleSnapshotCertificationDefinitionAuthorityError && error.code === "INVALID_INPUT"
    );
  } finally {
    fixture.close();
  }
});

test("lifecycle certification authority refuses an attempt not bound to the captured snapshot", async () => {
  const fixture = fixtureForAuthority();
  try {
    const early = createSnapshotCertificationAttemptV1({
      contractVersion: 1,
      tenantId: "tenant-a",
      certificationManifestId: "certification-manifest-a",
      snapshotId: "snapshot-substituted",
      snapshotHash: canonicalHash("snapshot-substituted"),
      actorId: "certification-checker",
      requestHash: canonicalHash("certification-request-a"),
      certifiedAt: "2026-02-01T00:00:00.000Z",
      createdAt: "2026-02-01T00:00:00.000Z"
    });
    await assert.rejects(
      fixture.authority.resolveForCertificationAttempt({ evidence: fixture.evidence, attempt: early }),
      (error: unknown) => error instanceof LifecycleSnapshotCertificationDefinitionAuthorityError && error.code === "INVALID_INPUT"
    );
  } finally {
    fixture.close();
  }
});

function fixtureForAuthority() {
  const directory = mkdtempSync(join(tmpdir(), "lifecycle-certification-definition-"));
  directories.push(directory);
  let tick = 0;
  const governedStore = new GovernedDefinitionV2Store(join(directory, "governed.sqlite"), {
    clock: () => new Date(Date.UTC(2026, 0, 10, 12, 0, tick++))
  });
  const governed = new GovernedDefinitionV2Resolver(governedStore);
  const artifacts = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "test-key",
    keys: { "test-key": Buffer.alloc(32, 17) }
  });
  let runtimeEvent = 0;
  const runtimeAuthority = new SqliteHistoricalRuntimeAuthorityV1(
    join(directory, "runtime.sqlite"),
    artifacts,
    {
      clock: () => new Date("2026-01-09T12:00:00.000Z"),
      eventId: () => `runtime-event-${++runtimeEvent}`
    }
  );
  const runtimeEvidence = runtime(runtimeAuthority);
  runtimeAuthority.activateRuntime(CHECKER, {
    runtimeBundleId: runtimeEvidence.runtime.runtimeBundleId,
    runtimeBundleHash: runtimeEvidence.runtime.runtimeBundleHash,
    idempotencyKey: "runtime-activate"
  });

  const source = createSourceContractV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    sourceContractId: "loan-source-a",
    sourceKey: "loan-tape",
    revision: 1,
    status: "active",
    delivery: {
      mode: "object_storage", format: "parquet", connectorId: "source-connector",
      credentialRef: "kms/source-connector", bucket: "governed-deliveries",
      keyPattern: "facility-*/*.parquet", immutableVersionRequired: true
    },
    schemaPolicy: {
      columns: [{ sourceName: "loan_id", ordinal: 0, nativeType: "string", nullable: false, required: true }],
      allowUnknownColumns: false,
      requireStableOrdinals: true
    },
    parserPolicy: {
      format: "parquet", parserId: "parquet-v1", parserVersion: "1.0.0",
      optionsHash: canonicalHash("parser-options"), exactDecimalMode: "string",
      timezone: "UTC", rejectSchemaMerging: true
    },
    extractionPolicy: {
      mode: "full", readOnly: true, maximumRows: 1_000, maximumColumns: 100,
      maximumBytes: 1_000_000, timeoutMs: 1_000, cursorRows: 100
    },
    sections: [{ sectionId: "loans", required: true, selector: "loans", keyFields: ["loan_id"] }],
    effectiveFrom: "2026-01-01",
    createdBy: "source-maker",
    createdAt: "2026-01-01T00:00:00.000Z",
    approvedBy: "source-checker",
    approvedAt: "2026-01-01T00:01:00.000Z"
  });
  const binding = createGovernedDatasetScopeBindingV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    bindingId: "facility-a-binding",
    revision: 1,
    datasetId: "loan-dataset",
    sourceContract: {
      sourceContractId: source.sourceContractId,
      revision: source.revision,
      sourceContractHash: source.sourceContractHash
    },
    scope: { scopeType: "facility", scopeId: "facility-a" },
    effectiveFrom: "2026-01-01"
  });
  const sourceView = activate(governedStore, {
    definitionVersionId: "source-v1", definitionKey: source.sourceKey, kind: "source_contract",
    semanticVersion: "1.0.0", document: source
  });
  const bindingView = activate(governedStore, {
    definitionVersionId: "binding-v1", definitionKey: binding.bindingId, kind: "dataset_scope_binding",
    semanticVersion: "1.0.0", document: binding
  });
  const mappingDocument = mapping(source, runtimeEvidence.dictionary);
  const mappingView = activate(governedStore, {
    definitionVersionId: "mapping-v1", definitionKey: mappingDocument.mappingKey, kind: "mapping_spec",
    semanticVersion: "1.0.0", document: mappingDocument
  });
  const mappings = new HistoricalMappingExecutionAuthorityV1(governed);
  const historicalMapping = mappings.resolveFrozenAt({
    tenantId: "tenant-a",
    definitionVersionId: mappingView.version.definitionVersionId,
    certificationAt: "2026-02-01T00:00:00.000Z"
  });
  const sourceRef = governed.resolveFrozen({ tenantId: "tenant-a", definitionVersionId: sourceView.version.definitionVersionId }).reference;
  const scopeRef = governed.resolveFrozen({ tenantId: "tenant-a", definitionVersionId: bindingView.version.definitionVersionId }).reference;
  const control = controlDefinition({ source, binding, sourceRef, scopeRef, historicalMapping, runtime: runtimeEvidence.runtime });
  activate(governedStore, {
    definitionVersionId: "certification-control-v1", definitionKey: binding.bindingId,
    kind: "snapshot_certification_control", semanticVersion: "1.0.0", document: control
  });

  const delivery = createGovernedSourceDeliveryRecordV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    deliveryId: "delivery-a",
    deliveryRevision: 1,
    datasetId: binding.datasetId,
    facilityId: binding.scope.scopeId,
    sourceContract: binding.sourceContract,
    scopeBinding: { bindingId: binding.bindingId, revision: binding.revision, bindingHash: binding.bindingHash },
    locator: {
      mode: "object_storage", format: "parquet", connectorId: "source-connector",
      bucket: "governed-deliveries", objectKey: "loan-tape.parquet", immutableVersionId: "version-a",
      immutableVersionHash: canonicalHash("version-a"), contentHash: canonicalHash("content-a"), byteCount: 100
    },
    sourceObservedAt: "2026-01-03T00:00:00.000Z",
    receivedAt: "2026-01-03T00:01:00.000Z",
    status: "usable",
    recordedBy: "capture-operator",
    identitySource: "server_derived",
    recordedAt: "2026-01-03T00:02:00.000Z",
    previousDeliveryHash: null
  });
  const receiptBody = {
    contractVersion: 1 as const,
    tenantId: "tenant-a",
    receiptId: modernSnapshotExtractionReceiptIdV1("snapshot-a"),
    snapshotId: "snapshot-a",
    deliveryId: delivery.deliveryId,
    datasetId: binding.datasetId,
    facilityId: binding.scope.scopeId,
    sourceContract: binding.sourceContract,
    scopeBinding: { bindingId: binding.bindingId, revision: binding.revision, bindingHash: binding.bindingHash },
    sourceDelivery: {
      deliveryId: delivery.deliveryId, deliveryRevision: delivery.deliveryRevision,
      deliveryHash: delivery.deliveryHash, locatorHash: canonicalHash(delivery.locator),
      sourceVersionHash: delivery.locator.immutableVersionHash
    },
    delivery: source.delivery,
    sourceLocator: `governed-delivery:${delivery.deliveryId}@${delivery.deliveryHash}`,
    immutableSourceVersion: delivery.locator.immutableVersionHash,
    asOfDate: "2026-01-31",
    knowledge: {
      sourceObservedAt: "2026-01-31T01:00:00.000Z", extractedAt: "2026-01-31T01:01:00.000Z",
      receivedAt: "2026-01-31T01:02:00.000Z", persistedAt: "2026-01-31T01:03:00.000Z"
    },
    watermark: { mode: "none" as const },
    hashes: {
      contentHash: delivery.locator.contentHash, schemaHash: canonicalHash("schema-a"),
      profileHash: canonicalHash("profile-a"), catalogHash: canonicalHash("catalog-a"), parserHash: canonicalHash("parser-a")
    },
    rowCount: 1, columnCount: 1, byteCount: 100, elapsedMs: 1,
    sections: [{ sectionId: "loans", required: true, present: true, rowCount: 1, contentHash: canonicalHash("loans"), schemaHash: canonicalHash("loans-schema"), controlPopulationHash: canonicalHash([{ loan_id: "loan-1" }]) }],
    correction: { kind: "original" as const }, capturedBy: "capture-operator"
  };
  const receipt = parseModernSnapshotExtractionReceiptV1({ ...receiptBody, receiptHash: canonicalHash(receiptBody) });
  const attempt = createSnapshotCertificationAttemptV1({
    contractVersion: 1, tenantId: "tenant-a", certificationManifestId: "certification-manifest-a",
    snapshotId: "snapshot-a", snapshotHash: canonicalHash("snapshot-a"), actorId: "certification-checker",
    requestHash: canonicalHash("certification-request-a"), certifiedAt: "2026-02-01T00:00:00.000Z",
    createdAt: "2026-02-01T00:00:00.000Z"
  });
  const authority = new LifecycleSnapshotCertificationDefinitionAuthorityV1({
    governed, mappings, runtime: new CertificationRuntimeAuthorityFactoryV1(runtimeAuthority)
  });
  return {
    authority, attempt, runtime: runtimeEvidence.runtime,
    evidence: {
      tenantId: "tenant-a", sourceContract: binding.sourceContract, deliveryHash: delivery.deliveryHash,
      extractionReceipt: receipt, delivery, scopeBinding: binding, asOfDate: receipt.asOfDate
    },
    close: () => { runtimeAuthority.close(); governedStore.close(); }
  };
}

function activate(store: GovernedDefinitionV2Store, input: {
  readonly definitionVersionId: string; readonly definitionKey: string; readonly kind: Parameters<GovernedDefinitionV2Store["propose"]>[0]["kind"];
  readonly semanticVersion: string; readonly document: unknown;
}) {
  let view = store.propose({ tenantId: "tenant-a", ...input, effectiveFrom: "2026-01-01", proposedBy: "maker-a", idempotencyKey: `${input.definitionVersionId}-propose` });
  for (const toStatus of ["validated", "approved", "active"] as const) {
    view = store.transition({ tenantId: "tenant-a", definitionVersionId: input.definitionVersionId, toStatus, expectedRevision: view.lifecycleRevision, actor: "checker-a", idempotencyKey: `${input.definitionVersionId}-${toStatus}` });
  }
  return view;
}

function runtime(authority: SqliteHistoricalRuntimeAuthorityV1) {
  const dictionaryContent = { dictionary: { fields: ["loan_id"] }, fieldPolicy: { nulls: "preserve" } };
  const dictionary = authority.registerBundle(MAKER, {
    bundleKind: "dictionary", bundleId: "dictionary-a", version: "1.0.0", mediaType: "application/json",
    createdAt: "2026-01-01T00:00:00.000Z", dictionaryVersion: "1.0.0", dictionaryHash: canonicalHash(dictionaryContent.dictionary),
    fieldPolicyVersion: "1.0.0", fieldPolicyHash: canonicalHash(dictionaryContent.fieldPolicy), content: dictionaryContent, idempotencyKey: "dictionary"
  }).value;
  if (dictionary.bundleKind !== "dictionary") throw new Error("expected dictionary");
  const compiler = authority.registerBundle(MAKER, {
    bundleKind: "mapping_compiler", bundleId: "compiler-a", version: "1.0.0", mediaType: "application/json",
    createdAt: "2026-01-01T00:01:00.000Z", content: { compiler: "mapping-v2" }, idempotencyKey: "compiler"
  }).value;
  if (compiler.bundleKind !== "mapping_compiler") throw new Error("expected compiler");
  const assembly = authority.registerRuntime(MAKER, {
    runtimeBundleId: "runtime-a", runtimeVersion: "1.0.0", dictionary, mappingCompiler: compiler,
    methodologies: [], assembledAt: "2026-01-01T00:02:00.000Z", idempotencyKey: "runtime"
  }).value;
  return { dictionary, compiler, runtime: assembly };
}

function mapping(source: ReturnType<typeof createSourceContractV1>, dictionary: ReturnType<typeof runtime>["dictionary"]): MappingSpecV2 {
  return createMappingSpecV2({
    contractVersion: 2, tenantId: "tenant-a", mappingSpecId: "mapping-spec-a", mappingKey: "loan-tape",
    revision: 1, status: "active", sourceContract: { sourceContractId: source.sourceContractId, revision: source.revision, sourceContractHash: source.sourceContractHash },
    dictionaryBundle: dictionary, rules: [{ ruleId: "loan-id", canonicalField: "loan_id", expression: { op: "source", column: "loan_id" }, onError: "fail_application" }],
    requiredCanonicalFields: ["loan_id"], createdBy: "mapping-maker", createdAt: "2026-01-01T00:00:00.000Z", approvedBy: "mapping-checker", approvedAt: "2026-01-01T00:01:00.000Z"
  });
}

function controlDefinition(input: {
  readonly source: ReturnType<typeof createSourceContractV1>; readonly binding: ReturnType<typeof createGovernedDatasetScopeBindingV1>;
  readonly sourceRef: ReturnType<GovernedDefinitionV2Resolver["resolveFrozen"]>["reference"];
  readonly scopeRef: ReturnType<GovernedDefinitionV2Resolver["resolveFrozen"]>["reference"];
  readonly historicalMapping: ReturnType<HistoricalMappingExecutionAuthorityV1["resolveFrozenAt"]>;
  readonly runtime: ReturnType<typeof runtime>["runtime"];
}): SnapshotCertificationDefinitionV1 {
  return createSnapshotCertificationDefinitionV1({
    contractVersion: 1, definitionKind: "snapshot_certification_control", tenantId: "tenant-a", certificationDefinitionId: input.binding.bindingId, revision: 1,
    sourceContract: input.binding.sourceContract,
    sourceContractExecution: { ...input.sourceRef, sourceContract: input.binding.sourceContract },
    scopeBinding: input.binding,
    scopeBindingExecution: { ...input.scopeRef, bindingId: input.binding.bindingId, revision: input.binding.revision, bindingHash: input.binding.bindingHash, sourceContract: input.binding.sourceContract },
    mappingExecution: {
      ...input.historicalMapping.reference, mappingSpecId: input.historicalMapping.mappingSpec.mappingSpecId,
      mappingSpecRevision: input.historicalMapping.mappingSpec.revision, mappingSpecHash: input.historicalMapping.mappingSpec.mappingSpecHash,
      sourceContract: input.binding.sourceContract, activation: input.historicalMapping.activationEvidence, window: input.historicalMapping.window
    },
    runtime: { runtimeBundleId: input.runtime.runtimeBundleId, runtimeVersion: input.runtime.runtimeVersion, runtimeBundleHash: input.runtime.runtimeBundleHash, dictionary: input.runtime.dictionary, mappingCompiler: input.runtime.mappingCompiler },
    dataQuality: {
      definitionId: "dq-a", rulesetId: "dq-rules-a", mappingSectionId: "loans", requiredSectionIds: ["loans"],
      rules: [{ ruleId: "loan-id", type: "required", field: "loan_id", severity: "critical", blocking: true }], balanceField: "current_balance", materialBalance: "0", window: { effectiveFrom: "2026-01-01" }
    },
    certificationReconciliation: {
      definitionId: "reconciliation-a", reconciliationId: "pool-tie-out", requiredSectionIds: ["loans"], controls: [{ controlId: "loan-count", sectionId: "loans", recordSource: "normalized", dimensions: ["pool"], balanceField: "current_balance", currencyField: "currency", expected: [{ dimensions: { pool: "a" }, rowCount: 1, balance: "0", currency: "USD" }], balanceTolerance: "0" }], window: { effectiveFrom: "2026-01-01" }
    },
    window: { effectiveFrom: "2026-01-01" }, approval: { status: "pending_durable_approval", authority: "governed_definition_v2_lifecycle" }
  });
}

const MAKER = { tenantId: "tenant-a", actorId: "runtime-maker", authority: "platform_operator", identitySource: "server_derived" } as const;
const CHECKER = { tenantId: "tenant-a", actorId: "runtime-checker", authority: "platform_operator", identitySource: "server_derived" } as const;
