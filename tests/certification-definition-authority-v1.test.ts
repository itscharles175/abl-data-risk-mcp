import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, test } from "node:test";

import {
  canonicalHash,
  createGovernedDatasetScopeBindingV1,
  createMappingSpecV2,
  type DictionaryBundleReferenceV1,
  type GovernedDatasetScopeBindingV1,
  type ImmutableBundleReferenceV1,
  type MappingSpecV2,
  type Sha256Hash
} from "../src/contracts/index.js";
import { createGovernedSourceDeliveryRecordV1 } from "../src/contracts/source-delivery-authority-v1.js";
import type { ModernSnapshotExtractionReceiptV1 } from "../src/services/modern-snapshot-capture.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import {
  CertificationDefinitionAuthorityError,
  SqliteCertificationDefinitionAuthorityV1,
  type CertifiedControlDefinitionIdentityV1,
  type RegisterCertificationDefinitionSetV1,
  type TrustedCertificationDefinitionActorV1
} from "../src/control/certification-definition-authority-v1.js";
import { GovernedDefinitionV2Store } from "../src/control/governed-definitions-v2.js";
import {
  SqliteHistoricalRuntimeAuthorityV1,
  type TrustedRuntimeAuthorityActorV1
} from "../src/control/historical-runtime-authority-v1.js";
import {
  ActiveMappingExecutionAuthorityV1,
  ActiveMappingExecutionAuthorityV1Error
} from "../src/services/active-mapping-execution-authority-v1.js";
import { GovernedDefinitionV2Resolver } from "../src/services/governed-definition-v2-resolver.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("active mapping adapter requires activation and rehashes the engine projection", () => {
  const fixture = platformFixture();
  const mapping = mappingDefinition(fixture);
  const proposed = fixture.governed.propose({
    tenantId: "tenant-a",
    definitionVersionId: "mapping-definition-v1",
    definitionKey: mapping.mappingKey,
    kind: "mapping_spec",
    semanticVersion: "1.0.0",
    effectiveFrom: "2026-01-01",
    document: mapping,
    proposedBy: "mapping-maker",
    idempotencyKey: "mapping-propose"
  });
  let current = fixture.governed.transition({
    tenantId: "tenant-a",
    definitionVersionId: proposed.version.definitionVersionId,
    toStatus: "validated",
    expectedRevision: proposed.lifecycleRevision,
    actor: "mapping-checker",
    idempotencyKey: "mapping-validated"
  });
  current = fixture.governed.transition({
    tenantId: "tenant-a",
    definitionVersionId: current.version.definitionVersionId,
    toStatus: "approved",
    expectedRevision: current.lifecycleRevision,
    actor: "mapping-checker",
    idempotencyKey: "mapping-approved"
  });
  const adapter = new ActiveMappingExecutionAuthorityV1(fixture.resolver);
  assert.throws(
    () => adapter.resolveFrozenActive({ tenantId: "tenant-a", definitionVersionId: "mapping-definition-v1" }),
    (error: unknown) =>
      error instanceof ActiveMappingExecutionAuthorityV1Error && error.code === "NOT_ACTIVE"
  );
  fixture.governed.transition({
    tenantId: "tenant-a",
    definitionVersionId: current.version.definitionVersionId,
    toStatus: "active",
    expectedRevision: current.lifecycleRevision,
    actor: "mapping-checker",
    idempotencyKey: "mapping-active"
  });
  const active = adapter.resolveEffective({
    tenantId: "tenant-a",
    definitionKey: mapping.mappingKey,
    asOfDate: "2026-07-31"
  });
  assert.equal(active.mappingSpec.status, "active");
  assert.equal(active.activationEvidence.activatedBy, "mapping-checker");
  assert.notEqual(active.mappingSpec.mappingSpecHash, mapping.mappingSpecHash);
  assert.equal(active.reference.definitionVersionId, "mapping-definition-v1");
  fixture.close();
});

test("certification set resolves exact facility, active mapping, runtime, DQ, and reconciliation evidence", async () => {
  const fixture = platformFixture();
  activateMapping(fixture);
  const binding = scopeBinding("facility-a", "binding-a");
  const input = definitionSetInput(fixture, binding, "certification-set-a");
  const registered = fixture.certifications.register(DEFINITION_CHECKER, input);
  const replay = fixture.certifications.register(DEFINITION_CHECKER, input);
  assert.deepEqual(replay, registered);
  assert.equal(registered.scopeBinding.scope.scopeId, "facility-a");
  assert.notEqual(registered.dataQuality.identity.createdBy, registered.dataQuality.identity.approvedBy);

  const bound = await fixture.certifications.resolveForBoundSnapshot({
    evidence: boundEvidence(binding)
  });
  assert.equal(bound?.mappingSpec.status, "active");
  assert.equal(bound?.runtime.runtimeBundleHash, fixture.runtimeBundleHash);
  assert.equal(bound?.dataQuality.definitionId, "dq-definition-a");
  assert.equal(bound?.reconciliation.definitionId, "recon-definition-a");

  assert.equal(
    await fixture.certifications.resolveForSnapshot({
      tenantId: "tenant-b",
      sourceContract: binding.sourceContract,
      asOfDate: "2026-07-31"
    }),
    undefined
  );
  assert.equal(
    await fixture.certifications.resolveForBoundSnapshot({
      evidence: boundEvidence(scopeBinding("facility-b", "binding-b"))
    }),
    undefined
  );

  fixture.certifications.close();
  const reopened = new SqliteCertificationDefinitionAuthorityV1(
    fixture.certificationDatabasePath,
    { governed: fixture.resolver, runtime: fixture.runtime },
    { clock: () => new Date("2026-08-13T15:00:00.000Z"), allowTrustedImports: true }
  );
  assert.equal(
    (await reopened.resolveForBoundSnapshot({ evidence: boundEvidence(binding) }))?.mappingSpec.status,
    "active"
  );
  reopened.close();
  fixture.close({ certificationsClosed: true });
});

test("certification selector fails closed on facility ambiguity, incompatible compiler, and row tampering", async () => {
  const fixture = platformFixture();
  activateMapping(fixture);
  const bindingA = scopeBinding("facility-a", "binding-a");
  const bindingB = scopeBinding("facility-b", "binding-b");
  fixture.certifications.register(DEFINITION_CHECKER, definitionSetInput(fixture, bindingA, "certification-set-a"));
  fixture.certifications.register(DEFINITION_CHECKER, definitionSetInput(fixture, bindingB, "certification-set-b"));

  await assert.rejects(
    fixture.certifications.resolveForSnapshot({
      tenantId: "tenant-a",
      sourceContract: bindingA.sourceContract,
      asOfDate: "2026-07-31"
    }),
    (error: unknown) => certificationError(error, "INTEGRITY_FAILURE")
  );
  assert.throws(
    () => fixture.certifications.register(DEFINITION_CHECKER, {
      ...definitionSetInput(fixture, bindingA, "bad-compiler"),
      revision: 2,
      effectiveFrom: "2027-01-01",
      compilerCompatibility: {
        bundleId: "substituted-compiler",
        version: fixture.compiler.version,
        contentHash: fixture.compiler.contentHash
      }
    }),
    (error: unknown) => certificationError(error, "INVALID_INPUT")
  );

  fixture.certifications.close();
  const database = new DatabaseSync(fixture.certificationDatabasePath);
  database.exec("DROP TRIGGER certification_definition_sets_v1_no_update");
  database.prepare(
    "UPDATE certification_definition_sets_v1 SET facility_id = 'facility-z' WHERE certification_set_id = 'certification-set-a'"
  ).run();
  database.close();
  assert.throws(
    () => new SqliteCertificationDefinitionAuthorityV1(
      fixture.certificationDatabasePath,
      { governed: fixture.resolver, runtime: fixture.runtime }
    ),
    (error: unknown) => certificationError(error, "INTEGRITY_FAILURE")
  );
  fixture.close({ certificationsClosed: true });
});

function platformFixture() {
  const directory = mkdtempSync(join(tmpdir(), "certification-authority-"));
  directories.push(directory);
  const governed = new GovernedDefinitionV2Store(join(directory, "governed.sqlite"), {
    clock: (() => {
      let tick = 0;
      return () => new Date(Date.UTC(2026, 5, 1, 12, tick++, 0, 0));
    })()
  });
  const resolver = new GovernedDefinitionV2Resolver(governed);
  const artifacts = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "test-key",
    keys: { "test-key": Buffer.alloc(32, 11) }
  });
  const runtime = new SqliteHistoricalRuntimeAuthorityV1(join(directory, "runtime.sqlite"), artifacts, {
    clock: () => new Date("2026-06-01T13:00:00.000Z")
  });
  const dictionaryContent = {
    dictionary: { fields: ["loan_id", "current_balance", "portfolio_id", "currency"] },
    fieldPolicy: { nulls: "preserve" }
  };
  const dictionary = runtime.registerBundle(RUNTIME_MAKER, {
    bundleKind: "dictionary",
    bundleId: "dictionary-core",
    version: "1.0.0",
    mediaType: "application/json",
    createdAt: "2026-05-01T00:00:00.000Z",
    dictionaryVersion: "1.0.0",
    dictionaryHash: canonicalHash(dictionaryContent.dictionary),
    fieldPolicyVersion: "1.0.0",
    fieldPolicyHash: canonicalHash(dictionaryContent.fieldPolicy),
    content: dictionaryContent,
    idempotencyKey: "dictionary"
  }).value as DictionaryBundleReferenceV1;
  const compiler = runtime.registerBundle(RUNTIME_MAKER, {
    bundleKind: "mapping_compiler",
    bundleId: "closed-ast-v2",
    version: "2.0.0",
    mediaType: "application/json",
    createdAt: "2026-05-01T00:00:00.000Z",
    content: { compiler: "closed-ast-v2", contractVersion: 2 },
    idempotencyKey: "compiler"
  }).value as ImmutableBundleReferenceV1 & { bundleKind: "mapping_compiler" };
  const runtimeBundle = runtime.registerRuntime(RUNTIME_MAKER, {
    runtimeBundleId: "runtime-v1",
    runtimeVersion: "1.0.0",
    dictionary,
    mappingCompiler: compiler,
    methodologies: [],
    assembledAt: "2026-05-15T00:00:00.000Z",
    idempotencyKey: "runtime"
  }).value;
  runtime.activateRuntime(RUNTIME_CHECKER, {
    runtimeBundleId: runtimeBundle.runtimeBundleId,
    runtimeBundleHash: runtimeBundle.runtimeBundleHash,
    idempotencyKey: "runtime-active"
  });
  const certificationDatabasePath = join(directory, "certification.sqlite");
  const certifications = new SqliteCertificationDefinitionAuthorityV1(
    certificationDatabasePath,
    { governed: resolver, runtime },
    { clock: () => new Date("2026-08-13T14:00:00.000Z"), allowTrustedImports: true }
  );
  return {
    governed,
    resolver,
    runtime,
    dictionary,
    compiler,
    runtimeBundleHash: runtimeBundle.runtimeBundleHash,
    certificationDatabasePath,
    certifications,
    close(options: { certificationsClosed?: boolean } = {}) {
      if (!options.certificationsClosed) certifications.close();
      runtime.close();
      governed.close();
    }
  };
}

function mappingDefinition(fixture: ReturnType<typeof platformFixture>): MappingSpecV2 {
  return createMappingSpecV2({
    contractVersion: 2,
    tenantId: "tenant-a",
    mappingSpecId: "mapping-spec-v1",
    mappingKey: "loan-tape",
    revision: 1,
    status: "proposed",
    sourceContract: sourceReference(),
    dictionaryBundle: fixture.dictionary,
    rules: [
      {
        ruleId: "loan-id",
        canonicalField: "loan_id",
        expression: { op: "source", column: "loan_no" },
        onError: "fail_application"
      },
      {
        ruleId: "balance",
        canonicalField: "current_balance",
        expression: { op: "source", column: "balance" },
        onError: "fail_application"
      },
      {
        ruleId: "portfolio",
        canonicalField: "portfolio_id",
        expression: { op: "source", column: "portfolio" },
        onError: "fail_application"
      },
      {
        ruleId: "currency",
        canonicalField: "currency",
        expression: { op: "source", column: "currency" },
        onError: "fail_application"
      }
    ],
    requiredCanonicalFields: ["loan_id", "current_balance", "portfolio_id", "currency"],
    createdBy: "mapping-maker",
    createdAt: "2026-05-01T00:00:00.000Z"
  });
}

function activateMapping(fixture: ReturnType<typeof platformFixture>) {
  const mapping = mappingDefinition(fixture);
  let current = fixture.governed.propose({
    tenantId: "tenant-a",
    definitionVersionId: "mapping-definition-v1",
    definitionKey: mapping.mappingKey,
    kind: "mapping_spec",
    semanticVersion: "1.0.0",
    effectiveFrom: "2026-01-01",
    document: mapping,
    proposedBy: "mapping-maker",
    idempotencyKey: "mapping-proposed"
  });
  for (const [status, key] of [
    ["validated", "mapping-validated"],
    ["approved", "mapping-approved"],
    ["active", "mapping-active"]
  ] as const) {
    current = fixture.governed.transition({
      tenantId: "tenant-a",
      definitionVersionId: current.version.definitionVersionId,
      toStatus: status,
      expectedRevision: current.lifecycleRevision,
      actor: "mapping-checker",
      idempotencyKey: key
    });
  }
}

function definitionSetInput(
  fixture: ReturnType<typeof platformFixture>,
  binding: GovernedDatasetScopeBindingV1,
  certificationSetId: string
): RegisterCertificationDefinitionSetV1 {
  const suffix = binding.scope.scopeId.at(-1)!;
  const dataQualityExecution = {
    definitionId: `dq-definition-${suffix}`,
    rulesetId: `dq-ruleset-${suffix}`,
    mappingSectionId: "loans",
    requiredSectionIds: ["loans"],
    rules: [
      {
        ruleId: "loan-id-required",
        type: "required" as const,
        field: "loan_id",
        severity: "critical" as const,
        blocking: true
      }
    ],
    balanceField: "current_balance",
    materialBalance: "1",
    window: { effectiveFrom: "2026-01-01" }
  };
  const reconciliationExecution = {
    definitionId: `recon-definition-${suffix}`,
    reconciliationId: `recon-${suffix}`,
    requiredSectionIds: ["loans"],
    controls: [
      {
        controlId: "pool-tie-out",
        sectionId: "loans",
        recordSource: "normalized" as const,
        dimensions: ["portfolio_id"],
        balanceField: "current_balance",
        currencyField: "currency",
        expected: [
          {
            dimensions: { portfolio_id: "portfolio-1" },
            rowCount: 2,
            balance: "300",
            currency: "USD"
          }
        ],
        balanceTolerance: "0"
      }
    ],
    window: { effectiveFrom: "2026-01-01" }
  };
  return {
    certificationSetId,
    revision: 1,
    scopeBinding: binding,
    mappingDefinitionVersionId: "mapping-definition-v1",
    runtimeBundleId: "runtime-v1",
    runtimeBundleHash: fixture.runtimeBundleHash,
    dataQuality: controlDefinition(dataQualityExecution.definitionId, binding, dataQualityExecution),
    reconciliation: controlDefinition(reconciliationExecution.definitionId, binding, reconciliationExecution),
    compilerCompatibility: {
      bundleId: fixture.compiler.bundleId,
      version: fixture.compiler.version,
      contentHash: fixture.compiler.contentHash
    },
    effectiveFrom: "2026-01-01",
    trustedImportOnly: true
  };
}

function controlDefinition<T>(
  definitionId: string,
  binding: GovernedDatasetScopeBindingV1,
  execution: T
): { readonly identity: CertifiedControlDefinitionIdentityV1; readonly execution: T } {
  const identityBody = {
    tenantId: binding.tenantId,
    datasetId: binding.datasetId,
    facilityId: binding.scope.scopeId,
    definitionId,
    revision: 1,
    status: "approved" as const,
    createdBy: "definition-maker",
    approvedBy: "definition-checker",
    approvedAt: "2026-06-15T00:00:00.000Z"
  };
  return {
    identity: {
      ...identityBody,
      definitionHash: canonicalHash({ identity: identityBody, execution })
    },
    execution
  };
}

function scopeBinding(facilityId: string, bindingId: string): GovernedDatasetScopeBindingV1 {
  return createGovernedDatasetScopeBindingV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    bindingId,
    revision: 1,
    datasetId: "loan-dataset",
    sourceContract: sourceReference(),
    scope: { scopeType: "facility", scopeId: facilityId },
    effectiveFrom: "2026-01-01"
  });
}

function boundEvidence(binding: GovernedDatasetScopeBindingV1) {
  const delivery = createGovernedSourceDeliveryRecordV1({
    contractVersion: 1,
    tenantId: binding.tenantId,
    deliveryId: `delivery-${binding.scope.scopeId}`,
    deliveryRevision: 1,
    datasetId: binding.datasetId,
    facilityId: binding.scope.scopeId,
    sourceContract: binding.sourceContract,
    scopeBinding: {
      bindingId: binding.bindingId,
      revision: binding.revision,
      bindingHash: binding.bindingHash
    },
    locator: {
      mode: "object_storage",
      format: "parquet",
      connectorId: "object-source",
      bucket: "governed-bucket",
      objectKey: `${binding.scope.scopeId}/loan-tape.parquet`,
      immutableVersionId: "version-1",
      immutableVersionHash: canonicalHash("version-1"),
      contentHash: canonicalHash("content"),
      byteCount: 100
    },
    sourceObservedAt: "2026-07-31T00:00:00.000Z",
    receivedAt: "2026-07-31T01:00:00.000Z",
    status: "usable",
    recordedBy: "capture-operator",
    identitySource: "server_derived",
    recordedAt: "2026-07-31T02:00:00.000Z",
    previousDeliveryHash: null
  });
  const receiptBody = {
    contractVersion: 1 as const,
    tenantId: binding.tenantId,
    receiptId: `snapshot-${binding.scope.scopeId}:extraction`,
    snapshotId: `snapshot-${binding.scope.scopeId}`,
    deliveryId: delivery.deliveryId,
    datasetId: binding.datasetId,
    facilityId: binding.scope.scopeId,
    sourceContract: binding.sourceContract,
    scopeBinding: {
      bindingId: binding.bindingId,
      revision: binding.revision,
      bindingHash: binding.bindingHash
    },
    sourceDelivery: {
      deliveryId: delivery.deliveryId,
      deliveryRevision: delivery.deliveryRevision,
      deliveryHash: delivery.deliveryHash,
      locatorHash: canonicalHash(delivery.locator),
      sourceVersionHash: canonicalHash({
        mode: delivery.locator.mode,
        versionId: delivery.locator.mode === "object_storage" ? delivery.locator.immutableVersionId : null
      })
    },
    delivery: {
      mode: "object_storage" as const,
      format: "parquet" as const,
      connectorId: "object-source",
      objectPrefix: ""
    },
    sourceLocator: `object://${binding.scope.scopeId}`,
    immutableSourceVersion: "version-1",
    asOfDate: "2026-07-31",
    knowledge: {
      sourceObservedAt: "2026-07-31T00:00:00.000Z",
      extractedAt: "2026-07-31T00:30:00.000Z",
      receivedAt: "2026-07-31T01:00:00.000Z",
      persistedAt: "2026-07-31T02:00:00.000Z"
    },
    watermark: { mode: "none" as const },
    hashes: {
      contentHash: canonicalHash("content"),
      schemaHash: canonicalHash("schema"),
      profileHash: canonicalHash("profile"),
      catalogHash: canonicalHash("catalog"),
      parserHash: canonicalHash("parser")
    },
    rowCount: 1,
    columnCount: 1,
    byteCount: 100,
    elapsedMs: 10,
    sections: [],
    correction: { kind: "original" as const },
    capturedBy: "capture-operator"
  };
  const extractionReceipt = {
    ...receiptBody,
    receiptHash: canonicalHash(receiptBody)
  } satisfies ModernSnapshotExtractionReceiptV1;
  return {
    tenantId: binding.tenantId,
    sourceContract: binding.sourceContract,
    deliveryHash: delivery.deliveryHash,
    extractionReceipt,
    delivery,
    scopeBinding: binding,
    asOfDate: "2026-07-31"
  };
}

function sourceReference() {
  return {
    sourceContractId: "loan-source-v1",
    revision: 1,
    sourceContractHash: canonicalHash({ source: "loan-source-v1", revision: 1 })
  };
}

const RUNTIME_MAKER: TrustedRuntimeAuthorityActorV1 = {
  tenantId: "tenant-a",
  actorId: "runtime-maker",
  authority: "platform_operator",
  identitySource: "server_derived"
};

const RUNTIME_CHECKER: TrustedRuntimeAuthorityActorV1 = {
  tenantId: "tenant-a",
  actorId: "runtime-checker",
  authority: "platform_operator",
  identitySource: "server_derived"
};

const DEFINITION_CHECKER: TrustedCertificationDefinitionActorV1 = {
  tenantId: "tenant-a",
  actorId: "definition-checker",
  authority: "platform_operator",
  identitySource: "server_derived"
};

function certificationError(error: unknown, code: CertificationDefinitionAuthorityError["code"]): boolean {
  return error instanceof CertificationDefinitionAuthorityError && error.code === code;
}
