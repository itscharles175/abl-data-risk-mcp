import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

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
import { GovernedCertifiedSnapshotPublicationLinkCatalogV2 } from "../src/control/governed-certified-snapshot-publication-links-v2.js";
import { GovernedDefinitionV2Store } from "../src/control/governed-definitions-v2.js";
import { SqliteHistoricalRuntimeAuthorityV1 } from "../src/control/historical-runtime-authority-v1.js";
import { LifecycleSnapshotCertificationDefinitionAuthorityV1 } from "../src/control/lifecycle-snapshot-certification-definition-authority-v1.js";
import { SqliteSourceDeliveryAuthorityV1 } from "../src/control/source-delivery-authority-v1.js";
import { runOperatorCli, type OperatorCliIo, type OperatorCommand } from "../src/operator/cli.js";
import {
  OperatorControlPlane,
  type OperatorControlPlaneDependencies,
  type OperatorPrincipal
} from "../src/operator/control-plane.js";
import { runOperatorMain } from "../src/operator/main.js";
import { deriveLocalOperatorPrincipal } from "../src/operator/runtime.js";
import { SqliteCapturedSourceMaterialStoreV1 } from "../src/repositories/captured-source-material-v1.js";
import { SqliteCertificationArtifactStagingStoreV1 } from "../src/repositories/certification-artifact-staging-v1.js";
import { SqliteCertifiedSnapshotEvidenceV2Repository } from "../src/repositories/certified-snapshot-evidence-v2.js";
import { SqliteModernSnapshotExtractionReceiptRepositoryV1 } from "../src/repositories/modern-snapshot-extraction-receipts-v1.js";
import { SqliteSnapshotCertificationAttemptStoreV1 } from "../src/repositories/snapshot-certification-attempts-v1.js";
import { SqliteSurveillanceEvidenceRepositories } from "../src/repositories/sqlite-surveillance.js";
import { GovernedCertifiedSnapshotPublicationV2Service } from "../src/services/governed-certified-snapshot-publication-v2.js";
import { GovernedDefinitionV2Resolver } from "../src/services/governed-definition-v2-resolver.js";
import { GovernedModernExtractionAuthorityV1 } from "../src/services/governed-modern-extraction-authority-v1.js";
import { HistoricalMappingExecutionAuthorityV1 } from "../src/services/historical-mapping-execution-authority-v1.js";
import { composeModernSnapshotRuntimeV1 } from "../src/services/modern-snapshot-runtime-v1.js";
import type { TrustedSnapshotSource } from "../src/services/sql-snapshot-extraction.js";

const TENANT = "tenant-a";
const DATASET = "loan-dataset";
const FACILITY = "facility-a";
const DELIVERY = "delivery-a";
const CAPTURE_AT = "2026-02-01T00:00:00.000Z";
const PRIVATE_CREDENTIAL = "kms/postgres/private-readonly";
const PRIVATE_RELATION = "private_loan_tape";
const RECORDS = Object.freeze([
  Object.freeze({ assetNumber: "loan-1", actualEndBalance: "100", pool: "a", currency: "USD" })
]);

test("operator entrypoints execute the governed capture, certification, and publication pilot", async () => {
  const fixture = await createPilotFixture();
  try {
    const captureIo = output();
    const captureCode = await runOperatorMain(
      ["extract-sql-v2", "--request", fixture.captureRequestPath],
      fixture.environment,
      captureIo.io,
      { modernSnapshotRuntime: fixture.runtime }
    );
    assert.equal(captureCode, 0, captureIo.stderr.join("\n"));
    const capture = successResult(captureIo.stdout[0], "extract-sql-v2");
    const snapshotId = requiredString(capture.snapshotId);
    const receiptId = requiredString(capture.receiptId);

    const trustedLocalPrincipal = deriveLocalOperatorPrincipal();
    const storedReceipt = await fixture.receipts.get(TENANT, receiptId);
    assert.ok(storedReceipt);
    assert.equal(storedReceipt.capturedBy, trustedLocalPrincipal.principalId);
    assert.equal(storedReceipt.tenantId, TENANT);
    assert.equal(storedReceipt.deliveryId, DELIVERY);
    assert.ok(await fixture.sourceMaterial.get({ tenantId: TENANT, snapshotId, sectionId: "loans" }));

    writePrivateJson(fixture.certificationRequestPath, { snapshotId });
    const certificationIo = output();
    const certificationCode = await runOperatorMain(
      ["certify-snapshot-v2", "--request", fixture.certificationRequestPath],
      fixture.environment,
      certificationIo.io,
      { modernSnapshotRuntime: fixture.runtime }
    );
    assert.equal(certificationCode, 0, certificationIo.stderr.join("\n"));
    const certification = successResult(certificationIo.stdout[0], "certify-snapshot-v2");
    const certificationManifestId = requiredString(certification.certificationManifestId);
    const evidence = await fixture.evidence.get(TENANT, certificationManifestId);
    assert.ok(evidence);
    assert.equal(evidence.tenantId, TENANT);
    assert.equal(evidence.v1Evidence.certification.certifiedBy, trustedLocalPrincipal.principalId);

    const publication = await invokeCli(fixture.publisher, "publish-snapshot-v2", {
      linkId: "publication-link-a",
      certificationManifestId,
      idempotencyKey: "publish-snapshot-a"
    });
    assert.equal(publication.result.snapshotId, snapshotId);
    assert.equal(publication.result.evidenceId, certificationManifestId);
    assert.equal(publication.result.enabled, true);
    const fetched = await invokeCli(fixture.publisher, "publication-v2-get", {
      linkId: "publication-link-a"
    });
    assert.deepEqual(fetched.result, publication.result);
    const publicationAudit = await invokeCli<unknown[]>(fixture.publisher, "publication-v2-audit-list", {
      afterSequence: 0,
      limit: 10
    });
    assert.equal((publicationAudit.result as unknown[]).length, 1);

    const publicOutput = [
      ...fixture.governanceOutput,
      ...captureIo.stdout,
      ...certificationIo.stdout,
      publication.serialized,
      fetched.serialized,
      publicationAudit.serialized
    ].join("\n");
    for (const privateValue of [
      PRIVATE_CREDENTIAL,
      PRIVATE_RELATION,
      trustedLocalPrincipal.principalId,
      "normalizedArtifactId",
      "artifactId",
      "executionDocument",
      "sourceLocator"
    ]) {
      assert.equal(publicOutput.includes(privateValue), false, `operator output leaked ${privateValue}`);
    }
    assert.equal(captureIo.stderr.length, 0);
    assert.equal(certificationIo.stderr.length, 0);
    assert.equal(JSON.stringify(capture).includes("tenantId"), false);
    assert.equal(JSON.stringify(certification).includes("tenantId"), false);
  } finally {
    fixture.close();
  }
});

async function createPilotFixture() {
  const root = mkdtempSync(join(tmpdir(), "aegis-operator-pilot-"));
  const artifacts = new ArtifactStore(
    join(root, "pilot-artifacts"),
    { activeKeyId: "pilot-key", keys: { "pilot-key": Buffer.alloc(32, 37) } },
    { maximumArtifactBytes: 1_000_000 }
  );
  let definitionTick = 0;
  const definitions = new GovernedDefinitionV2Store(join(root, "definitions.sqlite"), {
    clock: () => new Date(Date.UTC(2026, 0, 10, 12, 0, definitionTick++))
  });
  const resolver = new GovernedDefinitionV2Resolver(definitions);
  const historicalRuntime = new SqliteHistoricalRuntimeAuthorityV1(
    join(root, "historical-runtime.sqlite"),
    artifacts,
    { clock: () => new Date("2026-01-09T12:00:00.000Z") }
  );
  const sourceDeliveries = new SqliteSourceDeliveryAuthorityV1(
    join(root, "source-deliveries.sqlite"),
    { clock: () => new Date("2026-01-31T00:02:00.000Z") }
  );
  const governanceOutput: string[] = [];
  const source = sourceContract();
  const binding = createGovernedDatasetScopeBindingV1({
    contractVersion: 1,
    tenantId: TENANT,
    bindingId: "facility-a-binding",
    revision: 1,
    datasetId: DATASET,
    sourceContract: {
      sourceContractId: source.sourceContractId,
      revision: source.revision,
      sourceContractHash: source.sourceContractHash
    },
    scope: { scopeType: "facility", scopeId: FACILITY },
    effectiveFrom: "2026-01-01"
  });
  const baseDependencies: Omit<OperatorControlPlaneDependencies, "principal"> = {
    control: unreachable("control"),
    definitions: unreachable("legacy definitions"),
    governedDefinitionsV2: definitions,
    governedDefinitionV2Resolver: resolver,
    artifacts,
    memberships: unreachable("memberships"),
    alerts: unreachable("alerts"),
    ingestion: unreachable("ingestion"),
    sourceDeliveryAdministration: sourceDeliveries,
    historicalRuntimeAdministration: historicalRuntime
  };
  const maker = new OperatorControlPlane({ ...baseDependencies, principal: principal("operator-maker") });
  const checker = new OperatorControlPlane({ ...baseDependencies, principal: principal("operator-checker") });

  await activateDefinition(maker, checker, governanceOutput, {
    definitionVersionId: "source-v1",
    definitionKey: source.sourceKey,
    kind: "source_contract",
    document: source
  });
  await activateDefinition(maker, checker, governanceOutput, {
    definitionVersionId: "binding-v1",
    definitionKey: binding.bindingId,
    kind: "dataset_scope_binding",
    document: binding
  });

  const dictionaryContent = {
    dictionary: { fields: ["loan_id", "current_balance", "pool", "currency"] },
    fieldPolicy: { nulls: "preserve" }
  };
  const dictionaryPath = join(root, "dictionary.json");
  const compilerPath = join(root, "compiler.json");
  writePrivateJson(dictionaryPath, dictionaryContent);
  writePrivateJson(compilerPath, { compiler: "mapping-v2", privateCompilerOption: "never-return" });
  governanceOutput.push((await invokeCli(maker, "historical-bundle-register", {
    bundleKind: "dictionary",
    bundleId: "dictionary-a",
    version: "1.0.0",
    mediaType: "application/json",
    createdAt: "2026-01-01T00:00:00.000Z",
    filePath: dictionaryPath,
    dictionaryVersion: "1.0.0",
    dictionaryHash: canonicalHash(dictionaryContent.dictionary),
    fieldPolicyVersion: "1.0.0",
    fieldPolicyHash: canonicalHash(dictionaryContent.fieldPolicy),
    idempotencyKey: "register-dictionary-a"
  })).serialized);
  governanceOutput.push((await invokeCli(maker, "historical-bundle-register", {
    bundleKind: "mapping_compiler",
    bundleId: "compiler-a",
    version: "1.0.0",
    mediaType: "application/json",
    createdAt: "2026-01-01T00:01:00.000Z",
    filePath: compilerPath,
    idempotencyKey: "register-compiler-a"
  })).serialized);
  const runtimeRegistration = await invokeCli(maker, "historical-runtime-register", {
    runtimeBundleId: "runtime-a",
    runtimeVersion: "1.0.0",
    dictionary: { bundleId: "dictionary-a", version: "1.0.0" },
    mappingCompiler: { bundleId: "compiler-a", version: "1.0.0" },
    methodologies: [],
    assembledAt: "2026-01-01T00:02:00.000Z",
    idempotencyKey: "register-runtime-a"
  });
  governanceOutput.push(runtimeRegistration.serialized);
  governanceOutput.push((await invokeCli(checker, "historical-runtime-activate", {
    runtimeBundleId: "runtime-a",
    runtimeBundleHash: runtimeRegistration.result.runtimeBundleHash,
    idempotencyKey: "activate-runtime-a"
  })).serialized);

  const dictionary = historicalRuntime.resolveBundleReference(TENANT, "dictionary", "dictionary-a", "1.0.0");
  const runtime = historicalRuntime.resolveActivatedRuntime(
    TENANT,
    { runtimeBundleId: "runtime-a", runtimeBundleHash: requiredString(runtimeRegistration.result.runtimeBundleHash) as `sha256:${string}` },
    CAPTURE_AT
  ).runtime;
  const mappingDocument = mapping(source, dictionary);
  await activateDefinition(maker, checker, governanceOutput, {
    definitionVersionId: "mapping-v1",
    definitionKey: mappingDocument.mappingKey,
    kind: "mapping_spec",
    document: mappingDocument
  });
  const mappings = new HistoricalMappingExecutionAuthorityV1(resolver);
  const historicalMapping = mappings.resolveFrozenAt({
    tenantId: TENANT,
    definitionVersionId: "mapping-v1",
    certificationAt: CAPTURE_AT
  });
  const sourceRef = resolver.resolveFrozen({ tenantId: TENANT, definitionVersionId: "source-v1" }).reference;
  const scopeRef = resolver.resolveFrozen({ tenantId: TENANT, definitionVersionId: "binding-v1" }).reference;
  const control = controlDefinition({ source, binding, sourceRef, scopeRef, historicalMapping, runtime });
  await activateDefinition(maker, checker, governanceOutput, {
    definitionVersionId: "control-v1",
    definitionKey: binding.bindingId,
    kind: "snapshot_certification_control",
    document: control
  });
  const lifecycleSource = resolver.resolveFrozen({
    tenantId: TENANT,
    definitionVersionId: "source-v1"
  }).executionDocument as { readonly status?: unknown; readonly sourceContractHash?: unknown };
  assert.equal(lifecycleSource.status, "approved");
  assert.notEqual(lifecycleSource.sourceContractHash, source.sourceContractHash);

  // The local pilot deliberately uses the catalog's explicitly trusted active-import
  // boundary. A lifecycle-projected `approved` source must remain un-capturable until
  // the delivery record persists and verifies its exact lifecycle provenance.
  assert.equal(source.status, "active");
  sourceDeliveries.register(
    {
      tenantId: TENANT,
      actorId: "operator-maker",
      authority: "platform_operator",
      identitySource: "server_derived"
    },
    {
      deliveryId: DELIVERY,
      sourceContract: source,
      scopeBinding: binding,
      locator: {
        mode: "postgresql_pull",
        connectorId: "postgres-primary",
        catalog: "risk",
        schema: "servicing",
        relation: PRIVATE_RELATION,
        relationIdentityHash: canonicalHash({
          connectorId: "postgres-primary",
          catalog: "risk",
          schema: "servicing",
          relation: PRIVATE_RELATION
        }),
        sourceVersionHash: canonicalHash("repeatable-read-version-a")
      },
      sourceObservedAt: "2026-01-31T00:00:00.000Z",
      receivedAt: "2026-01-31T00:01:00.000Z",
      idempotencyKey: "register-delivery-a"
    }
  );
  governanceOutput.push((await invokeCli(maker, "source-delivery-get", {
    deliveryId: DELIVERY
  })).serialized);
  governanceOutput.push((await invokeCli<unknown[]>(maker, "source-delivery-audit-list", {
    afterSequence: 0,
    limit: 10
  })).serialized);

  const deliveryResolution = await sourceDeliveries.resolveGovernedDeliveryForCapture({
    tenantId: TENANT,
    sourceContractId: source.sourceContractId,
    deliveryId: DELIVERY
  });
  assert.ok(deliveryResolution);
  const trustedSource: TrustedSnapshotSource = {
    sourceId: "postgres-primary",
    dialect: "postgres",
    assumptions: {
      principalMode: "non_owner",
      accessMode: "read_only",
      configurationSource: "trusted_runtime"
    },
    async extract(request) {
      assert.deepEqual(request, {
        tenantId: TENANT,
        datasetId: DATASET,
        relationId: "loan-tape-approved",
        columnIds: ["asset-id", "ending-balance", "pool-code", "currency-code"]
      });
      return {
        sourceId: "postgres-primary",
        dialect: "postgres",
        tenantId: TENANT,
        datasetId: DATASET,
        relationId: "loan-tape-approved",
        columnIds: ["asset-id", "ending-balance", "pool-code", "currency-code"],
        outputColumns: ["assetNumber", "actualEndBalance", "pool", "currency"],
        orderBy: [{ columnId: "asset-id", direction: "asc", nulls: "last" }],
        queryFingerprint: canonicalHash("server-compiled-query"),
        records: RECORDS,
        rowCount: RECORDS.length,
        byteLength: Buffer.byteLength(JSON.stringify(RECORDS), "utf8")
      };
    }
  };
  let monotonic = 0;
  const extraction = new GovernedModernExtractionAuthorityV1({
    tenantId: TENANT,
    facilityId: FACILITY,
    plans: [{
      tenantId: TENANT,
      datasetId: DATASET,
      facilityId: FACILITY,
      deliveryId: DELIVERY,
      deliveryHash: deliveryResolution.delivery.deliveryHash,
      sourceContractId: source.sourceContractId,
      sourceContractRevision: source.revision,
      sourceContractHash: source.sourceContractHash,
      asOfDate: "2026-01-31",
      kind: "postgresql",
      source: trustedSource,
      relationId: "loan-tape-approved",
      columnIds: ["asset-id", "ending-balance", "pool-code", "currency-code"]
    }],
    now: () => CAPTURE_AT,
    monotonicNow: () => monotonic++
  });

  const repositories = new SqliteSurveillanceEvidenceRepositories(join(root, "surveillance.sqlite"));
  const receipts = new SqliteModernSnapshotExtractionReceiptRepositoryV1(join(root, "receipts.sqlite"));
  const sourceMaterial = new SqliteCapturedSourceMaterialStoreV1(join(root, "source-material.sqlite"));
  const evidence = new SqliteCertifiedSnapshotEvidenceV2Repository(join(root, "evidence-v2.sqlite"));
  const attempts = new SqliteSnapshotCertificationAttemptStoreV1(join(root, "attempts.sqlite"));
  const staging = new SqliteCertificationArtifactStagingStoreV1(join(root, "staging.sqlite"));
  const certificationRuntime = new CertificationRuntimeAuthorityFactoryV1(historicalRuntime);
  const lifecycleDefinitions = new LifecycleSnapshotCertificationDefinitionAuthorityV1({
    governed: resolver,
    mappings,
    runtime: certificationRuntime
  });
  const modernRuntime = composeModernSnapshotRuntimeV1({
    tenantId: TENANT,
    sourceDeliveries,
    extraction,
    receipts,
    snapshots: repositories.datasetSnapshots,
    certifiedEvidenceV2: evidence,
    attempts,
    artifactStaging: staging,
    sourceMaterial,
    lifecycleDefinitions,
    certificationRuntime,
    dimensions: { async resolveForMapping() { return []; } },
    artifacts,
    sourceMaterialMaximumBytes: 1_000_000,
    now: () => CAPTURE_AT
  });

  const publicationLinks = new GovernedCertifiedSnapshotPublicationLinkCatalogV2(
    join(root, "publication-links.sqlite"),
    { clock: () => new Date("2026-02-01T00:10:00.000Z") }
  );
  const publicationWriter = new GovernedCertifiedSnapshotPublicationV2Service({
    datasetSnapshots: repositories.datasetSnapshots,
    captureLineage: repositories.datasetSnapshots,
    certifiedSnapshotEvidence: evidence,
    artifacts,
    definitions: resolver,
    publicationLinks,
    clock: () => new Date("2026-02-01T00:10:00.000Z")
  });
  const publisher = new OperatorControlPlane({
    ...baseDependencies,
    principal: principal("publication-checker"),
    governedPublicationV2Writer: publicationWriter,
    governedPublicationV2Catalog: publicationLinks
  });

  const environment = runtimeEnvironment(root);
  const captureRequestPath = join(root, "capture-request.json");
  const certificationRequestPath = join(root, "certification-request.json");
  writePrivateJson(captureRequestPath, {
    sourceContractId: source.sourceContractId,
    deliveryId: DELIVERY
  });

  return {
    runtime: modernRuntime,
    environment,
    captureRequestPath,
    certificationRequestPath,
    governanceOutput,
    receipts,
    sourceMaterial,
    evidence,
    publisher,
    close() {
      publicationLinks.close();
      staging.close();
      attempts.close();
      evidence.close();
      sourceMaterial.close();
      receipts.close();
      repositories.close();
      sourceDeliveries.close();
      historicalRuntime.close();
      definitions.close();
      rmSync(root, { recursive: true, force: true });
    }
  };
}

async function activateDefinition(
  maker: OperatorControlPlane,
  checker: OperatorControlPlane,
  outputLines: string[],
  input: {
    readonly definitionVersionId: string;
    readonly definitionKey: string;
    readonly kind: "source_contract" | "dataset_scope_binding" | "mapping_spec" | "snapshot_certification_control";
    readonly document: unknown;
  }
): Promise<void> {
  const proposal = await invokeCli(maker, "definition-v2-propose", {
    tenantId: TENANT,
    ...input,
    semanticVersion: "1.0.0",
    effectiveFrom: "2026-01-01",
    idempotencyKey: `${input.definitionVersionId}-propose`
  });
  outputLines.push(proposal.serialized);
  let revision = 1;
  for (const toStatus of ["validated", "approved", "active"] as const) {
    const transition = await invokeCli(checker, "definition-v2-transition", {
      tenantId: TENANT,
      definitionVersionId: input.definitionVersionId,
      toStatus,
      expectedRevision: revision,
      idempotencyKey: `${input.definitionVersionId}-${toStatus}`
    });
    outputLines.push(transition.serialized);
    revision = Number(transition.result.lifecycleRevision);
  }
}

function sourceContract() {
  return createSourceContractV1({
    contractVersion: 1,
    tenantId: TENANT,
    sourceContractId: "loan-source-a",
    sourceKey: "loan-tape",
    revision: 1,
    status: "active",
    delivery: {
      mode: "postgresql_pull",
      connectorId: "postgres-primary",
      credentialRef: PRIVATE_CREDENTIAL,
      catalog: "risk",
      schema: "servicing",
      relation: PRIVATE_RELATION
    },
    schemaPolicy: {
      columns: [
        { sourceName: "assetNumber", ordinal: 0, nativeType: "text", nullable: false, required: true },
        { sourceName: "actualEndBalance", ordinal: 1, nativeType: "decimal(20,2)", nullable: false, required: true },
        { sourceName: "pool", ordinal: 2, nativeType: "text", nullable: false, required: true },
        { sourceName: "currency", ordinal: 3, nativeType: "text", nullable: false, required: true }
      ],
      allowUnknownColumns: false,
      requireStableOrdinals: true
    },
    parserPolicy: {
      format: "sql_rows",
      parserId: "postgres-exact-v1",
      parserVersion: "1.0.0",
      optionsHash: canonicalHash("postgres-parser"),
      exactDecimalMode: "string",
      timezone: "UTC"
    },
    extractionPolicy: {
      mode: "full",
      readOnly: true,
      maximumRows: 1_000,
      maximumColumns: 100,
      maximumBytes: 1_000_000,
      timeoutMs: 5_000,
      cursorRows: 100
    },
    sections: [{
      sectionId: "loans",
      required: true,
      selector: "Loan Tape",
      keyFields: ["assetNumber"],
      balanceField: "actualEndBalance",
      currencyField: "currency",
      minimumRows: 1,
      maximumRows: 1_000
    }],
    effectiveFrom: "2026-01-01",
    createdBy: "source-maker",
    createdAt: "2026-01-01T00:00:00.000Z",
    approvedBy: "source-checker",
    approvedAt: "2026-01-01T00:01:00.000Z"
  });
}

function mapping(
  source: ReturnType<typeof sourceContract>,
  dictionary: ReturnType<SqliteHistoricalRuntimeAuthorityV1["resolveBundleReference"]>
): MappingSpecV2 {
  if (dictionary.bundleKind !== "dictionary") throw new Error("Expected dictionary bundle");
  return createMappingSpecV2({
    contractVersion: 2,
    tenantId: TENANT,
    mappingSpecId: "mapping-spec-a",
    mappingKey: "loan-tape",
    revision: 1,
    status: "active",
    sourceContract: {
      sourceContractId: source.sourceContractId,
      revision: source.revision,
      sourceContractHash: source.sourceContractHash
    },
    dictionaryBundle: dictionary,
    rules: [
      { ruleId: "loan-id", canonicalField: "loan_id", expression: { op: "source", column: "assetNumber" }, onError: "fail_application" },
      { ruleId: "balance", canonicalField: "current_balance", expression: { op: "source", column: "actualEndBalance" }, onError: "fail_application" },
      { ruleId: "pool", canonicalField: "pool", expression: { op: "source", column: "pool" }, onError: "fail_application" },
      { ruleId: "currency", canonicalField: "currency", expression: { op: "source", column: "currency" }, onError: "fail_application" }
    ],
    requiredCanonicalFields: ["loan_id", "current_balance", "pool", "currency"],
    createdBy: "mapping-maker",
    createdAt: "2026-01-01T00:00:00.000Z",
    approvedBy: "mapping-checker",
    approvedAt: "2026-01-01T00:01:00.000Z"
  });
}

function controlDefinition(input: {
  readonly source: ReturnType<typeof sourceContract>;
  readonly binding: ReturnType<typeof createGovernedDatasetScopeBindingV1>;
  readonly sourceRef: ReturnType<GovernedDefinitionV2Resolver["resolveFrozen"]>["reference"];
  readonly scopeRef: ReturnType<GovernedDefinitionV2Resolver["resolveFrozen"]>["reference"];
  readonly historicalMapping: ReturnType<HistoricalMappingExecutionAuthorityV1["resolveFrozenAt"]>;
  readonly runtime: ReturnType<SqliteHistoricalRuntimeAuthorityV1["resolveActivatedRuntime"]>["runtime"];
}): SnapshotCertificationDefinitionV1 {
  return createSnapshotCertificationDefinitionV1({
    contractVersion: 1,
    definitionKind: "snapshot_certification_control",
    tenantId: TENANT,
    certificationDefinitionId: input.binding.bindingId,
    revision: 1,
    sourceContract: input.binding.sourceContract,
    sourceContractExecution: { ...input.sourceRef, sourceContract: input.binding.sourceContract },
    scopeBinding: input.binding,
    scopeBindingExecution: {
      ...input.scopeRef,
      bindingId: input.binding.bindingId,
      revision: input.binding.revision,
      bindingHash: input.binding.bindingHash,
      sourceContract: input.binding.sourceContract
    },
    mappingExecution: {
      ...input.historicalMapping.reference,
      mappingSpecId: input.historicalMapping.mappingSpec.mappingSpecId,
      mappingSpecRevision: input.historicalMapping.mappingSpec.revision,
      mappingSpecHash: input.historicalMapping.mappingSpec.mappingSpecHash,
      sourceContract: input.binding.sourceContract,
      activation: input.historicalMapping.activationEvidence,
      window: input.historicalMapping.window
    },
    runtime: {
      runtimeBundleId: input.runtime.runtimeBundleId,
      runtimeVersion: input.runtime.runtimeVersion,
      runtimeBundleHash: input.runtime.runtimeBundleHash,
      dictionary: input.runtime.dictionary,
      mappingCompiler: input.runtime.mappingCompiler
    },
    dataQuality: {
      definitionId: "dq-a",
      rulesetId: "dq-rules-a",
      mappingSectionId: "loans",
      requiredSectionIds: ["loans"],
      rules: [{ ruleId: "loan-id", type: "required", field: "loan_id", severity: "critical", blocking: true }],
      balanceField: "current_balance",
      materialBalance: "0",
      window: { effectiveFrom: "2026-01-01" }
    },
    certificationReconciliation: {
      definitionId: "reconciliation-a",
      reconciliationId: "pool-tie-out",
      requiredSectionIds: ["loans"],
      controls: [{
        controlId: "loan-pool",
        sectionId: "loans",
        recordSource: "normalized",
        dimensions: ["pool"],
        balanceField: "current_balance",
        currencyField: "currency",
        expected: [{ dimensions: { pool: "a" }, rowCount: 1, balance: "100", currency: "USD" }],
        balanceTolerance: "0"
      }],
      window: { effectiveFrom: "2026-01-01" }
    },
    window: { effectiveFrom: "2026-01-01" },
    approval: { status: "pending_durable_approval", authority: "governed_definition_v2_lifecycle" }
  });
}

function runtimeEnvironment(root: string): Readonly<Record<string, string>> {
  mkdirSync(join(root, "operator-state"), { recursive: true, mode: 0o700 });
  const sourceConfigPath = join(root, "sources.json");
  const policyPath = join(root, "policy.json");
  const signingKeysPath = join(root, "signing-keys.json");
  const artifactKeysPath = join(root, "artifact-keys.json");
  writePrivateJson(sourceConfigPath, { sources: [], analysis: {} });
  writePrivateJson(policyPath, {
    id: "operator-pilot-policy",
    version: "2026-02-01",
    defaultObligations: {
      maxResultRows: 500,
      maxResultBytes: 1_000_000,
      maxExecutionMs: 15_000,
      minimumCohortSize: 10,
      requireImmutableSnapshot: true,
      allowRawRows: false,
      allowExport: false,
      rowFilterRefs: [],
      fieldMasks: {},
      auditTags: ["operator-pilot"]
    },
    rules: [{
      id: "deny-default",
      effect: "deny",
      tenantIds: ["*"],
      principalIds: ["*"],
      tools: ["*"],
      datasets: ["*"]
    }]
  });
  writePrivateJson(signingKeysPath, {
    currentKeyId: "signing-v1",
    keys: [{ id: "signing-v1", secret: Buffer.alloc(32, 11).toString("base64") }]
  });
  writePrivateJson(artifactKeysPath, {
    activeKeyId: "artifact-v1",
    keys: [{ id: "artifact-v1", secret: Buffer.alloc(32, 13).toString("base64") }]
  });
  return {
    ABL_AUTH_MODE: "oauth",
    ABL_MCP_CONFIG: sourceConfigPath,
    ABL_MCP_HOST: "127.0.0.1",
    ABL_MCP_PORT: "3333",
    ABL_MCP_PUBLIC_URL: "https://operator-pilot.example.test",
    ABL_MCP_ALLOWED_HOSTS: "operator-pilot.example.test",
    ABL_MCP_ALLOWED_ORIGINS: "https://client.example.test",
    ABL_OAUTH_RESOURCE: "https://operator-pilot.example.test",
    ABL_OAUTH_ISSUERS_JSON: JSON.stringify([{
      issuer: "https://issuer.example.test",
      jwksUri: "https://issuer.example.test/.well-known/jwks.json",
      audiences: ["abl-mcp"],
      resources: ["https://operator-pilot.example.test"],
      algorithms: ["RS256"]
    }]),
    ABL_OAUTH_MAX_TOKEN_LENGTH: "16384",
    ABL_OAUTH_SCOPES_SUPPORTED: "abl:catalog abl:analyze abl:monitor",
    ABL_OAUTH_RESOURCE_NAME: "Aegis operator pilot",
    ABL_MCP_CONTROL_DB_PATH: join(root, "operator-state", "control.sqlite"),
    ABL_MCP_JOB_DB_PATH: join(root, "operator-state", "jobs.sqlite"),
    ABL_MCP_SECURITY_DB_PATH: join(root, "operator-state", "security.sqlite"),
    ABL_MCP_ARTIFACT_ROOT: join(root, "operator-artifacts"),
    ABL_MCP_POLICY_FILE: policyPath,
    ABL_MCP_SIGNING_KEYS_FILE: signingKeysPath,
    ABL_MCP_ARTIFACT_KEYS_FILE: artifactKeysPath,
    ABL_MCP_CODE_VERSION: "0.2.0+operator-pilot-test",
    ABL_MCP_WORKER_ID: "operator-pilot-worker",
    ABL_MCP_WORKER_LEASE_SECONDS: "60",
    ABL_MCP_WORKER_POLL_INTERVAL_MS: "50",
    ABL_MCP_RATE_LIMIT_WINDOW_MS: "1000",
    ABL_MCP_RATE_LIMIT_MAX_REQUESTS: "10",
    ABL_MCP_MAX_CONCURRENT_REQUESTS: "4",
    ABL_MCP_MAX_CONCURRENT_JOBS: "2"
  };
}

async function invokeCli<T = Record<string, unknown>>(
  plane: OperatorControlPlane,
  command: OperatorCommand,
  request: unknown
): Promise<{ readonly result: T; readonly serialized: string }> {
  const io = output();
  const code = await runOperatorCli([command, "--request", "server-owned-request.json"], plane, io.io, {
    readRequest: () => request
  });
  assert.equal(code, 0, io.stderr.join("\n"));
  assert.equal(io.stderr.length, 0);
  const serialized = requiredString(io.stdout[0]);
  return { result: successResult<T>(serialized, command), serialized };
}

function successResult<T = Record<string, unknown>>(serialized: string | undefined, command: string): T {
  const parsed = JSON.parse(requiredString(serialized)) as {
    readonly ok?: unknown;
    readonly command?: unknown;
    readonly result?: unknown;
  };
  assert.equal(parsed.ok, true);
  assert.equal(parsed.command, command);
  assert.notEqual(parsed.result, undefined);
  return parsed.result as T;
}

function output(): { readonly io: OperatorCliIo; readonly stdout: string[]; readonly stderr: string[] } {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    stdout,
    stderr,
    io: { stdout: (line) => stdout.push(line), stderr: (line) => stderr.push(line) }
  };
}

function principal(principalId: string): OperatorPrincipal {
  return {
    principalId,
    tenantId: TENANT,
    authenticationMethod: "trusted_service_identity",
    authorizationScope: "global_admin"
  };
}

function unreachable<T>(label: string): T {
  return new Proxy({}, {
    get: () => () => {
      throw new Error(`Unexpected dependency call: ${label}`);
    }
  }) as T;
}

function writePrivateJson(path: string, value: unknown): void {
  writeFileSync(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
}

function requiredString(value: unknown): string {
  assert.equal(typeof value, "string");
  assert.ok(value.length > 0);
  return value;
}
