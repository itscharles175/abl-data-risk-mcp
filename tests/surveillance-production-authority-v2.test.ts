import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import {
  canonicalHash,
  createCertifiedSnapshotArtifactMetadataV1,
  createCertifiedSnapshotEvidenceRecordV1,
  createCertifiedSnapshotPublicationV1,
  createDatasetSnapshotV2,
  createGovernedDatasetScopeBindingV1,
  createMappingApplicationV1,
  createMappingSpecV2,
  createNormalizedSnapshotArtifactV2,
  createSnapshotCertificationAttemptV1,
  createSnapshotCertificationDefinitionV1,
  createSourceContractV1,
  type DatasetSnapshotV2,
  type Sha256Hash
} from "../src/contracts/index.js";
import {
  createCertifiedSnapshotEvidenceRecordV2,
  type CertifiedSnapshotEvidenceRecordV2
} from "../src/contracts/certified-snapshot-evidence-v2.js";
import {
  createGovernedCertifiedSnapshotPublicationLinkV2,
  type GovernedCertifiedSnapshotPublicationLinkV2
} from "../src/contracts/governed-certified-snapshot-publication-link-v2.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import { GovernedCertifiedSnapshotPublicationLinkCatalogV2 } from "../src/control/governed-certified-snapshot-publication-links-v2.js";
import {
  createGovernedSnapshotCommitLineageV1,
  type GovernedSnapshotCommitLineageV1
} from "../src/repositories/governed-snapshot-commit.js";
import type { ImmutableRepositoryPort, RepositoryPage, RepositoryWriteContext } from "../src/repositories/ports.js";
import {
  GovernedDefinitionV2ResolverError,
  type ResolvedGovernedDefinitionV2
} from "../src/services/governed-definition-v2-resolver.js";
import {
  RepositoryBackedSurveillanceSourcePublicationAuthorityV2,
  SurveillanceProductionAuthorityV2Error,
  type GovernedCertifiedSnapshotPublicationLinkReadPortV2
} from "../src/services/surveillance-production-authority-v2.js";

const directories: string[] = [];
const HASH = (value: unknown): Sha256Hash => canonicalHash(value);

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("V2 artifact authority reloads immutable V2 evidence, lineage, definitions, and artifact metadata", async () => {
  const fixture = fixtureEnvironment();
  const resolved = await fixture.authority.resolveArtifact({ tenantId: "tenant-a", linkId: fixture.link.linkId });

  assert.ok(resolved);
  assert.equal(resolved.evidence.evidenceHash, fixture.evidence.evidenceHash);
  assert.equal(resolved.captureLineage.lineageHash, fixture.lineage.lineageHash);
  assert.equal(resolved.normalizedArtifact.artifactId, fixture.evidence.v1Evidence.normalizedArtifact.artifactId);
  assert.equal(resolved.controlDefinition.reference.definitionVersionId, "control-version-a");
  assert.equal(fixture.artifactReadCount(), 1);
  fixture.close();
});

test("V2 metadata authority verifies governed lineage without reading normalized artifact bytes", async () => {
  const fixture = fixtureEnvironment();
  const resolved = await fixture.authority.resolveMetadata({ tenantId: "tenant-a", linkId: fixture.link.linkId });

  assert.ok(resolved);
  assert.equal(resolved.evidence.evidenceHash, fixture.evidence.evidenceHash);
  assert.equal(Object.hasOwn(resolved, "normalizedArtifact"), false);
  assert.equal(fixture.artifactReadCount(), 0);
  fixture.close();
});

test("V2 authority does not fall back when governed capture lineage is unavailable", async () => {
  const fixture = fixtureEnvironment({ lineage: undefined });
  const resolved = await fixture.authority.resolveMetadata({ tenantId: "tenant-a", linkId: fixture.link.linkId });

  assert.equal(resolved, undefined);
  fixture.close();
});

test("V2 authority fails closed when a frozen mapping definition is substituted", async () => {
  const fixture = fixtureEnvironment({ substituteMapping: true });

  await assert.rejects(
    fixture.authority.resolveMetadata({ tenantId: "tenant-a", linkId: fixture.link.linkId }),
    (error: unknown) => authorityError(error, "INTEGRITY_FAILURE")
  );
  fixture.close();
});

test("V2 metadata retains a later-disabled link while artifact authority requires it currently enabled", async () => {
  const fixture = fixtureEnvironment({ catalogDisabled: true });
  const metadata = await fixture.authority.resolveMetadata({ tenantId: "tenant-a", linkId: fixture.link.linkId });
  const material = await fixture.authority.resolveArtifact({ tenantId: "tenant-a", linkId: fixture.link.linkId });

  assert.ok(metadata);
  assert.equal(material, undefined);
  assert.equal(fixture.artifactReadCount(), 0);
  fixture.close();
});

test("V2 metadata verifies a historical corrected ancestor while artifact authority rejects nonterminal materialization", async () => {
  const fixture = fixtureEnvironment({ includeCorrection: true, catalogDisabled: false });

  const metadata = await fixture.authority.resolveMetadata({ tenantId: "tenant-a", linkId: fixture.link.linkId });
  assert.ok(metadata);
  assert.equal(fixture.artifactReadCount(), 0);
  await assert.rejects(
    fixture.authority.resolveArtifact({ tenantId: "tenant-a", linkId: fixture.link.linkId }),
    (error: unknown) => authorityError(error, "NON_TERMINAL_SNAPSHOT")
  );
  assert.equal(fixture.artifactReadCount(), 0);
  fixture.close();
});

test("V2 artifact authority closes a disable race before normalized payload access", async () => {
  const fixture = fixtureEnvironment({ disableOnEnabledCheck: 3 });

  const resolved = await fixture.authority.resolveArtifact({ tenantId: "tenant-a", linkId: fixture.link.linkId });

  assert.equal(resolved, undefined);
  assert.equal(fixture.artifactReadCount(), 0);
  fixture.close();
});

test("V2 artifact authority closes a correction race before normalized payload access", async () => {
  const fixture = fixtureEnvironment({ injectCorrectionOnEnabledCheck: 3 });

  await assert.rejects(
    fixture.authority.resolveArtifact({ tenantId: "tenant-a", linkId: fixture.link.linkId }),
    (error: unknown) => authorityError(error, "NON_TERMINAL_SNAPSHOT")
  );
  assert.equal(fixture.artifactReadCount(), 0);
  fixture.close();
});

test("V2 artifact authority discards payload loaded during a correction race", async () => {
  const fixture = fixtureEnvironment({ injectCorrectionOnEnabledCheck: 4 });

  await assert.rejects(
    fixture.authority.resolveArtifact({ tenantId: "tenant-a", linkId: fixture.link.linkId }),
    (error: unknown) => authorityError(error, "NON_TERMINAL_SNAPSHOT")
  );
  assert.equal(fixture.artifactReadCount(), 1);
  fixture.close();
});

interface Fixture {
  readonly authority: RepositoryBackedSurveillanceSourcePublicationAuthorityV2;
  readonly evidence: CertifiedSnapshotEvidenceRecordV2;
  readonly link: GovernedCertifiedSnapshotPublicationLinkV2;
  readonly lineage: GovernedSnapshotCommitLineageV1;
  artifactReadCount(): number;
  close(): void;
}

function fixtureEnvironment(options: {
  readonly lineage?: GovernedSnapshotCommitLineageV1 | undefined;
  readonly substituteMapping?: boolean;
  readonly catalogDisabled?: boolean;
  readonly includeCorrection?: boolean;
  readonly disableOnEnabledCheck?: number;
  readonly injectCorrectionOnEnabledCheck?: number;
} = {}): Fixture {
  const directory = mkdtempSync(join(tmpdir(), "surveillance-production-authority-v2-"));
  directories.push(directory);
  const source = createSourceContractV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    sourceContractId: "loan-source-a",
    sourceKey: "loan-source-key-a",
    revision: 1,
    status: "proposed",
    delivery: { mode: "managed_upload", format: "parquet", logicalName: "loans.parquet" },
    schemaPolicy: {
      columns: [{ sourceName: "loan_id", ordinal: 0, nativeType: "string", nullable: false, required: true }],
      allowUnknownColumns: false,
      requireStableOrdinals: true
    },
    parserPolicy: { format: "parquet", parserId: "parquet-v1", parserVersion: "1.0.0", optionsHash: HASH("parser"), exactDecimalMode: "string", timezone: "UTC", rejectSchemaMerging: true },
    extractionPolicy: { mode: "full", readOnly: true, maximumRows: 100, maximumColumns: 10, maximumBytes: 10_000, timeoutMs: 1_000, cursorRows: 10 },
    sections: [{ sectionId: "loans", required: true, selector: "loans", keyFields: ["loan_id"] }],
    effectiveFrom: "2026-01-01",
    createdBy: "source-maker",
    createdAt: "2026-01-01T00:00:00.000Z"
  });
  const sourceReference = { sourceContractId: source.sourceContractId, revision: source.revision, sourceContractHash: source.sourceContractHash };
  const scope = createGovernedDatasetScopeBindingV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    bindingId: "facility-a-binding",
    revision: 1,
    datasetId: "loan-dataset-a",
    sourceContract: sourceReference,
    scope: { scopeType: "facility", scopeId: "facility-a" },
    effectiveFrom: "2026-01-01"
  });
  const dictionary = {
    contractVersion: 1 as const, bundleKind: "dictionary" as const, bundleId: "dictionary-a", version: "1.0.0", contentHash: HASH("dictionary-content"),
    artifactId: "dictionary-artifact-a", mediaType: "application/json", createdAt: "2026-01-01T00:00:00.000Z", dictionaryVersion: "1.0.0", dictionaryHash: HASH("dictionary"), fieldPolicyVersion: "1.0.0", fieldPolicyHash: HASH("field-policy")
  };
  const compiler = {
    contractVersion: 1 as const, bundleKind: "mapping_compiler" as const, bundleId: "compiler-a", version: "1.0.0", contentHash: HASH("compiler-content"),
    artifactId: "compiler-artifact-a", mediaType: "application/json", createdAt: "2026-01-01T00:00:00.000Z"
  };
  const mapping = createMappingSpecV2({
    contractVersion: 2, tenantId: "tenant-a", mappingSpecId: "mapping-spec-a", mappingKey: "loan-mapping-a", revision: 1, status: "active", sourceContract: sourceReference, dictionaryBundle: dictionary,
    rules: [{ ruleId: "loan-id", canonicalField: "loan_id", expression: { op: "source", column: "loan_id" }, onError: "fail_application" }], requiredCanonicalFields: ["loan_id"],
    createdBy: "mapping-maker", createdAt: "2026-01-01T00:00:00.000Z", approvedBy: "mapping-checker", approvedAt: "2026-01-01T00:01:00.000Z"
  });
  const sourceExecution = {
    ...definitionReference("source-version-a", source.sourceKey, "source_contract", source),
    sourceContract: sourceReference
  };
  const scopeExecution = {
    ...definitionReference("scope-version-a", scope.bindingId, "dataset_scope_binding", scope),
    bindingId: scope.bindingId,
    revision: scope.revision,
    bindingHash: scope.bindingHash,
    sourceContract: sourceReference
  };
  const activation = { status: "active" as const, lifecycleRevision: 1, activatedBy: "mapping-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationEventHash: HASH("mapping-activation") };
  const mappingExecution = {
    ...definitionReference("mapping-version-a", mapping.mappingKey, "mapping_spec", mapping),
    mappingSpecId: mapping.mappingSpecId,
    mappingSpecRevision: mapping.revision,
    mappingSpecHash: mapping.mappingSpecHash,
    sourceContract: sourceReference,
    activation,
    window: { effectiveFrom: "2026-01-01" }
  };
  const control = createSnapshotCertificationDefinitionV1({
    contractVersion: 1, definitionKind: "snapshot_certification_control", tenantId: "tenant-a", certificationDefinitionId: scope.bindingId, revision: 1,
    sourceContract: sourceReference, sourceContractExecution: sourceExecution, scopeBinding: scope, scopeBindingExecution: scopeExecution, mappingExecution,
    runtime: { runtimeBundleId: "runtime-a", runtimeVersion: "1.0.0", runtimeBundleHash: HASH("runtime"), dictionary, mappingCompiler: compiler },
    dataQuality: { definitionId: "dq-a", rulesetId: "dq-rules-a", mappingSectionId: "loans", requiredSectionIds: ["loans"], rules: [{ ruleId: "loan-required", type: "required", field: "loan_id", severity: "critical", blocking: true }], balanceField: "current_balance", materialBalance: "1", window: { effectiveFrom: "2026-01-01" } },
    certificationReconciliation: { definitionId: "recon-a", reconciliationId: "recon-a", requiredSectionIds: ["loans"], controls: [{ controlId: "pool-a", sectionId: "loans", recordSource: "normalized", dimensions: ["portfolio_id"], balanceField: "current_balance", currencyField: "currency", expected: [{ dimensions: { portfolio_id: "portfolio-a" }, rowCount: 1, balance: "100", currency: "USD" }], balanceTolerance: "0" }], window: { effectiveFrom: "2026-01-01" } },
    window: { effectiveFrom: "2026-01-01" }, approval: { status: "pending_durable_approval", authority: "governed_definition_v2_lifecycle" }
  });
  const controlReference = definitionReference("control-version-a", control.certificationDefinitionId, "snapshot_certification_control", control);
  const snapshot = createDatasetSnapshotV2({
    contractVersion: 2, tenantId: "tenant-a", snapshotId: "snapshot-a", sourceContract: sourceReference, delivery: source.delivery, sourceLocator: "upload://loans-a", asOfDate: "2026-01-31",
    knowledge: { sourceObservedAt: "2026-02-01T00:00:00.000Z", extractedAt: "2026-02-01T00:01:00.000Z", receivedAt: "2026-02-01T00:02:00.000Z", persistedAt: "2026-02-01T00:03:00.000Z" }, watermark: { mode: "none" },
    hashes: { contentHash: HASH("snapshot-content"), schemaHash: HASH("snapshot-schema"), catalogHash: HASH("snapshot-catalog"), parserHash: HASH("snapshot-parser"), extractionHash: HASH("receipt-a") },
    rowCount: 1, byteCount: 100, sections: [{ sectionId: "loans", required: true, present: true, rowCount: 1, contentHash: HASH("snapshot-section"), schemaHash: HASH("snapshot-section-schema") }], correction: { kind: "original" }, createdBy: "capture-worker"
  });
  const correctedSnapshot = options.includeCorrection || options.injectCorrectionOnEnabledCheck !== undefined
    ? createDatasetSnapshotV2({
        contractVersion: 2, tenantId: "tenant-a", snapshotId: "snapshot-a-correction", sourceContract: sourceReference, delivery: source.delivery, sourceLocator: "upload://loans-a-correction", asOfDate: snapshot.asOfDate,
        knowledge: { sourceObservedAt: "2026-02-02T00:00:00.000Z", extractedAt: "2026-02-02T00:01:00.000Z", receivedAt: "2026-02-02T00:02:00.000Z", persistedAt: "2026-02-02T00:03:00.000Z" }, watermark: { mode: "none" },
        hashes: { contentHash: HASH("correction-content"), schemaHash: snapshot.hashes.schemaHash, catalogHash: HASH("correction-catalog"), parserHash: snapshot.hashes.parserHash, extractionHash: HASH("correction-receipt") },
        rowCount: 1, byteCount: 101, sections: [{ sectionId: "loans", required: true, present: true, rowCount: 1, contentHash: HASH("correction-section"), schemaHash: HASH("snapshot-section-schema") }],
        correction: { kind: "correction", correctsSnapshotId: snapshot.snapshotId, correctsSnapshotHash: snapshot.snapshotHash, correctionSequence: 1, reasonCode: "source_correction", reason: "Source delivered a corrected population", detectedAt: "2026-02-02T00:00:00.000Z" }, createdBy: "capture-worker"
      })
    : undefined;
  const application = createMappingApplicationV1({
    contractVersion: 1, tenantId: "tenant-a", mappingApplicationId: "mapping-application-a", snapshot: { snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, contentHash: snapshot.hashes.contentHash },
    mappingSpec: { mappingSpecId: mapping.mappingSpecId, revision: mapping.revision, mappingSpecHash: mapping.mappingSpecHash }, dictionaryBundle: dictionary,
    runtimeBundle: { runtimeBundleId: "runtime-a", runtimeBundleHash: HASH("runtime"), runtimeVersion: "1.0.0" }, inputPopulationHash: HASH("input"), outputPopulationHash: HASH([{ loan_id: "loan-a" }]), inputRowCount: 1, outputRowCount: 1, rejectedRowCount: 0, appliedBy: "mapping-worker", appliedAt: "2026-02-01T00:04:00.000Z"
  });
  const normalized = createNormalizedSnapshotArtifactV2({
    contractVersion: 2, kind: "normalized_snapshot", tenantId: "tenant-a", normalizedPopulationId: "population-a", snapshot: { snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash },
    mappingApplication: { mappingApplicationId: application.mappingApplicationId, mappingApplicationHash: application.mappingApplicationHash }, records: [{ loan_id: "loan-a" }], createdAt: "2026-02-01T00:04:30.000Z"
  });
  const artifacts = new ArtifactStore(join(directory, "artifacts"), { activeKeyId: "key-a", keys: { "key-a": Buffer.alloc(32, 7) } });
  const stored = artifacts.putJson({ tenantId: "tenant-a", kind: "normalized_snapshot", mediaType: "application/json", value: normalized });
  let artifactReads = 0;
  const artifactReader = {
    getJson(tenantId: string, artifactId: string) {
      artifactReads += 1;
      return artifacts.getJson(tenantId, artifactId);
    }
  };
  const metadata = createCertifiedSnapshotArtifactMetadataV1({ artifact: normalized, loadedStoredArtifact: stored });
  const populationBody = {
    contractVersion: 1 as const, tenantId: "tenant-a", populationId: normalized.normalizedPopulationId, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, mappingApplicationId: application.mappingApplicationId, mappingApplicationHash: application.mappingApplicationHash,
    populationHash: normalized.populationHash, fieldSetHash: normalized.fieldSetHash, rowCount: normalized.rowCount,
    dataQuality: { runId: "dq-run-a", rulesetId: "dq-rules-a", rulesetHash: HASH("dq-rules"), resultHash: HASH("dq-result"), publicationDecision: "publish" as const, blockerCodes: [] as string[] },
    reconciliation: { reconciliationId: "recon-a", definitionHash: HASH("recon-definition"), resultHash: HASH("recon-result"), passed: true as const, populationHash: normalized.populationHash }, certifiedBy: "certification-checker", certifiedAt: "2026-02-01T01:00:00.000Z"
  };
  const population = { ...populationBody, certificationHash: HASH(populationBody) };
  const certificationBody = {
    contractVersion: 1 as const, tenantId: "tenant-a", certificationManifestId: "certification-a", evidenceFormat: "modern_snapshot_v2" as const, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, populationId: population.populationId, populationCertificationHash: population.certificationHash,
    mappingApplicationId: application.mappingApplicationId, mappingApplicationHash: application.mappingApplicationHash, normalizedArtifactId: metadata.artifactId, normalizedArtifactContentHash: metadata.contentHash as Sha256Hash, dataQualityResultHash: population.dataQuality.resultHash, reconciliationResultHash: population.reconciliation.resultHash, populationHash: population.populationHash, rowCount: population.rowCount, certifiedBy: population.certifiedBy, certifiedAt: population.certifiedAt
  };
  const v1Evidence = createCertifiedSnapshotEvidenceRecordV1({
    contractVersion: 1, tenantId: "tenant-a", certification: { ...certificationBody, certificationManifestHash: HASH(certificationBody) }, population, mappingSpec: mapping, mappingApplication: application, normalizedArtifact: metadata,
    dataQualityPopulation: { populationHash: population.populationHash, fieldSetHash: population.fieldSetHash, rowCount: population.rowCount }, recordedAt: "2026-02-01T01:00:00.000Z"
  });
  const evidence = createCertifiedSnapshotEvidenceRecordV2({
    contractVersion: 2, tenantId: "tenant-a", v1Evidence,
    certificationAttempt: createSnapshotCertificationAttemptV1({ contractVersion: 1, tenantId: "tenant-a", certificationManifestId: certificationBody.certificationManifestId, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, actorId: "certification-checker", requestHash: HASH("request-a"), certifiedAt: certificationBody.certifiedAt, createdAt: certificationBody.certifiedAt }),
    governance: {
      control: { definition: control, reference: controlReference, approval: { status: "approved", proposedBy: "control-maker", approvedBy: "control-checker", approvedAt: "2026-01-01T00:01:00.000Z", approvalEventHash: controlReference.approvalEventHash }, activation: { status: "active", lifecycleRevision: 1, activatedBy: "control-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationEventHash: HASH("control-activation") } },
      sourceContract: { raw: sourceReference, execution: sourceExecution }, scopeBinding: { raw: scope, execution: scopeExecution }, mapping: { execution: mappingExecution, activation },
      runtime: { runtimeBundleId: "runtime-a", runtimeVersion: "1.0.0", runtimeBundleHash: HASH("runtime"), activation: { tenantId: "tenant-a", runtimeBundleId: "runtime-a", runtimeBundleHash: HASH("runtime"), registeredBy: "runtime-maker", registeredAt: "2026-01-01T00:00:00.000Z", activatedBy: "runtime-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationHash: HASH("runtime-activation") }, dictionary, mappingCompiler: compiler }
    }, recordedAt: certificationBody.certifiedAt
  });
  const { sourceContract: _sourceContract, ...publishedSourceDefinition } = sourceExecution;
  const publication = createCertifiedSnapshotPublicationV1({
    contractVersion: 1, publicationId: "publication-a", tenantId: "tenant-a", datasetId: scope.datasetId, scope: scope.scope,
    datasetBinding: { contractVersion: 1, bindingId: scope.bindingId, tenantId: scope.tenantId, datasetId: scope.datasetId, sourceContract: sourceReference, scope: scope.scope, boundAt: "2026-01-01T00:01:00.000Z", bindingHash: HASH({ contractVersion: 1, bindingId: scope.bindingId, tenantId: scope.tenantId, datasetId: scope.datasetId, sourceContract: sourceReference, scope: scope.scope, boundAt: "2026-01-01T00:01:00.000Z" }) },
    sourceContract: { definition: publishedSourceDefinition, sourceContractId: source.sourceContractId, sourceKey: source.sourceKey, revision: source.revision, sourceContractHash: source.sourceContractHash },
    snapshot: { snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, sourceContract: sourceReference, delivery: { mode: snapshot.delivery.mode, deliveredContentHash: snapshot.hashes.contentHash }, asOfDate: snapshot.asOfDate, knowledge: snapshot.knowledge, hashes: snapshot.hashes, rowCount: snapshot.rowCount, byteCount: snapshot.byteCount, correction: snapshot.correction },
    certification: v1Evidence.certification, population: v1Evidence.population,
    mappingSpec: { mappingSpecId: mapping.mappingSpecId, mappingKey: mapping.mappingKey, revision: mapping.revision, mappingSpecHash: mapping.mappingSpecHash, sourceContract: sourceReference, dictionaryBundle: dictionary }, mappingApplication: application,
    normalizedArtifact: { artifactId: metadata.artifactId, artifactContractVersion: 2, artifactHash: metadata.artifactHash, kind: "normalized_snapshot", mediaType: "application/json", contentHash: metadata.contentHash as Sha256Hash, byteLength: metadata.byteLength, uri: metadata.uri, metadataHash: HASH({ artifactId: stored.artifactId, tenantBinding: stored.tenantBinding, kind: stored.kind, mediaType: stored.mediaType, contentHash: stored.contentHash, byteLength: stored.byteLength, keyId: stored.keyId, uri: stored.uri }), rowCount: normalized.rowCount, populationHash: normalized.populationHash, fieldSetHash: normalized.fieldSetHash },
    publishedBy: "publication-checker", publishedAt: "2026-02-01T01:01:00.000Z"
  });
  const link = createGovernedCertifiedSnapshotPublicationLinkV2({ linkId: "publication-link-a", publication, evidenceId: evidence.certificationAttempt.certificationManifestId, evidence, linkedAt: "2026-02-01T01:02:00.000Z" });
  const lineage = createGovernedSnapshotCommitLineageV1({
    contractVersion: 1, tenantId: "tenant-a", snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, datasetId: scope.datasetId, facilityId: "facility-a", sourceContract: sourceReference,
    scopeBinding: { bindingId: scope.bindingId, revision: scope.revision, bindingHash: scope.bindingHash }, sourceDelivery: { deliveryId: "delivery-a", deliveryRevision: 1, deliveryHash: HASH("delivery"), locatorHash: HASH("locator"), sourceVersionHash: HASH("source-version") }, extractionReceipt: { receiptId: "receipt-a", receiptHash: snapshot.hashes.extractionHash }, asOfDate: snapshot.asOfDate
  });
  const definitions = definitionResolver([
    resolved(controlReference, control), resolved(sourceExecution, source), resolved(scopeExecution, scope), resolved(mappingExecution, options.substituteMapping ? { ...mapping, mappingKey: "substituted-mapping" } : mapping)
  ]);
  const needsCatalog = options.catalogDisabled !== undefined ||
    options.disableOnEnabledCheck !== undefined ||
    options.injectCorrectionOnEnabledCheck !== undefined;
  const catalog = !needsCatalog
    ? undefined
    : new GovernedCertifiedSnapshotPublicationLinkCatalogV2(join(directory, "publication-links-v2.sqlite"));
  if (catalog !== undefined) {
    catalog.record({ link, requestHash: HASH("record-link-a"), actor: "publication-worker", idempotencyKey: "record-link-a" });
    if (options.catalogDisabled) {
      catalog.disable({
        tenantId: "tenant-a",
        linkId: link.linkId,
        expectedLinkHash: link.linkHash,
        reasonCode: "correction",
        reason: "Superseded by a corrected certification",
        disabledBy: "publication-worker",
        idempotencyKey: "disable-link-a"
      });
    }
  }
  let correctionVisible = options.includeCorrection === true;
  let enabledChecks = 0;
  const publicationLinks: GovernedCertifiedSnapshotPublicationLinkReadPortV2 = catalog === undefined
    ? new StaticLinkRepository(link)
    : {
        get(tenantId: string, linkId: string) {
          return catalog.get(tenantId, linkId);
        },
        getEnabled(tenantId: string, linkId: string) {
          enabledChecks += 1;
          if (enabledChecks === options.injectCorrectionOnEnabledCheck) correctionVisible = true;
          if (enabledChecks === options.disableOnEnabledCheck) {
            catalog.disable({
              tenantId,
              linkId,
              expectedLinkHash: link.linkHash,
              reasonCode: "race_disable",
              reason: "Injected immediately before artifact read",
              disabledBy: "publication-worker",
              idempotencyKey: "race-disable-link-a"
            });
          }
          return catalog.getEnabled(tenantId, linkId);
        }
      };
  const authority = new RepositoryBackedSurveillanceSourcePublicationAuthorityV2({
    datasetSnapshots: new StaticRepository(
      snapshot,
      [snapshot],
      () => correctionVisible && correctedSnapshot ? [snapshot, correctedSnapshot] : [snapshot]
    ),
    captureLineage: { async getGovernedCaptureLineage() { return options.lineage === undefined && Object.hasOwn(options, "lineage") ? undefined : lineage; } },
    certifiedSnapshotEvidence: new StaticRepository(evidence),
    publicationLinks,
    artifacts: artifactReader,
    definitions
  });
  return { authority, evidence, link, lineage, artifactReadCount: () => artifactReads, close: () => catalog?.close() };
}

function definitionReference(
  definitionVersionId: string,
  definitionKey: string,
  kind: "source_contract" | "dataset_scope_binding" | "mapping_spec" | "snapshot_certification_control",
  document: unknown
) {
  return { definitionVersionId, definitionKey, kind, semanticVersion: "1.0.0", versionHash: HASH(`${definitionVersionId}-version`), documentHash: HASH(document), approvalEventHash: HASH(`${definitionVersionId}-approval`) };
}

function resolved(reference: ReturnType<typeof definitionReference>, executionDocument: unknown): ResolvedGovernedDefinitionV2 {
  return { reference, approvalEvidence: { status: "approved", proposedBy: "definition-maker", approvedBy: "definition-checker", approvedAt: "2026-01-01T00:01:00.000Z", approvalEventHash: reference.approvalEventHash }, executionDocument: executionDocument as never };
}

function definitionResolver(records: readonly ResolvedGovernedDefinitionV2[]) {
  const byId = new Map(records.map((record) => [record.reference.definitionVersionId, record]));
  return {
    resolveFrozen(input: { readonly tenantId: string; readonly definitionVersionId: string }) {
      if (input.tenantId !== "tenant-a" || !byId.has(input.definitionVersionId)) {
        throw new GovernedDefinitionV2ResolverError("NOT_FOUND", "definition not found");
      }
      return byId.get(input.definitionVersionId)!;
    }
  };
}

class StaticRepository<T extends { readonly tenantId: string }> implements ImmutableRepositoryPort<T> {
  constructor(
    private readonly record: T,
    private readonly records: readonly T[] = [record],
    private readonly listRecords: () => readonly T[] = () => records
  ) {}
  async put(): Promise<never> { throw new Error("test repository is read only"); }
  async get(tenantId: string, _recordId: string): Promise<T | undefined> { return tenantId === this.record.tenantId ? this.record : undefined; }
  async list(tenantId: string): Promise<RepositoryPage<T>> { return { items: tenantId === this.record.tenantId ? this.listRecords() : [], nextCursor: null }; }
  async getDirectCorrection(
    tenantId: string,
    correctsSnapshotId: string,
    correctsSnapshotHash: string
  ): Promise<DatasetSnapshotV2 | undefined> {
    if (tenantId !== this.record.tenantId) return undefined;
    return this.listRecords()
      .map((value) => value as unknown as DatasetSnapshotV2)
      .find((candidate) =>
        candidate.correction?.kind === "correction" &&
        candidate.correction.correctsSnapshotId === correctsSnapshotId &&
        candidate.correction.correctsSnapshotHash === correctsSnapshotHash
      );
  }
}

class StaticLinkRepository implements GovernedCertifiedSnapshotPublicationLinkReadPortV2 {
  constructor(private readonly link: GovernedCertifiedSnapshotPublicationLinkV2) {}
  async get(tenantId: string, linkId: string): Promise<GovernedCertifiedSnapshotPublicationLinkV2 | undefined> { return tenantId === this.link.tenantId && linkId === this.link.linkId ? this.link : undefined; }
  async getEnabled(tenantId: string, linkId: string): Promise<GovernedCertifiedSnapshotPublicationLinkV2 | undefined> { return tenantId === this.link.tenantId && linkId === this.link.linkId ? this.link : undefined; }
}

function authorityError(error: unknown, expected: SurveillanceProductionAuthorityV2Error["code"]): boolean {
  return error instanceof SurveillanceProductionAuthorityV2Error && error.code === expected;
}
