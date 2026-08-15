import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";

import {
  canonicalHash, createCertifiedSnapshotEvidenceRecordV1,
  createCertifiedSnapshotPublicationV1, createGovernedDatasetScopeBindingV1,
  createMappingApplicationV1, createMappingSpecV2, type Sha256Hash
} from "../src/contracts/index.js";
import {
  createCertifiedSnapshotEvidenceRecordV2,
  type CertifiedSnapshotEvidenceRecordV2Input
} from "../src/contracts/certified-snapshot-evidence-v2.js";
import { createGovernedCertifiedSnapshotPublicationLinkV2 } from "../src/contracts/governed-certified-snapshot-publication-link-v2.js";
import { createSnapshotCertificationAttemptV1 } from "../src/contracts/snapshot-certification-attempt-v1.js";
import { createSnapshotCertificationDefinitionV1 } from "../src/contracts/snapshot-certification-definition-v1.js";
import {
  GovernedCertifiedSnapshotPublicationLinkCatalogV2,
  GovernedCertifiedSnapshotPublicationLinkCatalogV2Error
} from "../src/control/governed-certified-snapshot-publication-links-v2.js";

const HASH = (value: unknown): Sha256Hash => canonicalHash(value);
const requestHash = (link: { readonly linkId: string; readonly linkHash: Sha256Hash }): Sha256Hash =>
  HASH({ linkId: link.linkId, linkHash: link.linkHash });

test("governed V2 publication-link catalog is tenant-fenced, immutable, actor-idempotent, and disable-only", () => {
  const catalog = new GovernedCertifiedSnapshotPublicationLinkCatalogV2(":memory:", {
    clock: () => new Date("2026-01-02T02:00:00.000Z")
  });
  const link = fixtureLink();
  const input = { link, requestHash: requestHash(link), actor: "publication-worker", idempotencyKey: "record-a" };
  assert.deepEqual(catalog.record(input), link);
  assert.deepEqual(catalog.record(input), link);
  assert.equal(catalog.get("tenant-b", link.linkId), undefined);
  assert.deepEqual(catalog.list("tenant-b"), []);
  assert.throws(
    () => catalog.record({ ...input, actor: "another-worker", idempotencyKey: "record-a" }),
    (error: unknown) => catalogError(error, "CONFLICT")
  );
  assert.equal(catalog.getEnabled("tenant-a", link.linkId)?.linkHash, link.linkHash);
  const disable = catalog.disable({
    tenantId: "tenant-a", linkId: link.linkId, expectedLinkHash: link.linkHash,
    reasonCode: "superseded", reason: "A corrected source delivery superseded this bridge.",
    disabledBy: "publication-checker", idempotencyKey: "disable-a"
  });
  assert.equal(disable.linkHash, link.linkHash);
  assert.equal(catalog.getEnabled("tenant-a", link.linkId), undefined);
  assert.deepEqual(catalog.listAuditEvents("tenant-a").map((event) => event.eventType), [
    "governed_certified_snapshot_publication_link_v2.recorded",
    "governed_certified_snapshot_publication_link_v2.disabled"
  ]);
  assert.throws(
    () => catalog.disable({
      tenantId: "tenant-a", linkId: link.linkId, expectedLinkHash: link.linkHash,
      reasonCode: "different", reason: "This must not replace the immutable disable receipt.",
      disabledBy: "publication-checker", idempotencyKey: "disable-a"
    }),
    (error: unknown) => catalogError(error, "IDEMPOTENCY_CONFLICT")
  );
  catalog.close();
});

test("governed V2 publication-link catalog rejects tampered materialized indexes after reopen", () => {
  const directory = mkdtempSync(join(tmpdir(), "abl-link-catalog-v2-"));
  const path = join(directory, "links.sqlite");
  const catalog = new GovernedCertifiedSnapshotPublicationLinkCatalogV2(path);
  const link = fixtureLink();
  catalog.record({ link, requestHash: requestHash(link), actor: "publication-worker", idempotencyKey: "record-a" });
  catalog.close();
  const database = new DatabaseSync(path);
  database.exec("DROP TRIGGER governed_certified_snapshot_publication_links_v2_no_update");
  database.prepare("UPDATE governed_certified_snapshot_publication_links_v2 SET evidence_hash = ? WHERE tenant_id = ? AND link_id = ?")
    .run(HASH("substituted-evidence"), "tenant-a", link.linkId);
  database.exec(`CREATE TRIGGER governed_certified_snapshot_publication_links_v2_no_update
BEFORE UPDATE ON governed_certified_snapshot_publication_links_v2
BEGIN SELECT RAISE(ABORT, 'governed V2 publication links are immutable'); END;`);
  database.close();
  const reopened = new GovernedCertifiedSnapshotPublicationLinkCatalogV2(path);
  assert.throws(
    () => reopened.get("tenant-a", link.linkId),
    (error: unknown) => catalogError(error, "INTEGRITY_FAILURE")
  );
  reopened.close();
});

function fixtureLink() {
  const sourceContract = { sourceContractId: "loan-source", revision: 1, sourceContractHash: HASH("loan-source") };
  const scopeBinding = createGovernedDatasetScopeBindingV1({ contractVersion: 1, tenantId: "tenant-a", bindingId: "facility-a-binding", revision: 1, datasetId: "loan-dataset", sourceContract, scope: { scopeType: "facility", scopeId: "facility-a" }, effectiveFrom: "2026-01-01" });
  const dictionary = { contractVersion: 1 as const, bundleKind: "dictionary" as const, bundleId: "dictionary-a", version: "1.0.0", contentHash: HASH("dictionary-content"), artifactId: "dictionary-artifact", mediaType: "application/json", createdAt: "2026-01-01T00:00:00.000Z", dictionaryVersion: "1.0.0", dictionaryHash: HASH("dictionary"), fieldPolicyVersion: "1.0.0", fieldPolicyHash: HASH("field-policy") };
  const compiler = { contractVersion: 1 as const, bundleKind: "mapping_compiler" as const, bundleId: "compiler-a", version: "1.0.0", contentHash: HASH("compiler-content"), artifactId: "compiler-artifact", mediaType: "application/json", createdAt: "2026-01-01T00:00:00.000Z" };
  const mappingSpec = createMappingSpecV2({ contractVersion: 2, tenantId: "tenant-a", mappingSpecId: "mapping-spec-a", mappingKey: "loan-tape", revision: 1, status: "active", sourceContract, dictionaryBundle: dictionary, rules: [{ ruleId: "loan-id", canonicalField: "loan_id", expression: { op: "source", column: "loan_id" }, onError: "fail_application" }], requiredCanonicalFields: ["loan_id"], createdBy: "mapping-maker", createdAt: "2026-01-01T00:00:00.000Z", approvedBy: "mapping-checker", approvedAt: "2026-01-01T00:01:00.000Z" });
  const activation = { status: "active" as const, lifecycleRevision: 3, activatedBy: "mapping-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationEventHash: HASH("mapping-activation") };
  const mappingExecution = { definitionVersionId: "mapping-version-a", definitionKey: "loan-tape", kind: "mapping_spec" as const, semanticVersion: "1.0.0", versionHash: HASH("mapping-version"), documentHash: HASH("mapping-document"), approvalEventHash: HASH("mapping-approval"), mappingSpecId: mappingSpec.mappingSpecId, mappingSpecRevision: mappingSpec.revision, mappingSpecHash: mappingSpec.mappingSpecHash, sourceContract, activation, window: { effectiveFrom: "2026-01-01" } };
  const sourceExecution = { definitionVersionId: "source-version-a", definitionKey: "loan-source-key", kind: "source_contract" as const, semanticVersion: "1.0.0", versionHash: HASH("source-version"), documentHash: HASH("source-document"), approvalEventHash: HASH("source-approval"), sourceContract };
  const scopeExecution = { definitionVersionId: "scope-version-a", definitionKey: scopeBinding.bindingId, kind: "dataset_scope_binding" as const, semanticVersion: "1.0.0", versionHash: HASH("scope-version"), documentHash: HASH("scope-document"), approvalEventHash: HASH("scope-approval"), bindingId: scopeBinding.bindingId, revision: scopeBinding.revision, bindingHash: scopeBinding.bindingHash, sourceContract };
  const definition = createSnapshotCertificationDefinitionV1({ contractVersion: 1, definitionKind: "snapshot_certification_control", tenantId: "tenant-a", certificationDefinitionId: scopeBinding.bindingId, revision: 1, sourceContract, sourceContractExecution: sourceExecution, scopeBinding, scopeBindingExecution: scopeExecution, mappingExecution, runtime: { runtimeBundleId: "runtime-a", runtimeVersion: "1.0.0", runtimeBundleHash: HASH("runtime"), dictionary, mappingCompiler: compiler }, dataQuality: { definitionId: "dq-a", rulesetId: "dq-rules-a", mappingSectionId: "loans", requiredSectionIds: ["loans"], rules: [{ ruleId: "loan-required", type: "required", field: "loan_id", severity: "critical", blocking: true }], balanceField: "current_balance", materialBalance: "1", window: { effectiveFrom: "2026-01-01" } }, certificationReconciliation: { definitionId: "recon-a", reconciliationId: "recon-a", requiredSectionIds: ["loans"], controls: [{ controlId: "pool-balance", sectionId: "loans", recordSource: "normalized", dimensions: ["portfolio_id"], balanceField: "current_balance", currencyField: "currency", expected: [{ dimensions: { portfolio_id: "portfolio-a" }, rowCount: 1, balance: "100", currency: "USD" }], balanceTolerance: "0" }], window: { effectiveFrom: "2026-01-01" } }, window: { effectiveFrom: "2026-01-01" }, approval: { status: "pending_durable_approval", authority: "governed_definition_v2_lifecycle" } });
  const snapshot = { snapshotId: "snapshot-a", snapshotHash: HASH("snapshot"), contentHash: HASH("snapshot-content") };
  const mappingApplication = createMappingApplicationV1({ contractVersion: 1, tenantId: "tenant-a", mappingApplicationId: "application-a", snapshot, mappingSpec: { mappingSpecId: mappingSpec.mappingSpecId, revision: mappingSpec.revision, mappingSpecHash: mappingSpec.mappingSpecHash }, dictionaryBundle: dictionary, runtimeBundle: { runtimeBundleId: "runtime-a", runtimeBundleHash: HASH("runtime"), runtimeVersion: "1.0.0" }, inputPopulationHash: HASH("input-population"), outputPopulationHash: HASH("output-population"), inputRowCount: 1, outputRowCount: 1, rejectedRowCount: 0, appliedBy: "mapping-worker", appliedAt: "2026-01-02T00:01:00.000Z" });
  const populationBody = { contractVersion: 1 as const, tenantId: "tenant-a", populationId: "population-a", snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, mappingApplicationId: mappingApplication.mappingApplicationId, mappingApplicationHash: mappingApplication.mappingApplicationHash, populationHash: mappingApplication.outputPopulationHash, fieldSetHash: HASH("field-set"), rowCount: 1, dataQuality: { runId: "dq-run-a", rulesetId: "dq-rules-a", rulesetHash: HASH("dq-rules"), resultHash: HASH("dq-result"), publicationDecision: "publish" as const, blockerCodes: [] as string[] }, reconciliation: { reconciliationId: "recon-a", definitionHash: HASH("recon-definition"), resultHash: HASH("recon-result"), passed: true as const, populationHash: mappingApplication.outputPopulationHash }, certifiedBy: "certification-checker", certifiedAt: "2026-01-02T01:00:00.000Z" };
  const population = { ...populationBody, certificationHash: HASH(populationBody) };
  const certificationBody = { contractVersion: 1 as const, tenantId: "tenant-a", certificationManifestId: "manifest-a", evidenceFormat: "modern_snapshot_v2" as const, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, populationId: population.populationId, populationCertificationHash: population.certificationHash, mappingApplicationId: mappingApplication.mappingApplicationId, mappingApplicationHash: mappingApplication.mappingApplicationHash, normalizedArtifactId: "artifact-a", normalizedArtifactContentHash: HASH("artifact-content"), dataQualityResultHash: population.dataQuality.resultHash, reconciliationResultHash: population.reconciliation.resultHash, populationHash: population.populationHash, rowCount: population.rowCount, certifiedBy: population.certifiedBy, certifiedAt: population.certifiedAt };
  const v1Evidence = createCertifiedSnapshotEvidenceRecordV1({ contractVersion: 1, tenantId: "tenant-a", certification: { ...certificationBody, certificationManifestHash: HASH(certificationBody) }, population, mappingSpec, mappingApplication, normalizedArtifact: { tenantId: "tenant-a", artifactId: "artifact-a", kind: "normalized_snapshot", mediaType: "application/json", artifactContractVersion: 2, artifactHash: HASH("artifact"), contentHash: certificationBody.normalizedArtifactContentHash, byteLength: 100, keyId: "key-a", uri: `abl-artifact://${"a".repeat(64)}`, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, normalizedPopulationId: population.populationId, mappingApplicationId: mappingApplication.mappingApplicationId, mappingApplicationHash: mappingApplication.mappingApplicationHash, populationHash: population.populationHash, fieldSetHash: population.fieldSetHash, rowCount: 1, createdAt: "2026-01-02T00:30:00.000Z" }, dataQualityPopulation: { populationHash: population.populationHash, fieldSetHash: population.fieldSetHash, rowCount: 1 }, recordedAt: "2026-01-02T01:00:00.000Z" });
  const controlReference = { definitionVersionId: "control-version-a", definitionKey: definition.certificationDefinitionId, kind: "snapshot_certification_control" as const, semanticVersion: "1.0.0", versionHash: HASH("control-version"), documentHash: HASH(definition), approvalEventHash: HASH("control-approval") };
  const evidence = createCertifiedSnapshotEvidenceRecordV2({ contractVersion: 2 as const, tenantId: "tenant-a", v1Evidence, certificationAttempt: createSnapshotCertificationAttemptV1({ contractVersion: 1, tenantId: "tenant-a", certificationManifestId: certificationBody.certificationManifestId, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, actorId: "certification-checker", requestHash: HASH("certification-request"), certifiedAt: certificationBody.certifiedAt, createdAt: "2026-01-02T01:00:00.000Z" }), governance: { control: { definition, reference: controlReference, approval: { status: "approved" as const, proposedBy: "control-maker", approvedBy: "control-checker", approvedAt: "2026-01-01T00:01:00.000Z", approvalEventHash: controlReference.approvalEventHash }, activation: { status: "active" as const, lifecycleRevision: 3, activatedBy: "control-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationEventHash: HASH("control-activation") } }, sourceContract: { raw: sourceContract, execution: sourceExecution }, scopeBinding: { raw: scopeBinding, execution: scopeExecution }, mapping: { execution: mappingExecution, activation }, runtime: { runtimeBundleId: "runtime-a", runtimeVersion: "1.0.0", runtimeBundleHash: HASH("runtime"), activation: { tenantId: "tenant-a", runtimeBundleId: "runtime-a", runtimeBundleHash: HASH("runtime"), registeredBy: "runtime-maker", registeredAt: "2026-01-01T00:00:00.000Z", activatedBy: "runtime-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationHash: HASH("runtime-activation") }, dictionary, mappingCompiler: compiler } }, recordedAt: "2026-01-02T01:00:00.000Z" } satisfies CertifiedSnapshotEvidenceRecordV2Input);
  const datasetBindingBody = { contractVersion: 1 as const, bindingId: scopeBinding.bindingId, tenantId: "tenant-a", datasetId: scopeBinding.datasetId, sourceContract, scope: scopeBinding.scope, boundAt: "2026-01-01T00:00:00.000Z" };
  const publication = createCertifiedSnapshotPublicationV1({ contractVersion: 1, publicationId: "publication-a", tenantId: "tenant-a", datasetId: scopeBinding.datasetId, scope: scopeBinding.scope, datasetBinding: { ...datasetBindingBody, bindingHash: HASH(datasetBindingBody) }, sourceContract: { definition: { definitionVersionId: sourceExecution.definitionVersionId, definitionKey: sourceExecution.definitionKey, kind: "source_contract", semanticVersion: sourceExecution.semanticVersion, versionHash: sourceExecution.versionHash, documentHash: sourceExecution.documentHash, approvalEventHash: sourceExecution.approvalEventHash }, sourceContractId: sourceContract.sourceContractId, sourceKey: sourceExecution.definitionKey, revision: sourceContract.revision, sourceContractHash: sourceContract.sourceContractHash }, snapshot: { snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, sourceContract, delivery: { mode: "postgresql_pull", deliveredContentHash: snapshot.contentHash }, asOfDate: "2026-01-02", knowledge: { sourceObservedAt: "2026-01-02T00:00:00.000Z", extractedAt: "2026-01-02T00:00:01.000Z", receivedAt: "2026-01-02T00:00:02.000Z", persistedAt: "2026-01-02T00:00:03.000Z" }, hashes: { contentHash: snapshot.contentHash, schemaHash: HASH("schema"), catalogHash: HASH("catalog"), parserHash: HASH("parser"), extractionHash: HASH("extraction") }, rowCount: 1, byteCount: 100, correction: { kind: "original" } }, certification: v1Evidence.certification, population: v1Evidence.population, mappingSpec: { mappingSpecId: mappingSpec.mappingSpecId, mappingKey: mappingSpec.mappingKey, revision: mappingSpec.revision, mappingSpecHash: mappingSpec.mappingSpecHash, sourceContract, dictionaryBundle: dictionary }, mappingApplication, normalizedArtifact: { artifactId: v1Evidence.normalizedArtifact.artifactId, artifactContractVersion: 2, artifactHash: v1Evidence.normalizedArtifact.artifactHash, kind: "normalized_snapshot", mediaType: "application/json", contentHash: v1Evidence.normalizedArtifact.contentHash, byteLength: v1Evidence.normalizedArtifact.byteLength, uri: "artifact://tenant-a/normalized", metadataHash: HASH("metadata"), rowCount: 1, populationHash: population.populationHash, fieldSetHash: population.fieldSetHash }, publishedBy: "publication-worker", publishedAt: "2026-01-02T01:01:00.000Z" });
  return createGovernedCertifiedSnapshotPublicationLinkV2({ linkId: "publication-link-a", publication, evidenceId: evidence.certificationAttempt.certificationManifestId, evidence, linkedAt: "2026-01-02T01:01:00.000Z" });
}

function catalogError(error: unknown, code: GovernedCertifiedSnapshotPublicationLinkCatalogV2Error["code"]): boolean {
  return error instanceof GovernedCertifiedSnapshotPublicationLinkCatalogV2Error && error.code === code;
}
