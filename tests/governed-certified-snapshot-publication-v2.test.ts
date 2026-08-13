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
  createSnapshotCertificationAttemptV1,
  createSnapshotCertificationDefinitionV1,
  createSourceContractV1,
  type DatasetSnapshotV2,
  type Sha256Hash
} from "../src/contracts/index.js";
import { createCertifiedSnapshotEvidenceRecordV2, type CertifiedSnapshotEvidenceRecordV2 } from "../src/contracts/certified-snapshot-evidence-v2.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import { GovernedCertifiedSnapshotPublicationLinkCatalogV2 } from "../src/control/governed-certified-snapshot-publication-links-v2.js";
import { createGovernedSnapshotCommitLineageV1, type GovernedSnapshotCommitLineageV1 } from "../src/repositories/governed-snapshot-commit.js";
import type { ImmutableRepositoryPort, RepositoryPage, RepositoryWriteContext } from "../src/repositories/ports.js";
import { GovernedDefinitionV2ResolverError, type ResolvedGovernedDefinitionV2 } from "../src/services/governed-definition-v2-resolver.js";
import { GovernedCertifiedSnapshotPublicationV2Error, GovernedCertifiedSnapshotPublicationV2Service } from "../src/services/governed-certified-snapshot-publication-v2.js";

const directories: string[] = [];
const hash = (value: unknown): Sha256Hash => canonicalHash(value);

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("V2 publication service creates an IDs-only, actor-bound immutable sidecar link", async () => {
  const fixture = fixtureEnvironment();
  const request = {
    tenantId: "tenant-a",
    linkId: "link-a",
    certificationManifestId: fixture.evidence.certificationAttempt.certificationManifestId,
    idempotencyKey: "publish-once-a"
  };
  const recorded = await fixture.service.publish(request, "publication-checker");
  const replayed = await fixture.service.publish(request, "publication-checker");

  assert.equal(recorded.linkId, "link-a");
  assert.equal(recorded.publication.publicationId, "link-a");
  assert.equal(recorded.evidence.evidenceHash, fixture.evidence.evidenceHash);
  assert.deepEqual(replayed, recorded);
  assert.equal(fixture.catalog.getEnabled("tenant-a", "link-a")?.linkHash, recorded.linkHash);
  fixture.close();
});

test("V2 publication service reports a missing immutable evidence record distinctly", async () => {
  const fixture = fixtureEnvironment();
  await assert.rejects(
    fixture.service.publish({ tenantId: "tenant-a", linkId: "link-missing", certificationManifestId: "missing-evidence", idempotencyKey: "publish-missing" }, "publication-checker"),
    (error: unknown) => error instanceof GovernedCertifiedSnapshotPublicationV2Error && error.code === "EVIDENCE_NOT_FOUND"
  );
  fixture.close();
});

test("V2 publication service fails closed when frozen mapping authority is substituted", async () => {
  const fixture = fixtureEnvironment({ substituteMapping: true });
  await assert.rejects(
    fixture.service.publish({ tenantId: "tenant-a", linkId: "link-substituted", certificationManifestId: fixture.evidence.certificationAttempt.certificationManifestId, idempotencyKey: "publish-substituted" }, "publication-checker"),
    (error: unknown) => error instanceof GovernedCertifiedSnapshotPublicationV2Error && error.code === "AUTHORITY_MISMATCH"
  );
  fixture.close();
});

interface Fixture {
  readonly evidence: CertifiedSnapshotEvidenceRecordV2;
  readonly service: GovernedCertifiedSnapshotPublicationV2Service;
  readonly catalog: GovernedCertifiedSnapshotPublicationLinkCatalogV2;
  close(): void;
}

function fixtureEnvironment(options: { readonly substituteMapping?: boolean } = {}): Fixture {
  const directory = mkdtempSync(join(tmpdir(), "governed-publication-v2-"));
  directories.push(directory);
  const source = createSourceContractV1({
    contractVersion: 1, tenantId: "tenant-a", sourceContractId: "loan-source-a", sourceKey: "loan-source-key-a", revision: 1, status: "proposed",
    delivery: { mode: "managed_upload", format: "parquet", logicalName: "loans.parquet" },
    schemaPolicy: { columns: [{ sourceName: "loan_id", ordinal: 0, nativeType: "string", nullable: false, required: true }], allowUnknownColumns: false, requireStableOrdinals: true },
    parserPolicy: { format: "parquet", parserId: "parquet-v1", parserVersion: "1.0.0", optionsHash: hash("parser"), exactDecimalMode: "string", timezone: "UTC", rejectSchemaMerging: true },
    extractionPolicy: { mode: "full", readOnly: true, maximumRows: 100, maximumColumns: 10, maximumBytes: 10_000, timeoutMs: 1_000, cursorRows: 10 },
    sections: [{ sectionId: "loans", required: true, selector: "loans", keyFields: ["loan_id"] }], effectiveFrom: "2026-01-01", createdBy: "source-maker", createdAt: "2026-01-01T00:00:00.000Z"
  });
  const sourceReference = { sourceContractId: source.sourceContractId, revision: source.revision, sourceContractHash: source.sourceContractHash };
  const scope = createGovernedDatasetScopeBindingV1({ contractVersion: 1, tenantId: "tenant-a", bindingId: "facility-a-binding", revision: 1, datasetId: "loan-dataset-a", sourceContract: sourceReference, scope: { scopeType: "facility", scopeId: "facility-a" }, effectiveFrom: "2026-01-01" });
  const dictionary = { contractVersion: 1 as const, bundleKind: "dictionary" as const, bundleId: "dictionary-a", version: "1.0.0", contentHash: hash("dictionary-content"), artifactId: "dictionary-artifact-a", mediaType: "application/json", createdAt: "2026-01-01T00:00:00.000Z", dictionaryVersion: "1.0.0", dictionaryHash: hash("dictionary"), fieldPolicyVersion: "1.0.0", fieldPolicyHash: hash("field-policy") };
  const compiler = { contractVersion: 1 as const, bundleKind: "mapping_compiler" as const, bundleId: "compiler-a", version: "1.0.0", contentHash: hash("compiler-content"), artifactId: "compiler-artifact-a", mediaType: "application/json", createdAt: "2026-01-01T00:00:00.000Z" };
  const mapping = createMappingSpecV2({ contractVersion: 2, tenantId: "tenant-a", mappingSpecId: "mapping-spec-a", mappingKey: "loan-mapping-a", revision: 1, status: "active", sourceContract: sourceReference, dictionaryBundle: dictionary, rules: [{ ruleId: "loan-id", canonicalField: "loan_id", expression: { op: "source", column: "loan_id" }, onError: "fail_application" }], requiredCanonicalFields: ["loan_id"], createdBy: "mapping-maker", createdAt: "2026-01-01T00:00:00.000Z", approvedBy: "mapping-checker", approvedAt: "2026-01-01T00:01:00.000Z" });
  const sourceExecution = { ...definitionReference("source-version-a", source.sourceKey, "source_contract", source), sourceContract: sourceReference };
  const scopeExecution = { ...definitionReference("scope-version-a", scope.bindingId, "dataset_scope_binding", scope), bindingId: scope.bindingId, revision: scope.revision, bindingHash: scope.bindingHash, sourceContract: sourceReference };
  const activation = { status: "active" as const, lifecycleRevision: 1, activatedBy: "mapping-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationEventHash: hash("mapping-activation") };
  const mappingExecution = { ...definitionReference("mapping-version-a", mapping.mappingKey, "mapping_spec", mapping), mappingSpecId: mapping.mappingSpecId, mappingSpecRevision: mapping.revision, mappingSpecHash: mapping.mappingSpecHash, sourceContract: sourceReference, activation, window: { effectiveFrom: "2026-01-01" } };
  const control = createSnapshotCertificationDefinitionV1({
    contractVersion: 1, definitionKind: "snapshot_certification_control", tenantId: "tenant-a", certificationDefinitionId: scope.bindingId, revision: 1, sourceContract: sourceReference, sourceContractExecution: sourceExecution, scopeBinding: scope, scopeBindingExecution: scopeExecution, mappingExecution,
    runtime: { runtimeBundleId: "runtime-a", runtimeVersion: "1.0.0", runtimeBundleHash: hash("runtime"), dictionary, mappingCompiler: compiler },
    dataQuality: { definitionId: "dq-a", rulesetId: "dq-rules-a", mappingSectionId: "loans", requiredSectionIds: ["loans"], rules: [{ ruleId: "loan-required", type: "required", field: "loan_id", severity: "critical", blocking: true }], balanceField: "current_balance", materialBalance: "1", window: { effectiveFrom: "2026-01-01" } },
    certificationReconciliation: { definitionId: "recon-a", reconciliationId: "recon-a", requiredSectionIds: ["loans"], controls: [{ controlId: "pool-a", sectionId: "loans", recordSource: "normalized", dimensions: ["portfolio_id"], balanceField: "current_balance", currencyField: "currency", expected: [{ dimensions: { portfolio_id: "portfolio-a" }, rowCount: 1, balance: "100", currency: "USD" }], balanceTolerance: "0" }], window: { effectiveFrom: "2026-01-01" } }, window: { effectiveFrom: "2026-01-01" }, approval: { status: "pending_durable_approval", authority: "governed_definition_v2_lifecycle" }
  });
  const controlReference = definitionReference("control-version-a", control.certificationDefinitionId, "snapshot_certification_control", control);
  const snapshot = createDatasetSnapshotV2({ contractVersion: 2, tenantId: "tenant-a", snapshotId: "snapshot-a", sourceContract: sourceReference, delivery: source.delivery, sourceLocator: "upload://loans-a", asOfDate: "2026-01-31", knowledge: { sourceObservedAt: "2026-02-01T00:00:00.000Z", extractedAt: "2026-02-01T00:01:00.000Z", receivedAt: "2026-02-01T00:02:00.000Z", persistedAt: "2026-02-01T00:03:00.000Z" }, watermark: { mode: "none" }, hashes: { contentHash: hash("snapshot-content"), schemaHash: hash("snapshot-schema"), catalogHash: hash("snapshot-catalog"), parserHash: hash("snapshot-parser"), extractionHash: hash("receipt-a") }, rowCount: 1, byteCount: 100, sections: [{ sectionId: "loans", required: true, present: true, rowCount: 1, contentHash: hash("snapshot-section"), schemaHash: hash("snapshot-section-schema") }], correction: { kind: "original" }, createdBy: "capture-worker" });
  const application = createMappingApplicationV1({ contractVersion: 1, tenantId: "tenant-a", mappingApplicationId: "mapping-application-a", snapshot: { snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, contentHash: snapshot.hashes.contentHash }, mappingSpec: { mappingSpecId: mapping.mappingSpecId, revision: mapping.revision, mappingSpecHash: mapping.mappingSpecHash }, dictionaryBundle: dictionary, runtimeBundle: { runtimeBundleId: "runtime-a", runtimeBundleHash: hash("runtime"), runtimeVersion: "1.0.0" }, inputPopulationHash: hash("input"), outputPopulationHash: hash([{ loan_id: "loan-a" }]), inputRowCount: 1, outputRowCount: 1, rejectedRowCount: 0, appliedBy: "mapping-worker", appliedAt: "2026-02-01T00:04:00.000Z" });
  const normalized = createNormalizedSnapshotArtifactV2({ contractVersion: 2, kind: "normalized_snapshot", tenantId: "tenant-a", normalizedPopulationId: "population-a", snapshot: { snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash }, mappingApplication: { mappingApplicationId: application.mappingApplicationId, mappingApplicationHash: application.mappingApplicationHash }, records: [{ loan_id: "loan-a" }], createdAt: "2026-02-01T00:04:30.000Z" });
  const artifacts = new ArtifactStore(join(directory, "artifacts"), { activeKeyId: "key-a", keys: { "key-a": Buffer.alloc(32, 7) } });
  const stored = artifacts.putJson({ tenantId: "tenant-a", kind: "normalized_snapshot", mediaType: "application/json", value: normalized });
  const metadata = createCertifiedSnapshotArtifactMetadataV1({ artifact: normalized, loadedStoredArtifact: stored });
  const populationBody = { contractVersion: 1 as const, tenantId: "tenant-a", populationId: normalized.normalizedPopulationId, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, mappingApplicationId: application.mappingApplicationId, mappingApplicationHash: application.mappingApplicationHash, populationHash: normalized.populationHash, fieldSetHash: normalized.fieldSetHash, rowCount: normalized.rowCount, dataQuality: { runId: "dq-run-a", rulesetId: "dq-rules-a", rulesetHash: hash("dq-rules"), resultHash: hash("dq-result"), publicationDecision: "publish" as const, blockerCodes: [] as string[] }, reconciliation: { reconciliationId: "recon-a", definitionHash: hash("recon-definition"), resultHash: hash("recon-result"), passed: true as const, populationHash: normalized.populationHash }, certifiedBy: "certification-checker", certifiedAt: "2026-02-01T01:00:00.000Z" };
  const population = { ...populationBody, certificationHash: hash(populationBody) };
  const certificationBody = { contractVersion: 1 as const, tenantId: "tenant-a", certificationManifestId: "certification-a", evidenceFormat: "modern_snapshot_v2" as const, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, populationId: population.populationId, populationCertificationHash: population.certificationHash, mappingApplicationId: application.mappingApplicationId, mappingApplicationHash: application.mappingApplicationHash, normalizedArtifactId: metadata.artifactId, normalizedArtifactContentHash: metadata.contentHash as Sha256Hash, dataQualityResultHash: population.dataQuality.resultHash, reconciliationResultHash: population.reconciliation.resultHash, populationHash: population.populationHash, rowCount: population.rowCount, certifiedBy: population.certifiedBy, certifiedAt: population.certifiedAt };
  const v1Evidence = createCertifiedSnapshotEvidenceRecordV1({ contractVersion: 1, tenantId: "tenant-a", certification: { ...certificationBody, certificationManifestHash: hash(certificationBody) }, population, mappingSpec: mapping, mappingApplication: application, normalizedArtifact: metadata, dataQualityPopulation: { populationHash: population.populationHash, fieldSetHash: population.fieldSetHash, rowCount: population.rowCount }, recordedAt: certificationBody.certifiedAt });
  const evidence = createCertifiedSnapshotEvidenceRecordV2({
    contractVersion: 2, tenantId: "tenant-a", v1Evidence, certificationAttempt: createSnapshotCertificationAttemptV1({ contractVersion: 1, tenantId: "tenant-a", certificationManifestId: certificationBody.certificationManifestId, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, actorId: "certification-checker", requestHash: hash("request-a"), certifiedAt: certificationBody.certifiedAt, createdAt: certificationBody.certifiedAt }),
    governance: { control: { definition: control, reference: controlReference, approval: { status: "approved", proposedBy: "control-maker", approvedBy: "control-checker", approvedAt: "2026-01-01T00:01:00.000Z", approvalEventHash: controlReference.approvalEventHash }, activation: { status: "active", lifecycleRevision: 1, activatedBy: "control-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationEventHash: hash("control-activation") } }, sourceContract: { raw: sourceReference, execution: sourceExecution }, scopeBinding: { raw: scope, execution: scopeExecution }, mapping: { execution: mappingExecution, activation }, runtime: { runtimeBundleId: "runtime-a", runtimeVersion: "1.0.0", runtimeBundleHash: hash("runtime"), activation: { tenantId: "tenant-a", runtimeBundleId: "runtime-a", runtimeBundleHash: hash("runtime"), registeredBy: "runtime-maker", registeredAt: "2026-01-01T00:00:00.000Z", activatedBy: "runtime-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationHash: hash("runtime-activation") }, dictionary, mappingCompiler: compiler } }, recordedAt: certificationBody.certifiedAt
  });
  const lineage = createGovernedSnapshotCommitLineageV1({ contractVersion: 1, tenantId: "tenant-a", snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, datasetId: scope.datasetId, facilityId: "facility-a", sourceContract: sourceReference, scopeBinding: { bindingId: scope.bindingId, revision: scope.revision, bindingHash: scope.bindingHash }, sourceDelivery: { deliveryId: "delivery-a", deliveryRevision: 1, deliveryHash: hash("delivery"), locatorHash: hash("locator"), sourceVersionHash: hash("source-version") }, extractionReceipt: { receiptId: "receipt-a", receiptHash: snapshot.hashes.extractionHash }, asOfDate: snapshot.asOfDate });
  const definitions = definitionResolver([
    resolved(controlReference, control), resolved(sourceExecution, source), resolved(scopeExecution, scope), resolved(mappingExecution, options.substituteMapping ? { ...mapping, mappingKey: "substituted-mapping" } : mapping)
  ]);
  const catalog = new GovernedCertifiedSnapshotPublicationLinkCatalogV2(join(directory, "links.sqlite"), { clock: () => new Date("2026-02-01T01:01:00.000Z") });
  const service = new GovernedCertifiedSnapshotPublicationV2Service({ datasetSnapshots: new StaticRepository(snapshot), captureLineage: { async getGovernedCaptureLineage(tenantId, snapshotId) { return tenantId === "tenant-a" && snapshotId === snapshot.snapshotId ? lineage : undefined; } }, certifiedSnapshotEvidence: new StaticRepository(evidence), artifacts, definitions, publicationLinks: catalog, clock: () => new Date("2026-02-01T01:01:00.000Z") });
  return { evidence, service, catalog, close: () => { catalog.close(); } };
}

function definitionReference(definitionVersionId: string, definitionKey: string, kind: "source_contract" | "dataset_scope_binding" | "mapping_spec" | "snapshot_certification_control", document: unknown) {
  return { definitionVersionId, definitionKey, kind, semanticVersion: "1.0.0", versionHash: hash(`${definitionVersionId}-version`), documentHash: hash(document), approvalEventHash: hash(`${definitionVersionId}-approval`) };
}

function resolved(reference: ReturnType<typeof definitionReference>, executionDocument: unknown): ResolvedGovernedDefinitionV2 {
  return { reference, approvalEvidence: { status: "approved", proposedBy: "definition-maker", approvedBy: "definition-checker", approvedAt: "2026-01-01T00:01:00.000Z", approvalEventHash: reference.approvalEventHash }, executionDocument: executionDocument as never };
}

function definitionResolver(records: readonly ResolvedGovernedDefinitionV2[]) {
  const byId = new Map(records.map((record) => [record.reference.definitionVersionId, record]));
  return { resolveFrozen(input: { readonly tenantId: string; readonly definitionVersionId: string }) { if (input.tenantId !== "tenant-a" || !byId.has(input.definitionVersionId)) throw new GovernedDefinitionV2ResolverError("NOT_FOUND", "definition not found"); return byId.get(input.definitionVersionId)!; } };
}

class StaticRepository<T extends { readonly tenantId: string }> implements ImmutableRepositoryPort<T> {
  constructor(private readonly record: T) {}
  async put(_record: T, _context: RepositoryWriteContext): Promise<never> { throw new Error("test repository is read only"); }
  async get(tenantId: string, recordId: string): Promise<T | undefined> {
    const identity = "certificationAttempt" in this.record ? this.record.certificationAttempt.certificationManifestId : "snapshotId" in this.record ? this.record.snapshotId : "";
    return tenantId === this.record.tenantId && recordId === identity ? this.record : undefined;
  }
  async list(tenantId: string): Promise<RepositoryPage<T>> { return { items: tenantId === this.record.tenantId ? [this.record] : [], nextCursor: null }; }
}
