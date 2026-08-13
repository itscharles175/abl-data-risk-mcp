import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ContractValidationError,
  canonicalHash,
  createCertifiedSnapshotEvidenceRecordV1,
  createCertifiedSnapshotPublicationV1,
  createGovernedDatasetScopeBindingV1,
  createMappingApplicationV1,
  createMappingSpecV2,
  type CertifiedSnapshotPublicationV1,
  type Sha256Hash
} from "../src/contracts/index.js";
import {
  createCertifiedSnapshotEvidenceRecordV2,
  type CertifiedSnapshotEvidenceRecordV2,
  type CertifiedSnapshotEvidenceRecordV2Input
} from "../src/contracts/certified-snapshot-evidence-v2.js";
import {
  createGovernedCertifiedSnapshotPublicationLinkV2,
  parseGovernedCertifiedSnapshotPublicationLinkV2
} from "../src/contracts/governed-certified-snapshot-publication-link-v2.js";
import { createSnapshotCertificationAttemptV1 } from "../src/contracts/snapshot-certification-attempt-v1.js";
import { createSnapshotCertificationDefinitionV1 } from "../src/contracts/snapshot-certification-definition-v1.js";

const HASH = (value: unknown): Sha256Hash => canonicalHash(value);

test("governed publication link canonically binds V1 publication, V2 evidence, V1 evidence, and governed execution references", () => {
  const { publication, evidence } = fixture();
  const link = createGovernedCertifiedSnapshotPublicationLinkV2({
    linkId: "publication-link-a",
    publication,
    evidenceId: evidence.certificationAttempt.certificationManifestId,
    evidence,
    linkedAt: "2026-01-02T01:01:00.000Z"
  });

  assert.equal(link.contractVersion, 2);
  assert.equal(link.publication.publicationHash, publication.publicationHash);
  assert.equal(link.evidence.evidenceHash, evidence.evidenceHash);
  assert.equal(link.evidence.v1EvidenceHash, evidence.v1Evidence.evidenceHash);
  assert.equal(link.governance.certificationAttempt.attemptHash, evidence.certificationAttempt.attemptHash);
  assert.equal(link.governance.control.definitionVersionId, evidence.governance.control.reference.definitionVersionId);
  assert.equal(link.governance.scopeBinding.bindingHash, evidence.governance.scopeBinding.raw.bindingHash);
  assert.equal(link.governance.mapping.mappingSpecHash, evidence.governance.mapping.execution.mappingSpecHash);
  assert.equal(link.governance.runtime.runtimeBundleHash, evidence.governance.runtime.runtimeBundleHash);
  assert.ok(Object.isFrozen(link));
  assert.deepEqual(parseGovernedCertifiedSnapshotPublicationLinkV2(link), link);
});

test("governed publication link rejects link/governance hash tampering and recanonicalized cross-lineage substitution", () => {
  const { publication, evidence } = fixture();
  const link = createGovernedCertifiedSnapshotPublicationLinkV2({
    linkId: "publication-link-a",
    publication,
    evidenceId: evidence.certificationAttempt.certificationManifestId,
    evidence,
    linkedAt: "2026-01-02T01:01:00.000Z"
  });

  const forgedHash = structuredClone(link) as Record<string, unknown>;
  forgedHash.linkHash = HASH("forged-link");
  invalid(() => parseGovernedCertifiedSnapshotPublicationLinkV2(forgedHash));

  const forgedGovernance = structuredClone(link) as typeof link;
  const { governanceHash: _oldGovernanceHash, ...governanceBody } = forgedGovernance.governance;
  const altered = {
    ...governanceBody,
    runtime: { ...forgedGovernance.governance.runtime, runtimeBundleId: "runtime-substitute" }
  };
  const body = {
    ...forgedGovernance,
    governance: { ...altered, governanceHash: canonicalHash(altered) }
  };
  const { linkHash: _ignored, ...bodyWithoutHash } = body;
  const recanonicalized = { ...body, linkHash: canonicalHash(bodyWithoutHash) };
  invalid(() => parseGovernedCertifiedSnapshotPublicationLinkV2(recanonicalized));

  const forgedScope = structuredClone(link) as typeof link;
  const governanceWithScope = {
    ...forgedScope.governance,
    scopeBinding: { ...forgedScope.governance.scopeBinding, bindingId: "other-binding" }
  };
  const withScope = { ...forgedScope, governance: { ...governanceWithScope, governanceHash: canonicalHash(governanceWithScope) } };
  const { linkHash: _ignoredScope, ...scopeBody } = withScope;
  invalid(() => parseGovernedCertifiedSnapshotPublicationLinkV2({ ...withScope, linkHash: canonicalHash(scopeBody) }));
});

test("governed publication link fails construction for a non-record V2 ID or a separately valid publication with different lineage", () => {
  const { publication, evidence } = fixture();
  assert.throws(
    () => createGovernedCertifiedSnapshotPublicationLinkV2({
      linkId: "publication-link-a",
      publication,
      evidenceId: "other-record",
      evidence,
      linkedAt: "2026-01-02T01:01:00.000Z"
    }),
    (error: unknown) => error instanceof ContractValidationError && error.code === "INVARIANT_VIOLATION"
  );

  const { publicationHash: _oldPublicationHash, ...publicationBody } = publication;
  const { certificationManifestHash: _oldManifestHash, ...manifestBody } = publication.certification;
  const certification = {
    ...manifestBody,
    certificationManifestId: "other-manifest",
    certificationManifestHash: canonicalHash({ ...manifestBody, certificationManifestId: "other-manifest" })
  };
  const differentPublication = createCertifiedSnapshotPublicationV1({ ...publicationBody, publicationId: "publication-other", certification });
  assert.throws(
    () => createGovernedCertifiedSnapshotPublicationLinkV2({
      linkId: "publication-link-a",
      publication: differentPublication,
      evidenceId: evidence.certificationAttempt.certificationManifestId,
      evidence,
      linkedAt: "2026-01-02T01:01:00.000Z"
    }),
    (error: unknown) => error instanceof ContractValidationError
  );
});

function fixture(): { readonly publication: CertifiedSnapshotPublicationV1; readonly evidence: CertifiedSnapshotEvidenceRecordV2 } {
  const sourceContract = { sourceContractId: "loan-source", revision: 1, sourceContractHash: HASH("loan-source") };
  const scopeBinding = createGovernedDatasetScopeBindingV1({
    contractVersion: 1, tenantId: "tenant-a", bindingId: "facility-a-binding", revision: 1, datasetId: "loan-dataset", sourceContract,
    scope: { scopeType: "facility", scopeId: "facility-a" }, effectiveFrom: "2026-01-01"
  });
  const dictionary = {
    contractVersion: 1 as const, bundleKind: "dictionary" as const, bundleId: "dictionary-a", version: "1.0.0", contentHash: HASH("dictionary-content"),
    artifactId: "dictionary-artifact", mediaType: "application/json", createdAt: "2026-01-01T00:00:00.000Z", dictionaryVersion: "1.0.0",
    dictionaryHash: HASH("dictionary"), fieldPolicyVersion: "1.0.0", fieldPolicyHash: HASH("field-policy")
  };
  const compiler = {
    contractVersion: 1 as const, bundleKind: "mapping_compiler" as const, bundleId: "compiler-a", version: "1.0.0", contentHash: HASH("compiler-content"),
    artifactId: "compiler-artifact", mediaType: "application/json", createdAt: "2026-01-01T00:00:00.000Z"
  };
  const mappingSpec = createMappingSpecV2({
    contractVersion: 2, tenantId: "tenant-a", mappingSpecId: "mapping-spec-a", mappingKey: "loan-tape", revision: 1, status: "active", sourceContract, dictionaryBundle: dictionary,
    rules: [{ ruleId: "loan-id", canonicalField: "loan_id", expression: { op: "source", column: "loan_id" }, onError: "fail_application" }], requiredCanonicalFields: ["loan_id"],
    createdBy: "mapping-maker", createdAt: "2026-01-01T00:00:00.000Z", approvedBy: "mapping-checker", approvedAt: "2026-01-01T00:01:00.000Z"
  });
  const activation = { status: "active" as const, lifecycleRevision: 3, activatedBy: "mapping-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationEventHash: HASH("mapping-activation") };
  const mappingExecution = {
    definitionVersionId: "mapping-version-a", definitionKey: "loan-tape", kind: "mapping_spec" as const, semanticVersion: "1.0.0", versionHash: HASH("mapping-version"), documentHash: HASH("mapping-document"), approvalEventHash: HASH("mapping-approval"),
    mappingSpecId: mappingSpec.mappingSpecId, mappingSpecRevision: mappingSpec.revision, mappingSpecHash: mappingSpec.mappingSpecHash, sourceContract, activation, window: { effectiveFrom: "2026-01-01" }
  };
  const sourceExecution = { definitionVersionId: "source-version-a", definitionKey: "loan-source-key", kind: "source_contract" as const, semanticVersion: "1.0.0", versionHash: HASH("source-version"), documentHash: HASH("source-document"), approvalEventHash: HASH("source-approval"), sourceContract };
  const scopeExecution = {
    definitionVersionId: "scope-version-a", definitionKey: scopeBinding.bindingId, kind: "dataset_scope_binding" as const, semanticVersion: "1.0.0", versionHash: HASH("scope-version"), documentHash: HASH("scope-document"), approvalEventHash: HASH("scope-approval"),
    bindingId: scopeBinding.bindingId, revision: scopeBinding.revision, bindingHash: scopeBinding.bindingHash, sourceContract
  };
  const definition = createSnapshotCertificationDefinitionV1({
    contractVersion: 1, definitionKind: "snapshot_certification_control", tenantId: "tenant-a", certificationDefinitionId: scopeBinding.bindingId, revision: 1, sourceContract,
    sourceContractExecution: sourceExecution, scopeBinding, scopeBindingExecution: scopeExecution, mappingExecution,
    runtime: { runtimeBundleId: "runtime-a", runtimeVersion: "1.0.0", runtimeBundleHash: HASH("runtime"), dictionary, mappingCompiler: compiler },
    dataQuality: { definitionId: "dq-a", rulesetId: "dq-rules-a", mappingSectionId: "loans", requiredSectionIds: ["loans"], rules: [{ ruleId: "loan-required", type: "required", field: "loan_id", severity: "critical", blocking: true }], balanceField: "current_balance", materialBalance: "1", window: { effectiveFrom: "2026-01-01" } },
    certificationReconciliation: { definitionId: "recon-a", reconciliationId: "recon-a", requiredSectionIds: ["loans"], controls: [{ controlId: "pool-balance", sectionId: "loans", recordSource: "normalized", dimensions: ["portfolio_id"], balanceField: "current_balance", currencyField: "currency", expected: [{ dimensions: { portfolio_id: "portfolio-a" }, rowCount: 1, balance: "100", currency: "USD" }], balanceTolerance: "0" }], window: { effectiveFrom: "2026-01-01" } },
    window: { effectiveFrom: "2026-01-01" }, approval: { status: "pending_durable_approval", authority: "governed_definition_v2_lifecycle" }
  });
  const snapshot = { snapshotId: "snapshot-a", snapshotHash: HASH("snapshot"), contentHash: HASH("snapshot-content") };
  const mappingApplication = createMappingApplicationV1({
    contractVersion: 1, tenantId: "tenant-a", mappingApplicationId: "application-a", snapshot,
    mappingSpec: { mappingSpecId: mappingSpec.mappingSpecId, revision: mappingSpec.revision, mappingSpecHash: mappingSpec.mappingSpecHash }, dictionaryBundle: dictionary,
    runtimeBundle: { runtimeBundleId: "runtime-a", runtimeBundleHash: HASH("runtime"), runtimeVersion: "1.0.0" }, inputPopulationHash: HASH("input-population"), outputPopulationHash: HASH("output-population"), inputRowCount: 1, outputRowCount: 1, rejectedRowCount: 0, appliedBy: "mapping-worker", appliedAt: "2026-01-02T00:01:00.000Z"
  });
  const populationBody = {
    contractVersion: 1 as const, tenantId: "tenant-a", populationId: "population-a", snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, mappingApplicationId: mappingApplication.mappingApplicationId, mappingApplicationHash: mappingApplication.mappingApplicationHash,
    populationHash: mappingApplication.outputPopulationHash, fieldSetHash: HASH("field-set"), rowCount: 1, dataQuality: { runId: "dq-run-a", rulesetId: "dq-rules-a", rulesetHash: HASH("dq-rules"), resultHash: HASH("dq-result"), publicationDecision: "publish" as const, blockerCodes: [] as string[] },
    reconciliation: { reconciliationId: "recon-a", definitionHash: HASH("recon-definition"), resultHash: HASH("recon-result"), passed: true as const, populationHash: mappingApplication.outputPopulationHash }, certifiedBy: "certification-checker", certifiedAt: "2026-01-02T01:00:00.000Z"
  };
  const population = { ...populationBody, certificationHash: HASH(populationBody) };
  const certificationBody = {
    contractVersion: 1 as const, tenantId: "tenant-a", certificationManifestId: "manifest-a", evidenceFormat: "modern_snapshot_v2" as const, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, populationId: population.populationId, populationCertificationHash: population.certificationHash,
    mappingApplicationId: mappingApplication.mappingApplicationId, mappingApplicationHash: mappingApplication.mappingApplicationHash, normalizedArtifactId: "artifact-a", normalizedArtifactContentHash: HASH("artifact-content"), dataQualityResultHash: population.dataQuality.resultHash, reconciliationResultHash: population.reconciliation.resultHash, populationHash: population.populationHash, rowCount: population.rowCount, certifiedBy: population.certifiedBy, certifiedAt: population.certifiedAt
  };
  const v1Evidence = createCertifiedSnapshotEvidenceRecordV1({
    contractVersion: 1, tenantId: "tenant-a", certification: { ...certificationBody, certificationManifestHash: HASH(certificationBody) }, population, mappingSpec, mappingApplication,
    normalizedArtifact: { tenantId: "tenant-a", artifactId: "artifact-a", kind: "normalized_snapshot", mediaType: "application/json", artifactContractVersion: 2, artifactHash: HASH("artifact"), contentHash: certificationBody.normalizedArtifactContentHash, byteLength: 100, keyId: "key-a", uri: `abl-artifact://${"a".repeat(64)}`, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, normalizedPopulationId: population.populationId, mappingApplicationId: mappingApplication.mappingApplicationId, mappingApplicationHash: mappingApplication.mappingApplicationHash, populationHash: population.populationHash, fieldSetHash: population.fieldSetHash, rowCount: 1, createdAt: "2026-01-02T00:30:00.000Z" },
    dataQualityPopulation: { populationHash: population.populationHash, fieldSetHash: population.fieldSetHash, rowCount: 1 }, recordedAt: "2026-01-02T01:00:00.000Z"
  });
  const controlReference = { definitionVersionId: "control-version-a", definitionKey: definition.certificationDefinitionId, kind: "snapshot_certification_control" as const, semanticVersion: "1.0.0", versionHash: HASH("control-version"), documentHash: HASH(definition), approvalEventHash: HASH("control-approval") };
  const input = {
    contractVersion: 2 as const, tenantId: "tenant-a", v1Evidence,
    certificationAttempt: createSnapshotCertificationAttemptV1({ contractVersion: 1, tenantId: "tenant-a", certificationManifestId: certificationBody.certificationManifestId, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, actorId: "certification-checker", requestHash: HASH("certification-request"), certifiedAt: certificationBody.certifiedAt, createdAt: "2026-01-02T01:00:00.000Z" }),
    governance: {
      control: { definition, reference: controlReference, approval: { status: "approved" as const, proposedBy: "control-maker", approvedBy: "control-checker", approvedAt: "2026-01-01T00:01:00.000Z", approvalEventHash: controlReference.approvalEventHash }, activation: { status: "active" as const, lifecycleRevision: 3, activatedBy: "control-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationEventHash: HASH("control-activation") } },
      sourceContract: { raw: sourceContract, execution: sourceExecution }, scopeBinding: { raw: scopeBinding, execution: scopeExecution }, mapping: { execution: mappingExecution, activation },
      runtime: { runtimeBundleId: "runtime-a", runtimeVersion: "1.0.0", runtimeBundleHash: HASH("runtime"), activation: { tenantId: "tenant-a", runtimeBundleId: "runtime-a", runtimeBundleHash: HASH("runtime"), registeredBy: "runtime-maker", registeredAt: "2026-01-01T00:00:00.000Z", activatedBy: "runtime-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationHash: HASH("runtime-activation") }, dictionary, mappingCompiler: compiler }
    }, recordedAt: "2026-01-02T01:00:00.000Z"
  } satisfies CertifiedSnapshotEvidenceRecordV2Input;
  const evidence = createCertifiedSnapshotEvidenceRecordV2(input);
  const datasetBindingBody = { contractVersion: 1 as const, bindingId: scopeBinding.bindingId, tenantId: "tenant-a", datasetId: scopeBinding.datasetId, sourceContract, scope: scopeBinding.scope, boundAt: "2026-01-01T00:00:00.000Z" };
  const publication = createCertifiedSnapshotPublicationV1({
    contractVersion: 1, publicationId: "publication-a", tenantId: "tenant-a", datasetId: scopeBinding.datasetId, scope: scopeBinding.scope,
    datasetBinding: { ...datasetBindingBody, bindingHash: HASH(datasetBindingBody) },
    sourceContract: { definition: { definitionVersionId: sourceExecution.definitionVersionId, definitionKey: sourceExecution.definitionKey, kind: "source_contract", semanticVersion: sourceExecution.semanticVersion, versionHash: sourceExecution.versionHash, documentHash: sourceExecution.documentHash, approvalEventHash: sourceExecution.approvalEventHash }, sourceContractId: sourceContract.sourceContractId, sourceKey: sourceExecution.definitionKey, revision: sourceContract.revision, sourceContractHash: sourceContract.sourceContractHash },
    snapshot: { snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, sourceContract, delivery: { mode: "postgresql_pull", deliveredContentHash: snapshot.contentHash }, asOfDate: "2026-01-02", knowledge: { sourceObservedAt: "2026-01-02T00:00:00.000Z", extractedAt: "2026-01-02T00:00:01.000Z", receivedAt: "2026-01-02T00:00:02.000Z", persistedAt: "2026-01-02T00:00:03.000Z" }, hashes: { contentHash: snapshot.contentHash, schemaHash: HASH("schema"), catalogHash: HASH("catalog"), parserHash: HASH("parser"), extractionHash: HASH("extraction") }, rowCount: 1, byteCount: 100, correction: { kind: "original" } },
    certification: v1Evidence.certification, population: v1Evidence.population,
    mappingSpec: { mappingSpecId: mappingSpec.mappingSpecId, mappingKey: mappingSpec.mappingKey, revision: mappingSpec.revision, mappingSpecHash: mappingSpec.mappingSpecHash, sourceContract, dictionaryBundle: dictionary }, mappingApplication,
    normalizedArtifact: { artifactId: v1Evidence.normalizedArtifact.artifactId, artifactContractVersion: 2, artifactHash: v1Evidence.normalizedArtifact.artifactHash, kind: "normalized_snapshot", mediaType: "application/json", contentHash: v1Evidence.normalizedArtifact.contentHash, byteLength: v1Evidence.normalizedArtifact.byteLength, uri: "artifact://tenant-a/normalized", metadataHash: HASH("metadata"), rowCount: 1, populationHash: population.populationHash, fieldSetHash: population.fieldSetHash },
    publishedBy: "publication-worker", publishedAt: "2026-01-02T01:01:00.000Z"
  });
  return { publication, evidence };
}

function invalid(action: () => unknown): void {
  assert.throws(action, (error: unknown) => error instanceof ContractValidationError && ["HASH_MISMATCH", "INVALID_CONTRACT"].includes(error.code));
}
