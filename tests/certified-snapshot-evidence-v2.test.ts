import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ContractValidationError,
  canonicalHash,
  createCertifiedSnapshotEvidenceRecordV1,
  createGovernedDatasetScopeBindingV1,
  createMappingApplicationV1,
  createMappingSpecV2,
  type CertifiedSnapshotEvidenceRecordV1,
  type Sha256Hash
} from "../src/contracts/index.js";
import {
  createCertifiedSnapshotEvidenceRecordV2,
  parseCertifiedSnapshotEvidenceRecordV2,
  type CertifiedSnapshotEvidenceRecordV2Input
} from "../src/contracts/certified-snapshot-evidence-v2.js";
import { createSnapshotCertificationAttemptV1 } from "../src/contracts/snapshot-certification-attempt-v1.js";
import { createSnapshotCertificationDefinitionV1 } from "../src/contracts/snapshot-certification-definition-v1.js";

const HASH = (value: unknown): Sha256Hash => canonicalHash(value);

test("V2 certification evidence retains validated V1 evidence and canonically binds durable control lineage", () => {
  const fixture = evidenceFixture();
  const created = createCertifiedSnapshotEvidenceRecordV2(fixture.input);

  assert.equal(created.contractVersion, 2);
  assert.equal(created.v1Evidence.evidenceHash, fixture.v1Evidence.evidenceHash);
  assert.equal(created.governance.control.definition.definitionHash, fixture.definition.definitionHash);
  assert.equal(created.governance.control.reference.documentHash, canonicalHash(fixture.definition));
  assert.ok(Object.isFrozen(created));
  assert.deepEqual(parseCertifiedSnapshotEvidenceRecordV2(created), created);
});

test("V2 certification evidence rejects hash tampering and control/source/scope substitution", () => {
  const fixture = evidenceFixture();
  const created = createCertifiedSnapshotEvidenceRecordV2(fixture.input);
  const hashTampered = structuredClone(created) as Record<string, unknown>;
  hashTampered.evidenceHash = HASH("forged-v2-evidence");
  assert.throws(
    () => parseCertifiedSnapshotEvidenceRecordV2(hashTampered),
    (error: unknown) => error instanceof ContractValidationError && error.code === "HASH_MISMATCH"
  );

  const forgedV1 = structuredClone(fixture.input) as CertifiedSnapshotEvidenceRecordV2Input;
  (forgedV1.v1Evidence as { evidenceHash: Sha256Hash }).evidenceHash = HASH("forged-v1-evidence");
  assert.throws(
    () => createCertifiedSnapshotEvidenceRecordV2(forgedV1),
    (error: unknown) => error instanceof ContractValidationError && error.code === "HASH_MISMATCH"
  );

  const forgedControl = structuredClone(fixture.input) as CertifiedSnapshotEvidenceRecordV2Input;
  (forgedControl.governance.control.reference as { documentHash: Sha256Hash }).documentHash = HASH("substituted-control-document");
  invalid(() => createCertifiedSnapshotEvidenceRecordV2(forgedControl));

  const forgedSource = structuredClone(fixture.input) as CertifiedSnapshotEvidenceRecordV2Input;
  (forgedSource.governance.sourceContract.raw as { sourceContractHash: Sha256Hash }).sourceContractHash = HASH("other-source");
  invalid(() => createCertifiedSnapshotEvidenceRecordV2(forgedSource));

  const forgedScope = structuredClone(fixture.input) as CertifiedSnapshotEvidenceRecordV2Input;
  (forgedScope.governance.scopeBinding.execution as { definitionVersionId: string }).definitionVersionId = "other-scope-version";
  invalid(() => createCertifiedSnapshotEvidenceRecordV2(forgedScope));
});

test("V2 certification evidence rejects mapping activation and runtime/dictionary substitution while retained V1 remains valid", () => {
  const fixture = evidenceFixture();
  const forgedMapping = structuredClone(fixture.input) as CertifiedSnapshotEvidenceRecordV2Input;
  (forgedMapping.governance.mapping.activation as { activatedAt: string }).activatedAt = "2026-01-03T00:00:00.000Z";
  invalid(() => createCertifiedSnapshotEvidenceRecordV2(forgedMapping));

  const forgedRuntime = structuredClone(fixture.input) as CertifiedSnapshotEvidenceRecordV2Input;
  (forgedRuntime.governance.runtime.dictionary as { bundleId: string }).bundleId = "dictionary-substitute";
  invalid(() => createCertifiedSnapshotEvidenceRecordV2(forgedRuntime));
});

function evidenceFixture(): {
  readonly input: CertifiedSnapshotEvidenceRecordV2Input;
  readonly definition: ReturnType<typeof createSnapshotCertificationDefinitionV1>;
  readonly v1Evidence: CertifiedSnapshotEvidenceRecordV1;
} {
  const sourceContract = {
    sourceContractId: "loan-source",
    revision: 1,
    sourceContractHash: HASH("loan-source")
  };
  const scopeBinding = createGovernedDatasetScopeBindingV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    bindingId: "facility-a-binding",
    revision: 1,
    datasetId: "loan-dataset",
    sourceContract,
    scope: { scopeType: "facility", scopeId: "facility-a" },
    effectiveFrom: "2026-01-01"
  });
  const dictionary = {
    contractVersion: 1 as const,
    bundleKind: "dictionary" as const,
    bundleId: "dictionary-a",
    version: "1.0.0",
    contentHash: HASH("dictionary-content"),
    artifactId: "dictionary-artifact",
    mediaType: "application/json",
    createdAt: "2026-01-01T00:00:00.000Z",
    dictionaryVersion: "1.0.0",
    dictionaryHash: HASH("dictionary"),
    fieldPolicyVersion: "1.0.0",
    fieldPolicyHash: HASH("field-policy")
  };
  const compiler = {
    contractVersion: 1 as const,
    bundleKind: "mapping_compiler" as const,
    bundleId: "compiler-a",
    version: "1.0.0",
    contentHash: HASH("compiler-content"),
    artifactId: "compiler-artifact",
    mediaType: "application/json",
    createdAt: "2026-01-01T00:00:00.000Z"
  };
  const mappingSpec = createMappingSpecV2({
    contractVersion: 2,
    tenantId: "tenant-a",
    mappingSpecId: "mapping-spec-a",
    mappingKey: "loan-tape",
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
    definitionVersionId: "mapping-version-a",
    definitionKey: "loan-tape",
    kind: "mapping_spec" as const,
    semanticVersion: "1.0.0",
    versionHash: HASH("mapping-version"),
    documentHash: HASH("mapping-document"),
    approvalEventHash: HASH("mapping-approval"),
    mappingSpecId: mappingSpec.mappingSpecId,
    mappingSpecRevision: mappingSpec.revision,
    mappingSpecHash: mappingSpec.mappingSpecHash,
    sourceContract,
    activation: {
      status: "active" as const,
      lifecycleRevision: 3,
      activatedBy: "mapping-checker",
      activatedAt: "2026-01-02T00:00:00.000Z",
      activationEventHash: HASH("mapping-activation")
    },
    window: { effectiveFrom: "2026-01-01" }
  };
  const sourceExecution = {
    definitionVersionId: "source-version-a",
    definitionKey: "loan-source-key",
    kind: "source_contract" as const,
    semanticVersion: "1.0.0",
    versionHash: HASH("source-version"),
    documentHash: HASH("source-document"),
    approvalEventHash: HASH("source-approval"),
    sourceContract
  };
  const scopeExecution = {
    definitionVersionId: "scope-version-a",
    definitionKey: scopeBinding.bindingId,
    kind: "dataset_scope_binding" as const,
    semanticVersion: "1.0.0",
    versionHash: HASH("scope-version"),
    documentHash: HASH("scope-document"),
    approvalEventHash: HASH("scope-approval"),
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
    runtime: { runtimeBundleId: "runtime-a", runtimeVersion: "1.0.0", runtimeBundleHash: HASH("runtime"), dictionary, mappingCompiler: compiler },
    dataQuality: {
      definitionId: "dq-a", rulesetId: "dq-rules-a", mappingSectionId: "loans", requiredSectionIds: ["loans"],
      rules: [{ ruleId: "loan-required", type: "required", field: "loan_id", severity: "critical", blocking: true }],
      balanceField: "current_balance", materialBalance: "1", window: { effectiveFrom: "2026-01-01" }
    },
    certificationReconciliation: {
      definitionId: "recon-a", reconciliationId: "recon-a", requiredSectionIds: ["loans"],
      controls: [{ controlId: "pool-balance", sectionId: "loans", recordSource: "normalized", dimensions: ["portfolio_id"], balanceField: "current_balance", currencyField: "currency", expected: [{ dimensions: { portfolio_id: "portfolio-a" }, rowCount: 1, balance: "100", currency: "USD" }], balanceTolerance: "0" }],
      window: { effectiveFrom: "2026-01-01" }
    },
    window: { effectiveFrom: "2026-01-01" },
    approval: { status: "pending_durable_approval", authority: "governed_definition_v2_lifecycle" }
  });
  const snapshot = { snapshotId: "snapshot-a", snapshotHash: HASH("snapshot"), contentHash: HASH("snapshot-content") };
  const mappingApplication = createMappingApplicationV1({
    contractVersion: 1, tenantId: "tenant-a", mappingApplicationId: "application-a", snapshot,
    mappingSpec: { mappingSpecId: mappingSpec.mappingSpecId, revision: mappingSpec.revision, mappingSpecHash: mappingSpec.mappingSpecHash },
    dictionaryBundle: dictionary, runtimeBundle: { runtimeBundleId: "runtime-a", runtimeBundleHash: HASH("runtime"), runtimeVersion: "1.0.0" },
    inputPopulationHash: HASH("input-population"), outputPopulationHash: HASH("output-population"), inputRowCount: 1, outputRowCount: 1, rejectedRowCount: 0,
    appliedBy: "mapping-worker", appliedAt: "2026-01-02T00:01:00.000Z"
  });
  const populationBody = {
    contractVersion: 1 as const, tenantId: "tenant-a", populationId: "population-a", snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash,
    mappingApplicationId: mappingApplication.mappingApplicationId, mappingApplicationHash: mappingApplication.mappingApplicationHash,
    populationHash: mappingApplication.outputPopulationHash, fieldSetHash: HASH("field-set"), rowCount: 1,
    dataQuality: { runId: "dq-run-a", rulesetId: "dq-rules-a", rulesetHash: HASH("dq-rules"), resultHash: HASH("dq-result"), publicationDecision: "publish" as const, blockerCodes: [] as string[] },
    reconciliation: { reconciliationId: "recon-a", definitionHash: HASH("recon-definition"), resultHash: HASH("recon-result"), passed: true as const, populationHash: mappingApplication.outputPopulationHash },
    certifiedBy: "certification-checker", certifiedAt: "2026-01-02T01:00:00.000Z"
  };
  const population = { ...populationBody, certificationHash: HASH(populationBody) };
  const certificationBody = {
    contractVersion: 1 as const, tenantId: "tenant-a", certificationManifestId: "manifest-a", evidenceFormat: "modern_snapshot_v2" as const,
    snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, populationId: population.populationId, populationCertificationHash: population.certificationHash,
    mappingApplicationId: mappingApplication.mappingApplicationId, mappingApplicationHash: mappingApplication.mappingApplicationHash,
    normalizedArtifactId: "artifact-a", normalizedArtifactContentHash: HASH("artifact-content"), dataQualityResultHash: population.dataQuality.resultHash,
    reconciliationResultHash: population.reconciliation.resultHash, populationHash: population.populationHash, rowCount: population.rowCount,
    certifiedBy: population.certifiedBy, certifiedAt: population.certifiedAt
  };
  const v1Evidence = createCertifiedSnapshotEvidenceRecordV1({
    contractVersion: 1, tenantId: "tenant-a", certification: { ...certificationBody, certificationManifestHash: HASH(certificationBody) }, population,
    mappingSpec, mappingApplication,
    normalizedArtifact: { tenantId: "tenant-a", artifactId: "artifact-a", kind: "normalized_snapshot", mediaType: "application/json", artifactContractVersion: 2, artifactHash: HASH("artifact"), contentHash: certificationBody.normalizedArtifactContentHash, byteLength: 100, keyId: "key-a", uri: `abl-artifact://${"a".repeat(64)}`, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, normalizedPopulationId: population.populationId, mappingApplicationId: mappingApplication.mappingApplicationId, mappingApplicationHash: mappingApplication.mappingApplicationHash, populationHash: population.populationHash, fieldSetHash: population.fieldSetHash, rowCount: 1, createdAt: "2026-01-02T00:30:00.000Z" },
    dataQualityPopulation: { populationHash: population.populationHash, fieldSetHash: population.fieldSetHash, rowCount: 1 }, recordedAt: "2026-01-02T01:00:00.000Z"
  });
  const controlReference = { definitionVersionId: "control-version-a", definitionKey: definition.certificationDefinitionId, kind: "snapshot_certification_control" as const, semanticVersion: "1.0.0", versionHash: HASH("control-version"), documentHash: HASH(definition), approvalEventHash: HASH("control-approval") };
  const input = {
    contractVersion: 2 as const, tenantId: "tenant-a", v1Evidence,
    certificationAttempt: createSnapshotCertificationAttemptV1({ contractVersion: 1, tenantId: "tenant-a", certificationManifestId: certificationBody.certificationManifestId, snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, actorId: "certification-checker", requestHash: HASH("certification-request"), certifiedAt: certificationBody.certifiedAt, createdAt: "2026-01-02T01:00:00.000Z" }),
    governance: {
      control: { definition, reference: controlReference, approval: { status: "approved" as const, proposedBy: "control-maker", approvedBy: "control-checker", approvedAt: "2026-01-01T00:01:00.000Z", approvalEventHash: controlReference.approvalEventHash }, activation: { status: "active" as const, lifecycleRevision: 3, activatedBy: "control-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationEventHash: HASH("control-activation") } },
      sourceContract: { raw: sourceContract, execution: sourceExecution }, scopeBinding: { raw: scopeBinding, execution: scopeExecution }, mapping: { execution: mappingExecution, activation: mappingExecution.activation },
      runtime: { runtimeBundleId: "runtime-a", runtimeVersion: "1.0.0", runtimeBundleHash: HASH("runtime"), activation: { tenantId: "tenant-a", runtimeBundleId: "runtime-a", runtimeBundleHash: HASH("runtime"), registeredBy: "runtime-maker", registeredAt: "2026-01-01T00:00:00.000Z", activatedBy: "runtime-checker", activatedAt: "2026-01-02T00:00:00.000Z", activationHash: HASH("runtime-activation") }, dictionary, mappingCompiler: compiler }
    },
    recordedAt: "2026-01-02T01:00:00.000Z"
  } satisfies CertifiedSnapshotEvidenceRecordV2Input;
  return { input, definition, v1Evidence };
}

function invalid(action: () => unknown): void {
  assert.throws(action, (error: unknown) => error instanceof ContractValidationError && error.code === "INVALID_CONTRACT");
}
