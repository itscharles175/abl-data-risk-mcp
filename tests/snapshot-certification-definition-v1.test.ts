import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ContractValidationError,
  canonicalHash,
  createGovernedDatasetScopeBindingV1
} from "../src/contracts/index.js";
import {
  createSnapshotCertificationDefinitionV1,
  parseSnapshotCertificationDefinitionV1,
  type SnapshotCertificationDefinitionV1Input
} from "../src/contracts/snapshot-certification-definition-v1.js";

test("snapshot certification control definition is canonical, immutable, and hash-bound", () => {
  const created = createSnapshotCertificationDefinitionV1(definitionInput());
  assert.equal(created.definitionKind, "snapshot_certification_control");
  assert.equal(created.approval.status, "pending_durable_approval");
  assert.equal(created.scopeBinding.scope.scopeId, "facility-a");
  assert.ok(Object.isFrozen(created));
  assert.deepEqual(parseSnapshotCertificationDefinitionV1(created), created);

  const substituted = structuredClone(created) as Record<string, unknown>;
  substituted.definitionHash = canonicalHash("substituted");
  assert.throws(
    () => parseSnapshotCertificationDefinitionV1(substituted),
    (error: unknown) => error instanceof ContractValidationError && error.code === "HASH_MISMATCH"
  );
});

test("snapshot certification control definition binds source, facility scope, mapping execution, and runtime exactly", () => {
  const aliasedControl = definitionInput();
  aliasedControl.certificationDefinitionId = "another-certification-control";
  invalid(() => createSnapshotCertificationDefinitionV1(aliasedControl));

  const substitutedSourceExecution = definitionInput();
  substitutedSourceExecution.sourceContractExecution.sourceContract.sourceContractHash = canonicalHash("other-source");
  invalid(() => createSnapshotCertificationDefinitionV1(substitutedSourceExecution));

  const substitutedScopeExecution = definitionInput();
  substitutedScopeExecution.scopeBindingExecution.definitionKey = "another-binding";
  invalid(() => createSnapshotCertificationDefinitionV1(substitutedScopeExecution));

  const badSource = definitionInput();
  badSource.mappingExecution.sourceContract.sourceContractHash = canonicalHash("other-source");
  invalid(() => createSnapshotCertificationDefinitionV1(badSource));

  const portfolioScope = definitionInput();
  const { bindingHash: _bindingHash, ...scopeBindingBody } = portfolioScope.scopeBinding;
  portfolioScope.scopeBinding = createGovernedDatasetScopeBindingV1({
    ...scopeBindingBody,
    scope: { scopeType: "portfolio", scopeId: "portfolio-a" }
  });
  invalid(() => createSnapshotCertificationDefinitionV1(portfolioScope));

  const badRuntime = definitionInput();
  badRuntime.runtime.mappingCompiler.createdAt = "2026-01-03T00:00:00.000Z";
  invalid(() => createSnapshotCertificationDefinitionV1(badRuntime));

  const mismatchedWindow = definitionInput();
  mismatchedWindow.dataQuality.window.effectiveFrom = "2026-02-01";
  invalid(() => createSnapshotCertificationDefinitionV1(mismatchedWindow));
});

test("snapshot certification control definition rejects ambiguous or internally non-executable DQ and reconciliation controls", () => {
  const duplicateRequired = definitionInput();
  duplicateRequired.dataQuality.requiredSectionIds.push("loans");
  invalid(() => createSnapshotCertificationDefinitionV1(duplicateRequired));

  const unboundedDecimal = definitionInput();
  unboundedDecimal.dataQuality.rules[1] = {
    ruleId: "balance-range",
    type: "decimal_range",
    field: "current_balance",
    severity: "critical",
    blocking: true
  };
  invalid(() => createSnapshotCertificationDefinitionV1(unboundedDecimal));

  const duplicateExpectedGroup = definitionInput();
  duplicateExpectedGroup.certificationReconciliation.controls[0]!.expected.push({
    dimensions: { portfolio_id: "portfolio-a" },
    rowCount: 1,
    balance: "100",
    currency: "USD"
  });
  invalid(() => createSnapshotCertificationDefinitionV1(duplicateExpectedGroup));

  const nonneutral = definitionInput() as unknown as { approval: { status: string; authority: string } };
  nonneutral.approval.status = "approved";
  invalid(() => createSnapshotCertificationDefinitionV1(nonneutral as SnapshotCertificationDefinitionV1Input));
});

function definitionInput(): SnapshotCertificationDefinitionV1Input & {
  mappingExecution: { sourceContract: { sourceContractHash: `sha256:${string}` }; activation: { activatedAt: string }; window: { effectiveFrom: string; effectiveTo?: string } };
  sourceContractExecution: { sourceContract: { sourceContractHash: `sha256:${string}` } };
  scopeBindingExecution: { definitionKey: string };
  scopeBinding: ReturnType<typeof createGovernedDatasetScopeBindingV1>;
  runtime: { mappingCompiler: { createdAt: string } };
  dataQuality: { requiredSectionIds: string[]; rules: Array<Record<string, unknown>>; window: { effectiveFrom: string; effectiveTo?: string } };
  certificationReconciliation: { controls: Array<{ expected: Array<{ dimensions: Record<string, string>; rowCount: number; balance: string; currency: string }> }> };
} {
  const sourceContract = {
    sourceContractId: "loan-source",
    revision: 1,
    sourceContractHash: canonicalHash({ source: "loan-source", revision: 1 })
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
  return {
    contractVersion: 1,
    definitionKind: "snapshot_certification_control",
    tenantId: "tenant-a",
    certificationDefinitionId: "facility-a-binding",
    revision: 1,
    sourceContract,
    sourceContractExecution: {
      definitionVersionId: "source-definition-a",
      definitionKey: "loan-tape-source",
      kind: "source_contract",
      semanticVersion: "1.0.0",
      versionHash: canonicalHash("source-version"),
      documentHash: canonicalHash("source-document"),
      approvalEventHash: canonicalHash("source-approval"),
      sourceContract
    },
    scopeBinding,
    scopeBindingExecution: {
      definitionVersionId: "scope-definition-a",
      definitionKey: "facility-a-binding",
      kind: "dataset_scope_binding",
      semanticVersion: "1.0.0",
      versionHash: canonicalHash("scope-version"),
      documentHash: canonicalHash("scope-document"),
      approvalEventHash: canonicalHash("scope-approval"),
      bindingId: "facility-a-binding",
      revision: 1,
      bindingHash: scopeBinding.bindingHash,
      sourceContract
    },
    mappingExecution: {
      definitionVersionId: "mapping-definition-a",
      definitionKey: "loan-tape",
      kind: "mapping_spec",
      semanticVersion: "1.0.0",
      versionHash: canonicalHash("mapping-version"),
      documentHash: canonicalHash("mapping-document"),
      approvalEventHash: canonicalHash("mapping-approval"),
      mappingSpecId: "mapping-spec-a",
      mappingSpecRevision: 1,
      mappingSpecHash: canonicalHash("mapping-spec"),
      sourceContract,
      activation: {
        status: "active",
        lifecycleRevision: 3,
        activatedBy: "mapping-checker",
        activatedAt: "2026-01-02T00:00:00.000Z",
        activationEventHash: canonicalHash("mapping-activation")
      },
      window: { effectiveFrom: "2026-01-01" }
    },
    runtime: {
      runtimeBundleId: "runtime-a",
      runtimeVersion: "1.0.0",
      runtimeBundleHash: canonicalHash("runtime"),
      dictionary: {
        contractVersion: 1,
        bundleKind: "dictionary",
        bundleId: "dictionary-a",
        version: "1.0.0",
        contentHash: canonicalHash("dictionary-content"),
        artifactId: "dictionary-artifact",
        mediaType: "application/json",
        createdAt: "2026-01-01T00:00:00.000Z",
        dictionaryVersion: "1.0.0",
        dictionaryHash: canonicalHash("dictionary"),
        fieldPolicyVersion: "1.0.0",
        fieldPolicyHash: canonicalHash("field-policy")
      },
      mappingCompiler: {
        contractVersion: 1,
        bundleKind: "mapping_compiler",
        bundleId: "compiler-a",
        version: "1.0.0",
        contentHash: canonicalHash("compiler-content"),
        artifactId: "compiler-artifact",
        mediaType: "application/json",
        createdAt: "2026-01-01T00:00:00.000Z"
      }
    },
    dataQuality: {
      definitionId: "dq-a",
      rulesetId: "dq-rules-a",
      mappingSectionId: "loans",
      requiredSectionIds: ["loans"],
      rules: [
        {
          ruleId: "loan-id-required",
          type: "required",
          field: "loan_id",
          severity: "critical",
          blocking: true
        },
        {
          ruleId: "balance-range",
          type: "decimal_range",
          field: "current_balance",
          minimum: "0",
          severity: "critical",
          blocking: true
        }
      ],
      balanceField: "current_balance",
      materialBalance: "1",
      window: { effectiveFrom: "2026-01-01" }
    },
    certificationReconciliation: {
      definitionId: "reconciliation-a",
      reconciliationId: "pool-tie-out",
      requiredSectionIds: ["loans"],
      controls: [
        {
          controlId: "loan-pool-balance",
          sectionId: "loans",
          recordSource: "normalized",
          dimensions: ["portfolio_id"],
          balanceField: "current_balance",
          currencyField: "currency",
          expected: [
            {
              dimensions: { portfolio_id: "portfolio-a" },
              rowCount: 1,
              balance: "100",
              currency: "USD"
            }
          ],
          balanceTolerance: "0"
        }
      ],
      window: { effectiveFrom: "2026-01-01" }
    },
    window: { effectiveFrom: "2026-01-01" },
    approval: {
      status: "pending_durable_approval",
      authority: "governed_definition_v2_lifecycle"
    }
  } as SnapshotCertificationDefinitionV1Input & {
    mappingExecution: { sourceContract: { sourceContractHash: `sha256:${string}` }; activation: { activatedAt: string }; window: { effectiveFrom: string; effectiveTo?: string } };
    scopeBinding: ReturnType<typeof createGovernedDatasetScopeBindingV1>;
    runtime: { mappingCompiler: { createdAt: string } };
    dataQuality: { requiredSectionIds: string[]; rules: Array<Record<string, unknown>>; window: { effectiveFrom: string; effectiveTo?: string } };
    certificationReconciliation: { controls: Array<{ expected: Array<{ dimensions: Record<string, string>; rowCount: number; balance: string; currency: string }> }> };
  };
}

function invalid(action: () => unknown): void {
  assert.throws(
    action,
    (error: unknown) => error instanceof ContractValidationError && error.code === "INVALID_CONTRACT"
  );
}
