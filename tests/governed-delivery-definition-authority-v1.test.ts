import assert from "node:assert/strict";
import { test } from "node:test";

import {
  canonicalHash,
  createGovernedDatasetScopeBindingV1,
  createSourceContractV1,
  type GovernedDatasetScopeBindingV1,
  type Sha256Hash,
  type SourceContractV1
} from "../src/contracts/index.js";
import {
  GovernedDeliveryDefinitionAuthorityV1,
  GovernedDeliveryDefinitionAuthorityV1Error
} from "../src/services/governed-delivery-definition-authority-v1.js";
import {
  GovernedDefinitionV2ResolverError,
  type ResolvedGovernedDefinitionV2
} from "../src/services/governed-definition-v2-resolver.js";

const AS_OF_DATE = "2026-08-01";

test("projects an exact, effective source and binding pair with lifecycle evidence", () => {
  const source = sourceContract();
  const binding = scopeBinding(source);
  const calls: unknown[] = [];
  const authority = new GovernedDeliveryDefinitionAuthorityV1({
    resolveEffective: (input) => {
      calls.push(input);
      if (input.kind === "source_contract") {
        return resolvedDefinition("source-contract-v1", input.kind, "loan-tape", source);
      }
      return resolvedDefinition("dataset-binding-v1", input.kind, binding.bindingId, binding);
    }
  });

  const resolved = authority.resolveEffective({
    tenantId: "tenant-a",
    sourceContractDefinitionKey: "loan-tape",
    datasetScopeBindingDefinitionKey: binding.bindingId,
    asOfDate: AS_OF_DATE
  });

  assert.equal(resolved.sourceContract.sourceContractHash, source.sourceContractHash);
  assert.equal(resolved.scopeBinding.bindingHash, binding.bindingHash);
  assert.equal(resolved.sourceContractEvidence.definition.definitionVersionId, "source-contract-v1");
  assert.equal(resolved.scopeBindingEvidence.definition.definitionVersionId, "dataset-binding-v1");
  assert.equal(
    resolved.sourceContractEvidence.approval.approvalEventHash,
    resolved.sourceContractEvidence.definition.approvalEventHash
  );
  assert.deepEqual(calls, [
    {
      tenantId: "tenant-a",
      kind: "source_contract",
      definitionKey: "loan-tape",
      asOfDate: AS_OF_DATE
    },
    {
      tenantId: "tenant-a",
      kind: "dataset_scope_binding",
      definitionKey: binding.bindingId,
      asOfDate: AS_OF_DATE
    }
  ]);
  assert.ok(Object.isFrozen(resolved));
  assert.ok(Object.isFrozen(resolved.sourceContract));
});

test("fails closed for lifecycle, tenant, kind, hash, effectivity, and binding-substitution attacks", () => {
  const source = sourceContract();
  const binding = scopeBinding(source);
  const request = {
    tenantId: "tenant-a",
    sourceContractDefinitionKey: "loan-tape",
    datasetScopeBindingDefinitionKey: binding.bindingId,
    asOfDate: AS_OF_DATE
  } as const;

  const cases: readonly Readonly<{
    readonly name: string;
    readonly resolve: (input: {
      readonly kind: "source_contract" | "dataset_scope_binding";
    }) => ResolvedGovernedDefinitionV2;
    readonly code: GovernedDeliveryDefinitionAuthorityV1Error["code"];
  }>[] = [
    {
      name: "unapproved lifecycle state",
      resolve: () => {
        throw new GovernedDefinitionV2ResolverError("UNAPPROVED", "definition is not activated");
      },
      code: "UNAPPROVED"
    },
    {
      name: "tenant substitution",
      resolve: (input) =>
        input.kind === "source_contract"
          ? resolvedDefinition("source-contract-v1", input.kind, "loan-tape", sourceContract({ tenantId: "tenant-b" }))
          : resolvedDefinition("dataset-binding-v1", input.kind, binding.bindingId, binding),
      code: "INTEGRITY_FAILURE"
    },
    {
      name: "kind substitution",
      resolve: (input) =>
        resolvedDefinition(
          "source-contract-v1",
          "dataset_scope_binding",
          input.kind === "source_contract" ? "loan-tape" : binding.bindingId,
          source
        ),
      code: "INTEGRITY_FAILURE"
    },
    {
      name: "source document hash tampering",
      resolve: (input) =>
        input.kind === "source_contract"
          ? resolvedDefinition("source-contract-v1", input.kind, "loan-tape", {
              ...source,
              sourceContractHash: hash("forged-source-contract")
            })
          : resolvedDefinition("dataset-binding-v1", input.kind, binding.bindingId, binding),
      code: "INTEGRITY_FAILURE"
    },
    {
      name: "effective-window substitution",
      resolve: (input) => {
        const futureSource = sourceContract({ effectiveFrom: "2026-08-02" });
        const futureBinding = scopeBinding(futureSource, { effectiveFrom: "2026-08-02" });
        return input.kind === "source_contract"
          ? resolvedDefinition("source-contract-v1", input.kind, "loan-tape", futureSource)
          : resolvedDefinition("dataset-binding-v1", input.kind, futureBinding.bindingId, futureBinding);
      },
      code: "INTEGRITY_FAILURE"
    },
    {
      name: "binding source substitution",
      resolve: (input) => {
        const substitutedSource = sourceContract({ createdAt: "2026-07-02T00:00:00.000Z" });
        const substitutedBinding = scopeBinding(substitutedSource);
        return input.kind === "source_contract"
          ? resolvedDefinition("source-contract-v1", input.kind, "loan-tape", source)
          : resolvedDefinition("dataset-binding-v1", input.kind, substitutedBinding.bindingId, substitutedBinding);
      },
      code: "INTEGRITY_FAILURE"
    }
  ];

  for (const current of cases) {
    const authority = new GovernedDeliveryDefinitionAuthorityV1({
      resolveEffective: (input) => current.resolve({ kind: input.kind })
    });
    assert.throws(
      () => authority.resolveEffective(request),
      (error: unknown) => authorityError(error, current.code),
      current.name
    );
  }
});

test("rejects invalid public input before definition resolution", () => {
  let called = false;
  const authority = new GovernedDeliveryDefinitionAuthorityV1({
    resolveEffective: () => {
      called = true;
      throw new Error("must not resolve");
    }
  });

  assert.throws(
    () =>
      authority.resolveEffective({
        tenantId: "tenant-a",
        sourceContractDefinitionKey: "loan-tape",
        datasetScopeBindingDefinitionKey: "binding-a",
        asOfDate: "2026-08-01T00:00:00.000Z"
      }),
    (error: unknown) => authorityError(error, "INVALID_INPUT")
  );
  assert.equal(called, false);
});

function sourceContract(
  override: Partial<{
    readonly tenantId: string;
    readonly effectiveFrom: string;
    readonly createdAt: string;
  }> = {}
): SourceContractV1 {
  return createSourceContractV1({
    contractVersion: 1,
    tenantId: override.tenantId ?? "tenant-a",
    sourceContractId: "loan-tape-source",
    sourceKey: "loan-tape",
    revision: 1,
    status: "approved",
    delivery: { mode: "managed_upload", format: "parquet", logicalName: "loan-tape.parquet" },
    schemaPolicy: {
      columns: [{ sourceName: "loan_id", ordinal: 0, nativeType: "string", nullable: false, required: true }],
      allowUnknownColumns: false,
      requireStableOrdinals: true
    },
    parserPolicy: {
      format: "parquet",
      parserId: "parquet-v1",
      parserVersion: "1.0.0",
      optionsHash: hash("parser-options"),
      exactDecimalMode: "string",
      timezone: "UTC",
      rejectSchemaMerging: true
    },
    extractionPolicy: {
      mode: "full",
      readOnly: true,
      maximumRows: 1_000,
      maximumColumns: 100,
      maximumBytes: 1_000_000,
      timeoutMs: 1_000,
      cursorRows: 100
    },
    sections: [{ sectionId: "loans", required: true, selector: "loans", keyFields: ["loan_id"] }],
    effectiveFrom: override.effectiveFrom ?? "2026-08-01",
    createdBy: "maker-a",
    createdAt: override.createdAt ?? "2026-07-01T00:00:00.000Z",
    approvedBy: "checker-a",
    approvedAt: "2026-07-02T00:00:00.000Z"
  });
}

function scopeBinding(
  source: SourceContractV1,
  override: Partial<{ readonly effectiveFrom: string }> = {}
): GovernedDatasetScopeBindingV1 {
  return createGovernedDatasetScopeBindingV1({
    contractVersion: 1,
    tenantId: source.tenantId,
    bindingId: "loan-tape-facility-a",
    revision: 1,
    datasetId: "loan-tape-dataset",
    sourceContract: {
      sourceContractId: source.sourceContractId,
      revision: source.revision,
      sourceContractHash: source.sourceContractHash
    },
    scope: { scopeType: "facility", scopeId: "facility-a" },
    effectiveFrom: override.effectiveFrom ?? "2026-08-01"
  });
}

function resolvedDefinition(
  definitionVersionId: string,
  kind: "source_contract" | "dataset_scope_binding",
  definitionKey: string,
  executionDocument: unknown
): ResolvedGovernedDefinitionV2 {
  const approvalEventHash = hash(`${definitionVersionId}:approval`);
  return {
    reference: {
      definitionVersionId,
      definitionKey,
      kind,
      semanticVersion: "1.0.0",
      versionHash: hash(`${definitionVersionId}:version`),
      documentHash: hash(`${definitionVersionId}:document`),
      approvalEventHash
    },
    approvalEvidence: {
      status: "approved",
      proposedBy: "maker-a",
      approvedBy: "checker-a",
      approvedAt: "2026-07-02T00:00:00.000Z",
      approvalEventHash
    },
    executionDocument: executionDocument as never
  };
}

function hash(label: string): Sha256Hash {
  return canonicalHash({ label });
}

function authorityError(
  error: unknown,
  code: GovernedDeliveryDefinitionAuthorityV1Error["code"]
): boolean {
  assert.ok(error instanceof GovernedDeliveryDefinitionAuthorityV1Error);
  assert.equal(error.code, code);
  return true;
}
