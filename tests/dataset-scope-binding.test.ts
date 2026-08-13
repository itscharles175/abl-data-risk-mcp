import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ContractValidationError,
  canonicalHash,
  createGovernedDatasetScopeBindingV1,
  parseGovernedDatasetScopeBindingV1,
  type GovernedDatasetScopeBindingV1Input,
  type Sha256Hash
} from "../src/contracts/index.js";
import {
  GovernedDefinitionV2Store,
  GovernedDefinitionV2StoreError,
  type GovernedDefinitionViewV2
} from "../src/control/governed-definitions-v2.js";
import {
  GovernedDefinitionV2Resolver,
  GovernedDefinitionV2ResolverError
} from "../src/services/governed-definition-v2-resolver.js";

test("GovernedDatasetScopeBindingV1 is strict, deterministic, and hash-bound", () => {
  const binding = createGovernedDatasetScopeBindingV1(bindingInput());

  assert.equal(parseGovernedDatasetScopeBindingV1(binding).bindingHash, binding.bindingHash);
  assert.equal(
    createGovernedDatasetScopeBindingV1(bindingInput()).bindingHash,
    binding.bindingHash
  );
  assert.equal(
    createGovernedDatasetScopeBindingV1({
      ...bindingInput(),
      bindingId: "facility-a-loan-tape",
      scope: { scopeType: "facility", scopeId: "facility-a" }
    }).scope.scopeType,
    "facility"
  );
  assert.throws(
    () => parseGovernedDatasetScopeBindingV1({ ...binding, datasetId: "forged-dataset" }),
    (error: unknown) => contractError(error, "HASH_MISMATCH")
  );
  assert.throws(
    () => createGovernedDatasetScopeBindingV1({ ...bindingInput(), unexpected: true } as never),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
  assert.throws(
    () =>
      createGovernedDatasetScopeBindingV1({
        ...bindingInput(),
        effectiveTo: "2026-01-01"
      }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
  assert.throws(
    () =>
      createGovernedDatasetScopeBindingV1({
        ...bindingInput(),
        scope: { scopeType: "tenant", scopeId: "tenant-a" }
      } as never),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
});

test("dataset/scope bindings require matching governed identity, version, and effectivity", () => {
  const store = new GovernedDefinitionV2Store(":memory:");

  for (const [definitionVersionId, override, expectedMessage] of [
    ["wrong-tenant", { tenantId: "tenant-b" }, /another tenant/],
    ["wrong-key", { bindingId: "binding-b" }, /logical identity/],
    ["wrong-version", { revision: 2 }, /document version/],
    ["wrong-from", { effectiveFrom: "2026-02-01" }, /effectivity/],
    ["wrong-to", { effectiveTo: "2026-12-31" }, /effectivity/]
  ] as const) {
    assert.throws(
      () =>
        store.propose({
          ...proposal(definitionVersionId),
          document: createGovernedDatasetScopeBindingV1({
            ...bindingInput(),
            ...override
          })
        }),
      expectedMessage
    );
  }

  store.close();
});

test("dataset/scope bindings use maker/checker governance and resolve only after activation", () => {
  const clock = sequentialClock([
    "2026-08-12T12:00:00.000Z",
    "2026-08-12T12:01:00.000Z",
    "2026-08-12T12:02:00.000Z",
    "2026-08-12T12:03:00.000Z"
  ]);
  const store = new GovernedDefinitionV2Store(":memory:", { clock });
  const resolver = new GovernedDefinitionV2Resolver(store);
  let view = store.propose(proposal("dataset-binding-v1"));

  assert.throws(
    () => resolver.resolveFrozen({ tenantId: "tenant-a", definitionVersionId: "dataset-binding-v1" }),
    (error: unknown) => resolverError(error, "UNAPPROVED")
  );
  assert.throws(
    () =>
      store.transition({
        tenantId: "tenant-a",
        definitionVersionId: "dataset-binding-v1",
        toStatus: "validated",
        expectedRevision: view.lifecycleRevision,
        actor: "binding-maker",
        idempotencyKey: "maker-cannot-validate"
      }),
    (error: unknown) => storeError(error, "MAKER_CHECKER_VIOLATION")
  );

  view = transition(store, view, "validated", "binding-checker");
  view = transition(store, view, "approved", "binding-checker");
  assert.throws(
    () => resolver.resolveFrozen({ tenantId: "tenant-a", definitionVersionId: "dataset-binding-v1" }),
    (error: unknown) => resolverError(error, "UNAPPROVED")
  );

  view = transition(store, view, "active", "binding-checker");
  const resolved = resolver.resolveEffective({
    tenantId: "tenant-a",
    kind: "dataset_scope_binding",
    definitionKey: "portfolio-east-loan-tape",
    asOfDate: "2026-08-12"
  });
  assert.equal(view.status, "active");
  assert.equal(resolved.reference.kind, "dataset_scope_binding");
  assert.equal(resolved.approvalEvidence.approvedBy, "binding-checker");
  assert.equal(
    (resolved.executionDocument as { readonly bindingId: string }).bindingId,
    "portfolio-east-loan-tape"
  );
  assert.throws(
    () => resolver.resolveFrozen({ tenantId: "tenant-b", definitionVersionId: "dataset-binding-v1" }),
    (error: unknown) => resolverError(error, "NOT_FOUND")
  );

  store.close();
});

function bindingInput(): GovernedDatasetScopeBindingV1Input {
  return {
    contractVersion: 1,
    tenantId: "tenant-a",
    bindingId: "portfolio-east-loan-tape",
    revision: 1,
    datasetId: "loan-tape-dataset",
    sourceContract: {
      sourceContractId: "loan-tape-postgres-v1",
      revision: 1,
      sourceContractHash: hash("source-contract")
    },
    scope: { scopeType: "portfolio", scopeId: "portfolio-east" },
    effectiveFrom: "2026-01-01"
  };
}

function proposal(definitionVersionId: string) {
  return {
    tenantId: "tenant-a",
    definitionVersionId,
    definitionKey: "portfolio-east-loan-tape",
    kind: "dataset_scope_binding" as const,
    semanticVersion: "1.0.0",
    effectiveFrom: "2026-01-01",
    document: createGovernedDatasetScopeBindingV1(bindingInput()),
    proposedBy: "binding-maker",
    idempotencyKey: `propose-${definitionVersionId}`
  };
}

function transition(
  store: GovernedDefinitionV2Store,
  current: GovernedDefinitionViewV2,
  toStatus: "validated" | "approved" | "active",
  actor: string
): GovernedDefinitionViewV2 {
  return store.transition({
    tenantId: current.version.tenantId,
    definitionVersionId: current.version.definitionVersionId,
    toStatus,
    expectedRevision: current.lifecycleRevision,
    actor,
    idempotencyKey: `${current.version.definitionVersionId}-${toStatus}`
  });
}

function sequentialClock(timestamps: readonly string[]): () => Date {
  let index = 0;
  return () => new Date(timestamps[index++] ?? timestamps.at(-1)!);
}

function hash(seed: string): Sha256Hash {
  return canonicalHash(seed);
}

function contractError(error: unknown, code: ContractValidationError["code"]): boolean {
  return error instanceof ContractValidationError && error.code === code;
}

function storeError(error: unknown, code: GovernedDefinitionV2StoreError["code"]): boolean {
  return error instanceof GovernedDefinitionV2StoreError && error.code === code;
}

function resolverError(error: unknown, code: GovernedDefinitionV2ResolverError["code"]): boolean {
  return error instanceof GovernedDefinitionV2ResolverError && error.code === code;
}
