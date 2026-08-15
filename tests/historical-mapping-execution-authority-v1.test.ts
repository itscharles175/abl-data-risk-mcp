import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import { canonicalHash, createMappingSpecV2, type MappingSpecV2 } from "../src/contracts/index.js";
import { GovernedDefinitionV2Store } from "../src/control/governed-definitions-v2.js";
import {
  HistoricalMappingExecutionAuthorityV1,
  HistoricalMappingExecutionAuthorityV1Error
} from "../src/services/historical-mapping-execution-authority-v1.js";
import {
  GovernedDefinitionV2Resolver,
  type GovernedDefinitionV2AuthorityPort
} from "../src/services/governed-definition-v2-resolver.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("historical mapping authority replays a later-retired version with exact prior activation evidence", () => {
  const fixture = governedFixture();
  const first = activate(fixture, "mapping-definition-v1", "1.0.0", "2026-01-01", mappingSpec(1));
  const successor = activate(fixture, "mapping-definition-v2", "2.0.0", "2026-02-01", mappingSpec(2), {
    predecessorDefinitionVersionId: first.version.definitionVersionId,
    rollbackTargetDefinitionVersionId: first.version.definitionVersionId
  });
  const authority = new HistoricalMappingExecutionAuthorityV1(new GovernedDefinitionV2Resolver(fixture.store));
  assert.equal(fixture.store.get("tenant-a", first.version.definitionVersionId)?.status, "superseded");
  assert.equal(
    authority.resolveFrozenAt({
      tenantId: "tenant-a",
      definitionVersionId: first.version.definitionVersionId,
      certificationAt: "2026-01-01T12:00:03.000Z"
    }).activationEvidence.activationEventHash,
    fixture.store.listAuditEvents("tenant-a").find((event) =>
      event.definitionVersionId === first.version.definitionVersionId && event.toStatus === "active"
    )!.eventHash
  );
  fixture.store.transition({
    tenantId: "tenant-a",
    definitionVersionId: first.version.definitionVersionId,
    toStatus: "retired",
    expectedRevision: fixture.store.get("tenant-a", first.version.definitionVersionId)!.lifecycleRevision,
    actor: "mapping-checker",
    idempotencyKey: "retire-first"
  });

  const resolved = authority.resolveFrozenAt({
    tenantId: "tenant-a",
    definitionVersionId: first.version.definitionVersionId,
    certificationAt: "2026-01-01T12:00:03.000Z"
  });

  assert.equal(fixture.store.get("tenant-a", first.version.definitionVersionId)?.status, "retired");
  assert.equal(successor.status, "active");
  assert.equal(resolved.mappingSpec.status, "active");
  assert.equal(resolved.reference.definitionVersionId, first.version.definitionVersionId);
  assert.equal(resolved.activationEvidence.lifecycleRevision, 4);
  assert.equal(resolved.activationEvidence.activatedBy, "mapping-checker");
  assert.equal(resolved.activationEvidence.activatedAt, "2026-01-01T12:00:03.000Z");
  assert.notEqual(resolved.mappingSpec.mappingSpecHash, first.version.documentHash);
  assert.deepEqual(resolved.window, { effectiveFrom: "2026-01-01" });
  fixture.close();
});

test("historical mapping authority rejects mappings not yet active, never active, and withdrawn", () => {
  const fixture = governedFixture();
  const active = activate(fixture, "mapping-definition-v1", "1.0.0", "2026-01-01", mappingSpec(1));
  const authority = new HistoricalMappingExecutionAuthorityV1(new GovernedDefinitionV2Resolver(fixture.store));
  assert.throws(
    () => authority.resolveFrozenAt({
      tenantId: "tenant-a",
      definitionVersionId: active.version.definitionVersionId,
      certificationAt: "2026-01-01T12:00:02.999Z"
    }),
    (error: unknown) => historicalError(error, "NOT_ACTIVE_AT_TIME")
  );

  let withdrawn = fixture.store.propose({
    tenantId: "tenant-a",
    definitionVersionId: "mapping-definition-withdrawn",
    definitionKey: "loan-tape-other",
    kind: "mapping_spec",
    semanticVersion: "1.0.0",
    effectiveFrom: "2026-01-01",
    document: mappingSpec(1, "loan-tape-other"),
    proposedBy: "mapping-maker",
    idempotencyKey: "withdrawn-propose"
  });
  withdrawn = fixture.store.transition({
    tenantId: "tenant-a",
    definitionVersionId: withdrawn.version.definitionVersionId,
    toStatus: "validated",
    expectedRevision: withdrawn.lifecycleRevision,
    actor: "mapping-checker",
    idempotencyKey: "withdrawn-validated"
  });
  withdrawn = fixture.store.transition({
    tenantId: "tenant-a",
    definitionVersionId: withdrawn.version.definitionVersionId,
    toStatus: "approved",
    expectedRevision: withdrawn.lifecycleRevision,
    actor: "mapping-checker",
    idempotencyKey: "withdrawn-approved"
  });
  fixture.store.transition({
    tenantId: "tenant-a",
    definitionVersionId: withdrawn.version.definitionVersionId,
    toStatus: "withdrawn",
    expectedRevision: withdrawn.lifecycleRevision,
    actor: "mapping-checker",
    idempotencyKey: "withdrawn"
  });
  assert.throws(
    () => authority.resolveFrozenAt({
      tenantId: "tenant-a",
      definitionVersionId: "mapping-definition-withdrawn",
      certificationAt: "2026-01-01T12:01:00.000Z"
    }),
    (error: unknown) => historicalError(error, "NOT_ACTIVE_AT_TIME")
  );
  fixture.close();
});

test("historical mapping authority fails closed when the immutable audit chain is tampered", () => {
  const fixture = governedFixture();
  const active = activate(fixture, "mapping-definition-v1", "1.0.0", "2026-01-01", mappingSpec(1));
  const tampered: GovernedDefinitionV2AuthorityPort = {
    get: (...args) => fixture.store.get(...args),
    selectEffective: (...args) => fixture.store.selectEffective(...args),
    listAuditEvents: (...args) => fixture.store.listAuditEvents(...args).map((event) =>
      event.definitionVersionId === active.version.definitionVersionId && event.toStatus === "active"
        ? { ...event, actor: "tamperer" }
        : event
    )
  };
  const authority = new HistoricalMappingExecutionAuthorityV1(new GovernedDefinitionV2Resolver(tampered));
  assert.throws(
    () => authority.resolveFrozenAt({
      tenantId: "tenant-a",
      definitionVersionId: active.version.definitionVersionId,
      certificationAt: "2026-01-01T12:00:03.000Z"
    }),
    (error: unknown) => historicalError(error, "INTEGRITY_FAILURE")
  );
  fixture.close();
});

function governedFixture() {
  const directory = mkdtempSync(join(tmpdir(), "historical-mapping-authority-"));
  directories.push(directory);
  let second = 0;
  const store = new GovernedDefinitionV2Store(join(directory, "governed.sqlite"), {
    clock: () => new Date(Date.UTC(2026, 0, 1, 12, 0, second++))
  });
  return { store, close: () => store.close() };
}

function activate(
  fixture: ReturnType<typeof governedFixture>,
  definitionVersionId: string,
  semanticVersion: string,
  effectiveFrom: string,
  document: MappingSpecV2,
  predecessor: Readonly<{
    predecessorDefinitionVersionId: string;
    rollbackTargetDefinitionVersionId: string;
  }> | undefined = undefined
) {
  let current = fixture.store.propose({
    tenantId: "tenant-a",
    definitionVersionId,
    definitionKey: document.mappingKey,
    kind: "mapping_spec",
    semanticVersion,
    effectiveFrom,
    document,
    proposedBy: "mapping-maker",
    idempotencyKey: `${definitionVersionId}-proposed`,
    ...predecessor
  });
  for (const status of ["validated", "approved", "active"] as const) {
    current = fixture.store.transition({
      tenantId: "tenant-a",
      definitionVersionId,
      toStatus: status,
      expectedRevision: current.lifecycleRevision,
      actor: "mapping-checker",
      idempotencyKey: `${definitionVersionId}-${status}`
    });
  }
  return current;
}

function mappingSpec(revision: number, mappingKey = "loan-tape"): MappingSpecV2 {
  return createMappingSpecV2({
    contractVersion: 2,
    tenantId: "tenant-a",
    mappingSpecId: `mapping-spec-${revision}`,
    mappingKey,
    revision,
    status: "proposed",
    sourceContract: {
      sourceContractId: "loan-source",
      revision: 1,
      sourceContractHash: canonicalHash("loan-source-v1")
    },
    dictionaryBundle: {
      contractVersion: 1,
      bundleKind: "dictionary",
      bundleId: "dictionary-core",
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
    rules: [{
      ruleId: "loan-id",
      canonicalField: "loan_id",
      expression: { op: "source", column: "loan_no" },
      onError: "fail_application"
    }],
    requiredCanonicalFields: ["loan_id"],
    createdBy: "mapping-maker",
    createdAt: "2026-01-01T00:00:00.000Z"
  });
}

function historicalError(
  error: unknown,
  code: HistoricalMappingExecutionAuthorityV1Error["code"]
): boolean {
  return error instanceof HistoricalMappingExecutionAuthorityV1Error && error.code === code;
}
