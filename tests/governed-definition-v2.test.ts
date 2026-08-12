import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, test } from "node:test";

import {
  GovernedDefinitionStatusV2Schema,
  GovernedDefinitionTransitionV2Schema,
  ReconciliationDefinitionV1Schema,
  SemanticVersionV2Schema,
  canonicalHash,
  compareSemanticVersionsV2,
  computeSemanticDiffV1,
  createGovernedDefinitionVersionV2,
  createMappingSpecV2,
  createMetricProjectionV1,
  createSourceContractV1
} from "../src/contracts/index.js";
import {
  GOVERNED_DEFINITION_V2_STORE_COMPONENT,
  GOVERNED_DEFINITION_V2_STORE_SCHEMA_VERSION,
  GovernedDefinitionV2Store,
  GovernedDefinitionV2StoreError,
  type GovernedDefinitionViewV2
} from "../src/control/governed-definitions-v2.js";
import { DefinitionStore } from "../src/control/definitions.js";
import {
  GovernedDefinitionV2Resolver,
  GovernedDefinitionV2ResolverError
} from "../src/services/governed-definition-v2-resolver.js";

const directories: string[] = [];
const TIMES = [
  "2026-08-12T12:00:00.000Z",
  "2026-08-12T12:01:00.000Z",
  "2026-08-12T12:02:00.000Z",
  "2026-08-12T12:03:00.000Z",
  "2026-08-12T12:04:00.000Z",
  "2026-08-12T12:05:00.000Z",
  "2026-08-12T12:06:00.000Z",
  "2026-08-12T12:07:00.000Z",
  "2026-08-12T12:08:00.000Z",
  "2026-08-12T12:09:00.000Z"
];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("semantic versions and semantic diffs are strict and deterministic", () => {
  for (const value of ["0.0.0", "1.2.3", "1.2.3-alpha.1+build", "1.0.0+1"]) {
    assert.equal(SemanticVersionV2Schema.safeParse(value).success, true, value);
  }
  for (const value of ["1", "1.2", "01.2.3", "1.02.3", "1.2.03", "1.2.3-01", "v1.2.3"]) {
    assert.equal(SemanticVersionV2Schema.safeParse(value).success, false, value);
  }
  assert.equal(compareSemanticVersionsV2("1.0.0+1", "1.0.0+2"), 0);
  assert.equal(compareSemanticVersionsV2("9007199254740992.1.0", "9007199254740993.0.0"), -1);
  assert.equal(compareSemanticVersionsV2("1.0.0-alpha.2", "1.0.0-alpha.10"), -1);
  assert.equal(compareSemanticVersionsV2("1.0.0", "1.0.0-rc.1"), 1);
  const diff = computeSemanticDiffV1(
    { nested: { removed: true, value: "a" } },
    { nested: { added: true, value: "b" } }
  );
  assert.deepEqual(diff.changedPaths, ["/nested/added", "/nested/removed", "/nested/value"]);
  assert.equal(diff.beforeHash, canonicalHash({ nested: { removed: true, value: "a" } }));
});

test("v2 lifecycle preserves historical resolution and locks semantic diff, impact, and rollback", () => {
  const { store } = fixture();
  const first = store.propose(proposal("metric-v1", "1.0.0", "2026-01-01", 12));
  assert.equal(first.version.semanticDiff.beforeHash, null);
  assert.equal(first.version.impactPreview.impactLevel, "initial");
  assert.equal(first.version.impactPreview.rollbackTargetRequired, false);
  const activeFirst = activate(store, first, "checker-a", "v1");
  assert.equal(activeFirst.approvalEvidence?.approvedBy, "checker-a");
  assert.notEqual(activeFirst.approvalEvidence?.approvalEventHash, undefined);

  const second = store.propose({
    ...proposal("metric-v2", "2.0.0", "2026-07-01", 18),
    predecessorDefinitionVersionId: "metric-v1",
    rollbackTargetDefinitionVersionId: "metric-v1"
  });
  assert.equal(second.version.semanticDiff.beforeHash, first.version.documentHash);
  assert.deepEqual(second.version.semanticDiff.changedPaths, ["/maximumCells", "/version"]);
  assert.equal(second.version.impactPreview.impactLevel, "major");
  assert.equal(second.version.impactPreview.rollbackTargetRequired, true);
  const activeSecond = activate(store, second, "checker-b", "v2");

  assert.equal(store.get("tenant-a", "metric-v1")?.status, "superseded");
  assert.equal(store.selectEffective("tenant-a", "metric_definition", "roll-rate", "2026-06-30").version.definitionVersionId, "metric-v1");
  assert.equal(store.selectEffective("tenant-a", "metric_definition", "roll-rate", "2026-07-01").version.definitionVersionId, "metric-v2");
  assert.equal(store.get("tenant-a", "metric-v1")?.version.versionHash, first.version.versionHash);
  assert.equal(activeSecond.version.rollbackTargetDefinitionVersionId, "metric-v1");

  const retiredSecond = store.transition({
    tenantId: "tenant-a",
    definitionVersionId: "metric-v2",
    toStatus: "retired",
    expectedRevision: activeSecond.lifecycleRevision,
    actor: "checker-b",
    idempotencyKey: "v2-retired"
  });
  assert.equal(retiredSecond.status, "retired");
  assert.equal(store.get("tenant-a", "metric-v2")?.version.versionHash, second.version.versionHash);
  assert.equal(
    store.selectEffective("tenant-a", "metric_definition", "roll-rate", "2026-06-30").version.definitionVersionId,
    "metric-v1"
  );
  assert.throws(
    () => store.selectEffective("tenant-a", "metric_definition", "roll-rate", "2026-07-01"),
    (error: unknown) => storeError(error, "NOT_FOUND")
  );

  const third = store.propose({
    ...proposal("metric-v3", "3.0.0", "2027-01-01", 20),
    predecessorDefinitionVersionId: "metric-v2"
  });
  assert.equal(third.version.rollbackTargetDefinitionVersionId, null);
  store.close();
});

test("an expired latest version never resurrects a superseded predecessor", () => {
  const { store } = fixture();
  const first = activate(
    store,
    store.propose(proposal("metric-expiry-v1", "1.0.0", "2026-01-01", 12)),
    "checker-a",
    "expiry-v1"
  );
  const second = store.propose({
    ...proposal("metric-expiry-v2", "2.0.0", "2026-07-01", 18),
    effectiveTo: "2027-01-01",
    predecessorDefinitionVersionId: first.version.definitionVersionId,
    rollbackTargetDefinitionVersionId: first.version.definitionVersionId
  });
  activate(store, second, "checker-b", "expiry-v2");
  assert.equal(
    store.selectEffective("tenant-a", "metric_definition", "roll-rate", "2026-12-31").version
      .definitionVersionId,
    "metric-expiry-v2"
  );
  assert.throws(
    () => store.selectEffective("tenant-a", "metric_definition", "roll-rate", "2027-01-01"),
    (error: unknown) => storeError(error, "NOT_FOUND")
  );
  store.close();
});

test("a rollback target remains active until its pending replacement activates", () => {
  const { store } = fixture();
  const first = activate(
    store,
    store.propose(proposal("metric-rollback-v1", "1.0.0", "2026-01-01", 12)),
    "checker-a",
    "rollback-v1"
  );
  let replacement = store.propose({
    ...proposal("metric-rollback-v2", "2.0.0", "2026-07-01", 18),
    predecessorDefinitionVersionId: first.version.definitionVersionId,
    rollbackTargetDefinitionVersionId: first.version.definitionVersionId,
    idempotencyKey: "rollback-v2-propose"
  });
  const retireFirst = (suffix: string) =>
    store.transition({
      tenantId: "tenant-a",
      definitionVersionId: first.version.definitionVersionId,
      toStatus: "retired",
      expectedRevision: store.get("tenant-a", first.version.definitionVersionId)!.lifecycleRevision,
      actor: "retirement-checker",
      idempotencyKey: `rollback-target-retire-${suffix}`
    });

  assert.throws(() => retireFirst("proposed"), (error: unknown) => storeError(error, "CONFLICT"));
  replacement = transition(store, replacement, "validated", "checker-b", "rollback-v2-validated");
  assert.throws(() => retireFirst("validated"), (error: unknown) => storeError(error, "CONFLICT"));
  replacement = transition(store, replacement, "approved", "checker-b", "rollback-v2-approved");
  assert.throws(() => retireFirst("approved"), (error: unknown) => storeError(error, "CONFLICT"));

  replacement = transition(store, replacement, "active", "checker-b", "rollback-v2-active");
  assert.equal(replacement.status, "active");
  assert.equal(store.get("tenant-a", first.version.definitionVersionId)?.status, "superseded");
  assert.equal(retireFirst("after-activation").status, "retired");
  store.close();
});

test("withdrawal is terminal, non-executable, and allowed only before activation", () => {
  assert.equal(GovernedDefinitionStatusV2Schema.safeParse("withdrawn").success, true);
  assert.equal(GovernedDefinitionTransitionV2Schema.safeParse("withdrawn").success, true);

  for (const sourceStatus of ["proposed", "validated", "approved"] as const) {
    const { store } = fixture();
    let current = store.propose(
      proposal(`metric-withdraw-${sourceStatus}`, "1.0.0", "2026-01-01", 12)
    );
    if (sourceStatus !== "proposed") {
      current = transition(store, current, "validated", "checker-a", `${sourceStatus}-validate`);
    }
    if (sourceStatus === "approved") {
      current = transition(store, current, "approved", "checker-a", "approved-approve");
    }

    const immutableVersionHash = current.version.versionHash;
    const withdrawn = store.transition({
      tenantId: "tenant-a",
      definitionVersionId: current.version.definitionVersionId,
      toStatus: "withdrawn",
      expectedRevision: current.lifecycleRevision,
      actor: "checker-b",
      evidence: { reason: `withdraw ${sourceStatus} draft` },
      idempotencyKey: `${sourceStatus}-withdraw`
    });
    assert.equal(withdrawn.status, "withdrawn");
    assert.equal(withdrawn.lifecycleRevision, current.lifecycleRevision + 1);
    assert.equal(withdrawn.version.versionHash, immutableVersionHash);

    for (const toStatus of ["validated", "approved", "active", "retired", "withdrawn"] as const) {
      assert.throws(
        () =>
          store.transition({
            tenantId: "tenant-a",
            definitionVersionId: current.version.definitionVersionId,
            toStatus,
            expectedRevision: withdrawn.lifecycleRevision,
            actor: "checker-c",
            idempotencyKey: `${sourceStatus}-after-withdraw-${toStatus}`
          }),
        (error: unknown) => storeError(error, "ILLEGAL_TRANSITION")
      );
    }
    assert.throws(
      () => store.selectEffective("tenant-a", "metric_definition", "roll-rate", "2026-08-12"),
      (error: unknown) => storeError(error, "NOT_FOUND")
    );
    assert.throws(
      () =>
        new GovernedDefinitionV2Resolver(store).resolveFrozen({
          tenantId: "tenant-a",
          definitionVersionId: current.version.definitionVersionId
        }),
      (error: unknown) =>
        error instanceof GovernedDefinitionV2ResolverError && error.code === "UNAPPROVED"
    );
    store.close();
  }

  const { store } = fixture();
  const first = activate(
    store,
    store.propose(proposal("metric-withdraw-active-v1", "1.0.0", "2026-01-01", 12)),
    "checker-a",
    "withdraw-active-v1"
  );
  const cannotWithdraw = (version: GovernedDefinitionViewV2, suffix: string) =>
    store.transition({
      tenantId: "tenant-a",
      definitionVersionId: version.version.definitionVersionId,
      toStatus: "withdrawn",
      expectedRevision: version.lifecycleRevision,
      actor: "checker-c",
      idempotencyKey: `cannot-withdraw-${suffix}`
    });
  assert.throws(() => cannotWithdraw(first, "active"), (error: unknown) =>
    storeError(error, "ILLEGAL_TRANSITION")
  );
  const second = activate(
    store,
    store.propose({
      ...proposal("metric-withdraw-active-v2", "2.0.0", "2026-07-01", 18),
      predecessorDefinitionVersionId: first.version.definitionVersionId,
      rollbackTargetDefinitionVersionId: first.version.definitionVersionId
    }),
    "checker-b",
    "withdraw-active-v2"
  );
  const superseded = store.get("tenant-a", first.version.definitionVersionId)!;
  assert.equal(superseded.status, "superseded");
  assert.throws(() => cannotWithdraw(superseded, "superseded"), (error: unknown) =>
    storeError(error, "ILLEGAL_TRANSITION")
  );
  const retired = store.transition({
    tenantId: "tenant-a",
    definitionVersionId: superseded.version.definitionVersionId,
    toStatus: "retired",
    expectedRevision: superseded.lifecycleRevision,
    actor: "checker-c",
    idempotencyKey: "retire-before-withdraw-attempt"
  });
  assert.throws(() => cannotWithdraw(retired, "retired"), (error: unknown) =>
    storeError(error, "ILLEGAL_TRANSITION")
  );
  assert.equal(second.status, "active");
  store.close();
});

test("withdrawal preserves maker-checker, tenant, revision, replay, and audit guarantees", () => {
  const { store } = fixture();
  const proposed = store.propose(proposal("metric-withdraw-governed", "1.0.0", "2026-01-01", 12));
  const request = {
    tenantId: "tenant-a",
    definitionVersionId: proposed.version.definitionVersionId,
    toStatus: "withdrawn" as const,
    expectedRevision: proposed.lifecycleRevision,
    actor: "checker-a",
    evidence: { reason: "duplicate source delivery" },
    idempotencyKey: "governed-withdraw"
  };
  assert.throws(
    () => store.transition({ ...request, actor: "maker-a", idempotencyKey: "maker-withdraw" }),
    (error: unknown) => storeError(error, "MAKER_CHECKER_VIOLATION")
  );
  assert.throws(
    () => store.transition({ ...request, tenantId: "tenant-b", idempotencyKey: "other-tenant" }),
    (error: unknown) => storeError(error, "NOT_FOUND")
  );
  assert.throws(
    () => store.transition({ ...request, expectedRevision: proposed.lifecycleRevision + 1 }),
    (error: unknown) => storeError(error, "CONCURRENCY_CONFLICT")
  );

  const withdrawn = store.transition(request);
  const eventsBeforeReplay = store.listAuditEvents("tenant-a");
  const replay = store.transition(request);
  assert.deepEqual(replay, withdrawn);
  assert.equal(store.listAuditEvents("tenant-a").length, eventsBeforeReplay.length);
  assert.throws(
    () => store.transition({ ...request, evidence: { reason: "changed after receipt" } }),
    (error: unknown) => storeError(error, "IDEMPOTENCY_CONFLICT")
  );

  assert.equal(eventsBeforeReplay.at(-1)?.fromStatus, "proposed");
  assert.equal(eventsBeforeReplay.at(-1)?.toStatus, "withdrawn");
  for (const [index, event] of eventsBeforeReplay.entries()) {
    assert.equal(event.previousEventHash, index === 0 ? null : eventsBeforeReplay[index - 1]!.eventHash);
  }
  store.close();
});

test("a withdrawn rollback-dependent successor no longer blocks retirement and remains predecessor history", () => {
  const { store } = fixture();
  const first = activate(
    store,
    store.propose(proposal("metric-withdraw-history-v1", "1.0.0", "2026-01-01", 12)),
    "checker-a",
    "withdraw-history-v1"
  );
  let abandoned = store.propose({
    ...proposal("metric-withdraw-history-v2", "2.0.0", "2026-07-01", 18),
    predecessorDefinitionVersionId: first.version.definitionVersionId,
    rollbackTargetDefinitionVersionId: first.version.definitionVersionId
  });
  abandoned = transition(store, abandoned, "validated", "checker-b", "withdraw-history-v2-validate");
  abandoned = transition(store, abandoned, "approved", "checker-b", "withdraw-history-v2-approve");
  assert.throws(
    () =>
      store.transition({
        tenantId: "tenant-a",
        definitionVersionId: first.version.definitionVersionId,
        toStatus: "retired",
        expectedRevision: first.lifecycleRevision,
        actor: "checker-c",
        idempotencyKey: "retire-with-pending-successor"
      }),
    (error: unknown) => storeError(error, "CONFLICT")
  );
  const withdrawn = store.transition({
    tenantId: "tenant-a",
    definitionVersionId: abandoned.version.definitionVersionId,
    toStatus: "withdrawn",
    expectedRevision: abandoned.lifecycleRevision,
    actor: "checker-c",
    evidence: { reason: "replacement rejected during review" },
    idempotencyKey: "withdraw-history-v2"
  });
  assert.equal(withdrawn.approvalEvidence?.approvalEventHash, abandoned.approvalEvidence?.approvalEventHash);
  const retired = store.transition({
    tenantId: "tenant-a",
    definitionVersionId: first.version.definitionVersionId,
    toStatus: "retired",
    expectedRevision: first.lifecycleRevision,
    actor: "checker-c",
    idempotencyKey: "retire-after-withdrawal"
  });
  assert.equal(retired.status, "retired");

  const successor = store.propose({
    ...proposal("metric-withdraw-history-v3", "3.0.0", "2027-01-01", 24),
    predecessorDefinitionVersionId: withdrawn.version.definitionVersionId
  });
  assert.equal(successor.version.predecessorDefinitionVersionId, withdrawn.version.definitionVersionId);
  assert.equal(store.get("tenant-a", withdrawn.version.definitionVersionId)?.status, "withdrawn");
  const active = activate(store, successor, "checker-d", "withdraw-history-v3");
  assert.equal(
    store.selectEffective("tenant-a", "metric_definition", "roll-rate", "2027-01-01").version
      .definitionVersionId,
    active.version.definitionVersionId
  );
  store.close();
});

test("a retired predecessor cannot be replaced by an overlapping effective timeline", () => {
  const { store } = fixture();
  const first = activate(
    store,
    store.propose(proposal("metric-retired-v1", "1.0.0", "2026-06-01", 12)),
    "checker-a",
    "retired-v1"
  );
  store.transition({
    tenantId: "tenant-a",
    definitionVersionId: first.version.definitionVersionId,
    toStatus: "retired",
    expectedRevision: first.lifecycleRevision,
    actor: "checker-a",
    idempotencyKey: "retire-v1"
  });
  for (const effectiveFrom of ["2026-05-01", "2026-06-01"] as const) {
    assert.throws(
      () =>
        store.propose({
          ...proposal(`metric-overlap-${effectiveFrom}`, "2.0.0", effectiveFrom, 18),
          predecessorDefinitionVersionId: first.version.definitionVersionId,
          idempotencyKey: `overlap-${effectiveFrom}`
        }),
      (error: unknown) => storeError(error, "CONFLICT")
    );
  }
  const successor = store.propose({
    ...proposal("metric-retired-v2", "2.0.0", "2026-07-01", 18),
    predecessorDefinitionVersionId: first.version.definitionVersionId,
    idempotencyKey: "retired-v2"
  });
  activate(store, successor, "checker-b", "retired-v2");
  assert.equal(
    store.selectEffective("tenant-a", "metric_definition", "roll-rate", "2026-07-01").version
      .definitionVersionId,
    "metric-retired-v2"
  );
  store.close();
});

test("predecessor selection follows durable insertion order and the store clock cannot move backward", () => {
  const directory = mkdtempSync(join(tmpdir(), "abl-governed-definition-v2-clock-"));
  directories.push(directory);
  const times = [
    "2026-08-12T12:00:00.000Z",
    "2026-08-12T12:00:00.000Z",
    "2026-08-12T12:00:00.000Z",
    "2026-08-12T12:00:00.000Z"
  ];
  let index = 0;
  const store = new GovernedDefinitionV2Store(join(directory, "control.sqlite"), {
    clock: () => new Date(times[index++] ?? "2026-08-12T09:00:00.000Z")
  });
  store.propose(proposal("metric-clock-v1", "1.0.0", "2026-01-01", 12));
  store.propose({
    ...proposal("metric-clock-v2", "2.0.0", "2026-02-01", 18),
    predecessorDefinitionVersionId: "metric-clock-v1"
  });
  assert.throws(
    () =>
      store.propose({
        ...proposal("metric-clock-fork", "3.0.0", "2026-03-01", 24),
        predecessorDefinitionVersionId: "metric-clock-v1"
      }),
    (error: unknown) => storeError(error, "CONFLICT")
  );
  const third = store.propose({
    ...proposal("metric-clock-v3", "3.0.0", "2026-03-01", 24),
    predecessorDefinitionVersionId: "metric-clock-v2",
    idempotencyKey: "propose-metric-clock-v3"
  });
  assert.equal(third.version.predecessorDefinitionVersionId, "metric-clock-v2");
  store.close();

  const regressing = new GovernedDefinitionV2Store(join(directory, "regressing.sqlite"), {
    clock: sequentialClock(
      "2026-08-12T12:00:00.000Z",
      "2026-08-12T11:59:00.000Z"
    )
  });
  const proposed = regressing.propose(proposal("metric-time-v1", "1.0.0", "2026-01-01", 12));
  assert.throws(
    () => transition(regressing, proposed, "validated", "checker-a", "time-validated"),
    /clock must not move backward/
  );
  assert.equal(regressing.get("tenant-a", "metric-time-v1")?.status, "proposed");
  regressing.close();
});

test("caller-supplied approval metadata is never retained as execution authority", () => {
  const { store } = fixture();
  const forged = store.propose(
    proposal("metric-forged", "1.0.0", "2026-01-01", 12, {
      status: "approved",
      proposedBy: "forged-maker",
      approvedBy: "forged-checker",
      approvedAt: "2099-01-01T00:00:00.000Z"
    })
  );
  assert.deepEqual((forged.version.document as { approval: unknown }).approval, {
    authority: "governed_definition_v2_lifecycle",
    status: "pending_durable_approval"
  });
  assert.equal(forged.approvalEvidence, null);
  const active = activate(store, forged, "real-checker", "forged");
  assert.deepEqual(active.approvalEvidence, {
    status: "approved",
    proposedBy: "maker-a",
    approvedBy: "real-checker",
    approvedAt: "2026-08-12T12:02:00.000Z",
    approvalEventHash: active.approvalEvidence?.approvalEventHash
  });
  assert.notEqual(active.approvalEvidence?.approvedBy, "forged-checker");
  store.close();
});

test("source and mapping inner lifecycle are neutralized and logical identities cannot alias", () => {
  const { store } = fixture();
  const source = createSourceContractV1(sourceContractInput());
  const governedSource = store.propose({
    tenantId: "tenant-a",
    definitionVersionId: "source-v1",
    definitionKey: "loan-tape",
    kind: "source_contract",
    semanticVersion: "1.0.0",
    effectiveFrom: "2026-01-01",
    document: source,
    proposedBy: "maker-a",
    idempotencyKey: "source-propose"
  });
  const storedSource = governedSource.version.document as Record<string, unknown>;
  assert.equal(storedSource.status, "proposed");
  assert.equal("approvedBy" in storedSource, false);
  assert.equal("approvedAt" in storedSource, false);
  assert.notEqual(storedSource.sourceContractHash, source.sourceContractHash);

  const mapping = createMappingSpecV2(mappingSpecInput(source));
  const governedMapping = store.propose({
    tenantId: "tenant-a",
    definitionVersionId: "mapping-v1",
    definitionKey: "loan-tape",
    kind: "mapping_spec",
    semanticVersion: "1.0.0",
    effectiveFrom: "2026-01-01",
    document: mapping,
    proposedBy: "maker-a",
    idempotencyKey: "mapping-propose"
  });
  const storedMapping = governedMapping.version.document as Record<string, unknown>;
  assert.equal(storedMapping.status, "proposed");
  assert.equal("approvedBy" in storedMapping, false);
  assert.equal("approvedAt" in storedMapping, false);
  assert.notEqual(storedMapping.mappingSpecHash, mapping.mappingSpecHash);

  assert.throws(
    () =>
      store.propose({
        tenantId: "tenant-a",
        definitionVersionId: "source-alias",
        definitionKey: "another-source",
        kind: "source_contract",
        semanticVersion: "1.0.0",
        effectiveFrom: "2026-01-01",
        document: source,
        proposedBy: "maker-a",
        idempotencyKey: "source-alias"
      }),
    /logical identity/
  );
  const metricAlias = proposal("metric-alias", "1.0.0", "2026-01-01", 12);
  assert.throws(
    () => store.propose({ ...metricAlias, definitionKey: "another-metric" }),
    /logical identity/
  );
  assert.throws(
    () =>
      createGovernedDefinitionVersionV2({
        contractVersion: 2,
        tenantId: "tenant-a",
        definitionVersionId: "metric-direct-alias",
        definitionKey: "another-metric",
        kind: "metric_definition",
        semanticVersion: "1.0.0",
        effectiveFrom: "2026-01-01",
        effectiveTo: null,
        predecessorDefinitionVersionId: null,
        rollbackTargetDefinitionVersionId: null,
        document: metricAlias.document,
        semanticDiff: computeSemanticDiffV1(null, metricAlias.document),
        impactPreview: {
          contractVersion: 1,
          impactLevel: "initial",
          affectedCapabilities: ["analytics", "monitoring"],
          changedPathCount: 1,
          rollbackTargetRequired: false
        },
        proposedBy: "maker-a",
        proposedAt: "2026-08-12T00:00:00.000Z"
      }),
    /logical identity/
  );
  store.close();
});

test("maker-checker, optimistic revision, actor-scoped idempotency, and tenant scope fail closed", () => {
  const { store } = fixture();
  const input = proposal("metric-guard", "1.0.0", "2026-01-01", 12);
  const proposed = store.propose(input);
  assert.equal(store.propose(input).version.versionHash, proposed.version.versionHash);
  assert.throws(
    () => store.propose({ ...input, injectedActor: "forged" } as never),
    (error: unknown) => storeError(error, "INVALID_INPUT")
  );
  for (const optionalField of [
    "effectiveTo",
    "predecessorDefinitionVersionId",
    "rollbackTargetDefinitionVersionId"
  ] as const) {
    assert.throws(
      () => store.propose({ ...input, [optionalField]: undefined }),
      (error: unknown) => storeError(error, "INVALID_INPUT")
    );
  }
  assert.throws(
    () => store.propose({ ...input, effectiveFrom: "2026-02-01" }),
    (error: unknown) => storeError(error, "IDEMPOTENCY_CONFLICT")
  );
  assert.throws(
    () =>
      store.transition({
        tenantId: "tenant-a",
        definitionVersionId: "metric-guard",
        toStatus: "validated",
        expectedRevision: 1,
        actor: "maker-a",
        idempotencyKey: "self-review"
      }),
    (error: unknown) => storeError(error, "MAKER_CHECKER_VIOLATION")
  );
  const validationRequest = {
    tenantId: "tenant-a",
    definitionVersionId: "metric-guard",
    toStatus: "validated" as const,
    expectedRevision: 1,
    actor: "checker-a",
    idempotencyKey: "guard-validate"
  };
  assert.throws(
    () => store.transition({ ...validationRequest, evidence: undefined }),
    (error: unknown) => storeError(error, "INVALID_INPUT")
  );
  const validated = store.transition(validationRequest);
  assert.throws(
    () =>
      store.transition({
        tenantId: "tenant-a",
        definitionVersionId: "metric-guard",
        toStatus: "approved",
        expectedRevision: 1,
        actor: "checker-a",
        idempotencyKey: "stale"
      }),
    (error: unknown) => storeError(error, "CONCURRENCY_CONFLICT")
  );
  assert.equal(store.get("tenant-b", "metric-guard"), undefined);
  assert.throws(
    () => store.selectEffective("tenant-b", "metric_definition", "roll-rate", "2026-08-12"),
    (error: unknown) => storeError(error, "NOT_FOUND")
  );
  assert.equal(validated.lifecycleRevision, 2);
  const approved = transition(store, validated, "approved", "checker-a", "guard-approve");
  const active = transition(store, approved, "active", "checker-a", "guard-active");
  assert.equal(active.status, "active");
  assert.deepEqual(
    { status: store.propose(input).status, revision: store.propose(input).lifecycleRevision },
    { status: "proposed", revision: 1 }
  );
  assert.deepEqual(
    {
      status: store.transition(validationRequest).status,
      revision: store.transition(validationRequest).lifecycleRevision
    },
    { status: "validated", revision: 2 }
  );
  store.close();
});

test("strict methodology, metric projection, and borrowing-base documents use durable authority", () => {
  const { store } = fixture();
  const methodology = store.propose({
    tenantId: "tenant-a",
    definitionVersionId: "methodology-v1",
    definitionKey: "surveillance-methodology",
    kind: "methodology_bundle",
    semanticVersion: "1.0.0",
    effectiveFrom: "2026-01-01",
    document: {
      contractVersion: 1,
      bundleKind: "methodology",
      bundleId: "surveillance-methodology",
      version: "1.0.0",
      name: "Portfolio surveillance",
      description: "Deterministic longitudinal portfolio surveillance methodology.",
      calculationEngine: {
        engineId: "surveillance-engine",
        engineVersion: "1.0.0",
        runtimeBundleHash: `sha256:${"a".repeat(64)}`
      },
      requiredDefinitionKinds: ["metric_definition", "bin_definition"],
      deterministicParameters: { maximumPeriods: 120 },
      approval: { status: "pending_durable_approval", authority: "governed_definition_v2_lifecycle" }
    },
    proposedBy: "maker-a",
    idempotencyKey: "methodology-propose"
  });
  assert.equal(methodology.version.kind, "methodology_bundle");
  assert.throws(
    () =>
      store.propose({
        tenantId: "tenant-a",
        definitionVersionId: "methodology-version-alias",
        definitionKey: "surveillance-methodology-alias",
        kind: "methodology_bundle",
        semanticVersion: "1.0.0",
        effectiveFrom: "2026-01-01",
        document: {
          ...(methodology.version.document as Record<string, unknown>),
          bundleId: "surveillance-methodology-alias",
          version: "9.9.9"
        } as never,
        proposedBy: "maker-a",
        idempotencyKey: "methodology-version-alias"
      }),
    /document version/
  );

  const projectionDocument = createMetricProjectionV1({
    contractVersion: 1,
    definitionType: "metric_projection",
    definitionId: "roll-rate-portfolio",
    version: "1.0.0",
    metricDefinitionId: "roll-rate",
    metricName: "roll-rate",
    exactDimensionSelectors: { delinquencyBand: "30-59" },
    observationDateDimension: "asOfDate",
    scope: { type: "portfolio", idSource: "fixed", fixedId: "portfolio-a" },
    measurement: { source: "value", type: "decimal", unit: "ratio" },
    requireAvailable: true,
    requireUnsuppressed: true,
    approval: {
      status: "pending_durable_approval",
      authority: "governed_definition_v2_lifecycle"
    }
  });
  const projection = store.propose({
    tenantId: "tenant-a",
    definitionVersionId: "projection-v1",
    definitionKey: "roll-rate-portfolio",
    kind: "metric_projection",
    semanticVersion: "1.0.0",
    effectiveFrom: "2026-01-01",
    document: projectionDocument,
    proposedBy: "maker-a",
    idempotencyKey: "projection-propose"
  });
  assert.equal(projection.version.kind, "metric_projection");
  assert.equal(
    (projection.version.document as { projectionHash: string }).projectionHash,
    projectionDocument.projectionHash
  );
  assert.throws(
    () =>
      store.propose({
        tenantId: "tenant-a",
        definitionVersionId: "projection-alias",
        definitionKey: "another-projection",
        kind: "metric_projection",
        semanticVersion: "1.0.0",
        effectiveFrom: "2026-01-01",
        document: projectionDocument,
        proposedBy: "maker-a",
        idempotencyKey: "projection-alias"
      }),
    /logical identity/
  );
  assert.throws(
    () =>
      store.propose({
        tenantId: "tenant-a",
        definitionVersionId: "projection-version-alias",
        definitionKey: "roll-rate-portfolio-v2",
        kind: "metric_projection",
        semanticVersion: "2.0.0",
        effectiveFrom: "2026-01-01",
        document: (() => {
          const { projectionHash: _projectionHash, ...projectionBody } = projectionDocument;
          return createMetricProjectionV1({
            ...projectionBody,
            definitionId: "roll-rate-portfolio-v2",
            version: "9.0.0"
          });
        })(),
        proposedBy: "maker-a",
        idempotencyKey: "projection-version-alias"
      }),
    /document version/
  );

  const policy = store.propose({
    tenantId: "tenant-a",
    definitionVersionId: "bb-policy-v1",
    definitionKey: "bb-policy",
    kind: "borrowing_base_policy_v2",
    semanticVersion: "1.0.0",
    effectiveFrom: "2026-01-01",
    document: borrowingBasePolicy(),
    proposedBy: "maker-a",
    idempotencyKey: "bb-propose"
  });
  assert.deepEqual((policy.version.document as { approval: unknown }).approval, {
    authority: "governed_definition_v2_lifecycle",
    status: "pending_durable_approval"
  });
  const storedPolicy = policy.version.document as { policyHash: string };
  assert.notEqual(storedPolicy.policyHash, "a".repeat(64));
  const { policyHash: _policyHash, approval: _approval, ...policyProjection } = policy.version.document as Record<string, unknown>;
  assert.equal(storedPolicy.policyHash, canonicalHash(policyProjection).slice("sha256:".length));
  assert.throws(
    () =>
      store.propose({
        tenantId: "tenant-b",
        definitionVersionId: "bb-policy-cross-tenant",
        definitionKey: "bb-policy",
        kind: "borrowing_base_policy_v2",
        semanticVersion: "1.0.0",
        effectiveFrom: "2026-01-01",
        document: borrowingBasePolicy(),
        proposedBy: "maker-b",
        idempotencyKey: "bb-cross-tenant"
      }),
    /tenant/
  );
  assert.throws(
    () =>
      store.propose({
        tenantId: "tenant-a",
        definitionVersionId: "bb-policy-effectivity-alias",
        definitionKey: "bb-policy",
        kind: "borrowing_base_policy_v2",
        semanticVersion: "1.0.0",
        effectiveFrom: "2026-02-01",
        document: borrowingBasePolicy(),
        proposedBy: "maker-a",
        idempotencyKey: "bb-effectivity-alias"
      }),
    /effectivity/
  );
  assert.throws(
    () =>
      store.propose({
        tenantId: "tenant-a",
        definitionVersionId: "source-effectivity-alias",
        definitionKey: "loan-tape",
        kind: "source_contract",
        semanticVersion: "1.0.0",
        effectiveFrom: "2026-02-01",
        document: createSourceContractV1(sourceContractInput()),
        proposedBy: "maker-a",
        idempotencyKey: "source-effectivity-alias"
      }),
    /effectivity/
  );
  store.close();
});

test("governed decimal controls are canonical magnitudes", () => {
  const reconciliation = {
    schemaVersion: "1",
    definitionType: "reconciliation_definition",
    definitionId: "portfolio-tie-out",
    version: 1,
    name: "Portfolio tie-out",
    segments: ["facility"],
    controls: [
      {
        controlId: "balance",
        measure: "balance",
        tolerance: "0",
        materialityThreshold: "1.5"
      }
    ],
    approval: {
      status: "pending_durable_approval",
      authority: "governed_definition_v2_lifecycle"
    }
  } as const;
  assert.doesNotThrow(() => ReconciliationDefinitionV1Schema.parse(reconciliation));
  for (const invalidValue of ["-1", "-0", "1.00"] as const) {
    assert.throws(() =>
      ReconciliationDefinitionV1Schema.parse({
        ...reconciliation,
        controls: [
          {
            ...reconciliation.controls[0],
            tolerance: invalidValue
          }
        ]
      })
    );
  }
});

test("v2 component coexists with v1 rows and attests immutable schema on reopen", () => {
  const directory = mkdtempSync(join(tmpdir(), "abl-governed-definition-v2-coexist-"));
  directories.push(directory);
  const databasePath = join(directory, "control.sqlite");
  const v1 = new DefinitionStore(databasePath);
  v1.propose({
    tenantId: "tenant-a",
    definitionId: "legacy-v1",
    definitionKey: "legacy",
    kind: "stratification_recipe",
    version: "1.0.0",
    effectiveFrom: "2026-01-01",
    document: { dimension: "risk_grade" },
    proposedBy: "maker-a",
    idempotencyKey: "legacy-propose"
  });
  v1.close();
  const v2 = new GovernedDefinitionV2Store(databasePath);
  v2.propose(proposal("metric-coexist", "1.0.0", "2026-01-01", 12));
  v2.close();
  new GovernedDefinitionV2Store(databasePath).close();

  const database = new DatabaseSync(databasePath);
  assert.equal((database.prepare("SELECT COUNT(*) AS count FROM governed_definitions").get() as { count: number }).count, 1);
  assert.equal((database.prepare("SELECT COUNT(*) AS count FROM governed_definition_v2_versions").get() as { count: number }).count, 1);
  assert.equal(
    (database.prepare("SELECT schema_version FROM component_schema_versions WHERE component_name = ?").get(GOVERNED_DEFINITION_V2_STORE_COMPONENT) as { schema_version: number }).schema_version,
    GOVERNED_DEFINITION_V2_STORE_SCHEMA_VERSION
  );
  assert.throws(
    () => database.prepare("UPDATE governed_definition_v2_versions SET document_json = '{}' ").run(),
    /immutable/
  );
  database.close();
});

test("the shipped schema-v1 event history migrates atomically before withdrawal is used", () => {
  const directory = mkdtempSync(join(tmpdir(), "abl-governed-definition-v2-migration-"));
  directories.push(directory);
  const databasePath = join(directory, "control.sqlite");
  let clockIndex = 0;
  const clock = () => new Date(TIMES[clockIndex++] ?? "2026-08-12T13:00:00.000Z");
  const initial = new GovernedDefinitionV2Store(databasePath, { clock });
  const proposed = initial.propose(proposal("metric-migrate-v1", "1.0.0", "2026-01-01", 12));
  const validated = transition(initial, proposed, "validated", "checker-a", "migrate-v1-validate");
  const approved = transition(initial, validated, "approved", "checker-a", "migrate-v1-approve");
  const before = initial.listAuditEvents("tenant-a");
  initial.close();

  downgradeGovernedDefinitionEventsToShippedV1(databasePath);
  const sequenceDatabase = new DatabaseSync(databasePath);
  const sequenceUpdate = sequenceDatabase
    .prepare("UPDATE sqlite_sequence SET seq = 40 WHERE name = 'governed_definition_v2_events'")
    .run();
  assert.equal(sequenceUpdate.changes, 1);
  sequenceDatabase.close();

  const migrated = new GovernedDefinitionV2Store(databasePath, { clock });
  assert.deepEqual(migrated.listAuditEvents("tenant-a"), before);
  const withdrawn = migrated.transition({
    tenantId: "tenant-a",
    definitionVersionId: approved.version.definitionVersionId,
    toStatus: "withdrawn",
    expectedRevision: approved.lifecycleRevision,
    actor: "checker-b",
    evidence: { reason: "abandoned after migration" },
    idempotencyKey: "migrate-v1-withdraw"
  });
  assert.equal(withdrawn.status, "withdrawn");
  assert.equal(migrated.listAuditEvents("tenant-a").at(-1)?.sequence, 41);
  migrated.close();

  const database = new DatabaseSync(databasePath);
  assert.equal(
    (database.prepare("SELECT schema_version FROM component_schema_versions WHERE component_name = ?").get(GOVERNED_DEFINITION_V2_STORE_COMPONENT) as { schema_version: number }).schema_version,
    GOVERNED_DEFINITION_V2_STORE_SCHEMA_VERSION
  );
  const eventSql = (database.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'governed_definition_v2_events'").get() as { sql: string }).sql;
  assert.match(eventSql, /'withdrawn'/);
  assert.equal(
    (database.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'governed_definition_v2_events'").get() as { seq: number }).seq,
    41
  );
  assert.throws(
    () => database.prepare("UPDATE governed_definition_v2_events SET actor = 'tamper'").run(),
    /append-only/
  );
  database.close();
});

test("the exact shipped schema-v2 kind constraint migrates to v3 without rewriting evidence", () => {
  const directory = mkdtempSync(join(tmpdir(), "abl-governed-definition-v3-migration-"));
  directories.push(directory);
  const databasePath = join(directory, "control.sqlite");
  let clockIndex = 0;
  const clock = () => new Date(TIMES[clockIndex++] ?? "2026-08-12T13:00:00.000Z");
  const initial = new GovernedDefinitionV2Store(databasePath, { clock });
  const request = proposal("metric-migrate-v2", "1.0.0", "2026-01-01", 12);
  const proposed = initial.propose(request);
  const validated = transition(initial, proposed, "validated", "checker-a", "migrate-v2-validate");
  const approved = transition(initial, validated, "approved", "checker-a", "migrate-v2-approve");
  const beforeEvents = initial.listAuditEvents("tenant-a");
  const beforeVersionHash = approved.version.versionHash;
  initial.close();

  downgradeGovernedDefinitionVersionsToShippedV2(databasePath);
  const sequenceDatabase = new DatabaseSync(databasePath);
  const sequenceUpdate = sequenceDatabase
    .prepare("UPDATE sqlite_sequence SET seq = 70 WHERE name = 'governed_definition_v2_events'")
    .run();
  assert.equal(sequenceUpdate.changes, 1);
  sequenceDatabase.close();

  const migrated = new GovernedDefinitionV2Store(databasePath, { clock });
  assert.deepEqual(migrated.listAuditEvents("tenant-a"), beforeEvents);
  assert.equal(migrated.get("tenant-a", approved.version.definitionVersionId)?.version.versionHash, beforeVersionHash);
  assert.equal(migrated.propose(request).version.versionHash, beforeVersionHash);
  const withdrawn = migrated.transition({
    tenantId: "tenant-a",
    definitionVersionId: approved.version.definitionVersionId,
    toStatus: "withdrawn",
    expectedRevision: approved.lifecycleRevision,
    actor: "checker-b",
    evidence: { reason: "v2 migration high-water check" },
    idempotencyKey: "migrate-v2-withdraw"
  });
  assert.equal(withdrawn.status, "withdrawn");
  assert.equal(migrated.listAuditEvents("tenant-a").at(-1)?.sequence, 71);
  migrated.close();

  const database = new DatabaseSync(databasePath);
  assert.equal(
    (database.prepare("SELECT schema_version FROM component_schema_versions WHERE component_name = ?").get(GOVERNED_DEFINITION_V2_STORE_COMPONENT) as { schema_version: number }).schema_version,
    GOVERNED_DEFINITION_V2_STORE_SCHEMA_VERSION
  );
  const versionsSql = (database.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'governed_definition_v2_versions'").get() as { sql: string }).sql;
  assert.match(versionsSql, /'source_access_policy'/);
  assert.equal(
    (database.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'governed_definition_v2_events'").get() as { seq: number }).seq,
    71
  );
  assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), []);
  database.close();
});

function downgradeGovernedDefinitionEventsToShippedV1(databasePath: string): void {
  const database = new DatabaseSync(databasePath);
  database.exec(`
    PRAGMA foreign_keys = ON;
    BEGIN IMMEDIATE;
    DROP TRIGGER governed_definition_v2_idempotency_no_update;
    DROP TRIGGER governed_definition_v2_idempotency_no_delete;
    ALTER TABLE governed_definition_v2_idempotency RENAME TO governed_definition_v2_idempotency_v3;
    DROP TRIGGER governed_definition_v2_events_no_update;
    DROP TRIGGER governed_definition_v2_events_no_delete;
    DROP INDEX governed_definition_v2_events_tenant_sequence;
    ALTER TABLE governed_definition_v2_events RENAME TO governed_definition_v2_events_v2;
    DROP TRIGGER governed_definition_v2_versions_no_update;
    DROP TRIGGER governed_definition_v2_versions_no_delete;
    DROP INDEX governed_definition_v2_key;
    ALTER TABLE governed_definition_v2_versions RENAME TO governed_definition_v2_versions_v3;
    CREATE TABLE governed_definition_v2_versions (
      tenant_id TEXT NOT NULL,
      definition_version_id TEXT NOT NULL,
      definition_key TEXT NOT NULL,
      kind TEXT NOT NULL CHECK (kind IN (
        'source_contract','mapping_spec','methodology_bundle','borrowing_base_policy_v2',
        'metric_definition','metric_projection','cohort_definition','bin_definition',
        'reconciliation_definition','entity_resolution_definition','report_definition',
        'scenario_definition','covenant_definition'
      )),
      semantic_version TEXT NOT NULL,
      effective_from TEXT NOT NULL,
      effective_to TEXT,
      predecessor_definition_version_id TEXT,
      rollback_target_definition_version_id TEXT,
      document_json TEXT NOT NULL,
      document_hash TEXT NOT NULL CHECK (document_hash GLOB 'sha256:[0-9a-f]*' AND length(document_hash) = 71),
      semantic_diff_json TEXT NOT NULL,
      semantic_diff_hash TEXT NOT NULL CHECK (semantic_diff_hash GLOB 'sha256:[0-9a-f]*' AND length(semantic_diff_hash) = 71),
      impact_preview_json TEXT NOT NULL,
      impact_preview_hash TEXT NOT NULL CHECK (impact_preview_hash GLOB 'sha256:[0-9a-f]*' AND length(impact_preview_hash) = 71),
      proposed_by TEXT NOT NULL,
      proposed_at TEXT NOT NULL,
      version_hash TEXT NOT NULL CHECK (version_hash GLOB 'sha256:[0-9a-f]*' AND length(version_hash) = 71),
      PRIMARY KEY (tenant_id, definition_version_id),
      UNIQUE (tenant_id, kind, definition_key, semantic_version),
      FOREIGN KEY (tenant_id, predecessor_definition_version_id)
        REFERENCES governed_definition_v2_versions (tenant_id, definition_version_id),
      FOREIGN KEY (tenant_id, rollback_target_definition_version_id)
        REFERENCES governed_definition_v2_versions (tenant_id, definition_version_id)
    ) STRICT;
    INSERT INTO governed_definition_v2_versions
    SELECT * FROM governed_definition_v2_versions_v3;
    CREATE INDEX governed_definition_v2_key
      ON governed_definition_v2_versions (tenant_id, kind, definition_key, effective_from);
    CREATE TRIGGER governed_definition_v2_versions_no_update
    BEFORE UPDATE ON governed_definition_v2_versions
    BEGIN SELECT RAISE(ABORT, 'governed definition v2 versions are immutable'); END;
    CREATE TRIGGER governed_definition_v2_versions_no_delete
    BEFORE DELETE ON governed_definition_v2_versions
    BEGIN SELECT RAISE(ABORT, 'governed definition v2 versions are immutable'); END;
    CREATE TABLE governed_definition_v2_events (
      sequence INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL,
      event_id TEXT NOT NULL UNIQUE,
      definition_version_id TEXT NOT NULL,
      lifecycle_revision INTEGER NOT NULL CHECK (lifecycle_revision > 0),
      from_status TEXT CHECK (from_status IS NULL OR from_status IN (
        'proposed','validated','approved','active','superseded','retired'
      )),
      to_status TEXT NOT NULL CHECK (to_status IN (
        'proposed','validated','approved','active','superseded','retired'
      )),
      actor TEXT NOT NULL,
      evidence_json TEXT NOT NULL,
      occurred_at TEXT NOT NULL,
      previous_event_hash TEXT CHECK (
        previous_event_hash IS NULL OR
        (previous_event_hash GLOB 'sha256:[0-9a-f]*' AND length(previous_event_hash) = 71)
      ),
      event_hash TEXT NOT NULL CHECK (event_hash GLOB 'sha256:[0-9a-f]*' AND length(event_hash) = 71),
      UNIQUE (tenant_id, definition_version_id, lifecycle_revision),
      FOREIGN KEY (tenant_id, definition_version_id)
        REFERENCES governed_definition_v2_versions (tenant_id, definition_version_id)
    ) STRICT;
    INSERT INTO governed_definition_v2_events (
      sequence, tenant_id, event_id, definition_version_id, lifecycle_revision,
      from_status, to_status, actor, evidence_json, occurred_at,
      previous_event_hash, event_hash
    )
    SELECT sequence, tenant_id, event_id, definition_version_id, lifecycle_revision,
           from_status, to_status, actor, evidence_json, occurred_at,
           previous_event_hash, event_hash
      FROM governed_definition_v2_events_v2
     ORDER BY sequence;
    DROP TABLE governed_definition_v2_events_v2;
    CREATE INDEX governed_definition_v2_events_tenant_sequence
      ON governed_definition_v2_events (tenant_id, sequence);
    CREATE TRIGGER governed_definition_v2_events_no_update
    BEFORE UPDATE ON governed_definition_v2_events
    BEGIN SELECT RAISE(ABORT, 'governed definition v2 events are append-only'); END;
    CREATE TRIGGER governed_definition_v2_events_no_delete
    BEFORE DELETE ON governed_definition_v2_events
    BEGIN SELECT RAISE(ABORT, 'governed definition v2 events are append-only'); END;
    CREATE TABLE governed_definition_v2_idempotency (
      tenant_id TEXT NOT NULL,
      operation TEXT NOT NULL,
      actor TEXT NOT NULL,
      idempotency_key TEXT NOT NULL,
      request_hash TEXT NOT NULL CHECK (request_hash GLOB 'sha256:[0-9a-f]*' AND length(request_hash) = 71),
      definition_version_id TEXT NOT NULL,
      response_revision INTEGER NOT NULL CHECK (response_revision > 0),
      created_at TEXT NOT NULL,
      PRIMARY KEY (tenant_id, operation, actor, idempotency_key),
      FOREIGN KEY (tenant_id, definition_version_id)
        REFERENCES governed_definition_v2_versions (tenant_id, definition_version_id)
    ) STRICT;
    INSERT INTO governed_definition_v2_idempotency
    SELECT * FROM governed_definition_v2_idempotency_v3;
    CREATE TRIGGER governed_definition_v2_idempotency_no_update
    BEFORE UPDATE ON governed_definition_v2_idempotency
    BEGIN SELECT RAISE(ABORT, 'governed definition v2 idempotency is immutable'); END;
    CREATE TRIGGER governed_definition_v2_idempotency_no_delete
    BEFORE DELETE ON governed_definition_v2_idempotency
    BEGIN SELECT RAISE(ABORT, 'governed definition v2 idempotency is immutable'); END;
    DROP TABLE governed_definition_v2_idempotency_v3;
    DROP TABLE governed_definition_v2_versions_v3;
    UPDATE component_schema_versions
       SET schema_version = 1
     WHERE component_name = '${GOVERNED_DEFINITION_V2_STORE_COMPONENT}';
    COMMIT;
  `);
  database.close();
}

function downgradeGovernedDefinitionVersionsToShippedV2(databasePath: string): void {
  const database = new DatabaseSync(databasePath);
  const sql = (type: "table" | "index" | "trigger", name: string): string => {
    const row = database
      .prepare("SELECT sql FROM sqlite_master WHERE type = ? AND name = ?")
      .get(type, name) as { readonly sql: string } | undefined;
    assert.ok(row?.sql, `${type} ${name}`);
    return row.sql;
  };
  const versionTableSql = sql("table", "governed_definition_v2_versions").replace(
    ",'source_access_policy'",
    ""
  );
  assert.equal(versionTableSql.includes("source_access_policy"), false);
  const eventTableSql = sql("table", "governed_definition_v2_events");
  const idempotencyTableSql = sql("table", "governed_definition_v2_idempotency");
  const versionIndexSql = sql("index", "governed_definition_v2_key");
  const eventIndexSql = sql("index", "governed_definition_v2_events_tenant_sequence");
  const versionUpdateTriggerSql = sql("trigger", "governed_definition_v2_versions_no_update");
  const versionDeleteTriggerSql = sql("trigger", "governed_definition_v2_versions_no_delete");
  const eventUpdateTriggerSql = sql("trigger", "governed_definition_v2_events_no_update");
  const eventDeleteTriggerSql = sql("trigger", "governed_definition_v2_events_no_delete");
  const idempotencyUpdateTriggerSql = sql("trigger", "governed_definition_v2_idempotency_no_update");
  const idempotencyDeleteTriggerSql = sql("trigger", "governed_definition_v2_idempotency_no_delete");
  database.exec(`
    PRAGMA foreign_keys = OFF;
    BEGIN IMMEDIATE;
    DROP TRIGGER governed_definition_v2_idempotency_no_update;
    DROP TRIGGER governed_definition_v2_idempotency_no_delete;
    ALTER TABLE governed_definition_v2_idempotency RENAME TO governed_definition_v2_idempotency_v3;
    DROP TRIGGER governed_definition_v2_events_no_update;
    DROP TRIGGER governed_definition_v2_events_no_delete;
    DROP INDEX governed_definition_v2_events_tenant_sequence;
    ALTER TABLE governed_definition_v2_events RENAME TO governed_definition_v2_events_v3;
    DROP TRIGGER governed_definition_v2_versions_no_update;
    DROP TRIGGER governed_definition_v2_versions_no_delete;
    DROP INDEX governed_definition_v2_key;
    ALTER TABLE governed_definition_v2_versions RENAME TO governed_definition_v2_versions_v3;

    ${versionTableSql};
    INSERT INTO governed_definition_v2_versions SELECT * FROM governed_definition_v2_versions_v3;
    ${versionIndexSql};
    ${versionUpdateTriggerSql};
    ${versionDeleteTriggerSql};

    ${eventTableSql};
    INSERT INTO governed_definition_v2_events SELECT * FROM governed_definition_v2_events_v3 ORDER BY sequence;
    UPDATE sqlite_sequence
       SET seq = MAX(
         seq,
         COALESCE(
           (SELECT prior.seq FROM sqlite_sequence AS prior
             WHERE prior.name = 'governed_definition_v2_events_v3'),
           seq
         )
       )
     WHERE name = 'governed_definition_v2_events';
    ${eventIndexSql};
    ${eventUpdateTriggerSql};
    ${eventDeleteTriggerSql};

    ${idempotencyTableSql};
    INSERT INTO governed_definition_v2_idempotency SELECT * FROM governed_definition_v2_idempotency_v3;
    ${idempotencyUpdateTriggerSql};
    ${idempotencyDeleteTriggerSql};

    DROP TABLE governed_definition_v2_idempotency_v3;
    DROP TABLE governed_definition_v2_events_v3;
    DROP TABLE governed_definition_v2_versions_v3;
    UPDATE component_schema_versions
       SET schema_version = 2
     WHERE component_name = '${GOVERNED_DEFINITION_V2_STORE_COMPONENT}';
    COMMIT;
    PRAGMA foreign_keys = ON;
  `);
  assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), []);
  database.close();
}

function fixture(): { store: GovernedDefinitionV2Store } {
  const directory = mkdtempSync(join(tmpdir(), "abl-governed-definition-v2-"));
  directories.push(directory);
  let index = 0;
  return {
    store: new GovernedDefinitionV2Store(join(directory, "control.sqlite"), {
      clock: () => new Date(TIMES[index++] ?? "2026-08-12T13:00:00.000Z")
    })
  };
}

function proposal(
  definitionVersionId: string,
  semanticVersion: string,
  effectiveFrom: string,
  maximumCells: number,
  approval: unknown = {
    status: "pending_durable_approval",
    authority: "governed_definition_v2_lifecycle"
  }
) {
  return {
    tenantId: "tenant-a",
    definitionVersionId,
    definitionKey: "roll-rate",
    kind: "metric_definition" as const,
    semanticVersion,
    effectiveFrom,
    document: {
      schemaVersion: "1",
      definitionType: "metric_definition",
      definitionId: "roll-rate",
      version: Number(semanticVersion.split(".")[0]),
      name: "Roll rate",
      family: "roll_cure",
      grain: "loan",
      unit: "ratio",
      temporalSemantics: "transition",
      numerator: { label: "Transitioning", aggregation: "sum", field: "outstanding_balance" },
      denominator: { label: "Opening", aggregation: "sum", field: "outstanding_balance" },
      window: { kind: "adjacent_periods", maximumPeriods: 12 },
      population: null,
      nullPolicy: "unavailable",
      coverage: { minimumRatio: "0.95", minimumObservedRecords: 1 },
      privacy: { minimumCellCount: 3, complementarySuppression: true },
      maximumCells,
      configuration: {
        kind: "roll_cure",
        delinquencyField: "days_past_due",
        balanceField: "outstanding_balance",
        binDefinitionId: "dpd-bands"
      },
      approval
    },
    proposedBy: "maker-a",
    idempotencyKey: `propose-${definitionVersionId}`
  };
}

function activate(
  store: GovernedDefinitionV2Store,
  start: GovernedDefinitionViewV2,
  actor: string,
  suffix: string
): GovernedDefinitionViewV2 {
  let current = start;
  for (const status of ["validated", "approved", "active"] as const) {
    current = transition(store, current, status, actor, `${suffix}-${status}`);
  }
  return current;
}

function transition(
  store: GovernedDefinitionV2Store,
  current: GovernedDefinitionViewV2,
  toStatus: "validated" | "approved" | "active",
  actor: string,
  idempotencyKey: string
): GovernedDefinitionViewV2 {
  return store.transition({
    tenantId: current.version.tenantId,
    definitionVersionId: current.version.definitionVersionId,
    toStatus,
    expectedRevision: current.lifecycleRevision,
    actor,
    idempotencyKey
  });
}

function storeError(error: unknown, code: GovernedDefinitionV2StoreError["code"]): boolean {
  return error instanceof GovernedDefinitionV2StoreError && error.code === code;
}

function sequentialClock(...timestamps: readonly string[]): () => Date {
  let index = 0;
  return () => new Date(timestamps[index++] ?? timestamps.at(-1)!);
}

function borrowingBasePolicy() {
  return {
    schemaVersion: "2",
    policyId: "bb-policy",
    version: "1",
    policyHash: "a".repeat(64),
    tenantId: "tenant-a",
    facilityId: "facility-a",
    currencyCode: "USD",
    effectiveFrom: "2026-01-01",
    commitmentAmount: "1000",
    components: [
      {
        componentId: "ar",
        collateralClass: "accounts_receivable",
        valueBasis: "eligible_amount",
        advanceRate: "0.85"
      }
    ],
    reserves: [],
    triggers: [],
    ticklerWarningDays: 30,
    approval: {
      status: "approved",
      proposedBy: "forged-maker",
      approvedBy: "forged-checker",
      approvedAt: "2099-01-01T00:00:00.000Z",
      authorityRef: "forged-authority",
      rationale: "Caller supplied and therefore not authoritative"
    }
  };
}

function sourceContractInput() {
  return {
    contractVersion: 1 as const,
    tenantId: "tenant-a",
    sourceContractId: "loan-tape-postgres-v1",
    sourceKey: "loan-tape",
    revision: 1,
    status: "active" as const,
    delivery: {
      mode: "managed_upload" as const,
      format: "parquet" as const,
      logicalName: "loan-tape.parquet"
    },
    schemaPolicy: {
      columns: [{ sourceName: "loan_id", ordinal: 0, nativeType: "string", nullable: false, required: true }],
      allowUnknownColumns: false,
      requireStableOrdinals: true
    },
    parserPolicy: {
      format: "parquet" as const,
      parserId: "parquet-v1",
      parserVersion: "1.0.0",
      optionsHash: `sha256:${"a".repeat(64)}` as const,
      exactDecimalMode: "string" as const,
      timezone: "UTC" as const,
      rejectSchemaMerging: true
    },
    extractionPolicy: {
      mode: "full" as const,
      readOnly: true as const,
      maximumRows: 1_000,
      maximumColumns: 100,
      maximumBytes: 1_000_000,
      timeoutMs: 1_000,
      cursorRows: 100
    },
    sections: [{ sectionId: "loans", required: true, selector: "loans", keyFields: ["loan_id"] }],
    effectiveFrom: "2026-01-01",
    createdBy: "forged-maker",
    createdAt: "2026-08-12T00:00:00.000Z",
    approvedBy: "forged-checker",
    approvedAt: "2026-08-12T01:00:00.000Z"
  };
}

function mappingSpecInput(source: ReturnType<typeof createSourceContractV1>) {
  return {
    contractVersion: 2 as const,
    tenantId: "tenant-a",
    mappingSpecId: "loan-tape-mapping-v1",
    mappingKey: "loan-tape",
    revision: 1,
    status: "active" as const,
    sourceContract: {
      sourceContractId: source.sourceContractId,
      revision: source.revision,
      sourceContractHash: source.sourceContractHash
    },
    dictionaryBundle: {
      contractVersion: 1 as const,
      bundleKind: "dictionary" as const,
      bundleId: "dictionary-core",
      version: "1.0.0",
      contentHash: `sha256:${"b".repeat(64)}` as const,
      artifactId: "dictionary-artifact",
      mediaType: "application/json",
      createdAt: "2026-08-12T00:00:00.000Z",
      dictionaryVersion: "1.0.0",
      dictionaryHash: `sha256:${"c".repeat(64)}` as const,
      fieldPolicyVersion: "1.0.0",
      fieldPolicyHash: `sha256:${"d".repeat(64)}` as const
    },
    rules: [
      {
        ruleId: "loan-id",
        canonicalField: "loan_id",
        expression: { op: "source" as const, column: "loan_id" },
        onError: "fail_application" as const
      }
    ],
    requiredCanonicalFields: ["loan_id"],
    createdBy: "forged-maker",
    createdAt: "2026-08-12T00:00:00.000Z",
    approvedBy: "forged-checker",
    approvedAt: "2026-08-12T01:00:00.000Z"
  };
}
