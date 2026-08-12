import assert from "node:assert/strict";
import { test } from "node:test";

import {
  PIPELINE_STAGES,
  PipelineStore,
  PipelineStoreError,
  type PipelineRunV1
} from "../src/control/pipelines.js";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);

function createClock(start = "2026-01-01T00:00:00.000Z") {
  let now = new Date(start);
  return {
    clock: () => new Date(now),
    advance(milliseconds: number) {
      now = new Date(now.getTime() + milliseconds);
    }
  };
}

function createRun(store: PipelineStore, suffix = "one", overrides: Partial<Parameters<PipelineStore["createRun"]>[0]> = {}) {
  return store.createRun({
    tenantId: "tenant-a",
    pipelineDefinitionId: "daily-surveillance",
    pipelineDefinitionVersion: "1.0.0",
    sourceContractId: "loan-tape-v2",
    requestedBy: "principal-a",
    idempotencyKey: `create-${suffix}`,
    deliveryMode: "full",
    deliveryReference: `s3-version-${suffix}`,
    ...overrides
  });
}

function runStage(store: PipelineStore, run: PipelineRunV1, stage: (typeof PIPELINE_STAGES)[number]) {
  const attempt = store.startStage({
    tenantId: run.tenantId,
    runId: run.runId,
    workerId: "worker-a",
    idempotencyKey: `start-${stage}`
  });
  assert.equal(attempt.stage, stage);
  return store.completeStage({
    tenantId: run.tenantId,
    runId: run.runId,
    stage,
    attempt: attempt.attempt,
    workerId: "worker-a",
    idempotencyKey: `complete-${stage}`,
    evidenceHash: HASH_A,
    ...(stage === "extract" ? { snapshotId: "snapshot-a" } : {}),
    ...(stage === "certify" ? { certificationManifestId: "cert-a" } : {}),
    ...(stage === "monitor" ? {
      outbox: [{
        kind: "notification" as const,
        eventType: "monitor.triggered",
        destinationRef: "destination-risk-team",
        templateRef: "template-monitor-v2",
        payload: { monitorId: "delinquency-spike", severity: "high" }
      }]
    } : {})
  });
}

test("pipeline advances in order, gates certification, and atomically publishes governed outbox references", () => {
  const store = new PipelineStore(":memory:");
  try {
    let run = createRun(store);
    for (const stage of PIPELINE_STAGES) run = runStage(store, run, stage);
    assert.equal(run.status, "succeeded");
    assert.equal(run.currentStage, null);
    assert.equal(run.snapshotId, "snapshot-a");
    assert.equal(run.certificationManifestId, "cert-a");
    assert.equal(store.listStageAttempts("tenant-a", run.runId).length, 10);
    const [message] = store.listOutbox("tenant-a", run.runId);
    assert.equal(message?.destinationRef, "destination-risk-team");
    assert.equal(message?.templateRef, "template-monitor-v2");
    assert.equal(message?.status, "pending");

    const claimed = store.claimOutbox("tenant-a", "dispatcher-a", 30);
    assert.equal(claimed?.messageId, message?.messageId);
    const delivered = store.acknowledgeOutbox(
      "tenant-a",
      claimed!.messageId,
      "dispatcher-a",
      claimed!.claimToken,
      HASH_B
    );
    assert.equal(delivered.status, "delivered");
    assert.equal(delivered.receiptHash, HASH_B);
  } finally {
    store.close();
  }
});

test("failed data-trust gates cannot reach analysis, monitoring, report, or notification delivery", () => {
  const store = new PipelineStore(":memory:");
  try {
    let run = createRun(store, "blocked");
    for (const stage of ["detect", "extract", "profile", "map"] as const) run = runStage(store, run, stage);
    const attempt = store.startStage({
      tenantId: "tenant-a",
      runId: run.runId,
      workerId: "worker-a",
      idempotencyKey: "start-dq-blocked"
    });
    run = store.failStage({
      tenantId: "tenant-a",
      runId: run.runId,
      stage: "dq",
      attempt: attempt.attempt,
      workerId: "worker-a",
      idempotencyKey: "fail-dq",
      errorCode: "MATERIAL_DRIFT",
      retryable: false
    });
    assert.equal(run.status, "blocked");
    assert.equal(store.listOutbox("tenant-a", run.runId).length, 0);
    assert.throws(
      () => store.startStage({
        tenantId: "tenant-a",
        runId: run.runId,
        workerId: "worker-a",
        idempotencyKey: "cannot-continue"
      }),
      (error: unknown) => error instanceof PipelineStoreError && error.code === "INVALID_TRANSITION"
    );
  } finally {
    store.close();
  }
});

test("corrections link to succeeded runs and delivery selectors cannot originate in payload data", () => {
  const store = new PipelineStore(":memory:");
  try {
    let original = createRun(store, "original");
    for (const stage of PIPELINE_STAGES) original = runStage(store, original, stage);
    const correction = createRun(store, "correction", {
      deliveryMode: "correction",
      supersedesRunId: original.runId,
      deliveryReference: "immutable-version-2"
    });
    assert.equal(correction.supersedesRunId, original.runId);
    const attempt = store.startStage({
      tenantId: "tenant-a",
      runId: correction.runId,
      workerId: "worker-b",
      idempotencyKey: "start-correction"
    });
    assert.throws(
      () => store.completeStage({
        tenantId: "tenant-a",
        runId: correction.runId,
        stage: "detect",
        attempt: attempt.attempt,
        workerId: "worker-b",
        idempotencyKey: "unsafe-outbox",
        evidenceHash: HASH_A,
        outbox: [{
          kind: "notification",
          eventType: "delivery.detected",
          destinationRef: "approved-ref",
          templateRef: "approved-template",
          payload: { callbackUrl: "https://portfolio-data.invalid/exfiltrate" }
        }]
      }),
      (error: unknown) => error instanceof PipelineStoreError && error.code === "INVALID_INPUT"
    );
    assert.equal(store.getRun("tenant-a", correction.runId).status, "running");
    assert.equal(store.listOutbox("tenant-a", correction.runId).length, 0);
  } finally {
    store.close();
  }
});

test("outbox leases retry safely and exact idempotency rejects changed stage evidence", () => {
  const time = createClock();
  const store = new PipelineStore(":memory:", { clock: time.clock });
  try {
    const run = createRun(store, "retry");
    const attempt = store.startStage({ tenantId: "tenant-a", runId: run.runId, workerId: "worker-a", idempotencyKey: "start" });
    const complete = {
      tenantId: "tenant-a",
      runId: run.runId,
      stage: "detect" as const,
      attempt: attempt.attempt,
      workerId: "worker-a",
      idempotencyKey: "complete",
      evidenceHash: HASH_A,
      outbox: [{ kind: "audit" as const, eventType: "delivery.detected", payload: { sourceContractId: "loan-tape-v2" } }]
    };
    store.completeStage(complete);
    assert.equal(store.completeStage(complete).currentStage, "extract");
    assert.throws(
      () => store.completeStage({ ...complete, evidenceHash: HASH_B }),
      (error: unknown) => error instanceof PipelineStoreError && error.code === "IDEMPOTENCY_CONFLICT"
    );
    const first = store.claimOutbox("tenant-a", "dispatcher-a", 5)!;
    time.advance(6_000);
    const second = store.claimOutbox("tenant-a", "dispatcher-b", 5)!;
    assert.equal(second.messageId, first.messageId);
    assert.equal(second.attemptCount, 2);
    assert.throws(
      () => store.acknowledgeOutbox("tenant-a", first.messageId, "dispatcher-a", first.claimToken, HASH_A),
      (error: unknown) => error instanceof PipelineStoreError && error.code === "CLAIM_REJECTED"
    );
  } finally {
    store.close();
  }
});
