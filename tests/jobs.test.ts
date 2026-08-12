import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import { JobStore, JobStoreError } from "../src/control/jobs.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "abl-jobs-"));
  directories.push(directory);
  let now = new Date("2026-08-11T12:00:00.000Z");
  const store = new JobStore(join(directory, "jobs.sqlite"), { clock: () => now });
  return {
    store,
    advance(seconds: number) {
      now = new Date(now.getTime() + seconds * 1_000);
    }
  };
}

test("submission is durable, canonical and idempotent", () => {
  const { store } = fixture();
  const first = store.submit({
    tenantId: "tenant-a",
    requestedBy: "principal-a",
    idempotencyKey: "request-1",
    toolName: "analysis.run_stratification",
    datasetId: "snapshot-1",
    request: { z: 2, a: 1 }
  });
  const replay = store.submit({
    tenantId: "tenant-a",
    requestedBy: "principal-a",
    idempotencyKey: "request-1",
    toolName: "analysis.run_stratification",
    datasetId: "snapshot-1",
    request: { a: 1, z: 2 }
  });
  assert.equal(first.jobId, replay.jobId);
  assert.deepEqual(first.request, { a: 1, z: 2 });

  assert.throws(
    () =>
      store.submit({
        tenantId: "tenant-a",
        requestedBy: "principal-a",
        idempotencyKey: "request-1",
        toolName: "analysis.run_stratification",
        request: { a: 2 }
      }),
    (error: unknown) => error instanceof JobStoreError && error.code === "IDEMPOTENCY_CONFLICT"
  );
  store.close();
});

test("claims are tenant scoped, leased and fenced from stale workers", () => {
  const { store, advance } = fixture();
  const job = store.submit({
    tenantId: "tenant-a",
    requestedBy: "principal-a",
    idempotencyKey: "request-1",
    toolName: "analysis.run_vintage",
    request: { snapshotId: "snapshot-1" },
    maxAttempts: 2
  });
  assert.equal(store.claimNext({ tenantId: "tenant-b", workerId: "worker-b", leaseSeconds: 10 }), null);

  const firstClaim = store.claimNext({ tenantId: "tenant-a", workerId: "worker-1", leaseSeconds: 10 });
  assert.ok(firstClaim);
  assert.equal(firstClaim.attemptCount, 1);
  advance(11);
  const secondClaim = store.claimNext({ tenantId: "tenant-a", workerId: "worker-2", leaseSeconds: 10 });
  assert.ok(secondClaim);
  assert.equal(secondClaim.attemptCount, 2);
  assert.notEqual(secondClaim.claimToken, firstClaim.claimToken);
  assert.throws(
    () => store.complete("tenant-a", job.jobId, "worker-1", firstClaim.claimToken, "result-old"),
    (error: unknown) => error instanceof JobStoreError && error.code === "CLAIM_REJECTED"
  );
  const completed = store.complete("tenant-a", job.jobId, "worker-2", secondClaim.claimToken, "result-new");
  assert.equal(completed.status, "succeeded");
  assert.equal(completed.resultHandle, "result-new");
  store.close();
});

test("retry, cooperative cancellation and requester hiding are enforced", () => {
  const { store } = fixture();
  const job = store.submit({
    tenantId: "tenant-a",
    requestedBy: "principal-a",
    idempotencyKey: "request-1",
    toolName: "monitor.run",
    request: {},
    maxAttempts: 3
  });
  const first = store.claimNext({ tenantId: "tenant-a", workerId: "worker-1", leaseSeconds: 30 });
  assert.ok(first);
  const retry = store.fail("tenant-a", job.jobId, "worker-1", first.claimToken, "transient_db", true);
  assert.equal(retry.status, "queued");
  const second = store.claimNext({ tenantId: "tenant-a", workerId: "worker-1", leaseSeconds: 30 });
  assert.ok(second);
  const cancelling = store.requestCancellation("tenant-a", job.jobId, "principal-a");
  assert.equal(cancelling.cancellationRequested, true);
  const cancelled = store.fail("tenant-a", job.jobId, "worker-1", second.claimToken, "cancelled", false);
  assert.equal(cancelled.status, "cancelled");
  assert.throws(
    () => store.get("tenant-a", job.jobId, "principal-b"),
    (error: unknown) => error instanceof JobStoreError && error.code === "JOB_NOT_FOUND"
  );
  store.close();
});

test("cancellation wins atomically over a worker completion", () => {
  const { store } = fixture();
  const job = store.submit({
    tenantId: "tenant-a",
    requestedBy: "principal-a",
    idempotencyKey: "request-cancel-race",
    toolName: "analysis.run",
    request: {}
  });
  const claim = store.claimNext({ tenantId: "tenant-a", workerId: "worker-1", leaseSeconds: 30 });
  assert.ok(claim);

  const cancelling = store.requestCancellation("tenant-a", job.jobId, "principal-a");
  assert.equal(cancelling.cancellationRequested, true);
  assert.throws(
    () => store.complete("tenant-a", job.jobId, "worker-1", claim.claimToken, "result-too-late"),
    (error: unknown) => error instanceof JobStoreError && error.code === "CLAIM_REJECTED"
  );

  const cancelled = store.fail(
    "tenant-a",
    job.jobId,
    "worker-1",
    claim.claimToken,
    "CANCELLED",
    false
  );
  assert.equal(cancelled.status, "cancelled");
  assert.equal(cancelled.resultHandle, null);
  store.close();
});

test("worker discovery returns only bounded claimable tenant partitions", () => {
  const { store, advance } = fixture();
  store.submit({
    tenantId: "tenant-b",
    requestedBy: "principal-b",
    idempotencyKey: "request-b",
    toolName: "analysis.run",
    request: {}
  });
  store.submit({
    tenantId: "tenant-a",
    requestedBy: "principal-a",
    idempotencyKey: "request-a",
    toolName: "analysis.run",
    request: {}
  });
  store.submit({
    tenantId: "tenant-future",
    requestedBy: "principal-future",
    idempotencyKey: "request-future",
    toolName: "analysis.run",
    request: {},
    availableAt: "2026-08-11T12:01:00.000Z"
  });

  assert.deepEqual(store.listRunnableTenantIds(10), ["tenant-a", "tenant-b"]);
  assert.deepEqual(store.listRunnableTenantIds(1), ["tenant-a"]);
  advance(61);
  assert.deepEqual(store.listRunnableTenantIds(10), ["tenant-a", "tenant-b", "tenant-future"]);
  assert.throws(
    () => store.listRunnableTenantIds(1_001),
    (error: unknown) => error instanceof JobStoreError && error.code === "INVALID_INPUT"
  );
  store.close();
});

test("expired final claims are recovery-only while cancellations reap and retries remain claimable", () => {
  const { store, advance } = fixture();
  const consumed = store.submit({
    tenantId: "tenant-consumed",
    requestedBy: "principal-a",
    idempotencyKey: "request-consumed",
    toolName: "analysis.run",
    request: {},
    maxAttempts: 1
  });
  assert.ok(
    store.claimNext({ tenantId: "tenant-consumed", workerId: "worker-1", leaseSeconds: 5 })
  );
  advance(6);
  assert.deepEqual(store.listRunnableTenantIds(), ["tenant-consumed"]);
  assert.deepEqual(store.reapExpiredJobs(), []);
  const recovery = store.claimNext({
    tenantId: "tenant-consumed",
    workerId: "worker-recovery",
    leaseSeconds: 5
  });
  assert.ok(recovery);
  assert.equal(recovery.recoveryOnly, true);
  assert.equal(recovery.attemptCount, 1);
  store.fail(
    "tenant-consumed",
    consumed.jobId,
    "worker-recovery",
    recovery.claimToken,
    "EXECUTION_FAILED",
    false
  );
  assert.equal(store.get("tenant-consumed", consumed.jobId).status, "failed");

  const cancelled = store.submit({
    tenantId: "tenant-cancelled",
    requestedBy: "principal-b",
    idempotencyKey: "request-cancelled",
    toolName: "analysis.run",
    request: {},
    maxAttempts: 2
  });
  assert.ok(
    store.claimNext({ tenantId: "tenant-cancelled", workerId: "worker-1", leaseSeconds: 5 })
  );
  store.requestCancellation("tenant-cancelled", cancelled.jobId, "principal-b");
  advance(6);
  assert.deepEqual(store.reapExpiredJobs(), [
    {
      tenantId: "tenant-cancelled",
      jobId: cancelled.jobId,
      status: "cancelled",
      errorCode: "CANCELLED"
    }
  ]);

  const retryable = store.submit({
    tenantId: "tenant-retryable",
    requestedBy: "principal-c",
    idempotencyKey: "request-retryable",
    toolName: "analysis.run",
    request: {},
    maxAttempts: 2
  });
  assert.ok(
    store.claimNext({ tenantId: "tenant-retryable", workerId: "worker-1", leaseSeconds: 5 })
  );
  advance(6);
  assert.deepEqual(store.reapExpiredJobs(), []);
  assert.deepEqual(store.listRunnableTenantIds(), ["tenant-retryable"]);
  const reclaimed = store.claimNext({
    tenantId: "tenant-retryable",
    workerId: "worker-2",
    leaseSeconds: 5
  });
  assert.ok(reclaimed);
  assert.equal(reclaimed.jobId, retryable.jobId);
  assert.equal(reclaimed.attemptCount, 2);
  assert.equal(reclaimed.recoveryOnly, false);
  store.close();
});
