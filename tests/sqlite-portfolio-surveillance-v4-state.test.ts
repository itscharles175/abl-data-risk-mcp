import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, test } from "node:test";

import { canonicalHash, type Sha256Hash } from "../src/contracts/canonical.js";
import { JobStore } from "../src/control/jobs.js";
import {
  GOVERNED_ANALYSIS_RESULT_V4_KIND,
  GOVERNED_EXECUTION_ENVELOPE_V4_KIND,
  GOVERNED_PORTFOLIO_SURVEILLANCE_PLAN_V4_KIND,
  GOVERNED_RESULT_MANIFEST_V4_KIND,
  PortfolioSurveillanceV4StateStoreError,
  SqlitePortfolioSurveillanceV4StateStore,
  type PortfolioSurveillanceV4AttemptFenceV1,
  type PortfolioSurveillanceV4ManifestArtifactPointerV1,
  type PortfolioSurveillanceV4ResultArtifactPointerV1,
  type RecordPortfolioSurveillanceV4SubmissionInput
} from "../src/repositories/sqlite-portfolio-surveillance-v4-state.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("submission binding is tenant scoped, actor idempotent, immutable, paged, and coexists with JobStore", () => {
  const path = databasePath();
  const clock = fixedClock("2026-08-12T12:00:00.000Z");
  const store = new SqlitePortfolioSurveillanceV4StateStore(path, { clock });
  const jobs = new JobStore(path, { clock });
  const first = submission("job-1", "idem-1");

  const created = store.recordSubmission(first);
  assert.equal(created.replayed, false);
  assert.equal(created.state.status, "submitted");
  assert.equal(created.state.submission.jobId, first.jobId);
  assert.equal(created.state.submission.envelope.contentHash, first.envelope.contentHash);
  assert.equal(created.state.submission.planArtifact.byteLength, first.planArtifact.byteLength);
  assert.equal(store.recordSubmission(first).replayed, true);
  assert.deepEqual(
    store.getIdempotencyReceipt(first.tenantId, first.requestedBy, first.idempotencyKey),
    created.receipt
  );

  assert.throws(
    () => store.recordSubmission({ ...first, jobId: "job-conflict" }),
    (error: unknown) => hasStoreCode(error, "IDEMPOTENCY_CONFLICT")
  );
  assert.equal(store.get("tenant-b", first.jobId), undefined);
  assert.equal(store.getIdempotencyReceipt("tenant-b", first.requestedBy, first.idempotencyKey), undefined);
  assert.throws(
    () =>
      store.recordResultArtifact({
        tenantId: "tenant-b",
        jobId: first.jobId,
        actorId: "worker-1",
        attemptFence: fence(1),
        ...EXECUTION_PROVENANCE,
        resultArtifact: resultPointer("result-1")
      }),
    (error: unknown) => hasStoreCode(error, "NOT_FOUND")
  );

  clock.advance("2026-08-12T12:00:01.000Z");
  store.recordSubmission(submission("job-2", "idem-2"));
  const pageOne = store.list("tenant-a", { limit: 1 });
  assert.deepEqual(pageOne.items.map((state) => state.submission.jobId), ["job-1"]);
  assert.ok(pageOne.nextCursor);
  assert.deepEqual(
    store.list("tenant-a", { cursor: pageOne.nextCursor ?? undefined }).items.map(
      (state) => state.submission.jobId
    ),
    ["job-2"]
  );
  assert.throws(
    () => store.list("tenant-b", { cursor: pageOne.nextCursor ?? undefined }),
    (error: unknown) => hasStoreCode(error, "INVALID_ARGUMENT")
  );

  const queued = jobs.submit({
    tenantId: "tenant-a",
    jobId: "legacy-job",
    requestedBy: "principal-1",
    idempotencyKey: "legacy-idem",
    toolName: "legacy_tool",
    request: { version: 1 }
  });
  assert.equal(queued.status, "queued");

  const database = new DatabaseSync(path);
  assert.throws(() =>
    database
      .prepare("UPDATE portfolio_surveillance_v4_submissions SET requested_by = 'attacker'")
      .run()
  );
  assert.throws(() =>
    database.prepare("DELETE FROM portfolio_surveillance_v4_idempotency").run()
  );
  assert.throws(() =>
    database.prepare("DELETE FROM portfolio_surveillance_v4_state_events").run()
  );
  database.close();
  jobs.close();
  store.close();
});

test("staged result recovery permits a later lease attempt and fences every immutable stage", () => {
  const path = databasePath();
  const clock = fixedClock("2026-08-12T12:00:00.000Z");
  let store = new SqlitePortfolioSurveillanceV4StateStore(path, { clock });
  const input = submission("job-recovery", "idem-recovery");
  const result = resultPointer("result-recovery");
  const manifest = manifestPointer("manifest-recovery");
  const firstFence = fence(1, "worker-1", "lease-1");

  store.recordSubmission(input);
  recordSubmissionAuthorization(store, input);
  assert.throws(
    () =>
      store.recordManifestArtifact({
        tenantId: input.tenantId,
        jobId: input.jobId,
        actorId: firstFence.workerId,
        attemptFence: firstFence,
        ...EXECUTION_PROVENANCE,
        resultArtifact: result,
        manifestArtifact: manifest
      }),
    (error: unknown) => hasStoreCode(error, "INVALID_TRANSITION")
  );
  assert.throws(
    () =>
      store.recordCompletionPreparation({
        tenantId: input.tenantId,
        jobId: input.jobId,
        actorId: firstFence.workerId,
        attemptFence: firstFence,
        ...EXECUTION_PROVENANCE,
        resultArtifact: result,
        manifestArtifact: manifest
      }),
    (error: unknown) => hasStoreCode(error, "INVALID_TRANSITION")
  );

  clock.advance("2026-08-12T12:00:01.000Z");
  assert.equal(
    store.recordResultArtifact({
      tenantId: input.tenantId,
      jobId: input.jobId,
      actorId: firstFence.workerId,
      attemptFence: firstFence,
      ...EXECUTION_PROVENANCE,
      resultArtifact: result
    }).state.status,
    "result_artifact_persisted"
  );
  store.close();

  clock.advance("2026-08-12T12:00:02.000Z");
  store = new SqlitePortfolioSurveillanceV4StateStore(path, { clock });
  const recovered = store.get(input.tenantId, input.jobId);
  assert.equal(recovered?.status, "result_artifact_persisted");
  assert.deepEqual(recovered?.resultArtifact, result);
  assert.equal(recovered?.manifestArtifact, undefined);

  const substitutedFence = fence(1, "worker-2", "lease-substituted");
  assert.throws(
    () =>
      store.recordManifestArtifact({
        tenantId: input.tenantId,
        jobId: input.jobId,
        actorId: substitutedFence.workerId,
        attemptFence: substitutedFence,
        ...EXECUTION_PROVENANCE,
        resultArtifact: result,
        manifestArtifact: manifest
      }),
    (error: unknown) => hasStoreCode(error, "FENCE_MISMATCH")
  );

  const recoveryFence = fence(2, "worker-2", "lease-2");
  const manifestState = store.recordManifestArtifact({
    tenantId: input.tenantId,
    jobId: input.jobId,
    actorId: recoveryFence.workerId,
    attemptFence: recoveryFence,
    ...EXECUTION_PROVENANCE,
    resultArtifact: result,
    manifestArtifact: manifest
  });
  assert.equal(manifestState.state.status, "manifest_artifact_persisted");

  const wrongCompletionFence = fence(2, "worker-2", "lease-wrong");
  assert.throws(
    () =>
      store.recordCompletionPreparation({
        tenantId: input.tenantId,
        jobId: input.jobId,
        actorId: wrongCompletionFence.workerId,
        attemptFence: wrongCompletionFence,
        ...EXECUTION_PROVENANCE,
        resultArtifact: result,
        manifestArtifact: manifest
      }),
    (error: unknown) => hasStoreCode(error, "FENCE_MISMATCH")
  );
  clock.advance("2026-08-12T12:00:03.000Z");
  const prepared = store.recordCompletionPreparation({
    tenantId: input.tenantId,
    jobId: input.jobId,
    actorId: recoveryFence.workerId,
    attemptFence: recoveryFence,
    ...EXECUTION_PROVENANCE,
    resultArtifact: result,
    manifestArtifact: manifest
  });
  assert.equal(prepared.state.status, "completion_prepared");
  const completed = store.recordQueueCompletion({
    tenantId: input.tenantId,
    jobId: input.jobId,
    actorId: input.requestedBy,
    queueRequestHash: bareHash("queue-request"),
    resultHandleHash: bareHash("result-handle"),
    queueUpdatedAt: "2026-08-12T12:00:03.000Z",
    completionAudit: { sequence: 2, eventHash: hash("completion-audit") },
    resultArtifact: result,
    manifestArtifact: manifest
  });
  assert.equal(completed.state.status, "completed");
  assert.equal(store.getEvents(input.tenantId, input.jobId).length, 6);
  store.close();
});

test("duplicate stage replay is exact and pointer drift cannot replace durable recovery state", () => {
  const clock = fixedClock("2026-08-12T12:00:00.000Z");
  const store = new SqlitePortfolioSurveillanceV4StateStore(databasePath(), { clock });
  const input = submission("job-pointer", "idem-pointer");
  const result = resultPointer("result-pointer");
  const attempt = fence(1);
  store.recordSubmission(input);
  recordSubmissionAuthorization(store, input);
  clock.advance("2026-08-12T12:00:01.000Z");
  const write = {
    tenantId: input.tenantId,
    jobId: input.jobId,
    actorId: attempt.workerId,
    attemptFence: attempt,
    ...EXECUTION_PROVENANCE,
    resultArtifact: result
  } as const;
  assert.equal(store.recordResultArtifact(write).replayed, false);
  clock.advance("2026-08-12T12:30:00.000Z");
  assert.equal(store.recordResultArtifact(write).replayed, true);
  assert.throws(
    () => store.recordResultArtifact({ ...write, resultArtifact: resultPointer("drift") }),
    (error: unknown) => hasStoreCode(error, "POINTER_CONFLICT")
  );
  assert.throws(
    () => store.recordResultArtifact({ ...write, attemptFence: fence(1, "worker-2", "lease-2"), actorId: "worker-2" }),
    (error: unknown) => hasStoreCode(error, "FENCE_MISMATCH")
  );
  store.close();
});

test("failure and cancellation are append-only terminal events", () => {
  const clock = fixedClock("2026-08-12T12:00:00.000Z");
  const store = new SqlitePortfolioSurveillanceV4StateStore(databasePath(), { clock });
  const failed = submission("job-failed", "idem-failed");
  const cancelled = submission("job-cancelled", "idem-cancelled");
  store.recordSubmission(failed);
  clock.advance("2026-08-12T12:00:01.000Z");
  store.recordSubmission(cancelled);
  clock.advance("2026-08-12T12:00:02.000Z");
  assert.equal(
    store.recordFailure({
      tenantId: failed.tenantId,
      jobId: failed.jobId,
      actorId: "worker-1",
      attemptFence: fence(1),
      errorCode: "EXECUTION_FAILED"
    }).state.status,
    "failed"
  );
  clock.advance("2026-08-12T12:00:03.000Z");
  assert.equal(
    store.recordCancellation({
      tenantId: cancelled.tenantId,
      jobId: cancelled.jobId,
      actorId: "principal-1",
      reasonCode: "REQUESTED"
    }).state.status,
    "cancelled"
  );
  assert.throws(
    () =>
      store.recordResultArtifact({
        tenantId: failed.tenantId,
        jobId: failed.jobId,
        actorId: "worker-1",
        attemptFence: fence(1),
        ...EXECUTION_PROVENANCE,
        resultArtifact: resultPointer("too-late")
      }),
    (error: unknown) => hasStoreCode(error, "INVALID_TRANSITION")
  );
  store.close();
});

test("audit-chain tampering is detected after a clean schema-preserving reopen", () => {
  const path = databasePath();
  const store = new SqlitePortfolioSurveillanceV4StateStore(path, {
    clock: fixedClock("2026-08-12T12:00:00.000Z")
  });
  store.recordSubmission(submission("job-audit", "idem-audit"));
  store.close();

  const database = new DatabaseSync(path);
  const trigger = database
    .prepare(
      `SELECT sql FROM sqlite_master
        WHERE type = 'trigger' AND name = 'portfolio_surveillance_v4_state_events_no_update'`
    )
    .get() as { readonly sql: string };
  database.exec("DROP TRIGGER portfolio_surveillance_v4_state_events_no_update");
  database
    .prepare(
      "UPDATE portfolio_surveillance_v4_state_events SET event_hash = ? WHERE tenant_id = ? AND tenant_sequence = 1"
    )
    .run(hash("tampered"), "tenant-a");
  database.exec(trigger.sql);
  database.close();

  const reopened = new SqlitePortfolioSurveillanceV4StateStore(path);
  assert.throws(
    () => reopened.get("tenant-a", "job-audit"),
    (error: unknown) => hasStoreCode(error, "INTEGRITY_FAILURE")
  );
  reopened.close();
});

test("schema attestation rejects component drift", () => {
  const path = databasePath();
  const store = new SqlitePortfolioSurveillanceV4StateStore(path);
  store.close();
  const database = new DatabaseSync(path);
  database.exec("DROP INDEX portfolio_surveillance_v4_state_events_tenant_job");
  database.close();
  assert.throws(
    () => new SqlitePortfolioSurveillanceV4StateStore(path),
    (error: unknown) => hasStoreCode(error, "INTEGRITY_FAILURE")
  );
});

test("tenant audit clock rollback aborts the entire submission transaction", () => {
  const path = databasePath();
  const clock = fixedClock("2026-08-12T12:00:00.000Z");
  const store = new SqlitePortfolioSurveillanceV4StateStore(path, { clock });
  store.recordSubmission(submission("job-clock-1", "idem-clock-1"));
  clock.advance("2026-08-12T11:59:59.000Z");
  assert.throws(
    () => store.recordSubmission(submission("job-clock-2", "idem-clock-2")),
    (error: unknown) => hasStoreCode(error, "CLOCK_ROLLBACK")
  );
  assert.equal(store.get("tenant-a", "job-clock-2"), undefined);
  assert.equal(store.getIdempotencyReceipt("tenant-a", "principal-1", "idem-clock-2"), undefined);
  store.close();
});

test("strict pointer contracts reject kind, hash, and byte-length substitutions", () => {
  const store = new SqlitePortfolioSurveillanceV4StateStore(":memory:");
  const input = submission("job-strict", "idem-strict");
  assert.throws(
    () =>
      store.recordSubmission({
        ...input,
        planArtifact: { ...input.planArtifact, kind: "wrong_kind" }
      } as never),
    (error: unknown) => hasStoreCode(error, "INVALID_ARGUMENT")
  );
  assert.throws(
    () =>
      store.recordSubmission({
        ...input,
        envelope: { ...input.envelope, contentHash: "0".repeat(64) }
      } as never),
    (error: unknown) => hasStoreCode(error, "INVALID_ARGUMENT")
  );
  assert.throws(
    () =>
      store.recordSubmission({
        ...input,
        planArtifact: { ...input.planArtifact, byteLength: 0 }
      }),
    (error: unknown) => hasStoreCode(error, "INVALID_ARGUMENT")
  );
  store.close();
});

function submission(jobId: string, idempotencyKey: string): RecordPortfolioSurveillanceV4SubmissionInput {
  return {
    tenantId: "tenant-a",
    jobId,
    requestedBy: "principal-1",
    idempotencyKey,
    requestHash: hash(`request:${jobId}`),
    startAuthorizationAudit: {
      sequence: 1,
      eventHash: hash(`start-authorization:${jobId}`)
    },
    envelope: {
      envelopeId: `envelope-${jobId}`,
      kind: GOVERNED_EXECUTION_ENVELOPE_V4_KIND,
      mediaType: "application/json",
      contentHash: hash(`envelope:${jobId}`),
      byteLength: 2_048
    },
    planArtifact: {
      artifactId: bareHash(`plan-id:${jobId}`),
      kind: GOVERNED_PORTFOLIO_SURVEILLANCE_PLAN_V4_KIND,
      mediaType: "application/json",
      contentHash: bareHash(`plan-content:${jobId}`),
      byteLength: 4_096
    }
  };
}

const EXECUTION_PROVENANCE = {
  signedPlanId: "signed-plan-v4",
  executionCodeVersion: "test-v4"
} as const;

function resultPointer(label: string): PortfolioSurveillanceV4ResultArtifactPointerV1 {
  return {
    artifactId: bareHash(`${label}:id`),
    kind: GOVERNED_ANALYSIS_RESULT_V4_KIND,
    mediaType: "application/json",
    contentHash: bareHash(`${label}:content`),
    byteLength: 8_192
  };
}

function manifestPointer(label: string): PortfolioSurveillanceV4ManifestArtifactPointerV1 {
  return {
    artifactId: bareHash(`${label}:id`),
    kind: GOVERNED_RESULT_MANIFEST_V4_KIND,
    mediaType: "application/json",
    contentHash: bareHash(`${label}:content`),
    byteLength: 2_048
  };
}

function recordSubmissionAuthorization(
  store: SqlitePortfolioSurveillanceV4StateStore,
  input: RecordPortfolioSurveillanceV4SubmissionInput
): void {
  store.recordSubmissionAuthorization({
    tenantId: input.tenantId,
    jobId: input.jobId,
    actorId: input.requestedBy,
    authorizationAudit: {
      sequence: 2,
      eventHash: hash(`submission-authorization:${input.jobId}`)
    }
  });
}

function fence(
  attemptNumber: number,
  workerId = "worker-1",
  leaseLabel = "lease-1"
): PortfolioSurveillanceV4AttemptFenceV1 {
  return {
    attemptNumber,
    workerId,
    leaseTokenHash: bareHash(leaseLabel),
    leaseExpiresAt: "2026-08-12T13:00:00.000Z"
  };
}

function hash(label: string): Sha256Hash {
  return canonicalHash(label);
}

function bareHash(label: string): string {
  return canonicalHash(label).slice("sha256:".length);
}

function databasePath(): string {
  const directory = mkdtempSync(join(tmpdir(), "abl-v4-state-"));
  directories.push(directory);
  return join(directory, "control.sqlite");
}

function fixedClock(initial: string): (() => Date) & { advance(value: string): void } {
  let current = initial;
  const clock = (() => new Date(current)) as (() => Date) & { advance(value: string): void };
  clock.advance = (value: string) => {
    current = value;
  };
  return clock;
}

function hasStoreCode(error: unknown, code: string): boolean {
  return error instanceof PortfolioSurveillanceV4StateStoreError && error.code === code;
}
