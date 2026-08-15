import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import { canonicalHash } from "../src/contracts/index.js";
import {
  SnapshotCertificationAttemptStoreError,
  SqliteSnapshotCertificationAttemptStoreV1
} from "../src/repositories/snapshot-certification-attempts-v1.js";

test("certification attempts lock identity and trusted certification time across retries and reopen", async () => {
  const directory = mkdtempSync(join(tmpdir(), "abl-certification-attempts-"));
  const path = join(directory, "attempts.sqlite");
  try {
    const store = new SqliteSnapshotCertificationAttemptStoreV1(path);
    const first = await store.startOrReplay(input());
    assert.equal(first.replayed, false);
    assert.equal(first.attempt.certifiedAt, "2026-08-02T10:00:00.000Z");

    const replay = await store.startOrReplay({
      ...input(),
      certifiedAt: "2026-08-02T11:00:00.000Z",
      createdAt: "2026-08-02T11:00:00.000Z"
    });
    assert.equal(replay.replayed, true);
    assert.equal(replay.attempt.attemptHash, first.attempt.attemptHash);
    assert.equal(replay.attempt.certifiedAt, first.attempt.certifiedAt);

    await assert.rejects(
      () => store.startOrReplay({ ...input(), actorId: "other-checker" }),
      (error: unknown) => attemptError(error, "IDEMPOTENCY_CONFLICT")
    );
    store.close();

    const reopened = new SqliteSnapshotCertificationAttemptStoreV1(path);
    const reopenedReplay = await reopened.startOrReplay({
      ...input(),
      certifiedAt: "2026-08-02T12:00:00.000Z",
      createdAt: "2026-08-02T12:00:00.000Z"
    });
    assert.equal(reopenedReplay.replayed, true);
    assert.equal(reopenedReplay.attempt.attemptHash, first.attempt.attemptHash);
    reopened.close();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("attempt storage is immutable and fails reopen after direct row tampering", async () => {
  const directory = mkdtempSync(join(tmpdir(), "abl-certification-attempts-tamper-"));
  const path = join(directory, "attempts.sqlite");
  try {
    const store = new SqliteSnapshotCertificationAttemptStoreV1(path);
    await store.startOrReplay(input());
    store.close();

    const database = new DatabaseSync(path);
    assert.throws(() => {
      database.prepare(
        "UPDATE snapshot_certification_attempts_v1 SET actor_id = ? WHERE tenant_id = ?"
      ).run("forged", "tenant-a");
    });
    database.exec("DROP TRIGGER snapshot_certification_attempts_v1_no_update");
    database.prepare(
      "UPDATE snapshot_certification_attempts_v1 SET actor_id = ? WHERE tenant_id = ?"
    ).run("forged", "tenant-a");
    database.close();

    assert.throws(
      () => new SqliteSnapshotCertificationAttemptStoreV1(path),
      (error: unknown) => attemptError(error, "INTEGRITY_FAILURE")
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function input() {
  return {
    tenantId: "tenant-a",
    certificationManifestId: "certification-a",
    snapshotId: "snapshot-a",
    snapshotHash: canonicalHash("snapshot-a"),
    actorId: "checker-a",
    requestHash: canonicalHash("request-a"),
    certifiedAt: "2026-08-02T10:00:00.000Z",
    createdAt: "2026-08-02T10:00:00.000Z"
  };
}

function attemptError(
  error: unknown,
  code: SnapshotCertificationAttemptStoreError["code"]
): boolean {
  assert.ok(error instanceof SnapshotCertificationAttemptStoreError);
  assert.equal(error.code, code);
  return true;
}
