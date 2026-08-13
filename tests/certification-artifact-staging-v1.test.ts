import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import { canonicalHash } from "../src/contracts/canonical.js";
import {
  CertificationArtifactStagingStoreError,
  SqliteCertificationArtifactStagingStoreV1
} from "../src/repositories/certification-artifact-staging-v1.js";

test("staged artifacts are tenant-scoped, immutable, hash-bound, and idempotent across reopen", async () => {
  const directory = mkdtempSync(join(tmpdir(), "abl-certification-artifact-staging-"));
  const path = join(directory, "outbox.sqlite");
  try {
    const store = new SqliteCertificationArtifactStagingStoreV1(path);
    const first = await store.prepareOrReplay(stageInput());
    assert.equal(first.replayed, false);
    assert.equal(first.record.state, "prepared");
    assert.equal(first.record.events.length, 1);

    const replay = await store.prepareOrReplay({ ...stageInput(), preparedAt: "2026-08-03T12:00:00.000Z" });
    assert.equal(replay.replayed, true);
    assert.equal(replay.record.stage.stageHash, first.record.stage.stageHash);
    assert.equal(replay.record.stage.preparedAt, "2026-08-03T10:00:00.000Z");

    await assert.rejects(
      () =>
        store.prepareOrReplay(
          stageInput({
            normalizedArtifact: artifact("another-artifact")
          })
        ),
      (error: unknown) => stagingError(error, "IDEMPOTENCY_CONFLICT")
    );
    assert.equal(
      await store.get({ tenantId: "tenant-b", certificationManifestId: "certification-a" }),
      undefined
    );
    store.close();

    const reopened = new SqliteCertificationArtifactStagingStoreV1(path);
    const loaded = await reopened.get({ tenantId: "tenant-a", certificationManifestId: "certification-a" });
    assert.equal(loaded?.stage.artifactBindingHash, first.record.stage.artifactBindingHash);
    assert.equal(loaded?.events[0]?.eventType, "artifact_prepared");
    reopened.close();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("failure receipts preserve an orphan-safe recovery trail until exactly one evidence commit", async () => {
  const directory = mkdtempSync(join(tmpdir(), "abl-certification-artifact-recovery-"));
  const path = join(directory, "outbox.sqlite");
  try {
    const store = new SqliteCertificationArtifactStagingStoreV1(path);
    const prepared = await store.prepareOrReplay(stageInput());
    const binding = prepared.record.stage;
    const failed = await store.recordEvidenceFailure({
      tenantId: binding.tenantId,
      certificationManifestId: binding.certificationManifestId,
      attemptHash: binding.attemptHash,
      artifactBindingHash: binding.artifactBindingHash,
      failureHash: canonicalHash({ reason: "evidence-write-timeout", retry: 1 }),
      occurredAt: "2026-08-03T10:01:00.000Z"
    });
    assert.equal(failed.replayed, false);
    assert.equal(failed.record.state, "evidence_commit_failed");
    assert.equal(failed.record.latestFailureHash, canonicalHash({ reason: "evidence-write-timeout", retry: 1 }));

    const failedReplay = await store.recordEvidenceFailure({
      tenantId: binding.tenantId,
      certificationManifestId: binding.certificationManifestId,
      attemptHash: binding.attemptHash,
      artifactBindingHash: binding.artifactBindingHash,
      failureHash: canonicalHash({ reason: "evidence-write-timeout", retry: 1 }),
      occurredAt: "2026-08-03T10:02:00.000Z"
    });
    assert.equal(failedReplay.replayed, true);
    assert.equal(failedReplay.record.events.length, 2);

    const committed = await store.recordEvidenceCommitted({
      tenantId: binding.tenantId,
      certificationManifestId: binding.certificationManifestId,
      attemptHash: binding.attemptHash,
      artifactBindingHash: binding.artifactBindingHash,
      certificationEvidenceHash: canonicalHash({ evidence: "certification-a", artifact: binding.artifactBindingHash }),
      occurredAt: "2026-08-03T10:03:00.000Z"
    });
    assert.equal(committed.replayed, false);
    assert.equal(committed.record.state, "evidence_committed");
    assert.equal(committed.record.events.length, 3);
    assert.equal(committed.record.latestFailureHash, failed.record.latestFailureHash);

    const committedReplay = await store.recordEvidenceCommitted({
      tenantId: binding.tenantId,
      certificationManifestId: binding.certificationManifestId,
      attemptHash: binding.attemptHash,
      artifactBindingHash: binding.artifactBindingHash,
      certificationEvidenceHash: canonicalHash({ evidence: "certification-a", artifact: binding.artifactBindingHash }),
      occurredAt: "2026-08-03T10:04:00.000Z"
    });
    assert.equal(committedReplay.replayed, true);
    await assert.rejects(
      () =>
        store.recordEvidenceFailure({
          tenantId: binding.tenantId,
          certificationManifestId: binding.certificationManifestId,
          attemptHash: binding.attemptHash,
          artifactBindingHash: binding.artifactBindingHash,
          failureHash: canonicalHash({ reason: "late" }),
          occurredAt: "2026-08-03T10:05:00.000Z"
        }),
      (error: unknown) => stagingError(error, "STATE_CONFLICT")
    );
    store.close();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("stage and outbox tampering or an orphan event fails integrity checks on reopen", async () => {
  const directory = mkdtempSync(join(tmpdir(), "abl-certification-artifact-tamper-"));
  const path = join(directory, "outbox.sqlite");
  try {
    const store = new SqliteCertificationArtifactStagingStoreV1(path);
    await store.prepareOrReplay(stageInput());
    store.close();

    const database = new DatabaseSync(path);
    assert.throws(() => {
      database.prepare(
        "UPDATE certification_artifact_stages_v1 SET attempt_hash = ? WHERE tenant_id = ?"
      ).run(canonicalHash("forged"), "tenant-a");
    });
    database.exec("DROP TRIGGER certification_artifact_outbox_events_v1_no_update");
    database.prepare(
      "UPDATE certification_artifact_outbox_events_v1 SET stage_hash = ? WHERE tenant_id = ?"
    ).run(canonicalHash("forged-stage"), "tenant-a");
    database.close();

    assert.throws(
      () => new SqliteCertificationArtifactStagingStoreV1(path),
      (error: unknown) => stagingError(error, "INTEGRITY_FAILURE")
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function stageInput(overrides: Partial<ReturnType<typeof stageInput>> = {}) {
  const normalizedArtifact = overrides.normalizedArtifact ?? artifact("artifact-a");
  const base = {
    contractVersion: 1 as const,
    tenantId: "tenant-a",
    certificationManifestId: "certification-a",
    attemptHash: canonicalHash("attempt-a"),
    normalizedArtifact,
    preparedAt: "2026-08-03T10:00:00.000Z"
  };
  return {
    ...base,
    artifactBindingHash: canonicalHash({
      contractVersion: 1,
      tenantId: base.tenantId,
      certificationManifestId: base.certificationManifestId,
      attemptHash: base.attemptHash,
      normalizedArtifact: base.normalizedArtifact
    }),
    ...overrides
  };
}

function artifact(seed: string) {
  const artifactId = canonicalHash(`${seed}:id`).slice("sha256:".length);
  return {
    tenantId: "tenant-a",
    artifactId,
    kind: "normalized_snapshot" as const,
    mediaType: "application/json" as const,
    artifactContractVersion: 2 as const,
    artifactHash: canonicalHash(`${seed}:artifact`),
    contentHash: canonicalHash(`${seed}:content`),
    byteLength: 1024,
    keyId: "key-a",
    uri: `abl-artifact://${artifactId}`,
    snapshotId: "snapshot-a",
    snapshotHash: canonicalHash("snapshot-a"),
    normalizedPopulationId: "population-a",
    mappingApplicationId: "mapping-a",
    mappingApplicationHash: canonicalHash("mapping-a"),
    populationHash: canonicalHash("population-a"),
    fieldSetHash: canonicalHash("field-set-a"),
    rowCount: 10,
    createdAt: "2026-08-03T09:59:00.000Z"
  };
}

function stagingError(
  error: unknown,
  code: CertificationArtifactStagingStoreError["code"]
): boolean {
  assert.ok(error instanceof CertificationArtifactStagingStoreError);
  assert.equal(error.code, code);
  return true;
}
