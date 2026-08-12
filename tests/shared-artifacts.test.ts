import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";

import {
  GovernedArtifactDeletionWorkflow,
  ImmutableArtifactError,
  S3ImmutableArtifactRepository,
  type KmsDecryptDataKeyInput,
  type KmsEnvelopeEncryptionPort,
  type KmsGenerateDataKeyInput,
  type KmsGeneratedDataKey,
  type S3CompatibleObjectStorePort,
  type S3GetObjectResult,
  type S3HeadObjectResult,
  type S3PutObjectInput,
  type S3PutObjectResult
} from "../src/shared/artifacts.js";
import type {
  ArtifactDeletionRequestStorePort,
  ArtifactDeletionRequestV1,
  CreateArtifactDeletionRequest
} from "../src/shared/deletion-contracts.js";

interface StoredObject {
  body: Uint8Array;
  etag: string;
  versionId: string;
  contentType: string;
  metadata: Readonly<Record<string, string>>;
  retainUntil?: string;
  legalHold: boolean;
  deleted: boolean;
}

class FakeVersionedObjectStore implements S3CompatibleObjectStorePort {
  readonly objects = new Map<string, StoredObject[]>();
  returnEmptyVersionId = false;

  async putObject(input: S3PutObjectInput): Promise<S3PutObjectResult> {
    const mapKey = `${input.bucket}\u0000${input.key}`;
    const versions = this.objects.get(mapKey) ?? [];
    if (versions.some((version) => !version.deleted)) {
      const error = new Error("precondition failed") as Error & { code: string };
      error.code = "PreconditionFailed";
      throw error;
    }
    const versionId = this.returnEmptyVersionId ? "" : `v-${versions.length + 1}`;
    const stored: StoredObject = {
      body: Uint8Array.from(input.body),
      etag: `etag-${versions.length + 1}`,
      versionId,
      contentType: input.contentType,
      metadata: Object.freeze({ ...input.metadata }),
      ...(input.retainUntil ? { retainUntil: input.retainUntil } : {}),
      legalHold: input.legalHold === true,
      deleted: false
    };
    versions.push(stored);
    this.objects.set(mapKey, versions);
    return { etag: stored.etag, versionId };
  }

  async getObject(input: { readonly bucket: string; readonly key: string; readonly versionId?: string }): Promise<S3GetObjectResult | null> {
    const stored = this.#find(input.bucket, input.key, input.versionId);
    if (!stored) return null;
    return {
      body: Uint8Array.from(stored.body),
      etag: stored.etag,
      versionId: stored.versionId,
      contentType: stored.contentType,
      metadata: stored.metadata,
      ...(stored.retainUntil ? { retainUntil: stored.retainUntil } : {}),
      legalHold: stored.legalHold
    };
  }

  async headObject(input: { readonly bucket: string; readonly key: string; readonly versionId?: string }): Promise<S3HeadObjectResult | null> {
    const stored = this.#find(input.bucket, input.key, input.versionId);
    if (!stored) return null;
    return {
      etag: stored.etag,
      versionId: stored.versionId,
      contentType: stored.contentType,
      metadata: stored.metadata,
      ...(stored.retainUntil ? { retainUntil: stored.retainUntil } : {}),
      legalHold: stored.legalHold
    };
  }

  async putObjectRetention(input: {
    readonly bucket: string;
    readonly key: string;
    readonly versionId: string;
    readonly mode: "GOVERNANCE" | "COMPLIANCE";
    readonly retainUntil: string;
  }): Promise<void> {
    const stored = this.#find(input.bucket, input.key, input.versionId);
    if (!stored) throw new Error("not found");
    stored.retainUntil = input.retainUntil;
  }

  async putObjectLegalHold(input: {
    readonly bucket: string;
    readonly key: string;
    readonly versionId: string;
    readonly enabled: boolean;
  }): Promise<void> {
    const stored = this.#find(input.bucket, input.key, input.versionId);
    if (!stored) throw new Error("not found");
    stored.legalHold = input.enabled;
  }

  async deleteObjectVersion(input: { readonly bucket: string; readonly key: string; readonly versionId: string }): Promise<void> {
    const stored = this.#find(input.bucket, input.key, input.versionId);
    if (stored) stored.deleted = true;
  }

  tamper(bucket: string, key: string, versionId: string): void {
    const stored = this.#find(bucket, key, versionId);
    if (!stored) throw new Error("not found");
    const text = Buffer.from(stored.body).toString("utf8");
    const envelope = JSON.parse(text) as { ciphertext: string };
    envelope.ciphertext = `${envelope.ciphertext.slice(0, -4)}AAAA`;
    stored.body = Buffer.from(JSON.stringify(envelope), "utf8");
  }

  rawBody(bucket: string, key: string, versionId: string): string {
    return Buffer.from(this.#find(bucket, key, versionId)!.body).toString("utf8");
  }

  #find(bucket: string, key: string, versionId?: string): StoredObject | undefined {
    const versions = this.objects.get(`${bucket}\u0000${key}`) ?? [];
    if (versionId !== undefined) return versions.find((entry) => entry.versionId === versionId && !entry.deleted);
    return [...versions].reverse().find((entry) => !entry.deleted);
  }
}

class FakeKms implements KmsEnvelopeEncryptionPort {
  readonly #keys = new Map<string, { key: Uint8Array; context: string }>();
  #counter = 0;

  async generateDataKey(input: KmsGenerateDataKeyInput): Promise<KmsGeneratedDataKey> {
    const key = randomBytes(32);
    const encryptedKey = Buffer.from(`wrapped-${++this.#counter}`, "utf8");
    this.#keys.set(encryptedKey.toString("base64"), {
      key: Uint8Array.from(key),
      context: canonical(input.encryptionContext)
    });
    return { plaintextKey: Uint8Array.from(key), encryptedKey, keyVersion: `${input.keyId}:1` };
  }

  async decryptDataKey(input: KmsDecryptDataKeyInput): Promise<Uint8Array> {
    const stored = this.#keys.get(Buffer.from(input.encryptedKey).toString("base64"));
    if (!stored || stored.context !== canonical(input.encryptionContext)) throw new Error("kms context mismatch");
    return Uint8Array.from(stored.key);
  }
}

class InMemoryDeletionRequests implements ArtifactDeletionRequestStorePort {
  readonly records = new Map<string, ArtifactDeletionRequestV1>();
  #sequence = 0;

  async create(input: CreateArtifactDeletionRequest): Promise<ArtifactDeletionRequestV1> {
    const now = "2026-08-12T12:00:00.000Z";
    const record: ArtifactDeletionRequestV1 = Object.freeze({
      contractVersion: 1,
      tenantId: input.tenantId,
      requestId: `delete-${++this.#sequence}`,
      artifactId: input.artifactId,
      objectKey: input.objectKey,
      objectVersionId: input.objectVersionId,
      requestedBy: input.requestedBy,
      reasonHash: "a".repeat(64),
      executeAfter: input.executeAfter,
      status: "pending",
      approvedBy: null,
      approvedAt: null,
      executionId: null,
      completedAt: null,
      errorCode: null,
      createdAt: now,
      updatedAt: now
    });
    this.records.set(key(record.tenantId, record.requestId), record);
    return record;
  }

  async get(tenantId: string, requestId: string): Promise<ArtifactDeletionRequestV1 | undefined> {
    return this.records.get(key(tenantId, requestId));
  }

  async approve(tenantId: string, requestId: string, approvedBy: string, approvedAt: string): Promise<ArtifactDeletionRequestV1 | undefined> {
    const current = await this.get(tenantId, requestId);
    if (!current || current.status !== "pending" || current.requestedBy === approvedBy) return undefined;
    return this.#put(current, { status: "approved", approvedBy, approvedAt, updatedAt: approvedAt });
  }

  async markExecuting(tenantId: string, requestId: string, executionId: string, now: string): Promise<ArtifactDeletionRequestV1 | undefined> {
    const current = await this.get(tenantId, requestId);
    if (!current || current.status !== "approved" || current.executeAfter > now) return undefined;
    return this.#put(current, { status: "executing", executionId, updatedAt: now });
  }

  async markCompleted(tenantId: string, requestId: string, executionId: string, now: string): Promise<ArtifactDeletionRequestV1 | undefined> {
    const current = await this.get(tenantId, requestId);
    if (!current || current.status !== "executing" || current.executionId !== executionId) return undefined;
    return this.#put(current, { status: "completed", completedAt: now, updatedAt: now });
  }

  async markFailed(tenantId: string, requestId: string, executionId: string, errorCode: string, now: string): Promise<ArtifactDeletionRequestV1 | undefined> {
    const current = await this.get(tenantId, requestId);
    if (!current || current.status !== "executing" || current.executionId !== executionId) return undefined;
    return this.#put(current, { status: "failed", errorCode, updatedAt: now });
  }

  #put(current: ArtifactDeletionRequestV1, patch: Partial<ArtifactDeletionRequestV1>): ArtifactDeletionRequestV1 {
    const next = Object.freeze({ ...current, ...patch });
    this.records.set(key(next.tenantId, next.requestId), next);
    return next;
  }
}

test("artifacts are envelope encrypted, immutable, versioned and tenant scoped", async () => {
  const objects = new FakeVersionedObjectStore();
  const repository = fixture(objects).repository;
  const plaintext = Buffer.from("borrower=Acme;availability=125.50", "utf8");
  const first = await repository.put({
    tenantId: "tenant-a",
    kind: "borrowing-base",
    mediaType: "application/json",
    bytes: plaintext
  });
  const replay = await repository.put({
    tenantId: "tenant-a",
    kind: "borrowing-base",
    mediaType: "application/json",
    bytes: plaintext
  });
  assert.equal(replay.objectVersionId, first.objectVersionId);
  assert.equal(objects.rawBody("artifacts", first.objectKey, first.objectVersionId).includes("borrower=Acme"), false);
  const read = await repository.get("tenant-a", first.artifactId, first.objectVersionId);
  assert.deepEqual(Buffer.from(read.bytes), plaintext);
  await assert.rejects(
    repository.get("tenant-b", first.artifactId, first.objectVersionId),
    (error: unknown) => error instanceof ImmutableArtifactError && error.code === "NOT_FOUND"
  );
  assert.notEqual(repository.objectKey("tenant-a", first.artifactId), repository.objectKey("tenant-b", first.artifactId));
});

test("authenticated envelope and KMS context detect object tampering", async () => {
  const objects = new FakeVersionedObjectStore();
  const { repository } = fixture(objects);
  const artifact = await repository.put({
    tenantId: "tenant-a",
    kind: "report",
    mediaType: "application/pdf",
    bytes: Buffer.from("signed report bytes")
  });
  objects.tamper("artifacts", artifact.objectKey, artifact.objectVersionId);
  await assert.rejects(
    repository.get("tenant-a", artifact.artifactId, artifact.objectVersionId),
    (error: unknown) => error instanceof ImmutableArtifactError && error.code === "INTEGRITY_FAILURE"
  );
});

test("maker/checker, step-up, legal hold and retention gate version-specific deletion", async () => {
  const objects = new FakeVersionedObjectStore();
  let now = new Date("2026-08-12T12:00:00.000Z");
  const { repository } = fixture(objects, () => now);
  const requests = new InMemoryDeletionRequests();
  const workflow = new GovernedArtifactDeletionWorkflow(repository, requests, () => now);
  const artifact = await repository.put({
    tenantId: "tenant-a",
    kind: "audit-export",
    mediaType: "application/json",
    bytes: Buffer.from("immutable evidence"),
    retentionMode: "COMPLIANCE",
    retainUntil: "2026-08-12T12:10:00.000Z",
    legalHold: true
  });
  const request = await workflow.request({
    tenantId: "tenant-a",
    artifactId: artifact.artifactId,
    versionId: artifact.objectVersionId,
    requestedBy: "operator-a",
    reason: "Approved retention disposition",
    executeAfter: "2026-08-12T12:00:00.000Z"
  });
  await assert.rejects(
    workflow.approve({ tenantId: "tenant-a", requestId: request.requestId, approvedBy: "operator-a", stepUpSatisfied: true }),
    (error: unknown) => error instanceof ImmutableArtifactError && error.code === "APPROVAL_REQUIRED"
  );
  await assert.rejects(
    workflow.approve({ tenantId: "tenant-a", requestId: request.requestId, approvedBy: "reviewer-b", stepUpSatisfied: false }),
    (error: unknown) => error instanceof ImmutableArtifactError && error.code === "APPROVAL_REQUIRED"
  );
  await workflow.approve({ tenantId: "tenant-a", requestId: request.requestId, approvedBy: "reviewer-b", stepUpSatisfied: true });
  await assert.rejects(
    workflow.execute("tenant-a", request.requestId),
    (error: unknown) => error instanceof ImmutableArtifactError && error.code === "RETENTION_BLOCKED"
  );
  await repository.setLegalHold(artifact, false);
  await assert.rejects(
    workflow.execute("tenant-a", request.requestId),
    (error: unknown) => error instanceof ImmutableArtifactError && error.code === "RETENTION_BLOCKED"
  );
  now = new Date("2026-08-12T12:10:01.000Z");
  const completed = await workflow.execute("tenant-a", request.requestId);
  assert.equal(completed.status, "completed");
  assert.equal(await workflow.execute("tenant-a", request.requestId), completed);
  await assert.rejects(
    repository.get("tenant-a", artifact.artifactId, artifact.objectVersionId),
    (error: unknown) => error instanceof ImmutableArtifactError && error.code === "NOT_FOUND"
  );
});

test("an object store without version ids is rejected", async () => {
  const objects = new FakeVersionedObjectStore();
  objects.returnEmptyVersionId = true;
  const { repository } = fixture(objects);
  await assert.rejects(
    repository.put({ tenantId: "tenant-a", kind: "report", mediaType: "application/json", bytes: Buffer.from("{}") }),
    (error: unknown) => error instanceof ImmutableArtifactError && error.code === "VERSIONING_REQUIRED"
  );
});

function fixture(objects: FakeVersionedObjectStore, clock: () => Date = () => new Date("2026-08-12T12:00:00.000Z")) {
  const kms = new FakeKms();
  const repository = new S3ImmutableArtifactRepository(objects, kms, {
    bucket: "artifacts",
    kmsKeyId: "kms-key-ref",
    clock
  });
  return { repository, kms };
}

function canonical(value: Readonly<Record<string, string>>): string {
  return JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b))));
}

function key(tenantId: string, requestId: string): string {
  return `${tenantId}\u0000${requestId}`;
}
