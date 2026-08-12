import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID
} from "node:crypto";

import type {
  ArtifactDeletionRequestStorePort,
  ArtifactDeletionRequestV1
} from "./deletion-contracts.js";

export interface KmsGenerateDataKeyInput {
  readonly keyId: string;
  readonly encryptionContext: Readonly<Record<string, string>>;
}

export interface KmsGeneratedDataKey {
  /** A 32-byte AES key. Callers erase this buffer after use. */
  readonly plaintextKey: Uint8Array;
  readonly encryptedKey: Uint8Array;
  readonly keyVersion: string;
}

export interface KmsDecryptDataKeyInput {
  readonly keyId: string;
  readonly encryptedKey: Uint8Array;
  readonly encryptionContext: Readonly<Record<string, string>>;
}

export interface KmsEnvelopeEncryptionPort {
  generateDataKey(input: KmsGenerateDataKeyInput): Promise<KmsGeneratedDataKey>;
  decryptDataKey(input: KmsDecryptDataKeyInput): Promise<Uint8Array>;
}

export interface S3PutObjectInput {
  readonly bucket: string;
  readonly key: string;
  readonly body: Uint8Array;
  readonly contentType: string;
  readonly metadata: Readonly<Record<string, string>>;
  readonly ifNoneMatch: "*";
  readonly objectLockMode?: "GOVERNANCE" | "COMPLIANCE";
  readonly retainUntil?: string;
  readonly legalHold?: boolean;
}

export interface S3PutObjectResult {
  readonly etag: string;
  /** Versioning is mandatory; an empty version id is rejected. */
  readonly versionId: string;
}

export interface S3GetObjectResult {
  readonly body: Uint8Array;
  readonly etag: string;
  readonly versionId: string;
  readonly contentType: string;
  readonly metadata: Readonly<Record<string, string>>;
  readonly retentionMode?: "GOVERNANCE" | "COMPLIANCE";
  readonly retainUntil?: string;
  readonly legalHold?: boolean;
}

export interface S3HeadObjectResult extends Omit<S3GetObjectResult, "body"> {}

export interface S3CompatibleObjectStorePort {
  putObject(input: S3PutObjectInput): Promise<S3PutObjectResult>;
  getObject(input: {
    readonly bucket: string;
    readonly key: string;
    readonly versionId?: string;
  }): Promise<S3GetObjectResult | null>;
  headObject(input: {
    readonly bucket: string;
    readonly key: string;
    readonly versionId?: string;
  }): Promise<S3HeadObjectResult | null>;
  putObjectRetention(input: {
    readonly bucket: string;
    readonly key: string;
    readonly versionId: string;
    readonly mode: "GOVERNANCE" | "COMPLIANCE";
    readonly retainUntil: string;
  }): Promise<void>;
  putObjectLegalHold(input: {
    readonly bucket: string;
    readonly key: string;
    readonly versionId: string;
    readonly enabled: boolean;
  }): Promise<void>;
  deleteObjectVersion(input: {
    readonly bucket: string;
    readonly key: string;
    readonly versionId: string;
  }): Promise<void>;
}

export class ImmutableArtifactError extends Error {
  constructor(
    readonly code:
      | "INVALID_INPUT"
      | "NOT_FOUND"
      | "ALREADY_EXISTS_CONFLICT"
      | "INTEGRITY_FAILURE"
      | "VERSIONING_REQUIRED"
      | "RETENTION_BLOCKED"
      | "APPROVAL_REQUIRED"
      | "INVALID_TRANSITION"
      | "STORAGE_FAILURE",
    message: string
  ) {
    super(message);
    this.name = "ImmutableArtifactError";
  }
}

export interface ImmutableArtifactRecordV1 {
  readonly contractVersion: 1;
  readonly tenantId: string;
  readonly artifactId: string;
  readonly kind: string;
  readonly mediaType: string;
  readonly contentHash: string;
  readonly byteLength: number;
  readonly objectKey: string;
  readonly objectVersionId: string;
  readonly etag: string;
  readonly kmsKeyId: string;
  readonly kmsKeyVersion: string;
  readonly createdAt: string;
  readonly retentionMode: "GOVERNANCE" | "COMPLIANCE" | null;
  readonly retainUntil: string | null;
  readonly legalHold: boolean;
}

export interface PutImmutableArtifactInput {
  readonly tenantId: string;
  readonly kind: string;
  readonly mediaType: string;
  readonly bytes: Uint8Array;
  readonly retentionMode?: "GOVERNANCE" | "COMPLIANCE";
  readonly retainUntil?: string;
  readonly legalHold?: boolean;
}

export interface ImmutableArtifactRepositoryOptions {
  readonly bucket: string;
  readonly kmsKeyId: string;
  readonly keyPrefix?: string;
  readonly maximumArtifactBytes?: number;
  readonly clock?: () => Date;
}

interface ArtifactEnvelopeV1 {
  readonly envelopeVersion: 1;
  readonly cipher: "AES-256-GCM";
  readonly tenantBindingHash: string;
  readonly artifactId: string;
  readonly kind: string;
  readonly mediaType: string;
  readonly contentHash: string;
  readonly byteLength: number;
  readonly kmsKeyId: string;
  readonly kmsKeyVersion: string;
  readonly encryptedDataKey: string;
  readonly iv: string;
  readonly authenticationTag: string;
  readonly ciphertext: string;
  readonly createdAt: string;
}

const METADATA = Object.freeze({
  tenantBinding: "tenant-binding-sha256",
  artifactId: "artifact-id",
  contentHash: "content-sha256",
  byteLength: "plaintext-byte-length",
  kind: "artifact-kind",
  mediaTypeHash: "media-type-sha256",
  mediaType: "artifact-media-type",
  kmsKeyIdHash: "kms-key-id-sha256",
  kmsKeyVersion: "kms-key-version",
  createdAt: "created-at"
});

export class S3ImmutableArtifactRepository {
  readonly #objects: S3CompatibleObjectStorePort;
  readonly #kms: KmsEnvelopeEncryptionPort;
  readonly #bucket: string;
  readonly #kmsKeyId: string;
  readonly #keyPrefix: string;
  readonly #maximumArtifactBytes: number;
  readonly #clock: () => Date;

  constructor(
    objects: S3CompatibleObjectStorePort,
    kms: KmsEnvelopeEncryptionPort,
    options: ImmutableArtifactRepositoryOptions
  ) {
    validateName(options.bucket, "bucket", 255);
    validateName(options.kmsKeyId, "kmsKeyId", 1_024);
    if (options.keyPrefix !== undefined) validateName(options.keyPrefix, "keyPrefix", 512);
    const maximum = options.maximumArtifactBytes ?? 256 * 1024 * 1024;
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 1024 * 1024 * 1024) {
      invalid("maximumArtifactBytes must be between 1 byte and 1 GiB");
    }
    this.#objects = objects;
    this.#kms = kms;
    this.#bucket = options.bucket;
    this.#kmsKeyId = options.kmsKeyId;
    this.#keyPrefix = normalizePrefix(options.keyPrefix ?? "abl");
    this.#maximumArtifactBytes = maximum;
    this.#clock = options.clock ?? (() => new Date());
  }

  async put(input: PutImmutableArtifactInput): Promise<ImmutableArtifactRecordV1> {
    validateName(input.tenantId, "tenantId");
    validateName(input.kind, "kind");
    validateMediaType(input.mediaType);
    if (!(input.bytes instanceof Uint8Array)) invalid("bytes must be a Uint8Array");
    if (input.bytes.byteLength < 1 || input.bytes.byteLength > this.#maximumArtifactBytes) {
      invalid(`Artifact size must be between 1 and ${this.#maximumArtifactBytes} bytes`);
    }
    const retention = validateRetention(input.retentionMode, input.retainUntil, this.#clock());
    const contentHash = sha256(input.bytes);
    const artifactId = contentHash;
    const tenantBindingHash = tenantHash(input.tenantId);
    const objectKey = this.objectKey(input.tenantId, artifactId);
    const createdAt = this.#clock().toISOString();
    const context = encryptionContext(tenantBindingHash, artifactId, contentHash, input.kind);
    const generated = await this.#kms.generateDataKey({ keyId: this.#kmsKeyId, encryptionContext: context });
    const plaintextKey = Buffer.from(generated.plaintextKey);
    if (plaintextKey.byteLength !== 32) {
      plaintextKey.fill(0);
      throw new ImmutableArtifactError("STORAGE_FAILURE", "KMS returned an invalid data-key length");
    }

    try {
      const aad = artifactAad({
        tenantBindingHash,
        artifactId,
        kind: input.kind,
        mediaType: input.mediaType,
        contentHash,
        byteLength: input.bytes.byteLength,
        kmsKeyId: this.#kmsKeyId,
        kmsKeyVersion: generated.keyVersion,
        createdAt
      });
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", plaintextKey, iv);
      cipher.setAAD(aad);
      const ciphertext = Buffer.concat([cipher.update(input.bytes), cipher.final()]);
      const envelope: ArtifactEnvelopeV1 = Object.freeze({
        envelopeVersion: 1,
        cipher: "AES-256-GCM",
        tenantBindingHash,
        artifactId,
        kind: input.kind,
        mediaType: input.mediaType,
        contentHash,
        byteLength: input.bytes.byteLength,
        kmsKeyId: this.#kmsKeyId,
        kmsKeyVersion: generated.keyVersion,
        encryptedDataKey: Buffer.from(generated.encryptedKey).toString("base64"),
        iv: iv.toString("base64"),
        authenticationTag: cipher.getAuthTag().toString("base64"),
        ciphertext: ciphertext.toString("base64"),
        createdAt
      });
      const metadata = artifactMetadata(envelope);
      let stored: S3PutObjectResult;
      try {
        stored = await this.#objects.putObject({
          bucket: this.#bucket,
          key: objectKey,
          body: Buffer.from(JSON.stringify(envelope), "utf8"),
          contentType: "application/vnd.abl.encrypted-artifact+json",
          metadata,
          ifNoneMatch: "*",
          ...(retention.mode && retention.until
            ? { objectLockMode: retention.mode, retainUntil: retention.until }
            : {}),
          ...(input.legalHold === true ? { legalHold: true } : {})
        });
      } catch (error) {
        if (!isPreconditionFailure(error)) throw storageFailure(error);
        const existing = await this.#objects.headObject({ bucket: this.#bucket, key: objectKey });
        if (!existing) throw new ImmutableArtifactError("STORAGE_FAILURE", "Immutable object conflict could not be verified");
        assertMetadata(existing.metadata, tenantBindingHash, artifactId, contentHash, input.kind, input.mediaType);
        return recordFromHead(
          input.tenantId,
          objectKey,
          this.#kmsKeyId,
          existing
        );
      }
      if (!stored.versionId.trim()) {
        throw new ImmutableArtifactError("VERSIONING_REQUIRED", "Object storage did not return an immutable version id");
      }
      return Object.freeze({
        contractVersion: 1,
        tenantId: input.tenantId,
        artifactId,
        kind: input.kind,
        mediaType: input.mediaType,
        contentHash,
        byteLength: input.bytes.byteLength,
        objectKey,
        objectVersionId: stored.versionId,
        etag: stored.etag,
        kmsKeyId: this.#kmsKeyId,
        kmsKeyVersion: generated.keyVersion,
        createdAt,
        retentionMode: retention.mode,
        retainUntil: retention.until,
        legalHold: input.legalHold === true
      });
    } finally {
      plaintextKey.fill(0);
      if (generated.plaintextKey instanceof Uint8Array) generated.plaintextKey.fill(0);
    }
  }

  async get(
    tenantId: string,
    artifactId: string,
    versionId?: string
  ): Promise<{ readonly record: ImmutableArtifactRecordV1; readonly bytes: Uint8Array }> {
    validateName(tenantId, "tenantId");
    validateDigest(artifactId, "artifactId");
    if (versionId !== undefined) validateName(versionId, "versionId");
    const objectKey = this.objectKey(tenantId, artifactId);
    const stored = await this.#objects.getObject({
      bucket: this.#bucket,
      key: objectKey,
      ...(versionId ? { versionId } : {})
    });
    if (!stored) throw new ImmutableArtifactError("NOT_FOUND", "Artifact was not found");
    const expectedTenantHash = tenantHash(tenantId);
    assertMetadata(stored.metadata, expectedTenantHash, artifactId);
    let envelope: ArtifactEnvelopeV1;
    try {
      envelope = parseEnvelope(stored.body);
      assertEnvelope(envelope, expectedTenantHash, artifactId, stored.metadata);
    } catch (error) {
      if (error instanceof ImmutableArtifactError) throw error;
      throw new ImmutableArtifactError("INTEGRITY_FAILURE", "Encrypted artifact envelope is invalid");
    }
    const context = encryptionContext(
      envelope.tenantBindingHash,
      envelope.artifactId,
      envelope.contentHash,
      envelope.kind
    );
    let decryptedKey: Uint8Array;
    try {
      decryptedKey = await this.#kms.decryptDataKey({
        keyId: envelope.kmsKeyId,
        encryptedKey: decodeBase64(envelope.encryptedDataKey, "encrypted data key"),
        encryptionContext: context
      });
    } catch {
      throw new ImmutableArtifactError("INTEGRITY_FAILURE", "KMS envelope binding could not be verified");
    }
    const key = Buffer.from(decryptedKey);
    if (key.byteLength !== 32) {
      key.fill(0);
      throw new ImmutableArtifactError("INTEGRITY_FAILURE", "Decrypted data key has an invalid length");
    }
    try {
      const decipher = createDecipheriv(
        "aes-256-gcm",
        key,
        decodeBase64(envelope.iv, "initialization vector")
      );
      decipher.setAAD(artifactAad(envelope));
      decipher.setAuthTag(decodeBase64(envelope.authenticationTag, "authentication tag"));
      const plaintext = Buffer.concat([
        decipher.update(decodeBase64(envelope.ciphertext, "ciphertext")),
        decipher.final()
      ]);
      if (plaintext.byteLength !== envelope.byteLength || sha256(plaintext) !== envelope.contentHash) {
        throw new ImmutableArtifactError("INTEGRITY_FAILURE", "Artifact plaintext hash does not match its manifest");
      }
      return Object.freeze({
        record: recordFromEnvelope(tenantId, objectKey, stored, envelope),
        bytes: Uint8Array.from(plaintext)
      });
    } catch (error) {
      if (error instanceof ImmutableArtifactError) throw error;
      throw new ImmutableArtifactError("INTEGRITY_FAILURE", "Artifact authenticated decryption failed");
    } finally {
      key.fill(0);
    }
  }

  async describe(tenantId: string, artifactId: string, versionId?: string): Promise<ImmutableArtifactRecordV1> {
    validateName(tenantId, "tenantId");
    validateDigest(artifactId, "artifactId");
    const objectKey = this.objectKey(tenantId, artifactId);
    const head = await this.#objects.headObject({
      bucket: this.#bucket,
      key: objectKey,
      ...(versionId ? { versionId } : {})
    });
    if (!head) throw new ImmutableArtifactError("NOT_FOUND", "Artifact was not found");
    assertMetadata(head.metadata, tenantHash(tenantId), artifactId);
    return recordFromHead(tenantId, objectKey, this.#kmsKeyId, head);
  }

  async extendRetention(
    record: ImmutableArtifactRecordV1,
    mode: "GOVERNANCE" | "COMPLIANCE",
    retainUntil: string
  ): Promise<void> {
    validateRecordBinding(record, this.#bucket, this.#keyPrefix);
    const normalized = validateRetention(mode, retainUntil, this.#clock());
    await this.#objects.putObjectRetention({
      bucket: this.#bucket,
      key: record.objectKey,
      versionId: record.objectVersionId,
      mode,
      retainUntil: normalized.until!
    });
  }

  async setLegalHold(record: ImmutableArtifactRecordV1, enabled: boolean): Promise<void> {
    validateRecordBinding(record, this.#bucket, this.#keyPrefix);
    await this.#objects.putObjectLegalHold({
      bucket: this.#bucket,
      key: record.objectKey,
      versionId: record.objectVersionId,
      enabled
    });
  }

  objectKey(tenantId: string, artifactId: string): string {
    return `${this.#keyPrefix}/tenants/${tenantHash(tenantId)}/artifacts/${artifactId.slice(0, 2)}/${artifactId}`;
  }

  get bucket(): string {
    return this.#bucket;
  }

  get objectStore(): S3CompatibleObjectStorePort {
    return this.#objects;
  }
}

export class GovernedArtifactDeletionWorkflow {
  readonly #artifacts: S3ImmutableArtifactRepository;
  readonly #requests: ArtifactDeletionRequestStorePort;
  readonly #clock: () => Date;

  constructor(
    artifacts: S3ImmutableArtifactRepository,
    requests: ArtifactDeletionRequestStorePort,
    clock: () => Date = () => new Date()
  ) {
    this.#artifacts = artifacts;
    this.#requests = requests;
    this.#clock = clock;
  }

  async request(input: {
    readonly tenantId: string;
    readonly artifactId: string;
    readonly versionId: string;
    readonly requestedBy: string;
    readonly reason: string;
    readonly executeAfter: string;
  }): Promise<ArtifactDeletionRequestV1> {
    validateName(input.requestedBy, "requestedBy");
    if (!input.reason.trim() || input.reason.length > 2_000) invalid("reason must contain 1 through 2000 characters");
    const executeAfter = normalizeTimestamp(input.executeAfter, "executeAfter");
    const record = await this.#artifacts.describe(input.tenantId, input.artifactId, input.versionId);
    return this.#requests.create({
      tenantId: input.tenantId,
      artifactId: input.artifactId,
      objectKey: record.objectKey,
      objectVersionId: record.objectVersionId,
      requestedBy: input.requestedBy,
      reason: input.reason,
      executeAfter
    });
  }

  async approve(input: {
    readonly tenantId: string;
    readonly requestId: string;
    readonly approvedBy: string;
    readonly stepUpSatisfied: boolean;
  }): Promise<ArtifactDeletionRequestV1> {
    if (!input.stepUpSatisfied) {
      throw new ImmutableArtifactError("APPROVAL_REQUIRED", "Step-up authentication is required");
    }
    const current = await this.#requests.get(input.tenantId, input.requestId);
    if (!current) throw new ImmutableArtifactError("NOT_FOUND", "Deletion request was not found");
    if (current.requestedBy === input.approvedBy) {
      throw new ImmutableArtifactError("APPROVAL_REQUIRED", "A different principal must approve deletion");
    }
    const approved = await this.#requests.approve(
      input.tenantId,
      input.requestId,
      input.approvedBy,
      this.#clock().toISOString()
    );
    if (!approved) throw new ImmutableArtifactError("INVALID_TRANSITION", "Deletion request is not pending");
    return approved;
  }

  async execute(tenantId: string, requestId: string): Promise<ArtifactDeletionRequestV1> {
    let request = await this.#requests.get(tenantId, requestId);
    if (!request) throw new ImmutableArtifactError("NOT_FOUND", "Deletion request was not found");
    if (request.status === "completed") return request;
    const now = this.#clock();
    if (request.status !== "approved" && request.status !== "executing") {
      throw new ImmutableArtifactError("INVALID_TRANSITION", "Deletion request is not approved for execution");
    }
    if (Date.parse(request.executeAfter) > now.getTime()) {
      throw new ImmutableArtifactError("RETENTION_BLOCKED", "Deletion request has not reached its execution time");
    }
    const head = await this.#artifacts.objectStore.headObject({
      bucket: this.#artifacts.bucket,
      key: request.objectKey,
      versionId: request.objectVersionId
    });
    if (head?.legalHold === true) {
      throw new ImmutableArtifactError("RETENTION_BLOCKED", "Artifact is protected by a legal hold");
    }
    if (head?.retainUntil && Date.parse(head.retainUntil) > now.getTime()) {
      throw new ImmutableArtifactError("RETENTION_BLOCKED", "Artifact retention period has not expired");
    }

    let executionId = request.executionId;
    if (request.status === "approved") {
      executionId = randomUUID();
      const executing = await this.#requests.markExecuting(
        tenantId,
        requestId,
        executionId,
        now.toISOString()
      );
      if (!executing) throw new ImmutableArtifactError("INVALID_TRANSITION", "Deletion execution could not be fenced");
      request = executing;
    }
    if (!executionId) throw new ImmutableArtifactError("INVALID_TRANSITION", "Deletion execution is missing its fence");
    try {
      await this.#artifacts.objectStore.deleteObjectVersion({
        bucket: this.#artifacts.bucket,
        key: request.objectKey,
        versionId: request.objectVersionId
      });
      const completed = await this.#requests.markCompleted(
        tenantId,
        requestId,
        executionId,
        this.#clock().toISOString()
      );
      if (!completed) throw new ImmutableArtifactError("INVALID_TRANSITION", "Deletion completion fence was rejected");
      return completed;
    } catch (error) {
      if (error instanceof ImmutableArtifactError && error.code === "INVALID_TRANSITION") throw error;
      await this.#requests.markFailed(
        tenantId,
        requestId,
        executionId,
        "OBJECT_DELETE_FAILED",
        this.#clock().toISOString()
      );
      throw storageFailure(error);
    }
  }
}

function artifactMetadata(envelope: ArtifactEnvelopeV1): Readonly<Record<string, string>> {
  return Object.freeze({
    [METADATA.tenantBinding]: envelope.tenantBindingHash,
    [METADATA.artifactId]: envelope.artifactId,
    [METADATA.contentHash]: envelope.contentHash,
    [METADATA.byteLength]: String(envelope.byteLength),
    [METADATA.kind]: envelope.kind,
    [METADATA.mediaTypeHash]: sha256(envelope.mediaType),
    [METADATA.mediaType]: envelope.mediaType,
    [METADATA.kmsKeyIdHash]: sha256(envelope.kmsKeyId),
    [METADATA.kmsKeyVersion]: envelope.kmsKeyVersion,
    [METADATA.createdAt]: envelope.createdAt
  });
}

function assertMetadata(
  metadata: Readonly<Record<string, string>>,
  tenantBindingHash: string,
  artifactId: string,
  contentHash?: string,
  kind?: string,
  mediaType?: string
): void {
  if (
    metadata[METADATA.tenantBinding] !== tenantBindingHash ||
    metadata[METADATA.artifactId] !== artifactId ||
    (contentHash !== undefined && metadata[METADATA.contentHash] !== contentHash) ||
    (kind !== undefined && metadata[METADATA.kind] !== kind) ||
    (mediaType !== undefined && metadata[METADATA.mediaTypeHash] !== sha256(mediaType))
  ) {
    throw new ImmutableArtifactError("INTEGRITY_FAILURE", "Artifact metadata binding is invalid");
  }
}

function assertEnvelope(
  envelope: ArtifactEnvelopeV1,
  tenantBindingHash: string,
  artifactId: string,
  metadata: Readonly<Record<string, string>>
): void {
  if (
    envelope.envelopeVersion !== 1 ||
    envelope.cipher !== "AES-256-GCM" ||
    envelope.tenantBindingHash !== tenantBindingHash ||
    envelope.artifactId !== artifactId ||
    envelope.contentHash !== metadata[METADATA.contentHash] ||
    String(envelope.byteLength) !== metadata[METADATA.byteLength] ||
    envelope.kind !== metadata[METADATA.kind] ||
    sha256(envelope.mediaType) !== metadata[METADATA.mediaTypeHash] ||
    sha256(envelope.kmsKeyId) !== metadata[METADATA.kmsKeyIdHash] ||
    envelope.kmsKeyVersion !== metadata[METADATA.kmsKeyVersion] ||
    envelope.createdAt !== metadata[METADATA.createdAt] ||
    !Number.isSafeInteger(envelope.byteLength) ||
    envelope.byteLength < 1
  ) {
    throw new ImmutableArtifactError("INTEGRITY_FAILURE", "Artifact envelope binding is invalid");
  }
  validateDigest(envelope.contentHash, "contentHash");
}

function parseEnvelope(bytes: Uint8Array): ArtifactEnvelopeV1 {
  const value = JSON.parse(Buffer.from(bytes).toString("utf8")) as unknown;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ImmutableArtifactError("INTEGRITY_FAILURE", "Artifact envelope is not an object");
  }
  return value as ArtifactEnvelopeV1;
}

function recordFromEnvelope(
  tenantId: string,
  objectKey: string,
  stored: S3GetObjectResult,
  envelope: ArtifactEnvelopeV1
): ImmutableArtifactRecordV1 {
  if (!stored.versionId.trim()) {
    throw new ImmutableArtifactError("VERSIONING_REQUIRED", "Object storage did not return an immutable version id");
  }
  return Object.freeze({
    contractVersion: 1,
    tenantId,
    artifactId: envelope.artifactId,
    kind: envelope.kind,
    mediaType: envelope.mediaType,
    contentHash: envelope.contentHash,
    byteLength: envelope.byteLength,
    objectKey,
    objectVersionId: stored.versionId,
    etag: stored.etag,
    kmsKeyId: envelope.kmsKeyId,
    kmsKeyVersion: envelope.kmsKeyVersion,
    createdAt: envelope.createdAt,
    retentionMode: stored.retentionMode ?? null,
    retainUntil: stored.retainUntil ?? null,
    legalHold: stored.legalHold === true
  });
}

function recordFromHead(
  tenantId: string,
  objectKey: string,
  kmsKeyId: string,
  head: S3HeadObjectResult
): ImmutableArtifactRecordV1 {
  const artifactId = requiredMetadata(head.metadata, METADATA.artifactId);
  const kind = requiredMetadata(head.metadata, METADATA.kind);
  const contentHash = requiredMetadata(head.metadata, METADATA.contentHash);
  const byteLength = Number(requiredMetadata(head.metadata, METADATA.byteLength));
  const createdAt = normalizeTimestamp(requiredMetadata(head.metadata, METADATA.createdAt), "createdAt");
  if (!head.versionId.trim()) {
    throw new ImmutableArtifactError("VERSIONING_REQUIRED", "Object storage did not return an immutable version id");
  }
  if (!Number.isSafeInteger(byteLength) || byteLength < 1) {
    throw new ImmutableArtifactError("INTEGRITY_FAILURE", "Artifact byte length metadata is invalid");
  }
  validateDigest(artifactId, "artifactId");
  validateDigest(contentHash, "contentHash");
  return Object.freeze({
    contractVersion: 1,
    tenantId,
    artifactId,
    kind,
    mediaType: requiredMetadata(head.metadata, METADATA.mediaType),
    contentHash,
    byteLength,
    objectKey,
    objectVersionId: head.versionId,
    etag: head.etag,
    kmsKeyId,
    kmsKeyVersion: requiredMetadata(head.metadata, METADATA.kmsKeyVersion),
    createdAt,
    retentionMode: head.retentionMode ?? null,
    retainUntil: head.retainUntil ?? null,
    legalHold: head.legalHold === true
  });
}

function requiredMetadata(metadata: Readonly<Record<string, string>>, name: string): string {
  const value = metadata[name];
  if (!value) throw new ImmutableArtifactError("INTEGRITY_FAILURE", `Required artifact metadata ${name} is missing`);
  return value;
}

function artifactAad(input: {
  readonly tenantBindingHash: string;
  readonly artifactId: string;
  readonly kind: string;
  readonly mediaType: string;
  readonly contentHash: string;
  readonly byteLength: number;
  readonly kmsKeyId: string;
  readonly kmsKeyVersion: string;
  readonly createdAt: string;
}): Buffer {
  return Buffer.from(JSON.stringify({
    artifactId: input.artifactId,
    byteLength: input.byteLength,
    contentHash: input.contentHash,
    createdAt: input.createdAt,
    kind: input.kind,
    kmsKeyId: input.kmsKeyId,
    kmsKeyVersion: input.kmsKeyVersion,
    mediaType: input.mediaType,
    tenantBindingHash: input.tenantBindingHash
  }), "utf8");
}

function encryptionContext(
  tenantBindingHash: string,
  artifactId: string,
  contentHash: string,
  kind: string
): Readonly<Record<string, string>> {
  return Object.freeze({ tenantBindingHash, artifactId, contentHash, artifactKindHash: sha256(kind) });
}

function validateRetention(
  mode: "GOVERNANCE" | "COMPLIANCE" | undefined,
  retainUntil: string | undefined,
  now: Date
): { readonly mode: "GOVERNANCE" | "COMPLIANCE" | null; readonly until: string | null } {
  if ((mode === undefined) !== (retainUntil === undefined)) {
    invalid("retentionMode and retainUntil must be supplied together");
  }
  if (!mode || !retainUntil) return { mode: null, until: null };
  const until = normalizeTimestamp(retainUntil, "retainUntil");
  if (Date.parse(until) <= now.getTime()) invalid("retainUntil must be in the future");
  return { mode, until };
}

function validateRecordBinding(record: ImmutableArtifactRecordV1, bucket: string, prefix: string): void {
  if (record.contractVersion !== 1) invalid("Unsupported artifact record version");
  validateName(bucket, "bucket");
  const expected = `${prefix}/tenants/${tenantHash(record.tenantId)}/artifacts/${record.artifactId.slice(0, 2)}/${record.artifactId}`;
  if (record.objectKey !== expected) invalid("Artifact record does not belong to this repository");
}

function normalizePrefix(value: string): string {
  const normalized = value.replace(/^\/+|\/+$/g, "");
  if (!normalized || normalized.includes("..") || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    invalid("keyPrefix is invalid");
  }
  return normalized;
}

function validateName(value: string, name: string, maximum = 256): void {
  if (!value.trim() || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) {
    invalid(`${name} must contain 1 through ${maximum} printable characters`);
  }
}

function validateMediaType(value: string): void {
  validateName(value, "mediaType", 255);
  if (!/^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*(?:\s*;\s*[a-z0-9-]+=[a-z0-9._+-]+)*$/i.test(value)) {
    invalid("mediaType is invalid");
  }
}

function validateDigest(value: string, name: string): void {
  if (!/^[a-f0-9]{64}$/.test(value)) invalid(`${name} must be a lowercase SHA-256 digest`);
}

function normalizeTimestamp(value: string, name: string): string {
  const timestamp = new Date(value);
  if (!Number.isFinite(timestamp.getTime())) invalid(`${name} must be an ISO timestamp`);
  return timestamp.toISOString();
}

function decodeBase64(value: string, name: string): Buffer {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new ImmutableArtifactError("INTEGRITY_FAILURE", `${name} is not valid base64`);
  }
  return Buffer.from(value, "base64");
}

function recordErrorCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object") return undefined;
  const code = (error as { readonly code?: unknown; readonly name?: unknown }).code;
  const name = (error as { readonly code?: unknown; readonly name?: unknown }).name;
  return typeof code === "string" ? code : typeof name === "string" ? name : undefined;
}

function isPreconditionFailure(error: unknown): boolean {
  return ["PreconditionFailed", "ConditionalRequestConflict", "412"].includes(recordErrorCode(error) ?? "");
}

function storageFailure(error: unknown): ImmutableArtifactError {
  if (error instanceof ImmutableArtifactError) return error;
  return new ImmutableArtifactError("STORAGE_FAILURE", "Immutable object-store operation failed");
}

function tenantHash(tenantId: string): string {
  return sha256(`abl-tenant:${tenantId}`);
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function invalid(message: string): never {
  throw new ImmutableArtifactError("INVALID_INPUT", message);
}
