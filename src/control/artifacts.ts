import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual
} from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeFileSync
} from "node:fs";
import { dirname, join, resolve } from "node:path";

export interface ArtifactKeyRing {
  readonly activeKeyId: string;
  readonly keys: Readonly<Record<string, Uint8Array>>;
}

export interface PutArtifactInput {
  readonly tenantId: string;
  readonly kind: string;
  readonly mediaType: string;
  readonly value: unknown;
}

export interface StoredArtifact {
  readonly artifactId: string;
  readonly tenantBinding: string;
  readonly kind: string;
  readonly mediaType: string;
  readonly contentHash: string;
  readonly byteLength: number;
  readonly keyId: string;
  readonly uri: string;
}

export interface ArtifactStoreOptions {
  readonly maximumArtifactBytes?: number;
}

export class ArtifactStoreError extends Error {
  constructor(
    readonly code:
      | "INVALID_INPUT"
      | "ARTIFACT_NOT_FOUND"
      | "ARTIFACT_TOO_LARGE"
      | "UNKNOWN_KEY"
      | "INTEGRITY_FAILURE",
    message: string
  ) {
    super(message);
    this.name = "ArtifactStoreError";
  }
}

interface ArtifactEnvelope {
  readonly version: 1;
  readonly artifactId: string;
  readonly tenantBinding: string;
  readonly kind: string;
  readonly mediaType: string;
  readonly contentHash: string;
  readonly byteLength: number;
  readonly keyId: string;
  readonly iv: string;
  readonly authenticationTag: string;
  readonly ciphertext: string;
}

/**
 * Computes the exact content hash ArtifactStore.putJson will persist without
 * performing encryption, directory creation, or any other write.
 */
export function artifactJsonContentHash(value: unknown): string {
  return sha256(Buffer.from(canonicalJson(value), "utf8"));
}

/** Encrypted, content-addressed, write-once JSON artifacts partitioned by tenant. */
export class ArtifactStore {
  readonly #rootPath: string;
  readonly #keyRing: ArtifactKeyRing;
  readonly #maximumArtifactBytes: number;

  constructor(rootPath: string, keyRing: ArtifactKeyRing, options: ArtifactStoreOptions = {}) {
    if (!rootPath.trim()) throw new ArtifactStoreError("INVALID_INPUT", "Artifact root path is required");
    this.#rootPath = resolve(rootPath);
    this.#keyRing = validateKeyRing(keyRing);
    this.#maximumArtifactBytes = options.maximumArtifactBytes ?? 10_000_000;
    if (
      !Number.isSafeInteger(this.#maximumArtifactBytes) ||
      this.#maximumArtifactBytes < 1_024 ||
      this.#maximumArtifactBytes > 100_000_000
    ) {
      throw new ArtifactStoreError(
        "INVALID_INPUT",
        "maximumArtifactBytes must be an integer from 1024 through 100000000"
      );
    }
    mkdirSync(this.#rootPath, { recursive: true, mode: 0o700 });
  }

  putJson(input: PutArtifactInput): StoredArtifact {
    const tenantId = requiredIdentifier(input.tenantId, "tenant id");
    const kind = requiredIdentifier(input.kind, "artifact kind");
    const mediaType = requiredMediaType(input.mediaType);
    const plaintext = Buffer.from(canonicalJson(input.value), "utf8");
    if (plaintext.byteLength > this.#maximumArtifactBytes) {
      throw new ArtifactStoreError("ARTIFACT_TOO_LARGE", "Artifact exceeds the configured byte limit");
    }

    const contentHash = sha256(plaintext);
    const tenantBinding = tenantDigest(tenantId, this.#activeKey());
    const artifactId = createHmac("sha256", this.#activeKey())
      .update(canonicalJson({ tenantBinding, kind, mediaType, contentHash }))
      .digest("hex");
    const path = this.#artifactPath(tenantBinding, artifactId);
    if (!existsSync(path)) {
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", this.#activeKey(), iv);
      cipher.setAAD(aad({ artifactId, tenantBinding, kind, mediaType, contentHash, byteLength: plaintext.byteLength }));
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const envelope: ArtifactEnvelope = {
        version: 1,
        artifactId,
        tenantBinding,
        kind,
        mediaType,
        contentHash,
        byteLength: plaintext.byteLength,
        keyId: this.#keyRing.activeKeyId,
        iv: iv.toString("base64"),
        authenticationTag: cipher.getAuthTag().toString("base64"),
        ciphertext: ciphertext.toString("base64")
      };
      writeOnce(path, Buffer.from(`${canonicalJson(envelope)}\n`, "utf8"));
    }

    const stored = this.#readEnvelope(path);
    this.#assertEnvelopeMatches(stored, { artifactId, tenantBinding, kind, mediaType, contentHash });
    return metadata(stored);
  }

  getJson(tenantIdInput: string, artifactIdInput: string): { readonly metadata: StoredArtifact; readonly value: unknown } {
    const tenantId = requiredIdentifier(tenantIdInput, "tenant id");
    const artifactId = requiredHash(artifactIdInput, "artifact id");
    const candidateBindings = Object.values(this.#keyRing.keys).map((key) => tenantDigest(tenantId, Buffer.from(key)));
    const located = candidateBindings
      .map((tenantBinding) => ({ tenantBinding, path: this.#artifactPath(tenantBinding, artifactId) }))
      .find(({ path }) => existsSync(path));
    if (!located) throw new ArtifactStoreError("ARTIFACT_NOT_FOUND", "Artifact was not found");

    const envelope = this.#readEnvelope(located.path);
    if (envelope.tenantBinding !== located.tenantBinding || envelope.artifactId !== artifactId) {
      throw new ArtifactStoreError("INTEGRITY_FAILURE", "Artifact identity did not match its storage location");
    }
    const keyBytes = this.#keyRing.keys[envelope.keyId];
    if (!keyBytes) throw new ArtifactStoreError("UNKNOWN_KEY", "Artifact encryption key is not available");
    const key = Buffer.from(keyBytes);
    const iv = strictBase64(envelope.iv, 12, "initialization vector");
    const authenticationTag = strictBase64(envelope.authenticationTag, 16, "authentication tag");
    const ciphertext = strictBase64(envelope.ciphertext, undefined, "ciphertext");

    try {
      const decipher = createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAAD(
        aad({
          artifactId: envelope.artifactId,
          tenantBinding: envelope.tenantBinding,
          kind: envelope.kind,
          mediaType: envelope.mediaType,
          contentHash: envelope.contentHash,
          byteLength: envelope.byteLength
        })
      );
      decipher.setAuthTag(authenticationTag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      if (plaintext.byteLength !== envelope.byteLength || !safeEqual(sha256(plaintext), envelope.contentHash)) {
        throw new ArtifactStoreError("INTEGRITY_FAILURE", "Artifact content hash did not verify");
      }
      return { metadata: metadata(envelope), value: JSON.parse(plaintext.toString("utf8")) as unknown };
    } catch (error) {
      if (error instanceof ArtifactStoreError) throw error;
      throw new ArtifactStoreError("INTEGRITY_FAILURE", "Artifact authentication failed");
    }
  }

  #activeKey(): Buffer {
    return Buffer.from(this.#keyRing.keys[this.#keyRing.activeKeyId]!);
  }

  #artifactPath(tenantBinding: string, artifactId: string): string {
    return join(this.#rootPath, tenantBinding.slice(0, 2), tenantBinding, `${artifactId}.json.enc`);
  }

  #readEnvelope(path: string): ArtifactEnvelope {
    let parsed: unknown;
    try {
      const data = readFileSync(path);
      if (data.byteLength > Math.ceil((this.#maximumArtifactBytes * 4) / 3) + 16_384) {
        throw new ArtifactStoreError("ARTIFACT_TOO_LARGE", "Stored artifact exceeds the configured byte limit");
      }
      parsed = JSON.parse(data.toString("utf8"));
    } catch (error) {
      if (error instanceof ArtifactStoreError) throw error;
      throw new ArtifactStoreError("INTEGRITY_FAILURE", "Artifact envelope is unreadable");
    }
    return parseEnvelope(parsed);
  }

  #assertEnvelopeMatches(
    envelope: ArtifactEnvelope,
    expected: Pick<ArtifactEnvelope, "artifactId" | "tenantBinding" | "kind" | "mediaType" | "contentHash">
  ): void {
    for (const key of ["artifactId", "tenantBinding", "kind", "mediaType", "contentHash"] as const) {
      if (!safeEqual(envelope[key], expected[key])) {
        throw new ArtifactStoreError("INTEGRITY_FAILURE", "Stored artifact does not match the requested content");
      }
    }
  }
}

function validateKeyRing(keyRing: ArtifactKeyRing): ArtifactKeyRing {
  const activeKeyId = requiredIdentifier(keyRing.activeKeyId, "active key id");
  const entries = Object.entries(keyRing.keys);
  if (entries.length === 0 || entries.length > 32) {
    throw new ArtifactStoreError("INVALID_INPUT", "Artifact key ring must contain 1 through 32 keys");
  }
  const keys: Record<string, Uint8Array> = {};
  for (const [keyIdInput, keyBytes] of entries) {
    const keyId = requiredIdentifier(keyIdInput, "key id");
    if (!(keyBytes instanceof Uint8Array) || keyBytes.byteLength !== 32) {
      throw new ArtifactStoreError("INVALID_INPUT", `Artifact key ${keyId} must contain exactly 32 bytes`);
    }
    keys[keyId] = Uint8Array.from(keyBytes);
  }
  if (!keys[activeKeyId]) throw new ArtifactStoreError("INVALID_INPUT", "Active artifact key is missing");
  return Object.freeze({ activeKeyId, keys: Object.freeze(keys) });
}

function parseEnvelope(value: unknown): ArtifactEnvelope {
  if (!value || typeof value !== "object") {
    throw new ArtifactStoreError("INTEGRITY_FAILURE", "Artifact envelope is invalid");
  }
  const record = value as Record<string, unknown>;
  if (
    record.version !== 1 ||
    typeof record.artifactId !== "string" ||
    typeof record.tenantBinding !== "string" ||
    typeof record.kind !== "string" ||
    typeof record.mediaType !== "string" ||
    typeof record.contentHash !== "string" ||
    !Number.isSafeInteger(record.byteLength) ||
    (record.byteLength as number) < 0 ||
    typeof record.keyId !== "string" ||
    typeof record.iv !== "string" ||
    typeof record.authenticationTag !== "string" ||
    typeof record.ciphertext !== "string"
  ) {
    throw new ArtifactStoreError("INTEGRITY_FAILURE", "Artifact envelope fields are invalid");
  }
  requiredHash(record.artifactId, "artifact id");
  requiredHash(record.tenantBinding, "tenant binding");
  requiredHash(record.contentHash, "content hash");
  return record as unknown as ArtifactEnvelope;
}

function metadata(envelope: ArtifactEnvelope): StoredArtifact {
  return Object.freeze({
    artifactId: envelope.artifactId,
    tenantBinding: envelope.tenantBinding,
    kind: envelope.kind,
    mediaType: envelope.mediaType,
    contentHash: envelope.contentHash,
    byteLength: envelope.byteLength,
    keyId: envelope.keyId,
    uri: `abl-artifact://${envelope.artifactId}`
  });
}

function aad(
  value: Pick<ArtifactEnvelope, "artifactId" | "tenantBinding" | "kind" | "mediaType" | "contentHash" | "byteLength">
): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}

function tenantDigest(tenantId: string, key: Buffer): string {
  return createHmac("sha256", key).update(`tenant\u0000${tenantId}`).digest("hex");
}

function writeOnce(path: string, data: Buffer): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporaryPath = `${path}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporaryPath, data, { flag: "wx", mode: 0o600 });
    const file = openSync(temporaryPath, "r");
    try {
      fsyncSync(file);
    } finally {
      closeSync(file);
    }
    try {
      linkSync(temporaryPath, path);
    } catch (error) {
      if (!existsSync(path)) throw error;
    }
    const directory = openSync(dirname(path), "r");
    try {
      fsyncSync(directory);
    } finally {
      closeSync(directory);
    }
  } finally {
    try {
      unlinkSync(temporaryPath);
    } catch {
      // The temporary path may already be absent after an interrupted write.
    }
  }
}

function requiredIdentifier(value: string, label: string): string {
  if (!value || value.length > 256 || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(value)) {
    throw new ArtifactStoreError("INVALID_INPUT", `${label} is invalid`);
  }
  return value;
}

function requiredMediaType(value: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$/.test(value)) {
    throw new ArtifactStoreError("INVALID_INPUT", "Artifact media type is invalid");
  }
  return value.toLowerCase();
}

function requiredHash(value: string, label: string): string {
  if (!/^[a-f0-9]{64}$/.test(value)) throw new ArtifactStoreError("INVALID_INPUT", `${label} is invalid`);
  return value;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    if (value instanceof Date) return value.toISOString();
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, nested]) => nested !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalize(nested)])
    );
  }
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new ArtifactStoreError("INVALID_INPUT", "Artifacts cannot contain non-finite numbers");
  }
  return value;
}

function strictBase64(value: string, expectedBytes: number | undefined, label: string): Buffer {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new ArtifactStoreError("INTEGRITY_FAILURE", `Artifact ${label} is invalid`);
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value || (expectedBytes !== undefined && bytes.byteLength !== expectedBytes)) {
    throw new ArtifactStoreError("INTEGRITY_FAILURE", `Artifact ${label} is invalid`);
  }
  return bytes;
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.byteLength === rightBytes.byteLength && timingSafeEqual(leftBytes, rightBytes);
}
