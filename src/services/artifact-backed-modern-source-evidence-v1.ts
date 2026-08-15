import {
  canonicalHash,
  canonicalJson
} from "../contracts/canonical.js";
import {
  createCapturedSourceSectionArtifactMetadataV1,
  parseCapturedSourceSectionArtifactV1,
  type CapturedSourceSectionArtifactV1,
  type CapturedSourceSectionArtifactV1Input,
  type CapturedSourceSectionArtifactMetadataV1
} from "../contracts/captured-source-section-artifact-v1.js";
import { artifactJsonContentHash, type ArtifactStore, type StoredArtifact } from "../control/artifacts.js";
import type { CapturedSourceMaterialStoreV1 } from "../repositories/captured-source-material-v1.js";
import type {
  CapturedSourcePopulationV2,
  ModernSnapshotSourceEvidenceAuthorityV1
} from "./modern-snapshot-certification.js";

const ARTIFACT_HASH_CANONICAL_FIELD_BYTES = Buffer.byteLength(
  `,"artifactHash":"sha256:${"0".repeat(64)}"`,
  "utf8"
);

export type CapturedSourceMaterialErrorCode = "INVALID_ARGUMENT" | "NOT_FOUND" | "INTEGRITY_FAILURE";

export class CapturedSourceMaterialError extends Error {
  constructor(readonly code: CapturedSourceMaterialErrorCode, message: string) {
    super(message);
    this.name = "CapturedSourceMaterialError";
  }
}

export interface CapturedSourceMaterialPublisherV1Options {
  readonly artifacts: Pick<ArtifactStore, "putJson" | "getJson">;
  readonly material: CapturedSourceMaterialStoreV1;
  /**
   * Maximum canonical JSON bytes for one captured source-section artifact.
   * This is a storage bound, not extraction authority: the active source
   * contract must independently govern the source delivery byte limit.
   */
  readonly maximumSectionBytes: number;
}

/**
 * Trusted capture-side publisher. It writes the exact source section as an
 * encrypted artifact, reloads it immediately, and then persists only a
 * hash-bound metadata pointer. The caller never supplies storage identifiers.
 */
export class CapturedSourceMaterialPublisherV1 {
  readonly #maximumSectionBytes: number;

  constructor(readonly options: CapturedSourceMaterialPublisherV1Options) {
    this.#maximumSectionBytes = sourceMaterialMaximumBytes(options.maximumSectionBytes);
  }

  async publish(inputValue: CapturedSourceSectionArtifactV1Input): Promise<{
    readonly artifact: CapturedSourceSectionArtifactV1;
    readonly metadata: CapturedSourceSectionArtifactMetadataV1;
    readonly replayed: boolean;
  }> {
    // The authenticated artifact adds one fixed-width hash field to this
    // non-empty object. Count first without materializing the complete JSON so
    // an oversized section fails before canonical hashing or encryption.
    if (
      boundedCanonicalJsonByteLength(
        inputValue,
        this.#maximumSectionBytes - ARTIFACT_HASH_CANONICAL_FIELD_BYTES
      ) > this.#maximumSectionBytes - ARTIFACT_HASH_CANONICAL_FIELD_BYTES
    ) {
      throw new CapturedSourceMaterialError(
        "INVALID_ARGUMENT",
        "Captured source artifact exceeds the configured section byte limit"
      );
    }
    const artifact = parseCapturedSourceSectionArtifactV1({
      ...inputValue,
      artifactHash: canonicalHashForArtifact(inputValue)
    });
    const artifactBytes = Buffer.byteLength(canonicalJson(artifact), "utf8");
    if (artifactBytes > this.#maximumSectionBytes) {
      throw new CapturedSourceMaterialError(
        "INVALID_ARGUMENT",
        "Captured source artifact exceeds the configured section byte limit"
      );
    }
    const existing = await this.options.material.get({
      tenantId: artifact.tenantId,
      snapshotId: artifact.snapshotId,
      sectionId: artifact.sectionId
    });
    if (existing !== undefined) {
      return this.#replayExisting(artifact, existing);
    }
    const stored = this.options.artifacts.putJson({
      tenantId: artifact.tenantId,
      kind: "captured_source_section",
      mediaType: "application/json",
      value: artifact
    });
    const reloaded = this.options.artifacts.getJson(artifact.tenantId, stored.artifactId);
    const loadedArtifact = parseCapturedSourceSectionArtifactV1(reloaded.value);
    if (canonicalJson(loadedArtifact) !== canonicalJson(artifact)) {
      throw new CapturedSourceMaterialError("INTEGRITY_FAILURE", "Captured source artifact reload drifted");
    }
    const metadata = metadataFor(artifact, reloaded.metadata);
    let persisted: Awaited<ReturnType<CapturedSourceMaterialStoreV1["put"]>>;
    try {
      persisted = await this.options.material.put(metadata);
    } catch (error) {
      const raced = await this.options.material.get({
        tenantId: artifact.tenantId,
        snapshotId: artifact.snapshotId,
        sectionId: artifact.sectionId
      });
      if (raced !== undefined) return this.#replayExisting(artifact, raced);
      throw error;
    }
    if (canonicalJson(persisted.metadata) !== canonicalJson(metadata)) {
      throw new CapturedSourceMaterialError("INTEGRITY_FAILURE", "Captured source metadata replay drifted");
    }
    return Object.freeze({ artifact, metadata: persisted.metadata, replayed: persisted.replayed });
  }

  async resolveReplayIdentity(input: {
    readonly tenantId: string;
    readonly snapshotId: string;
    readonly sourceContract: {
      readonly sourceContractId: string;
      readonly revision: number;
      readonly sourceContractHash: string;
    };
    readonly sectionIds: readonly string[];
  }): Promise<
    | {
        readonly snapshotHash: `sha256:${string}`;
        readonly extractionReceiptHash: `sha256:${string}`;
        readonly capturedAt: string;
      }
    | undefined
  > {
    const sectionIds = [...new Set(input.sectionIds)].sort();
    if (sectionIds.length === 0) return undefined;
    const existing = await Promise.all(
      sectionIds.map((sectionId) =>
        this.options.material.get({
          tenantId: input.tenantId,
          snapshotId: input.snapshotId,
          sectionId
        })
      )
    );
    if (existing.every((metadata) => metadata === undefined)) return undefined;
    const artifacts = await Promise.all(
      existing
        .filter((metadata): metadata is CapturedSourceSectionArtifactMetadataV1 => metadata !== undefined)
        .map((metadata) => this.#loadStoredArtifact(input.tenantId, metadata))
    );
    const first = artifacts[0]!;
    for (const artifact of artifacts) {
      if (
        artifact.tenantId !== input.tenantId ||
        artifact.snapshotId !== input.snapshotId ||
        canonicalJson(artifact.sourceContract) !== canonicalJson(input.sourceContract) ||
        artifact.snapshotHash !== first.snapshotHash ||
        artifact.extractionReceiptHash !== first.extractionReceiptHash ||
        artifact.capturedAt !== first.capturedAt
      ) {
        throw new CapturedSourceMaterialError(
          "INTEGRITY_FAILURE",
          "Interrupted capture source material does not share one immutable lineage"
        );
      }
    }
    return Object.freeze({
      snapshotHash: first.snapshotHash,
      extractionReceiptHash: first.extractionReceiptHash,
      capturedAt: first.capturedAt
    });
  }

  async #replayExisting(
    candidate: CapturedSourceSectionArtifactV1,
    metadata: CapturedSourceSectionArtifactMetadataV1
  ): Promise<{
    readonly artifact: CapturedSourceSectionArtifactV1;
    readonly metadata: CapturedSourceSectionArtifactMetadataV1;
    readonly replayed: boolean;
  }> {
    const artifact = this.#loadStoredArtifact(candidate.tenantId, metadata);
    if (canonicalJson(artifact) !== canonicalJson(candidate)) {
      throw new CapturedSourceMaterialError(
        "INTEGRITY_FAILURE",
        "Existing captured source material does not match the exact capture replay"
      );
    }
    return Object.freeze({ artifact, metadata, replayed: true });
  }

  #loadStoredArtifact(
    tenantId: string,
    metadata: CapturedSourceSectionArtifactMetadataV1
  ): CapturedSourceSectionArtifactV1 {
    let loaded: ReturnType<ArtifactStore["getJson"]>;
    try {
      loaded = this.options.artifacts.getJson(tenantId, metadata.artifactId);
    } catch {
      throw new CapturedSourceMaterialError("INTEGRITY_FAILURE", "Existing captured source artifact is unavailable");
    }
    const artifact = parseCapturedSourceSectionArtifactV1(loaded.value);
    const expectedMetadata = metadataFor(artifact, loaded.metadata);
    if (canonicalJson(expectedMetadata) !== canonicalJson(metadata)) {
      throw new CapturedSourceMaterialError(
        "INTEGRITY_FAILURE",
        "Existing captured source metadata does not bind its stored artifact"
      );
    }
    return artifact;
  }
}

function sourceMaterialMaximumBytes(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1_024 || value > 100_000_000) {
    throw new CapturedSourceMaterialError(
      "INVALID_ARGUMENT",
      "maximumSectionBytes must be an integer from 1024 through 100000000"
    );
  }
  return value;
}

function boundedCanonicalJsonByteLength(value: unknown, maximumBytes: number): number {
  const ancestors = new Set<object>();
  const measure = (candidate: unknown): number => {
    if (candidate === null) return 4;
    if (typeof candidate === "boolean") return candidate ? 4 : 5;
    if (typeof candidate === "number") {
      if (!Number.isSafeInteger(candidate)) return maximumBytes + 1;
      return Buffer.byteLength(Object.is(candidate, -0) ? "0" : String(candidate), "utf8");
    }
    if (typeof candidate === "string") {
      if (candidate.length > maximumBytes) return maximumBytes + 1;
      return Buffer.byteLength(JSON.stringify(candidate), "utf8");
    }
    if (typeof candidate !== "object" || ancestors.has(candidate)) return maximumBytes + 1;

    ancestors.add(candidate);
    try {
      if (Array.isArray(candidate)) {
        let total = 2;
        for (let index = 0; index < candidate.length; index += 1) {
          if (!(index in candidate)) return maximumBytes + 1;
          if (index > 0) total += 1;
          total += measure(candidate[index]);
          if (total > maximumBytes) return total;
        }
        return total;
      }

      const prototype = Object.getPrototypeOf(candidate) as object | null;
      if (
        (prototype !== Object.prototype && prototype !== null) ||
        Object.getOwnPropertySymbols(candidate).length > 0
      ) {
        return maximumBytes + 1;
      }
      const record = candidate as Record<string, unknown>;
      let total = 2;
      let index = 0;
      for (const key of Object.keys(record)) {
        const nested = record[key];
        if (nested === undefined) return maximumBytes + 1;
        if (index > 0) total += 1;
        total += Buffer.byteLength(JSON.stringify(key), "utf8") + 1 + measure(nested);
        if (total > maximumBytes) return total;
        index += 1;
      }
      return total;
    } finally {
      ancestors.delete(candidate);
    }
  };
  return measure(value);
}

export interface ArtifactBackedModernSnapshotSourceEvidenceAuthorityV1Options {
  readonly artifacts: Pick<ArtifactStore, "getJson">;
  readonly material: CapturedSourceMaterialStoreV1;
}

/** Production-shaped implementation of certification's source-evidence port. */
export class ArtifactBackedModernSnapshotSourceEvidenceAuthorityV1
  implements ModernSnapshotSourceEvidenceAuthorityV1
{
  constructor(readonly options: ArtifactBackedModernSnapshotSourceEvidenceAuthorityV1Options) {}

  async loadSection(input: {
    readonly tenantId: string;
    readonly snapshotId: string;
    readonly sectionId: string;
  }): Promise<CapturedSourcePopulationV2 | undefined> {
    const metadata = await this.options.material.get(input);
    if (!metadata) return undefined;
    let loaded: ReturnType<ArtifactStore["getJson"]>;
    try {
      loaded = this.options.artifacts.getJson(input.tenantId, metadata.artifactId);
    } catch {
      throw new CapturedSourceMaterialError("INTEGRITY_FAILURE", "Captured source artifact is unavailable");
    }
    const artifact = parseCapturedSourceSectionArtifactV1(loaded.value);
    const expectedMetadata = metadataFor(artifact, loaded.metadata);
    if (canonicalJson(expectedMetadata) !== canonicalJson(metadata)) {
      throw new CapturedSourceMaterialError("INTEGRITY_FAILURE", "Captured source metadata does not bind the loaded artifact");
    }
    if (
      artifact.tenantId !== input.tenantId ||
      artifact.snapshotId !== input.snapshotId ||
      artifact.sectionId !== input.sectionId
    ) {
      throw new CapturedSourceMaterialError("INTEGRITY_FAILURE", "Captured source artifact crossed the requested lineage boundary");
    }
    return Object.freeze({
      tenantId: artifact.tenantId,
      snapshotId: artifact.snapshotId,
      snapshotHash: artifact.snapshotHash,
      sourceContract: artifact.sourceContract,
      sectionId: artifact.sectionId,
      extractionHash: artifact.extractionReceiptHash,
      sectionContentHash: artifact.sectionContentHash,
      sectionSchemaHash: artifact.sectionSchemaHash,
      controlPopulationHash: artifact.controlPopulationHash,
      records: Object.freeze(artifact.records.map((record) => Object.freeze({ ...record })))
    });
  }
}

function canonicalHashForArtifact(input: CapturedSourceSectionArtifactV1Input): string {
  return canonicalHash(input);
}

function metadataFor(
  artifact: CapturedSourceSectionArtifactV1,
  stored: StoredArtifact
): CapturedSourceSectionArtifactMetadataV1 {
  if (
    stored.kind !== "captured_source_section" ||
    stored.mediaType !== "application/json" ||
    stored.contentHash !== artifactJsonContentHash(artifact) ||
    stored.uri !== `abl-artifact://${stored.artifactId}`
  ) {
    throw new CapturedSourceMaterialError("INTEGRITY_FAILURE", "Captured source storage metadata does not match the artifact");
  }
  return createCapturedSourceSectionArtifactMetadataV1({
    contractVersion: 1,
    tenantId: artifact.tenantId,
    snapshotId: artifact.snapshotId,
    snapshotHash: artifact.snapshotHash,
    sectionId: artifact.sectionId,
    artifactHash: artifact.artifactHash,
    artifactId: stored.artifactId,
    contentHash: stored.contentHash,
    byteLength: stored.byteLength,
    keyId: stored.keyId,
    uri: stored.uri,
    storedAt: artifact.capturedAt
  });
}
