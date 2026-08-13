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
}

/**
 * Trusted capture-side publisher. It writes the exact source section as an
 * encrypted artifact, reloads it immediately, and then persists only a
 * hash-bound metadata pointer. The caller never supplies storage identifiers.
 */
export class CapturedSourceMaterialPublisherV1 {
  constructor(readonly options: CapturedSourceMaterialPublisherV1Options) {}

  async publish(inputValue: CapturedSourceSectionArtifactV1Input): Promise<{
    readonly artifact: CapturedSourceSectionArtifactV1;
    readonly metadata: CapturedSourceSectionArtifactMetadataV1;
    readonly replayed: boolean;
  }> {
    const artifact = parseCapturedSourceSectionArtifactV1({
      ...inputValue,
      artifactHash: canonicalHashForArtifact(inputValue)
    });
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
