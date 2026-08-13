import {
  canonicalJson,
  createCertifiedSnapshotArtifactMetadataV1,
  parseCertifiedSnapshotEvidenceRecordV1,
  parseDatasetSnapshotV2,
  parseGovernedDatasetScopeBindingV1,
  parseNormalizedSnapshotArtifactV2,
  parseSourceContractV1,
  type CertifiedSnapshotEvidenceRecordV1,
  type DatasetSnapshotV2
} from "../contracts/index.js";
import { ArtifactStoreError, type ArtifactStore } from "../control/artifacts.js";
import type { ImmutableRepositoryPort } from "../repositories/ports.js";
import type {
  CertifiedSnapshotPublicationEvidenceV1,
  SurveillanceSourcePublicationAuthorityV1
} from "./surveillance-source-publication.js";
import {
  GovernedDefinitionV2ResolverError,
  type GovernedDefinitionV2Resolver,
  type ResolvedGovernedDefinitionV2
} from "./governed-definition-v2-resolver.js";

const PAGE_SIZE = 1_000;
const MAX_SNAPSHOTS_PER_TENANT = 1_000_000;

export interface RepositoryBackedSurveillanceSourcePublicationAuthorityV1Dependencies {
  readonly datasetSnapshots: ImmutableRepositoryPort<DatasetSnapshotV2>;
  readonly certifiedSnapshotEvidence: ImmutableRepositoryPort<CertifiedSnapshotEvidenceRecordV1>;
  readonly artifacts: Pick<ArtifactStore, "getJson">;
  readonly definitions: Pick<GovernedDefinitionV2Resolver, "resolveFrozen">;
}

export type SurveillanceProductionAuthorityErrorCode =
  | "INTEGRITY_FAILURE"
  | "NON_TERMINAL_SNAPSHOT"
  | "RESOURCE_LIMIT";

export class SurveillanceProductionAuthorityError extends Error {
  constructor(readonly code: SurveillanceProductionAuthorityErrorCode, message: string) {
    super(message);
    this.name = "SurveillanceProductionAuthorityError";
  }
}

/**
 * Production publication authority for the modern SnapshotV2 evidence path.
 * It accepts identifiers only, reloads every immutable record from its tenant
 * repository, and obtains artifact metadata exclusively from tenant-scoped
 * ArtifactStore.getJson. It does not accept caller-provided hashes, records,
 * StoredArtifact metadata, or dataset/scope projections.
 */
export class RepositoryBackedSurveillanceSourcePublicationAuthorityV1
  implements SurveillanceSourcePublicationAuthorityV1
{
  readonly #dependencies: RepositoryBackedSurveillanceSourcePublicationAuthorityV1Dependencies;

  constructor(dependencies: RepositoryBackedSurveillanceSourcePublicationAuthorityV1Dependencies) {
    this.#dependencies = dependencies;
  }

  async resolveDatasetSnapshotV2(input: {
    readonly tenantId: string;
    readonly datasetSnapshotId: string;
    readonly certificationManifestId: string;
  }): Promise<DatasetSnapshotV2 | undefined> {
    const [snapshotValue, evidenceValue] = await Promise.all([
      this.#dependencies.datasetSnapshots.get(input.tenantId, input.datasetSnapshotId),
      this.#dependencies.certifiedSnapshotEvidence.get(
        input.tenantId,
        input.certificationManifestId
      )
    ]);
    if (!snapshotValue || !evidenceValue) return undefined;
    const snapshot = verified(() => parseDatasetSnapshotV2(snapshotValue));
    const evidence = verified(() => parseCertifiedSnapshotEvidenceRecordV1(evidenceValue));
    if (
      snapshot.tenantId !== input.tenantId ||
      snapshot.snapshotId !== input.datasetSnapshotId ||
      evidence.tenantId !== input.tenantId ||
      evidence.certification.certificationManifestId !== input.certificationManifestId ||
      evidence.certification.snapshotId !== snapshot.snapshotId ||
      evidence.certification.snapshotHash !== snapshot.snapshotHash
    ) {
      integrity("Snapshot and certification repositories returned inconsistent tenant lineage");
    }
    await this.#assertTerminalSnapshot(snapshot);
    return snapshot;
  }

  resolveFrozenDatasetBinding(input: {
    readonly tenantId: string;
    readonly datasetBindingDefinitionVersionId: string;
  }): ResolvedGovernedDefinitionV2 | undefined {
    const resolved = this.#resolveDefinition(
      input.tenantId,
      input.datasetBindingDefinitionVersionId
    );
    if (!resolved) return undefined;
    if (resolved.reference.kind !== "dataset_scope_binding") {
      integrity("Dataset binding definition id resolved to another governed definition kind");
    }
    const document = verified(() =>
      parseGovernedDatasetScopeBindingV1(resolved.executionDocument)
    );
    if (
      document.tenantId !== input.tenantId ||
      resolved.reference.definitionVersionId !== input.datasetBindingDefinitionVersionId
    ) {
      integrity("Frozen dataset binding crossed its requested tenant or version boundary");
    }
    return resolved;
  }

  resolveFrozenSourceContract(input: {
    readonly tenantId: string;
    readonly sourceContractDefinitionVersionId: string;
  }): ResolvedGovernedDefinitionV2 | undefined {
    const resolved = this.#resolveDefinition(
      input.tenantId,
      input.sourceContractDefinitionVersionId
    );
    if (!resolved) return undefined;
    if (resolved.reference.kind !== "source_contract") {
      integrity("Source contract definition id resolved to another governed definition kind");
    }
    const document = verified(() => parseSourceContractV1(resolved.executionDocument));
    if (
      document.tenantId !== input.tenantId ||
      resolved.reference.definitionVersionId !== input.sourceContractDefinitionVersionId
    ) {
      integrity("Frozen source contract crossed its requested tenant or version boundary");
    }
    return resolved;
  }

  async resolveCertifiedPublicationEvidence(input: {
    readonly tenantId: string;
    readonly certificationManifestId: string;
  }): Promise<CertifiedSnapshotPublicationEvidenceV1 | undefined> {
    const evidenceValue = await this.#dependencies.certifiedSnapshotEvidence.get(
      input.tenantId,
      input.certificationManifestId
    );
    if (!evidenceValue) return undefined;
    const evidence = verified(() => parseCertifiedSnapshotEvidenceRecordV1(evidenceValue));
    if (
      evidence.tenantId !== input.tenantId ||
      evidence.certification.certificationManifestId !== input.certificationManifestId ||
      evidence.normalizedArtifact.tenantId !== input.tenantId
    ) {
      integrity("Certified evidence crossed its requested tenant or manifest boundary");
    }

    let loaded: ReturnType<ArtifactStore["getJson"]>;
    try {
      loaded = this.#dependencies.artifacts.getJson(
        input.tenantId,
        evidence.normalizedArtifact.artifactId
      );
    } catch (error) {
      if (error instanceof ArtifactStoreError) {
        integrity(`Tenant-scoped normalized artifact reload failed: ${error.code}`);
      }
      throw error;
    }
    const artifact = verified(() => parseNormalizedSnapshotArtifactV2(loaded.value));
    if (artifact.tenantId !== input.tenantId) {
      integrity("Normalized artifact payload tenant does not match its tenant-scoped lookup");
    }
    const verifiedMetadata = verified(() =>
      createCertifiedSnapshotArtifactMetadataV1({
        artifact,
        loadedStoredArtifact: loaded.metadata
      })
    );
    if (canonicalJson(verifiedMetadata) !== canonicalJson(evidence.normalizedArtifact)) {
      integrity("Reloaded artifact metadata or payload does not match certified evidence");
    }

    return Object.freeze({
      certification: evidence.certification,
      population: evidence.population,
      mappingSpec: evidence.mappingSpec,
      mappingApplication: evidence.mappingApplication,
      normalizedArtifactIdentity: {
        artifactContractVersion: artifact.contractVersion,
        artifactHash: artifact.artifactHash
      },
      normalizedArtifact: loaded.metadata
    });
  }

  #resolveDefinition(
    tenantId: string,
    definitionVersionId: string
  ): ResolvedGovernedDefinitionV2 | undefined {
    try {
      return this.#dependencies.definitions.resolveFrozen({ tenantId, definitionVersionId });
    } catch (error) {
      if (
        error instanceof GovernedDefinitionV2ResolverError &&
        (error.code === "NOT_FOUND" || error.code === "UNAPPROVED")
      ) {
        return undefined;
      }
      throw error;
    }
  }

  async #assertTerminalSnapshot(snapshot: DatasetSnapshotV2): Promise<void> {
    let cursor: string | undefined;
    let seen = 0;
    do {
      const page = await this.#dependencies.datasetSnapshots.list(snapshot.tenantId, {
        limit: PAGE_SIZE,
        ...(cursor === undefined ? {} : { cursor })
      });
      seen += page.items.length;
      if (seen > MAX_SNAPSHOTS_PER_TENANT) {
        throw new SurveillanceProductionAuthorityError(
          "RESOURCE_LIMIT",
          "Tenant snapshot history exceeds the publication resolution bound"
        );
      }
      for (const candidateValue of page.items) {
        const candidate = verified(() => parseDatasetSnapshotV2(candidateValue));
        if (
          candidate.correction.kind === "correction" &&
          candidate.correction.correctsSnapshotId === snapshot.snapshotId &&
          candidate.correction.correctsSnapshotHash === snapshot.snapshotHash
        ) {
          throw new SurveillanceProductionAuthorityError(
            "NON_TERMINAL_SNAPSHOT",
            "A corrected snapshot cannot be selected for a new publication"
          );
        }
      }
      cursor = page.nextCursor ?? undefined;
    } while (cursor !== undefined);
  }
}

function verified<T>(operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    if (error instanceof SurveillanceProductionAuthorityError) throw error;
    const detail = error instanceof Error ? `: ${error.message}` : "";
    throw new SurveillanceProductionAuthorityError(
      "INTEGRITY_FAILURE",
      `Authoritative surveillance evidence failed verification${detail}`
    );
  }
}

function integrity(message: string): never {
  throw new SurveillanceProductionAuthorityError("INTEGRITY_FAILURE", message);
}
