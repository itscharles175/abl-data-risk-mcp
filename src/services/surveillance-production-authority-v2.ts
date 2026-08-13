import {
  canonicalHash,
  canonicalJson,
  createCertifiedSnapshotArtifactMetadataV1,
  parseDatasetSnapshotV2,
  parseGovernedDatasetScopeBindingV1,
  parseMappingSpecV2,
  parseNormalizedSnapshotArtifactV2,
  parseSnapshotCertificationDefinitionV1,
  parseSourceContractV1,
  type DatasetSnapshotV2
} from "../contracts/index.js";
import {
  parseCertifiedSnapshotEvidenceRecordV2,
  type CertifiedSnapshotEvidenceRecordV2
} from "../contracts/certified-snapshot-evidence-v2.js";
import {
  parseGovernedCertifiedSnapshotPublicationLinkV2,
  type GovernedCertifiedSnapshotPublicationLinkV2
} from "../contracts/governed-certified-snapshot-publication-link-v2.js";
import { ArtifactStoreError, type ArtifactStore, type StoredArtifact } from "../control/artifacts.js";
import type { GovernedSnapshotCaptureLineageReadPortV1, GovernedSnapshotCommitLineageV1 } from "../repositories/governed-snapshot-commit.js";
import type { ImmutableRepositoryPort } from "../repositories/ports.js";
import {
  GovernedDefinitionV2ResolverError,
  type GovernedDefinitionExecutionReferenceV2,
  type GovernedDefinitionV2Resolver,
  type ResolvedGovernedDefinitionV2
} from "./governed-definition-v2-resolver.js";

const PAGE_SIZE = 1_000;
const MAX_SNAPSHOTS_PER_TENANT = 1_000_000;

/**
 * Read port for the immutable publication-link sidecar.  The authority does
 * not accept a caller-supplied link because that would let a caller select
 * unrecorded governance lineage.
 */
export interface GovernedCertifiedSnapshotPublicationLinkReadPortV2 {
  /**
   * Returns only a link that has not been disabled.  The V2 publication
   * authority deliberately has no raw-read capability: revocation is part of
   * selection authority, not an optional post-read policy check.
   */
  getEnabled(
    tenantId: string,
    linkId: string
  ): Promise<GovernedCertifiedSnapshotPublicationLinkV2 | undefined>;
}

export interface RepositoryBackedSurveillanceSourcePublicationAuthorityV2Dependencies {
  readonly datasetSnapshots: ImmutableRepositoryPort<DatasetSnapshotV2>;
  readonly captureLineage: GovernedSnapshotCaptureLineageReadPortV1;
  readonly certifiedSnapshotEvidence: ImmutableRepositoryPort<CertifiedSnapshotEvidenceRecordV2>;
  readonly publicationLinks: GovernedCertifiedSnapshotPublicationLinkReadPortV2;
  readonly artifacts: Pick<ArtifactStore, "getJson">;
  readonly definitions: Pick<GovernedDefinitionV2Resolver, "resolveFrozen">;
}

export interface ResolvedGovernedCertifiedSnapshotPublicationV2 {
  readonly link: GovernedCertifiedSnapshotPublicationLinkV2;
  readonly evidence: CertifiedSnapshotEvidenceRecordV2;
  readonly snapshot: DatasetSnapshotV2;
  readonly captureLineage: GovernedSnapshotCommitLineageV1;
  readonly controlDefinition: ResolvedGovernedDefinitionV2;
  readonly sourceContractDefinition: ResolvedGovernedDefinitionV2;
  readonly scopeBindingDefinition: ResolvedGovernedDefinitionV2;
  readonly mappingDefinition: ResolvedGovernedDefinitionV2;
  /** Exact server-reloaded metadata; never reconstructed from the evidence envelope. */
  readonly normalizedArtifact: StoredArtifact;
}

export type SurveillanceProductionAuthorityV2ErrorCode =
  | "INTEGRITY_FAILURE"
  | "NON_TERMINAL_SNAPSHOT"
  | "RESOURCE_LIMIT";

export class SurveillanceProductionAuthorityV2Error extends Error {
  constructor(readonly code: SurveillanceProductionAuthorityV2ErrorCode, message: string) {
    super(message);
    this.name = "SurveillanceProductionAuthorityV2Error";
  }
}

/**
 * V2-only publication-read authority.  It intentionally does not implement
 * the V1 publication authority interface and never reads the V1 evidence
 * repository.  A V1 record retained inside the V2 envelope is verified only
 * by the V2 contract parser, not used as a fallback source of authority.
 */
export class RepositoryBackedSurveillanceSourcePublicationAuthorityV2 {
  readonly #dependencies: RepositoryBackedSurveillanceSourcePublicationAuthorityV2Dependencies;

  constructor(dependencies: RepositoryBackedSurveillanceSourcePublicationAuthorityV2Dependencies) {
    this.#dependencies = dependencies;
  }

  /**
   * Resolve a durable V2 publication link by tenant-scoped opaque ID.  Missing
   * immutable evidence returns undefined; every mismatch or malformed record
   * fails closed with an integrity error.
   */
  async resolve(input: {
    readonly tenantId: string;
    readonly linkId: string;
  }): Promise<ResolvedGovernedCertifiedSnapshotPublicationV2 | undefined> {
    const linkValue = await this.#dependencies.publicationLinks.getEnabled(input.tenantId, input.linkId);
    if (!linkValue) return undefined;
    const link = verified(() => parseGovernedCertifiedSnapshotPublicationLinkV2(linkValue));
    if (link.tenantId !== input.tenantId || link.linkId !== input.linkId) {
      integrity("Publication-link repository crossed its requested tenant or identity boundary");
    }

    const [evidenceValue, snapshotValue, lineageValue] = await Promise.all([
      this.#dependencies.certifiedSnapshotEvidence.get(input.tenantId, link.evidence.evidenceId),
      this.#dependencies.datasetSnapshots.get(input.tenantId, link.governance.certificationAttempt.snapshotId),
      this.#dependencies.captureLineage.getGovernedCaptureLineage(
        input.tenantId,
        link.governance.certificationAttempt.snapshotId
      )
    ]);
    if (!evidenceValue || !snapshotValue || !lineageValue) return undefined;

    const evidence = verified(() => parseCertifiedSnapshotEvidenceRecordV2(evidenceValue));
    const snapshot = verified(() => parseDatasetSnapshotV2(snapshotValue));
    const lineage = lineageValue;
    if (
      evidence.tenantId !== input.tenantId ||
      evidence.certificationAttempt.certificationManifestId !== link.evidence.evidenceId ||
      evidence.evidenceHash !== link.evidence.evidenceHash ||
      canonicalJson(evidence) !== canonicalJson(link.evidence.record) ||
      snapshot.tenantId !== input.tenantId ||
      snapshot.snapshotId !== link.governance.certificationAttempt.snapshotId ||
      snapshot.snapshotHash !== link.governance.certificationAttempt.snapshotHash ||
      lineage.tenantId !== input.tenantId ||
      lineage.snapshotId !== snapshot.snapshotId ||
      lineage.snapshotHash !== snapshot.snapshotHash ||
      lineage.asOfDate !== snapshot.asOfDate
    ) {
      integrity("Publication link, V2 evidence, snapshot, or governed capture lineage is inconsistent");
    }
    await this.#assertTerminalSnapshot(snapshot);
    this.#assertCaptureLineage(evidence, snapshot, lineage);

    const [controlDefinition, sourceContractDefinition, scopeBindingDefinition, mappingDefinition] =
      await Promise.all([
        this.#resolveDefinition(
          input.tenantId,
          evidence.governance.control.reference,
          "snapshot_certification_control"
        ),
        this.#resolveDefinition(input.tenantId, evidence.governance.sourceContract.execution, "source_contract"),
        this.#resolveDefinition(input.tenantId, evidence.governance.scopeBinding.execution, "dataset_scope_binding"),
        this.#resolveDefinition(input.tenantId, evidence.governance.mapping.execution, "mapping_spec")
      ]);
    if (!controlDefinition || !sourceContractDefinition || !scopeBindingDefinition || !mappingDefinition) {
      return undefined;
    }
    this.#assertDefinitionDocuments(
      evidence,
      snapshot,
      controlDefinition,
      sourceContractDefinition,
      scopeBindingDefinition,
      mappingDefinition
    );
    const normalizedArtifact = this.#reloadArtifact(input.tenantId, evidence);

    return Object.freeze({
      link,
      evidence,
      snapshot,
      captureLineage: lineage,
      controlDefinition,
      sourceContractDefinition,
      scopeBindingDefinition,
      mappingDefinition,
      normalizedArtifact
    });
  }

  #resolveDefinition(
    tenantId: string,
    expected: GovernedDefinitionExecutionReferenceV2,
    expectedKind: GovernedDefinitionExecutionReferenceV2["kind"]
  ): ResolvedGovernedDefinitionV2 | undefined {
    let resolved: ResolvedGovernedDefinitionV2;
    try {
      resolved = this.#dependencies.definitions.resolveFrozen({
        tenantId,
        definitionVersionId: expected.definitionVersionId
      });
    } catch (error) {
      if (
        error instanceof GovernedDefinitionV2ResolverError &&
        (error.code === "NOT_FOUND" || error.code === "UNAPPROVED")
      ) {
        return undefined;
      }
      throw error;
    }
    if (
      expected.kind !== expectedKind ||
      canonicalJson(resolved.reference) !== canonicalJson(expected) ||
      resolved.approvalEvidence.approvalEventHash !== expected.approvalEventHash ||
      canonicalHash(resolved.executionDocument) !== expected.documentHash
    ) {
      integrity("Frozen governed definition does not match the V2 certification governance reference");
    }
    return resolved;
  }

  #assertDefinitionDocuments(
    evidence: CertifiedSnapshotEvidenceRecordV2,
    snapshot: DatasetSnapshotV2,
    controlDefinition: ResolvedGovernedDefinitionV2,
    sourceContractDefinition: ResolvedGovernedDefinitionV2,
    scopeBindingDefinition: ResolvedGovernedDefinitionV2,
    mappingDefinition: ResolvedGovernedDefinitionV2
  ): void {
    const control = verified(() => parseSnapshotCertificationDefinitionV1(controlDefinition.executionDocument));
    const source = verified(() => parseSourceContractV1(sourceContractDefinition.executionDocument));
    const scope = verified(() => parseGovernedDatasetScopeBindingV1(scopeBindingDefinition.executionDocument));
    const mapping = verified(() => parseMappingSpecV2(mappingDefinition.executionDocument));
    if (
      canonicalJson(control) !== canonicalJson(evidence.governance.control.definition) ||
      canonicalJson({
        sourceContractId: source.sourceContractId,
        revision: source.revision,
        sourceContractHash: source.sourceContractHash
      }) !== canonicalJson(evidence.governance.sourceContract.raw) ||
      canonicalJson(scope) !== canonicalJson(evidence.governance.scopeBinding.raw) ||
      source.tenantId !== evidence.tenantId ||
      scope.tenantId !== evidence.tenantId ||
      mapping.tenantId !== evidence.tenantId ||
      mapping.mappingSpecId !== evidence.governance.mapping.execution.mappingSpecId ||
      mapping.revision !== evidence.governance.mapping.execution.mappingSpecRevision ||
      mapping.mappingSpecHash !== evidence.governance.mapping.execution.mappingSpecHash ||
      canonicalJson(mapping.sourceContract) !== canonicalJson(evidence.governance.sourceContract.raw) ||
      canonicalJson(source.delivery) !== canonicalJson(snapshot.delivery)
    ) {
      integrity("Frozen V2 governance documents do not match the certified capture and mapping evidence");
    }
  }

  #assertCaptureLineage(
    evidence: CertifiedSnapshotEvidenceRecordV2,
    snapshot: DatasetSnapshotV2,
    lineage: GovernedSnapshotCommitLineageV1
  ): void {
    const scope = evidence.governance.scopeBinding.raw;
    if (
      canonicalJson(lineage.sourceContract) !== canonicalJson(evidence.governance.sourceContract.raw) ||
      lineage.scopeBinding.bindingId !== scope.bindingId ||
      lineage.scopeBinding.revision !== scope.revision ||
      lineage.scopeBinding.bindingHash !== scope.bindingHash ||
      lineage.datasetId !== scope.datasetId ||
      (scope.scope.scopeType === "facility" && lineage.facilityId !== scope.scope.scopeId) ||
      canonicalJson(snapshot.sourceContract) !== canonicalJson(lineage.sourceContract) ||
      lineage.extractionReceipt.receiptHash !== snapshot.hashes.extractionHash
    ) {
      integrity("Governed capture lineage does not match the V2 source, scope, facility, or snapshot evidence");
    }
  }

  #reloadArtifact(tenantId: string, evidence: CertifiedSnapshotEvidenceRecordV2): StoredArtifact {
    let loaded: ReturnType<ArtifactStore["getJson"]>;
    try {
      loaded = this.#dependencies.artifacts.getJson(tenantId, evidence.v1Evidence.normalizedArtifact.artifactId);
    } catch (error) {
      if (error instanceof ArtifactStoreError) {
        integrity(`Tenant-scoped normalized artifact reload failed: ${error.code}`);
      }
      throw error;
    }
    const artifact = verified(() => parseNormalizedSnapshotArtifactV2(loaded.value));
    const metadata = verified(() =>
      createCertifiedSnapshotArtifactMetadataV1({ artifact, loadedStoredArtifact: loaded.metadata })
    );
    if (
      artifact.tenantId !== tenantId ||
      canonicalJson(metadata) !== canonicalJson(evidence.v1Evidence.normalizedArtifact)
    ) {
      integrity("Reloaded normalized artifact metadata or payload does not match V2 certified evidence");
    }
    return loaded.metadata;
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
        throw new SurveillanceProductionAuthorityV2Error(
          "RESOURCE_LIMIT",
          "Tenant snapshot history exceeds the V2 publication resolution bound"
        );
      }
      for (const candidateValue of page.items) {
        const candidate = verified(() => parseDatasetSnapshotV2(candidateValue));
        if (
          candidate.correction.kind === "correction" &&
          candidate.correction.correctsSnapshotId === snapshot.snapshotId &&
          candidate.correction.correctsSnapshotHash === snapshot.snapshotHash
        ) {
          throw new SurveillanceProductionAuthorityV2Error(
            "NON_TERMINAL_SNAPSHOT",
            "A corrected snapshot cannot be selected for a V2 publication"
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
    if (error instanceof SurveillanceProductionAuthorityV2Error) throw error;
    const detail = error instanceof Error ? `: ${error.message}` : "";
    throw new SurveillanceProductionAuthorityV2Error(
      "INTEGRITY_FAILURE",
      `Authoritative V2 surveillance evidence failed verification${detail}`
    );
  }
}

function integrity(message: string): never {
  throw new SurveillanceProductionAuthorityV2Error("INTEGRITY_FAILURE", message);
}
