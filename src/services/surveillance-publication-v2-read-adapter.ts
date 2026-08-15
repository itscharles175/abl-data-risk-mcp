import {
  canonicalJson,
  parseCertifiedSnapshotPublicationV1,
  type CertifiedSnapshotPublicationV1
} from "../contracts/index.js";
import type {
  GovernedCertifiedSnapshotPublicationLinkDisableEventV2
} from "../control/governed-certified-snapshot-publication-links-v2.js";
import type { SurveillancePublicationDisableEventV1 } from "../control/surveillance-publications.js";
import type {
  CompletePublicationLineagePageV1,
  SurveillancePublicationLineageQueryV1,
  SurveillancePublicationReadPortV1
} from "./surveillance-access-preflight.js";
import type { SurveillanceMaterializationPublicationReadPortV1 } from "./surveillance-materializer.js";
import {
  RepositoryBackedSurveillanceSourcePublicationAuthorityV2,
  type ResolvedGovernedCertifiedSnapshotPublicationMetadataV2,
  type ResolvedGovernedCertifiedSnapshotPublicationV2
} from "./surveillance-production-authority-v2.js";
import type { GovernedCertifiedSnapshotPublicationLinkV2 } from "../contracts/governed-certified-snapshot-publication-link-v2.js";

const MAXIMUM_LINKS_PER_TENANT = 1_000;

/**
 * The narrow read surface required from the immutable V2 publication-link
 * sidecar.  In particular, preflight requests are resolved by V2 evidence ID,
 * not by any legacy V1 publication index.
 */
export interface GovernedCertifiedSnapshotPublicationLinkCatalogReadPortV2 {
  getEnabled(
    tenantId: string,
    linkId: string
  ): Promise<GovernedCertifiedSnapshotPublicationLinkV2 | undefined> | GovernedCertifiedSnapshotPublicationLinkV2 | undefined;
  getByEvidence(
    tenantId: string,
    evidenceId: string
  ): Promise<GovernedCertifiedSnapshotPublicationLinkV2 | undefined> | GovernedCertifiedSnapshotPublicationLinkV2 | undefined;
  list(
    tenantId: string,
    limit: number
  ): Promise<readonly GovernedCertifiedSnapshotPublicationLinkV2[]> | readonly GovernedCertifiedSnapshotPublicationLinkV2[];
  getDisable(
    tenantId: string,
    linkId: string
  ):
    | Promise<GovernedCertifiedSnapshotPublicationLinkDisableEventV2 | undefined>
    | GovernedCertifiedSnapshotPublicationLinkDisableEventV2
    | undefined;
}

export interface V2SurveillancePublicationReadAdapterDependencies {
  /** Metadata-only verification. It has no normalized artifact read capability. */
  readonly metadataAuthority: Pick<RepositoryBackedSurveillanceSourcePublicationAuthorityV2, "resolveMetadata">;
  /** Isolated V2 sidecar; a legacy publication catalog is intentionally not accepted. */
  readonly publicationLinks: GovernedCertifiedSnapshotPublicationLinkCatalogReadPortV2;
}

export interface V2SurveillancePublicationMaterializationReadAdapterDependencies {
  /** Full post-policy verification, including the normalized artifact. */
  readonly artifactAuthority: Pick<RepositoryBackedSurveillanceSourcePublicationAuthorityV2, "resolveArtifact">;
  /** Isolated V2 sidecar; a legacy publication catalog is intentionally not accepted. */
  readonly publicationLinks: GovernedCertifiedSnapshotPublicationLinkCatalogReadPortV2;
}

export type V2SurveillancePublicationReadAdapterErrorCode =
  | "INTEGRITY_FAILURE"
  | "RESOURCE_LIMIT";

export class V2SurveillancePublicationReadAdapterError extends Error {
  constructor(
    readonly code: V2SurveillancePublicationReadAdapterErrorCode,
    message: string
  ) {
    super(message);
    this.name = "V2SurveillancePublicationReadAdapterError";
  }
}

/**
 * Metadata-only compatibility adapter for the surveillance preflight port.
 * It never reads V1 catalog or evidence state:
 * every returned V1-shaped publication is the record embedded in an immutable
 * V2 link after the V2 authority has independently reloaded and verified its
 * governed lineage. A later disable remains visible so preflight can evaluate
 * it against the immutable planning cutoff.
 *
 * This class is deliberately not a publication writer.  It cannot make a V1
 * publication authoritative, nor can it turn a disabled V2 link back on.
 */
export class V2OnlySurveillancePublicationReadAdapter
  implements SurveillancePublicationReadPortV1
{
  readonly #dependencies: V2SurveillancePublicationReadAdapterDependencies;

  constructor(dependencies: V2SurveillancePublicationReadAdapterDependencies) {
    this.#dependencies = dependencies;
  }

  /** Direct source selections must bind the certification-manifest V2 evidence id. */
  async getByCertificationManifest(
    tenantId: string,
    certificationManifestId: string
  ): Promise<CertifiedSnapshotPublicationV1 | undefined> {
    const link = await this.#dependencies.publicationLinks.getByEvidence(
      tenantId,
      certificationManifestId
    );
    if (!link) return undefined;
    this.#assertEvidenceSelection(link, tenantId, certificationManifestId);
    return this.#resolveMetadataLink(tenantId, link);
  }

  /**
   * Preflight re-resolves by publication id without payload access. The V2
   * sidecar has no public legacy lookup, so this bounded scan is fail-closed
   * if the tenant sidecar reaches its maximum result size.
   */
  async get(tenantId: string, publicationId: string): Promise<CertifiedSnapshotPublicationV1 | undefined> {
    const links = await this.#listBounded(tenantId);
    const link = links.find((candidate) =>
      candidate.tenantId === tenantId && candidate.publication.publicationId === publicationId
    );
    if (!link) return undefined;
    return this.#resolveMetadataLink(tenantId, link);
  }

  /**
   * A disabled V2 link is projected only as a denial marker.  No V1 evidence
   * is read or trusted; the projection exists solely because the legacy ports
   * use this shape to recheck revocation between preflight and materialization.
   */
  async getDisable(
    tenantId: string,
    publicationId: string
  ): Promise<SurveillancePublicationDisableEventV1 | undefined> {
    const links = await this.#listBounded(tenantId);
    const link = links.find((candidate) =>
      candidate.tenantId === tenantId && candidate.publication.publicationId === publicationId
    );
    if (!link) return undefined;
    const disable = await this.#dependencies.publicationLinks.getDisable(tenantId, link.linkId);
    if (!disable) return undefined;
    if (disable.tenantId !== tenantId || disable.linkId !== link.linkId || disable.linkHash !== link.linkHash) {
      integrity("V2 publication-link disable authority substituted tenant, link, or immutable hash");
    }
    return Object.freeze({
      tenantId,
      publicationId: link.publication.publicationId,
      publicationHash: link.publication.publicationHash,
      reasonCode: disable.reasonCode,
      reason: disable.reason,
      disabledBy: disable.disabledBy,
      disabledAt: disable.disabledAt
    });
  }

  async listByScopeAsOf(
    query: SurveillancePublicationLineageQueryV1
  ): Promise<CompletePublicationLineagePageV1> {
    if (!Number.isSafeInteger(query.maximumResults) || query.maximumResults < 1 || query.maximumResults > MAXIMUM_LINKS_PER_TENANT) {
      throw new V2SurveillancePublicationReadAdapterError(
        "RESOURCE_LIMIT",
        "V2 publication lineage query exceeds its governed result bound"
      );
    }
    const links = await this.#listBounded(query.tenantId);
    const publications: CertifiedSnapshotPublicationV1[] = [];
    for (const link of links) {
      const publication = await this.#resolveMetadataLink(query.tenantId, link);
      if (publication && matchesScopeQuery(publication, query)) publications.push(publication);
    }
    const ordered = publications.sort((left, right) =>
      left.publishedAt.localeCompare(right.publishedAt) || left.publicationId.localeCompare(right.publicationId)
    );
    if (ordered.length > query.maximumResults) {
      return Object.freeze({
        publications: Object.freeze(ordered.slice(0, query.maximumResults)),
        complete: false
      });
    }
    return Object.freeze({ publications: Object.freeze(ordered), complete: true });
  }

  async #resolveMetadataLink(
    tenantId: string,
    selected: GovernedCertifiedSnapshotPublicationLinkV2
  ): Promise<CertifiedSnapshotPublicationV1 | undefined> {
    if (selected.tenantId !== tenantId) {
      integrity("V2 publication-link selector crossed its requested tenant boundary");
    }
    const resolved = await this.#dependencies.metadataAuthority.resolveMetadata({ tenantId, linkId: selected.linkId });
    if (!resolved) return undefined;
    this.#assertAuthorityResolution(tenantId, selected, resolved);
    try {
      return parseCertifiedSnapshotPublicationV1(resolved.link.publication.record);
    } catch (error) {
      const detail = error instanceof Error ? `: ${error.message}` : "";
      integrity(`V2 authority returned a malformed embedded publication${detail}`);
    }
  }

  async #listBounded(tenantId: string): Promise<readonly GovernedCertifiedSnapshotPublicationLinkV2[]> {
    const links = await this.#dependencies.publicationLinks.list(tenantId, MAXIMUM_LINKS_PER_TENANT);
    if (!Array.isArray(links) || links.length >= MAXIMUM_LINKS_PER_TENANT) {
      throw new V2SurveillancePublicationReadAdapterError(
        "RESOURCE_LIMIT",
        "V2 publication-link sidecar cannot prove the tenant result set is complete"
      );
    }
    for (const link of links) {
      if (!link || typeof link !== "object" || link.tenantId !== tenantId) {
        integrity("V2 publication-link sidecar crossed its tenant boundary during list");
      }
    }
    return links;
  }

  #assertEvidenceSelection(
    link: GovernedCertifiedSnapshotPublicationLinkV2,
    tenantId: string,
    certificationManifestId: string
  ): void {
    if (
      link.tenantId !== tenantId ||
      link.evidence.evidenceId !== certificationManifestId ||
      link.publication.certificationManifestId !== certificationManifestId
    ) {
      integrity("V2 evidence selector substituted tenant or certification-manifest identity");
    }
  }

  #assertAuthorityResolution(
    tenantId: string,
    selected: GovernedCertifiedSnapshotPublicationLinkV2,
    resolved: ResolvedGovernedCertifiedSnapshotPublicationMetadataV2
  ): void {
    if (
      resolved.link.tenantId !== tenantId ||
      canonicalJson(resolved.link) !== canonicalJson(selected) ||
      resolved.evidence.tenantId !== tenantId ||
      resolved.evidence.certificationAttempt.certificationManifestId !== selected.evidence.evidenceId ||
      resolved.snapshot.tenantId !== tenantId ||
      resolved.snapshot.snapshotId !== selected.governance.certificationAttempt.snapshotId ||
      resolved.snapshot.snapshotHash !== selected.governance.certificationAttempt.snapshotHash
    ) {
      integrity("V2 publication authority substituted governed publication, evidence, or snapshot lineage");
    }
  }
}

/**
 * Post-policy materialization adapter. Unlike the preflight adapter, its get
 * requires the link to be currently enabled and invokes full artifact
 * verification. Keeping this as a separate object prevents an authorization
 * read port from accidentally crossing the payload boundary.
 */
export class V2OnlySurveillancePublicationMaterializationReadAdapter
  implements SurveillanceMaterializationPublicationReadPortV1
{
  readonly #dependencies: V2SurveillancePublicationMaterializationReadAdapterDependencies;

  constructor(dependencies: V2SurveillancePublicationMaterializationReadAdapterDependencies) {
    this.#dependencies = dependencies;
  }

  async get(tenantId: string, publicationId: string): Promise<CertifiedSnapshotPublicationV1 | undefined> {
    const links = await listBounded(this.#dependencies.publicationLinks, tenantId);
    const selected = links.find((candidate) =>
      candidate.tenantId === tenantId && candidate.publication.publicationId === publicationId
    );
    if (!selected) return undefined;
    const enabled = await this.#dependencies.publicationLinks.getEnabled(tenantId, selected.linkId);
    if (!enabled) return undefined;
    if (canonicalJson(enabled) !== canonicalJson(selected)) {
      integrity("V2 publication-link enabled selector substituted immutable link evidence");
    }
    const resolved = await this.#dependencies.artifactAuthority.resolveArtifact({
      tenantId,
      linkId: selected.linkId
    });
    if (!resolved) return undefined;
    assertAuthorityResolution(tenantId, selected, resolved);
    return parseEmbeddedPublication(resolved);
  }

  async getDisable(
    tenantId: string,
    publicationId: string
  ): Promise<SurveillancePublicationDisableEventV1 | undefined> {
    return projectDisable(this.#dependencies.publicationLinks, tenantId, publicationId);
  }
}

async function listBounded(
  publicationLinks: GovernedCertifiedSnapshotPublicationLinkCatalogReadPortV2,
  tenantId: string
): Promise<readonly GovernedCertifiedSnapshotPublicationLinkV2[]> {
  const links = await publicationLinks.list(tenantId, MAXIMUM_LINKS_PER_TENANT);
  if (!Array.isArray(links) || links.length >= MAXIMUM_LINKS_PER_TENANT) {
    throw new V2SurveillancePublicationReadAdapterError(
      "RESOURCE_LIMIT",
      "V2 publication-link sidecar cannot prove the tenant result set is complete"
    );
  }
  for (const link of links) {
    if (!link || typeof link !== "object" || link.tenantId !== tenantId) {
      integrity("V2 publication-link sidecar crossed its tenant boundary during list");
    }
  }
  return links;
}

async function projectDisable(
  publicationLinks: GovernedCertifiedSnapshotPublicationLinkCatalogReadPortV2,
  tenantId: string,
  publicationId: string
): Promise<SurveillancePublicationDisableEventV1 | undefined> {
  const links = await listBounded(publicationLinks, tenantId);
  const link = links.find((candidate) =>
    candidate.tenantId === tenantId && candidate.publication.publicationId === publicationId
  );
  if (!link) return undefined;
  const disable = await publicationLinks.getDisable(tenantId, link.linkId);
  if (!disable) return undefined;
  if (disable.tenantId !== tenantId || disable.linkId !== link.linkId || disable.linkHash !== link.linkHash) {
    integrity("V2 publication-link disable authority substituted tenant, link, or immutable hash");
  }
  return Object.freeze({
    tenantId,
    publicationId: link.publication.publicationId,
    publicationHash: link.publication.publicationHash,
    reasonCode: disable.reasonCode,
    reason: disable.reason,
    disabledBy: disable.disabledBy,
    disabledAt: disable.disabledAt
  });
}

function assertAuthorityResolution(
  tenantId: string,
  selected: GovernedCertifiedSnapshotPublicationLinkV2,
  resolved: ResolvedGovernedCertifiedSnapshotPublicationMetadataV2 | ResolvedGovernedCertifiedSnapshotPublicationV2
): void {
  if (
    resolved.link.tenantId !== tenantId ||
    canonicalJson(resolved.link) !== canonicalJson(selected) ||
    resolved.evidence.tenantId !== tenantId ||
    resolved.evidence.certificationAttempt.certificationManifestId !== selected.evidence.evidenceId ||
    resolved.snapshot.tenantId !== tenantId ||
    resolved.snapshot.snapshotId !== selected.governance.certificationAttempt.snapshotId ||
    resolved.snapshot.snapshotHash !== selected.governance.certificationAttempt.snapshotHash
  ) {
    integrity("V2 publication authority substituted governed publication, evidence, or snapshot lineage");
  }
}

function parseEmbeddedPublication(
  resolved: ResolvedGovernedCertifiedSnapshotPublicationMetadataV2 | ResolvedGovernedCertifiedSnapshotPublicationV2
): CertifiedSnapshotPublicationV1 {
  try {
    return parseCertifiedSnapshotPublicationV1(resolved.link.publication.record);
  } catch (error) {
    const detail = error instanceof Error ? `: ${error.message}` : "";
    integrity(`V2 authority returned a malformed embedded publication${detail}`);
  }
}

function matchesScopeQuery(
  publication: CertifiedSnapshotPublicationV1,
  query: SurveillancePublicationLineageQueryV1
): boolean {
  return (
    publication.tenantId === query.tenantId &&
    publication.datasetId === query.datasetId &&
    publication.sourceContract.sourceContractId === query.sourceContract.sourceContractId &&
    publication.sourceContract.sourceKey === query.sourceContract.sourceKey &&
    publication.sourceContract.revision === query.sourceContract.revision &&
    publication.sourceContract.sourceContractHash === query.sourceContract.sourceContractHash &&
    publication.scope.scopeType === query.scope.scopeType &&
    publication.scope.scopeId === query.scope.scopeId &&
    publication.snapshot.asOfDate === query.asOfDate &&
    publication.publishedAt <= query.publishedThrough
  );
}

function integrity(message: string): never {
  throw new V2SurveillancePublicationReadAdapterError("INTEGRITY_FAILURE", message);
}
