import {
  IdentifierSchema,
  IsoTimestampSchema,
  canonicalHash,
  canonicalJson,
  createCertifiedSnapshotArtifactMetadataV1,
  createCertifiedSnapshotPublicationV1,
  parseDatasetScopeBindingV1,
  parseDatasetSnapshotV2,
  parseGovernedDatasetScopeBindingV1,
  parseMappingApplicationV1,
  parseMappingSpecV2,
  parseNormalizedSnapshotArtifactV2,
  parseSnapshotCertificationDefinitionV1,
  parseSourceContractV1,
  parseWithSchema,
  type DatasetSnapshotV2
} from "../contracts/index.js";
import {
  parseCertifiedSnapshotEvidenceRecordV2,
  type CertifiedSnapshotEvidenceRecordV2
} from "../contracts/certified-snapshot-evidence-v2.js";
import { createGovernedCertifiedSnapshotPublicationLinkV2, type GovernedCertifiedSnapshotPublicationLinkV2 } from "../contracts/governed-certified-snapshot-publication-link-v2.js";
import { ArtifactStoreError, type ArtifactStore, type StoredArtifact } from "../control/artifacts.js";
import { GovernedCertifiedSnapshotPublicationLinkCatalogV2 } from "../control/governed-certified-snapshot-publication-links-v2.js";
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

export interface PublishGovernedCertifiedSnapshotV2Request {
  readonly tenantId: string;
  /** Opaque V2 link and derived V1 publication identity. */
  readonly linkId: string;
  /** Immutable V2 evidence identity, currently the certification manifest ID. */
  readonly certificationManifestId: string;
  readonly idempotencyKey: string;
}

export interface GovernedCertifiedSnapshotPublicationV2Dependencies {
  readonly datasetSnapshots: ImmutableRepositoryPort<DatasetSnapshotV2>;
  readonly captureLineage: GovernedSnapshotCaptureLineageReadPortV1;
  readonly certifiedSnapshotEvidence: ImmutableRepositoryPort<CertifiedSnapshotEvidenceRecordV2>;
  readonly artifacts: Pick<ArtifactStore, "getJson">;
  readonly definitions: Pick<GovernedDefinitionV2Resolver, "resolveFrozen">;
  readonly publicationLinks: Pick<GovernedCertifiedSnapshotPublicationLinkCatalogV2, "record">;
  readonly clock?: () => Date;
}

export type GovernedCertifiedSnapshotPublicationV2ErrorCode =
  | "INVALID_REQUEST"
  | "EVIDENCE_NOT_FOUND"
  | "AUTHORITY_MISMATCH"
  | "FROZEN_EVIDENCE_DRIFT"
  | "NON_TERMINAL_SNAPSHOT"
  | "RESOURCE_LIMIT";

export class GovernedCertifiedSnapshotPublicationV2Error extends Error {
  constructor(readonly code: GovernedCertifiedSnapshotPublicationV2ErrorCode, message: string) {
    super(message);
    this.name = "GovernedCertifiedSnapshotPublicationV2Error";
  }
}

/**
 * Trusted, IDs-only writer for the additive V2 publication-link sidecar.
 *
 * This is intentionally independent of the V2 read authority: before a link
 * exists it reloads and validates immutable V2 evidence, governed capture
 * lineage, frozen definitions, and the stored normalized artifact. It never
 * reads the legacy evidence repository or legacy publication catalog.
 */
export class GovernedCertifiedSnapshotPublicationV2Service {
  readonly #dependencies: GovernedCertifiedSnapshotPublicationV2Dependencies;
  readonly #clock: () => Date;

  constructor(dependencies: GovernedCertifiedSnapshotPublicationV2Dependencies) {
    this.#dependencies = dependencies;
    this.#clock = dependencies.clock ?? (() => new Date());
  }

  async publish(
    requestValue: PublishGovernedCertifiedSnapshotV2Request,
    trustedActorValue: string
  ): Promise<GovernedCertifiedSnapshotPublicationLinkV2> {
    const request = parseRequest(requestValue);
    const trustedActor = parseInput(() =>
      parseWithSchema(IdentifierSchema, trustedActorValue, "trusted V2 publication actor")
    );
    const requestHash = canonicalHash({ ...request, trustedActor });

    const evidenceValue = await this.#dependencies.certifiedSnapshotEvidence.get(
      request.tenantId,
      request.certificationManifestId
    );

    // The evidence gives the authoritative snapshot identity; it is never
    // accepted from the public request.
    if (!evidenceValue) missing("Certified V2 evidence was not found");
    const evidence = verifiedEvidence(() => parseCertifiedSnapshotEvidenceRecordV2(evidenceValue));
    if (
      evidence.tenantId !== request.tenantId ||
      evidence.certificationAttempt.certificationManifestId !== request.certificationManifestId
    ) {
      mismatch("V2 evidence repository crossed its requested tenant or certification identity boundary");
    }
    const [snapshotRecord, lineageRecord] = await Promise.all([
      this.#dependencies.datasetSnapshots.get(request.tenantId, evidence.certificationAttempt.snapshotId),
      this.#dependencies.captureLineage.getGovernedCaptureLineage(request.tenantId, evidence.certificationAttempt.snapshotId)
    ]);
    if (!snapshotRecord || !lineageRecord) missing("Certified V2 snapshot or governed capture lineage was not found");
    const snapshot = verifiedEvidence(() => parseDatasetSnapshotV2(snapshotRecord));
    const lineage = lineageRecord;
    if (
      snapshot.tenantId !== request.tenantId ||
      snapshot.snapshotId !== evidence.certificationAttempt.snapshotId ||
      snapshot.snapshotHash !== evidence.certificationAttempt.snapshotHash ||
      lineage.tenantId !== request.tenantId ||
      lineage.snapshotId !== snapshot.snapshotId ||
      lineage.snapshotHash !== snapshot.snapshotHash ||
      lineage.asOfDate !== snapshot.asOfDate
    ) {
      mismatch("V2 evidence, snapshot, or governed capture lineage is inconsistent");
    }
    await this.#assertTerminalSnapshot(snapshot);

    const [controlDefinition, sourceContractDefinition, scopeBindingDefinition, mappingDefinition] = await Promise.all([
      this.#resolveDefinition(request.tenantId, evidence.governance.control.reference, "snapshot_certification_control"),
      this.#resolveDefinition(request.tenantId, evidence.governance.sourceContract.execution, "source_contract"),
      this.#resolveDefinition(request.tenantId, evidence.governance.scopeBinding.execution, "dataset_scope_binding"),
      this.#resolveDefinition(request.tenantId, evidence.governance.mapping.execution, "mapping_spec")
    ]);
    if (!controlDefinition || !sourceContractDefinition || !scopeBindingDefinition || !mappingDefinition) {
      missing("Frozen V2 publication governance evidence was not found");
    }
    const resolved = { controlDefinition, sourceContractDefinition, scopeBindingDefinition, mappingDefinition };
    this.#assertCaptureLineage(evidence, snapshot, lineage);
    this.#assertDefinitionDocuments(evidence, snapshot, resolved);
    const storedArtifact = this.#reloadArtifact(request.tenantId, evidence);
    const publishedAt = now(this.#clock);
    const publication = this.#derivePublication({
      request,
      trustedActor,
      publishedAt,
      evidence,
      snapshot,
      sourceContractDefinition,
      scopeBindingDefinition,
      storedArtifact
    });
    const link = verifiedEvidence(() =>
      createGovernedCertifiedSnapshotPublicationLinkV2({
        linkId: request.linkId,
        publication,
        evidenceId: request.certificationManifestId,
        evidence,
        linkedAt: publishedAt
      })
    );
    try {
      return this.#dependencies.publicationLinks.record({
        link,
        requestHash,
        actor: trustedActor,
        idempotencyKey: request.idempotencyKey
      });
    } catch (error) {
      if (error instanceof GovernedCertifiedSnapshotPublicationV2Error) throw error;
      throw error;
    }
  }

  #derivePublication(input: {
    readonly request: PublishGovernedCertifiedSnapshotV2Request;
    readonly trustedActor: string;
    readonly publishedAt: string;
    readonly evidence: CertifiedSnapshotEvidenceRecordV2;
    readonly snapshot: DatasetSnapshotV2;
    readonly sourceContractDefinition: ResolvedGovernedDefinitionV2;
    readonly scopeBindingDefinition: ResolvedGovernedDefinitionV2;
    readonly storedArtifact: StoredArtifact;
  }) {
    const source = verifiedEvidence(() => parseSourceContractV1(input.sourceContractDefinition.executionDocument));
    const governedScope = verifiedEvidence(() => parseGovernedDatasetScopeBindingV1(input.scopeBindingDefinition.executionDocument));
    const bindingBody = {
      contractVersion: 1 as const,
      bindingId: governedScope.bindingId,
      tenantId: governedScope.tenantId,
      datasetId: governedScope.datasetId,
      sourceContract: governedScope.sourceContract,
      scope: governedScope.scope,
      boundAt: input.scopeBindingDefinition.approvalEvidence.approvedAt
    };
    const binding = verifiedEvidence(() =>
      parseDatasetScopeBindingV1({ ...bindingBody, bindingHash: canonicalHash(bindingBody) })
    );
    const v1 = input.evidence.v1Evidence;
    const certification = verifiedEvidence(() => v1.certification);
    const population = verifiedEvidence(() => v1.population);
    const mappingSpec = verifiedEvidence(() => parseMappingSpecV2(v1.mappingSpec));
    const mappingApplication = verifiedEvidence(() => parseMappingApplicationV1(v1.mappingApplication));
    const normalizedArtifact = v1.normalizedArtifact;
    const metadataHash = canonicalHash({
      artifactId: input.storedArtifact.artifactId,
      tenantBinding: input.storedArtifact.tenantBinding,
      kind: input.storedArtifact.kind,
      mediaType: input.storedArtifact.mediaType,
      contentHash: input.storedArtifact.contentHash,
      byteLength: input.storedArtifact.byteLength,
      keyId: input.storedArtifact.keyId,
      uri: input.storedArtifact.uri
    });
    const { sourceContract: _sourceContract, ...sourceDefinition } = input.evidence.governance.sourceContract.execution;
    return verifiedEvidence(() =>
      createCertifiedSnapshotPublicationV1({
        contractVersion: 1,
        publicationId: input.request.linkId,
        tenantId: input.request.tenantId,
        datasetId: binding.datasetId,
        scope: binding.scope,
        datasetBinding: binding,
        sourceContract: {
          definition: sourceDefinition,
          sourceContractId: source.sourceContractId,
          sourceKey: source.sourceKey,
          revision: source.revision,
          sourceContractHash: source.sourceContractHash
        },
        snapshot: {
          snapshotId: input.snapshot.snapshotId,
          snapshotHash: input.snapshot.snapshotHash,
          sourceContract: input.snapshot.sourceContract,
          delivery: {
            mode: input.snapshot.delivery.mode,
            deliveredContentHash: input.snapshot.hashes.contentHash,
            ...(input.snapshot.immutableSourceVersion === undefined
              ? {}
              : { immutableSourceVersion: input.snapshot.immutableSourceVersion })
          },
          asOfDate: input.snapshot.asOfDate,
          knowledge: input.snapshot.knowledge,
          hashes: input.snapshot.hashes,
          rowCount: input.snapshot.rowCount,
          byteCount: input.snapshot.byteCount,
          correction: input.snapshot.correction
        },
        certification,
        population,
        mappingSpec: {
          mappingSpecId: mappingSpec.mappingSpecId,
          mappingKey: mappingSpec.mappingKey,
          revision: mappingSpec.revision,
          mappingSpecHash: mappingSpec.mappingSpecHash,
          sourceContract: mappingSpec.sourceContract,
          dictionaryBundle: mappingSpec.dictionaryBundle
        },
        mappingApplication,
        normalizedArtifact: {
          artifactId: normalizedArtifact.artifactId,
          artifactContractVersion: normalizedArtifact.artifactContractVersion,
          artifactHash: normalizedArtifact.artifactHash,
          kind: "normalized_snapshot",
          mediaType: "application/json",
          contentHash: normalizedArtifact.contentHash,
          byteLength: normalizedArtifact.byteLength,
          uri: normalizedArtifact.uri,
          metadataHash,
          rowCount: population.rowCount,
          populationHash: population.populationHash,
          fieldSetHash: population.fieldSetHash
        },
        publishedBy: input.trustedActor,
        publishedAt: input.publishedAt
      })
    );
  }

  #resolveDefinition(
    tenantId: string,
    expected: GovernedDefinitionExecutionReferenceV2,
    expectedKind: GovernedDefinitionExecutionReferenceV2["kind"]
  ): ResolvedGovernedDefinitionV2 | undefined {
    let resolved: ResolvedGovernedDefinitionV2;
    try {
      resolved = this.#dependencies.definitions.resolveFrozen({ tenantId, definitionVersionId: expected.definitionVersionId });
    } catch (error) {
      if (error instanceof GovernedDefinitionV2ResolverError && (error.code === "NOT_FOUND" || error.code === "UNAPPROVED")) {
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
      mismatch("Frozen governed definition does not match V2 certification governance evidence");
    }
    return resolved;
  }

  #assertDefinitionDocuments(
    evidenceRecord: CertifiedSnapshotEvidenceRecordV2,
    snapshot: DatasetSnapshotV2,
    definitions: {
      readonly controlDefinition: ResolvedGovernedDefinitionV2;
      readonly sourceContractDefinition: ResolvedGovernedDefinitionV2;
      readonly scopeBindingDefinition: ResolvedGovernedDefinitionV2;
      readonly mappingDefinition: ResolvedGovernedDefinitionV2;
    }
  ): void {
    const control = verifiedEvidence(() => parseSnapshotCertificationDefinitionV1(definitions.controlDefinition.executionDocument));
    const source = verifiedEvidence(() => parseSourceContractV1(definitions.sourceContractDefinition.executionDocument));
    const scope = verifiedEvidence(() => parseGovernedDatasetScopeBindingV1(definitions.scopeBindingDefinition.executionDocument));
    const mapping = verifiedEvidence(() => parseMappingSpecV2(definitions.mappingDefinition.executionDocument));
    if (
      canonicalJson(control) !== canonicalJson(evidenceRecord.governance.control.definition) ||
      canonicalJson({ sourceContractId: source.sourceContractId, revision: source.revision, sourceContractHash: source.sourceContractHash }) !== canonicalJson(evidenceRecord.governance.sourceContract.raw) ||
      canonicalJson(scope) !== canonicalJson(evidenceRecord.governance.scopeBinding.raw) ||
      source.tenantId !== evidenceRecord.tenantId ||
      scope.tenantId !== evidenceRecord.tenantId ||
      mapping.tenantId !== evidenceRecord.tenantId ||
      mapping.mappingSpecId !== evidenceRecord.governance.mapping.execution.mappingSpecId ||
      mapping.revision !== evidenceRecord.governance.mapping.execution.mappingSpecRevision ||
      mapping.mappingSpecHash !== evidenceRecord.governance.mapping.execution.mappingSpecHash ||
      canonicalJson(mapping.sourceContract) !== canonicalJson(evidenceRecord.governance.sourceContract.raw) ||
      canonicalJson(source.delivery) !== canonicalJson(snapshot.delivery)
    ) {
      mismatch("Frozen V2 governance documents do not match certified capture and mapping evidence");
    }
  }

  #assertCaptureLineage(
    evidenceRecord: CertifiedSnapshotEvidenceRecordV2,
    snapshot: DatasetSnapshotV2,
    lineage: GovernedSnapshotCommitLineageV1
  ): void {
    const scope = evidenceRecord.governance.scopeBinding.raw;
    if (
      canonicalJson(lineage.sourceContract) !== canonicalJson(evidenceRecord.governance.sourceContract.raw) ||
      lineage.scopeBinding.bindingId !== scope.bindingId ||
      lineage.scopeBinding.revision !== scope.revision ||
      lineage.scopeBinding.bindingHash !== scope.bindingHash ||
      lineage.datasetId !== scope.datasetId ||
      (scope.scope.scopeType === "facility" && lineage.facilityId !== scope.scope.scopeId) ||
      canonicalJson(snapshot.sourceContract) !== canonicalJson(lineage.sourceContract) ||
      lineage.extractionReceipt.receiptHash !== snapshot.hashes.extractionHash
    ) {
      mismatch("Governed capture lineage does not match V2 source, scope, facility, or snapshot evidence");
    }
  }

  #reloadArtifact(tenantId: string, evidenceRecord: CertifiedSnapshotEvidenceRecordV2): StoredArtifact {
    let loaded: ReturnType<ArtifactStore["getJson"]>;
    try {
      loaded = this.#dependencies.artifacts.getJson(tenantId, evidenceRecord.v1Evidence.normalizedArtifact.artifactId);
    } catch (error) {
      if (error instanceof ArtifactStoreError) mismatch(`Tenant-scoped normalized artifact reload failed: ${error.code}`);
      throw error;
    }
    const artifact = verifiedEvidence(() => parseNormalizedSnapshotArtifactV2(loaded.value));
    const metadata = verifiedEvidence(() => createCertifiedSnapshotArtifactMetadataV1({ artifact, loadedStoredArtifact: loaded.metadata }));
    if (
      artifact.tenantId !== tenantId ||
      canonicalJson(metadata) !== canonicalJson(evidenceRecord.v1Evidence.normalizedArtifact)
    ) {
      mismatch("Reloaded normalized artifact metadata or payload does not match V2 certified evidence");
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
      if (seen > MAX_SNAPSHOTS_PER_TENANT) resource("Tenant snapshot history exceeds the V2 publication resolution bound");
      for (const candidateValue of page.items) {
        const candidate = verifiedEvidence(() => parseDatasetSnapshotV2(candidateValue));
        if (
          candidate.correction.kind === "correction" &&
          candidate.correction.correctsSnapshotId === snapshot.snapshotId &&
          candidate.correction.correctsSnapshotHash === snapshot.snapshotHash
        ) {
          throw new GovernedCertifiedSnapshotPublicationV2Error(
            "NON_TERMINAL_SNAPSHOT",
            "A corrected snapshot cannot be selected for a V2 publication"
          );
        }
      }
      cursor = page.nextCursor ?? undefined;
    } while (cursor !== undefined);
  }
}

function parseRequest(value: PublishGovernedCertifiedSnapshotV2Request): PublishGovernedCertifiedSnapshotV2Request {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid("V2 publication request is invalid");
  const expected = ["certificationManifestId", "idempotencyKey", "linkId", "tenantId"];
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson(expected)) {
    invalid("V2 publication request must contain only IDs and idempotency metadata");
  }
  return Object.freeze({
    tenantId: parseInput(() => parseWithSchema(IdentifierSchema, value.tenantId, "V2 publication tenantId")),
    linkId: parseInput(() => parseWithSchema(IdentifierSchema, value.linkId, "V2 publication linkId")),
    certificationManifestId: parseInput(() => parseWithSchema(IdentifierSchema, value.certificationManifestId, "V2 publication certificationManifestId")),
    idempotencyKey: parseInput(() => parseWithSchema(IdentifierSchema, value.idempotencyKey, "V2 publication idempotencyKey"))
  });
}

function now(clock: () => Date): string {
  const value = clock();
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) invalid("V2 publication clock is invalid");
  return parseInput(() => parseWithSchema(IsoTimestampSchema, value.toISOString(), "V2 publication time"));
}

function parseInput<T>(operation: () => T): T {
  try { return operation(); } catch (error) {
    if (error instanceof GovernedCertifiedSnapshotPublicationV2Error) throw error;
    invalid(error instanceof Error ? error.message : "V2 publication input is invalid");
  }
}

function verifiedEvidence<T>(operation: () => T): T {
  try { return operation(); } catch (error) {
    if (error instanceof GovernedCertifiedSnapshotPublicationV2Error) throw error;
    throw new GovernedCertifiedSnapshotPublicationV2Error(
      "FROZEN_EVIDENCE_DRIFT",
      error instanceof Error ? `V2 publication evidence failed verification: ${error.message}` : "V2 publication evidence failed verification"
    );
  }
}

function invalid(message: string): never {
  throw new GovernedCertifiedSnapshotPublicationV2Error("INVALID_REQUEST", message);
}

function missing(message: string): never {
  throw new GovernedCertifiedSnapshotPublicationV2Error("EVIDENCE_NOT_FOUND", message);
}

function mismatch(message: string): never {
  throw new GovernedCertifiedSnapshotPublicationV2Error("AUTHORITY_MISMATCH", message);
}

function resource(message: string): never {
  throw new GovernedCertifiedSnapshotPublicationV2Error("RESOURCE_LIMIT", message);
}
