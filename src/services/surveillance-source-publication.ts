import {
  IdentifierSchema,
  IsoTimestampSchema,
  canonicalHash,
  canonicalJson,
  createCertifiedSnapshotPublicationV1,
  parseCertificationManifestPublicationV1,
  parseDatasetScopeBindingV1,
  parseDataPopulationCertificationV1,
  parseDatasetSnapshotV2,
  parseMappingApplicationV1,
  parseMappingSpecV2,
  parseSourceContractV1,
  parseWithSchema,
  type CertificationManifestPublicationV1,
  type CertifiedSnapshotPublicationV1,
  type DataPopulationCertificationV1,
  type DatasetScopeBindingV1,
  type DatasetSnapshotV2,
  type MappingApplicationV1,
  type MappingSpecV2
} from "../contracts/index.js";
import type { StoredArtifact } from "../control/artifacts.js";
import type { SurveillancePublicationCatalog } from "../control/surveillance-publications.js";
import type { ResolvedGovernedDefinitionV2 } from "./governed-definition-v2-resolver.js";

export interface PublishCertifiedSnapshotRequestV1 {
  readonly tenantId: string;
  readonly publicationId: string;
  readonly certificationManifestId: string;
  readonly datasetSnapshotId: string;
  readonly datasetBindingId: string;
  readonly sourceContractDefinitionVersionId: string;
  readonly idempotencyKey: string;
}

export interface CertifiedSnapshotPublicationEvidenceV1 {
  readonly certification: CertificationManifestPublicationV1;
  readonly population: DataPopulationCertificationV1;
  readonly mappingSpec: MappingSpecV2;
  readonly mappingApplication: MappingApplicationV1;
  /** Exact metadata returned by tenant-scoped ArtifactStore.getJson; implementations must not synthesize it. */
  readonly normalizedArtifact: StoredArtifact;
}

export interface SurveillanceSourcePublicationAuthorityV1 {
  /** Production DatasetSnapshotV2 persistence is intentionally still an explicit, fail-closed port. */
  resolveDatasetSnapshotV2(input: {
    readonly tenantId: string;
    readonly datasetSnapshotId: string;
    readonly certificationManifestId: string;
  }): Promise<DatasetSnapshotV2 | undefined> | DatasetSnapshotV2 | undefined;
  /** Durable tenant/dataset/source/scope identity; it is never supplied by the publication caller. */
  resolveDatasetBinding(input: {
    readonly tenantId: string;
    readonly datasetBindingId: string;
  }): Promise<DatasetScopeBindingV1 | undefined> | DatasetScopeBindingV1 | undefined;
  /** Resolves the activated, frozen governed SourceContract v2 definition and lifecycle evidence. */
  resolveFrozenSourceContract(input: {
    readonly tenantId: string;
    readonly sourceContractDefinitionVersionId: string;
  }): Promise<ResolvedGovernedDefinitionV2 | undefined> | ResolvedGovernedDefinitionV2 | undefined;
  /** Resolves and verifies current legacy or modern certification, normalized artifact, and population evidence. */
  resolveCertifiedPublicationEvidence(input: {
    readonly tenantId: string;
    readonly certificationManifestId: string;
  }):
    | Promise<CertifiedSnapshotPublicationEvidenceV1 | undefined>
    | CertifiedSnapshotPublicationEvidenceV1
    | undefined;
}

export type SurveillanceSourcePublicationErrorCode =
  | "INVALID_REQUEST"
  | "EVIDENCE_NOT_FOUND"
  | "AUTHORITY_MISMATCH"
  | "FROZEN_EVIDENCE_DRIFT";

export class SurveillanceSourcePublicationError extends Error {
  constructor(readonly code: SurveillanceSourcePublicationErrorCode, message: string) {
    super(message);
    this.name = "SurveillanceSourcePublicationError";
  }
}

/**
 * Trusted data-publication gate. Its public request is IDs-only: every hash,
 * row count, source/dataset/scope binding, and certification field is loaded
 * from an authority port, cross-verified, then written to the immutable catalog.
 */
export class SurveillanceSourcePublicationService {
  readonly #authority: SurveillanceSourcePublicationAuthorityV1;
  readonly #catalog: SurveillancePublicationCatalog;
  readonly #clock: () => Date;

  constructor(
    authority: SurveillanceSourcePublicationAuthorityV1,
    catalog: SurveillancePublicationCatalog,
    options: { readonly clock?: () => Date } = {}
  ) {
    this.#authority = authority;
    this.#catalog = catalog;
    this.#clock = options.clock ?? (() => new Date());
  }

  async publish(
    inputValue: PublishCertifiedSnapshotRequestV1,
    trustedActorValue: string
  ): Promise<CertifiedSnapshotPublicationV1> {
    const input = request(inputValue);
    const trustedActor = parseWithSchema(IdentifierSchema, trustedActorValue, "trusted publication actor");
    const requestHash = canonicalHash({ ...input, trustedActor });
    const [snapshotValue, bindingValue, sourceDefinition, evidenceValue] = await Promise.all([
      this.#authority.resolveDatasetSnapshotV2({
        tenantId: input.tenantId,
        datasetSnapshotId: input.datasetSnapshotId,
        certificationManifestId: input.certificationManifestId
      }),
      this.#authority.resolveDatasetBinding({
        tenantId: input.tenantId,
        datasetBindingId: input.datasetBindingId
      }),
      this.#authority.resolveFrozenSourceContract({
        tenantId: input.tenantId,
        sourceContractDefinitionVersionId: input.sourceContractDefinitionVersionId
      }),
      this.#authority.resolveCertifiedPublicationEvidence({
        tenantId: input.tenantId,
        certificationManifestId: input.certificationManifestId
      })
    ]);
    if (!snapshotValue || !bindingValue || !sourceDefinition || !evidenceValue) {
      throw new SurveillanceSourcePublicationError(
        "EVIDENCE_NOT_FOUND",
        "Certified snapshot publication evidence was not found"
      );
    }
    const snapshot = evidence(() => parseDatasetSnapshotV2(snapshotValue));
    const binding = evidence(() => parseDatasetScopeBindingV1(bindingValue));
    const sourceContract = evidence(() => parseSourceContractV1(sourceDefinition.executionDocument));
    const certification = evidence(() =>
      parseCertificationManifestPublicationV1(evidenceValue.certification)
    );
    const population = evidence(() => parseDataPopulationCertificationV1(evidenceValue.population));
    const mappingSpec = evidence(() => parseMappingSpecV2(evidenceValue.mappingSpec));
    const mappingApplication = evidence(() =>
      parseMappingApplicationV1(evidenceValue.mappingApplication)
    );
    const normalizedArtifact = storedArtifact(evidenceValue.normalizedArtifact);
    const normalizedArtifactMetadataHash = canonicalHash({
      artifactId: normalizedArtifact.artifactId,
      tenantBinding: normalizedArtifact.tenantBinding,
      kind: normalizedArtifact.kind,
      mediaType: normalizedArtifact.mediaType,
      contentHash: normalizedArtifact.contentHash,
      byteLength: normalizedArtifact.byteLength,
      keyId: normalizedArtifact.keyId,
      uri: normalizedArtifact.uri
    });

    if (
      sourceDefinition.reference.kind !== "source_contract" ||
      sourceDefinition.reference.definitionVersionId !== input.sourceContractDefinitionVersionId ||
      sourceDefinition.reference.definitionKey !== sourceContract.sourceKey ||
      sourceDefinition.reference.semanticVersion !== `${sourceContract.revision}.0.0` ||
      sourceDefinition.reference.approvalEventHash !== sourceDefinition.approvalEvidence.approvalEventHash ||
      sourceContract.tenantId !== input.tenantId ||
      snapshot.tenantId !== input.tenantId ||
      binding.tenantId !== input.tenantId ||
      certification.tenantId !== input.tenantId ||
      certification.certificationManifestId !== input.certificationManifestId ||
      snapshot.snapshotId !== input.datasetSnapshotId ||
      certification.snapshotId !== input.datasetSnapshotId ||
      binding.bindingId !== input.datasetBindingId
    ) {
      mismatch("Publication authority substituted a tenant, id, kind, or frozen definition");
    }
    const sourceIdentity = {
      sourceContractId: sourceContract.sourceContractId,
      revision: sourceContract.revision,
      sourceContractHash: sourceContract.sourceContractHash
    };
    if (
      canonicalJson(snapshot.sourceContract) !== canonicalJson(sourceIdentity) ||
      canonicalJson(binding.sourceContract) !== canonicalJson(sourceIdentity) ||
      canonicalJson(mappingSpec.sourceContract) !== canonicalJson(sourceIdentity)
    ) {
      mismatch("Dataset snapshot, binding, mapping, and source contract do not match");
    }
    if (canonicalJson(snapshot.delivery) !== canonicalJson(sourceContract.delivery)) {
      mismatch("Dataset snapshot delivery does not match the frozen source contract");
    }
    if (
      normalizedArtifact.kind !== "normalized_snapshot" ||
      normalizedArtifact.mediaType !== "application/json" ||
      controlHash(normalizedArtifact.artifactId) !== certification.normalizedArtifactId ||
      controlHash(normalizedArtifact.contentHash) !== certification.normalizedArtifactContentHash
    ) {
      mismatch("Normalized artifact metadata does not match certification");
    }
    const publishedAt = timestamp(this.#clock());
    const publication = evidence(() =>
      createCertifiedSnapshotPublicationV1({
        contractVersion: 1,
        publicationId: input.publicationId,
        tenantId: input.tenantId,
        datasetId: binding.datasetId,
        scope: binding.scope,
        datasetBinding: binding,
        sourceContract: {
          definition: sourceDefinition.reference as Extract<
            typeof sourceDefinition.reference,
            { readonly kind: "source_contract" }
          >,
          sourceContractId: sourceContract.sourceContractId,
          sourceKey: sourceContract.sourceKey,
          revision: sourceContract.revision,
          sourceContractHash: sourceContract.sourceContractHash
        },
        snapshot: {
          snapshotId: snapshot.snapshotId,
          snapshotHash: snapshot.snapshotHash,
          sourceContract: snapshot.sourceContract,
          delivery: {
            mode: snapshot.delivery.mode,
            deliveredContentHash: snapshot.hashes.contentHash,
            ...(snapshot.immutableSourceVersion === undefined
              ? {}
              : { immutableSourceVersion: snapshot.immutableSourceVersion })
          },
          asOfDate: snapshot.asOfDate,
          knowledge: snapshot.knowledge,
          hashes: snapshot.hashes,
          rowCount: snapshot.rowCount,
          byteCount: snapshot.byteCount,
          correction: snapshot.correction
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
          artifactId: controlHash(normalizedArtifact.artifactId),
          kind: "normalized_snapshot",
          mediaType: "application/json",
          contentHash: controlHash(normalizedArtifact.contentHash),
          byteLength: normalizedArtifact.byteLength,
          uri: normalizedArtifact.uri,
          metadataHash: normalizedArtifactMetadataHash,
          rowCount: population.rowCount,
          populationHash: population.populationHash,
          fieldSetHash: population.fieldSetHash
        },
        publishedBy: trustedActor,
        publishedAt
      })
    );
    return this.#catalog.record({
      publication,
      requestHash,
      actor: trustedActor,
      idempotencyKey: input.idempotencyKey
    });
  }
}

function request(input: PublishCertifiedSnapshotRequestV1): PublishCertifiedSnapshotRequestV1 {
  if (!input || typeof input !== "object" || Array.isArray(input)) invalid("Publication request is invalid");
  const expected = [
    "certificationManifestId",
    "datasetBindingId",
    "datasetSnapshotId",
    "idempotencyKey",
    "publicationId",
    "sourceContractDefinitionVersionId",
    "tenantId"
  ];
  if (canonicalJson(Object.keys(input).sort()) !== canonicalJson(expected)) {
    invalid("Publication request must contain only IDs and execution metadata");
  }
  const parsed = Object.fromEntries(
    Object.entries(input).map(([key, value]) => [
      key,
      parseWithSchema(IdentifierSchema, value, `publication ${key}`)
    ])
  ) as unknown as PublishCertifiedSnapshotRequestV1;
  return Object.freeze(parsed);
}

function storedArtifact(
  value: StoredArtifact
): StoredArtifact {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    mismatch("Normalized artifact authority returned invalid metadata");
  }
  const keys = Object.keys(value).sort();
  const expected = [
    "artifactId",
    "byteLength",
    "contentHash",
    "keyId",
    "kind",
    "mediaType",
    "tenantBinding",
    "uri"
  ];
  if (canonicalJson(keys) !== canonicalJson(expected)) {
    mismatch("Normalized artifact authority returned unsupported metadata");
  }
  for (const [label, hash] of [
    ["artifact id", value.artifactId],
    ["tenant binding", value.tenantBinding],
    ["content hash", value.contentHash]
  ] as const) {
    if (!/^[a-f0-9]{64}$/u.test(hash)) mismatch(`Normalized artifact ${label} is invalid`);
  }
  return Object.freeze({ ...value });
}

function timestamp(value: Date): string {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) invalid("Publication clock is invalid");
  return parseWithSchema(IsoTimestampSchema, value.toISOString(), "publication time");
}

function controlHash(value: string): `sha256:${string}` {
  const normalized = value.startsWith("sha256:") ? value : `sha256:${value}`;
  if (!/^sha256:[a-f0-9]{64}$/u.test(normalized)) {
    mismatch("Normalized artifact content hash is invalid");
  }
  return normalized as `sha256:${string}`;
}

function evidence<T>(operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    if (error instanceof SurveillanceSourcePublicationError) throw error;
    const issues =
      error && typeof error === "object" && Array.isArray((error as { readonly issues?: unknown }).issues)
        ? `: ${(error as { readonly issues: readonly unknown[] }).issues.join("; ")}`
        : "";
    throw new SurveillanceSourcePublicationError(
      "FROZEN_EVIDENCE_DRIFT",
      error instanceof Error ? `${error.message}${issues}` : "Publication evidence failed validation"
    );
  }
}

function invalid(message: string): never {
  throw new SurveillanceSourcePublicationError("INVALID_REQUEST", message);
}

function mismatch(message: string): never {
  throw new SurveillanceSourcePublicationError("AUTHORITY_MISMATCH", message);
}
