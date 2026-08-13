import { Buffer } from "node:buffer";

import {
  canonicalHash,
  canonicalJson,
  normalizedSnapshotArtifactByteLength,
  normalizedSnapshotArtifactContentHash,
  parseCertifiedSnapshotPublicationV1,
  parseNormalizedSnapshotArtifactV2,
  type CanonicalJsonValue,
  type CertifiedSnapshotPublicationV1
} from "../contracts/index.js";
import {
  artifactJsonContentHash,
  type ArtifactStore,
  type StoredArtifact
} from "../control/artifacts.js";
import type { SurveillancePublicationDisableEventV1 } from "../control/surveillance-publications.js";
import type { ResolvedGovernedDefinitionV2 } from "./governed-definition-v2-resolver.js";
import type { GovernedPlanArtifactReferenceV4 } from "./governed-operation-v4.js";
import {
  bindPortfolioSurveillanceGovernanceV1,
  createCertifiedSnapshotMaterialV1,
  parsePortfolioSurveillanceExecutionPlanV1,
  parsePortfolioSurveillanceOperationRequestV1,
  preparePortfolioSurveillanceExecutionPlanV1,
  type CertifiedSnapshotMaterialV1,
  type PortfolioSurveillanceExecutionPlanV1,
  type PortfolioSurveillanceOperationAuthorityV1,
  type PortfolioSurveillanceOperationRequestV1,
  type PortfolioSurveillanceSnapshotLoadRequestV1
} from "./operations/portfolio-surveillance-v1.js";
import {
  assertAuthorizedPortfolioSurveillancePreflightV1,
  parsePortfolioSurveillanceMetadataPreflightV1,
  type AuthorizedPortfolioSurveillancePreflightV1,
  type FrozenGovernedDefinitionResolutionPortV1,
  type PortfolioSurveillanceMetadataPreflightV1,
  type TerminalCertifiedPublicationLineageV1
} from "./surveillance-access-preflight.js";

const PLAN_ARTIFACT_KIND = "governed_portfolio_surveillance_plan_v4" as const;
const JSON_MEDIA_TYPE = "application/json" as const;

export interface SurveillanceMaterializationPublicationReadPortV1 {
  get(
    tenantId: string,
    publicationId: string
  ): Promise<unknown | undefined> | unknown | undefined;
  getDisable(
    tenantId: string,
    publicationId: string
  ):
    | Promise<SurveillancePublicationDisableEventV1 | undefined>
    | SurveillancePublicationDisableEventV1
    | undefined;
}

export interface PortfolioSurveillanceMaterializerDependenciesV1 {
  readonly publications: SurveillanceMaterializationPublicationReadPortV1;
  /** Tenant id and artifact id are always supplied from authorized preflight. */
  readonly artifacts: Pick<ArtifactStore, "getJson">;
  readonly analyticalDefinitions: FrozenGovernedDefinitionResolutionPortV1;
  /** When present, the final authority-bound plan is persisted exactly once. */
  readonly planArtifacts?: Pick<ArtifactStore, "putJson">;
}

export interface PortfolioSurveillancePlanMaterializationResultV1 {
  readonly plan: PortfolioSurveillanceExecutionPlanV1;
  readonly planArtifact: GovernedPlanArtifactReferenceV4 | null;
}

export type PortfolioSurveillanceMaterializationErrorCode =
  | "AUTHORIZATION_INVALID"
  | "REQUEST_MISMATCH"
  | "PUBLICATION_NOT_FOUND"
  | "PUBLICATION_SUBSTITUTION"
  | "PUBLICATION_DISABLED"
  | "DEFINITION_NOT_FOUND"
  | "DEFINITION_SUBSTITUTION"
  | "ARTIFACT_INTEGRITY_FAILURE"
  | "PLAN_INTEGRITY_FAILURE";

export class PortfolioSurveillanceMaterializationError extends Error {
  constructor(
    readonly code: PortfolioSurveillanceMaterializationErrorCode,
    message: string
  ) {
    super(message);
    this.name = "PortfolioSurveillanceMaterializationError";
  }
}

/**
 * The first component allowed to read normalized rows. It requires a nominal
 * runtime permit, rechecks every immutable publication and disable marker,
 * verifies tenant-scoped artifact bytes, and projects records before they are
 * retained in any plan-building object.
 */
export class PortfolioSurveillancePlanMaterializerV1 {
  constructor(readonly dependencies: PortfolioSurveillanceMaterializerDependenciesV1) {}

  async materialize(
    authorizedValue: AuthorizedPortfolioSurveillancePreflightV1,
    operationRequestValue: unknown
  ): Promise<PortfolioSurveillancePlanMaterializationResultV1> {
    let metadata: PortfolioSurveillanceMetadataPreflightV1;
    let request: PortfolioSurveillanceOperationRequestV1;
    try {
      assertAuthorizedPortfolioSurveillancePreflightV1(authorizedValue);
      metadata = parsePortfolioSurveillanceMetadataPreflightV1(authorizedValue.metadata);
      request = parsePortfolioSurveillanceOperationRequestV1(operationRequestValue);
    } catch {
      fail("AUTHORIZATION_INVALID", "Portfolio surveillance authorization did not verify");
    }
    if (canonicalJson(request) !== canonicalJson(metadata.request)) {
      fail("REQUEST_MISMATCH", "Operation request did not exactly match authorized preflight");
    }

    const definitions = await resolveDefinitions(metadata, this.dependencies.analyticalDefinitions);

    // This complete metadata and disable-state pass is deliberately the final
    // repository interaction before the first normalized-artifact read.
    const publications = await recheckPublications(metadata, this.dependencies.publications);

    const materials = new Map<string, CertifiedSnapshotMaterialV1>();
    const materialEvidenceHashes = new Map<string, `sha256:${string}`>();
    for (const expected of metadata.publications) {
      const materialized = await readAndProjectArtifact(
        metadata,
        expected,
        this.dependencies.artifacts
      );
      materials.set(expected.certificationManifestId, materialized.material);
      materialEvidenceHashes.set(
        expected.certificationManifestId,
        materialized.materialEvidenceHash
      );
    }

    const authority = new MaterializedPlanAuthority(materials, definitions);
    let plan: PortfolioSurveillanceExecutionPlanV1;
    try {
      const base = await preparePortfolioSurveillanceExecutionPlanV1(
        request,
        { tenantId: metadata.tenantId, purpose: metadata.purpose },
        authority
      );
      plan = bindCertifiedPopulationLineage(
        base,
        metadata,
        materialEvidenceHashes
      );
      plan = bindPortfolioSurveillanceGovernanceV1(plan, {
        metadataHash: metadata.metadataHash,
        preflightHash: metadata.v4Preflight.preflightHash,
        sourceSelectionHash: metadata.sourceSelectionHash,
        sourceIdentityHash: metadata.sourceIdentityHash,
        sourceAccessPolicies: [...metadata.sourceAccessPolicies],
        sourceAccessPolicySetHash: metadata.sourceAccessPolicySetHash,
        datasetScopeBindings: [...metadata.datasetScopeBindings],
        datasetScopeBindingSetHash: metadata.datasetScopeBindingSetHash
      });
    } catch (error) {
      if (error instanceof PortfolioSurveillanceMaterializationError) throw error;
      fail("PLAN_INTEGRITY_FAILURE", "Projected surveillance plan failed deterministic validation");
    }
    assertFinalPlan(plan, metadata, publications);

    const planArtifact = this.dependencies.planArtifacts === undefined
      ? null
      : persistPlan(metadata.tenantId, plan, this.dependencies.planArtifacts);
    return Object.freeze({ plan, planArtifact });
  }
}

async function resolveDefinitions(
  metadata: PortfolioSurveillanceMetadataPreflightV1,
  port: FrozenGovernedDefinitionResolutionPortV1
): Promise<ReadonlyMap<string, ResolvedGovernedDefinitionV2>> {
  const result = new Map<string, ResolvedGovernedDefinitionV2>();
  for (const expected of metadata.definitions) {
    const value = await port.resolveFrozenDefinition(
      metadata.tenantId,
      expected.definitionVersionId
    );
    if (value === undefined) {
      fail("DEFINITION_NOT_FOUND", "An authorized analytical definition was not found");
    }
    const actual = {
      kind: value.reference.kind,
      definitionVersionId: value.reference.definitionVersionId,
      definitionKey: value.reference.definitionKey,
      semanticVersion: value.reference.semanticVersion,
      versionHash: value.reference.versionHash,
      documentHash: value.reference.documentHash,
      approvalEventHash: value.reference.approvalEventHash,
      executionDocumentHash: canonicalHash(value.executionDocument)
    };
    if (
      canonicalJson(actual) !== canonicalJson(expected) ||
      value.approvalEvidence.status !== "approved" ||
      value.approvalEvidence.approvalEventHash !== expected.approvalEventHash ||
      value.approvalEvidence.approvedAt > metadata.planningCutoff
    ) {
      fail("DEFINITION_SUBSTITUTION", "Frozen analytical definition authority drifted");
    }
    result.set(expected.definitionVersionId, value);
  }
  return result;
}

async function recheckPublications(
  metadata: PortfolioSurveillanceMetadataPreflightV1,
  port: SurveillanceMaterializationPublicationReadPortV1
): Promise<ReadonlyMap<string, CertifiedSnapshotPublicationV1>> {
  const result = new Map<string, CertifiedSnapshotPublicationV1>();
  for (const expected of metadata.publications) {
    const candidate = await port.get(metadata.tenantId, expected.publicationId);
    if (candidate === undefined) {
      fail("PUBLICATION_NOT_FOUND", "An authorized publication was not found at materialization");
    }
    let publication: CertifiedSnapshotPublicationV1;
    try {
      publication = parseCertifiedSnapshotPublicationV1(candidate);
    } catch {
      fail("PUBLICATION_SUBSTITUTION", "Publication failed immutable verification at materialization");
    }
    if (
      publication.tenantId !== metadata.tenantId ||
      canonicalJson(publicationProjection(publication)) !==
        canonicalJson(directPublicationProjection(expected))
    ) {
      fail("PUBLICATION_SUBSTITUTION", "Publication authority substituted authorized evidence");
    }
    const disabled = await port.getDisable(metadata.tenantId, expected.publicationId);
    if (disabled !== undefined) {
      fail("PUBLICATION_DISABLED", "An authorized publication was disabled before materialization");
    }
    result.set(expected.publicationId, publication);
  }
  return result;
}

function publicationProjection(
  publication: CertifiedSnapshotPublicationV1
): Omit<TerminalCertifiedPublicationLineageV1, "lineagePublicationHashes" | "correctionLineageHash"> {
  if (
    publication.normalizedArtifact.artifactContractVersion !== 2 ||
    publication.normalizedArtifact.artifactHash === undefined
  ) {
    fail("PUBLICATION_SUBSTITUTION", "Publication omitted modern normalized artifact identity");
  }
  return {
    publicationId: publication.publicationId,
    publicationHash: publication.publicationHash,
    certificationManifestId: publication.certification.certificationManifestId,
    certificationManifestHash: publication.certification.certificationManifestHash,
    certifiedAt: publication.certification.certifiedAt,
    snapshotId: publication.snapshot.snapshotId,
    snapshotHash: publication.snapshot.snapshotHash,
    asOfDate: publication.snapshot.asOfDate,
    datasetId: publication.datasetId,
    datasetBindingId: publication.datasetBinding.bindingId,
    sourceContract: {
      sourceContractId: publication.sourceContract.sourceContractId,
      sourceKey: publication.sourceContract.sourceKey,
      revision: publication.sourceContract.revision,
      sourceContractHash: publication.sourceContract.sourceContractHash
    },
    scope: publication.scope,
    populationHash: publication.population.populationHash,
    rowCount: publication.population.rowCount,
    normalizedPopulationId: publication.population.populationId,
    mappingApplicationId: publication.mappingApplication.mappingApplicationId,
    mappingApplicationHash: publication.mappingApplication.mappingApplicationHash,
    normalizedArtifact: {
      artifactId: publication.normalizedArtifact.artifactId,
      artifactContractVersion: publication.normalizedArtifact.artifactContractVersion,
      artifactHash: publication.normalizedArtifact.artifactHash,
      kind: publication.normalizedArtifact.kind,
      mediaType: publication.normalizedArtifact.mediaType,
      contentHash: publication.normalizedArtifact.contentHash,
      byteLength: publication.normalizedArtifact.byteLength,
      uri: publication.normalizedArtifact.uri,
      metadataHash: publication.normalizedArtifact.metadataHash,
      rowCount: publication.normalizedArtifact.rowCount,
      populationHash: publication.normalizedArtifact.populationHash,
      fieldSetHash: publication.normalizedArtifact.fieldSetHash
    },
    publishedAt: publication.publishedAt
  };
}

function directPublicationProjection(
  expected: TerminalCertifiedPublicationLineageV1
): Omit<TerminalCertifiedPublicationLineageV1, "lineagePublicationHashes" | "correctionLineageHash"> {
  const {
    lineagePublicationHashes: _lineagePublicationHashes,
    correctionLineageHash: _correctionLineageHash,
    ...direct
  } = expected;
  return direct;
}

async function readAndProjectArtifact(
  metadata: PortfolioSurveillanceMetadataPreflightV1,
  expected: TerminalCertifiedPublicationLineageV1,
  port: Pick<ArtifactStore, "getJson">
): Promise<Readonly<{
  material: CertifiedSnapshotMaterialV1;
  materialEvidenceHash: `sha256:${string}`;
}>> {
  let loaded: ReturnType<ArtifactStore["getJson"]>;
  try {
    loaded = await port.getJson(metadata.tenantId, bareArtifactId(expected.normalizedArtifact.artifactId));
  } catch {
    fail("ARTIFACT_INTEGRITY_FAILURE", "Tenant-scoped normalized artifact read failed");
  }
  const stored = parseStoredArtifact(loaded.metadata);
  let artifact: ReturnType<typeof parseNormalizedSnapshotArtifactV2>;
  try {
    artifact = parseNormalizedSnapshotArtifactV2(loaded.value);
  } catch {
    fail("ARTIFACT_INTEGRITY_FAILURE", "Normalized artifact canonical contract did not verify");
  }
  if (
    stored.artifactId !== bareArtifactId(expected.normalizedArtifact.artifactId) ||
    stored.kind !== expected.normalizedArtifact.kind ||
    stored.mediaType !== expected.normalizedArtifact.mediaType ||
    stored.contentHash !== bareCanonicalHash(expected.normalizedArtifact.contentHash) ||
    stored.byteLength !== expected.normalizedArtifact.byteLength ||
    stored.uri !== expected.normalizedArtifact.uri ||
    canonicalHash(stored) !== expected.normalizedArtifact.metadataHash ||
    normalizedSnapshotArtifactContentHash(artifact) !== expected.normalizedArtifact.contentHash ||
    normalizedSnapshotArtifactByteLength(artifact) !== expected.normalizedArtifact.byteLength ||
    artifact.contractVersion !== expected.normalizedArtifact.artifactContractVersion ||
    artifact.kind !== expected.normalizedArtifact.kind ||
    artifact.artifactHash !== expected.normalizedArtifact.artifactHash ||
    artifact.tenantId !== metadata.tenantId ||
    artifact.snapshot.snapshotId !== expected.snapshotId ||
    artifact.snapshot.snapshotHash !== expected.snapshotHash ||
    artifact.mappingApplication.mappingApplicationId !== expected.mappingApplicationId ||
    artifact.mappingApplication.mappingApplicationHash !== expected.mappingApplicationHash ||
    artifact.normalizedPopulationId !== expected.normalizedPopulationId ||
    artifact.populationHash !== expected.populationHash ||
    artifact.populationHash !== expected.normalizedArtifact.populationHash ||
    artifact.fieldSetHash !== expected.normalizedArtifact.fieldSetHash ||
    artifact.rowCount !== expected.rowCount ||
    artifact.rowCount !== expected.normalizedArtifact.rowCount
  ) {
    fail("ARTIFACT_INTEGRITY_FAILURE", "Normalized artifact did not match authorized publication");
  }

  // No unrequested field is copied into the retained material. The parsed
  // full artifact becomes unreachable when this function returns.
  const records = projectRecords(artifact.records, metadata.requestedFields);
  const material = createCertifiedSnapshotMaterialV1({
    contractVersion: 1,
    tenantId: metadata.tenantId,
    datasetId: expected.datasetId,
    source: expected.sourceContract,
    scope: expected.scope,
    authorizedPurpose: metadata.purpose,
    authorizedFields: [...metadata.requestedFields],
    authorizedAggregateDimensionFields: [...metadata.requestedAggregateDimensionFields],
    certificationManifestId: expected.certificationManifestId,
    certificationManifestHash: expected.certificationManifestHash,
    populationHash: canonicalHash(records),
    normalizedArtifact: {
      artifactId: expected.normalizedArtifact.artifactId,
      contentHash: expected.normalizedArtifact.contentHash
    },
    rowCount: records.length,
    snapshot: {
      schemaVersion: "1",
      snapshotId: expected.snapshotId,
      tenantId: metadata.tenantId,
      asOfDate: expected.asOfDate,
      snapshotHash: expected.snapshotHash,
      certification: {
        status: "certified",
        certificationId: expected.certificationManifestId,
        certificationHash: expected.certificationManifestHash,
        certifiedAt: expected.certifiedAt
      },
      records: [...records]
    }
  });
  return Object.freeze({
    material,
    materialEvidenceHash: canonicalHash({
      contract: "portfolio_surveillance_projected_material_v1",
      metadataHash: metadata.metadataHash,
      publication: expected,
      projectedPopulationHash: canonicalHash(records)
    })
  });
}

function bindCertifiedPopulationLineage(
  base: PortfolioSurveillanceExecutionPlanV1,
  metadata: PortfolioSurveillanceMetadataPreflightV1,
  materialEvidenceHashes: ReadonlyMap<string, `sha256:${string}`>
): PortfolioSurveillanceExecutionPlanV1 {
  if (
    base.requestHash !== metadata.requestHash ||
    base.definitionSetHash !== metadata.definitionSetHash ||
    base.requestedFieldsHash !== metadata.requestedFieldsHash ||
    canonicalJson(base.definitionLineage) !== canonicalJson(metadata.definitions) ||
    canonicalJson(base.requestedFields) !== canonicalJson(metadata.requestedFields)
  ) {
    fail("PLAN_INTEGRITY_FAILURE", "Plan preparation drifted from authorized metadata");
  }
  const byCertification = new Map(
    metadata.publications.map((publication) => [publication.certificationManifestId, publication])
  );
  const sourceLineage = base.sourceLineage.map((source) => {
    const expected = byCertification.get(source.certificationManifestId);
    const materialHash = materialEvidenceHashes.get(source.certificationManifestId);
    if (
      expected === undefined ||
      materialHash === undefined ||
      source.snapshotId !== expected.snapshotId ||
      source.snapshotHash !== expected.snapshotHash ||
      source.normalizedArtifactId !== expected.normalizedArtifact.artifactId ||
      source.normalizedArtifactContentHash !== expected.normalizedArtifact.contentHash ||
      source.rowCount !== expected.rowCount
    ) {
      fail("PLAN_INTEGRITY_FAILURE", "Projected source lineage drifted from publication");
    }
    return { ...source, materialHash, populationHash: expected.populationHash };
  });
  const { planHash: _planHash, ...baseBody } = base;
  const body = {
    ...baseBody,
    sourceLineage,
    sourceSetHash: canonicalHash(sourceLineage)
  };
  return parsePortfolioSurveillanceExecutionPlanV1({
    ...body,
    planHash: canonicalHash(body)
  });
}

function assertFinalPlan(
  planValue: PortfolioSurveillanceExecutionPlanV1,
  metadata: PortfolioSurveillanceMetadataPreflightV1,
  publications: ReadonlyMap<string, CertifiedSnapshotPublicationV1>
): void {
  const plan = parsePortfolioSurveillanceExecutionPlanV1(planValue);
  const governance = plan.governanceBindings;
  if (
    plan.requestHash !== metadata.requestHash ||
    governance === undefined ||
    governance.metadataHash !== metadata.metadataHash ||
    governance.preflightHash !== metadata.v4Preflight.preflightHash ||
    governance.sourceSelectionHash !== metadata.sourceSelectionHash ||
    governance.sourceIdentityHash !== metadata.sourceIdentityHash ||
    publications.size !== metadata.publications.length ||
    plan.sourceLineage.some(
      (source) =>
        !metadata.publications.some(
          (publication) =>
            publication.certificationManifestId === source.certificationManifestId &&
            publication.populationHash === source.populationHash
        )
    )
  ) {
    fail("PLAN_INTEGRITY_FAILURE", "Final plan did not preserve authorized authority bindings");
  }
}

function persistPlan(
  tenantId: string,
  plan: PortfolioSurveillanceExecutionPlanV1,
  port: Pick<ArtifactStore, "putJson">
): GovernedPlanArtifactReferenceV4 {
  const canonicalPlan = canonicalJson(plan);
  const expectedContentHash = artifactJsonContentHash(plan);
  let stored: StoredArtifact;
  try {
    stored = parseStoredArtifact(port.putJson({
      tenantId,
      kind: PLAN_ARTIFACT_KIND,
      mediaType: JSON_MEDIA_TYPE,
      value: plan
    }));
  } catch {
    fail("PLAN_INTEGRITY_FAILURE", "Governed surveillance plan persistence failed");
  }
  const mismatches = [
    stored.kind === PLAN_ARTIFACT_KIND ? null : "kind",
    stored.mediaType === JSON_MEDIA_TYPE ? null : "mediaType",
    stored.contentHash === expectedContentHash ? null : "contentHash",
    stored.byteLength === Buffer.byteLength(canonicalPlan, "utf8") ? null : "byteLength",
    stored.uri === `abl-artifact://${stored.artifactId}` ? null : "uri"
  ].filter((value): value is string => value !== null);
  if (mismatches.length !== 0) {
    fail(
      "PLAN_INTEGRITY_FAILURE",
      `Stored surveillance plan metadata did not match exact ${mismatches.join(", ")}` +
        (mismatches.includes("contentHash")
          ? ` (${stored.contentHash} != ${expectedContentHash})`
          : "")
    );
  }
  return Object.freeze({
    artifactId: stored.artifactId,
    kind: PLAN_ARTIFACT_KIND,
    mediaType: JSON_MEDIA_TYPE,
    contentHash: stored.contentHash,
    byteLength: stored.byteLength
  });
}

class MaterializedPlanAuthority implements PortfolioSurveillanceOperationAuthorityV1 {
  constructor(
    readonly materials: ReadonlyMap<string, CertifiedSnapshotMaterialV1>,
    readonly definitions: ReadonlyMap<string, ResolvedGovernedDefinitionV2>
  ) {}

  loadLongitudinalBundle(): undefined {
    return undefined;
  }

  loadCertifiedSnapshot(
    input: PortfolioSurveillanceSnapshotLoadRequestV1
  ): CertifiedSnapshotMaterialV1 | undefined {
    if (input.sourceKind !== "certification_manifest") return undefined;
    return this.materials.get(input.certificationManifestId);
  }

  resolveFrozenDefinition(
    _tenantId: string,
    definitionVersionId: string
  ): ResolvedGovernedDefinitionV2 | undefined {
    return this.definitions.get(definitionVersionId);
  }
}

function projectRecords(
  records: readonly Readonly<Record<string, CanonicalJsonValue>>[],
  fields: readonly string[]
): readonly Readonly<Record<string, CanonicalJsonValue>>[] {
  return Object.freeze(records.map((record) => {
    const projected: Record<string, CanonicalJsonValue> = {};
    for (const field of fields) {
      if (Object.prototype.hasOwnProperty.call(record, field)) projected[field] = record[field]!;
    }
    return Object.freeze(projected);
  }));
}

function parseStoredArtifact(value: StoredArtifact): StoredArtifact {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    canonicalJson(Object.keys(value).sort()) !==
      canonicalJson([
        "artifactId",
        "byteLength",
        "contentHash",
        "keyId",
        "kind",
        "mediaType",
        "tenantBinding",
        "uri"
      ]) ||
    !/^[a-f0-9]{64}$/u.test(value.artifactId) ||
    !/^[a-f0-9]{64}$/u.test(value.contentHash) ||
    !/^[a-f0-9]{64}$/u.test(value.tenantBinding) ||
    !Number.isSafeInteger(value.byteLength) ||
    value.byteLength < 1 ||
    typeof value.kind !== "string" ||
    typeof value.mediaType !== "string" ||
    typeof value.keyId !== "string" ||
    typeof value.uri !== "string"
  ) {
    fail("ARTIFACT_INTEGRITY_FAILURE", "Artifact store returned invalid metadata");
  }
  return Object.freeze({ ...value });
}

function bareArtifactId(value: string): string {
  const bare = value.startsWith("sha256:") ? value.slice("sha256:".length) : value;
  if (!/^[a-f0-9]{64}$/u.test(bare)) {
    fail("ARTIFACT_INTEGRITY_FAILURE", "Authorized artifact identity is invalid");
  }
  return bare;
}

function bareCanonicalHash(value: string): string {
  if (!/^sha256:[a-f0-9]{64}$/u.test(value)) {
    fail("ARTIFACT_INTEGRITY_FAILURE", "Authorized artifact hash is invalid");
  }
  return value.slice("sha256:".length);
}

function fail(code: PortfolioSurveillanceMaterializationErrorCode, message: string): never {
  throw new PortfolioSurveillanceMaterializationError(code, message);
}
