import assert from "node:assert/strict";
import { test } from "node:test";

import {
  canonicalHash,
  createCertifiedSnapshotPublicationV1,
  createMappingApplicationV1,
  type CertifiedSnapshotPublicationV1,
  type Sha256Hash
} from "../src/contracts/index.js";
import type {
  GovernedCertifiedSnapshotPublicationLinkV2
} from "../src/contracts/governed-certified-snapshot-publication-link-v2.js";
import type {
  GovernedCertifiedSnapshotPublicationLinkDisableEventV2
} from "../src/control/governed-certified-snapshot-publication-links-v2.js";
import type {
  ResolvedGovernedCertifiedSnapshotPublicationMetadataV2,
  ResolvedGovernedCertifiedSnapshotPublicationV2
} from "../src/services/surveillance-production-authority-v2.js";
import {
  V2OnlySurveillancePublicationMaterializationReadAdapter,
  V2OnlySurveillancePublicationReadAdapter,
  V2SurveillancePublicationReadAdapterError,
  type GovernedCertifiedSnapshotPublicationLinkCatalogReadPortV2
} from "../src/services/surveillance-publication-v2-read-adapter.js";

const HASH = (value: unknown): Sha256Hash => canonicalHash(value);

test("V2 preflight adapter verifies metadata without invoking artifact authority", async () => {
  const fixture = fixtureEnvironment();

  const byEvidence = await fixture.adapter.getByCertificationManifest("tenant-a", "certification-a");
  const byPublication = await fixture.adapter.get("tenant-a", "publication-a");
  const page = await fixture.adapter.listByScopeAsOf({
    tenantId: "tenant-a",
    datasetId: "dataset-a",
    sourceContract: sourceSelector(),
    scope: { scopeType: "facility", scopeId: "facility-a" },
    asOfDate: "2026-02-28",
    publishedThrough: "2026-03-02T00:00:00.000Z",
    maximumResults: 10
  });

  assert.equal(byEvidence?.publicationHash, fixture.publication.publicationHash);
  assert.equal(byPublication?.publicationHash, fixture.publication.publicationHash);
  assert.deepEqual(page.publications.map((publication) => publication.publicationId), ["publication-a"]);
  assert.equal(page.complete, true);
  assert.equal(fixture.authority.metadataCalls.length, 3);
  assert.equal(fixture.authority.artifactCalls.length, 0);
});

test("V2 materialization adapter invokes full authority only after an enabled recheck", async () => {
  const fixture = fixtureEnvironment();
  const material = await fixture.materializationAdapter.get("tenant-a", "publication-a");

  assert.equal(material?.publicationHash, fixture.publication.publicationHash);
  assert.equal(fixture.authority.metadataCalls.length, 0);
  assert.equal(fixture.authority.artifactCalls.length, 1);
});

test("V2 preflight retains later-disabled evidence while materialization fails before artifact authority", async () => {
  const fixture = fixtureEnvironment({ disabled: true });

  const result = await fixture.adapter.getByCertificationManifest("tenant-a", "certification-a");
  const disable = await fixture.adapter.getDisable("tenant-a", "publication-a");
  const material = await fixture.materializationAdapter.get("tenant-a", "publication-a");

  assert.equal(result?.publicationHash, fixture.publication.publicationHash);
  assert.equal(material, undefined);
  assert.equal(fixture.authority.metadataCalls.length, 1);
  assert.equal(fixture.authority.artifactCalls.length, 0);
  assert.deepEqual(disable, {
    tenantId: "tenant-a",
    publicationId: "publication-a",
    publicationHash: fixture.publication.publicationHash,
    reasonCode: "superseded",
    reason: "controlled test disable",
    disabledBy: "checker-a",
    disabledAt: "2026-03-02T00:00:00.000Z"
  });
});

test("V2-only adapter fails closed when the V2 authority substitutes a selected link", async () => {
  const fixture = fixtureEnvironment({ substituteAuthorityLink: true });

  await assert.rejects(
    fixture.adapter.getByCertificationManifest("tenant-a", "certification-a"),
    (error: unknown) => adapterError(error, "INTEGRITY_FAILURE")
  );
});

test("V2-only adapter rejects catalog tenant substitution before consulting the V2 authority", async () => {
  const fixture = fixtureEnvironment({ substituteCatalogTenant: true });

  await assert.rejects(
    fixture.adapter.getByCertificationManifest("tenant-a", "certification-a"),
    (error: unknown) => adapterError(error, "INTEGRITY_FAILURE")
  );
  assert.equal(fixture.authority.metadataCalls.length, 0);
  assert.equal(fixture.authority.artifactCalls.length, 0);
});

test("V2-only adapter has no V1 fallback when no V2 evidence link exists", async () => {
  const fixture = fixtureEnvironment({ omitEvidenceLink: true });

  assert.equal(await fixture.adapter.getByCertificationManifest("tenant-a", "certification-a"), undefined);
  assert.equal(fixture.authority.metadataCalls.length, 0);
  assert.equal(fixture.authority.artifactCalls.length, 0);
});

interface Fixture {
  readonly adapter: V2OnlySurveillancePublicationReadAdapter;
  readonly materializationAdapter: V2OnlySurveillancePublicationMaterializationReadAdapter;
  readonly authority: FakeAuthority;
  readonly publication: CertifiedSnapshotPublicationV1;
}

function fixtureEnvironment(options: {
  readonly disabled?: boolean;
  readonly substituteAuthorityLink?: boolean;
  readonly substituteCatalogTenant?: boolean;
  readonly omitEvidenceLink?: boolean;
} = {}): Fixture {
  const publication = publicationFixture();
  const link = linkFor(publication, options.substituteCatalogTenant ? "tenant-b" : "tenant-a");
  const catalog = new FakeCatalog(options.omitEvidenceLink ? [] : [link], options.disabled ? link.linkId : undefined);
  const authority = new FakeAuthority(link, options.substituteAuthorityLink);
  const adapter = new V2OnlySurveillancePublicationReadAdapter({ metadataAuthority: authority, publicationLinks: catalog });
  const materializationAdapter = new V2OnlySurveillancePublicationMaterializationReadAdapter({ artifactAuthority: authority, publicationLinks: catalog });
  return { adapter, materializationAdapter, authority, publication };
}

class FakeCatalog implements GovernedCertifiedSnapshotPublicationLinkCatalogReadPortV2 {
  constructor(
    private readonly links: readonly GovernedCertifiedSnapshotPublicationLinkV2[],
    private readonly disabledLinkId?: string
  ) {}

  getEnabled(tenantId: string, linkId: string): GovernedCertifiedSnapshotPublicationLinkV2 | undefined {
    return this.disabledLinkId === linkId
      ? undefined
      : this.links.find((link) => link.tenantId === tenantId && link.linkId === linkId);
  }

  getByEvidence(tenantId: string, evidenceId: string): GovernedCertifiedSnapshotPublicationLinkV2 | undefined {
    // The deliberately substituted fixture simulates a repository that violated
    // tenant fencing, which the adapter must reject rather than reinterpret.
    return this.links.find((link) => link.evidence.evidenceId === evidenceId && (tenantId === "tenant-a" || link.tenantId === tenantId));
  }

  list(tenantId: string): readonly GovernedCertifiedSnapshotPublicationLinkV2[] {
    return this.links.filter((link) => link.tenantId === tenantId);
  }

  getDisable(tenantId: string, linkId: string): GovernedCertifiedSnapshotPublicationLinkDisableEventV2 | undefined {
    const link = this.links.find((candidate) => candidate.tenantId === tenantId && candidate.linkId === linkId);
    if (!link || this.disabledLinkId !== linkId) return undefined;
    return {
      tenantId,
      linkId,
      linkHash: link.linkHash,
      reasonCode: "superseded",
      reason: "controlled test disable",
      disabledBy: "checker-a",
      disabledAt: "2026-03-02T00:00:00.000Z"
    };
  }
}

class FakeAuthority {
  readonly metadataCalls: Array<{ readonly tenantId: string; readonly linkId: string }> = [];
  readonly artifactCalls: Array<{ readonly tenantId: string; readonly linkId: string }> = [];

  constructor(
    private readonly link: GovernedCertifiedSnapshotPublicationLinkV2,
    private readonly substituteLink: boolean
  ) {}

  async resolveMetadata(input: { readonly tenantId: string; readonly linkId: string }): Promise<ResolvedGovernedCertifiedSnapshotPublicationMetadataV2 | undefined> {
    this.metadataCalls.push(input);
    if (input.tenantId !== this.link.tenantId || input.linkId !== this.link.linkId) return undefined;
    const resolvedLink = this.substituteLink
      ? { ...this.link, linkHash: HASH("substituted-link") }
      : this.link;
    return {
      link: resolvedLink,
      evidence: {
        tenantId: this.link.tenantId,
        certificationAttempt: { certificationManifestId: this.link.evidence.evidenceId }
      },
      snapshot: {
        tenantId: this.link.tenantId,
        snapshotId: this.link.governance.certificationAttempt.snapshotId,
        snapshotHash: this.link.governance.certificationAttempt.snapshotHash
      }
    } as ResolvedGovernedCertifiedSnapshotPublicationMetadataV2;
  }

  async resolveArtifact(input: { readonly tenantId: string; readonly linkId: string }): Promise<ResolvedGovernedCertifiedSnapshotPublicationV2 | undefined> {
    this.artifactCalls.push(input);
    const before = this.metadataCalls.length;
    const metadata = await this.resolveMetadata(input);
    this.metadataCalls.splice(before);
    return metadata === undefined
      ? undefined
      : { ...metadata, normalizedArtifact: {} as never };
  }
}

function linkFor(publication: CertifiedSnapshotPublicationV1, tenantId: string): GovernedCertifiedSnapshotPublicationLinkV2 {
  return {
    contractVersion: 2,
    tenantId,
    linkId: "link-a",
    linkHash: HASH("link-a"),
    linkedAt: "2026-03-01T00:00:00.000Z",
    publication: {
      publicationId: publication.publicationId,
      publicationHash: publication.publicationHash,
      certificationManifestId: publication.certification.certificationManifestId,
      snapshotId: publication.snapshot.snapshotId,
      snapshotHash: publication.snapshot.snapshotHash,
      datasetBindingId: publication.datasetBinding.bindingId,
      datasetBindingHash: publication.datasetBinding.bindingHash,
      mappingApplicationId: publication.mappingApplication.mappingApplicationId,
      mappingApplicationHash: publication.mappingApplication.mappingApplicationHash,
      record: publication
    },
    evidence: {
      evidenceId: publication.certification.certificationManifestId,
      evidenceHash: HASH("evidence-a"),
      v1EvidenceHash: HASH("v1-evidence-a"),
      record: {} as never
    },
    governance: {
      certificationAttempt: {
        certificationManifestId: publication.certification.certificationManifestId,
        attemptHash: HASH("attempt-a"),
        snapshotId: publication.snapshot.snapshotId,
        snapshotHash: publication.snapshot.snapshotHash,
        certifiedAt: publication.certification.certifiedAt
      },
      control: {} as never,
      scopeBinding: {} as never,
      mapping: {} as never,
      runtime: {} as never,
      governanceHash: HASH("governance-a")
    }
  } as GovernedCertifiedSnapshotPublicationLinkV2;
}

function sourceSelector() {
  return {
    sourceContractId: "source-a",
    sourceKey: "source-key-a",
    revision: 1,
    sourceContractHash: HASH("source-a")
  };
}

function publicationFixture(): CertifiedSnapshotPublicationV1 {
  const tenantId = "tenant-a";
  const sourceContract = {
    sourceContractId: "source-a",
    revision: 1,
    sourceContractHash: HASH("source-a")
  } as const;
  const dictionary = {
    contractVersion: 1 as const,
    bundleKind: "dictionary" as const,
    bundleId: "dictionary-a",
    version: "1.0.0",
    contentHash: HASH("dictionary"),
    artifactId: "dictionary-artifact-a",
    mediaType: "application/json",
    createdAt: "2026-01-01T00:00:00.000Z",
    dictionaryVersion: "1.0.0",
    dictionaryHash: HASH("dictionary-hash"),
    fieldPolicyVersion: "1.0.0",
    fieldPolicyHash: HASH("field-policy")
  };
  const snapshot = {
    snapshotId: "snapshot-a",
    snapshotHash: HASH("snapshot-a"),
    sourceContract,
    delivery: { mode: "managed_upload" as const, deliveredContentHash: HASH("contents-a") },
    asOfDate: "2026-02-28",
    knowledge: {
      sourceObservedAt: "2026-03-01T00:00:00.000Z",
      extractedAt: "2026-03-01T00:01:00.000Z",
      receivedAt: "2026-03-01T00:02:00.000Z",
      persistedAt: "2026-03-01T00:03:00.000Z"
    },
    hashes: {
      contentHash: HASH("contents-a"), schemaHash: HASH("schema-a"), catalogHash: HASH("catalog-a"),
      parserHash: HASH("parser-a"), extractionHash: HASH("receipt-a")
    },
    rowCount: 1,
    byteCount: 100,
    correction: { kind: "original" as const }
  };
  const mappingApplication = createMappingApplicationV1({
    contractVersion: 1,
    tenantId,
    mappingApplicationId: "mapping-application-a",
    snapshot: { snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash, contentHash: snapshot.hashes.contentHash },
    mappingSpec: { mappingSpecId: "mapping-a", revision: 1, mappingSpecHash: HASH("mapping-a") },
    dictionaryBundle: dictionary,
    runtimeBundle: { runtimeBundleId: "runtime-a", runtimeBundleHash: HASH("runtime-a"), runtimeVersion: "1.0.0" },
    inputPopulationHash: HASH("input-a"),
    outputPopulationHash: HASH("population-a"),
    inputRowCount: 1,
    outputRowCount: 1,
    rejectedRowCount: 0,
    appliedBy: "mapper-a",
    appliedAt: "2026-03-01T00:04:00.000Z"
  });
  const populationBody = {
    contractVersion: 1 as const,
    tenantId,
    populationId: "population-a",
    snapshotId: snapshot.snapshotId,
    snapshotHash: snapshot.snapshotHash,
    mappingApplicationId: mappingApplication.mappingApplicationId,
    mappingApplicationHash: mappingApplication.mappingApplicationHash,
    populationHash: HASH("population-a"),
    fieldSetHash: HASH("fields-a"),
    rowCount: 1,
    dataQuality: { runId: "dq-a", rulesetId: "dq-rules-a", rulesetHash: HASH("dq-rules-a"), resultHash: HASH("dq-a"), publicationDecision: "publish" as const, blockerCodes: [] as string[] },
    reconciliation: { reconciliationId: "recon-a", definitionHash: HASH("recon-definition-a"), resultHash: HASH("recon-a"), passed: true as const, populationHash: HASH("population-a") },
    certifiedBy: "checker-a",
    certifiedAt: "2026-03-01T00:05:00.000Z"
  };
  const population = { ...populationBody, certificationHash: HASH(populationBody) };
  const certificationBody = {
    contractVersion: 1 as const,
    tenantId,
    certificationManifestId: "certification-a",
    evidenceFormat: "modern_snapshot_v2" as const,
    snapshotId: snapshot.snapshotId,
    snapshotHash: snapshot.snapshotHash,
    populationId: population.populationId,
    populationCertificationHash: population.certificationHash,
    mappingApplicationId: mappingApplication.mappingApplicationId,
    mappingApplicationHash: mappingApplication.mappingApplicationHash,
    normalizedArtifactId: "artifact-a",
    normalizedArtifactContentHash: HASH("artifact-content-a"),
    dataQualityResultHash: population.dataQuality.resultHash,
    reconciliationResultHash: population.reconciliation.resultHash,
    populationHash: population.populationHash,
    rowCount: population.rowCount,
    certifiedBy: population.certifiedBy,
    certifiedAt: population.certifiedAt
  };
  const bindingBody = {
    contractVersion: 1 as const,
    bindingId: "binding-a",
    tenantId,
    datasetId: "dataset-a",
    sourceContract,
    scope: { scopeType: "facility" as const, scopeId: "facility-a" },
    boundAt: "2026-01-01T00:00:00.000Z"
  };
  return createCertifiedSnapshotPublicationV1({
    contractVersion: 1,
    publicationId: "publication-a",
    tenantId,
    datasetId: bindingBody.datasetId,
    scope: bindingBody.scope,
    datasetBinding: { ...bindingBody, bindingHash: HASH(bindingBody) },
    sourceContract: {
      definition: { definitionVersionId: "source-definition-a", definitionKey: "source-key-a", kind: "source_contract", semanticVersion: "1.0.0", versionHash: HASH("source-version-a"), documentHash: HASH("source-document-a"), approvalEventHash: HASH("source-approval-a") },
      ...sourceContract,
      sourceKey: "source-key-a"
    },
    snapshot,
    certification: { ...certificationBody, certificationManifestHash: HASH(certificationBody) },
    population,
    mappingSpec: { mappingSpecId: "mapping-a", mappingKey: "mapping-key-a", revision: 1, mappingSpecHash: HASH("mapping-a"), sourceContract, dictionaryBundle: dictionary },
    mappingApplication,
    normalizedArtifact: {
      artifactId: "artifact-a", artifactContractVersion: 2, artifactHash: HASH("artifact-contract-a"),
      kind: "normalized_snapshot", mediaType: "application/json", contentHash: certificationBody.normalizedArtifactContentHash,
      byteLength: 100, uri: "artifact://tenant-a/artifact-a", metadataHash: HASH("artifact-metadata-a"),
      rowCount: 1, populationHash: population.populationHash, fieldSetHash: population.fieldSetHash
    },
    publishedBy: "publisher-a",
    publishedAt: "2026-03-01T00:06:00.000Z"
  });
}

function adapterError(
  error: unknown,
  code: V2SurveillancePublicationReadAdapterError["code"]
): boolean {
  return error instanceof V2SurveillancePublicationReadAdapterError && error.code === code;
}
