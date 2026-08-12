import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, test } from "node:test";

import {
  ContractValidationError,
  canonicalHash,
  createCertifiedSnapshotPublicationV1,
  createMappingApplicationV1,
  createSourceAccessPolicyV1,
  parseCertifiedSnapshotPublicationV1,
  parseSourceAccessPolicyV1,
  type CertifiedSnapshotPublicationV1,
  type Sha256Hash
} from "../src/contracts/index.js";
import {
  GovernedDefinitionV2Store,
  GovernedDefinitionV2StoreError
} from "../src/control/governed-definitions-v2.js";
import {
  SurveillancePublicationCatalog,
  SurveillancePublicationCatalogError
} from "../src/control/surveillance-publications.js";
import { GovernedDefinitionV2Resolver } from "../src/services/governed-definition-v2-resolver.js";
import {
  SurveillanceSourcePublicationError,
  SurveillanceSourcePublicationService,
  type CertifiedSnapshotPublicationEvidenceV1,
  type SurveillanceSourcePublicationAuthorityV1
} from "../src/services/surveillance-source-publication.js";

const directories: string[] = [];
const PUBLISHED_AT = "2026-08-12T13:00:00.000Z";

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("SourceAccessPolicyV1 is strict, grant-only, sorted, and hash-bound", () => {
  const policy = sourceAccessPolicy();
  assert.deepEqual(policy.allowedFields, ["as_of_date", "current_balance", "loan_id"]);
  assert.deepEqual(policy.allowedAggregateDimensionFields, ["as_of_date"]);
  assert.equal(parseSourceAccessPolicyV1(policy).policyHash, policy.policyHash);
  assert.equal("approval" in policy, false);

  assert.throws(
    () => createSourceAccessPolicyV1({ ...withoutPolicyHash(policy), allowedFields: ["loan_id", "as_of_date"] }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
  assert.throws(
    () => createSourceAccessPolicyV1({
      ...withoutPolicyHash(policy),
      allowedAggregateDimensionFields: ["borrower_id"]
    }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
  assert.throws(
    () => parseSourceAccessPolicyV1({ ...policy, purpose: "forged" }),
    (error: unknown) => contractError(error, "HASH_MISMATCH")
  );
  assert.throws(
    () => createSourceAccessPolicyV1({
      ...withoutPolicyHash(policy),
      purpose: "free form analyst prose"
    }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
});

test("source access policies use the existing v2 maker/checker lifecycle and frozen resolver", () => {
  const directory = temporaryDirectory();
  const clock = sequentialClock([
    "2026-08-12T12:00:00.000Z",
    "2026-08-12T12:01:00.000Z",
    "2026-08-12T12:02:00.000Z",
    "2026-08-12T12:03:00.000Z"
  ]);
  const store = new GovernedDefinitionV2Store(join(directory, "definitions.sqlite"), { clock });
  const proposed = store.propose({
    tenantId: "tenant-a",
    definitionVersionId: "source-access-policy-v1",
    definitionKey: "portfolio-risk-read",
    kind: "source_access_policy",
    semanticVersion: "1.0.0",
    effectiveFrom: "2026-01-01",
    document: sourceAccessPolicy(),
    proposedBy: "data-steward-maker",
    idempotencyKey: "policy-propose"
  });
  assert.throws(
    () => store.transition({
      tenantId: "tenant-a",
      definitionVersionId: proposed.version.definitionVersionId,
      toStatus: "validated",
      expectedRevision: proposed.lifecycleRevision,
      actor: "data-steward-maker",
      idempotencyKey: "maker-self-validates"
    }),
    (error: unknown) =>
      error instanceof GovernedDefinitionV2StoreError && error.code === "MAKER_CHECKER_VIOLATION"
  );
  let view = proposed;
  for (const toStatus of ["validated", "approved", "active"] as const) {
    view = store.transition({
      tenantId: "tenant-a",
      definitionVersionId: proposed.version.definitionVersionId,
      toStatus,
      expectedRevision: view.lifecycleRevision,
      actor: "risk-checker",
      idempotencyKey: `policy-${toStatus}`
    });
  }
  const resolved = new GovernedDefinitionV2Resolver(store).resolveFrozen({
    tenantId: "tenant-a",
    definitionVersionId: proposed.version.definitionVersionId
  });
  assert.equal(resolved.reference.kind, "source_access_policy");
  assert.equal((resolved.executionDocument as { policyId: string }).policyId, "portfolio-risk-read");
  assert.equal(resolved.approvalEvidence.approvedBy, "risk-checker");

  assert.throws(
    () => store.propose({
      tenantId: "tenant-a",
      definitionVersionId: "bad-policy",
      definitionKey: "another-key",
      kind: "source_access_policy",
      semanticVersion: "1.0.0",
      effectiveFrom: "2026-01-01",
      document: sourceAccessPolicy(),
      proposedBy: "maker-b",
      idempotencyKey: "bad-policy"
    }),
    (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
  );
  store.close();
});

test("CertifiedSnapshotPublicationV1 is data-lineage-only and rejects cross-lineage tampering", () => {
  const publication = publicationFixture();
  assert.equal(parseCertifiedSnapshotPublicationV1(publication).publicationHash, publication.publicationHash);
  const serialized = JSON.stringify(publication);
  for (const forbidden of ["allowedFields", "allowedAggregateDimensionFields", "accessPolicy", "purpose"]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  assert.equal("records" in publication, false);
  assert.equal(publication.scope.scopeType, "portfolio");

  for (const tampered of [
    { ...publication, datasetId: "dataset-forged" },
    { ...publication, scope: { scopeType: "facility" as const, scopeId: "facility-forged" } },
    {
      ...publication,
      normalizedArtifact: { ...publication.normalizedArtifact, populationHash: hash("wrong-population") }
    },
    {
      ...publication,
      sourceContract: { ...publication.sourceContract, sourceContractHash: hash("wrong-source") }
    }
  ]) {
    assert.throws(
      () => parseCertifiedSnapshotPublicationV1(tampered),
      (error: unknown) =>
        contractError(error, "HASH_MISMATCH") || contractError(error, "INVALID_CONTRACT")
    );
  }
});

test("publication chronology binds dataset scope, persistence, mapping, certification, and publication", () => {
  const publication = publicationFixture();
  const body = withoutPublicationHash(publication);
  const lateBindingBody = {
    ...withoutBindingHash(publication.datasetBinding),
    boundAt: "2026-08-12T13:00:01.000Z"
  };
  assert.throws(
    () => createCertifiedSnapshotPublicationV1({
      ...body,
      datasetBinding: { ...lateBindingBody, bindingHash: canonicalHash(lateBindingBody) }
    }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
  assert.throws(
    () => createCertifiedSnapshotPublicationV1({
      ...body,
      snapshot: {
        ...publication.snapshot,
        knowledge: {
          ...publication.snapshot.knowledge,
          persistedAt: "2026-08-01T10:06:00.000Z"
        }
      }
    }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );

  const earlyPopulationBody = {
    ...withoutCertificationHash(publication.population),
    certifiedAt: "2026-08-01T10:03:30.000Z"
  };
  const earlyPopulation = {
    ...earlyPopulationBody,
    certificationHash: canonicalHash(earlyPopulationBody)
  };
  const earlyCertificationBody = {
    ...withoutManifestHash(publication.certification),
    populationCertificationHash: earlyPopulation.certificationHash,
    certifiedAt: earlyPopulation.certifiedAt
  };
  assert.throws(
    () => createCertifiedSnapshotPublicationV1({
      ...body,
      population: earlyPopulation,
      certification: {
        ...earlyCertificationBody,
        certificationManifestHash: canonicalHash(earlyCertificationBody)
      }
    }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
});

test("publication catalog is tenant-scoped, immutable, exactly idempotent, disable-only, and hash-chained", () => {
  const directory = temporaryDirectory();
  const path = join(directory, "shared.sqlite");
  const publication = publicationFixture();
  const catalog = new SurveillancePublicationCatalog(path, {
    clock: () => new Date("2026-08-12T14:00:00.000Z")
  });
  const requestHash = canonicalHash({
    tenantId: publication.tenantId,
    publicationId: publication.publicationId,
    certificationManifestId: publication.certification.certificationManifestId,
    snapshotId: publication.snapshot.snapshotId,
    datasetBindingId: publication.datasetBinding.bindingId,
    sourceContractDefinitionVersionId: publication.sourceContract.definition.definitionVersionId,
    publishedBy: publication.publishedBy
  });
  const input = {
    publication,
    requestHash,
    actor: publication.publishedBy,
    idempotencyKey: "publish-once"
  } as const;
  assert.equal(catalog.record(input).publicationHash, publication.publicationHash);
  assert.equal(catalog.record(input).publicationHash, publication.publicationHash);
  assert.equal(catalog.get("tenant-b", publication.publicationId), undefined);
  assert.equal(
    catalog.getByCertificationManifest("tenant-a", publication.certification.certificationManifestId)
      ?.publicationId,
    publication.publicationId
  );
  assert.throws(
    () => catalog.record({ ...input, requestHash: hash("another-request") }),
    (error: unknown) => catalogError(error, "IDEMPOTENCY_CONFLICT")
  );
  assert.throws(
    () => catalog.record({ ...input, actor: "forged-actor", idempotencyKey: "forged-actor" }),
    (error: unknown) => catalogError(error, "INVALID_INPUT")
  );
  assert.throws(
    () => catalog.record({
      publication: rehashPublication({ ...publication, publicationId: "publication-duplicate" }),
      requestHash: hash("duplicate-manifest-request"),
      actor: publication.publishedBy,
      idempotencyKey: "duplicate-manifest"
    }),
    (error: unknown) => catalogError(error, "CONFLICT")
  );

  const disableInput = {
    tenantId: publication.tenantId,
    publicationId: publication.publicationId,
    expectedPublicationHash: publication.publicationHash,
    reasonCode: "source_restatement",
    reason: "A certified replacement snapshot was published.",
    disabledBy: "risk-checker",
    idempotencyKey: "disable-once"
  } as const;
  assert.equal(catalog.disable(disableInput).publicationHash, publication.publicationHash);
  assert.deepEqual(catalog.disable(disableInput), catalog.getDisable("tenant-a", publication.publicationId));
  assert.equal(catalog.get("tenant-a", publication.publicationId)?.publicationHash, publication.publicationHash);
  const audit = catalog.listAuditEvents("tenant-a");
  assert.deepEqual(audit.map((event) => event.tenantSequence), [1, 2]);
  assert.equal(audit[1]?.previousEventHash, audit[0]?.eventHash);

  const attacker = new DatabaseSync(path);
  assert.throws(() => attacker.exec("UPDATE surveillance_publications SET published_by = 'attacker'"));
  assert.throws(() => attacker.exec("DELETE FROM surveillance_publication_audit_events"));
  attacker.close();
  catalog.close();
});

test("publication catalog schema attestation coexists and rejects drift", () => {
  const directory = temporaryDirectory();
  const path = join(directory, "coexist.sqlite");
  const definitions = new GovernedDefinitionV2Store(path);
  definitions.close();
  const catalog = new SurveillancePublicationCatalog(path);
  catalog.close();

  const database = new DatabaseSync(path);
  const components = database
    .prepare("SELECT component_name FROM component_schema_versions ORDER BY component_name")
    .all() as unknown as { component_name: string }[];
  assert.deepEqual(
    components.map((row) => row.component_name),
    ["abl.governed-definition-v2-store", "abl.surveillance-publication-catalog"]
  );
  database.exec("DROP TRIGGER surveillance_publications_no_update");
  database.close();
  assert.throws(
    () => new SurveillancePublicationCatalog(path),
    (error: unknown) => error instanceof Error && /schema/iu.test(error.message)
  );
});

test("trusted publication service accepts IDs only and rejects authority substitutions", async () => {
  const directory = temporaryDirectory();
  const expected = publicationFixture();
  const catalog = new SurveillancePublicationCatalog(join(directory, "service.sqlite"));
  const authority = authorityFor(expected);
  const service = new SurveillanceSourcePublicationService(authority, catalog, {
    clock: () => new Date(PUBLISHED_AT)
  });
  const request = {
    tenantId: expected.tenantId,
    publicationId: expected.publicationId,
    certificationManifestId: expected.certification.certificationManifestId,
    datasetBindingId: expected.datasetBinding.bindingId,
    datasetSnapshotId: expected.snapshot.snapshotId,
    sourceContractDefinitionVersionId: expected.sourceContract.definition.definitionVersionId,
    idempotencyKey: "service-publish"
  } as const;
  const published = await service.publish(request, expected.publishedBy);
  assert.equal(published.datasetId, expected.datasetId);
  assert.deepEqual(published.scope, expected.scope);
  assert.equal(parseCertifiedSnapshotPublicationV1(published).publicationHash, published.publicationHash);
  assert.equal(published.normalizedArtifact.uri, expected.normalizedArtifact.uri);
  assert.equal(
    published.normalizedArtifact.metadataHash,
    canonicalHash({
      artifactId: authorityEvidence(expected).normalizedArtifact.artifactId,
      tenantBinding: authorityEvidence(expected).normalizedArtifact.tenantBinding,
      kind: authorityEvidence(expected).normalizedArtifact.kind,
      mediaType: authorityEvidence(expected).normalizedArtifact.mediaType,
      contentHash: authorityEvidence(expected).normalizedArtifact.contentHash,
      byteLength: authorityEvidence(expected).normalizedArtifact.byteLength,
      keyId: authorityEvidence(expected).normalizedArtifact.keyId,
      uri: authorityEvidence(expected).normalizedArtifact.uri
    })
  );
  assert.deepEqual(await service.publish(request, expected.publishedBy), published);

  for (const forged of [
    { ...request, populationHash: hash("forged") },
    { ...request, publishedBy: "forged-actor" },
    { ...request, snapshotId: "forged-snapshot" }
  ]) await assert.rejects(
    () => service.publish(forged as never, expected.publishedBy),
    (error: unknown) => sourceError(error, "INVALID_REQUEST")
  );
  await assert.rejects(
    () => service.publish(request, "different-trusted-actor"),
    (error: unknown) => catalogError(error, "CONFLICT")
  );
  await assert.rejects(
    () => service.publish(
      { ...request, datasetSnapshotId: "substituted-snapshot", publicationId: "substituted", idempotencyKey: "substituted" },
      expected.publishedBy
    ),
    (error: unknown) => sourceError(error, "AUTHORITY_MISMATCH")
  );
  const crossTenant = new SurveillanceSourcePublicationService(
    authorityFor(expected, {
      datasetBinding: {
        ...expected.datasetBinding,
        tenantId: "tenant-b",
        bindingHash: hash("forged-binding")
      }
    }),
    new SurveillancePublicationCatalog(join(directory, "cross-tenant.sqlite")),
    { clock: () => new Date(PUBLISHED_AT) }
  );
  await assert.rejects(
    () => crossTenant.publish(
      { ...request, publicationId: "cross-tenant", idempotencyKey: "cross-tenant" },
      expected.publishedBy
    ),
    (error: unknown) => sourceError(error, "FROZEN_EVIDENCE_DRIFT") || sourceError(error, "AUTHORITY_MISMATCH")
  );
  const wrongPopulation = new SurveillanceSourcePublicationService(
    authorityFor(expected, {
      evidence: {
        ...authorityEvidence(expected),
        normalizedArtifact: {
          ...authorityEvidence(expected).normalizedArtifact,
          contentHash: hash("substituted-artifact")
        }
      }
    }),
    new SurveillancePublicationCatalog(join(directory, "wrong-population.sqlite")),
    { clock: () => new Date(PUBLISHED_AT) }
  );
  await assert.rejects(
    () => wrongPopulation.publish(
      { ...request, publicationId: "wrong-population", idempotencyKey: "wrong-population" },
      expected.publishedBy
    ),
    (error: unknown) => sourceError(error, "AUTHORITY_MISMATCH")
  );
  catalog.close();
});

function sourceAccessPolicy() {
  return createSourceAccessPolicyV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    policyId: "portfolio-risk-read",
    revision: 1,
    datasetId: "loan-book",
    sourceContract: {
      sourceContractId: "source-contract-1",
      revision: 1,
      sourceContractHash: hash("source-contract")
    },
    scope: { scopeType: "portfolio", scopeId: "portfolio-east" },
    purpose: "portfolio_surveillance",
    allowedFields: ["as_of_date", "current_balance", "loan_id"],
    allowedAggregateDimensionFields: ["as_of_date"],
    effectiveFrom: "2026-01-01"
  });
}

function publicationFixture(): CertifiedSnapshotPublicationV1 {
  const sourceContract = {
    sourceContractId: "source-contract-1",
    revision: 1,
    sourceContractHash: hash("source-contract")
  } as const;
  const dictionaryBundle = {
    contractVersion: 1,
    bundleKind: "dictionary" as const,
    bundleId: "dictionary-1",
    version: "1.0.0",
    contentHash: hash("dictionary-content"),
    artifactId: "dictionary-artifact-1",
    mediaType: "application/json",
    createdAt: "2026-01-01T00:00:00.000Z",
    dictionaryVersion: "1.0.0",
    dictionaryHash: hash("dictionary"),
    fieldPolicyVersion: "1.0.0",
    fieldPolicyHash: hash("field-policy")
  } as const;
  const snapshot = {
    snapshotId: "snapshot-2026-07",
    snapshotHash: hash("snapshot"),
    sourceContract,
    delivery: {
      mode: "object_storage" as const,
      deliveredContentHash: hash("delivered"),
      immutableSourceVersion: "version-17"
    },
    asOfDate: "2026-07-31",
    knowledge: {
      sourceObservedAt: "2026-08-01T10:00:00.000Z",
      extractedAt: "2026-08-01T10:01:00.000Z",
      receivedAt: "2026-08-01T10:02:00.000Z",
      persistedAt: "2026-08-01T10:03:00.000Z"
    },
    hashes: {
      contentHash: hash("delivered"),
      schemaHash: hash("schema"),
      catalogHash: hash("catalog"),
      parserHash: hash("parser"),
      extractionHash: hash("extraction")
    },
    rowCount: 2,
    byteCount: 512,
    correction: { kind: "original" as const }
  };
  const mappingSpec = {
    mappingSpecId: "mapping-spec-1",
    mappingKey: "mapping-loans",
    revision: 1,
    mappingSpecHash: hash("mapping-spec"),
    sourceContract,
    dictionaryBundle
  } as const;
  const populationHash = hash("population");
  const fieldSetHash = hash("field-set");
  const mappingApplication = createMappingApplicationV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    mappingApplicationId: "mapping-application-1",
    snapshot: {
      snapshotId: snapshot.snapshotId,
      snapshotHash: snapshot.snapshotHash,
      contentHash: snapshot.hashes.contentHash
    },
    mappingSpec: {
      mappingSpecId: mappingSpec.mappingSpecId,
      revision: mappingSpec.revision,
      mappingSpecHash: mappingSpec.mappingSpecHash
    },
    dictionaryBundle,
    runtimeBundle: {
      runtimeBundleId: "runtime-1",
      runtimeBundleHash: hash("runtime"),
      runtimeVersion: "1.0.0"
    },
    inputPopulationHash: hash("input-population"),
    outputPopulationHash: populationHash,
    inputRowCount: 2,
    outputRowCount: 2,
    rejectedRowCount: 0,
    appliedBy: "mapping-worker",
    appliedAt: "2026-08-01T10:04:00.000Z"
  });
  const populationBody = {
    contractVersion: 1 as const,
    tenantId: "tenant-a",
    populationId: "population-2026-07",
    snapshotId: snapshot.snapshotId,
    snapshotHash: snapshot.snapshotHash,
    mappingApplicationId: mappingApplication.mappingApplicationId,
    mappingApplicationHash: mappingApplication.mappingApplicationHash,
    populationHash,
    fieldSetHash,
    rowCount: 2,
    dataQuality: {
      runId: "dq-1",
      rulesetId: "dq-rules-1",
      rulesetHash: hash("dq-rules"),
      resultHash: hash("dq-result"),
      publicationDecision: "publish" as const,
      blockerCodes: []
    },
    reconciliation: {
      reconciliationId: "reconciliation-1",
      definitionHash: hash("reconciliation-definition"),
      resultHash: hash("reconciliation-result"),
      passed: true as const,
      populationHash
    },
    certifiedBy: "certification-checker",
    certifiedAt: "2026-08-01T10:05:00.000Z"
  };
  const population = { ...populationBody, certificationHash: canonicalHash(populationBody) };
  const certificationBody = {
    contractVersion: 1 as const,
    tenantId: "tenant-a",
    certificationManifestId: "certification-manifest-1",
    evidenceFormat: "modern_snapshot_v2" as const,
    snapshotId: snapshot.snapshotId,
    snapshotHash: snapshot.snapshotHash,
    populationId: population.populationId,
    populationCertificationHash: population.certificationHash,
    mappingApplicationId: mappingApplication.mappingApplicationId,
    mappingApplicationHash: mappingApplication.mappingApplicationHash,
    normalizedArtifactId: hash("normalized-artifact-id"),
    normalizedArtifactContentHash: hash("normalized-artifact"),
    dataQualityResultHash: population.dataQuality.resultHash,
    reconciliationResultHash: population.reconciliation.resultHash,
    populationHash,
    rowCount: 2,
    certifiedBy: population.certifiedBy,
    certifiedAt: population.certifiedAt
  };
  const bindingBody = {
    contractVersion: 1 as const,
    bindingId: "dataset-binding-1",
    tenantId: "tenant-a",
    datasetId: "loan-book",
    sourceContract,
    scope: { scopeType: "portfolio" as const, scopeId: "portfolio-east" },
    boundAt: "2026-01-01T00:00:00.000Z"
  };
  return createCertifiedSnapshotPublicationV1({
    contractVersion: 1,
    publicationId: "publication-2026-07",
    tenantId: "tenant-a",
    datasetId: bindingBody.datasetId,
    scope: bindingBody.scope,
    datasetBinding: { ...bindingBody, bindingHash: canonicalHash(bindingBody) },
    sourceContract: {
      definition: {
        definitionVersionId: "source-contract-definition-v1",
        definitionKey: "loans-source",
        kind: "source_contract",
        semanticVersion: "1.0.0",
        versionHash: hash("source-definition-version"),
        documentHash: hash("source-definition-document"),
        approvalEventHash: hash("source-definition-approval")
      },
      ...sourceContract,
      sourceKey: "loans-source"
    },
    snapshot,
    certification: {
      ...certificationBody,
      certificationManifestHash: canonicalHash(certificationBody)
    },
    population,
    mappingSpec,
    mappingApplication,
    normalizedArtifact: {
      artifactId: certificationBody.normalizedArtifactId,
      kind: "normalized_snapshot",
      mediaType: "application/json",
      contentHash: certificationBody.normalizedArtifactContentHash,
      byteLength: 256,
      uri: "artifact://tenant-a/normalized-artifact-1",
      metadataHash: hash("normalized-artifact-metadata"),
      rowCount: 2,
      populationHash,
      fieldSetHash
    },
    publishedBy: "publication-worker",
    publishedAt: PUBLISHED_AT
  });
}

function authorityFor(
  publication: CertifiedSnapshotPublicationV1,
  overrides: {
    readonly datasetBinding?: CertifiedSnapshotPublicationV1["datasetBinding"];
    readonly evidence?: CertifiedSnapshotPublicationEvidenceV1;
  } = {}
): SurveillanceSourcePublicationAuthorityV1 {
  const sourceDocumentBody = {
    contractVersion: 1 as const,
    tenantId: publication.tenantId,
    sourceContractId: publication.sourceContract.sourceContractId,
    sourceKey: publication.sourceContract.sourceKey,
    revision: publication.sourceContract.revision,
    status: "active" as const,
    delivery: {
      mode: "object_storage" as const,
      format: "parquet" as const,
      connectorId: "connector-1",
      credentialRef: "secret/source-1",
      bucket: "loan-data",
      keyPattern: "loan/{date}.parquet",
      immutableVersionRequired: true as const
    },
    schemaPolicy: {
      columns: [{ sourceName: "loan_id", ordinal: 0, nativeType: "string", nullable: false, required: true }],
      allowUnknownColumns: true,
      requireStableOrdinals: true
    },
    parserPolicy: {
      format: "parquet" as const,
      parserId: "parquet-parser",
      parserVersion: "1.0.0",
      optionsHash: hash("parser-options"),
      exactDecimalMode: "string" as const,
      timezone: "UTC" as const,
      rejectSchemaMerging: true
    },
    extractionPolicy: {
      mode: "full" as const,
      readOnly: true as const,
      maximumRows: 1_000_000,
      maximumColumns: 500,
      maximumBytes: 1_000_000_000,
      timeoutMs: 60_000,
      cursorRows: 1_000
    },
    sections: [{ sectionId: "loans", required: true, selector: "loans", keyFields: ["loan_id"] }],
    effectiveFrom: "2026-01-01",
    createdBy: "source-maker",
    createdAt: "2026-01-01T00:00:00.000Z",
    approvedBy: "source-checker",
    approvedAt: "2026-01-01T00:01:00.000Z"
  };
  const sourceContract = {
    ...sourceDocumentBody,
    sourceContractHash: canonicalHash(sourceDocumentBody)
  };
  const snapshotBody = {
    contractVersion: 2 as const,
    tenantId: publication.tenantId,
    snapshotId: publication.snapshot.snapshotId,
    sourceContract: {
      sourceContractId: sourceContract.sourceContractId,
      revision: sourceContract.revision,
      sourceContractHash: sourceContract.sourceContractHash
    },
    delivery: sourceContract.delivery,
    sourceLocator: "object://loan-data/loan/2026-07.parquet",
    immutableSourceVersion: publication.snapshot.delivery.immutableSourceVersion,
    asOfDate: publication.snapshot.asOfDate,
    knowledge: publication.snapshot.knowledge,
    watermark: { mode: "none" as const },
    hashes: publication.snapshot.hashes,
    rowCount: publication.snapshot.rowCount,
    byteCount: publication.snapshot.byteCount,
    sections: [{
      sectionId: "loans",
      required: true,
      present: true,
      rowCount: publication.snapshot.rowCount,
      contentHash: hash("section-content"),
      schemaHash: hash("section-schema")
    }],
    correction: publication.snapshot.correction,
    createdBy: "snapshot-worker"
  };
  const snapshot = { ...snapshotBody, snapshotHash: canonicalHash(snapshotBody) };
  // Rebind the fixture's data projections to the exact authoritative source and snapshot hashes.
  const evidence = overrides.evidence ?? authorityEvidence(publication);
  return {
    resolveDatasetSnapshotV2: () => snapshot,
    resolveDatasetBinding: () => {
      const binding = overrides.datasetBinding ?? publication.datasetBinding;
      const body = {
        contractVersion: binding.contractVersion,
        bindingId: binding.bindingId,
        tenantId: binding.tenantId,
        datasetId: binding.datasetId,
        sourceContract: snapshot.sourceContract,
        scope: binding.scope,
        boundAt: binding.boundAt
      };
      return { ...body, bindingHash: canonicalHash(body) };
    },
    resolveFrozenSourceContract: () => ({
      reference: publication.sourceContract.definition,
      approvalEvidence: {
        status: "approved",
        proposedBy: "source-maker",
        approvedBy: "source-checker",
        approvedAt: "2026-01-01T00:01:00.000Z",
        approvalEventHash: publication.sourceContract.definition.approvalEventHash
      },
      executionDocument: sourceContract
    }),
    resolveCertifiedPublicationEvidence: () => {
      const mappingSpecBody = {
        ...withoutMappingSpecHash(evidence.mappingSpec),
        sourceContract: snapshot.sourceContract
      };
      const mappingSpec = { ...mappingSpecBody, mappingSpecHash: canonicalHash(mappingSpecBody) };
      const mappingApplicationBody = {
        ...withoutApplicationHash(evidence.mappingApplication),
        snapshot: {
          snapshotId: snapshot.snapshotId,
          snapshotHash: snapshot.snapshotHash,
          contentHash: snapshot.hashes.contentHash
        },
        mappingSpec: {
          mappingSpecId: mappingSpec.mappingSpecId,
          revision: mappingSpec.revision,
          mappingSpecHash: mappingSpec.mappingSpecHash
        }
      };
      const mappingApplication = {
        ...mappingApplicationBody,
        mappingApplicationHash: canonicalHash(mappingApplicationBody)
      };
      const populationBody = {
        ...withoutCertificationHash(evidence.population),
        snapshotId: snapshot.snapshotId,
        snapshotHash: snapshot.snapshotHash,
        mappingApplicationId: mappingApplication.mappingApplicationId,
        mappingApplicationHash: mappingApplication.mappingApplicationHash
      };
      const population = { ...populationBody, certificationHash: canonicalHash(populationBody) };
      const certificationBody = {
        ...withoutManifestHash(evidence.certification),
        snapshotId: snapshot.snapshotId,
        snapshotHash: snapshot.snapshotHash,
        populationCertificationHash: population.certificationHash,
        mappingApplicationHash: mappingApplication.mappingApplicationHash
      };
      return {
        ...evidence,
        certification: {
          ...certificationBody,
          certificationManifestHash: canonicalHash(certificationBody)
        },
        population,
        mappingSpec,
        mappingApplication
      };
    }
  };
}

function authorityEvidence(publication: CertifiedSnapshotPublicationV1): CertifiedSnapshotPublicationEvidenceV1 {
  const mappingSpecBody = {
    contractVersion: 2 as const,
    tenantId: publication.tenantId,
    mappingSpecId: publication.mappingSpec.mappingSpecId,
    mappingKey: publication.mappingSpec.mappingKey,
    revision: publication.mappingSpec.revision,
    status: "active" as const,
    sourceContract: publication.mappingSpec.sourceContract,
    dictionaryBundle: publication.mappingSpec.dictionaryBundle,
    rules: [{
      ruleId: "loan-id",
      canonicalField: "loan_id",
      expression: { op: "source" as const, column: "loan_id" },
      onError: "fail_application" as const
    }],
    requiredCanonicalFields: ["loan_id"],
    createdBy: "mapping-maker",
    createdAt: "2026-01-01T00:00:00.000Z",
    approvedBy: "mapping-checker",
    approvedAt: "2026-01-01T00:01:00.000Z"
  };
  return {
    certification: publication.certification,
    population: publication.population,
    mappingSpec: { ...mappingSpecBody, mappingSpecHash: canonicalHash(mappingSpecBody) },
    mappingApplication: publication.mappingApplication,
    normalizedArtifact: {
      artifactId: publication.normalizedArtifact.artifactId.slice("sha256:".length),
      tenantBinding: hash("tenant-binding").slice("sha256:".length),
      kind: "normalized_snapshot",
      mediaType: "application/json",
      contentHash: publication.normalizedArtifact.contentHash.slice("sha256:".length),
      byteLength: publication.normalizedArtifact.byteLength,
      keyId: "key-1",
      uri: publication.normalizedArtifact.uri,
    }
  };
}

function withoutApplicationHash<T extends { readonly mappingApplicationHash: unknown }>(value: T) {
  const { mappingApplicationHash: _mappingApplicationHash, ...body } = value;
  return body;
}

function withoutCertificationHash<T extends { readonly certificationHash: unknown }>(value: T) {
  const { certificationHash: _certificationHash, ...body } = value;
  return body;
}

function withoutManifestHash<T extends { readonly certificationManifestHash: unknown }>(value: T) {
  const { certificationManifestHash: _certificationManifestHash, ...body } = value;
  return body;
}

function withoutMappingSpecHash<T extends { readonly mappingSpecHash: unknown }>(value: T) {
  const { mappingSpecHash: _mappingSpecHash, ...body } = value;
  return body;
}

function rehashPublication(
  value: Omit<CertifiedSnapshotPublicationV1, "publicationHash"> & { readonly publicationHash?: Sha256Hash }
): CertifiedSnapshotPublicationV1 {
  const { publicationHash: _publicationHash, ...body } = value;
  return parseCertifiedSnapshotPublicationV1({ ...body, publicationHash: canonicalHash(body) });
}

function withoutPolicyHash(policy: ReturnType<typeof sourceAccessPolicy>) {
  const { policyHash: _policyHash, ...body } = policy;
  return body;
}

function withoutPublicationHash(publication: CertifiedSnapshotPublicationV1) {
  const { publicationHash: _publicationHash, ...body } = publication;
  return body;
}

function withoutBindingHash<T extends { readonly bindingHash: unknown }>(value: T) {
  const { bindingHash: _bindingHash, ...body } = value;
  return body;
}

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "surveillance-publication-"));
  directories.push(directory);
  return directory;
}

function sequentialClock(values: readonly string[]): () => Date {
  let index = 0;
  return () => new Date(values[Math.min(index++, values.length - 1)]!);
}

function hash(value: string): Sha256Hash {
  return canonicalHash({ value });
}

function contractError(error: unknown, code: ContractValidationError["code"]): boolean {
  return error instanceof ContractValidationError && error.code === code;
}

function catalogError(error: unknown, code: SurveillancePublicationCatalogError["code"]): boolean {
  return error instanceof SurveillancePublicationCatalogError && error.code === code;
}

function sourceError(error: unknown, code: SurveillanceSourcePublicationError["code"]): boolean {
  return error instanceof SurveillanceSourcePublicationError && error.code === code;
}
