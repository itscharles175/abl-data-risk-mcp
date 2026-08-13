import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, test } from "node:test";

import {
  canonicalHash,
  createCertifiedSnapshotPublicationV1,
  createMappingApplicationV1,
  createSourceAccessPolicyV1,
  type CertifiedSnapshotPublicationV1,
  type Sha256Hash
} from "../src/contracts/index.js";
import {
  GovernedDefinitionV2Store,
  GOVERNED_DEFINITION_V2_STORE_SCHEMA_VERSION
} from "../src/control/governed-definitions-v2.js";
import {
  SurveillancePublicationCatalog,
  SurveillancePublicationCatalogError,
  SURVEILLANCE_PUBLICATION_CATALOG_COMPONENT,
  SURVEILLANCE_PUBLICATION_CATALOG_SCHEMA_VERSION
} from "../src/control/surveillance-publications.js";
import { GovernedDefinitionV2Resolver } from "../src/services/governed-definition-v2-resolver.js";
import {
  GovernedDefinitionSourceAccessPolicyCandidateIndexV1,
  GovernedDefinitionV2PreflightResolutionAdapterV1,
  SurveillancePublicationCatalogReadAdapterV1
} from "../src/services/surveillance-preflight-persistence.js";

const directories: string[] = [];
const PUBLISHED_AT = "2026-08-12T13:00:00.000Z";

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("publication adapter uses an exact complete scope index and fails closed at its bound", () => {
  const catalog = new SurveillancePublicationCatalog(":memory:", {
    clock: () => new Date("2026-08-12T15:00:00.000Z")
  });
  const original = publicationFixture();
  const correctionOne = publicationVariant(original, "correction-1", {
    correction: correction(original, 1),
    publishedAt: "2026-08-12T13:01:00.000Z"
  });
  const correctionTwo = publicationVariant(correctionOne, "correction-2", {
    correction: correction(correctionOne, 2),
    publishedAt: "2026-08-12T13:02:00.000Z"
  });
  const postCutoff = publicationVariant(correctionTwo, "correction-3", {
    correction: correction(correctionTwo, 3),
    publishedAt: "2026-08-12T14:00:00.000Z"
  });
  for (const publication of [original, correctionOne, correctionTwo, postCutoff]) {
    record(catalog, publication);
  }
  const adapter = new SurveillancePublicationCatalogReadAdapterV1(catalog);
  assert.equal(
    adapter.get("tenant-a", original.publicationId)?.publicationHash,
    original.publicationHash
  );
  assert.equal(adapter.get("tenant-b", original.publicationId), undefined);
  assert.equal(
    adapter.getByCertificationManifest(
      "tenant-a",
      correctionTwo.certification.certificationManifestId
    )?.publicationId,
    correctionTwo.publicationId
  );
  assert.equal(
    adapter.getByCertificationManifest(
      "tenant-b",
      correctionTwo.certification.certificationManifestId
    ),
    undefined
  );

  const exact = adapter.listByScopeAsOf(lineageQuery(original, { maximumResults: 10 }));
  assert.equal(exact.complete, true);
  assert.deepEqual(
    exact.publications.map(({ publicationId }) => publicationId),
    [original.publicationId, correctionOne.publicationId, correctionTwo.publicationId]
  );
  assert.equal(exact.publications.includes(postCutoff), false);

  const bounded = adapter.listByScopeAsOf(lineageQuery(original, { maximumResults: 2 }));
  assert.equal(bounded.complete, false);
  assert.equal(bounded.publications.length, 2);

  for (const query of [
    lineageQuery(original, { tenantId: "tenant-b" }),
    lineageQuery(original, { datasetId: "another-dataset" }),
    lineageQuery(original, {
      sourceContract: { ...publishedSource(original), sourceContractId: "another-source" }
    }),
    lineageQuery(original, {
      sourceContract: { ...publishedSource(original), revision: 2 }
    }),
    lineageQuery(original, {
      sourceContract: { ...publishedSource(original), sourceContractHash: hash("another-source") }
    }),
    lineageQuery(original, {
      scope: { scopeType: "facility" as const, scopeId: original.scope.scopeId }
    }),
    lineageQuery(original, { asOfDate: "2026-06-30" }),
    lineageQuery(original, { publishedThrough: "2026-08-12T12:59:59.999Z" })
  ]) {
    const page = adapter.listByScopeAsOf(query);
    assert.equal(page.complete, true);
    assert.deepEqual(page.publications, []);
  }

  const disabled = catalog.disable({
    tenantId: "tenant-a",
    publicationId: correctionTwo.publicationId,
    expectedPublicationHash: correctionTwo.publicationHash,
    reasonCode: "source_restatement",
    reason: "A later correction superseded this snapshot.",
    disabledBy: "risk-checker",
    idempotencyKey: "disable-correction-two"
  });
  assert.deepEqual(adapter.getDisable("tenant-a", correctionTwo.publicationId), disabled);
  assert.equal(adapter.getDisable("tenant-b", correctionTwo.publicationId), undefined);
  catalog.close();
});

test("publication catalog v1 to v2 migration preserves rows, receipts, audit high-water, and backfills", () => {
  const directory = temporaryDirectory();
  const databasePath = join(directory, "publication-migration.sqlite");
  const publication = publicationFixture();
  const input = recordInput(publication);
  const initial = new SurveillancePublicationCatalog(databasePath, {
    clock: () => new Date("2026-08-12T15:00:00.000Z")
  });
  initial.record(input);
  const beforeAudit = initial.listAuditEvents("tenant-a");
  initial.close();

  downgradePublicationCatalogToV1(databasePath);
  const highWater = new DatabaseSync(databasePath);
  highWater
    .prepare(
      "UPDATE sqlite_sequence SET seq = 40 WHERE name = 'surveillance_publication_audit_events'"
    )
    .run();
  highWater.close();

  const migrated = new SurveillancePublicationCatalog(databasePath, {
    clock: () => new Date("2026-08-12T15:00:00.000Z")
  });
  assert.equal(migrated.record(input).publicationHash, publication.publicationHash);
  assert.deepEqual(migrated.listAuditEvents("tenant-a"), beforeAudit);
  assert.equal(
    migrated.listByScopeAsOf(lineageQuery(publication)).publications[0]?.publicationHash,
    publication.publicationHash
  );
  migrated.disable({
    tenantId: publication.tenantId,
    publicationId: publication.publicationId,
    expectedPublicationHash: publication.publicationHash,
    reasonCode: "source_restatement",
    reason: "Migration high-water verification.",
    disabledBy: "risk-checker",
    idempotencyKey: "migration-disable"
  });
  assert.equal(migrated.listAuditEvents("tenant-a").at(-1)?.sequence, 41);
  migrated.close();

  const database = new DatabaseSync(databasePath);
  assert.equal(
    (
      database
        .prepare(
          "SELECT schema_version FROM component_schema_versions WHERE component_name = ?"
        )
        .get(SURVEILLANCE_PUBLICATION_CATALOG_COMPONENT) as { schema_version: number }
    ).schema_version,
    SURVEILLANCE_PUBLICATION_CATALOG_SCHEMA_VERSION
  );
  assert.equal(
    (
      database
        .prepare("SELECT COUNT(*) AS count FROM surveillance_publication_scope_index")
        .get() as { count: number }
    ).count,
    1
  );
  assert.equal(
    (
      database
        .prepare(
          "SELECT seq FROM sqlite_sequence WHERE name = 'surveillance_publication_audit_events'"
        )
        .get() as { seq: number }
    ).seq,
    41
  );
  assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), []);
  database.close();
});

test("publication scope-index migration rolls back atomically on corrupt legacy JSON", () => {
  const directory = temporaryDirectory();
  const databasePath = join(directory, "publication-corruption.sqlite");
  const initial = new SurveillancePublicationCatalog(databasePath);
  record(initial, publicationFixture());
  initial.close();
  downgradePublicationCatalogToV1(databasePath);

  const corrupt = new DatabaseSync(databasePath);
  corrupt.exec(`
    DROP TRIGGER surveillance_publications_no_update;
    UPDATE surveillance_publications
       SET publication_json = json_set(publication_json, '$.scope.scopeType', 'cross_tenant');
    CREATE TRIGGER surveillance_publications_no_update BEFORE UPDATE ON surveillance_publications
    BEGIN SELECT RAISE(ABORT, 'surveillance publications are immutable'); END;
  `);
  const beforeRows = corrupt
    .prepare("SELECT tenant_id, publication_id, publication_hash FROM surveillance_publications")
    .all();
  corrupt.close();

  assert.throws(() => new SurveillancePublicationCatalog(databasePath));
  const after = new DatabaseSync(databasePath);
  assert.equal(
    (
      after
        .prepare(
          "SELECT schema_version FROM component_schema_versions WHERE component_name = ?"
        )
        .get(SURVEILLANCE_PUBLICATION_CATALOG_COMPONENT) as { schema_version: number }
    ).schema_version,
    1
  );
  assert.equal(
    after
      .prepare(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'surveillance_publication_scope_index'"
      )
      .get(),
    undefined
  );
  assert.deepEqual(
    after
      .prepare("SELECT tenant_id, publication_id, publication_hash FROM surveillance_publications")
      .all(),
    beforeRows
  );
  assert.equal(
    (
      after
        .prepare("SELECT COUNT(*) AS count FROM surveillance_publication_audit_events")
        .get() as { count: number }
    ).count,
    1
  );
  after.close();
});

test("source-policy candidate adapter is exact, distinct across versions, and incomplete over bound", () => {
  const store = new GovernedDefinitionV2Store(":memory:", {
    clock: () => new Date("2026-08-12T12:00:00.000Z")
  });
  const exactV1 = proposePolicy(store, policyFixture({ policyId: "policy-exact" }), "exact-v1");
  proposePolicy(
    store,
    policyFixture({
      policyId: "policy-exact",
      revision: 2,
      effectiveFrom: "2026-06-01"
    }),
    "exact-v2",
    exactV1.version.definitionVersionId
  );
  proposePolicy(store, policyFixture({ policyId: "policy-second" }), "second-v1");
  proposePolicy(
    store,
    policyFixture({ policyId: "wrong-dataset", datasetId: "other-dataset" }),
    "wrong-dataset-v1"
  );
  proposePolicy(
    store,
    policyFixture({
      policyId: "wrong-source",
      sourceContract: {
        sourceContractId: "other-source",
        revision: 1,
        sourceContractHash: hash("source-contract")
      }
    }),
    "wrong-source-v1"
  );
  proposePolicy(
    store,
    policyFixture({
      policyId: "wrong-source-hash",
      sourceContract: {
        sourceContractId: "source-contract-1",
        revision: 1,
        sourceContractHash: hash("other-source-contract")
      }
    }),
    "wrong-source-hash-v1"
  );
  proposePolicy(
    store,
    policyFixture({
      policyId: "wrong-scope",
      scope: { scopeType: "facility", scopeId: "portfolio-east" }
    }),
    "wrong-scope-v1"
  );
  proposePolicy(
    store,
    policyFixture({ policyId: "wrong-purpose", purpose: "borrowing_base" }),
    "wrong-purpose-v1"
  );
  proposePolicy(
    store,
    policyFixture({ policyId: "wrong-tenant", tenantId: "tenant-b" }),
    "wrong-tenant-v1"
  );

  const selector = policySelector();
  const complete = new GovernedDefinitionSourceAccessPolicyCandidateIndexV1(
    store,
    100
  ).listCandidateDefinitionKeys(selector);
  assert.equal(complete.complete, true);
  assert.deepEqual(complete.definitionKeys, ["policy-exact", "policy-second"]);
  assert.equal(new Set(complete.definitionKeys).size, complete.definitionKeys.length);

  const bounded = new GovernedDefinitionSourceAccessPolicyCandidateIndexV1(
    store,
    1
  ).listCandidateDefinitionKeys(selector);
  assert.equal(bounded.complete, false);
  assert.deepEqual(bounded.definitionKeys, ["policy-exact"]);
  assert.deepEqual(
    new GovernedDefinitionSourceAccessPolicyCandidateIndexV1(store, 100)
      .listCandidateDefinitionKeys({ ...selector, tenantId: "tenant-b" }).definitionKeys,
    ["wrong-tenant"]
  );
  assert.deepEqual(
    new GovernedDefinitionSourceAccessPolicyCandidateIndexV1(store, 100)
      .listCandidateDefinitionKeys({
        ...selector,
        scope: { scopeType: "facility", scopeId: "portfolio-east" }
      }).definitionKeys,
    ["wrong-scope"]
  );

  let active = exactV1;
  for (const toStatus of ["validated", "approved", "active"] as const) {
    active = store.transition({
      tenantId: "tenant-a",
      definitionVersionId: exactV1.version.definitionVersionId,
      toStatus,
      expectedRevision: active.lifecycleRevision,
      actor: "policy-checker",
      idempotencyKey: `exact-${toStatus}`
    });
  }
  const resolution = new GovernedDefinitionV2PreflightResolutionAdapterV1(
    new GovernedDefinitionV2Resolver(store)
  );
  assert.equal(
    resolution.resolveFrozenDefinition("tenant-a", exactV1.version.definitionVersionId)
      ?.reference.definitionKey,
    "policy-exact"
  );
  assert.equal(
    resolution.resolveEffective({
      tenantId: "tenant-a",
      kind: "source_access_policy",
      definitionKey: "policy-exact",
      asOfDate: "2026-03-01"
    })?.reference.definitionVersionId,
    exactV1.version.definitionVersionId
  );
  assert.equal(resolution.resolveFrozenDefinition("tenant-a", "missing-policy"), undefined);
  assert.equal(
    resolution.resolveEffective({
      tenantId: "tenant-a",
      kind: "source_access_policy",
      definitionKey: "missing-policy",
      asOfDate: "2026-03-01"
    }),
    undefined
  );
  assert.equal(GOVERNED_DEFINITION_V2_STORE_SCHEMA_VERSION >= 4, true);
  store.close();
});

test("publication startup rejects a scope-index row moved away from its legitimate selector", () => {
  const directory = temporaryDirectory();
  const databasePath = join(directory, "publication-index-corruption.sqlite");
  const initial = new SurveillancePublicationCatalog(databasePath);
  record(initial, publicationFixture());
  initial.close();

  const attacker = new DatabaseSync(databasePath);
  attacker.exec(`
    DROP TRIGGER surveillance_publication_scope_index_no_update;
    UPDATE surveillance_publication_scope_index SET dataset_id = 'forged-dataset';
    CREATE TRIGGER surveillance_publication_scope_index_no_update
    BEFORE UPDATE ON surveillance_publication_scope_index
    BEGIN SELECT RAISE(ABORT, 'surveillance publication scope index is immutable'); END;
  `);
  attacker.close();

  assert.throws(
    () => new SurveillancePublicationCatalog(databasePath),
    (error: unknown) =>
      error instanceof SurveillancePublicationCatalogError && error.code === "INTEGRITY_FAILURE"
  );
});

test("publication lineage reads reject an index row deleted after startup", () => {
  const directory = temporaryDirectory();
  const databasePath = join(directory, "publication-index-deletion.sqlite");
  const publication = publicationFixture();
  const catalog = new SurveillancePublicationCatalog(databasePath);
  record(catalog, publication);

  const attacker = new DatabaseSync(databasePath);
  attacker.exec(`
    DROP TRIGGER surveillance_publication_scope_index_no_delete;
    DELETE FROM surveillance_publication_scope_index;
    CREATE TRIGGER surveillance_publication_scope_index_no_delete
    BEFORE DELETE ON surveillance_publication_scope_index
    BEGIN SELECT RAISE(ABORT, 'surveillance publication scope index is immutable'); END;
  `);
  attacker.close();

  assert.throws(
    () => catalog.listByScopeAsOf(lineageQuery(publication)),
    (error: unknown) =>
      error instanceof SurveillancePublicationCatalogError && error.code === "INTEGRITY_FAILURE"
  );
  catalog.close();
});

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
    snapshotId: "snapshot-original",
    snapshotHash: hash("snapshot-original"),
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
  const populationHash = hash("population-original");
  const fieldSetHash = hash("field-set");
  const mappingApplication = createMappingApplicationV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    mappingApplicationId: "mapping-application-original",
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
    populationId: "population-original",
    snapshotId: snapshot.snapshotId,
    snapshotHash: snapshot.snapshotHash,
    mappingApplicationId: mappingApplication.mappingApplicationId,
    mappingApplicationHash: mappingApplication.mappingApplicationHash,
    populationHash,
    fieldSetHash,
    rowCount: 2,
    dataQuality: {
      runId: "dq-original",
      rulesetId: "dq-rules-1",
      rulesetHash: hash("dq-rules"),
      resultHash: hash("dq-result-original"),
      publicationDecision: "publish" as const,
      blockerCodes: []
    },
    reconciliation: {
      reconciliationId: "reconciliation-original",
      definitionHash: hash("reconciliation-definition"),
      resultHash: hash("reconciliation-result-original"),
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
    certificationManifestId: "certification-original",
    evidenceFormat: "modern_snapshot_v2" as const,
    snapshotId: snapshot.snapshotId,
    snapshotHash: snapshot.snapshotHash,
    populationId: population.populationId,
    populationCertificationHash: population.certificationHash,
    mappingApplicationId: mappingApplication.mappingApplicationId,
    mappingApplicationHash: mappingApplication.mappingApplicationHash,
    normalizedArtifactId: "normalized-original",
    normalizedArtifactContentHash: hash("normalized-content-original"),
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
    publicationId: "publication-original",
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
      artifactContractVersion: 2,
      artifactHash: hash("normalized-artifact-contract-original"),
      kind: "normalized_snapshot",
      mediaType: "application/json",
      contentHash: certificationBody.normalizedArtifactContentHash,
      byteLength: 256,
      uri: "abl-artifact://normalized-original",
      metadataHash: hash("normalized-metadata-original"),
      rowCount: 2,
      populationHash,
      fieldSetHash
    },
    publishedBy: "publication-worker",
    publishedAt: PUBLISHED_AT
  });
}

function publicationVariant(
  base: CertifiedSnapshotPublicationV1,
  suffix: string,
  options: Readonly<{
    correction: CertifiedSnapshotPublicationV1["snapshot"]["correction"];
    publishedAt: string;
  }>
): CertifiedSnapshotPublicationV1 {
  const snapshot = {
    ...base.snapshot,
    snapshotId: `snapshot-${suffix}`,
    snapshotHash: hash(`snapshot-${suffix}`),
    correction: options.correction
  };
  const {
    mappingApplicationHash: _mappingApplicationHash,
    ...priorMappingApplication
  } = base.mappingApplication;
  const populationHash = hash(`population-${suffix}`);
  const mappingApplication = createMappingApplicationV1({
    ...priorMappingApplication,
    mappingApplicationId: `mapping-${suffix}`,
    snapshot: {
      snapshotId: snapshot.snapshotId,
      snapshotHash: snapshot.snapshotHash,
      contentHash: snapshot.hashes.contentHash
    },
    outputPopulationHash: populationHash
  });
  const { certificationHash: _certificationHash, ...priorPopulation } = base.population;
  const populationBody = {
    ...priorPopulation,
    populationId: `population-${suffix}`,
    snapshotId: snapshot.snapshotId,
    snapshotHash: snapshot.snapshotHash,
    mappingApplicationId: mappingApplication.mappingApplicationId,
    mappingApplicationHash: mappingApplication.mappingApplicationHash,
    populationHash,
    dataQuality: {
      ...priorPopulation.dataQuality,
      runId: `dq-${suffix}`,
      resultHash: hash(`dq-result-${suffix}`)
    },
    reconciliation: {
      ...priorPopulation.reconciliation,
      reconciliationId: `reconciliation-${suffix}`,
      resultHash: hash(`reconciliation-result-${suffix}`),
      populationHash
    }
  };
  const population = { ...populationBody, certificationHash: canonicalHash(populationBody) };
  const {
    certificationManifestHash: _certificationManifestHash,
    ...priorCertification
  } = base.certification;
  const certificationBody = {
    ...priorCertification,
    certificationManifestId: `certification-${suffix}`,
    snapshotId: snapshot.snapshotId,
    snapshotHash: snapshot.snapshotHash,
    populationId: population.populationId,
    populationCertificationHash: population.certificationHash,
    mappingApplicationId: mappingApplication.mappingApplicationId,
    mappingApplicationHash: mappingApplication.mappingApplicationHash,
    normalizedArtifactId: `normalized-${suffix}`,
    normalizedArtifactContentHash: hash(`normalized-content-${suffix}`),
    dataQualityResultHash: population.dataQuality.resultHash,
    reconciliationResultHash: population.reconciliation.resultHash,
    populationHash
  };
  return createCertifiedSnapshotPublicationV1({
    ...withoutPublicationHash(base),
    publicationId: `publication-${suffix}`,
    snapshot,
    certification: {
      ...certificationBody,
      certificationManifestHash: canonicalHash(certificationBody)
    },
    population,
    mappingApplication,
    normalizedArtifact: {
      ...base.normalizedArtifact,
      artifactId: certificationBody.normalizedArtifactId,
      artifactHash: hash(`normalized-artifact-contract-${suffix}`),
      contentHash: certificationBody.normalizedArtifactContentHash,
      uri: `abl-artifact://${certificationBody.normalizedArtifactId}`,
      metadataHash: hash(`normalized-metadata-${suffix}`),
      populationHash
    },
    publishedAt: options.publishedAt
  });
}

function correction(
  parent: CertifiedSnapshotPublicationV1,
  correctionSequence: number
): CertifiedSnapshotPublicationV1["snapshot"]["correction"] {
  return {
    kind: "correction",
    correctsSnapshotId: parent.snapshot.snapshotId,
    correctsSnapshotHash: parent.snapshot.snapshotHash,
    correctionSequence,
    reasonCode: "source_restatement",
    reason: `Correction ${correctionSequence}`,
    detectedAt: "2026-08-01T10:03:30.000Z"
  };
}

function lineageQuery(
  publication: CertifiedSnapshotPublicationV1,
  overrides: Readonly<Record<string, unknown>> = {}
) {
  return {
    tenantId: publication.tenantId,
    datasetId: publication.datasetId,
    sourceContract: publishedSource(publication),
    scope: publication.scope,
    asOfDate: publication.snapshot.asOfDate,
    publishedThrough: "2026-08-12T13:59:59.999Z",
    maximumResults: 100,
    ...overrides
  } as Parameters<SurveillancePublicationCatalogReadAdapterV1["listByScopeAsOf"]>[0];
}

function publishedSource(publication: CertifiedSnapshotPublicationV1) {
  return {
    sourceContractId: publication.sourceContract.sourceContractId,
    sourceKey: publication.sourceContract.sourceKey,
    revision: publication.sourceContract.revision,
    sourceContractHash: publication.sourceContract.sourceContractHash
  };
}

function record(catalog: SurveillancePublicationCatalog, publication: CertifiedSnapshotPublicationV1) {
  return catalog.record(recordInput(publication));
}

function recordInput(publication: CertifiedSnapshotPublicationV1) {
  return {
    publication,
    requestHash: canonicalHash({
      tenantId: publication.tenantId,
      publicationId: publication.publicationId,
      certificationManifestId: publication.certification.certificationManifestId
    }),
    actor: publication.publishedBy,
    idempotencyKey: `record-${publication.publicationId}`
  } as const;
}

function policyFixture(
  overrides: Readonly<{
    policyId?: string;
    tenantId?: string;
    revision?: number;
    datasetId?: string;
    sourceContract?: Readonly<{
      sourceContractId: string;
      revision: number;
      sourceContractHash: Sha256Hash;
    }>;
    scope?: Readonly<{ scopeType: "portfolio" | "facility"; scopeId: string }>;
    purpose?: string;
    effectiveFrom?: string;
  }> = {}
) {
  return createSourceAccessPolicyV1({
    contractVersion: 1,
    tenantId: overrides.tenantId ?? "tenant-a",
    policyId: overrides.policyId ?? "policy-exact",
    revision: overrides.revision ?? 1,
    datasetId: overrides.datasetId ?? "loan-book",
    sourceContract: overrides.sourceContract ?? {
      sourceContractId: "source-contract-1",
      revision: 1,
      sourceContractHash: hash("source-contract")
    },
    scope: overrides.scope ?? { scopeType: "portfolio", scopeId: "portfolio-east" },
    purpose: overrides.purpose ?? "portfolio_surveillance",
    allowedFields: ["as_of_date", "current_balance", "loan_id"],
    allowedAggregateDimensionFields: ["as_of_date"],
    effectiveFrom: overrides.effectiveFrom ?? "2026-01-01"
  });
}

function proposePolicy(
  store: GovernedDefinitionV2Store,
  policy: ReturnType<typeof policyFixture>,
  definitionVersionId: string,
  predecessorDefinitionVersionId?: string
) {
  return store.propose({
    tenantId: policy.tenantId,
    definitionVersionId,
    definitionKey: policy.policyId,
    kind: "source_access_policy",
    semanticVersion: `${policy.revision}.0.0`,
    effectiveFrom: policy.effectiveFrom,
    ...(policy.effectiveTo === undefined ? {} : { effectiveTo: policy.effectiveTo }),
    ...(predecessorDefinitionVersionId === undefined ? {} : { predecessorDefinitionVersionId }),
    document: policy,
    proposedBy: "policy-maker",
    idempotencyKey: `propose-${definitionVersionId}`
  });
}

function policySelector() {
  return {
    tenantId: "tenant-a",
    datasetId: "loan-book",
    sourceContract: {
      sourceContractId: "source-contract-1",
      sourceKey: "loans-source",
      revision: 1,
      sourceContractHash: hash("source-contract")
    },
    scope: { scopeType: "portfolio" as const, scopeId: "portfolio-east" },
    purpose: "portfolio_surveillance"
  };
}

function downgradePublicationCatalogToV1(databasePath: string): void {
  const database = new DatabaseSync(databasePath);
  database.exec(`
    PRAGMA foreign_keys = ON;
    BEGIN IMMEDIATE;
    DROP TRIGGER surveillance_publications_scope_index_insert;
    DROP TRIGGER surveillance_publication_scope_index_no_update;
    DROP TRIGGER surveillance_publication_scope_index_no_delete;
    DROP INDEX surveillance_publication_scope_lookup;
    DROP TABLE surveillance_publication_scope_index;
    UPDATE component_schema_versions
       SET schema_version = 1
     WHERE component_name = '${SURVEILLANCE_PUBLICATION_CATALOG_COMPONENT}';
    COMMIT;
  `);
  database.close();
}

function withoutPublicationHash(publication: CertifiedSnapshotPublicationV1) {
  const { publicationHash: _publicationHash, ...body } = publication;
  return body;
}

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "surveillance-preflight-persistence-"));
  directories.push(directory);
  return directory;
}

function hash(value: string): Sha256Hash {
  return canonicalHash({ value });
}
