import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  canonicalHash,
  canonicalJson,
  createCertifiedSnapshotPublicationV1,
  createGovernedDatasetScopeBindingV1,
  createMappingApplicationV1,
  createNormalizedSnapshotArtifactV2,
  createSourceAccessPolicyV1,
  type CanonicalJsonValue,
  type CertifiedSnapshotPublicationV1,
  type NormalizedSnapshotArtifactV2,
  type Sha256Hash
} from "../src/contracts/index.js";
import {
  ArtifactStore,
  artifactJsonContentHash,
  type StoredArtifact
} from "../src/control/artifacts.js";
import type { SurveillancePublicationDisableEventV1 } from "../src/control/surveillance-publications.js";
import type { MetricDefinitionV1 } from "../src/domain/surveillance/contracts.js";
import { createVerifiedPrincipalContext } from "../src/security/identity.js";
import {
  compileAuthorizationPolicy,
  evaluatePolicy,
  type PolicyEvaluationRequest
} from "../src/security/policy.js";
import type { ResolvedGovernedDefinitionV2 } from "../src/services/governed-definition-v2-resolver.js";
import {
  GovernedSourceAccessPolicyDirectoryV1,
  PortfolioSurveillanceAuthorizationPreflightServiceV1,
  type CompletePublicationLineagePageV1,
  type EffectiveGovernedDefinitionResolutionPortV1,
  type SurveillancePublicationLineageQueryV1,
  type SurveillancePublicationReadPortV1
} from "../src/services/surveillance-access-preflight.js";
import {
  PortfolioSurveillanceMaterializationError,
  PortfolioSurveillancePlanMaterializerV1,
  type PortfolioSurveillanceMaterializerDependenciesV1
} from "../src/services/surveillance-materializer.js";

const TENANT = "tenant-a";
const PURPOSE = "portfolio_surveillance";
const CUTOFF = "2026-08-12T12:00:00.000Z";
const REQUESTED_FIELDS = [
  "as_of_date",
  "commitment_amount",
  "facility_id",
  "loan_id",
  "original_balance",
  "outstanding_balance",
  "source_system"
] as const;
const SOURCE_CONTRACT = {
  sourceContractId: "source-contract-1",
  revision: 1,
  sourceContractHash: hash("source-contract")
} as const;
const SCOPE = { scopeType: "portfolio" as const, scopeId: "portfolio-east" };

test("post-policy materialization rechecks first, projects immediately, and persists exact plan bytes", async () => {
  const environment = await fixtureEnvironment();
  environment.events.length = 0;

  const result = await environment.materializer.materialize(
    environment.authorized,
    environment.request
  );

  const firstArtifactRead = environment.events.findIndex((event) => event.startsWith("artifact:"));
  assert.equal(firstArtifactRead, 4);
  assert.deepEqual(environment.events.slice(0, firstArtifactRead), [
    "publication:publication-jan",
    "disable:publication-jan",
    "publication:publication-feb",
    "disable:publication-feb"
  ]);
  assert.ok(result.planArtifact);
  assert.equal(result.planArtifact.kind, "governed_portfolio_surveillance_plan_v4");
  assert.equal(result.planArtifact.mediaType, "application/json");
  assert.equal(result.planArtifact.contentHash, artifactJsonContentHash(result.plan));
  assert.equal(
    result.planArtifact.byteLength,
    Buffer.byteLength(canonicalJson(result.plan), "utf8")
  );
  const storedPlan = environment.store.getJson(TENANT, result.planArtifact.artifactId);
  assert.deepEqual(storedPlan.value, result.plan);
  assert.equal(storedPlan.metadata.contentHash, result.planArtifact.contentHash);
  assert.equal(canonicalJson(result.plan).includes("secret_note"), false);
  assert.ok(
    result.plan.engineInput.snapshots.every((snapshot) =>
      snapshot.records.every((record) => !Object.hasOwn(record, "secret_note"))
    )
  );
  assert.deepEqual(
    result.plan.sourceLineage.map(({ populationHash }) => populationHash),
    environment.sources.map(({ artifact }) => artifact.populationHash)
  );
  assert.equal(
    result.plan.governanceBindings?.sourceAccessPolicySetHash,
    environment.authorized.metadata.sourceAccessPolicySetHash
  );
  assert.equal(
    result.plan.governanceBindings?.datasetScopeBindingSetHash,
    environment.authorized.metadata.datasetScopeBindingSetHash
  );
});

test("runtime permit substitution and post-preflight disable fail before any artifact read", async () => {
  const permitEnvironment = await fixtureEnvironment();
  permitEnvironment.events.length = 0;
  await assert.rejects(
    () => permitEnvironment.materializer.materialize(
      {
        metadata: permitEnvironment.authorized.metadata,
        permit: structuredClone(permitEnvironment.authorized.permit)
      },
      permitEnvironment.request
    ),
    materializationCode("AUTHORIZATION_INVALID")
  );
  assert.equal(permitEnvironment.events.some((event) => event.startsWith("artifact:")), false);

  const disableEnvironment = await fixtureEnvironment();
  disableEnvironment.disabled.add("publication-jan");
  disableEnvironment.events.length = 0;
  await assert.rejects(
    () => disableEnvironment.materializer.materialize(
      disableEnvironment.authorized,
      disableEnvironment.request
    ),
    materializationCode("PUBLICATION_DISABLED")
  );
  assert.equal(disableEnvironment.events.some((event) => event.startsWith("artifact:")), false);
});

test("exact request mismatch and publication-B-for-plan-A substitution fail closed", async () => {
  const requestEnvironment = await fixtureEnvironment();
  requestEnvironment.events.length = 0;
  await assert.rejects(
    () => requestEnvironment.materializer.materialize(
      requestEnvironment.authorized,
      {
        ...requestEnvironment.request,
        sources: [
          { kind: "certification_manifest", certificationManifestId: "cert-feb" },
          { kind: "certification_manifest", certificationManifestId: "cert-other" }
        ]
      }
    ),
    materializationCode("REQUEST_MISMATCH")
  );
  assert.equal(requestEnvironment.events.some((event) => event.startsWith("artifact:")), false);

  const substitutionEnvironment = await fixtureEnvironment();
  const second = substitutionEnvironment.sources[1]!;
  const dependencies = tamperedDependencies(substitutionEnvironment, (_loaded, artifactId) =>
    artifactId === bare(substitutionEnvironment.sources[0]!.publication.normalizedArtifact.artifactId)
      ? cloneLoaded(second.loaded)
      : undefined
  );
  const materializer = new PortfolioSurveillancePlanMaterializerV1(dependencies);
  await assert.rejects(
    () => materializer.materialize(
      substitutionEnvironment.authorized,
      substitutionEnvironment.request
    ),
    materializationCode("ARTIFACT_INTEGRITY_FAILURE")
  );
});

test("tenant, metadata, payload, row, population, and value tampering are rejected", async () => {
  const cases: ReadonlyArray<Readonly<{
    name: string;
    mutate: (loaded: MutableLoaded) => void;
  }>> = [
    {
      name: "tenant",
      mutate: ({ value }) => { value.tenantId = "tenant-b"; }
    },
    {
      name: "artifact id",
      mutate: ({ metadata }) => { metadata.artifactId = bare(hash("another-artifact")); }
    },
    {
      name: "kind",
      mutate: ({ metadata }) => { metadata.kind = "another_kind"; }
    },
    {
      name: "media type",
      mutate: ({ metadata }) => { metadata.mediaType = "text/plain"; }
    },
    {
      name: "content hash",
      mutate: ({ metadata }) => { metadata.contentHash = bare(hash("another-content")); }
    },
    {
      name: "artifact hash",
      mutate: ({ value }) => { value.artifactHash = hash("another-contract"); }
    },
    {
      name: "record value",
      mutate: ({ value }) => {
        const records = value.records as Array<Record<string, CanonicalJsonValue>>;
        records[0]!.outstanding_balance = "999999";
      }
    },
    {
      name: "row count",
      mutate: ({ value }) => { value.rowCount = 2; }
    },
    {
      name: "population hash",
      mutate: ({ value }) => { value.populationHash = hash("another-population"); }
    }
  ];

  for (const candidate of cases) {
    const environment = await fixtureEnvironment();
    const firstId = bare(environment.sources[0]!.publication.normalizedArtifact.artifactId);
    const dependencies = tamperedDependencies(environment, (loaded, artifactId) => {
      if (artifactId !== firstId) return undefined;
      candidate.mutate(loaded);
      return loaded;
    });
    const materializer = new PortfolioSurveillancePlanMaterializerV1(dependencies);
    await assert.rejects(
      () => materializer.materialize(environment.authorized, environment.request),
      (error: unknown) =>
        materializationCode("ARTIFACT_INTEGRITY_FAILURE")(error) ||
        (error instanceof PortfolioSurveillanceMaterializationError &&
          error.code === "PLAN_INTEGRITY_FAILURE"),
      candidate.name
    );
  }
});

interface FixtureSource {
  readonly artifact: NormalizedSnapshotArtifactV2;
  readonly stored: StoredArtifact;
  readonly loaded: Readonly<{ metadata: StoredArtifact; value: unknown }>;
  readonly publication: CertifiedSnapshotPublicationV1;
}

async function fixtureEnvironment() {
  const store = new ArtifactStore(mkdtempSync(join(tmpdir(), "abl-materializer-")), {
    activeKeyId: "key-1",
    keys: { "key-1": Buffer.alloc(32, 17) }
  });
  const sources = [
    sourceFixture(store, "jan", "2026-01-31", "100"),
    sourceFixture(store, "feb", "2026-02-28", "120")
  ];
  const publications = sources.map(({ publication }) => publication);
  const definitions = new Map<string, ResolvedGovernedDefinitionV2>([
    [METHODOLOGY.reference.definitionVersionId, METHODOLOGY],
    [METRIC.reference.definitionVersionId, METRIC]
  ]);
  const sourcePolicy = createSourceAccessPolicyV1({
    contractVersion: 1,
    tenantId: TENANT,
    policyId: "portfolio-risk-read",
    revision: 1,
    datasetId: "loan-book",
    sourceContract: SOURCE_CONTRACT,
    scope: SCOPE,
    purpose: PURPOSE,
    allowedFields: [...REQUESTED_FIELDS],
    allowedAggregateDimensionFields: [],
    effectiveFrom: "2026-01-01"
  });
  const binding = createGovernedDatasetScopeBindingV1({
    contractVersion: 1,
    tenantId: TENANT,
    bindingId: "dataset-binding-1",
    revision: 1,
    datasetId: "loan-book",
    sourceContract: SOURCE_CONTRACT,
    scope: SCOPE,
    effectiveFrom: "2026-01-01"
  });
  const effective = effectiveAuthority(new Map([
    ["portfolio-risk-read", resolved(
      "source-policy-v1",
      "source_access_policy",
      "portfolio-risk-read",
      sourcePolicy
    )],
    ["dataset-binding-1", resolved(
      "dataset-binding-v1",
      "dataset_scope_binding",
      "dataset-binding-1",
      binding
    )]
  ]));
  const disabled = new Set<string>();
  const events: string[] = [];
  const publicationPort = publicationAuthority(publications, disabled, events);
  const policy = compileAuthorizationPolicy({
    id: "portfolio-policy",
    version: "1.0.0",
    defaultObligations: {
      maxResultRows: 1_000,
      maxResultBytes: 2_000_000,
      maxExecutionMs: 10_000,
      minimumCohortSize: 1,
      requireImmutableSnapshot: true,
      allowRawRows: false,
      allowExport: false,
      rowFilterRefs: [],
      fieldMasks: {},
      auditTags: ["governed-analysis"]
    },
    rules: [{
      id: "permit",
      effect: "permit",
      tenantIds: [TENANT],
      tools: ["abl_run_portfolio_surveillance"],
      datasets: ["loan-book"],
      purposes: [PURPOSE],
      fields: ["*"],
      requiredScopes: ["analysis:run"]
    }]
  });
  const analyticalDefinitions = {
    resolveFrozenDefinition: (tenantId: string, definitionVersionId: string) =>
      tenantId === TENANT ? definitions.get(definitionVersionId) : undefined
  };
  const preflight = new PortfolioSurveillanceAuthorizationPreflightServiceV1({
    publications: publicationPort,
    sourcePolicies: new GovernedSourceAccessPolicyDirectoryV1(
      { listCandidateDefinitionKeys: () => ({ complete: true, definitionKeys: ["portfolio-risk-read"] }) },
      effective
    ),
    datasetScopeBindings: effective,
    analyticalDefinitions,
    globalAuthorizer: {
      authorize: (input: PolicyEvaluationRequest) => evaluatePolicy(policy, input)
    }
  });
  const request = {
    contractVersion: 1 as const,
    operation: "portfolio_surveillance_v1" as const,
    sources: publications.map((publication) => ({
      kind: "certification_manifest" as const,
      certificationManifestId: publication.certification.certificationManifestId
    })),
    definitionVersionIds: ["metric-balance-v1", "methodology-v1"]
  };
  const authorized = await preflight.authorize(request, {
    principal: createVerifiedPrincipalContext({
      issuer: "https://identity.example.test",
      subject: "risk-analyst",
      principalId: "risk-analyst",
      tenantId: TENANT,
      clientId: "codex-client",
      audiences: ["abl-api"],
      resourceIndicators: ["https://mcp.example.test/mcp"],
      scopes: ["analysis:run", "data:read"],
      credentialFingerprint: bare(hash("credential")),
      verifiedAtEpochSeconds: 1_786_500_000,
      expiresAtEpochSeconds: 1_787_000_000,
      authenticationMethods: ["mfa"]
    }),
    purpose: PURPOSE,
    planningCutoff: CUTOFF
  });
  const dependencies: PortfolioSurveillanceMaterializerDependenciesV1 = {
    publications: publicationPort,
    artifacts: {
      getJson: (tenantId, artifactId) => {
        events.push(`artifact:${artifactId}`);
        return store.getJson(tenantId, artifactId);
      }
    },
    analyticalDefinitions,
    planArtifacts: store
  };
  return {
    store,
    sources,
    disabled,
    events,
    request,
    authorized,
    publicationPort,
    analyticalDefinitions,
    materializer: new PortfolioSurveillancePlanMaterializerV1(dependencies)
  };
}

function sourceFixture(
  store: ArtifactStore,
  suffix: string,
  asOfDate: string,
  outstandingBalance: string
): FixtureSource {
  const snapshotId = `snapshot-${suffix}`;
  const certificationManifestId = `cert-${suffix}`;
  const populationId = `population-${suffix}`;
  const persistedAt = "2026-03-01T10:03:00.000Z";
  const certifiedAt = "2026-03-01T10:05:00.000Z";
  const publishedAt = "2026-03-01T10:06:00.000Z";
  const snapshotHash = hash(`snapshot:${suffix}`);
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
  const mappingSpec = {
    mappingSpecId: "mapping-spec-1",
    mappingKey: "mapping-loans",
    revision: 1,
    mappingSpecHash: hash("mapping-spec"),
    sourceContract: SOURCE_CONTRACT,
    dictionaryBundle
  } as const;
  const records = [{
    as_of_date: asOfDate,
    source_system: "core",
    facility_id: "facility-a",
    loan_id: "loan-1",
    outstanding_balance: outstandingBalance,
    original_balance: "150",
    commitment_amount: "200",
    secret_note: `borrower-secret-${suffix}`
  }];
  const mappingApplication = createMappingApplicationV1({
    contractVersion: 1,
    tenantId: TENANT,
    mappingApplicationId: `mapping-${suffix}`,
    snapshot: {
      snapshotId,
      snapshotHash,
      contentHash: hash(`delivered:${suffix}`)
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
    inputPopulationHash: hash(`input:${suffix}`),
    outputPopulationHash: canonicalHash(records),
    inputRowCount: records.length,
    outputRowCount: records.length,
    rejectedRowCount: 0,
    appliedBy: "mapping-worker",
    appliedAt: "2026-03-01T10:04:00.000Z"
  });
  const artifact = createNormalizedSnapshotArtifactV2({
    contractVersion: 2,
    kind: "normalized_snapshot",
    tenantId: TENANT,
    normalizedPopulationId: populationId,
    snapshot: { snapshotId, snapshotHash },
    mappingApplication: {
      mappingApplicationId: mappingApplication.mappingApplicationId,
      mappingApplicationHash: mappingApplication.mappingApplicationHash
    },
    records,
    createdAt: "2026-03-01T10:04:30.000Z"
  });
  const stored = store.putJson({
    tenantId: TENANT,
    kind: "normalized_snapshot",
    mediaType: "application/json",
    value: artifact
  });
  const populationBody = {
    contractVersion: 1 as const,
    tenantId: TENANT,
    populationId,
    snapshotId,
    snapshotHash,
    mappingApplicationId: mappingApplication.mappingApplicationId,
    mappingApplicationHash: mappingApplication.mappingApplicationHash,
    populationHash: artifact.populationHash,
    fieldSetHash: artifact.fieldSetHash,
    rowCount: artifact.rowCount,
    dataQuality: {
      runId: `dq-${suffix}`,
      rulesetId: "dq-rules-1",
      rulesetHash: hash("dq-rules"),
      resultHash: hash(`dq:${suffix}`),
      publicationDecision: "publish" as const,
      blockerCodes: []
    },
    reconciliation: {
      reconciliationId: `recon-${suffix}`,
      definitionHash: hash("reconciliation-definition"),
      resultHash: hash(`reconciliation:${suffix}`),
      passed: true as const,
      populationHash: artifact.populationHash
    },
    certifiedBy: "certification-checker",
    certifiedAt
  };
  const population = { ...populationBody, certificationHash: canonicalHash(populationBody) };
  const certificationBody = {
    contractVersion: 1 as const,
    tenantId: TENANT,
    certificationManifestId,
    evidenceFormat: "modern_snapshot_v2" as const,
    snapshotId,
    snapshotHash,
    populationId,
    populationCertificationHash: population.certificationHash,
    mappingApplicationId: mappingApplication.mappingApplicationId,
    mappingApplicationHash: mappingApplication.mappingApplicationHash,
    normalizedArtifactId: control(stored.artifactId),
    normalizedArtifactContentHash: control(stored.contentHash),
    dataQualityResultHash: population.dataQuality.resultHash,
    reconciliationResultHash: population.reconciliation.resultHash,
    populationHash: artifact.populationHash,
    rowCount: artifact.rowCount,
    certifiedBy: population.certifiedBy,
    certifiedAt
  };
  const bindingBody = {
    contractVersion: 1 as const,
    bindingId: "dataset-binding-1",
    tenantId: TENANT,
    datasetId: "loan-book",
    sourceContract: SOURCE_CONTRACT,
    scope: SCOPE,
    boundAt: "2026-01-01T00:00:00.000Z"
  };
  const publication = createCertifiedSnapshotPublicationV1({
    contractVersion: 1,
    publicationId: `publication-${suffix}`,
    tenantId: TENANT,
    datasetId: "loan-book",
    scope: SCOPE,
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
      ...SOURCE_CONTRACT,
      sourceKey: "loans-source"
    },
    snapshot: {
      snapshotId,
      snapshotHash,
      sourceContract: SOURCE_CONTRACT,
      delivery: {
        mode: "object_storage",
        deliveredContentHash: hash(`delivered:${suffix}`),
        immutableSourceVersion: `version-${suffix}`
      },
      asOfDate,
      knowledge: {
        sourceObservedAt: "2026-03-01T10:00:00.000Z",
        extractedAt: "2026-03-01T10:01:00.000Z",
        receivedAt: "2026-03-01T10:02:00.000Z",
        persistedAt
      },
      hashes: {
        contentHash: hash(`delivered:${suffix}`),
        schemaHash: hash("schema"),
        catalogHash: hash("catalog"),
        parserHash: hash("parser"),
        extractionHash: hash(`extraction:${suffix}`)
      },
      rowCount: artifact.rowCount,
      byteCount: 512,
      correction: { kind: "original" }
    },
    certification: {
      ...certificationBody,
      certificationManifestHash: canonicalHash(certificationBody)
    },
    population,
    mappingSpec,
    mappingApplication,
    normalizedArtifact: {
      artifactId: control(stored.artifactId),
      artifactContractVersion: artifact.contractVersion,
      artifactHash: artifact.artifactHash,
      kind: "normalized_snapshot",
      mediaType: "application/json",
      contentHash: control(stored.contentHash),
      byteLength: stored.byteLength,
      uri: stored.uri,
      metadataHash: canonicalHash(stored),
      rowCount: artifact.rowCount,
      populationHash: artifact.populationHash,
      fieldSetHash: artifact.fieldSetHash
    },
    publishedBy: "publication-worker",
    publishedAt
  });
  return { artifact, stored, loaded: store.getJson(TENANT, stored.artifactId), publication };
}

function publicationAuthority(
  publications: readonly CertifiedSnapshotPublicationV1[],
  disabled: ReadonlySet<string>,
  events: string[]
): SurveillancePublicationReadPortV1 {
  const byId = new Map(publications.map((publication) => [publication.publicationId, publication]));
  const byCertification = new Map(
    publications.map((publication) => [publication.certification.certificationManifestId, publication])
  );
  return {
    get: (tenantId, publicationId) => {
      events.push(`publication:${publicationId}`);
      return tenantId === TENANT ? byId.get(publicationId) : undefined;
    },
    getByCertificationManifest: (tenantId, certificationManifestId) =>
      tenantId === TENANT ? byCertification.get(certificationManifestId) : undefined,
    getDisable: (tenantId, publicationId): SurveillancePublicationDisableEventV1 | undefined => {
      events.push(`disable:${publicationId}`);
      const publication = byId.get(publicationId);
      if (tenantId !== TENANT || publication === undefined || !disabled.has(publicationId)) {
        return undefined;
      }
      return {
        tenantId,
        publicationId,
        publicationHash: publication.publicationHash,
        reasonCode: "withdrawn",
        reason: "Publication was withdrawn after authorization",
        disabledBy: "data-steward",
        disabledAt: "2026-08-12T12:00:01.000Z"
      };
    },
    listByScopeAsOf: (query: SurveillancePublicationLineageQueryV1): CompletePublicationLineagePageV1 => ({
      complete: true,
      publications: publications.filter(
        (publication) =>
          publication.tenantId === query.tenantId &&
          publication.datasetId === query.datasetId &&
          publication.snapshot.asOfDate === query.asOfDate &&
          canonicalJson(publication.scope) === canonicalJson(query.scope) &&
          publication.publishedAt <= query.publishedThrough
      )
    })
  };
}

function effectiveAuthority(
  values: ReadonlyMap<string, ResolvedGovernedDefinitionV2>
): EffectiveGovernedDefinitionResolutionPortV1 {
  return {
    resolveEffective: (input) => input.tenantId === TENANT
      ? values.get(input.definitionKey)
      : undefined
  };
}

function tamperedDependencies(
  environment: Awaited<ReturnType<typeof fixtureEnvironment>>,
  tamper: (loaded: MutableLoaded, artifactId: string) => MutableLoaded | undefined
): PortfolioSurveillanceMaterializerDependenciesV1 {
  return {
    publications: environment.publicationPort,
    artifacts: {
      getJson: (tenantId, artifactId) => {
        environment.events.push(`artifact:${artifactId}`);
        const loaded = cloneLoaded(environment.store.getJson(tenantId, artifactId));
        return tamper(loaded, artifactId) ?? loaded;
      }
    },
    analyticalDefinitions: environment.analyticalDefinitions
  };
}

interface MutableLoaded {
  readonly metadata: StoredArtifact & Record<string, unknown>;
  readonly value: Record<string, unknown>;
}

function cloneLoaded(value: Readonly<{ metadata: StoredArtifact; value: unknown }>): MutableLoaded {
  return structuredClone(value) as MutableLoaded;
}

function resolved(
  definitionVersionId: string,
  kind: ResolvedGovernedDefinitionV2["reference"]["kind"],
  definitionKey: string,
  executionDocument: CanonicalJsonValue
): ResolvedGovernedDefinitionV2 {
  const approvalEventHash = hash(`approval:${definitionVersionId}`);
  const semanticVersion = kind === "methodology_bundle"
    ? (executionDocument as typeof METHODOLOGY_DOCUMENT).version
    : `${(executionDocument as { readonly revision?: number; readonly version?: number }).revision ??
        (executionDocument as { readonly version?: number }).version ?? 1}.0.0`;
  return {
    reference: {
      definitionVersionId,
      definitionKey,
      kind,
      semanticVersion,
      versionHash: hash(`version:${definitionVersionId}`),
      documentHash: canonicalHash(executionDocument),
      approvalEventHash
    },
    approvalEvidence: {
      status: "approved",
      proposedBy: "data-steward",
      approvedBy: "risk-reviewer",
      approvedAt: "2026-01-02T12:00:00.000Z",
      approvalEventHash
    },
    executionDocument
  };
}

const METHODOLOGY_DOCUMENT = {
  contractVersion: 1,
  bundleKind: "methodology",
  bundleId: "portfolio-surveillance",
  version: "1.0.0",
  name: "Portfolio surveillance",
  description: "Deterministic portfolio surveillance.",
  calculationEngine: {
    engineId: "portfolio-surveillance-engine",
    engineVersion: "1.0.0",
    runtimeBundleHash: hash("surveillance-runtime")
  },
  requiredDefinitionKinds: ["metric_definition"],
  deterministicParameters: { maximumPeriods: 120 },
  approval: {
    status: "pending_durable_approval",
    authority: "governed_definition_v2_lifecycle"
  }
} as const;

const METRIC_DOCUMENT: MetricDefinitionV1 = {
  schemaVersion: "1",
  definitionType: "metric_definition",
  definitionId: "balance-utilization",
  version: 1,
  name: "Balance and utilization",
  family: "balance_utilization",
  grain: "loan",
  unit: "ratio",
  temporalSemantics: "point_in_time",
  numerator: { label: "Outstanding balance", aggregation: "sum", field: "outstanding_balance" },
  denominator: { label: "Commitment", aggregation: "sum", field: "commitment_amount" },
  window: { kind: "ever_to_date", maximumPeriods: 120 },
  population: null,
  nullPolicy: "unavailable",
  coverage: { minimumRatio: "1", minimumObservedRecords: 1 },
  privacy: { minimumCellCount: 1, complementarySuppression: true },
  maximumCells: 100,
  configuration: {
    kind: "balance_utilization",
    balanceField: "outstanding_balance",
    originalBalanceField: "original_balance",
    commitmentField: "commitment_amount"
  },
  approval: {
    status: "approved",
    proposedBy: "data-steward",
    approvedBy: "risk-reviewer",
    approvedAt: "2026-01-02T12:00:00.000Z"
  }
};

const METHODOLOGY = resolved(
  "methodology-v1",
  "methodology_bundle",
  "portfolio-surveillance",
  METHODOLOGY_DOCUMENT
);
const METRIC = resolved(
  "metric-balance-v1",
  "metric_definition",
  "balance-utilization",
  METRIC_DOCUMENT
);

function materializationCode(code: PortfolioSurveillanceMaterializationError["code"]) {
  return (error: unknown): boolean =>
    error instanceof PortfolioSurveillanceMaterializationError && error.code === code;
}

function control(value: string): Sha256Hash {
  return `sha256:${value}` as Sha256Hash;
}

function bare(value: string): string {
  return value.startsWith("sha256:") ? value.slice("sha256:".length) : value;
}

function hash(value: string): Sha256Hash {
  return canonicalHash(value);
}
