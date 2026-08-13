import assert from "node:assert/strict";
import { test } from "node:test";

import {
  canonicalHash,
  canonicalJson,
  createCertifiedSnapshotPublicationV1,
  createGovernedDatasetScopeBindingV1,
  createMappingApplicationV1,
  createSourceAccessPolicyV1,
  type CanonicalJsonValue,
  type CertifiedSnapshotPublicationV1,
  type Sha256Hash
} from "../src/contracts/index.js";
import type { MetricDefinitionV1 } from "../src/domain/surveillance/contracts.js";
import { createVerifiedPrincipalContext } from "../src/security/identity.js";
import {
  compileAuthorizationPolicy,
  evaluatePolicy,
  type CompiledAuthorizationPolicy,
  type PolicyEvaluationRequest
} from "../src/security/policy.js";
import type { ResolvedGovernedDefinitionV2 } from "../src/services/governed-definition-v2-resolver.js";
import { parsePortfolioSurveillanceOperationRequestV1 } from "../src/services/operations/portfolio-surveillance-v1.js";
import {
  GovernedSourceAccessPolicyDirectoryV1,
  PortfolioSurveillanceAccessPreflightError,
  PortfolioSurveillanceAuthorizationPreflightServiceV1,
  assertAuthorizedPortfolioSurveillancePreflightV1,
  parsePortfolioSurveillanceMetadataPreflightV1,
  type CompletePublicationLineagePageV1,
  type EffectiveGovernedDefinitionResolutionPortV1,
  type FrozenGovernedDefinitionResolutionPortV1,
  type SourceAccessPolicyCandidateIndexV1,
  type SurveillancePublicationLineageQueryV1,
  type SurveillancePublicationReadPortV1
} from "../src/services/surveillance-access-preflight.js";

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

test("metadata-only preflight derives fields and binds current source, scope, definition, and policy authority", async () => {
  const environment = fixtureEnvironment();
  const result = await environment.service.authorize(request(environment.publications), context());

  assert.deepEqual(result.metadata.requestedFields, REQUESTED_FIELDS);
  assert.deepEqual(result.metadata.requestedAggregateDimensionFields, []);
  assert.equal(result.metadata.publications.length, 2);
  assert.equal(result.metadata.datasetScopeBindings.length, 1);
  assert.equal(result.metadata.sourceAccessPolicies.length, 1);
  assert.equal(result.metadata.maximumPlannedCells, 100);
  assert.equal(result.metadata.maximumDisclosedItems, 105);
  assert.equal(result.metadata.authorization.principalId, "risk-analyst");
  assert.equal(
    canonicalHash(parsePortfolioSurveillanceOperationRequestV1(result.metadata.request)),
    result.metadata.requestHash
  );
  assert.ok(result.metadata.request.sources.every((source) => !("publicationId" in source)));
  assert.equal(result.metadata.v4Preflight.sourceAccessPolicySetHash, result.metadata.sourceAccessPolicySetHash);
  assert.deepEqual(parsePortfolioSurveillanceMetadataPreflightV1(result.metadata), result.metadata);
  assert.doesNotThrow(() => assertAuthorizedPortfolioSurveillancePreflightV1(result));
  assert.deepEqual(environment.policyAuthority.calls, [
    {
      asOfDate: "2026-08-12",
      definitionKey: "portfolio-risk-read",
      kind: "source_access_policy",
      tenantId: TENANT
    }
  ]);
  assert.ok(environment.bindingAuthority.calls.every(({ kind }) => kind === "dataset_scope_binding"));
  assert.deepEqual(Object.keys(environment.dependencies).sort(), [
    "analyticalDefinitions",
    "datasetScopeBindings",
    "globalAuthorizer",
    "publications",
    "sourcePolicies"
  ]);
  assert.equal("readArtifact" in environment.dependencies, false);
  assert.equal("loadRecords" in environment.dependencies, false);

  const postCutoffDisable = fixtureEnvironment(undefined, {
    disabledPublicationId: environment.publications[0]!.publicationId,
    disabledAt: "2026-08-13T12:00:00.000Z"
  });
  await assert.doesNotReject(() =>
    postCutoffDisable.service.authorize(request(postCutoffDisable.publications), context())
  );
});

test("source-policy directory rejects no effective policy, ambiguity, incomplete indexes, and selector substitution", async () => {
  const environment = fixtureEnvironment();
  const selector = sourceSelector(environment.publications[0]!);
  const noPolicy = new GovernedSourceAccessPolicyDirectoryV1(
    index([]),
    effectiveAuthority(new Map())
  );
  await assert.rejects(
    () => noPolicy.resolveExact(selector, CUTOFF),
    errorCode("SOURCE_POLICY_NOT_FOUND")
  );

  const expiredDocument = createSourceAccessPolicyV1({
    ...withoutPolicyHash(sourcePolicy("portfolio-risk-read")),
    effectiveTo: "2026-07-01"
  });
  const expired = new GovernedSourceAccessPolicyDirectoryV1(
    index(["portfolio-risk-read"]),
    effectiveAuthority(new Map([
      ["portfolio-risk-read", resolved(
        "expired-policy-v1",
        "source_access_policy",
        "portfolio-risk-read",
        expiredDocument
      )]
    ]))
  );
  await assert.rejects(
    () => expired.resolveExact(selector, CUTOFF),
    errorCode("SOURCE_POLICY_NOT_FOUND")
  );

  const second = sourcePolicy("portfolio-risk-read-2");
  const ambiguous = new GovernedSourceAccessPolicyDirectoryV1(
    index(["portfolio-risk-read", "portfolio-risk-read-2"]),
    effectiveAuthority(new Map([
      ["portfolio-risk-read", SOURCE_POLICY],
      ["portfolio-risk-read-2", resolved("policy-v2", "source_access_policy", "portfolio-risk-read-2", second)]
    ]))
  );
  await assert.rejects(
    () => ambiguous.resolveExact(selector, CUTOFF),
    errorCode("SOURCE_POLICY_AMBIGUOUS")
  );

  const incomplete = new GovernedSourceAccessPolicyDirectoryV1(
    { listCandidateDefinitionKeys: () => ({ complete: false, definitionKeys: [] }) },
    effectiveAuthority(new Map())
  );
  await assert.rejects(
    () => incomplete.resolveExact(selector, CUTOFF),
    errorCode("SOURCE_POLICY_EVIDENCE_INVALID")
  );

  const substituted = new GovernedSourceAccessPolicyDirectoryV1(
    index(["portfolio-risk-read"]),
    effectiveAuthority(new Map([
      ["portfolio-risk-read", resolved("policy-v1", "source_access_policy", "another-policy", SOURCE_POLICY.executionDocument)]
    ]))
  );
  await assert.rejects(
    () => substituted.resolveExact(selector, CUTOFF),
    errorCode("SOURCE_POLICY_EVIDENCE_INVALID")
  );
});

test("preflight rejects obsolete corrections, forks, gaps, disabled evidence, and duplicate periods before authorization", async () => {
  const original = publication("jan-original", "cert-jan-original", "snapshot-jan-original", "2026-01-31");
  const correction = publication(
    "jan-correction",
    "cert-jan-correction",
    "snapshot-jan-correction",
    "2026-01-31",
    {
      kind: "correction",
      correctsSnapshotId: original.snapshot.snapshotId,
      correctsSnapshotHash: original.snapshot.snapshotHash,
      correctionSequence: 1,
      reasonCode: "late_cash",
      reason: "Late cash application",
      detectedAt: "2026-03-02T09:00:00.000Z"
    },
    "2026-03-02T10:00:00.000Z"
  );
  const feb = publication("feb", "cert-feb", "snapshot-feb", "2026-02-28");

  const obsolete = fixtureEnvironment([original, correction, feb]);
  await assert.rejects(
    () => obsolete.service.authorize(request([original, feb]), context()),
    errorCode("PUBLICATION_NOT_TERMINAL")
  );

  const fork = publication(
    "jan-correction-fork",
    "cert-jan-correction-fork",
    "snapshot-jan-correction-fork",
    "2026-01-31",
    {
      kind: "correction",
      correctsSnapshotId: original.snapshot.snapshotId,
      correctsSnapshotHash: original.snapshot.snapshotHash,
      correctionSequence: 1,
      reasonCode: "other_cash",
      reason: "Another correction",
      detectedAt: "2026-03-02T09:30:00.000Z"
    },
    "2026-03-02T11:00:00.000Z"
  );
  const forked = fixtureEnvironment([original, correction, fork, feb]);
  await assert.rejects(
    () => forked.service.authorize(request([correction, feb]), context()),
    errorCode("CORRECTION_LINEAGE_INVALID")
  );

  const gap = publication(
    "jan-gap",
    "cert-jan-gap",
    "snapshot-jan-gap",
    "2026-01-31",
    {
      kind: "correction",
      correctsSnapshotId: original.snapshot.snapshotId,
      correctsSnapshotHash: original.snapshot.snapshotHash,
      correctionSequence: 2,
      reasonCode: "gap",
      reason: "Skipped correction sequence",
      detectedAt: "2026-03-02T09:00:00.000Z"
    },
    "2026-03-02T10:00:00.000Z"
  );
  const gapped = fixtureEnvironment([original, gap, feb]);
  await assert.rejects(
    () => gapped.service.authorize(request([gap, feb]), context()),
    errorCode("CORRECTION_LINEAGE_INVALID")
  );

  const disabled = fixtureEnvironment([original, correction, feb], {
    disabledPublicationId: correction.publicationId
  });
  await assert.rejects(
    () => disabled.service.authorize(request([correction, feb]), context()),
    errorCode("PUBLICATION_DISABLED")
  );

  const duplicatePeriod = fixtureEnvironment([
    publication("jan-a", "cert-jan-a", "snapshot-jan-a", "2026-01-31"),
    publication("jan-b", "cert-jan-b", "snapshot-jan-b", "2026-01-31")
  ]);
  await assert.rejects(
    () => duplicatePeriod.service.authorize(request(duplicatePeriod.publications), context()),
    errorCode("CORRECTION_LINEAGE_INVALID")
  );

  const timeTravel = publication(
    "jan-time-travel",
    "cert-jan-time-travel",
    "snapshot-jan-time-travel",
    "2026-01-31",
    {
      kind: "correction",
      correctsSnapshotId: original.snapshot.snapshotId,
      correctsSnapshotHash: original.snapshot.snapshotHash,
      correctionSequence: 1,
      reasonCode: "time_travel",
      reason: "Detected before predecessor persistence",
      detectedAt: "2026-02-28T09:00:00.000Z"
    },
    "2026-03-02T10:00:00.000Z"
  );
  const temporal = fixtureEnvironment([original, timeTravel, feb]);
  await assert.rejects(
    () => temporal.service.authorize(request([timeTravel, feb]), context()),
    errorCode("CORRECTION_LINEAGE_INVALID")
  );
});

test("preflight rejects cross-tenant substitution, definition substitution, governed binding drift, and policy coverage gaps", async () => {
  const crossTenant = fixtureEnvironment(undefined, { substitutePublicationTenant: true });
  await assert.rejects(
    () => crossTenant.service.authorize(request(crossTenant.publications), context()),
    errorCode("PUBLICATION_SUBSTITUTION")
  );

  const definitionSubstitution = fixtureEnvironment(undefined, { substituteDefinitionId: true });
  await assert.rejects(
    () => definitionSubstitution.service.authorize(request(definitionSubstitution.publications), context()),
    errorCode("DEFINITION_SUBSTITUTION")
  );

  const bindingDrift = fixtureEnvironment(undefined, { substituteBindingDataset: true });
  await assert.rejects(
    () => bindingDrift.service.authorize(request(bindingDrift.publications), context()),
    errorCode("SOURCE_SET_MISMATCH")
  );

  const coverage = fixtureEnvironment(undefined, { omitPolicyField: "commitment_amount" });
  await assert.rejects(
    () => coverage.service.authorize(request(coverage.publications), context()),
    errorCode("SOURCE_POLICY_COVERAGE_DENIED")
  );
});

test("all global deny paths and insufficient aggregate-only obligations fail before materialization", async () => {
  const denied = fixtureEnvironment(undefined, { denyGlobalPolicy: true });
  await assert.rejects(
    () => denied.service.authorize(request(denied.publications), context()),
    errorCode("GLOBAL_POLICY_DENIED")
  );

  const rows = fixtureEnvironment(undefined, { maximumResultRows: 104 });
  await assert.rejects(
    () => rows.service.authorize(request(rows.publications), context()),
    errorCode("AUTHORIZATION_OBLIGATION_DENIED")
  );

  const raw = fixtureEnvironment(undefined, { allowRawRows: true });
  await assert.rejects(
    () => raw.service.authorize(request(raw.publications), context()),
    errorCode("AUTHORIZATION_OBLIGATION_DENIED")
  );
});

test("metadata hash, publication selection, source-policy set, binding set, and runtime permit substitution fail closed", async () => {
  const environment = fixtureEnvironment();
  const result = await environment.service.authorize(request(environment.publications), context());

  for (const mutation of [
    (value: Record<string, unknown>) => { value.sourceSelectionHash = hash("forged-selection"); },
    (value: Record<string, unknown>) => { value.sourceAccessPolicySetHash = hash("forged-policy-set"); },
    (value: Record<string, unknown>) => { value.datasetScopeBindingSetHash = hash("forged-binding-set"); },
    (value: Record<string, unknown>) => { value.tenantId = "tenant-b"; }
  ]) {
    const tampered = structuredClone(result.metadata) as unknown as Record<string, unknown>;
    mutation(tampered);
    assert.throws(() => parsePortfolioSurveillanceMetadataPreflightV1(tampered));
  }

  const serializedPermit = structuredClone(result.permit);
  assert.throws(
    () => assertAuthorizedPortfolioSurveillancePreflightV1({
      metadata: result.metadata,
      permit: serializedPermit
    }),
    errorCode("INTEGRITY_FAILURE")
  );
});

interface FixtureOptions {
  readonly disabledPublicationId?: string;
  readonly disabledAt?: string;
  readonly substitutePublicationTenant?: boolean;
  readonly substituteDefinitionId?: boolean;
  readonly substituteBindingDataset?: boolean;
  readonly omitPolicyField?: string;
  readonly denyGlobalPolicy?: boolean;
  readonly maximumResultRows?: number;
  readonly allowRawRows?: boolean;
}

function fixtureEnvironment(
  publicationsValue: readonly CertifiedSnapshotPublicationV1[] = [
    publication("jan", "cert-jan", "snapshot-jan", "2026-01-31"),
    publication("feb", "cert-feb", "snapshot-feb", "2026-02-28")
  ],
  options: FixtureOptions = {}
) {
  const publications = [...publicationsValue];
  const publicationPort = publicationAuthority(publications, options);
  const policyDocument = sourcePolicy("portfolio-risk-read", options.omitPolicyField);
  const policyResolved = resolved(
    "source-policy-v1",
    "source_access_policy",
    "portfolio-risk-read",
    policyDocument
  );
  const policyAuthority = effectiveAuthority(new Map([["portfolio-risk-read", policyResolved]]));
  const sourcePolicies = new GovernedSourceAccessPolicyDirectoryV1(
    index(["portfolio-risk-read"]),
    policyAuthority
  );
  const bindingDocument = governedBinding(options.substituteBindingDataset ? "other-dataset" : "loan-book");
  const bindingAuthority = effectiveAuthority(new Map([
    ["dataset-binding-1", resolved(
      "dataset-binding-v1",
      "dataset_scope_binding",
      "dataset-binding-1",
      bindingDocument
    )]
  ]));
  const definitions = new Map<string, ResolvedGovernedDefinitionV2>([
    [METHODOLOGY.reference.definitionVersionId, METHODOLOGY],
    [METRIC.reference.definitionVersionId, METRIC]
  ]);
  const analyticalDefinitions: FrozenGovernedDefinitionResolutionPortV1 = {
    resolveFrozenDefinition: (tenantId, definitionVersionId) => {
      if (tenantId !== TENANT) return undefined;
      const value = definitions.get(definitionVersionId);
      if (!options.substituteDefinitionId || value === undefined) return value;
      return {
        ...value,
        reference: { ...value.reference, definitionVersionId: "substituted-definition" }
      };
    }
  };
  const compiled = globalPolicy(options);
  const globalAuthorizer = {
    authorize: (input: PolicyEvaluationRequest) => evaluatePolicy(compiled, input)
  };
  const dependencies = {
    publications: publicationPort,
    sourcePolicies,
    datasetScopeBindings: bindingAuthority,
    analyticalDefinitions,
    globalAuthorizer
  };
  return {
    publications,
    dependencies,
    policyAuthority,
    bindingAuthority,
    service: new PortfolioSurveillanceAuthorizationPreflightServiceV1(dependencies)
  };
}

function publicationAuthority(
  publications: readonly CertifiedSnapshotPublicationV1[],
  options: FixtureOptions
): SurveillancePublicationReadPortV1 {
  const byId = new Map(publications.map((value) => [value.publicationId, value]));
  const byCertification = new Map(
    publications.map((value) => [value.certification.certificationManifestId, value])
  );
  return {
    get: (tenantId, publicationId) => {
      if (tenantId !== TENANT) return undefined;
      const value = byId.get(publicationId);
      if (!options.substitutePublicationTenant || value === undefined) return value;
      return { ...value, tenantId: "tenant-b" };
    },
    getByCertificationManifest: (tenantId, certificationManifestId) =>
      tenantId === TENANT ? byCertification.get(certificationManifestId) : undefined,
    getDisable: (tenantId, publicationId) => {
      const value = byId.get(publicationId);
      if (
        tenantId !== TENANT ||
        value === undefined ||
        options.disabledPublicationId !== publicationId
      ) return undefined;
      return {
        tenantId,
        publicationId,
        publicationHash: value.publicationHash,
        reasonCode: "invalid_source",
        reason: "Source evidence withdrawn",
        disabledBy: "data-steward",
        disabledAt: options.disabledAt ?? "2026-08-11T12:00:00.000Z"
      };
    },
    listByScopeAsOf: (query: SurveillancePublicationLineageQueryV1): CompletePublicationLineagePageV1 => ({
      complete: true,
      publications: publications.filter(
        (value) =>
          value.tenantId === query.tenantId &&
          value.datasetId === query.datasetId &&
          value.snapshot.asOfDate === query.asOfDate &&
          canonicalJson(value.scope) === canonicalJson(query.scope) &&
          value.publishedAt <= query.publishedThrough
      )
    })
  };
}

function index(definitionKeys: readonly string[]): SourceAccessPolicyCandidateIndexV1 {
  return {
    listCandidateDefinitionKeys: () => ({ complete: true, definitionKeys })
  };
}

function effectiveAuthority(
  values: ReadonlyMap<string, ResolvedGovernedDefinitionV2>
): EffectiveGovernedDefinitionResolutionPortV1 & {
  readonly calls: Array<{
    tenantId: string;
    kind: "source_access_policy" | "dataset_scope_binding";
    definitionKey: string;
    asOfDate: string;
  }>;
} {
  const calls: Array<{
    tenantId: string;
    kind: "source_access_policy" | "dataset_scope_binding";
    definitionKey: string;
    asOfDate: string;
  }> = [];
  return {
    calls,
    resolveEffective: (input) => {
      calls.push({ ...input });
      return input.tenantId === TENANT ? values.get(input.definitionKey) : undefined;
    }
  };
}

function request(publications: readonly CertifiedSnapshotPublicationV1[]) {
  return {
    contractVersion: 1 as const,
    operation: "portfolio_surveillance_v1" as const,
    sources: publications.map((publication) => ({
      kind: "certification_manifest" as const,
      certificationManifestId: publication.certification.certificationManifestId
    })),
    definitionVersionIds: ["metric-balance-v1", "methodology-v1"]
  };
}

function context() {
  return {
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
  };
}

function globalPolicy(options: FixtureOptions): CompiledAuthorizationPolicy {
  const obligations = {
    maxResultRows: options.maximumResultRows ?? 1_000,
    maxResultBytes: 2_000_000,
    maxExecutionMs: 10_000,
    minimumCohortSize: 1,
    requireImmutableSnapshot: true,
    allowRawRows: options.allowRawRows ?? false,
    allowExport: false,
    rowFilterRefs: [],
    fieldMasks: {},
    auditTags: ["governed-analysis"]
  };
  return compileAuthorizationPolicy({
    id: "portfolio-policy",
    version: "1.0.0",
    defaultObligations: obligations,
    rules: [{
      id: options.denyGlobalPolicy ? "deny" : "permit",
      effect: options.denyGlobalPolicy ? "deny" : "permit",
      tenantIds: [TENANT],
      tools: ["abl_run_portfolio_surveillance"],
      datasets: ["loan-book"],
      purposes: [PURPOSE],
      fields: ["*"],
      ...(options.denyGlobalPolicy ? {} : { requiredScopes: ["analysis:run"] })
    }]
  });
}

function sourceSelector(publicationValue: CertifiedSnapshotPublicationV1) {
  return {
    tenantId: TENANT,
    datasetId: publicationValue.datasetId,
    sourceContract: {
      sourceContractId: publicationValue.sourceContract.sourceContractId,
      sourceKey: publicationValue.sourceContract.sourceKey,
      revision: publicationValue.sourceContract.revision,
      sourceContractHash: publicationValue.sourceContract.sourceContractHash
    },
    scope: publicationValue.scope,
    purpose: PURPOSE
  };
}

function sourcePolicy(policyId: string, omittedField?: string) {
  return createSourceAccessPolicyV1({
    contractVersion: 1,
    tenantId: TENANT,
    policyId,
    revision: 1,
    datasetId: "loan-book",
    sourceContract: SOURCE_CONTRACT,
    scope: SCOPE,
    purpose: PURPOSE,
    allowedFields: REQUESTED_FIELDS.filter((field) => field !== omittedField),
    allowedAggregateDimensionFields: [],
    effectiveFrom: "2026-01-01"
  });
}

function governedBinding(datasetId: string) {
  return createGovernedDatasetScopeBindingV1({
    contractVersion: 1,
    tenantId: TENANT,
    bindingId: "dataset-binding-1",
    revision: 1,
    datasetId,
    sourceContract: SOURCE_CONTRACT,
    scope: SCOPE,
    effectiveFrom: "2026-01-01"
  });
}

function publication(
  publicationId: string,
  certificationManifestId: string,
  snapshotId: string,
  asOfDate: string,
  correction:
    | { readonly kind: "original" }
    | {
        readonly kind: "correction";
        readonly correctsSnapshotId: string;
        readonly correctsSnapshotHash: Sha256Hash;
        readonly correctionSequence: number;
        readonly reasonCode: string;
        readonly reason: string;
        readonly detectedAt: string;
      } = { kind: "original" },
  publishedAt = "2026-03-02T12:00:00.000Z"
): CertifiedSnapshotPublicationV1 {
  const suffix = publicationId;
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
  const persistedAt = correction.kind === "correction"
    ? "2026-03-02T09:15:00.000Z"
    : "2026-03-01T10:03:00.000Z";
  const certifiedAt = correction.kind === "correction"
    ? "2026-03-02T09:45:00.000Z"
    : "2026-03-01T10:05:00.000Z";
  const snapshot = {
    snapshotId,
    snapshotHash: hash(`snapshot:${suffix}`),
    sourceContract: SOURCE_CONTRACT,
    delivery: {
      mode: "object_storage" as const,
      deliveredContentHash: hash(`delivered:${suffix}`),
      immutableSourceVersion: `version-${suffix}`
    },
    asOfDate,
    knowledge: {
      sourceObservedAt: correction.kind === "correction" ? "2026-03-02T09:10:00.000Z" : "2026-03-01T10:00:00.000Z",
      extractedAt: correction.kind === "correction" ? "2026-03-02T09:11:00.000Z" : "2026-03-01T10:01:00.000Z",
      receivedAt: correction.kind === "correction" ? "2026-03-02T09:12:00.000Z" : "2026-03-01T10:02:00.000Z",
      persistedAt
    },
    hashes: {
      contentHash: hash(`delivered:${suffix}`),
      schemaHash: hash("schema"),
      catalogHash: hash("catalog"),
      parserHash: hash("parser"),
      extractionHash: hash(`extraction:${suffix}`)
    },
    rowCount: 2,
    byteCount: 512,
    correction
  };
  const mappingSpec = {
    mappingSpecId: "mapping-spec-1",
    mappingKey: "mapping-loans",
    revision: 1,
    mappingSpecHash: hash("mapping-spec"),
    sourceContract: SOURCE_CONTRACT,
    dictionaryBundle
  } as const;
  const populationHash = hash(`population:${suffix}`);
  const fieldSetHash = canonicalHash(REQUESTED_FIELDS);
  const mappingApplication = createMappingApplicationV1({
    contractVersion: 1,
    tenantId: TENANT,
    mappingApplicationId: `mapping-${suffix}`,
    snapshot: {
      snapshotId,
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
    inputPopulationHash: hash(`input:${suffix}`),
    outputPopulationHash: populationHash,
    inputRowCount: 2,
    outputRowCount: 2,
    rejectedRowCount: 0,
    appliedBy: "mapping-worker",
    appliedAt: certifiedAt
  });
  const populationBody = {
    contractVersion: 1 as const,
    tenantId: TENANT,
    populationId: `population-${suffix}`,
    snapshotId,
    snapshotHash: snapshot.snapshotHash,
    mappingApplicationId: mappingApplication.mappingApplicationId,
    mappingApplicationHash: mappingApplication.mappingApplicationHash,
    populationHash,
    fieldSetHash,
    rowCount: 2,
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
      populationHash
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
    snapshotHash: snapshot.snapshotHash,
    populationId: population.populationId,
    populationCertificationHash: population.certificationHash,
    mappingApplicationId: mappingApplication.mappingApplicationId,
    mappingApplicationHash: mappingApplication.mappingApplicationHash,
    normalizedArtifactId: hash(`artifact-id:${suffix}`),
    normalizedArtifactContentHash: hash(`artifact:${suffix}`),
    dataQualityResultHash: population.dataQuality.resultHash,
    reconciliationResultHash: population.reconciliation.resultHash,
    populationHash,
    rowCount: 2,
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
  return createCertifiedSnapshotPublicationV1({
    contractVersion: 1,
    publicationId,
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
      artifactHash: hash(`artifact:${suffix}`),
      kind: "normalized_snapshot",
      mediaType: "application/json",
      contentHash: certificationBody.normalizedArtifactContentHash,
      byteLength: 256,
      uri: `artifact://${TENANT}/${suffix}`,
      metadataHash: hash(`metadata:${suffix}`),
      rowCount: 2,
      populationHash,
      fieldSetHash
    },
    publishedBy: "publication-worker",
    publishedAt
  });
}

function resolved(
  definitionVersionId: string,
  kind: ResolvedGovernedDefinitionV2["reference"]["kind"],
  definitionKey: string,
  executionDocument: CanonicalJsonValue
): ResolvedGovernedDefinitionV2 {
  const approvalEventHash = hash(`approval:${definitionVersionId}`);
  return {
    reference: {
      definitionVersionId,
      definitionKey,
      kind,
      semanticVersion: "1.0.0",
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

const SOURCE_CONTRACT = {
  sourceContractId: "source-contract-1",
  revision: 1,
  sourceContractHash: hash("source-contract")
} as const;

const SCOPE = { scopeType: "portfolio" as const, scopeId: "portfolio-east" };

const SOURCE_POLICY = resolved(
  "source-policy-v1",
  "source_access_policy",
  "portfolio-risk-read",
  sourcePolicy("portfolio-risk-read")
);

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
    runtimeBundleHash: hash("runtime")
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
  METRIC_DOCUMENT as unknown as CanonicalJsonValue
);

function errorCode(code: PortfolioSurveillanceAccessPreflightError["code"]) {
  return (error: unknown): boolean =>
    error instanceof PortfolioSurveillanceAccessPreflightError && error.code === code;
}

function hash(value: string): Sha256Hash {
  return canonicalHash(value);
}

function bare(value: Sha256Hash): string {
  return value.slice("sha256:".length);
}

function withoutPolicyHash<T extends { readonly policyHash: Sha256Hash }>(value: T): Omit<T, "policyHash"> {
  const { policyHash: _policyHash, ...body } = value;
  return body;
}
