import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import {
  canonicalHash,
  createGovernedDatasetScopeBindingV1,
  createMappingSpecV2,
  createSnapshotCertificationDefinitionV1,
  createSourceAccessPolicyV1,
  createSourceContractV1,
  type CanonicalJsonValue,
  type MappingSpecV2,
  type Sha256Hash,
  type SnapshotCertificationDefinitionV1
} from "../src/contracts/index.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import { CertificationRuntimeAuthorityFactoryV1 } from "../src/control/certification-runtime-authority-v1.js";
import { ControlStore } from "../src/control/store.js";
import { GovernedCertifiedSnapshotPublicationLinkCatalogV2 } from "../src/control/governed-certified-snapshot-publication-links-v2.js";
import { GovernedDefinitionV2Store } from "../src/control/governed-definitions-v2.js";
import { SqliteHistoricalRuntimeAuthorityV1 } from "../src/control/historical-runtime-authority-v1.js";
import { JobStore } from "../src/control/jobs.js";
import { LifecycleSnapshotCertificationDefinitionAuthorityV1 } from "../src/control/lifecycle-snapshot-certification-definition-authority-v1.js";
import { SqliteSourceDeliveryAuthorityV1 } from "../src/control/source-delivery-authority-v1.js";
import type { MetricDefinitionV1 } from "../src/domain/surveillance/contracts.js";
import { SqliteCapturedSourceMaterialStoreV1 } from "../src/repositories/captured-source-material-v1.js";
import { SqliteCertificationArtifactStagingStoreV1 } from "../src/repositories/certification-artifact-staging-v1.js";
import { SqliteCertifiedSnapshotEvidenceV2Repository } from "../src/repositories/certified-snapshot-evidence-v2.js";
import {
  JobHandleRouteCatalogError,
  SqliteJobHandleRouteCatalog
} from "../src/repositories/sqlite-job-handle-route-catalog.js";
import { SqliteModernSnapshotExtractionReceiptRepositoryV1 } from "../src/repositories/modern-snapshot-extraction-receipts-v1.js";
import { SqlitePortfolioSurveillanceV4StateStore } from "../src/repositories/sqlite-portfolio-surveillance-v4-state.js";
import { SqliteSnapshotCertificationAttemptStoreV1 } from "../src/repositories/snapshot-certification-attempts-v1.js";
import { SqliteSurveillanceEvidenceRepositories } from "../src/repositories/sqlite-surveillance.js";
import { createVerifiedPrincipalContext, type VerifiedPrincipalContext } from "../src/security/identity.js";
import {
  compileAuthorizationPolicy,
  evaluatePolicy,
  type PolicyEvaluationRequest
} from "../src/security/policy.js";
import { createHmacKeyRing } from "../src/security/signed-plan.js";
import { SecurityStateStore } from "../src/security/state-store.js";
import {
  CompositeGovernedWorkflowRouter,
  type LegacyRoutedWorkflowApi
} from "../src/services/composite-governed-workflow-router.js";
import { GovernedCertifiedSnapshotPublicationV2Service } from "../src/services/governed-certified-snapshot-publication-v2.js";
import { GovernedDefinitionV2Resolver } from "../src/services/governed-definition-v2-resolver.js";
import { HistoricalMappingExecutionAuthorityV1 } from "../src/services/historical-mapping-execution-authority-v1.js";
import {
  modernSnapshotExtractionReceiptIdV1,
  type TrustedModernSnapshotExtractionV1
} from "../src/services/modern-snapshot-capture.js";
import {
  composeModernSnapshotRuntimeV1,
  type ModernSnapshotRuntimeV1Dependencies
} from "../src/services/modern-snapshot-runtime-v1.js";
import { executePortfolioSurveillanceOperationV1 } from "../src/services/operations/portfolio-surveillance-v1.js";
import {
  PortfolioSurveillanceAccessPreflightError
} from "../src/services/surveillance-access-preflight.js";
import {
  composeProductionDisabledSingleFacilityV2SurveillanceRuntime
} from "../src/services/single-facility-v2-surveillance-runtime.js";
import { RepositoryBackedSurveillanceSourcePublicationAuthorityV2 } from "../src/services/surveillance-production-authority-v2.js";

const DIRECTORIES: string[] = [];
const TENANT = "tenant-a";
const DATASET = "loan-dataset";
const PURPOSE = "portfolio_surveillance";
const CERTIFICATION_AT = "2026-02-01T01:00:00.000Z";
const REQUESTED_FIELDS = [
  "as_of_date",
  "commitment_amount",
  "facility_id",
  "loan_id",
  "original_balance",
  "outstanding_balance",
  "source_system"
] as const;
const OPERATOR = {
  tenantId: TENANT,
  actorId: "operator-a",
  authority: "platform_operator" as const,
  identitySource: "server_derived" as const
};
const RUNTIME_MAKER = { ...OPERATOR, actorId: "runtime-maker" };
const RUNTIME_CHECKER = { ...OPERATOR, actorId: "runtime-checker" };

afterEach(() => {
  for (const directory of DIRECTORIES.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("governed pilot runs capture through durable V4 results, then corrects, disables, and reopens", async () => {
  const fixture = createPilotFixture();
  try {
    const prior = await fixture.captureAndCertify("delivery-prior");
    await fixture.publish(
      "publication-prior",
      prior.certification.evidence.certification.certificationManifestId,
      "2026-01-30T04:00:00.000Z"
    );
    const original = await fixture.captureAndCertify("delivery-original");
    assert.equal(
      original.capture.receipt.receiptId,
      modernSnapshotExtractionReceiptIdV1(original.capture.snapshot.snapshotId)
    );
    assert.ok(original.certification.evidenceV2);
    const originalLink = await fixture.publish(
      "publication-original",
      original.certification.evidence.certification.certificationManifestId,
      "2026-02-01T01:05:00.000Z"
    );

    const firstRequest = operationRequest(
      prior.certification.evidence.certification.certificationManifestId,
      original.certification.evidence.certification.certificationManifestId
    );
    fixture.setWorkflowClock("2026-02-01T01:10:00.000Z");
    let opened = fixture.openWorkflow();
    assert.deepEqual(opened.runtime.exposure, {
      productionEnabled: false,
      remoteAdvertised: false
    });
    assert.notEqual(
      opened.runtime.preflightPublications,
      opened.runtime.materializationPublications
    );
    await opened.runtime.preflight.authorize(firstRequest, {
      principal: fixture.principal,
      purpose: PURPOSE,
      planningCutoff: "2026-02-01T01:10:00.000Z"
    });
    assert.equal(
      fixture.surveillanceArtifactReads,
      0,
      "metadata preflight must not possess normalized-artifact read authority"
    );
    const started = await opened.router.startPortfolioSurveillanceAuthorized(
      fixture.principal,
      startInput(firstRequest, "pilot-original")
    );
    assert.equal(started.value.status, "queued");
    const queued = await opened.router.getJobStatusAuthorized(
      fixture.principal,
      started.value.jobHandle
    );
    assert.equal(queued.value.status, "queued");
    const originalProcessed = await opened.workflow.processNext(TENANT, "worker-a");
    if (originalProcessed?.status === "failed" && opened.workerFailure !== undefined) {
      throw opened.workerFailure;
    }
    assert.deepEqual(originalProcessed, {
      operation: "portfolio_surveillance_v1",
      status: "succeeded",
      errorCode: null
    });
    const originalResult = await opened.router.getJobResultAuthorized(
      fixture.principal,
      started.value.jobHandle
    );
    assert.equal(originalResult.value.operation, "portfolio_surveillance_v1");

    fixture.registerCorrectionDelivery(original.capture.snapshot.snapshotId, original.capture.snapshot.snapshotHash);
    const corrected = await fixture.captureAndCertify("delivery-correction");
    assert.equal(corrected.capture.snapshot.correction.kind, "correction");
    const correctedLink = await fixture.publish(
      "publication-correction",
      corrected.certification.evidence.certification.certificationManifestId,
      "2026-02-01T03:05:00.000Z"
    );
    assert.equal(correctedLink.publication.snapshotId, corrected.capture.snapshot.snapshotId);
    assert.equal(
      fixture.publicationLinks.getEnabled(TENANT, originalLink.linkId)?.linkHash,
      originalLink.linkHash
    );

    const correctedRequest = operationRequest(
      prior.certification.evidence.certification.certificationManifestId,
      corrected.certification.evidence.certification.certificationManifestId
    );
    fixture.setWorkflowClock("2026-02-01T03:10:00.000Z");
    await opened.runtime.preflight.authorize(correctedRequest, {
      principal: fixture.principal,
      purpose: PURPOSE,
      planningCutoff: "2026-02-01T03:10:00.000Z"
    });
    const correctedStart = await opened.router.startPortfolioSurveillanceAuthorized(
      fixture.principal,
      startInput(correctedRequest, "pilot-correction")
    );
    const correctedProcessed = await opened.workflow.processNext(TENANT, "worker-a");
    if (correctedProcessed?.status === "failed" && opened.workerFailure !== undefined) {
      throw opened.workerFailure;
    }
    assert.deepEqual(correctedProcessed, {
      operation: "portfolio_surveillance_v1",
      status: "succeeded",
      errorCode: null
    });
    const correctedStatus = await opened.router.getJobStatusAuthorized(
      fixture.principal,
      correctedStart.value.jobHandle
    );
    assert.equal(correctedStatus.value.status, "succeeded");
    const correctedResult = await opened.router.getJobResultAuthorized(
      fixture.principal,
      correctedStart.value.jobHandle
    );
    assert.equal(correctedResult.value.resultHash, canonicalHash(correctedResult.value.result));
    const cancelStart = await opened.router.startPortfolioSurveillanceAuthorized(
      fixture.principal,
      startInput(correctedRequest, "pilot-cancel")
    );
    const cancelled = await opened.router.cancelJobAuthorized(
      fixture.principal,
      cancelStart.value.jobHandle
    );
    assert.equal(cancelled.value.status, "cancelled");
    assert.equal(await opened.workflow.processNext(TENANT, "worker-a"), null);

    fixture.disable(correctedLink, "2026-02-01T03:20:00.000Z");
    await assert.rejects(
      () => opened.runtime.preflight.authorize(correctedRequest, {
        principal: fixture.principal,
        purpose: PURPOSE,
        planningCutoff: "2026-02-01T03:30:00.000Z"
      }),
      (error: unknown) =>
        error instanceof PortfolioSurveillanceAccessPreflightError &&
        error.code === "PUBLICATION_DISABLED"
    );
    opened.close();

    opened = fixture.openWorkflow();
    const reopenedResult = await opened.router.getJobResultAuthorized(
      fixture.principal,
      correctedStart.value.jobHandle
    );
    assert.equal(reopenedResult.value.operation, "portfolio_surveillance_v1");
    assert.equal(reopenedResult.value.resultHash, canonicalHash(reopenedResult.value.result));
    await assert.rejects(
      () => opened.router.getJobResultAuthorized(
        principal("tenant-b", "cross-tenant-analyst"),
        correctedStart.value.jobHandle
      ),
      (error: unknown) =>
        error instanceof JobHandleRouteCatalogError && error.code === "ROUTE_NOT_FOUND"
    );
    opened.close();
  } finally {
    fixture.close();
  }
});

function createPilotFixture() {
  const directory = mkdtempSync(join(tmpdir(), "aegis-pilot-vertical-"));
  DIRECTORIES.push(directory);
  const artifacts = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "test-key",
    keys: { "test-key": Buffer.alloc(32, 7) },
    maximumArtifactBytes: 1_000_000
  });
  const source = sourceContract();
  const binding = createGovernedDatasetScopeBindingV1({
    contractVersion: 1,
    tenantId: TENANT,
    bindingId: "facility-a-binding",
    revision: 1,
    datasetId: DATASET,
    sourceContract: {
      sourceContractId: source.sourceContractId,
      revision: source.revision,
      sourceContractHash: source.sourceContractHash
    },
    scope: { scopeType: "facility", scopeId: "facility-a" },
    effectiveFrom: "2026-01-01"
  });

  let deliveryClock = "2026-01-30T00:02:00.000Z";
  let deliveryEvent = 0;
  const sourceDeliveries = new SqliteSourceDeliveryAuthorityV1(
    join(directory, "deliveries.sqlite"),
    {
      clock: () => new Date(deliveryClock),
      eventId: () => `delivery-event-${++deliveryEvent}`
    }
  );
  registerDelivery(sourceDeliveries, source, binding, "delivery-prior", "prior", {
    sourceObservedAt: "2026-01-30T00:00:00.000Z",
    receivedAt: "2026-01-30T00:01:00.000Z"
  });
  deliveryClock = "2026-01-31T00:02:00.000Z";
  registerDelivery(sourceDeliveries, source, binding, "delivery-original", "original", {
    sourceObservedAt: "2026-01-31T00:00:00.000Z",
    receivedAt: "2026-01-31T00:01:00.000Z"
  });

  let governedTick = 0;
  const governedStore = new GovernedDefinitionV2Store(join(directory, "governed.sqlite"), {
    clock: () => new Date(Date.UTC(2026, 0, 10, 12, 0, governedTick++))
  });
  const governed = new GovernedDefinitionV2Resolver(governedStore);
  let runtimeEvent = 0;
  const historicalRuntime = new SqliteHistoricalRuntimeAuthorityV1(
    join(directory, "runtime.sqlite"),
    artifacts,
    {
      clock: () => new Date("2026-01-09T12:00:00.000Z"),
      eventId: () => `runtime-event-${++runtimeEvent}`
    }
  );
  const runtimeEvidence = runtime(historicalRuntime);
  historicalRuntime.activateRuntime(RUNTIME_CHECKER, {
    runtimeBundleId: runtimeEvidence.runtime.runtimeBundleId,
    runtimeBundleHash: runtimeEvidence.runtime.runtimeBundleHash,
    idempotencyKey: "activate-runtime-a"
  });

  const sourceView = activate(governedStore, {
    definitionVersionId: "source-v1",
    definitionKey: source.sourceKey,
    kind: "source_contract",
    document: source
  });
  const bindingView = activate(governedStore, {
    definitionVersionId: "binding-v1",
    definitionKey: binding.bindingId,
    kind: "dataset_scope_binding",
    document: binding
  });
  const mappingDocument = mapping(source, runtimeEvidence.dictionary);
  const mappingView = activate(governedStore, {
    definitionVersionId: "mapping-v1",
    definitionKey: mappingDocument.mappingKey,
    kind: "mapping_spec",
    document: mappingDocument
  });
  const mappings = new HistoricalMappingExecutionAuthorityV1(governed);
  const historicalMapping = mappings.resolveFrozenAt({
    tenantId: TENANT,
    definitionVersionId: mappingView.version.definitionVersionId,
    certificationAt: CERTIFICATION_AT
  });
  const sourceRef = governed.resolveFrozen({
    tenantId: TENANT,
    definitionVersionId: sourceView.version.definitionVersionId
  }).reference;
  const scopeRef = governed.resolveFrozen({
    tenantId: TENANT,
    definitionVersionId: bindingView.version.definitionVersionId
  }).reference;
  const control = controlDefinition({
    source,
    binding,
    sourceRef,
    scopeRef,
    historicalMapping,
    runtime: runtimeEvidence.runtime
  });
  activate(governedStore, {
    definitionVersionId: "control-v1",
    definitionKey: binding.bindingId,
    kind: "snapshot_certification_control",
    document: control
  });

  const sourcePolicy = createSourceAccessPolicyV1({
    contractVersion: 1,
    tenantId: TENANT,
    policyId: "portfolio-risk-read",
    revision: 1,
    datasetId: DATASET,
    sourceContract: binding.sourceContract,
    scope: binding.scope,
    purpose: PURPOSE,
    allowedFields: [...REQUESTED_FIELDS],
    allowedAggregateDimensionFields: [],
    effectiveFrom: "2026-01-01"
  });
  activate(governedStore, {
    definitionVersionId: "source-policy-v1",
    definitionKey: sourcePolicy.policyId,
    kind: "source_access_policy",
    document: sourcePolicy
  });
  activate(governedStore, {
    definitionVersionId: "methodology-v1",
    definitionKey: "portfolio-surveillance",
    kind: "methodology_bundle",
    document: METHODOLOGY_DOCUMENT
  });
  activate(governedStore, {
    definitionVersionId: "metric-balance-v1",
    definitionKey: METRIC_DOCUMENT.definitionId,
    kind: "metric_definition",
    document: METRIC_DOCUMENT
  });

  const evidenceRepositories = new SqliteSurveillanceEvidenceRepositories(
    join(directory, "surveillance-evidence.sqlite")
  );
  const receipts = new SqliteModernSnapshotExtractionReceiptRepositoryV1(
    join(directory, "extraction-receipts.sqlite")
  );
  const sourceMaterial = new SqliteCapturedSourceMaterialStoreV1(
    join(directory, "source-material.sqlite")
  );
  const evidenceV2 = new SqliteCertifiedSnapshotEvidenceV2Repository(
    join(directory, "evidence-v2.sqlite")
  );
  const attempts = new SqliteSnapshotCertificationAttemptStoreV1(
    join(directory, "attempts.sqlite")
  );
  const artifactStaging = new SqliteCertificationArtifactStagingStoreV1(
    join(directory, "staging.sqlite")
  );
  const certificationRuntime = new CertificationRuntimeAuthorityFactoryV1(historicalRuntime);
  const lifecycleDefinitions = new LifecycleSnapshotCertificationDefinitionAuthorityV1({
    governed,
    mappings,
    runtime: certificationRuntime
  });
  let currentTime = CERTIFICATION_AT;
  let originalSnapshot:
    | Readonly<{ readonly snapshotId: string; readonly snapshotHash: Sha256Hash }>
    | undefined;
  const dependencies: ModernSnapshotRuntimeV1Dependencies = {
    tenantId: TENANT,
    sourceDeliveries,
    extraction: {
      async extract(input): Promise<TrustedModernSnapshotExtractionV1> {
        const corrected = input.deliveryId === "delivery-correction";
        const prior = input.deliveryId === "delivery-prior";
        const records = [
          loanRecord(prior ? "180" : corrected ? "250" : "200", prior ? "2026-01-30" : "2026-01-31")
        ];
        const suffix = prior ? "prior" : corrected ? "correction" : "original";
        if (corrected && originalSnapshot === undefined) {
          throw new Error("Original snapshot must be captured before its correction");
        }
        return {
          tenantId: TENANT,
          datasetId: DATASET,
          facilityId: binding.scope.scopeId,
          snapshotId: input.snapshotId,
          deliveryId: input.deliveryId,
          asOfDate: prior ? "2026-01-30" : "2026-01-31",
          knowledge: prior
            ? {
                sourceObservedAt: "2026-01-30T00:00:00.000Z",
                extractedAt: "2026-01-30T00:03:00.000Z",
                receivedAt: "2026-01-30T00:04:00.000Z"
              }
            : corrected
            ? {
                sourceObservedAt: "2026-02-01T02:00:00.000Z",
                extractedAt: "2026-02-01T02:03:00.000Z",
                receivedAt: "2026-02-01T02:04:00.000Z"
              }
            : {
                sourceObservedAt: "2026-01-31T00:00:00.000Z",
                extractedAt: "2026-01-31T00:03:00.000Z",
                receivedAt: "2026-01-31T00:04:00.000Z"
              },
          watermark: { mode: "none" },
          hashes: {
            contentHash: canonicalHash(`content-${suffix}`),
            schemaHash: canonicalHash("schema-v1"),
            profileHash: canonicalHash(`profile-${suffix}`),
            catalogHash: canonicalHash("catalog-v1"),
            parserHash: canonicalHash({
              parserId: source.parserPolicy.parserId,
              parserVersion: source.parserPolicy.parserVersion,
              optionsHash: source.parserPolicy.optionsHash
            })
          },
          rowCount: 1,
          columnCount: 9,
          byteCount: 256,
          elapsedMs: 1,
          sections: [{
            sectionId: "loans",
            required: true,
            present: true,
            rowCount: 1,
            contentHash: canonicalHash(`loans-${suffix}`),
            schemaHash: canonicalHash("loans-schema"),
            controlPopulationHash: canonicalHash(records)
          }],
          correction: corrected
            ? {
                kind: "correction",
                correctsSnapshotId: originalSnapshot!.snapshotId,
                correctsSnapshotHash: originalSnapshot!.snapshotHash,
                correctionSequence: 1,
                reasonCode: "servicer_restated",
                reason: "Synthetic corrected commitment amount.",
                detectedAt: "2026-02-01T02:30:00.000Z"
              }
            : { kind: "original" },
          sourceSections: [{ sectionId: "loans", records }]
        };
      }
    },
    receipts,
    snapshots: evidenceRepositories.datasetSnapshots,
    certifiedEvidenceV2: evidenceV2,
    attempts,
    artifactStaging,
    sourceMaterial,
    lifecycleDefinitions,
    certificationRuntime,
    dimensions: { async resolveForMapping() { return []; } },
    artifacts,
    sourceMaterialMaximumBytes: 1_000_000,
    now: () => currentTime
  };
  const modern = composeModernSnapshotRuntimeV1(dependencies);

  let publicationClock = "2026-02-01T01:05:00.000Z";
  const publicationLinks = new GovernedCertifiedSnapshotPublicationLinkCatalogV2(
    join(directory, "publication-links.sqlite"),
    { clock: () => new Date(publicationClock) }
  );
  const publisher = new GovernedCertifiedSnapshotPublicationV2Service({
    datasetSnapshots: evidenceRepositories.datasetSnapshots,
    captureLineage: evidenceRepositories.datasetSnapshots,
    certifiedSnapshotEvidence: evidenceV2,
    artifacts,
    definitions: governed,
    publicationLinks,
    clock: () => new Date(publicationClock)
  });
  let surveillanceArtifactReads = 0;
  const surveillanceArtifacts = {
    getJson(tenantId: string, artifactId: string) {
      surveillanceArtifactReads += 1;
      return artifacts.getJson(tenantId, artifactId);
    },
    putJson: artifacts.putJson.bind(artifacts)
  };
  const publicationAuthority = new RepositoryBackedSurveillanceSourcePublicationAuthorityV2({
    datasetSnapshots: evidenceRepositories.datasetSnapshots,
    captureLineage: evidenceRepositories.datasetSnapshots,
    certifiedSnapshotEvidence: evidenceV2,
    publicationLinks,
    artifacts: surveillanceArtifacts,
    definitions: governed
  });
  const analyticalDefinitions = {
    resolveFrozenDefinition(tenantId: string, definitionVersionId: string) {
      if (tenantId !== TENANT) return undefined;
      return governed.resolveFrozen({ tenantId, definitionVersionId });
    }
  };
  const policy = authorizationPolicy();
  const workflowDatabasePath = join(directory, "workflow.sqlite");
  const workflowRouteDatabasePath = join(directory, "workflow-routes.sqlite");
  let workflowClock = "2026-02-01T01:10:00.000Z";
  const principalValue = principal(TENANT, "risk-analyst");

  return {
    artifacts,
    publicationLinks,
    principal: principalValue,
    get surveillanceArtifactReads() {
      return surveillanceArtifactReads;
    },
    setWorkflowClock(value: string) {
      workflowClock = value;
    },
    async captureAndCertify(deliveryId: string) {
      currentTime = deliveryId === "delivery-prior"
        ? "2026-01-30T03:00:00.000Z"
        : deliveryId === "delivery-correction"
          ? "2026-02-01T03:00:00.000Z"
          : CERTIFICATION_AT;
      const capture = await modern.capture.capture(OPERATOR, {
        sourceContractId: source.sourceContractId,
        deliveryId
      });
      if (deliveryId === "delivery-original") {
        originalSnapshot = {
          snapshotId: capture.snapshot.snapshotId,
          snapshotHash: capture.snapshot.snapshotHash
        };
      }
      const certification = await modern.certification.certify(
        { snapshotId: capture.snapshot.snapshotId },
        OPERATOR
      );
      return { capture, certification };
    },
    async publish(linkId: string, certificationManifestId: string, publishedAt: string) {
      publicationClock = publishedAt;
      return publisher.publish(
        {
          tenantId: TENANT,
          linkId,
          certificationManifestId,
          idempotencyKey: `publish-${linkId}`
        },
        "publication-checker"
      );
    },
    disable(link: Readonly<{ readonly linkId: string; readonly linkHash: Sha256Hash }>, disabledAt: string) {
      publicationClock = disabledAt;
      return publicationLinks.disable({
        tenantId: TENANT,
        linkId: link.linkId,
        expectedLinkHash: link.linkHash,
        reasonCode: "superseded",
        reason: "A governed correction replaced the synthetic original.",
        disabledBy: "publication-checker",
        idempotencyKey: `disable-${link.linkId}`
      });
    },
    registerCorrectionDelivery(correctsSnapshotId: string, correctsSnapshotHash: Sha256Hash) {
      assert.equal(originalSnapshot?.snapshotId, correctsSnapshotId);
      assert.equal(originalSnapshot?.snapshotHash, correctsSnapshotHash);
      deliveryClock = "2026-02-01T02:02:00.000Z";
      registerDelivery(sourceDeliveries, source, binding, "delivery-correction", "correction", {
        sourceObservedAt: "2026-02-01T02:00:00.000Z",
        receivedAt: "2026-02-01T02:01:00.000Z"
      });
    },
    openWorkflow() {
      const clock = () => new Date(workflowClock);
      const jobs = new JobStore(workflowDatabasePath, { clock });
      const state = new SqlitePortfolioSurveillanceV4StateStore(workflowDatabasePath, { clock });
      const controlStore = new ControlStore(workflowDatabasePath, { clock });
      const securityState = new SecurityStateStore(workflowDatabasePath, { clock });
      let workerFailure: unknown;
      const runtime = composeProductionDisabledSingleFacilityV2SurveillanceRuntime(
        { tenantId: TENANT, facilityId: binding.scope.scopeId },
        {
          publicationAuthorities: {
            metadata: publicationAuthority,
            artifact: publicationAuthority
          },
          publicationLinks,
          definitions: {
            sourcePolicyCandidates: {
              listCandidateDefinitionKeys: () => ({
                complete: true,
                definitionKeys: [sourcePolicy.policyId]
              })
            },
            effective: governed,
            frozen: analyticalDefinitions
          },
          globalAuthorizer: {
            authorize: (input: PolicyEvaluationRequest) => evaluatePolicy(policy, input)
          },
          artifacts: surveillanceArtifacts,
          state,
          control: controlStore,
          jobs,
          securityState,
          tenantMembershipResolver: {
          async resolveTenantMembership(input) {
            return input.issuer === principalValue.issuer &&
              input.subject === principalValue.subject &&
              input.clientId === principalValue.clientId
              ? { tenantId: TENANT, principalId: principalValue.principalId }
              : null;
          }
          },
          policy,
          keyRing: createHmacKeyRing(
            [{ id: "signing-key", secret: Buffer.alloc(32, 47) }],
            "signing-key"
          ),
          workerExecutor: async (plan) => {
            try {
              return await executePortfolioSurveillanceOperationV1(plan);
            } catch (error) {
              workerFailure = error;
              throw error;
            }
          }
        },
        {
          codeVersion: "pilot-vertical-v1",
          clock,
          workerLeaseSeconds: 30
        }
      );
      const routes = new SqliteJobHandleRouteCatalog(workflowRouteDatabasePath, { clock });
      const router = new CompositeGovernedWorkflowRouter({
        legacy: unsupportedLegacyWorkflow(),
        portfolioSurveillanceV4: runtime.workflow,
        routes
      });
      return {
        runtime,
        workflow: runtime.workflow,
        router,
        get workerFailure() {
          return workerFailure;
        },
        close() {
          routes.close();
          securityState.close();
          controlStore.close();
          state.close();
          jobs.close();
        }
      };
    },
    close() {
      publicationLinks.close();
      receipts.close();
      artifactStaging.close();
      attempts.close();
      evidenceV2.close();
      sourceMaterial.close();
      evidenceRepositories.close();
      historicalRuntime.close();
      governedStore.close();
      sourceDeliveries.close();
    }
  };
}

function registerDelivery(
  authority: SqliteSourceDeliveryAuthorityV1,
  source: ReturnType<typeof sourceContract>,
  binding: ReturnType<typeof createGovernedDatasetScopeBindingV1>,
  deliveryId: string,
  suffix: string,
  timestamps: Readonly<{ readonly sourceObservedAt: string; readonly receivedAt: string }>
): void {
  const objectKey = `facility-a/${suffix}.parquet`;
  const immutableVersionId = `version-${suffix}`;
  authority.register(OPERATOR, {
    deliveryId,
    sourceContract: source,
    scopeBinding: binding,
    locator: {
      mode: "object_storage",
      format: "parquet",
      connectorId: "source-connector",
      bucket: "governed-deliveries",
      objectKey,
      immutableVersionId,
      immutableVersionHash: canonicalHash({
        connectorId: "source-connector",
        bucket: "governed-deliveries",
        objectKey,
        immutableVersionId
      }),
      contentHash: canonicalHash(`content-${suffix}`),
      byteCount: 256
    },
    ...timestamps,
    idempotencyKey: `register-${deliveryId}`
  });
}

function sourceContract() {
  const fields = [
    ["assetNumber", "string"],
    ["asOfDate", "date"],
    ["sourceSystem", "string"],
    ["facilityId", "string"],
    ["actualEndBalance", "decimal"],
    ["originalBalance", "decimal"],
    ["commitmentAmount", "decimal"],
    ["pool", "string"],
    ["currency", "string"]
  ] as const;
  return createSourceContractV1({
    contractVersion: 1,
    tenantId: TENANT,
    sourceContractId: "loan-source-a",
    sourceKey: "loan-tape",
    revision: 1,
    status: "active",
    delivery: {
      mode: "object_storage",
      format: "parquet",
      connectorId: "source-connector",
      credentialRef: "kms/source",
      bucket: "governed-deliveries",
      keyPattern: "facility-a/*.parquet",
      immutableVersionRequired: true
    },
    schemaPolicy: {
      columns: fields.map(([sourceName, nativeType], ordinal) => ({
        sourceName,
        ordinal,
        nativeType,
        nullable: false,
        required: true
      })),
      allowUnknownColumns: false,
      requireStableOrdinals: true
    },
    parserPolicy: {
      format: "parquet",
      parserId: "parquet-v1",
      parserVersion: "1.0.0",
      optionsHash: canonicalHash("parser-options"),
      exactDecimalMode: "string",
      timezone: "UTC",
      rejectSchemaMerging: true
    },
    extractionPolicy: {
      mode: "full",
      readOnly: true,
      maximumRows: 1_000,
      maximumColumns: 100,
      maximumBytes: 1_000_000,
      timeoutMs: 1_000,
      cursorRows: 100
    },
    sections: [{ sectionId: "loans", required: true, selector: "loans", keyFields: ["assetNumber"] }],
    effectiveFrom: "2026-01-01",
    createdBy: "source-maker",
    createdAt: "2026-01-01T00:00:00.000Z",
    approvedBy: "source-checker",
    approvedAt: "2026-01-01T00:01:00.000Z"
  });
}

function activate(
  store: GovernedDefinitionV2Store,
  input: {
    readonly definitionVersionId: string;
    readonly definitionKey: string;
    readonly kind: Parameters<GovernedDefinitionV2Store["propose"]>[0]["kind"];
    readonly document: unknown;
  }
) {
  let view = store.propose({
    tenantId: TENANT,
    ...input,
    semanticVersion: "1.0.0",
    effectiveFrom: "2026-01-01",
    proposedBy: "maker-a",
    idempotencyKey: `${input.definitionVersionId}-propose`
  });
  for (const toStatus of ["validated", "approved", "active"] as const) {
    view = store.transition({
      tenantId: TENANT,
      definitionVersionId: input.definitionVersionId,
      toStatus,
      expectedRevision: view.lifecycleRevision,
      actor: "checker-a",
      idempotencyKey: `${input.definitionVersionId}-${toStatus}`
    });
  }
  return view;
}

function runtime(authority: SqliteHistoricalRuntimeAuthorityV1) {
  const dictionaryContent = {
    dictionary: { fields: [...REQUESTED_FIELDS, "pool", "currency"] },
    fieldPolicy: { nulls: "preserve" }
  };
  const dictionary = authority.registerBundle(RUNTIME_MAKER, {
    bundleKind: "dictionary",
    bundleId: "dictionary-a",
    version: "1.0.0",
    mediaType: "application/json",
    createdAt: "2026-01-01T00:00:00.000Z",
    dictionaryVersion: "1.0.0",
    dictionaryHash: canonicalHash(dictionaryContent.dictionary),
    fieldPolicyVersion: "1.0.0",
    fieldPolicyHash: canonicalHash(dictionaryContent.fieldPolicy),
    content: dictionaryContent,
    idempotencyKey: "dictionary-a"
  }).value;
  if (dictionary.bundleKind !== "dictionary") throw new Error("Expected dictionary bundle");
  const compiler = authority.registerBundle(RUNTIME_MAKER, {
    bundleKind: "mapping_compiler",
    bundleId: "compiler-a",
    version: "1.0.0",
    mediaType: "application/json",
    createdAt: "2026-01-01T00:01:00.000Z",
    content: { compiler: "mapping-v2" },
    idempotencyKey: "compiler-a"
  }).value;
  if (compiler.bundleKind !== "mapping_compiler") throw new Error("Expected compiler bundle");
  const assembly = authority.registerRuntime(RUNTIME_MAKER, {
    runtimeBundleId: "runtime-a",
    runtimeVersion: "1.0.0",
    dictionary,
    mappingCompiler: compiler,
    methodologies: [],
    assembledAt: "2026-01-01T00:02:00.000Z",
    idempotencyKey: "runtime-a"
  }).value;
  return { dictionary, compiler, runtime: assembly };
}

function mapping(
  source: ReturnType<typeof sourceContract>,
  dictionary: ReturnType<typeof runtime>["dictionary"]
): MappingSpecV2 {
  const rules = [
    ["loan-id", "loan_id", "assetNumber"],
    ["as-of-date", "as_of_date", "asOfDate"],
    ["source-system", "source_system", "sourceSystem"],
    ["facility-id", "facility_id", "facilityId"],
    ["outstanding", "outstanding_balance", "actualEndBalance"],
    ["original", "original_balance", "originalBalance"],
    ["commitment", "commitment_amount", "commitmentAmount"],
    ["pool", "pool", "pool"],
    ["currency", "currency", "currency"]
  ] as const;
  return createMappingSpecV2({
    contractVersion: 2,
    tenantId: TENANT,
    mappingSpecId: "mapping-spec-a",
    mappingKey: "loan-tape",
    revision: 1,
    status: "active",
    sourceContract: {
      sourceContractId: source.sourceContractId,
      revision: source.revision,
      sourceContractHash: source.sourceContractHash
    },
    dictionaryBundle: dictionary,
    rules: rules.map(([ruleId, canonicalField, column]) => ({
      ruleId,
      canonicalField,
      expression: { op: "source" as const, column },
      onError: "fail_application" as const
    })),
    requiredCanonicalFields: rules.map(([, canonicalField]) => canonicalField),
    createdBy: "mapping-maker",
    createdAt: "2026-01-01T00:00:00.000Z",
    approvedBy: "mapping-checker",
    approvedAt: "2026-01-01T00:01:00.000Z"
  });
}

function controlDefinition(input: {
  readonly source: ReturnType<typeof sourceContract>;
  readonly binding: ReturnType<typeof createGovernedDatasetScopeBindingV1>;
  readonly sourceRef: ReturnType<GovernedDefinitionV2Resolver["resolveFrozen"]>["reference"];
  readonly scopeRef: ReturnType<GovernedDefinitionV2Resolver["resolveFrozen"]>["reference"];
  readonly historicalMapping: ReturnType<HistoricalMappingExecutionAuthorityV1["resolveFrozenAt"]>;
  readonly runtime: ReturnType<typeof runtime>["runtime"];
}): SnapshotCertificationDefinitionV1 {
  return createSnapshotCertificationDefinitionV1({
    contractVersion: 1,
    definitionKind: "snapshot_certification_control",
    tenantId: TENANT,
    certificationDefinitionId: input.binding.bindingId,
    revision: 1,
    sourceContract: input.binding.sourceContract,
    sourceContractExecution: { ...input.sourceRef, sourceContract: input.binding.sourceContract },
    scopeBinding: input.binding,
    scopeBindingExecution: {
      ...input.scopeRef,
      bindingId: input.binding.bindingId,
      revision: input.binding.revision,
      bindingHash: input.binding.bindingHash,
      sourceContract: input.binding.sourceContract
    },
    mappingExecution: {
      ...input.historicalMapping.reference,
      mappingSpecId: input.historicalMapping.mappingSpec.mappingSpecId,
      mappingSpecRevision: input.historicalMapping.mappingSpec.revision,
      mappingSpecHash: input.historicalMapping.mappingSpec.mappingSpecHash,
      sourceContract: input.binding.sourceContract,
      activation: input.historicalMapping.activationEvidence,
      window: input.historicalMapping.window
    },
    runtime: {
      runtimeBundleId: input.runtime.runtimeBundleId,
      runtimeVersion: input.runtime.runtimeVersion,
      runtimeBundleHash: input.runtime.runtimeBundleHash,
      dictionary: input.runtime.dictionary,
      mappingCompiler: input.runtime.mappingCompiler
    },
    dataQuality: {
      definitionId: "dq-a",
      rulesetId: "dq-rules-a",
      mappingSectionId: "loans",
      requiredSectionIds: ["loans"],
      rules: [{
        ruleId: "loan-id",
        type: "required",
        field: "loan_id",
        severity: "critical",
        blocking: true
      }],
      balanceField: "outstanding_balance",
      materialBalance: "0",
      window: { effectiveFrom: "2026-01-01" }
    },
    certificationReconciliation: {
      definitionId: "reconciliation-a",
      reconciliationId: "pool-tie-out",
      requiredSectionIds: ["loans"],
      controls: [{
        controlId: "loan-pool",
        sectionId: "loans",
        recordSource: "normalized",
        dimensions: ["pool"],
        balanceField: "outstanding_balance",
        currencyField: "currency",
        expected: [{ dimensions: { pool: "a" }, rowCount: 1, balance: "100", currency: "USD" }],
        balanceTolerance: "0"
      }],
      window: { effectiveFrom: "2026-01-01" }
    },
    window: { effectiveFrom: "2026-01-01" },
    approval: { status: "pending_durable_approval", authority: "governed_definition_v2_lifecycle" }
  });
}

function loanRecord(commitmentAmount: string, asOfDate: string) {
  return {
    assetNumber: "synthetic-loan-1",
    asOfDate,
    sourceSystem: "synthetic-core",
    facilityId: "facility-a",
    actualEndBalance: "100",
    originalBalance: "150",
    commitmentAmount,
    pool: "a",
    currency: "USD"
  } as const;
}

function operationRequest(...certificationManifestIds: readonly string[]) {
  return {
    contractVersion: 1 as const,
    operation: "portfolio_surveillance_v1" as const,
    sources: certificationManifestIds.map((certificationManifestId) => ({
      kind: "certification_manifest" as const,
      certificationManifestId
    })),
    definitionVersionIds: ["metric-balance-v1", "methodology-v1"]
  };
}

function startInput(
  request: ReturnType<typeof operationRequest>,
  idempotencyKey: string
) {
  return {
    operation: "portfolio_surveillance_v1" as const,
    operationRequest: request,
    idempotencyKey,
    purpose: PURPOSE
  };
}

function unsupportedLegacyWorkflow(): LegacyRoutedWorkflowApi {
  const unsupported = (): never => {
    throw new Error("The pilot acceptance route must remain on portfolio_surveillance_v4");
  };
  return {
    startAuthorized: unsupported,
    getJobStatusAuthorized: unsupported,
    getJobResultAuthorized: unsupported,
    cancelJobAuthorized: unsupported
  };
}

function authorizationPolicy() {
  const obligations = {
    maxResultRows: 5_000,
    maxResultBytes: 2_000_000,
    maxExecutionMs: 10_000,
    minimumCohortSize: 1,
    requireImmutableSnapshot: true,
    allowRawRows: false,
    allowExport: false,
    rowFilterRefs: [],
    fieldMasks: {},
    auditTags: ["governed-pilot"]
  };
  return compileAuthorizationPolicy({
    id: "portfolio-policy",
    version: "1.0.0",
    defaultObligations: obligations,
    rules: [{
      id: "permit-analysis",
      effect: "permit",
      tenantIds: [TENANT],
      tools: ["abl_run_portfolio_surveillance"],
      datasets: [DATASET],
      purposes: [PURPOSE],
      fields: ["*"],
      requiredScopes: ["analysis:run"]
    }, {
      id: "permit-job-actions",
      effect: "permit",
      tenantIds: [TENANT],
      tools: ["job.status", "job.result", "job.cancel"],
      datasets: [DATASET],
      purposes: [PURPOSE],
      fields: ["*"]
    }]
  });
}

function principal(tenantId: string, principalId: string): VerifiedPrincipalContext {
  const verifiedAt = Math.floor(Date.parse("2026-02-01T00:00:00.000Z") / 1_000);
  return createVerifiedPrincipalContext({
    issuer: "https://identity.example.test",
    subject: principalId,
    principalId,
    tenantId,
    clientId: "pilot-client",
    audiences: ["abl-api"],
    resourceIndicators: ["https://mcp.example.test/mcp"],
    scopes: ["analysis:run", "data:read"],
    credentialFingerprint: bare(canonicalHash(`credential:${tenantId}:${principalId}`)),
    verifiedAtEpochSeconds: verifiedAt,
    expiresAtEpochSeconds: verifiedAt + 86_400,
    authenticationMethods: ["mfa"]
  });
}

const METHODOLOGY_DOCUMENT = {
  contractVersion: 1,
  bundleKind: "methodology",
  bundleId: "portfolio-surveillance",
  version: "1.0.0",
  name: "Portfolio surveillance",
  description: "Deterministic certified portfolio surveillance.",
  calculationEngine: {
    engineId: "portfolio-surveillance-engine",
    engineVersion: "1.0.0",
    runtimeBundleHash: canonicalHash("surveillance-runtime")
  },
  requiredDefinitionKinds: ["metric_definition"],
  deterministicParameters: { maximumPeriods: 120 },
  approval: {
    status: "pending_durable_approval",
    authority: "governed_definition_v2_lifecycle"
  }
} as const satisfies CanonicalJsonValue;

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
  numerator: {
    label: "Outstanding balance",
    aggregation: "sum",
    field: "outstanding_balance"
  },
  denominator: {
    label: "Commitment",
    aggregation: "sum",
    field: "commitment_amount"
  },
  window: { kind: "ever_to_date", maximumPeriods: 120 },
  population: null,
  nullPolicy: "unavailable",
  coverage: { minimumRatio: "1", minimumObservedRecords: 1 },
  privacy: { minimumCellCount: 1, complementarySuppression: true },
  maximumCells: 1_000,
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
    approvedAt: "2026-01-01T12:00:00.000Z"
  }
};

function bare(value: string): string {
  return value.slice("sha256:".length);
}
