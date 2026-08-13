import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import {
  canonicalHash,
  canonicalJson,
  type CanonicalJsonValue,
  type Sha256Hash
} from "../src/contracts/index.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import { JobStore } from "../src/control/jobs.js";
import { ControlStore } from "../src/control/store.js";
import {
  SqlitePortfolioSurveillanceV4StateStore
} from "../src/repositories/sqlite-portfolio-surveillance-v4-state.js";
import {
  createVerifiedPrincipalContext,
  type VerifiedPrincipalContext
} from "../src/security/identity.js";
import {
  compileAuthorizationPolicy,
  evaluatePolicy,
  type AuthorizationPolicyDocument,
  type CompiledAuthorizationPolicy,
  type PermitPolicyDecision
} from "../src/security/policy.js";
import { createHmacKeyRing } from "../src/security/signed-plan.js";
import { SecurityStateStore } from "../src/security/state-store.js";
import {
  createPortfolioSurveillanceAuthorizationPreflightV4,
  portfolioSurveillanceDescriptorBindingV4
} from "../src/services/governed-operation-v4.js";
import {
  bindPortfolioSurveillanceGovernanceV1,
  createCertifiedSnapshotMaterialV1,
  executePortfolioSurveillanceOperationV1,
  preparePortfolioSurveillanceExecutionPlanV1,
  type CertifiedSnapshotMaterialV1,
  type PortfolioSurveillanceExecutionPlanV1,
  type PortfolioSurveillanceOperationAuthorityV1,
  type PortfolioSurveillanceSnapshotLoadRequestV1
} from "../src/services/operations/portfolio-surveillance-v1.js";
import {
  PortfolioSurveillanceWorkflowV4,
  PortfolioSurveillanceWorkflowV4Error,
  type PortfolioSurveillanceWorkflowV4FaultPoint,
  type PortfolioSurveillanceWorkflowV4Services
} from "../src/services/portfolio-surveillance-workflow-v4.js";
import type { ResolvedGovernedDefinitionV2 } from "../src/services/governed-definition-v2-resolver.js";
import type { AuthorizedPortfolioSurveillancePreflightV1 } from "../src/services/surveillance-access-preflight.js";
import type { PortfolioSurveillancePlanMaterializationResultV1 } from "../src/services/surveillance-materializer.js";

const TENANT = "tenant-a";
const PURPOSE = "portfolio-surveillance";
const DATASET = "loan-tape";
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
const REQUEST = {
  contractVersion: 1 as const,
  operation: "portfolio_surveillance_v1" as const,
  sources: [
    { kind: "certification_manifest" as const, certificationManifestId: "cert-feb" },
    { kind: "certification_manifest" as const, certificationManifestId: "cert-jan" }
  ],
  definitionVersionIds: ["metric-balance-v1", "methodology-v1"]
};
const DIRECTORIES: string[] = [];

afterEach(() => {
  for (const directory of DIRECTORIES.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("durable v4 workflow executes queued surveillance and reauthorizes exact result reads", async () => {
  const fixture = await workflowFixture();
  const started = await fixture.workflow.startPortfolioSurveillanceAuthorized(
    fixture.principal,
    startInput("idem-happy")
  );
  assert.equal(started.value.status, "queued");
  assert.equal(fixture.preflightCalls, 1);
  assert.equal(fixture.materializerCalls, 1);

  const status = await fixture.workflow.getPortfolioSurveillanceJobStatusAuthorized(
    fixture.principal,
    started.value.jobHandle
  );
  assert.equal(status.value.status, "queued");
  assert.equal(status.value.durableStatus, "submitted");

  const processed = await fixture.workflow.processNext(TENANT, "worker-1");
  assert.deepEqual(processed, {
    operation: "portfolio_surveillance_v1",
    status: "succeeded",
    errorCode: null
  });
  const result = await fixture.workflow.getPortfolioSurveillanceJobResultAuthorized(
    fixture.principal,
    started.value.jobHandle
  );
  assert.equal(result.value.operation, "portfolio_surveillance_v1");
  assert.equal(result.value.resultHash, canonicalHash(result.value.result));
  assert.equal(canonicalJson(result.value.result).includes("engineInput"), false);
  assert.equal(result.obligations.length, 2);
  assert.equal(fixture.workerCalls, 1);
  const state = fixture.state.list(TENANT).items[0]!;
  assert.equal(state.status, "completed");
  assert.ok(state.resultArtifact);
  assert.ok(state.manifestArtifact);
  assert.ok(
    fixture.control
      .listAuditEvents(TENANT, { limit: 1_000 })
      .some((event) => event.eventType === "portfolio_surveillance_v4.completed")
  );
  fixture.close();
});

test("denial is audited before materialization and creates no queue or workflow state", async () => {
  const fixture = await workflowFixture({ denyAnalysis: true });
  await assert.rejects(
    () => fixture.workflow.startPortfolioSurveillanceAuthorized(
      fixture.principal,
      startInput("idem-denied")
    ),
    hasCode("POLICY_DENIED")
  );
  assert.equal(fixture.materializerCalls, 0);
  assert.equal(fixture.jobs.list(TENANT, canonicalPrincipalBinding(fixture.principal)).length, 0);
  assert.equal(fixture.state.list(TENANT).items.length, 0);
  assert.equal(
    fixture.control.listAuditEvents(TENANT).filter(
      (event) => event.eventType === "authorization.denied"
    ).length,
    1
  );
  fixture.close();
});

test("actor-scoped idempotency replays before preflight and conflicts without rematerializing", async () => {
  const fixture = await workflowFixture();
  const first = await fixture.workflow.startPortfolioSurveillanceAuthorized(
    fixture.principal,
    startInput("idem-replay")
  );
  const second = await fixture.workflow.startPortfolioSurveillanceAuthorized(
    fixture.principal,
    startInput("idem-replay")
  );
  assert.equal(first.value.status, "queued");
  assert.equal(second.value.status, "queued");
  assert.notEqual(first.value.jobHandle, second.value.jobHandle);
  assert.equal(fixture.preflightCalls, 1);
  assert.equal(fixture.materializerCalls, 1);
  assert.equal(fixture.state.list(TENANT).items.length, 1);

  await assert.rejects(
    () => fixture.workflow.startPortfolioSurveillanceAuthorized(
      fixture.principal,
      { ...startInput("idem-replay"), purpose: "another-purpose" }
    ),
    hasCode("IDEMPOTENCY_CONFLICT")
  );
  assert.equal(fixture.preflightCalls, 1);
  assert.equal(fixture.materializerCalls, 1);
  fixture.close();
});

test("job handles are principal and tenant bound; current revocation blocks reads", async () => {
  const fixture = await workflowFixture();
  const started = await fixture.workflow.startPortfolioSurveillanceAuthorized(
    fixture.principal,
    startInput("idem-handle")
  );
  await assert.rejects(
    () => fixture.workflow.getPortfolioSurveillanceJobStatusAuthorized(
      principal("other-principal"),
      started.value.jobHandle
    ),
    hasCode("POLICY_DENIED")
  );
  fixture.membershipActive = false;
  const readsBeforeDenial = fixture.artifactReadCalls;
  await assert.rejects(
    () => fixture.workflow.getPortfolioSurveillanceJobStatusAuthorized(
      fixture.principal,
      started.value.jobHandle
    ),
    hasCode("POLICY_DENIED")
  );
  assert.equal(fixture.artifactReadCalls, readsBeforeDenial);
  fixture.close();
});

test("worker membership denial occurs before any envelope or plan artifact read", async () => {
  const fixture = await workflowFixture();
  await fixture.workflow.startPortfolioSurveillanceAuthorized(
    fixture.principal,
    startInput("idem-worker-denial-read-order")
  );
  fixture.membershipActive = false;
  const readsBeforeDenial = fixture.artifactReadCalls;
  const processed = await fixture.workflow.processNext(TENANT, "worker-1");
  assert.equal(processed?.status, "failed");
  assert.equal(processed?.errorCode, "POLICY_DENIED");
  assert.equal(fixture.artifactReadCalls, readsBeforeDenial);
  assert.equal(fixture.workerCalls, 0);
  fixture.close();
});

test("queued cancellation terminalizes queue and durable state without worker execution", async () => {
  const fixture = await workflowFixture();
  const started = await fixture.workflow.startPortfolioSurveillanceAuthorized(
    fixture.principal,
    startInput("idem-cancel")
  );
  const cancelled = await fixture.workflow.cancelPortfolioSurveillanceJobAuthorized(
    fixture.principal,
    started.value.jobHandle
  );
  assert.equal(cancelled.value.status, "cancelled");
  assert.equal(cancelled.value.durableStatus, "cancelled");
  assert.equal(await fixture.workflow.processNext(TENANT, "worker-1"), null);
  assert.equal(fixture.workerCalls, 0);
  fixture.close();
});

test("durable completed output is readable after reopening workflow stores", async () => {
  const directory = temporaryDirectory();
  const first = await workflowFixture({ directory });
  const started = await first.workflow.startPortfolioSurveillanceAuthorized(
    first.principal,
    startInput("idem-reopen")
  );
  await first.workflow.processNext(TENANT, "worker-1");
  first.close();

  const reopened = await workflowFixture({ directory, initializeArtifacts: false });
  const result = await reopened.workflow.getPortfolioSurveillanceJobResultAuthorized(
    reopened.principal,
    started.value.jobHandle
  );
  assert.equal(result.value.operation, "portfolio_surveillance_v1");
  assert.equal(reopened.state.list(TENANT).items[0]!.status, "completed");
  reopened.close();
});

test("idempotent start repairs a crash between durable receipt and submission audit", async () => {
  const directory = temporaryDirectory();
  const first = await workflowFixture({ directory, faultAt: "after_submission_state" });
  await assert.rejects(
    () => first.workflow.startPortfolioSurveillanceAuthorized(
      first.principal,
      startInput("idem-submission-repair")
    ),
    /Injected v4 workflow crash/
  );
  const stranded = first.state.list(TENANT).items[0]!;
  assert.equal(stranded.status, "submitted");
  assert.equal(stranded.submissionAuthorizationAudit, undefined);
  first.close();

  const recovered = await workflowFixture({ directory, initializeArtifacts: false });
  const replay = await recovered.workflow.startPortfolioSurveillanceAuthorized(
    recovered.principal,
    startInput("idem-submission-repair")
  );
  assert.equal(replay.value.status, "queued");
  const repaired = recovered.state.list(TENANT).items[0]!;
  assert.ok(repaired.submissionAuthorizationAudit);
  assert.equal(recovered.jobs.get(TENANT, repaired.submission.jobId).status, "queued");
  recovered.close();
});

test("a later lease adopts a verified persisted manifest without rerunning analysis", async () => {
  const directory = temporaryDirectory();
  const first = await workflowFixture({ directory, faultAt: "after_manifest_state" });
  const started = await first.workflow.startPortfolioSurveillanceAuthorized(
    first.principal,
    startInput("idem-manifest-recovery")
  );
  await assert.rejects(
    () => first.workflow.processNext(TENANT, "worker-1"),
    /Injected v4 workflow crash/
  );
  assert.equal(first.state.list(TENANT).items[0]!.status, "manifest_artifact_persisted");
  assert.equal(first.workerCalls, 1);
  first.close();

  const recovered = await workflowFixture({
    directory,
    initializeArtifacts: false,
    clockStart: "2026-08-12T12:00:31.000Z",
    codeVersion: "deployed-v5"
  });
  const processed = await recovered.workflow.processNext(TENANT, "worker-2");
  assert.equal(processed?.status, "succeeded");
  assert.equal(recovered.workerCalls, 0);
  const state = recovered.state.list(TENANT).items[0]!;
  assert.equal(state.status, "completed");
  assert.equal(state.executionCodeVersion, "test-v4");
  const result = await recovered.workflow.getPortfolioSurveillanceJobResultAuthorized(
    recovered.principal,
    started.value.jobHandle
  );
  assert.equal(result.value.operation, "portfolio_surveillance_v1");
  recovered.close();
});

test("result-only recovery freezes the original execution code version and signed-plan identity", async () => {
  const directory = temporaryDirectory();
  const first = await workflowFixture({ directory, faultAt: "after_result_state" });
  await first.workflow.startPortfolioSurveillanceAuthorized(
    first.principal,
    startInput("idem-result-recovery")
  );
  await assert.rejects(
    () => first.workflow.processNext(TENANT, "worker-1"),
    /Injected v4 workflow crash/
  );
  const original = first.state.list(TENANT).items[0]!;
  assert.equal(original.status, "result_artifact_persisted");
  const signedPlanId = original.signedPlanId!;
  first.close();

  const recovered = await workflowFixture({
    directory,
    initializeArtifacts: false,
    clockStart: "2026-08-12T12:00:31.000Z",
    codeVersion: "deployed-v5"
  });
  await recovered.workflow.processNext(TENANT, "worker-2");
  const state = recovered.state.list(TENANT).items[0]!;
  const manifest = recovered.artifacts.getJson(TENANT, state.manifestArtifact!.artifactId).value as {
    readonly codeVersion: string;
  };
  assert.equal(manifest.codeVersion, "test-v4");
  assert.equal(state.signedPlanId, signedPlanId);
  const completionPointer = state.queueCompletion!.completionAudit;
  const completionAudit = recovered.control.listAuditEvents(TENANT, {
    afterSequence: completionPointer.sequence - 1,
    limit: 1
  })[0]!;
  assert.equal((completionAudit.details as { readonly signedPlanId: string }).signedPlanId, signedPlanId);
  recovered.close();
});

test("queue success is not disclosed until completion audit and state are repaired", async () => {
  const fixture = await workflowFixture({ faultAt: "after_queue_completion" });
  const started = await fixture.workflow.startPortfolioSurveillanceAuthorized(
    fixture.principal,
    startInput("idem-queue-repair")
  );
  await assert.rejects(
    () => fixture.workflow.processNext(TENANT, "worker-1"),
    /Injected v4 workflow crash/
  );
  const before = fixture.state.list(TENANT).items[0]!;
  assert.equal(fixture.jobs.get(TENANT, before.submission.jobId).status, "succeeded");
  assert.equal(before.status, "completion_prepared");
  assert.equal(before.queueCompletion, undefined);

  const status = await fixture.workflow.getPortfolioSurveillanceJobStatusAuthorized(
    fixture.principal,
    started.value.jobHandle
  );
  assert.equal(status.value.status, "succeeded");
  assert.equal(status.value.durableStatus, "completed");
  assert.equal(status.value.resultAvailable, true);
  assert.ok(fixture.state.list(TENANT).items[0]!.queueCompletion);
  fixture.close();
});

test("cancellation after durable completion preparation terminalizes both queue and state", async () => {
  const fixture = await workflowFixture({ faultAt: "after_completion_preparation" });
  const started = await fixture.workflow.startPortfolioSurveillanceAuthorized(
    fixture.principal,
    startInput("idem-late-cancel")
  );
  await assert.rejects(
    () => fixture.workflow.processNext(TENANT, "worker-1"),
    /Injected v4 workflow crash/
  );
  const staged = fixture.state.list(TENANT).items[0]!;
  assert.equal(staged.status, "completion_prepared");
  const requested = await fixture.workflow.cancelPortfolioSurveillanceJobAuthorized(
    fixture.principal,
    started.value.jobHandle
  );
  assert.equal(requested.value.cancellationRequested, true);
  fixture.setClock("2026-08-12T12:00:31.000Z");
  assert.equal(fixture.jobs.reapExpiredJobs().length, 1);
  const reconciled = await fixture.workflow.getPortfolioSurveillanceJobStatusAuthorized(
    fixture.principal,
    started.value.jobHandle
  );
  assert.equal(reconciled.value.status, "cancelled");
  assert.equal(reconciled.value.durableStatus, "cancelled");
  assert.equal(reconciled.value.resultAvailable, false);
  fixture.close();
});

interface WorkflowFixtureOptions {
  readonly denyAnalysis?: boolean;
  readonly directory?: string;
  readonly initializeArtifacts?: boolean;
  readonly codeVersion?: string;
  readonly clockStart?: string;
  readonly faultAt?: PortfolioSurveillanceWorkflowV4FaultPoint;
}

async function workflowFixture(options: WorkflowFixtureOptions = {}) {
  const directory = options.directory ?? temporaryDirectory();
  const databasePath = join(directory, "workflow.sqlite");
  const artifactPath = join(directory, "artifacts");
  let currentTime = options.clockStart ?? CUTOFF;
  const clock = () => new Date(currentTime);
  const artifacts = new ArtifactStore(artifactPath, {
    activeKeyId: "artifact-key",
    keys: { "artifact-key": Buffer.alloc(32, 31) }
  });
  const jobs = new JobStore(databasePath, { clock });
  const state = new SqlitePortfolioSurveillanceV4StateStore(databasePath, { clock });
  const control = new ControlStore(databasePath, { clock });
  const securityState = new SecurityStateStore(databasePath, { clock });
  const keyRing = createHmacKeyRing([
    { id: "signing-key", secret: Buffer.alloc(32, 47) }
  ], "signing-key");
  const principalContext = principal();
  const plan = await planFixture(PURPOSE);
  const policy = policyFixture(options.denyAnalysis === true);
  let membershipActive = true;
  let preflightCalls = 0;
  let materializerCalls = 0;
  let workerCalls = 0;
  let artifactReadCalls = 0;

  const startDecision = evaluatePolicy(policy, {
    principal: principalContext,
    toolName: "abl_run_portfolio_surveillance",
    dataset: { id: DATASET, tenantId: TENANT },
    fields: plan.requestedFields,
    purpose: PURPOSE,
    nowEpochSeconds: Math.floor(Date.parse(CUTOFF) / 1_000)
  });
  const authorized = options.denyAnalysis
    ? undefined
    : authorizedFixture(principalContext, startDecision as PermitPolicyDecision, plan);
  if (options.initializeArtifacts !== false) {
    const persisted = artifacts.putJson({
      tenantId: TENANT,
      kind: "governed_portfolio_surveillance_plan_v4",
      mediaType: "application/json",
      value: plan
    });
    assert.equal(persisted.contentHash.length, 64);
  }
  const services: PortfolioSurveillanceWorkflowV4Services = {
    preflight: {
      authorize: async () => {
        preflightCalls += 1;
        if (!authorized) throw Object.assign(new Error("denied"), { code: "GLOBAL_POLICY_DENIED" });
        return authorized;
      }
    },
    materializer: {
      materialize: async (): Promise<PortfolioSurveillancePlanMaterializationResultV1> => {
        materializerCalls += 1;
        const stored = artifacts.putJson({
          tenantId: TENANT,
          kind: "governed_portfolio_surveillance_plan_v4",
          mediaType: "application/json",
          value: plan
        });
        return {
          plan,
          planArtifact: {
            artifactId: stored.artifactId,
            kind: "governed_portfolio_surveillance_plan_v4",
            mediaType: "application/json",
            contentHash: stored.contentHash,
            byteLength: stored.byteLength
          }
        };
      }
    },
    state,
    control,
    artifacts: {
      getJson: (tenantId: string, artifactId: string) => {
        artifactReadCalls += 1;
        return artifacts.getJson(tenantId, artifactId);
      },
      putJson: artifacts.putJson.bind(artifacts)
    },
    jobs,
    securityState,
    tenantMembershipResolver: {
      resolveTenantMembership: async () =>
        membershipActive ? { tenantId: TENANT, principalId: "risk-analyst" } : null
    },
    policy,
    keyRing,
    workerExecutor: async (workerPlan) => {
      workerCalls += 1;
      return executePortfolioSurveillanceOperationV1(workerPlan);
    }
  };
  const workflow = new PortfolioSurveillanceWorkflowV4(services, {
    codeVersion: options.codeVersion ?? "test-v4",
    clock,
    workerLeaseSeconds: 30,
    ...(options.faultAt
      ? { faultInjector: (point: PortfolioSurveillanceWorkflowV4FaultPoint) => point === options.faultAt }
      : {})
  });
  return {
    directory,
    workflow,
    jobs,
    state,
    control,
    artifacts,
    principal: principalContext,
    get membershipActive() { return membershipActive; },
    set membershipActive(value: boolean) { membershipActive = value; },
    get preflightCalls() { return preflightCalls; },
    get materializerCalls() { return materializerCalls; },
    get workerCalls() { return workerCalls; },
    get artifactReadCalls() { return artifactReadCalls; },
    setClock(value: string) { currentTime = value; },
    close() {
      securityState.close();
      control.close();
      state.close();
      jobs.close();
    }
  };
}

function authorizedFixture(
  principalContext: VerifiedPrincipalContext,
  decision: PermitPolicyDecision,
  plan: PortfolioSurveillanceExecutionPlanV1
): AuthorizedPortfolioSurveillancePreflightV1 {
  const preflight = createPortfolioSurveillanceAuthorizationPreflightV4({
    contractVersion: 1,
    operation: "portfolio_surveillance_v1",
    tenantId: TENANT,
    purpose: PURPOSE,
    descriptor: portfolioSurveillanceDescriptorBindingV4(),
    requestHash: plan.requestHash,
    datasetId: DATASET,
    scopeHash: canonicalHash(plan.sourceLineage[0]!.scope),
    sourceIdentityHash: canonicalHash(
      plan.sourceLineage.map(({ datasetId, source, scope }) => ({ datasetId, source, scope }))
    ),
    sourceSelectionHash: plan.governanceBindings!.sourceSelectionHash,
    sourceAccessPolicySetHash: plan.governanceBindings!.sourceAccessPolicySetHash,
    datasetScopeBindingSetHash: plan.governanceBindings!.datasetScopeBindingSetHash,
    definitionSetHash: plan.definitionSetHash,
    requestedFields: [...plan.requestedFields],
    requestedFieldsHash: plan.requestedFieldsHash,
    planningCutoff: CUTOFF,
    maximumPlannedCells: 1_000,
    minimumMetricCellCount: 1
  });
  const authorization = {
    decisionId: decision.decisionId,
    policyId: decision.policyId,
    policyVersion: decision.policyVersion,
    policyFingerprint: decision.policyFingerprint,
    principalBinding: decision.principalBinding,
    tenantId: decision.tenantId,
    principalId: principalContext.principalId,
    toolName: decision.toolName,
    datasetId: decision.datasetId,
    requestedFields: [...decision.requestedFields],
    purpose: PURPOSE,
    evaluatedAtEpochSeconds: decision.evaluatedAtEpochSeconds,
    matchedRuleIds: [...decision.matchedRuleIds],
    obligations: decision.obligations
  };
  const body = {
    contractVersion: 1 as const,
    operation: "portfolio_surveillance_v1" as const,
    request: REQUEST,
    requestHash: plan.requestHash,
    planningCutoff: CUTOFF,
    tenantId: TENANT,
    purpose: PURPOSE,
    publications: [],
    sourceSelectionHash: plan.governanceBindings!.sourceSelectionHash,
    sourceIdentityHash: preflight.sourceIdentityHash,
    datasetId: DATASET,
    scopeHash: preflight.scopeHash,
    sourceAccessPolicies: [...plan.governanceBindings!.sourceAccessPolicies],
    sourceAccessPolicySetHash: plan.governanceBindings!.sourceAccessPolicySetHash,
    datasetScopeBindings: [...plan.governanceBindings!.datasetScopeBindings],
    datasetScopeBindingSetHash: plan.governanceBindings!.datasetScopeBindingSetHash,
    definitions: plan.definitionLineage,
    definitionSetHash: plan.definitionSetHash,
    requestedFields: [...plan.requestedFields],
    requestedFieldsHash: plan.requestedFieldsHash,
    requestedAggregateDimensionFields: [],
    maximumPlannedCells: 1_000,
    maximumDisclosedItems: 1_005,
    minimumMetricCellCount: 1,
    authorization,
    v4Preflight: preflight
  };
  return {
    metadata: { ...body, metadataHash: canonicalHash(body) },
    permit: decision
  } as AuthorizedPortfolioSurveillancePreflightV1;
}

function policyFixture(denyAnalysis: boolean): CompiledAuthorizationPolicy {
  const obligations = {
    maxResultRows: 5_000,
    maxResultBytes: 5_000_000,
    maxExecutionMs: 10_000,
    minimumCohortSize: 1,
    requireImmutableSnapshot: true,
    allowRawRows: false,
    allowExport: false,
    rowFilterRefs: [],
    fieldMasks: {},
    auditTags: ["governed-analysis"]
  };
  const document: AuthorizationPolicyDocument = {
    id: "portfolio-policy",
    version: "1.0.0",
    defaultObligations: obligations,
    rules: [{
      id: denyAnalysis ? "deny-analysis" : "permit-analysis",
      effect: denyAnalysis ? "deny" : "permit",
      tenantIds: [TENANT],
      tools: ["abl_run_portfolio_surveillance"],
      datasets: [DATASET],
      purposes: [PURPOSE],
      fields: ["*"]
    }, ...(denyAnalysis ? [] : [{
      id: "permit-actions",
      effect: "permit" as const,
      tenantIds: [TENANT],
      tools: ["job.status", "job.result", "job.cancel"],
      datasets: [DATASET],
      purposes: [PURPOSE],
      fields: ["*"]
    }])]
  };
  return compileAuthorizationPolicy(document);
}

function principal(principalId = "risk-analyst"): VerifiedPrincipalContext {
  return createVerifiedPrincipalContext({
    issuer: "https://identity.example.test",
    subject: principalId,
    principalId,
    tenantId: TENANT,
    clientId: "codex-client",
    audiences: ["abl-api"],
    resourceIndicators: ["https://mcp.example.test/mcp"],
    scopes: ["analysis:run"],
    credentialFingerprint: bare(canonicalHash(`credential:${principalId}`)),
    verifiedAtEpochSeconds: Math.floor(Date.parse(CUTOFF) / 1_000) - 60,
    expiresAtEpochSeconds: Math.floor(Date.parse(CUTOFF) / 1_000) + 3_600,
    authenticationMethods: ["mfa"]
  });
}

function startInput(idempotencyKey: string) {
  return {
    operation: "portfolio_surveillance_v1" as const,
    operationRequest: REQUEST,
    idempotencyKey,
    purpose: PURPOSE
  };
}

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "abl-v4-workflow-"));
  DIRECTORIES.push(directory);
  return directory;
}

function canonicalPrincipalBinding(principalContext: VerifiedPrincipalContext): string {
  // Kept local so the assertion does not accidentally rely on job ids or handles.
  const identity = JSON.stringify({
    audiences: principalContext.audiences,
    clientId: principalContext.clientId ?? null,
    issuer: principalContext.issuer,
    principalId: principalContext.principalId,
    resourceIndicators: principalContext.resourceIndicators,
    subject: principalContext.subject,
    tenantId: principalContext.tenantId
  });
  return bare(canonicalHash(JSON.parse(identity)));
}

function hasCode(code: string): (error: unknown) => boolean {
  return (error) =>
    error instanceof PortfolioSurveillanceWorkflowV4Error && error.code === code;
}

const SOURCE_ACCESS_POLICIES = [{
  definitionVersionId: "source-policy-v1",
  definitionKey: "portfolio-risk-read",
  semanticVersion: "1.0.0",
  versionHash: hash("source-policy-version"),
  documentHash: hash("source-policy-document"),
  approvalEventHash: hash("source-policy-approval"),
  executionDocumentHash: hash("source-policy-execution"),
  policyId: "portfolio-risk-read",
  revision: 1,
  policyHash: hash("source-policy"),
  effectiveFrom: "2026-01-01",
  effectiveTo: null
}] as const;
const DATASET_SCOPE_BINDINGS = [{
  definitionVersionId: "dataset-binding-v1",
  definitionKey: "loan-tape-binding",
  semanticVersion: "1.0.0",
  versionHash: hash("dataset-binding-version"),
  documentHash: hash("dataset-binding-document"),
  approvalEventHash: hash("dataset-binding-approval"),
  executionDocumentHash: hash("dataset-binding-execution"),
  bindingId: "loan-tape-binding",
  revision: 1,
  bindingHash: hash("dataset-binding"),
  effectiveFrom: "2026-01-01",
  effectiveTo: null
}] as const;

async function planFixture(purpose: string): Promise<PortfolioSurveillanceExecutionPlanV1> {
  const authority = new FixtureAuthority([
    certifiedMaterial("cert-jan", "snapshot-jan", "2026-01-31", "100", purpose),
    certifiedMaterial("cert-feb", "snapshot-feb", "2026-02-28", "120", purpose)
  ]);
  const legacy = await preparePortfolioSurveillanceExecutionPlanV1(
    REQUEST,
    { tenantId: TENANT, purpose },
    authority
  );
  const sourceIdentityHash = canonicalHash(
    legacy.sourceLineage.map(({ datasetId, source, scope }) => ({ datasetId, source, scope }))
  );
  const sourceSelectionHash = canonicalHash({ cutoff: CUTOFF, sources: REQUEST.sources });
  const preflight = createPortfolioSurveillanceAuthorizationPreflightV4({
    contractVersion: 1,
    operation: "portfolio_surveillance_v1",
    tenantId: TENANT,
    purpose,
    descriptor: portfolioSurveillanceDescriptorBindingV4(),
    requestHash: legacy.requestHash,
    datasetId: DATASET,
    scopeHash: canonicalHash(legacy.sourceLineage[0]!.scope),
    sourceIdentityHash,
    sourceSelectionHash,
    sourceAccessPolicySetHash: canonicalHash(SOURCE_ACCESS_POLICIES),
    datasetScopeBindingSetHash: canonicalHash(DATASET_SCOPE_BINDINGS),
    definitionSetHash: legacy.definitionSetHash,
    requestedFields: [...legacy.requestedFields],
    requestedFieldsHash: legacy.requestedFieldsHash,
    planningCutoff: CUTOFF,
    maximumPlannedCells: 1_000,
    minimumMetricCellCount: 1
  });
  return bindPortfolioSurveillanceGovernanceV1(legacy, {
    metadataHash: canonicalHash("complete-preflight"),
    preflightHash: preflight.preflightHash,
    sourceSelectionHash,
    sourceIdentityHash,
    sourceAccessPolicies: [...SOURCE_ACCESS_POLICIES],
    sourceAccessPolicySetHash: canonicalHash(SOURCE_ACCESS_POLICIES),
    datasetScopeBindings: [...DATASET_SCOPE_BINDINGS],
    datasetScopeBindingSetHash: canonicalHash(DATASET_SCOPE_BINDINGS)
  });
}

function certifiedMaterial(
  certificationManifestId: string,
  snapshotId: string,
  asOfDate: string,
  outstanding: string,
  purpose: string
): CertifiedSnapshotMaterialV1 {
  const records = [{
    as_of_date: asOfDate,
    source_system: "core",
    facility_id: "facility-a",
    loan_id: "loan-1",
    outstanding_balance: outstanding,
    original_balance: "150",
    commitment_amount: "200"
  }];
  return createCertifiedSnapshotMaterialV1({
    contractVersion: 1,
    tenantId: TENANT,
    datasetId: DATASET,
    source: {
      sourceContractId: "loan-source-v1",
      sourceKey: "loan-source",
      revision: 1,
      sourceContractHash: hash("source-contract")
    },
    scope: { scopeType: "portfolio", scopeId: "portfolio-a" },
    authorizedPurpose: purpose,
    authorizedFields: [...REQUESTED_FIELDS],
    authorizedAggregateDimensionFields: [],
    certificationManifestId,
    certificationManifestHash: hash(`manifest:${certificationManifestId}`),
    populationHash: canonicalHash(records),
    normalizedArtifact: {
      artifactId: `artifact-${snapshotId}`,
      contentHash: hash(`artifact-content:${snapshotId}`)
    },
    rowCount: records.length,
    snapshot: {
      schemaVersion: "1",
      snapshotId,
      tenantId: TENANT,
      asOfDate,
      snapshotHash: hash(`snapshot:${snapshotId}`),
      certification: {
        status: "certified",
        certificationId: certificationManifestId,
        certificationHash: hash(`manifest:${certificationManifestId}`),
        certifiedAt: "2026-08-10T12:00:00.000Z"
      },
      records
    }
  });
}

class FixtureAuthority implements PortfolioSurveillanceOperationAuthorityV1 {
  readonly #materials = new Map<string, CertifiedSnapshotMaterialV1>();
  readonly #definitions = new Map<string, ResolvedGovernedDefinitionV2>([
    [METHODOLOGY.reference.definitionVersionId, METHODOLOGY],
    [METRIC.reference.definitionVersionId, METRIC]
  ]);

  constructor(materials: readonly CertifiedSnapshotMaterialV1[]) {
    for (const material of materials) this.#materials.set(material.certificationManifestId, material);
  }

  loadLongitudinalBundle(): undefined { return undefined; }

  loadCertifiedSnapshot(input: PortfolioSurveillanceSnapshotLoadRequestV1): unknown | undefined {
    return input.tenantId === TENANT
      ? this.#materials.get(input.certificationManifestId)
      : undefined;
  }

  resolveFrozenDefinition(
    tenantId: string,
    definitionVersionId: string
  ): ResolvedGovernedDefinitionV2 | undefined {
    return tenantId === TENANT ? this.#definitions.get(definitionVersionId) : undefined;
  }
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
    runtimeBundleHash: hash("surveillance-runtime")
  },
  requiredDefinitionKinds: ["metric_definition"],
  deterministicParameters: { maximumPeriods: 120 },
  approval: { status: "pending_durable_approval", authority: "governed_definition_v2_lifecycle" }
} as const;
const METRIC_DOCUMENT = {
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
    approvedAt: "2026-08-01T12:00:00.000Z"
  }
} as const;
const METHODOLOGY = resolvedDefinition(
  "methodology-v1",
  "methodology_bundle",
  "portfolio-surveillance",
  METHODOLOGY_DOCUMENT
);
const METRIC = resolvedDefinition(
  "metric-balance-v1",
  "metric_definition",
  "balance-utilization",
  METRIC_DOCUMENT
);

function resolvedDefinition(
  definitionVersionId: string,
  kind: "methodology_bundle" | "metric_definition",
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
      approvedAt: "2026-08-01T12:00:00.000Z",
      approvalEventHash
    },
    executionDocument
  };
}

function hash(value: string): Sha256Hash { return canonicalHash(value); }
function bare(value: string): string { return value.slice("sha256:".length); }
