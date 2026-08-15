import { Buffer } from "node:buffer";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { Worker } from "node:worker_threads";

import {
  canonicalHash,
  canonicalJson,
  type CanonicalJsonValue,
  type Sha256Hash
} from "../contracts/index.js";
import {
  artifactJsonContentHash,
  type ArtifactStore,
  type StoredArtifact
} from "../control/artifacts.js";
import { JobStoreError, type ClaimedJob, type JobRecord, type JobStore } from "../control/jobs.js";
import type { ControlStore, JsonValue } from "../control/store.js";
import {
  GOVERNED_ANALYSIS_RESULT_V4_KIND,
  GOVERNED_EXECUTION_ENVELOPE_V4_KIND,
  GOVERNED_RESULT_MANIFEST_V4_KIND,
  PORTFOLIO_SURVEILLANCE_V4_JOB_KIND,
  PortfolioSurveillanceV4StateStoreError,
  type PortfolioSurveillanceV4AuditPointerV1,
  type PortfolioSurveillanceV4AttemptFenceV1,
  type PortfolioSurveillanceV4JobStateV1,
  type PortfolioSurveillanceV4ManifestArtifactPointerV1,
  type PortfolioSurveillanceV4ResultArtifactPointerV1,
  type SqlitePortfolioSurveillanceV4StateStore
} from "../repositories/sqlite-portfolio-surveillance-v4-state.js";
import {
  assertActivePrincipal,
  assertVerifiedPrincipalContext,
  createVerifiedPrincipalContext,
  principalBinding,
  type VerifiedIdentityAttestation,
  type VerifiedPrincipalContext
} from "../security/identity.js";
import type { TenantMembershipResolver } from "../security/oauth.js";
import {
  assertPermitDecision,
  evaluatePolicy,
  type CompiledAuthorizationPolicy,
  type PermitPolicyDecision,
  type PolicyDecision,
  type PolicyObligations
} from "../security/policy.js";
import {
  issueExecutionPlan,
  issuePrincipalBoundHandle,
  SignedArtifactError,
  verifyExecutionPlan,
  verifyPrincipalBoundHandle,
  type HmacKeyRing
} from "../security/signed-plan.js";
import { SecurityStateStoreError, type SecurityStateStore } from "../security/state-store.js";
import { MCP_SERVER_NAME, MCP_SERVER_VERSION } from "../product.js";
import { modernMcpSuccessResultByteLength } from "../transports/mcp-result-envelope.js";
import {
  assertGovernedResultArtifactV4EvidenceMatchesEnvelope,
  assertGovernedResultManifestV4Creator,
  assertGovernedResultManifestV4MatchesResult,
  createGovernedExecutionEnvelopeV4,
  finalizeGovernedResultArtifactV4,
  finalizeGovernedResultManifestV4,
  parseGovernedExecutionEnvelopeV4,
  parseGovernedResultArtifactV4Structure,
  parseGovernedResultManifestV4Structure,
  portfolioSurveillanceDescriptorBindingV4,
  type GovernedExecutionAuthorizationV4,
  type GovernedExecutionEnvelopeV4,
  type GovernedResultArtifactV4,
  type GovernedResultManifestV4
} from "./governed-operation-v4.js";
import {
  parsePortfolioSurveillanceExecutionPlanV1,
  type PortfolioSurveillanceExecutionPlanV1,
  type PortfolioSurveillanceOperationRequestV1
} from "./operations/portfolio-surveillance-v1.js";
import type { PortfolioSurveillanceWorkerMessageV4 } from "./portfolio-surveillance-worker-v4.js";
import {
  parsePortfolioSurveillanceAuthorizationRequestV1,
  type AuthorizedPortfolioSurveillancePreflightV1,
  type PortfolioSurveillanceAuthorizationPreflightServiceV1
} from "./surveillance-access-preflight.js";
import type {
  PortfolioSurveillancePlanMaterializationResultV1,
  PortfolioSurveillancePlanMaterializerV1
} from "./surveillance-materializer.js";

const OPERATION = "portfolio_surveillance_v1" as const;
const ANALYSIS_TOOL = "abl_run_portfolio_surveillance" as const;
const JSON_MEDIA_TYPE = "application/json" as const;

export const PORTFOLIO_SURVEILLANCE_V4_WORKER_RESOURCE_LIMITS = Object.freeze({
  maxOldGenerationSizeMb: 256,
  maxYoungGenerationSizeMb: 64,
  stackSizeMb: 8
});

export interface StartPortfolioSurveillanceJobV4Input {
  readonly operation: typeof OPERATION;
  readonly operationRequest: PortfolioSurveillanceOperationRequestV1;
  readonly idempotencyKey: string;
  readonly purpose: string;
}

export interface PortfolioSurveillanceMutationRequestContextV4 {
  readonly requestStartedAtMonotonicMs: number;
}

export interface StartedPortfolioSurveillanceJobV4 {
  readonly jobHandle: string;
  readonly status: JobRecord["status"];
  readonly operation: typeof OPERATION;
}

export interface PortfolioSurveillanceJobStatusViewV4 {
  readonly operation: typeof OPERATION;
  readonly status: JobRecord["status"];
  readonly durableStatus: PortfolioSurveillanceV4JobStateV1["status"];
  readonly attemptCount: number;
  readonly maxAttempts: number;
  readonly cancellationRequested: boolean;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly errorCode: string | null;
  readonly resultAvailable: boolean;
}

export interface PortfolioSurveillanceJobResultViewV4 {
  readonly operation: typeof OPERATION;
  readonly manifestId: string;
  readonly artifactId: string;
  readonly resultHash: Sha256Hash;
  readonly result: CanonicalJsonValue;
}

export interface PortfolioSurveillanceAuthorizedResponseV4<T> {
  readonly value: T;
  readonly obligations: readonly PolicyObligations[];
}

export interface ProcessedPortfolioSurveillanceJobV4 {
  readonly operation: typeof OPERATION;
  readonly status: "succeeded" | "failed" | "cancelled";
  readonly errorCode: string | null;
}

export interface PortfolioSurveillanceWorkerExecutionContextV4 {
  readonly maximumExecutionMs: number;
}

export type PortfolioSurveillanceWorkerExecutorV4 = (
  plan: PortfolioSurveillanceExecutionPlanV1,
  context: PortfolioSurveillanceWorkerExecutionContextV4
) => Promise<unknown>;

export interface PortfolioSurveillanceWorkflowV4Services {
  readonly preflight: Pick<PortfolioSurveillanceAuthorizationPreflightServiceV1, "authorize">;
  readonly materializer: Pick<PortfolioSurveillancePlanMaterializerV1, "materialize">;
  readonly state: SqlitePortfolioSurveillanceV4StateStore;
  readonly control: Pick<ControlStore, "appendAuditEvent" | "listAuditEvents">;
  readonly artifacts: Pick<ArtifactStore, "getJson" | "putJson">;
  /** Use a dedicated v4 queue database; JobStore does not expose a tool-filtered claim. */
  readonly jobs: JobStore;
  readonly securityState: SecurityStateStore;
  readonly tenantMembershipResolver: TenantMembershipResolver;
  readonly policy: CompiledAuthorizationPolicy;
  readonly keyRing: HmacKeyRing;
  /** Test seam. Production leaves this absent so execution uses a bounded worker thread. */
  readonly workerExecutor?: PortfolioSurveillanceWorkerExecutorV4;
}

export interface PortfolioSurveillanceWorkflowV4Options {
  readonly codeVersion: string;
  readonly clock?: () => Date;
  readonly defaultPlanTtlSeconds?: number;
  readonly defaultHandleTtlSeconds?: number;
  readonly workerLeaseSeconds?: number;
  readonly maxAttempts?: number;
  /** Test-only crash seam; production composition must leave this absent. */
  readonly faultInjector?: (point: PortfolioSurveillanceWorkflowV4FaultPoint) => boolean;
}

export type PortfolioSurveillanceWorkflowV4FaultPoint =
  | "after_submission_state"
  | "after_result_state"
  | "after_manifest_state"
  | "after_completion_preparation"
  | "after_queue_completion";

export type PortfolioSurveillanceWorkflowV4ErrorCode =
  | "INVALID_INPUT"
  | "POLICY_DENIED"
  | "AUTHORIZATION_UNAVAILABLE"
  | "AUDIT_REQUIRED"
  | "IDEMPOTENCY_CONFLICT"
  | "RESULT_NOT_READY"
  | "RESULT_TOO_LARGE"
  | "EXECUTION_TIMEOUT"
  | "CANCELLED"
  | "INTEGRITY_FAILURE"
  | "EXECUTION_FAILED";

export class PortfolioSurveillanceWorkflowV4Error extends Error {
  constructor(
    readonly code: PortfolioSurveillanceWorkflowV4ErrorCode,
    message: string
  ) {
    super(message);
    this.name = "PortfolioSurveillanceWorkflowV4Error";
  }
}

class PortfolioSurveillanceWorkflowV4InjectedCrash extends Error {
  constructor(readonly point: PortfolioSurveillanceWorkflowV4FaultPoint) {
    super(`Injected v4 workflow crash at ${point}`);
    this.name = "PortfolioSurveillanceWorkflowV4InjectedCrash";
  }
}

interface AuthorizedJobAccessV4 {
  readonly job: JobRecord;
  readonly state: PortfolioSurveillanceV4JobStateV1;
  readonly envelope: GovernedExecutionEnvelopeV4;
  readonly analysisDecision: PermitPolicyDecision;
  readonly actionDecision: PermitPolicyDecision;
}

interface VerifiedDurableOutputV4 {
  readonly result: GovernedResultArtifactV4;
  readonly resultPointer: PortfolioSurveillanceV4ResultArtifactPointerV1;
  readonly manifest?: GovernedResultManifestV4;
  readonly manifestPointer?: PortfolioSurveillanceV4ManifestArtifactPointerV1;
}

/**
 * Dedicated durable workflow for the v4 portfolio-surveillance operation.
 * It is intentionally not wired into the legacy dispatcher: production can
 * expose it only after composing the new publication/preflight authorities.
 */
export class PortfolioSurveillanceWorkflowV4 {
  readonly #services: PortfolioSurveillanceWorkflowV4Services;
  readonly #codeVersion: string;
  readonly #clock: () => Date;
  readonly #defaultPlanTtlSeconds: number;
  readonly #defaultHandleTtlSeconds: number;
  readonly #workerLeaseSeconds: number;
  readonly #maxAttempts: number;
  readonly #faultInjector:
    | ((point: PortfolioSurveillanceWorkflowV4FaultPoint) => boolean)
    | undefined;

  constructor(
    services: PortfolioSurveillanceWorkflowV4Services,
    options: PortfolioSurveillanceWorkflowV4Options
  ) {
    if (
      !services.tenantMembershipResolver ||
      typeof services.tenantMembershipResolver.resolveTenantMembership !== "function"
    ) {
      fail("INVALID_INPUT", "A trusted tenant membership resolver is required");
    }
    this.#services = services;
    this.#codeVersion = identifier(options.codeVersion, "codeVersion");
    this.#clock = options.clock ?? (() => new Date());
    this.#defaultPlanTtlSeconds = boundedInteger(
      options.defaultPlanTtlSeconds ?? 300,
      "defaultPlanTtlSeconds",
      1,
      900
    );
    this.#defaultHandleTtlSeconds = boundedInteger(
      options.defaultHandleTtlSeconds ?? 3_600,
      "defaultHandleTtlSeconds",
      1,
      604_800
    );
    this.#workerLeaseSeconds = boundedInteger(
      options.workerLeaseSeconds ?? 300,
      "workerLeaseSeconds",
      5,
      3_600
    );
    this.#maxAttempts = boundedInteger(options.maxAttempts ?? 3, "maxAttempts", 1, 10);
    this.#faultInjector = options.faultInjector;
    if (
      this.#workerLeaseSeconds * 1_000 <=
      services.policy.defaultObligations.maxExecutionMs + 5_000
    ) {
      fail(
        "INVALID_INPUT",
        "Worker lease must exceed the maximum policy execution time plus finalization margin"
      );
    }
  }

  async startPortfolioSurveillanceAuthorized(
    principal: VerifiedPrincipalContext,
    inputValue: StartPortfolioSurveillanceJobV4Input,
    requestContext?: PortfolioSurveillanceMutationRequestContextV4
  ): Promise<PortfolioSurveillanceAuthorizedResponseV4<StartedPortfolioSurveillanceJobV4>> {
    const requestStartedAt = mutationRequestStartedAt(requestContext);
    assertVerifiedPrincipalContext(principal);
    const input = parseStartInput(inputValue);
    const nowEpochSeconds = this.#nowEpochSeconds();
    assertActivePrincipal(principal, nowEpochSeconds, 0);
    await this.#assertCurrentMembership(principal);
    const requester = principalBinding(principal);
    const operationRequest = parsePortfolioSurveillanceAuthorizationRequestV1(
      input.operationRequest
    );
    const planTtlSeconds = this.#defaultPlanTtlSeconds;
    const startRequestHash = canonicalHash({
      contractVersion: 1,
      operation: OPERATION,
      operationRequest,
      purpose: input.purpose,
      planTtlSeconds
    });
    const startFingerprint = bareHash(startRequestHash);
    const idempotencyFingerprint = sha256Text(input.idempotencyKey);

    const replay = this.#services.state.getIdempotencyReceipt(
      principal.tenantId,
      requester,
      input.idempotencyKey
    );
    if (replay) {
      if (replay.requestHash !== startRequestHash) {
        fail("IDEMPOTENCY_CONFLICT", "Idempotency key is already bound to another request");
      }
      return await this.#resumeIdempotentStart(
        principal,
        input,
        replay.jobId,
        startFingerprint,
        requestStartedAt
      );
    }

    const planningCutoff = this.#nowIso();
    let authorized: AuthorizedPortfolioSurveillancePreflightV1;
    try {
      authorized = await this.#services.preflight.authorize(operationRequest, {
        principal,
        purpose: input.purpose,
        planningCutoff
      });
    } catch (error) {
      this.#recordPreflightDenial(principal, startRequestHash, error);
      throw normalizeStartError(error);
    }
    const startPermitAudit = this.#recordPolicyDecision(
      authorized.permit,
      "start_preflight",
      startRequestHash
    );
    assertAggregateOnlyObligations(authorized.permit.obligations);
    assertPreCommitDeadline(requestStartedAt, authorized.permit.obligations.maxExecutionMs);

    let materialized: PortfolioSurveillancePlanMaterializationResultV1;
    try {
      materialized = await this.#services.materializer.materialize(
        authorized,
        operationRequest
      );
    } catch {
      fail("INTEGRITY_FAILURE", "Authorized surveillance plan materialization failed");
    }
    if (materialized.planArtifact === null) {
      fail("INTEGRITY_FAILURE", "Durable v4 execution requires an exact plan artifact");
    }
    const plan = parsePortfolioSurveillanceExecutionPlanV1(materialized.plan);
    const planArtifact = materialized.planArtifact;
    const metadata = authorized.metadata;
    const envelope = createGovernedExecutionEnvelopeV4({
      version: 4,
      operation: OPERATION,
      tenantId: principal.tenantId,
      purpose: input.purpose,
      identity: persistedIdentity(principal),
      descriptor: portfolioSurveillanceDescriptorBindingV4(),
      preflight: metadata.v4Preflight,
      planArtifact,
      requestHash: plan.requestHash,
      planHash: plan.planHash,
      sourceSelectionHash: metadata.sourceSelectionHash,
      sourceIdentityHash: metadata.sourceIdentityHash,
      sourceAccessPolicySetHash: metadata.sourceAccessPolicySetHash,
      datasetScopeBindingSetHash: metadata.datasetScopeBindingSetHash,
      sourceSetHash: plan.sourceSetHash,
      definitionSetHash: plan.definitionSetHash,
      requestedFields: [...plan.requestedFields],
      requestedFieldsHash: plan.requestedFieldsHash,
      datasetId: metadata.datasetId,
      scopeHash: metadata.scopeHash,
      planningCutoff,
      planTtlSeconds,
      startAuthorization: executionDecisionProjection(
        authorized.permit,
        principal.principalId,
        input.purpose
      ),
      parameterFingerprint: bareHash(plan.planHash),
      idempotencyFingerprint,
      startFingerprint
    });
    assertPreCommitDeadline(requestStartedAt, authorized.permit.obligations.maxExecutionMs);
    const envelopeStored = this.#putExactArtifact(
      principal.tenantId,
      GOVERNED_EXECUTION_ENVELOPE_V4_KIND,
      envelope
    );
    const proposedJobId = randomUUID();
    let submission;
    try {
      submission = this.#services.state.recordSubmission({
        tenantId: principal.tenantId,
        jobId: proposedJobId,
        requestedBy: requester,
        idempotencyKey: input.idempotencyKey,
        requestHash: startRequestHash,
        startAuthorizationAudit: auditPointer(startPermitAudit),
        envelope: {
          envelopeId: envelopeStored.artifactId,
          kind: GOVERNED_EXECUTION_ENVELOPE_V4_KIND,
          mediaType: JSON_MEDIA_TYPE,
          contentHash: controlHash(envelopeStored.contentHash),
          byteLength: envelopeStored.byteLength
        },
        planArtifact
      });
      this.#injectFault("after_submission_state");
    } catch (error) {
      if (
        error instanceof PortfolioSurveillanceV4StateStoreError &&
        error.code === "IDEMPOTENCY_CONFLICT"
      ) {
        return await this.#resumeIdempotentStart(
          principal,
          input,
          this.#requiredIdempotencyJobId(principal, input.idempotencyKey),
          startFingerprint,
          requestStartedAt
        );
      }
      throw error;
    }
    const submissionAudit = this.#recordSubmissionAuthorization(
      submission.state,
      envelope,
      authorized.permit.decisionId
    );
    this.#services.state.recordSubmissionAuthorization({
      tenantId: submission.state.submission.tenantId,
      jobId: submission.state.submission.jobId,
      actorId: submission.state.submission.requestedBy,
      authorizationAudit: auditPointer(submissionAudit)
    });
    assertPreCommitDeadline(requestStartedAt, authorized.permit.obligations.maxExecutionMs);
    const job = this.#ensureQueuedSubmission(
      submission.state,
      envelope,
      input.idempotencyKey
    );
    this.#recordStarted(job, envelope);
    return authorizedResponse(
      this.#issueJobHandle(principal, job, nowEpochSeconds),
      authorized.permit.obligations
    );
  }

  async getPortfolioSurveillanceJobStatusAuthorized(
    principal: VerifiedPrincipalContext,
    jobHandle: string
  ): Promise<PortfolioSurveillanceAuthorizedResponseV4<PortfolioSurveillanceJobStatusViewV4>> {
    const authorized = await this.#resolveAuthorizedJob(principal, jobHandle, "job.status");
    return authorizedResponse(
      publicJobStatus(authorized.job, authorized.state),
      authorized.analysisDecision.obligations,
      authorized.actionDecision.obligations
    );
  }

  async getPortfolioSurveillanceJobResultAuthorized(
    principal: VerifiedPrincipalContext,
    jobHandle: string
  ): Promise<PortfolioSurveillanceAuthorizedResponseV4<PortfolioSurveillanceJobResultViewV4>> {
    const authorized = await this.#resolveAuthorizedJob(principal, jobHandle, "job.result");
    if (authorized.job.status !== "succeeded" || !authorized.job.resultHandle) {
      fail("RESULT_NOT_READY", "Job result is not available");
    }
    const plan = this.#loadExactPlan(authorized.job.tenantId, authorized.envelope);
    const durable = this.#loadDurableOutput(
      authorized.job,
      authorized.state,
      authorized.envelope,
      plan,
      true
    );
    if (!durable?.manifest || !durable.manifestPointer) {
      fail("RESULT_NOT_READY", "Job result manifest is not available");
    }
    this.#verifyPersistedResultHandle(
      principal,
      authorized.job.resultHandle,
      durable.resultPointer.artifactId
    );
    const view = resultView(durable.result, durable.resultPointer.artifactId);
    assertCurrentDisclosure(
      durable.result,
      plan,
      view,
      authorized.analysisDecision,
      authorized.actionDecision
    );
    return authorizedResponse(
      view,
      authorized.analysisDecision.obligations,
      authorized.actionDecision.obligations
    );
  }

  async cancelPortfolioSurveillanceJobAuthorized(
    principal: VerifiedPrincipalContext,
    jobHandle: string,
    requestContext?: PortfolioSurveillanceMutationRequestContextV4
  ): Promise<PortfolioSurveillanceAuthorizedResponseV4<PortfolioSurveillanceJobStatusViewV4>> {
    const requestStartedAt = mutationRequestStartedAt(requestContext);
    const authorized = await this.#resolveAuthorizedJob(principal, jobHandle, "job.cancel");
    assertPreCommitDeadline(
      requestStartedAt,
      Math.min(
        authorized.analysisDecision.obligations.maxExecutionMs,
        authorized.actionDecision.obligations.maxExecutionMs
      )
    );
    const actor = principalBinding(principal);
    const job = this.#services.jobs.requestCancellation(
      principal.tenantId,
      authorized.job.jobId,
      actor
    );
    let state = authorized.state;
    if (
      job.status === "cancelled" &&
      state.status !== "cancelled" &&
      state.status !== "failed" &&
      state.status !== "completed"
    ) {
      state = this.#services.state.recordCancellation({
        tenantId: job.tenantId,
        jobId: job.jobId,
        actorId: actor,
        reasonCode: "user_requested"
      }).state;
    }
    this.#appendAudit({
      tenantId: job.tenantId,
      eventType: "portfolio_surveillance_v4.cancellation_requested",
      entityType: "job",
      entityId: job.jobId,
      actor,
      details: { cancellationRequested: true },
      idempotencyKey: auditKey("cancel", job.jobId)
    });
    return authorizedResponse(
      publicJobStatus(job, state),
      authorized.analysisDecision.obligations,
      authorized.actionDecision.obligations
    );
  }

  async processNext(
    tenantIdValue: string,
    workerIdValue: string
  ): Promise<ProcessedPortfolioSurveillanceJobV4 | null> {
    const tenantId = identifier(tenantIdValue, "tenantId");
    const workerId = identifier(workerIdValue, "workerId");
    const claimed = this.#services.jobs.claimNext({
      tenantId,
      workerId,
      leaseSeconds: this.#workerLeaseSeconds
    });
    if (!claimed) return null;
    const fence = attemptFence(claimed, workerId);
    let durableEvidenceExists = false;
    try {
      if (claimed.toolName !== ANALYSIS_TOOL || claimed.datasetId === null) {
        fail("INTEGRITY_FAILURE", "Dedicated v4 queue contained an unexpected operation");
      }
      const envelope = parseGovernedExecutionEnvelopeV4(claimed.request);
      const state = this.#requiredState(tenantId, claimed.jobId);
      this.#assertJobSubmission(claimed, state, envelope);
      this.#assertSubmissionAuthorization(claimed, state, envelope);
      const principal = rehydrateIdentity(envelope.identity);
      assertActivePrincipal(principal, this.#nowEpochSeconds(), 0);
      await this.#assertCurrentMembership(principal);
      const currentDecision = this.#evaluateAndAudit(
        principal,
        ANALYSIS_TOOL,
        envelope,
        "worker_claim",
        claimed.jobId,
        claimed.attemptCount
      );
      assertAggregateOnlyObligations(currentDecision.obligations);
      this.#throwIfCancelled(claimed);
      const storedEnvelope = this.#loadExactEnvelope(state);
      if (canonicalJson(storedEnvelope) !== canonicalJson(envelope)) {
        fail("INTEGRITY_FAILURE", "Queued envelope did not match durable submission evidence");
      }
      const plan = this.#loadExactPlan(tenantId, envelope);

      const recovered = this.#loadDurableOutput(
        claimed,
        state,
        envelope,
        plan,
        false
      );
      if (recovered) {
        durableEvidenceExists = true;
        if (!state.signedPlanId || !state.executionCodeVersion) {
          fail("INTEGRITY_FAILURE", "Durable result evidence is missing execution provenance");
        }
        const completed = await this.#adoptDurableOutput(
          claimed,
          principal,
          envelope,
          plan,
          currentDecision,
          recovered,
          state.signedPlanId,
          state.executionCodeVersion,
          fence,
          workerId
        );
        return { operation: OPERATION, status: "succeeded", errorCode: completed.errorCode };
      }
      if (claimed.recoveryOnly) {
        fail("EXECUTION_FAILED", "Recovery-only claim has no verified durable result evidence");
      }
      this.#assertExecutionWindow(envelope, principal);
      const signedPlan = await this.#issueAndConsumeExecutionPlan(
        principal,
        currentDecision,
        envelope,
        plan,
        claimed
      );
      this.#throwIfCancelled(claimed);
      const startedAt = this.#nowIso();
      const maximumExecutionMs = Math.min(
        envelope.startAuthorization.obligations.maxExecutionMs,
        currentDecision.obligations.maxExecutionMs,
        Math.max(1, Date.parse(envelope.planningCutoff) + envelope.planTtlSeconds * 1_000 - Date.parse(startedAt)),
        Math.max(1, envelope.identity.expiresAtEpochSeconds * 1_000 - Date.parse(startedAt))
      );
      const operationResult = await this.#executeIsolated(
        plan,
        claimed,
        workerId,
        maximumExecutionMs
      );
      this.#throwIfCancelled(claimed);
      const completedAt = this.#nowIso();
      const executionAuthorization: GovernedExecutionAuthorizationV4 = {
        decisionId: signedPlan.claims.authorizationDecisionId,
        policyFingerprint: signedPlan.claims.policyFingerprint,
        tenantId: envelope.tenantId,
        principalId: envelope.identity.principalId,
        requestedFields: [...signedPlan.claims.requestedFields],
        purpose: envelope.purpose,
        obligations: mutableObligations(signedPlan.claims.obligations),
        authorizedAt: new Date(currentDecision.evaluatedAtEpochSeconds * 1_000).toISOString(),
        startedAt,
        completedAt
      };
      const result = finalizeGovernedResultArtifactV4(
        {
          version: 4,
          jobId: claimed.jobId,
          manifestId: claimed.jobId,
          operation: OPERATION,
          tenantId,
          purpose: envelope.purpose,
          result: operationResult as CanonicalJsonValue
        },
        envelope,
        plan,
        executionAuthorization
      );
      const prospectiveView = resultView(result, "0".repeat(64));
      assertCurrentDisclosure(result, plan, prospectiveView, currentDecision, currentDecision);
      if (this.#services.jobs.get(tenantId, claimed.jobId).cancellationRequested) {
        fail("CANCELLED", "Job cancellation was requested before result commit");
      }
      const resultStored = this.#putExactArtifact(
        tenantId,
        GOVERNED_ANALYSIS_RESULT_V4_KIND,
        result
      );
      const resultPointer = resultPointerFrom(resultStored);
      this.#services.state.recordResultArtifact({
        tenantId,
        jobId: claimed.jobId,
        actorId: workerId,
        attemptFence: fence,
        signedPlanId: signedPlan.planId,
        executionCodeVersion: this.#codeVersion,
        resultArtifact: resultPointer
      });
      durableEvidenceExists = true;
      this.#injectFault("after_result_state");
      this.#throwIfCancelled(claimed);
      const manifest = deterministicManifest(
        result,
        resultPointer,
        envelope,
        this.#codeVersion
      );
      const manifestStored = this.#putExactArtifact(
        tenantId,
        GOVERNED_RESULT_MANIFEST_V4_KIND,
        manifest
      );
      const manifestPointer = manifestPointerFrom(manifestStored);
      this.#services.state.recordManifestArtifact({
        tenantId,
        jobId: claimed.jobId,
        actorId: workerId,
        attemptFence: fence,
        signedPlanId: signedPlan.planId,
        executionCodeVersion: this.#codeVersion,
        resultArtifact: resultPointer,
        manifestArtifact: manifestPointer
      });
      this.#injectFault("after_manifest_state");
      this.#throwIfCancelled(claimed);
      const resultHandle = this.#bindResultHandle(principal, resultPointer.artifactId);
      this.#services.jobs.heartbeat(
        tenantId,
        claimed.jobId,
        workerId,
        claimed.claimToken,
        this.#workerLeaseSeconds
      );
      this.#services.state.recordCompletionPreparation({
        tenantId,
        jobId: claimed.jobId,
        actorId: workerId,
        attemptFence: fence,
        signedPlanId: signedPlan.planId,
        executionCodeVersion: this.#codeVersion,
        resultArtifact: resultPointer,
        manifestArtifact: manifestPointer
      });
      this.#injectFault("after_completion_preparation");
      const completed = this.#services.jobs.complete(
        tenantId,
        claimed.jobId,
        workerId,
        claimed.claimToken,
        resultHandle
      );
      this.#injectFault("after_queue_completion");
      this.#recordQueueCompletion(
        principal,
        completed,
        result,
        resultPointer,
        manifest,
        manifestPointer,
        signedPlan.planId
      );
      return { operation: OPERATION, status: "succeeded", errorCode: completed.errorCode };
    } catch (error) {
      if (error instanceof PortfolioSurveillanceWorkflowV4InjectedCrash) throw error;
      if (durableEvidenceExists) {
        const current = this.#services.jobs.get(tenantId, claimed.jobId);
        if (current.status === "succeeded") {
          // Queue success is already immutable. A later read repairs the exact
          // completion audit/state linkage before advertising result availability.
          throw error;
        }
      }
      const code = executionErrorCode(error);
      let failed: JobRecord;
      try {
        failed = this.#services.jobs.fail(
          tenantId,
          claimed.jobId,
          workerId,
          claimed.claimToken,
          code,
          isRetryable(code),
          isRetryable(code)
            ? new Date(this.#nowDate().getTime() + 30_000).toISOString()
            : undefined
        );
      } catch (failure) {
        if (failure instanceof JobStoreError && failure.code === "CLAIM_REJECTED") {
          return { operation: OPERATION, status: "failed", errorCode: "LEASE_EXPIRED" };
        }
        throw failure;
      }
      this.#recordAttemptTerminalState(claimed, failed, fence, workerId, code);
      this.#recordFailureAudit(claimed, failed, code);
      return {
        operation: OPERATION,
        status: failed.status === "cancelled" ? "cancelled" : "failed",
        errorCode: failed.errorCode
      };
    }
  }

  async #resumeIdempotentStart(
    principal: VerifiedPrincipalContext,
    input: StartPortfolioSurveillanceJobV4Input,
    jobId: string,
    startFingerprint: string,
    requestStartedAt: number
  ): Promise<PortfolioSurveillanceAuthorizedResponseV4<StartedPortfolioSurveillanceJobV4>> {
    let state = this.#requiredState(principal.tenantId, jobId);
    const envelope = this.#loadExactEnvelope(state);
    const storedPrincipal = rehydrateIdentity(envelope.identity);
    if (
      envelope.startFingerprint !== startFingerprint ||
      envelope.purpose !== input.purpose ||
      envelope.requestHash !== canonicalHash(input.operationRequest) ||
      principalBinding(storedPrincipal) !== principalBinding(principal) ||
      state.submission.requestedBy !== principalBinding(principal)
    ) {
      fail("IDEMPOTENCY_CONFLICT", "Idempotency key is already bound to another request");
    }
    this.#assertStartAuthorizationAudit(
      {
        tenantId: state.submission.tenantId,
        jobId: state.submission.jobId,
        requestedBy: state.submission.requestedBy
      },
      state,
      envelope
    );
    const currentDecision = this.#evaluateAndAudit(
      principal,
      ANALYSIS_TOOL,
      envelope,
      "start_replay",
      jobId,
      0
    );
    assertAggregateOnlyObligations(currentDecision.obligations);
    assertPreCommitDeadline(requestStartedAt, currentDecision.obligations.maxExecutionMs);
    state = this.#ensureSubmissionAuthorization(
      {
        tenantId: state.submission.tenantId,
        jobId: state.submission.jobId,
        requestedBy: state.submission.requestedBy
      },
      state,
      envelope
    );
    const job = this.#ensureQueuedSubmission(state, envelope, input.idempotencyKey);
    this.#recordStarted(job, envelope);
    return authorizedResponse(
      this.#issueJobHandle(principal, job, this.#nowEpochSeconds()),
      currentDecision.obligations
    );
  }

  #requiredIdempotencyJobId(
    principal: VerifiedPrincipalContext,
    idempotencyKey: string
  ): string {
    const receipt = this.#services.state.getIdempotencyReceipt(
      principal.tenantId,
      principalBinding(principal),
      idempotencyKey
    );
    if (!receipt) fail("IDEMPOTENCY_CONFLICT", "Concurrent idempotent submission did not verify");
    return receipt.jobId;
  }

  #ensureQueuedSubmission(
    state: PortfolioSurveillanceV4JobStateV1,
    envelope: GovernedExecutionEnvelopeV4,
    idempotencyKey: string
  ): JobRecord {
    let job: JobRecord;
    try {
      job = this.#services.jobs.submit({
        tenantId: state.submission.tenantId,
        jobId: state.submission.jobId,
        requestedBy: state.submission.requestedBy,
        idempotencyKey,
        toolName: ANALYSIS_TOOL,
        datasetId: envelope.datasetId,
        request: asRecord(envelope),
        maxAttempts: this.#maxAttempts
      });
    } catch (error) {
      if (error instanceof JobStoreError && error.code === "IDEMPOTENCY_CONFLICT") {
        fail("IDEMPOTENCY_CONFLICT", "Queue idempotency evidence conflicted with durable state");
      }
      throw error;
    }
    this.#assertJobSubmission(job, state, envelope);
    return job;
  }

  #assertJobSubmission(
    job: Pick<JobRecord, "tenantId" | "jobId" | "requestedBy"> &
      Partial<Pick<JobRecord, "toolName" | "datasetId" | "request" | "requestHash">>,
    state: PortfolioSurveillanceV4JobStateV1,
    envelope: GovernedExecutionEnvelopeV4
  ): void {
    if (
      job.tenantId !== state.submission.tenantId ||
      job.jobId !== state.submission.jobId ||
      job.requestedBy !== state.submission.requestedBy ||
      state.submission.jobKind !== PORTFOLIO_SURVEILLANCE_V4_JOB_KIND ||
      (job.toolName !== undefined && job.toolName !== ANALYSIS_TOOL) ||
      (job.datasetId !== undefined && job.datasetId !== envelope.datasetId) ||
      (job.request !== undefined && canonicalJson(job.request) !== canonicalJson(envelope)) ||
      (job.requestHash !== undefined && job.requestHash !== artifactJsonContentHash(envelope)) ||
      state.submission.envelope.contentHash !== controlHash(artifactJsonContentHash(envelope)) ||
      canonicalJson(state.submission.planArtifact) !== canonicalJson(envelope.planArtifact)
    ) {
      fail("INTEGRITY_FAILURE", "Queue, submission, and execution-envelope identity did not verify");
    }
  }

  #loadExactEnvelope(state: PortfolioSurveillanceV4JobStateV1): GovernedExecutionEnvelopeV4 {
    const pointer = state.submission.envelope;
    const loaded = this.#getExactArtifact(
      state.submission.tenantId,
      pointer.envelopeId,
      pointer.kind,
      pointer.mediaType,
      bareHash(pointer.contentHash),
      pointer.byteLength
    );
    const envelope = parseGovernedExecutionEnvelopeV4(loaded.value);
    if (controlHash(artifactJsonContentHash(envelope)) !== pointer.contentHash) {
      fail("INTEGRITY_FAILURE", "Durable envelope hash did not match its submission pointer");
    }
    return envelope;
  }

  #loadExactPlan(
    tenantId: string,
    envelope: GovernedExecutionEnvelopeV4
  ): PortfolioSurveillanceExecutionPlanV1 {
    const reference = envelope.planArtifact;
    const loaded = this.#getExactArtifact(
      tenantId,
      reference.artifactId,
      reference.kind,
      reference.mediaType,
      reference.contentHash,
      reference.byteLength
    );
    const plan = parsePortfolioSurveillanceExecutionPlanV1(loaded.value);
    if (
      plan.planHash !== envelope.planHash ||
      plan.tenantId !== tenantId ||
      artifactJsonContentHash(plan) !== reference.contentHash ||
      Buffer.byteLength(canonicalJson(plan), "utf8") !== reference.byteLength
    ) {
      fail("INTEGRITY_FAILURE", "Frozen surveillance plan did not match its execution envelope");
    }
    return plan;
  }

  #loadDurableOutput(
    job: Pick<JobRecord, "tenantId" | "jobId" | "requestedBy">,
    state: PortfolioSurveillanceV4JobStateV1,
    envelope: GovernedExecutionEnvelopeV4,
    plan: PortfolioSurveillanceExecutionPlanV1,
    requireManifest: boolean
  ): VerifiedDurableOutputV4 | null {
    if (state.status === "submitted") return null;
    if (state.status === "cancelled" || state.status === "failed") {
      fail("INTEGRITY_FAILURE", "Terminal workflow state cannot expose durable result evidence");
    }
    const resultPointer = state.resultArtifact;
    if (!resultPointer) fail("INTEGRITY_FAILURE", "Durable result state is missing its artifact pointer");
    const loadedResult = this.#getExactArtifact(
      job.tenantId,
      resultPointer.artifactId,
      resultPointer.kind,
      resultPointer.mediaType,
      resultPointer.contentHash,
      resultPointer.byteLength
    );
    const result = parseGovernedResultArtifactV4Structure(loadedResult.value);
    try {
      assertGovernedResultArtifactV4EvidenceMatchesEnvelope(
        result,
        envelope,
        plan,
        result.authorization
      );
    } catch {
      fail("INTEGRITY_FAILURE", "Durable result artifact did not match frozen execution authority");
    }
    if (
      result.jobId !== job.jobId ||
      result.tenantId !== job.tenantId ||
      result.authorization.principalId !== envelope.identity.principalId ||
      resultPointer.contentHash !== artifactJsonContentHash(result)
    ) {
      fail("INTEGRITY_FAILURE", "Durable result artifact identity did not verify");
    }

    const manifestPointer = state.manifestArtifact;
    if (!manifestPointer) {
      if (requireManifest) {
        return { result, resultPointer };
      }
      return { result, resultPointer };
    }
    const loadedManifest = this.#getExactArtifact(
      job.tenantId,
      manifestPointer.artifactId,
      manifestPointer.kind,
      manifestPointer.mediaType,
      manifestPointer.contentHash,
      manifestPointer.byteLength
    );
    const manifest = parseGovernedResultManifestV4Structure(loadedManifest.value);
    try {
      assertGovernedResultManifestV4MatchesResult(manifest, result);
      assertGovernedResultManifestV4Creator(manifest, envelope.identity.principalId);
    } catch {
      fail("INTEGRITY_FAILURE", "Durable result manifest did not verify");
    }
    if (
      manifest.jobId !== job.jobId ||
      manifest.tenantId !== job.tenantId ||
      manifest.planId !== bareHash(envelope.planHash) ||
      manifestPointer.contentHash !== artifactJsonContentHash(manifest)
    ) {
      fail("INTEGRITY_FAILURE", "Durable result manifest identity did not verify");
    }
    return { result, resultPointer, manifest, manifestPointer };
  }

  async #adoptDurableOutput(
    claimed: ClaimedJob,
    principal: VerifiedPrincipalContext,
    envelope: GovernedExecutionEnvelopeV4,
    plan: PortfolioSurveillanceExecutionPlanV1,
    currentDecision: PermitPolicyDecision,
    durable: VerifiedDurableOutputV4,
    signedPlanId: string,
    executionCodeVersion: string,
    fence: PortfolioSurveillanceV4AttemptFenceV1,
    workerId: string
  ): Promise<JobRecord> {
    assertCurrentDisclosure(
      durable.result,
      plan,
      resultView(durable.result, durable.resultPointer.artifactId),
      currentDecision,
      currentDecision
    );
    const expectedManifest = deterministicManifest(
      durable.result,
      durable.resultPointer,
      envelope,
      executionCodeVersion
    );
    let manifest = expectedManifest;
    let manifestPointer = durable.manifestPointer;
    if (durable.manifest && manifestPointer) {
      if (canonicalJson(durable.manifest) !== canonicalJson(expectedManifest)) {
        fail("INTEGRITY_FAILURE", "Persisted manifest did not match execution provenance");
      }
      manifest = durable.manifest;
    } else {
      if (durable.manifest || manifestPointer) {
        fail("INTEGRITY_FAILURE", "Durable manifest state was only partially persisted");
      }
      const stored = this.#putExactArtifact(
        claimed.tenantId,
        GOVERNED_RESULT_MANIFEST_V4_KIND,
        manifest
      );
      manifestPointer = manifestPointerFrom(stored);
      this.#services.state.recordManifestArtifact({
        tenantId: claimed.tenantId,
        jobId: claimed.jobId,
        actorId: workerId,
        attemptFence: fence,
        signedPlanId,
        executionCodeVersion,
        resultArtifact: durable.resultPointer,
        manifestArtifact: manifestPointer
      });
    }
    if (!manifestPointer) {
      fail("INTEGRITY_FAILURE", "Durable manifest pointer was not established");
    }
    this.#throwIfCancelled(claimed);
    const resultHandle = this.#bindResultHandle(principal, durable.resultPointer.artifactId);
    this.#services.jobs.heartbeat(
      claimed.tenantId,
      claimed.jobId,
      workerId,
      claimed.claimToken,
      this.#workerLeaseSeconds
    );
    this.#services.state.recordCompletionPreparation({
      tenantId: claimed.tenantId,
      jobId: claimed.jobId,
      actorId: workerId,
      attemptFence: fence,
      signedPlanId,
      executionCodeVersion,
      resultArtifact: durable.resultPointer,
      manifestArtifact: manifestPointer
    });
    const completed = this.#services.jobs.complete(
      claimed.tenantId,
      claimed.jobId,
      workerId,
      claimed.claimToken,
      resultHandle
    );
    this.#recordQueueCompletion(
      principal,
      completed,
      durable.result,
      durable.resultPointer,
      manifest,
      manifestPointer,
      signedPlanId
    );
    return completed;
  }

  async #issueAndConsumeExecutionPlan(
    principal: VerifiedPrincipalContext,
    decision: PermitPolicyDecision,
    envelope: GovernedExecutionEnvelopeV4,
    plan: PortfolioSurveillanceExecutionPlanV1,
    claimed: ClaimedJob
  ) {
    const nowEpochSeconds = this.#nowEpochSeconds();
    const deadlineEpochSeconds = Math.floor(
      (Date.parse(envelope.planningCutoff) + envelope.planTtlSeconds * 1_000) / 1_000
    );
    const remainingSeconds = Math.min(
      principal.expiresAtEpochSeconds - nowEpochSeconds,
      deadlineEpochSeconds - nowEpochSeconds,
      envelope.planTtlSeconds
    );
    if (remainingSeconds < 1) fail("EXECUTION_TIMEOUT", "Frozen execution authority expired");
    const recipeFingerprint = bareHash(canonicalHash({
      definitionSetHash: envelope.definitionSetHash,
      sourceAccessPolicySetHash: envelope.sourceAccessPolicySetHash
    }));
    const issued = issueExecutionPlan(this.#services.keyRing, {
      principal,
      authorization: decision,
      spec: {
        operation: OPERATION,
        parameterFingerprint: bareHash(plan.planHash),
        schemaFingerprint: bareHash(envelope.descriptor.executionSchemaHash),
        snapshotFingerprint: bareHash(envelope.sourceSelectionHash),
        mappingFingerprint: bareHash(envelope.datasetScopeBindingSetHash),
        recipeFingerprint
      },
      ttlSeconds: remainingSeconds,
      nowEpochSeconds,
      nonce: stateCompatibleOpaqueId()
    });
    const verified = await verifyExecutionPlan(
      this.#services.keyRing,
      issued.token,
      principal,
      this.#services.securityState,
      {
        nowEpochSeconds: this.#nowEpochSeconds(),
        clockSkewSeconds: 0,
        expected: {
          toolName: ANALYSIS_TOOL,
          datasetId: envelope.datasetId,
          operation: OPERATION,
          parameterFingerprint: bareHash(plan.planHash),
          schemaFingerprint: bareHash(envelope.descriptor.executionSchemaHash),
          policyFingerprint: this.#services.policy.fingerprint,
          snapshotFingerprint: bareHash(envelope.sourceSelectionHash)
        }
      }
    );
    if (
      verified.claims.mappingFingerprint !== bareHash(envelope.datasetScopeBindingSetHash) ||
      verified.claims.recipeFingerprint !== recipeFingerprint ||
      verified.claims.authorizationDecisionId !== decision.decisionId ||
      canonicalJson(verified.claims.requestedFields) !== canonicalJson(plan.requestedFields) ||
      claimed.datasetId !== verified.claims.datasetId
    ) {
      fail("INTEGRITY_FAILURE", "Signed execution plan did not preserve frozen v4 lineage");
    }
    return verified;
  }

  async #executeIsolated(
    plan: PortfolioSurveillanceExecutionPlanV1,
    claimed: ClaimedJob,
    workerId: string,
    maximumExecutionMs: number
  ): Promise<unknown> {
    if (!Number.isSafeInteger(maximumExecutionMs) || maximumExecutionMs < 1) {
      fail("EXECUTION_TIMEOUT", "No execution time remains");
    }
    this.#services.jobs.heartbeat(
      claimed.tenantId,
      claimed.jobId,
      workerId,
      claimed.claimToken,
      this.#workerLeaseSeconds
    );
    return await new Promise<unknown>((resolve, reject) => {
      let settled = false;
      let worker: Worker | undefined;
      const finish = (error: PortfolioSurveillanceWorkflowV4Error | null, value?: unknown): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        clearInterval(supervisor);
        if (worker) {
          worker.removeAllListeners();
          void worker.terminate();
        }
        if (error) reject(error);
        else resolve(value);
      };
      const timeout = setTimeout(
        () => finish(workflowError("EXECUTION_TIMEOUT", "Analysis execution timed out")),
        maximumExecutionMs
      );
      const supervisor = setInterval(() => {
        try {
          const job = this.#services.jobs.get(claimed.tenantId, claimed.jobId);
          if (job.cancellationRequested) {
            finish(workflowError("CANCELLED", "Job cancellation was requested"));
            return;
          }
          this.#services.jobs.heartbeat(
            claimed.tenantId,
            claimed.jobId,
            workerId,
            claimed.claimToken,
            this.#workerLeaseSeconds
          );
        } catch {
          finish(workflowError("EXECUTION_FAILED", "Execution supervisor lost its lease"));
        }
      }, Math.max(250, Math.floor((this.#workerLeaseSeconds * 1_000) / 3)));

      if (this.#services.workerExecutor) {
        void this.#services.workerExecutor(plan, { maximumExecutionMs }).then(
          (value) => finish(null, value),
          () => finish(workflowError("EXECUTION_FAILED", "Analysis worker rejected execution"))
        );
        return;
      }
      const entry = new URL(
        import.meta.url.endsWith(".ts")
          ? "./portfolio-surveillance-worker-v4.ts"
          : "./portfolio-surveillance-worker-v4.js",
        import.meta.url
      );
      worker = new Worker(entry, {
        workerData: plan,
        resourceLimits: PORTFOLIO_SURVEILLANCE_V4_WORKER_RESOURCE_LIMITS
      });
      worker.once("message", (message: PortfolioSurveillanceWorkerMessageV4 | unknown) => {
        if (!message || typeof message !== "object" || Array.isArray(message)) {
          finish(workflowError("EXECUTION_FAILED", "Analysis worker returned an invalid response"));
          return;
        }
        const response = message as Partial<PortfolioSurveillanceWorkerMessageV4>;
        if (response.ok === true && "result" in response) {
          finish(null, response.result);
          return;
        }
        finish(workflowError("EXECUTION_FAILED", "Analysis worker rejected governed input"));
      });
      worker.once("error", () =>
        finish(workflowError("EXECUTION_FAILED", "Analysis worker failed"))
      );
      worker.once("exit", (code) => {
        if (!settled && code !== 0) {
          finish(workflowError("EXECUTION_FAILED", "Analysis worker exited unexpectedly"));
        }
      });
    });
  }

  async #resolveAuthorizedJob(
    principal: VerifiedPrincipalContext,
    jobHandle: string,
    actionToolName: "job.status" | "job.result" | "job.cancel"
  ): Promise<AuthorizedJobAccessV4> {
    assertVerifiedPrincipalContext(principal);
    const job = this.#resolveJobHandle(principal, jobHandle);
    let state = this.#requiredState(principal.tenantId, job.jobId);
    const envelope = parseGovernedExecutionEnvelopeV4(job.request);
    this.#assertJobSubmission(job, state, envelope);
    this.#assertSubmissionAuthorization(job, state, envelope);
    await this.#assertCurrentMembership(principal);
    const common = {
      principal,
      dataset: { id: envelope.datasetId, tenantId: envelope.tenantId },
      fields: envelope.requestedFields,
      purpose: envelope.purpose,
      nowEpochSeconds: this.#nowEpochSeconds()
    } as const;
    const analysisDecision = evaluatePolicy(this.#services.policy, {
      ...common,
      toolName: ANALYSIS_TOOL
    });
    const actionDecision = evaluatePolicy(this.#services.policy, {
      ...common,
      toolName: actionToolName
    });
    this.#recordAccessAuthorization(job, actionToolName, analysisDecision, actionDecision);
    try {
      assertPermitDecision(analysisDecision);
      assertPermitDecision(actionDecision);
    } catch {
      fail("POLICY_DENIED", "Current policy denied portfolio-surveillance job access");
    }
    assertAggregateOnlyObligations(analysisDecision.obligations);
    assertAggregateOnlyObligations(actionDecision.obligations);
    const storedEnvelope = this.#loadExactEnvelope(state);
    if (canonicalJson(storedEnvelope) !== canonicalJson(envelope)) {
      fail("INTEGRITY_FAILURE", "Queued envelope did not match durable submission evidence");
    }
    if (
      job.status === "cancelled" &&
      state.status !== "cancelled" &&
      state.status !== "failed" &&
      state.status !== "completed"
    ) {
      state = this.#services.state.recordCancellation({
        tenantId: job.tenantId,
        jobId: job.jobId,
        actorId: job.requestedBy,
        reasonCode: "queue_cancelled"
      }).state;
    }
    state = this.#reconcileQueueCompletion(principal, job, state, envelope);
    return { job, state, envelope, analysisDecision, actionDecision };
  }

  #reconcileQueueCompletion(
    principal: VerifiedPrincipalContext,
    job: JobRecord,
    state: PortfolioSurveillanceV4JobStateV1,
    envelope: GovernedExecutionEnvelopeV4
  ): PortfolioSurveillanceV4JobStateV1 {
    if (job.status !== "succeeded") {
      if (state.status === "completed") {
        fail("INTEGRITY_FAILURE", "Durable completion cannot precede queue success");
      }
      return state;
    }
    if (!job.resultHandle || !state.signedPlanId) {
      fail("INTEGRITY_FAILURE", "Queue success is missing its durable result binding");
    }
    if (state.status !== "completion_prepared" && state.status !== "completed") {
      fail("INTEGRITY_FAILURE", "Queue success is missing a fenced completion preparation");
    }
    const plan = this.#loadExactPlan(job.tenantId, envelope);
    const durable = this.#loadDurableOutput(job, state, envelope, plan, true);
    if (!durable?.manifest || !durable.manifestPointer) {
      fail("INTEGRITY_FAILURE", "Queue success is missing its verified result manifest");
    }
    this.#verifyPersistedResultHandle(principal, job.resultHandle, durable.resultPointer.artifactId);
    if (state.status === "completion_prepared") {
      return this.#recordQueueCompletion(
        principal,
        job,
        durable.result,
        durable.resultPointer,
        durable.manifest,
        durable.manifestPointer,
        state.signedPlanId
      );
    }
    this.#assertQueueCompletionEvidence(
      job,
      state,
      durable.result,
      durable.manifest,
      state.signedPlanId
    );
    return state;
  }

  #resolveJobHandle(principal: VerifiedPrincipalContext, handle: string): JobRecord {
    let record;
    try {
      record = verifyPrincipalBoundHandle(this.#services.keyRing, handle, principal, {
        expectedKind: "job",
        nowEpochSeconds: this.#nowEpochSeconds(),
        clockSkewSeconds: 0
      });
      const binding = this.#services.securityState.resolveHandle(record);
      return this.#services.jobs.get(
        principal.tenantId,
        binding.resourceId,
        principalBinding(principal)
      );
    } catch {
      fail("POLICY_DENIED", "Job handle did not authorize this request");
    }
  }

  #verifyPersistedResultHandle(
    principal: VerifiedPrincipalContext,
    handle: string,
    expectedArtifactId: string
  ): void {
    try {
      const record = verifyPrincipalBoundHandle(this.#services.keyRing, handle, principal, {
        expectedKind: "result",
        nowEpochSeconds: this.#nowEpochSeconds(),
        clockSkewSeconds: 0
      });
      const binding = this.#services.securityState.resolveHandle(record);
      if (binding.resourceId !== expectedArtifactId) {
        fail("INTEGRITY_FAILURE", "Result handle did not match durable result state");
      }
    } catch (error) {
      const expired =
        (error instanceof SignedArtifactError && error.code === "ARTIFACT_EXPIRED") ||
        (error instanceof SecurityStateStoreError && error.code === "HANDLE_EXPIRED");
      if (!expired) throw error;
      // The job handle and current policy already authorized this read. Expired
      // result capabilities may be recovered only from exact durable v4 state.
    }
  }

  #issueJobHandle(
    principal: VerifiedPrincipalContext,
    job: JobRecord,
    nowEpochSeconds: number
  ): StartedPortfolioSurveillanceJobV4 {
    if (
      job.tenantId !== principal.tenantId ||
      job.requestedBy !== principalBinding(principal) ||
      job.toolName !== ANALYSIS_TOOL
    ) {
      fail("INTEGRITY_FAILURE", "Job ownership did not verify before handle issuance");
    }
    const issued = issuePrincipalBoundHandle(this.#services.keyRing, {
      kind: "job",
      principal,
      ttlSeconds: this.#defaultHandleTtlSeconds,
      nowEpochSeconds,
      handleId: stateCompatibleOpaqueId()
    });
    this.#services.securityState.bindHandle(issued.record, job.jobId);
    return { jobHandle: issued.handle, status: job.status, operation: OPERATION };
  }

  #bindResultHandle(principal: VerifiedPrincipalContext, artifactId: string): string {
    const issued = issuePrincipalBoundHandle(this.#services.keyRing, {
      kind: "result",
      principal,
      ttlSeconds: this.#defaultHandleTtlSeconds,
      nowEpochSeconds: this.#nowEpochSeconds(),
      handleId: stateCompatibleOpaqueId()
    });
    this.#services.securityState.bindHandle(issued.record, artifactId);
    return issued.handle;
  }

  #requiredState(tenantId: string, jobId: string): PortfolioSurveillanceV4JobStateV1 {
    const state = this.#services.state.get(tenantId, jobId);
    if (!state) fail("INTEGRITY_FAILURE", "Durable v4 workflow state was not found");
    return state;
  }

  #assertSubmissionAuthorization(
    job: Pick<JobRecord, "tenantId" | "jobId" | "requestedBy">,
    state: PortfolioSurveillanceV4JobStateV1,
    envelope: GovernedExecutionEnvelopeV4
  ): void {
    this.#assertStartAuthorizationAudit(job, state, envelope);
    const pointer = state.submissionAuthorizationAudit;
    if (!pointer) {
      fail("AUDIT_REQUIRED", "Durable submission authorization evidence was not recorded");
    }
    const submission = this.#auditEventAtPointer(job.tenantId, pointer);
    if (
      submission.eventType !== "portfolio_surveillance_v4.submission_authorized" ||
      submission.entityType !== "job" ||
      submission.entityId !== job.jobId ||
      submission.actor !== job.requestedBy
    ) {
      fail("AUDIT_REQUIRED", "Durable submission authorization evidence was not found");
    }
    const details = objectValue(submission.details);
    if (
      details.submissionHash !== state.submission.submissionHash ||
      details.envelopeHash !== envelope.envelopeHash ||
      details.startFingerprint !== envelope.startFingerprint ||
      details.authorizationDecisionId !== envelope.startAuthorization.decisionId
    ) {
      fail("AUDIT_REQUIRED", "Submission authorization evidence did not match the job");
    }
  }

  #assertStartAuthorizationAudit(
    job: Pick<JobRecord, "tenantId" | "jobId" | "requestedBy">,
    state: PortfolioSurveillanceV4JobStateV1,
    envelope: GovernedExecutionEnvelopeV4
  ): void {
    const permit = this.#auditEventAtPointer(
      job.tenantId,
      state.submission.startAuthorizationAudit
    );
    const details = objectValue(permit.details);
    if (
      permit.eventType !== "authorization.permitted" ||
      permit.entityType !== "policy_decision" ||
      permit.entityId !== envelope.startAuthorization.decisionId ||
      permit.actor !== job.requestedBy ||
      details.phase !== "start_preflight" ||
      details.contextHash !== state.submission.requestHash ||
      details.decisionId !== envelope.startAuthorization.decisionId ||
      details.effect !== "permit" ||
      details.policyFingerprint !== envelope.startAuthorization.policyFingerprint ||
      details.toolName !== ANALYSIS_TOOL ||
      details.datasetId !== envelope.datasetId ||
      details.purpose !== envelope.purpose ||
      canonicalJson(details.requestedFields) !== canonicalJson(envelope.requestedFields)
    ) {
      fail("AUDIT_REQUIRED", "Start authorization audit did not match the frozen envelope");
    }
  }

  #ensureSubmissionAuthorization(
    job: Pick<JobRecord, "tenantId" | "jobId" | "requestedBy">,
    stateValue: PortfolioSurveillanceV4JobStateV1,
    envelope: GovernedExecutionEnvelopeV4
  ): PortfolioSurveillanceV4JobStateV1 {
    let state = stateValue;
    this.#assertStartAuthorizationAudit(job, state, envelope);
    if (!state.submissionAuthorizationAudit) {
      const event = this.#recordSubmissionAuthorization(
        state,
        envelope,
        envelope.startAuthorization.decisionId
      );
      state = this.#services.state.recordSubmissionAuthorization({
        tenantId: state.submission.tenantId,
        jobId: state.submission.jobId,
        actorId: state.submission.requestedBy,
        authorizationAudit: auditPointer(event)
      }).state;
    }
    this.#assertSubmissionAuthorization(job, state, envelope);
    return state;
  }

  #auditEventAtPointer(
    tenantId: string,
    pointer: PortfolioSurveillanceV4AuditPointerV1
  ): ReturnType<ControlStore["listAuditEvents"]>[number] {
    const event = this.#services.control.listAuditEvents(tenantId, {
      afterSequence: pointer.sequence - 1,
      limit: 1
    })[0];
    if (
      !event ||
      event.sequence !== pointer.sequence ||
      event.tenantId !== tenantId ||
      canonicalHash(event) !== pointer.eventHash
    ) {
      fail("AUDIT_REQUIRED", "Exact durable authorization audit pointer did not verify");
    }
    return event;
  }

  async #assertCurrentMembership(principal: VerifiedPrincipalContext): Promise<void> {
    assertActivePrincipal(principal, this.#nowEpochSeconds(), 0);
    if (!principal.clientId) fail("POLICY_DENIED", "Current client membership is required");
    let membership;
    try {
      membership = await this.#services.tenantMembershipResolver.resolveTenantMembership({
        issuer: principal.issuer,
        subject: principal.subject,
        clientId: principal.clientId,
        audiences: principal.audiences,
        resourceIndicators: principal.resourceIndicators,
        scopes: principal.scopes,
        credentialFingerprint: principal.credentialFingerprint
      });
    } catch {
      fail("AUTHORIZATION_UNAVAILABLE", "Current membership could not be verified");
    }
    if (
      !membership ||
      membership.tenantId !== principal.tenantId ||
      membership.principalId !== principal.principalId
    ) {
      fail("POLICY_DENIED", "Current tenant membership denied the operation");
    }
  }

  #evaluateAndAudit(
    principal: VerifiedPrincipalContext,
    toolName: string,
    envelope: GovernedExecutionEnvelopeV4,
    phase: string,
    jobId: string,
    attemptCount: number
  ): PermitPolicyDecision {
    const decision = evaluatePolicy(this.#services.policy, {
      principal,
      toolName,
      dataset: { id: envelope.datasetId, tenantId: envelope.tenantId },
      fields: envelope.requestedFields,
      purpose: envelope.purpose,
      nowEpochSeconds: this.#nowEpochSeconds()
    });
    this.#recordPolicyDecision(decision, phase, canonicalHash({ jobId, attemptCount }));
    try {
      assertPermitDecision(decision);
    } catch {
      fail("POLICY_DENIED", "Current policy denied portfolio-surveillance execution");
    }
    return decision;
  }

  #recordPolicyDecision(
    decision: PolicyDecision,
    phase: string,
    contextHash: string
  ): ReturnType<ControlStore["appendAuditEvent"]> {
    return this.#appendAudit({
      tenantId: decision.tenantId,
      eventType: decision.effect === "permit" ? "authorization.permitted" : "authorization.denied",
      entityType: "policy_decision",
      entityId: decision.decisionId,
      actor: decision.principalBinding,
      details: {
        phase,
        contextHash,
        decisionId: decision.decisionId,
        effect: decision.effect,
        policyId: decision.policyId,
        policyVersion: decision.policyVersion,
        policyFingerprint: decision.policyFingerprint,
        toolName: decision.toolName,
        datasetId: decision.datasetId,
        requestedFields: [...decision.requestedFields],
        purpose: decision.purpose ?? null,
        matchedRuleIds: [...decision.matchedRuleIds],
        ...(decision.effect === "permit"
          ? { auditTags: [...decision.obligations.auditTags] }
          : { reasonCodes: decision.reasons.map((reason) => reason.code) })
      },
      idempotencyKey: auditKey("authorization", {
        phase,
        contextHash,
        decisionId: decision.decisionId
      })
    });
  }

  #recordPreflightDenial(
    principal: VerifiedPrincipalContext,
    requestHash: Sha256Hash,
    error: unknown
  ): void {
    try {
      this.#appendAudit({
        tenantId: principal.tenantId,
        eventType: "authorization.denied",
        entityType: "policy_decision",
        entityId: bareHash(canonicalHash({ requestHash, principal: principalBinding(principal) })),
        actor: principalBinding(principal),
        details: {
          phase: "metadata_preflight",
          requestHash,
          reasonCode: boundedErrorCode(error)
        },
        idempotencyKey: auditKey("preflight-denial", {
          requestHash,
          principal: principalBinding(principal)
        })
      });
    } catch {
      fail("AUDIT_REQUIRED", "Authorization denial audit could not be recorded");
    }
  }

  #recordSubmissionAuthorization(
    state: PortfolioSurveillanceV4JobStateV1,
    envelope: GovernedExecutionEnvelopeV4,
    authorizationDecisionId: string
  ): ReturnType<ControlStore["appendAuditEvent"]> {
    return this.#appendAudit({
      tenantId: state.submission.tenantId,
      eventType: "portfolio_surveillance_v4.submission_authorized",
      entityType: "job",
      entityId: state.submission.jobId,
      actor: state.submission.requestedBy,
      details: {
        operation: OPERATION,
        authorizationDecisionId,
        submissionHash: state.submission.submissionHash,
        envelopeHash: envelope.envelopeHash,
        planHash: envelope.planHash,
        startFingerprint: envelope.startFingerprint
      },
      idempotencyKey: auditKey("submission", state.submission.jobId)
    });
  }

  #recordStarted(job: JobRecord, envelope: GovernedExecutionEnvelopeV4): void {
    this.#appendAudit({
      tenantId: job.tenantId,
      eventType: "portfolio_surveillance_v4.started",
      entityType: "job",
      entityId: job.jobId,
      actor: job.requestedBy,
      details: {
        operation: OPERATION,
        envelopeHash: envelope.envelopeHash,
        requestHash: envelope.requestHash,
        planHash: envelope.planHash,
        idempotencyFingerprint: envelope.idempotencyFingerprint,
        startFingerprint: envelope.startFingerprint
      },
      idempotencyKey: auditKey("started", job.jobId)
    });
  }

  #recordAccessAuthorization(
    job: JobRecord,
    actionToolName: string,
    analysis: PolicyDecision,
    action: PolicyDecision
  ): void {
    const accessId = bareHash(canonicalHash({
      jobId: job.jobId,
      actionToolName,
      analysisDecisionId: analysis.decisionId,
      actionDecisionId: action.decisionId
    }));
    this.#appendAudit({
      tenantId: job.tenantId,
      eventType:
        analysis.effect === "permit" && action.effect === "permit"
          ? "authorization.permitted"
          : "authorization.denied",
      entityType: "job_access",
      entityId: accessId,
      actor: job.requestedBy,
      details: {
        jobId: job.jobId,
        actionToolName,
        analysis: policyAuditDetails(analysis),
        action: policyAuditDetails(action)
      },
      idempotencyKey: auditKey("access", accessId)
    });
  }

  #recordCompletionAudit(
    job: Pick<JobRecord, "tenantId" | "jobId" | "requestedBy" | "attemptCount">,
    result: GovernedResultArtifactV4,
    manifest: GovernedResultManifestV4,
    signedPlanId: string
  ): ReturnType<ControlStore["appendAuditEvent"]> {
    return this.#appendAudit({
      tenantId: job.tenantId,
      eventType: "portfolio_surveillance_v4.completed",
      entityType: "job",
      entityId: job.jobId,
      actor: job.requestedBy,
      details: {
        attemptCount: job.attemptCount,
        resultHash: result.resultHash,
        manifestHash: manifest.manifestHash,
        planId: manifest.planId,
        signedPlanId
      },
      idempotencyKey: auditKey("completed", job.jobId)
    });
  }

  #recordQueueCompletion(
    principal: VerifiedPrincipalContext,
    job: JobRecord,
    result: GovernedResultArtifactV4,
    resultPointer: PortfolioSurveillanceV4ResultArtifactPointerV1,
    manifest: GovernedResultManifestV4,
    manifestPointer: PortfolioSurveillanceV4ManifestArtifactPointerV1,
    signedPlanId: string
  ): PortfolioSurveillanceV4JobStateV1 {
    if (job.status !== "succeeded" || !job.resultHandle) {
      fail("INTEGRITY_FAILURE", "Queue did not persist a successful result capability");
    }
    this.#verifyPersistedResultHandle(principal, job.resultHandle, resultPointer.artifactId);
    const completionAudit = this.#recordCompletionAudit(job, result, manifest, signedPlanId);
    return this.#services.state.recordQueueCompletion({
      tenantId: job.tenantId,
      jobId: job.jobId,
      actorId: job.requestedBy,
      queueRequestHash: job.requestHash,
      resultHandleHash: sha256Text(job.resultHandle),
      queueUpdatedAt: job.updatedAt,
      completionAudit: auditPointer(completionAudit),
      resultArtifact: resultPointer,
      manifestArtifact: manifestPointer
    }).state;
  }

  #assertQueueCompletionEvidence(
    job: JobRecord,
    state: PortfolioSurveillanceV4JobStateV1,
    result: GovernedResultArtifactV4,
    manifest: GovernedResultManifestV4,
    signedPlanId: string
  ): void {
    const evidence = state.queueCompletion;
    if (!job.resultHandle || !evidence) {
      fail("INTEGRITY_FAILURE", "Durable queue completion evidence was not found");
    }
    const audit = this.#auditEventAtPointer(job.tenantId, evidence.completionAudit);
    const details = objectValue(audit.details);
    if (
      evidence.queueRequestHash !== job.requestHash ||
      evidence.resultHandleHash !== sha256Text(job.resultHandle) ||
      evidence.queueUpdatedAt !== job.updatedAt ||
      audit.eventType !== "portfolio_surveillance_v4.completed" ||
      audit.entityType !== "job" ||
      audit.entityId !== job.jobId ||
      audit.actor !== job.requestedBy ||
      details.attemptCount !== job.attemptCount ||
      details.resultHash !== result.resultHash ||
      details.manifestHash !== manifest.manifestHash ||
      details.planId !== manifest.planId ||
      details.signedPlanId !== signedPlanId
    ) {
      fail("AUDIT_REQUIRED", "Queue completion audit did not match durable output");
    }
  }

  #recordAttemptTerminalState(
    claimed: ClaimedJob,
    failed: JobRecord,
    fence: PortfolioSurveillanceV4AttemptFenceV1,
    workerId: string,
    code: string
  ): void {
    try {
      if (failed.status === "cancelled") {
        this.#services.state.recordCancellation({
          tenantId: claimed.tenantId,
          jobId: claimed.jobId,
          actorId: workerId,
          reasonCode: "cancelled"
        });
      } else if (failed.status === "failed") {
        this.#services.state.recordFailure({
          tenantId: claimed.tenantId,
          jobId: claimed.jobId,
          actorId: workerId,
          attemptFence: fence,
          errorCode: identifier(code, "errorCode")
        });
      }
    } catch {
      // The queue outcome remains authoritative; supplemental state is fail-closed on read.
    }
  }

  #recordFailureAudit(claimed: ClaimedJob, failed: JobRecord, code: string): void {
    try {
      this.#appendAudit({
        tenantId: claimed.tenantId,
        eventType: "portfolio_surveillance_v4.attempt_failed",
        entityType: "job",
        entityId: claimed.jobId,
        actor: claimed.requestedBy,
        details: {
          attemptCount: claimed.attemptCount,
          errorCode: code,
          outcomeStatus: failed.status
        },
        idempotencyKey: auditKey("attempt-failure", {
          jobId: claimed.jobId,
          attemptCount: claimed.attemptCount
        })
      });
    } catch {
      // Job state is authoritative after the authorization audit has been recorded.
    }
  }

  #injectFault(point: PortfolioSurveillanceWorkflowV4FaultPoint): void {
    if (this.#faultInjector?.(point) === true) {
      throw new PortfolioSurveillanceWorkflowV4InjectedCrash(point);
    }
  }

  #appendAudit(
    input: Parameters<ControlStore["appendAuditEvent"]>[0]
  ): ReturnType<ControlStore["appendAuditEvent"]> {
    try {
      return this.#services.control.appendAuditEvent(input);
    } catch {
      fail("AUDIT_REQUIRED", "Required authorization audit could not be recorded");
    }
  }

  #putExactArtifact(tenantId: string, kind: string, value: unknown): StoredArtifact {
    let stored: StoredArtifact;
    try {
      stored = this.#services.artifacts.putJson({
        tenantId,
        kind,
        mediaType: JSON_MEDIA_TYPE,
        value
      });
    } catch {
      fail("INTEGRITY_FAILURE", "Durable artifact persistence failed");
    }
    const expectedContentHash = artifactJsonContentHash(value);
    const expectedByteLength = Buffer.byteLength(canonicalJson(value), "utf8");
    if (
      stored.kind !== kind ||
      stored.mediaType !== JSON_MEDIA_TYPE ||
      stored.contentHash !== expectedContentHash ||
      stored.byteLength !== expectedByteLength ||
      stored.uri !== `abl-artifact://${stored.artifactId}`
    ) {
      fail("INTEGRITY_FAILURE", "Persisted artifact metadata did not match exact bytes");
    }
    return stored;
  }

  #getExactArtifact(
    tenantId: string,
    artifactId: string,
    kind: string,
    mediaType: string,
    contentHash: string,
    byteLength: number
  ): ReturnType<ArtifactStore["getJson"]> {
    let loaded: ReturnType<ArtifactStore["getJson"]>;
    try {
      loaded = this.#services.artifacts.getJson(tenantId, artifactId);
    } catch {
      fail("INTEGRITY_FAILURE", "Tenant-scoped durable artifact read failed");
    }
    if (
      loaded.metadata.artifactId !== artifactId ||
      loaded.metadata.kind !== kind ||
      loaded.metadata.mediaType !== mediaType ||
      loaded.metadata.contentHash !== contentHash ||
      loaded.metadata.byteLength !== byteLength ||
      loaded.metadata.uri !== `abl-artifact://${artifactId}` ||
      artifactJsonContentHash(loaded.value) !== contentHash ||
      Buffer.byteLength(canonicalJson(loaded.value), "utf8") !== byteLength
    ) {
      fail("INTEGRITY_FAILURE", "Durable artifact metadata or bytes did not verify");
    }
    return loaded;
  }

  #throwIfCancelled(job: Pick<JobRecord, "tenantId" | "jobId">): void {
    if (this.#services.jobs.get(job.tenantId, job.jobId).cancellationRequested) {
      fail("CANCELLED", "Job cancellation was requested");
    }
  }

  #assertExecutionWindow(
    envelope: GovernedExecutionEnvelopeV4,
    principal: VerifiedPrincipalContext
  ): void {
    const now = this.#nowDate().getTime();
    if (
      now >= Date.parse(envelope.planningCutoff) + envelope.planTtlSeconds * 1_000 ||
      now >= principal.expiresAtEpochSeconds * 1_000
    ) {
      fail("EXECUTION_TIMEOUT", "Frozen execution authority expired before execution");
    }
  }

  #nowDate(): Date {
    const value = this.#clock();
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
      fail("INVALID_INPUT", "Workflow clock is invalid");
    }
    return value;
  }

  #nowIso(): string {
    return this.#nowDate().toISOString();
  }

  #nowEpochSeconds(): number {
    return Math.floor(this.#nowDate().getTime() / 1_000);
  }
}

function parseStartInput(value: unknown): StartPortfolioSurveillanceJobV4Input {
  const record = objectValue(value);
  exactKeys(record, ["idempotencyKey", "operation", "operationRequest", "purpose"]);
  if (record.operation !== OPERATION) fail("INVALID_INPUT", "Unsupported operation");
  const operationRequest = parsePortfolioSurveillanceAuthorizationRequestV1(
    record.operationRequest
  );
  return Object.freeze({
    operation: OPERATION,
    operationRequest,
    idempotencyKey: identifier(record.idempotencyKey, "idempotencyKey"),
    purpose: identifier(record.purpose, "purpose")
  });
}

function executionDecisionProjection(
  decision: PermitPolicyDecision,
  principalId: string,
  purpose: string
) {
  if (decision.purpose !== purpose) {
    fail("INTEGRITY_FAILURE", "Start policy decision purpose did not verify");
  }
  return {
    decisionId: decision.decisionId,
    policyFingerprint: decision.policyFingerprint,
    tenantId: decision.tenantId,
    principalId,
    requestedFields: [...decision.requestedFields],
    purpose,
    obligations: mutableObligations(decision.obligations)
  };
}

function deterministicManifest(
  result: GovernedResultArtifactV4,
  resultPointer: PortfolioSurveillanceV4ResultArtifactPointerV1,
  envelope: GovernedExecutionEnvelopeV4,
  codeVersion: string
): GovernedResultManifestV4 {
  try {
    return finalizeGovernedResultManifestV4(
      {
        version: 4,
        createdAt: result.authorization.completedAt,
        codeVersion,
        planId: bareHash(envelope.planHash)
      },
      result,
      resultPointer
    );
  } catch {
    fail("INTEGRITY_FAILURE", "Governed result manifest finalization failed");
  }
}

function resultPointerFrom(stored: StoredArtifact): PortfolioSurveillanceV4ResultArtifactPointerV1 {
  if (stored.kind !== GOVERNED_ANALYSIS_RESULT_V4_KIND) {
    fail("INTEGRITY_FAILURE", "Stored result artifact kind did not verify");
  }
  return Object.freeze({
    artifactId: stored.artifactId,
    kind: GOVERNED_ANALYSIS_RESULT_V4_KIND,
    mediaType: JSON_MEDIA_TYPE,
    contentHash: stored.contentHash,
    byteLength: stored.byteLength
  });
}

function manifestPointerFrom(
  stored: StoredArtifact
): PortfolioSurveillanceV4ManifestArtifactPointerV1 {
  if (stored.kind !== GOVERNED_RESULT_MANIFEST_V4_KIND) {
    fail("INTEGRITY_FAILURE", "Stored result manifest kind did not verify");
  }
  return Object.freeze({
    artifactId: stored.artifactId,
    kind: GOVERNED_RESULT_MANIFEST_V4_KIND,
    mediaType: JSON_MEDIA_TYPE,
    contentHash: stored.contentHash,
    byteLength: stored.byteLength
  });
}

function resultView(
  result: GovernedResultArtifactV4,
  artifactId: string
): PortfolioSurveillanceJobResultViewV4 {
  return Object.freeze({
    operation: OPERATION,
    manifestId: result.manifestId,
    artifactId,
    resultHash: result.resultHash,
    result: result.result
  });
}

function assertCurrentDisclosure(
  result: GovernedResultArtifactV4,
  plan: PortfolioSurveillanceExecutionPlanV1,
  view: PortfolioSurveillanceJobResultViewV4,
  analysisDecision: PermitPolicyDecision,
  actionDecision: PermitPolicyDecision
): void {
  const minimumMetricCellCount = Math.min(
    ...plan.engineInput.metricDefinitions.map((metric) => metric.privacy.minimumCellCount)
  );
  for (const decision of [analysisDecision, actionDecision]) {
    assertAggregateOnlyObligations(decision.obligations);
    if (decision.obligations.minimumCohortSize > minimumMetricCellCount) {
      fail("POLICY_DENIED", "Stored result does not satisfy the current cohort minimum");
    }
    if (result.accounting.disclosedItemCount > decision.obligations.maxResultRows) {
      fail("POLICY_DENIED", "Stored result exceeds the current row disclosure bound");
    }
    if (
      result.accounting.bytes > decision.obligations.maxResultBytes ||
      governedMcpResultByteLength(view) > decision.obligations.maxResultBytes
    ) {
      fail("POLICY_DENIED", "Stored result exceeds the current byte disclosure bound");
    }
  }
}

function assertAggregateOnlyObligations(obligations: PolicyObligations): void {
  if (
    !obligations.requireImmutableSnapshot ||
    obligations.allowRawRows ||
    obligations.allowExport ||
    obligations.rowFilterRefs.length !== 0 ||
    Object.keys(obligations.fieldMasks).length !== 0
  ) {
    fail("POLICY_DENIED", "Policy obligations cannot support aggregate-only surveillance");
  }
}

function governedMcpResultByteLength(view: PortfolioSurveillanceJobResultViewV4): number {
  return modernMcpSuccessResultByteLength(
    { result: view },
    { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION }
  );
}

function persistedIdentity(principal: VerifiedPrincipalContext) {
  return {
    issuer: principal.issuer,
    subject: principal.subject,
    principalId: principal.principalId,
    tenantId: principal.tenantId,
    ...(principal.clientId === undefined ? {} : { clientId: principal.clientId }),
    audiences: [...principal.audiences],
    resourceIndicators: [...principal.resourceIndicators],
    scopes: [...principal.scopes],
    credentialFingerprint: principal.credentialFingerprint,
    verifiedAtEpochSeconds: principal.verifiedAtEpochSeconds,
    ...(principal.notBeforeEpochSeconds === undefined
      ? {}
      : { notBeforeEpochSeconds: principal.notBeforeEpochSeconds }),
    expiresAtEpochSeconds: principal.expiresAtEpochSeconds,
    authenticationMethods: [...principal.authenticationMethods]
  };
}

function rehydrateIdentity(
  identity: GovernedExecutionEnvelopeV4["identity"]
): VerifiedPrincipalContext {
  const attestation: VerifiedIdentityAttestation = {
    issuer: identity.issuer,
    subject: identity.subject,
    principalId: identity.principalId,
    tenantId: identity.tenantId,
    ...(identity.clientId === undefined ? {} : { clientId: identity.clientId }),
    audiences: [...identity.audiences],
    resourceIndicators: [...identity.resourceIndicators],
    scopes: [...identity.scopes],
    credentialFingerprint: identity.credentialFingerprint,
    verifiedAtEpochSeconds: identity.verifiedAtEpochSeconds,
    ...(identity.notBeforeEpochSeconds === undefined
      ? {}
      : { notBeforeEpochSeconds: identity.notBeforeEpochSeconds }),
    expiresAtEpochSeconds: identity.expiresAtEpochSeconds,
    ...(identity.authenticationMethods === undefined
      ? {}
      : { authenticationMethods: [...identity.authenticationMethods] })
  };
  return createVerifiedPrincipalContext(attestation);
}

function mutableObligations(obligations: PolicyObligations) {
  return {
    maxResultRows: obligations.maxResultRows,
    maxResultBytes: obligations.maxResultBytes,
    maxExecutionMs: obligations.maxExecutionMs,
    minimumCohortSize: obligations.minimumCohortSize,
    requireImmutableSnapshot: obligations.requireImmutableSnapshot,
    allowRawRows: obligations.allowRawRows,
    allowExport: obligations.allowExport,
    rowFilterRefs: [...obligations.rowFilterRefs],
    fieldMasks: { ...obligations.fieldMasks },
    auditTags: [...obligations.auditTags]
  };
}

function attemptFence(
  claimed: ClaimedJob,
  workerId: string
): PortfolioSurveillanceV4AttemptFenceV1 {
  return Object.freeze({
    attemptNumber: claimed.attemptCount,
    workerId,
    leaseTokenHash: sha256Text(claimed.claimToken),
    leaseExpiresAt: claimed.leaseExpiresAt
  });
}

function publicJobStatus(
  job: JobRecord,
  state: PortfolioSurveillanceV4JobStateV1
): PortfolioSurveillanceJobStatusViewV4 {
  return Object.freeze({
    operation: OPERATION,
    status: job.status,
    durableStatus: state.status,
    attemptCount: job.attemptCount,
    maxAttempts: job.maxAttempts,
    cancellationRequested: job.cancellationRequested,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    errorCode: job.errorCode,
    resultAvailable:
      job.status === "succeeded" &&
      job.resultHandle !== null &&
      state.status === "completed" &&
      state.queueCompletion !== undefined &&
      state.resultArtifact !== undefined &&
      state.manifestArtifact !== undefined
  });
}

function policyAuditDetails(decision: PolicyDecision): JsonValue {
  return {
    decisionId: decision.decisionId,
    effect: decision.effect,
    policyId: decision.policyId,
    policyVersion: decision.policyVersion,
    policyFingerprint: decision.policyFingerprint,
    toolName: decision.toolName,
    datasetId: decision.datasetId,
    requestedFields: [...decision.requestedFields],
    purpose: decision.purpose ?? null,
    matchedRuleIds: [...decision.matchedRuleIds],
    ...(decision.effect === "permit"
      ? { auditTags: [...decision.obligations.auditTags] }
      : { reasonCodes: decision.reasons.map((reason) => reason.code) })
  };
}

function mutationRequestStartedAt(
  context?: PortfolioSurveillanceMutationRequestContextV4
): number {
  const now = performance.now();
  if (context === undefined) return now;
  if (
    !Number.isFinite(context.requestStartedAtMonotonicMs) ||
    context.requestStartedAtMonotonicMs < 0 ||
    context.requestStartedAtMonotonicMs > now + 1
  ) {
    fail("INVALID_INPUT", "Request timing context is invalid");
  }
  return context.requestStartedAtMonotonicMs;
}

function assertPreCommitDeadline(startedAt: number, maximumExecutionMs: number): void {
  if (performance.now() - startedAt > maximumExecutionMs) {
    fail("EXECUTION_TIMEOUT", "Request exceeded its authorized pre-commit deadline");
  }
}

function authorizedResponse<T>(
  value: T,
  ...obligations: readonly PolicyObligations[]
): PortfolioSurveillanceAuthorizedResponseV4<T> {
  return Object.freeze({ value, obligations: Object.freeze([...obligations]) });
}

function asRecord(value: unknown): Readonly<Record<string, unknown>> {
  return objectValue(value);
}

function objectValue(value: unknown): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_INPUT", "Expected a canonical object");
  }
  return value as Readonly<Record<string, unknown>>;
}

function exactKeys(record: Readonly<Record<string, unknown>>, expected: readonly string[]): void {
  const actual = Object.keys(record).sort(compare);
  const normalized = [...expected].sort(compare);
  if (canonicalJson(actual) !== canonicalJson(normalized)) {
    fail("INVALID_INPUT", "Request contains missing or unknown fields");
  }
}

function identifier(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 256 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/u.test(value)
  ) {
    fail("INVALID_INPUT", `${label} is invalid`);
  }
  return value;
}

function boundedInteger(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    fail("INVALID_INPUT", `${label} is outside the supported range`);
  }
  return value;
}

function bareHash(value: string): string {
  if (!/^sha256:[a-f0-9]{64}$/u.test(value)) {
    fail("INTEGRITY_FAILURE", "Expected a canonical SHA-256 hash");
  }
  return value.slice("sha256:".length);
}

function controlHash(value: string): Sha256Hash {
  if (!/^[a-f0-9]{64}$/u.test(value)) {
    fail("INTEGRITY_FAILURE", "Expected a bare SHA-256 hash");
  }
  return `sha256:${value}`;
}

function sha256Text(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function auditKey(scope: string, identity: unknown): string {
  return `portfolio-v4-${scope}:${bareHash(canonicalHash(identity))}`;
}

function auditPointer(
  event: ReturnType<ControlStore["appendAuditEvent"]>
): { readonly sequence: number; readonly eventHash: Sha256Hash } {
  return Object.freeze({ sequence: event.sequence, eventHash: canonicalHash(event) });
}

function stateCompatibleOpaqueId(): string {
  return `h${randomBytes(24).toString("base64url")}`;
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function boundedErrorCode(error: unknown): string {
  if (
    error &&
    typeof error === "object" &&
    "code" in error &&
    typeof error.code === "string" &&
    /^[A-Z][A-Z0-9_]{0,63}$/u.test(error.code)
  ) {
    return error.code;
  }
  return "POLICY_DENIED";
}

function normalizeStartError(error: unknown): PortfolioSurveillanceWorkflowV4Error {
  const code = boundedErrorCode(error);
  return workflowError(
    code.includes("POLICY") || code.includes("AUTHORIZATION")
      ? "POLICY_DENIED"
      : "INTEGRITY_FAILURE",
    "Portfolio-surveillance authorization preflight failed"
  );
}

function executionErrorCode(error: unknown): string {
  if (error instanceof PortfolioSurveillanceWorkflowV4Error) return error.code;
  if (error instanceof SignedArtifactError) return error.code;
  if (error instanceof PortfolioSurveillanceV4StateStoreError) return error.code;
  return "EXECUTION_FAILED";
}

function isRetryable(code: string): boolean {
  return code === "AUTHORIZATION_UNAVAILABLE";
}

function workflowError(
  code: PortfolioSurveillanceWorkflowV4ErrorCode,
  message: string
): PortfolioSurveillanceWorkflowV4Error {
  return new PortfolioSurveillanceWorkflowV4Error(code, message);
}

function fail(code: PortfolioSurveillanceWorkflowV4ErrorCode, message: string): never {
  throw workflowError(code, message);
}
