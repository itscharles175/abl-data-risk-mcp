import { z } from "zod";

import {
  IdentifierSchema,
  Sha256HashSchema,
  canonicalJson,
  parseWithSchema,
  type Sha256Hash
} from "../contracts/canonical.js";
import { MetricProjectionReferenceV1Schema } from "../contracts/metric-projection-v1.js";
import {
  MetricDefinitionReferenceV1Schema,
  MetricRunMethodologyReferenceV1Schema,
  MetricRunObservationInputV1Schema,
  MetricRunScopeV1Schema,
  MetricRunSourceV1Schema,
  MetricRunValueV1Schema,
  parseMetricRunV1,
  type MetricRunScopeV1,
  type MetricRunV1,
  type MetricRunValueV1,
  type MetricRunViewV1
} from "../contracts/metric-run-v1.js";
import {
  MetricRunStore,
  type ApproveMetricRunInput,
  type CreateMetricRunInput
} from "../control/metric-runs.js";

const FrozenMetricResultCellV1Schema = z
  .object({
    tenantId: IdentifierSchema,
    projection: MetricProjectionReferenceV1Schema,
    metricId: IdentifierSchema,
    metricDefinition: MetricDefinitionReferenceV1Schema,
    methodology: MetricRunMethodologyReferenceV1Schema,
    source: MetricRunSourceV1Schema,
    observation: MetricRunObservationInputV1Schema
  })
  .strict()
  .superRefine((value, context) => {
    if (
      value.source.resultArtifactId.length === 0 ||
      value.source.cellId.length === 0 ||
      value.observation.asOfDate.length === 0
    ) {
      context.addIssue({ code: "custom", message: "result-cell evidence must be complete" });
    }
  });

export type FrozenMetricResultCellV1 = Readonly<z.infer<typeof FrozenMetricResultCellV1Schema>>;

/**
 * Resolves an immutable, previously executed and signed surveillance result
 * cell. The implementation must verify the projection, result manifest and
 * artifact, cell hash, certified population (snapshot or longitudinal bundle),
 * frozen metric definition, and frozen methodology before returning a value.
 */
export interface MetricRunAuthorityResolver {
  resolveFrozenResultCell(input: {
    readonly tenantId: string;
    readonly projectionDefinitionId: string;
    readonly surveillanceResultArtifactId: string;
    readonly cellId: string;
  }): FrozenMetricResultCellV1 | undefined;
}

export interface CreateMetricRunCandidateRequestV1 {
  readonly tenantId: string;
  readonly runId: string;
  readonly projectionDefinitionId: string;
  readonly surveillanceResultArtifactId: string;
  readonly cellId: string;
  readonly createdBy: string;
  readonly idempotencyKey: string;
}

export interface ApproveMetricRunCandidateRequestV1
  extends Omit<ApproveMetricRunInput, "expectedRunHash"> {
  readonly expectedRunHash: Sha256Hash;
}

/** Exact comparison surface used when a certified metric run is referenced by monitoring input. */
export interface VerifyMetricRunObservationRequestV1 {
  readonly tenantId: string;
  readonly runId: string;
  readonly metricId: string;
  readonly asOfDate: string;
  readonly scope: MetricRunScopeV1;
  readonly measurement: MetricRunValueV1;
}

export interface VerifiedMetricRunEvidenceV1 {
  readonly run: MetricRunV1;
  readonly reference: { readonly kind: "metric_run"; readonly id: string };
  readonly summary: {
    readonly runId: string;
    readonly metricId: string;
    readonly projectionDefinitionId: string;
    readonly projectionDefinitionVersionId: string;
    readonly projectionDefinitionVersion: string;
    readonly projectionDefinitionHash: Sha256Hash;
    readonly projectionDocumentHash: Sha256Hash;
    readonly projectionVersionHash: Sha256Hash;
    readonly projectionApprovalEventHash: Sha256Hash;
    readonly metricDefinitionId: string;
    readonly metricDefinitionVersionId: string;
    readonly metricDefinitionVersion: string;
    readonly metricDefinitionHash: Sha256Hash;
    readonly metricDefinitionDocumentHash: Sha256Hash;
    readonly metricDefinitionVersionHash: Sha256Hash;
    readonly metricDefinitionApprovalEventHash: Sha256Hash;
    readonly methodologyId: string;
    readonly methodologyDefinitionVersionId: string;
    readonly methodologyVersion: string;
    readonly methodologyHash: Sha256Hash;
    readonly methodologyDocumentHash: Sha256Hash;
    readonly methodologyVersionHash: Sha256Hash;
    readonly methodologyApprovalEventHash: Sha256Hash;
    readonly resultArtifactId: string;
    readonly cellId: string;
    readonly cellHash: Sha256Hash;
    readonly populationHash: Sha256Hash;
    readonly sourceHash: Sha256Hash;
    readonly derivationHash: Sha256Hash;
    readonly runHash: Sha256Hash;
    readonly certificationHash: Sha256Hash;
    readonly approvedAt: string;
  };
}

export type MetricRunEvidenceErrorCode =
  | "INVALID_REQUEST"
  | "NOT_FOUND"
  | "NOT_CERTIFIED"
  | "AUTHORITY_MISMATCH"
  | "OBSERVATION_MISMATCH";

export class MetricRunEvidenceError extends Error {
  constructor(readonly code: MetricRunEvidenceErrorCode, message: string) {
    super(message);
    this.name = "MetricRunEvidenceError";
  }
}

export interface MetricRunEvidenceServiceDependencies {
  readonly metricRuns: Pick<
    MetricRunStore,
    "create" | "approve" | "get" | "getCertified" | "findCertifiedByObservation"
  >;
  readonly authority: MetricRunAuthorityResolver;
}

/**
 * Server-only certification surface. Creation accepts identifiers only; every
 * quantitative fact is loaded from an immutable governed result cell.
 */
export class MetricRunEvidenceService {
  readonly #dependencies: MetricRunEvidenceServiceDependencies;

  constructor(dependencies: MetricRunEvidenceServiceDependencies) {
    this.#dependencies = dependencies;
  }

  createCandidate(request: CreateMetricRunCandidateRequestV1) {
    validateCreateRequest(request);
    const existing = this.#dependencies.metricRuns.get(request.tenantId, request.runId);
    if (existing) {
      assertRepositoryIdentity(existing, request.tenantId, request.runId);
      if (!candidateIntentMatches(existing, request)) {
        throw new MetricRunEvidenceError(
          "INVALID_REQUEST",
          "Metric-run candidate request conflicts with its durable intent"
        );
      }
      const replayed = this.#dependencies.metricRuns.create(
        storeReplayInput(existing, request.idempotencyKey)
      );
      assertRepositoryIdentity(replayed, request.tenantId, request.runId);
      return replayed;
    }
    const resolved = this.#resolve(request);
    const storeInput: CreateMetricRunInput = {
      contractVersion: 1,
      tenantId: request.tenantId,
      runId: request.runId,
      metricId: resolved.metricId,
      projection: resolved.projection,
      metricDefinition: resolved.metricDefinition,
      methodology: resolved.methodology,
      source: resolved.source,
      observation: resolved.observation,
      createdBy: request.createdBy,
      idempotencyKey: request.idempotencyKey
    };
    const created = this.#dependencies.metricRuns.create(storeInput);
    assertRepositoryIdentity(created, request.tenantId, request.runId);
    return created;
  }

  approveCandidate(request: ApproveMetricRunCandidateRequestV1): MetricRunV1 {
    validateApprovalRequest(request);
    const candidate = this.#dependencies.metricRuns.get(request.tenantId, request.runId);
    if (!candidate) throw new MetricRunEvidenceError("NOT_FOUND", "Metric-run candidate was not found");
    assertRepositoryIdentity(candidate, request.tenantId, request.runId);
    if (candidate.status !== "created") {
      if (
        candidate.approvedBy === request.approvedBy &&
        candidate.runHash === request.expectedRunHash
      ) {
        const replayed = this.#dependencies.metricRuns.approve(request);
        assertRepositoryIdentity(replayed, request.tenantId, request.runId);
        return replayed;
      }
      throw new MetricRunEvidenceError("NOT_CERTIFIED", "Metric-run candidate is already terminal");
    }
    this.#assertAuthority(candidate);
    const certified = this.#dependencies.metricRuns.approve(request);
    assertRepositoryIdentity(certified, request.tenantId, request.runId);
    return certified;
  }

  getCertified(tenantId: string, runId: string): VerifiedMetricRunEvidenceV1 | undefined {
    const run = this.#dependencies.metricRuns.getCertified(tenantId, runId);
    if (!run) return undefined;
    assertRepositoryIdentity(run, tenantId, runId);
    return this.#verified(run);
  }

  lookupCertified(input: {
    readonly tenantId: string;
    readonly metricId: string;
    readonly asOfDate: string;
    readonly scope: MetricRunScopeV1;
    readonly sourceHash: Sha256Hash;
  }): VerifiedMetricRunEvidenceV1 | undefined {
    const run = this.#dependencies.metricRuns.findCertifiedByObservation(input);
    if (!run) return undefined;
    assertRepositoryObservationIdentity(run, input);
    return this.#verified(run);
  }

  verifyObservation(request: VerifyMetricRunObservationRequestV1): VerifiedMetricRunEvidenceV1 {
    validateVerificationRequest(request);
    const candidate = this.#dependencies.metricRuns.get(request.tenantId, request.runId);
    if (!candidate) throw new MetricRunEvidenceError("NOT_FOUND", "Metric-run evidence was not found");
    assertRepositoryIdentity(candidate, request.tenantId, request.runId);
    if (candidate.status !== "certified") {
      throw new MetricRunEvidenceError("NOT_CERTIFIED", "Metric-run evidence is not certified");
    }
    const run = parseMetricRunV1(candidate);
    if (
      run.metricId !== request.metricId ||
      run.observation.asOfDate !== request.asOfDate ||
      canonicalJson(run.observation.scope) !== canonicalJson(request.scope) ||
      canonicalJson(run.observation.measurement) !== canonicalJson(request.measurement)
    ) {
      throw new MetricRunEvidenceError(
        "OBSERVATION_MISMATCH",
        "Metric-run evidence did not exactly match the monitoring observation"
      );
    }
    return this.#verified(run);
  }

  #verified(runValue: MetricRunV1): VerifiedMetricRunEvidenceV1 {
    const run = parseMetricRunV1(runValue);
    this.#assertAuthority(run);
    return Object.freeze({
      run,
      reference: Object.freeze({ kind: "metric_run" as const, id: run.runId }),
      summary: Object.freeze({
        runId: run.runId,
        metricId: run.metricId,
        projectionDefinitionId: run.projection.definitionId,
        projectionDefinitionVersionId: run.projection.definitionVersionId,
        projectionDefinitionVersion: run.projection.version,
        projectionDefinitionHash: run.projection.definitionHash,
        projectionDocumentHash: run.projection.documentHash,
        projectionVersionHash: run.projection.versionHash,
        projectionApprovalEventHash: run.projection.approvalEventHash,
        metricDefinitionId: run.metricDefinition.definitionId,
        metricDefinitionVersionId: run.metricDefinition.definitionVersionId,
        metricDefinitionVersion: run.metricDefinition.version,
        metricDefinitionHash: run.metricDefinition.definitionHash,
        metricDefinitionDocumentHash: run.metricDefinition.documentHash,
        metricDefinitionVersionHash: run.metricDefinition.versionHash,
        metricDefinitionApprovalEventHash: run.metricDefinition.approvalEventHash,
        methodologyId: run.methodology.definitionId,
        methodologyDefinitionVersionId: run.methodology.definitionVersionId,
        methodologyVersion: run.methodology.version,
        methodologyHash: run.methodology.definitionHash,
        methodologyDocumentHash: run.methodology.documentHash,
        methodologyVersionHash: run.methodology.versionHash,
        methodologyApprovalEventHash: run.methodology.approvalEventHash,
        resultArtifactId: run.source.resultArtifactId,
        cellId: run.source.cellId,
        cellHash: run.source.cellHash,
        populationHash: run.source.populationHash,
        sourceHash: run.source.sourceHash,
        derivationHash: run.derivationHash,
        runHash: run.runHash,
        certificationHash: run.certificationHash,
        approvedAt: run.approvedAt
      })
    });
  }

  #assertAuthority(run: MetricRunViewV1): void {
    const resolved = this.#resolve({
      tenantId: run.tenantId,
      projectionDefinitionId: run.projection.definitionId,
      surveillanceResultArtifactId: run.source.resultArtifactId,
      cellId: run.source.cellId
    });
    if (canonicalJson(candidateBody(resolved)) !== canonicalJson(candidateBody(run))) {
      authorityMismatch("Metric-run evidence no longer matches the frozen governed result cell");
    }
  }

  #resolve(input: {
    readonly tenantId: string;
    readonly projectionDefinitionId: string;
    readonly surveillanceResultArtifactId: string;
    readonly cellId: string;
  }): FrozenMetricResultCellV1 {
    const value = this.#dependencies.authority.resolveFrozenResultCell(input);
    if (!value) authorityMismatch("A frozen governed result cell was not found");
    const resolved = parseWithSchema(
      FrozenMetricResultCellV1Schema,
      value,
      "FrozenMetricResultCellV1"
    );
    if (
      resolved.tenantId !== input.tenantId ||
      resolved.projection.definitionId !== input.projectionDefinitionId ||
      resolved.source.resultArtifactId !== input.surveillanceResultArtifactId ||
      resolved.source.cellId !== input.cellId
    ) {
      authorityMismatch("Result-cell authority returned different frozen identifiers");
    }
    if (
      resolved.source.cellHash === resolved.source.resultArtifactHash ||
      resolved.source.populationHash === resolved.source.cellHash
    ) {
      authorityMismatch("Result-cell authority returned aliased evidence hashes");
    }
    return resolved;
  }
}

function assertRepositoryIdentity(
  value: unknown,
  tenantId: string,
  runId: string
): asserts value is Readonly<{ tenantId: string; runId: string }> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    (value as Readonly<Record<string, unknown>>).tenantId !== tenantId ||
    (value as Readonly<Record<string, unknown>>).runId !== runId
  ) {
    authorityMismatch("Metric-run repository returned a different tenant or run identity");
  }
}

function assertRepositoryObservationIdentity(
  run: MetricRunV1,
  input: Readonly<{
    tenantId: string;
    metricId: string;
    asOfDate: string;
    scope: MetricRunScopeV1;
    sourceHash: Sha256Hash;
  }>
): void {
  if (
    run.tenantId !== input.tenantId ||
    run.metricId !== input.metricId ||
    run.observation.asOfDate !== input.asOfDate ||
    canonicalJson(run.observation.scope) !== canonicalJson(input.scope) ||
    run.source.sourceHash !== input.sourceHash
  ) {
    authorityMismatch("Metric-run repository returned a different observation identity");
  }
}

function candidateIntentMatches(
  run: Exclude<ReturnType<MetricRunStore["get"]>, undefined>,
  request: CreateMetricRunCandidateRequestV1
): boolean {
  return (
    run.tenantId === request.tenantId &&
    run.runId === request.runId &&
    run.projection.definitionId === request.projectionDefinitionId &&
    run.source.resultArtifactId === request.surveillanceResultArtifactId &&
    run.source.cellId === request.cellId &&
    run.createdBy === request.createdBy
  );
}

function candidateBody(value: FrozenMetricResultCellV1 | MetricRunViewV1) {
  return {
    tenantId: value.tenantId,
    projection: value.projection,
    metricId: value.metricId,
    metricDefinition: value.metricDefinition,
    methodology: value.methodology,
    source: value.source,
    observation: "scopeHash" in value.observation
      ? withoutScopeHash(value.observation)
      : value.observation
  };
}

function storeReplayInput(
  run: Exclude<ReturnType<MetricRunStore["get"]>, undefined>,
  idempotencyKey: string
): CreateMetricRunInput {
  return {
    contractVersion: 1,
    tenantId: run.tenantId,
    runId: run.runId,
    metricId: run.metricId,
    projection: run.projection,
    metricDefinition: run.metricDefinition,
    methodology: run.methodology,
    source: run.source,
    observation: withoutScopeHash(run.observation),
    createdBy: run.createdBy,
    idempotencyKey
  };
}

function withoutScopeHash(observation: MetricRunV1["observation"]) {
  const { scopeHash: _scopeHash, ...requestObservation } = observation;
  return requestObservation;
}

function validateCreateRequest(request: CreateMetricRunCandidateRequestV1): void {
  requestObject(request, [
    "cellId",
    "createdBy",
    "idempotencyKey",
    "projectionDefinitionId",
    "runId",
    "surveillanceResultArtifactId",
    "tenantId"
  ]);
  for (const [value, label] of [
    [request.tenantId, "tenantId"],
    [request.runId, "runId"],
    [request.projectionDefinitionId, "projectionDefinitionId"],
    [request.surveillanceResultArtifactId, "surveillanceResultArtifactId"],
    [request.cellId, "cellId"],
    [request.createdBy, "createdBy"],
    [request.idempotencyKey, "idempotencyKey"]
  ] as const) {
    parseWithSchema(IdentifierSchema, value, label);
  }
}

function validateApprovalRequest(request: ApproveMetricRunCandidateRequestV1): void {
  requestObject(request, ["approvedBy", "expectedRunHash", "idempotencyKey", "runId", "tenantId"]);
  for (const [value, label] of [
    [request.tenantId, "tenantId"],
    [request.runId, "runId"],
    [request.approvedBy, "approvedBy"],
    [request.idempotencyKey, "idempotencyKey"]
  ] as const) {
    parseWithSchema(IdentifierSchema, value, label);
  }
  parseWithSchema(Sha256HashSchema, request.expectedRunHash, "expectedRunHash");
}

function validateVerificationRequest(request: VerifyMetricRunObservationRequestV1): void {
  requestObject(request, ["asOfDate", "measurement", "metricId", "runId", "scope", "tenantId"]);
  for (const [value, label] of [
    [request.tenantId, "tenantId"],
    [request.runId, "runId"],
    [request.metricId, "metricId"]
  ] as const) {
    parseWithSchema(IdentifierSchema, value, label);
  }
  parseWithSchema(
    z.object({
      asOfDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
      scope: MetricRunScopeV1Schema,
      measurement: MetricRunValueV1Schema
    }).strict(),
    { asOfDate: request.asOfDate, scope: request.scope, measurement: request.measurement },
    "MetricRunV1 observation verification"
  );
}

function requestObject(value: unknown, expectedKeys: readonly string[]): void {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalidRequest("Request must be an object");
  if (canonicalJson(Object.keys(value as Record<string, unknown>).sort()) !== canonicalJson([...expectedKeys].sort())) {
    invalidRequest("Request contains missing or unknown fields");
  }
}

function invalidRequest(message: string): never {
  throw new MetricRunEvidenceError("INVALID_REQUEST", message);
}

function authorityMismatch(message: string): never {
  throw new MetricRunEvidenceError("AUTHORITY_MISMATCH", message);
}
