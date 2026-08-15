import {
  GovernedDefinitionKindV2Schema,
  IdentifierSchema,
  IsoDateSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  canonicalHash,
  canonicalJson,
  parseFxRateDefinitionV1,
  parseGovernedDefinitionVersionV2,
  parseMappingSpecV2,
  parseSourceContractV1,
  validateGovernedDefinitionDocumentV2,
  type CanonicalJsonValue,
  type GovernedDefinitionKindV2,
  type GovernedDefinitionVersionV2,
  type Sha256Hash
} from "../contracts/index.js";
import type {
  GovernedDefinitionAuditEventV2,
  GovernedDefinitionStatusV2,
  GovernedDefinitionViewV2
} from "../control/governed-definitions-v2.js";
import type { BorrowingBasePolicyV2 } from "../domain/abl-v2/contracts.js";
import { validateBorrowingBasePolicyV2 } from "../domain/abl-v2/engine.js";
import type {
  BinDefinitionV1,
  CohortDefinitionV1,
  EntityResolutionDefinitionV1,
  MetricDefinitionV1
} from "../domain/surveillance/contracts.js";
import {
  validateBinDefinitionV1,
  validateCohortDefinitionV1,
  validateEntityResolutionDefinitionV1,
  validateMetricDefinitionV1
} from "../domain/surveillance/definitions.js";

const AUDIT_PAGE_SIZE = 1_000;
const MAX_AUDIT_EVENTS_PER_RESOLUTION = 1_000_000;
const BORROWING_BASE_APPROVAL_RATIONALE =
  "Approved through the governed definition v2 lifecycle";

export interface GovernedDefinitionV2AuthorityPort {
  get(tenantId: string, definitionVersionId: string): GovernedDefinitionViewV2 | undefined;
  selectEffective(
    tenantId: string,
    kind: GovernedDefinitionKindV2,
    definitionKey: string,
    asOfDate: string
  ): GovernedDefinitionViewV2;
  listAuditEvents(
    tenantId: string,
    afterSequence?: number,
    limit?: number
  ): readonly GovernedDefinitionAuditEventV2[];
}

export interface ResolveEffectiveGovernedDefinitionV2Input {
  readonly tenantId: string;
  readonly kind: GovernedDefinitionKindV2;
  readonly definitionKey: string;
  readonly asOfDate: string;
}

export interface ResolveFrozenGovernedDefinitionV2Input {
  readonly tenantId: string;
  readonly definitionVersionId: string;
}

export interface GovernedDefinitionExecutionReferenceV2 {
  readonly definitionVersionId: string;
  readonly definitionKey: string;
  readonly kind: GovernedDefinitionKindV2;
  readonly semanticVersion: string;
  readonly versionHash: Sha256Hash;
  readonly documentHash: Sha256Hash;
  readonly approvalEventHash: Sha256Hash;
}

/**
 * Compares only the seven fields that constitute a governed definition's
 * immutable execution reference. Certification evidence may extend this
 * reference with definition-specific identity and activation lineage; those
 * fields are validated separately against the resolved execution document.
 */
export function sameGovernedDefinitionExecutionReferenceV2(
  left: GovernedDefinitionExecutionReferenceV2,
  right: GovernedDefinitionExecutionReferenceV2
): boolean {
  return (
    left.definitionVersionId === right.definitionVersionId &&
    left.definitionKey === right.definitionKey &&
    left.kind === right.kind &&
    left.semanticVersion === right.semanticVersion &&
    left.versionHash === right.versionHash &&
    left.documentHash === right.documentHash &&
    left.approvalEventHash === right.approvalEventHash
  );
}

export interface GovernedDefinitionExecutionApprovalV2 {
  readonly status: "approved";
  readonly proposedBy: string;
  readonly approvedBy: string;
  readonly approvedAt: string;
  readonly approvalEventHash: Sha256Hash;
}

export interface ResolvedGovernedDefinitionV2 {
  readonly reference: GovernedDefinitionExecutionReferenceV2;
  readonly approvalEvidence: GovernedDefinitionExecutionApprovalV2;
  readonly executionDocument: CanonicalJsonValue;
}

export type GovernedDefinitionV2ResolverErrorCode =
  | "INVALID_INPUT"
  | "NOT_FOUND"
  | "UNAPPROVED"
  | "INTEGRITY_FAILURE";

export class GovernedDefinitionV2ResolverError extends Error {
  constructor(readonly code: GovernedDefinitionV2ResolverErrorCode, message: string) {
    super(message);
    this.name = "GovernedDefinitionV2ResolverError";
  }
}

/**
 * Resolves only durable, lifecycle-approved definition versions into engine
 * documents. The neutral document stored at proposal time never supplies
 * execution authority; that authority is reconstructed from the immutable
 * approval event on every resolution.
 */
export class GovernedDefinitionV2Resolver {
  constructor(readonly authority: GovernedDefinitionV2AuthorityPort) {}

  resolveEffective(inputValue: ResolveEffectiveGovernedDefinitionV2Input): ResolvedGovernedDefinitionV2 {
    const input = effectiveInput(inputValue);
    const view = this.authority.selectEffective(
      input.tenantId,
      input.kind,
      input.definitionKey,
      input.asOfDate
    );
    const resolved = this.#resolve(input.tenantId, view, ["active", "superseded"]);
    if (
      resolved.version.kind !== input.kind ||
      resolved.version.definitionKey !== input.definitionKey ||
      resolved.version.effectiveFrom > input.asOfDate ||
      (resolved.version.effectiveTo !== null && resolved.version.effectiveTo <= input.asOfDate)
    ) {
      integrity("Effective definition selection did not match the requested kind, key, or date");
    }
    return resolved.result;
  }

  resolveFrozen(inputValue: ResolveFrozenGovernedDefinitionV2Input): ResolvedGovernedDefinitionV2 {
    const input = frozenInput(inputValue);
    const view = this.authority.get(input.tenantId, input.definitionVersionId);
    if (view === undefined) {
      throw new GovernedDefinitionV2ResolverError(
        "NOT_FOUND",
        "The governed definition version was not found in the requested tenant"
      );
    }
    const resolved = this.#resolve(input.tenantId, view, [
      "active",
      "superseded",
      "retired"
    ]);
    if (resolved.version.definitionVersionId !== input.definitionVersionId) {
      integrity("Frozen definition resolution returned another definition version");
    }
    return resolved.result;
  }

  #resolve(
    tenantId: string,
    view: GovernedDefinitionViewV2,
    allowedStatuses: readonly GovernedDefinitionStatusV2[]
  ): Readonly<{
    version: GovernedDefinitionVersionV2;
    result: ResolvedGovernedDefinitionV2;
  }> {
    let version: GovernedDefinitionVersionV2;
    try {
      version = parseGovernedDefinitionVersionV2(view.version);
    } catch {
      return integrity("Governed definition version hashes or document validation failed");
    }
    if (version.tenantId !== tenantId) {
      integrity("Governed definition resolution crossed a tenant boundary");
    }
    const lifecycle = this.#verifyLifecycle(tenantId, version, view);
    if (!allowedStatuses.includes(view.status)) {
      throw new GovernedDefinitionV2ResolverError(
        "UNAPPROVED",
        `Governed definition status ${String(view.status)} is not executable in this resolution mode`
      );
    }
    const executionDocument = projectExecutionDocument(
      version,
      lifecycle.approval,
      lifecycle.activationEvent
    );
    const reference = immutable({
      definitionVersionId: version.definitionVersionId,
      definitionKey: version.definitionKey,
      kind: version.kind,
      semanticVersion: version.semanticVersion,
      versionHash: version.versionHash,
      documentHash: version.documentHash,
      approvalEventHash: lifecycle.approval.approvalEventHash
    });
    const result = immutable({
      reference,
      approvalEvidence: lifecycle.approval,
      executionDocument
    });
    return Object.freeze({ version, result });
  }

  #verifyLifecycle(
    tenantId: string,
    version: GovernedDefinitionVersionV2,
    view: GovernedDefinitionViewV2
  ): Readonly<{
    approval: GovernedDefinitionExecutionApprovalV2;
    activationEvent: GovernedDefinitionAuditEventV2 | undefined;
  }> {
    const events = this.#auditEvents(tenantId).filter(
      (event) => event.definitionVersionId === version.definitionVersionId
    );
    if (events.length === 0) integrity("Governed definition lifecycle evidence is missing");
    if (events.length !== view.lifecycleRevision) {
      integrity("Governed definition lifecycle revision does not match immutable audit evidence");
    }

    let expectedFrom: GovernedDefinitionStatusV2 | null = null;
    let approvalEvent: GovernedDefinitionAuditEventV2 | undefined;
    let activationEvent: GovernedDefinitionAuditEventV2 | undefined;
    for (const [index, event] of events.entries()) {
      const expectedRevision = index + 1;
      if (
        event.lifecycleRevision !== expectedRevision ||
        event.fromStatus !== expectedFrom ||
        !isLegalTransition(event.fromStatus, event.toStatus)
      ) {
        integrity("Governed definition lifecycle transition evidence is invalid");
      }
      if (expectedRevision === 1) {
        if (
          event.toStatus !== "proposed" ||
          event.actor !== version.proposedBy ||
          event.occurredAt !== version.proposedAt ||
          canonicalJson(event.evidence) !==
            canonicalJson({
              documentHash: version.documentHash,
              semanticDiffHash: version.semanticDiffHash,
              versionHash: version.versionHash
            })
        ) {
          integrity("Governed definition proposal evidence does not match the immutable version");
        }
      }
      if (
        event.actor === version.proposedBy &&
        ["validated", "approved", "active", "retired", "withdrawn"].includes(event.toStatus)
      ) {
        integrity("Governed definition maker cannot perform a checker lifecycle transition");
      }
      if (event.toStatus === "approved") {
        if (approvalEvent !== undefined) integrity("Governed definition contains duplicate approvals");
        approvalEvent = event;
      }
      if (event.toStatus === "active") {
        if (activationEvent !== undefined) integrity("Governed definition contains duplicate activations");
        activationEvent = event;
      }
      expectedFrom = event.toStatus;
    }

    const current = events.at(-1)!;
    if (
      current.lifecycleRevision !== view.lifecycleRevision ||
      current.toStatus !== view.status ||
      current.actor !== view.lastTransitionBy ||
      current.occurredAt !== view.lastTransitionAt
    ) {
      integrity("Governed definition current lifecycle state does not match audit evidence");
    }
    if (approvalEvent === undefined || view.approvalEvidence === null) {
      throw new GovernedDefinitionV2ResolverError(
        "UNAPPROVED",
        "Governed definition does not have durable approval evidence"
      );
    }
    const evidence = view.approvalEvidence;
    if (
      evidence.status !== "approved" ||
      evidence.proposedBy !== version.proposedBy ||
      evidence.approvedBy !== approvalEvent.actor ||
      evidence.approvedAt !== approvalEvent.occurredAt ||
      evidence.approvalEventHash !== approvalEvent.eventHash ||
      evidence.approvedBy === evidence.proposedBy
    ) {
      integrity("Governed definition approval evidence does not match the approval event");
    }
    return immutable({
      approval: {
        status: "approved" as const,
        proposedBy: version.proposedBy,
        approvedBy: approvalEvent.actor,
        approvedAt: approvalEvent.occurredAt,
        approvalEventHash: approvalEvent.eventHash
      },
      activationEvent
    });
  }

  #auditEvents(tenantId: string): readonly GovernedDefinitionAuditEventV2[] {
    const events: GovernedDefinitionAuditEventV2[] = [];
    let afterSequence = 0;
    let previousHash: Sha256Hash | null = null;
    let previousOccurredAt: string | null = null;
    for (;;) {
      const page = this.authority.listAuditEvents(tenantId, afterSequence, AUDIT_PAGE_SIZE);
      if (!Array.isArray(page)) integrity("Governed definition audit authority returned an invalid page");
      if (page.length === 0) break;
      for (const event of page) {
        validateAuditEvent(tenantId, event, afterSequence, previousHash, previousOccurredAt);
        afterSequence = event.sequence;
        previousHash = event.eventHash;
        previousOccurredAt = event.occurredAt;
        events.push(event);
        if (events.length > MAX_AUDIT_EVENTS_PER_RESOLUTION) {
          integrity("Governed definition audit history exceeds the resolution safety bound");
        }
      }
      if (page.length < AUDIT_PAGE_SIZE) break;
    }
    return events;
  }
}

function projectExecutionDocument(
  version: GovernedDefinitionVersionV2,
  approval: GovernedDefinitionExecutionApprovalV2,
  activationEvent: GovernedDefinitionAuditEventV2 | undefined
): CanonicalJsonValue {
  const document = record(version.document, `${version.kind} document`);
  try {
    switch (version.kind) {
      case "source_contract": {
        const { sourceContractHash: _sourceContractHash, ...stored } = document;
        const body = {
          ...stored,
          status: "approved" as const,
          createdBy: approval.proposedBy,
          createdAt: version.proposedAt,
          approvedBy: approval.approvedBy,
          approvedAt: approval.approvedAt
        };
        return immutable(canonicalClone(parseSourceContractV1({
          ...body,
          sourceContractHash: canonicalHash(body)
        })));
      }
      case "mapping_spec": {
        const { mappingSpecHash: _mappingSpecHash, ...stored } = document;
        const body = {
          ...stored,
          status: "approved" as const,
          createdBy: approval.proposedBy,
          createdAt: version.proposedAt,
          approvedBy: approval.approvedBy,
          approvedAt: approval.approvedAt
        };
        return immutable(canonicalClone(parseMappingSpecV2({
          ...body,
          mappingSpecHash: canonicalHash(body)
        })));
      }
      case "fx_rate_definition": {
        if (activationEvent === undefined) {
          integrity("FX execution requires immutable lifecycle activation evidence");
        }
        const { definitionHash: _definitionHash, ...stored } = document;
        const activationBody = {
          authority: "governed_definition_v2_lifecycle" as const,
          tenantId: version.tenantId,
          fxDefinitionId: version.definitionKey,
          version: version.semanticVersion,
          definitionVersionId: version.definitionVersionId,
          definitionVersionHash: version.versionHash,
          activationEventId: activationEvent.eventId,
          tenantSequence: activationEvent.sequence,
          previousEventHash: activationEvent.previousEventHash,
          activationEventHash: activationEvent.eventHash,
          activatedBy: activationEvent.actor,
          activatedAt: activationEvent.occurredAt
        };
        const body = {
          ...stored,
          status: "active" as const,
          createdBy: approval.proposedBy,
          createdAt: version.proposedAt,
          approvedBy: approval.approvedBy,
          approvedAt: approval.approvedAt,
          activation: {
            ...activationBody,
            referenceHash: canonicalHash(activationBody)
          }
        };
        return immutable(canonicalClone(parseFxRateDefinitionV1({
          ...body,
          definitionHash: canonicalHash(body)
        })));
      }
      case "metric_definition": {
        const projected = canonicalClone({ ...document, approval: engineApproval(approval) });
        validateMetricDefinitionV1(projected as unknown as MetricDefinitionV1);
        return immutable(projected);
      }
      case "cohort_definition": {
        const projected = canonicalClone({ ...document, approval: engineApproval(approval) });
        validateCohortDefinitionV1(projected as unknown as CohortDefinitionV1);
        return immutable(projected);
      }
      case "bin_definition": {
        const projected = canonicalClone({ ...document, approval: engineApproval(approval) });
        validateBinDefinitionV1(projected as unknown as BinDefinitionV1);
        return immutable(projected);
      }
      case "entity_resolution_definition": {
        const projected = canonicalClone({ ...document, approval: engineApproval(approval) });
        validateEntityResolutionDefinitionV1(
          projected as unknown as EntityResolutionDefinitionV1,
          version.tenantId
        );
        return immutable(projected);
      }
      case "borrowing_base_policy_v2": {
        const projected = canonicalClone({
          ...document,
          approval: {
            ...engineApproval(approval),
            authorityRef: approval.approvalEventHash,
            rationale: BORROWING_BASE_APPROVAL_RATIONALE
          }
        });
        validateBorrowingBasePolicyV2(projected as unknown as BorrowingBasePolicyV2);
        return immutable(projected);
      }
      default: {
        const projected = validateGovernedDefinitionDocumentV2(
          version.kind,
          document,
          version.tenantId,
          version.definitionKey,
          version.semanticVersion,
          version.effectiveFrom,
          version.effectiveTo
        );
        return immutable(canonicalClone(projected));
      }
    }
  } catch {
    return integrity(`Approved ${version.kind} document cannot be projected into a valid engine document`);
  }
}

function engineApproval(approval: GovernedDefinitionExecutionApprovalV2): Readonly<{
  status: "approved";
  proposedBy: string;
  approvedBy: string;
  approvedAt: string;
}> {
  return {
    status: "approved",
    proposedBy: approval.proposedBy,
    approvedBy: approval.approvedBy,
    approvedAt: approval.approvedAt
  };
}

function validateAuditEvent(
  tenantId: string,
  event: GovernedDefinitionAuditEventV2,
  previousSequence: number,
  previousHash: Sha256Hash | null,
  previousOccurredAt: string | null
): void {
  if (
    !Number.isSafeInteger(event.sequence) ||
    event.sequence <= previousSequence ||
    event.tenantId !== tenantId ||
    !IdentifierSchema.safeParse(event.eventId).success ||
    !IdentifierSchema.safeParse(event.definitionVersionId).success ||
    !Number.isSafeInteger(event.lifecycleRevision) ||
    event.lifecycleRevision < 1 ||
    !IdentifierSchema.safeParse(event.actor).success ||
    !IsoTimestampSchema.safeParse(event.occurredAt).success ||
    !Sha256HashSchema.safeParse(event.eventHash).success ||
    event.previousEventHash !== previousHash ||
    (previousOccurredAt !== null && event.occurredAt < previousOccurredAt)
  ) {
    integrity("Governed definition audit sequence or event fields failed validation");
  }
  const { sequence: _sequence, eventHash: _eventHash, ...body } = event;
  try {
    if (canonicalHash(body) !== event.eventHash) {
      integrity("Governed definition audit event hash failed verification");
    }
  } catch {
    integrity("Governed definition audit event is not canonical");
  }
}

function isLegalTransition(
  fromStatus: GovernedDefinitionStatusV2 | null,
  toStatus: GovernedDefinitionStatusV2
): boolean {
  if (fromStatus === null) return toStatus === "proposed";
  return (
    (fromStatus === "proposed" && (toStatus === "validated" || toStatus === "withdrawn")) ||
    (fromStatus === "validated" && (toStatus === "approved" || toStatus === "withdrawn")) ||
    (fromStatus === "approved" && (toStatus === "active" || toStatus === "withdrawn")) ||
    (fromStatus === "active" && (toStatus === "superseded" || toStatus === "retired")) ||
    (fromStatus === "superseded" && toStatus === "retired")
  );
}

function effectiveInput(
  input: ResolveEffectiveGovernedDefinitionV2Input
): ResolveEffectiveGovernedDefinitionV2Input {
  identifier(input.tenantId, "tenantId");
  if (!GovernedDefinitionKindV2Schema.safeParse(input.kind).success) invalid("kind is invalid");
  identifier(input.definitionKey, "definitionKey");
  if (!IsoDateSchema.safeParse(input.asOfDate).success) invalid("asOfDate is invalid");
  return Object.freeze({ ...input });
}

function frozenInput(
  input: ResolveFrozenGovernedDefinitionV2Input
): ResolveFrozenGovernedDefinitionV2Input {
  identifier(input.tenantId, "tenantId");
  identifier(input.definitionVersionId, "definitionVersionId");
  return Object.freeze({ ...input });
}

function identifier(value: string, label: string): void {
  if (!IdentifierSchema.safeParse(value).success) invalid(`${label} is invalid`);
}

function record(value: CanonicalJsonValue, label: string): Readonly<Record<string, CanonicalJsonValue>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    integrity(`${label} is not an object`);
  }
  return value as Readonly<Record<string, CanonicalJsonValue>>;
}

function canonicalClone(value: unknown): CanonicalJsonValue {
  return JSON.parse(canonicalJson(value)) as CanonicalJsonValue;
}

function immutable<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) immutable(nested);
    Object.freeze(value);
  }
  return value;
}

function invalid(message: string): never {
  throw new GovernedDefinitionV2ResolverError("INVALID_INPUT", message);
}

function integrity(message: string): never {
  throw new GovernedDefinitionV2ResolverError("INTEGRITY_FAILURE", message);
}
