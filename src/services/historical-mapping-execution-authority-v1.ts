import {
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  canonicalHash,
  canonicalJson,
  createMappingSpecV2,
  parseMappingSpecV2,
  type MappingSpecV2,
  type Sha256Hash
} from "../contracts/index.js";
import type {
  GovernedDefinitionAuditEventV2,
  GovernedDefinitionStatusV2,
  GovernedDefinitionViewV2
} from "../control/governed-definitions-v2.js";
import {
  GovernedDefinitionV2Resolver,
  GovernedDefinitionV2ResolverError,
  type GovernedDefinitionExecutionReferenceV2
} from "./governed-definition-v2-resolver.js";

const AUDIT_PAGE_SIZE = 1_000;
const MAX_AUDIT_EVENTS = 1_000_000;

export interface HistoricalMappingActivationEvidenceV1 {
  readonly status: "active";
  readonly lifecycleRevision: number;
  readonly activatedBy: string;
  readonly activatedAt: string;
  readonly activationEventHash: `sha256:${string}`;
}

export interface HistoricalMappingExecutionV1 {
  readonly reference: GovernedDefinitionExecutionReferenceV2;
  readonly mappingSpec: MappingSpecV2;
  readonly window: Readonly<{
    effectiveFrom: string;
    effectiveTo?: string;
  }>;
  /** Immutable evidence that the frozen mapping was active no later than certification. */
  readonly activationEvidence: HistoricalMappingActivationEvidenceV1;
}

export interface ResolveHistoricalFrozenMappingV1Input {
  readonly tenantId: string;
  readonly definitionVersionId: string;
  /** ISO timestamp of the certification or other governed replay decision. */
  readonly certificationAt: string;
}

export type HistoricalMappingExecutionAuthorityV1ErrorCode =
  | "INVALID_INPUT"
  | "NOT_FOUND"
  | "NOT_ACTIVE_AT_TIME"
  | "INTEGRITY_FAILURE";

export class HistoricalMappingExecutionAuthorityV1Error extends Error {
  constructor(readonly code: HistoricalMappingExecutionAuthorityV1ErrorCode, message: string) {
    super(message);
    this.name = "HistoricalMappingExecutionAuthorityV1Error";
  }
}

/**
 * Resolves a named mapping version for deterministic replay. Unlike the live
 * authority, a currently superseded or retired version remains executable only
 * when its immutable lifecycle chain proves it had already become active at
 * the requested certification instant. A withdrawn or never-active version
 * can never gain replay authority.
 */
export class HistoricalMappingExecutionAuthorityV1 {
  constructor(readonly resolver: GovernedDefinitionV2Resolver) {}

  resolveFrozenAt(inputValue: ResolveHistoricalFrozenMappingV1Input): HistoricalMappingExecutionV1 {
    const input = validateInput(inputValue);
    const before = this.resolver.authority.get(input.tenantId, input.definitionVersionId);
    if (before === undefined) {
      throw new HistoricalMappingExecutionAuthorityV1Error(
        "NOT_FOUND",
        "The requested governed mapping definition was not found"
      );
    }
    if (before.version.tenantId !== input.tenantId || before.version.kind !== "mapping_spec") {
      integrity("Governed historical mapping resolution crossed a tenant or definition-kind boundary");
    }

    let resolved: ReturnType<GovernedDefinitionV2Resolver["resolveFrozen"]>;
    try {
      resolved = this.resolver.resolveFrozen({
        tenantId: input.tenantId,
        definitionVersionId: input.definitionVersionId
      });
    } catch (error) {
      rethrowResolutionError(error);
    }
    if (
      resolved.reference.kind !== "mapping_spec" ||
      resolved.reference.definitionVersionId !== before.version.definitionVersionId ||
      resolved.reference.versionHash !== before.version.versionHash ||
      resolved.reference.documentHash !== before.version.documentHash
    ) {
      integrity("Resolved historical mapping execution reference did not match the frozen lifecycle view");
    }

    const activationEvent = this.#activationEventAtOrBefore(input, before);
    const after = this.resolver.authority.get(input.tenantId, input.definitionVersionId);
    if (after === undefined || canonicalJson(after) !== canonicalJson(before)) {
      integrity("Governed mapping lifecycle changed during historical execution resolution");
    }

    let approved: MappingSpecV2;
    try {
      approved = parseMappingSpecV2(resolved.executionDocument);
    } catch {
      return integrity("Resolved historical mapping document could not be parsed");
    }
    if (
      approved.status !== "approved" ||
      approved.tenantId !== input.tenantId ||
      approved.mappingKey !== before.version.definitionKey
    ) {
      integrity("Approved historical mapping projection did not match its lifecycle identity");
    }
    const { mappingSpecHash: _approvedHash, ...approvedBody } = approved;
    const mappingSpec = createMappingSpecV2({ ...approvedBody, status: "active" });
    const window = Object.freeze({
      effectiveFrom: before.version.effectiveFrom,
      ...(before.version.effectiveTo === null ? {} : { effectiveTo: before.version.effectiveTo })
    });
    return Object.freeze({
      reference: resolved.reference,
      mappingSpec,
      window,
      activationEvidence: Object.freeze({
        status: "active" as const,
        lifecycleRevision: activationEvent.lifecycleRevision,
        activatedBy: activationEvent.actor,
        activatedAt: activationEvent.occurredAt,
        activationEventHash: activationEvent.eventHash
      })
    });
  }

  #activationEventAtOrBefore(
    input: ResolveHistoricalFrozenMappingV1Input,
    view: GovernedDefinitionViewV2
  ): GovernedDefinitionAuditEventV2 {
    const events = this.#auditEvents(input.tenantId).filter(
      (event) => event.definitionVersionId === input.definitionVersionId
    );
    if (events.length !== view.lifecycleRevision) {
      integrity("Historical mapping lifecycle revision does not match immutable audit evidence");
    }

    let expectedFrom: GovernedDefinitionStatusV2 | null = null;
    let activation: GovernedDefinitionAuditEventV2 | undefined;
    for (const [index, event] of events.entries()) {
      const revision = index + 1;
      if (
        event.lifecycleRevision !== revision ||
        event.fromStatus !== expectedFrom ||
        !isLegalTransition(event.fromStatus, event.toStatus)
      ) {
        integrity("Historical mapping lifecycle transition evidence is invalid");
      }
      if (event.toStatus === "active") {
        if (activation !== undefined) integrity("Historical mapping activation evidence was duplicated");
        activation = event;
      }
      expectedFrom = event.toStatus;
    }
    const current = events.at(-1);
    if (
      current === undefined ||
      current.toStatus !== view.status ||
      current.actor !== view.lastTransitionBy ||
      current.occurredAt !== view.lastTransitionAt
    ) {
      integrity("Historical mapping current lifecycle state does not match audit evidence");
    }
    if (activation === undefined || activation.occurredAt > input.certificationAt) {
      throw new HistoricalMappingExecutionAuthorityV1Error(
        "NOT_ACTIVE_AT_TIME",
        "The requested mapping version was not active by the requested certification time"
      );
    }
    return activation;
  }

  #auditEvents(tenantId: string): readonly GovernedDefinitionAuditEventV2[] {
    const events: GovernedDefinitionAuditEventV2[] = [];
    let afterSequence = 0;
    let previousHash: Sha256Hash | null = null;
    let previousOccurredAt: string | null = null;
    for (;;) {
      const page = this.resolver.authority.listAuditEvents(tenantId, afterSequence, AUDIT_PAGE_SIZE);
      if (!Array.isArray(page)) integrity("Governed mapping audit authority returned an invalid page");
      if (page.length === 0) break;
      for (const event of page) {
        validateAuditEvent(tenantId, event, afterSequence, previousHash, previousOccurredAt);
        afterSequence = event.sequence;
        previousHash = event.eventHash;
        previousOccurredAt = event.occurredAt;
        events.push(event);
        if (events.length > MAX_AUDIT_EVENTS) {
          integrity("Governed mapping audit history exceeded its safety bound");
        }
      }
      if (page.length < AUDIT_PAGE_SIZE) break;
    }
    return events;
  }
}

function validateInput(value: ResolveHistoricalFrozenMappingV1Input): ResolveHistoricalFrozenMappingV1Input {
  if (!IdentifierSchema.safeParse(value.tenantId).success) invalid("tenantId is invalid");
  if (!IdentifierSchema.safeParse(value.definitionVersionId).success) invalid("definitionVersionId is invalid");
  if (!IsoTimestampSchema.safeParse(value.certificationAt).success) invalid("certificationAt is invalid");
  return Object.freeze({ ...value });
}

function rethrowResolutionError(error: unknown): never {
  if (error instanceof GovernedDefinitionV2ResolverError) {
    switch (error.code) {
      case "NOT_FOUND":
        throw new HistoricalMappingExecutionAuthorityV1Error("NOT_FOUND", error.message);
      case "UNAPPROVED":
        throw new HistoricalMappingExecutionAuthorityV1Error("NOT_ACTIVE_AT_TIME", error.message);
      case "INVALID_INPUT":
        throw new HistoricalMappingExecutionAuthorityV1Error("INVALID_INPUT", error.message);
      case "INTEGRITY_FAILURE":
        throw new HistoricalMappingExecutionAuthorityV1Error("INTEGRITY_FAILURE", error.message);
    }
  }
  throw error;
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
    integrity("Governed historical mapping audit sequence or event fields failed validation");
  }
  const { sequence: _sequence, eventHash: _eventHash, ...body } = event;
  try {
    if (canonicalHash(body) !== event.eventHash) {
      integrity("Governed historical mapping audit event hash failed verification");
    }
  } catch {
    integrity("Governed historical mapping audit event is not canonical");
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

function invalid(message: string): never {
  throw new HistoricalMappingExecutionAuthorityV1Error("INVALID_INPUT", message);
}

function integrity(message: string): never {
  throw new HistoricalMappingExecutionAuthorityV1Error("INTEGRITY_FAILURE", message);
}
