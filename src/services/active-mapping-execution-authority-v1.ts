import {
  canonicalJson,
  createMappingSpecV2,
  parseMappingSpecV2,
  type MappingSpecV2
} from "../contracts/index.js";
import type {
  GovernedDefinitionAuditEventV2,
  GovernedDefinitionViewV2
} from "../control/governed-definitions-v2.js";
import type {
  GovernedDefinitionExecutionReferenceV2,
  GovernedDefinitionV2Resolver
} from "./governed-definition-v2-resolver.js";

const AUDIT_PAGE_SIZE = 1_000;
const MAX_AUDIT_EVENTS = 1_000_000;

export interface ActiveMappingActivationEvidenceV1 {
  readonly status: "active";
  readonly lifecycleRevision: number;
  readonly activatedBy: string;
  readonly activatedAt: string;
  readonly activationEventHash: `sha256:${string}`;
}

export interface ActiveMappingExecutionV1 {
  readonly reference: GovernedDefinitionExecutionReferenceV2;
  readonly mappingSpec: MappingSpecV2;
  readonly window: Readonly<{
    effectiveFrom: string;
    effectiveTo?: string;
  }>;
  readonly activationEvidence: ActiveMappingActivationEvidenceV1;
}

export type ActiveMappingExecutionAuthorityV1ErrorCode =
  | "NOT_FOUND"
  | "NOT_ACTIVE"
  | "INTEGRITY_FAILURE";

export class ActiveMappingExecutionAuthorityV1Error extends Error {
  constructor(readonly code: ActiveMappingExecutionAuthorityV1ErrorCode, message: string) {
    super(message);
    this.name = "ActiveMappingExecutionAuthorityV1Error";
  }
}

/**
 * Adds the current lifecycle activation proof that engine projections need.
 * The shared governed resolver deliberately projects approval, not activation;
 * this adapter leaves that high-impact resolver unchanged and derives a newly
 * hashed `active` MappingSpec only after re-verifying the exact current view.
 */
export class ActiveMappingExecutionAuthorityV1 {
  constructor(readonly resolver: GovernedDefinitionV2Resolver) {}

  resolveEffective(input: {
    readonly tenantId: string;
    readonly definitionKey: string;
    readonly asOfDate: string;
  }): ActiveMappingExecutionV1 {
    const view = this.resolver.authority.selectEffective(
      input.tenantId,
      "mapping_spec",
      input.definitionKey,
      input.asOfDate
    );
    return this.#resolveActiveView(input.tenantId, view);
  }

  resolveFrozenActive(input: {
    readonly tenantId: string;
    readonly definitionVersionId: string;
  }): ActiveMappingExecutionV1 {
    const view = this.resolver.authority.get(input.tenantId, input.definitionVersionId);
    if (view === undefined) {
      throw new ActiveMappingExecutionAuthorityV1Error(
        "NOT_FOUND",
        "The requested governed mapping definition was not found"
      );
    }
    return this.#resolveActiveView(input.tenantId, view);
  }

  #resolveActiveView(
    tenantId: string,
    view: GovernedDefinitionViewV2
  ): ActiveMappingExecutionV1 {
    if (view.version.tenantId !== tenantId || view.version.kind !== "mapping_spec") {
      integrity("Governed mapping authority crossed a tenant or definition-kind boundary");
    }
    if (view.status !== "active") {
      throw new ActiveMappingExecutionAuthorityV1Error(
        "NOT_ACTIVE",
        "Certification requires a currently active governed mapping definition"
      );
    }

    const resolved = this.resolver.resolveFrozen({
      tenantId,
      definitionVersionId: view.version.definitionVersionId
    });
    if (
      resolved.reference.kind !== "mapping_spec" ||
      resolved.reference.definitionVersionId !== view.version.definitionVersionId ||
      resolved.reference.versionHash !== view.version.versionHash ||
      resolved.reference.documentHash !== view.version.documentHash
    ) {
      integrity("Resolved mapping execution reference did not match the active lifecycle view");
    }

    const after = this.resolver.authority.get(tenantId, view.version.definitionVersionId);
    if (after === undefined || canonicalJson(after) !== canonicalJson(view) || after.status !== "active") {
      integrity("Governed mapping lifecycle changed during active execution resolution");
    }
    const activationEvent = this.#activationEvent(tenantId, after);
    const approved = parseMappingSpecV2(resolved.executionDocument);
    if (
      approved.status !== "approved" ||
      approved.tenantId !== tenantId ||
      approved.mappingKey !== view.version.definitionKey
    ) {
      integrity("Approved governed mapping projection did not match its lifecycle identity");
    }
    const { mappingSpecHash: _approvedHash, ...approvedBody } = approved;
    const mappingSpec = createMappingSpecV2({ ...approvedBody, status: "active" });
    const window = Object.freeze({
      effectiveFrom: view.version.effectiveFrom,
      ...(view.version.effectiveTo === null ? {} : { effectiveTo: view.version.effectiveTo })
    });
    return Object.freeze({
      reference: resolved.reference,
      mappingSpec,
      window,
      activationEvidence: Object.freeze({
        status: "active" as const,
        lifecycleRevision: view.lifecycleRevision,
        activatedBy: activationEvent.actor,
        activatedAt: activationEvent.occurredAt,
        activationEventHash: activationEvent.eventHash
      })
    });
  }

  #activationEvent(
    tenantId: string,
    view: GovernedDefinitionViewV2
  ): GovernedDefinitionAuditEventV2 {
    let afterSequence = 0;
    let count = 0;
    let matched: GovernedDefinitionAuditEventV2 | undefined;
    for (;;) {
      const page = this.resolver.authority.listAuditEvents(
        tenantId,
        afterSequence,
        AUDIT_PAGE_SIZE
      );
      if (!Array.isArray(page)) integrity("Governed mapping audit authority returned an invalid page");
      if (page.length === 0) break;
      for (const event of page) {
        count += 1;
        if (count > MAX_AUDIT_EVENTS) integrity("Governed mapping audit history exceeded its safety bound");
        if (event.sequence <= afterSequence) integrity("Governed mapping audit pagination did not advance");
        afterSequence = event.sequence;
        if (
          event.definitionVersionId === view.version.definitionVersionId &&
          event.lifecycleRevision === view.lifecycleRevision
        ) {
          if (matched !== undefined) integrity("Governed mapping activation evidence was duplicated");
          matched = event;
        }
      }
      if (page.length < AUDIT_PAGE_SIZE) break;
    }
    if (
      matched === undefined ||
      matched.toStatus !== "active" ||
      matched.actor !== view.lastTransitionBy ||
      matched.occurredAt !== view.lastTransitionAt
    ) {
      integrity("Current active mapping view lacks exact immutable activation evidence");
    }
    return matched;
  }
}

function integrity(message: string): never {
  throw new ActiveMappingExecutionAuthorityV1Error("INTEGRITY_FAILURE", message);
}
