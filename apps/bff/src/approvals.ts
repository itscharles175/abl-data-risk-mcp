import { randomUUID } from "node:crypto";
import {
  type ApprovalDecision,
  type ApprovalRecord,
  type HighRiskActionKind,
  type HighRiskActionRequest,
  type PlatformPermission,
  type SessionPrincipal,
} from "@abl/platform-contracts";

const ACTION_PERMISSIONS: Readonly<
  Record<HighRiskActionKind, { readonly propose: PlatformPermission; readonly approve: PlatformPermission }>
> = {
  source_contract_activation: { propose: "source:govern", approve: "source:approve" },
  mapping_activation: { propose: "mapping:govern", approve: "mapping:approve" },
  methodology_activation: { propose: "definition:govern", approve: "definition:approve" },
  membership_change: { propose: "membership:govern", approve: "membership:approve" },
  policy_change: { propose: "policy:govern", approve: "policy:approve" },
  connector_change: { propose: "connector:govern", approve: "connector:approve" },
  key_rotation: { propose: "key:rotate", approve: "key:approve" },
  deployment_change: { propose: "deployment:govern", approve: "deployment:approve" },
};

export function permissionForAction(
  kind: HighRiskActionKind,
  stage: "propose" | "approve",
): PlatformPermission {
  return ACTION_PERMISSIONS[kind][stage];
}

export class ApprovalConflictError extends Error {}
export class ApprovalNotFoundError extends Error {}

export class ApprovalService {
  readonly #records = new Map<string, ApprovalRecord>();

  public constructor(private readonly now: () => Date = () => new Date()) {}

  public create(request: HighRiskActionRequest, maker: SessionPrincipal): ApprovalRecord {
    const record: ApprovalRecord = {
      id: randomUUID(),
      kind: request.kind,
      targetId: request.targetId,
      reason: request.reason,
      ...(request.secretRef ? { secretRef: request.secretRef } : {}),
      semanticDiff: request.semanticDiff,
      rollbackTargetId: request.rollbackTargetId,
      maker,
      status: "pending",
      createdAt: this.now().toISOString(),
    };
    this.#records.set(record.id, record);
    return record;
  }

  public list(): readonly ApprovalRecord[] {
    return [...this.#records.values()].sort((left, right) =>
      right.createdAt.localeCompare(left.createdAt),
    );
  }

  public get(id: string): ApprovalRecord | undefined {
    return this.#records.get(id);
  }

  public decide(id: string, decision: ApprovalDecision, checker: SessionPrincipal): ApprovalRecord {
    const current = this.#records.get(id);
    if (!current) throw new ApprovalNotFoundError("Approval request was not found");
    if (current.status !== "pending") {
      throw new ApprovalConflictError("Approval request has already been decided");
    }
    if (current.maker.id === checker.id) {
      throw new ApprovalConflictError("Maker and checker must be different principals");
    }
    const decided: ApprovalRecord = {
      ...current,
      status: decision.decision,
      checker,
      decidedAt: this.now().toISOString(),
      rationale: decision.rationale,
    };
    this.#records.set(id, decided);
    return decided;
  }
}
