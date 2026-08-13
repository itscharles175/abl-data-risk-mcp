import { z } from "zod";

import {
  IdentifierSchema,
  IsoTimestampSchema,
  parseFxRateDefinitionV1,
  parseWithSchema,
  type FxRateDefinitionV1,
  type FxRateEvidenceV1,
  type Sha256Hash
} from "../contracts/index.js";
import {
  FxRateEvidenceStoreError,
  SqliteFxRateEvidenceStoreV1,
  type FxRateEvidenceWriteContextV1
} from "../control/fx-rate-evidence-store-v1.js";
import type { ResolvedGovernedDefinitionV2 } from "./governed-definition-v2-resolver.js";
import { createFxRateEvidenceV1 } from "../contracts/fx-evidence-v1.js";

const RequestSchema = z.object({
  fxDefinitionId: IdentifierSchema,
  effectiveAt: IsoTimestampSchema,
  idempotencyKey: IdentifierSchema
}).strict();

const ActorSchema = z.object({
  tenantId: IdentifierSchema,
  actorId: IdentifierSchema,
  authority: z.literal("platform_operator"),
  identitySource: z.literal("server_derived")
}).strict();

const MaterialSchema = z.object({
  rateEvidenceId: IdentifierSchema,
  sourceSnapshotId: IdentifierSchema,
  effectiveAt: IsoTimestampSchema,
  observedAt: IsoTimestampSchema,
  receivedAt: IsoTimestampSchema,
  sourceRate: z.string().min(1).max(275)
}).strict();

const CertifiedSnapshotSchema = z.object({
  tenantId: IdentifierSchema,
  snapshotId: IdentifierSchema,
  snapshotHash: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
  sourceContract: z.object({
    sourceContractId: IdentifierSchema,
    revision: z.number().int().positive().max(1_000_000),
    sourceContractHash: z.string().regex(/^sha256:[a-f0-9]{64}$/u)
  }).strict(),
  certifiedAt: IsoTimestampSchema
}).strict();

export interface TrustedFxRateCaptureActorV1 {
  readonly tenantId: string;
  readonly actorId: string;
  readonly authority: "platform_operator";
  readonly identitySource: "server_derived";
}

/** No rate, snapshot, source hash, tenant, or actor values cross this public boundary. */
export interface GovernedFxRateCaptureRequestV1 {
  readonly fxDefinitionId: string;
  readonly effectiveAt: string;
  readonly idempotencyKey: string;
}

export interface EffectiveFxDefinitionResolverV1 {
  resolveEffective(input: {
    readonly tenantId: string;
    readonly kind: "fx_rate_definition";
    readonly definitionKey: string;
    readonly asOfDate: string;
  }): ResolvedGovernedDefinitionV2;
}

/** Trusted delivery/provider implementation; never an operator or remote-tool payload. */
export interface TrustedFxRateMaterialAuthorityV1 {
  loadRateMaterial(input: {
    readonly tenantId: string;
    readonly definition: FxRateDefinitionV1;
    readonly effectiveAt: string;
  }): Promise<{
    readonly rateEvidenceId: string;
    readonly sourceSnapshotId: string;
    readonly effectiveAt: string;
    readonly observedAt: string;
    readonly receivedAt: string;
    readonly sourceRate: string;
  }>;
}

/** Proves the source snapshot was independently certified before it is bound to the FX rate. */
export interface CertifiedFxSourceSnapshotAuthorityV1 {
  resolveCertifiedSourceSnapshot(input: {
    readonly tenantId: string;
    readonly snapshotId: string;
  }): Promise<{
    readonly tenantId: string;
    readonly snapshotId: string;
    readonly snapshotHash: Sha256Hash;
    readonly sourceContract: {
      readonly sourceContractId: string;
      readonly revision: number;
      readonly sourceContractHash: Sha256Hash;
    };
    readonly certifiedAt: string;
  } | undefined>;
}

export interface GovernedFxRateCaptureServiceOptionsV1 {
  readonly definitions: EffectiveFxDefinitionResolverV1;
  readonly material: TrustedFxRateMaterialAuthorityV1;
  readonly snapshots: CertifiedFxSourceSnapshotAuthorityV1;
  readonly evidence: SqliteFxRateEvidenceStoreV1;
  readonly clock?: () => Date;
}

export type GovernedFxRateCaptureErrorCode =
  | "INVALID_REQUEST"
  | "NOT_FOUND"
  | "AUTHORITY_MISMATCH"
  | "INTEGRITY_FAILURE"
  | "CONFLICT";

export class GovernedFxRateCaptureError extends Error {
  constructor(readonly code: GovernedFxRateCaptureErrorCode, message: string) {
    super(message);
    this.name = "GovernedFxRateCaptureError";
  }
}

/**
 * Binds trusted FX provider material to an activated v2 definition and a
 * separately certified source snapshot. It is intentionally uncomposed from
 * operator/remote runtime until a production provider and snapshot authority
 * are supplied.
 */
export class GovernedFxRateCaptureServiceV1 {
  readonly #clock: () => Date;

  constructor(readonly options: GovernedFxRateCaptureServiceOptionsV1) {
    this.#clock = options.clock ?? (() => new Date());
  }

  async capture(
    requestValue: GovernedFxRateCaptureRequestV1,
    actorValue: TrustedFxRateCaptureActorV1
  ): Promise<Readonly<{ evidence: FxRateEvidenceV1; replayed: boolean }>> {
    const request = parsed(RequestSchema, requestValue, "FX capture request");
    const actor = parsed(ActorSchema, actorValue, "trusted FX capture actor");
    const asOfDate = request.effectiveAt.slice(0, 10);
    let resolved: ResolvedGovernedDefinitionV2;
    try {
      resolved = this.options.definitions.resolveEffective({
        tenantId: actor.tenantId,
        kind: "fx_rate_definition",
        definitionKey: request.fxDefinitionId,
        asOfDate
      });
    } catch {
      throw new GovernedFxRateCaptureError("NOT_FOUND", "No active governed FX definition is effective");
    }
    const definition = this.#definition(actor.tenantId, request.fxDefinitionId, resolved);
    const material = parsed(
      MaterialSchema,
      await this.options.material.loadRateMaterial({
        tenantId: actor.tenantId,
        definition,
        effectiveAt: request.effectiveAt
      }),
      "trusted FX rate material"
    );
    if (material.effectiveAt !== request.effectiveAt) {
      throw new GovernedFxRateCaptureError("AUTHORITY_MISMATCH", "Trusted FX material changed effective time");
    }
    const snapshot = parsed(
      CertifiedSnapshotSchema,
      await this.options.snapshots.resolveCertifiedSourceSnapshot({
        tenantId: actor.tenantId,
        snapshotId: material.sourceSnapshotId
      }),
      "certified FX source snapshot"
    );
    if (
      snapshot.tenantId !== actor.tenantId ||
      snapshot.snapshotId !== material.sourceSnapshotId ||
      snapshot.certifiedAt > material.observedAt ||
      snapshot.sourceContract.sourceContractId !== definition.sourceContract.sourceContractId ||
      snapshot.sourceContract.revision !== definition.sourceContract.revision ||
      snapshot.sourceContract.sourceContractHash !== definition.sourceContract.sourceContractHash
    ) {
      throw new GovernedFxRateCaptureError("AUTHORITY_MISMATCH", "Certified FX source snapshot is not usable for the definition");
    }
    const evidence = createFxRateEvidenceV1({
      definition,
      tenantId: actor.tenantId,
      rateEvidenceId: material.rateEvidenceId,
      sourceSnapshot: {
        snapshotId: snapshot.snapshotId,
        snapshotHash: snapshot.snapshotHash,
        sourceContract: snapshot.sourceContract
      },
      effectiveAt: material.effectiveAt,
      observedAt: material.observedAt,
      receivedAt: material.receivedAt,
      sourceRate: material.sourceRate,
      capturedBy: actor.actorId
    });
    const recordedAt = trustedNow(this.#clock);
    const context: FxRateEvidenceWriteContextV1 = {
      tenantId: actor.tenantId,
      actorId: actor.actorId,
      idempotencyKey: request.idempotencyKey,
      recordedAt
    };
    try {
      return this.options.evidence.record(evidence, context);
    } catch (error) {
      if (error instanceof FxRateEvidenceStoreError) {
        if (error.code === "IDEMPOTENCY_CONFLICT" || error.code === "CONFLICT") {
          throw new GovernedFxRateCaptureError("CONFLICT", "FX rate capture conflicts with immutable evidence");
        }
        if (error.code === "INTEGRITY_FAILURE") {
          throw new GovernedFxRateCaptureError("INTEGRITY_FAILURE", "FX rate evidence store failed integrity verification");
        }
      }
      throw error;
    }
  }

  #definition(
    tenantId: string,
    definitionId: string,
    resolved: ResolvedGovernedDefinitionV2
  ): FxRateDefinitionV1 {
    let definition: FxRateDefinitionV1;
    try {
      definition = parseFxRateDefinitionV1(resolved.executionDocument);
    } catch {
      throw new GovernedFxRateCaptureError("INTEGRITY_FAILURE", "Resolved FX definition is invalid");
    }
    if (
      resolved.reference.kind !== "fx_rate_definition" ||
      resolved.reference.definitionKey !== definitionId ||
      definition.tenantId !== tenantId ||
      definition.fxDefinitionId !== definitionId ||
      definition.status !== "active" ||
      definition.approvedBy !== resolved.approvalEvidence.approvedBy ||
      definition.approvedAt !== resolved.approvalEvidence.approvedAt ||
      definition.activation === undefined ||
      definition.activation.definitionVersionId !== resolved.reference.definitionVersionId ||
      definition.activation.definitionVersionHash !== resolved.reference.versionHash ||
      definition.activation.activatedAt < resolved.approvalEvidence.approvedAt
    ) {
      throw new GovernedFxRateCaptureError("AUTHORITY_MISMATCH", "Resolved FX definition identity drifted");
    }
    return definition;
  }
}

function parsed<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  try {
    return parseWithSchema(schema, value, label);
  } catch {
    throw new GovernedFxRateCaptureError("INVALID_REQUEST", `${label} failed strict validation`);
  }
}

function trustedNow(clock: () => Date): string {
  const now = clock();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new GovernedFxRateCaptureError("INTEGRITY_FAILURE", "Trusted FX capture clock is invalid");
  }
  return now.toISOString();
}
