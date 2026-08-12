import { z } from "zod";

import {
  IdentifierSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  parseWithSchema,
  type CanonicalJsonValue,
  type Sha256Hash
} from "../contracts/canonical.js";

/**
 * Clone-safe policy carried with an analysis plan. Enforcement code may add
 * stricter obligations, but it may never relax these operation-level limits.
 */
export const AggregateOnlyDisclosurePolicyV2Schema = z
  .object({
    policyId: IdentifierSchema,
    mode: z.literal("aggregate_only"),
    detailRowsAllowed: z.literal(false),
    sourceRecordFieldsAllowed: z.literal(false),
    populationHashRequiredPerCell: z.literal(true),
    suppressionStateRequiredPerCell: z.literal(true)
  })
  .strict();

export type AggregateOnlyDisclosurePolicyV2 = Readonly<
  z.infer<typeof AggregateOnlyDisclosurePolicyV2Schema>
>;

const CanonicalLimitsSchema = z.custom<CanonicalJsonValue>((value) => {
  try {
    canonicalHash(value);
    return value !== null && typeof value === "object" && !Array.isArray(value);
  } catch {
    return false;
  }
}, "must be a canonical JSON object");

const AnalysisOperationDescriptorBodyV2Schema = z
  .object({
    contractVersion: z.literal(2),
    operationId: IdentifierSchema,
    kind: z.literal("analysis"),
    requestMode: z.literal("ids_only"),
    requestContract: IdentifierSchema,
    executionContract: IdentifierSchema,
    resultContract: IdentifierSchema,
    requestSchemaHash: Sha256HashSchema,
    executionSchemaHash: Sha256HashSchema,
    resultSchemaHash: Sha256HashSchema,
    limits: CanonicalLimitsSchema,
    disclosurePolicy: AggregateOnlyDisclosurePolicyV2Schema
  })
  .strict();

export const AnalysisOperationDescriptorV2Schema =
  AnalysisOperationDescriptorBodyV2Schema.extend({
    descriptorHash: Sha256HashSchema
  }).strict();

export type AnalysisOperationDescriptorV2 = Readonly<
  z.infer<typeof AnalysisOperationDescriptorV2Schema>
>;

export type AnalysisOperationDescriptorV2Input = Readonly<
  z.input<typeof AnalysisOperationDescriptorBodyV2Schema>
>;

/** Builds a self-hashed descriptor that is safe to persist or structured-clone. */
export function createAnalysisOperationDescriptorV2(
  input: AnalysisOperationDescriptorV2Input
): AnalysisOperationDescriptorV2 {
  const body = parseWithSchema(
    AnalysisOperationDescriptorBodyV2Schema,
    input,
    "AnalysisOperationDescriptorV2"
  );
  return parseAnalysisOperationDescriptorV2({
    ...body,
    descriptorHash: canonicalHash(body)
  });
}

export function parseAnalysisOperationDescriptorV2(
  value: unknown
): AnalysisOperationDescriptorV2 {
  const parsed = parseWithSchema(
    AnalysisOperationDescriptorV2Schema,
    value,
    "AnalysisOperationDescriptorV2"
  );
  const { descriptorHash, ...body } = parsed;
  assertCanonicalHash(body, descriptorHash, "AnalysisOperationDescriptorV2");
  return parsed;
}

export interface AnalysisOperationPlanningContextV2 {
  readonly tenantId: string;
  readonly purpose: string;
}

export interface FrozenDefinitionRequirementV2 {
  readonly kind: string;
  readonly definitionVersionId: string;
  readonly versionHash: Sha256Hash;
  readonly documentHash: Sha256Hash;
  readonly approvalEventHash: Sha256Hash;
}

export interface AnalysisOperationResultAccountingV2 {
  readonly aggregateRows: number;
  readonly bytes: number;
  readonly metricCount: number;
  readonly suppressedCellCount: number;
  readonly unavailableCellCount: number;
  readonly populationHashes: readonly Sha256Hash[];
  readonly disclosureClasses: readonly string[];
}

/**
 * A v2 module plans after resolving frozen definitions. This is the narrow
 * capability absent from OperationRegistryV1: requested source fields can be
 * derived from the exact immutable documents that will execute.
 *
 * The module object contains functions and is process-local. Its descriptor,
 * request, prepared payload, result and accounting values must be canonical
 * JSON and therefore structured-clone safe.
 */
export interface AnalysisOperationModuleV2<
  Request,
  Prepared,
  Result
> {
  readonly descriptor: AnalysisOperationDescriptorV2;
  parseRequest(value: unknown): Request;
  prepare(
    request: Request,
    context: AnalysisOperationPlanningContextV2
  ): Promise<Prepared>;
  execute(prepared: Prepared): Result;
  accountResult(result: Result, prepared: Prepared): AnalysisOperationResultAccountingV2;
}
