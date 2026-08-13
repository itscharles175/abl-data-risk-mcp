import { z } from "zod";

import {
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  parseWithSchema,
  type Sha256Hash
} from "./canonical.js";
import type { GovernedDatasetScopeBindingV1 } from "./dataset-scope-binding-v1.js";
import type { SourceContractV1 } from "./source-contract-v1.js";

const BoundedTextSchema = z
  .string()
  .min(1)
  .max(1_024)
  .refine((value) => !/[\u0000-\u001f\u007f]/.test(value), "must not contain control characters");

const PostgresqlDeliveryLocatorV1Schema = z
  .object({
    mode: z.literal("postgresql_pull"),
    connectorId: IdentifierSchema,
    catalog: BoundedTextSchema.optional(),
    schema: BoundedTextSchema,
    relation: BoundedTextSchema,
    relationIdentityHash: Sha256HashSchema,
    sourceVersionHash: Sha256HashSchema,
    watermark: BoundedTextSchema.optional()
  })
  .strict();

const ObjectStorageDeliveryLocatorV1Schema = z
  .object({
    mode: z.literal("object_storage"),
    format: z.enum(["xlsx", "parquet"]),
    connectorId: IdentifierSchema,
    bucket: BoundedTextSchema,
    objectKey: BoundedTextSchema,
    immutableVersionId: BoundedTextSchema,
    immutableVersionHash: Sha256HashSchema,
    contentHash: Sha256HashSchema,
    byteCount: z.number().int().positive().max(10_000_000_000)
  })
  .strict();

export const GovernedSourceDeliveryLocatorV1Schema = z.discriminatedUnion("mode", [
  PostgresqlDeliveryLocatorV1Schema,
  ObjectStorageDeliveryLocatorV1Schema
]);

const SourceContractReferenceV1Schema = z
  .object({
    sourceContractId: IdentifierSchema,
    revision: z.number().int().positive().max(1_000_000),
    sourceContractHash: Sha256HashSchema
  })
  .strict();

const DatasetScopeBindingReferenceV1Schema = z
  .object({
    bindingId: IdentifierSchema,
    revision: z.number().int().positive().max(1_000_000),
    bindingHash: Sha256HashSchema
  })
  .strict();

const GovernedSourceDeliveryRecordBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    deliveryId: IdentifierSchema,
    deliveryRevision: z.number().int().min(1).max(2),
    datasetId: IdentifierSchema,
    facilityId: IdentifierSchema,
    sourceContract: SourceContractReferenceV1Schema,
    scopeBinding: DatasetScopeBindingReferenceV1Schema,
    locator: GovernedSourceDeliveryLocatorV1Schema,
    sourceObservedAt: IsoTimestampSchema,
    receivedAt: IsoTimestampSchema,
    status: z.enum(["usable", "disabled"]),
    statusReason: IdentifierSchema.optional(),
    recordedBy: IdentifierSchema,
    identitySource: z.literal("server_derived"),
    recordedAt: IsoTimestampSchema,
    previousDeliveryHash: Sha256HashSchema.nullable()
  })
  .strict()
  .superRefine((value, context) => {
    if (value.sourceObservedAt > value.receivedAt) {
      context.addIssue({
        code: "custom",
        path: ["sourceObservedAt"],
        message: "must not be after receivedAt"
      });
    }
    if (value.receivedAt > value.recordedAt) {
      context.addIssue({
        code: "custom",
        path: ["receivedAt"],
        message: "must not be after recordedAt"
      });
    }
    const usable = value.status === "usable";
    if (
      (usable &&
        (value.deliveryRevision !== 1 ||
          value.previousDeliveryHash !== null ||
          value.statusReason !== undefined)) ||
      (!usable &&
        (value.deliveryRevision !== 2 ||
          value.previousDeliveryHash === null ||
          value.statusReason === undefined))
    ) {
      context.addIssue({
        code: "custom",
        path: ["status"],
        message: "usable must be revision 1; disabled must be revision 2 linked to revision 1"
      });
    }
  });

export const GovernedSourceDeliveryRecordV1Schema =
  GovernedSourceDeliveryRecordBodyV1Schema.extend({ deliveryHash: Sha256HashSchema }).strict();

export type GovernedSourceDeliveryLocatorV1 = Readonly<
  z.infer<typeof GovernedSourceDeliveryLocatorV1Schema>
>;
export type GovernedSourceDeliveryRecordV1 = Readonly<
  z.infer<typeof GovernedSourceDeliveryRecordV1Schema>
>;
export type GovernedSourceDeliveryRecordV1Input = Readonly<
  z.input<typeof GovernedSourceDeliveryRecordBodyV1Schema>
>;

export interface TrustedSourceDeliveryActorV1 {
  readonly tenantId: string;
  readonly actorId: string;
  readonly authority: "platform_operator";
  readonly identitySource: "server_derived";
}

export interface RegisterGovernedSourceDeliveryV1 {
  readonly deliveryId: string;
  readonly sourceContract: SourceContractV1;
  readonly scopeBinding: GovernedDatasetScopeBindingV1;
  readonly locator: GovernedSourceDeliveryLocatorV1;
  readonly sourceObservedAt: string;
  readonly receivedAt: string;
  readonly idempotencyKey: string;
}

export interface DisableGovernedSourceDeliveryV1 {
  readonly deliveryId: string;
  readonly reasonCode: string;
  readonly idempotencyKey: string;
}

export interface GovernedSourceDeliveryResolutionV1 {
  readonly delivery: GovernedSourceDeliveryRecordV1;
  readonly sourceContract: SourceContractV1;
  readonly scopeBinding: GovernedDatasetScopeBindingV1;
}

/** Safe inspection projection: no relation, bucket, object key, version, or credential reference. */
export interface GovernedSourceDeliveryStatusV1 {
  readonly contractVersion: 1;
  readonly tenantId: string;
  readonly deliveryId: string;
  readonly deliveryRevision: number;
  readonly deliveryHash: Sha256Hash;
  readonly datasetId: string;
  readonly facilityId: string;
  readonly sourceContract: GovernedSourceDeliveryRecordV1["sourceContract"];
  readonly scopeBinding: GovernedSourceDeliveryRecordV1["scopeBinding"];
  readonly mode: "postgresql_pull" | "object_storage";
  readonly format: "sql_rows" | "xlsx" | "parquet";
  readonly sourceObservedAt: string;
  readonly receivedAt: string;
  readonly status: "usable" | "disabled";
  readonly statusReason?: string;
  readonly recordedAt: string;
}

export interface GovernedSourceDeliveryMutationResultV1 {
  readonly resolution: GovernedSourceDeliveryResolutionV1;
  readonly replayed: boolean;
}

export interface SourceDeliveryAuditEventV1 {
  readonly contractVersion: 1;
  readonly tenantId: string;
  readonly tenantSequence: number;
  readonly eventId: string;
  readonly eventType: "source_delivery_registered" | "source_delivery_disabled";
  readonly deliveryId: string;
  readonly deliveryRevision: number;
  readonly deliveryHash: Sha256Hash;
  readonly actorId: string;
  readonly identitySource: "server_derived";
  readonly occurredAt: string;
  readonly previousEventHash: Sha256Hash | null;
  readonly eventHash: Sha256Hash;
}

export function createGovernedSourceDeliveryRecordV1(
  input: GovernedSourceDeliveryRecordV1Input
): GovernedSourceDeliveryRecordV1 {
  const body = parseWithSchema(
    GovernedSourceDeliveryRecordBodyV1Schema,
    input,
    "GovernedSourceDeliveryRecordV1"
  );
  return parseGovernedSourceDeliveryRecordV1({ ...body, deliveryHash: canonicalHash(body) });
}

export function parseGovernedSourceDeliveryRecordV1(
  value: unknown
): GovernedSourceDeliveryRecordV1 {
  const parsed = parseWithSchema(
    GovernedSourceDeliveryRecordV1Schema,
    value,
    "GovernedSourceDeliveryRecordV1"
  );
  const { deliveryHash, ...body } = parsed;
  assertCanonicalHash(body, deliveryHash, "GovernedSourceDeliveryRecordV1");
  return parsed;
}
