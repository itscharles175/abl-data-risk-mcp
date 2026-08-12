import { z } from "zod";

import type { DatasetSnapshot as LegacyDatasetSnapshotV1 } from "../control/store.js";
import {
  ContractValidationError,
  IdentifierSchema,
  IsoDateSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  assertTimestampOrder,
  canonicalHash,
  parseWithSchema
} from "./canonical.js";
import { SourceDeliveryV1Schema } from "./source-contract-v1.js";

const SourceContractReferenceV1Schema = z
  .object({
    sourceContractId: IdentifierSchema,
    revision: z.number().int().positive(),
    sourceContractHash: Sha256HashSchema
  })
  .strict();

const WatermarkRangeV1Schema = z.discriminatedUnion("mode", [
  z.object({ mode: z.literal("none") }).strict(),
  z
    .object({
      mode: z.literal("bounded"),
      field: z.string().min(1).max(256),
      lowerExclusive: z.string().max(1_024).optional(),
      upperInclusive: z.string().min(1).max(1_024),
      valueType: z.enum(["integer", "decimal", "date", "datetime", "opaque"])
    })
    .strict()
]);

const SnapshotSectionControlV2Schema = z
  .object({
    sectionId: IdentifierSchema,
    required: z.boolean(),
    present: z.boolean(),
    rowCount: z.number().int().min(0),
    contentHash: Sha256HashSchema.optional(),
    schemaHash: Sha256HashSchema.optional(),
    balance: z.string().regex(/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/).optional(),
    currency: z.string().regex(/^[A-Z]{3}$/).optional(),
    controlPopulationHash: Sha256HashSchema.optional()
  })
  .strict()
  .superRefine((value, context) => {
    if (!value.present && value.rowCount !== 0) {
      context.addIssue({ code: "custom", path: ["rowCount"], message: "absent sections must have zero rows" });
    }
    if (value.present && (value.contentHash === undefined || value.schemaHash === undefined)) {
      context.addIssue({ code: "custom", path: ["contentHash"], message: "present sections require content and schema hashes" });
    }
    if (value.balance !== undefined && value.currency === undefined) {
      context.addIssue({ code: "custom", path: ["currency"], message: "balance requires a currency" });
    }
  });

const CorrectionLineageV1Schema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("original") }).strict(),
  z
    .object({
      kind: z.literal("correction"),
      correctsSnapshotId: IdentifierSchema,
      correctsSnapshotHash: Sha256HashSchema,
      correctionSequence: z.number().int().positive(),
      reasonCode: IdentifierSchema,
      reason: z.string().min(1).max(2_000),
      detectedAt: IsoTimestampSchema
    })
    .strict()
]);

const DatasetSnapshotBodyV2Schema = z
  .object({
    contractVersion: z.literal(2),
    tenantId: IdentifierSchema,
    snapshotId: IdentifierSchema,
    sourceContract: SourceContractReferenceV1Schema,
    delivery: SourceDeliveryV1Schema,
    sourceLocator: z
      .string()
      .min(1)
      .max(2_048)
      .refine((value) => !/[\u0000-\u001f\u007f]/.test(value), "must not contain control characters"),
    immutableSourceVersion: z.string().min(1).max(1_024).optional(),
    asOfDate: IsoDateSchema,
    knowledge: z
      .object({
        sourceObservedAt: IsoTimestampSchema,
        extractedAt: IsoTimestampSchema,
        receivedAt: IsoTimestampSchema,
        persistedAt: IsoTimestampSchema
      })
      .strict(),
    watermark: WatermarkRangeV1Schema,
    hashes: z
      .object({
        contentHash: Sha256HashSchema,
        schemaHash: Sha256HashSchema,
        catalogHash: Sha256HashSchema,
        parserHash: Sha256HashSchema,
        extractionHash: Sha256HashSchema
      })
      .strict(),
    rowCount: z.number().int().min(0),
    byteCount: z.number().int().min(0),
    sections: z.array(SnapshotSectionControlV2Schema).min(1).max(256),
    correction: CorrectionLineageV1Schema,
    createdBy: IdentifierSchema
  })
  .strict()
  .superRefine((value, context) => {
    const sectionIds = value.sections.map((section) => section.sectionId);
    if (new Set(sectionIds).size !== sectionIds.length) {
      context.addIssue({ code: "custom", path: ["sections"], message: "section ids must be unique" });
    }
    for (const [index, section] of value.sections.entries()) {
      if (section.required && !section.present) {
        context.addIssue({
          code: "custom",
          path: ["sections", index, "present"],
          message: "required section must be present"
        });
      }
    }
    const sectionRows = value.sections.reduce((sum, section) => sum + section.rowCount, 0);
    if (sectionRows !== value.rowCount) {
      context.addIssue({
        code: "custom",
        path: ["rowCount"],
        message: "must equal the sum of section row counts"
      });
    }
    if (value.delivery.mode === "object_storage" && value.immutableSourceVersion === undefined) {
      context.addIssue({
        code: "custom",
        path: ["immutableSourceVersion"],
        message: "object-storage delivery requires an immutable version id"
      });
    }
    if (value.delivery.mode !== "object_storage" && value.immutableSourceVersion !== undefined) {
      context.addIssue({
        code: "custom",
        path: ["immutableSourceVersion"],
        message: "is only valid for object-storage delivery"
      });
    }
    if (value.correction.kind === "correction" && value.correction.correctsSnapshotId === value.snapshotId) {
      context.addIssue({
        code: "custom",
        path: ["correction", "correctsSnapshotId"],
        message: "a correction cannot replace itself"
      });
    }
  });

export const DatasetSnapshotV2Schema = DatasetSnapshotBodyV2Schema.extend({
  snapshotHash: Sha256HashSchema
}).strict();

export type DatasetSnapshotV2 = Readonly<z.infer<typeof DatasetSnapshotV2Schema>>;
export type DatasetSnapshotV2Input = Readonly<z.input<typeof DatasetSnapshotBodyV2Schema>>;

export function createDatasetSnapshotV2(input: DatasetSnapshotV2Input): DatasetSnapshotV2 {
  const body = parseWithSchema(DatasetSnapshotBodyV2Schema, input, "DatasetSnapshotV2");
  validateKnowledgeOrder(body.knowledge);
  return parseDatasetSnapshotV2({ ...body, snapshotHash: canonicalHash(body) });
}

export function parseDatasetSnapshotV2(value: unknown): DatasetSnapshotV2 {
  const parsed = parseWithSchema(DatasetSnapshotV2Schema, value, "DatasetSnapshotV2");
  validateKnowledgeOrder(parsed.knowledge);
  const { snapshotHash, ...body } = parsed;
  assertCanonicalHash(body, snapshotHash, "DatasetSnapshotV2");
  return parsed;
}

export interface UpgradeLegacyDatasetSnapshotV1Input {
  readonly sourceContract: z.infer<typeof SourceContractReferenceV1Schema>;
  readonly delivery: z.infer<typeof SourceDeliveryV1Schema>;
  readonly knowledge: DatasetSnapshotV2Input["knowledge"];
  readonly hashes: Omit<DatasetSnapshotV2Input["hashes"], "contentHash">;
  readonly byteCount: number;
  readonly sections: DatasetSnapshotV2Input["sections"];
  readonly correction?: DatasetSnapshotV2Input["correction"];
  readonly immutableSourceVersion?: string;
}

/** Explicit bridge that keeps the existing v1 snapshot readable while adding v2 evidence. */
export function upgradeLegacyDatasetSnapshotV1(
  legacy: LegacyDatasetSnapshotV1,
  input: UpgradeLegacyDatasetSnapshotV1Input
): DatasetSnapshotV2 {
  if (input.sections.reduce((sum, section) => sum + section.rowCount, 0) !== legacy.rowCount) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "Legacy snapshot row count must reconcile to v2 section controls"
    );
  }
  return createDatasetSnapshotV2({
    contractVersion: 2,
    tenantId: legacy.tenantId,
    snapshotId: legacy.snapshotId,
    sourceContract: input.sourceContract,
    delivery: input.delivery,
    sourceLocator: legacy.sourceLocator,
    ...(input.immutableSourceVersion === undefined
      ? {}
      : { immutableSourceVersion: input.immutableSourceVersion }),
    asOfDate: legacy.asOfDate,
    knowledge: input.knowledge,
    watermark: { mode: "none" },
    hashes: { ...input.hashes, contentHash: normalizeLegacyHash(legacy.contentHash) },
    rowCount: legacy.rowCount,
    byteCount: input.byteCount,
    sections: input.sections,
    correction: input.correction ?? { kind: "original" },
    createdBy: legacy.createdBy
  });
}

function validateKnowledgeOrder(knowledge: DatasetSnapshotV2["knowledge"]): void {
  assertTimestampOrder(
    knowledge.sourceObservedAt,
    knowledge.extractedAt,
    "sourceObservedAt",
    "extractedAt"
  );
  assertTimestampOrder(knowledge.extractedAt, knowledge.receivedAt, "extractedAt", "receivedAt");
  assertTimestampOrder(knowledge.receivedAt, knowledge.persistedAt, "receivedAt", "persistedAt");
}

function normalizeLegacyHash(value: string): `sha256:${string}` {
  const normalized = value.startsWith("sha256:") ? value : `sha256:${value}`;
  const parsed = Sha256HashSchema.safeParse(normalized);
  if (!parsed.success) {
    throw new ContractValidationError("INVALID_HASH", "Legacy snapshot content hash is invalid");
  }
  return parsed.data;
}
