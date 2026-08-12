import { z } from "zod";

import {
  IdentifierSchema,
  IsoDateSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  parseWithSchema
} from "./canonical.js";

const BoundedTextSchema = z.string().min(1).max(512).refine(
  (value) => !/[\u0000-\u001f\u007f]/.test(value),
  "must not contain control characters"
);

const CredentialReferenceSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/, "must be an opaque secret-manager reference")
  .refine((value) => !value.includes("://") && !value.includes("@"), {
    message: "must not be a connection URI or embedded credential"
  });

const SourceColumnV1Schema = z
  .object({
    sourceName: BoundedTextSchema,
    ordinal: z.number().int().min(0).max(10_000),
    nativeType: BoundedTextSchema,
    nullable: z.boolean(),
    required: z.boolean(),
    unit: z.string().min(1).max(64).optional(),
    description: z.string().max(2_000).optional()
  })
  .strict();

const PostgresqlDeliveryV1Schema = z
  .object({
    mode: z.literal("postgresql_pull"),
    connectorId: IdentifierSchema,
    credentialRef: CredentialReferenceSchema,
    catalog: BoundedTextSchema.optional(),
    schema: BoundedTextSchema,
    relation: BoundedTextSchema
  })
  .strict();

const ManagedUploadDeliveryV1Schema = z
  .object({
    mode: z.literal("managed_upload"),
    format: z.enum(["xlsx", "parquet"]),
    logicalName: BoundedTextSchema
  })
  .strict();

const ObjectStorageDeliveryV1Schema = z
  .object({
    mode: z.literal("object_storage"),
    format: z.enum(["xlsx", "parquet"]),
    connectorId: IdentifierSchema,
    credentialRef: CredentialReferenceSchema,
    bucket: BoundedTextSchema,
    keyPattern: BoundedTextSchema,
    immutableVersionRequired: z.literal(true)
  })
  .strict();

export const SourceDeliveryV1Schema = z.discriminatedUnion("mode", [
  PostgresqlDeliveryV1Schema,
  ManagedUploadDeliveryV1Schema,
  ObjectStorageDeliveryV1Schema
]);

const SqlParserPolicyV1Schema = z
  .object({
    format: z.literal("sql_rows"),
    parserId: IdentifierSchema,
    parserVersion: z.string().min(1).max(64),
    optionsHash: Sha256HashSchema,
    exactDecimalMode: z.literal("string"),
    timezone: z.literal("UTC")
  })
  .strict();

const XlsxParserPolicyV1Schema = z
  .object({
    format: z.literal("xlsx"),
    parserId: IdentifierSchema,
    parserVersion: z.string().min(1).max(64),
    optionsHash: Sha256HashSchema,
    rejectMacros: z.literal(true),
    rejectExternalLinks: z.literal(true),
    rejectFormulaCells: z.literal(true),
    dateSystem: z.enum(["1900", "1904", "reject_mixed"]),
    exactDecimalMode: z.literal("string")
  })
  .strict();

const ParquetParserPolicyV1Schema = z
  .object({
    format: z.literal("parquet"),
    parserId: IdentifierSchema,
    parserVersion: z.string().min(1).max(64),
    optionsHash: Sha256HashSchema,
    exactDecimalMode: z.literal("string"),
    timezone: z.literal("UTC"),
    rejectSchemaMerging: z.boolean()
  })
  .strict();

const ExtractionPolicyV1Schema = z
  .object({
    mode: z.enum(["full", "watermark"]),
    watermarkField: BoundedTextSchema.optional(),
    readOnly: z.literal(true),
    maximumRows: z.number().int().positive().max(10_000_000),
    maximumColumns: z.number().int().positive().max(10_000),
    maximumBytes: z.number().int().positive().max(10_000_000_000),
    timeoutMs: z.number().int().min(100).max(3_600_000),
    cursorRows: z.number().int().positive().max(100_000)
  })
  .strict()
  .superRefine((value, context) => {
    if (value.mode === "watermark" && value.watermarkField === undefined) {
      context.addIssue({
        code: "custom",
        path: ["watermarkField"],
        message: "watermark extraction requires a watermark field"
      });
    }
    if (value.mode === "full" && value.watermarkField !== undefined) {
      context.addIssue({
        code: "custom",
        path: ["watermarkField"],
        message: "full extraction cannot declare a watermark field"
      });
    }
  });

const SectionControlV1Schema = z
  .object({
    sectionId: IdentifierSchema,
    required: z.boolean(),
    selector: BoundedTextSchema,
    keyFields: z.array(BoundedTextSchema).min(1).max(32),
    balanceField: BoundedTextSchema.optional(),
    currencyField: BoundedTextSchema.optional(),
    minimumRows: z.number().int().min(0).optional(),
    maximumRows: z.number().int().positive().optional()
  })
  .strict()
  .superRefine((value, context) => {
    if (
      value.minimumRows !== undefined &&
      value.maximumRows !== undefined &&
      value.minimumRows > value.maximumRows
    ) {
      context.addIssue({
        code: "custom",
        path: ["maximumRows"],
        message: "must be greater than or equal to minimumRows"
      });
    }
    if (new Set(value.keyFields).size !== value.keyFields.length) {
      context.addIssue({ code: "custom", path: ["keyFields"], message: "must be unique" });
    }
  });

const SourceContractBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    sourceContractId: IdentifierSchema,
    sourceKey: IdentifierSchema,
    revision: z.number().int().positive(),
    status: z.enum(["proposed", "approved", "active", "retired"]),
    delivery: SourceDeliveryV1Schema,
    schemaPolicy: z
      .object({
        columns: z.array(SourceColumnV1Schema).min(1).max(10_000),
        allowUnknownColumns: z.boolean(),
        requireStableOrdinals: z.boolean()
      })
      .strict(),
    parserPolicy: z.discriminatedUnion("format", [
      SqlParserPolicyV1Schema,
      XlsxParserPolicyV1Schema,
      ParquetParserPolicyV1Schema
    ]),
    extractionPolicy: ExtractionPolicyV1Schema,
    sections: z.array(SectionControlV1Schema).min(1).max(256),
    effectiveFrom: IsoDateSchema,
    effectiveTo: IsoDateSchema.optional(),
    createdBy: IdentifierSchema,
    createdAt: IsoTimestampSchema,
    approvedBy: IdentifierSchema.optional(),
    approvedAt: IsoTimestampSchema.optional()
  })
  .strict()
  .superRefine((value, context) => {
    const columnNames = value.schemaPolicy.columns.map((column) => column.sourceName);
    if (new Set(columnNames).size !== columnNames.length) {
      context.addIssue({ code: "custom", path: ["schemaPolicy", "columns"], message: "source names must be unique" });
    }
    const ordinals = value.schemaPolicy.columns.map((column) => column.ordinal);
    if (new Set(ordinals).size !== ordinals.length) {
      context.addIssue({ code: "custom", path: ["schemaPolicy", "columns"], message: "ordinals must be unique" });
    }
    const sectionIds = value.sections.map((section) => section.sectionId);
    if (new Set(sectionIds).size !== sectionIds.length) {
      context.addIssue({ code: "custom", path: ["sections"], message: "section ids must be unique" });
    }
    const deliveryFormat = value.delivery.mode === "postgresql_pull" ? "sql_rows" : value.delivery.format;
    if (value.parserPolicy.format !== deliveryFormat) {
      context.addIssue({ code: "custom", path: ["parserPolicy", "format"], message: "must match delivery format" });
    }
    if (value.effectiveTo !== undefined && value.effectiveTo <= value.effectiveFrom) {
      context.addIssue({ code: "custom", path: ["effectiveTo"], message: "must be after effectiveFrom" });
    }
    const governed = value.status === "approved" || value.status === "active" || value.status === "retired";
    if (governed && (value.approvedBy === undefined || value.approvedAt === undefined)) {
      context.addIssue({ code: "custom", path: ["approvedBy"], message: "governed status requires approval evidence" });
    }
    if (value.approvedBy !== undefined && value.approvedBy === value.createdBy) {
      context.addIssue({ code: "custom", path: ["approvedBy"], message: "must differ from createdBy" });
    }
  });

export const SourceContractV1Schema = SourceContractBodyV1Schema.extend({
  sourceContractHash: Sha256HashSchema
}).strict();

export type SourceContractV1 = Readonly<z.infer<typeof SourceContractV1Schema>>;
export type SourceContractV1Input = Readonly<z.input<typeof SourceContractBodyV1Schema>>;
export type SourceDeliveryModeV1 = SourceContractV1["delivery"]["mode"];

export function createSourceContractV1(input: SourceContractV1Input): SourceContractV1 {
  const body = parseWithSchema(SourceContractBodyV1Schema, input, "SourceContractV1");
  return parseSourceContractV1({ ...body, sourceContractHash: canonicalHash(body) });
}

export function parseSourceContractV1(value: unknown): SourceContractV1 {
  const parsed = parseWithSchema(SourceContractV1Schema, value, "SourceContractV1");
  const { sourceContractHash, ...body } = parsed;
  assertCanonicalHash(body, sourceContractHash, "SourceContractV1");
  return parsed;
}
