import { z } from "zod";

import {
  IdentifierSchema,
  IsoDateSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  parseWithSchema
} from "./canonical.js";

const FieldDefinitionV2Schema = z.object({
  canonicalId: IdentifierSchema,
  label: z.string().min(1).max(256),
  description: z.string().min(1).max(4_000),
  entity: z.enum(["loan", "loan_history", "borrower", "facility", "receivable", "inventory", "equipment", "cash", "payment", "collateral", "legal_entity"]),
  grain: z.string().min(1).max(256),
  logicalType: z.enum(["identifier", "string", "integer", "decimal", "boolean", "date", "datetime", "currency", "percentage"]),
  temporalKind: z.enum(["stock", "flow", "event", "lifetime_to_date", "dimension"]),
  unit: z.string().min(1).max(64),
  scale: z.string().regex(/^(?:0|[1-9]\d*)(?:\.\d+)?$/u),
  signConvention: z.enum(["asset_positive", "liability_positive", "natural", "boolean"]),
  currencySemantics: z.enum(["not_applicable", "record_currency", "facility_currency", "reporting_currency"]),
  enumValues: z.array(z.string().max(512)).max(10_000).optional(),
  owner: IdentifierSchema,
  steward: IdentifierSchema,
  sourceLineage: z.string().min(1).max(2_000),
  derivation: z.string().max(4_000).optional(),
  sensitivity: z.enum(["public", "internal", "confidential", "restricted"]),
  directIdentifier: z.boolean(),
  quasiIdentifier: z.boolean(),
  allowedPurposes: z.array(IdentifierSchema).min(1).max(128),
  allowedRoles: z.array(IdentifierSchema).min(1).max(128),
  maskingRule: z.enum(["none", "partial", "tokenize", "redact"]),
  aggregation: z.enum(["sum", "weighted_average", "average", "minimum", "maximum", "count_distinct", "not_aggregatable"]),
  retentionClass: IdentifierSchema,
  residencyClass: IdentifierSchema,
  exportClass: z.enum(["aggregate_only", "masked_detail", "approved_detail", "never"]),
  requiredTests: z.array(IdentifierSchema).max(128),
  effectiveFrom: IsoDateSchema,
  effectiveTo: IsoDateSchema.optional()
}).strict().superRefine((field, context) => {
  if (field.effectiveTo !== undefined && field.effectiveTo < field.effectiveFrom) {
    context.addIssue({ code: "custom", path: ["effectiveTo"], message: "must not precede effectiveFrom" });
  }
  if ((field.logicalType === "currency") !== (field.currencySemantics !== "not_applicable")) {
    context.addIssue({ code: "custom", path: ["currencySemantics"], message: "must match currency logical type" });
  }
  if ((field.enumValues?.length ?? 0) > 0 && field.logicalType !== "string") {
    context.addIssue({ code: "custom", path: ["enumValues"], message: "enumerations require string logical type" });
  }
  if (field.directIdentifier && field.maskingRule === "none") {
    context.addIssue({ code: "custom", path: ["maskingRule"], message: "direct identifiers require masking" });
  }
});

const CompatibilityChangeSchema = z.object({
  fieldId: IdentifierSchema,
  compatibility: z.enum(["additive", "behavioral", "breaking"]),
  description: z.string().min(1).max(2_000),
  migrationRef: IdentifierSchema.optional()
}).strict();

const FieldPackBodyV1Schema = z.object({
  contractVersion: z.literal(1),
  tenantId: IdentifierSchema,
  fieldPackId: IdentifierSchema,
  version: z.string().min(1).max(64),
  status: z.enum(["proposed", "approved", "active", "retired"]),
  effectiveFrom: IsoDateSchema,
  effectiveTo: IsoDateSchema.optional(),
  predecessorHash: Sha256HashSchema.optional(),
  fields: z.array(FieldDefinitionV2Schema).min(1).max(2_000),
  changes: z.array(CompatibilityChangeSchema).max(2_000),
  createdBy: IdentifierSchema,
  approvedBy: IdentifierSchema.optional()
}).strict().superRefine((pack, context) => {
  const ids = pack.fields.map((field) => field.canonicalId);
  if (new Set(ids).size !== ids.length) context.addIssue({ code: "custom", path: ["fields"], message: "canonical ids must be unique" });
  if ((pack.status === "approved" || pack.status === "active" || pack.status === "retired") && pack.approvedBy === undefined) {
    context.addIssue({ code: "custom", path: ["approvedBy"], message: "governed field pack requires approval" });
  }
  if (pack.approvedBy !== undefined && pack.approvedBy === pack.createdBy) context.addIssue({ code: "custom", path: ["approvedBy"], message: "must differ from creator" });
  if (pack.effectiveTo !== undefined && pack.effectiveTo < pack.effectiveFrom) context.addIssue({ code: "custom", path: ["effectiveTo"], message: "must not precede effectiveFrom" });
  const fieldSet = new Set(ids);
  for (const change of pack.changes) if (!fieldSet.has(change.fieldId)) context.addIssue({ code: "custom", path: ["changes"], message: `unknown changed field ${change.fieldId}` });
});

export const FieldPackV1Schema = FieldPackBodyV1Schema.extend({ fieldPackHash: Sha256HashSchema }).strict();

export type FieldDefinitionV2 = Readonly<z.infer<typeof FieldDefinitionV2Schema>>;
export type FieldPackV1 = Readonly<z.infer<typeof FieldPackV1Schema>>;
export type FieldPackV1Input = Readonly<z.input<typeof FieldPackBodyV1Schema>>;

export function createFieldPackV1(input: FieldPackV1Input): FieldPackV1 {
  const body = parseWithSchema(FieldPackBodyV1Schema, input, "FieldPackV1");
  return parseFieldPackV1({ ...body, fieldPackHash: canonicalHash(body) });
}

export function parseFieldPackV1(value: unknown): FieldPackV1 {
  const parsed = parseWithSchema(FieldPackV1Schema, value, "FieldPackV1");
  const { fieldPackHash, ...body } = parsed;
  assertCanonicalHash(body, fieldPackHash, "FieldPackV1");
  return parsed;
}

export function activeFieldsOn(pack: FieldPackV1, asOfDate: string): readonly FieldDefinitionV2[] {
  IsoDateSchema.parse(asOfDate);
  return Object.freeze(pack.fields.filter((field) => field.effectiveFrom <= asOfDate && (field.effectiveTo === undefined || field.effectiveTo >= asOfDate)));
}
