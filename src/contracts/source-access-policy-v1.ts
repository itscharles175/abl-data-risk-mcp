import { z } from "zod";

import {
  IdentifierSchema,
  IsoDateSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  parseWithSchema
} from "./canonical.js";

const SourceAccessPolicyBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    policyId: IdentifierSchema,
    revision: z.number().int().positive().max(1_000_000),
    datasetId: IdentifierSchema,
    sourceContract: z
      .object({
        sourceContractId: IdentifierSchema,
        revision: z.number().int().positive().max(1_000_000),
        sourceContractHash: Sha256HashSchema
      })
      .strict(),
    scope: z
      .object({
        scopeType: z.enum(["portfolio", "facility"]),
        scopeId: IdentifierSchema
      })
      .strict(),
    purpose: IdentifierSchema,
    allowedFields: z.array(IdentifierSchema).min(1).max(2_000),
    allowedAggregateDimensionFields: z.array(IdentifierSchema).max(256),
    effectiveFrom: IsoDateSchema,
    effectiveTo: IsoDateSchema.optional()
  })
  .strict()
  .superRefine((value, context) => {
    sortedUnique(value.allowedFields, context, ["allowedFields"]);
    sortedUnique(
      value.allowedAggregateDimensionFields,
      context,
      ["allowedAggregateDimensionFields"]
    );
    const allowedFields = new Set(value.allowedFields);
    for (const [index, field] of value.allowedAggregateDimensionFields.entries()) {
      if (!allowedFields.has(field)) {
        context.addIssue({
          code: "custom",
          path: ["allowedAggregateDimensionFields", index],
          message: "must also be present in allowedFields"
        });
      }
    }
    if (value.effectiveTo !== undefined && value.effectiveTo <= value.effectiveFrom) {
      context.addIssue({
        code: "custom",
        path: ["effectiveTo"],
        message: "must be after effectiveFrom"
      });
    }
  });

export const SourceAccessPolicyV1Schema = SourceAccessPolicyBodyV1Schema.extend({
  policyHash: Sha256HashSchema
}).strict();

export type SourceAccessPolicyV1 = Readonly<z.infer<typeof SourceAccessPolicyV1Schema>>;
export type SourceAccessPolicyV1Input = Readonly<z.input<typeof SourceAccessPolicyBodyV1Schema>>;

export function createSourceAccessPolicyV1(input: SourceAccessPolicyV1Input): SourceAccessPolicyV1 {
  const body = parseWithSchema(SourceAccessPolicyBodyV1Schema, input, "SourceAccessPolicyV1");
  return parseSourceAccessPolicyV1({ ...body, policyHash: canonicalHash(body) });
}

export function parseSourceAccessPolicyV1(value: unknown): SourceAccessPolicyV1 {
  const parsed = parseWithSchema(SourceAccessPolicyV1Schema, value, "SourceAccessPolicyV1");
  const { policyHash, ...body } = parsed;
  assertCanonicalHash(body, policyHash, "SourceAccessPolicyV1");
  return parsed;
}

function sortedUnique(
  values: readonly string[],
  context: z.RefinementCtx,
  path: readonly PropertyKey[]
): void {
  if (new Set(values).size !== values.length) {
    context.addIssue({ code: "custom", path: [...path], message: "must be unique" });
  }
  const sorted = [...values].sort(compare);
  if (sorted.some((value, index) => value !== values[index])) {
    context.addIssue({ code: "custom", path: [...path], message: "must be sorted" });
  }
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
