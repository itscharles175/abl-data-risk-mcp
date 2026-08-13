import * as z from "zod/v4";

import {
  IdentifierSchema,
  IsoDateSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  parseWithSchema
} from "./canonical.js";

const GovernedDatasetScopeBindingBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    bindingId: IdentifierSchema,
    revision: z.number().int().min(1).max(1_000_000),
    datasetId: IdentifierSchema,
    sourceContract: z
      .object({
        sourceContractId: IdentifierSchema,
        revision: z.number().int().min(1).max(1_000_000),
        sourceContractHash: Sha256HashSchema
      })
      .strict(),
    scope: z
      .object({
        scopeType: z.enum(["portfolio", "facility"]),
        scopeId: IdentifierSchema
      })
      .strict(),
    effectiveFrom: IsoDateSchema,
    effectiveTo: IsoDateSchema.optional()
  })
  .strict()
  .superRefine((value, context) => {
    if (value.effectiveTo !== undefined && value.effectiveTo <= value.effectiveFrom) {
      context.addIssue({
        code: "custom",
        path: ["effectiveTo"],
        message: "must be after effectiveFrom"
      });
    }
  });

export const GovernedDatasetScopeBindingV1Schema =
  GovernedDatasetScopeBindingBodyV1Schema.extend({ bindingHash: Sha256HashSchema }).strict();

export type GovernedDatasetScopeBindingV1 = Readonly<
  z.infer<typeof GovernedDatasetScopeBindingV1Schema>
>;

export type GovernedDatasetScopeBindingV1Input = Readonly<
  z.input<typeof GovernedDatasetScopeBindingBodyV1Schema>
>;

export function createGovernedDatasetScopeBindingV1(
  input: GovernedDatasetScopeBindingV1Input
): GovernedDatasetScopeBindingV1 {
  const body = parseWithSchema(
    GovernedDatasetScopeBindingBodyV1Schema,
    input,
    "GovernedDatasetScopeBindingV1"
  );
  return parseGovernedDatasetScopeBindingV1({ ...body, bindingHash: canonicalHash(body) });
}

export function parseGovernedDatasetScopeBindingV1(
  value: unknown
): GovernedDatasetScopeBindingV1 {
  const parsed = parseWithSchema(
    GovernedDatasetScopeBindingV1Schema,
    value,
    "GovernedDatasetScopeBindingV1"
  );
  const { bindingHash, ...body } = parsed;
  assertCanonicalHash(body, bindingHash, "GovernedDatasetScopeBindingV1");
  return parsed;
}
