import { z } from "zod";

import type { FieldMapping } from "../domain/mapping.js";
import {
  DictionaryBundleReferenceV1Schema,
} from "./bundles.js";
import {
  ContractValidationError,
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  parseWithSchema
} from "./canonical.js";

const FieldNameSchema = z.string().min(1).max(256).refine(
  (value) => !/[\u0000-\u001f\u007f]/.test(value),
  "must not contain control characters"
);
const ExactLiteralSchema = z.union([z.string().max(4_096), z.boolean(), z.null()]);
const LogicalTypeSchema = z.enum([
  "identifier",
  "string",
  "integer",
  "decimal",
  "boolean",
  "date",
  "datetime",
  "currency",
  "percentage"
]);

export type MappingExpressionV2 =
  | { readonly op: "source"; readonly column: string }
  | { readonly op: "literal"; readonly value: string | boolean | null }
  | {
      readonly op: "exact_cast";
      readonly input: MappingExpressionV2;
      readonly to: z.infer<typeof LogicalTypeSchema>;
    }
  | {
      readonly op: "parse_date";
      readonly input: MappingExpressionV2;
      readonly formats: readonly string[];
      readonly timezone: "UTC";
    }
  | {
      readonly op: "scale_decimal";
      readonly input: MappingExpressionV2;
      readonly factor: string;
      readonly decimalPlaces: number;
      readonly rounding: "reject" | "half_even";
    }
  | {
      readonly op: "code_map";
      readonly input: MappingExpressionV2;
      readonly values: Readonly<Record<string, string>>;
      readonly unknown: "reject" | "null" | "preserve";
    }
  | { readonly op: "coalesce"; readonly inputs: readonly MappingExpressionV2[] }
  | {
      readonly op: "when";
      readonly condition: MappingConditionV2;
      readonly then: MappingExpressionV2;
      readonly otherwise: MappingExpressionV2;
    }
  | {
      readonly op: "split";
      readonly input: MappingExpressionV2;
      readonly delimiter: string;
      readonly index: number;
      readonly trim: boolean;
    }
  | {
      readonly op: "combine";
      readonly inputs: readonly MappingExpressionV2[];
      readonly separator: string;
      readonly skipNulls: boolean;
    }
  | {
      readonly op: "dimension_lookup";
      readonly input: MappingExpressionV2;
      readonly definitionId: string;
      readonly definitionVersion: string;
      readonly definitionHash: string;
      readonly missing: "reject" | "null" | "preserve";
    };

export type MappingConditionV2 =
  | {
      readonly op: "equals";
      readonly left: MappingExpressionV2;
      readonly right: MappingExpressionV2;
    }
  | {
      readonly op: "in";
      readonly input: MappingExpressionV2;
      readonly values: readonly (string | boolean | null)[];
    }
  | { readonly op: "is_null"; readonly input: MappingExpressionV2 }
  | { readonly op: "not"; readonly condition: MappingConditionV2 }
  | { readonly op: "and" | "or"; readonly conditions: readonly MappingConditionV2[] };

export const MappingExpressionV2Schema: z.ZodType<MappingExpressionV2> = z.lazy(() =>
  z.discriminatedUnion("op", [
    z.object({ op: z.literal("source"), column: FieldNameSchema }).strict(),
    z.object({ op: z.literal("literal"), value: ExactLiteralSchema }).strict(),
    z
      .object({
        op: z.literal("exact_cast"),
        input: MappingExpressionV2Schema,
        to: LogicalTypeSchema
      })
      .strict(),
    z
      .object({
        op: z.literal("parse_date"),
        input: MappingExpressionV2Schema,
        formats: z.array(z.string().min(1).max(64)).min(1).max(16),
        timezone: z.literal("UTC")
      })
      .strict(),
    z
      .object({
        op: z.literal("scale_decimal"),
        input: MappingExpressionV2Schema,
        factor: z.string().regex(/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/, "must be an exact decimal string"),
        decimalPlaces: z.number().int().min(0).max(38),
        rounding: z.enum(["reject", "half_even"])
      })
      .strict(),
    z
      .object({
        op: z.literal("code_map"),
        input: MappingExpressionV2Schema,
        values: z.record(z.string().max(1_024), z.string().max(1_024)),
        unknown: z.enum(["reject", "null", "preserve"])
      })
      .strict(),
    z
      .object({
        op: z.literal("coalesce"),
        inputs: z.array(MappingExpressionV2Schema).min(2).max(16)
      })
      .strict(),
    z
      .object({
        op: z.literal("when"),
        condition: z.lazy(() => MappingConditionV2Schema),
        then: MappingExpressionV2Schema,
        otherwise: MappingExpressionV2Schema
      })
      .strict(),
    z
      .object({
        op: z.literal("split"),
        input: MappingExpressionV2Schema,
        delimiter: z.string().min(1).max(32),
        index: z.number().int().min(0).max(255),
        trim: z.boolean()
      })
      .strict(),
    z
      .object({
        op: z.literal("combine"),
        inputs: z.array(MappingExpressionV2Schema).min(2).max(16),
        separator: z.string().max(32),
        skipNulls: z.boolean()
      })
      .strict(),
    z
      .object({
        op: z.literal("dimension_lookup"),
        input: MappingExpressionV2Schema,
        definitionId: IdentifierSchema,
        definitionVersion: z.string().min(1).max(64),
        definitionHash: Sha256HashSchema,
        missing: z.enum(["reject", "null", "preserve"])
      })
      .strict()
  ])
);

export const MappingConditionV2Schema: z.ZodType<MappingConditionV2> = z.lazy(() =>
  z.discriminatedUnion("op", [
    z
      .object({
        op: z.literal("equals"),
        left: MappingExpressionV2Schema,
        right: MappingExpressionV2Schema
      })
      .strict(),
    z
      .object({
        op: z.literal("in"),
        input: MappingExpressionV2Schema,
        values: z.array(ExactLiteralSchema).min(1).max(256)
      })
      .strict(),
    z.object({ op: z.literal("is_null"), input: MappingExpressionV2Schema }).strict(),
    z.object({ op: z.literal("not"), condition: MappingConditionV2Schema }).strict(),
    z
      .object({
        op: z.enum(["and", "or"]),
        conditions: z.array(MappingConditionV2Schema).min(2).max(16)
      })
      .strict()
  ])
);

const MappingRuleV2Schema = z
  .object({
    ruleId: IdentifierSchema,
    canonicalField: FieldNameSchema,
    expression: MappingExpressionV2Schema,
    onError: z.enum(["reject_row", "null", "fail_application"]),
    description: z.string().max(2_000).optional()
  })
  .strict();

const SourceContractReferenceV1Schema = z
  .object({
    sourceContractId: IdentifierSchema,
    revision: z.number().int().positive(),
    sourceContractHash: Sha256HashSchema
  })
  .strict();

const MappingSpecBodyV2Schema = z
  .object({
    contractVersion: z.literal(2),
    tenantId: IdentifierSchema,
    mappingSpecId: IdentifierSchema,
    mappingKey: IdentifierSchema,
    revision: z.number().int().positive(),
    status: z.enum(["proposed", "validated", "approved", "active", "retired"]),
    sourceContract: SourceContractReferenceV1Schema,
    dictionaryBundle: DictionaryBundleReferenceV1Schema,
    rules: z.array(MappingRuleV2Schema).min(1).max(500),
    requiredCanonicalFields: z.array(FieldNameSchema).max(500),
    createdBy: IdentifierSchema,
    createdAt: IsoTimestampSchema,
    approvedBy: IdentifierSchema.optional(),
    approvedAt: IsoTimestampSchema.optional(),
    supersedesMappingSpecId: IdentifierSchema.optional()
  })
  .strict()
  .superRefine((value, context) => {
    const ruleIds = value.rules.map((rule) => rule.ruleId);
    if (new Set(ruleIds).size !== ruleIds.length) {
      context.addIssue({ code: "custom", path: ["rules"], message: "rule ids must be unique" });
    }
    const fields = value.rules.map((rule) => rule.canonicalField);
    if (new Set(fields).size !== fields.length) {
      context.addIssue({ code: "custom", path: ["rules"], message: "canonical targets must be unique" });
    }
    if (new Set(value.requiredCanonicalFields).size !== value.requiredCanonicalFields.length) {
      context.addIssue({ code: "custom", path: ["requiredCanonicalFields"], message: "must be unique" });
    }
    const mappedFields = new Set(fields);
    for (const requiredField of value.requiredCanonicalFields) {
      if (!mappedFields.has(requiredField)) {
        context.addIssue({
          code: "custom",
          path: ["requiredCanonicalFields"],
          message: `required field ${requiredField} is not produced by a rule`
        });
      }
    }
    for (const [index, rule] of value.rules.entries()) {
      const budget = expressionBudget(rule.expression);
      if (budget.nodes > 64 || budget.depth > 8) {
        context.addIssue({
          code: "custom",
          path: ["rules", index, "expression"],
          message: "expression exceeds the 64-node or 8-level execution bound"
        });
      }
    }
    const governed = value.status === "approved" || value.status === "active" || value.status === "retired";
    if (governed && (value.approvedBy === undefined || value.approvedAt === undefined)) {
      context.addIssue({ code: "custom", path: ["approvedBy"], message: "governed status requires approval evidence" });
    }
    if (value.approvedBy !== undefined && value.approvedBy === value.createdBy) {
      context.addIssue({ code: "custom", path: ["approvedBy"], message: "must differ from createdBy" });
    }
  });

export const MappingSpecV2Schema = MappingSpecBodyV2Schema.extend({
  mappingSpecHash: Sha256HashSchema
}).strict();

export type MappingSpecV2 = Readonly<z.infer<typeof MappingSpecV2Schema>>;
export type MappingSpecV2Input = Readonly<z.input<typeof MappingSpecBodyV2Schema>>;

const SnapshotReferenceV2Schema = z
  .object({
    snapshotId: IdentifierSchema,
    snapshotHash: Sha256HashSchema,
    contentHash: Sha256HashSchema
  })
  .strict();

const MappingSpecReferenceV2Schema = z
  .object({
    mappingSpecId: IdentifierSchema,
    revision: z.number().int().positive(),
    mappingSpecHash: Sha256HashSchema
  })
  .strict();

const RuntimeBundleReferenceV1Schema = z
  .object({
    runtimeBundleId: IdentifierSchema,
    runtimeBundleHash: Sha256HashSchema,
    runtimeVersion: z.string().min(1).max(64)
  })
  .strict();

const MappingApplicationBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    mappingApplicationId: IdentifierSchema,
    snapshot: SnapshotReferenceV2Schema,
    mappingSpec: MappingSpecReferenceV2Schema,
    dictionaryBundle: DictionaryBundleReferenceV1Schema,
    runtimeBundle: RuntimeBundleReferenceV1Schema,
    inputPopulationHash: Sha256HashSchema,
    outputPopulationHash: Sha256HashSchema,
    inputRowCount: z.number().int().min(0),
    outputRowCount: z.number().int().min(0),
    rejectedRowCount: z.number().int().min(0),
    appliedBy: IdentifierSchema,
    appliedAt: IsoTimestampSchema
  })
  .strict()
  .superRefine((value, context) => {
    if (value.outputRowCount + value.rejectedRowCount !== value.inputRowCount) {
      context.addIssue({
        code: "custom",
        path: ["outputRowCount"],
        message: "outputRowCount plus rejectedRowCount must equal inputRowCount"
      });
    }
  });

export const MappingApplicationV1Schema = MappingApplicationBodyV1Schema.extend({
  mappingApplicationHash: Sha256HashSchema
}).strict();

export type MappingApplicationV1 = Readonly<z.infer<typeof MappingApplicationV1Schema>>;
export type MappingApplicationV1Input = Readonly<z.input<typeof MappingApplicationBodyV1Schema>>;

export function createMappingSpecV2(input: MappingSpecV2Input): MappingSpecV2 {
  const body = parseWithSchema(MappingSpecBodyV2Schema, input, "MappingSpecV2");
  return parseMappingSpecV2({ ...body, mappingSpecHash: canonicalHash(body) });
}

export function parseMappingSpecV2(value: unknown): MappingSpecV2 {
  const parsed = parseWithSchema(MappingSpecV2Schema, value, "MappingSpecV2");
  const { mappingSpecHash, ...body } = parsed;
  assertCanonicalHash(body, mappingSpecHash, "MappingSpecV2");
  return parsed;
}

export function createMappingApplicationV1(
  input: MappingApplicationV1Input
): MappingApplicationV1 {
  const body = parseWithSchema(
    MappingApplicationBodyV1Schema,
    input,
    "MappingApplicationV1"
  );
  return parseMappingApplicationV1({ ...body, mappingApplicationHash: canonicalHash(body) });
}

export function parseMappingApplicationV1(value: unknown): MappingApplicationV1 {
  const parsed = parseWithSchema(
    MappingApplicationV1Schema,
    value,
    "MappingApplicationV1"
  );
  const { mappingApplicationHash, ...body } = parsed;
  assertCanonicalHash(body, mappingApplicationHash, "MappingApplicationV1");
  return parsed;
}

export function assertMappingApplicationBindings(
  application: MappingApplicationV1,
  spec: MappingSpecV2
): void {
  if (
    application.tenantId !== spec.tenantId ||
    application.mappingSpec.mappingSpecId !== spec.mappingSpecId ||
    application.mappingSpec.revision !== spec.revision ||
    application.mappingSpec.mappingSpecHash !== spec.mappingSpecHash ||
    application.dictionaryBundle.contentHash !== spec.dictionaryBundle.contentHash
  ) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "Mapping application is not bound to the supplied immutable mapping specification"
    );
  }
}

/** Converts the current v1 direct pairs into an additive v2 mapping body. */
export function legacyFieldMappingsToRules(
  mappings: readonly FieldMapping[]
): readonly z.infer<typeof MappingRuleV2Schema>[] {
  const rules = mappings.map((mapping, index) =>
    parseWithSchema(
      MappingRuleV2Schema,
      {
        ruleId: `legacy-${String(index + 1).padStart(4, "0")}`,
        canonicalField: mapping.canonicalField,
        expression: { op: "source", column: mapping.sourceColumn },
        onError: "fail_application"
      },
      "legacy field mapping"
    )
  );
  return Object.freeze(rules);
}

/** Lossless only for direct-source expressions; transformed v2 mappings are intentionally rejected. */
export function mappingRulesToLegacyFieldMappings(
  rules: readonly z.infer<typeof MappingRuleV2Schema>[]
): readonly FieldMapping[] {
  return Object.freeze(
    rules.map((rule) => {
      if (rule.expression.op !== "source") {
        throw new ContractValidationError(
          "INVARIANT_VIOLATION",
          `Mapping rule ${rule.ruleId} cannot be represented by the v1 direct-pair contract`
        );
      }
      return Object.freeze({
        sourceColumn: rule.expression.column,
        canonicalField: rule.canonicalField
      });
    })
  );
}

function expressionBudget(expression: MappingExpressionV2): { readonly nodes: number; readonly depth: number } {
  switch (expression.op) {
    case "source":
    case "literal":
      return { nodes: 1, depth: 1 };
    case "exact_cast":
    case "parse_date":
    case "scale_decimal":
    case "code_map":
    case "split":
    case "dimension_lookup":
      return addExpressionNode(expressionBudget(expression.input));
    case "coalesce":
    case "combine":
      return combineBudgets(expression.inputs.map(expressionBudget));
    case "when": {
      const condition = conditionBudget(expression.condition);
      return combineBudgets([
        { nodes: condition.nodes, depth: condition.depth },
        expressionBudget(expression.then),
        expressionBudget(expression.otherwise)
      ]);
    }
  }
}

function conditionBudget(condition: MappingConditionV2): { readonly nodes: number; readonly depth: number } {
  switch (condition.op) {
    case "equals":
      return combineBudgets([expressionBudget(condition.left), expressionBudget(condition.right)]);
    case "in":
    case "is_null":
      return addExpressionNode(expressionBudget(condition.input));
    case "not":
      return addExpressionNode(conditionBudget(condition.condition));
    case "and":
    case "or":
      return combineBudgets(condition.conditions.map(conditionBudget));
  }
}

function addExpressionNode(budget: { readonly nodes: number; readonly depth: number }): {
  readonly nodes: number;
  readonly depth: number;
} {
  return { nodes: budget.nodes + 1, depth: budget.depth + 1 };
}

function combineBudgets(
  children: readonly { readonly nodes: number; readonly depth: number }[]
): { readonly nodes: number; readonly depth: number } {
  return {
    nodes: 1 + children.reduce((sum, child) => sum + child.nodes, 0),
    depth: 1 + Math.max(...children.map((child) => child.depth), 0)
  };
}
