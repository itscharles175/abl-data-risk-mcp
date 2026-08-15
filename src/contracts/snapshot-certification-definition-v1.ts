import { z } from "zod";

import {
  DictionaryBundleReferenceV1Schema,
  ImmutableBundleReferenceV1Schema
} from "./bundles.js";
import {
  IdentifierSchema,
  IsoDateSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  canonicalJson,
  parseWithSchema
} from "./canonical.js";
import { GovernedDatasetScopeBindingV1Schema } from "./dataset-scope-binding-v1.js";

const ExactDecimalSchema = z
  .string()
  .max(256)
  .regex(/^-?(?:0|[1-9]\d*)(?:\.\d*[1-9])?$/u, "must be a canonical exact decimal string")
  .refine((value) => value !== "-0", "must encode zero as 0");

const NonnegativeDecimalSchema = ExactDecimalSchema.refine(
  (value) => !value.startsWith("-"),
  "must be nonnegative"
);

const SourceContractReferenceV1Schema = z
  .object({
    sourceContractId: IdentifierSchema,
    revision: z.number().int().min(1).max(1_000_000),
    sourceContractHash: Sha256HashSchema
  })
  .strict();

const EffectiveWindowV1Schema = z
  .object({
    effectiveFrom: IsoDateSchema,
    effectiveTo: IsoDateSchema.optional()
  })
  .strict()
  .superRefine((value, context) => {
    if (value.effectiveTo !== undefined && value.effectiveTo <= value.effectiveFrom) {
      context.addIssue({ code: "custom", path: ["effectiveTo"], message: "must be after effectiveFrom" });
    }
  });

const GovernedMappingExecutionReferenceV1Schema = z
  .object({
    definitionVersionId: IdentifierSchema,
    definitionKey: IdentifierSchema,
    kind: z.literal("mapping_spec"),
    semanticVersion: z.string().min(1).max(64),
    versionHash: Sha256HashSchema,
    documentHash: Sha256HashSchema,
    approvalEventHash: Sha256HashSchema,
    mappingSpecId: IdentifierSchema,
    mappingSpecRevision: z.number().int().min(1).max(1_000_000),
    mappingSpecHash: Sha256HashSchema,
    sourceContract: SourceContractReferenceV1Schema,
    activation: z
      .object({
        status: z.literal("active"),
        lifecycleRevision: z.number().int().min(1).max(1_000_000),
        activatedBy: IdentifierSchema,
        activatedAt: IsoTimestampSchema,
        activationEventHash: Sha256HashSchema
      })
      .strict(),
    window: EffectiveWindowV1Schema
  })
  .strict();

const GovernedSourceContractExecutionReferenceV1Schema = z
  .object({
    definitionVersionId: IdentifierSchema,
    definitionKey: IdentifierSchema,
    kind: z.literal("source_contract"),
    semanticVersion: z.string().min(1).max(64),
    versionHash: Sha256HashSchema,
    documentHash: Sha256HashSchema,
    approvalEventHash: Sha256HashSchema,
    sourceContract: SourceContractReferenceV1Schema
  })
  .strict();

const GovernedDatasetScopeBindingExecutionReferenceV1Schema = z
  .object({
    definitionVersionId: IdentifierSchema,
    definitionKey: IdentifierSchema,
    kind: z.literal("dataset_scope_binding"),
    semanticVersion: z.string().min(1).max(64),
    versionHash: Sha256HashSchema,
    documentHash: Sha256HashSchema,
    approvalEventHash: Sha256HashSchema,
    bindingId: IdentifierSchema,
    revision: z.number().int().min(1).max(1_000_000),
    bindingHash: Sha256HashSchema,
    sourceContract: SourceContractReferenceV1Schema
  })
  .strict();

const DataQualityRuleV1Schema = z.discriminatedUnion("type", [
  z
    .object({
      ruleId: IdentifierSchema,
      type: z.literal("required"),
      field: IdentifierSchema,
      severity: z.enum(["info", "warning", "error", "critical"]),
      blocking: z.boolean()
    })
    .strict(),
  z
    .object({
      ruleId: IdentifierSchema,
      type: z.literal("unique"),
      field: IdentifierSchema,
      severity: z.enum(["info", "warning", "error", "critical"]),
      blocking: z.boolean()
    })
    .strict(),
  z
    .object({
      ruleId: IdentifierSchema,
      type: z.literal("allowed_values"),
      field: IdentifierSchema,
      values: z.array(z.string().min(1).max(4_096)).min(1).max(10_000),
      severity: z.enum(["info", "warning", "error", "critical"]),
      blocking: z.boolean()
    })
    .strict(),
  z
    .object({
      ruleId: IdentifierSchema,
      type: z.literal("decimal_range"),
      field: IdentifierSchema,
      minimum: ExactDecimalSchema.optional(),
      maximum: ExactDecimalSchema.optional(),
      severity: z.enum(["info", "warning", "error", "critical"]),
      blocking: z.boolean()
    })
    .strict(),
  z
    .object({
      ruleId: IdentifierSchema,
      type: z.literal("equals_sum"),
      field: IdentifierSchema,
      addends: z.array(IdentifierSchema).min(1).max(32),
      tolerance: NonnegativeDecimalSchema,
      severity: z.enum(["info", "warning", "error", "critical"]),
      blocking: z.boolean()
    })
    .strict()
]);

const DataQualityDefinitionV1Schema = z
  .object({
    definitionId: IdentifierSchema,
    rulesetId: IdentifierSchema,
    mappingSectionId: IdentifierSchema,
    requiredSectionIds: z.array(IdentifierSchema).min(1).max(256),
    rules: z.array(DataQualityRuleV1Schema).min(1).max(1_000),
    balanceField: IdentifierSchema,
    materialBalance: NonnegativeDecimalSchema,
    window: EffectiveWindowV1Schema
  })
  .strict()
  .superRefine((value, context) => {
    unique(value.requiredSectionIds, context, ["requiredSectionIds"], "must be unique");
    unique(value.rules.map((rule) => rule.ruleId), context, ["rules"], "rule ids must be unique");
    if (!value.requiredSectionIds.includes(value.mappingSectionId)) {
      context.addIssue({
        code: "custom",
        path: ["mappingSectionId"],
        message: "must name a required section"
      });
    }
    for (const [index, rule] of value.rules.entries()) {
      if (rule.type === "allowed_values") {
        unique(rule.values, context, ["rules", index, "values"], "must be unique");
      }
      if (rule.type === "equals_sum") {
        unique(rule.addends, context, ["rules", index, "addends"], "must be unique");
        if (rule.addends.includes(rule.field)) {
          context.addIssue({
            code: "custom",
            path: ["rules", index, "addends"],
            message: "cannot include the measured field"
          });
        }
      }
      if (rule.type === "decimal_range") {
        if (rule.minimum === undefined && rule.maximum === undefined) {
          context.addIssue({
            code: "custom",
            path: ["rules", index],
            message: "must declare a minimum or maximum"
          });
        }
        if (
          rule.minimum !== undefined &&
          rule.maximum !== undefined &&
          compareDecimal(rule.minimum, rule.maximum) > 0
        ) {
          context.addIssue({
            code: "custom",
            path: ["rules", index, "maximum"],
            message: "must be greater than or equal to minimum"
          });
        }
      }
    }
  });

const SegmentedControlTotalV1Schema = z
  .object({
    dimensions: z.record(IdentifierSchema, z.string().min(1).max(4_096)),
    rowCount: z.number().int().min(0).max(1_000_000),
    balance: ExactDecimalSchema,
    currency: z.string().regex(/^[A-Z]{3}$/u)
  })
  .strict();

const ReconciliationControlV1Schema = z
  .object({
    controlId: IdentifierSchema,
    sectionId: IdentifierSchema,
    recordSource: z.enum(["normalized", "source"]),
    dimensions: z.array(IdentifierSchema).min(1).max(5),
    balanceField: IdentifierSchema,
    currencyField: IdentifierSchema,
    expected: z.array(SegmentedControlTotalV1Schema).min(1).max(100_000),
    balanceTolerance: NonnegativeDecimalSchema
  })
  .strict()
  .superRefine((value, context) => {
    unique(value.dimensions, context, ["dimensions"], "must be unique");
    const expected = value.expected.map((total) => canonicalJson(total.dimensions));
    unique(expected, context, ["expected"], "dimension groups must be unique");
  });

const CertificationReconciliationDefinitionV1Schema = z
  .object({
    definitionId: IdentifierSchema,
    reconciliationId: IdentifierSchema,
    requiredSectionIds: z.array(IdentifierSchema).min(1).max(256),
    controls: z.array(ReconciliationControlV1Schema).min(1).max(256),
    window: EffectiveWindowV1Schema
  })
  .strict()
  .superRefine((value, context) => {
    unique(value.requiredSectionIds, context, ["requiredSectionIds"], "must be unique");
    unique(value.controls.map((control) => control.controlId), context, ["controls"], "control ids must be unique");
    for (const sectionId of value.requiredSectionIds) {
      if (!value.controls.some((control) => control.sectionId === sectionId)) {
        context.addIssue({ code: "custom", path: ["controls"], message: `required section ${sectionId} must have a control` });
      }
    }
    for (const [index, control] of value.controls.entries()) {
      if (!value.requiredSectionIds.includes(control.sectionId)) {
        context.addIssue({
          code: "custom",
          path: ["controls", index, "sectionId"],
          message: "must name a required section"
        });
      }
    }
  });

const NeutralApprovalV1Schema = z
  .object({
    status: z.literal("pending_durable_approval"),
    authority: z.literal("governed_definition_v2_lifecycle")
  })
  .strict();

const SnapshotCertificationDefinitionBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    definitionKind: z.literal("snapshot_certification_control"),
    tenantId: IdentifierSchema,
    certificationDefinitionId: IdentifierSchema,
    revision: z.number().int().min(1).max(1_000_000),
    sourceContract: SourceContractReferenceV1Schema,
    sourceContractExecution: GovernedSourceContractExecutionReferenceV1Schema,
    scopeBinding: GovernedDatasetScopeBindingV1Schema,
    scopeBindingExecution: GovernedDatasetScopeBindingExecutionReferenceV1Schema,
    mappingExecution: GovernedMappingExecutionReferenceV1Schema,
    runtime: z
      .object({
        runtimeBundleId: IdentifierSchema,
        runtimeVersion: z.string().min(1).max(64),
        runtimeBundleHash: Sha256HashSchema,
        dictionary: DictionaryBundleReferenceV1Schema,
        mappingCompiler: ImmutableBundleReferenceV1Schema.extend({ bundleKind: z.literal("mapping_compiler") }).strict()
      })
      .strict(),
    dataQuality: DataQualityDefinitionV1Schema,
    certificationReconciliation: CertificationReconciliationDefinitionV1Schema,
    window: EffectiveWindowV1Schema,
    approval: NeutralApprovalV1Schema
  })
  .strict()
  .superRefine((value, context) => {
    const scope = value.scopeBinding;
    const source = value.sourceContract;
    const sourceExecution = value.sourceContractExecution;
    const scopeExecution = value.scopeBindingExecution;
    if (value.certificationDefinitionId !== scope.bindingId) {
      context.addIssue({
        code: "custom",
        path: ["certificationDefinitionId"],
        message: "must equal the facility scope binding id"
      });
    }
    if (
      sourceExecution.sourceContract.sourceContractId !== source.sourceContractId ||
      sourceExecution.sourceContract.revision !== source.revision ||
      sourceExecution.sourceContract.sourceContractHash !== source.sourceContractHash
    ) {
      context.addIssue({
        code: "custom",
        path: ["sourceContractExecution", "sourceContract"],
        message: "must match the exact raw source contract reference"
      });
    }
    if (
      scopeExecution.definitionKey !== scope.bindingId ||
      scopeExecution.bindingId !== scope.bindingId ||
      scopeExecution.revision !== scope.revision ||
      scopeExecution.bindingHash !== scope.bindingHash ||
      scopeExecution.sourceContract.sourceContractId !== source.sourceContractId ||
      scopeExecution.sourceContract.revision !== source.revision ||
      scopeExecution.sourceContract.sourceContractHash !== source.sourceContractHash
    ) {
      context.addIssue({
        code: "custom",
        path: ["scopeBindingExecution"],
        message: "must bind the exact raw scope binding and source contract under its binding id"
      });
    }
    if (
      scope.tenantId !== value.tenantId ||
      scope.scope.scopeType !== "facility" ||
      scope.sourceContract.sourceContractId !== source.sourceContractId ||
      scope.sourceContract.revision !== source.revision ||
      scope.sourceContract.sourceContractHash !== source.sourceContractHash
    ) {
      context.addIssue({ code: "custom", path: ["scopeBinding"], message: "must bind this tenant, facility, and exact source contract" });
    }
    const mapping = value.mappingExecution;
    if (
      mapping.sourceContract.sourceContractId !== source.sourceContractId ||
      mapping.sourceContract.revision !== source.revision ||
      mapping.sourceContract.sourceContractHash !== source.sourceContractHash
    ) {
      context.addIssue({ code: "custom", path: ["mappingExecution", "sourceContract"], message: "must match the exact source contract" });
    }
    for (const [path, candidate] of [
      [["mappingExecution", "window"], mapping.window],
      [["dataQuality", "window"], value.dataQuality.window],
      [["certificationReconciliation", "window"], value.certificationReconciliation.window]
    ] as const) {
      if (!sameWindow(candidate, value.window)) {
        context.addIssue({ code: "custom", path: [...path], message: "must exactly match the certification control window" });
      }
    }
    if (value.runtime.dictionary.createdAt > value.mappingExecution.activation.activatedAt) {
      context.addIssue({ code: "custom", path: ["runtime", "dictionary", "createdAt"], message: "cannot be after mapping activation" });
    }
    if (value.runtime.mappingCompiler.createdAt > value.mappingExecution.activation.activatedAt) {
      context.addIssue({ code: "custom", path: ["runtime", "mappingCompiler", "createdAt"], message: "cannot be after mapping activation" });
    }
  });

export const SnapshotCertificationDefinitionV1Schema = SnapshotCertificationDefinitionBodyV1Schema.extend({
  definitionHash: Sha256HashSchema
}).strict();

export type SnapshotCertificationDefinitionV1 = Readonly<z.infer<typeof SnapshotCertificationDefinitionV1Schema>>;
export type SnapshotCertificationDefinitionV1Input = Readonly<
  z.input<typeof SnapshotCertificationDefinitionBodyV1Schema>
>;

/**
 * Neutral, canonical proposal document for one facility-scoped snapshot certification control.
 * It intentionally contains no local approval claim: executable authority must be supplied by
 * the separate governed-definition lifecycle and bind this exact document hash.
 */
export function createSnapshotCertificationDefinitionV1(
  input: SnapshotCertificationDefinitionV1Input
): SnapshotCertificationDefinitionV1 {
  const body = parseWithSchema(
    SnapshotCertificationDefinitionBodyV1Schema,
    input,
    "SnapshotCertificationDefinitionV1"
  );
  return parseSnapshotCertificationDefinitionV1({ ...body, definitionHash: canonicalHash(body) });
}

export function parseSnapshotCertificationDefinitionV1(value: unknown): SnapshotCertificationDefinitionV1 {
  const parsed = parseWithSchema(
    SnapshotCertificationDefinitionV1Schema,
    value,
    "SnapshotCertificationDefinitionV1"
  );
  const { definitionHash, ...body } = parsed;
  assertCanonicalHash(body, definitionHash, "SnapshotCertificationDefinitionV1");
  return parsed;
}

function unique(
  values: readonly string[],
  context: z.RefinementCtx,
  path: readonly (string | number)[],
  message: string
): void {
  if (new Set(values).size !== values.length) context.addIssue({ code: "custom", path: [...path], message });
}

function sameWindow(
  left: z.infer<typeof EffectiveWindowV1Schema>,
  right: z.infer<typeof EffectiveWindowV1Schema>
): boolean {
  return left.effectiveFrom === right.effectiveFrom && left.effectiveTo === right.effectiveTo;
}

function compareDecimal(left: string, right: string): number {
  const [leftWhole, leftFraction = ""] = left.replace("-", "").split(".") as [string, string?];
  const [rightWhole, rightFraction = ""] = right.replace("-", "").split(".") as [string, string?];
  const leftNegative = left.startsWith("-");
  const rightNegative = right.startsWith("-");
  if (leftNegative !== rightNegative) return leftNegative ? -1 : 1;
  const length = Math.max(leftFraction.length, rightFraction.length);
  const leftMagnitude = `${leftWhole}.${leftFraction.padEnd(length, "0")}`;
  const rightMagnitude = `${rightWhole}.${rightFraction.padEnd(length, "0")}`;
  const magnitude = leftWhole.length === rightWhole.length
    ? leftMagnitude === rightMagnitude ? 0 : leftMagnitude < rightMagnitude ? -1 : 1
    : leftWhole.length - rightWhole.length;
  return leftNegative ? -magnitude : magnitude;
}
