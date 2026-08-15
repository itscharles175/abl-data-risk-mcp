import { z } from "zod";

import {
  IdentifierSchema,
  IsoDateSchema,
  Sha256HashSchema,
  type DatasetSnapshotV2,
  type GovernedDatasetScopeBindingV1,
  type MappingSpecV2,
  type Sha256Hash
} from "../contracts/index.js";
import type { GovernedSourceDeliveryRecordV1 } from "../contracts/source-delivery-authority-v1.js";
import type {
  DataQualityRuleV2,
  SegmentedControlTotalV2
} from "../domain/data-quality-v2.js";
import type { ModernSnapshotExtractionReceiptV1 } from "./modern-snapshot-capture.js";

export const EffectiveWindowV1Schema = z
  .object({
    effectiveFrom: IsoDateSchema,
    effectiveTo: IsoDateSchema.optional()
  })
  .strict()
  .superRefine((value, context) => {
    if (value.effectiveTo !== undefined && value.effectiveFrom > value.effectiveTo) {
      context.addIssue({ code: "custom", path: ["effectiveTo"], message: "cannot precede effectiveFrom" });
    }
  });

export const DataQualityRuleV2Schema = z.discriminatedUnion("type", [
  z
    .object({
      ruleId: IdentifierSchema,
      type: z.literal("required"),
      field: z.string().min(1).max(256),
      severity: z.enum(["info", "warning", "error", "critical"]),
      blocking: z.boolean()
    })
    .strict(),
  z
    .object({
      ruleId: IdentifierSchema,
      type: z.literal("unique"),
      field: z.string().min(1).max(256),
      severity: z.enum(["info", "warning", "error", "critical"]),
      blocking: z.boolean()
    })
    .strict(),
  z
    .object({
      ruleId: IdentifierSchema,
      type: z.literal("allowed_values"),
      field: z.string().min(1).max(256),
      values: z.array(z.string().max(4_096)).min(1).max(10_000),
      severity: z.enum(["info", "warning", "error", "critical"]),
      blocking: z.boolean()
    })
    .strict(),
  z
    .object({
      ruleId: IdentifierSchema,
      type: z.literal("decimal_range"),
      field: z.string().min(1).max(256),
      minimum: z.string().optional(),
      maximum: z.string().optional(),
      severity: z.enum(["info", "warning", "error", "critical"]),
      blocking: z.boolean()
    })
    .strict(),
  z
    .object({
      ruleId: IdentifierSchema,
      type: z.literal("equals_sum"),
      field: z.string().min(1).max(256),
      addends: z.array(z.string().min(1).max(256)).min(1).max(32),
      tolerance: z.string(),
      severity: z.enum(["info", "warning", "error", "critical"]),
      blocking: z.boolean()
    })
    .strict()
]);

export const DataQualityDefinitionV1Schema = z
  .object({
    definitionId: IdentifierSchema,
    rulesetId: IdentifierSchema,
    mappingSectionId: IdentifierSchema,
    requiredSectionIds: z.array(IdentifierSchema).min(1).max(256),
    rules: z.array(DataQualityRuleV2Schema).min(1).max(1_000),
    balanceField: z.string().min(1).max(256),
    materialBalance: z.string().regex(/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/u),
    window: EffectiveWindowV1Schema
  })
  .strict();

export const SegmentedControlTotalV2Schema: z.ZodType<SegmentedControlTotalV2> = z
  .object({
    dimensions: z.record(z.string().min(1).max(256), z.string().max(4_096)),
    rowCount: z.number().int().min(0).max(1_000_000),
    balance: z.string().regex(/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/u),
    currency: z.string().regex(/^[A-Z]{3}$/u)
  })
  .strict();

export const ReconciliationControlV1Schema = z
  .object({
    controlId: IdentifierSchema,
    sectionId: IdentifierSchema,
    recordSource: z.enum(["normalized", "source"]),
    dimensions: z.array(z.string().min(1).max(256)).min(1).max(5),
    balanceField: z.string().min(1).max(256),
    currencyField: z.string().min(1).max(256),
    expected: z.array(SegmentedControlTotalV2Schema).min(1).max(100_000),
    balanceTolerance: z.string().regex(/^(?:0|[1-9]\d*)(?:\.\d+)?$/u)
  })
  .strict();

export const ReconciliationDefinitionV1Schema = z
  .object({
    definitionId: IdentifierSchema,
    reconciliationId: IdentifierSchema,
    requiredSectionIds: z.array(IdentifierSchema).min(1).max(256),
    controls: z.array(ReconciliationControlV1Schema).min(1).max(256),
    window: EffectiveWindowV1Schema
  })
  .strict()
  .superRefine((value, context) => {
    const required = new Set(value.requiredSectionIds);
    if (required.size !== value.requiredSectionIds.length) {
      context.addIssue({ code: "custom", path: ["requiredSectionIds"], message: "must be unique" });
    }
    const ids = value.controls.map((control) => control.controlId);
    if (new Set(ids).size !== ids.length) {
      context.addIssue({ code: "custom", path: ["controls"], message: "control ids must be unique" });
    }
    for (const sectionId of required) {
      if (!value.controls.some((control) => control.sectionId === sectionId)) {
        context.addIssue({
          code: "custom",
          path: ["controls"],
          message: `required section ${sectionId} must have an executable control`
        });
      }
    }
    for (const [index, control] of value.controls.entries()) {
      if (!required.has(control.sectionId)) {
        context.addIssue({
          code: "custom",
          path: ["controls", index, "sectionId"],
          message: "must name a required section"
        });
      }
    }
  });

export const RuntimeActivationV1Schema = z
  .object({
    runtimeBundleId: IdentifierSchema,
    runtimeBundleHash: Sha256HashSchema,
    window: EffectiveWindowV1Schema
  })
  .strict();

export interface ModernDataQualityDefinitionV1 {
  readonly definitionId: string;
  readonly rulesetId: string;
  readonly mappingSectionId: string;
  readonly requiredSectionIds: readonly string[];
  readonly rules: readonly DataQualityRuleV2[];
  readonly balanceField: string;
  readonly materialBalance: string;
  readonly window: Readonly<z.infer<typeof EffectiveWindowV1Schema>>;
}

export type ModernReconciliationDefinitionV1 = Readonly<
  z.infer<typeof ReconciliationDefinitionV1Schema>
>;

export interface ModernCertificationDefinitionResolutionV1 {
  readonly mappingSpec: MappingSpecV2;
  readonly mappingWindow: Readonly<z.infer<typeof EffectiveWindowV1Schema>>;
  readonly runtime: {
    readonly runtimeBundleId: string;
    readonly runtimeBundleHash: Sha256Hash;
    readonly window: Readonly<z.infer<typeof EffectiveWindowV1Schema>>;
  };
  readonly dataQuality: ModernDataQualityDefinitionV1;
  readonly reconciliation: ModernReconciliationDefinitionV1;
}

export interface ModernCertificationDefinitionAuthorityV1 {
  resolveForBoundSnapshot(input: {
    readonly evidence: {
      readonly tenantId: string;
      readonly sourceContract: DatasetSnapshotV2["sourceContract"];
      readonly deliveryHash: Sha256Hash;
      readonly extractionReceipt: ModernSnapshotExtractionReceiptV1;
      readonly delivery: GovernedSourceDeliveryRecordV1;
      readonly scopeBinding: GovernedDatasetScopeBindingV1;
      readonly asOfDate: string;
    };
  }): Promise<ModernCertificationDefinitionResolutionV1 | undefined>;
}
