import { Decimal } from "decimal.js";
import { z } from "zod";

import {
  ContractValidationError,
  IdentifierSchema,
  IsoDateSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  canonicalJson,
  parseWithSchema
} from "./canonical.js";

const MAX_EXACT_DECIMAL_SIGNIFICANT_DIGITS = 256;
const MAX_EXACT_DECIMAL_CHARACTERS =
  MAX_EXACT_DECIMAL_SIGNIFICANT_DIGITS + 1 + 18;
// Two maximum-width operands can produce 512 integer digits. Division can also
// shift the result by the full scale of the divisor, so retain enough guard
// precision to round the largest accepted result to the supported 18 places.
const ExactDecimal = Decimal.clone({ precision: 640, rounding: Decimal.ROUND_HALF_EVEN });
const CurrencyCodeSchema = z.string().regex(/^[A-Z]{3}$/u, "must be an ISO-style currency code");
const ExactDecimalSchema = z
  .string()
  .max(MAX_EXACT_DECIMAL_CHARACTERS)
  .regex(/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/u, "must be an exact decimal string")
  .refine(
    (value) => significantDigitCount(value) <= MAX_EXACT_DECIMAL_SIGNIFICANT_DIGITS,
    `must contain at most ${MAX_EXACT_DECIMAL_SIGNIFICANT_DIGITS} significant digits`
  );
const PositiveDecimalSchema = z
  .string()
  .max(MAX_EXACT_DECIMAL_CHARACTERS)
  .regex(/^(?:0|[1-9]\d*)(?:\.\d+)?$/u, "must be an exact non-negative decimal string")
  .refine(
    (value) => significantDigitCount(value) <= MAX_EXACT_DECIMAL_SIGNIFICANT_DIGITS,
    `must contain at most ${MAX_EXACT_DECIMAL_SIGNIFICANT_DIGITS} significant digits`
  )
  .refine((value) => new ExactDecimal(value).greaterThan(0), "must be greater than zero");

const SourceContractReferenceSchema = z
  .object({
    sourceContractId: IdentifierSchema,
    revision: z.number().int().positive().max(1_000_000),
    sourceContractHash: Sha256HashSchema
  })
  .strict();

const CurrencyPairSchema = z
  .object({
    baseCurrency: CurrencyCodeSchema,
    quoteCurrency: CurrencyCodeSchema
  })
  .strict()
  .superRefine((value, context) => {
    if (value.baseCurrency === value.quoteCurrency) {
      context.addIssue({
        code: "custom",
        path: ["quoteCurrency"],
        message: "must differ from baseCurrency"
      });
    }
  });

const FxDefinitionActivationReferenceBodyV1Schema = z
  .object({
    authority: z.literal("governed_definition_v2_lifecycle"),
    tenantId: IdentifierSchema,
    fxDefinitionId: IdentifierSchema,
    version: z.string().min(1).max(64),
    definitionVersionId: IdentifierSchema,
    definitionVersionHash: Sha256HashSchema,
    activationEventId: IdentifierSchema,
    tenantSequence: z.number().int().positive().safe(),
    previousEventHash: Sha256HashSchema.nullable(),
    activationEventHash: Sha256HashSchema,
    activatedBy: IdentifierSchema,
    activatedAt: IsoTimestampSchema
  })
  .strict();

const FxDefinitionActivationReferenceV1Schema =
  FxDefinitionActivationReferenceBodyV1Schema.extend({
    referenceHash: Sha256HashSchema
  })
    .strict()
    .superRefine((value, context) => {
      const { referenceHash, ...body } = value;
      if (canonicalHash(body) !== referenceHash) {
        context.addIssue({
          code: "custom",
          path: ["referenceHash"],
          message: "must authenticate the exact governed activation reference"
        });
      }
    });

const FxRateDefinitionBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    fxDefinitionId: IdentifierSchema,
    version: z.string().min(1).max(64),
    status: z.enum(["proposed", "approved", "active", "superseded", "retired"]),
    sourceContract: SourceContractReferenceSchema,
    provider: IdentifierSchema,
    pair: CurrencyPairSchema,
    rateType: z.enum(["spot", "closing", "period_average", "contractual"]),
    sourceConvention: z.enum(["base_to_quote", "quote_to_base"]),
    ratePrecision: z.number().int().min(0).max(18),
    baseAmountPrecision: z.number().int().min(0).max(18),
    quoteAmountPrecision: z.number().int().min(0).max(18),
    effectiveFrom: IsoDateSchema,
    effectiveTo: IsoDateSchema.optional(),
    createdBy: IdentifierSchema,
    createdAt: IsoTimestampSchema,
    approvedBy: IdentifierSchema.optional(),
    approvedAt: IsoTimestampSchema.optional(),
    activation: FxDefinitionActivationReferenceV1Schema.optional()
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
    const governed = value.status !== "proposed";
    if (governed && (value.approvedBy === undefined || value.approvedAt === undefined)) {
      context.addIssue({
        code: "custom",
        path: ["approvedBy"],
        message: "governed status requires approval evidence"
      });
    }
    if (value.approvedBy !== undefined && value.approvedBy === value.createdBy) {
      context.addIssue({
        code: "custom",
        path: ["approvedBy"],
        message: "must differ from createdBy"
      });
    }
    if (value.approvedAt !== undefined && value.approvedAt < value.createdAt) {
      context.addIssue({
        code: "custom",
        path: ["approvedAt"],
        message: "cannot precede creation"
      });
    }
    const activatedStatus =
      value.status === "active" || value.status === "superseded" || value.status === "retired";
    if (activatedStatus && value.activation === undefined) {
      context.addIssue({
        code: "custom",
        path: ["activation"],
        message: "activated status requires a durable governed lifecycle reference"
      });
    }
    if (!activatedStatus && value.activation !== undefined) {
      context.addIssue({
        code: "custom",
        path: ["activation"],
        message: "is only valid after durable lifecycle activation"
      });
    }
    if (value.activation !== undefined) {
      if (value.activation.tenantId !== value.tenantId) {
        context.addIssue({
          code: "custom",
          path: ["activation", "tenantId"],
          message: "must match the FX definition tenant"
        });
      }
      if (value.activation.fxDefinitionId !== value.fxDefinitionId) {
        context.addIssue({
          code: "custom",
          path: ["activation", "fxDefinitionId"],
          message: "must match the FX definition identity"
        });
      }
      if (value.activation.version !== value.version) {
        context.addIssue({
          code: "custom",
          path: ["activation", "version"],
          message: "must match the FX definition version"
        });
      }
      if (value.approvedAt !== undefined && value.activation.activatedAt < value.approvedAt) {
        context.addIssue({
          code: "custom",
          path: ["activation", "activatedAt"],
          message: "cannot precede approval"
        });
      }
    }
  });

export const FxRateDefinitionV1Schema = FxRateDefinitionBodyV1Schema.extend({
  definitionHash: Sha256HashSchema
}).strict();

export type FxRateDefinitionV1 = Readonly<z.infer<typeof FxRateDefinitionV1Schema>>;
export type FxRateDefinitionV1Input = Readonly<z.input<typeof FxRateDefinitionBodyV1Schema>>;

const FrozenFxDefinitionReferenceV1Schema = z
  .object({
    tenantId: IdentifierSchema,
    fxDefinitionId: IdentifierSchema,
    version: z.string().min(1).max(64),
    status: z.literal("active"),
    definitionHash: Sha256HashSchema,
    activation: FxDefinitionActivationReferenceV1Schema,
    sourceContract: SourceContractReferenceSchema,
    pair: CurrencyPairSchema,
    rateType: z.enum(["spot", "closing", "period_average", "contractual"]),
    sourceConvention: z.enum(["base_to_quote", "quote_to_base"]),
    ratePrecision: z.number().int().min(0).max(18),
    baseAmountPrecision: z.number().int().min(0).max(18),
    quoteAmountPrecision: z.number().int().min(0).max(18)
  })
  .strict();

const FxRateEvidenceBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    rateEvidenceId: IdentifierSchema,
    definition: FrozenFxDefinitionReferenceV1Schema,
    sourceSnapshot: z
      .object({
        snapshotId: IdentifierSchema,
        snapshotHash: Sha256HashSchema,
        sourceContract: SourceContractReferenceSchema
      })
      .strict(),
    effectiveAt: IsoTimestampSchema,
    observedAt: IsoTimestampSchema,
    receivedAt: IsoTimestampSchema,
    sourceRate: PositiveDecimalSchema,
    normalizedBaseToQuoteRate: PositiveDecimalSchema,
    capturedBy: IdentifierSchema
  })
  .strict()
  .superRefine((value, context) => {
    if (value.definition.tenantId !== value.tenantId) {
      context.addIssue({
        code: "custom",
        path: ["definition", "tenantId"],
        message: "must match the FX rate evidence tenant"
      });
    }
    if (value.definition.activation.tenantId !== value.tenantId) {
      context.addIssue({
        code: "custom",
        path: ["definition", "activation", "tenantId"],
        message: "must match the FX rate evidence tenant"
      });
    }
    if (
      value.definition.activation.fxDefinitionId !== value.definition.fxDefinitionId ||
      value.definition.activation.version !== value.definition.version
    ) {
      context.addIssue({
        code: "custom",
        path: ["definition", "activation"],
        message: "must match the frozen FX definition identity and version"
      });
    }
    const scale = decimalScale(value.normalizedBaseToQuoteRate);
    if (scale !== value.definition.ratePrecision) {
      context.addIssue({
        code: "custom",
        path: ["normalizedBaseToQuoteRate"],
        message: "must use the frozen definition rate precision"
      });
    }
    if (value.effectiveAt > value.observedAt || value.observedAt > value.receivedAt) {
      context.addIssue({
        code: "custom",
        path: ["receivedAt"],
        message: "rate evidence timestamps must be chronological"
      });
    }
    if (value.definition.activation.activatedAt > value.observedAt) {
      context.addIssue({
        code: "custom",
        path: ["definition", "activation", "activatedAt"],
        message: "governed activation must precede rate observation"
      });
    }
    if (
      canonicalJson(value.sourceSnapshot.sourceContract) !==
      canonicalJson(value.definition.sourceContract)
    ) {
      context.addIssue({
        code: "custom",
        path: ["sourceSnapshot", "sourceContract"],
        message: "must match the frozen FX definition source contract"
      });
    }
  });

export const FxRateEvidenceV1Schema = FxRateEvidenceBodyV1Schema.extend({
  rateEvidenceHash: Sha256HashSchema
}).strict();

export type FxRateEvidenceV1 = Readonly<z.infer<typeof FxRateEvidenceV1Schema>>;

const FxConversionBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    conversionId: IdentifierSchema,
    purpose: IdentifierSchema,
    rateEvidence: FxRateEvidenceV1Schema,
    direction: z.enum(["base_to_quote", "quote_to_base"]),
    sourceAmount: ExactDecimalSchema,
    sourceCurrency: CurrencyCodeSchema,
    convertedAmount: ExactDecimalSchema,
    targetCurrency: CurrencyCodeSchema,
    targetPrecision: z.number().int().min(0).max(18),
    rounding: z.literal("half_even"),
    performedAt: IsoTimestampSchema,
    performedBy: IdentifierSchema
  })
  .strict()
  .superRefine((value, context) => {
    if (decimalScale(value.convertedAmount) !== value.targetPrecision) {
      context.addIssue({
        code: "custom",
        path: ["convertedAmount"],
        message: "must use the declared target precision"
      });
    }
    const pair = value.rateEvidence.definition.pair;
    const expected = value.direction === "base_to_quote"
      ? { source: pair.baseCurrency, target: pair.quoteCurrency }
      : { source: pair.quoteCurrency, target: pair.baseCurrency };
    if (value.sourceCurrency !== expected.source || value.targetCurrency !== expected.target) {
      context.addIssue({
        code: "custom",
        path: ["direction"],
        message: "does not match the frozen currency pair"
      });
    }
    const expectedPrecision = value.direction === "base_to_quote"
      ? value.rateEvidence.definition.quoteAmountPrecision
      : value.rateEvidence.definition.baseAmountPrecision;
    if (value.targetPrecision !== expectedPrecision) {
      context.addIssue({
        code: "custom",
        path: ["targetPrecision"],
        message: "must match the frozen target-currency precision"
      });
    }
    if (value.rateEvidence.tenantId !== value.tenantId) {
      context.addIssue({
        code: "custom",
        path: ["rateEvidence", "tenantId"],
        message: "must match the conversion tenant"
      });
    }
    if (value.rateEvidence.receivedAt > value.performedAt) {
      context.addIssue({
        code: "custom",
        path: ["performedAt"],
        message: "cannot precede receipt of the rate evidence"
      });
    }
  });

export const FxConversionLineageV1Schema = FxConversionBodyV1Schema.extend({
  conversionHash: Sha256HashSchema
}).strict();

export type FxConversionLineageV1 = Readonly<z.infer<typeof FxConversionLineageV1Schema>>;

export interface CreateFxRateEvidenceV1Input {
  readonly definition: FxRateDefinitionV1;
  readonly tenantId: string;
  readonly rateEvidenceId: string;
  readonly sourceSnapshot: z.input<typeof FxRateEvidenceBodyV1Schema>["sourceSnapshot"];
  readonly effectiveAt: string;
  readonly observedAt: string;
  readonly receivedAt: string;
  readonly sourceRate: string;
  readonly capturedBy: string;
}

export interface CreateFxConversionLineageV1Input {
  readonly definition: FxRateDefinitionV1;
  readonly rateEvidence: FxRateEvidenceV1;
  readonly tenantId: string;
  readonly conversionId: string;
  readonly purpose: string;
  readonly sourceAmount: string;
  readonly sourceCurrency: string;
  readonly targetCurrency: string;
  readonly performedAt: string;
  readonly performedBy: string;
}

export function createFxRateDefinitionV1(
  inputValue: FxRateDefinitionV1Input
): FxRateDefinitionV1 {
  canonicalJson(inputValue);
  const body = parseWithSchema(
    FxRateDefinitionBodyV1Schema,
    inputValue,
    "FxRateDefinitionV1 input"
  );
  return parseFxRateDefinitionV1({ ...body, definitionHash: canonicalHash(body) });
}

export function parseFxRateDefinitionV1(value: unknown): FxRateDefinitionV1 {
  canonicalJson(value);
  const parsed = parseWithSchema(FxRateDefinitionV1Schema, value, "FxRateDefinitionV1");
  const { definitionHash, ...body } = parsed;
  assertCanonicalHash(body, definitionHash, "FxRateDefinitionV1");
  return parsed;
}

export function createFxRateEvidenceV1(
  inputValue: CreateFxRateEvidenceV1Input
): FxRateEvidenceV1 {
  canonicalJson(inputValue);
  const definition = parseFxRateDefinitionV1(inputValue.definition);
  if (definition.status !== "active") {
    invariant("New FX rate evidence requires an active definition");
  }
  if (definition.tenantId !== inputValue.tenantId) {
    invariant("FX rate definition tenant does not match the capture tenant");
  }
  if (!dateIsEffective(inputValue.effectiveAt.slice(0, 10), definition)) {
    invariant("FX rate timestamp is outside the definition effectivity interval");
  }
  if (definition.approvedAt === undefined || definition.approvedAt > inputValue.observedAt) {
    invariant("FX definition approval must precede observation");
  }
  if (definition.activation === undefined || definition.activation.activatedAt > inputValue.observedAt) {
    invariant("FX definition governed activation must precede observation");
  }
  if (
    inputValue.sourceSnapshot.sourceContract.sourceContractId !==
      definition.sourceContract.sourceContractId ||
    inputValue.sourceSnapshot.sourceContract.revision !== definition.sourceContract.revision ||
    inputValue.sourceSnapshot.sourceContract.sourceContractHash !==
      definition.sourceContract.sourceContractHash
  ) {
    invariant("FX source snapshot is not bound to the frozen source contract");
  }
  const sourceRate = positive(inputValue.sourceRate, "sourceRate");
  const normalized = definition.sourceConvention === "base_to_quote"
    ? sourceRate
    : new ExactDecimal(1).div(sourceRate);
  const body = parseWithSchema(
    FxRateEvidenceBodyV1Schema,
    {
      contractVersion: 1,
      tenantId: inputValue.tenantId,
      rateEvidenceId: inputValue.rateEvidenceId,
      definition: definitionReference(definition),
      sourceSnapshot: inputValue.sourceSnapshot,
      effectiveAt: inputValue.effectiveAt,
      observedAt: inputValue.observedAt,
      receivedAt: inputValue.receivedAt,
      sourceRate: inputValue.sourceRate,
      normalizedBaseToQuoteRate: fixed(normalized, definition.ratePrecision),
      capturedBy: inputValue.capturedBy
    },
    "FxRateEvidenceV1 input"
  );
  return parseFxRateEvidenceV1({ ...body, rateEvidenceHash: canonicalHash(body) });
}

export function parseFxRateEvidenceV1(value: unknown): FxRateEvidenceV1 {
  canonicalJson(value);
  const parsed = parseWithSchema(FxRateEvidenceV1Schema, value, "FxRateEvidenceV1");
  const { rateEvidenceHash, ...body } = parsed;
  assertCanonicalHash(body, rateEvidenceHash, "FxRateEvidenceV1");
  assertNormalizedRate(parsed);
  return parsed;
}

export function createFxConversionLineageV1(
  inputValue: CreateFxConversionLineageV1Input
): FxConversionLineageV1 {
  canonicalJson(inputValue);
  const definition = parseFxRateDefinitionV1(inputValue.definition);
  const rateEvidence = parseFxRateEvidenceV1(inputValue.rateEvidence);
  if (definition.status !== "active") {
    invariant("New FX conversions require an active definition");
  }
  if (inputValue.tenantId !== definition.tenantId || rateEvidence.tenantId !== definition.tenantId) {
    invariant("FX conversion tenant does not match its frozen evidence");
  }
  const expectedReference = definitionReference(definition);
  if (canonicalJson(rateEvidence.definition) !== canonicalJson(expectedReference)) {
    invariant("FX rate evidence does not match the supplied frozen definition");
  }
  if (rateEvidence.receivedAt > inputValue.performedAt) {
    invariant("FX conversion cannot precede receipt of its rate evidence");
  }
  const pair = definition.pair;
  let direction: "base_to_quote" | "quote_to_base";
  let targetPrecision: number;
  let converted: Decimal;
  const sourceAmount = decimal(inputValue.sourceAmount, "sourceAmount");
  const rate = positive(rateEvidence.normalizedBaseToQuoteRate, "normalizedBaseToQuoteRate");
  if (
    inputValue.sourceCurrency === pair.baseCurrency &&
    inputValue.targetCurrency === pair.quoteCurrency
  ) {
    direction = "base_to_quote";
    targetPrecision = definition.quoteAmountPrecision;
    converted = sourceAmount.times(rate);
  } else if (
    inputValue.sourceCurrency === pair.quoteCurrency &&
    inputValue.targetCurrency === pair.baseCurrency
  ) {
    direction = "quote_to_base";
    targetPrecision = definition.baseAmountPrecision;
    converted = sourceAmount.div(rate);
  } else {
    invariant("FX conversion currencies do not match the frozen pair");
  }
  const body = parseWithSchema(
    FxConversionBodyV1Schema,
    {
      contractVersion: 1,
      tenantId: inputValue.tenantId,
      conversionId: inputValue.conversionId,
      purpose: inputValue.purpose,
      rateEvidence,
      direction,
      sourceAmount: inputValue.sourceAmount,
      sourceCurrency: inputValue.sourceCurrency,
      convertedAmount: fixed(converted, targetPrecision),
      targetCurrency: inputValue.targetCurrency,
      targetPrecision,
      rounding: "half_even",
      performedAt: inputValue.performedAt,
      performedBy: inputValue.performedBy
    },
    "FxConversionLineageV1 input"
  );
  return parseFxConversionLineageV1({ ...body, conversionHash: canonicalHash(body) });
}

export function parseFxConversionLineageV1(value: unknown): FxConversionLineageV1 {
  canonicalJson(value);
  const parsed = parseWithSchema(FxConversionLineageV1Schema, value, "FxConversionLineageV1");
  parseFxRateEvidenceV1(parsed.rateEvidence);
  const { conversionHash, ...body } = parsed;
  assertCanonicalHash(body, conversionHash, "FxConversionLineageV1");
  assertConversionCalculation(parsed);
  return parsed;
}

function definitionReference(
  definition: FxRateDefinitionV1
): z.infer<typeof FrozenFxDefinitionReferenceV1Schema> {
  return {
    tenantId: definition.tenantId,
    fxDefinitionId: definition.fxDefinitionId,
    version: definition.version,
    status: "active",
    definitionHash: definition.definitionHash,
    activation: definition.activation!,
    sourceContract: definition.sourceContract,
    pair: definition.pair,
    rateType: definition.rateType,
    sourceConvention: definition.sourceConvention,
    ratePrecision: definition.ratePrecision,
    baseAmountPrecision: definition.baseAmountPrecision,
    quoteAmountPrecision: definition.quoteAmountPrecision
  };
}

function dateIsEffective(date: string, definition: FxRateDefinitionV1): boolean {
  return date >= definition.effectiveFrom &&
    (definition.effectiveTo === undefined || date < definition.effectiveTo);
}

function decimal(value: string, label: string): Decimal {
  const parsed = parseWithSchema(ExactDecimalSchema, value, label);
  try {
    return new ExactDecimal(parsed);
  } catch {
    invariant(`${label} must be an exact decimal string`);
  }
}

function positive(value: string, label: string): Decimal {
  const parsed = parseWithSchema(PositiveDecimalSchema, value, label);
  return new ExactDecimal(parsed);
}

function fixed(value: Decimal, precision: number): string {
  return value.toDecimalPlaces(precision, Decimal.ROUND_HALF_EVEN).toFixed(precision);
}

function decimalScale(value: string): number {
  const point = value.indexOf(".");
  return point === -1 ? 0 : value.length - point - 1;
}

function significantDigitCount(value: string): number {
  const digits = value
    .replace("-", "")
    .replace(".", "")
    .replace(/^0+/u, "")
    .replace(/0+$/u, "");
  return digits.length === 0 ? 1 : digits.length;
}

function assertConversionCalculation(value: FxConversionLineageV1): void {
  const source = decimal(value.sourceAmount, "sourceAmount");
  const rate = positive(
    value.rateEvidence.normalizedBaseToQuoteRate,
    "normalizedBaseToQuoteRate"
  );
  const calculated = value.direction === "base_to_quote"
    ? source.times(rate)
    : source.div(rate);
  if (fixed(calculated, value.targetPrecision) !== value.convertedAmount) {
    invariant("FX converted amount does not match its frozen rate and rounding lineage");
  }
}

function assertNormalizedRate(value: FxRateEvidenceV1): void {
  const sourceRate = positive(value.sourceRate, "sourceRate");
  const normalized = value.definition.sourceConvention === "base_to_quote"
    ? sourceRate
    : new ExactDecimal(1).div(sourceRate);
  if (
    fixed(normalized, value.definition.ratePrecision) !==
    value.normalizedBaseToQuoteRate
  ) {
    invariant("FX normalized rate does not match its source rate and frozen convention");
  }
}

function invariant(message: string): never {
  throw new ContractValidationError("INVARIANT_VIOLATION", message);
}
