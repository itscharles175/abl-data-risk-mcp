import { Decimal } from "decimal.js";

import {
  parseMappingSpecV2,
  type MappingConditionV2,
  type MappingExpressionV2,
  type MappingSpecV2
} from "../contracts/mapping-v2.js";
import { canonicalHash } from "../contracts/canonical.js";

const ExactDecimal = Decimal.clone({ precision: 50, rounding: Decimal.ROUND_HALF_EVEN });

export type MappingSourceScalar = null | boolean | string | number;
export type MappingOutputScalar = null | boolean | string;

export interface MappingDimensionLookupV1 {
  readonly definitionId: string;
  readonly definitionVersion: string;
  readonly definitionHash: string;
  resolve(value: string): string | null | undefined;
}

export interface ExecuteMappingSpecV2Input {
  readonly spec: MappingSpecV2;
  readonly records: readonly Readonly<Record<string, MappingSourceScalar>>[];
  readonly dimensions?: readonly MappingDimensionLookupV1[];
  readonly maximumRecords?: number;
  readonly maximumSourceColumns?: number;
  readonly maximumOutputBytes?: number;
}

export interface MappingRowRejectionV1 {
  readonly rowIndex: number;
  readonly ruleId: string;
  readonly code: "EXPRESSION_FAILED";
}

export interface MappingExecutionResultV1 {
  readonly schemaVersion: 1;
  readonly mappingSpecId: string;
  readonly mappingSpecHash: string;
  readonly inputRowCount: number;
  readonly outputRowCount: number;
  readonly rejectedRowCount: number;
  readonly inputPopulationHash: string;
  readonly outputPopulationHash: string;
  readonly records: readonly Readonly<Record<string, MappingOutputScalar>>[];
  readonly rejections: readonly MappingRowRejectionV1[];
  readonly executionHash: string;
}

export class MappingExecutionError extends Error {
  constructor(
    readonly code: "INVALID_INPUT" | "MAPPING_FAILED" | "OUTPUT_LIMIT_EXCEEDED",
    message: string
  ) {
    super(message);
    this.name = "MappingExecutionError";
  }
}

/** Executes the closed mapping AST. It never evaluates code, SQL, regex, or a user expression language. */
export function executeMappingSpecV2(input: ExecuteMappingSpecV2Input): MappingExecutionResultV1 {
  const spec = parseMappingSpecV2(input.spec);
  if (spec.status !== "approved" && spec.status !== "active" && spec.status !== "retired") {
    fail("MAPPING_FAILED", "Mapping execution requires an approved historical specification");
  }
  const maximumRecords = bounded(input.maximumRecords ?? 1_000_000, "maximumRecords", 1, 1_000_000);
  const maximumSourceColumns = bounded(input.maximumSourceColumns ?? 2_000, "maximumSourceColumns", 1, 2_000);
  const maximumOutputBytes = bounded(input.maximumOutputBytes ?? 512 * 1_024 * 1_024, "maximumOutputBytes", 1_024, 2_147_483_647);
  if (!Array.isArray(input.records) || input.records.length > maximumRecords) invalid("Input records exceed the configured bound");
  const dimensions = new Map<string, MappingDimensionLookupV1>();
  for (const dimension of input.dimensions ?? []) {
    const key = `${dimension.definitionId}:${dimension.definitionVersion}:${dimension.definitionHash}`;
    if (dimensions.has(key)) invalid("Duplicate dimension lookup");
    dimensions.set(key, dimension);
  }
  const sourceColumns = new Set<string>();
  for (const record of input.records) {
    if (!isPlainRecord(record)) invalid("Mapping input row must be a plain object");
    for (const [field, value] of Object.entries(record)) {
      safeField(field);
      validateSourceScalar(value);
      sourceColumns.add(field);
      if (sourceColumns.size > maximumSourceColumns) invalid("Source column count exceeds the configured bound");
    }
  }
  const inputPopulationHash = canonicalHash(input.records as never);
  const output: Readonly<Record<string, MappingOutputScalar>>[] = [];
  const rejections: MappingRowRejectionV1[] = [];
  for (const [rowIndex, record] of input.records.entries()) {
    const mapped: Record<string, MappingOutputScalar> = {};
    let reject = false;
    for (const rule of spec.rules) {
      try {
        mapped[rule.canonicalField] = evaluateExpression(rule.expression, record, dimensions, 0);
      } catch (error) {
        if (!(error instanceof MappingExpressionError)) throw error;
        if (rule.onError === "fail_application") {
          fail("MAPPING_FAILED", `Mapping rule ${rule.ruleId} failed at row ${rowIndex}`);
        }
        if (rule.onError === "null") {
          mapped[rule.canonicalField] = null;
          continue;
        }
        rejections.push({ rowIndex, ruleId: rule.ruleId, code: "EXPRESSION_FAILED" });
        reject = true;
        break;
      }
    }
    if (!reject) output.push(Object.freeze(mapped));
  }
  const frozenRecords = Object.freeze(output);
  const frozenRejections: readonly MappingRowRejectionV1[] = Object.freeze(
    rejections.map((rejection) => Object.freeze(rejection))
  );
  const outputPopulationHash = canonicalHash(frozenRecords as never);
  const body = {
    schemaVersion: 1 as const,
    mappingSpecId: spec.mappingSpecId,
    mappingSpecHash: spec.mappingSpecHash,
    inputRowCount: input.records.length,
    outputRowCount: frozenRecords.length,
    rejectedRowCount: frozenRejections.length,
    inputPopulationHash,
    outputPopulationHash,
    records: frozenRecords,
    rejections: frozenRejections
  };
  if (Buffer.byteLength(JSON.stringify(body), "utf8") > maximumOutputBytes) {
    fail("OUTPUT_LIMIT_EXCEEDED", "Mapped output exceeds the configured byte bound");
  }
  return Object.freeze({ ...body, executionHash: canonicalHash(body as never) });
}

function evaluateExpression(
  expression: MappingExpressionV2,
  record: Readonly<Record<string, MappingSourceScalar>>,
  dimensions: ReadonlyMap<string, MappingDimensionLookupV1>,
  depth: number
): MappingOutputScalar {
  if (depth > 8) expressionError();
  if (expression.op === "source") return normalizeSource(record[expression.column] ?? null);
  if (expression.op === "literal") return expression.value;
  if (expression.op === "exact_cast") {
    return exactCast(evaluateExpression(expression.input, record, dimensions, depth + 1), expression.to);
  }
  if (expression.op === "parse_date") {
    const value = evaluateExpression(expression.input, record, dimensions, depth + 1);
    if (value === null) return null;
    if (typeof value !== "string") expressionError();
    for (const format of expression.formats) {
      const parsed = parseDate(value, format);
      if (parsed !== null) return parsed;
    }
    expressionError();
  }
  if (expression.op === "scale_decimal") {
    const value = evaluateExpression(expression.input, record, dimensions, depth + 1);
    if (value === null) return null;
    if (typeof value !== "string") expressionError();
    const scaled = decimal(value).times(decimal(expression.factor));
    const fixed = scaled.toDecimalPlaces(expression.decimalPlaces, Decimal.ROUND_HALF_EVEN);
    if (expression.rounding === "reject" && !fixed.equals(scaled)) expressionError();
    return canonicalDecimal(fixed, expression.decimalPlaces);
  }
  if (expression.op === "code_map") {
    const value = evaluateExpression(expression.input, record, dimensions, depth + 1);
    if (value === null) return null;
    if (typeof value !== "string") expressionError();
    const found = Object.prototype.hasOwnProperty.call(expression.values, value)
      ? expression.values[value]
      : undefined;
    if (found !== undefined) return found;
    if (expression.unknown === "null") return null;
    if (expression.unknown === "preserve") return value;
    expressionError();
  }
  if (expression.op === "coalesce") {
    for (const nested of expression.inputs) {
      const value = evaluateExpression(nested, record, dimensions, depth + 1);
      if (value !== null) return value;
    }
    return null;
  }
  if (expression.op === "when") {
    return evaluateCondition(expression.condition, record, dimensions, depth + 1)
      ? evaluateExpression(expression.then, record, dimensions, depth + 1)
      : evaluateExpression(expression.otherwise, record, dimensions, depth + 1);
  }
  if (expression.op === "split") {
    const value = evaluateExpression(expression.input, record, dimensions, depth + 1);
    if (value === null) return null;
    if (typeof value !== "string") expressionError();
    const part = value.split(expression.delimiter)[expression.index];
    if (part === undefined) expressionError();
    return expression.trim ? part.trim() : part;
  }
  if (expression.op === "combine") {
    const values = expression.inputs.map((nested) => evaluateExpression(nested, record, dimensions, depth + 1));
    if (values.some((value) => typeof value === "boolean")) expressionError();
    const selected = expression.skipNulls ? values.filter((value) => value !== null) : values;
    if (!expression.skipNulls && selected.some((value) => value === null)) return null;
    return selected.map((value) => value ?? "").join(expression.separator);
  }
  const value = evaluateExpression(expression.input, record, dimensions, depth + 1);
  if (value === null) return null;
  if (typeof value !== "string") expressionError();
  const key = `${expression.definitionId}:${expression.definitionVersion}:${expression.definitionHash}`;
  const lookup = dimensions.get(key);
  if (!lookup) expressionError();
  const resolved = lookup.resolve(value);
  if (resolved !== null && resolved !== undefined) return resolved;
  if (expression.missing === "null") return null;
  if (expression.missing === "preserve") return value;
  expressionError();
}

function evaluateCondition(
  condition: MappingConditionV2,
  record: Readonly<Record<string, MappingSourceScalar>>,
  dimensions: ReadonlyMap<string, MappingDimensionLookupV1>,
  depth: number
): boolean {
  if (depth > 8) expressionError();
  if (condition.op === "equals") {
    return scalarEqual(
      evaluateExpression(condition.left, record, dimensions, depth + 1),
      evaluateExpression(condition.right, record, dimensions, depth + 1)
    );
  }
  if (condition.op === "in") {
    const value = evaluateExpression(condition.input, record, dimensions, depth + 1);
    return condition.values.some((candidate) => scalarEqual(value, candidate));
  }
  if (condition.op === "is_null") return evaluateExpression(condition.input, record, dimensions, depth + 1) === null;
  if (condition.op === "not") return !evaluateCondition(condition.condition, record, dimensions, depth + 1);
  if (condition.op === "and") return condition.conditions.every((nested) => evaluateCondition(nested, record, dimensions, depth + 1));
  return condition.conditions.some((nested) => evaluateCondition(nested, record, dimensions, depth + 1));
}

function exactCast(value: MappingOutputScalar, type: string): MappingOutputScalar {
  if (value === null) return null;
  if (type === "boolean") {
    if (typeof value === "boolean") return value;
    if (value === "true" || value === "1") return true;
    if (value === "false" || value === "0") return false;
    expressionError();
  }
  if (typeof value !== "string") expressionError();
  if (type === "integer") {
    if (!/^-?(?:0|[1-9]\d*)$/u.test(value)) expressionError();
    return BigInt(value).toString();
  }
  if (type === "decimal" || type === "currency" || type === "percentage") return canonicalDecimal(decimal(value));
  if (type === "date") return parseDate(value, "YYYY-MM-DD") ?? expressionError();
  if (type === "datetime") {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value)) expressionError();
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) expressionError();
    return date.toISOString();
  }
  if (type === "identifier" || type === "string") return value;
  expressionError();
}

function parseDate(value: string, format: string): string | null {
  let year: string;
  let month: string;
  let day: string;
  if (format === "YYYY-MM-DD") {
    const match = /^(\d{4})-(\d{2})-(\d{2})$/u.exec(value);
    if (!match) return null;
    [, year, month, day] = match as RegExpExecArray & [string, string, string, string];
  } else if (format === "MM/DD/YYYY") {
    const match = /^(\d{2})\/(\d{2})\/(\d{4})$/u.exec(value);
    if (!match) return null;
    month = match[1]!; day = match[2]!; year = match[3]!;
  } else if (format === "YYYYMMDD") {
    const match = /^(\d{4})(\d{2})(\d{2})$/u.exec(value);
    if (!match) return null;
    year = match[1]!; month = match[2]!; day = match[3]!;
  } else {
    expressionError();
  }
  const canonical = `${year}-${month}-${day}`;
  const parsed = new Date(`${canonical}T00:00:00.000Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === canonical ? canonical : null;
}

function normalizeSource(value: MappingSourceScalar): MappingOutputScalar {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (!Number.isSafeInteger(value)) expressionError();
  return String(value);
}

function validateSourceScalar(value: unknown): asserts value is MappingSourceScalar {
  if (value === null || typeof value === "boolean" || typeof value === "string") return;
  if (typeof value === "number" && Number.isSafeInteger(value)) return;
  invalid("Source values must be null, boolean, string, or safe integers");
}

function scalarEqual(left: MappingOutputScalar, right: MappingOutputScalar): boolean {
  return left === right;
}

function decimal(value: string): Decimal {
  if (!/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/u.test(value)) expressionError();
  try {
    return new ExactDecimal(value);
  } catch {
    expressionError();
  }
}

function canonicalDecimal(value: Decimal, decimalPlaces?: number): string {
  const text = decimalPlaces === undefined ? value.toFixed() : value.toFixed(decimalPlaces);
  const normalized = text.includes(".") ? text.replace(/\.?0+$/u, "") : text;
  return normalized === "-0" || normalized === "" ? "0" : normalized;
}

function isPlainRecord(value: unknown): value is Readonly<Record<string, MappingSourceScalar>> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function safeField(value: string): void {
  if (!value || value.length > 256 || /[\u0000-\u001f\u007f]/u.test(value)) invalid("Source field is invalid");
}

function bounded(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalid(`${label} is outside its bound`);
  return value;
}

class MappingExpressionError extends Error {}

function expressionError(): never {
  throw new MappingExpressionError("Mapping expression failed");
}

function invalid(message: string): never {
  fail("INVALID_INPUT", message);
}

function fail(code: MappingExecutionError["code"], message: string): never {
  throw new MappingExecutionError(code, message);
}
