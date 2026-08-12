import { createHash } from "node:crypto";

import {
  canonicalHash,
  deepFreeze,
  type Sha256Hash
} from "../contracts/canonical.js";

export type AdapterKindV1 = "xlsx" | "parquet";

export type AdapterLogicalTypeV1 =
  | "text"
  | "integer"
  | "decimal"
  | "boolean"
  | "date"
  | "timestamp";

/**
 * Numeric values deliberately remain strings. This is the common interchange
 * boundary for all adapters, so neither a JavaScript decoder nor an upstream
 * workbook can silently round an integer or fixed-point amount.
 */
export type AdapterScalarV1 = null | boolean | string;

export interface AdapterColumnV1 {
  readonly name: string;
  readonly logicalType: AdapterLogicalTypeV1;
  readonly nullable: boolean;
  readonly decimalPrecision?: number;
  readonly decimalScale?: number;
  readonly timezone?: "UTC";
}

export interface AdapterParserIdentityV1 {
  readonly parserId: string;
  readonly parserVersion: string;
  readonly optionsHash: Sha256Hash;
}

export interface AdapterLimitsV1 {
  readonly maximumRows: number;
  readonly maximumColumns: number;
  readonly maximumCellCharacters: number;
}

export interface ConformedDatasetV1 {
  readonly contractVersion: 1;
  readonly adapterKind: AdapterKindV1;
  readonly sourceMediaType: string;
  readonly sourceContentHash: Sha256Hash;
  readonly parser: AdapterParserIdentityV1;
  readonly parserFingerprint: Sha256Hash;
  readonly columns: readonly Readonly<AdapterColumnV1>[];
  readonly schemaHash: Sha256Hash;
  readonly records: readonly Readonly<Record<string, AdapterScalarV1>>[];
  readonly rowCount: number;
  readonly columnCount: number;
  readonly populationHash: Sha256Hash;
}

export interface BoundedTabularAdapter<Input> {
  readonly adapterKind: AdapterKindV1;
  ingest(input: Input): Promise<ConformedDatasetV1>;
}

export interface AdapterConformanceCaseV1<Input> {
  readonly caseId: string;
  readonly input: Input;
  readonly expectedRowCount: number;
  readonly expectedColumnCount: number;
  readonly expectedSourceContentHash?: Sha256Hash;
  readonly expectedPopulationHash?: Sha256Hash;
}

export interface AdapterConformanceCaseResultV1 {
  readonly caseId: string;
  readonly sourceContentHash: Sha256Hash;
  readonly schemaHash: Sha256Hash;
  readonly populationHash: Sha256Hash;
}

export type AdapterValidationErrorCode =
  | "INVALID_INPUT"
  | "LIMIT_EXCEEDED"
  | "UNSUPPORTED_FEATURE"
  | "INTEGRITY_FAILURE"
  | "SCHEMA_MISMATCH"
  | "UNSAFE_VALUE"
  | "DECODER_CONTRACT_VIOLATION"
  | "DELIVERY_NOT_ALLOWED";

export class AdapterValidationError extends Error {
  constructor(
    readonly code: AdapterValidationErrorCode,
    message: string,
    readonly details: readonly string[] = []
  ) {
    super(message);
    this.name = "AdapterValidationError";
  }
}

export function sha256Bytes(bytes: Uint8Array): Sha256Hash {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function createConformedDataset(input: {
  readonly adapterKind: AdapterKindV1;
  readonly sourceMediaType: string;
  readonly sourceContentHash: Sha256Hash;
  readonly parser: AdapterParserIdentityV1;
  readonly columns: readonly Readonly<AdapterColumnV1>[];
  readonly records: readonly Readonly<Record<string, AdapterScalarV1>>[];
  readonly limits: AdapterLimitsV1;
}): ConformedDatasetV1 {
  if (input.adapterKind !== "xlsx" && input.adapterKind !== "parquet") {
    throw new AdapterValidationError("INVALID_INPUT", "adapterKind is unsupported");
  }
  assertHash(input.sourceContentHash, "sourceContentHash");
  validateParser(input.parser);
  validateLimits(input.limits);
  const columns = validateColumns(input.columns, input.limits.maximumColumns);
  const records = validateRecords(input.records, columns, input.limits);
  const parserFingerprint = canonicalHash(input.parser);
  const schemaHash = canonicalHash(columns);
  const populationHash = canonicalHash({ schemaHash, records });

  return deepFreeze({
    contractVersion: 1 as const,
    adapterKind: input.adapterKind,
    sourceMediaType: boundedText(input.sourceMediaType, "sourceMediaType", 1, 128),
    sourceContentHash: input.sourceContentHash,
    parser: Object.freeze({
      parserId: input.parser.parserId,
      parserVersion: input.parser.parserVersion,
      optionsHash: input.parser.optionsHash
    }),
    parserFingerprint,
    columns,
    schemaHash,
    records,
    rowCount: records.length,
    columnCount: columns.length,
    populationHash
  });
}

/** Revalidates the full result at a trust boundary and verifies all hashes. */
export function verifyConformedDataset(
  dataset: ConformedDatasetV1,
  limits: AdapterLimitsV1
): ConformedDatasetV1 {
  const rebuilt = createConformedDataset({
    adapterKind: dataset.adapterKind,
    sourceMediaType: dataset.sourceMediaType,
    sourceContentHash: dataset.sourceContentHash,
    parser: dataset.parser,
    columns: dataset.columns,
    records: dataset.records,
    limits
  });
  if (
    rebuilt.parserFingerprint !== dataset.parserFingerprint ||
    rebuilt.schemaHash !== dataset.schemaHash ||
    rebuilt.populationHash !== dataset.populationHash ||
    rebuilt.rowCount !== dataset.rowCount ||
    rebuilt.columnCount !== dataset.columnCount
  ) {
    throw new AdapterValidationError(
      "INTEGRITY_FAILURE",
      "Adapter result hashes or counts did not match the canonical payload"
    );
  }
  return rebuilt;
}

/**
 * Shared certification kit for future decoder implementations. Every fixture
 * is executed twice to catch non-deterministic parsing, locale, timezone or
 * row-order behavior before an adapter is advertised as conforming.
 */
export async function runAdapterConformanceKitV1<Input>(input: {
  readonly adapter: BoundedTabularAdapter<Input>;
  readonly cases: readonly Readonly<AdapterConformanceCaseV1<Input>>[];
  readonly limits: AdapterLimitsV1;
}): Promise<readonly Readonly<AdapterConformanceCaseResultV1>[]> {
  if (!Array.isArray(input.cases) || input.cases.length < 1 || input.cases.length > 100) {
    throw new AdapterValidationError("INVALID_INPUT", "Conformance kit requires 1 through 100 fixtures");
  }
  const caseIds = new Set<string>();
  const results: Readonly<AdapterConformanceCaseResultV1>[] = [];
  for (const fixture of input.cases) {
    const caseId = boundedText(fixture.caseId, "conformance caseId", 1, 128);
    if (caseIds.has(caseId)) {
      throw new AdapterValidationError("INVALID_INPUT", `Duplicate conformance case '${caseId}'`);
    }
    caseIds.add(caseId);
    const first = verifyConformedDataset(await input.adapter.ingest(fixture.input), input.limits);
    const replay = verifyConformedDataset(await input.adapter.ingest(fixture.input), input.limits);
    if (first.adapterKind !== input.adapter.adapterKind || replay.adapterKind !== input.adapter.adapterKind) {
      throw new AdapterValidationError("DECODER_CONTRACT_VIOLATION", `Adapter kind drifted in case '${caseId}'`);
    }
    if (
      first.sourceContentHash !== replay.sourceContentHash ||
      first.parserFingerprint !== replay.parserFingerprint ||
      first.schemaHash !== replay.schemaHash ||
      first.populationHash !== replay.populationHash
    ) {
      throw new AdapterValidationError("INTEGRITY_FAILURE", `Adapter output was non-deterministic in case '${caseId}'`);
    }
    if (first.rowCount !== fixture.expectedRowCount || first.columnCount !== fixture.expectedColumnCount) {
      throw new AdapterValidationError("DECODER_CONTRACT_VIOLATION", `Adapter counts differed in case '${caseId}'`);
    }
    if (
      fixture.expectedSourceContentHash !== undefined &&
      first.sourceContentHash !== fixture.expectedSourceContentHash
    ) {
      throw new AdapterValidationError("INTEGRITY_FAILURE", `Source hash differed in case '${caseId}'`);
    }
    if (fixture.expectedPopulationHash !== undefined && first.populationHash !== fixture.expectedPopulationHash) {
      throw new AdapterValidationError("INTEGRITY_FAILURE", `Population hash differed in case '${caseId}'`);
    }
    results.push(Object.freeze({
      caseId,
      sourceContentHash: first.sourceContentHash,
      schemaHash: first.schemaHash,
      populationHash: first.populationHash
    }));
  }
  return Object.freeze(results);
}

export function assertCanonicalInteger(value: string, label: string): string {
  if (!/^-?(?:0|[1-9]\d*)$/.test(value) || value === "-0") {
    throw new AdapterValidationError("UNSAFE_VALUE", `${label} is not a canonical exact integer`);
  }
  return value;
}

export function assertCanonicalDecimal(
  value: string,
  label: string,
  precision?: number,
  scale?: number
): string {
  if (!/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value) || /^-0(?:\.0+)?$/.test(value)) {
    throw new AdapterValidationError("UNSAFE_VALUE", `${label} is not a canonical exact decimal`);
  }
  const unsigned = value.startsWith("-") ? value.slice(1) : value;
  const [whole = "0", fraction = ""] = unsigned.split(".");
  const significantWhole = whole.replace(/^0+/, "");
  const actualPrecision = significantWhole.length + fraction.length || 1;
  if (precision !== undefined && actualPrecision > precision) {
    throw new AdapterValidationError(
      "UNSAFE_VALUE",
      `${label} exceeds decimal precision ${precision}`
    );
  }
  if (scale !== undefined && fraction.length !== scale) {
    throw new AdapterValidationError(
      "UNSAFE_VALUE",
      `${label} must have exactly ${scale} fractional digits`
    );
  }
  return value;
}

export function assertSafeText(value: string, label: string, maximumCharacters: number): string {
  if (value.length > maximumCharacters) {
    throw new AdapterValidationError("LIMIT_EXCEEDED", `${label} exceeds the text length limit`);
  }
  if (/[ --‪-‮⁦-⁩]/u.test(value)) {
    throw new AdapterValidationError("UNSAFE_VALUE", `${label} contains unsafe control characters`);
  }
  if (/^[\t\r\n ]*[=+\-@]/u.test(value)) {
    throw new AdapterValidationError(
      "UNSAFE_VALUE",
      `${label} begins with a spreadsheet formula-injection marker`
    );
  }
  return value;
}

export function assertCanonicalDate(value: string, label: string): string {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) throw new AdapterValidationError("UNSAFE_VALUE", `${label} must use YYYY-MM-DD`);
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    throw new AdapterValidationError("UNSAFE_VALUE", `${label} is not a real calendar date`);
  }
  return value;
}

export function assertCanonicalUtcTimestamp(value: string, label: string): string {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value)) {
    throw new AdapterValidationError(
      "UNSAFE_VALUE",
      `${label} must be an explicit UTC timestamp ending in Z`
    );
  }
  if (!Number.isFinite(Date.parse(value))) {
    throw new AdapterValidationError("UNSAFE_VALUE", `${label} is not a valid UTC timestamp`);
  }
  return value;
}

export function boundedPositiveInteger(
  value: number,
  label: string,
  maximum: number
): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new AdapterValidationError(
      "INVALID_INPUT",
      `${label} must be an integer from 1 through ${maximum}`
    );
  }
  return value;
}

function validateColumns(
  input: readonly Readonly<AdapterColumnV1>[],
  maximumColumns: number
): readonly Readonly<AdapterColumnV1>[] {
  if (!Array.isArray(input)) {
    throw new AdapterValidationError("SCHEMA_MISMATCH", "Columns must be an array");
  }
  if (input.length < 1) {
    throw new AdapterValidationError("SCHEMA_MISMATCH", "At least one column is required");
  }
  if (input.length > maximumColumns) {
    throw new AdapterValidationError("LIMIT_EXCEEDED", "Column count exceeds the configured limit");
  }
  const names = new Set<string>();
  return Object.freeze(input.map((raw, index) => {
    assertPlainDataObject(raw, `columns[${index}]`);
    assertExactKeys(
      raw,
      ["name", "logicalType", "nullable"],
      `columns[${index}]`,
      ["decimalPrecision", "decimalScale", "timezone"]
    );
    const name = boundedText(raw.name, `columns[${index}].name`, 1, 128);
    if (name.trim() !== name) {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Column '${name}' has surrounding whitespace`);
    }
    if (names.has(name)) {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Duplicate column '${name}'`);
    }
    names.add(name);
    if (!["text", "integer", "decimal", "boolean", "date", "timestamp"].includes(raw.logicalType)) {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Column '${name}' has an unsupported logical type`);
    }
    if (typeof raw.nullable !== "boolean") {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Column '${name}' must declare nullability`);
    }
    if (raw.logicalType === "decimal") {
      if (!Number.isSafeInteger(raw.decimalPrecision) || raw.decimalPrecision! < 1 || raw.decimalPrecision! > 1_000) {
        throw new AdapterValidationError("SCHEMA_MISMATCH", `Decimal column '${name}' requires a bounded precision`);
      }
      if (!Number.isSafeInteger(raw.decimalScale) || raw.decimalScale! < 0 || raw.decimalScale! > raw.decimalPrecision!) {
        throw new AdapterValidationError("SCHEMA_MISMATCH", `Decimal column '${name}' requires a valid scale`);
      }
    } else if (raw.decimalPrecision !== undefined || raw.decimalScale !== undefined) {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Non-decimal column '${name}' cannot declare precision or scale`);
    }
    if (raw.logicalType === "timestamp" && raw.timezone !== "UTC") {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Timestamp column '${name}' must declare UTC`);
    }
    if (raw.logicalType !== "timestamp" && raw.timezone !== undefined) {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Non-timestamp column '${name}' cannot declare a timezone`);
    }
    return Object.freeze({
      name,
      logicalType: raw.logicalType,
      nullable: raw.nullable,
      ...(raw.decimalPrecision !== undefined ? { decimalPrecision: raw.decimalPrecision } : {}),
      ...(raw.decimalScale !== undefined ? { decimalScale: raw.decimalScale } : {}),
      ...(raw.timezone !== undefined ? { timezone: raw.timezone } : {})
    });
  }));
}

function validateRecords(
  input: readonly Readonly<Record<string, AdapterScalarV1>>[],
  columns: readonly Readonly<AdapterColumnV1>[],
  limits: AdapterLimitsV1
): readonly Readonly<Record<string, AdapterScalarV1>>[] {
  if (!Array.isArray(input)) {
    throw new AdapterValidationError("DECODER_CONTRACT_VIOLATION", "Records must be an array");
  }
  if (input.length > limits.maximumRows) {
    throw new AdapterValidationError("LIMIT_EXCEEDED", "Row count exceeds the configured limit");
  }
  const names = columns.map((column) => column.name);
  const nameSet = new Set(names);
  return Object.freeze(input.map((record, rowIndex) => {
    assertPlainDataObject(record, `records[${rowIndex}]`);
    const keys = Object.keys(record);
    if (keys.length !== names.length || keys.some((key) => !nameSet.has(key))) {
      throw new AdapterValidationError(
        "DECODER_CONTRACT_VIOLATION",
        `Row ${rowIndex + 1} does not exactly match the governed schema`
      );
    }
    const normalized: Record<string, AdapterScalarV1> = Object.create(null) as Record<string, AdapterScalarV1>;
    for (const column of columns) {
      const value = record[column.name];
      if (value === undefined) {
        throw new AdapterValidationError(
          "DECODER_CONTRACT_VIOLATION",
          `Row ${rowIndex + 1} is missing column '${column.name}'`
        );
      }
      if (value === null) {
        if (!column.nullable) {
          throw new AdapterValidationError(
            "SCHEMA_MISMATCH",
            `Row ${rowIndex + 1} has null in required column '${column.name}'`
          );
        }
        normalized[column.name] = null;
        continue;
      }
      normalized[column.name] = validateScalar(value, column, rowIndex, limits.maximumCellCharacters);
    }
    return Object.freeze(normalized);
  }));
}

function validateScalar(
  value: AdapterScalarV1,
  column: Readonly<AdapterColumnV1>,
  rowIndex: number,
  maximumCellCharacters: number
): AdapterScalarV1 {
  const label = `row ${rowIndex + 1} column '${column.name}'`;
  if (column.logicalType === "boolean") {
    if (typeof value !== "boolean") {
      throw new AdapterValidationError("DECODER_CONTRACT_VIOLATION", `${label} must be boolean`);
    }
    return value;
  }
  if (typeof value !== "string") {
    throw new AdapterValidationError(
      "DECODER_CONTRACT_VIOLATION",
      `${label} must be an exact string representation`
    );
  }
  if (value.length > maximumCellCharacters) {
    throw new AdapterValidationError("LIMIT_EXCEEDED", `${label} exceeds the cell length limit`);
  }
  switch (column.logicalType) {
    case "text":
      return assertSafeText(value, label, maximumCellCharacters);
    case "integer":
      return assertCanonicalInteger(value, label);
    case "decimal":
      return assertCanonicalDecimal(value, label, column.decimalPrecision, column.decimalScale);
    case "date":
      return assertCanonicalDate(value, label);
    case "timestamp":
      return assertCanonicalUtcTimestamp(value, label);
  }
}

function validateParser(parser: AdapterParserIdentityV1): void {
  assertPlainDataObject(parser, "parser");
  assertExactKeys(parser, ["parserId", "parserVersion", "optionsHash"], "parser");
  boundedText(parser.parserId, "parser.parserId", 1, 128);
  boundedText(parser.parserVersion, "parser.parserVersion", 1, 64);
  assertHash(parser.optionsHash, "parser.optionsHash");
}

function validateLimits(limits: AdapterLimitsV1): void {
  boundedPositiveInteger(limits.maximumRows, "maximumRows", 10_000_000);
  boundedPositiveInteger(limits.maximumColumns, "maximumColumns", 10_000);
  boundedPositiveInteger(limits.maximumCellCharacters, "maximumCellCharacters", 1_000_000);
}

function assertHash(value: string, label: string): asserts value is Sha256Hash {
  if (!/^sha256:[a-f0-9]{64}$/.test(value)) {
    throw new AdapterValidationError("INVALID_INPUT", `${label} must be a lowercase sha256: hash`);
  }
}

function boundedText(value: string, label: string, minimum: number, maximum: number): string {
  if (typeof value !== "string" || value.length < minimum || value.length > maximum) {
    throw new AdapterValidationError("INVALID_INPUT", `${label} has an invalid length`);
  }
  if (/[ -]/u.test(value)) {
    throw new AdapterValidationError("INVALID_INPUT", `${label} contains control characters`);
  }
  return value;
}

function assertExactKeys(
  value: object,
  requiredKeys: readonly string[],
  label: string,
  optionalKeys: readonly string[] = []
): void {
  const actualKeys = Object.keys(value);
  const allowed = new Set([...requiredKeys, ...optionalKeys]);
  if (
    actualKeys.some((key) => !allowed.has(key)) ||
    requiredKeys.some((key) => !actualKeys.includes(key))
  ) {
    throw new AdapterValidationError("INVALID_INPUT", `${label} contains missing or unapproved fields`);
  }
}

function assertPlainDataObject(value: unknown, label: string): void {
  if (value === null || typeof value !== "object") {
    throw new AdapterValidationError("DECODER_CONTRACT_VIOLATION", `${label} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value) as object | null;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new AdapterValidationError("DECODER_CONTRACT_VIOLATION", `${label} must be a plain object`);
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new AdapterValidationError("DECODER_CONTRACT_VIOLATION", `${label} contains symbol keys`);
  }
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (descriptor.get !== undefined || descriptor.set !== undefined) {
      throw new AdapterValidationError("DECODER_CONTRACT_VIOLATION", `${label} cannot contain accessors`);
    }
  }
}
