import { canonicalHash } from "../contracts/canonical.js";
import {
  AdapterValidationError,
  assertCanonicalDate,
  assertCanonicalDecimal,
  assertCanonicalInteger,
  assertCanonicalUtcTimestamp,
  assertSafeText,
  boundedPositiveInteger,
  createConformedDataset,
  sha256Bytes,
  type AdapterColumnV1,
  type AdapterLimitsV1,
  type AdapterParserIdentityV1,
  type AdapterScalarV1,
  type BoundedTabularAdapter,
  type ConformedDatasetV1
} from "./conformance.js";

export const PARQUET_MEDIA_TYPE = "application/vnd.apache.parquet";

export interface ParquetSecurityLimitsV1 extends AdapterLimitsV1 {
  readonly maximumFileBytes: number;
  readonly maximumFooterBytes: number;
  readonly maximumRowGroups: number;
  readonly maximumPartitionFields: number;
}

export type ParquetPhysicalTypeV1 =
  | "BOOLEAN"
  | "INT32"
  | "INT64"
  | "BYTE_ARRAY"
  | "FIXED_LEN_BYTE_ARRAY";

export interface ParquetDecodedColumnV1 extends AdapterColumnV1 {
  readonly physicalType: ParquetPhysicalTypeV1;
  readonly repetition: "required" | "optional";
  readonly pathDepth: 1;
  readonly adjustedToUtc?: true;
}

export type ParquetDecodedValueV1 =
  | { readonly kind: "null" }
  | { readonly kind: "text"; readonly value: string }
  | { readonly kind: "integer"; readonly value: string }
  | { readonly kind: "decimal"; readonly value: string }
  | { readonly kind: "boolean"; readonly value: boolean }
  | { readonly kind: "date"; readonly value: string }
  | { readonly kind: "timestamp"; readonly value: string; readonly timezone: "UTC" };

export interface ParquetDecodedSchemaVariantV1 {
  readonly columns: readonly Readonly<ParquetDecodedColumnV1>[];
}

export interface ParquetDecodedRowGroupV1 {
  readonly ordinal: number;
  readonly rowCount: number;
  readonly schemaVariantIndex: number;
}

export interface ParquetDecodedDatasetV1 {
  readonly schemaVariants: readonly Readonly<ParquetDecodedSchemaVariantV1>[];
  readonly rowGroups: readonly Readonly<ParquetDecodedRowGroupV1>[];
  readonly declaredRowCount: number;
  readonly rows: readonly (readonly ParquetDecodedValueV1[])[];
}

export interface ParquetDecoderPortV1 {
  /**
   * The decoder is an explicit deployment dependency. It must return integer
   * and DECIMAL values as exact strings and must never merge file schemas.
   */
  decode(input: {
    readonly bytes: Uint8Array;
    readonly maximumRows: number;
    readonly maximumColumns: number;
    readonly maximumRowGroups: number;
    readonly maximumCellCharacters: number;
    readonly exactDecimalMode: "string";
    readonly timestampTimezone: "UTC";
    readonly rejectSchemaMerging: true;
  }): Promise<ParquetDecodedDatasetV1>;
}

export interface ParquetPartitionValueV1 {
  readonly name: string;
  readonly value: string;
}

export interface ParquetPartitionExpectationV1 {
  readonly name: string;
  readonly expectedValue: string;
  /** If true, an in-file column of the same name must equal the partition. */
  readonly requireMatchingColumn: boolean;
}

export interface ParquetIngestionInputV1 {
  readonly bytes: Uint8Array;
  readonly columns: readonly Readonly<AdapterColumnV1>[];
  readonly partitions: readonly Readonly<ParquetPartitionValueV1>[];
  readonly partitionExpectations: readonly Readonly<ParquetPartitionExpectationV1>[];
  readonly expectedSourceContentHash?: `sha256:${string}`;
}

export interface ParquetBinaryInspectionV1 {
  readonly byteLength: number;
  readonly footerByteLength: number;
  readonly footerOffset: number;
}

const DEFAULT_LIMITS: ParquetSecurityLimitsV1 = Object.freeze({
  maximumFileBytes: 512 * 1024 * 1024,
  maximumFooterBytes: 16 * 1024 * 1024,
  maximumRowGroups: 10_000,
  maximumPartitionFields: 32,
  maximumRows: 1_000_000,
  maximumColumns: 2_000,
  maximumCellCharacters: 1_000_000
});

export class ParquetIngestionAdapterV1 implements BoundedTabularAdapter<ParquetIngestionInputV1> {
  readonly adapterKind = "parquet" as const;
  readonly #decoder: ParquetDecoderPortV1;
  readonly #parser: AdapterParserIdentityV1;
  readonly #limits: ParquetSecurityLimitsV1;

  constructor(input: {
    readonly decoder: ParquetDecoderPortV1;
    readonly parser: AdapterParserIdentityV1;
    readonly limits?: Partial<ParquetSecurityLimitsV1>;
  }) {
    this.#decoder = input.decoder;
    this.#parser = Object.freeze({ ...input.parser });
    this.#limits = validateParquetLimits({ ...DEFAULT_LIMITS, ...input.limits });
  }

  async ingest(input: ParquetIngestionInputV1): Promise<ConformedDatasetV1> {
    if (!(input.bytes instanceof Uint8Array)) {
      throw new AdapterValidationError("INVALID_INPUT", "Parquet input must be a Uint8Array");
    }
    const sourceContentHash = sha256Bytes(input.bytes);
    if (input.expectedSourceContentHash !== undefined && sourceContentHash !== input.expectedSourceContentHash) {
      throw new AdapterValidationError("INTEGRITY_FAILURE", "Parquet content hash did not match the delivery manifest");
    }
    createConformedDataset({
      adapterKind: "parquet",
      sourceMediaType: PARQUET_MEDIA_TYPE,
      sourceContentHash,
      parser: this.#parser,
      columns: input.columns,
      records: [],
      limits: this.#limits
    });
    const partitions = validatePartitions(
      input.partitions,
      input.partitionExpectations,
      this.#limits.maximumPartitionFields,
      this.#limits.maximumCellCharacters
    );
    inspectParquetBinary(input.bytes, this.#limits);
    const decoded = await this.#decoder.decode({
      bytes: input.bytes,
      maximumRows: this.#limits.maximumRows,
      maximumColumns: this.#limits.maximumColumns,
      maximumRowGroups: this.#limits.maximumRowGroups,
      maximumCellCharacters: this.#limits.maximumCellCharacters,
      exactDecimalMode: "string",
      timestampTimezone: "UTC",
      rejectSchemaMerging: true
    });
    const records = normalizeDecodedDataset(decoded, input.columns, partitions, input.partitionExpectations, this.#limits);
    return createConformedDataset({
      adapterKind: "parquet",
      sourceMediaType: PARQUET_MEDIA_TYPE,
      sourceContentHash,
      parser: this.#parser,
      columns: input.columns,
      records,
      limits: this.#limits
    });
  }
}

export function inspectParquetBinary(
  bytes: Uint8Array,
  providedLimits: ParquetSecurityLimitsV1 = DEFAULT_LIMITS
): ParquetBinaryInspectionV1 {
  const limits = validateParquetLimits(providedLimits);
  if (bytes.byteLength < 12) {
    throw new AdapterValidationError("INVALID_INPUT", "Parquet file is truncated");
  }
  if (bytes.byteLength > limits.maximumFileBytes) {
    throw new AdapterValidationError("LIMIT_EXCEEDED", "Parquet file exceeds the configured byte limit");
  }
  const buffer = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (buffer.subarray(0, 4).toString("ascii") !== "PAR1" || buffer.subarray(-4).toString("ascii") !== "PAR1") {
    throw new AdapterValidationError("INVALID_INPUT", "Parquet magic bytes are missing");
  }
  const footerByteLength = buffer.readUInt32LE(buffer.length - 8);
  const footerOffset = buffer.length - 8 - footerByteLength;
  if (footerByteLength < 1 || footerByteLength > limits.maximumFooterBytes || footerOffset < 4) {
    throw new AdapterValidationError("LIMIT_EXCEEDED", "Parquet footer length is invalid or exceeds policy");
  }
  return Object.freeze({ byteLength: buffer.length, footerByteLength, footerOffset });
}

function normalizeDecodedDataset(
  decoded: ParquetDecodedDatasetV1,
  governedColumns: readonly Readonly<AdapterColumnV1>[],
  partitions: ReadonlyMap<string, string>,
  expectations: readonly Readonly<ParquetPartitionExpectationV1>[],
  limits: ParquetSecurityLimitsV1
): readonly Readonly<Record<string, AdapterScalarV1>>[] {
  assertPlainObject(decoded, "decoded Parquet dataset");
  if (!Array.isArray(decoded.schemaVariants) || decoded.schemaVariants.length !== 1) {
    throw new AdapterValidationError(
      "SCHEMA_MISMATCH",
      "Parquet decoding must yield exactly one schema variant; schema merging is forbidden"
    );
  }
  const variant = decoded.schemaVariants[0]!;
  assertPlainObject(variant, "decoded Parquet schema variant");
  if (!Array.isArray(variant.columns)) throw decoderViolation("Parquet schema columns must be an array");
  validateDecodedSchema(variant.columns, governedColumns, limits.maximumColumns);
  if (!Array.isArray(decoded.rowGroups) || decoded.rowGroups.length < 1) {
    throw decoderViolation("Parquet decoder returned no row groups");
  }
  if (decoded.rowGroups.length > limits.maximumRowGroups) {
    throw new AdapterValidationError("LIMIT_EXCEEDED", "Parquet row-group count exceeds policy");
  }
  let rowGroupTotal = 0;
  decoded.rowGroups.forEach((rowGroup, index) => {
    assertPlainObject(rowGroup, `Parquet row group ${index}`);
    if (rowGroup.ordinal !== index || !Number.isSafeInteger(rowGroup.rowCount) || rowGroup.rowCount < 0) {
      throw decoderViolation(`Parquet row group ${index} has invalid ordering or row count`);
    }
    if (rowGroup.schemaVariantIndex !== 0) {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Parquet row group ${index} uses a different schema`);
    }
    rowGroupTotal += rowGroup.rowCount;
    if (!Number.isSafeInteger(rowGroupTotal) || rowGroupTotal > limits.maximumRows) {
      throw new AdapterValidationError("LIMIT_EXCEEDED", "Parquet row count exceeds policy");
    }
  });
  if (
    !Number.isSafeInteger(decoded.declaredRowCount) ||
    decoded.declaredRowCount < 0 ||
    decoded.declaredRowCount !== rowGroupTotal
  ) {
    throw decoderViolation("Parquet declared row count does not reconcile to row groups");
  }
  if (!Array.isArray(decoded.rows) || decoded.rows.length !== decoded.declaredRowCount) {
    throw decoderViolation("Parquet decoded row count does not reconcile to the footer population");
  }

  const matchingPartitionColumns = new Map(
    expectations.filter((expectation) => expectation.requireMatchingColumn)
      .map((expectation) => [expectation.name, partitions.get(expectation.name)!] as const)
  );
  for (const partitionName of matchingPartitionColumns.keys()) {
    if (!governedColumns.some((column) => column.name === partitionName)) {
      throw new AdapterValidationError(
        "SCHEMA_MISMATCH",
        `Required matching partition column '${partitionName}' is absent from the Parquet schema`
      );
    }
  }
  return Object.freeze(decoded.rows.map((row, rowIndex) => {
    if (!Array.isArray(row) || row.length !== governedColumns.length) {
      throw decoderViolation(`Parquet row ${rowIndex + 1} does not match the governed column count`);
    }
    const record: Record<string, AdapterScalarV1> = Object.create(null) as Record<string, AdapterScalarV1>;
    governedColumns.forEach((column, columnIndex) => {
      const value = normalizeParquetValue(row[columnIndex]!, column, rowIndex, limits.maximumCellCharacters);
      const expectedPartition = matchingPartitionColumns.get(column.name);
      if (expectedPartition !== undefined && value !== expectedPartition) {
        throw new AdapterValidationError(
          "SCHEMA_MISMATCH",
          `Parquet row ${rowIndex + 1} does not match partition '${column.name}'`
        );
      }
      record[column.name] = value;
    });
    return Object.freeze(record);
  }));
}

function validateDecodedSchema(
  decodedColumns: readonly Readonly<ParquetDecodedColumnV1>[],
  governedColumns: readonly Readonly<AdapterColumnV1>[],
  maximumColumns: number
): void {
  if (decodedColumns.length < 1 || decodedColumns.length > maximumColumns) {
    throw new AdapterValidationError("LIMIT_EXCEEDED", "Parquet column count is outside policy");
  }
  if (decodedColumns.length !== governedColumns.length) {
    throw new AdapterValidationError("SCHEMA_MISMATCH", "Parquet schema does not match governed column count");
  }
  const names = new Set<string>();
  decodedColumns.forEach((decoded, index) => {
    assertPlainObject(decoded, `Parquet schema column ${index}`);
    const governed = governedColumns[index]!;
    if (names.has(decoded.name)) throw new AdapterValidationError("SCHEMA_MISMATCH", `Duplicate Parquet column '${decoded.name}'`);
    names.add(decoded.name);
    if (
      decoded.name !== governed.name ||
      decoded.logicalType !== governed.logicalType ||
      decoded.nullable !== governed.nullable ||
      decoded.repetition !== (governed.nullable ? "optional" : "required") ||
      decoded.pathDepth !== 1
    ) {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Parquet column '${decoded.name}' differs from the governed schema`);
    }
    if (!physicalTypeAllowed(decoded.logicalType, decoded.physicalType)) {
      throw new AdapterValidationError(
        "SCHEMA_MISMATCH",
        `Parquet column '${decoded.name}' has incompatible physical type '${decoded.physicalType}'`
      );
    }
    if (
      decoded.logicalType === "decimal" &&
      (decoded.decimalPrecision !== governed.decimalPrecision || decoded.decimalScale !== governed.decimalScale)
    ) {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Parquet DECIMAL '${decoded.name}' precision or scale drifted`);
    }
    if (
      decoded.logicalType !== "decimal" &&
      (decoded.decimalPrecision !== undefined || decoded.decimalScale !== undefined)
    ) {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Parquet column '${decoded.name}' has stray DECIMAL metadata`);
    }
    if (
      decoded.logicalType === "timestamp" &&
      (decoded.timezone !== "UTC" || decoded.adjustedToUtc !== true || governed.timezone !== "UTC")
    ) {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Parquet timestamp '${decoded.name}' must be UTC-adjusted`);
    }
    if (decoded.logicalType !== "timestamp" && decoded.adjustedToUtc !== undefined) {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Parquet column '${decoded.name}' has stray UTC metadata`);
    }
    if (decoded.logicalType !== "timestamp" && decoded.timezone !== undefined) {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Parquet column '${decoded.name}' has a stray timezone`);
    }
  });

  // A compact schema fingerprint is computed here as a deliberate validation
  // side effect; it also guarantees the decoder supplied canonical JSON data.
  canonicalHash(decodedColumns);
}

function normalizeParquetValue(
  cell: ParquetDecodedValueV1,
  column: Readonly<AdapterColumnV1>,
  rowIndex: number,
  maximumCellCharacters: number
): AdapterScalarV1 {
  assertPlainObject(cell, `Parquet row ${rowIndex + 1} column '${column.name}'`);
  const label = `Parquet row ${rowIndex + 1} column '${column.name}'`;
  if (cell.kind === "null") {
    if (!column.nullable) throw new AdapterValidationError("SCHEMA_MISMATCH", `${label} is required`);
    return null;
  }
  switch (column.logicalType) {
    case "text":
      if (cell.kind !== "text") throw decoderViolation(`${label} must decode as UTF-8 text`);
      return assertSafeText(cell.value, label, maximumCellCharacters);
    case "integer":
      if (cell.kind !== "integer") throw decoderViolation(`${label} must decode as an exact integer string`);
      return assertCanonicalInteger(cell.value, label);
    case "decimal":
      if (cell.kind !== "decimal") throw decoderViolation(`${label} must decode as an exact DECIMAL string`);
      return assertCanonicalDecimal(cell.value, label, column.decimalPrecision, column.decimalScale);
    case "boolean":
      if (cell.kind !== "boolean") throw decoderViolation(`${label} must decode as boolean`);
      return cell.value;
    case "date":
      if (cell.kind !== "date") throw decoderViolation(`${label} must decode as a canonical date`);
      return assertCanonicalDate(cell.value, label);
    case "timestamp":
      if (cell.kind !== "timestamp" || cell.timezone !== "UTC") {
        throw decoderViolation(`${label} must decode as an explicit UTC timestamp`);
      }
      return assertCanonicalUtcTimestamp(cell.value, label);
  }
}

function validatePartitions(
  supplied: readonly Readonly<ParquetPartitionValueV1>[],
  expectations: readonly Readonly<ParquetPartitionExpectationV1>[],
  maximumFields: number,
  maximumCharacters: number
): ReadonlyMap<string, string> {
  if (!Array.isArray(supplied) || !Array.isArray(expectations)) {
    throw new AdapterValidationError("INVALID_INPUT", "Parquet partition metadata must be arrays");
  }
  if (supplied.length > maximumFields || expectations.length > maximumFields) {
    throw new AdapterValidationError("LIMIT_EXCEEDED", "Parquet partition field count exceeds policy");
  }
  if (supplied.length !== expectations.length) {
    throw new AdapterValidationError("SCHEMA_MISMATCH", "Parquet partitions do not match the governed partition set");
  }
  const output = new Map<string, string>();
  for (let index = 0; index < expectations.length; index += 1) {
    const expected = expectations[index]!;
    const actual = supplied[index]!;
    assertPlainObject(expected, `partition expectation ${index}`);
    assertPlainObject(actual, `partition value ${index}`);
    if (typeof expected.requireMatchingColumn !== "boolean") {
      throw new AdapterValidationError("INVALID_INPUT", "Parquet partition matching policy must be boolean");
    }
    validatePartitionName(expected.name);
    validatePartitionName(actual.name);
    if (actual.name !== expected.name || actual.value !== expected.expectedValue) {
      throw new AdapterValidationError(
        "SCHEMA_MISMATCH",
        `Parquet partition ${index + 1} does not match the governed exact value`
      );
    }
    if (output.has(actual.name)) {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Duplicate Parquet partition '${actual.name}'`);
    }
    const value = assertSafeText(actual.value, `partition '${actual.name}'`, maximumCharacters);
    output.set(actual.name, value);
  }
  return output;
}

function physicalTypeAllowed(logicalType: AdapterColumnV1["logicalType"], physicalType: ParquetPhysicalTypeV1): boolean {
  switch (logicalType) {
    case "text":
      return physicalType === "BYTE_ARRAY";
    case "integer":
      return physicalType === "INT32" || physicalType === "INT64";
    case "decimal":
      return physicalType === "INT32" || physicalType === "INT64" ||
        physicalType === "BYTE_ARRAY" || physicalType === "FIXED_LEN_BYTE_ARRAY";
    case "boolean":
      return physicalType === "BOOLEAN";
    case "date":
      return physicalType === "INT32";
    case "timestamp":
      return physicalType === "INT64";
  }
}

function validatePartitionName(value: string): void {
  if (typeof value !== "string" || !/^[A-Za-z][A-Za-z0-9_]{0,127}$/.test(value)) {
    throw new AdapterValidationError("INVALID_INPUT", "Parquet partition name is not portable");
  }
}

function validateParquetLimits(input: ParquetSecurityLimitsV1): ParquetSecurityLimitsV1 {
  boundedPositiveInteger(input.maximumFileBytes, "maximumFileBytes", 2_000_000_000);
  boundedPositiveInteger(input.maximumFooterBytes, "maximumFooterBytes", 256_000_000);
  boundedPositiveInteger(input.maximumRowGroups, "maximumRowGroups", 1_000_000);
  boundedPositiveInteger(input.maximumPartitionFields, "maximumPartitionFields", 1_000);
  boundedPositiveInteger(input.maximumRows, "maximumRows", 10_000_000);
  boundedPositiveInteger(input.maximumColumns, "maximumColumns", 10_000);
  boundedPositiveInteger(input.maximumCellCharacters, "maximumCellCharacters", 1_000_000);
  if (input.maximumFooterBytes >= input.maximumFileBytes) {
    throw new AdapterValidationError("INVALID_INPUT", "Parquet footer limit must be below the file limit");
  }
  return Object.freeze({ ...input });
}

function assertPlainObject(value: unknown, label: string): void {
  if (value === null || typeof value !== "object") throw decoderViolation(`${label} must be a plain object`);
  const prototype = Object.getPrototypeOf(value) as object | null;
  if (prototype !== Object.prototype && prototype !== null) throw decoderViolation(`${label} must be a plain object`);
  if (Object.getOwnPropertySymbols(value).length > 0) throw decoderViolation(`${label} contains symbol keys`);
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (descriptor.get !== undefined || descriptor.set !== undefined) throw decoderViolation(`${label} contains accessors`);
  }
}

function decoderViolation(message: string): AdapterValidationError {
  return new AdapterValidationError("DECODER_CONTRACT_VIOLATION", message);
}
