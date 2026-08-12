import { inflateRawSync } from "node:zlib";

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

export const XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

export interface XlsxSecurityLimitsV1 extends AdapterLimitsV1 {
  readonly maximumWorkbookBytes: number;
  readonly maximumSheets: number;
  readonly maximumZipEntries: number;
  readonly maximumArchiveUncompressedBytes: number;
  readonly maximumEntryUncompressedBytes: number;
  readonly maximumCompressionRatio: number;
}

export type XlsxDecodedCellV1 =
  | { readonly kind: "blank" }
  | { readonly kind: "text"; readonly value: string }
  | { readonly kind: "integer"; readonly value: string }
  | { readonly kind: "decimal"; readonly value: string }
  | { readonly kind: "boolean"; readonly value: boolean }
  | { readonly kind: "date"; readonly value: string }
  | { readonly kind: "timestamp"; readonly value: string; readonly timezone: "UTC" }
  | { readonly kind: "formula"; readonly expression: string; readonly cachedValue?: unknown };

export interface XlsxDecodedWorksheetV1 {
  readonly name: string;
  readonly visibility: "visible" | "hidden" | "very_hidden";
  readonly rows: readonly (readonly XlsxDecodedCellV1[])[];
}

export interface XlsxDecodedWorkbookV1 {
  readonly dateSystem: "1900" | "1904";
  readonly worksheets: readonly XlsxDecodedWorksheetV1[];
}

export interface XlsxDecoderPortV1 {
  /**
   * Implementations must decode values without going through IEEE-754 for
   * integer or decimal cells. The adapter validates that contract again.
   */
  decode(input: {
    readonly bytes: Uint8Array;
    readonly maximumSheets: number;
    readonly maximumRows: number;
    readonly maximumColumns: number;
    readonly maximumCellCharacters: number;
  }): Promise<XlsxDecodedWorkbookV1>;
}

export interface XlsxIngestionInputV1 {
  readonly bytes: Uint8Array;
  readonly sheetName: string;
  readonly headerRow: number;
  readonly columns: readonly Readonly<AdapterColumnV1>[];
  readonly expectedSourceContentHash?: `sha256:${string}`;
}

export interface XlsxArchiveInspectionV1 {
  readonly entryCount: number;
  readonly totalUncompressedBytes: number;
  readonly archiveHasContentTypes: boolean;
  readonly archiveHasWorkbook: boolean;
}

interface ZipEntry {
  readonly name: string;
  readonly flags: number;
  readonly compressionMethod: number;
  readonly crc32: number;
  readonly compressedSize: number;
  readonly uncompressedSize: number;
  readonly localHeaderOffset: number;
}

const DEFAULT_LIMITS: XlsxSecurityLimitsV1 = Object.freeze({
  maximumWorkbookBytes: 100 * 1024 * 1024,
  maximumSheets: 32,
  maximumRows: 100_000,
  maximumColumns: 500,
  maximumCellCharacters: 32_767,
  maximumZipEntries: 10_000,
  maximumArchiveUncompressedBytes: 250 * 1024 * 1024,
  maximumEntryUncompressedBytes: 64 * 1024 * 1024,
  maximumCompressionRatio: 100
});

export class XlsxIngestionAdapterV1 implements BoundedTabularAdapter<XlsxIngestionInputV1> {
  readonly adapterKind = "xlsx" as const;
  readonly #decoder: XlsxDecoderPortV1;
  readonly #parser: AdapterParserIdentityV1;
  readonly #limits: XlsxSecurityLimitsV1;

  constructor(input: {
    readonly decoder: XlsxDecoderPortV1;
    readonly parser: AdapterParserIdentityV1;
    readonly limits?: Partial<XlsxSecurityLimitsV1>;
  }) {
    this.#decoder = input.decoder;
    this.#parser = Object.freeze({ ...input.parser });
    this.#limits = validateXlsxLimits({ ...DEFAULT_LIMITS, ...input.limits });
  }

  async ingest(input: XlsxIngestionInputV1): Promise<ConformedDatasetV1> {
    if (!(input.bytes instanceof Uint8Array)) {
      throw new AdapterValidationError("INVALID_INPUT", "XLSX input must be a Uint8Array");
    }
    const contentHash = sha256Bytes(input.bytes);
    if (input.expectedSourceContentHash !== undefined && contentHash !== input.expectedSourceContentHash) {
      throw new AdapterValidationError("INTEGRITY_FAILURE", "XLSX content hash did not match the delivery manifest");
    }
    const sheetName = validateSheetName(input.sheetName);
    boundedPositiveInteger(input.headerRow, "headerRow", 10_000);
    createConformedDataset({
      adapterKind: "xlsx",
      sourceMediaType: XLSX_MEDIA_TYPE,
      sourceContentHash: contentHash,
      parser: this.#parser,
      columns: input.columns,
      records: [],
      limits: this.#limits
    });
    inspectXlsxArchive(input.bytes, this.#limits);

    const decoded = await this.#decoder.decode({
      bytes: input.bytes,
      maximumSheets: this.#limits.maximumSheets,
      maximumRows: this.#limits.maximumRows + input.headerRow,
      maximumColumns: this.#limits.maximumColumns,
      maximumCellCharacters: this.#limits.maximumCellCharacters
    });
    const records = normalizeDecodedWorkbook(decoded, sheetName, input.headerRow, input.columns, this.#limits);
    return createConformedDataset({
      adapterKind: "xlsx",
      sourceMediaType: XLSX_MEDIA_TYPE,
      sourceContentHash: contentHash,
      parser: this.#parser,
      columns: input.columns,
      records,
      limits: this.#limits
    });
  }
}

/**
 * Performs a parser-independent OPC/ZIP security pass. Decoder plugins are
 * never invoked until the entire workbook has been checked for macros,
 * external relationships, formula cells, unsafe XML and archive bombs.
 */
export function inspectXlsxArchive(
  bytes: Uint8Array,
  providedLimits: XlsxSecurityLimitsV1 = DEFAULT_LIMITS
): XlsxArchiveInspectionV1 {
  const limits = validateXlsxLimits(providedLimits);
  if (bytes.byteLength < 22) {
    throw new AdapterValidationError("INVALID_INPUT", "XLSX archive is truncated");
  }
  if (bytes.byteLength > limits.maximumWorkbookBytes) {
    throw new AdapterValidationError("LIMIT_EXCEEDED", "XLSX archive exceeds the byte limit");
  }
  const buffer = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const { entries, centralDirectoryOffset } = readCentralDirectory(buffer, limits);
  let totalUncompressedBytes = 0;
  let archiveHasContentTypes = false;
  let archiveHasWorkbook = false;
  const localRanges: { readonly start: number; readonly end: number; readonly name: string }[] = [];

  for (const entry of entries) {
    totalUncompressedBytes += entry.uncompressedSize;
    if (totalUncompressedBytes > limits.maximumArchiveUncompressedBytes) {
      throw new AdapterValidationError("LIMIT_EXCEEDED", "XLSX expanded size exceeds the archive limit");
    }
    inspectEntryMetadata(entry, limits);
    localRanges.push(validateZipEntryEnvelope(buffer, entry, centralDirectoryOffset));
    const lowerName = entry.name.toLowerCase();
    if (lowerName === "[content_types].xml") archiveHasContentTypes = true;
    if (lowerName === "xl/workbook.xml") archiveHasWorkbook = true;
    if (isForbiddenOpaqueXlsxPart(lowerName)) {
      throw new AdapterValidationError(
        "UNSUPPORTED_FEATURE",
        `XLSX archive contains forbidden active or linked content: ${entry.name}`
      );
    }
    if (mustInspectXml(lowerName)) {
      const xml = readZipEntry(buffer, entry, centralDirectoryOffset, limits);
      inspectXmlPart(entry.name, xml, lowerName);
    }
  }
  localRanges.sort((left, right) => left.start - right.start);
  for (let index = 1; index < localRanges.length; index += 1) {
    const previous = localRanges[index - 1]!;
    const current = localRanges[index]!;
    if (current.start < previous.end) {
      throw new AdapterValidationError(
        "INVALID_INPUT",
        `XLSX ZIP entries '${previous.name}' and '${current.name}' overlap`
      );
    }
  }
  if (!archiveHasContentTypes || !archiveHasWorkbook) {
    throw new AdapterValidationError(
      "INVALID_INPUT",
      "XLSX archive is missing required OPC workbook parts"
    );
  }
  return Object.freeze({
    entryCount: entries.length,
    totalUncompressedBytes,
    archiveHasContentTypes,
    archiveHasWorkbook
  });
}

function normalizeDecodedWorkbook(
  workbook: XlsxDecodedWorkbookV1,
  sheetName: string,
  headerRow: number,
  columns: readonly Readonly<AdapterColumnV1>[],
  limits: XlsxSecurityLimitsV1
): readonly Readonly<Record<string, AdapterScalarV1>>[] {
  assertPlainObject(workbook, "decoded workbook");
  if (workbook.dateSystem !== "1900" && workbook.dateSystem !== "1904") {
    throw decoderViolation("Decoder returned an unsupported workbook date system");
  }
  if (!Array.isArray(workbook.worksheets) || workbook.worksheets.length < 1) {
    throw decoderViolation("Decoder returned no worksheets");
  }
  if (workbook.worksheets.length > limits.maximumSheets) {
    throw new AdapterValidationError("LIMIT_EXCEEDED", "Worksheet count exceeds the configured limit");
  }
  const names = new Set<string>();
  let selected: XlsxDecodedWorksheetV1 | undefined;
  for (const [index, worksheet] of workbook.worksheets.entries()) {
    assertPlainObject(worksheet, `decoded worksheet ${index + 1}`);
    const name = validateSheetName(worksheet.name);
    if (names.has(name)) throw decoderViolation(`Decoder returned duplicate worksheet '${name}'`);
    names.add(name);
    if (!["visible", "hidden", "very_hidden"].includes(worksheet.visibility)) {
      throw decoderViolation(`Worksheet '${name}' has an invalid visibility`);
    }
    if (!Array.isArray(worksheet.rows)) throw decoderViolation(`Worksheet '${name}' has invalid rows`);
    if (name === sheetName) selected = worksheet;
  }
  if (selected === undefined) {
    throw new AdapterValidationError("SCHEMA_MISMATCH", `Required worksheet '${sheetName}' was not found`);
  }
  if (selected.visibility !== "visible") {
    throw new AdapterValidationError("UNSUPPORTED_FEATURE", "Hidden worksheets cannot be ingestion sources");
  }
  if (selected.rows.length < headerRow) {
    throw new AdapterValidationError("SCHEMA_MISMATCH", "Configured XLSX header row is missing");
  }
  if (selected.rows.length > limits.maximumRows + headerRow) {
    throw new AdapterValidationError("LIMIT_EXCEEDED", "Worksheet row count exceeds the configured limit");
  }
  const header = selected.rows[headerRow - 1]!;
  validateHeader(header, columns, limits);

  const candidateRows = selected.rows.slice(headerRow);
  let lastDataRow = candidateRows.length - 1;
  while (lastDataRow >= 0 && rowIsBlank(candidateRows[lastDataRow]!)) lastDataRow -= 1;
  const records: Readonly<Record<string, AdapterScalarV1>>[] = [];
  for (let rowOffset = 0; rowOffset <= lastDataRow; rowOffset += 1) {
    const row = candidateRows[rowOffset]!;
    if (rowIsBlank(row)) {
      throw new AdapterValidationError(
        "SCHEMA_MISMATCH",
        `Blank row ${headerRow + rowOffset + 1} would make the population ambiguous`
      );
    }
    if (row.length > limits.maximumColumns || row.length > columns.length) {
      throw new AdapterValidationError("LIMIT_EXCEEDED", `Row ${headerRow + rowOffset + 1} has too many cells`);
    }
    const record: Record<string, AdapterScalarV1> = Object.create(null) as Record<string, AdapterScalarV1>;
    for (let columnIndex = 0; columnIndex < columns.length; columnIndex += 1) {
      const column = columns[columnIndex]!;
      const cell = row[columnIndex] ?? { kind: "blank" as const };
      record[column.name] = normalizeCell(cell, column, headerRow + rowOffset + 1, limits);
    }
    records.push(Object.freeze(record));
  }
  return Object.freeze(records);
}

function validateHeader(
  row: readonly XlsxDecodedCellV1[],
  columns: readonly Readonly<AdapterColumnV1>[],
  limits: XlsxSecurityLimitsV1
): void {
  if (!Array.isArray(row) || row.length !== columns.length || row.length > limits.maximumColumns) {
    throw new AdapterValidationError("SCHEMA_MISMATCH", "XLSX header must exactly match the governed column count");
  }
  const seen = new Set<string>();
  row.forEach((cell, index) => {
    assertPlainObject(cell, `header cell ${index + 1}`);
    if (cell.kind !== "text") {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Header cell ${index + 1} must be text`);
    }
    const value = assertSafeText(cell.value, `header cell ${index + 1}`, 128);
    if (value.trim() !== value || value.length === 0) {
      throw new AdapterValidationError("SCHEMA_MISMATCH", `Header cell ${index + 1} is not canonical`);
    }
    if (seen.has(value)) throw new AdapterValidationError("SCHEMA_MISMATCH", `Duplicate XLSX header '${value}'`);
    seen.add(value);
    if (value !== columns[index]!.name) {
      throw new AdapterValidationError(
        "SCHEMA_MISMATCH",
        `XLSX header '${value}' does not match governed column '${columns[index]!.name}'`
      );
    }
  });
}

function normalizeCell(
  cell: XlsxDecodedCellV1,
  column: Readonly<AdapterColumnV1>,
  rowNumber: number,
  limits: XlsxSecurityLimitsV1
): AdapterScalarV1 {
  assertPlainObject(cell, `cell ${rowNumber}:${column.name}`);
  const label = `cell ${rowNumber}:${column.name}`;
  if (cell.kind === "formula") {
    throw new AdapterValidationError("UNSUPPORTED_FEATURE", `${label} contains a formula`);
  }
  if (cell.kind === "blank") {
    if (!column.nullable) throw new AdapterValidationError("SCHEMA_MISMATCH", `${label} is required`);
    return null;
  }
  switch (column.logicalType) {
    case "text":
      if (cell.kind !== "text") throw decoderViolation(`${label} must decode as text`);
      return assertSafeText(cell.value, label, limits.maximumCellCharacters);
    case "integer":
      if (cell.kind !== "integer") throw decoderViolation(`${label} must decode as an exact integer string`);
      return assertCanonicalInteger(cell.value, label);
    case "decimal":
      if (cell.kind !== "decimal" && cell.kind !== "integer") {
        throw decoderViolation(`${label} must decode as an exact decimal string`);
      }
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

function readCentralDirectory(
  buffer: Buffer,
  limits: XlsxSecurityLimitsV1
): { readonly entries: readonly ZipEntry[]; readonly centralDirectoryOffset: number } {
  const minimumOffset = Math.max(0, buffer.length - 65_557);
  let eocdOffset = -1;
  for (let offset = buffer.length - 22; offset >= minimumOffset; offset -= 1) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) {
      const commentLength = buffer.readUInt16LE(offset + 20);
      if (offset + 22 + commentLength === buffer.length) {
        eocdOffset = offset;
        break;
      }
    }
  }
  if (eocdOffset < 0) throw new AdapterValidationError("INVALID_INPUT", "XLSX ZIP directory was not found");
  const disk = buffer.readUInt16LE(eocdOffset + 4);
  const centralDisk = buffer.readUInt16LE(eocdOffset + 6);
  const diskEntries = buffer.readUInt16LE(eocdOffset + 8);
  const totalEntries = buffer.readUInt16LE(eocdOffset + 10);
  const centralSize = buffer.readUInt32LE(eocdOffset + 12);
  const centralOffset = buffer.readUInt32LE(eocdOffset + 16);
  if (disk !== 0 || centralDisk !== 0 || diskEntries !== totalEntries) {
    throw new AdapterValidationError("UNSUPPORTED_FEATURE", "Multi-disk XLSX archives are not supported");
  }
  if (totalEntries === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) {
    throw new AdapterValidationError("UNSUPPORTED_FEATURE", "ZIP64 XLSX archives are rejected by policy");
  }
  if (totalEntries < 1 || totalEntries > limits.maximumZipEntries) {
    throw new AdapterValidationError("LIMIT_EXCEEDED", "XLSX ZIP entry count is outside the configured limit");
  }
  if (centralOffset + centralSize !== eocdOffset || centralOffset > buffer.length) {
    throw new AdapterValidationError("INVALID_INPUT", "XLSX ZIP directory offsets are inconsistent");
  }
  const entries: ZipEntry[] = [];
  const names = new Set<string>();
  let offset = centralOffset;
  for (let index = 0; index < totalEntries; index += 1) {
    if (offset + 46 > eocdOffset || buffer.readUInt32LE(offset) !== 0x02014b50) {
      throw new AdapterValidationError("INVALID_INPUT", "XLSX ZIP central directory is malformed");
    }
    const flags = buffer.readUInt16LE(offset + 8);
    const compressionMethod = buffer.readUInt16LE(offset + 10);
    const crc32Value = buffer.readUInt32LE(offset + 16);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const diskStart = buffer.readUInt16LE(offset + 34);
    const localHeaderOffset = buffer.readUInt32LE(offset + 42);
    const recordEnd = offset + 46 + nameLength + extraLength + commentLength;
    if (recordEnd > eocdOffset || nameLength < 1) {
      throw new AdapterValidationError("INVALID_INPUT", "XLSX ZIP entry metadata is truncated");
    }
    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localHeaderOffset === 0xffffffff) {
      throw new AdapterValidationError("UNSUPPORTED_FEATURE", "ZIP64 XLSX entries are rejected by policy");
    }
    if (diskStart !== 0) throw new AdapterValidationError("UNSUPPORTED_FEATURE", "Split ZIP entries are rejected");
    const name = decodeZipName(buffer.subarray(offset + 46, offset + 46 + nameLength), flags);
    validateZipEntryName(name);
    if (names.has(name)) throw new AdapterValidationError("INVALID_INPUT", `Duplicate XLSX ZIP entry '${name}'`);
    names.add(name);
    entries.push(Object.freeze({
      name,
      flags,
      compressionMethod,
      crc32: crc32Value,
      compressedSize,
      uncompressedSize,
      localHeaderOffset
    }));
    offset = recordEnd;
  }
  if (offset !== eocdOffset) {
    throw new AdapterValidationError("INVALID_INPUT", "XLSX ZIP central directory has trailing records");
  }
  return { entries: Object.freeze(entries), centralDirectoryOffset: centralOffset };
}

function readZipEntry(
  archive: Buffer,
  entry: ZipEntry,
  centralDirectoryOffset: number,
  limits: XlsxSecurityLimitsV1
): Buffer {
  const offset = entry.localHeaderOffset;
  if (offset + 30 > centralDirectoryOffset || archive.readUInt32LE(offset) !== 0x04034b50) {
    throw new AdapterValidationError("INVALID_INPUT", `XLSX ZIP local header is invalid for '${entry.name}'`);
  }
  const flags = archive.readUInt16LE(offset + 6);
  const method = archive.readUInt16LE(offset + 8);
  const nameLength = archive.readUInt16LE(offset + 26);
  const extraLength = archive.readUInt16LE(offset + 28);
  const dataOffset = offset + 30 + nameLength + extraLength;
  const dataEnd = dataOffset + entry.compressedSize;
  if (flags !== entry.flags || method !== entry.compressionMethod || dataEnd > centralDirectoryOffset) {
    throw new AdapterValidationError("INVALID_INPUT", `XLSX ZIP headers disagree for '${entry.name}'`);
  }
  const localName = decodeZipName(archive.subarray(offset + 30, offset + 30 + nameLength), flags);
  if (localName !== entry.name) {
    throw new AdapterValidationError("INVALID_INPUT", `XLSX ZIP entry name mismatch for '${entry.name}'`);
  }
  const compressed = archive.subarray(dataOffset, dataEnd);
  let output: Buffer;
  if (entry.compressionMethod === 0) {
    output = Buffer.from(compressed);
  } else if (entry.compressionMethod === 8) {
    try {
      output = inflateRawSync(compressed, { maxOutputLength: limits.maximumEntryUncompressedBytes });
    } catch {
      throw new AdapterValidationError("INVALID_INPUT", `XLSX ZIP entry '${entry.name}' could not be inflated safely`);
    }
  } else {
    throw new AdapterValidationError("UNSUPPORTED_FEATURE", `Unsupported ZIP compression for '${entry.name}'`);
  }
  if (output.length !== entry.uncompressedSize || crc32(output) !== entry.crc32) {
    throw new AdapterValidationError("INTEGRITY_FAILURE", `XLSX ZIP entry '${entry.name}' failed integrity validation`);
  }
  return output;
}

function validateZipEntryEnvelope(
  archive: Buffer,
  entry: ZipEntry,
  centralDirectoryOffset: number
): { readonly start: number; readonly end: number; readonly name: string } {
  const offset = entry.localHeaderOffset;
  if (offset + 30 > centralDirectoryOffset || archive.readUInt32LE(offset) !== 0x04034b50) {
    throw new AdapterValidationError("INVALID_INPUT", `XLSX ZIP local header is invalid for '${entry.name}'`);
  }
  const flags = archive.readUInt16LE(offset + 6);
  const method = archive.readUInt16LE(offset + 8);
  const localCrc = archive.readUInt32LE(offset + 14);
  const localCompressedSize = archive.readUInt32LE(offset + 18);
  const localUncompressedSize = archive.readUInt32LE(offset + 22);
  const nameLength = archive.readUInt16LE(offset + 26);
  const extraLength = archive.readUInt16LE(offset + 28);
  const nameEnd = offset + 30 + nameLength;
  const dataOffset = nameEnd + extraLength;
  const dataEnd = dataOffset + entry.compressedSize;
  if (nameEnd > centralDirectoryOffset || dataEnd > centralDirectoryOffset) {
    throw new AdapterValidationError("INVALID_INPUT", `XLSX ZIP local entry '${entry.name}' is truncated`);
  }
  const localName = decodeZipName(archive.subarray(offset + 30, nameEnd), flags);
  if (localName !== entry.name || flags !== entry.flags || method !== entry.compressionMethod) {
    throw new AdapterValidationError("INVALID_INPUT", `XLSX ZIP headers disagree for '${entry.name}'`);
  }
  let rangeEnd = dataEnd;
  if ((flags & 0x8) === 0) {
    if (
      localCrc !== entry.crc32 ||
      localCompressedSize !== entry.compressedSize ||
      localUncompressedSize !== entry.uncompressedSize
    ) {
      throw new AdapterValidationError("INTEGRITY_FAILURE", `XLSX ZIP local sizes disagree for '${entry.name}'`);
    }
  } else {
    const hasSignature = dataEnd + 4 <= centralDirectoryOffset && archive.readUInt32LE(dataEnd) === 0x08074b50;
    const descriptorOffset = dataEnd + (hasSignature ? 4 : 0);
    rangeEnd = descriptorOffset + 12;
    if (rangeEnd > centralDirectoryOffset) {
      throw new AdapterValidationError("INVALID_INPUT", `XLSX ZIP descriptor is truncated for '${entry.name}'`);
    }
    if (
      archive.readUInt32LE(descriptorOffset) !== entry.crc32 ||
      archive.readUInt32LE(descriptorOffset + 4) !== entry.compressedSize ||
      archive.readUInt32LE(descriptorOffset + 8) !== entry.uncompressedSize
    ) {
      throw new AdapterValidationError("INTEGRITY_FAILURE", `XLSX ZIP descriptor disagrees for '${entry.name}'`);
    }
  }
  return Object.freeze({ start: offset, end: rangeEnd, name: entry.name });
}

function inspectEntryMetadata(entry: ZipEntry, limits: XlsxSecurityLimitsV1): void {
  if ((entry.flags & 0x1) !== 0 || (entry.flags & 0x40) !== 0) {
    throw new AdapterValidationError("UNSUPPORTED_FEATURE", "Encrypted XLSX ZIP entries are rejected");
  }
  if (entry.compressionMethod !== 0 && entry.compressionMethod !== 8) {
    throw new AdapterValidationError("UNSUPPORTED_FEATURE", `Unsupported ZIP compression for '${entry.name}'`);
  }
  if (entry.uncompressedSize > limits.maximumEntryUncompressedBytes) {
    throw new AdapterValidationError("LIMIT_EXCEEDED", `XLSX ZIP entry '${entry.name}' is too large`);
  }
  if (
    entry.uncompressedSize > 0 &&
    (entry.compressedSize === 0 || entry.uncompressedSize / entry.compressedSize > limits.maximumCompressionRatio)
  ) {
    throw new AdapterValidationError("LIMIT_EXCEEDED", `XLSX ZIP entry '${entry.name}' exceeds the compression ratio limit`);
  }
}

function inspectXmlPart(name: string, bytes: Buffer, lowerName: string): void {
  let xml: string;
  try {
    xml = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new AdapterValidationError("INVALID_INPUT", `XLSX XML part '${name}' is not valid UTF-8`);
  }
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) {
    throw new AdapterValidationError("UNSUPPORTED_FEATURE", `XLSX XML part '${name}' contains a DTD or entity`);
  }
  if (lowerName === "[content_types].xml" && /macroEnabled|vbaProject|macroSheet|intlMacroSheet/i.test(xml)) {
    throw new AdapterValidationError("UNSUPPORTED_FEATURE", "Macro-enabled XLSX content types are rejected");
  }
  if (lowerName.endsWith(".rels") && /TargetMode\s*=\s*["']External["']/i.test(xml)) {
    throw new AdapterValidationError("UNSUPPORTED_FEATURE", `External XLSX relationship found in '${name}'`);
  }
  if (
    lowerName.startsWith("xl/worksheets/") &&
    /<(?:[A-Za-z_][\w.-]*:)?f(?:\s|\/|>)/i.test(xml)
  ) {
    throw new AdapterValidationError("UNSUPPORTED_FEATURE", `Formula cell found in '${name}'`);
  }
}

function mustInspectXml(name: string): boolean {
  return name === "[content_types].xml" ||
    name.endsWith(".rels") ||
    name.startsWith("xl/worksheets/");
}

function isForbiddenOpaqueXlsxPart(name: string): boolean {
  return name === "xl/vbaproject.bin" ||
    name.startsWith("xl/externallinks/") ||
    name.startsWith("xl/macrosheets/") ||
    name.startsWith("xl/dialogsheets/") ||
    name.startsWith("xl/querytables/") ||
    name.startsWith("xl/embeddings/") ||
    name.startsWith("xl/oleobjects/") ||
    name === "xl/connections.xml";
}

function decodeZipName(bytes: Buffer, flags: number): string {
  if ((flags & 0x800) === 0 && bytes.some((byte) => byte > 0x7f)) {
    throw new AdapterValidationError("UNSUPPORTED_FEATURE", "Non-UTF-8 XLSX ZIP names are rejected");
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new AdapterValidationError("INVALID_INPUT", "XLSX ZIP entry name is not valid UTF-8");
  }
}

function validateZipEntryName(name: string): void {
  if (
    name.length > 512 ||
    name.includes("\\") ||
    name.startsWith("/") ||
    name.includes("\u0000") ||
    name.split("/").some((segment) => segment === ".." || segment === "." || segment.length === 0)
  ) {
    throw new AdapterValidationError("INVALID_INPUT", `Unsafe XLSX ZIP entry name '${name}'`);
  }
}

function validateXlsxLimits(input: XlsxSecurityLimitsV1): XlsxSecurityLimitsV1 {
  boundedPositiveInteger(input.maximumWorkbookBytes, "maximumWorkbookBytes", 1_000_000_000);
  boundedPositiveInteger(input.maximumSheets, "maximumSheets", 1_000);
  boundedPositiveInteger(input.maximumRows, "maximumRows", 10_000_000);
  boundedPositiveInteger(input.maximumColumns, "maximumColumns", 10_000);
  boundedPositiveInteger(input.maximumCellCharacters, "maximumCellCharacters", 1_000_000);
  boundedPositiveInteger(input.maximumZipEntries, "maximumZipEntries", 100_000);
  boundedPositiveInteger(input.maximumArchiveUncompressedBytes, "maximumArchiveUncompressedBytes", 2_000_000_000);
  boundedPositiveInteger(input.maximumEntryUncompressedBytes, "maximumEntryUncompressedBytes", 1_000_000_000);
  boundedPositiveInteger(input.maximumCompressionRatio, "maximumCompressionRatio", 10_000);
  if (input.maximumEntryUncompressedBytes > input.maximumArchiveUncompressedBytes) {
    throw new AdapterValidationError("INVALID_INPUT", "Per-entry XLSX limit cannot exceed the archive limit");
  }
  return Object.freeze({ ...input });
}

function validateSheetName(value: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 31 ||
    value.trim() !== value ||
    /[\\/*?:\[\]\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new AdapterValidationError("INVALID_INPUT", "Worksheet name is not canonical");
  }
  return value;
}

function rowIsBlank(row: readonly XlsxDecodedCellV1[]): boolean {
  if (!Array.isArray(row)) throw decoderViolation("Decoder returned a non-array row");
  return row.every((cell, index) => {
    assertPlainObject(cell, `decoded cell ${index + 1}`);
    if (cell.kind === "formula") {
      throw new AdapterValidationError("UNSUPPORTED_FEATURE", "Decoder returned a formula cell");
    }
    return cell.kind === "blank";
  });
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

const CRC32_TABLE = Uint32Array.from({ length: 256 }, (_, index) => {
  let entry = index;
  for (let bit = 0; bit < 8; bit += 1) {
    entry = (entry >>> 1) ^ ((entry & 1) === 1 ? 0xedb88320 : 0);
  }
  return entry >>> 0;
});

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ byte) & 0xff]!;
  }
  return (crc ^ 0xffffffff) >>> 0;
}
