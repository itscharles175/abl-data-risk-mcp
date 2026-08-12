import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { extname, resolve } from "node:path";
import { TextDecoder } from "node:util";

export type LoanTapeFileFormat = "csv" | "json" | "ndjson";
export type LoanTapeCell = string | boolean | number | null;
export type LoanTapeRecord = Readonly<Record<string, LoanTapeCell>>;

export interface LoadLoanTapeFileOptions {
  readonly format?: LoanTapeFileFormat;
  readonly maximumBytes?: number;
  readonly maximumRecords?: number;
  readonly maximumColumns?: number;
  readonly maximumCellCharacters?: number;
}

export interface LoadedLoanTapeFile {
  readonly path: string;
  readonly format: LoanTapeFileFormat;
  readonly mediaType: "text/csv" | "application/json" | "application/x-ndjson";
  readonly byteLength: number;
  readonly sourceHash: string;
  readonly columns: readonly string[];
  readonly records: readonly LoanTapeRecord[];
}

export type LoanTapeFileErrorCode =
  | "INVALID_INPUT"
  | "UNSUPPORTED_FORMAT"
  | "FILE_NOT_REGULAR"
  | "FILE_TOO_LARGE"
  | "INVALID_UTF8"
  | "INVALID_DOCUMENT"
  | "LIMIT_EXCEEDED";

export class LoanTapeFileError extends Error {
  constructor(readonly code: LoanTapeFileErrorCode, message: string) {
    super(message);
    this.name = "LoanTapeFileError";
  }
}

const DEFAULT_MAXIMUM_BYTES = 10_000_000;
const DEFAULT_MAXIMUM_RECORDS = 100_000;
const DEFAULT_MAXIMUM_COLUMNS = 500;
const DEFAULT_MAXIMUM_CELL_CHARACTERS = 100_000;
const IDENTIFIER_CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;
const VALUE_DISALLOWED_CHARACTERS = /[\u0000\u007f]/;

/**
 * Trusted operator-side loader for bounded CSV, JSON, and NDJSON loan tapes.
 * It never accepts a path through MCP and preserves exact decimal text.
 */
export function loadLoanTapeFile(pathInput: string, options: LoadLoanTapeFileOptions = {}): LoadedLoanTapeFile {
  const path = validatedPath(pathInput);
  const format = options.format ?? inferFormat(path);
  const limits = {
    maximumBytes: boundedInteger(options.maximumBytes ?? DEFAULT_MAXIMUM_BYTES, "maximumBytes", 1_024, 100_000_000),
    maximumRecords: boundedInteger(options.maximumRecords ?? DEFAULT_MAXIMUM_RECORDS, "maximumRecords", 1, 1_000_000),
    maximumColumns: boundedInteger(options.maximumColumns ?? DEFAULT_MAXIMUM_COLUMNS, "maximumColumns", 1, 2_000),
    maximumCellCharacters: boundedInteger(
      options.maximumCellCharacters ?? DEFAULT_MAXIMUM_CELL_CHARACTERS,
      "maximumCellCharacters",
      1,
      1_000_000
    )
  };
  const bytes = readBoundedRegularFile(path, limits.maximumBytes);
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new LoanTapeFileError("INVALID_UTF8", "Loan tape must be valid UTF-8");
  }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);

  const records =
    format === "csv"
      ? parseCsv(text, limits)
      : format === "json"
        ? parseJsonDocument(text, limits)
        : parseNdjsonDocument(text, limits);
  const columns = collectAndValidateColumns(records, limits.maximumColumns);
  return Object.freeze({
    path,
    format,
    mediaType:
      format === "csv" ? "text/csv" : format === "json" ? "application/json" : "application/x-ndjson",
    byteLength: bytes.byteLength,
    sourceHash: createHash("sha256").update(bytes).digest("hex"),
    columns,
    records
  });
}

interface ParsingLimits {
  readonly maximumRecords: number;
  readonly maximumColumns: number;
  readonly maximumCellCharacters: number;
}

function readBoundedRegularFile(path: string, maximumBytes: number): Buffer {
  let descriptor: number | undefined;
  try {
    const noFollow = process.platform === "win32" ? 0 : constants.O_NOFOLLOW;
    descriptor = openSync(path, constants.O_RDONLY | noFollow);
    const stats = fstatSync(descriptor);
    if (!stats.isFile()) throw new LoanTapeFileError("FILE_NOT_REGULAR", "Loan tape path must name a regular file");
    if (stats.size > maximumBytes) throw new LoanTapeFileError("FILE_TOO_LARGE", "Loan tape exceeds the byte limit");
    const bytes = readFileSync(descriptor);
    if (bytes.byteLength > maximumBytes) throw new LoanTapeFileError("FILE_TOO_LARGE", "Loan tape exceeds the byte limit");
    return bytes;
  } catch (error) {
    if (error instanceof LoanTapeFileError) throw error;
    throw new LoanTapeFileError("INVALID_INPUT", "Loan tape file could not be opened safely");
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function parseCsv(text: string, limits: ParsingLimits): readonly LoanTapeRecord[] {
  if (!text) throw new LoanTapeFileError("INVALID_DOCUMENT", "CSV loan tape is empty");
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let cellCharacters = 0;
  let inQuotes = false;
  let afterQuote = false;

  const append = (value: string): void => {
    cellCharacters += value.length;
    if (cellCharacters > limits.maximumCellCharacters) {
      throw new LoanTapeFileError("LIMIT_EXCEEDED", "CSV cell exceeds the character limit");
    }
    cell += value;
  };
  const finishCell = (): void => {
    row.push(cell);
    if (row.length > limits.maximumColumns) {
      throw new LoanTapeFileError("LIMIT_EXCEEDED", "CSV exceeds the column limit");
    }
    cell = "";
    cellCharacters = 0;
    afterQuote = false;
  };
  const finishRow = (): void => {
    finishCell();
    rows.push(row);
    if (rows.length > limits.maximumRecords + 1) {
      throw new LoanTapeFileError("LIMIT_EXCEEDED", "CSV exceeds the record limit");
    }
    row = [];
  };

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index]!;
    if (inQuotes) {
      if (character === '"') {
        if (text[index + 1] === '"') {
          append('"');
          index += 1;
        } else {
          inQuotes = false;
          afterQuote = true;
        }
      } else {
        append(character);
      }
      continue;
    }
    if (afterQuote) {
      if (character === ",") finishCell();
      else if (character === "\n") finishRow();
      else if (character === "\r") {
        if (text[index + 1] === "\n") index += 1;
        finishRow();
      } else {
        throw new LoanTapeFileError("INVALID_DOCUMENT", "CSV contains characters after a closing quote");
      }
      continue;
    }
    if (character === '"') {
      if (cell.length !== 0) throw new LoanTapeFileError("INVALID_DOCUMENT", "CSV quote must begin a field");
      inQuotes = true;
    } else if (character === ",") finishCell();
    else if (character === "\n") finishRow();
    else if (character === "\r") {
      if (text[index + 1] === "\n") index += 1;
      finishRow();
    } else append(character);
  }
  if (inQuotes) throw new LoanTapeFileError("INVALID_DOCUMENT", "CSV has an unterminated quoted field");
  if (afterQuote || cell.length > 0 || row.length > 0) finishRow();
  if (rows.length < 2) throw new LoanTapeFileError("INVALID_DOCUMENT", "CSV must contain a header and at least one record");

  const header = validateHeader(rows[0]!, limits.maximumColumns);
  const records = rows.slice(1).map((values, rowIndex) => {
    if (values.length !== header.length) {
      throw new LoanTapeFileError("INVALID_DOCUMENT", `CSV row ${rowIndex + 2} does not match the header width`);
    }
    return Object.freeze(Object.fromEntries(header.map((column, index) => [column, validatedCell(values[index]!, limits)])));
  });
  return Object.freeze(records);
}

function parseJsonDocument(text: string, limits: ParsingLimits): readonly LoanTapeRecord[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new LoanTapeFileError("INVALID_DOCUMENT", "JSON loan tape is malformed");
  }
  if (!Array.isArray(parsed)) throw new LoanTapeFileError("INVALID_DOCUMENT", "JSON loan tape must be an array of records");
  return validateJsonRecords(parsed, limits);
}

function parseNdjsonDocument(text: string, limits: ParsingLimits): readonly LoanTapeRecord[] {
  const records: unknown[] = [];
  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    if (!rawLine.trim()) continue;
    if (records.length >= limits.maximumRecords) {
      throw new LoanTapeFileError("LIMIT_EXCEEDED", "NDJSON exceeds the record limit");
    }
    try {
      records.push(JSON.parse(rawLine));
    } catch {
      throw new LoanTapeFileError("INVALID_DOCUMENT", `NDJSON line ${index + 1} is malformed`);
    }
  }
  return validateJsonRecords(records, limits);
}

function validateJsonRecords(values: readonly unknown[], limits: ParsingLimits): readonly LoanTapeRecord[] {
  if (values.length === 0) throw new LoanTapeFileError("INVALID_DOCUMENT", "Loan tape contains no records");
  if (values.length > limits.maximumRecords) throw new LoanTapeFileError("LIMIT_EXCEEDED", "Loan tape exceeds the record limit");
  return Object.freeze(
    values.map((value, index) => {
      if (!isPlainRecord(value)) {
        throw new LoanTapeFileError("INVALID_DOCUMENT", `Loan tape record ${index + 1} must be a JSON object`);
      }
      const entries = Object.entries(value);
      if (entries.length > limits.maximumColumns) {
        throw new LoanTapeFileError("LIMIT_EXCEEDED", "Loan tape exceeds the column limit");
      }
      return Object.freeze(
        Object.fromEntries(
          entries.map(([column, cell]) => [validateColumn(column), validatedJsonCell(cell, limits.maximumCellCharacters)])
        )
      );
    })
  );
}

function collectAndValidateColumns(records: readonly LoanTapeRecord[], maximumColumns: number): readonly string[] {
  const columns = new Set<string>();
  for (const record of records) {
    for (const column of Object.keys(record)) {
      columns.add(validateColumn(column));
      if (columns.size > maximumColumns) throw new LoanTapeFileError("LIMIT_EXCEEDED", "Loan tape exceeds the column limit");
    }
  }
  if (columns.size === 0) throw new LoanTapeFileError("INVALID_DOCUMENT", "Loan tape has no columns");
  return Object.freeze([...columns].sort((left, right) => left.localeCompare(right)));
}

function validateHeader(values: readonly string[], maximumColumns: number): readonly string[] {
  if (values.length === 0 || values.length > maximumColumns) {
    throw new LoanTapeFileError("LIMIT_EXCEEDED", "CSV header exceeds the column limit");
  }
  const seen = new Set<string>();
  return Object.freeze(
    values.map((value) => {
      const column = validateColumn(value.trim());
      if (seen.has(column)) throw new LoanTapeFileError("INVALID_DOCUMENT", "CSV header contains duplicate columns");
      seen.add(column);
      return column;
    })
  );
}

function validateColumn(value: string): string {
  if (!value || value.length > 128 || IDENTIFIER_CONTROL_CHARACTERS.test(value)) {
    throw new LoanTapeFileError("INVALID_DOCUMENT", "Loan tape column names must be bounded printable strings");
  }
  return value;
}

function validatedCell(value: string, limits: ParsingLimits): string {
  if (value.length > limits.maximumCellCharacters) throw new LoanTapeFileError("LIMIT_EXCEEDED", "Cell exceeds the character limit");
  if (VALUE_DISALLOWED_CHARACTERS.test(value)) throw new LoanTapeFileError("INVALID_DOCUMENT", "Cell contains a disallowed control character");
  return value;
}

function validatedJsonCell(value: unknown, maximumCellCharacters: number): LoanTapeCell {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    return validatedCell(value, { maximumCellCharacters, maximumColumns: 1, maximumRecords: 1 });
  }
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "number") {
    throw new LoanTapeFileError(
      "INVALID_DOCUMENT",
      "JSON decimal and large integer values must be strings so exact source precision is preserved"
    );
  }
  throw new LoanTapeFileError("INVALID_DOCUMENT", "Loan tape cells must be scalar JSON values");
}

function inferFormat(path: string): LoanTapeFileFormat {
  const extension = extname(path).toLowerCase();
  if (extension === ".csv") return "csv";
  if (extension === ".json") return "json";
  if (extension === ".jsonl" || extension === ".ndjson") return "ndjson";
  throw new LoanTapeFileError("UNSUPPORTED_FORMAT", "Loan tape format must be csv, json, or ndjson");
}

function validatedPath(value: string): string {
  if (!value || value.length > 4_096 || /[\u0000\r\n]/.test(value)) {
    throw new LoanTapeFileError("INVALID_INPUT", "Loan tape path is invalid");
  }
  return resolve(value);
}

function boundedInteger(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new LoanTapeFileError("INVALID_INPUT", `${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function isPlainRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
