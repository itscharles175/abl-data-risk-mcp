import assert from "node:assert/strict";
import { test } from "node:test";

import { canonicalHash } from "../src/contracts/canonical.js";
import {
  AdapterValidationError,
  XlsxIngestionAdapterV1,
  inspectXlsxArchive,
  sha256Bytes,
  type AdapterColumnV1,
  type XlsxDecodedWorkbookV1,
  type XlsxDecoderPortV1
} from "../src/adapters/index.js";

const COLUMNS: readonly AdapterColumnV1[] = Object.freeze([
  { name: "loan_id", logicalType: "text", nullable: false },
  { name: "balance", logicalType: "decimal", nullable: false, decimalPrecision: 20, decimalScale: 2 },
  { name: "as_of_date", logicalType: "date", nullable: false }
]);

const SAFE_PARTS = Object.freeze({
  "[Content_Types].xml": "<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"></Types>",
  "_rels/.rels": "<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"></Relationships>",
  "xl/workbook.xml": "<?xml version=\"1.0\"?><workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"></workbook>",
  "xl/worksheets/sheet1.xml": "<?xml version=\"1.0\"?><worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData/></worksheet>"
});

test("XLSX preflight rejects formulas, macros and external relationships before decoder execution", async () => {
  let decoderCalls = 0;
  const decoder: XlsxDecoderPortV1 = {
    async decode() {
      decoderCalls += 1;
      return decodedWorkbook();
    }
  };
  const adapter = xlsxAdapter(decoder);

  const formula = createStoredZip({
    ...SAFE_PARTS,
    "xl/worksheets/sheet1.xml": "<worksheet><sheetData><row><c><f>SUM(A1:A2)</f></c></row></sheetData></worksheet>"
  });
  await assert.rejects(
    adapter.ingest(input(formula)),
    (error: unknown) => adapterError(error, "UNSUPPORTED_FEATURE", /Formula cell/)
  );

  const macro = createStoredZip({ ...SAFE_PARTS, "xl/vbaProject.bin": "opaque macro bytes" });
  await assert.rejects(
    adapter.ingest(input(macro)),
    (error: unknown) => adapterError(error, "UNSUPPORTED_FEATURE", /forbidden active/)
  );

  const external = createStoredZip({
    ...SAFE_PARTS,
    "xl/_rels/workbook.xml.rels": "<Relationships><Relationship TargetMode=\"External\" Target=\"https://example.invalid/tape.xlsx\"/></Relationships>"
  });
  await assert.rejects(
    adapter.ingest(input(external)),
    (error: unknown) => adapterError(error, "UNSUPPORTED_FEATURE", /External XLSX relationship/)
  );
  assert.equal(decoderCalls, 0);
});

test("XLSX adapter preserves exact decimals and emits deterministic conformance hashes", async () => {
  const bytes = createStoredZip(SAFE_PARTS);
  const inspection = inspectXlsxArchive(bytes);
  assert.equal(inspection.entryCount, 4);
  assert.equal(inspection.archiveHasContentTypes, true);
  assert.equal(inspection.archiveHasWorkbook, true);

  const decoder: XlsxDecoderPortV1 = { async decode() { return decodedWorkbook(); } };
  const adapter = xlsxAdapter(decoder);
  const first = await adapter.ingest({ ...input(bytes), expectedSourceContentHash: sha256Bytes(bytes) });
  const second = await adapter.ingest(input(bytes));

  assert.equal(first.records[0]!.balance, "9007199254740993.12");
  assert.equal(first.sourceContentHash, sha256Bytes(bytes));
  assert.equal(first.populationHash, second.populationHash);
  assert.equal(first.schemaHash, second.schemaHash);
  assert.equal(first.rowCount, 1);
  assert.equal(first.columnCount, 3);
  assert.equal(Object.isFrozen(first.records[0]), true);
});

test("XLSX adapter enforces manifest hash, exact headers, safe text and decimal scale", async () => {
  const bytes = createStoredZip(SAFE_PARTS);
  let workbook = decodedWorkbook();
  const decoder: XlsxDecoderPortV1 = { async decode() { return workbook; } };
  const adapter = xlsxAdapter(decoder);

  await assert.rejects(
    adapter.ingest({ ...input(bytes), expectedSourceContentHash: `sha256:${"0".repeat(64)}` }),
    (error: unknown) => adapterError(error, "INTEGRITY_FAILURE", /content hash/)
  );

  workbook = decodedWorkbook({ headerLoanId: "Loan ID" });
  await assert.rejects(
    adapter.ingest(input(bytes)),
    (error: unknown) => adapterError(error, "SCHEMA_MISMATCH", /does not match governed column/)
  );

  workbook = decodedWorkbook({ loanId: "=HYPERLINK(\"https://evil.invalid\")" });
  await assert.rejects(
    adapter.ingest(input(bytes)),
    (error: unknown) => adapterError(error, "UNSAFE_VALUE", /formula-injection/)
  );

  workbook = decodedWorkbook({ balance: "10.2" });
  await assert.rejects(
    adapter.ingest(input(bytes)),
    (error: unknown) => adapterError(error, "UNSAFE_VALUE", /exactly 2 fractional digits/)
  );
});

test("XLSX archive integrity and bomb limits are enforced", () => {
  const bytes = createStoredZip(SAFE_PARTS);
  const tampered = Buffer.from(bytes);
  const worksheet = tampered.indexOf(Buffer.from("<worksheet"));
  assert.notEqual(worksheet, -1);
  tampered[worksheet + 1] = 0x58;
  assert.throws(
    () => inspectXlsxArchive(tampered),
    (error: unknown) => adapterError(error, "INTEGRITY_FAILURE", /failed integrity/)
  );

  assert.throws(
    () => inspectXlsxArchive(bytes, {
      maximumWorkbookBytes: bytes.byteLength - 1,
      maximumSheets: 2,
      maximumRows: 2,
      maximumColumns: 3,
      maximumCellCharacters: 100,
      maximumZipEntries: 10,
      maximumArchiveUncompressedBytes: 10_000,
      maximumEntryUncompressedBytes: 10_000,
      maximumCompressionRatio: 100
    }),
    (error: unknown) => adapterError(error, "LIMIT_EXCEEDED", /byte limit/)
  );
});

function xlsxAdapter(decoder: XlsxDecoderPortV1): XlsxIngestionAdapterV1 {
  return new XlsxIngestionAdapterV1({
    decoder,
    parser: {
      parserId: "test-xlsx-decoder",
      parserVersion: "1.0.0",
      optionsHash: canonicalHash({ formulas: "reject", decimal: "string" })
    },
    limits: {
      maximumWorkbookBytes: 2_000_000,
      maximumArchiveUncompressedBytes: 2_000_000,
      maximumEntryUncompressedBytes: 1_000_000,
      maximumRows: 10,
      maximumColumns: 10,
      maximumSheets: 4
    }
  });
}

function input(bytes: Uint8Array) {
  return { bytes, sheetName: "Loan Tape", headerRow: 1, columns: COLUMNS } as const;
}

function decodedWorkbook(overrides: {
  readonly headerLoanId?: string;
  readonly loanId?: string;
  readonly balance?: string;
} = {}): XlsxDecodedWorkbookV1 {
  return {
    dateSystem: "1900",
    worksheets: [{
      name: "Loan Tape",
      visibility: "visible",
      rows: [
        [
          { kind: "text", value: overrides.headerLoanId ?? "loan_id" },
          { kind: "text", value: "balance" },
          { kind: "text", value: "as_of_date" }
        ],
        [
          { kind: "text", value: overrides.loanId ?? "LN-001" },
          { kind: "decimal", value: overrides.balance ?? "9007199254740993.12" },
          { kind: "date", value: "2026-06-30" }
        ]
      ]
    }]
  };
}

function adapterError(
  error: unknown,
  code: AdapterValidationError["code"],
  message: RegExp
): boolean {
  assert.ok(error instanceof AdapterValidationError);
  assert.equal(error.code, code);
  assert.match(error.message, message);
  return true;
}

function createStoredZip(parts: Readonly<Record<string, string>>): Buffer {
  const localRecords: Buffer[] = [];
  const centralRecords: Buffer[] = [];
  let localOffset = 0;
  for (const [name, text] of Object.entries(parts)) {
    const nameBytes = Buffer.from(name, "utf8");
    const content = Buffer.from(text, "utf8");
    const checksum = crc32(content);
    const local = Buffer.alloc(30 + nameBytes.length + content.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x800, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(content.length, 18);
    local.writeUInt32LE(content.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    nameBytes.copy(local, 30);
    content.copy(local, 30 + nameBytes.length);
    localRecords.push(local);

    const central = Buffer.alloc(46 + nameBytes.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x800, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(content.length, 20);
    central.writeUInt32LE(content.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(localOffset, 42);
    nameBytes.copy(central, 46);
    centralRecords.push(central);
    localOffset += local.length;
  }
  const centralDirectory = Buffer.concat(centralRecords);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(centralRecords.length, 8);
  eocd.writeUInt16LE(centralRecords.length, 10);
  eocd.writeUInt32LE(centralDirectory.length, 12);
  eocd.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...localRecords, centralDirectory, eocd]);
}

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) === 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
