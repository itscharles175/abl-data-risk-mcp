import assert from "node:assert/strict";
import { test } from "node:test";

import { canonicalHash } from "../src/contracts/canonical.js";
import {
  AdapterValidationError,
  ParquetIngestionAdapterV1,
  inspectParquetBinary,
  sha256Bytes,
  type AdapterColumnV1,
  type ParquetDecodedColumnV1,
  type ParquetDecodedDatasetV1,
  type ParquetDecodedRowGroupV1,
  type ParquetDecodedValueV1,
  type ParquetDecoderPortV1
} from "../src/adapters/index.js";

const COLUMNS: readonly AdapterColumnV1[] = Object.freeze([
  { name: "loan_id", logicalType: "text", nullable: false },
  { name: "balance", logicalType: "decimal", nullable: false, decimalPrecision: 20, decimalScale: 2 },
  { name: "as_of_date", logicalType: "date", nullable: false },
  { name: "event_at", logicalType: "timestamp", nullable: false, timezone: "UTC" }
]);

test("Parquet adapter preserves exact DECIMAL values and reconciles footer populations", async () => {
  const bytes = parquetEnvelope("bounded thrift footer");
  const inspection = inspectParquetBinary(bytes);
  assert.equal(inspection.footerByteLength, Buffer.byteLength("bounded thrift footer"));
  assert.equal(inspection.footerOffset, 4);

  const adapter = parquetAdapter({ async decode() { return decodedDataset(); } });
  const first = await adapter.ingest(input(bytes));
  const second = await adapter.ingest({ ...input(bytes), expectedSourceContentHash: sha256Bytes(bytes) });

  assert.equal(first.records[0]!.balance, "9007199254740993.12");
  assert.equal(first.records[0]!.event_at, "2026-06-30T23:59:59.123456Z");
  assert.equal(first.rowCount, 2);
  assert.equal(first.populationHash, second.populationHash);
  assert.equal(first.sourceContentHash, sha256Bytes(bytes));
});

test("Parquet binary and delivery hash preflight fail before decoder execution", async () => {
  let calls = 0;
  const adapter = parquetAdapter({ async decode() { calls += 1; return decodedDataset(); } });
  const invalidMagic = Buffer.from("NOT_A_PARQUET_FILE");
  await assert.rejects(
    adapter.ingest(input(invalidMagic)),
    (error: unknown) => adapterError(error, "INVALID_INPUT", /magic bytes|truncated/)
  );
  const bytes = parquetEnvelope("footer");
  await assert.rejects(
    adapter.ingest({ ...input(bytes), expectedSourceContentHash: `sha256:${"f".repeat(64)}` }),
    (error: unknown) => adapterError(error, "INTEGRITY_FAILURE", /content hash/)
  );
  assert.equal(calls, 0);
});

test("Parquet schema variants, decimal drift, nested columns and non-UTC timestamps are rejected", async () => {
  const bytes = parquetEnvelope("footer");
  let decoded = decodedDataset();
  const adapter = parquetAdapter({ async decode() { return decoded; } });

  decoded = { ...decodedDataset(), schemaVariants: [decodedDataset().schemaVariants[0]!, decodedDataset().schemaVariants[0]!] };
  await assert.rejects(
    adapter.ingest(input(bytes)),
    (error: unknown) => adapterError(error, "SCHEMA_MISMATCH", /exactly one schema variant/)
  );

  const scaleDrift = mutableDecoded();
  scaleDrift.schemaVariants[0]!.columns[1] = {
    ...scaleDrift.schemaVariants[0]!.columns[1]!, decimalScale: 3
  };
  decoded = scaleDrift;
  await assert.rejects(
    adapter.ingest(input(bytes)),
    (error: unknown) => adapterError(error, "SCHEMA_MISMATCH", /precision or scale drifted/)
  );

  const nested = mutableDecoded();
  nested.schemaVariants[0]!.columns[0] = {
    ...nested.schemaVariants[0]!.columns[0]!, pathDepth: 2
  } as unknown as ParquetDecodedColumnV1;
  decoded = nested;
  await assert.rejects(
    adapter.ingest(input(bytes)),
    (error: unknown) => adapterError(error, "SCHEMA_MISMATCH", /differs from the governed schema/)
  );

  const notUtc = mutableDecoded();
  const withoutUtcAdjustment = { ...notUtc.schemaVariants[0]!.columns[3]! };
  Reflect.deleteProperty(withoutUtcAdjustment, "adjustedToUtc");
  notUtc.schemaVariants[0]!.columns[3] = withoutUtcAdjustment;
  decoded = notUtc;
  await assert.rejects(
    adapter.ingest(input(bytes)),
    (error: unknown) => adapterError(error, "SCHEMA_MISMATCH", /must be UTC-adjusted/)
  );
});

test("Parquet partitions are exact, ordered and reconciled to in-file columns", async () => {
  const bytes = parquetEnvelope("footer");
  let decoded = decodedDataset();
  const adapter = parquetAdapter({ async decode() { return decoded; } });

  await assert.rejects(
    adapter.ingest({
      ...input(bytes),
      partitions: [{ name: "as_of_date", value: "2026-07-31" }]
    }),
    (error: unknown) => adapterError(error, "SCHEMA_MISMATCH", /governed exact value/)
  );

  await assert.rejects(
    adapter.ingest({
      ...input(bytes),
      partitions: [{ name: "period", value: "2026Q2" }],
      partitionExpectations: [{ name: "period", expectedValue: "2026Q2", requireMatchingColumn: true }]
    }),
    (error: unknown) => adapterError(error, "SCHEMA_MISMATCH", /absent from the Parquet schema/)
  );

  const mismatch = mutableDecoded();
  mismatch.rows[1]![2] = { kind: "date", value: "2026-07-31" };
  decoded = mismatch;
  await assert.rejects(
    adapter.ingest(input(bytes)),
    (error: unknown) => adapterError(error, "SCHEMA_MISMATCH", /does not match partition/)
  );

  decoded = { ...decodedDataset(), declaredRowCount: 3 };
  await assert.rejects(
    adapter.ingest(input(bytes)),
    (error: unknown) => adapterError(error, "DECODER_CONTRACT_VIOLATION", /reconcile to row groups/)
  );
});

function parquetAdapter(decoder: ParquetDecoderPortV1): ParquetIngestionAdapterV1 {
  return new ParquetIngestionAdapterV1({
    decoder,
    parser: {
      parserId: "test-parquet-decoder",
      parserVersion: "1.0.0",
      optionsHash: canonicalHash({ decimal: "string", timezone: "UTC", mergeSchemas: false })
    },
    limits: {
      maximumFileBytes: 1_000_000,
      maximumFooterBytes: 100_000,
      maximumRows: 10,
      maximumColumns: 10,
      maximumRowGroups: 4
    }
  });
}

function input(bytes: Uint8Array) {
  return {
    bytes,
    columns: COLUMNS,
    partitions: [{ name: "as_of_date", value: "2026-06-30" }],
    partitionExpectations: [{ name: "as_of_date", expectedValue: "2026-06-30", requireMatchingColumn: true }]
  } as const;
}

function decodedDataset(): ParquetDecodedDatasetV1 {
  return {
    schemaVariants: [{ columns: [
      {
        name: "loan_id", logicalType: "text", nullable: false,
        physicalType: "BYTE_ARRAY", repetition: "required", pathDepth: 1
      },
      {
        name: "balance", logicalType: "decimal", nullable: false,
        decimalPrecision: 20, decimalScale: 2,
        physicalType: "FIXED_LEN_BYTE_ARRAY", repetition: "required", pathDepth: 1
      },
      {
        name: "as_of_date", logicalType: "date", nullable: false,
        physicalType: "INT32", repetition: "required", pathDepth: 1
      },
      {
        name: "event_at", logicalType: "timestamp", nullable: false, timezone: "UTC",
        adjustedToUtc: true, physicalType: "INT64", repetition: "required", pathDepth: 1
      }
    ] }],
    rowGroups: [
      { ordinal: 0, rowCount: 1, schemaVariantIndex: 0 },
      { ordinal: 1, rowCount: 1, schemaVariantIndex: 0 }
    ],
    declaredRowCount: 2,
    rows: [
      [
        { kind: "text", value: "LN-001" },
        { kind: "decimal", value: "9007199254740993.12" },
        { kind: "date", value: "2026-06-30" },
        { kind: "timestamp", value: "2026-06-30T23:59:59.123456Z", timezone: "UTC" }
      ],
      [
        { kind: "text", value: "LN-002" },
        { kind: "decimal", value: "0.00" },
        { kind: "date", value: "2026-06-30" },
        { kind: "timestamp", value: "2026-06-30T23:59:59Z", timezone: "UTC" }
      ]
    ]
  };
}

function mutableDecoded(): {
  schemaVariants: { columns: ParquetDecodedColumnV1[] }[];
  rowGroups: ParquetDecodedRowGroupV1[];
  declaredRowCount: number;
  rows: ParquetDecodedValueV1[][];
} {
  return structuredClone(decodedDataset()) as ReturnType<typeof mutableDecoded>;
}

function parquetEnvelope(footer: string): Buffer {
  const footerBytes = Buffer.from(footer, "utf8");
  const footerLength = Buffer.alloc(4);
  footerLength.writeUInt32LE(footerBytes.length, 0);
  return Buffer.concat([Buffer.from("PAR1", "ascii"), footerBytes, footerLength, Buffer.from("PAR1", "ascii")]);
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
