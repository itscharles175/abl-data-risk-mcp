import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ImmutableObjectDeliveryLoaderV1,
  PARQUET_MEDIA_TYPE,
  XLSX_MEDIA_TYPE,
  sha256Bytes,
  type ImmutableObjectClientPortV1,
  type ParquetDecodedDatasetV1,
  type ParquetDecoderPortV1,
  type XlsxDecodedWorkbookV1,
  type XlsxDecoderPortV1
} from "../src/adapters/index.js";
import {
  canonicalHash,
  createGovernedDatasetScopeBindingV1,
  createGovernedSourceDeliveryRecordV1,
  createSourceContractV1,
  type GovernedSourceDeliveryRecordV1,
  type SourceContractV1
} from "../src/contracts/index.js";
import {
  GovernedModernExtractionAuthorityV1,
  GovernedModernExtractionError,
  type GovernedModernExtractionPlanV1
} from "../src/services/governed-modern-extraction-authority-v1.js";
import type { TrustedSnapshotSource } from "../src/services/sql-snapshot-extraction.js";

const TENANT = "tenant-a";
const DATASET = "dataset-loans";
const FACILITY = "facility-auto-1";
const EXTRACTED_AT = "2026-08-15T12:00:00.000Z";
const LIMITS = Object.freeze({
  maximumRows: 1_000,
  maximumColumns: 25,
  maximumBytes: 1_000_000,
  timeoutMs: 5_000,
  cursorRows: 100
});

test("governed PostgreSQL extraction compiles only server-owned relation and column IDs", async () => {
  const source = sourceContract("postgresql");
  const binding = scopeBinding(source);
  const delivery = deliveryRecord(source, binding, "delivery-pg");
  let observedRequest: Parameters<TrustedSnapshotSource["extract"]>[0] | undefined;
  const records = Object.freeze([
    Object.freeze({ assetNumber: "A-1", actualEndBalance: "100.25", currency: "USD" }),
    Object.freeze({ assetNumber: "A-2", actualEndBalance: "5.25", currency: "USD" })
  ]);
  const trustedSource: TrustedSnapshotSource = {
    sourceId: "postgres-primary",
    dialect: "postgres",
    assumptions: {
      principalMode: "non_owner",
      accessMode: "read_only",
      configurationSource: "trusted_runtime"
    },
    async extract(request) {
      observedRequest = request;
      return {
        sourceId: "postgres-primary",
        dialect: "postgres",
        tenantId: TENANT,
        datasetId: DATASET,
        relationId: "loan-tape-approved",
        columnIds: ["asset-id", "ending-balance", "currency-code"],
        outputColumns: ["assetNumber", "actualEndBalance", "currency"],
        orderBy: [{ columnId: "asset-id", direction: "asc", nulls: "last" }],
        queryFingerprint: canonicalHash("compiled-postgres-query"),
        records,
        rowCount: records.length,
        byteLength: Buffer.byteLength(JSON.stringify(records), "utf8")
      };
    }
  };
  const authority = authorityFor([{
    ...planBase(source, delivery),
    kind: "postgresql",
    source: trustedSource,
    relationId: "loan-tape-approved",
    columnIds: ["asset-id", "ending-balance", "currency-code"]
  }]);

  const result = await authority.extract(extractionInput(source, binding, delivery));

  assert.deepEqual(observedRequest, {
    tenantId: TENANT,
    datasetId: DATASET,
    relationId: "loan-tape-approved",
    columnIds: ["asset-id", "ending-balance", "currency-code"]
  });
  assert.equal(JSON.stringify(observedRequest).includes("SELECT"), false);
  assert.equal(result.hashes.contentHash, canonicalHash(records));
  assert.equal(result.sections[0]!.balance, "105.50");
  assert.equal(result.sections[0]!.currency, "USD");
  assert.deepEqual(result.sourceSections?.[0]?.records, records);
  assert.equal(result.knowledge.sourceObservedAt, delivery.sourceObservedAt);
  assert.equal(result.knowledge.extractedAt, EXTRACTED_AT);
  assert.equal(result.knowledge.receivedAt, EXTRACTED_AT);
  assert.equal(Object.isFrozen(result), true);
});

test("governed XLSX extraction loads the exact immutable delivery and enforces its date system", async () => {
  const bytes = createStoredZip(SAFE_XLSX_PARTS);
  const source = sourceContract("xlsx");
  const binding = scopeBinding(source);
  const delivery = deliveryRecord(source, binding, "delivery-xlsx", bytes);
  const requests: string[] = [];
  const loader = objectLoader(new Map([[delivery.locator.mode === "object_storage" ? delivery.locator.objectKey : "", {
    bytes,
    mediaType: XLSX_MEDIA_TYPE
  }]]), requests);
  const decoder: XlsxDecoderPortV1 = {
    async decode(): Promise<XlsxDecodedWorkbookV1> {
      return {
        dateSystem: "1900",
        worksheets: [{
          name: "Loan Tape",
          visibility: "visible",
          rows: [
            [
              { kind: "text", value: "assetNumber" },
              { kind: "text", value: "actualEndBalance" },
              { kind: "text", value: "currency" }
            ],
            [
              { kind: "text", value: "A-1" },
              { kind: "decimal", value: "100.25" },
              { kind: "text", value: "USD" }
            ]
          ]
        }]
      };
    }
  };
  const authority = authorityFor([{
    ...planBase(source, delivery),
    kind: "object_xlsx",
    endpointOrigin: "https://objects.example.test",
    headerRow: 1,
    columns: adapterColumns()
  }], { objectLoader: loader, xlsxDecoder: decoder });

  const result = await authority.extract(extractionInput(source, binding, delivery));

  assert.equal(result.hashes.contentHash, sha256Bytes(bytes));
  assert.equal(result.byteCount, bytes.byteLength);
  assert.equal(result.sections[0]!.balance, "100.25");
  assert.deepEqual(requests, ["head:tenant-a/loan-tape.xlsx", "read:tenant-a/loan-tape.xlsx"]);

  const wrongDateSystem = authorityFor([{
    ...planBase(source, delivery),
    kind: "object_xlsx",
    endpointOrigin: "https://objects.example.test",
    headerRow: 1,
    columns: adapterColumns()
  }], {
    objectLoader: loader,
    xlsxDecoder: { async decode() { return { ...(await decoder.decode({
      bytes,
      maximumSheets: 1,
      maximumRows: 2,
      maximumColumns: 3,
      maximumCellCharacters: 100
    })), dateSystem: "1904" }; } }
  });
  await assert.rejects(
    wrongDateSystem.extract(extractionInput(source, binding, delivery)),
    (error: unknown) => extractionError(error, "EXTRACTION_FAILED")
  );
});

test("governed Parquet extraction binds parser output to immutable object evidence", async () => {
  const bytes = parquetEnvelope("bounded footer");
  const source = sourceContract("parquet");
  const binding = scopeBinding(source);
  const delivery = deliveryRecord(source, binding, "delivery-parquet", bytes);
  const loader = objectLoader(new Map([[delivery.locator.mode === "object_storage" ? delivery.locator.objectKey : "", {
    bytes,
    mediaType: PARQUET_MEDIA_TYPE
  }]]));
  const decoder: ParquetDecoderPortV1 = { async decode() { return decodedParquet(); } };
  const authority = authorityFor([{
    ...planBase(source, delivery),
    kind: "object_parquet",
    endpointOrigin: "https://objects.example.test",
    columns: adapterColumns(),
    partitions: [],
    partitionExpectations: []
  }], { objectLoader: loader, parquetDecoder: decoder });

  const result = await authority.extract(extractionInput(source, binding, delivery));

  assert.equal(result.hashes.contentHash, sha256Bytes(bytes));
  assert.equal(result.rowCount, 1);
  assert.equal(result.columnCount, 3);
  assert.deepEqual(result.sourceSections?.[0]?.records[0], {
    assetNumber: "A-1",
    actualEndBalance: "100.25",
    currency: "USD"
  });
});

test("delivery hash substitution is denied before a trusted source is called", async () => {
  const source = sourceContract("postgresql");
  const binding = scopeBinding(source);
  const delivery = deliveryRecord(source, binding, "delivery-pg");
  let calls = 0;
  const trustedSource: TrustedSnapshotSource = {
    sourceId: "postgres-primary",
    dialect: "postgres",
    assumptions: { principalMode: "non_owner", accessMode: "read_only", configurationSource: "trusted_runtime" },
    async extract() { calls += 1; throw new Error("must not execute"); }
  };
  const authority = authorityFor([{
    ...planBase(source, delivery),
    kind: "postgresql",
    source: trustedSource,
    relationId: "loan-tape-approved",
    columnIds: ["asset-id", "ending-balance", "currency-code"]
  }]);
  const substituted = {
    ...delivery,
    deliveryHash: canonicalHash("attacker-controlled-delivery")
  } as GovernedSourceDeliveryRecordV1;

  await assert.rejects(
    authority.extract(extractionInput(source, binding, substituted)),
    (error: unknown) => extractionError(error, "BINDING_MISMATCH")
  );
  assert.equal(calls, 0);
});

function authorityFor(
  plans: readonly GovernedModernExtractionPlanV1[],
  optional: {
    readonly objectLoader?: ImmutableObjectDeliveryLoaderV1;
    readonly xlsxDecoder?: XlsxDecoderPortV1;
    readonly parquetDecoder?: ParquetDecoderPortV1;
  } = {}
): GovernedModernExtractionAuthorityV1 {
  let monotonic = 0;
  return new GovernedModernExtractionAuthorityV1({
    tenantId: TENANT,
    facilityId: FACILITY,
    plans,
    ...(optional.objectLoader === undefined ? {} : { objectLoader: optional.objectLoader }),
    ...(optional.xlsxDecoder === undefined ? {} : { xlsxDecoder: optional.xlsxDecoder }),
    ...(optional.parquetDecoder === undefined ? {} : { parquetDecoder: optional.parquetDecoder }),
    now: () => EXTRACTED_AT,
    monotonicNow: () => monotonic++
  });
}

function planBase(source: SourceContractV1, delivery: GovernedSourceDeliveryRecordV1) {
  return {
    tenantId: TENANT,
    datasetId: DATASET,
    facilityId: FACILITY,
    deliveryId: delivery.deliveryId,
    deliveryHash: delivery.deliveryHash,
    sourceContractId: source.sourceContractId,
    sourceContractRevision: source.revision,
    sourceContractHash: source.sourceContractHash,
    asOfDate: "2021-10-31"
  } as const;
}

function extractionInput(
  sourceContract: SourceContractV1,
  scope: ReturnType<typeof scopeBinding>,
  sourceDelivery: GovernedSourceDeliveryRecordV1
) {
  return {
    tenantId: TENANT,
    actorId: "operator-a",
    datasetId: DATASET,
    facilityId: FACILITY,
    snapshotId: "snapshot-a",
    deliveryId: sourceDelivery.deliveryId,
    sourceContract,
    scopeBinding: scope,
    sourceDelivery,
    limits: LIMITS
  };
}

function sourceContract(kind: "postgresql" | "xlsx" | "parquet"): SourceContractV1 {
  const delivery = kind === "postgresql"
    ? {
        mode: "postgresql_pull" as const,
        connectorId: "postgres-primary",
        credentialRef: "kms/postgres/readonly",
        catalog: "risk",
        schema: "servicing",
        relation: "loan_tape"
      }
    : {
        mode: "object_storage" as const,
        format: kind,
        connectorId: "object-primary",
        credentialRef: "kms/objects/readonly",
        bucket: "governed-deliveries",
        keyPattern: "tenant-a/*.${kind}",
        immutableVersionRequired: true as const
      };
  const parserPolicy = kind === "postgresql"
    ? {
        format: "sql_rows" as const,
        parserId: "postgres-exact-v1",
        parserVersion: "1.0.0",
        optionsHash: canonicalHash("postgres-parser"),
        exactDecimalMode: "string" as const,
        timezone: "UTC" as const
      }
    : kind === "xlsx"
      ? {
          format: "xlsx" as const,
          parserId: "xlsx-safe-v1",
          parserVersion: "1.0.0",
          optionsHash: canonicalHash("xlsx-parser"),
          rejectMacros: true as const,
          rejectExternalLinks: true as const,
          rejectFormulaCells: true as const,
          dateSystem: "1900" as const,
          exactDecimalMode: "string" as const
        }
      : {
          format: "parquet" as const,
          parserId: "parquet-safe-v1",
          parserVersion: "1.0.0",
          optionsHash: canonicalHash("parquet-parser"),
          exactDecimalMode: "string" as const,
          timezone: "UTC" as const,
          rejectSchemaMerging: true
        };
  return createSourceContractV1({
    contractVersion: 1,
    tenantId: TENANT,
    sourceContractId: `source-${kind}`,
    sourceKey: `loan-tape-${kind}`,
    revision: 1,
    status: "active",
    delivery,
    schemaPolicy: {
      columns: [
        { sourceName: "assetNumber", ordinal: 0, nativeType: "text", nullable: false, required: true },
        { sourceName: "actualEndBalance", ordinal: 1, nativeType: "decimal(20,2)", nullable: false, required: true },
        { sourceName: "currency", ordinal: 2, nativeType: "text", nullable: false, required: true }
      ],
      allowUnknownColumns: false,
      requireStableOrdinals: true
    },
    parserPolicy,
    extractionPolicy: {
      mode: "full",
      readOnly: true,
      maximumRows: LIMITS.maximumRows,
      maximumColumns: LIMITS.maximumColumns,
      maximumBytes: LIMITS.maximumBytes,
      timeoutMs: LIMITS.timeoutMs,
      cursorRows: LIMITS.cursorRows
    },
    sections: [{
      sectionId: "loans",
      required: true,
      selector: "Loan Tape",
      keyFields: ["assetNumber"],
      balanceField: "actualEndBalance",
      currencyField: "currency",
      minimumRows: 1,
      maximumRows: LIMITS.maximumRows
    }],
    effectiveFrom: "2021-01-01",
    createdBy: "maker-a",
    createdAt: "2021-01-01T00:00:00.000Z",
    approvedBy: "checker-a",
    approvedAt: "2021-01-02T00:00:00.000Z"
  });
}

function scopeBinding(source: SourceContractV1) {
  return createGovernedDatasetScopeBindingV1({
    contractVersion: 1,
    tenantId: TENANT,
    bindingId: `binding-${source.sourceContractId}`,
    revision: 1,
    datasetId: DATASET,
    sourceContract: {
      sourceContractId: source.sourceContractId,
      revision: source.revision,
      sourceContractHash: source.sourceContractHash
    },
    scope: { scopeType: "facility", scopeId: FACILITY },
    effectiveFrom: "2021-01-01"
  });
}

function deliveryRecord(
  source: SourceContractV1,
  binding: ReturnType<typeof scopeBinding>,
  deliveryId: string,
  bytes?: Uint8Array
): GovernedSourceDeliveryRecordV1 {
  const locator = source.delivery.mode === "postgresql_pull"
    ? {
        mode: "postgresql_pull" as const,
        connectorId: source.delivery.connectorId,
        catalog: source.delivery.catalog,
        schema: source.delivery.schema,
        relation: source.delivery.relation,
        relationIdentityHash: canonicalHash({
          catalog: source.delivery.catalog,
          schema: source.delivery.schema,
          relation: source.delivery.relation
        }),
        sourceVersionHash: canonicalHash("repeatable-read-version")
      }
    : {
        mode: "object_storage" as const,
        format: source.delivery.format,
        connectorId: source.delivery.connectorId,
        bucket: source.delivery.bucket,
        objectKey: source.delivery.format === "xlsx" ? "tenant-a/loan-tape.xlsx" : "tenant-a/loan-tape.parquet",
        immutableVersionId: "version-1",
        immutableVersionHash: canonicalHash("version-1"),
        contentHash: sha256Bytes(bytes!),
        byteCount: bytes!.byteLength
      };
  return createGovernedSourceDeliveryRecordV1({
    contractVersion: 1,
    tenantId: TENANT,
    deliveryId,
    deliveryRevision: 1,
    datasetId: DATASET,
    facilityId: FACILITY,
    sourceContract: {
      sourceContractId: source.sourceContractId,
      revision: source.revision,
      sourceContractHash: source.sourceContractHash
    },
    scopeBinding: {
      bindingId: binding.bindingId,
      revision: binding.revision,
      bindingHash: binding.bindingHash
    },
    locator,
    sourceObservedAt: "2026-08-15T10:00:00.000Z",
    receivedAt: "2026-08-15T10:01:00.000Z",
    status: "usable",
    recordedBy: "operator-a",
    identitySource: "server_derived",
    recordedAt: "2026-08-15T10:01:00.000Z",
    previousDeliveryHash: null
  });
}

function adapterColumns() {
  return [
    { name: "assetNumber", logicalType: "text" as const, nullable: false },
    {
      name: "actualEndBalance",
      logicalType: "decimal" as const,
      nullable: false,
      decimalPrecision: 20,
      decimalScale: 2
    },
    { name: "currency", logicalType: "text" as const, nullable: false }
  ] as const;
}

function decodedParquet(): ParquetDecodedDatasetV1 {
  return {
    schemaVariants: [{ columns: [
      {
        name: "assetNumber", logicalType: "text", nullable: false,
        physicalType: "BYTE_ARRAY", repetition: "required", pathDepth: 1
      },
      {
        name: "actualEndBalance", logicalType: "decimal", nullable: false,
        decimalPrecision: 20, decimalScale: 2,
        physicalType: "FIXED_LEN_BYTE_ARRAY", repetition: "required", pathDepth: 1
      },
      {
        name: "currency", logicalType: "text", nullable: false,
        physicalType: "BYTE_ARRAY", repetition: "required", pathDepth: 1
      }
    ] }],
    rowGroups: [{ ordinal: 0, rowCount: 1, schemaVariantIndex: 0 }],
    declaredRowCount: 1,
    rows: [[
      { kind: "text", value: "A-1" },
      { kind: "decimal", value: "100.25" },
      { kind: "text", value: "USD" }
    ]]
  };
}

function objectLoader(
  objects: ReadonlyMap<string, { readonly bytes: Uint8Array; readonly mediaType: string }>,
  requests: string[] = []
): ImmutableObjectDeliveryLoaderV1 {
  const client: ImmutableObjectClientPortV1 = {
    async headImmutableObject(request) {
      requests.push(`head:${request.key}`);
      const object = objects.get(request.key)!;
      return {
        connectorId: request.connectorId,
        endpointOrigin: request.endpointOrigin,
        bucket: request.bucket,
        key: request.key,
        versionId: request.versionId,
        contentLength: object.bytes.byteLength,
        contentType: object.mediaType,
        contentHash: sha256Bytes(object.bytes),
        immutability: { mode: "version_id", versionId: request.versionId }
      };
    },
    async readImmutableObject(request) {
      requests.push(`read:${request.key}`);
      const object = objects.get(request.key)!;
      return {
        versionId: request.versionId,
        body: (async function* () { yield object.bytes; })()
      };
    }
  };
  return new ImmutableObjectDeliveryLoaderV1({
    client,
    maximumObjectBytes: LIMITS.maximumBytes,
    allowlist: [{
      connectorId: "object-primary",
      endpointOrigin: "https://objects.example.test",
      buckets: [{
        bucket: "governed-deliveries",
        keyPrefixes: ["tenant-a/"],
        mediaTypes: [XLSX_MEDIA_TYPE, PARQUET_MEDIA_TYPE]
      }]
    }]
  });
}

function parquetEnvelope(footer: string): Buffer {
  const footerBytes = Buffer.from(footer, "utf8");
  const bytes = Buffer.alloc(4 + footerBytes.length + 8);
  bytes.write("PAR1", 0, "ascii");
  footerBytes.copy(bytes, 4);
  bytes.writeUInt32LE(footerBytes.length, 4 + footerBytes.length);
  bytes.write("PAR1", 8 + footerBytes.length, "ascii");
  return bytes;
}

function extractionError(error: unknown, code: GovernedModernExtractionError["code"]): boolean {
  assert.ok(error instanceof GovernedModernExtractionError);
  assert.equal(error.code, code);
  return true;
}

const SAFE_XLSX_PARTS = Object.freeze({
  "[Content_Types].xml": "<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"></Types>",
  "_rels/.rels": "<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"></Relationships>",
  "xl/workbook.xml": "<?xml version=\"1.0\"?><workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"></workbook>",
  "xl/worksheets/sheet1.xml": "<?xml version=\"1.0\"?><worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData/></worksheet>"
});

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
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(centralRecords.length, 8);
  end.writeUInt16LE(centralRecords.length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...localRecords, centralDirectory, end]);
}

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}
