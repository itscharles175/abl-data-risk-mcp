import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, test } from "node:test";

import { ArtifactStore } from "../src/control/artifacts.js";
import { ControlStore } from "../src/control/store.js";
import { SnapshotIngestionService } from "../src/services/ingestion.js";
import {
  SqlSnapshotExtractionError,
  SqlSnapshotExtractionService,
  TrustedSqliteSnapshotSource,
  type ReadOnlySourceAssumptions,
  type SnapshotExtractionLimits,
  type SnapshotRelationPolicy,
  type TrustedSnapshotSource
} from "../src/services/sql-snapshot-extraction.js";
import { createSqliteFixture, type SqliteFixture } from "./helpers/sqlite-fixture.js";

interface ExtractionHarness {
  readonly fixture: SqliteFixture;
  readonly control: ControlStore;
  readonly artifacts: ArtifactStore;
  readonly source: TrustedSqliteSnapshotSource;
  service(limits?: SnapshotExtractionLimits): SqlSnapshotExtractionService;
}

const cleanups: Array<() => void> = [];

afterEach(() => {
  for (const cleanup of cleanups.splice(0).reverse()) cleanup();
});

function loanPolicy(overrides: Partial<SnapshotRelationPolicy> = {}): SnapshotRelationPolicy {
  return {
    relationId: "loan-tape",
    tenantId: "tenant-a",
    tenantIsolation: "dedicated_relation",
    datasetId: "loan-dataset",
    schema: "main",
    table: "loan_tape",
    relationKind: "table",
    columns: [
      {
        columnId: "as-of-date",
        sourceName: "as_of_dt",
        outputName: "as_of_dt",
        classification: "approved",
        encoding: "native"
      },
      {
        columnId: "loan-id",
        sourceName: "loan_no",
        outputName: "loan_no",
        classification: "approved",
        encoding: "native"
      },
      {
        columnId: "balance",
        sourceName: "current_balance",
        outputName: "current_balance",
        classification: "approved",
        encoding: "exact_text"
      },
      {
        columnId: "risk-grade",
        sourceName: "risk_grade",
        outputName: "risk_grade",
        classification: "approved",
        encoding: "native"
      }
    ],
    orderBy: [
      { columnId: "as-of-date", direction: "asc", nulls: "last" },
      { columnId: "loan-id", direction: "asc", nulls: "last" }
    ],
    orderIsUnique: true,
    watermark: {
      columnId: "as-of-date",
      valueKind: "date",
      comparison: "lte",
      required: true
    },
    ...overrides
  };
}

function harness(policy: SnapshotRelationPolicy = loanPolicy()): ExtractionHarness {
  const fixture = createSqliteFixture();
  const controlDirectory = mkdtempSync(join(tmpdir(), "abl-sql-extraction-"));
  const control = new ControlStore(join(controlDirectory, "control.sqlite"));
  const artifacts = new ArtifactStore(join(controlDirectory, "artifacts"), {
    activeKeyId: "test-key",
    keys: { "test-key": Buffer.alloc(32, 17) }
  });
  const ingestion = new SnapshotIngestionService(control, artifacts);
  const source = new TrustedSqliteSnapshotSource({
    sourceId: "servicer-db",
    databasePath: fixture.databasePath,
    assumptions: {
      principalMode: "non_owner",
      accessMode: "read_only",
      configurationSource: "trusted_runtime"
    },
    relations: [policy]
  });
  cleanups.push(() => {
    control.close();
    fixture.cleanup();
    rmSync(controlDirectory, { recursive: true, force: true });
  });
  return {
    fixture,
    control,
    artifacts,
    source,
    service: (limits = {}) => new SqlSnapshotExtractionService(source, ingestion, limits)
  };
}

function extractionInput(snapshotId: string) {
  return {
    tenantId: "tenant-a",
    datasetId: "loan-dataset",
    snapshotId,
    relationId: "loan-tape",
    columnIds: ["balance", "loan-id", "as-of-date"],
    watermark: { upperBound: "2025-02-28" },
    asOfDate: "2025-02-28",
    deliveredBy: "snapshot-connector",
    idempotencyKey: `extract-${snapshotId}`
  } as const;
}

function extractionError(code: SqlSnapshotExtractionError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof SqlSnapshotExtractionError && error.code === code;
}

test("policy-compiled SQLite extraction is deterministic, watermarked, exact, and immutably registered", async () => {
  const context = harness();
  const service = context.service({
    maximumRows: 10,
    maximumBytes: 10_000,
    maximumCellBytes: 1_024,
    maximumExecutionMs: 5_000,
    maximumColumns: 4
  });

  const first = await service.extractAndRegister(extractionInput("snapshot-one"));
  const second = await service.extractAndRegister({
    ...extractionInput("snapshot-two"),
    columnIds: ["as-of-date", "balance", "loan-id"]
  });

  assert.equal(first.snapshot.rowCount, 6);
  assert.equal(first.extraction.tenantId, "tenant-a");
  assert.equal(first.snapshot.sourceId, "servicer-db:loan-dataset");
  assert.deepEqual(first.extraction.outputColumns, ["as_of_dt", "loan_no", "current_balance"]);
  assert.deepEqual(first.extraction.columnIds, ["as-of-date", "loan-id", "balance"]);
  assert.equal(first.extraction.queryFingerprint, second.extraction.queryFingerprint);
  assert.equal(first.sourceArtifact.contentHash, second.sourceArtifact.contentHash);

  const stored = context.artifacts.getJson("tenant-a", first.sourceArtifact.artifactId).value as {
    readonly records: readonly Record<string, unknown>[];
  };
  assert.deepEqual(stored.records, [
    { as_of_dt: "2025-01-31", loan_no: "L1", current_balance: "90" },
    { as_of_dt: "2025-01-31", loan_no: "L2", current_balance: "170" },
    { as_of_dt: "2025-01-31", loan_no: "L3", current_balance: "220" },
    { as_of_dt: "2025-02-28", loan_no: "L1", current_balance: "85" },
    { as_of_dt: "2025-02-28", loan_no: "L2", current_balance: "160" },
    { as_of_dt: "2025-02-28", loan_no: "L3", current_balance: "200" }
  ]);
});

test("runtime input cannot supply SQL, connection details, injected identifiers, or non-allowlisted columns", async () => {
  const context = harness();
  const service = context.service();

  await assert.rejects(
    service.extractAndRegister({
      ...extractionInput("snapshot-sql"),
      sql: "DROP TABLE loan_tape",
      connectionUrl: "sqlite:///untrusted.sqlite"
    } as Parameters<typeof service.extractAndRegister>[0]),
    extractionError("INVALID_REQUEST")
  );
  await assert.rejects(
    service.extractAndRegister({
      ...extractionInput("snapshot-injection"),
      relationId: "loan-tape;DROP TABLE loan_tape"
    }),
    extractionError("INVALID_REQUEST")
  );
  await assert.rejects(
    service.extractAndRegister({
      ...extractionInput("snapshot-column"),
      columnIds: ["as-of-date", "loan-id", "password"]
    }),
    extractionError("COLUMN_NOT_ALLOWED")
  );
  await assert.rejects(
    service.extractAndRegister({
      ...extractionInput("snapshot-watermark"),
      watermark: undefined
    }),
    extractionError("WATERMARK_REQUIRED")
  );
  await assert.rejects(
    service.extractAndRegister({
      ...extractionInput("snapshot-cross-tenant"),
      tenantId: "tenant-b"
    }),
    extractionError("RELATION_NOT_ALLOWED")
  );

  const sourceDatabase = new DatabaseSync(context.fixture.databasePath, { readOnly: true });
  const row = sourceDatabase.prepare("SELECT COUNT(*) AS count FROM loan_tape").get() as {
    readonly count: number;
  };
  sourceDatabase.close();
  assert.equal(row.count, 9);
  assert.equal(context.control.listDatasetSnapshots("tenant-a").length, 0);
});

test("orchestration rejects a trusted-source result whose tenant binding changed", async () => {
  const context = harness();
  const mismatchedSource: TrustedSnapshotSource = {
    sourceId: context.source.sourceId,
    dialect: context.source.dialect,
    assumptions: context.source.assumptions,
    extract: async (request, limits, signal) => ({
      ...(await context.source.extract(request, limits, signal)),
      tenantId: "tenant-b"
    })
  };
  const service = new SqlSnapshotExtractionService(
    mismatchedSource,
    new SnapshotIngestionService(context.control, context.artifacts)
  );

  await assert.rejects(
    service.extractAndRegister(extractionInput("snapshot-mismatched-tenant")),
    extractionError("SOURCE_FAILURE")
  );
  assert.equal(context.control.listDatasetSnapshots("tenant-a").length, 0);
});

test("trusted policy rejects unsafe physical identifiers and non-read-only assumptions", () => {
  const fixture = createSqliteFixture();
  cleanups.push(fixture.cleanup);
  assert.throws(
    () =>
      new TrustedSqliteSnapshotSource({
        sourceId: "servicer-db",
        databasePath: fixture.databasePath,
        assumptions: {
          principalMode: "non_owner",
          accessMode: "read_only",
          configurationSource: "trusted_runtime"
        },
        relations: [loanPolicy({ table: 'loan_tape"; DROP TABLE loan_tape; --' })]
      }),
    extractionError("INVALID_POLICY")
  );

  const invalidAssumptions = {
    principalMode: "owner",
    accessMode: "read_write",
    configurationSource: "task_input"
  } as unknown as ReadOnlySourceAssumptions;
  assert.throws(
    () =>
      new TrustedSqliteSnapshotSource({
        sourceId: "servicer-db",
        databasePath: fixture.databasePath,
        assumptions: invalidAssumptions,
        relations: [loanPolicy()]
      }),
    extractionError("READ_ONLY_REQUIRED")
  );
  assert.throws(
    () =>
      new TrustedSqliteSnapshotSource({
        sourceId: "servicer-db",
        databasePath: fixture.databasePath,
        assumptions: {
          principalMode: "non_owner",
          accessMode: "read_only",
          configurationSource: "trusted_runtime"
        },
        relations: [loanPolicy({ relationKind: "view" as "table" })]
      }),
    extractionError("INVALID_POLICY")
  );
});

test("row and byte ceilings fail closed before creating a snapshot", async () => {
  const context = harness();
  await assert.rejects(
    context.service({ maximumRows: 2 }).extractAndRegister(extractionInput("snapshot-row-limit")),
    extractionError("ROW_LIMIT_EXCEEDED")
  );
  await assert.rejects(
    context.service({ maximumBytes: 16 }).extractAndRegister(extractionInput("snapshot-byte-limit")),
    extractionError("BYTE_LIMIT_EXCEEDED")
  );
  assert.equal(context.control.listDatasetSnapshots("tenant-a").length, 0);
});

test("cell ceilings fail closed in the isolated SQLite worker before retaining the row", async () => {
  const context = harness();
  const database = new DatabaseSync(context.fixture.databasePath);
  database.prepare("UPDATE loan_tape SET loan_no = ? WHERE rowid = 1").run("L".repeat(256));
  database.close();

  await assert.rejects(
    context
      .service({ maximumBytes: 10_000, maximumCellBytes: 32 })
      .extractAndRegister(extractionInput("snapshot-cell-limit")),
    extractionError("CELL_LIMIT_EXCEEDED")
  );
  assert.equal(context.control.listDatasetSnapshots("tenant-a").length, 0);
});

test("time limits and AbortSignal cancellation terminate extraction without ingestion", async () => {
  const context = harness();
  await assert.rejects(
    context
      .service({ maximumExecutionMs: 1 })
      .extractAndRegister(extractionInput("snapshot-time-limit")),
    extractionError("TIME_LIMIT_EXCEEDED")
  );

  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    context.service().extractAndRegister(extractionInput("snapshot-cancelled"), {
      signal: controller.signal
    }),
    extractionError("CANCELLED")
  );
  assert.equal(context.control.listDatasetSnapshots("tenant-a").length, 0);
});
