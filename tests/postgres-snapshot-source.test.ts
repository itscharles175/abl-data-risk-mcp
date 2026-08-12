import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import { ArtifactStore } from "../src/control/artifacts.js";
import { ControlStore } from "../src/control/store.js";
import {
  TrustedPostgresSnapshotSource,
  type PostgresSnapshotClient,
  type PostgresSnapshotPool
} from "../src/services/postgres-snapshot-source.js";
import { SnapshotIngestionService } from "../src/services/ingestion.js";
import {
  SqlSnapshotExtractionError,
  SqlSnapshotExtractionService,
  type ReadOnlySourceAssumptions,
  type ResolvedSnapshotExtractionLimits,
  type SnapshotRelationPolicy,
  type SourceExtractionRequest
} from "../src/services/sql-snapshot-extraction.js";

interface QueryCall {
  readonly text: string;
  readonly values: readonly unknown[];
}

class FakePostgresClient implements PostgresSnapshotClient {
  readonly calls: QueryCall[] = [];
  readonly releases: Array<boolean | Error | undefined> = [];
  rows: readonly Record<string, unknown>[] = [
    { as_of_date: "2025-01-31", loan_id: "L1", outstanding_balance: "90.10" },
    { as_of_date: "2025-02-28", loan_id: "L2", outstanding_balance: "170.20" }
  ];
  ownershipRows: readonly Record<string, unknown>[] = [
    {
      read_only: true,
      non_owner: true,
      non_superuser: true,
      non_bypass_rls: true,
      row_security_enabled: false,
      row_security_forced: false,
      relation_kind: "r"
    }
  ];
  attestationRows: readonly Record<string, unknown>[] | undefined;
  dataFailure: unknown;
  dataPromise: Promise<{ readonly rows: readonly Record<string, unknown>[] }> | undefined;
  cursorOffset = 0;

  async query(
    query: string | { readonly text: string; readonly values?: readonly unknown[] }
  ): Promise<{ readonly rows: readonly Record<string, unknown>[] }> {
    const text = typeof query === "string" ? query : query.text;
    const values = typeof query === "string" ? [] : [...(query.values ?? [])];
    this.calls.push({ text, values });
    if (text.includes("FROM pg_catalog.pg_class")) return { rows: this.ownershipRows };
    if (text.includes('row_to_json("bounded_snapshot")')) {
      if (this.attestationRows) return { rows: this.attestationRows };
      const outputNames = ["as_of_date", "loan_id", "outstanding_balance"] as const;
      const maximumRowBytes = Math.max(
        0,
        ...this.rows.map((row) => Buffer.byteLength(JSON.stringify(row), "utf8"))
      );
      return {
        rows: [
          Object.fromEntries([
            ["maximum_row_bytes", String(maximumRowBytes)],
            ...outputNames.map((name, index) => [
              `cell_${index}`,
              String(
                Math.max(
                  0,
                  ...this.rows.map((row) =>
                    Buffer.byteLength(JSON.stringify(row[name] ?? null), "utf8")
                  )
                )
              )
            ])
          ])
        ]
      };
    }
    if (text.startsWith('DECLARE "abl_snapshot_cursor"')) {
      this.cursorOffset = 0;
      return { rows: [] };
    }
    if (text.startsWith("FETCH FORWARD ")) {
      if (this.dataFailure !== undefined) throw this.dataFailure;
      if (this.dataPromise) return this.dataPromise;
      const match = /^FETCH FORWARD (\d+) FROM/.exec(text);
      if (!match) throw new Error("Invalid test cursor fetch");
      const count = Number(match[1]);
      const rows = this.rows.slice(this.cursorOffset, this.cursorOffset + count);
      this.cursorOffset += rows.length;
      return { rows };
    }
    return { rows: [] };
  }

  release(destroy?: boolean | Error): void {
    this.releases.push(destroy);
  }
}

class FakePostgresPool implements PostgresSnapshotPool {
  connectCount = 0;

  constructor(readonly client: FakePostgresClient) {}

  async connect(): Promise<PostgresSnapshotClient> {
    this.connectCount += 1;
    return this.client;
  }
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
    schema: "servicing",
    table: "loan_tape",
    relationKind: "table",
    columns: [
      {
        columnId: "as-of-date",
        sourceName: "as_of_dt",
        outputName: "as_of_date",
        classification: "approved",
        encoding: "exact_text"
      },
      {
        columnId: "loan-id",
        sourceName: "loan_no",
        outputName: "loan_id",
        classification: "approved",
        encoding: "native"
      },
      {
        columnId: "balance",
        sourceName: "current_balance",
        outputName: "outstanding_balance",
        classification: "approved",
        encoding: "exact_text"
      }
    ],
    orderBy: [
      { columnId: "as-of-date", direction: "asc", nulls: "last" },
      { columnId: "loan-id", direction: "asc", nulls: "last" }
    ],
    orderIsUnique: true,
    watermark: { columnId: "as-of-date", valueKind: "date", comparison: "lte", required: true },
    ...overrides
  };
}

function request(overrides: Partial<SourceExtractionRequest> = {}): SourceExtractionRequest {
  return {
    tenantId: "tenant-a",
    datasetId: "loan-dataset",
    relationId: "loan-tape",
    columnIds: ["balance", "loan-id", "as-of-date"],
    watermark: { upperBound: "2025-02-28" },
    ...overrides
  };
}

function limits(overrides: Partial<ResolvedSnapshotExtractionLimits> = {}): ResolvedSnapshotExtractionLimits {
  return {
    maximumRows: 10,
    maximumBytes: 10_000,
    maximumCellBytes: 1_024,
    maximumExecutionMs: 5_000,
    maximumColumns: 10,
    ...overrides
  };
}

function source(
  client = new FakePostgresClient(),
  policy: SnapshotRelationPolicy = loanPolicy()
): { readonly client: FakePostgresClient; readonly pool: FakePostgresPool; readonly source: TrustedPostgresSnapshotSource } {
  const pool = new FakePostgresPool(client);
  return {
    client,
    pool,
    source: new TrustedPostgresSnapshotSource({
      sourceId: "servicer-postgres",
      pool,
      assumptions: {
        principalMode: "non_owner",
        accessMode: "read_only",
        configurationSource: "trusted_runtime"
      },
      relations: [policy],
      lockTimeoutMs: 250,
      idleInTransactionTimeoutMs: 4_000
    })
  };
}

function extractionError(code: SqlSnapshotExtractionError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof SqlSnapshotExtractionError && error.code === code;
}

test("injected PostgreSQL pool executes a read-only deterministic parameterized snapshot", async () => {
  const context = source();
  const first = await context.source.extract(request(), limits());
  const second = await context.source.extract(
    request({ columnIds: ["as-of-date", "balance", "loan-id"] }),
    limits()
  );

  assert.equal(first.dialect, "postgres");
  assert.equal(first.tenantId, "tenant-a");
  assert.deepEqual(first.columnIds, ["as-of-date", "loan-id", "balance"]);
  assert.deepEqual(first.outputColumns, ["as_of_date", "loan_id", "outstanding_balance"]);
  assert.deepEqual(first.records, context.client.rows);
  assert.equal(first.byteLength, Buffer.byteLength(JSON.stringify(first.records), "utf8"));
  assert.equal(second.queryFingerprint, first.queryFingerprint);
  assert.match(first.queryFingerprint, /^sha256:[a-f0-9]{64}$/);

  assert.deepEqual(context.client.calls.slice(0, 4).map((call) => call.text), [
    "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",
    "SET LOCAL statement_timeout = '5000ms'",
    "SET LOCAL lock_timeout = '250ms'",
    "SET LOCAL idle_in_transaction_session_timeout = '4000ms'"
  ]);
  assert.match(context.client.calls[4]!.text, /FROM pg_catalog\.pg_class/);
  assert.match(context.client.calls[4]!.text, /pg_has_role/);
  assert.match(context.client.calls[4]!.text, /rolbypassrls/);
  const declarations = context.client.calls.filter((call) =>
    call.text.startsWith('DECLARE "abl_snapshot_cursor"')
  );
  assert.equal(declarations.length, 2);
  assert.equal(
    declarations[0]?.text,
    'DECLARE "abl_snapshot_cursor" NO SCROLL CURSOR FOR SELECT CAST("as_of_dt" AS TEXT) AS "as_of_date", "loan_no" AS "loan_id", CAST("current_balance" AS TEXT) AS "outstanding_balance"\n' +
      '  FROM "servicing"."loan_tape"\n' +
      ' WHERE "as_of_dt" <= $1\n' +
      ' ORDER BY "as_of_dt" ASC NULLS LAST, "loan_no" ASC NULLS LAST\n' +
      " LIMIT $2"
  );
  assert.deepEqual(declarations[0]?.values, ["2025-02-28", 11]);
  assert.equal(declarations[0]?.text.includes("2025-02-28"), false);
  assert.ok(context.client.calls.some((call) => call.text.startsWith("FETCH FORWARD ")));
  assert.deepEqual(context.client.releases, [false, false]);
});

test("PostgreSQL source interoperates with extraction and immutable ingestion services", async () => {
  const context = source();
  const directory = mkdtempSync(join(tmpdir(), "abl-postgres-source-"));
  const control = new ControlStore(join(directory, "control.sqlite"));
  const artifacts = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "artifact-key",
    keys: { "artifact-key": Buffer.alloc(32, 19) }
  });
  cleanups.push(() => {
    control.close();
    rmSync(directory, { recursive: true, force: true });
  });
  const extraction = new SqlSnapshotExtractionService(
    context.source,
    new SnapshotIngestionService(control, artifacts),
    limits()
  );

  const result = await extraction.extractAndRegister({
    tenantId: "tenant-a",
    datasetId: "loan-dataset",
    snapshotId: "snapshot-postgres",
    relationId: "loan-tape",
    columnIds: ["as-of-date", "loan-id", "balance"],
    watermark: { upperBound: "2025-02-28" },
    asOfDate: "2025-02-28",
    deliveredBy: "postgres-connector",
    idempotencyKey: "extract-postgres"
  });
  assert.equal(result.snapshot.sourceId, "servicer-postgres:loan-dataset");
  assert.equal(result.snapshot.rowCount, 2);
  assert.equal(result.extraction.dialect, "postgres");
  const stored = artifacts.getJson("tenant-a", result.sourceArtifact.artifactId).value as {
    readonly records: readonly Record<string, unknown>[];
  };
  assert.deepEqual(stored.records, context.client.rows);
});

test("runtime requests cannot supply SQL, connectivity, credentials, paths, or URLs", async () => {
  for (const [key, value] of [
    ["sql", "SELECT pg_sleep(10)"],
    ["connectionString", "postgres://admin:secret@db/prod"],
    ["credentials", { password: "secret" }],
    ["databasePath", "/tmp/untrusted"],
    ["url", "https://attacker.example"]
  ] as const) {
    const context = source();
    await assert.rejects(
      context.source.extract({ ...request(), [key]: value } as SourceExtractionRequest, limits()),
      extractionError("INVALID_REQUEST")
    );
    assert.equal(context.pool.connectCount, 0);
  }

  const context = source();
  await assert.rejects(
    context.source.extract(request({ relationId: 'loan-tape"; DROP TABLE loan_tape; --' }), limits()),
    extractionError("INVALID_REQUEST")
  );
  await assert.rejects(
    context.source.extract(request({ columnIds: ["loan-id", "password"] }), limits()),
    extractionError("COLUMN_NOT_ALLOWED")
  );
  await assert.rejects(
    context.source.extract(request({ tenantId: "tenant-b" }), limits()),
    extractionError("RELATION_NOT_ALLOWED")
  );
  assert.equal(context.pool.connectCount, 0);
});

test("trusted policy and physical catalog checks enforce non-owner read-only assumptions", async () => {
  const invalidAssumptions = {
    principalMode: "owner",
    accessMode: "read_write",
    configurationSource: "request"
  } as unknown as ReadOnlySourceAssumptions;
  assert.throws(
    () =>
      new TrustedPostgresSnapshotSource({
        sourceId: "servicer-postgres",
        pool: new FakePostgresPool(new FakePostgresClient()),
        assumptions: invalidAssumptions,
        relations: [loanPolicy()]
      }),
    extractionError("READ_ONLY_REQUIRED")
  );
  assert.throws(
    () => source(new FakePostgresClient(), loanPolicy({ table: 'loan_tape"; DROP SCHEMA public; --' })),
    extractionError("INVALID_POLICY")
  );
  assert.throws(
    () => source(new FakePostgresClient(), loanPolicy({ orderIsUnique: false as true })),
    extractionError("INVALID_POLICY")
  );
  assert.throws(
    () => source(new FakePostgresClient(), loanPolicy({ relationKind: "view" as "table" })),
    extractionError("INVALID_POLICY")
  );

  const ownerClient = new FakePostgresClient();
  ownerClient.ownershipRows = [
    { read_only: true, non_owner: false, non_superuser: true, relation_kind: "r" }
  ];
  const owner = source(ownerClient);
  await assert.rejects(owner.source.extract(request(), limits()), extractionError("READ_ONLY_REQUIRED"));
  assert.ok(ownerClient.calls.some((call) => call.text === "ROLLBACK"));
  assert.deepEqual(ownerClient.releases, [false]);

  const writableClient = new FakePostgresClient();
  writableClient.ownershipRows = [
    { read_only: false, non_owner: true, non_superuser: true, relation_kind: "r" }
  ];
  await assert.rejects(
    source(writableClient).source.extract(request(), limits()),
    extractionError("READ_ONLY_REQUIRED")
  );

  const privilegedClient = new FakePostgresClient();
  privilegedClient.ownershipRows = [
    { read_only: true, non_owner: true, non_superuser: false, relation_kind: "r" }
  ];
  await assert.rejects(
    source(privilegedClient).source.extract(request(), limits()),
    extractionError("READ_ONLY_REQUIRED")
  );

  const bypassClient = new FakePostgresClient();
  bypassClient.ownershipRows = [
    {
      read_only: true,
      non_owner: true,
      non_superuser: true,
      non_bypass_rls: false,
      row_security_enabled: true,
      row_security_forced: true,
      relation_kind: "r"
    }
  ];
  await assert.rejects(
    source(bypassClient).source.extract(request(), limits()),
    extractionError("READ_ONLY_REQUIRED")
  );

  for (const relationKind of ["v", "m"]) {
    const viewClient = new FakePostgresClient();
    viewClient.ownershipRows = [
      {
        read_only: true,
        non_owner: true,
        non_superuser: true,
        non_bypass_rls: true,
        row_security_enabled: false,
        row_security_forced: false,
        relation_kind: relationKind
      }
    ];
    await assert.rejects(
      source(viewClient).source.extract(request(), limits()),
      extractionError("SOURCE_FAILURE")
    );
  }
});

test("row, byte, column, and scalar bounds fail closed inside the transaction", async () => {
  const rowClient = new FakePostgresClient();
  rowClient.rows = [
    ...rowClient.rows,
    { as_of_date: "2025-03-31", loan_id: "L3", outstanding_balance: "200" }
  ];
  await assert.rejects(
    source(rowClient).source.extract(request(), limits({ maximumRows: 2 })),
    extractionError("ROW_LIMIT_EXCEEDED")
  );
  assert.ok(rowClient.calls.some((call) => call.text === "ROLLBACK"));
  assert.deepEqual(rowClient.releases, [false]);

  const byteClient = new FakePostgresClient();
  await assert.rejects(
    source(byteClient).source.extract(
      request(),
      limits({ maximumBytes: 32, maximumCellBytes: 32 })
    ),
    extractionError("BYTE_LIMIT_EXCEEDED")
  );
  const columnContext = source();
  await assert.rejects(
    columnContext.source.extract(request(), limits({ maximumColumns: 2 })),
    extractionError("COLUMN_NOT_ALLOWED")
  );
  assert.equal(columnContext.pool.connectCount, 0);

  const exactClient = new FakePostgresClient();
  exactClient.rows = [{ as_of_date: new Date(), loan_id: "L1", outstanding_balance: "10" }];
  await assert.rejects(
    source(exactClient).source.extract(request(), limits()),
    extractionError("UNSUPPORTED_VALUE")
  );

  const cellClient = new FakePostgresClient();
  cellClient.rows = [
    { as_of_date: "2025-01-31", loan_id: "L".repeat(128), outstanding_balance: "10" }
  ];
  await assert.rejects(
    source(cellClient).source.extract(request(), limits({ maximumCellBytes: 32 })),
    extractionError("CELL_LIMIT_EXCEEDED")
  );
  assert.equal(cellClient.calls.some((call) => call.text.startsWith("FETCH FORWARD ")), false);
});

test("PostgreSQL cursor fetches incrementally under the attested allocation budget", async () => {
  const client = new FakePostgresClient();
  client.rows = Array.from({ length: 600 }, (_, index) => ({
    as_of_date: "2025-02-28",
    loan_id: `L${String(index).padStart(4, "0")}`,
    outstanding_balance: String(index)
  }));
  const result = await source(client).source.extract(
    request(),
    limits({ maximumRows: 1_000, maximumBytes: 100_000 })
  );

  assert.equal(result.rowCount, 600);
  const fetches = client.calls.filter((call) => call.text.startsWith("FETCH FORWARD "));
  assert.ok(fetches.length >= 2);
  for (const fetch of fetches) {
    const count = Number(/^FETCH FORWARD (\d+) FROM/.exec(fetch.text)?.[1]);
    assert.ok(Number.isSafeInteger(count) && count >= 1 && count <= 512);
  }
});

test("AbortSignal cancellation destroys the active PostgreSQL connection", async () => {
  const client = new FakePostgresClient();
  client.dataPromise = new Promise(() => undefined);
  const context = source(client);
  const controller = new AbortController();
  const extraction = context.source.extract(request(), limits(), controller.signal);
  await waitFor(() => client.calls.some((call) => call.text.startsWith("FETCH FORWARD ")));
  controller.abort();
  await assert.rejects(extraction, extractionError("CANCELLED"));
  assert.deepEqual(client.releases, [true]);
  assert.equal(client.calls.some((call) => call.text === "COMMIT"), false);
});

test("total execution timeout destroys a pending connection and query", async () => {
  const client = new FakePostgresClient();
  client.dataPromise = new Promise(() => undefined);
  const context = source(client);
  await assert.rejects(
    context.source.extract(request(), limits({ maximumExecutionMs: 10 })),
    extractionError("TIME_LIMIT_EXCEEDED")
  );
  assert.deepEqual(client.releases, [true]);
});

test("PostgreSQL failures are code-mapped and redact server details", async () => {
  const client = new FakePostgresClient();
  client.dataFailure = Object.assign(
    new Error("password=super-secret relation=private_loans SELECT * FROM private_loans"),
    { code: "XX000" }
  );
  const context = source(client);
  await assert.rejects(context.source.extract(request(), limits()), (error: unknown) => {
    assert.ok(error instanceof SqlSnapshotExtractionError);
    assert.equal(error.code, "SOURCE_FAILURE");
    assert.equal(error.message, "PostgreSQL snapshot source execution failed");
    assert.equal(error.message.includes("super-secret"), false);
    assert.equal(error.message.includes("private_loans"), false);
    return true;
  });
  assert.ok(client.calls.some((call) => call.text === "ROLLBACK"));

  const timeoutClient = new FakePostgresClient();
  timeoutClient.dataFailure = Object.assign(new Error("canceling statement with SQL text"), { code: "57014" });
  await assert.rejects(
    source(timeoutClient).source.extract(request(), limits()),
    extractionError("TIME_LIMIT_EXCEEDED")
  );
});

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let index = 0; index < 100; index += 1) {
    if (predicate()) return;
    await new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 1));
  }
  assert.fail("Timed out waiting for fake PostgreSQL query");
}
