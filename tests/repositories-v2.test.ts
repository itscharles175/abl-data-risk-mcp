import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  canonicalHash,
  createSourceContractV1,
  type SourceContractV1
} from "../src/contracts/index.js";
import {
  InMemoryFoundationRepositories,
  RepositoryError,
  type DefinitionRepositoryRecordV1,
  type RepositoryWriteContext
} from "../src/repositories/index.js";

const HASH_A = `sha256:${"a".repeat(64)}` as const;
const AT = "2026-08-12T12:00:00.000Z";

test("immutable repository ports are tenant scoped and exactly idempotent", async () => {
  const repositories = new InMemoryFoundationRepositories();
  const source = sourceContract("tenant-a", "source-1");
  const context = writeContext("tenant-a", "create-source");

  const created = await repositories.control.sourceContracts.put(source, context);
  const replay = await repositories.control.sourceContracts.put(source, context);
  assert.equal(created.replayed, false);
  assert.equal(replay.replayed, true);
  assert.deepEqual(replay.record, created.record);
  assert.equal(await repositories.control.sourceContracts.get("tenant-b", "source-1@1"), undefined);

  await assert.rejects(
    repositories.control.sourceContracts.put(
      sourceContract("tenant-a", "source-2"),
      context
    ),
    (error: unknown) => repositoryError(error, "IDEMPOTENCY_CONFLICT")
  );
  await assert.rejects(
    repositories.control.sourceContracts.put(source, writeContext("tenant-b", "cross-tenant")),
    (error: unknown) => repositoryError(error, "INVALID_ARGUMENT")
  );
});

test("immutable repository pagination is deterministic and cursors are collection bound", async () => {
  const repositories = new InMemoryFoundationRepositories();
  for (const id of ["source-c", "source-a", "source-b"]) {
    await repositories.control.sourceContracts.put(
      sourceContract("tenant-a", id),
      writeContext("tenant-a", `create-${id}`)
    );
  }
  const first = await repositories.control.sourceContracts.list("tenant-a", { limit: 2 });
  assert.deepEqual(first.items.map((record) => record.sourceContractId), ["source-a", "source-b"]);
  assert.ok(first.nextCursor);
  const second = await repositories.control.sourceContracts.list("tenant-a", {
    limit: 2,
    cursor: first.nextCursor ?? undefined
  });
  assert.deepEqual(second.items.map((record) => record.sourceContractId), ["source-c"]);
  assert.equal(second.nextCursor, null);

  await assert.rejects(
    repositories.definitions.records.listCurrent("tenant-a", { cursor: first.nextCursor ?? undefined }),
    (error: unknown) => repositoryError(error, "INVALID_ARGUMENT")
  );
});

test("versioned ports enforce optimistic concurrency and preserve complete history", async () => {
  const repositories = new InMemoryFoundationRepositories();
  const first = definition(1, "proposed");
  await repositories.definitions.records.put(first, {
    ...writeContext("tenant-a", "definition-v1"),
    expectedRevision: 0
  });
  const second = definition(2, "active");
  await repositories.definitions.records.put(second, {
    ...writeContext("tenant-a", "definition-v2"),
    expectedRevision: 1
  });

  assert.deepEqual(
    (await repositories.definitions.records.listHistory("tenant-a", "metric-1")).map(
      (record) => [record.revision, record.status]
    ),
    [
      [1, "proposed"],
      [2, "active"]
    ]
  );
  assert.equal(
    (await repositories.definitions.records.getRevision("tenant-a", "metric-1", 1))?.status,
    "proposed"
  );
  assert.equal(
    (await repositories.definitions.records.getCurrent("tenant-a", "metric-1"))?.status,
    "active"
  );

  await assert.rejects(
    repositories.definitions.records.put(
      { ...second, revision: 3, status: "retired" },
      { ...writeContext("tenant-a", "stale-write"), expectedRevision: 1 }
    ),
    (error: unknown) => repositoryError(error, "CONCURRENCY_CONFLICT")
  );
  assert.equal(
    (await repositories.definitions.records.getCurrent("tenant-a", "metric-1"))?.revision,
    2
  );
});

test("artifact repository verifies exact bytes and returns defensive copies", async () => {
  const repositories = new InMemoryFoundationRepositories();
  const bytes = Buffer.from("immutable evidence", "utf8");
  const contentHash = `sha256:${createHash("sha256").update(bytes).digest("hex")}` as const;
  const command = {
    metadata: {
      contractVersion: 1 as const,
      tenantId: "tenant-a",
      artifactId: "artifact-1",
      kind: "runtime_bundle",
      mediaType: "application/json",
      contentHash,
      byteLength: bytes.byteLength,
      keyId: "kms-key-1",
      uri: "memory://tenant-a/artifact-1",
      createdAt: AT
    },
    bytes
  };
  const result = await repositories.artifacts.put(command, writeContext("tenant-a", "put-artifact"));
  assert.equal(result.replayed, false);
  const read = await repositories.artifacts.read("tenant-a", "artifact-1");
  assert.deepEqual([...read!], [...bytes]);
  read![0] = 0;
  assert.deepEqual([...(await repositories.artifacts.read("tenant-a", "artifact-1"))!], [...bytes]);
  assert.equal(await repositories.artifacts.read("tenant-b", "artifact-1"), undefined);

  await assert.rejects(
    repositories.artifacts.put(
      { ...command, metadata: { ...command.metadata, contentHash: HASH_A } },
      writeContext("tenant-a", "bad-artifact")
    ),
    (error: unknown) => repositoryError(error, "INTEGRITY_FAILURE")
  );
});

test("audit repository is append-only, tenant-scoped, idempotent, and hash chained", async () => {
  const repositories = new InMemoryFoundationRepositories();
  const firstCommand = {
    contractVersion: 1 as const,
    tenantId: "tenant-a",
    eventId: "event-1",
    eventType: "mapping.proposed",
    entityType: "mapping_spec",
    entityId: "mapping-1",
    actorId: "maker-1",
    details: { mappingHash: HASH_A },
    occurredAt: AT
  };
  const firstContext = writeContext("tenant-a", "audit-1", "maker-1");
  const first = await repositories.audit.append(firstCommand, firstContext);
  const replay = await repositories.audit.append(firstCommand, firstContext);
  assert.equal(first.record.sequence, 1);
  assert.equal(first.record.previousEventHash, null);
  assert.equal(replay.replayed, true);

  const second = await repositories.audit.append(
    {
      ...firstCommand,
      eventId: "event-2",
      eventType: "mapping.approved",
      actorId: "reviewer-1"
    },
    writeContext("tenant-a", "audit-2", "reviewer-1")
  );
  assert.equal(second.record.sequence, 2);
  assert.equal(second.record.previousEventHash, first.record.eventHash);
  assert.deepEqual(await repositories.audit.list("tenant-b"), []);
});

test("all foundation repository families are available behind one aggregate", () => {
  const repositories = new InMemoryFoundationRepositories();
  assert.ok(repositories.control.sourceContracts);
  assert.ok(repositories.definitions.records);
  assert.ok(repositories.memberships.records);
  assert.ok(repositories.jobs.records);
  assert.ok(repositories.alerts.records);
  assert.ok(repositories.security.records);
  assert.ok(repositories.artifacts);
  assert.ok(repositories.audit);
});

function sourceContract(tenantId: string, sourceContractId: string): SourceContractV1 {
  return createSourceContractV1({
    contractVersion: 1,
    tenantId,
    sourceContractId,
    sourceKey: sourceContractId,
    revision: 1,
    status: "active",
    delivery: {
      mode: "managed_upload",
      format: "parquet",
      logicalName: `${sourceContractId}.parquet`
    },
    schemaPolicy: {
      columns: [{ sourceName: "loan_id", ordinal: 0, nativeType: "string", nullable: false, required: true }],
      allowUnknownColumns: false,
      requireStableOrdinals: true
    },
    parserPolicy: {
      format: "parquet",
      parserId: "parquet-v1",
      parserVersion: "1.0.0",
      optionsHash: HASH_A,
      exactDecimalMode: "string",
      timezone: "UTC",
      rejectSchemaMerging: true
    },
    extractionPolicy: {
      mode: "full",
      readOnly: true,
      maximumRows: 100,
      maximumColumns: 10,
      maximumBytes: 1_000_000,
      timeoutMs: 1_000,
      cursorRows: 100
    },
    sections: [{ sectionId: "loans", required: true, selector: "loans", keyFields: ["loan_id"] }],
    effectiveFrom: "2026-01-01",
    createdBy: "maker-1",
    createdAt: AT,
    approvedBy: "reviewer-1",
    approvedAt: AT
  });
}

function definition(
  revision: number,
  status: DefinitionRepositoryRecordV1["status"]
): DefinitionRepositoryRecordV1 {
  const document = { grain: "loan", numerator: "outstanding_balance" } as const;
  return {
    contractVersion: 1,
    tenantId: "tenant-a",
    definitionId: "metric-1",
    definitionKey: "total-outstanding",
    kind: "metric_definition",
    version: `1.0.${revision - 1}`,
    status,
    revision,
    document,
    documentHash: canonicalHash(document),
    effectiveFrom: "2026-01-01"
  };
}

function writeContext(
  tenantId: string,
  idempotencyKey: string,
  actorId = "operator-1"
): RepositoryWriteContext {
  return { tenantId, actorId, idempotencyKey };
}

function repositoryError(error: unknown, code: RepositoryError["code"]): boolean {
  return error instanceof RepositoryError && error.code === code;
}
