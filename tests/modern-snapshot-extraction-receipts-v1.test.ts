import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, test } from "node:test";

import { canonicalHash, canonicalJson } from "../src/contracts/canonical.js";
import { migrateSqliteComponent } from "../src/infrastructure/sqlite-component-schema.js";
import { RepositoryError } from "../src/repositories/ports.js";
import {
  SQLITE_MODERN_SNAPSHOT_EXTRACTION_RECEIPTS_V1_COMPONENT,
  SQLITE_MODERN_SNAPSHOT_EXTRACTION_RECEIPTS_V1_MIGRATIONS,
  SqliteModernSnapshotExtractionReceiptRepositoryV1
} from "../src/repositories/modern-snapshot-extraction-receipts-v1.js";
import {
  modernSnapshotExtractionReceiptIdV1,
  parseModernSnapshotExtractionReceiptV1,
  type ModernSnapshotExtractionReceiptV1
} from "../src/services/modern-snapshot-capture.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("extraction receipts are tenant-fenced, actor-bound, idempotent, immutable, paged, and reopen-safe", async () => {
  const path = databasePath();
  const repository = new SqliteModernSnapshotExtractionReceiptRepositoryV1(path);
  const first = receipt("a");
  const second = receipt("b");
  const context = {
    tenantId: first.tenantId,
    actorId: first.capturedBy,
    idempotencyKey: "capture-a"
  };

  assert.equal((await repository.put(first, context)).replayed, false);
  assert.equal((await repository.put(first, context)).replayed, true);
  await repository.put(second, { ...context, idempotencyKey: "capture-b" });

  assert.equal(await repository.get("tenant-b", first.receiptId), undefined);
  assert.deepEqual((await repository.list("tenant-b")).items, []);
  const page = await repository.list("tenant-a", { limit: 1 });
  assert.equal(page.items.length, 1);
  assert.ok(page.nextCursor);
  const next = await repository.list("tenant-a", { cursor: page.nextCursor ?? undefined });
  assert.equal(next.items.length, 1);
  await assert.rejects(
    repository.list("tenant-b", { cursor: page.nextCursor ?? undefined }),
    (error: unknown) => repositoryCode(error, "INVALID_ARGUMENT")
  );

  await assert.rejects(
    repository.put(second, context),
    (error: unknown) => repositoryCode(error, "IDEMPOTENCY_CONFLICT")
  );
  await assert.rejects(
    repository.put(first, { ...context, actorId: "different-operator", idempotencyKey: "capture-other" }),
    (error: unknown) => repositoryCode(error, "INVALID_ARGUMENT")
  );
  await assert.rejects(
    repository.put(first, { ...context, idempotencyKey: "capture-duplicate" }),
    (error: unknown) => repositoryCode(error, "ALREADY_EXISTS")
  );

  const database = new DatabaseSync(path);
  assert.throws(
    () => database.prepare("UPDATE modern_snapshot_extraction_receipts_v1 SET captured_by = ?").run("attacker"),
    /immutable/u
  );
  assert.throws(
    () => database.prepare("DELETE FROM modern_snapshot_extraction_receipts_v1_idempotency").run(),
    /immutable/u
  );
  database.close();
  repository.close();

  const reopened = new SqliteModernSnapshotExtractionReceiptRepositoryV1(path);
  assert.equal((await reopened.get(first.tenantId, first.receiptId))?.receiptHash, first.receiptHash);
  reopened.close();
});

test("extraction receipt repository fails closed on content or index tampering at reopen", async () => {
  const path = databasePath();
  const repository = new SqliteModernSnapshotExtractionReceiptRepositoryV1(path);
  const stored = receipt("tamper");
  await repository.put(stored, {
    tenantId: stored.tenantId,
    actorId: stored.capturedBy,
    idempotencyKey: "capture-tamper"
  });
  repository.close();

  const database = new DatabaseSync(path);
  database.exec("DROP TRIGGER modern_snapshot_extraction_receipts_v1_no_update");
  database
    .prepare("UPDATE modern_snapshot_extraction_receipts_v1 SET delivery_id = ? WHERE tenant_id = ?")
    .run("substituted-delivery", stored.tenantId);
  database.exec(`
    CREATE TRIGGER modern_snapshot_extraction_receipts_v1_no_update
    BEFORE UPDATE ON modern_snapshot_extraction_receipts_v1
    BEGIN SELECT RAISE(ABORT, 'modern snapshot extraction receipt is immutable'); END;
  `);
  database.close();

  assert.throws(
    () => new SqliteModernSnapshotExtractionReceiptRepositoryV1(path),
    (error: unknown) => {
      assert.ok(repositoryCode(error, "INTEGRITY_FAILURE"));
      assert.match((error as Error).message, /indexes do not match canonical content/u);
      return true;
    }
  );
});

test("extraction receipt repository fails closed when v2 idempotency evidence is deleted", async () => {
  const path = databasePath();
  const repository = new SqliteModernSnapshotExtractionReceiptRepositoryV1(path);
  const stored = receipt("deleted-idempotency");
  await repository.put(stored, {
    tenantId: stored.tenantId,
    actorId: stored.capturedBy,
    idempotencyKey: "capture-deleted-idempotency"
  });
  repository.close();

  const database = new DatabaseSync(path);
  database.exec("DROP TRIGGER modern_snapshot_extraction_receipts_v1_idempotency_no_delete");
  database
    .prepare(
      `DELETE FROM modern_snapshot_extraction_receipts_v1_idempotency
        WHERE tenant_id = ? AND receipt_id = ?`
    )
    .run(stored.tenantId, stored.receiptId);
  database.exec(`
    CREATE TABLE attacker_legacy_receipt_marker (
      tenant_id TEXT NOT NULL,
      receipt_id TEXT NOT NULL,
      receipt_hash TEXT NOT NULL,
      PRIMARY KEY (tenant_id, receipt_id)
    ) STRICT;
  `);
  database
    .prepare(
      `INSERT INTO attacker_legacy_receipt_marker (tenant_id, receipt_id, receipt_hash)
       VALUES (?, ?, ?)`
    )
    .run(stored.tenantId, stored.receiptId, stored.receiptHash);
  database.exec(`
    CREATE TRIGGER modern_snapshot_extraction_receipts_v1_idempotency_no_delete
    BEFORE DELETE ON modern_snapshot_extraction_receipts_v1_idempotency
    BEGIN SELECT RAISE(ABORT, 'modern snapshot extraction receipt idempotency evidence is immutable'); END;
  `);
  database.close();

  assert.throws(
    () => new SqliteModernSnapshotExtractionReceiptRepositoryV1(path),
    (error: unknown) => {
      assert.ok(repositoryCode(error, "INTEGRITY_FAILURE"));
      assert.match((error as Error).message, /idempotency evidence/u);
      return true;
    }
  );
});

test("extraction receipt repository migrates and reopens an empty version-one component", async () => {
  const path = databasePath();
  const database = new DatabaseSync(path, { enableForeignKeyConstraints: true });
  migrateSqliteComponent(database, {
    componentName: SQLITE_MODERN_SNAPSHOT_EXTRACTION_RECEIPTS_V1_COMPONENT,
    supportedVersion: 1,
    migrations: [SQLITE_MODERN_SNAPSHOT_EXTRACTION_RECEIPTS_V1_MIGRATIONS[0]!],
    unsupportedVersionError: () => new Error("unexpected version")
  });
  database.close();

  const repository = new SqliteModernSnapshotExtractionReceiptRepositoryV1(path);
  const verifier = new DatabaseSync(path);
  const currentVersion = verifier
    .prepare("SELECT schema_version FROM component_schema_versions WHERE component_name = ?")
    .get(SQLITE_MODERN_SNAPSHOT_EXTRACTION_RECEIPTS_V1_COMPONENT) as { schema_version: number };
  assert.equal(currentVersion.schema_version, 2);
  verifier.close();

  repository.close();
  const reopened = new SqliteModernSnapshotExtractionReceiptRepositoryV1(path);
  const current = receipt("current");
  assert.equal(
    (await reopened.put(current, {
      tenantId: current.tenantId,
      actorId: current.capturedBy,
      idempotencyKey: "capture-current"
    })).replayed,
    false
  );
  reopened.close();

  const verifiedReopen = new SqliteModernSnapshotExtractionReceiptRepositoryV1(path);
  assert.equal((await verifiedReopen.get(current.tenantId, current.receiptId))?.receiptHash, current.receiptHash);
  verifiedReopen.close();
});

test("extraction receipt repository rejects nonempty pre-idempotency version-one migration", () => {
  const path = databasePath();
  const legacy = receipt("legacy");
  const database = new DatabaseSync(path, { enableForeignKeyConstraints: true });
  migrateSqliteComponent(database, {
    componentName: SQLITE_MODERN_SNAPSHOT_EXTRACTION_RECEIPTS_V1_COMPONENT,
    supportedVersion: 1,
    migrations: [SQLITE_MODERN_SNAPSHOT_EXTRACTION_RECEIPTS_V1_MIGRATIONS[0]!],
    unsupportedVersionError: () => new Error("unexpected version")
  });
  insertLegacyReceipt(database, legacy);
  database.close();

  assert.throws(
    () => new SqliteModernSnapshotExtractionReceiptRepositoryV1(path),
    (error: unknown) => {
      assert.ok(repositoryCode(error, "INTEGRITY_FAILURE"));
      assert.match((error as Error).message, /offline reviewed migration/u);
      return true;
    }
  );

  const verifier = new DatabaseSync(path);
  const currentVersion = verifier
    .prepare("SELECT schema_version FROM component_schema_versions WHERE component_name = ?")
    .get(SQLITE_MODERN_SNAPSHOT_EXTRACTION_RECEIPTS_V1_COMPONENT) as { schema_version: number };
  assert.equal(currentVersion.schema_version, 1);
  const idempotencyTable = verifier
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
    .get("modern_snapshot_extraction_receipts_v1_idempotency");
  assert.equal(idempotencyTable, undefined);
  verifier.close();
});

function insertLegacyReceipt(database: DatabaseSync, record: ModernSnapshotExtractionReceiptV1): void {
  database
    .prepare(
      `INSERT INTO modern_snapshot_extraction_receipts_v1 (
         tenant_id, receipt_id, receipt_hash, snapshot_id, delivery_id,
         dataset_id, facility_id, source_contract_id, source_contract_hash,
         scope_binding_id, scope_binding_hash, delivery_hash,
         source_version_hash, captured_by, persisted_at, record_json
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      record.tenantId,
      record.receiptId,
      record.receiptHash,
      record.snapshotId,
      record.deliveryId,
      record.datasetId,
      record.facilityId,
      record.sourceContract.sourceContractId,
      record.sourceContract.sourceContractHash,
      record.scopeBinding.bindingId,
      record.scopeBinding.bindingHash,
      record.sourceDelivery.deliveryHash,
      record.sourceDelivery.sourceVersionHash,
      record.capturedBy,
      record.knowledge.persistedAt,
      canonicalJson(record)
    );
}

function receipt(suffix: string): ModernSnapshotExtractionReceiptV1 {
  const snapshotId = `snapshot-${suffix}`;
  const deliveryId = `delivery-${suffix}`;
  const contentHash = canonicalHash(`content-${suffix}`);
  const body = {
    contractVersion: 1 as const,
    tenantId: "tenant-a",
    receiptId: modernSnapshotExtractionReceiptIdV1(snapshotId),
    snapshotId,
    deliveryId,
    datasetId: "loan-dataset",
    facilityId: "facility-a",
    sourceContract: {
      sourceContractId: "loan-source",
      revision: 1,
      sourceContractHash: canonicalHash("loan-source-v1")
    },
    scopeBinding: {
      bindingId: "facility-a-binding",
      revision: 1,
      bindingHash: canonicalHash("facility-a-binding-v1")
    },
    sourceDelivery: {
      deliveryId,
      deliveryRevision: 1,
      deliveryHash: canonicalHash(`delivery-evidence-${suffix}`),
      locatorHash: canonicalHash(`delivery-locator-${suffix}`),
      sourceVersionHash: canonicalHash(`source-version-${suffix}`)
    },
    delivery: {
      mode: "managed_upload" as const,
      format: "xlsx" as const,
      logicalName: `loan-tape-${suffix}.xlsx`
    },
    sourceLocator: `governed-delivery:${deliveryId}`,
    asOfDate: "2026-07-31",
    knowledge: {
      sourceObservedAt: "2026-08-01T09:00:00.000Z",
      extractedAt: "2026-08-01T09:01:00.000Z",
      receivedAt: "2026-08-01T09:02:00.000Z",
      persistedAt: "2026-08-01T09:03:00.000Z"
    },
    watermark: { mode: "none" as const },
    hashes: {
      contentHash,
      schemaHash: canonicalHash(`schema-${suffix}`),
      profileHash: canonicalHash(`profile-${suffix}`),
      catalogHash: canonicalHash(`catalog-${suffix}`),
      parserHash: canonicalHash("xlsx-safe-v1")
    },
    rowCount: 1,
    columnCount: 2,
    byteCount: 100,
    elapsedMs: 25,
    sections: [{
      sectionId: "loans",
      required: true,
      present: true,
      rowCount: 1,
      contentHash,
      schemaHash: canonicalHash(`loans-schema-${suffix}`),
      controlPopulationHash: canonicalHash([{ asset_number: `loan-${suffix}`, balance: "100.00" }])
    }],
    correction: { kind: "original" as const },
    capturedBy: "capture-operator"
  };
  return parseModernSnapshotExtractionReceiptV1({ ...body, receiptHash: canonicalHash(body) });
}

function databasePath(): string {
  const directory = mkdtempSync(join(tmpdir(), "abl-modern-extraction-receipts-"));
  directories.push(directory);
  return join(directory, "receipts.sqlite");
}

function repositoryCode(error: unknown, code: RepositoryError["code"]): boolean {
  assert.ok(error instanceof RepositoryError);
  assert.equal(error.code, code);
  return true;
}
