import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  IdentifierSchema,
  canonicalHash,
  canonicalJson,
  type Sha256Hash
} from "../contracts/canonical.js";
import { migrateSqliteComponent, type SqliteComponentMigration } from "../infrastructure/sqlite-component-schema.js";
import {
  parseModernSnapshotExtractionReceiptV1,
  type ModernSnapshotExtractionReceiptV1
} from "../services/modern-snapshot-capture.js";
import type {
  ImmutableRepositoryPort,
  RepositoryPage,
  RepositoryPageRequest,
  RepositoryPutResult,
  RepositoryWriteContext
} from "./ports.js";
import { RepositoryError } from "./ports.js";

export const SQLITE_MODERN_SNAPSHOT_EXTRACTION_RECEIPTS_V1_COMPONENT =
  "abl.modern-snapshot-extraction-receipts-v1" as const;
export const SQLITE_MODERN_SNAPSHOT_EXTRACTION_RECEIPTS_V1_SCHEMA_VERSION = 2 as const;

const RECEIPT_SCHEMA_V1 = `
CREATE TABLE modern_snapshot_extraction_receipts_v1 (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  receipt_id TEXT NOT NULL CHECK (length(receipt_id) BETWEEN 1 AND 128),
  receipt_hash TEXT NOT NULL CHECK (receipt_hash GLOB 'sha256:[0-9a-f]*' AND length(receipt_hash) = 71),
  snapshot_id TEXT NOT NULL CHECK (length(snapshot_id) BETWEEN 1 AND 128),
  delivery_id TEXT NOT NULL CHECK (length(delivery_id) BETWEEN 1 AND 128),
  dataset_id TEXT NOT NULL CHECK (length(dataset_id) BETWEEN 1 AND 128),
  facility_id TEXT NOT NULL CHECK (length(facility_id) BETWEEN 1 AND 128),
  source_contract_id TEXT NOT NULL CHECK (length(source_contract_id) BETWEEN 1 AND 128),
  source_contract_hash TEXT NOT NULL CHECK (source_contract_hash GLOB 'sha256:[0-9a-f]*' AND length(source_contract_hash) = 71),
  scope_binding_id TEXT NOT NULL CHECK (length(scope_binding_id) BETWEEN 1 AND 128),
  scope_binding_hash TEXT NOT NULL CHECK (scope_binding_hash GLOB 'sha256:[0-9a-f]*' AND length(scope_binding_hash) = 71),
  delivery_hash TEXT NOT NULL CHECK (delivery_hash GLOB 'sha256:[0-9a-f]*' AND length(delivery_hash) = 71),
  source_version_hash TEXT NOT NULL CHECK (source_version_hash GLOB 'sha256:[0-9a-f]*' AND length(source_version_hash) = 71),
  captured_by TEXT NOT NULL CHECK (length(captured_by) BETWEEN 1 AND 128),
  persisted_at TEXT NOT NULL,
  record_json TEXT NOT NULL CHECK (json_valid(record_json)),
  PRIMARY KEY (tenant_id, receipt_id),
  UNIQUE (tenant_id, receipt_hash),
  UNIQUE (tenant_id, snapshot_id)
) STRICT;

CREATE INDEX modern_snapshot_extraction_receipts_v1_delivery
  ON modern_snapshot_extraction_receipts_v1 (tenant_id, delivery_id, receipt_id);

CREATE TRIGGER modern_snapshot_extraction_receipts_v1_no_update
BEFORE UPDATE ON modern_snapshot_extraction_receipts_v1
BEGIN SELECT RAISE(ABORT, 'modern snapshot extraction receipt is immutable'); END;

CREATE TRIGGER modern_snapshot_extraction_receipts_v1_no_delete
BEFORE DELETE ON modern_snapshot_extraction_receipts_v1
BEGIN SELECT RAISE(ABORT, 'modern snapshot extraction receipt is immutable'); END;
`;

const RECEIPT_SCHEMA_V2 = `
CREATE TABLE modern_snapshot_extraction_receipts_v1_migration_guard (
  guard INTEGER PRIMARY KEY CHECK (guard = 1)
) STRICT;

CREATE TRIGGER modern_snapshot_extraction_receipts_v1_migration_requires_empty_v1
BEFORE INSERT ON modern_snapshot_extraction_receipts_v1_migration_guard
WHEN EXISTS (SELECT 1 FROM modern_snapshot_extraction_receipts_v1)
BEGIN SELECT RAISE(ABORT, 'nonempty pre-idempotency extraction receipt migration requires an offline reviewed migration'); END;

INSERT INTO modern_snapshot_extraction_receipts_v1_migration_guard (guard) VALUES (1);
DROP TRIGGER modern_snapshot_extraction_receipts_v1_migration_requires_empty_v1;
DROP TABLE modern_snapshot_extraction_receipts_v1_migration_guard;

CREATE TABLE modern_snapshot_extraction_receipts_v1_idempotency (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
  idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  request_hash TEXT NOT NULL CHECK (request_hash GLOB 'sha256:[0-9a-f]*' AND length(request_hash) = 71),
  receipt_id TEXT NOT NULL CHECK (length(receipt_id) BETWEEN 1 AND 128),
  receipt_hash TEXT NOT NULL CHECK (receipt_hash GLOB 'sha256:[0-9a-f]*' AND length(receipt_hash) = 71),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, actor_id, idempotency_key),
  UNIQUE (tenant_id, receipt_id),
  FOREIGN KEY (tenant_id, receipt_id)
    REFERENCES modern_snapshot_extraction_receipts_v1 (tenant_id, receipt_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER modern_snapshot_extraction_receipts_v1_idempotency_no_update
BEFORE UPDATE ON modern_snapshot_extraction_receipts_v1_idempotency
BEGIN SELECT RAISE(ABORT, 'modern snapshot extraction receipt idempotency evidence is immutable'); END;

CREATE TRIGGER modern_snapshot_extraction_receipts_v1_idempotency_no_delete
BEFORE DELETE ON modern_snapshot_extraction_receipts_v1_idempotency
BEGIN SELECT RAISE(ABORT, 'modern snapshot extraction receipt idempotency evidence is immutable'); END;
`;

export const SQLITE_MODERN_SNAPSHOT_EXTRACTION_RECEIPTS_V1_MIGRATIONS = Object.freeze([
  { version: 1, sql: RECEIPT_SCHEMA_V1 },
  { version: 2, sql: RECEIPT_SCHEMA_V2 }
] as const satisfies readonly SqliteComponentMigration[]);

export interface SqliteModernSnapshotExtractionReceiptRepositoryV1Options {
  readonly busyTimeoutMs?: number;
}

interface ReceiptRow {
  readonly tenant_id: string;
  readonly receipt_id: string;
  readonly receipt_hash: string;
  readonly snapshot_id: string;
  readonly delivery_id: string;
  readonly dataset_id: string;
  readonly facility_id: string;
  readonly source_contract_id: string;
  readonly source_contract_hash: string;
  readonly scope_binding_id: string;
  readonly scope_binding_hash: string;
  readonly delivery_hash: string;
  readonly source_version_hash: string;
  readonly captured_by: string;
  readonly persisted_at: string;
  readonly record_json: string;
}

interface IdempotencyRow {
  readonly tenant_id: string;
  readonly actor_id: string;
  readonly idempotency_key: string;
  readonly request_hash: string;
  readonly receipt_id: string;
  readonly receipt_hash: string;
}

interface CursorBody {
  readonly version: 1;
  readonly tenantId: string;
  readonly afterId: string;
}

/**
 * Durable Bronze extraction-receipt evidence for the modern snapshot path.
 * Records and actor-bound idempotency evidence are append-only, tenant-fenced,
 * contract-validated on every read, and exhaustively verified when reopened.
 * This initial release permits empty v1 stores to upgrade, but requires any
 * populated pre-idempotency v1 store to use a separately reviewed offline migration.
 */
export class SqliteModernSnapshotExtractionReceiptRepositoryV1
  implements ImmutableRepositoryPort<ModernSnapshotExtractionReceiptV1>
{
  readonly #database: DatabaseSync;
  #closed = false;

  constructor(
    databasePath: string,
    options: SqliteModernSnapshotExtractionReceiptRepositoryV1Options = {}
  ) {
    const path = requiredPath(databasePath);
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(path, { enableForeignKeyConstraints: true });
    try {
      this.#database.exec(
        `PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${safeInteger(options.busyTimeoutMs ?? 5_000, "busyTimeoutMs", 0, 60_000)};`
      );
      migrateSqliteComponent(this.#database, {
        componentName: SQLITE_MODERN_SNAPSHOT_EXTRACTION_RECEIPTS_V1_COMPONENT,
        supportedVersion: SQLITE_MODERN_SNAPSHOT_EXTRACTION_RECEIPTS_V1_SCHEMA_VERSION,
        migrations: SQLITE_MODERN_SNAPSHOT_EXTRACTION_RECEIPTS_V1_MIGRATIONS,
        unsupportedVersionError: (current, supported) =>
          new RepositoryError(
            "INTEGRITY_FAILURE",
            `Modern extraction receipt schema ${current} is newer than supported version ${supported}`
          )
      });
      this.#verifyStoredIntegrity();
    } catch (error) {
      this.#database.close();
      if (error instanceof RepositoryError) throw error;
      throw integrity("Modern extraction receipt schema initialization failed", error);
    }
  }

  async put(
    recordValue: ModernSnapshotExtractionReceiptV1,
    contextValue: RepositoryWriteContext
  ): Promise<RepositoryPutResult<ModernSnapshotExtractionReceiptV1>> {
    this.#assertOpen();
    const record = verifiedReceipt(recordValue);
    const context = writeContext(contextValue, record);
    const requestHash = canonicalHash({ actorId: context.actorId, record });
    const recordJson = canonicalJson(record);

    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const prior = this.#database
        .prepare(
          `SELECT tenant_id, actor_id, idempotency_key, request_hash, receipt_id, receipt_hash
             FROM modern_snapshot_extraction_receipts_v1_idempotency
            WHERE tenant_id = ? AND actor_id = ? AND idempotency_key = ?`
        )
        .get(context.tenantId, context.actorId, context.idempotencyKey) as IdempotencyRow | undefined;
      if (prior) {
        if (
          prior.request_hash !== requestHash ||
          prior.receipt_id !== record.receiptId ||
          prior.receipt_hash !== record.receiptHash
        ) {
          throw new RepositoryError(
            "IDEMPOTENCY_CONFLICT",
            "Idempotency key was used by this actor for a different extraction receipt write"
          );
        }
        const replay = this.#read(record.tenantId, record.receiptId);
        if (!replay) {
          throw new RepositoryError(
            "INTEGRITY_FAILURE",
            "Extraction receipt idempotency evidence does not resolve"
          );
        }
        this.#database.exec("COMMIT");
        return Object.freeze({ record: replay, replayed: true });
      }
      if (this.#read(record.tenantId, record.receiptId)) {
        throw new RepositoryError("ALREADY_EXISTS", "Immutable extraction receipt already exists");
      }
      this.#insert(record, recordJson);
      this.#database
        .prepare(
          `INSERT INTO modern_snapshot_extraction_receipts_v1_idempotency (
             tenant_id, actor_id, idempotency_key, request_hash, receipt_id,
             receipt_hash, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          context.tenantId,
          context.actorId,
          context.idempotencyKey,
          requestHash,
          record.receiptId,
          record.receiptHash,
          record.knowledge.persistedAt
        );
      const stored = this.#read(record.tenantId, record.receiptId);
      if (!stored) throw new RepositoryError("INTEGRITY_FAILURE", "Extraction receipt was not durable");
      this.#database.exec("COMMIT");
      return Object.freeze({ record: stored, replayed: false });
    } catch (error) {
      rollback(this.#database);
      throw error instanceof RepositoryError ? error : mapConstraint(error);
    }
  }

  async get(
    tenantIdValue: string,
    receiptIdValue: string
  ): Promise<ModernSnapshotExtractionReceiptV1 | undefined> {
    this.#assertOpen();
    return this.#read(identifier(tenantIdValue, "tenant id"), identifier(receiptIdValue, "receipt id"));
  }

  async list(
    tenantIdValue: string,
    page: RepositoryPageRequest = {}
  ): Promise<RepositoryPage<ModernSnapshotExtractionReceiptV1>> {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenant id");
    const limit = safeInteger(page.limit ?? 100, "page limit", 1, 1_000);
    const afterId = page.cursor ? decodeCursor(page.cursor, tenantId) : "";
    const rows = this.#database
      .prepare(
        `SELECT * FROM modern_snapshot_extraction_receipts_v1
          WHERE tenant_id = ? AND receipt_id > ?
          ORDER BY receipt_id
          LIMIT ?`
      )
      .all(tenantId, afterId, limit + 1) as unknown as ReceiptRow[];
    const hasNext = rows.length > limit;
    const selected = hasNext ? rows.slice(0, limit) : rows;
    const items = selected.map((row) => this.#recordFromRow(row));
    const last = selected.at(-1);
    return Object.freeze({
      items: Object.freeze(items),
      nextCursor: hasNext && last
        ? encodeCursor({ version: 1, tenantId, afterId: last.receipt_id })
        : null
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#database.close();
  }

  #insert(record: ModernSnapshotExtractionReceiptV1, recordJson: string): void {
    this.#database
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
        recordJson
      );
  }

  #read(tenantId: string, receiptId: string): ModernSnapshotExtractionReceiptV1 | undefined {
    const row = this.#database
      .prepare(
        `SELECT * FROM modern_snapshot_extraction_receipts_v1
          WHERE tenant_id = ? AND receipt_id = ?`
      )
      .get(tenantId, receiptId) as ReceiptRow | undefined;
    return row ? this.#recordFromRow(row) : undefined;
  }

  #recordFromRow(row: ReceiptRow): ModernSnapshotExtractionReceiptV1 {
    try {
      const raw = JSON.parse(row.record_json) as unknown;
      if (canonicalJson(raw) !== row.record_json) {
        throw new RepositoryError("INTEGRITY_FAILURE", "Stored extraction receipt JSON is not canonical");
      }
      const record = parseModernSnapshotExtractionReceiptV1(raw);
      const expected = indexedReceipt(record);
      const actual = {
        tenant_id: row.tenant_id,
        receipt_id: row.receipt_id,
        receipt_hash: row.receipt_hash,
        snapshot_id: row.snapshot_id,
        delivery_id: row.delivery_id,
        dataset_id: row.dataset_id,
        facility_id: row.facility_id,
        source_contract_id: row.source_contract_id,
        source_contract_hash: row.source_contract_hash,
        scope_binding_id: row.scope_binding_id,
        scope_binding_hash: row.scope_binding_hash,
        delivery_hash: row.delivery_hash,
        source_version_hash: row.source_version_hash,
        captured_by: row.captured_by,
        persisted_at: row.persisted_at
      };
      if (canonicalJson(actual) !== canonicalJson(expected)) {
        throw new RepositoryError(
          "INTEGRITY_FAILURE",
          "Stored extraction receipt indexes do not match canonical content"
        );
      }
      return record;
    } catch (error) {
      if (error instanceof RepositoryError) throw error;
      throw integrity("Stored extraction receipt failed integrity verification", error);
    }
  }

  #verifyStoredIntegrity(): void {
    const rows = this.#database
      .prepare("SELECT * FROM modern_snapshot_extraction_receipts_v1 ORDER BY tenant_id, receipt_id")
      .all() as unknown as ReceiptRow[];
    const records = new Map<string, ModernSnapshotExtractionReceiptV1>();
    for (const row of rows) {
      records.set(`${row.tenant_id}\u0000${row.receipt_id}`, this.#recordFromRow(row));
    }
    const idempotencyRows = this.#database
      .prepare(
        `SELECT tenant_id, actor_id, idempotency_key, request_hash, receipt_id, receipt_hash
           FROM modern_snapshot_extraction_receipts_v1_idempotency
          ORDER BY tenant_id, actor_id, idempotency_key`
      )
      .all() as unknown as IdempotencyRow[];
    const bindings = new Map<string, IdempotencyRow[]>();
    for (const row of idempotencyRows) {
      const key = `${row.tenant_id}\u0000${row.receipt_id}`;
      const record = records.get(key);
      if (
        !record ||
        record.capturedBy !== row.actor_id ||
        record.receiptHash !== row.receipt_hash ||
        canonicalHash({ actorId: row.actor_id, record }) !== row.request_hash
      ) {
        throw new RepositoryError(
          "INTEGRITY_FAILURE",
          "Stored extraction receipt idempotency evidence failed integrity verification"
        );
      }
      bindings.set(key, [...(bindings.get(key) ?? []), row]);
    }
    for (const key of records.keys()) {
      if (bindings.get(key)?.length !== 1) {
        throw new RepositoryError(
          "INTEGRITY_FAILURE",
          "Stored extraction receipt idempotency evidence must contain exactly one actor-bound receipt binding"
        );
      }
    }
  }

  #assertOpen(): void {
    if (this.#closed) throw new RepositoryError("INVALID_ARGUMENT", "Repository is closed");
  }
}

function verifiedReceipt(value: ModernSnapshotExtractionReceiptV1): ModernSnapshotExtractionReceiptV1 {
  try {
    canonicalJson(value);
    return parseModernSnapshotExtractionReceiptV1(value);
  } catch (error) {
    throw integrity("Modern extraction receipt failed contract validation", error);
  }
}

function indexedReceipt(record: ModernSnapshotExtractionReceiptV1) {
  return {
    tenant_id: record.tenantId,
    receipt_id: record.receiptId,
    receipt_hash: record.receiptHash,
    snapshot_id: record.snapshotId,
    delivery_id: record.deliveryId,
    dataset_id: record.datasetId,
    facility_id: record.facilityId,
    source_contract_id: record.sourceContract.sourceContractId,
    source_contract_hash: record.sourceContract.sourceContractHash,
    scope_binding_id: record.scopeBinding.bindingId,
    scope_binding_hash: record.scopeBinding.bindingHash,
    delivery_hash: record.sourceDelivery.deliveryHash,
    source_version_hash: record.sourceDelivery.sourceVersionHash,
    captured_by: record.capturedBy,
    persisted_at: record.knowledge.persistedAt
  };
}

function writeContext(
  context: RepositoryWriteContext,
  record: ModernSnapshotExtractionReceiptV1
): Required<Pick<RepositoryWriteContext, "tenantId" | "actorId" | "idempotencyKey">> {
  if (!context || typeof context !== "object") {
    throw new RepositoryError("INVALID_ARGUMENT", "Repository write context is required");
  }
  const tenantId = identifier(context.tenantId, "context tenant id");
  const actorId = identifier(context.actorId, "context actor id");
  const idempotencyKey = identifier(context.idempotencyKey, "idempotency key");
  if (tenantId !== record.tenantId) {
    throw new RepositoryError("INVALID_ARGUMENT", "Write context tenant does not match receipt tenant");
  }
  if (actorId !== record.capturedBy) {
    throw new RepositoryError("INVALID_ARGUMENT", "Write actor does not match the server-derived capture actor");
  }
  if (context.expectedRevision !== undefined) {
    throw new RepositoryError("INVALID_ARGUMENT", "Immutable extraction receipts do not accept expectedRevision");
  }
  return Object.freeze({ tenantId, actorId, idempotencyKey });
}

function requiredPath(value: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new RepositoryError("INVALID_ARGUMENT", "SQLite database path is required");
  }
  return value === ":memory:" ? value : resolve(value);
}

function identifier(value: string, label: string): string {
  const parsed = IdentifierSchema.safeParse(value);
  if (!parsed.success) throw new RepositoryError("INVALID_ARGUMENT", `${label} is invalid`);
  return parsed.data;
}

function safeInteger(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new RepositoryError("INVALID_ARGUMENT", `${label} must be between ${minimum} and ${maximum}`);
  }
  return value;
}

function encodeCursor(body: CursorBody): string {
  return Buffer.from(canonicalJson({ body, cursorHash: canonicalHash(body) }), "utf8").toString("base64url");
}

function decodeCursor(value: string, tenantId: string): string {
  try {
    const envelope = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as {
      readonly body?: CursorBody;
      readonly cursorHash?: Sha256Hash;
    };
    const body = envelope.body;
    if (!body || envelope.cursorHash !== canonicalHash(body) || body.version !== 1 || body.tenantId !== tenantId) {
      throw new Error("cursor binding mismatch");
    }
    return identifier(body.afterId, "cursor receipt id");
  } catch {
    throw new RepositoryError("INVALID_ARGUMENT", "Repository cursor is invalid or out of scope");
  }
}

function mapConstraint(error: unknown): RepositoryError {
  const message = error instanceof Error ? error.message : String(error);
  if (/UNIQUE constraint failed|PRIMARY KEY/u.test(message)) {
    return new RepositoryError("ALREADY_EXISTS", "Immutable extraction receipt identity already exists");
  }
  return integrity("SQLite rejected immutable extraction receipt evidence", error);
}

function integrity(message: string, cause: unknown): RepositoryError {
  const detail = cause instanceof Error ? `: ${cause.message}` : "";
  return new RepositoryError("INTEGRITY_FAILURE", `${message}${detail}`);
}

function rollback(database: DatabaseSync): void {
  try {
    database.exec("ROLLBACK");
  } catch {
    // Preserve the operation error when SQLite has already closed the transaction.
  }
}
