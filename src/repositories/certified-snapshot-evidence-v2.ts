import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  IdentifierSchema,
  canonicalHash,
  canonicalJson,
  type Sha256Hash
} from "../contracts/canonical.js";
import {
  parseCertifiedSnapshotEvidenceRecordV2,
  type CertifiedSnapshotEvidenceRecordV2
} from "../contracts/certified-snapshot-evidence-v2.js";
import { migrateSqliteComponent, type SqliteComponentMigration } from "../infrastructure/sqlite-component-schema.js";
import type {
  ImmutableRepositoryPort,
  RepositoryPage,
  RepositoryPageRequest,
  RepositoryPutResult,
  RepositoryWriteContext
} from "./ports.js";
import { RepositoryError } from "./ports.js";

/**
 * Separate component from the V1 surveillance repository.  A V2 record retains
 * its exact V1 evidence envelope, but this component does not require a V1
 * table to be co-located: migration can therefore run without cross-database
 * foreign keys or a mutable V1 backfill.
 */
export const SQLITE_CERTIFIED_SNAPSHOT_EVIDENCE_V2_COMPONENT =
  "abl.certified-snapshot-evidence-v2" as const;
export const SQLITE_CERTIFIED_SNAPSHOT_EVIDENCE_V2_SCHEMA_VERSION = 1 as const;

const SQLITE_CERTIFIED_SNAPSHOT_EVIDENCE_V2_SCHEMA = `
CREATE TABLE certified_snapshot_evidence_v2 (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  record_id TEXT NOT NULL CHECK (length(record_id) BETWEEN 1 AND 128),
  record_hash TEXT NOT NULL CHECK (record_hash GLOB 'sha256:[0-9a-f]*' AND length(record_hash) = 71),
  v1_evidence_hash TEXT NOT NULL CHECK (v1_evidence_hash GLOB 'sha256:[0-9a-f]*' AND length(v1_evidence_hash) = 71),
  snapshot_id TEXT NOT NULL CHECK (length(snapshot_id) BETWEEN 1 AND 128),
  snapshot_hash TEXT NOT NULL CHECK (snapshot_hash GLOB 'sha256:[0-9a-f]*' AND length(snapshot_hash) = 71),
  attempt_hash TEXT NOT NULL CHECK (attempt_hash GLOB 'sha256:[0-9a-f]*' AND length(attempt_hash) = 71),
  control_definition_version_id TEXT NOT NULL CHECK (length(control_definition_version_id) BETWEEN 1 AND 128),
  control_version_hash TEXT NOT NULL CHECK (control_version_hash GLOB 'sha256:[0-9a-f]*' AND length(control_version_hash) = 71),
  scope_binding_id TEXT NOT NULL CHECK (length(scope_binding_id) BETWEEN 1 AND 128),
  scope_binding_hash TEXT NOT NULL CHECK (scope_binding_hash GLOB 'sha256:[0-9a-f]*' AND length(scope_binding_hash) = 71),
  mapping_definition_version_id TEXT NOT NULL CHECK (length(mapping_definition_version_id) BETWEEN 1 AND 128),
  runtime_bundle_id TEXT NOT NULL CHECK (length(runtime_bundle_id) BETWEEN 1 AND 128),
  runtime_bundle_hash TEXT NOT NULL CHECK (runtime_bundle_hash GLOB 'sha256:[0-9a-f]*' AND length(runtime_bundle_hash) = 71),
  certified_at TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  record_json TEXT NOT NULL CHECK (json_valid(record_json)),
  PRIMARY KEY (tenant_id, record_id),
  UNIQUE (tenant_id, record_hash),
  UNIQUE (tenant_id, v1_evidence_hash)
) STRICT;

CREATE INDEX certified_snapshot_evidence_v2_tenant_snapshot
  ON certified_snapshot_evidence_v2 (tenant_id, snapshot_id, certified_at, record_id);

CREATE TRIGGER certified_snapshot_evidence_v2_no_update
BEFORE UPDATE ON certified_snapshot_evidence_v2
BEGIN SELECT RAISE(ABORT, 'certified snapshot evidence v2 is immutable'); END;
CREATE TRIGGER certified_snapshot_evidence_v2_no_delete
BEFORE DELETE ON certified_snapshot_evidence_v2
BEGIN SELECT RAISE(ABORT, 'certified snapshot evidence v2 is immutable'); END;

CREATE TABLE certified_snapshot_evidence_v2_idempotency (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
  idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  request_hash TEXT NOT NULL CHECK (request_hash GLOB 'sha256:[0-9a-f]*' AND length(request_hash) = 71),
  record_id TEXT NOT NULL CHECK (length(record_id) BETWEEN 1 AND 128),
  record_hash TEXT NOT NULL CHECK (record_hash GLOB 'sha256:[0-9a-f]*' AND length(record_hash) = 71),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, actor_id, idempotency_key),
  FOREIGN KEY (tenant_id, record_id)
    REFERENCES certified_snapshot_evidence_v2 (tenant_id, record_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER certified_snapshot_evidence_v2_idempotency_no_update
BEFORE UPDATE ON certified_snapshot_evidence_v2_idempotency
BEGIN SELECT RAISE(ABORT, 'certified snapshot evidence v2 idempotency receipts are immutable'); END;
CREATE TRIGGER certified_snapshot_evidence_v2_idempotency_no_delete
BEFORE DELETE ON certified_snapshot_evidence_v2_idempotency
BEGIN SELECT RAISE(ABORT, 'certified snapshot evidence v2 idempotency receipts are immutable'); END;
`;

export const SQLITE_CERTIFIED_SNAPSHOT_EVIDENCE_V2_MIGRATIONS = Object.freeze([
  { version: 1, sql: SQLITE_CERTIFIED_SNAPSHOT_EVIDENCE_V2_SCHEMA }
] as const satisfies readonly SqliteComponentMigration[]);

export interface SqliteCertifiedSnapshotEvidenceV2RepositoryOptions {
  readonly busyTimeoutMs?: number;
}

interface EvidenceRow {
  readonly tenant_id: string;
  readonly record_id: string;
  readonly record_hash: string;
  readonly v1_evidence_hash: string;
  readonly snapshot_id: string;
  readonly snapshot_hash: string;
  readonly attempt_hash: string;
  readonly control_definition_version_id: string;
  readonly control_version_hash: string;
  readonly scope_binding_id: string;
  readonly scope_binding_hash: string;
  readonly mapping_definition_version_id: string;
  readonly runtime_bundle_id: string;
  readonly runtime_bundle_hash: string;
  readonly certified_at: string;
  readonly recorded_at: string;
  readonly record_json: string;
}

interface ReceiptRow {
  readonly request_hash: string;
  readonly record_id: string;
  readonly record_hash: string;
}

interface CursorBody {
  readonly version: 1;
  readonly tenantId: string;
  readonly afterId: string;
}

/**
 * Tenant-fenced, append-only V2 evidence storage.  Idempotency is intentionally
 * actor-bound: a retry by the same actor returns the exact record, whereas a
 * second actor cannot claim an existing immutable certification manifest.
 */
export class SqliteCertifiedSnapshotEvidenceV2Repository
  implements ImmutableRepositoryPort<CertifiedSnapshotEvidenceRecordV2>
{
  readonly #database: DatabaseSync;
  #closed = false;

  constructor(databasePath: string, options: SqliteCertifiedSnapshotEvidenceV2RepositoryOptions = {}) {
    const path = requiredPath(databasePath);
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(path, { enableForeignKeyConstraints: true });
    try {
      this.#database.exec(
        `PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${safeInteger(options.busyTimeoutMs ?? 5_000, "busyTimeoutMs", 0, 60_000)};`
      );
      migrateSqliteComponent(this.#database, {
        componentName: SQLITE_CERTIFIED_SNAPSHOT_EVIDENCE_V2_COMPONENT,
        supportedVersion: SQLITE_CERTIFIED_SNAPSHOT_EVIDENCE_V2_SCHEMA_VERSION,
        migrations: SQLITE_CERTIFIED_SNAPSHOT_EVIDENCE_V2_MIGRATIONS,
        unsupportedVersionError: (current, supported) =>
          new RepositoryError(
            "INTEGRITY_FAILURE",
            `Certified snapshot evidence V2 schema ${current} is newer than supported version ${supported}`
          )
      });
    } catch (error) {
      this.#database.close();
      if (error instanceof RepositoryError) throw error;
      throw integrity("Certified snapshot evidence V2 schema initialization failed", error);
    }
  }

  async put(
    recordValue: CertifiedSnapshotEvidenceRecordV2,
    contextValue: RepositoryWriteContext
  ): Promise<RepositoryPutResult<CertifiedSnapshotEvidenceRecordV2>> {
    this.#assertOpen();
    let record: CertifiedSnapshotEvidenceRecordV2;
    try {
      canonicalJson(recordValue);
      record = parseCertifiedSnapshotEvidenceRecordV2(recordValue);
    } catch (error) {
      throw integrity("Certified snapshot evidence V2 failed contract validation", error);
    }
    const context = writeContext(contextValue, record.tenantId);
    const recordId = record.certificationAttempt.certificationManifestId;
    const requestHash = canonicalHash({ actorId: context.actorId, record });
    const json = canonicalJson(record);

    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const receipt = this.#database
        .prepare(
          `SELECT request_hash, record_id, record_hash
             FROM certified_snapshot_evidence_v2_idempotency
            WHERE tenant_id = ? AND actor_id = ? AND idempotency_key = ?`
        )
        .get(context.tenantId, context.actorId, context.idempotencyKey) as ReceiptRow | undefined;
      if (receipt) {
        if (
          receipt.request_hash !== requestHash ||
          receipt.record_id !== recordId ||
          receipt.record_hash !== record.evidenceHash
        ) {
          throw new RepositoryError(
            "IDEMPOTENCY_CONFLICT",
            "Idempotency key was used by this actor for a different immutable evidence write"
          );
        }
        const replay = this.#read(record.tenantId, recordId);
        if (!replay) {
          throw new RepositoryError("INTEGRITY_FAILURE", "Idempotency receipt does not resolve to V2 evidence");
        }
        this.#database.exec("COMMIT");
        return Object.freeze({ record: replay, replayed: true });
      }
      if (this.#read(record.tenantId, recordId)) {
        throw new RepositoryError("ALREADY_EXISTS", "Immutable V2 certification evidence already exists");
      }
      this.#insert(record, json);
      this.#database
        .prepare(
          `INSERT INTO certified_snapshot_evidence_v2_idempotency (
             tenant_id, actor_id, idempotency_key, request_hash, record_id,
             record_hash, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          context.tenantId,
          context.actorId,
          context.idempotencyKey,
          requestHash,
          recordId,
          record.evidenceHash,
          record.recordedAt
        );
      const stored = this.#read(record.tenantId, recordId);
      if (!stored) throw new RepositoryError("INTEGRITY_FAILURE", "Immutable V2 evidence was not durable");
      this.#database.exec("COMMIT");
      return Object.freeze({ record: stored, replayed: false });
    } catch (error) {
      rollback(this.#database);
      throw error instanceof RepositoryError ? error : mapConstraint(error);
    }
  }

  async get(tenantIdValue: string, recordIdValue: string): Promise<CertifiedSnapshotEvidenceRecordV2 | undefined> {
    this.#assertOpen();
    return this.#read(identifier(tenantIdValue, "tenant id"), identifier(recordIdValue, "record id"));
  }

  async list(
    tenantIdValue: string,
    page: RepositoryPageRequest = {}
  ): Promise<RepositoryPage<CertifiedSnapshotEvidenceRecordV2>> {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenant id");
    const limit = safeInteger(page.limit ?? 100, "page limit", 1, 1_000);
    const afterId = page.cursor ? decodeCursor(page.cursor, tenantId) : "";
    const rows = this.#database
      .prepare(
        `SELECT * FROM certified_snapshot_evidence_v2
          WHERE tenant_id = ? AND record_id > ?
          ORDER BY record_id
          LIMIT ?`
      )
      .all(tenantId, afterId, limit + 1) as unknown as EvidenceRow[];
    const hasNext = rows.length > limit;
    const selected = hasNext ? rows.slice(0, limit) : rows;
    const items = selected.map((row) => this.#recordFromRow(row));
    const last = selected.at(-1);
    return Object.freeze({
      items: Object.freeze(items),
      nextCursor: hasNext && last ? encodeCursor({ version: 1, tenantId, afterId: last.record_id }) : null
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#database.close();
  }

  #insert(record: CertifiedSnapshotEvidenceRecordV2, json: string): void {
    const governance = record.governance;
    this.#database
      .prepare(
        `INSERT INTO certified_snapshot_evidence_v2 (
           tenant_id, record_id, record_hash, v1_evidence_hash, snapshot_id,
           snapshot_hash, attempt_hash, control_definition_version_id,
           control_version_hash, scope_binding_id, scope_binding_hash,
           mapping_definition_version_id, runtime_bundle_id, runtime_bundle_hash,
           certified_at, recorded_at, record_json
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        record.tenantId,
        record.certificationAttempt.certificationManifestId,
        record.evidenceHash,
        record.v1Evidence.evidenceHash,
        record.certificationAttempt.snapshotId,
        record.certificationAttempt.snapshotHash,
        record.certificationAttempt.attemptHash,
        governance.control.reference.definitionVersionId,
        governance.control.reference.versionHash,
        governance.scopeBinding.raw.bindingId,
        governance.scopeBinding.raw.bindingHash,
        governance.mapping.execution.definitionVersionId,
        governance.runtime.runtimeBundleId,
        governance.runtime.runtimeBundleHash,
        record.certificationAttempt.certifiedAt,
        record.recordedAt,
        json
      );
  }

  #read(tenantId: string, recordId: string): CertifiedSnapshotEvidenceRecordV2 | undefined {
    const row = this.#database
      .prepare(
        `SELECT * FROM certified_snapshot_evidence_v2
          WHERE tenant_id = ? AND record_id = ?`
      )
      .get(tenantId, recordId) as EvidenceRow | undefined;
    return row ? this.#recordFromRow(row) : undefined;
  }

  #recordFromRow(row: EvidenceRow): CertifiedSnapshotEvidenceRecordV2 {
    try {
      const raw = JSON.parse(row.record_json) as unknown;
      if (canonicalJson(raw) !== row.record_json) {
        throw new RepositoryError("INTEGRITY_FAILURE", "Stored V2 evidence JSON is not canonical");
      }
      const record = parseCertifiedSnapshotEvidenceRecordV2(raw);
      const expected = {
        tenant_id: record.tenantId,
        record_id: record.certificationAttempt.certificationManifestId,
        record_hash: record.evidenceHash,
        v1_evidence_hash: record.v1Evidence.evidenceHash,
        snapshot_id: record.certificationAttempt.snapshotId,
        snapshot_hash: record.certificationAttempt.snapshotHash,
        attempt_hash: record.certificationAttempt.attemptHash,
        control_definition_version_id: record.governance.control.reference.definitionVersionId,
        control_version_hash: record.governance.control.reference.versionHash,
        scope_binding_id: record.governance.scopeBinding.raw.bindingId,
        scope_binding_hash: record.governance.scopeBinding.raw.bindingHash,
        mapping_definition_version_id: record.governance.mapping.execution.definitionVersionId,
        runtime_bundle_id: record.governance.runtime.runtimeBundleId,
        runtime_bundle_hash: record.governance.runtime.runtimeBundleHash,
        certified_at: record.certificationAttempt.certifiedAt,
        recorded_at: record.recordedAt
      };
      const actual = {
        tenant_id: row.tenant_id,
        record_id: row.record_id,
        record_hash: row.record_hash,
        v1_evidence_hash: row.v1_evidence_hash,
        snapshot_id: row.snapshot_id,
        snapshot_hash: row.snapshot_hash,
        attempt_hash: row.attempt_hash,
        control_definition_version_id: row.control_definition_version_id,
        control_version_hash: row.control_version_hash,
        scope_binding_id: row.scope_binding_id,
        scope_binding_hash: row.scope_binding_hash,
        mapping_definition_version_id: row.mapping_definition_version_id,
        runtime_bundle_id: row.runtime_bundle_id,
        runtime_bundle_hash: row.runtime_bundle_hash,
        certified_at: row.certified_at,
        recorded_at: row.recorded_at
      };
      if (canonicalJson(actual) !== canonicalJson(expected)) {
        throw new RepositoryError("INTEGRITY_FAILURE", "Stored V2 evidence indexes do not match canonical content");
      }
      return record;
    } catch (error) {
      if (error instanceof RepositoryError) throw error;
      throw integrity("Stored V2 certification evidence failed integrity verification", error);
    }
  }

  #assertOpen(): void {
    if (this.#closed) throw new RepositoryError("INVALID_ARGUMENT", "Repository is closed");
  }
}

function writeContext(
  context: RepositoryWriteContext,
  recordTenantId: string
): Required<Pick<RepositoryWriteContext, "tenantId" | "actorId" | "idempotencyKey">> {
  if (!context || typeof context !== "object") {
    throw new RepositoryError("INVALID_ARGUMENT", "Repository write context is required");
  }
  const tenantId = identifier(context.tenantId, "context tenant id");
  const actorId = identifier(context.actorId, "context actor id");
  const idempotencyKey = identifier(context.idempotencyKey, "idempotency key");
  if (tenantId !== recordTenantId) {
    throw new RepositoryError("INVALID_ARGUMENT", "Write context tenant does not match record tenant");
  }
  if (context.expectedRevision !== undefined) {
    throw new RepositoryError("INVALID_ARGUMENT", "Immutable V2 evidence does not accept expectedRevision");
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
    return identifier(body.afterId, "cursor record id");
  } catch {
    throw new RepositoryError("INVALID_ARGUMENT", "Repository cursor is invalid or out of scope");
  }
}

function mapConstraint(error: unknown): RepositoryError {
  const message = error instanceof Error ? error.message : String(error);
  if (/UNIQUE constraint failed|PRIMARY KEY/u.test(message)) {
    return new RepositoryError("ALREADY_EXISTS", "Immutable V2 certification evidence identity already exists");
  }
  return integrity("SQLite rejected immutable V2 certification evidence", error);
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
