import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  canonicalJson,
  createSnapshotCertificationAttemptV1,
  parseSnapshotCertificationAttemptV1,
  parseWithSchema,
  type SnapshotCertificationAttemptV1
} from "../contracts/index.js";
import { migrateSqliteComponent, type SqliteComponentMigration } from "../infrastructure/sqlite-component-schema.js";

import { z } from "zod";

export const SQLITE_SNAPSHOT_CERTIFICATION_ATTEMPTS_COMPONENT =
  "abl.snapshot-certification-attempts" as const;
export const SQLITE_SNAPSHOT_CERTIFICATION_ATTEMPTS_SCHEMA_VERSION = 1 as const;

const SQLITE_SNAPSHOT_CERTIFICATION_ATTEMPTS_SCHEMA = `
CREATE TABLE snapshot_certification_attempts_v1 (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  certification_manifest_id TEXT NOT NULL CHECK (length(certification_manifest_id) BETWEEN 1 AND 128),
  snapshot_id TEXT NOT NULL CHECK (length(snapshot_id) BETWEEN 1 AND 128),
  snapshot_hash TEXT NOT NULL CHECK (length(snapshot_hash) = 71 AND snapshot_hash GLOB 'sha256:*'),
  actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
  request_hash TEXT NOT NULL CHECK (length(request_hash) = 71 AND request_hash GLOB 'sha256:*'),
  certified_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  attempt_hash TEXT NOT NULL CHECK (length(attempt_hash) = 71 AND attempt_hash GLOB 'sha256:*'),
  attempt_json TEXT NOT NULL CHECK (json_valid(attempt_json)),
  PRIMARY KEY (tenant_id, certification_manifest_id),
  UNIQUE (tenant_id, attempt_hash)
) STRICT;

CREATE TRIGGER snapshot_certification_attempts_v1_no_update
BEFORE UPDATE ON snapshot_certification_attempts_v1
BEGIN SELECT RAISE(ABORT, 'snapshot certification attempts are immutable'); END;
CREATE TRIGGER snapshot_certification_attempts_v1_no_delete
BEFORE DELETE ON snapshot_certification_attempts_v1
BEGIN SELECT RAISE(ABORT, 'snapshot certification attempts are immutable'); END;
`;

export const SQLITE_SNAPSHOT_CERTIFICATION_ATTEMPTS_MIGRATIONS = Object.freeze([
  { version: 1, sql: SQLITE_SNAPSHOT_CERTIFICATION_ATTEMPTS_SCHEMA }
] as const satisfies readonly SqliteComponentMigration[]);

const StartInputSchema = z
  .object({
    tenantId: IdentifierSchema,
    certificationManifestId: IdentifierSchema,
    snapshotId: IdentifierSchema,
    snapshotHash: Sha256HashSchema,
    actorId: IdentifierSchema,
    requestHash: Sha256HashSchema,
    certifiedAt: IsoTimestampSchema,
    createdAt: IsoTimestampSchema
  })
  .strict();

export interface StartSnapshotCertificationAttemptV1 {
  readonly tenantId: string;
  readonly certificationManifestId: string;
  readonly snapshotId: string;
  readonly snapshotHash: string;
  readonly actorId: string;
  readonly requestHash: string;
  readonly certifiedAt: string;
  readonly createdAt: string;
}

export interface SnapshotCertificationAttemptStoreV1 {
  startOrReplay(input: StartSnapshotCertificationAttemptV1): Promise<{
    readonly attempt: SnapshotCertificationAttemptV1;
    readonly replayed: boolean;
  }>;
}

export type SnapshotCertificationAttemptStoreErrorCode =
  | "INVALID_ARGUMENT"
  | "IDEMPOTENCY_CONFLICT"
  | "INTEGRITY_FAILURE"
  | "STORE_CLOSED";

export class SnapshotCertificationAttemptStoreError extends Error {
  constructor(readonly code: SnapshotCertificationAttemptStoreErrorCode, message: string) {
    super(message);
    this.name = "SnapshotCertificationAttemptStoreError";
  }
}

interface AttemptRow {
  readonly tenant_id: string;
  readonly certification_manifest_id: string;
  readonly snapshot_id: string;
  readonly snapshot_hash: string;
  readonly actor_id: string;
  readonly request_hash: string;
  readonly certified_at: string;
  readonly created_at: string;
  readonly attempt_hash: string;
  readonly attempt_json: string;
}

export class SqliteSnapshotCertificationAttemptStoreV1 implements SnapshotCertificationAttemptStoreV1 {
  readonly #database: DatabaseSync;
  #closed = false;

  constructor(databasePath: string, busyTimeoutMs = 5_000) {
    const path = requiredPath(databasePath);
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(path, { enableForeignKeyConstraints: true });
    try {
      this.#database.exec(
        `PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${integer(busyTimeoutMs, "busyTimeoutMs", 0, 60_000)};`
      );
      migrateSqliteComponent(this.#database, {
        componentName: SQLITE_SNAPSHOT_CERTIFICATION_ATTEMPTS_COMPONENT,
        supportedVersion: SQLITE_SNAPSHOT_CERTIFICATION_ATTEMPTS_SCHEMA_VERSION,
        migrations: SQLITE_SNAPSHOT_CERTIFICATION_ATTEMPTS_MIGRATIONS,
        unsupportedVersionError: (current, supported) =>
          integrity(`Snapshot-certification attempts schema ${current} is newer than supported ${supported}`)
      });
      this.#verifyIntegrity();
    } catch (error) {
      this.#database.close();
      if (error instanceof SnapshotCertificationAttemptStoreError) throw error;
      throw integrity("Snapshot-certification attempt store initialization failed");
    }
  }

  async startOrReplay(inputValue: StartSnapshotCertificationAttemptV1): Promise<{
    readonly attempt: SnapshotCertificationAttemptV1;
    readonly replayed: boolean;
  }> {
    this.#assertOpen();
    const input = parsed(StartInputSchema, inputValue, "attempt input");
    const attempt = createSnapshotCertificationAttemptV1({
      contractVersion: 1,
      ...input
    });
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const existing = this.#row(input.tenantId, input.certificationManifestId);
      if (existing !== undefined) {
        const parsedExisting = rowAttempt(existing);
        if (
          parsedExisting.snapshotId !== attempt.snapshotId ||
          parsedExisting.snapshotHash !== attempt.snapshotHash ||
          parsedExisting.actorId !== attempt.actorId ||
          parsedExisting.requestHash !== attempt.requestHash
        ) {
          throw new SnapshotCertificationAttemptStoreError(
            "IDEMPOTENCY_CONFLICT",
            "Certification manifest is already bound to a different immutable attempt"
          );
        }
        this.#database.exec("COMMIT");
        return Object.freeze({ attempt: parsedExisting, replayed: true });
      }
      this.#database
        .prepare(
          `INSERT INTO snapshot_certification_attempts_v1 (
            tenant_id, certification_manifest_id, snapshot_id, snapshot_hash, actor_id,
            request_hash, certified_at, created_at, attempt_hash, attempt_json
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          attempt.tenantId,
          attempt.certificationManifestId,
          attempt.snapshotId,
          attempt.snapshotHash,
          attempt.actorId,
          attempt.requestHash,
          attempt.certifiedAt,
          attempt.createdAt,
          attempt.attemptHash,
          canonicalJson(attempt)
        );
      this.#database.exec("COMMIT");
      return Object.freeze({ attempt, replayed: false });
    } catch (error) {
      try {
        this.#database.exec("ROLLBACK");
      } catch {
        // Preserve the original failure.
      }
      if (error instanceof SnapshotCertificationAttemptStoreError) throw error;
      throw integrity("Snapshot-certification attempt transaction failed");
    }
  }

  close(): void {
    if (!this.#closed) {
      this.#database.close();
      this.#closed = true;
    }
  }

  #row(tenantId: string, certificationManifestId: string): AttemptRow | undefined {
    return this.#database
      .prepare(
        `SELECT * FROM snapshot_certification_attempts_v1
         WHERE tenant_id = ? AND certification_manifest_id = ?`
      )
      .get(tenantId, certificationManifestId) as AttemptRow | undefined;
  }

  #verifyIntegrity(): void {
    const rows = this.#database
      .prepare("SELECT * FROM snapshot_certification_attempts_v1 ORDER BY tenant_id, certification_manifest_id")
      .all() as unknown as AttemptRow[];
    for (const row of rows) rowAttempt(row);
  }

  #assertOpen(): void {
    if (this.#closed) throw new SnapshotCertificationAttemptStoreError("STORE_CLOSED", "Store is closed");
  }
}

function rowAttempt(row: AttemptRow): SnapshotCertificationAttemptV1 {
  let value: SnapshotCertificationAttemptV1;
  try {
    value = parseSnapshotCertificationAttemptV1(JSON.parse(row.attempt_json));
  } catch {
    throw integrity("Stored certification attempt failed canonical validation");
  }
  if (
    value.tenantId !== row.tenant_id ||
    value.certificationManifestId !== row.certification_manifest_id ||
    value.snapshotId !== row.snapshot_id ||
    value.snapshotHash !== row.snapshot_hash ||
    value.actorId !== row.actor_id ||
    value.requestHash !== row.request_hash ||
    value.certifiedAt !== row.certified_at ||
    value.createdAt !== row.created_at ||
    value.attemptHash !== row.attempt_hash
  ) {
    throw integrity("Stored certification-attempt columns do not match canonical evidence");
  }
  return value;
}

function parsed<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  try {
    return parseWithSchema(schema, value, label);
  } catch {
    throw new SnapshotCertificationAttemptStoreError("INVALID_ARGUMENT", `${label} failed strict validation`);
  }
}

function integer(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new SnapshotCertificationAttemptStoreError("INVALID_ARGUMENT", `${label} is outside allowed bounds`);
  }
  return value;
}

function requiredPath(value: string): string {
  if (value === ":memory:") return value;
  if (typeof value !== "string" || value.length === 0) {
    throw new SnapshotCertificationAttemptStoreError("INVALID_ARGUMENT", "databasePath is required");
  }
  return resolve(value);
}

function integrity(message: string): SnapshotCertificationAttemptStoreError {
  return new SnapshotCertificationAttemptStoreError("INTEGRITY_FAILURE", message);
}
