import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { z } from "zod";

import {
  IdentifierSchema,
  canonicalJson,
  parseWithSchema
} from "../contracts/canonical.js";
import {
  parseCapturedSourceSectionArtifactMetadataV1,
  type CapturedSourceSectionArtifactMetadataV1
} from "../contracts/captured-source-section-artifact-v1.js";
import { migrateSqliteComponent, type SqliteComponentMigration } from "../infrastructure/sqlite-component-schema.js";

export const SQLITE_CAPTURED_SOURCE_MATERIAL_COMPONENT = "abl.captured-source-material-v1" as const;
export const SQLITE_CAPTURED_SOURCE_MATERIAL_SCHEMA_VERSION = 1 as const;

const SCHEMA = `
CREATE TABLE captured_source_section_material_v1 (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  snapshot_id TEXT NOT NULL CHECK (length(snapshot_id) BETWEEN 1 AND 128),
  section_id TEXT NOT NULL CHECK (length(section_id) BETWEEN 1 AND 128),
  snapshot_hash TEXT NOT NULL CHECK (length(snapshot_hash) = 71 AND snapshot_hash GLOB 'sha256:*'),
  artifact_hash TEXT NOT NULL CHECK (length(artifact_hash) = 71 AND artifact_hash GLOB 'sha256:*'),
  artifact_id TEXT NOT NULL CHECK (length(artifact_id) = 64 AND artifact_id GLOB '[0-9a-f]*'),
  metadata_hash TEXT NOT NULL CHECK (length(metadata_hash) = 71 AND metadata_hash GLOB 'sha256:*'),
  stored_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json)),
  PRIMARY KEY (tenant_id, snapshot_id, section_id),
  UNIQUE (tenant_id, metadata_hash),
  UNIQUE (tenant_id, artifact_id)
) STRICT;

CREATE INDEX captured_source_section_material_v1_snapshot
  ON captured_source_section_material_v1 (tenant_id, snapshot_id, section_id);

CREATE TRIGGER captured_source_section_material_v1_no_update
BEFORE UPDATE ON captured_source_section_material_v1
BEGIN SELECT RAISE(ABORT, 'captured source material is immutable'); END;
CREATE TRIGGER captured_source_section_material_v1_no_delete
BEFORE DELETE ON captured_source_section_material_v1
BEGIN SELECT RAISE(ABORT, 'captured source material is immutable'); END;
`;

export const SQLITE_CAPTURED_SOURCE_MATERIAL_MIGRATIONS = Object.freeze([
  { version: 1, sql: SCHEMA }
] as const satisfies readonly SqliteComponentMigration[]);

const GetSchema = z.object({
  tenantId: IdentifierSchema,
  snapshotId: IdentifierSchema,
  sectionId: IdentifierSchema
}).strict();

export interface CapturedSourceMaterialStoreV1 {
  put(metadata: CapturedSourceSectionArtifactMetadataV1): Promise<{
    readonly metadata: CapturedSourceSectionArtifactMetadataV1;
    readonly replayed: boolean;
  }>;
  get(input: {
    readonly tenantId: string;
    readonly snapshotId: string;
    readonly sectionId: string;
  }): Promise<CapturedSourceSectionArtifactMetadataV1 | undefined>;
}

export type CapturedSourceMaterialStoreErrorCode =
  | "INVALID_ARGUMENT"
  | "CONFLICT"
  | "INTEGRITY_FAILURE"
  | "STORE_CLOSED";

export class CapturedSourceMaterialStoreError extends Error {
  constructor(readonly code: CapturedSourceMaterialStoreErrorCode, message: string) {
    super(message);
    this.name = "CapturedSourceMaterialStoreError";
  }
}

interface Row {
  readonly tenant_id: string;
  readonly snapshot_id: string;
  readonly section_id: string;
  readonly snapshot_hash: string;
  readonly artifact_hash: string;
  readonly artifact_id: string;
  readonly metadata_hash: string;
  readonly stored_at: string;
  readonly metadata_json: string;
}

/** Immutable metadata companion for tenant-scoped encrypted captured-source artifacts. */
export class SqliteCapturedSourceMaterialStoreV1 implements CapturedSourceMaterialStoreV1 {
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
        componentName: SQLITE_CAPTURED_SOURCE_MATERIAL_COMPONENT,
        supportedVersion: SQLITE_CAPTURED_SOURCE_MATERIAL_SCHEMA_VERSION,
        migrations: SQLITE_CAPTURED_SOURCE_MATERIAL_MIGRATIONS,
        unsupportedVersionError: (current, supported) =>
          integrity(`Captured source material schema ${current} is newer than supported ${supported}`)
      });
      this.#verifyIntegrity();
    } catch (error) {
      this.#database.close();
      if (error instanceof CapturedSourceMaterialStoreError) throw error;
      throw integrity("Captured source material store initialization failed");
    }
  }

  async put(value: CapturedSourceSectionArtifactMetadataV1): Promise<{
    readonly metadata: CapturedSourceSectionArtifactMetadataV1;
    readonly replayed: boolean;
  }> {
    this.#assertOpen();
    const metadata = parsedMetadata(value);
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const existing = this.#row(metadata.tenantId, metadata.snapshotId, metadata.sectionId);
      if (existing) {
        const replay = rowMetadata(existing);
        if (canonicalJson(replay) !== canonicalJson(metadata)) {
          throw new CapturedSourceMaterialStoreError(
            "CONFLICT",
            "Captured section identity is already bound to different immutable material"
          );
        }
        this.#database.exec("COMMIT");
        return Object.freeze({ metadata: replay, replayed: true });
      }
      this.#database.prepare(
        `INSERT INTO captured_source_section_material_v1 (
          tenant_id, snapshot_id, section_id, snapshot_hash, artifact_hash,
          artifact_id, metadata_hash, stored_at, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        metadata.tenantId,
        metadata.snapshotId,
        metadata.sectionId,
        metadata.snapshotHash,
        metadata.artifactHash,
        metadata.artifactId,
        metadata.metadataHash,
        metadata.storedAt,
        canonicalJson(metadata)
      );
      this.#database.exec("COMMIT");
      return Object.freeze({ metadata, replayed: false });
    } catch (error) {
      rollback(this.#database);
      if (error instanceof CapturedSourceMaterialStoreError) throw error;
      throw integrity("Captured source material transaction failed");
    }
  }

  async get(inputValue: {
    readonly tenantId: string;
    readonly snapshotId: string;
    readonly sectionId: string;
  }): Promise<CapturedSourceSectionArtifactMetadataV1 | undefined> {
    this.#assertOpen();
    const input = parsed(GetSchema, inputValue, "captured source material lookup");
    const row = this.#row(input.tenantId, input.snapshotId, input.sectionId);
    return row ? rowMetadata(row) : undefined;
  }

  close(): void {
    if (!this.#closed) {
      this.#database.close();
      this.#closed = true;
    }
  }

  #row(tenantId: string, snapshotId: string, sectionId: string): Row | undefined {
    return this.#database.prepare(
      `SELECT * FROM captured_source_section_material_v1
        WHERE tenant_id = ? AND snapshot_id = ? AND section_id = ?`
    ).get(tenantId, snapshotId, sectionId) as Row | undefined;
  }

  #verifyIntegrity(): void {
    const rows = this.#database.prepare(
      "SELECT * FROM captured_source_section_material_v1 ORDER BY tenant_id, snapshot_id, section_id"
    ).all() as unknown as Row[];
    for (const row of rows) rowMetadata(row);
  }

  #assertOpen(): void {
    if (this.#closed) throw new CapturedSourceMaterialStoreError("STORE_CLOSED", "Captured source material store is closed");
  }
}

function rowMetadata(row: Row): CapturedSourceSectionArtifactMetadataV1 {
  let metadata: CapturedSourceSectionArtifactMetadataV1;
  try {
    const raw = JSON.parse(row.metadata_json) as unknown;
    if (canonicalJson(raw) !== row.metadata_json) throw new Error("noncanonical");
    metadata = parseCapturedSourceSectionArtifactMetadataV1(raw);
  } catch {
    throw integrity("Stored captured source metadata failed canonical validation");
  }
  if (
    metadata.tenantId !== row.tenant_id ||
    metadata.snapshotId !== row.snapshot_id ||
    metadata.sectionId !== row.section_id ||
    metadata.snapshotHash !== row.snapshot_hash ||
    metadata.artifactHash !== row.artifact_hash ||
    metadata.artifactId !== row.artifact_id ||
    metadata.metadataHash !== row.metadata_hash ||
    metadata.storedAt !== row.stored_at
  ) {
    throw integrity("Captured source material indexes do not match canonical metadata");
  }
  return metadata;
}

function parsedMetadata(value: CapturedSourceSectionArtifactMetadataV1): CapturedSourceSectionArtifactMetadataV1 {
  try {
    return parseCapturedSourceSectionArtifactMetadataV1(value);
  } catch {
    throw new CapturedSourceMaterialStoreError("INVALID_ARGUMENT", "Captured source metadata failed canonical validation");
  }
}

function parsed<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  try {
    return parseWithSchema(schema, value, label);
  } catch {
    throw new CapturedSourceMaterialStoreError("INVALID_ARGUMENT", `${label} failed strict validation`);
  }
}

function requiredPath(value: string): string {
  if (value === ":memory:") return value;
  if (!value.trim()) throw new CapturedSourceMaterialStoreError("INVALID_ARGUMENT", "Captured source material database path is required");
  return resolve(value);
}

function integer(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new CapturedSourceMaterialStoreError("INVALID_ARGUMENT", `${label} is outside allowed bounds`);
  }
  return value;
}

function rollback(database: DatabaseSync): void {
  try {
    database.exec("ROLLBACK");
  } catch {
    // Preserve the original error.
  }
}

function integrity(message: string): CapturedSourceMaterialStoreError {
  return new CapturedSourceMaterialStoreError("INTEGRITY_FAILURE", message);
}
