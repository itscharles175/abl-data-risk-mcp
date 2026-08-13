import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  IdentifierSchema,
  canonicalHash,
  canonicalJson,
  parseDatasetSnapshotV2,
  type DatasetSnapshotV2,
  type Sha256Hash
} from "../contracts/index.js";
import {
  parseCertifiedSnapshotEvidenceRecordV1,
  type CertifiedSnapshotEvidenceRecordV1
} from "../contracts/certified-snapshot-evidence-v1.js";
import { migrateSqliteComponent, type SqliteComponentMigration } from "../infrastructure/sqlite-component-schema.js";
import type {
  ImmutableRepositoryPort,
  RepositoryPage,
  RepositoryPageRequest,
  RepositoryPutResult,
  RepositoryWriteContext,
  TenantRecord
} from "./ports.js";
import { RepositoryError } from "./ports.js";

export const SQLITE_SURVEILLANCE_EVIDENCE_COMPONENT = "abl.surveillance-evidence" as const;
export const SQLITE_SURVEILLANCE_EVIDENCE_SCHEMA_VERSION = 1 as const;

const SQLITE_SURVEILLANCE_EVIDENCE_SCHEMA = `
CREATE TABLE surveillance_dataset_snapshots_v2 (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  record_id TEXT NOT NULL CHECK (length(record_id) BETWEEN 1 AND 128),
  record_hash TEXT NOT NULL CHECK (record_hash GLOB 'sha256:[0-9a-f]*' AND length(record_hash) = 71),
  source_contract_id TEXT NOT NULL CHECK (length(source_contract_id) BETWEEN 1 AND 128),
  source_contract_revision INTEGER NOT NULL CHECK (source_contract_revision > 0),
  source_contract_hash TEXT NOT NULL CHECK (source_contract_hash GLOB 'sha256:[0-9a-f]*' AND length(source_contract_hash) = 71),
  as_of_date TEXT NOT NULL CHECK (length(as_of_date) = 10),
  correction_kind TEXT NOT NULL CHECK (correction_kind IN ('original', 'correction')),
  corrects_snapshot_id TEXT,
  corrects_snapshot_hash TEXT,
  correction_sequence INTEGER,
  persisted_at TEXT NOT NULL,
  record_json TEXT NOT NULL CHECK (json_valid(record_json)),
  PRIMARY KEY (tenant_id, record_id),
  CHECK (
    (correction_kind = 'original' AND corrects_snapshot_id IS NULL AND corrects_snapshot_hash IS NULL AND correction_sequence IS NULL)
    OR
    (correction_kind = 'correction' AND corrects_snapshot_id IS NOT NULL AND corrects_snapshot_hash IS NOT NULL AND correction_sequence > 0)
  ),
  FOREIGN KEY (tenant_id, corrects_snapshot_id)
    REFERENCES surveillance_dataset_snapshots_v2 (tenant_id, record_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX surveillance_dataset_snapshots_v2_single_replacement
  ON surveillance_dataset_snapshots_v2 (tenant_id, corrects_snapshot_id)
  WHERE corrects_snapshot_id IS NOT NULL;

CREATE UNIQUE INDEX surveillance_dataset_snapshots_v2_single_original
  ON surveillance_dataset_snapshots_v2 (
    tenant_id, source_contract_id, source_contract_revision, source_contract_hash, as_of_date
  )
  WHERE correction_kind = 'original';

CREATE INDEX surveillance_dataset_snapshots_v2_tenant_order
  ON surveillance_dataset_snapshots_v2 (tenant_id, record_id);

CREATE TRIGGER surveillance_dataset_snapshots_v2_no_update
BEFORE UPDATE ON surveillance_dataset_snapshots_v2
BEGIN
  SELECT RAISE(ABORT, 'surveillance dataset snapshots are immutable');
END;

CREATE TRIGGER surveillance_dataset_snapshots_v2_no_delete
BEFORE DELETE ON surveillance_dataset_snapshots_v2
BEGIN
  SELECT RAISE(ABORT, 'surveillance dataset snapshots are immutable');
END;

CREATE TABLE surveillance_certified_snapshot_evidence_v1 (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  record_id TEXT NOT NULL CHECK (length(record_id) BETWEEN 1 AND 128),
  record_hash TEXT NOT NULL CHECK (record_hash GLOB 'sha256:[0-9a-f]*' AND length(record_hash) = 71),
  snapshot_id TEXT NOT NULL CHECK (length(snapshot_id) BETWEEN 1 AND 128),
  snapshot_hash TEXT NOT NULL CHECK (snapshot_hash GLOB 'sha256:[0-9a-f]*' AND length(snapshot_hash) = 71),
  population_hash TEXT NOT NULL CHECK (population_hash GLOB 'sha256:[0-9a-f]*' AND length(population_hash) = 71),
  mapping_application_id TEXT NOT NULL CHECK (length(mapping_application_id) BETWEEN 1 AND 128),
  mapping_application_hash TEXT NOT NULL CHECK (mapping_application_hash GLOB 'sha256:[0-9a-f]*' AND length(mapping_application_hash) = 71),
  mapping_spec_id TEXT NOT NULL CHECK (length(mapping_spec_id) BETWEEN 1 AND 128),
  mapping_spec_hash TEXT NOT NULL CHECK (mapping_spec_hash GLOB 'sha256:[0-9a-f]*' AND length(mapping_spec_hash) = 71),
  normalized_artifact_id TEXT NOT NULL CHECK (length(normalized_artifact_id) BETWEEN 1 AND 128),
  normalized_artifact_content_hash TEXT NOT NULL CHECK (normalized_artifact_content_hash GLOB 'sha256:[0-9a-f]*' AND length(normalized_artifact_content_hash) = 71),
  normalized_artifact_created_at TEXT NOT NULL,
  certified_at TEXT NOT NULL,
  record_json TEXT NOT NULL CHECK (json_valid(record_json)),
  PRIMARY KEY (tenant_id, record_id),
  UNIQUE (tenant_id, record_hash),
  FOREIGN KEY (tenant_id, snapshot_id)
    REFERENCES surveillance_dataset_snapshots_v2 (tenant_id, record_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE INDEX surveillance_certified_snapshot_evidence_v1_tenant_order
  ON surveillance_certified_snapshot_evidence_v1 (tenant_id, record_id);

CREATE TRIGGER surveillance_certified_snapshot_evidence_v1_no_update
BEFORE UPDATE ON surveillance_certified_snapshot_evidence_v1
BEGIN
  SELECT RAISE(ABORT, 'certified snapshot evidence is immutable');
END;

CREATE TRIGGER surveillance_certified_snapshot_evidence_v1_no_delete
BEFORE DELETE ON surveillance_certified_snapshot_evidence_v1
BEGIN
  SELECT RAISE(ABORT, 'certified snapshot evidence is immutable');
END;

CREATE TABLE surveillance_evidence_idempotency (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  repository_kind TEXT NOT NULL CHECK (repository_kind IN ('dataset_snapshot_v2', 'certified_snapshot_evidence_v1')),
  actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
  idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  request_hash TEXT NOT NULL CHECK (request_hash GLOB 'sha256:[0-9a-f]*' AND length(request_hash) = 71),
  record_id TEXT NOT NULL CHECK (length(record_id) BETWEEN 1 AND 128),
  record_hash TEXT NOT NULL CHECK (record_hash GLOB 'sha256:[0-9a-f]*' AND length(record_hash) = 71),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, repository_kind, actor_id, idempotency_key)
) STRICT;

CREATE TRIGGER surveillance_evidence_idempotency_no_update
BEFORE UPDATE ON surveillance_evidence_idempotency
BEGIN
  SELECT RAISE(ABORT, 'surveillance evidence idempotency receipts are immutable');
END;

CREATE TRIGGER surveillance_evidence_idempotency_no_delete
BEFORE DELETE ON surveillance_evidence_idempotency
BEGIN
  SELECT RAISE(ABORT, 'surveillance evidence idempotency receipts are immutable');
END;
`;

export const SQLITE_SURVEILLANCE_EVIDENCE_MIGRATIONS = Object.freeze([
  { version: 1, sql: SQLITE_SURVEILLANCE_EVIDENCE_SCHEMA }
] as const satisfies readonly SqliteComponentMigration[]);

export interface SqliteSurveillanceRepositoryOptions {
  readonly busyTimeoutMs?: number;
}

type RepositoryKind = "dataset_snapshot_v2" | "certified_snapshot_evidence_v1";

interface StoredRecordRow {
  readonly tenant_id: string;
  readonly record_id: string;
  readonly record_hash: string;
  readonly record_json: string;
}

interface ReceiptRow {
  readonly request_hash: string;
  readonly record_id: string;
  readonly record_hash: string;
}

interface CursorBody {
  readonly version: 1;
  readonly repositoryKind: RepositoryKind;
  readonly tenantId: string;
  readonly afterId: string;
}

interface ImmutableSqliteConfiguration<T extends TenantRecord> {
  readonly repositoryKind: RepositoryKind;
  readonly tableName: string;
  readonly recordId: (record: T) => string;
  readonly recordHash: (record: T) => Sha256Hash;
  readonly recordTime: (record: T) => string;
  readonly parse: (value: unknown) => T;
  readonly assertRow: (record: T, row: StoredRecordRow & Record<string, unknown>) => void;
  readonly beforeInsert: (database: DatabaseSync, record: T) => void;
  readonly insert: (database: DatabaseSync, record: T, json: string) => void;
}

abstract class SqliteImmutableSurveillanceRepository<T extends TenantRecord>
  implements ImmutableRepositoryPort<T>
{
  readonly #database: DatabaseSync;
  readonly #configuration: ImmutableSqliteConfiguration<T>;
  #closed = false;

  protected constructor(
    databasePath: string,
    configuration: ImmutableSqliteConfiguration<T>,
    options: SqliteSurveillanceRepositoryOptions
  ) {
    const path = requiredPath(databasePath);
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(path);
    this.#configuration = configuration;
    const timeout = safeInteger(options.busyTimeoutMs ?? 5_000, "busyTimeoutMs", 0, 60_000);
    try {
      this.#database.exec(
        `PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${timeout};`
      );
      migrateSqliteComponent(this.#database, {
        componentName: SQLITE_SURVEILLANCE_EVIDENCE_COMPONENT,
        supportedVersion: SQLITE_SURVEILLANCE_EVIDENCE_SCHEMA_VERSION,
        migrations: SQLITE_SURVEILLANCE_EVIDENCE_MIGRATIONS,
        unsupportedVersionError: (current, supported) =>
          new RepositoryError(
            "INTEGRITY_FAILURE",
            `Surveillance evidence schema ${current} is newer than supported version ${supported}`
          )
      });
    } catch (error) {
      this.#database.close();
      if (error instanceof RepositoryError) throw error;
      throw integrity("Surveillance evidence schema initialization failed", error);
    }
  }

  async put(recordValue: T, contextValue: RepositoryWriteContext): Promise<RepositoryPutResult<T>> {
    this.#assertOpen();
    let record: T;
    try {
      canonicalJson(recordValue);
      record = this.#configuration.parse(recordValue);
    } catch (error) {
      if (error instanceof RepositoryError) throw error;
      throw integrity("Immutable surveillance record failed contract validation", error);
    }
    const context = writeContext(contextValue, record.tenantId);
    const recordId = identifier(this.#configuration.recordId(record), "record id");
    const recordHash = this.#configuration.recordHash(record);
    const requestHash = canonicalHash({ actorId: context.actorId, record });
    const json = canonicalJson(record);

    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const receipt = this.#database
        .prepare(
          `SELECT request_hash, record_id, record_hash
             FROM surveillance_evidence_idempotency
            WHERE tenant_id = ? AND repository_kind = ? AND actor_id = ? AND idempotency_key = ?`
        )
        .get(
          context.tenantId,
          this.#configuration.repositoryKind,
          context.actorId,
          context.idempotencyKey
        ) as ReceiptRow | undefined;
      if (receipt) {
        if (
          receipt.request_hash !== requestHash ||
          receipt.record_id !== recordId ||
          receipt.record_hash !== recordHash
        ) {
          throw new RepositoryError(
            "IDEMPOTENCY_CONFLICT",
            "Idempotency key was used by this actor for a different immutable write"
          );
        }
        const replay = this.#read(record.tenantId, recordId);
        if (!replay) {
          throw new RepositoryError(
            "INTEGRITY_FAILURE",
            "Idempotency receipt does not resolve to an immutable record"
          );
        }
        this.#database.exec("COMMIT");
        return Object.freeze({ record: replay, replayed: true });
      }
      if (this.#read(record.tenantId, recordId)) {
        throw new RepositoryError("ALREADY_EXISTS", "Immutable surveillance record already exists");
      }
      this.#configuration.beforeInsert(this.#database, record);
      try {
        this.#configuration.insert(this.#database, record, json);
      } catch (error) {
        throw mapConstraint(error);
      }
      this.#database
        .prepare(
          `INSERT INTO surveillance_evidence_idempotency (
             tenant_id, repository_kind, actor_id, idempotency_key,
             request_hash, record_id, record_hash, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          context.tenantId,
          this.#configuration.repositoryKind,
          context.actorId,
          context.idempotencyKey,
          requestHash,
          recordId,
          recordHash,
          this.#configuration.recordTime(record)
        );
      const stored = this.#read(record.tenantId, recordId);
      if (!stored) throw new RepositoryError("INTEGRITY_FAILURE", "Immutable write was not durable");
      this.#database.exec("COMMIT");
      return Object.freeze({ record: stored, replayed: false });
    } catch (error) {
      rollback(this.#database);
      throw error;
    }
  }

  async get(tenantIdValue: string, recordIdValue: string): Promise<T | undefined> {
    this.#assertOpen();
    return this.#read(
      identifier(tenantIdValue, "tenant id"),
      identifier(recordIdValue, "record id")
    );
  }

  async list(
    tenantIdValue: string,
    page: RepositoryPageRequest = {}
  ): Promise<RepositoryPage<T>> {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenant id");
    const limit = safeInteger(page.limit ?? 100, "page limit", 1, 1_000);
    const afterId = page.cursor
      ? decodeCursor(page.cursor, this.#configuration.repositoryKind, tenantId)
      : undefined;
    const rows = this.#database
      .prepare(
        `SELECT * FROM ${this.#configuration.tableName}
          WHERE tenant_id = ? AND record_id > ?
          ORDER BY record_id
          LIMIT ?`
      )
      .all(tenantId, afterId ?? "", limit + 1) as unknown as (StoredRecordRow &
      Record<string, unknown>)[];
    const hasNext = rows.length > limit;
    const selected = hasNext ? rows.slice(0, limit) : rows;
    const items = selected.map((row) => this.#recordFromRow(row));
    const last = selected.at(-1);
    return Object.freeze({
      items: Object.freeze(items),
      nextCursor:
        hasNext && last
          ? encodeCursor({
              version: 1,
              repositoryKind: this.#configuration.repositoryKind,
              tenantId,
              afterId: last.record_id
            })
          : null
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#database.close();
  }

  #read(tenantId: string, recordId: string): T | undefined {
    const row = this.#database
      .prepare(
        `SELECT * FROM ${this.#configuration.tableName}
          WHERE tenant_id = ? AND record_id = ?`
      )
      .get(tenantId, recordId) as (StoredRecordRow & Record<string, unknown>) | undefined;
    return row ? this.#recordFromRow(row) : undefined;
  }

  #recordFromRow(row: StoredRecordRow & Record<string, unknown>): T {
    try {
      const raw = JSON.parse(row.record_json) as unknown;
      if (canonicalJson(raw) !== row.record_json) {
        throw new RepositoryError("INTEGRITY_FAILURE", "Stored surveillance JSON is not canonical");
      }
      const parsed = this.#configuration.parse(raw);
      if (
        parsed.tenantId !== row.tenant_id ||
        this.#configuration.recordId(parsed) !== row.record_id ||
        this.#configuration.recordHash(parsed) !== row.record_hash
      ) {
        throw new RepositoryError(
          "INTEGRITY_FAILURE",
          "Stored surveillance index columns do not match canonical content"
        );
      }
      this.#configuration.assertRow(parsed, row);
      return parsed;
    } catch (error) {
      if (error instanceof RepositoryError) throw error;
      throw integrity("Stored surveillance record failed integrity verification", error);
    }
  }

  #assertOpen(): void {
    if (this.#closed) throw new RepositoryError("INVALID_ARGUMENT", "Repository is closed");
  }
}

export class SqliteDatasetSnapshotV2Repository extends SqliteImmutableSurveillanceRepository<DatasetSnapshotV2> {
  constructor(databasePath: string, options: SqliteSurveillanceRepositoryOptions = {}) {
    super(databasePath, datasetSnapshotConfiguration(), options);
  }
}

export class SqliteCertifiedSnapshotEvidenceV1Repository extends SqliteImmutableSurveillanceRepository<CertifiedSnapshotEvidenceRecordV1> {
  constructor(databasePath: string, options: SqliteSurveillanceRepositoryOptions = {}) {
    super(databasePath, certifiedEvidenceConfiguration(), options);
  }
}

/** Convenience aggregate; both ports intentionally coexist in one component schema. */
export class SqliteSurveillanceEvidenceRepositories {
  readonly datasetSnapshots: SqliteDatasetSnapshotV2Repository;
  readonly certifiedSnapshotEvidence: SqliteCertifiedSnapshotEvidenceV1Repository;

  constructor(databasePath: string, options: SqliteSurveillanceRepositoryOptions = {}) {
    if (databasePath === ":memory:") {
      throw new RepositoryError(
        "INVALID_ARGUMENT",
        "The aggregate requires a shared file path; use individual in-memory repositories only for isolated tests"
      );
    }
    this.datasetSnapshots = new SqliteDatasetSnapshotV2Repository(databasePath, options);
    try {
      this.certifiedSnapshotEvidence = new SqliteCertifiedSnapshotEvidenceV1Repository(
        databasePath,
        options
      );
    } catch (error) {
      this.datasetSnapshots.close();
      throw error;
    }
  }

  close(): void {
    this.certifiedSnapshotEvidence.close();
    this.datasetSnapshots.close();
  }
}

function datasetSnapshotConfiguration(): ImmutableSqliteConfiguration<DatasetSnapshotV2> {
  return {
    repositoryKind: "dataset_snapshot_v2",
    tableName: "surveillance_dataset_snapshots_v2",
    recordId: (record) => record.snapshotId,
    recordHash: (record) => record.snapshotHash,
    recordTime: (record) => record.knowledge.persistedAt,
    parse: parsePersistableDatasetSnapshot,
    assertRow: (record, row) => {
      const correction = record.correction;
      const indexed = {
        sourceContractId: row.source_contract_id,
        sourceContractRevision: row.source_contract_revision,
        sourceContractHash: row.source_contract_hash,
        asOfDate: row.as_of_date,
        correctionKind: row.correction_kind,
        correctsSnapshotId: row.corrects_snapshot_id,
        correctsSnapshotHash: row.corrects_snapshot_hash,
        correctionSequence: row.correction_sequence,
        persistedAt: row.persisted_at
      };
      const expected = {
        sourceContractId: record.sourceContract.sourceContractId,
        sourceContractRevision: record.sourceContract.revision,
        sourceContractHash: record.sourceContract.sourceContractHash,
        asOfDate: record.asOfDate,
        correctionKind: correction.kind,
        correctsSnapshotId: correction.kind === "correction" ? correction.correctsSnapshotId : null,
        correctsSnapshotHash: correction.kind === "correction" ? correction.correctsSnapshotHash : null,
        correctionSequence: correction.kind === "correction" ? correction.correctionSequence : null,
        persistedAt: record.knowledge.persistedAt
      };
      if (canonicalJson(indexed) !== canonicalJson(expected)) {
        throw new RepositoryError("INTEGRITY_FAILURE", "Dataset snapshot indexes do not match its contract");
      }
    },
    beforeInsert: validateCorrectionLineage,
    insert: (database, record, json) => {
      const correction = record.correction;
      database
        .prepare(
          `INSERT INTO surveillance_dataset_snapshots_v2 (
             tenant_id, record_id, record_hash, source_contract_id,
             source_contract_revision, source_contract_hash, as_of_date,
             correction_kind, corrects_snapshot_id, corrects_snapshot_hash,
             correction_sequence, persisted_at, record_json
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          record.tenantId,
          record.snapshotId,
          record.snapshotHash,
          record.sourceContract.sourceContractId,
          record.sourceContract.revision,
          record.sourceContract.sourceContractHash,
          record.asOfDate,
          correction.kind,
          correction.kind === "correction" ? correction.correctsSnapshotId : null,
          correction.kind === "correction" ? correction.correctsSnapshotHash : null,
          correction.kind === "correction" ? correction.correctionSequence : null,
          record.knowledge.persistedAt,
          json
        );
    }
  };
}

function certifiedEvidenceConfiguration(): ImmutableSqliteConfiguration<CertifiedSnapshotEvidenceRecordV1> {
  return {
    repositoryKind: "certified_snapshot_evidence_v1",
    tableName: "surveillance_certified_snapshot_evidence_v1",
    recordId: (record) => record.certification.certificationManifestId,
    recordHash: (record) => record.evidenceHash,
    recordTime: (record) => record.recordedAt,
    parse: parseCertifiedSnapshotEvidenceRecordV1,
    assertRow: (record, row) => {
      const indexed = {
        snapshotId: row.snapshot_id,
        snapshotHash: row.snapshot_hash,
        populationHash: row.population_hash,
        mappingApplicationId: row.mapping_application_id,
        mappingApplicationHash: row.mapping_application_hash,
        mappingSpecId: row.mapping_spec_id,
        mappingSpecHash: row.mapping_spec_hash,
        normalizedArtifactId: row.normalized_artifact_id,
        normalizedArtifactContentHash: row.normalized_artifact_content_hash,
        normalizedArtifactCreatedAt: row.normalized_artifact_created_at,
        certifiedAt: row.certified_at
      };
      const expected = {
        snapshotId: record.certification.snapshotId,
        snapshotHash: record.certification.snapshotHash,
        populationHash: record.population.populationHash,
        mappingApplicationId: record.mappingApplication.mappingApplicationId,
        mappingApplicationHash: record.mappingApplication.mappingApplicationHash,
        mappingSpecId: record.mappingSpec.mappingSpecId,
        mappingSpecHash: record.mappingSpec.mappingSpecHash,
        normalizedArtifactId: record.normalizedArtifact.artifactId,
        normalizedArtifactContentHash: record.normalizedArtifact.contentHash,
        normalizedArtifactCreatedAt: record.normalizedArtifact.createdAt,
        certifiedAt: record.certification.certifiedAt
      };
      if (canonicalJson(indexed) !== canonicalJson(expected)) {
        throw new RepositoryError("INTEGRITY_FAILURE", "Certified evidence indexes do not match its contract");
      }
    },
    beforeInsert: validateCertifiedSnapshotReference,
    insert: (database, record, json) => {
      database
        .prepare(
          `INSERT INTO surveillance_certified_snapshot_evidence_v1 (
             tenant_id, record_id, record_hash, snapshot_id, snapshot_hash,
             population_hash, mapping_application_id, mapping_application_hash,
             mapping_spec_id, mapping_spec_hash, normalized_artifact_id,
             normalized_artifact_content_hash, normalized_artifact_created_at,
             certified_at, record_json
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          record.tenantId,
          record.certification.certificationManifestId,
          record.evidenceHash,
          record.certification.snapshotId,
          record.certification.snapshotHash,
          record.population.populationHash,
          record.mappingApplication.mappingApplicationId,
          record.mappingApplication.mappingApplicationHash,
          record.mappingSpec.mappingSpecId,
          record.mappingSpec.mappingSpecHash,
          record.normalizedArtifact.artifactId,
          record.normalizedArtifact.contentHash,
          record.normalizedArtifact.createdAt,
          record.certification.certifiedAt,
          json
        );
    }
  };
}

function validateCorrectionLineage(database: DatabaseSync, record: DatasetSnapshotV2): void {
  if (record.correction.kind === "original") return;
  const row = database
    .prepare(
      `SELECT * FROM surveillance_dataset_snapshots_v2
        WHERE tenant_id = ? AND record_id = ?`
    )
    .get(record.tenantId, record.correction.correctsSnapshotId) as
    | (StoredRecordRow & Record<string, unknown>)
    | undefined;
  if (!row) {
    throw new RepositoryError(
      "NOT_FOUND",
      "Correction predecessor does not exist in the same tenant"
    );
  }
  const predecessor = verifiedDatasetSnapshotRow(row);
  const expectedSequence =
    predecessor.correction.kind === "original"
      ? 1
      : predecessor.correction.correctionSequence + 1;
  if (
    predecessor.snapshotHash !== record.correction.correctsSnapshotHash ||
    record.correction.correctionSequence !== expectedSequence ||
    predecessor.asOfDate !== record.asOfDate ||
    canonicalJson(predecessor.sourceContract) !== canonicalJson(record.sourceContract)
  ) {
    throw new RepositoryError(
      "INTEGRITY_FAILURE",
      "Correction does not extend the exact same-period source lineage"
    );
  }
  if (
    record.correction.detectedAt < predecessor.knowledge.persistedAt ||
    record.correction.detectedAt > record.knowledge.persistedAt
  ) {
    throw new RepositoryError(
      "INTEGRITY_FAILURE",
      "Correction detection time is outside its predecessor and replacement persistence window"
    );
  }
  const replacement = database
    .prepare(
      `SELECT record_id FROM surveillance_dataset_snapshots_v2
        WHERE tenant_id = ? AND corrects_snapshot_id = ?`
    )
    .get(record.tenantId, predecessor.snapshotId) as { readonly record_id: string } | undefined;
  if (replacement) {
    throw new RepositoryError(
      "CONCURRENCY_CONFLICT",
      "Correction predecessor already has an immutable replacement"
    );
  }
}

function parsePersistableDatasetSnapshot(value: unknown): DatasetSnapshotV2 {
  const snapshot = parseDatasetSnapshotV2(value);
  const locator = snapshot.sourceLocator;
  if (
    /(?:^|\s)bearer\s+[A-Za-z0-9._~+/=-]+/iu.test(locator) ||
    /-----BEGIN [A-Z ]*(?:PRIVATE KEY|CERTIFICATE)-----/u.test(locator) ||
    /(?:^|[^A-Za-z0-9_-])[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}(?:$|[^A-Za-z0-9_-])/u.test(locator) ||
    /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/\s]*@/u.test(locator) ||
    /[?#].*(?:password|passwd|pwd|secret|token|api[_-]?key|credential|signature|x-amz-[^=]*)=/iu.test(locator)
  ) {
    throw new RepositoryError(
      "INVALID_ARGUMENT",
      "Dataset snapshot source locator must be an opaque, non-credentialed reference"
    );
  }
  return snapshot;
}

function validateCertifiedSnapshotReference(
  database: DatabaseSync,
  evidence: CertifiedSnapshotEvidenceRecordV1
): void {
  const row = database
    .prepare(
      `SELECT * FROM surveillance_dataset_snapshots_v2
        WHERE tenant_id = ? AND record_id = ?`
    )
    .get(evidence.tenantId, evidence.certification.snapshotId) as
    | (StoredRecordRow & Record<string, unknown>)
    | undefined;
  if (!row) {
    throw new RepositoryError(
      "NOT_FOUND",
      "Certified evidence snapshot does not exist in the same tenant"
    );
  }
  const snapshot = verifiedDatasetSnapshotRow(row);
  if (
    snapshot.snapshotHash !== evidence.certification.snapshotHash ||
    snapshot.hashes.contentHash !== evidence.mappingApplication.snapshot.contentHash ||
    canonicalJson(snapshot.sourceContract) !== canonicalJson(evidence.mappingSpec.sourceContract)
  ) {
    throw new RepositoryError(
      "INTEGRITY_FAILURE",
      "Certified evidence does not bind the persisted snapshot and source lineage"
    );
  }
  if (snapshot.knowledge.persistedAt > evidence.certification.certifiedAt) {
    throw new RepositoryError("INTEGRITY_FAILURE", "Certification predates snapshot persistence");
  }
  if (snapshot.asOfDate > evidence.certification.certifiedAt.slice(0, 10)) {
    throw new RepositoryError("INTEGRITY_FAILURE", "Certification predates the snapshot as-of date");
  }
  if (snapshot.knowledge.persistedAt > evidence.mappingApplication.appliedAt) {
    throw new RepositoryError("INTEGRITY_FAILURE", "Mapping application predates snapshot persistence");
  }
  if (snapshot.knowledge.persistedAt > evidence.normalizedArtifact.createdAt) {
    throw new RepositoryError(
      "INTEGRITY_FAILURE",
      "Normalized artifact creation predates snapshot persistence"
    );
  }
}

function verifiedDatasetSnapshotRow(
  row: StoredRecordRow & Record<string, unknown>
): DatasetSnapshotV2 {
  try {
    const raw = JSON.parse(row.record_json) as unknown;
    if (canonicalJson(raw) !== row.record_json) {
      throw new RepositoryError("INTEGRITY_FAILURE", "Stored dataset snapshot JSON is not canonical");
    }
    const parsed = parseDatasetSnapshotV2(raw);
    if (
      parsed.tenantId !== row.tenant_id ||
      parsed.snapshotId !== row.record_id ||
      parsed.snapshotHash !== row.record_hash
    ) {
      throw new RepositoryError("INTEGRITY_FAILURE", "Dataset snapshot row is internally inconsistent");
    }
    return parsed;
  } catch (error) {
    if (error instanceof RepositoryError) throw error;
    throw integrity("Stored correction predecessor failed integrity verification", error);
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
    throw new RepositoryError(
      "INVALID_ARGUMENT",
      "Immutable surveillance repositories do not accept expectedRevision"
    );
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

function safeInteger(
  value: number,
  label: string,
  minimum: number,
  maximum: number
): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new RepositoryError(
      "INVALID_ARGUMENT",
      `${label} must be between ${minimum} and ${maximum}`
    );
  }
  return value;
}

function encodeCursor(body: CursorBody): string {
  const envelope = { body, cursorHash: canonicalHash(body) };
  return Buffer.from(canonicalJson(envelope), "utf8").toString("base64url");
}

function decodeCursor(
  value: string,
  repositoryKind: RepositoryKind,
  tenantId: string
): string {
  try {
    const envelope = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as {
      readonly body?: CursorBody;
      readonly cursorHash?: string;
    };
    const body = envelope.body;
    if (
      !body ||
      envelope.cursorHash !== canonicalHash(body) ||
      body.version !== 1 ||
      body.repositoryKind !== repositoryKind ||
      body.tenantId !== tenantId
    ) {
      throw new Error("cursor binding mismatch");
    }
    return identifier(body.afterId, "cursor record id");
  } catch {
    throw new RepositoryError("INVALID_ARGUMENT", "Repository cursor is invalid or out of scope");
  }
}

function mapConstraint(error: unknown): RepositoryError {
  const message = error instanceof Error ? error.message : String(error);
  if (/FOREIGN KEY constraint failed/u.test(message)) {
    return new RepositoryError("INTEGRITY_FAILURE", "Immutable write has a missing lineage reference");
  }
  if (/single_replacement|corrects_snapshot_id/u.test(message)) {
    return new RepositoryError("CONCURRENCY_CONFLICT", "Correction predecessor already has a replacement");
  }
  if (/UNIQUE constraint failed|PRIMARY KEY/u.test(message)) {
    return new RepositoryError("ALREADY_EXISTS", "Immutable surveillance identity already exists");
  }
  return integrity("SQLite rejected immutable surveillance evidence", error);
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
