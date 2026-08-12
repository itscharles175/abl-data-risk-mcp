import { createHash, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

import type { FieldMapping } from "../domain/mapping.js";
import {
  migrateSqliteComponent,
  SQLITE_SHARED_AUDIT_OBJECTS
} from "../infrastructure/sqlite-component-schema.js";

export const CONTROL_STORE_COMPONENT = "abl.control-store" as const;
export const CONTROL_STORE_SCHEMA_VERSION = 1 as const;

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

export type ControlStoreErrorCode =
  | "INVALID_ARGUMENT"
  | "NOT_FOUND"
  | "CONFLICT"
  | "IDEMPOTENCY_CONFLICT"
  | "ILLEGAL_TRANSITION"
  | "MAKER_CHECKER_VIOLATION"
  | "STORE_CLOSED";

export class ControlStoreError extends Error {
  readonly code: ControlStoreErrorCode;

  constructor(code: ControlStoreErrorCode, message: string) {
    super(message);
    this.name = "ControlStoreError";
    this.code = code;
  }
}

export interface ControlStoreOptions {
  readonly clock?: () => Date;
  readonly busyTimeoutMs?: number;
}

export interface CreateDatasetSnapshotInput {
  readonly tenantId: string;
  readonly snapshotId: string;
  readonly sourceId: string;
  /** A non-secret source/table locator. Connection credentials must never be stored here. */
  readonly sourceLocator: string;
  readonly asOfDate: string;
  readonly contentHash: string;
  readonly rowCount: number;
  readonly schema: JsonValue;
  readonly createdBy: string;
  readonly idempotencyKey: string;
}

export interface DatasetSnapshot {
  readonly tenantId: string;
  readonly snapshotId: string;
  readonly sourceId: string;
  readonly sourceLocator: string;
  readonly asOfDate: string;
  readonly contentHash: string;
  readonly rowCount: number;
  readonly schema: JsonValue;
  readonly createdBy: string;
  readonly createdAt: string;
}

export type MappingStatus = "proposed" | "validated" | "approved" | "active" | "superseded";
export type MappingTransitionStatus = "validated" | "approved" | "active";

export interface ProposeMappingVersionInput {
  readonly tenantId: string;
  readonly mappingVersionId: string;
  readonly mappingKey: string;
  readonly snapshotId: string;
  readonly dictionaryVersion: string;
  readonly mappings: readonly FieldMapping[];
  readonly proposedBy: string;
  readonly idempotencyKey: string;
}

export interface MappingVersion {
  readonly tenantId: string;
  readonly mappingVersionId: string;
  readonly mappingKey: string;
  readonly version: number;
  readonly snapshotId: string;
  readonly dictionaryVersion: string;
  readonly mappings: readonly FieldMapping[];
  readonly mappingHash: string;
  readonly status: MappingStatus;
  readonly proposedBy: string;
  readonly proposedAt: string;
  readonly validatedBy?: string;
  readonly validatedAt?: string;
  readonly approvedBy?: string;
  readonly approvedAt?: string;
  readonly activatedBy?: string;
  readonly activatedAt?: string;
  readonly supersededBy?: string;
  readonly supersededAt?: string;
}

export interface TransitionMappingVersionInput {
  readonly tenantId: string;
  readonly mappingVersionId: string;
  readonly toStatus: MappingTransitionStatus;
  readonly actor: string;
  readonly evidence?: JsonValue;
  readonly idempotencyKey: string;
}

export type DataQualitySeverity = "info" | "warning" | "error";

export interface DataQualityFindingInput {
  readonly findingId: string;
  readonly ruleId: string;
  readonly severity: DataQualitySeverity;
  readonly passed: boolean;
  readonly affectedRows: number;
  readonly message: string;
  readonly evidence?: JsonValue;
}

export interface RecordDataQualityRunInput {
  readonly tenantId: string;
  readonly runId: string;
  readonly snapshotId: string;
  readonly rulesetId: string;
  readonly rulesetHash: string;
  readonly findings: readonly DataQualityFindingInput[];
  readonly executedBy: string;
  readonly idempotencyKey: string;
}

export interface DataQualityFinding extends DataQualityFindingInput {
  readonly tenantId: string;
  readonly runId: string;
}

export interface DataQualityRun {
  readonly tenantId: string;
  readonly runId: string;
  readonly snapshotId: string;
  readonly rulesetId: string;
  readonly rulesetHash: string;
  readonly passed: boolean;
  readonly findingCount: number;
  readonly failedFindingCount: number;
  readonly findings: readonly DataQualityFinding[];
  readonly executedBy: string;
  readonly executedAt: string;
}

export interface ReconciliationCheck {
  readonly checkId: string;
  readonly expected: string;
  readonly actual: string;
  readonly difference: string;
  readonly tolerance?: string;
  readonly passed: boolean;
}

export interface RecordReconciliationInput {
  readonly tenantId: string;
  readonly reconciliationId: string;
  readonly snapshotId: string;
  readonly kind: string;
  readonly checks: readonly ReconciliationCheck[];
  readonly details?: JsonValue;
  readonly performedBy: string;
  readonly idempotencyKey: string;
}

export interface Reconciliation {
  readonly tenantId: string;
  readonly reconciliationId: string;
  readonly snapshotId: string;
  readonly kind: string;
  readonly checks: readonly ReconciliationCheck[];
  readonly passed: boolean;
  readonly details?: JsonValue;
  readonly performedBy: string;
  readonly performedAt: string;
}

export interface AnalysisArtifactInput {
  readonly artifactId: string;
  readonly kind: string;
  readonly mediaType: string;
  readonly contentHash: string;
  readonly uri?: string;
  readonly metadata?: JsonValue;
}

export interface RecordAnalysisManifestInput {
  readonly tenantId: string;
  readonly manifestId: string;
  readonly snapshotId: string;
  readonly mappingVersionId: string;
  readonly analysisType: string;
  readonly parameters: JsonValue;
  readonly queryHash: string;
  readonly codeVersion: string;
  readonly artifacts: readonly AnalysisArtifactInput[];
  readonly createdBy: string;
  readonly idempotencyKey: string;
}

export interface AnalysisArtifact extends AnalysisArtifactInput {
  readonly tenantId: string;
  readonly manifestId: string;
  readonly createdAt: string;
}

export interface AnalysisManifest {
  readonly tenantId: string;
  readonly manifestId: string;
  readonly snapshotId: string;
  readonly mappingVersionId: string;
  readonly analysisType: string;
  readonly parameters: JsonValue;
  readonly queryHash: string;
  readonly codeVersion: string;
  readonly manifestHash: string;
  readonly artifacts: readonly AnalysisArtifact[];
  readonly createdBy: string;
  readonly createdAt: string;
}

export interface AppendAuditEventInput {
  readonly tenantId: string;
  readonly eventType: string;
  readonly entityType: string;
  readonly entityId: string;
  readonly actor: string;
  readonly details: JsonValue;
  readonly idempotencyKey: string;
}

export interface AuditEvent {
  readonly sequence: number;
  readonly tenantId: string;
  readonly eventId: string;
  readonly eventType: string;
  readonly entityType: string;
  readonly entityId: string;
  readonly actor: string;
  readonly details: JsonValue;
  readonly occurredAt: string;
}

export interface ListAuditEventsOptions {
  readonly afterSequence?: number;
  readonly limit?: number;
}

interface DatasetSnapshotRow {
  readonly tenant_id: string;
  readonly snapshot_id: string;
  readonly source_id: string;
  readonly source_locator: string;
  readonly as_of_date: string;
  readonly content_hash: string;
  readonly row_count: number;
  readonly schema_json: string;
  readonly created_by: string;
  readonly created_at: string;
}

interface MappingVersionRow {
  readonly tenant_id: string;
  readonly mapping_version_id: string;
  readonly mapping_key: string;
  readonly version_number: number;
  readonly snapshot_id: string;
  readonly dictionary_version: string;
  readonly mapping_json: string;
  readonly mapping_hash: string;
  readonly status: MappingStatus;
  readonly proposed_by: string;
  readonly proposed_at: string;
  readonly validated_by: string | null;
  readonly validated_at: string | null;
  readonly approved_by: string | null;
  readonly approved_at: string | null;
  readonly activated_by: string | null;
  readonly activated_at: string | null;
  readonly superseded_by: string | null;
  readonly superseded_at: string | null;
}

interface DataQualityRunRow {
  readonly tenant_id: string;
  readonly run_id: string;
  readonly snapshot_id: string;
  readonly ruleset_id: string;
  readonly ruleset_hash: string;
  readonly passed: number;
  readonly finding_count: number;
  readonly failed_finding_count: number;
  readonly executed_by: string;
  readonly executed_at: string;
}

interface DataQualityFindingRow {
  readonly tenant_id: string;
  readonly run_id: string;
  readonly finding_id: string;
  readonly rule_id: string;
  readonly severity: DataQualitySeverity;
  readonly passed: number;
  readonly affected_rows: number;
  readonly message: string;
  readonly evidence_json: string | null;
}

interface ReconciliationRow {
  readonly tenant_id: string;
  readonly reconciliation_id: string;
  readonly snapshot_id: string;
  readonly kind: string;
  readonly checks_json: string;
  readonly passed: number;
  readonly details_json: string | null;
  readonly performed_by: string;
  readonly performed_at: string;
}

interface AnalysisManifestRow {
  readonly tenant_id: string;
  readonly manifest_id: string;
  readonly snapshot_id: string;
  readonly mapping_version_id: string;
  readonly analysis_type: string;
  readonly parameters_json: string;
  readonly query_hash: string;
  readonly code_version: string;
  readonly manifest_hash: string;
  readonly created_by: string;
  readonly created_at: string;
}

interface AnalysisArtifactRow {
  readonly tenant_id: string;
  readonly manifest_id: string;
  readonly artifact_id: string;
  readonly kind: string;
  readonly media_type: string;
  readonly content_hash: string;
  readonly uri: string | null;
  readonly metadata_json: string | null;
  readonly created_at: string;
}

interface AuditEventRow {
  readonly sequence: number;
  readonly tenant_id: string;
  readonly event_id: string;
  readonly event_type: string;
  readonly entity_type: string;
  readonly entity_id: string;
  readonly actor: string;
  readonly details_json: string;
  readonly occurred_at: string;
}

interface IdempotencyRow {
  readonly request_hash: string;
  readonly response_json: string;
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS dataset_snapshots (
  tenant_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  source_locator TEXT NOT NULL,
  as_of_date TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  row_count INTEGER NOT NULL CHECK (row_count >= 0),
  schema_json TEXT NOT NULL CHECK (json_valid(schema_json)),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, snapshot_id)
) STRICT;

CREATE INDEX IF NOT EXISTS dataset_snapshots_content_hash
  ON dataset_snapshots (tenant_id, content_hash);
CREATE INDEX IF NOT EXISTS dataset_snapshots_source
  ON dataset_snapshots (tenant_id, source_id, source_locator, as_of_date);

CREATE TABLE IF NOT EXISTS mapping_versions (
  tenant_id TEXT NOT NULL,
  mapping_version_id TEXT NOT NULL,
  mapping_key TEXT NOT NULL,
  version_number INTEGER NOT NULL CHECK (version_number > 0),
  snapshot_id TEXT NOT NULL,
  dictionary_version TEXT NOT NULL,
  mapping_json TEXT NOT NULL CHECK (json_valid(mapping_json)),
  mapping_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('proposed', 'validated', 'approved', 'active', 'superseded')),
  proposed_by TEXT NOT NULL,
  proposed_at TEXT NOT NULL,
  validated_by TEXT,
  validated_at TEXT,
  approved_by TEXT,
  approved_at TEXT,
  activated_by TEXT,
  activated_at TEXT,
  superseded_by TEXT,
  superseded_at TEXT,
  PRIMARY KEY (tenant_id, mapping_version_id),
  UNIQUE (tenant_id, mapping_key, version_number),
  UNIQUE (tenant_id, mapping_version_id, snapshot_id),
  FOREIGN KEY (tenant_id, snapshot_id)
    REFERENCES dataset_snapshots (tenant_id, snapshot_id),
  CHECK (validated_by IS NULL OR validated_by <> proposed_by),
  CHECK (approved_by IS NULL OR approved_by <> proposed_by),
  CHECK (activated_by IS NULL OR activated_by <> proposed_by),
  CHECK (
    (status = 'proposed' AND validated_by IS NULL AND approved_by IS NULL AND activated_by IS NULL AND superseded_by IS NULL) OR
    (status = 'validated' AND validated_by IS NOT NULL AND validated_at IS NOT NULL AND approved_by IS NULL AND activated_by IS NULL AND superseded_by IS NULL) OR
    (status = 'approved' AND validated_by IS NOT NULL AND approved_by IS NOT NULL AND approved_at IS NOT NULL AND activated_by IS NULL AND superseded_by IS NULL) OR
    (status = 'active' AND validated_by IS NOT NULL AND approved_by IS NOT NULL AND activated_by IS NOT NULL AND activated_at IS NOT NULL AND superseded_by IS NULL) OR
    (status = 'superseded' AND validated_by IS NOT NULL AND approved_by IS NOT NULL AND activated_by IS NOT NULL AND superseded_by IS NOT NULL AND superseded_at IS NOT NULL)
  )
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS one_active_mapping_per_key
  ON mapping_versions (tenant_id, mapping_key)
  WHERE status = 'active';

CREATE TABLE IF NOT EXISTS data_quality_runs (
  tenant_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  ruleset_id TEXT NOT NULL,
  ruleset_hash TEXT NOT NULL,
  passed INTEGER NOT NULL CHECK (passed IN (0, 1)),
  finding_count INTEGER NOT NULL CHECK (finding_count >= 0),
  failed_finding_count INTEGER NOT NULL CHECK (failed_finding_count >= 0),
  executed_by TEXT NOT NULL,
  executed_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, run_id),
  FOREIGN KEY (tenant_id, snapshot_id)
    REFERENCES dataset_snapshots (tenant_id, snapshot_id)
) STRICT;

CREATE TABLE IF NOT EXISTS data_quality_findings (
  tenant_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'error')),
  passed INTEGER NOT NULL CHECK (passed IN (0, 1)),
  affected_rows INTEGER NOT NULL CHECK (affected_rows >= 0),
  message TEXT NOT NULL,
  evidence_json TEXT CHECK (evidence_json IS NULL OR json_valid(evidence_json)),
  PRIMARY KEY (tenant_id, run_id, finding_id),
  FOREIGN KEY (tenant_id, run_id)
    REFERENCES data_quality_runs (tenant_id, run_id)
) STRICT;

CREATE TABLE IF NOT EXISTS reconciliations (
  tenant_id TEXT NOT NULL,
  reconciliation_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  checks_json TEXT NOT NULL CHECK (json_valid(checks_json)),
  passed INTEGER NOT NULL CHECK (passed IN (0, 1)),
  details_json TEXT CHECK (details_json IS NULL OR json_valid(details_json)),
  performed_by TEXT NOT NULL,
  performed_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, reconciliation_id),
  FOREIGN KEY (tenant_id, snapshot_id)
    REFERENCES dataset_snapshots (tenant_id, snapshot_id)
) STRICT;

CREATE TABLE IF NOT EXISTS analysis_manifests (
  tenant_id TEXT NOT NULL,
  manifest_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  mapping_version_id TEXT NOT NULL,
  analysis_type TEXT NOT NULL,
  parameters_json TEXT NOT NULL CHECK (json_valid(parameters_json)),
  query_hash TEXT NOT NULL,
  code_version TEXT NOT NULL,
  manifest_hash TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, manifest_id),
  FOREIGN KEY (tenant_id, snapshot_id)
    REFERENCES dataset_snapshots (tenant_id, snapshot_id),
  FOREIGN KEY (tenant_id, mapping_version_id, snapshot_id)
    REFERENCES mapping_versions (tenant_id, mapping_version_id, snapshot_id)
) STRICT;

CREATE TABLE IF NOT EXISTS analysis_artifacts (
  tenant_id TEXT NOT NULL,
  manifest_id TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  media_type TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  uri TEXT,
  metadata_json TEXT CHECK (metadata_json IS NULL OR json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, manifest_id, artifact_id),
  FOREIGN KEY (tenant_id, manifest_id)
    REFERENCES analysis_manifests (tenant_id, manifest_id)
) STRICT;

CREATE TABLE IF NOT EXISTS audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  details_json TEXT NOT NULL CHECK (json_valid(details_json)),
  occurred_at TEXT NOT NULL,
  UNIQUE (tenant_id, event_id)
) STRICT;

CREATE INDEX IF NOT EXISTS audit_events_tenant_sequence
  ON audit_events (tenant_id, sequence);

CREATE TABLE IF NOT EXISTS idempotency_records (
  tenant_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  response_json TEXT NOT NULL CHECK (json_valid(response_json)),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, operation, idempotency_key)
) STRICT;

CREATE TRIGGER IF NOT EXISTS dataset_snapshots_no_update
BEFORE UPDATE ON dataset_snapshots BEGIN
  SELECT RAISE(ABORT, 'dataset snapshots are immutable');
END;
CREATE TRIGGER IF NOT EXISTS dataset_snapshots_no_delete
BEFORE DELETE ON dataset_snapshots BEGIN
  SELECT RAISE(ABORT, 'dataset snapshots are immutable');
END;

CREATE TRIGGER IF NOT EXISTS mapping_versions_payload_immutable
BEFORE UPDATE ON mapping_versions
WHEN NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.mapping_version_id IS NOT OLD.mapping_version_id
  OR NEW.mapping_key IS NOT OLD.mapping_key
  OR NEW.version_number IS NOT OLD.version_number
  OR NEW.snapshot_id IS NOT OLD.snapshot_id
  OR NEW.dictionary_version IS NOT OLD.dictionary_version
  OR NEW.mapping_json IS NOT OLD.mapping_json
  OR NEW.mapping_hash IS NOT OLD.mapping_hash
  OR NEW.proposed_by IS NOT OLD.proposed_by
  OR NEW.proposed_at IS NOT OLD.proposed_at
BEGIN
  SELECT RAISE(ABORT, 'mapping version payload is immutable');
END;
CREATE TRIGGER IF NOT EXISTS mapping_versions_transition_only
BEFORE UPDATE ON mapping_versions
WHEN NEW.status = OLD.status BEGIN
  SELECT RAISE(ABORT, 'mapping version updates require a lifecycle transition');
END;
CREATE TRIGGER IF NOT EXISTS mapping_versions_transition_guard
BEFORE UPDATE ON mapping_versions
WHEN NOT (
  (OLD.status = 'proposed' AND NEW.status = 'validated') OR
  (OLD.status = 'validated' AND NEW.status = 'approved') OR
  (OLD.status = 'approved' AND NEW.status = 'active') OR
  (OLD.status = 'active' AND NEW.status = 'superseded')
) BEGIN
  SELECT RAISE(ABORT, 'illegal mapping lifecycle transition');
END;
CREATE TRIGGER IF NOT EXISTS mapping_versions_no_delete
BEFORE DELETE ON mapping_versions BEGIN
  SELECT RAISE(ABORT, 'mapping versions cannot be deleted');
END;

CREATE TRIGGER IF NOT EXISTS data_quality_runs_no_update
BEFORE UPDATE ON data_quality_runs BEGIN SELECT RAISE(ABORT, 'data quality runs are immutable'); END;
CREATE TRIGGER IF NOT EXISTS data_quality_runs_no_delete
BEFORE DELETE ON data_quality_runs BEGIN SELECT RAISE(ABORT, 'data quality runs are immutable'); END;
CREATE TRIGGER IF NOT EXISTS data_quality_findings_no_update
BEFORE UPDATE ON data_quality_findings BEGIN SELECT RAISE(ABORT, 'data quality findings are immutable'); END;
CREATE TRIGGER IF NOT EXISTS data_quality_findings_no_delete
BEFORE DELETE ON data_quality_findings BEGIN SELECT RAISE(ABORT, 'data quality findings are immutable'); END;
CREATE TRIGGER IF NOT EXISTS reconciliations_no_update
BEFORE UPDATE ON reconciliations BEGIN SELECT RAISE(ABORT, 'reconciliations are immutable'); END;
CREATE TRIGGER IF NOT EXISTS reconciliations_no_delete
BEFORE DELETE ON reconciliations BEGIN SELECT RAISE(ABORT, 'reconciliations are immutable'); END;
CREATE TRIGGER IF NOT EXISTS analysis_manifests_no_update
BEFORE UPDATE ON analysis_manifests BEGIN SELECT RAISE(ABORT, 'analysis manifests are immutable'); END;
CREATE TRIGGER IF NOT EXISTS analysis_manifests_no_delete
BEFORE DELETE ON analysis_manifests BEGIN SELECT RAISE(ABORT, 'analysis manifests are immutable'); END;
CREATE TRIGGER IF NOT EXISTS analysis_artifacts_no_update
BEFORE UPDATE ON analysis_artifacts BEGIN SELECT RAISE(ABORT, 'analysis artifacts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS analysis_artifacts_no_delete
BEFORE DELETE ON analysis_artifacts BEGIN SELECT RAISE(ABORT, 'analysis artifacts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS idempotency_records_no_update
BEFORE UPDATE ON idempotency_records BEGIN SELECT RAISE(ABORT, 'idempotency records are immutable'); END;
CREATE TRIGGER IF NOT EXISTS idempotency_records_no_delete
BEFORE DELETE ON idempotency_records BEGIN SELECT RAISE(ABORT, 'idempotency records are immutable'); END;
`;

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CONTENT_HASH_PATTERN = /^(?:sha256:)?[a-f0-9]{64}$/;

/**
 * A durable, tenant-isolated control-plane store. It opens and writes only the
 * SQLite path supplied to the constructor; source-system adapters are never
 * accepted by this API, which makes source writes structurally impossible.
 */
export class ControlStore {
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;
  #closed = false;

  constructor(path: string, options: ControlStoreOptions = {}) {
    if (!path.trim()) invalid("path", "must not be blank");
    const busyTimeoutMs = options.busyTimeoutMs ?? 5_000;
    if (!Number.isSafeInteger(busyTimeoutMs) || busyTimeoutMs < 0 || busyTimeoutMs > 60_000) {
      invalid("busyTimeoutMs", "must be an integer between 0 and 60000");
    }

    this.#clock = options.clock ?? (() => new Date());
    this.#database = new DatabaseSync(path, {
      enableForeignKeyConstraints: true,
      allowExtension: false
    });
    try {
      this.#database.exec(`PRAGMA busy_timeout = ${busyTimeoutMs}`);
      this.#database.exec("PRAGMA journal_mode = WAL");
      this.#migrate();
    } catch (error) {
      this.#database.close();
      this.#closed = true;
      throw error;
    }
  }

  createDatasetSnapshot(input: CreateDatasetSnapshotInput): DatasetSnapshot {
    validateSnapshotInput(input);
    return this.#idempotent(
      input.tenantId,
      "dataset_snapshot.create",
      input.idempotencyKey,
      input,
      () => {
        if (this.getDatasetSnapshot(input.tenantId, input.snapshotId)) {
          conflict(`Dataset snapshot '${input.snapshotId}' already exists for tenant '${input.tenantId}'`);
        }
        const createdAt = this.#now();
        this.#database
          .prepare(
            `INSERT INTO dataset_snapshots (
               tenant_id, snapshot_id, source_id, source_locator, as_of_date,
               content_hash, row_count, schema_json, created_by, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .run(
            input.tenantId,
            input.snapshotId,
            input.sourceId,
            input.sourceLocator,
            input.asOfDate,
            input.contentHash,
            input.rowCount,
            canonicalJson(input.schema),
            input.createdBy,
            createdAt
          );
        this.#insertAudit(
          input.tenantId,
          "dataset_snapshot.created",
          "dataset_snapshot",
          input.snapshotId,
          input.createdBy,
          {
            contentHash: input.contentHash,
            rowCount: input.rowCount,
            sourceId: input.sourceId
          },
          createdAt
        );
        return required(this.getDatasetSnapshot(input.tenantId, input.snapshotId));
      }
    );
  }

  getDatasetSnapshot(tenantId: string, snapshotId: string): DatasetSnapshot | undefined {
    this.#assertOpen();
    scopedId("tenantId", tenantId);
    scopedId("snapshotId", snapshotId);
    const row = this.#database
      .prepare(
        `SELECT tenant_id, snapshot_id, source_id, source_locator, as_of_date,
                content_hash, row_count, schema_json, created_by, created_at
           FROM dataset_snapshots
          WHERE tenant_id = ? AND snapshot_id = ?`
      )
      .get(tenantId, snapshotId) as unknown as DatasetSnapshotRow | undefined;
    return row ? snapshotFromRow(row) : undefined;
  }

  listDatasetSnapshots(tenantId: string): readonly DatasetSnapshot[] {
    this.#assertOpen();
    scopedId("tenantId", tenantId);
    const rows = this.#database
      .prepare(
        `SELECT tenant_id, snapshot_id, source_id, source_locator, as_of_date,
                content_hash, row_count, schema_json, created_by, created_at
           FROM dataset_snapshots
          WHERE tenant_id = ?
          ORDER BY created_at, snapshot_id`
      )
      .all(tenantId) as unknown as DatasetSnapshotRow[];
    return rows.map(snapshotFromRow);
  }

  proposeMappingVersion(input: ProposeMappingVersionInput): MappingVersion {
    validateProposeMappingInput(input);
    return this.#idempotent(
      input.tenantId,
      "mapping_version.propose",
      input.idempotencyKey,
      input,
      () => {
        this.#requireSnapshot(input.tenantId, input.snapshotId);
        if (this.getMappingVersion(input.tenantId, input.mappingVersionId)) {
          conflict(`Mapping version '${input.mappingVersionId}' already exists for tenant '${input.tenantId}'`);
        }
        const versionRow = this.#database
          .prepare(
            `SELECT COALESCE(MAX(version_number), 0) + 1 AS next_version
               FROM mapping_versions
              WHERE tenant_id = ? AND mapping_key = ?`
          )
          .get(input.tenantId, input.mappingKey) as unknown as { readonly next_version: number };
        const proposedAt = this.#now();
        const mappingJson = canonicalJson(input.mappings);
        const mappingHash = sha256(
          canonicalJson({
            dictionaryVersion: input.dictionaryVersion,
            mappings: input.mappings
          })
        );
        this.#database
          .prepare(
            `INSERT INTO mapping_versions (
               tenant_id, mapping_version_id, mapping_key, version_number,
               snapshot_id, dictionary_version, mapping_json, mapping_hash,
               status, proposed_by, proposed_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?, ?)`
          )
          .run(
            input.tenantId,
            input.mappingVersionId,
            input.mappingKey,
            versionRow.next_version,
            input.snapshotId,
            input.dictionaryVersion,
            mappingJson,
            mappingHash,
            input.proposedBy,
            proposedAt
          );
        this.#insertAudit(
          input.tenantId,
          "mapping_version.proposed",
          "mapping_version",
          input.mappingVersionId,
          input.proposedBy,
          {
            mappingHash,
            mappingKey: input.mappingKey,
            snapshotId: input.snapshotId,
            version: versionRow.next_version
          },
          proposedAt
        );
        return required(this.getMappingVersion(input.tenantId, input.mappingVersionId));
      }
    );
  }

  transitionMappingVersion(input: TransitionMappingVersionInput): MappingVersion {
    validateTransitionInput(input);
    return this.#idempotent(
      input.tenantId,
      "mapping_version.transition",
      input.idempotencyKey,
      input,
      () => {
        const current = this.getMappingVersion(input.tenantId, input.mappingVersionId);
        if (!current) notFound("Mapping version", input.mappingVersionId, input.tenantId);
        const expected: Readonly<Record<MappingTransitionStatus, MappingStatus>> = {
          validated: "proposed",
          approved: "validated",
          active: "approved"
        };
        if (current.status !== expected[input.toStatus]) {
          throw new ControlStoreError(
            "ILLEGAL_TRANSITION",
            `Cannot transition mapping '${input.mappingVersionId}' from '${current.status}' to '${input.toStatus}'`
          );
        }
        if (input.actor === current.proposedBy) {
          throw new ControlStoreError(
            "MAKER_CHECKER_VIOLATION",
            `Proposer '${current.proposedBy}' cannot ${transitionVerb(input.toStatus)} their own mapping version`
          );
        }

        const occurredAt = this.#now();
        if (input.toStatus === "validated") {
          this.#database
            .prepare(
              `UPDATE mapping_versions
                  SET status = 'validated', validated_by = ?, validated_at = ?
                WHERE tenant_id = ? AND mapping_version_id = ? AND status = 'proposed'`
            )
            .run(input.actor, occurredAt, input.tenantId, input.mappingVersionId);
        } else if (input.toStatus === "approved") {
          this.#database
            .prepare(
              `UPDATE mapping_versions
                  SET status = 'approved', approved_by = ?, approved_at = ?
                WHERE tenant_id = ? AND mapping_version_id = ? AND status = 'validated'`
            )
            .run(input.actor, occurredAt, input.tenantId, input.mappingVersionId);
        } else {
          const priorActive = this.#database
            .prepare(
              `SELECT mapping_version_id
                 FROM mapping_versions
                WHERE tenant_id = ? AND mapping_key = ? AND status = 'active'`
            )
            .get(input.tenantId, current.mappingKey) as unknown as
            | { readonly mapping_version_id: string }
            | undefined;
          if (priorActive) {
            this.#database
              .prepare(
                `UPDATE mapping_versions
                    SET status = 'superseded', superseded_by = ?, superseded_at = ?
                  WHERE tenant_id = ? AND mapping_version_id = ? AND status = 'active'`
              )
              .run(input.actor, occurredAt, input.tenantId, priorActive.mapping_version_id);
            this.#insertAudit(
              input.tenantId,
              "mapping_version.superseded",
              "mapping_version",
              priorActive.mapping_version_id,
              input.actor,
              { replacementMappingVersionId: input.mappingVersionId },
              occurredAt
            );
          }
          this.#database
            .prepare(
              `UPDATE mapping_versions
                  SET status = 'active', activated_by = ?, activated_at = ?
                WHERE tenant_id = ? AND mapping_version_id = ? AND status = 'approved'`
            )
            .run(input.actor, occurredAt, input.tenantId, input.mappingVersionId);
        }

        this.#insertAudit(
          input.tenantId,
          `mapping_version.${input.toStatus}`,
          "mapping_version",
          input.mappingVersionId,
          input.actor,
          input.evidence === undefined ? {} : { evidence: input.evidence },
          occurredAt
        );
        return required(this.getMappingVersion(input.tenantId, input.mappingVersionId));
      }
    );
  }

  getMappingVersion(tenantId: string, mappingVersionId: string): MappingVersion | undefined {
    this.#assertOpen();
    scopedId("tenantId", tenantId);
    scopedId("mappingVersionId", mappingVersionId);
    const row = this.#database
      .prepare(
        `SELECT tenant_id, mapping_version_id, mapping_key, version_number,
                snapshot_id, dictionary_version, mapping_json, mapping_hash, status,
                proposed_by, proposed_at, validated_by, validated_at, approved_by,
                approved_at, activated_by, activated_at, superseded_by, superseded_at
           FROM mapping_versions
          WHERE tenant_id = ? AND mapping_version_id = ?`
      )
      .get(tenantId, mappingVersionId) as unknown as MappingVersionRow | undefined;
    return row ? mappingFromRow(row) : undefined;
  }

  listMappingVersions(tenantId: string, mappingKey?: string): readonly MappingVersion[] {
    this.#assertOpen();
    scopedId("tenantId", tenantId);
    if (mappingKey !== undefined) scopedId("mappingKey", mappingKey);
    const columns = `tenant_id, mapping_version_id, mapping_key, version_number,
      snapshot_id, dictionary_version, mapping_json, mapping_hash, status,
      proposed_by, proposed_at, validated_by, validated_at, approved_by,
      approved_at, activated_by, activated_at, superseded_by, superseded_at`;
    const rows = mappingKey === undefined
      ? this.#database
          .prepare(
            `SELECT ${columns} FROM mapping_versions
              WHERE tenant_id = ? ORDER BY mapping_key, version_number`
          )
          .all(tenantId)
      : this.#database
          .prepare(
            `SELECT ${columns} FROM mapping_versions
              WHERE tenant_id = ? AND mapping_key = ? ORDER BY version_number`
          )
          .all(tenantId, mappingKey);
    return (rows as unknown as MappingVersionRow[]).map(mappingFromRow);
  }

  recordDataQualityRun(input: RecordDataQualityRunInput): DataQualityRun {
    validateDataQualityRunInput(input);
    return this.#idempotent(
      input.tenantId,
      "data_quality_run.record",
      input.idempotencyKey,
      input,
      () => {
        this.#requireSnapshot(input.tenantId, input.snapshotId);
        if (this.getDataQualityRun(input.tenantId, input.runId)) {
          conflict(`Data quality run '${input.runId}' already exists for tenant '${input.tenantId}'`);
        }
        const executedAt = this.#now();
        const failedFindingCount = input.findings.filter((finding) => !finding.passed).length;
        const passed = failedFindingCount === 0;
        this.#database
          .prepare(
            `INSERT INTO data_quality_runs (
               tenant_id, run_id, snapshot_id, ruleset_id, ruleset_hash, passed,
               finding_count, failed_finding_count, executed_by, executed_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .run(
            input.tenantId,
            input.runId,
            input.snapshotId,
            input.rulesetId,
            input.rulesetHash,
            passed ? 1 : 0,
            input.findings.length,
            failedFindingCount,
            input.executedBy,
            executedAt
          );
        const insertFinding = this.#database.prepare(
          `INSERT INTO data_quality_findings (
             tenant_id, run_id, finding_id, rule_id, severity, passed,
             affected_rows, message, evidence_json
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        );
        for (const finding of input.findings) {
          insertFinding.run(
            input.tenantId,
            input.runId,
            finding.findingId,
            finding.ruleId,
            finding.severity,
            finding.passed ? 1 : 0,
            finding.affectedRows,
            finding.message,
            finding.evidence === undefined ? null : canonicalJson(finding.evidence)
          );
        }
        this.#insertAudit(
          input.tenantId,
          "data_quality_run.recorded",
          "data_quality_run",
          input.runId,
          input.executedBy,
          {
            failedFindingCount,
            findingCount: input.findings.length,
            passed,
            rulesetHash: input.rulesetHash,
            snapshotId: input.snapshotId
          },
          executedAt
        );
        return required(this.getDataQualityRun(input.tenantId, input.runId));
      }
    );
  }

  getDataQualityRun(tenantId: string, runId: string): DataQualityRun | undefined {
    this.#assertOpen();
    scopedId("tenantId", tenantId);
    scopedId("runId", runId);
    const row = this.#database
      .prepare(
        `SELECT tenant_id, run_id, snapshot_id, ruleset_id, ruleset_hash, passed,
                finding_count, failed_finding_count, executed_by, executed_at
           FROM data_quality_runs
          WHERE tenant_id = ? AND run_id = ?`
      )
      .get(tenantId, runId) as unknown as DataQualityRunRow | undefined;
    if (!row) return undefined;
    const findings = this.#database
      .prepare(
        `SELECT tenant_id, run_id, finding_id, rule_id, severity, passed,
                affected_rows, message, evidence_json
           FROM data_quality_findings
          WHERE tenant_id = ? AND run_id = ?
          ORDER BY finding_id`
      )
      .all(tenantId, runId) as unknown as DataQualityFindingRow[];
    return dataQualityRunFromRows(row, findings);
  }

  recordReconciliation(input: RecordReconciliationInput): Reconciliation {
    validateReconciliationInput(input);
    return this.#idempotent(
      input.tenantId,
      "reconciliation.record",
      input.idempotencyKey,
      input,
      () => {
        this.#requireSnapshot(input.tenantId, input.snapshotId);
        if (this.getReconciliation(input.tenantId, input.reconciliationId)) {
          conflict(`Reconciliation '${input.reconciliationId}' already exists for tenant '${input.tenantId}'`);
        }
        const performedAt = this.#now();
        const passed = input.checks.every((check) => check.passed);
        this.#database
          .prepare(
            `INSERT INTO reconciliations (
               tenant_id, reconciliation_id, snapshot_id, kind, checks_json,
               passed, details_json, performed_by, performed_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .run(
            input.tenantId,
            input.reconciliationId,
            input.snapshotId,
            input.kind,
            canonicalJson(input.checks),
            passed ? 1 : 0,
            input.details === undefined ? null : canonicalJson(input.details),
            input.performedBy,
            performedAt
          );
        this.#insertAudit(
          input.tenantId,
          "reconciliation.recorded",
          "reconciliation",
          input.reconciliationId,
          input.performedBy,
          { checkCount: input.checks.length, passed, snapshotId: input.snapshotId },
          performedAt
        );
        return required(this.getReconciliation(input.tenantId, input.reconciliationId));
      }
    );
  }

  getReconciliation(tenantId: string, reconciliationId: string): Reconciliation | undefined {
    this.#assertOpen();
    scopedId("tenantId", tenantId);
    scopedId("reconciliationId", reconciliationId);
    const row = this.#database
      .prepare(
        `SELECT tenant_id, reconciliation_id, snapshot_id, kind, checks_json,
                passed, details_json, performed_by, performed_at
           FROM reconciliations
          WHERE tenant_id = ? AND reconciliation_id = ?`
      )
      .get(tenantId, reconciliationId) as unknown as ReconciliationRow | undefined;
    return row ? reconciliationFromRow(row) : undefined;
  }

  recordAnalysisManifest(input: RecordAnalysisManifestInput): AnalysisManifest {
    validateAnalysisManifestInput(input);
    return this.#idempotent(
      input.tenantId,
      "analysis_manifest.record",
      input.idempotencyKey,
      input,
      () => {
        this.#requireSnapshot(input.tenantId, input.snapshotId);
        const mapping = this.getMappingVersion(input.tenantId, input.mappingVersionId);
        if (!mapping) notFound("Mapping version", input.mappingVersionId, input.tenantId);
        if (mapping.snapshotId !== input.snapshotId) {
          conflict(
            `Mapping '${input.mappingVersionId}' belongs to snapshot '${mapping.snapshotId}', not '${input.snapshotId}'`
          );
        }
        if (mapping.status !== "active") {
          throw new ControlStoreError(
            "ILLEGAL_TRANSITION",
            `Analysis manifests require an active mapping; '${input.mappingVersionId}' is '${mapping.status}'`
          );
        }
        if (this.getAnalysisManifest(input.tenantId, input.manifestId)) {
          conflict(`Analysis manifest '${input.manifestId}' already exists for tenant '${input.tenantId}'`);
        }
        const createdAt = this.#now();
        const manifestHash = sha256(
          canonicalJson({
            analysisType: input.analysisType,
            artifacts: input.artifacts,
            codeVersion: input.codeVersion,
            mappingVersionId: input.mappingVersionId,
            parameters: input.parameters,
            queryHash: input.queryHash,
            snapshotId: input.snapshotId
          })
        );
        this.#database
          .prepare(
            `INSERT INTO analysis_manifests (
               tenant_id, manifest_id, snapshot_id, mapping_version_id, analysis_type,
               parameters_json, query_hash, code_version, manifest_hash, created_by, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .run(
            input.tenantId,
            input.manifestId,
            input.snapshotId,
            input.mappingVersionId,
            input.analysisType,
            canonicalJson(input.parameters),
            input.queryHash,
            input.codeVersion,
            manifestHash,
            input.createdBy,
            createdAt
          );
        const insertArtifact = this.#database.prepare(
          `INSERT INTO analysis_artifacts (
             tenant_id, manifest_id, artifact_id, kind, media_type,
             content_hash, uri, metadata_json, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        );
        for (const artifact of input.artifacts) {
          insertArtifact.run(
            input.tenantId,
            input.manifestId,
            artifact.artifactId,
            artifact.kind,
            artifact.mediaType,
            artifact.contentHash,
            artifact.uri ?? null,
            artifact.metadata === undefined ? null : canonicalJson(artifact.metadata),
            createdAt
          );
        }
        this.#insertAudit(
          input.tenantId,
          "analysis_manifest.recorded",
          "analysis_manifest",
          input.manifestId,
          input.createdBy,
          {
            analysisType: input.analysisType,
            artifactCount: input.artifacts.length,
            manifestHash,
            mappingVersionId: input.mappingVersionId,
            snapshotId: input.snapshotId
          },
          createdAt
        );
        return required(this.getAnalysisManifest(input.tenantId, input.manifestId));
      }
    );
  }

  getAnalysisManifest(tenantId: string, manifestId: string): AnalysisManifest | undefined {
    this.#assertOpen();
    scopedId("tenantId", tenantId);
    scopedId("manifestId", manifestId);
    const row = this.#database
      .prepare(
        `SELECT tenant_id, manifest_id, snapshot_id, mapping_version_id, analysis_type,
                parameters_json, query_hash, code_version, manifest_hash, created_by, created_at
           FROM analysis_manifests
          WHERE tenant_id = ? AND manifest_id = ?`
      )
      .get(tenantId, manifestId) as unknown as AnalysisManifestRow | undefined;
    if (!row) return undefined;
    const artifacts = this.#database
      .prepare(
        `SELECT tenant_id, manifest_id, artifact_id, kind, media_type,
                content_hash, uri, metadata_json, created_at
           FROM analysis_artifacts
          WHERE tenant_id = ? AND manifest_id = ?
          ORDER BY artifact_id`
      )
      .all(tenantId, manifestId) as unknown as AnalysisArtifactRow[];
    return analysisManifestFromRows(row, artifacts);
  }

  appendAuditEvent(input: AppendAuditEventInput): AuditEvent {
    validateAppendAuditInput(input);
    return this.#idempotent(
      input.tenantId,
      "audit_event.append",
      input.idempotencyKey,
      input,
      () =>
        this.#insertAudit(
          input.tenantId,
          input.eventType,
          input.entityType,
          input.entityId,
          input.actor,
          input.details,
          this.#now()
        )
    );
  }

  listAuditEvents(tenantId: string, options: ListAuditEventsOptions = {}): readonly AuditEvent[] {
    this.#assertOpen();
    scopedId("tenantId", tenantId);
    const afterSequence = options.afterSequence ?? 0;
    const limit = options.limit ?? 100;
    if (!Number.isSafeInteger(afterSequence) || afterSequence < 0) {
      invalid("afterSequence", "must be a non-negative integer");
    }
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      invalid("limit", "must be an integer between 1 and 1000");
    }
    const rows = this.#database
      .prepare(
        `SELECT sequence, tenant_id, event_id, event_type, entity_type,
                entity_id, actor, details_json, occurred_at
           FROM audit_events
          WHERE tenant_id = ? AND sequence > ?
          ORDER BY sequence
          LIMIT ?`
      )
      .all(tenantId, afterSequence, limit) as unknown as AuditEventRow[];
    return rows.map(auditFromRow);
  }

  close(): void {
    if (this.#closed) return;
    this.#database.close();
    this.#closed = true;
  }

  #migrate(): void {
    migrateSqliteComponent(this.#database, {
      componentName: CONTROL_STORE_COMPONENT,
      supportedVersion: CONTROL_STORE_SCHEMA_VERSION,
      migrations: [{ version: 1, sql: SCHEMA_SQL }],
      sharedObjects: SQLITE_SHARED_AUDIT_OBJECTS,
      unsupportedVersionError: (current, supported) =>
        new ControlStoreError(
          "CONFLICT",
          `Control-store schema ${current} is newer than supported version ${supported}`
        )
    });
  }

  #idempotent<T>(
    tenantId: string,
    operation: string,
    idempotencyKey: string,
    request: unknown,
    execute: () => T
  ): T {
    this.#assertOpen();
    scopedId("tenantId", tenantId);
    scopedId("idempotencyKey", idempotencyKey);
    const requestHash = sha256(canonicalJson(request));
    return this.#transaction(() => {
      const existing = this.#database
        .prepare(
          `SELECT request_hash, response_json
             FROM idempotency_records
            WHERE tenant_id = ? AND operation = ? AND idempotency_key = ?`
        )
        .get(tenantId, operation, idempotencyKey) as unknown as IdempotencyRow | undefined;
      if (existing) {
        if (existing.request_hash !== requestHash) {
          throw new ControlStoreError(
            "IDEMPOTENCY_CONFLICT",
            `Idempotency key '${idempotencyKey}' was already used with a different ${operation} request`
          );
        }
        return parseJson<T>(existing.response_json);
      }

      const response = execute();
      this.#database
        .prepare(
          `INSERT INTO idempotency_records (
             tenant_id, operation, idempotency_key, request_hash, response_json, created_at
           ) VALUES (?, ?, ?, ?, ?, ?)`
        )
        .run(
          tenantId,
          operation,
          idempotencyKey,
          requestHash,
          canonicalJson(response),
          this.#now()
        );
      return response;
    });
  }

  #transaction<T>(operation: () => T): T {
    this.#assertOpen();
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      this.#database.exec("ROLLBACK");
      throw error;
    }
  }

  #insertAudit(
    tenantId: string,
    eventType: string,
    entityType: string,
    entityId: string,
    actor: string,
    details: JsonValue,
    occurredAt: string
  ): AuditEvent {
    const eventId = randomUUID();
    const result = this.#database
      .prepare(
        `INSERT INTO audit_events (
           tenant_id, event_id, event_type, entity_type, entity_id,
           actor, details_json, occurred_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        tenantId,
        eventId,
        eventType,
        entityType,
        entityId,
        actor,
        canonicalJson(details),
        occurredAt
      );
    const sequence = Number(result.lastInsertRowid);
    return {
      sequence,
      tenantId,
      eventId,
      eventType,
      entityType,
      entityId,
      actor,
      details,
      occurredAt
    };
  }

  #requireSnapshot(tenantId: string, snapshotId: string): DatasetSnapshot {
    const snapshot = this.getDatasetSnapshot(tenantId, snapshotId);
    if (!snapshot) notFound("Dataset snapshot", snapshotId, tenantId);
    return snapshot;
  }

  #now(): string {
    const value = this.#clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw new ControlStoreError("INVALID_ARGUMENT", "clock must return a valid Date");
    }
    return value.toISOString();
  }

  #assertOpen(): void {
    if (this.#closed) throw new ControlStoreError("STORE_CLOSED", "Control store is closed");
  }
}

function validateSnapshotInput(input: CreateDatasetSnapshotInput): void {
  scopedId("tenantId", input.tenantId);
  scopedId("snapshotId", input.snapshotId);
  scopedId("sourceId", input.sourceId);
  scopedId("createdBy", input.createdBy);
  scopedId("idempotencyKey", input.idempotencyKey);
  nonBlank("sourceLocator", input.sourceLocator);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(input.asOfDate) || !validIsoDate(input.asOfDate)) {
    invalid("asOfDate", "must be a real calendar date in YYYY-MM-DD form");
  }
  contentHash("contentHash", input.contentHash);
  nonNegativeInteger("rowCount", input.rowCount);
  canonicalJson(input.schema);
}

function validateProposeMappingInput(input: ProposeMappingVersionInput): void {
  scopedId("tenantId", input.tenantId);
  scopedId("mappingVersionId", input.mappingVersionId);
  scopedId("mappingKey", input.mappingKey);
  scopedId("snapshotId", input.snapshotId);
  scopedId("proposedBy", input.proposedBy);
  scopedId("idempotencyKey", input.idempotencyKey);
  nonBlank("dictionaryVersion", input.dictionaryVersion);
  if (input.mappings.length === 0) invalid("mappings", "must contain at least one mapping");
  const sourceColumns = new Set<string>();
  const canonicalFields = new Set<string>();
  for (const [index, mapping] of input.mappings.entries()) {
    nonBlank(`mappings[${index}].sourceColumn`, mapping.sourceColumn);
    nonBlank(`mappings[${index}].canonicalField`, mapping.canonicalField);
    if (sourceColumns.has(mapping.sourceColumn)) {
      invalid("mappings", `contains duplicate source column '${mapping.sourceColumn}'`);
    }
    if (canonicalFields.has(mapping.canonicalField)) {
      invalid("mappings", `contains duplicate canonical field '${mapping.canonicalField}'`);
    }
    sourceColumns.add(mapping.sourceColumn);
    canonicalFields.add(mapping.canonicalField);
  }
}

function validateTransitionInput(input: TransitionMappingVersionInput): void {
  scopedId("tenantId", input.tenantId);
  scopedId("mappingVersionId", input.mappingVersionId);
  scopedId("actor", input.actor);
  scopedId("idempotencyKey", input.idempotencyKey);
  if (!(input.toStatus === "validated" || input.toStatus === "approved" || input.toStatus === "active")) {
    invalid("toStatus", "must be validated, approved, or active");
  }
  if (input.evidence !== undefined) canonicalJson(input.evidence);
}

function validateDataQualityRunInput(input: RecordDataQualityRunInput): void {
  scopedId("tenantId", input.tenantId);
  scopedId("runId", input.runId);
  scopedId("snapshotId", input.snapshotId);
  scopedId("rulesetId", input.rulesetId);
  scopedId("executedBy", input.executedBy);
  scopedId("idempotencyKey", input.idempotencyKey);
  contentHash("rulesetHash", input.rulesetHash);
  const ids = new Set<string>();
  for (const [index, finding] of input.findings.entries()) {
    scopedId(`findings[${index}].findingId`, finding.findingId);
    scopedId(`findings[${index}].ruleId`, finding.ruleId);
    if (!(finding.severity === "info" || finding.severity === "warning" || finding.severity === "error")) {
      invalid(`findings[${index}].severity`, "must be info, warning, or error");
    }
    nonNegativeInteger(`findings[${index}].affectedRows`, finding.affectedRows);
    nonBlank(`findings[${index}].message`, finding.message);
    if (ids.has(finding.findingId)) invalid("findings", `contains duplicate id '${finding.findingId}'`);
    ids.add(finding.findingId);
    if (finding.evidence !== undefined) canonicalJson(finding.evidence);
  }
}

function validateReconciliationInput(input: RecordReconciliationInput): void {
  scopedId("tenantId", input.tenantId);
  scopedId("reconciliationId", input.reconciliationId);
  scopedId("snapshotId", input.snapshotId);
  scopedId("performedBy", input.performedBy);
  scopedId("idempotencyKey", input.idempotencyKey);
  scopedId("kind", input.kind);
  if (input.checks.length === 0) invalid("checks", "must contain at least one reconciliation check");
  const ids = new Set<string>();
  for (const [index, check] of input.checks.entries()) {
    scopedId(`checks[${index}].checkId`, check.checkId);
    nonBlank(`checks[${index}].expected`, check.expected);
    nonBlank(`checks[${index}].actual`, check.actual);
    nonBlank(`checks[${index}].difference`, check.difference);
    if (check.tolerance !== undefined) nonBlank(`checks[${index}].tolerance`, check.tolerance);
    if (ids.has(check.checkId)) invalid("checks", `contains duplicate id '${check.checkId}'`);
    ids.add(check.checkId);
  }
  if (input.details !== undefined) canonicalJson(input.details);
}

function validateAnalysisManifestInput(input: RecordAnalysisManifestInput): void {
  scopedId("tenantId", input.tenantId);
  scopedId("manifestId", input.manifestId);
  scopedId("snapshotId", input.snapshotId);
  scopedId("mappingVersionId", input.mappingVersionId);
  scopedId("analysisType", input.analysisType);
  scopedId("createdBy", input.createdBy);
  scopedId("idempotencyKey", input.idempotencyKey);
  nonBlank("codeVersion", input.codeVersion);
  contentHash("queryHash", input.queryHash);
  canonicalJson(input.parameters);
  const ids = new Set<string>();
  for (const [index, artifact] of input.artifacts.entries()) {
    scopedId(`artifacts[${index}].artifactId`, artifact.artifactId);
    scopedId(`artifacts[${index}].kind`, artifact.kind);
    nonBlank(`artifacts[${index}].mediaType`, artifact.mediaType);
    contentHash(`artifacts[${index}].contentHash`, artifact.contentHash);
    if (artifact.uri !== undefined) nonBlank(`artifacts[${index}].uri`, artifact.uri);
    if (artifact.metadata !== undefined) canonicalJson(artifact.metadata);
    if (ids.has(artifact.artifactId)) invalid("artifacts", `contains duplicate id '${artifact.artifactId}'`);
    ids.add(artifact.artifactId);
  }
}

function validateAppendAuditInput(input: AppendAuditEventInput): void {
  scopedId("tenantId", input.tenantId);
  scopedId("eventType", input.eventType);
  scopedId("entityType", input.entityType);
  scopedId("entityId", input.entityId);
  scopedId("actor", input.actor);
  scopedId("idempotencyKey", input.idempotencyKey);
  canonicalJson(input.details);
}

function snapshotFromRow(row: DatasetSnapshotRow): DatasetSnapshot {
  return {
    tenantId: row.tenant_id,
    snapshotId: row.snapshot_id,
    sourceId: row.source_id,
    sourceLocator: row.source_locator,
    asOfDate: row.as_of_date,
    contentHash: row.content_hash,
    rowCount: row.row_count,
    schema: parseJson(row.schema_json),
    createdBy: row.created_by,
    createdAt: row.created_at
  };
}

function mappingFromRow(row: MappingVersionRow): MappingVersion {
  return {
    tenantId: row.tenant_id,
    mappingVersionId: row.mapping_version_id,
    mappingKey: row.mapping_key,
    version: row.version_number,
    snapshotId: row.snapshot_id,
    dictionaryVersion: row.dictionary_version,
    mappings: parseJson<readonly FieldMapping[]>(row.mapping_json),
    mappingHash: row.mapping_hash,
    status: row.status,
    proposedBy: row.proposed_by,
    proposedAt: row.proposed_at,
    ...(row.validated_by === null ? {} : { validatedBy: row.validated_by }),
    ...(row.validated_at === null ? {} : { validatedAt: row.validated_at }),
    ...(row.approved_by === null ? {} : { approvedBy: row.approved_by }),
    ...(row.approved_at === null ? {} : { approvedAt: row.approved_at }),
    ...(row.activated_by === null ? {} : { activatedBy: row.activated_by }),
    ...(row.activated_at === null ? {} : { activatedAt: row.activated_at }),
    ...(row.superseded_by === null ? {} : { supersededBy: row.superseded_by }),
    ...(row.superseded_at === null ? {} : { supersededAt: row.superseded_at })
  };
}

function dataQualityRunFromRows(
  run: DataQualityRunRow,
  findingRows: readonly DataQualityFindingRow[]
): DataQualityRun {
  return {
    tenantId: run.tenant_id,
    runId: run.run_id,
    snapshotId: run.snapshot_id,
    rulesetId: run.ruleset_id,
    rulesetHash: run.ruleset_hash,
    passed: run.passed === 1,
    findingCount: run.finding_count,
    failedFindingCount: run.failed_finding_count,
    findings: findingRows.map((finding) => ({
      tenantId: finding.tenant_id,
      runId: finding.run_id,
      findingId: finding.finding_id,
      ruleId: finding.rule_id,
      severity: finding.severity,
      passed: finding.passed === 1,
      affectedRows: finding.affected_rows,
      message: finding.message,
      ...(finding.evidence_json === null ? {} : { evidence: parseJson(finding.evidence_json) })
    })),
    executedBy: run.executed_by,
    executedAt: run.executed_at
  };
}

function reconciliationFromRow(row: ReconciliationRow): Reconciliation {
  return {
    tenantId: row.tenant_id,
    reconciliationId: row.reconciliation_id,
    snapshotId: row.snapshot_id,
    kind: row.kind,
    checks: parseJson<readonly ReconciliationCheck[]>(row.checks_json),
    passed: row.passed === 1,
    ...(row.details_json === null ? {} : { details: parseJson(row.details_json) }),
    performedBy: row.performed_by,
    performedAt: row.performed_at
  };
}

function analysisManifestFromRows(
  manifest: AnalysisManifestRow,
  artifactRows: readonly AnalysisArtifactRow[]
): AnalysisManifest {
  return {
    tenantId: manifest.tenant_id,
    manifestId: manifest.manifest_id,
    snapshotId: manifest.snapshot_id,
    mappingVersionId: manifest.mapping_version_id,
    analysisType: manifest.analysis_type,
    parameters: parseJson(manifest.parameters_json),
    queryHash: manifest.query_hash,
    codeVersion: manifest.code_version,
    manifestHash: manifest.manifest_hash,
    artifacts: artifactRows.map((artifact) => ({
      tenantId: artifact.tenant_id,
      manifestId: artifact.manifest_id,
      artifactId: artifact.artifact_id,
      kind: artifact.kind,
      mediaType: artifact.media_type,
      contentHash: artifact.content_hash,
      ...(artifact.uri === null ? {} : { uri: artifact.uri }),
      ...(artifact.metadata_json === null ? {} : { metadata: parseJson(artifact.metadata_json) }),
      createdAt: artifact.created_at
    })),
    createdBy: manifest.created_by,
    createdAt: manifest.created_at
  };
}

function auditFromRow(row: AuditEventRow): AuditEvent {
  return {
    sequence: row.sequence,
    tenantId: row.tenant_id,
    eventId: row.event_id,
    eventType: row.event_type,
    entityType: row.entity_type,
    entityId: row.entity_id,
    actor: row.actor,
    details: parseJson(row.details_json),
    occurredAt: row.occurred_at
  };
}

function transitionVerb(status: MappingTransitionStatus): string {
  if (status === "validated") return "validate";
  if (status === "approved") return "approve";
  return "activate";
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value, "$"));
}

function canonicalize(value: unknown, path: string): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) invalid(path, "contains a non-finite number");
    return Object.is(value, -0) ? 0 : value;
  }
  if (Array.isArray(value)) {
    return value.map((entry, index) => {
      if (entry === undefined) invalid(`${path}[${index}]`, "must not be undefined");
      return canonicalize(entry, `${path}[${index}]`);
    });
  }
  if (typeof value === "object") {
    if (value instanceof Date) {
      if (!Number.isFinite(value.getTime())) invalid(path, "contains an invalid Date");
      return value.toISOString();
    }
    const prototype = Object.getPrototypeOf(value) as unknown;
    if (!(prototype === Object.prototype || prototype === null)) {
      invalid(path, "must contain only JSON-compatible plain objects");
    }
    const output: Record<string, JsonValue> = {};
    for (const key of Object.keys(value).sort()) {
      const entry = (value as Record<string, unknown>)[key];
      if (entry !== undefined) output[key] = canonicalize(entry, `${path}.${key}`);
    }
    return output;
  }
  invalid(path, `contains unsupported JSON value of type '${typeof value}'`);
}

function parseJson<T = JsonValue>(value: string): T {
  return JSON.parse(value) as T;
}

function sha256(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function scopedId(name: string, value: string): void {
  if (!IDENTIFIER_PATTERN.test(value)) {
    invalid(name, "must be 1-128 characters using letters, digits, dot, underscore, colon, or hyphen");
  }
}

function contentHash(name: string, value: string): void {
  if (!CONTENT_HASH_PATTERN.test(value)) {
    invalid(name, "must be a lowercase SHA-256 digest, optionally prefixed with 'sha256:'");
  }
}

function nonBlank(name: string, value: string): void {
  if (!value.trim()) invalid(name, "must not be blank");
}

function nonNegativeInteger(name: string, value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) invalid(name, "must be a non-negative integer");
}

function validIsoDate(value: string): boolean {
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw new Error("Control-store invariant failed: expected persisted row");
  return value;
}

function invalid(name: string, detail: string): never {
  throw new ControlStoreError("INVALID_ARGUMENT", `${name} ${detail}`);
}

function conflict(message: string): never {
  throw new ControlStoreError("CONFLICT", message);
}

function notFound(entity: string, id: string, tenantId: string): never {
  throw new ControlStoreError(
    "NOT_FOUND",
    `${entity} '${id}' was not found for tenant '${tenantId}'`
  );
}
