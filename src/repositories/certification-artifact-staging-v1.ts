import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { z } from "zod";

import {
  createCertificationArtifactOutboxEventV1,
  createCertificationArtifactStageV1,
  deriveCertificationArtifactOutboxRecordV1,
  parseCertificationArtifactOutboxEventV1,
  parseCertificationArtifactStageV1,
  type CertificationArtifactOutboxEventV1,
  type CertificationArtifactOutboxRecordV1,
  type CertificationArtifactStageV1,
  type CertificationArtifactStageV1Input
} from "../contracts/certification-artifact-staging-v1.js";
import {
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  canonicalJson,
  parseWithSchema
} from "../contracts/canonical.js";
import { migrateSqliteComponent, type SqliteComponentMigration } from "../infrastructure/sqlite-component-schema.js";

export const SQLITE_CERTIFICATION_ARTIFACT_STAGING_COMPONENT =
  "abl.certification-artifact-staging" as const;
export const SQLITE_CERTIFICATION_ARTIFACT_STAGING_SCHEMA_VERSION = 1 as const;

const SQLITE_CERTIFICATION_ARTIFACT_STAGING_SCHEMA = `
CREATE TABLE certification_artifact_stages_v1 (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  certification_manifest_id TEXT NOT NULL CHECK (length(certification_manifest_id) BETWEEN 1 AND 128),
  attempt_hash TEXT NOT NULL CHECK (length(attempt_hash) = 71 AND attempt_hash GLOB 'sha256:*'),
  artifact_binding_hash TEXT NOT NULL CHECK (length(artifact_binding_hash) = 71 AND artifact_binding_hash GLOB 'sha256:*'),
  stage_hash TEXT NOT NULL CHECK (length(stage_hash) = 71 AND stage_hash GLOB 'sha256:*'),
  prepared_at TEXT NOT NULL,
  stage_json TEXT NOT NULL CHECK (json_valid(stage_json)),
  PRIMARY KEY (tenant_id, certification_manifest_id),
  UNIQUE (tenant_id, stage_hash)
) STRICT;

CREATE TABLE certification_artifact_outbox_events_v1 (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  certification_manifest_id TEXT NOT NULL CHECK (length(certification_manifest_id) BETWEEN 1 AND 128),
  sequence INTEGER NOT NULL CHECK (sequence > 0),
  event_type TEXT NOT NULL CHECK (event_type IN (
    'artifact_prepared', 'certification_evidence_failed', 'certification_evidence_committed'
  )),
  stage_hash TEXT NOT NULL CHECK (length(stage_hash) = 71 AND stage_hash GLOB 'sha256:*'),
  event_hash TEXT NOT NULL CHECK (length(event_hash) = 71 AND event_hash GLOB 'sha256:*'),
  occurred_at TEXT NOT NULL,
  event_json TEXT NOT NULL CHECK (json_valid(event_json)),
  PRIMARY KEY (tenant_id, certification_manifest_id, sequence),
  UNIQUE (tenant_id, event_hash),
  FOREIGN KEY (tenant_id, certification_manifest_id)
    REFERENCES certification_artifact_stages_v1 (tenant_id, certification_manifest_id)
) STRICT;

CREATE INDEX certification_artifact_outbox_events_v1_stage
  ON certification_artifact_outbox_events_v1 (tenant_id, certification_manifest_id, sequence);

CREATE TRIGGER certification_artifact_stages_v1_no_update
BEFORE UPDATE ON certification_artifact_stages_v1
BEGIN SELECT RAISE(ABORT, 'certification artifact stages are immutable'); END;
CREATE TRIGGER certification_artifact_stages_v1_no_delete
BEFORE DELETE ON certification_artifact_stages_v1
BEGIN SELECT RAISE(ABORT, 'certification artifact stages are immutable'); END;
CREATE TRIGGER certification_artifact_outbox_events_v1_no_update
BEFORE UPDATE ON certification_artifact_outbox_events_v1
BEGIN SELECT RAISE(ABORT, 'certification artifact outbox events are immutable'); END;
CREATE TRIGGER certification_artifact_outbox_events_v1_no_delete
BEFORE DELETE ON certification_artifact_outbox_events_v1
BEGIN SELECT RAISE(ABORT, 'certification artifact outbox events are immutable'); END;
`;

export const SQLITE_CERTIFICATION_ARTIFACT_STAGING_MIGRATIONS = Object.freeze([
  { version: 1, sql: SQLITE_CERTIFICATION_ARTIFACT_STAGING_SCHEMA }
] as const satisfies readonly SqliteComponentMigration[]);

const StageInputSchema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    certificationManifestId: IdentifierSchema,
    attemptHash: Sha256HashSchema,
    normalizedArtifact: z.unknown(),
    artifactBindingHash: Sha256HashSchema,
    preparedAt: IsoTimestampSchema
  })
  .strict();

const CompletionInputSchema = z
  .object({
    tenantId: IdentifierSchema,
    certificationManifestId: IdentifierSchema,
    attemptHash: Sha256HashSchema,
    artifactBindingHash: Sha256HashSchema,
    certificationEvidenceHash: Sha256HashSchema,
    occurredAt: IsoTimestampSchema
  })
  .strict();

const FailureInputSchema = z
  .object({
    tenantId: IdentifierSchema,
    certificationManifestId: IdentifierSchema,
    attemptHash: Sha256HashSchema,
    artifactBindingHash: Sha256HashSchema,
    failureHash: Sha256HashSchema,
    occurredAt: IsoTimestampSchema
  })
  .strict();

const GetInputSchema = z.object({ tenantId: IdentifierSchema, certificationManifestId: IdentifierSchema }).strict();

export interface CertificationArtifactStagingStoreV1 {
  prepareOrReplay(input: CertificationArtifactStageV1Input): Promise<{
    readonly record: CertificationArtifactOutboxRecordV1;
    readonly replayed: boolean;
  }>;
  recordEvidenceCommitted(input: RecordCertificationEvidenceCommittedV1): Promise<{
    readonly record: CertificationArtifactOutboxRecordV1;
    readonly replayed: boolean;
  }>;
  recordEvidenceFailure(input: RecordCertificationEvidenceFailureV1): Promise<{
    readonly record: CertificationArtifactOutboxRecordV1;
    readonly replayed: boolean;
  }>;
  get(input: GetCertificationArtifactOutboxRecordV1): Promise<CertificationArtifactOutboxRecordV1 | undefined>;
}

export interface RecordCertificationEvidenceCommittedV1 {
  readonly tenantId: string;
  readonly certificationManifestId: string;
  readonly attemptHash: string;
  readonly artifactBindingHash: string;
  /** Hash of the immutable primary certification evidence record that consumed this exact staged pointer. */
  readonly certificationEvidenceHash: string;
  readonly occurredAt: string;
}

export interface RecordCertificationEvidenceFailureV1 {
  readonly tenantId: string;
  readonly certificationManifestId: string;
  readonly attemptHash: string;
  readonly artifactBindingHash: string;
  /** Canonical hash of the non-sensitive failure receipt; raw error text must not be persisted here. */
  readonly failureHash: string;
  readonly occurredAt: string;
}

export interface GetCertificationArtifactOutboxRecordV1 {
  readonly tenantId: string;
  readonly certificationManifestId: string;
}

export type CertificationArtifactStagingStoreErrorCode =
  | "INVALID_ARGUMENT"
  | "IDEMPOTENCY_CONFLICT"
  | "STATE_CONFLICT"
  | "INTEGRITY_FAILURE"
  | "STORE_CLOSED";

export class CertificationArtifactStagingStoreError extends Error {
  constructor(readonly code: CertificationArtifactStagingStoreErrorCode, message: string) {
    super(message);
    this.name = "CertificationArtifactStagingStoreError";
  }
}

interface StageRow {
  readonly tenant_id: string;
  readonly certification_manifest_id: string;
  readonly attempt_hash: string;
  readonly artifact_binding_hash: string;
  readonly stage_hash: string;
  readonly prepared_at: string;
  readonly stage_json: string;
}

interface EventRow {
  readonly tenant_id: string;
  readonly certification_manifest_id: string;
  readonly sequence: number;
  readonly event_type: string;
  readonly stage_hash: string;
  readonly event_hash: string;
  readonly occurred_at: string;
  readonly event_json: string;
}

/**
 * Durable, append-only artifact staging/outbox state for crash-safe certification handoff.
 * It intentionally does not write artifacts or certification evidence; callers must compose it
 * with their trusted artifact and evidence authorities in one recovery workflow.
 */
export class SqliteCertificationArtifactStagingStoreV1 implements CertificationArtifactStagingStoreV1 {
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
        componentName: SQLITE_CERTIFICATION_ARTIFACT_STAGING_COMPONENT,
        supportedVersion: SQLITE_CERTIFICATION_ARTIFACT_STAGING_SCHEMA_VERSION,
        migrations: SQLITE_CERTIFICATION_ARTIFACT_STAGING_MIGRATIONS,
        unsupportedVersionError: (current, supported) =>
          integrity(`Certification artifact staging schema ${current} is newer than supported ${supported}`)
      });
      this.#verifyIntegrity();
    } catch (error) {
      this.#database.close();
      if (error instanceof CertificationArtifactStagingStoreError) throw error;
      throw integrity("Certification artifact staging store initialization failed");
    }
  }

  async prepareOrReplay(inputValue: CertificationArtifactStageV1Input): Promise<{
    readonly record: CertificationArtifactOutboxRecordV1;
    readonly replayed: boolean;
  }> {
    this.#assertOpen();
    const input = parsed(StageInputSchema, inputValue, "stage input");
    const stage = createCertificationArtifactStageV1(input as CertificationArtifactStageV1Input);
    return this.#transaction(() => {
      const existing = this.#stage(stage.tenantId, stage.certificationManifestId);
      if (existing !== undefined) {
        const record = this.#record(existing);
        if (
          record.stage.attemptHash !== stage.attemptHash ||
          record.stage.artifactBindingHash !== stage.artifactBindingHash
        ) {
          throw new CertificationArtifactStagingStoreError(
            "IDEMPOTENCY_CONFLICT",
            "Certification manifest is already bound to a different staged artifact"
          );
        }
        return Object.freeze({ record, replayed: true });
      }
      const prepared = createCertificationArtifactOutboxEventV1({
        contractVersion: 1,
        tenantId: stage.tenantId,
        certificationManifestId: stage.certificationManifestId,
        stageHash: stage.stageHash,
        sequence: 1,
        eventType: "artifact_prepared",
        occurredAt: stage.preparedAt
      });
      this.#insertStage(stage);
      this.#insertEvent(prepared);
      return Object.freeze({
        record: deriveCertificationArtifactOutboxRecordV1({ stage, events: [prepared] }),
        replayed: false
      });
    });
  }

  async recordEvidenceCommitted(inputValue: RecordCertificationEvidenceCommittedV1): Promise<{
    readonly record: CertificationArtifactOutboxRecordV1;
    readonly replayed: boolean;
  }> {
    this.#assertOpen();
    const input = parsed(CompletionInputSchema, inputValue, "evidence-commit input");
    return this.#transaction(() => {
      const record = this.#requiredRecord(input.tenantId, input.certificationManifestId);
      assertStageBinding(record.stage, input.attemptHash, input.artifactBindingHash);
      const committed = record.events.find(
        (event) => event.eventType === "certification_evidence_committed"
      );
      if (committed) {
        if (committed.certificationEvidenceHash !== input.certificationEvidenceHash) {
          throw new CertificationArtifactStagingStoreError(
            "IDEMPOTENCY_CONFLICT",
            "Staged artifact is already committed to different certification evidence"
          );
        }
        return Object.freeze({ record, replayed: true });
      }
      const event = createCertificationArtifactOutboxEventV1({
        contractVersion: 1,
        tenantId: input.tenantId,
        certificationManifestId: input.certificationManifestId,
        stageHash: record.stage.stageHash,
        sequence: record.events.length + 1,
        eventType: "certification_evidence_committed",
        certificationEvidenceHash: input.certificationEvidenceHash,
        occurredAt: input.occurredAt
      });
      this.#insertEvent(event);
      return Object.freeze({
        record: deriveCertificationArtifactOutboxRecordV1({ stage: record.stage, events: [...record.events, event] }),
        replayed: false
      });
    });
  }

  async recordEvidenceFailure(inputValue: RecordCertificationEvidenceFailureV1): Promise<{
    readonly record: CertificationArtifactOutboxRecordV1;
    readonly replayed: boolean;
  }> {
    this.#assertOpen();
    const input = parsed(FailureInputSchema, inputValue, "evidence-failure input");
    return this.#transaction(() => {
      const record = this.#requiredRecord(input.tenantId, input.certificationManifestId);
      assertStageBinding(record.stage, input.attemptHash, input.artifactBindingHash);
      if (record.state === "evidence_committed") {
        throw new CertificationArtifactStagingStoreError(
          "STATE_CONFLICT",
          "Cannot record an evidence failure after certification evidence has committed"
        );
      }
      const prior = record.events.find(
        (event) =>
          event.eventType === "certification_evidence_failed" && event.failureHash === input.failureHash
      );
      if (prior) return Object.freeze({ record, replayed: true });
      const event = createCertificationArtifactOutboxEventV1({
        contractVersion: 1,
        tenantId: input.tenantId,
        certificationManifestId: input.certificationManifestId,
        stageHash: record.stage.stageHash,
        sequence: record.events.length + 1,
        eventType: "certification_evidence_failed",
        failureHash: input.failureHash,
        occurredAt: input.occurredAt
      });
      this.#insertEvent(event);
      return Object.freeze({
        record: deriveCertificationArtifactOutboxRecordV1({ stage: record.stage, events: [...record.events, event] }),
        replayed: false
      });
    });
  }

  async get(inputValue: GetCertificationArtifactOutboxRecordV1): Promise<CertificationArtifactOutboxRecordV1 | undefined> {
    this.#assertOpen();
    const input = parsed(GetInputSchema, inputValue, "outbox lookup");
    const stage = this.#stage(input.tenantId, input.certificationManifestId);
    return stage === undefined ? undefined : this.#record(stage);
  }

  close(): void {
    if (!this.#closed) {
      this.#database.close();
      this.#closed = true;
    }
  }

  #transaction<T>(action: () => T): T {
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const value = action();
      this.#database.exec("COMMIT");
      return value;
    } catch (error) {
      try {
        this.#database.exec("ROLLBACK");
      } catch {
        // Preserve the original failure.
      }
      if (error instanceof CertificationArtifactStagingStoreError) throw error;
      throw integrity("Certification artifact staging transaction failed");
    }
  }

  #requiredRecord(tenantId: string, certificationManifestId: string): CertificationArtifactOutboxRecordV1 {
    const stage = this.#stage(tenantId, certificationManifestId);
    if (!stage) {
      throw new CertificationArtifactStagingStoreError(
        "IDEMPOTENCY_CONFLICT",
        "No staged artifact exists for this tenant-scoped certification manifest"
      );
    }
    return this.#record(stage);
  }

  #stage(tenantId: string, certificationManifestId: string): CertificationArtifactStageV1 | undefined {
    const row = this.#database
      .prepare(
        `SELECT * FROM certification_artifact_stages_v1
          WHERE tenant_id = ? AND certification_manifest_id = ?`
      )
      .get(tenantId, certificationManifestId) as StageRow | undefined;
    return row === undefined ? undefined : rowStage(row);
  }

  #record(stage: CertificationArtifactStageV1): CertificationArtifactOutboxRecordV1 {
    const rows = this.#database
      .prepare(
        `SELECT * FROM certification_artifact_outbox_events_v1
          WHERE tenant_id = ? AND certification_manifest_id = ? ORDER BY sequence`
      )
      .all(stage.tenantId, stage.certificationManifestId) as unknown as EventRow[];
    return deriveCertificationArtifactOutboxRecordV1({ stage, events: rows.map(rowEvent) });
  }

  #insertStage(stage: CertificationArtifactStageV1): void {
    this.#database
      .prepare(
        `INSERT INTO certification_artifact_stages_v1 (
          tenant_id, certification_manifest_id, attempt_hash, artifact_binding_hash,
          stage_hash, prepared_at, stage_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        stage.tenantId,
        stage.certificationManifestId,
        stage.attemptHash,
        stage.artifactBindingHash,
        stage.stageHash,
        stage.preparedAt,
        canonicalJson(stage)
      );
  }

  #insertEvent(event: CertificationArtifactOutboxEventV1): void {
    this.#database
      .prepare(
        `INSERT INTO certification_artifact_outbox_events_v1 (
          tenant_id, certification_manifest_id, sequence, event_type, stage_hash,
          event_hash, occurred_at, event_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        event.tenantId,
        event.certificationManifestId,
        event.sequence,
        event.eventType,
        event.stageHash,
        event.eventHash,
        event.occurredAt,
        canonicalJson(event)
      );
  }

  #verifyIntegrity(): void {
    const stages = this.#database
      .prepare("SELECT * FROM certification_artifact_stages_v1 ORDER BY tenant_id, certification_manifest_id")
      .all() as unknown as StageRow[];
    for (const row of stages) this.#record(rowStage(row));
    const orphans = this.#database
      .prepare(
        `SELECT event_hash FROM certification_artifact_outbox_events_v1
          WHERE (tenant_id, certification_manifest_id) NOT IN (
            SELECT tenant_id, certification_manifest_id FROM certification_artifact_stages_v1
          ) LIMIT 1`
      )
      .get() as { readonly event_hash: string } | undefined;
    if (orphans) throw integrity("Certification artifact outbox contains an orphan event");
  }

  #assertOpen(): void {
    if (this.#closed) throw new CertificationArtifactStagingStoreError("STORE_CLOSED", "Store is closed");
  }
}

function rowStage(row: StageRow): CertificationArtifactStageV1 {
  let stage: CertificationArtifactStageV1;
  try {
    stage = parseCertificationArtifactStageV1(JSON.parse(row.stage_json));
  } catch {
    throw integrity("Stored certification artifact stage failed canonical validation");
  }
  if (
    stage.tenantId !== row.tenant_id ||
    stage.certificationManifestId !== row.certification_manifest_id ||
    stage.attemptHash !== row.attempt_hash ||
    stage.artifactBindingHash !== row.artifact_binding_hash ||
    stage.stageHash !== row.stage_hash ||
    stage.preparedAt !== row.prepared_at
  ) {
    throw integrity("Stored certification artifact stage columns do not match canonical evidence");
  }
  return stage;
}

function rowEvent(row: EventRow): CertificationArtifactOutboxEventV1 {
  let event: CertificationArtifactOutboxEventV1;
  try {
    event = parseCertificationArtifactOutboxEventV1(JSON.parse(row.event_json));
  } catch {
    throw integrity("Stored certification artifact outbox event failed canonical validation");
  }
  if (
    event.tenantId !== row.tenant_id ||
    event.certificationManifestId !== row.certification_manifest_id ||
    event.sequence !== row.sequence ||
    event.eventType !== row.event_type ||
    event.stageHash !== row.stage_hash ||
    event.eventHash !== row.event_hash ||
    event.occurredAt !== row.occurred_at
  ) {
    throw integrity("Stored certification artifact outbox columns do not match canonical evidence");
  }
  return event;
}

function assertStageBinding(
  stage: CertificationArtifactStageV1,
  attemptHash: string,
  artifactBindingHash: string
): void {
  if (stage.attemptHash !== attemptHash || stage.artifactBindingHash !== artifactBindingHash) {
    throw new CertificationArtifactStagingStoreError(
      "IDEMPOTENCY_CONFLICT",
      "Evidence event does not bind to the immutable staged artifact"
    );
  }
}

function parsed<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  try {
    return parseWithSchema(schema, value, label);
  } catch {
    throw new CertificationArtifactStagingStoreError("INVALID_ARGUMENT", `${label} failed strict validation`);
  }
}

function integer(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new CertificationArtifactStagingStoreError("INVALID_ARGUMENT", `${label} is outside allowed bounds`);
  }
  return value;
}

function requiredPath(value: string): string {
  if (value === ":memory:") return value;
  if (typeof value !== "string" || value.length === 0) {
    throw new CertificationArtifactStagingStoreError("INVALID_ARGUMENT", "databasePath is required");
  }
  return resolve(value);
}

function integrity(message: string): CertificationArtifactStagingStoreError {
  return new CertificationArtifactStagingStoreError("INTEGRITY_FAILURE", message);
}
