import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  ContractValidationError,
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  canonicalHash,
  canonicalJson,
  parseWithSchema,
  type Sha256Hash
} from "../contracts/canonical.js";
import {
  certifyMetricRunV1,
  createMetricRunV1,
  metricRunObservationKey,
  parseMetricRunCreatedV1,
  parseMetricRunV1,
  type CreateMetricRunV1Input,
  type MetricRunCreatedV1,
  type MetricRunScopeV1,
  type MetricRunV1,
  type MetricRunViewV1
} from "../contracts/metric-run-v1.js";
import { migrateSqliteComponent } from "../infrastructure/sqlite-component-schema.js";

export const METRIC_RUN_STORE_COMPONENT = "abl.metric-run-store" as const;
export const METRIC_RUN_STORE_SCHEMA_VERSION = 1 as const;

export type CreateMetricRunInput = Readonly<
  Omit<CreateMetricRunV1Input, "createdAt"> & { readonly idempotencyKey: string }
>;

export interface ApproveMetricRunInput {
  readonly tenantId: string;
  readonly runId: string;
  readonly expectedRunHash: Sha256Hash;
  readonly approvedBy: string;
  readonly idempotencyKey: string;
}

export interface MetricRunAuditEventV1 {
  readonly sequence: number;
  readonly tenantId: string;
  readonly eventId: string;
  readonly eventType: "metric_run.created" | "metric_run.certified";
  readonly runId: string;
  readonly actor: string;
  readonly details: Readonly<Record<string, unknown>>;
  readonly occurredAt: string;
}

export interface MetricRunStoreOptions {
  readonly clock?: () => Date;
  readonly busyTimeoutMs?: number;
}

export type MetricRunStoreErrorCode =
  | "INVALID_INPUT"
  | "NOT_FOUND"
  | "CONFLICT"
  | "IDEMPOTENCY_CONFLICT"
  | "MAKER_CHECKER_VIOLATION"
  | "ILLEGAL_TRANSITION"
  | "STORE_INTEGRITY_FAILURE"
  | "STORE_CLOSED";

export class MetricRunStoreError extends Error {
  constructor(readonly code: MetricRunStoreErrorCode, message: string) {
    super(message);
    this.name = "MetricRunStoreError";
  }
}

/**
 * @internal Persistence primitive for MetricRunEvidenceService. Direct writes
 * are not authoritative evidence until the service has resolved and verified
 * the frozen definition, methodology, and certified source repositories.
 */
export class MetricRunStore {
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;
  #closed = false;

  constructor(databasePath: string, options: MetricRunStoreOptions = {}) {
    if (!databasePath.trim()) invalid("Metric-run database path is required");
    const absolute = resolve(databasePath);
    if (databasePath !== ":memory:") mkdirSync(dirname(absolute), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(databasePath === ":memory:" ? databasePath : absolute);
    this.#clock = options.clock ?? (() => new Date());
    const busyTimeoutMs = integer(options.busyTimeoutMs ?? 5_000, "busyTimeoutMs", 0, 60_000);
    try {
      this.#database.exec(
        `PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${busyTimeoutMs};`
      );
      migrateSqliteComponent(this.#database, {
        componentName: METRIC_RUN_STORE_COMPONENT,
        supportedVersion: METRIC_RUN_STORE_SCHEMA_VERSION,
        migrations: [{ version: 1, sql: METRIC_RUN_SCHEMA }],
        unsupportedVersionError: (current, supported) =>
          new MetricRunStoreError(
            "CONFLICT",
            `Metric-run schema ${current} is newer than supported version ${supported}`
          )
      });
    } catch (error) {
      this.#database.close();
      throw error;
    }
  }

  create(inputValue: CreateMetricRunInput): MetricRunCreatedV1 {
    this.#assertOpen();
    const { input, requestHash } = validateCreate(inputValue);
    return this.#transaction(() => {
      const replay = this.#readReceipt(
        input.tenantId,
        "metric_run.create",
        input.createdBy,
        input.idempotencyKey,
        requestHash
      );
      if (replay) return this.#requiredCreated(input.tenantId, replay.runId);
      if (this.get(input.tenantId, input.runId)) conflict("Metric run id already exists");
      const key = metricRunObservationKey({
        metricId: input.metricId,
        asOfDate: input.observation.asOfDate,
        scope: input.observation.scope
      });
      const duplicate = this.#database
        .prepare(
          `SELECT run_id FROM metric_runs
            WHERE tenant_id = ? AND metric_id = ? AND scope_hash = ? AND as_of_date = ?
              AND source_hash = ?`
        )
        .get(
          input.tenantId,
          key.metricId,
          key.scopeHash,
          key.asOfDate,
          input.source.sourceHash
        ) as
        | { readonly run_id: string }
        | undefined;
      if (duplicate) {
        conflict("A metric run already exists for this tenant, metric, scope, and observation date");
      }
      const created = inputContract(() =>
        createMetricRunV1({
          contractVersion: input.contractVersion,
          runId: input.runId,
          tenantId: input.tenantId,
          metricId: input.metricId,
          projection: input.projection,
          metricDefinition: input.metricDefinition,
          methodology: input.methodology,
          source: input.source,
          observation: input.observation,
          createdBy: input.createdBy,
          createdAt: this.#now()
        })
      );
      this.#database
        .prepare(
          `INSERT INTO metric_runs (
             tenant_id, run_id, metric_id, scope_hash, as_of_date,
             source_hash, run_hash,
             created_by, created_at, run_json
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          created.tenantId,
          created.runId,
          created.metricId,
          created.observation.scopeHash,
          created.observation.asOfDate,
          created.source.sourceHash,
          created.runHash,
          created.createdBy,
          created.createdAt,
          canonicalJson(created)
        );
      this.#audit(created.tenantId, created.runId, "metric_run.created", created.createdBy, {
        asOfDate: created.observation.asOfDate,
        derivationHash: created.derivationHash,
        metricDefinitionHash: created.metricDefinition.definitionHash,
        metricId: created.metricId,
        populationHash: created.source.populationHash,
        runHash: created.runHash,
        scopeHash: created.observation.scopeHash
      }, created.createdAt);
      this.#recordReceipt(
        created.tenantId,
        "metric_run.create",
        created.createdBy,
        input.idempotencyKey,
        requestHash,
        created.runId,
        created.createdAt
      );
      return created;
    });
  }

  approve(inputValue: ApproveMetricRunInput): MetricRunV1 {
    this.#assertOpen();
    const input = validateApproval(inputValue);
    const requestHash = canonicalHash(input);
    return this.#transaction(() => {
      const replay = this.#readReceipt(
        input.tenantId,
        "metric_run.approve",
        input.approvedBy,
        input.idempotencyKey,
        requestHash
      );
      if (replay) return this.#required(input.tenantId, replay.runId) as MetricRunV1;
      const run = this.#required(input.tenantId, input.runId);
      if (run.status !== "created") transition("Metric run is already terminal");
      if (run.createdBy === input.approvedBy) {
        throw new MetricRunStoreError(
          "MAKER_CHECKER_VIOLATION",
          "Metric-run creator cannot approve the same run"
        );
      }
      if (run.runHash !== input.expectedRunHash) {
        conflict("Metric-run approval did not bind the current run hash");
      }
      const certified = inputContract(() =>
        certifyMetricRunV1(run, { approvedBy: input.approvedBy, approvedAt: this.#now() })
      );
      this.#database
        .prepare(
          `INSERT INTO metric_run_certifications (
             tenant_id, run_id, certification_hash, approved_by, approved_at,
             certification_json
           ) VALUES (?, ?, ?, ?, ?, ?)`
        )
        .run(
          certified.tenantId,
          certified.runId,
          certified.certificationHash,
          certified.approvedBy,
          certified.approvedAt,
          canonicalJson(certified)
        );
      this.#audit(certified.tenantId, certified.runId, "metric_run.certified", certified.approvedBy, {
        certificationHash: certified.certificationHash,
        derivationHash: certified.derivationHash,
        runHash: certified.runHash
      }, certified.approvedAt);
      this.#recordReceipt(
        certified.tenantId,
        "metric_run.approve",
        certified.approvedBy,
        input.idempotencyKey,
        requestHash,
        certified.runId,
        certified.approvedAt
      );
      return certified;
    });
  }

  get(tenantIdValue: string, runIdValue: string): MetricRunViewV1 | undefined {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenantId");
    const runId = identifier(runIdValue, "runId");
    const row = this.#database
      .prepare(METRIC_RUN_SELECT + " WHERE run.tenant_id = ? AND run.run_id = ?")
      .get(tenantId, runId) as MetricRunRow | undefined;
    return row ? recordFromRow(row) : undefined;
  }

  getCertified(tenantId: string, runId: string): MetricRunV1 | undefined {
    const value = this.get(tenantId, runId);
    return value?.status === "certified" ? value : undefined;
  }

  findCertifiedByObservation(input: {
    readonly tenantId: string;
    readonly metricId: string;
    readonly asOfDate: string;
    readonly scope: MetricRunScopeV1;
    readonly sourceHash: Sha256Hash;
  }): MetricRunV1 | undefined {
    this.#assertOpen();
    const tenantId = identifier(input.tenantId, "tenantId");
    const key = inputContract(() => metricRunObservationKey(input));
    const row = this.#database
      .prepare(
        METRIC_RUN_SELECT +
          ` WHERE run.tenant_id = ? AND run.metric_id = ?
              AND run.scope_hash = ? AND run.as_of_date = ?
              AND run.source_hash = ?
              AND certification.run_id IS NOT NULL`
      )
      .get(
        tenantId,
        key.metricId,
        key.scopeHash,
        key.asOfDate,
        inputContract(() => parseWithSchema(Sha256HashSchema, input.sourceHash, "sourceHash"))
      ) as MetricRunRow | undefined;
    if (!row) return undefined;
    const value = recordFromRow(row);
    if (value.status !== "certified") integrity("Certified metric-run lookup returned a non-certified record");
    return value;
  }

  list(tenantIdValue: string, limit = 100): readonly MetricRunViewV1[] {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenantId");
    integer(limit, "limit", 1, 1_000);
    const rows = this.#database
      .prepare(METRIC_RUN_SELECT + " WHERE run.tenant_id = ? ORDER BY run.created_at, run.run_id LIMIT ?")
      .all(tenantId, limit) as unknown as MetricRunRow[];
    return rows.map(recordFromRow);
  }

  listAuditEvents(
    tenantIdValue: string,
    afterSequence = 0,
    limit = 100
  ): readonly MetricRunAuditEventV1[] {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenantId");
    integer(afterSequence, "afterSequence", 0, Number.MAX_SAFE_INTEGER);
    integer(limit, "limit", 1, 1_000);
    const rows = this.#database
      .prepare(
        `SELECT * FROM metric_run_audit_events
          WHERE tenant_id = ? AND sequence > ?
          ORDER BY sequence LIMIT ?`
      )
      .all(tenantId, afterSequence, limit) as unknown as MetricRunAuditRow[];
    return rows.map((row) => ({
      sequence: row.sequence,
      tenantId: row.tenant_id,
      eventId: row.event_id,
      eventType: row.event_type,
      runId: row.run_id,
      actor: row.actor,
      details: parseObject(row.details_json, "metric-run audit details"),
      occurredAt: row.occurred_at
    }));
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#database.close();
  }

  #required(tenantId: string, runId: string): MetricRunViewV1 {
    const value = this.get(tenantId, runId);
    if (!value) throw new MetricRunStoreError("NOT_FOUND", "Metric run was not found");
    return value;
  }

  #requiredCreated(tenantId: string, runId: string): MetricRunCreatedV1 {
    const row = this.#database
      .prepare("SELECT run_json FROM metric_runs WHERE tenant_id = ? AND run_id = ?")
      .get(tenantId, runId) as { readonly run_json: string } | undefined;
    if (!row) throw new MetricRunStoreError("NOT_FOUND", "Metric run was not found");
    return inputContract(() => parseMetricRunCreatedV1(parseJson(row.run_json, "metric run")));
  }

  #readReceipt(
    tenantId: string,
    operation: string,
    actor: string,
    idempotencyKey: string,
    requestHash: Sha256Hash
  ): { readonly runId: string } | null {
    const row = this.#database
      .prepare(
        `SELECT request_hash, run_id FROM metric_run_idempotency
          WHERE tenant_id = ? AND operation = ? AND actor = ? AND idempotency_key = ?`
      )
      .get(tenantId, operation, actor, idempotencyKey) as
      | { readonly request_hash: string; readonly run_id: string }
      | undefined;
    if (!row) return null;
    if (row.request_hash !== requestHash) {
      throw new MetricRunStoreError(
        "IDEMPOTENCY_CONFLICT",
        "Idempotency key was used with another metric-run request"
      );
    }
    return { runId: row.run_id };
  }

  #recordReceipt(
    tenantId: string,
    operation: string,
    actor: string,
    idempotencyKey: string,
    requestHash: Sha256Hash,
    runId: string,
    now: string
  ): void {
    this.#database
      .prepare(
        `INSERT INTO metric_run_idempotency (
           tenant_id, operation, actor, idempotency_key, request_hash, run_id, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(tenantId, operation, actor, idempotencyKey, requestHash, runId, now);
  }

  #audit(
    tenantId: string,
    runId: string,
    eventType: MetricRunAuditEventV1["eventType"],
    actor: string,
    details: Readonly<Record<string, unknown>>,
    now: string
  ): void {
    this.#database
      .prepare(
        `INSERT INTO metric_run_audit_events (
           tenant_id, event_id, run_id, event_type, actor, details_json, occurred_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(tenantId, randomUUID(), runId, eventType, actor, canonicalJson(details), now);
  }

  #transaction<T>(operation: () => T): T {
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      try {
        this.#database.exec("ROLLBACK");
      } catch {
        // Preserve the original failure.
      }
      throw error;
    }
  }

  #now(): string {
    const value = this.#clock();
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) invalid("Metric-run clock is invalid");
    const timestamp = inputContract(() =>
      parseWithSchema(IsoTimestampSchema, value.toISOString(), "metric-run time")
    );
    const latest = this.#database
      .prepare("SELECT occurred_at FROM metric_run_audit_events ORDER BY sequence DESC LIMIT 1")
      .get() as { readonly occurred_at: string } | undefined;
    if (latest && timestamp < latest.occurred_at) invalid("Metric-run clock must not move backward");
    return timestamp;
  }

  #assertOpen(): void {
    if (this.#closed) throw new MetricRunStoreError("STORE_CLOSED", "Metric-run store is closed");
  }
}

const METRIC_RUN_SELECT = `
SELECT run.tenant_id, run.run_id, run.metric_id, run.scope_hash, run.as_of_date,
       run.source_hash,
       run.run_hash, run.created_by, run.created_at, run.run_json,
       certification.certification_hash, certification.approved_by,
       certification.approved_at, certification.certification_json
  FROM metric_runs AS run
  LEFT JOIN metric_run_certifications AS certification
    ON certification.tenant_id = run.tenant_id
   AND certification.run_id = run.run_id`;

const METRIC_RUN_SCHEMA = `
CREATE TABLE metric_runs (
  tenant_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  metric_id TEXT NOT NULL,
  scope_hash TEXT NOT NULL CHECK (scope_hash GLOB 'sha256:[0-9a-f]*' AND length(scope_hash) = 71),
  as_of_date TEXT NOT NULL,
  source_hash TEXT NOT NULL CHECK (source_hash GLOB 'sha256:[0-9a-f]*' AND length(source_hash) = 71),
  run_hash TEXT NOT NULL CHECK (run_hash GLOB 'sha256:[0-9a-f]*' AND length(run_hash) = 71),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  run_json TEXT NOT NULL,
  PRIMARY KEY (tenant_id, run_id),
  UNIQUE (
    tenant_id, metric_id, scope_hash, as_of_date,
    source_hash
  )
) STRICT;
CREATE INDEX metric_runs_tenant_created ON metric_runs (tenant_id, created_at, run_id);
CREATE TRIGGER metric_runs_no_update BEFORE UPDATE ON metric_runs
BEGIN SELECT RAISE(ABORT, 'metric runs are immutable'); END;
CREATE TRIGGER metric_runs_no_delete BEFORE DELETE ON metric_runs
BEGIN SELECT RAISE(ABORT, 'metric runs are immutable'); END;

CREATE TABLE metric_run_certifications (
  tenant_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  certification_hash TEXT NOT NULL CHECK (certification_hash GLOB 'sha256:[0-9a-f]*' AND length(certification_hash) = 71),
  approved_by TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  certification_json TEXT NOT NULL,
  PRIMARY KEY (tenant_id, run_id),
  FOREIGN KEY (tenant_id, run_id) REFERENCES metric_runs (tenant_id, run_id)
) STRICT;
CREATE INDEX metric_run_certifications_tenant_approved
  ON metric_run_certifications (tenant_id, approved_at, run_id);
CREATE TRIGGER metric_run_certifications_no_update BEFORE UPDATE ON metric_run_certifications
BEGIN SELECT RAISE(ABORT, 'metric run certifications are immutable'); END;
CREATE TRIGGER metric_run_certifications_no_delete BEFORE DELETE ON metric_run_certifications
BEGIN SELECT RAISE(ABORT, 'metric run certifications are immutable'); END;

CREATE TABLE metric_run_audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL UNIQUE,
  run_id TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('metric_run.created','metric_run.certified')),
  actor TEXT NOT NULL,
  details_json TEXT NOT NULL,
  occurred_at TEXT NOT NULL
) STRICT;
CREATE INDEX metric_run_audit_tenant_sequence
  ON metric_run_audit_events (tenant_id, sequence);
CREATE TRIGGER metric_run_audit_no_update BEFORE UPDATE ON metric_run_audit_events
BEGIN SELECT RAISE(ABORT, 'metric run audit is append-only'); END;
CREATE TRIGGER metric_run_audit_no_delete BEFORE DELETE ON metric_run_audit_events
BEGIN SELECT RAISE(ABORT, 'metric run audit is append-only'); END;

CREATE TABLE metric_run_idempotency (
  tenant_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  actor TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL CHECK (request_hash GLOB 'sha256:[0-9a-f]*' AND length(request_hash) = 71),
  run_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, operation, actor, idempotency_key)
) STRICT;
CREATE TRIGGER metric_run_idempotency_no_update BEFORE UPDATE ON metric_run_idempotency
BEGIN SELECT RAISE(ABORT, 'metric run idempotency is immutable'); END;
CREATE TRIGGER metric_run_idempotency_no_delete BEFORE DELETE ON metric_run_idempotency
BEGIN SELECT RAISE(ABORT, 'metric run idempotency is immutable'); END;
`;

interface MetricRunRow {
  readonly tenant_id: string;
  readonly run_id: string;
  readonly metric_id: string;
  readonly scope_hash: string;
  readonly as_of_date: string;
  readonly source_hash: string;
  readonly run_hash: string;
  readonly created_by: string;
  readonly created_at: string;
  readonly run_json: string;
  readonly certification_hash: string | null;
  readonly approved_by: string | null;
  readonly approved_at: string | null;
  readonly certification_json: string | null;
}

interface MetricRunAuditRow {
  readonly sequence: number;
  readonly tenant_id: string;
  readonly event_id: string;
  readonly event_type: MetricRunAuditEventV1["eventType"];
  readonly run_id: string;
  readonly actor: string;
  readonly details_json: string;
  readonly occurred_at: string;
}

function recordFromRow(row: MetricRunRow): MetricRunViewV1 {
  const created = inputContract(() => parseMetricRunCreatedV1(parseJson(row.run_json, "metric run")));
  if (
    created.tenantId !== row.tenant_id ||
    created.runId !== row.run_id ||
    created.metricId !== row.metric_id ||
    created.observation.scopeHash !== row.scope_hash ||
    created.observation.asOfDate !== row.as_of_date ||
    created.source.sourceHash !== row.source_hash ||
    created.runHash !== row.run_hash ||
    created.createdBy !== row.created_by ||
    created.createdAt !== row.created_at
  ) {
    integrity("Metric-run indexed columns did not match the immutable contract");
  }
  const certificationFields = [
    row.certification_hash,
    row.approved_by,
    row.approved_at,
    row.certification_json
  ];
  if (certificationFields.every((value) => value === null)) return created;
  if (certificationFields.some((value) => value === null)) {
    integrity("Metric-run certification columns were only partially populated");
  }
  const certified = inputContract(() => parseMetricRunV1(parseJson(row.certification_json!, "metric run certification")));
  const {
    approvedAt: _approvedAt,
    approvedBy: _approvedBy,
    certificationHash: _certificationHash,
    status: _certifiedStatus,
    ...certifiedCreatedFields
  } = certified;
  const reconstructedCreated = { ...certifiedCreatedFields, status: "created" as const };
  if (
    canonicalJson(reconstructedCreated) !== canonicalJson(created) ||
    certified.certificationHash !== row.certification_hash ||
    certified.approvedBy !== row.approved_by ||
    certified.approvedAt !== row.approved_at
  ) {
    integrity("Metric-run certification did not match its immutable created record");
  }
  return certified;
}

function validateCreate(inputValue: CreateMetricRunInput): {
  readonly input: CreateMetricRunInput;
  readonly requestHash: Sha256Hash;
} {
  if (!inputValue || typeof inputValue !== "object" || Array.isArray(inputValue)) {
    invalid("Metric-run create request must be an object");
  }
  const input = inputValue as CreateMetricRunInput;
  const keys = Object.keys(input).sort();
  if (
    canonicalJson(keys) !==
    canonicalJson([
      "contractVersion",
      "createdBy",
      "idempotencyKey",
      "metricDefinition",
      "metricId",
      "methodology",
      "observation",
      "projection",
      "runId",
      "source",
      "tenantId"
    ].sort())
  ) {
    invalid("Metric-run create request contains missing or unknown fields");
  }
  identifier(input.idempotencyKey, "idempotencyKey");
  inputContract(() =>
    createMetricRunV1({
      contractVersion: input.contractVersion,
      runId: input.runId,
      tenantId: input.tenantId,
      metricId: input.metricId,
      projection: input.projection,
      metricDefinition: input.metricDefinition,
      methodology: input.methodology,
      source: input.source,
      observation: input.observation,
      createdBy: input.createdBy,
      createdAt: input.source.resultRecordedAt
    })
  );
  const { idempotencyKey: _idempotencyKey, ...request } = input;
  return { input, requestHash: canonicalHash(request) };
}

function validateApproval(inputValue: ApproveMetricRunInput): ApproveMetricRunInput {
  if (!inputValue || typeof inputValue !== "object" || Array.isArray(inputValue)) {
    invalid("Metric-run approval request must be an object");
  }
  const input = inputValue as ApproveMetricRunInput;
  identifier(input.tenantId, "tenantId");
  identifier(input.runId, "runId");
  inputContract(() => parseWithSchema(Sha256HashSchema, input.expectedRunHash, "expectedRunHash"));
  identifier(input.approvedBy, "approvedBy");
  identifier(input.idempotencyKey, "idempotencyKey");
  const keys = Object.keys(input).sort();
  if (canonicalJson(keys) !== canonicalJson(["approvedBy", "expectedRunHash", "idempotencyKey", "runId", "tenantId"])) {
    invalid("Metric-run approval request contains unknown fields");
  }
  return input;
}

function identifier(value: unknown, label: string): string {
  return inputContract(() => parseWithSchema(IdentifierSchema, value, label));
}

function integer(value: unknown, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    invalid(`${label} must be a safe integer between ${minimum} and ${maximum}`);
  }
  return value as number;
}

function inputContract<T>(operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    if (error instanceof MetricRunStoreError) throw error;
    if (error instanceof ContractValidationError) {
      throw new MetricRunStoreError("INVALID_INPUT", error.message);
    }
    throw error;
  }
}

function parseJson(value: string, label: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    integrity(`${label} JSON was invalid`);
  }
}

function parseObject(value: string, label: string): Readonly<Record<string, unknown>> {
  const parsed = parseJson(value, label);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) integrity(`${label} must be an object`);
  return Object.freeze(parsed as Record<string, unknown>);
}

function invalid(message: string): never {
  throw new MetricRunStoreError("INVALID_INPUT", message);
}

function conflict(message: string): never {
  throw new MetricRunStoreError("CONFLICT", message);
}

function transition(message: string): never {
  throw new MetricRunStoreError("ILLEGAL_TRANSITION", message);
}

function integrity(message: string): never {
  throw new MetricRunStoreError("STORE_INTEGRITY_FAILURE", message);
}
