import { createHash, randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import type {
  MonitorEvaluation,
  MonitoringAlert,
  MonitoringAlertEvidence,
  MonitoringBlockedResult,
  MonitoringResult,
  MonitoringScope,
  MonitorSeverity
} from "../domain/monitoring.js";
import {
  migrateSqliteComponent,
  SQLITE_SHARED_AUDIT_OBJECTS
} from "../infrastructure/sqlite-component-schema.js";
import type { JsonValue } from "./store.js";

export const ALERT_STORE_COMPONENT = "abl.monitoring-alert-store" as const;
export const ALERT_STORE_SCHEMA_VERSION = 1 as const;
export const MAX_MONITORING_RUN_JSON_BYTES = 512_000 as const;
export const MAX_ALERT_OCCURRENCE_JSON_BYTES = 128_000 as const;

export type AlertStatus = "open" | "acknowledged" | "escalated" | "resolved" | "suppressed";
export type ManualAlertTransitionAction =
  | "acknowledge"
  | "escalate"
  | "resolve"
  | "suppress"
  | "reopen";
export type AlertTransitionAction = ManualAlertTransitionAction | "recurrence_reopen";

export type MonitoringAlertStoreErrorCode =
  | "INVALID_ARGUMENT"
  | "IDEMPOTENCY_CONFLICT"
  | "CONFLICT"
  | "ALERT_NOT_FOUND"
  | "INVALID_TRANSITION"
  | "STORE_CLOSED"
  | "UNSUPPORTED_SCHEMA";

export class MonitoringAlertStoreError extends Error {
  constructor(
    readonly code: MonitoringAlertStoreErrorCode,
    message: string
  ) {
    super(message);
    this.name = "MonitoringAlertStoreError";
  }
}

export interface MonitoringAlertStoreOptions {
  readonly clock?: () => Date;
  readonly busyTimeoutMs?: number;
}

export interface RecordMonitoringRunInput {
  readonly tenantId: string;
  readonly runId: string;
  readonly result: MonitoringResult;
  readonly recordedBy: string;
  readonly idempotencyKey: string;
}

export interface MonitoringRunRecord {
  readonly tenantId: string;
  readonly runId: string;
  readonly status: MonitoringResult["status"];
  readonly asOfDate: string;
  readonly scope: MonitoringScope;
  readonly gateId: string;
  readonly snapshotId: string;
  readonly blockedReason?: MonitoringBlockedResult["reason"];
  readonly result: MonitoringResult;
  readonly resultHash: string;
  readonly alertIds: readonly string[];
  readonly occurrenceKeys: readonly string[];
  readonly recordedBy: string;
  readonly recordedAt: string;
}

export interface AlertRecord {
  readonly tenantId: string;
  readonly alertId: string;
  readonly dedupeKey: string;
  readonly monitorId: string;
  readonly monitorVersion: string;
  readonly scope: MonitoringScope;
  readonly title: string;
  readonly message: string;
  readonly severity: MonitorSeverity;
  readonly status: AlertStatus;
  readonly recurrenceCount: number;
  readonly firstSeenOn: string;
  readonly lastSeenOn: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface AlertOccurrenceRecord {
  readonly tenantId: string;
  readonly occurrenceKey: string;
  readonly alertId: string;
  readonly dedupeKey: string;
  readonly asOfDate: string;
  readonly severity: MonitorSeverity;
  readonly alert: MonitoringAlert;
  readonly evidence: MonitoringAlertEvidence;
  readonly evidenceHash: string;
  readonly recordedAt: string;
}

interface TransitionBase {
  readonly tenantId: string;
  readonly alertId: string;
  readonly actor: string;
  readonly idempotencyKey: string;
}

export type TransitionAlertInput =
  | (TransitionBase & { readonly action: "acknowledge"; readonly note?: string })
  | (TransitionBase & { readonly action: "escalate"; readonly reason: string })
  | (TransitionBase & { readonly action: "resolve"; readonly resolution: string })
  | (TransitionBase & { readonly action: "suppress"; readonly reason: string })
  | (TransitionBase & { readonly action: "reopen"; readonly reason: string });

export interface AlertTransitionRecord {
  readonly tenantId: string;
  readonly transitionId: string;
  readonly alertId: string;
  readonly fromStatus: AlertStatus;
  readonly toStatus: AlertStatus;
  readonly action: AlertTransitionAction;
  readonly actor: string;
  readonly reason?: string;
  readonly createdAt: string;
}

export interface ListAlertsOptions {
  readonly status?: AlertStatus;
  readonly limit?: number;
}

export interface MonitoringAuditEvent {
  readonly sequence: number;
  readonly tenantId: string;
  readonly eventId: string;
  readonly eventType: string;
  readonly entityType: "monitoring_alert" | "monitoring_alert_occurrence" | "monitoring_run";
  readonly entityId: string;
  readonly actor: string;
  readonly details: JsonValue;
  readonly occurredAt: string;
}

export interface ListMonitoringAuditOptions {
  readonly afterSequence?: number;
  readonly limit?: number;
}

interface RunRow {
  readonly tenant_id: string;
  readonly run_id: string;
  readonly status: MonitoringResult["status"];
  readonly as_of_date: string;
  readonly scope_type: MonitoringScope["type"];
  readonly scope_id: string;
  readonly gate_id: string;
  readonly snapshot_id: string;
  readonly blocked_reason: MonitoringBlockedResult["reason"] | null;
  readonly result_json: string;
  readonly result_hash: string;
  readonly recorded_by: string;
  readonly recorded_at: string;
}

interface RunOccurrenceRow {
  readonly alert_id: string;
  readonly occurrence_key: string;
}

interface AlertRow {
  readonly tenant_id: string;
  readonly alert_id: string;
  readonly dedupe_key: string;
  readonly monitor_id: string;
  readonly monitor_version: string;
  readonly scope_type: MonitoringScope["type"];
  readonly scope_id: string;
  readonly title: string;
  readonly message: string;
  readonly severity: MonitorSeverity;
  readonly status: AlertStatus;
  readonly recurrence_count: number;
  readonly first_seen_on: string;
  readonly last_seen_on: string;
  readonly created_at: string;
  readonly updated_at: string;
}

interface OccurrenceRow {
  readonly tenant_id: string;
  readonly occurrence_key: string;
  readonly alert_id: string;
  readonly dedupe_key: string;
  readonly as_of_date: string;
  readonly severity: MonitorSeverity;
  readonly alert_json: string;
  readonly evidence_json: string;
  readonly evidence_hash: string;
  readonly recorded_at: string;
}

interface TransitionRow {
  readonly tenant_id: string;
  readonly transition_id: string;
  readonly alert_id: string;
  readonly from_status: AlertStatus;
  readonly to_status: AlertStatus;
  readonly action: AlertTransitionAction;
  readonly actor: string;
  readonly reason: string | null;
  readonly created_at: string;
}

interface AuditRow {
  readonly sequence: number;
  readonly tenant_id: string;
  readonly event_id: string;
  readonly event_type: string;
  readonly entity_type: MonitoringAuditEvent["entityType"];
  readonly entity_id: string;
  readonly actor: string;
  readonly details_json: string;
  readonly occurred_at: string;
}

interface IdempotencyRow {
  readonly request_hash: string;
  readonly response_json: string;
}

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DEDUPE_KEY_PATTERN = /^monitor:[a-f0-9]{64}$/;
const OCCURRENCE_KEY_PATTERN = /^occurrence:[a-f0-9]{64}$/;
const MAX_EVALUATIONS_PER_RUN = 5_000;
const MAX_ALERTS_PER_RUN = 1_000;
const MAX_TEXT_BYTES = 64_000;
const MAX_JSON_DEPTH = 12;
const MAX_JSON_NODES = 25_000;
const FORBIDDEN_DELIVERY_KEYS = new Set([
  "channel",
  "delivery",
  "deliverytarget",
  "destination",
  "recipient",
  "recipients",
  "webhook",
  "webhookurl"
]);

const LEGACY_ALERT_METADATA_SQL = `
CREATE TABLE monitoring_store_metadata (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version INTEGER NOT NULL CHECK (schema_version > 0)
) STRICT;
`;

const ALERT_SCHEMA = `
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

CREATE TABLE IF NOT EXISTS monitoring_runs (
  tenant_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('blocked', 'evaluated')),
  as_of_date TEXT NOT NULL,
  scope_type TEXT NOT NULL CHECK (scope_type IN ('facility', 'portfolio', 'source')),
  scope_id TEXT NOT NULL,
  gate_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  blocked_reason TEXT CHECK (
    blocked_reason IS NULL OR blocked_reason IN (
      'blocking_findings_present', 'data_quality_failed', 'data_quality_pending'
    )
  ),
  result_json TEXT NOT NULL CHECK (json_valid(result_json)),
  result_hash TEXT NOT NULL,
  recorded_by TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, run_id),
  CHECK (
    (status = 'blocked' AND blocked_reason IS NOT NULL) OR
    (status = 'evaluated' AND blocked_reason IS NULL)
  )
) STRICT;

CREATE TABLE IF NOT EXISTS monitoring_alerts (
  tenant_id TEXT NOT NULL,
  alert_id TEXT NOT NULL,
  dedupe_key TEXT NOT NULL,
  monitor_id TEXT NOT NULL,
  monitor_version TEXT NOT NULL,
  scope_type TEXT NOT NULL CHECK (scope_type IN ('facility', 'portfolio', 'source')),
  scope_id TEXT NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'high', 'critical')),
  status TEXT NOT NULL CHECK (status IN ('open', 'acknowledged', 'escalated', 'resolved', 'suppressed')),
  recurrence_count INTEGER NOT NULL CHECK (recurrence_count >= 0),
  first_seen_on TEXT NOT NULL,
  last_seen_on TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, alert_id),
  UNIQUE (tenant_id, dedupe_key),
  CHECK (first_seen_on <= last_seen_on)
) STRICT;

CREATE TABLE IF NOT EXISTS monitoring_alert_occurrences (
  tenant_id TEXT NOT NULL,
  occurrence_key TEXT NOT NULL,
  alert_id TEXT NOT NULL,
  dedupe_key TEXT NOT NULL,
  as_of_date TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'high', 'critical')),
  alert_json TEXT NOT NULL CHECK (json_valid(alert_json)),
  evidence_json TEXT NOT NULL CHECK (json_valid(evidence_json)),
  evidence_hash TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, occurrence_key),
  FOREIGN KEY (tenant_id, alert_id)
    REFERENCES monitoring_alerts (tenant_id, alert_id),
  FOREIGN KEY (tenant_id, dedupe_key)
    REFERENCES monitoring_alerts (tenant_id, dedupe_key)
) STRICT;
CREATE INDEX IF NOT EXISTS monitoring_occurrences_by_alert
  ON monitoring_alert_occurrences (tenant_id, alert_id, as_of_date, occurrence_key);

CREATE TABLE IF NOT EXISTS monitoring_run_occurrences (
  tenant_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  occurrence_key TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  PRIMARY KEY (tenant_id, run_id, occurrence_key),
  UNIQUE (tenant_id, run_id, ordinal),
  FOREIGN KEY (tenant_id, run_id)
    REFERENCES monitoring_runs (tenant_id, run_id),
  FOREIGN KEY (tenant_id, occurrence_key)
    REFERENCES monitoring_alert_occurrences (tenant_id, occurrence_key)
) STRICT;

CREATE TABLE IF NOT EXISTS monitoring_alert_transitions (
  tenant_id TEXT NOT NULL,
  transition_id TEXT NOT NULL,
  alert_id TEXT NOT NULL,
  from_status TEXT NOT NULL CHECK (from_status IN ('open', 'acknowledged', 'escalated', 'resolved', 'suppressed')),
  to_status TEXT NOT NULL CHECK (to_status IN ('open', 'acknowledged', 'escalated', 'resolved', 'suppressed')),
  action TEXT NOT NULL CHECK (action IN ('acknowledge', 'escalate', 'resolve', 'suppress', 'reopen', 'recurrence_reopen')),
  actor TEXT NOT NULL,
  reason TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, transition_id),
  FOREIGN KEY (tenant_id, alert_id)
    REFERENCES monitoring_alerts (tenant_id, alert_id)
) STRICT;
CREATE INDEX IF NOT EXISTS monitoring_transitions_by_alert
  ON monitoring_alert_transitions (tenant_id, alert_id, created_at, transition_id);

CREATE TRIGGER IF NOT EXISTS monitoring_runs_no_update
BEFORE UPDATE ON monitoring_runs BEGIN SELECT RAISE(ABORT, 'monitoring runs are immutable'); END;
CREATE TRIGGER IF NOT EXISTS monitoring_runs_no_delete
BEFORE DELETE ON monitoring_runs BEGIN SELECT RAISE(ABORT, 'monitoring runs are immutable'); END;
CREATE TRIGGER IF NOT EXISTS monitoring_occurrences_no_update
BEFORE UPDATE ON monitoring_alert_occurrences BEGIN SELECT RAISE(ABORT, 'monitoring occurrences are immutable'); END;
CREATE TRIGGER IF NOT EXISTS monitoring_occurrences_no_delete
BEFORE DELETE ON monitoring_alert_occurrences BEGIN SELECT RAISE(ABORT, 'monitoring occurrences are immutable'); END;
CREATE TRIGGER IF NOT EXISTS monitoring_run_occurrences_no_update
BEFORE UPDATE ON monitoring_run_occurrences BEGIN SELECT RAISE(ABORT, 'monitoring run evidence links are immutable'); END;
CREATE TRIGGER IF NOT EXISTS monitoring_run_occurrences_no_delete
BEFORE DELETE ON monitoring_run_occurrences BEGIN SELECT RAISE(ABORT, 'monitoring run evidence links are immutable'); END;
CREATE TRIGGER IF NOT EXISTS monitoring_transitions_no_update
BEFORE UPDATE ON monitoring_alert_transitions BEGIN SELECT RAISE(ABORT, 'monitoring transitions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS monitoring_transitions_no_delete
BEFORE DELETE ON monitoring_alert_transitions BEGIN SELECT RAISE(ABORT, 'monitoring transitions are append-only'); END;

CREATE TRIGGER IF NOT EXISTS monitoring_alerts_payload_immutable
BEFORE UPDATE ON monitoring_alerts
WHEN NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.alert_id IS NOT OLD.alert_id
  OR NEW.dedupe_key IS NOT OLD.dedupe_key
  OR NEW.monitor_id IS NOT OLD.monitor_id
  OR NEW.monitor_version IS NOT OLD.monitor_version
  OR NEW.scope_type IS NOT OLD.scope_type
  OR NEW.scope_id IS NOT OLD.scope_id
  OR NEW.title IS NOT OLD.title
  OR NEW.message IS NOT OLD.message
  OR NEW.severity IS NOT OLD.severity
  OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'monitoring alert identity is immutable'); END;
CREATE TRIGGER IF NOT EXISTS monitoring_alerts_progress_guard
BEFORE UPDATE ON monitoring_alerts
WHEN NEW.recurrence_count < OLD.recurrence_count
  OR NEW.first_seen_on > OLD.first_seen_on
  OR NEW.last_seen_on < OLD.last_seen_on
  OR NEW.updated_at < OLD.updated_at
BEGIN SELECT RAISE(ABORT, 'monitoring alert recurrence cannot move backward'); END;
CREATE TRIGGER IF NOT EXISTS monitoring_alerts_status_guard
BEFORE UPDATE ON monitoring_alerts
WHEN NOT (
  NEW.status = OLD.status OR
  (OLD.status = 'open' AND NEW.status IN ('acknowledged', 'escalated', 'resolved', 'suppressed')) OR
  (OLD.status = 'acknowledged' AND NEW.status IN ('escalated', 'resolved', 'suppressed')) OR
  (OLD.status = 'escalated' AND NEW.status IN ('resolved', 'suppressed')) OR
  (OLD.status IN ('resolved', 'suppressed') AND NEW.status = 'open')
)
BEGIN SELECT RAISE(ABORT, 'invalid monitoring alert status transition'); END;
CREATE TRIGGER IF NOT EXISTS monitoring_alerts_no_delete
BEFORE DELETE ON monitoring_alerts BEGIN SELECT RAISE(ABORT, 'monitoring alerts cannot be deleted'); END;

CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS idempotency_records_no_update
BEFORE UPDATE ON idempotency_records BEGIN SELECT RAISE(ABORT, 'idempotency records are immutable'); END;
CREATE TRIGGER IF NOT EXISTS idempotency_records_no_delete
BEFORE DELETE ON idempotency_records BEGIN SELECT RAISE(ABORT, 'idempotency records are immutable'); END;
`;

/**
 * Durable monitoring evidence and alert-case persistence. This store has no
 * recipient, webhook, transport, or delivery API; it records decisions only.
 */
export class MonitoringAlertStore {
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;
  #closed = false;

  constructor(databasePath: string, options: MonitoringAlertStoreOptions = {}) {
    if (!databasePath.trim()) invalid("databasePath is required");
    const busyTimeoutMs = options.busyTimeoutMs ?? 5_000;
    if (!Number.isSafeInteger(busyTimeoutMs) || busyTimeoutMs < 0 || busyTimeoutMs > 60_000) {
      invalid("busyTimeoutMs must be an integer between 0 and 60000");
    }
    const absolutePath = resolve(databasePath);
    if (databasePath !== ":memory:") mkdirSync(dirname(absolutePath), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(databasePath === ":memory:" ? databasePath : absolutePath, {
      enableForeignKeyConstraints: true,
      allowExtension: false
    });
    this.#clock = options.clock ?? (() => new Date());
    try {
      this.#database.exec(`PRAGMA busy_timeout = ${busyTimeoutMs}`);
      this.#database.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;");
      migrateSqliteComponent(this.#database, {
        componentName: ALERT_STORE_COMPONENT,
        supportedVersion: ALERT_STORE_SCHEMA_VERSION,
        migrations: [{ version: 1, sql: ALERT_SCHEMA }],
        sharedObjects: SQLITE_SHARED_AUDIT_OBJECTS,
        legacyVersion: legacyAlertSchemaVersion,
        unsupportedVersionError: (current, supported) =>
          new MonitoringAlertStoreError(
            "UNSUPPORTED_SCHEMA",
            `Monitoring alert schema ${current} is newer than supported version ${supported}`
          )
      });
    } catch (error) {
      this.#database.close();
      this.#closed = true;
      throw error;
    }
  }

  recordRun(input: RecordMonitoringRunInput): MonitoringRunRecord {
    const resultJson = validateRunInput(input);
    return this.#idempotent(
      input.tenantId,
      "monitoring_run.record",
      input.idempotencyKey,
      input,
      () => {
        if (this.#getRunRow(input.tenantId, input.runId)) {
          conflict(`Monitoring run '${input.runId}' already exists for tenant '${input.tenantId}'`);
        }
        const recordedAt = this.#now();
        const resultHash = sha256(resultJson);
        this.#database
          .prepare(
            `INSERT INTO monitoring_runs (
               tenant_id, run_id, status, as_of_date, scope_type, scope_id,
               gate_id, snapshot_id, blocked_reason, result_json, result_hash,
               recorded_by, recorded_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .run(
            input.tenantId,
            input.runId,
            input.result.status,
            input.result.asOfDate,
            input.result.scope.type,
            input.result.scope.id,
            input.result.gateId,
            input.result.snapshotId,
            input.result.status === "blocked" ? input.result.reason : null,
            resultJson,
            resultHash,
            input.recordedBy,
            recordedAt
          );

        if (input.result.status === "evaluated") {
          input.result.alerts.forEach((alert, ordinal) => {
            this.#recordOccurrence(input, alert, ordinal, recordedAt);
          });
        }

        this.#insertAudit(
          input.tenantId,
          "monitoring_run.recorded",
          "monitoring_run",
          input.runId,
          input.recordedBy,
          input.result.status === "blocked"
            ? {
                alertCount: 0,
                reason: input.result.reason,
                resultHash,
                snapshotId: input.result.snapshotId,
                status: "blocked"
              }
            : {
                alertCount: input.result.alerts.length,
                evaluationCount: input.result.evaluations.length,
                resultHash,
                snapshotId: input.result.snapshotId,
                status: "evaluated"
              },
          recordedAt
        );
        return required(this.getRun(input.tenantId, input.runId));
      }
    );
  }

  getRun(tenantId: string, runId: string): MonitoringRunRecord | undefined {
    this.#assertOpen();
    identifier(tenantId, "tenantId");
    identifier(runId, "runId");
    const row = this.#getRunRow(tenantId, runId);
    if (!row) return undefined;
    const links = this.#database
      .prepare(
        `SELECT occurrence.alert_id, link.occurrence_key
           FROM monitoring_run_occurrences AS link
           JOIN monitoring_alert_occurrences AS occurrence
             ON occurrence.tenant_id = link.tenant_id
            AND occurrence.occurrence_key = link.occurrence_key
          WHERE link.tenant_id = ? AND link.run_id = ?
          ORDER BY link.ordinal`
      )
      .all(tenantId, runId) as unknown as RunOccurrenceRow[];
    return runFromRow(row, links);
  }

  getAlert(tenantId: string, alertId: string): AlertRecord | undefined {
    this.#assertOpen();
    identifier(tenantId, "tenantId");
    identifier(alertId, "alertId");
    const row = this.#database
      .prepare("SELECT * FROM monitoring_alerts WHERE tenant_id = ? AND alert_id = ?")
      .get(tenantId, alertId) as unknown as AlertRow | undefined;
    return row ? alertFromRow(row) : undefined;
  }

  getAlertByDedupeKey(tenantId: string, dedupeKey: string): AlertRecord | undefined {
    this.#assertOpen();
    identifier(tenantId, "tenantId");
    dedupeKeyValue(dedupeKey);
    const row = this.#database
      .prepare("SELECT * FROM monitoring_alerts WHERE tenant_id = ? AND dedupe_key = ?")
      .get(tenantId, dedupeKey) as unknown as AlertRow | undefined;
    return row ? alertFromRow(row) : undefined;
  }

  listAlerts(tenantId: string, options: ListAlertsOptions = {}): readonly AlertRecord[] {
    this.#assertOpen();
    identifier(tenantId, "tenantId");
    const limit = options.limit ?? 100;
    boundedLimit(limit, 500);
    if (options.status !== undefined) alertStatus(options.status);
    const rows = options.status === undefined
      ? this.#database
          .prepare(
            `SELECT * FROM monitoring_alerts
              WHERE tenant_id = ?
              ORDER BY last_seen_on DESC, alert_id
              LIMIT ?`
          )
          .all(tenantId, limit)
      : this.#database
          .prepare(
            `SELECT * FROM monitoring_alerts
              WHERE tenant_id = ? AND status = ?
              ORDER BY last_seen_on DESC, alert_id
              LIMIT ?`
          )
          .all(tenantId, options.status, limit);
    return (rows as unknown as AlertRow[]).map(alertFromRow);
  }

  listOccurrences(tenantId: string, alertId: string, limit = 100): readonly AlertOccurrenceRecord[] {
    this.#assertOpen();
    identifier(tenantId, "tenantId");
    identifier(alertId, "alertId");
    boundedLimit(limit, 1_000);
    const rows = this.#database
      .prepare(
        `SELECT * FROM monitoring_alert_occurrences
          WHERE tenant_id = ? AND alert_id = ?
          ORDER BY as_of_date, occurrence_key
          LIMIT ?`
      )
      .all(tenantId, alertId, limit) as unknown as OccurrenceRow[];
    return rows.map(occurrenceFromRow);
  }

  transitionAlert(input: TransitionAlertInput): AlertRecord {
    validateTransitionInput(input);
    return this.#idempotent(
      input.tenantId,
      "monitoring_alert.transition",
      input.idempotencyKey,
      input,
      () => {
        const current = this.getAlert(input.tenantId, input.alertId);
        if (!current) {
          throw new MonitoringAlertStoreError("ALERT_NOT_FOUND", "Monitoring alert was not found");
        }
        const toStatus = transitionTarget(input.action);
        if (!allowedManualTransition(current.status, input.action)) {
          throw new MonitoringAlertStoreError(
            "INVALID_TRANSITION",
            `Cannot ${input.action} an alert in '${current.status}' status`
          );
        }
        const createdAt = this.#now();
        const reason = transitionReason(input);
        this.#database
          .prepare(
            `UPDATE monitoring_alerts
                SET status = ?, updated_at = ?
              WHERE tenant_id = ? AND alert_id = ? AND status = ?`
          )
          .run(toStatus, createdAt, input.tenantId, input.alertId, current.status);
        this.#insertTransition(
          input.tenantId,
          input.alertId,
          current.status,
          toStatus,
          input.action,
          input.actor,
          reason,
          createdAt
        );
        this.#insertAudit(
          input.tenantId,
          `monitoring_alert.${transitionEventName(input.action)}`,
          "monitoring_alert",
          input.alertId,
          input.actor,
          {
            action: input.action,
            fromStatus: current.status,
            ...(reason === undefined ? {} : { reason }),
            toStatus
          },
          createdAt
        );
        return required(this.getAlert(input.tenantId, input.alertId));
      }
    );
  }

  listTransitions(tenantId: string, alertId: string, limit = 100): readonly AlertTransitionRecord[] {
    this.#assertOpen();
    identifier(tenantId, "tenantId");
    identifier(alertId, "alertId");
    boundedLimit(limit, 1_000);
    const rows = this.#database
      .prepare(
        `SELECT * FROM monitoring_alert_transitions
          WHERE tenant_id = ? AND alert_id = ?
          ORDER BY created_at, transition_id
          LIMIT ?`
      )
      .all(tenantId, alertId, limit) as unknown as TransitionRow[];
    return rows.map(transitionFromRow);
  }

  listAuditEvents(
    tenantId: string,
    options: ListMonitoringAuditOptions = {}
  ): readonly MonitoringAuditEvent[] {
    this.#assertOpen();
    identifier(tenantId, "tenantId");
    const afterSequence = options.afterSequence ?? 0;
    const limit = options.limit ?? 100;
    if (!Number.isSafeInteger(afterSequence) || afterSequence < 0) {
      invalid("afterSequence must be a non-negative integer");
    }
    boundedLimit(limit, 1_000);
    const rows = this.#database
      .prepare(
        `SELECT sequence, tenant_id, event_id, event_type, entity_type,
                entity_id, actor, details_json, occurred_at
           FROM audit_events
          WHERE tenant_id = ?
            AND sequence > ?
            AND event_type GLOB 'monitoring_*'
          ORDER BY sequence
          LIMIT ?`
      )
      .all(tenantId, afterSequence, limit) as unknown as AuditRow[];
    return rows.map(auditFromRow);
  }

  close(): void {
    if (this.#closed) return;
    this.#database.close();
    this.#closed = true;
  }

  #recordOccurrence(
    input: RecordMonitoringRunInput,
    occurrence: MonitoringAlert,
    ordinal: number,
    recordedAt: string
  ): void {
    const alertJson = boundedCanonicalJson(
      occurrence,
      "monitoring alert occurrence",
      MAX_ALERT_OCCURRENCE_JSON_BYTES
    );
    const evidenceJson = boundedCanonicalJson(
      occurrence.evidence,
      "monitoring alert evidence",
      MAX_ALERT_OCCURRENCE_JSON_BYTES
    );
    const evidenceHash = sha256(evidenceJson);
    const existingRow = this.#database
      .prepare("SELECT * FROM monitoring_alerts WHERE tenant_id = ? AND dedupe_key = ?")
      .get(input.tenantId, occurrence.dedupeKey) as unknown as AlertRow | undefined;
    let alertId: string;
    let created = false;

    if (existingRow) {
      assertDedupeIdentity(existingRow, occurrence);
      alertId = existingRow.alert_id;
    } else {
      alertId = randomUUID();
      created = true;
      this.#database
        .prepare(
          `INSERT INTO monitoring_alerts (
             tenant_id, alert_id, dedupe_key, monitor_id, monitor_version,
             scope_type, scope_id, title, message, severity, status,
             recurrence_count, first_seen_on, last_seen_on, created_at, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 0, ?, ?, ?, ?)`
        )
        .run(
          input.tenantId,
          alertId,
          occurrence.dedupeKey,
          occurrence.monitorId,
          occurrence.monitorVersion,
          occurrence.scope.type,
          occurrence.scope.id,
          occurrence.title,
          occurrence.message,
          occurrence.severity,
          occurrence.asOfDate,
          occurrence.asOfDate,
          recordedAt,
          recordedAt
        );
    }

    const existingOccurrence = this.#database
      .prepare(
        `SELECT alert_id, dedupe_key, alert_json, evidence_hash
           FROM monitoring_alert_occurrences
          WHERE tenant_id = ? AND occurrence_key = ?`
      )
      .get(input.tenantId, occurrence.occurrenceKey) as unknown as
      | {
          readonly alert_id: string;
          readonly dedupe_key: string;
          readonly alert_json: string;
          readonly evidence_hash: string;
        }
      | undefined;

    if (existingOccurrence) {
      if (
        existingOccurrence.alert_id !== alertId ||
        existingOccurrence.dedupe_key !== occurrence.dedupeKey ||
        existingOccurrence.alert_json !== alertJson ||
        existingOccurrence.evidence_hash !== evidenceHash
      ) {
        conflict(`Occurrence '${occurrence.occurrenceKey}' conflicts with immutable stored evidence`);
      }
    } else {
      this.#database
        .prepare(
          `INSERT INTO monitoring_alert_occurrences (
             tenant_id, occurrence_key, alert_id, dedupe_key, as_of_date,
             severity, alert_json, evidence_json, evidence_hash, recorded_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          input.tenantId,
          occurrence.occurrenceKey,
          alertId,
          occurrence.dedupeKey,
          occurrence.asOfDate,
          occurrence.severity,
          alertJson,
          evidenceJson,
          evidenceHash,
          recordedAt
        );

      const beforeUpdate = required(this.getAlert(input.tenantId, alertId));
      const reopen = beforeUpdate.status === "resolved";
      this.#database
        .prepare(
          `UPDATE monitoring_alerts
              SET recurrence_count = recurrence_count + 1,
                  first_seen_on = CASE WHEN ? < first_seen_on THEN ? ELSE first_seen_on END,
                  last_seen_on = CASE WHEN ? > last_seen_on THEN ? ELSE last_seen_on END,
                  status = CASE WHEN status = 'resolved' THEN 'open' ELSE status END,
                  updated_at = ?
            WHERE tenant_id = ? AND alert_id = ?`
        )
        .run(
          occurrence.asOfDate,
          occurrence.asOfDate,
          occurrence.asOfDate,
          occurrence.asOfDate,
          recordedAt,
          input.tenantId,
          alertId
        );

      if (reopen) {
        this.#insertTransition(
          input.tenantId,
          alertId,
          "resolved",
          "open",
          "recurrence_reopen",
          input.recordedBy,
          "A distinct monitoring occurrence recurred after resolution.",
          recordedAt
        );
        this.#insertAudit(
          input.tenantId,
          "monitoring_alert.reopened",
          "monitoring_alert",
          alertId,
          input.recordedBy,
          { occurrenceKey: occurrence.occurrenceKey, reason: "recurrence_after_resolution" },
          recordedAt
        );
      }

      const updated = required(this.getAlert(input.tenantId, alertId));
      this.#insertAudit(
        input.tenantId,
        created ? "monitoring_alert.opened" : "monitoring_alert.recurred",
        created ? "monitoring_alert" : "monitoring_alert_occurrence",
        created ? alertId : occurrence.occurrenceKey,
        input.recordedBy,
        {
          alertId,
          dedupeKey: occurrence.dedupeKey,
          evidenceHash,
          occurrenceKey: occurrence.occurrenceKey,
          recurrenceCount: updated.recurrenceCount
        },
        recordedAt
      );
    }

    this.#database
      .prepare(
        `INSERT INTO monitoring_run_occurrences (
           tenant_id, run_id, occurrence_key, ordinal
         ) VALUES (?, ?, ?, ?)`
      )
      .run(input.tenantId, input.runId, occurrence.occurrenceKey, ordinal);
  }

  #insertTransition(
    tenantId: string,
    alertId: string,
    fromStatus: AlertStatus,
    toStatus: AlertStatus,
    action: AlertTransitionAction,
    actor: string,
    reason: string | undefined,
    createdAt: string
  ): AlertTransitionRecord {
    const transitionId = randomUUID();
    this.#database
      .prepare(
        `INSERT INTO monitoring_alert_transitions (
           tenant_id, transition_id, alert_id, from_status, to_status,
           action, actor, reason, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        tenantId,
        transitionId,
        alertId,
        fromStatus,
        toStatus,
        action,
        actor,
        reason ?? null,
        createdAt
      );
    return {
      tenantId,
      transitionId,
      alertId,
      fromStatus,
      toStatus,
      action,
      actor,
      ...(reason === undefined ? {} : { reason }),
      createdAt
    };
  }

  #insertAudit(
    tenantId: string,
    eventType: string,
    entityType: MonitoringAuditEvent["entityType"],
    entityId: string,
    actor: string,
    details: JsonValue,
    occurredAt: string
  ): void {
    this.#database
      .prepare(
        `INSERT INTO audit_events (
           tenant_id, event_id, event_type, entity_type, entity_id,
           actor, details_json, occurred_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        tenantId,
        randomUUID(),
        eventType,
        entityType,
        entityId,
        actor,
        boundedCanonicalJson(details, "audit details", 64_000),
        occurredAt
      );
  }

  #idempotent<T>(
    tenantId: string,
    operation: string,
    idempotencyKey: string,
    request: unknown,
    execute: () => T
  ): T {
    this.#assertOpen();
    const requestJson = boundedCanonicalJson(request, "idempotent request", MAX_MONITORING_RUN_JSON_BYTES);
    const requestHash = sha256(requestJson);
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const receipt = this.#database
        .prepare(
          `SELECT request_hash, response_json
             FROM idempotency_records
            WHERE tenant_id = ? AND operation = ? AND idempotency_key = ?`
        )
        .get(tenantId, operation, idempotencyKey) as unknown as IdempotencyRow | undefined;
      if (receipt) {
        if (receipt.request_hash !== requestHash) {
          throw new MonitoringAlertStoreError(
            "IDEMPOTENCY_CONFLICT",
            `Idempotency key '${idempotencyKey}' was used with a different ${operation} request`
          );
        }
        const replay = JSON.parse(receipt.response_json) as T;
        this.#database.exec("COMMIT");
        return replay;
      }
      const response = execute();
      const responseJson = boundedCanonicalJson(
        response,
        "idempotent response",
        MAX_MONITORING_RUN_JSON_BYTES
      );
      this.#database
        .prepare(
          `INSERT INTO idempotency_records (
             tenant_id, operation, idempotency_key, request_hash, response_json, created_at
           ) VALUES (?, ?, ?, ?, ?, ?)`
        )
        .run(tenantId, operation, idempotencyKey, requestHash, responseJson, this.#now());
      this.#database.exec("COMMIT");
      return response;
    } catch (error) {
      rollback(this.#database);
      throw error;
    }
  }

  #getRunRow(tenantId: string, runId: string): RunRow | undefined {
    return this.#database
      .prepare("SELECT * FROM monitoring_runs WHERE tenant_id = ? AND run_id = ?")
      .get(tenantId, runId) as unknown as RunRow | undefined;
  }

  #now(): string {
    const value = this.#clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      invalid("clock must return a valid Date");
    }
    return value.toISOString();
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw new MonitoringAlertStoreError("STORE_CLOSED", "Monitoring alert store is closed");
    }
  }
}

function legacyAlertSchemaVersion(database: DatabaseSync): number | undefined {
  const table = database
    .prepare(
      "SELECT type, sql FROM sqlite_master WHERE name = 'monitoring_store_metadata'"
    )
    .get() as { readonly type: string; readonly sql: string | null } | undefined;
  if (!table) return undefined;
  if (
    table.type !== "table" ||
    table.sql === null ||
    normalizeSchemaSql(table.sql) !== normalizeSchemaSql(LEGACY_ALERT_METADATA_SQL)
  ) {
    throw new MonitoringAlertStoreError(
      "UNSUPPORTED_SCHEMA",
      "Legacy monitoring alert schema metadata is not canonical"
    );
  }
  const row = database
    .prepare("SELECT schema_version FROM monitoring_store_metadata WHERE singleton = 1")
    .get() as { readonly schema_version: number } | undefined;
  if (!row) {
    throw new MonitoringAlertStoreError(
      "UNSUPPORTED_SCHEMA",
      "Legacy monitoring alert schema metadata is missing"
    );
  }
  return row.schema_version;
}

function normalizeSchemaSql(sql: string): string {
  return sql.replace(/\s+/g, " ").trim().replace(/;$/, "");
}

function validateRunInput(input: RecordMonitoringRunInput): string {
  identifier(input.tenantId, "tenantId");
  identifier(input.runId, "runId");
  identifier(input.recordedBy, "recordedBy");
  identifier(input.idempotencyKey, "idempotencyKey");
  const result = input.result;
  if (!(result.status === "blocked" || result.status === "evaluated")) {
    invalid("monitoring result status must be blocked or evaluated");
  }
  isoDate(result.asOfDate, "result.asOfDate");
  scope(result.scope, "result.scope");
  identifier(result.gateId, "result.gateId");
  identifier(result.snapshotId, "result.snapshotId");
  if (result.evaluations.length > MAX_EVALUATIONS_PER_RUN) {
    invalid(`monitoring run exceeds ${MAX_EVALUATIONS_PER_RUN} evaluations`);
  }
  if (result.alerts.length > MAX_ALERTS_PER_RUN) {
    invalid(`monitoring run exceeds ${MAX_ALERTS_PER_RUN} alerts`);
  }
  if (result.status === "blocked") {
    if (result.evaluations.length !== 0 || result.alerts.length !== 0) {
      invalid("blocked monitoring runs cannot contain evaluations or alerts");
    }
    if (!(
      result.reason === "blocking_findings_present" ||
      result.reason === "data_quality_failed" ||
      result.reason === "data_quality_pending"
    )) {
      invalid("blocked monitoring run has an invalid reason");
    }
  } else {
    validateEvaluatedResult(result.evaluations, result.alerts, result);
  }
  return boundedCanonicalJson(result, "monitoring result", MAX_MONITORING_RUN_JSON_BYTES);
}

function validateEvaluatedResult(
  evaluations: readonly MonitorEvaluation[],
  alerts: readonly MonitoringAlert[],
  result: Extract<MonitoringResult, { readonly status: "evaluated" }>
): void {
  const evaluationByDedupe = new Map<string, MonitorEvaluation>();
  for (const [index, evaluation] of evaluations.entries()) {
    identifier(evaluation.monitorId, `evaluations[${index}].monitorId`);
    nonBlankBounded(evaluation.monitorVersion, `evaluations[${index}].monitorVersion`, 256);
    identifier(evaluation.metricId, `evaluations[${index}].metricId`);
    dedupeKeyValue(evaluation.dedupeKey);
    if (!(evaluation.outcome === "clear" || evaluation.outcome === "missing_observation" || evaluation.outcome === "triggered")) {
      invalid(`evaluations[${index}].outcome is invalid`);
    }
    severity(evaluation.severity);
    if (evaluationByDedupe.has(evaluation.dedupeKey)) {
      invalid(`evaluations contain duplicate dedupe key '${evaluation.dedupeKey}'`);
    }
    evaluationByDedupe.set(evaluation.dedupeKey, evaluation);
  }

  const occurrenceKeys = new Set<string>();
  const alertDedupeKeys = new Set<string>();
  for (const [index, alert] of alerts.entries()) {
    occurrenceKeyValue(alert.occurrenceKey);
    dedupeKeyValue(alert.dedupeKey);
    identifier(alert.monitorId, `alerts[${index}].monitorId`);
    nonBlankBounded(alert.monitorVersion, `alerts[${index}].monitorVersion`, 256);
    scope(alert.scope, `alerts[${index}].scope`);
    isoDate(alert.asOfDate, `alerts[${index}].asOfDate`);
    nonBlankBounded(alert.title, `alerts[${index}].title`, 512);
    nonBlankBounded(alert.message, `alerts[${index}].message`, 4_000);
    severity(alert.severity);
    validateEvidence(alert.evidence, index);
    if (alert.asOfDate !== result.asOfDate || !sameScope(alert.scope, result.scope)) {
      invalid(`alerts[${index}] does not match the monitoring run date and scope`);
    }
    if (alert.evidence.gateId !== result.gateId || alert.evidence.snapshotId !== result.snapshotId) {
      invalid(`alerts[${index}] evidence does not match the monitoring run gate and snapshot`);
    }
    const evaluation = evaluationByDedupe.get(alert.dedupeKey);
    if (
      !evaluation ||
      evaluation.outcome !== "triggered" ||
      evaluation.monitorId !== alert.monitorId ||
      evaluation.monitorVersion !== alert.monitorVersion
    ) {
      invalid(`alerts[${index}] does not have a matching triggered evaluation`);
    }
    if (occurrenceKeys.has(alert.occurrenceKey)) {
      invalid(`alerts contain duplicate occurrence key '${alert.occurrenceKey}'`);
    }
    if (alertDedupeKeys.has(alert.dedupeKey)) {
      invalid(`alerts contain duplicate dedupe key '${alert.dedupeKey}'`);
    }
    occurrenceKeys.add(alert.occurrenceKey);
    alertDedupeKeys.add(alert.dedupeKey);
    boundedCanonicalJson(alert, `alerts[${index}]`, MAX_ALERT_OCCURRENCE_JSON_BYTES);
  }
}

function validateEvidence(evidence: MonitoringAlertEvidence, alertIndex: number): void {
  identifier(evidence.gateId, `alerts[${alertIndex}].evidence.gateId`);
  identifier(evidence.snapshotId, `alerts[${alertIndex}].evidence.snapshotId`);
  isoTimestamp(evidence.certifiedAt, `alerts[${alertIndex}].evidence.certifiedAt`);
  identifier(evidence.observationId, `alerts[${alertIndex}].evidence.observationId`);
  isoDate(evidence.observationAsOfDate, `alerts[${alertIndex}].evidence.observationAsOfDate`);
  identifier(evidence.metricId, `alerts[${alertIndex}].evidence.metricId`);
  nonBlankBounded(evidence.observedValue, `alerts[${alertIndex}].evidence.observedValue`, 512);
  if (evidence.references.length > 100) invalid("alert evidence cannot contain more than 100 references");
  for (const [index, reference] of evidence.references.entries()) {
    if (!(
      reference.kind === "borrowing_base_run" ||
      reference.kind === "mapping" ||
      reference.kind === "metric_run" ||
      reference.kind === "policy" ||
      reference.kind === "reconciliation" ||
      reference.kind === "source_artifact"
    )) {
      invalid(`alerts[${alertIndex}].evidence.references[${index}].kind is invalid`);
    }
    identifier(reference.id, `alerts[${alertIndex}].evidence.references[${index}].id`);
  }
}

function validateTransitionInput(input: TransitionAlertInput): void {
  identifier(input.tenantId, "tenantId");
  identifier(input.alertId, "alertId");
  identifier(input.actor, "actor");
  identifier(input.idempotencyKey, "idempotencyKey");
  if (!(
    input.action === "acknowledge" ||
    input.action === "escalate" ||
    input.action === "resolve" ||
    input.action === "suppress" ||
    input.action === "reopen"
  )) {
    invalid("alert transition action is invalid");
  }
  const reason = transitionReason(input);
  if (reason !== undefined) nonBlankBounded(reason, "transition reason", 4_000);
}

function assertDedupeIdentity(row: AlertRow, alert: MonitoringAlert): void {
  if (
    row.monitor_id !== alert.monitorId ||
    row.monitor_version !== alert.monitorVersion ||
    row.scope_type !== alert.scope.type ||
    row.scope_id !== alert.scope.id ||
    row.title !== alert.title ||
    row.message !== alert.message ||
    row.severity !== alert.severity
  ) {
    conflict(`Dedupe key '${alert.dedupeKey}' collides with a different alert identity`);
  }
}

function transitionTarget(action: ManualAlertTransitionAction): AlertStatus {
  if (action === "acknowledge") return "acknowledged";
  if (action === "escalate") return "escalated";
  if (action === "resolve") return "resolved";
  if (action === "suppress") return "suppressed";
  return "open";
}

function transitionEventName(action: ManualAlertTransitionAction): string {
  if (action === "acknowledge") return "acknowledged";
  if (action === "escalate") return "escalated";
  if (action === "resolve") return "resolved";
  if (action === "suppress") return "suppressed";
  return "reopened";
}

function allowedManualTransition(status: AlertStatus, action: ManualAlertTransitionAction): boolean {
  if (action === "acknowledge") return status === "open";
  if (action === "escalate") return status === "open" || status === "acknowledged";
  if (action === "resolve" || action === "suppress") {
    return status === "open" || status === "acknowledged" || status === "escalated";
  }
  return status === "resolved" || status === "suppressed";
}

function transitionReason(input: TransitionAlertInput): string | undefined {
  if (input.action === "acknowledge") return input.note;
  if (input.action === "resolve") return input.resolution;
  return input.reason;
}

function runFromRow(row: RunRow, links: readonly RunOccurrenceRow[]): MonitoringRunRecord {
  return {
    tenantId: row.tenant_id,
    runId: row.run_id,
    status: row.status,
    asOfDate: row.as_of_date,
    scope: { type: row.scope_type, id: row.scope_id },
    gateId: row.gate_id,
    snapshotId: row.snapshot_id,
    ...(row.blocked_reason === null ? {} : { blockedReason: row.blocked_reason }),
    result: JSON.parse(row.result_json) as MonitoringResult,
    resultHash: row.result_hash,
    alertIds: links.map((link) => link.alert_id),
    occurrenceKeys: links.map((link) => link.occurrence_key),
    recordedBy: row.recorded_by,
    recordedAt: row.recorded_at
  };
}

function alertFromRow(row: AlertRow): AlertRecord {
  return {
    tenantId: row.tenant_id,
    alertId: row.alert_id,
    dedupeKey: row.dedupe_key,
    monitorId: row.monitor_id,
    monitorVersion: row.monitor_version,
    scope: { type: row.scope_type, id: row.scope_id },
    title: row.title,
    message: row.message,
    severity: row.severity,
    status: row.status,
    recurrenceCount: row.recurrence_count,
    firstSeenOn: row.first_seen_on,
    lastSeenOn: row.last_seen_on,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function occurrenceFromRow(row: OccurrenceRow): AlertOccurrenceRecord {
  return {
    tenantId: row.tenant_id,
    occurrenceKey: row.occurrence_key,
    alertId: row.alert_id,
    dedupeKey: row.dedupe_key,
    asOfDate: row.as_of_date,
    severity: row.severity,
    alert: JSON.parse(row.alert_json) as MonitoringAlert,
    evidence: JSON.parse(row.evidence_json) as MonitoringAlertEvidence,
    evidenceHash: row.evidence_hash,
    recordedAt: row.recorded_at
  };
}

function transitionFromRow(row: TransitionRow): AlertTransitionRecord {
  return {
    tenantId: row.tenant_id,
    transitionId: row.transition_id,
    alertId: row.alert_id,
    fromStatus: row.from_status,
    toStatus: row.to_status,
    action: row.action,
    actor: row.actor,
    ...(row.reason === null ? {} : { reason: row.reason }),
    createdAt: row.created_at
  };
}

function auditFromRow(row: AuditRow): MonitoringAuditEvent {
  return {
    sequence: row.sequence,
    tenantId: row.tenant_id,
    eventId: row.event_id,
    eventType: row.event_type,
    entityType: row.entity_type,
    entityId: row.entity_id,
    actor: row.actor,
    details: JSON.parse(row.details_json) as JsonValue,
    occurredAt: row.occurred_at
  };
}

function boundedCanonicalJson(value: unknown, label: string, maxBytes: number): string {
  const budget = { nodes: 0 };
  const normalized = canonicalize(value, label, 0, budget);
  const json = JSON.stringify(normalized);
  if (Buffer.byteLength(json, "utf8") > maxBytes) {
    invalid(`${label} exceeds ${maxBytes} bytes`);
  }
  return json;
}

function canonicalize(
  value: unknown,
  path: string,
  depth: number,
  budget: { nodes: number }
): JsonValue {
  budget.nodes += 1;
  if (budget.nodes > MAX_JSON_NODES) invalid(`${path} exceeds the JSON node limit`);
  if (depth > MAX_JSON_DEPTH) invalid(`${path} exceeds the JSON depth limit`);
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") > MAX_TEXT_BYTES) invalid(`${path} contains an oversized string`);
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) invalid(`${path} contains a non-finite number`);
    return Object.is(value, -0) ? 0 : value;
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_JSON_NODES) invalid(`${path} contains an oversized array`);
    return value.map((entry, index) => {
      if (entry === undefined) invalid(`${path}[${index}] cannot be undefined`);
      return canonicalize(entry, `${path}[${index}]`, depth + 1, budget);
    });
  }
  if (typeof value === "object") {
    if (value instanceof Date) {
      if (!Number.isFinite(value.getTime())) invalid(`${path} contains an invalid Date`);
      return value.toISOString();
    }
    const prototype = Object.getPrototypeOf(value) as unknown;
    if (!(prototype === Object.prototype || prototype === null)) {
      invalid(`${path} must contain only JSON-compatible plain objects`);
    }
    const keys = Object.keys(value).sort();
    if (keys.length > 1_000) invalid(`${path} contains too many object keys`);
    const output: Record<string, JsonValue> = {};
    for (const key of keys) {
      if (FORBIDDEN_DELIVERY_KEYS.has(key.toLowerCase().replace(/[^a-z0-9]/g, ""))) {
        invalid(`${path}.${key} is not supported; this store does not accept delivery targets`);
      }
      if (Buffer.byteLength(key, "utf8") > 256) invalid(`${path} contains an oversized key`);
      const nested = (value as Record<string, unknown>)[key];
      if (nested !== undefined) output[key] = canonicalize(nested, `${path}.${key}`, depth + 1, budget);
    }
    return output;
  }
  invalid(`${path} contains an unsupported '${typeof value}' value`);
}

function sameScope(left: MonitoringScope, right: MonitoringScope): boolean {
  return left.type === right.type && left.id === right.id;
}

function scope(value: MonitoringScope, label: string): void {
  if (!(value.type === "facility" || value.type === "portfolio" || value.type === "source")) {
    invalid(`${label}.type is invalid`);
  }
  identifier(value.id, `${label}.id`);
}

function severity(value: MonitorSeverity): void {
  if (!(value === "info" || value === "warning" || value === "high" || value === "critical")) {
    invalid("monitoring severity is invalid");
  }
}

function alertStatus(value: AlertStatus): void {
  if (!(
    value === "open" ||
    value === "acknowledged" ||
    value === "escalated" ||
    value === "resolved" ||
    value === "suppressed"
  )) {
    invalid("alert status is invalid");
  }
}

function identifier(value: string, label: string): void {
  if (!IDENTIFIER_PATTERN.test(value)) {
    invalid(`${label} must be 1-128 characters using letters, digits, dot, underscore, colon, or hyphen`);
  }
}

function dedupeKeyValue(value: string): void {
  if (!DEDUPE_KEY_PATTERN.test(value)) invalid("dedupeKey is not a canonical monitoring dedupe key");
}

function occurrenceKeyValue(value: string): void {
  if (!OCCURRENCE_KEY_PATTERN.test(value)) {
    invalid("occurrenceKey is not a canonical monitoring occurrence key");
  }
}

function nonBlankBounded(value: string, label: string, maxBytes: number): void {
  if (!value.trim()) invalid(`${label} must not be blank`);
  if (Buffer.byteLength(value, "utf8") > maxBytes) invalid(`${label} exceeds ${maxBytes} bytes`);
}

function isoDate(value: string, label: string): void {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) invalid(`${label} must use YYYY-MM-DD`);
  const date = new Date(`${value}T00:00:00.000Z`);
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 10) !== value) {
    invalid(`${label} must be a real calendar date`);
  }
}

function isoTimestamp(value: string, label: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T/.test(value) || !Number.isFinite(Date.parse(value))) {
    invalid(`${label} must be an ISO-8601 timestamp`);
  }
}

function boundedLimit(value: number, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    invalid(`limit must be an integer between 1 and ${maximum}`);
  }
}

function sha256(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function rollback(database: DatabaseSync): void {
  try {
    database.exec("ROLLBACK");
  } catch {
    // Preserve the original error if SQLite already rolled back the transaction.
  }
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw new Error("Monitoring alert store invariant failed");
  return value;
}

function invalid(message: string): never {
  throw new MonitoringAlertStoreError("INVALID_ARGUMENT", message);
}

function conflict(message: string): never {
  throw new MonitoringAlertStoreError("CONFLICT", message);
}
