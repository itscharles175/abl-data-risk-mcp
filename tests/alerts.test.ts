import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, test } from "node:test";

import {
  MonitoringAlertStore,
  MonitoringAlertStoreError,
  type RecordMonitoringRunInput
} from "../src/control/alerts.js";
import { ControlStore } from "../src/control/store.js";
import {
  evaluateMonitoring,
  type DataQualityGate,
  type MonitorDefinition,
  type MonitoringResult
} from "../src/domain/monitoring.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("duplicate run evaluation is idempotent and a repeated occurrence does not inflate recurrence", () => {
  const { store } = createStore();
  const result = evaluatedResult("2025-06-30", "snapshot-june", "availability-june", "-25");
  const input = runInput("tenant-a", "run-june", "record-run-june", result);

  const first = store.recordRun(input);
  assert.deepEqual(store.recordRun(input), first);
  assert.equal(first.alertIds.length, 1);
  const alertId = first.alertIds[0]!;
  assert.equal(store.getAlert("tenant-a", alertId)?.recurrenceCount, 1);
  assert.equal(store.listOccurrences("tenant-a", alertId).length, 1);
  assert.equal(store.listAuditEvents("tenant-a").length, 2);

  assert.throws(
    () => store.recordRun({ ...input, recordedBy: "different-actor" }),
    (error: unknown) => isAlertStoreError(error, "IDEMPOTENCY_CONFLICT")
  );

  const duplicateEvaluation = store.recordRun({
    ...input,
    runId: "run-june-retry",
    idempotencyKey: "record-run-june-retry"
  });
  assert.deepEqual(duplicateEvaluation.occurrenceKeys, first.occurrenceKeys);
  assert.equal(store.getAlert("tenant-a", alertId)?.recurrenceCount, 1);
  assert.equal(store.listOccurrences("tenant-a", alertId).length, 1);
  store.close();
});

test("distinct occurrences dedupe into one alert and preserve immutable evidence", () => {
  const { databasePath, store } = createStore();
  const june = evaluatedResult("2025-06-30", "snapshot-june", "availability-june", "-25");
  const july = evaluatedResult("2025-07-31", "snapshot-july", "availability-july", "-10");
  const first = store.recordRun(runInput("tenant-a", "run-june", "record-june", june));
  const second = store.recordRun(runInput("tenant-a", "run-july", "record-july", july));

  assert.equal(first.alertIds[0], second.alertIds[0]);
  const alertId = first.alertIds[0]!;
  assert.deepEqual(store.getAlert("tenant-a", alertId), {
    ...store.getAlert("tenant-a", alertId),
    recurrenceCount: 2,
    firstSeenOn: "2025-06-30",
    lastSeenOn: "2025-07-31"
  });
  const occurrences = store.listOccurrences("tenant-a", alertId);
  assert.equal(occurrences.length, 2);
  assert.notEqual(occurrences[0]?.occurrenceKey, occurrences[1]?.occurrenceKey);
  assert.notEqual(occurrences[0]?.evidenceHash, occurrences[1]?.evidenceHash);
  assert.equal(occurrences[0]?.evidence.observedValue, "-25");
  assert.equal(occurrences[1]?.evidence.observedValue, "-10");
  store.close();

  const database = new DatabaseSync(databasePath, { enableForeignKeyConstraints: true });
  assert.throws(
    () =>
      database
        .prepare(
          "UPDATE monitoring_alert_occurrences SET evidence_json = '{}' WHERE tenant_id = ? AND occurrence_key = ?"
        )
        .run("tenant-a", occurrences[0]!.occurrenceKey),
    /monitoring occurrences are immutable/
  );
  assert.throws(
    () => database.prepare("DELETE FROM audit_events WHERE tenant_id = ?").run("tenant-a"),
    /audit events are append-only/
  );
  database.close();
});

test("typed alert transitions cover case states and recurrence reopens only resolved alerts", () => {
  const { store } = createStore(tickingClock());
  const initial = store.recordRun(
    runInput(
      "tenant-a",
      "run-june",
      "record-june",
      evaluatedResult("2025-06-30", "snapshot-june", "availability-june", "-25")
    )
  );
  const alertId = initial.alertIds[0]!;

  const acknowledged = store.transitionAlert({
    tenantId: "tenant-a",
    alertId,
    action: "acknowledge",
    actor: "risk-analyst",
    note: "Review started.",
    idempotencyKey: "ack-alert"
  });
  assert.equal(acknowledged.status, "acknowledged");
  assert.deepEqual(
    store.transitionAlert({
      tenantId: "tenant-a",
      alertId,
      action: "acknowledge",
      actor: "risk-analyst",
      note: "Review started.",
      idempotencyKey: "ack-alert"
    }),
    acknowledged
  );
  assert.equal(
    store.transitionAlert({
      tenantId: "tenant-a",
      alertId,
      action: "escalate",
      actor: "risk-manager",
      reason: "Immediate lender review required.",
      idempotencyKey: "escalate-alert"
    }).status,
    "escalated"
  );
  assert.equal(
    store.transitionAlert({
      tenantId: "tenant-a",
      alertId,
      action: "resolve",
      actor: "risk-manager",
      resolution: "Borrower cured the overadvance.",
      idempotencyKey: "resolve-alert"
    }).status,
    "resolved"
  );
  assert.throws(
    () =>
      store.transitionAlert({
        tenantId: "tenant-a",
        alertId,
        action: "acknowledge",
        actor: "risk-analyst",
        idempotencyKey: "invalid-ack"
      }),
    (error: unknown) => isAlertStoreError(error, "INVALID_TRANSITION")
  );

  store.recordRun(
    runInput(
      "tenant-a",
      "run-july",
      "record-july",
      evaluatedResult("2025-07-31", "snapshot-july", "availability-july", "-10")
    )
  );
  assert.equal(store.getAlert("tenant-a", alertId)?.status, "open");
  assert.ok(
    store.listTransitions("tenant-a", alertId).some((transition) => transition.action === "recurrence_reopen")
  );

  assert.equal(
    store.transitionAlert({
      tenantId: "tenant-a",
      alertId,
      action: "suppress",
      actor: "risk-manager",
      reason: "Approved monitoring exception.",
      idempotencyKey: "suppress-alert"
    }).status,
    "suppressed"
  );
  store.recordRun(
    runInput(
      "tenant-a",
      "run-august",
      "record-august",
      evaluatedResult("2025-08-31", "snapshot-august", "availability-august", "-5")
    )
  );
  assert.equal(store.getAlert("tenant-a", alertId)?.status, "suppressed");
  assert.equal(store.getAlert("tenant-a", alertId)?.recurrenceCount, 3);
  assert.equal(
    store.transitionAlert({
      tenantId: "tenant-a",
      alertId,
      action: "reopen",
      actor: "risk-manager",
      reason: "Exception expired.",
      idempotencyKey: "reopen-alert"
    }).status,
    "open"
  );
  assert.deepEqual(
    store.listTransitions("tenant-a", alertId).map((transition) => transition.action),
    ["acknowledge", "escalate", "resolve", "recurrence_reopen", "suppress", "reopen"]
  );
  store.close();
});

test("blocked monitoring runs are durable without creating alert cases", () => {
  const { store } = createStore();
  const blocked = evaluateMonitoring({
    asOfDate: "2025-06-30",
    scope: { type: "facility", id: "facility-1" },
    dataQualityGate: {
      status: "failed",
      gateId: "dq-failed",
      snapshotId: "snapshot-failed",
      blockingFindingCount: 2,
      evidence: []
    },
    monitorDefinitions: [monitor],
    observations: []
  });
  assert.equal(blocked.status, "blocked");

  const record = store.recordRun(runInput("tenant-a", "run-blocked", "record-blocked", blocked));
  assert.equal(record.status, "blocked");
  assert.equal(record.blockedReason, "data_quality_failed");
  assert.deepEqual(record.alertIds, []);
  assert.deepEqual(record.occurrenceKeys, []);
  assert.deepEqual(store.listAlerts("tenant-a"), []);
  assert.equal(store.listAuditEvents("tenant-a")[0]?.eventType, "monitoring_run.recorded");
  store.close();
});

test("tenant boundaries hide runs, alerts, occurrences, transitions, and audit", () => {
  const { store } = createStore();
  const result = evaluatedResult("2025-06-30", "snapshot-june", "availability-june", "-25");
  const tenantA = store.recordRun(runInput("tenant-a", "shared-run", "shared-key", result));
  const tenantB = store.recordRun(runInput("tenant-b", "shared-run", "shared-key", result));
  const alertA = tenantA.alertIds[0]!;
  const alertB = tenantB.alertIds[0]!;

  assert.notEqual(alertA, alertB);
  assert.equal(store.getRun("tenant-c", "shared-run"), undefined);
  assert.equal(store.getAlert("tenant-b", alertA), undefined);
  assert.deepEqual(store.listOccurrences("tenant-b", alertA), []);
  assert.deepEqual(store.listTransitions("tenant-b", alertA), []);
  assert.equal(store.listAuditEvents("tenant-a").length, 2);
  assert.equal(store.listAuditEvents("tenant-b").length, 2);
  assert.throws(
    () =>
      store.transitionAlert({
        tenantId: "tenant-b",
        alertId: alertA,
        action: "acknowledge",
        actor: "risk-analyst",
        idempotencyKey: "cross-tenant-transition"
      }),
    (error: unknown) => isAlertStoreError(error, "ALERT_NOT_FOUND")
  );
  store.close();
});

test("the alert schema coexists with the control store and rejects delivery targets", () => {
  const directory = temporaryDirectory();
  const databasePath = join(directory, "shared-control.sqlite");
  const alertStore = new MonitoringAlertStore(databasePath, { clock: fixedClock });
  const blocked = evaluateMonitoring({
    asOfDate: "2025-06-30",
    scope: { type: "portfolio", id: "portfolio-1" },
    dataQualityGate: {
      status: "pending",
      gateId: "dq-pending",
      snapshotId: "snapshot-shared",
      blockingFindingCount: 0,
      evidence: []
    },
    monitorDefinitions: [],
    observations: []
  });
  alertStore.recordRun(runInput("tenant-a", "run-pending", "record-pending", blocked));

  const unsafe = {
    ...blocked,
    webhookUrl: "https://example.invalid/alerts"
  } as unknown as MonitoringResult;
  assert.throws(
    () => alertStore.recordRun(runInput("tenant-a", "run-unsafe", "record-unsafe", unsafe)),
    (error: unknown) => isAlertStoreError(error, "INVALID_ARGUMENT")
  );
  alertStore.close();

  const controlStore = new ControlStore(databasePath, { clock: fixedClock });
  controlStore.createDatasetSnapshot({
    tenantId: "tenant-a",
    snapshotId: "snapshot-shared",
    sourceId: "warehouse",
    sourceLocator: "warehouse.public.loan_tape",
    asOfDate: "2025-06-30",
    contentHash: digest("snapshot"),
    rowCount: 10,
    schema: { columns: [] },
    createdBy: "data-steward",
    idempotencyKey: "create-shared-snapshot"
  });
  assert.equal(controlStore.getDatasetSnapshot("tenant-a", "snapshot-shared")?.rowCount, 10);
  assert.ok(
    controlStore.listAuditEvents("tenant-a").some((event) => event.eventType === "monitoring_run.recorded")
  );
  controlStore.close();
});

const monitor: MonitorDefinition = {
  monitorId: "availability-negative",
  version: "1",
  effectiveFrom: "2025-01-01",
  metricId: "excess_availability",
  title: "Negative availability",
  message: "Excess availability is below zero.",
  severity: "critical",
  threshold: { type: "decimal", operator: "lt", value: "0", unit: "currency" }
};

function evaluatedResult(
  asOfDate: string,
  snapshotId: string,
  observationId: string,
  value: string
): MonitoringResult {
  const gate: DataQualityGate = {
    status: "certified",
    gateId: `dq-${asOfDate}`,
    snapshotId,
    certifiedAt: `${nextDay(asOfDate)}T09:00:00.000Z`,
    blockingFindingCount: 0,
    evidence: [{ kind: "reconciliation", id: `recon-${asOfDate}` }]
  };
  return evaluateMonitoring({
    asOfDate,
    scope: { type: "facility", id: "facility-1" },
    dataQualityGate: gate,
    monitorDefinitions: [monitor],
    observations: [
      {
        type: "decimal",
        observationId,
        metricId: "excess_availability",
        snapshotId,
        asOfDate,
        value,
        unit: "currency",
        evidence: [{ kind: "borrowing_base_run", id: `bb-${asOfDate}` }]
      }
    ]
  });
}

function runInput(
  tenantId: string,
  runId: string,
  idempotencyKey: string,
  result: MonitoringResult
): RecordMonitoringRunInput {
  return { tenantId, runId, result, recordedBy: "monitoring-worker", idempotencyKey };
}

function createStore(clock: () => Date = fixedClock): {
  readonly databasePath: string;
  readonly store: MonitoringAlertStore;
} {
  const directory = temporaryDirectory();
  const databasePath = join(directory, "alerts.sqlite");
  return { databasePath, store: new MonitoringAlertStore(databasePath, { clock }) };
}

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "abl-alert-store-test-"));
  temporaryDirectories.push(directory);
  return directory;
}

function fixedClock(): Date {
  return new Date("2026-08-11T12:00:00.000Z");
}

function tickingClock(): () => Date {
  let ticks = 0;
  return () => {
    const value = new Date(Date.parse("2026-08-11T12:00:00.000Z") + ticks);
    ticks += 1;
    return value;
  };
}

function nextDay(value: string): string {
  const date = new Date(`${value}T00:00:00.000Z`);
  date.setUTCDate(date.getUTCDate() + 1);
  return date.toISOString().slice(0, 10);
}

function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function isAlertStoreError(
  error: unknown,
  code: MonitoringAlertStoreError["code"]
): boolean {
  return error instanceof MonitoringAlertStoreError && error.code === code;
}
