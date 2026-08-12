import assert from "node:assert/strict";
import { test } from "node:test";

import {
  evaluateMonitoring,
  type DataQualityGate,
  type MetricObservation,
  type MonitorDefinition
} from "../src/domain/monitoring.js";

const certifiedGate: DataQualityGate = {
  status: "certified",
  gateId: "dq-2025-06-30",
  snapshotId: "snapshot-2025-06-30",
  certifiedAt: "2025-07-01T09:00:00Z",
  blockingFindingCount: 0,
  evidence: [{ kind: "reconciliation", id: "recon-1" }]
};

const monitors: readonly MonitorDefinition[] = [
  {
    monitorId: "availability-negative",
    version: "1",
    effectiveFrom: "2025-01-01",
    metricId: "excess_availability",
    title: "Negative availability",
    message: "Excess availability is below zero.",
    severity: "critical",
    threshold: { type: "decimal", operator: "lt", value: "0", unit: "currency" }
  },
  {
    monitorId: "overadvance",
    version: "1",
    effectiveFrom: "2025-01-01",
    metricId: "overadvance_flag",
    title: "Overadvance",
    message: "The facility is overadvanced.",
    severity: "critical",
    threshold: { type: "boolean", operator: "eq", value: true, unit: "boolean" }
  },
  {
    monitorId: "utilization-high",
    version: "1",
    effectiveFrom: "2025-01-01",
    metricId: "utilization",
    title: "High utilization",
    message: "Utilization exceeds the approved threshold.",
    severity: "warning",
    threshold: { type: "decimal", operator: "gt", value: "0.90", unit: "ratio" }
  },
  {
    monitorId: "dso-high",
    version: "1",
    effectiveFrom: "2025-01-01",
    metricId: "days_sales_outstanding",
    title: "High DSO",
    message: "DSO exceeds the approved threshold.",
    severity: "high",
    threshold: { type: "decimal", operator: "gt", value: "75", unit: "days" }
  }
];

const observations: readonly MetricObservation[] = [
  {
    type: "decimal",
    observationId: "availability-obs",
    metricId: "excess_availability",
    snapshotId: "snapshot-2025-06-30",
    asOfDate: "2025-06-30",
    value: "-25.00",
    unit: "currency",
    evidence: [
      { kind: "borrowing_base_run", id: "bb-1" },
      { kind: "reconciliation", id: "recon-1" }
    ]
  },
  {
    type: "boolean",
    observationId: "overadvance-obs",
    metricId: "overadvance_flag",
    snapshotId: "snapshot-2025-06-30",
    asOfDate: "2025-06-30",
    value: true,
    unit: "boolean",
    evidence: [{ kind: "borrowing_base_run", id: "bb-1" }]
  },
  {
    type: "decimal",
    observationId: "utilization-obs",
    metricId: "utilization",
    snapshotId: "snapshot-2025-06-30",
    asOfDate: "2025-06-30",
    value: "0.85",
    unit: "ratio",
    evidence: [{ kind: "metric_run", id: "metrics-1" }]
  }
];

test("monitoring is blocked before parsing or evaluating thresholds when DQ is not certified", () => {
  const failedGate: DataQualityGate = {
    status: "failed",
    gateId: "dq-failed",
    snapshotId: "snapshot-bad",
    blockingFindingCount: 2,
    evidence: []
  };
  const invalidMonitor: MonitorDefinition = {
    monitorId: "invalid-unless-evaluated",
    version: "1",
    effectiveFrom: "2025-01-01",
    metricId: "bad",
    title: "Invalid",
    message: "This invalid decimal must not be evaluated after a failed gate.",
    severity: "warning",
    threshold: { type: "decimal", operator: "gt", value: "not-a-decimal", unit: "currency" }
  };

  const result = evaluateMonitoring({
    asOfDate: "2025-06-30",
    scope: { type: "facility", id: "facility-1" },
    dataQualityGate: failedGate,
    monitorDefinitions: [invalidMonitor],
    observations: []
  });

  assert.deepEqual(result, {
    status: "blocked",
    asOfDate: "2025-06-30",
    scope: { type: "facility", id: "facility-1" },
    gateId: "dq-failed",
    snapshotId: "snapshot-bad",
    reason: "data_quality_failed",
    evaluations: [],
    alerts: []
  });
});

test("certified monitoring evaluates typed thresholds and returns deduplicated evidence", () => {
  const result = evaluateMonitoring({
    asOfDate: "2025-06-30",
    scope: { type: "facility", id: "facility-1" },
    dataQualityGate: certifiedGate,
    monitorDefinitions: monitors,
    observations
  });

  assert.equal(result.status, "evaluated");
  if (result.status !== "evaluated") return;
  assert.deepEqual(
    result.evaluations.map((evaluation) => [evaluation.monitorId, evaluation.outcome]),
    [
      ["availability-negative", "triggered"],
      ["dso-high", "missing_observation"],
      ["overadvance", "triggered"],
      ["utilization-high", "clear"]
    ]
  );
  assert.equal(result.alerts.length, 2);
  const availability = result.alerts.find((alert) => alert.monitorId === "availability-negative");
  assert.equal(availability?.evidence.observedValue, "-25");
  assert.deepEqual(availability?.evidence.threshold, {
    type: "decimal",
    operator: "lt",
    value: "0",
    unit: "currency"
  });
  assert.deepEqual(availability?.evidence.references, [
    { kind: "borrowing_base_run", id: "bb-1" },
    { kind: "reconciliation", id: "recon-1" }
  ]);
  assert.match(availability?.dedupeKey ?? "", /^monitor:[a-f0-9]{64}$/);
  assert.match(availability?.occurrenceKey ?? "", /^occurrence:[a-f0-9]{64}$/);
});

test("dedupe keys persist across repeated breach dates while occurrence keys change", () => {
  const first = evaluateMonitoring({
    asOfDate: "2025-06-30",
    scope: { type: "facility", id: "facility-1" },
    dataQualityGate: certifiedGate,
    monitorDefinitions: [monitors[0]!],
    observations: [observations[0]!]
  });
  const second = evaluateMonitoring({
    asOfDate: "2025-07-01",
    scope: { type: "facility", id: "facility-1" },
    dataQualityGate: {
      status: "certified",
      gateId: "dq-2025-07-01",
      snapshotId: "snapshot-2025-07-01",
      certifiedAt: "2025-07-02T09:00:00Z",
      blockingFindingCount: 0,
      evidence: []
    },
    monitorDefinitions: [monitors[0]!],
    observations: [
      {
        type: "decimal",
        observationId: "availability-obs-next",
        metricId: "excess_availability",
        snapshotId: "snapshot-2025-07-01",
        asOfDate: "2025-07-01",
        value: "-20",
        unit: "currency",
        evidence: []
      }
    ]
  });

  assert.equal(first.status, "evaluated");
  assert.equal(second.status, "evaluated");
  if (first.status !== "evaluated" || second.status !== "evaluated") return;
  assert.equal(first.alerts[0]?.dedupeKey, second.alerts[0]?.dedupeKey);
  assert.notEqual(first.alerts[0]?.occurrenceKey, second.alerts[0]?.occurrenceKey);
});

test("monitor threshold versions switch on their exclusive effective boundary", () => {
  const versions: readonly MonitorDefinition[] = [
    {
      monitorId: "availability",
      version: "old",
      effectiveFrom: "2025-01-01",
      effectiveTo: "2025-07-01",
      metricId: "excess_availability",
      title: "Old availability limit",
      message: "Availability breached the old limit.",
      severity: "warning",
      threshold: { type: "decimal", operator: "lt", value: "-10", unit: "currency" }
    },
    {
      monitorId: "availability",
      version: "new",
      effectiveFrom: "2025-07-01",
      metricId: "excess_availability",
      title: "New availability limit",
      message: "Availability breached the new limit.",
      severity: "high",
      threshold: { type: "decimal", operator: "lt", value: "0", unit: "currency" }
    }
  ];
  const result = evaluateMonitoring({
    asOfDate: "2025-07-01",
    scope: { type: "facility", id: "facility-1" },
    dataQualityGate: {
      status: "certified",
      gateId: "dq-boundary",
      snapshotId: "snapshot-boundary",
      certifiedAt: "2025-07-02T00:00:00Z",
      blockingFindingCount: 0,
      evidence: []
    },
    monitorDefinitions: versions,
    observations: [
      {
        type: "decimal",
        observationId: "availability-boundary",
        metricId: "excess_availability",
        snapshotId: "snapshot-boundary",
        asOfDate: "2025-07-01",
        value: "-5",
        unit: "currency",
        evidence: []
      }
    ]
  });

  assert.equal(result.status, "evaluated");
  if (result.status !== "evaluated") return;
  assert.equal(result.evaluations[0]?.monitorVersion, "new");
  assert.equal(result.evaluations[0]?.outcome, "triggered");
});

test("a certified evaluation rejects metric type or unit mismatches", () => {
  assert.throws(
    () =>
      evaluateMonitoring({
        asOfDate: "2025-06-30",
        scope: { type: "facility", id: "facility-1" },
        dataQualityGate: certifiedGate,
        monitorDefinitions: [monitors[0]!],
        observations: [
          {
            type: "decimal",
            observationId: "wrong-unit",
            metricId: "excess_availability",
            snapshotId: "snapshot-2025-06-30",
            asOfDate: "2025-06-30",
            value: "-25",
            unit: "ratio",
            evidence: []
          }
        ]
      }),
    /expects unit currency/
  );
});
