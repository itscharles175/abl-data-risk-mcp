import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import {
  evaluateMonitorV2,
  type CertifiedMetricPointV1,
  type MonitorDefinitionV2
} from "../src/domain/monitoring-v2.js";

const hash = (value: string) => createHash("sha256").update(value).digest("hex");

function point(date: string, value: string, id = date): CertifiedMetricPointV1 {
  return {
    pointId: `point-${id}`,
    metricId: "portfolio.delinquency_rate",
    snapshotId: `snapshot-${id}`,
    certificationManifestId: `cert-${id}`,
    populationHash: hash(`population-${id}`),
    asOfDate: date,
    value,
    unit: "percent",
    coverage: "1"
  };
}

function definition(condition: MonitorDefinitionV2["condition"]): MonitorDefinitionV2 {
  return {
    schemaVersion: 2,
    monitorId: "delinquency-rise",
    version: "2.0.0",
    effectiveFrom: "2026-01-01",
    metricId: "portfolio.delinquency_rate",
    scopeTypes: ["portfolio"],
    title: "Delinquency deterioration",
    message: "Certified portfolio delinquency breached the approved rule.",
    severity: "high",
    ownerId: "portfolio-risk",
    slaHours: 24,
    missingPolicy: "alert",
    staleAfterDays: 35,
    cooldownDays: 7,
    condition
  };
}

test("monitor v2 evaluates exact percentage change, cooldown, and evidence lineage", () => {
  const monitor = definition({
    type: "change",
    mode: "percent_change",
    lookbackPeriods: 1,
    operator: "gte",
    value: "20",
    unit: "percent",
    resetValue: "5"
  });
  const input = {
    asOfDate: "2026-03-31",
    scope: { type: "portfolio" as const, id: "portfolio-a" },
    definition: monitor,
    history: [point("2026-02-28", "5", "feb"), point("2026-03-31", "6.5", "mar")]
  };
  const triggered = evaluateMonitorV2(input);
  assert.equal(triggered.outcome, "triggered");
  assert.equal(triggered.observedValue, "30");
  assert.equal(triggered.comparisonValue, "20");
  assert.equal(triggered.observationIds.length, 2);
  assert.match(triggered.occurrenceKey!, /^occurrence-v2:[a-f0-9]{64}$/);
  assert.equal(triggered.dueAt, "2026-04-01T00:00:00.000Z");

  const cooldown = evaluateMonitorV2({
    ...input,
    state: { caseOpen: true, lastTriggeredOn: "2026-03-28", lastClearedOn: null }
  });
  assert.equal(cooldown.outcome, "cooldown");
  assert.equal(cooldown.occurrenceKey, null);
});

test("monitor v2 supports rolling, consecutive, compound, stale, and missing policies", () => {
  const history = [
    point("2026-01-31", "4", "jan"),
    point("2026-02-28", "6", "feb"),
    point("2026-03-31", "8", "mar")
  ];
  const rolling = evaluateMonitorV2({
    asOfDate: "2026-03-31",
    scope: { type: "portfolio", id: "portfolio-a" },
    definition: definition({
      type: "rolling",
      aggregation: "average",
      windowPeriods: 3,
      minimumObservations: 3,
      operator: "gt",
      value: "5",
      unit: "percent"
    }),
    history
  });
  assert.equal(rolling.outcome, "triggered");
  assert.equal(rolling.observedValue, "6");

  const consecutive = evaluateMonitorV2({
    asOfDate: "2026-03-31",
    scope: { type: "portfolio", id: "portfolio-a" },
    definition: definition({
      type: "consecutive",
      requiredPeriods: 2,
      condition: { type: "absolute", operator: "gte", value: "6", unit: "percent" }
    }),
    history
  });
  assert.equal(consecutive.outcome, "triggered");

  const compound = evaluateMonitorV2({
    asOfDate: "2026-03-31",
    scope: { type: "portfolio", id: "portfolio-a" },
    definition: definition({
      type: "compound",
      operator: "all",
      conditions: [
        { type: "absolute", operator: "gte", value: "8", unit: "percent" },
        { type: "change", mode: "delta", lookbackPeriods: 1, operator: "gte", value: "2", unit: "percent" }
      ]
    }),
    history
  });
  assert.equal(compound.outcome, "triggered");

  const stale = evaluateMonitorV2({
    asOfDate: "2026-06-30",
    scope: { type: "portfolio", id: "portfolio-a" },
    definition: definition({ type: "absolute", operator: "gt", value: "5", unit: "percent" }),
    history
  });
  assert.equal(stale.outcome, "missing");
  assert.equal(stale.reason, "stale_observation");
});

test("monitor v2 blocks insufficient certified history and applies hysteresis reset", () => {
  const monitor = { ...definition({
    type: "absolute" as const,
    operator: "gte" as const,
    value: "7",
    unit: "percent" as const,
    resetValue: "5"
  }), missingPolicy: "block" as const };
  const missing = evaluateMonitorV2({
    asOfDate: "2026-03-31",
    scope: { type: "portfolio", id: "portfolio-a" },
    definition: { ...monitor, condition: {
      type: "rolling",
      aggregation: "average",
      windowPeriods: 3,
      minimumObservations: 3,
      operator: "gt",
      value: "5",
      unit: "percent"
    } },
    history: [point("2026-03-31", "8", "mar")]
  });
  assert.equal(missing.outcome, "blocked");
  assert.equal(missing.reason, "insufficient_history");

  const heldOpen = evaluateMonitorV2({
    asOfDate: "2026-04-30",
    scope: { type: "portfolio", id: "portfolio-a" },
    definition: monitor,
    history: [point("2026-04-30", "6", "apr")],
    state: { caseOpen: true, lastTriggeredOn: "2026-03-31", lastClearedOn: null }
  });
  assert.equal(heldOpen.outcome, "clear");
  assert.equal(heldOpen.reason, "hysteresis_not_reset");

  const reset = evaluateMonitorV2({
    asOfDate: "2026-05-31",
    scope: { type: "portfolio", id: "portfolio-a" },
    definition: monitor,
    history: [point("2026-05-31", "4", "may")],
    state: { caseOpen: true, lastTriggeredOn: "2026-03-31", lastClearedOn: null }
  });
  assert.equal(reset.outcome, "reset");
});
