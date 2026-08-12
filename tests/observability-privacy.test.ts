import assert from "node:assert/strict";
import { test } from "node:test";

import {
  BoundedTelemetryCollector,
  PrivacySafeTelemetry
} from "../src/observability/privacy.js";

test("privacy boundary hashes identities and drops raw SQL, secrets, payloads and free text", () => {
  const collector = new BoundedTelemetryCollector({ maximumRecords: 20 });
  const telemetry = new PrivacySafeTelemetry(collector, {
    identityHashKey: Buffer.alloc(32, 7),
    clock: () => new Date("2026-08-12T12:00:00.000Z")
  });
  telemetry.event("abl.policy.decision", "warn", {
    tenantId: "customer-bank-a",
    principalId: "alice@example.test",
    operation: "https://attacker.test/?secret=raw",
    outcome: "denied",
    "error.code": "DETAIL_SCOPE_REQUIRED",
    password: "correct-horse-battery-staple",
    authorization: "Bearer highly-sensitive",
    sql: "select * from borrowers",
    payload: { ssn: "123-45-6789" },
    "tenant.hash": "not-actually-a-hash",
    "row.count": 12
  });
  const [record] = collector.snapshot();
  assert.ok(record && record.kind === "event");
  assert.equal(record.attributes.operation, "redacted");
  assert.equal(record.attributes.outcome, "denied");
  assert.equal(record.attributes["row.count"], 12);
  assert.match(String(record.attributes["tenant.hash"]), /^[a-f0-9]{64}$/);
  assert.match(String(record.attributes["principal.hash"]), /^[a-f0-9]{64}$/);
  const serialized = JSON.stringify(record);
  for (const forbidden of [
    "customer-bank-a",
    "alice@example.test",
    "correct-horse-battery-staple",
    "highly-sensitive",
    "select * from borrowers",
    "123-45-6789",
    "attacker.test"
  ]) assert.equal(serialized.includes(forbidden), false);
});

test("metric-series and record bounds prevent unbounded telemetry cardinality", () => {
  const collector = new BoundedTelemetryCollector({ maximumRecords: 2, maximumMetricSeries: 2 });
  const telemetry = new PrivacySafeTelemetry(collector, { identityHashKey: Buffer.alloc(32, 3) });
  telemetry.metric("abl.queue.age", "gauge", 1, "ms", { "queue.name": "analytics-a" });
  telemetry.metric("abl.queue.age", "gauge", 2, "ms", { "queue.name": "analytics-b" });
  telemetry.metric("abl.queue.age", "gauge", 3, "ms", { "queue.name": "analytics-c" });
  assert.equal(collector.snapshot().length, 2);
  assert.equal(collector.droppedMetricSeries, 1);
  telemetry.metric("abl.queue.age", "gauge", 4, "ms", { "queue.name": "analytics-a" });
  assert.equal(collector.snapshot().length, 2);
  assert.equal(collector.droppedRecords, 1);
  const values = collector.snapshot().map((record) => record.kind === "metric" ? record.value : null);
  assert.deepEqual(values, [2, 4]);
});

test("spans are OpenTelemetry-neutral, idempotently ended and event bounded", () => {
  const collector = new BoundedTelemetryCollector({ maximumRecords: 10, maximumSpanEvents: 4 });
  let now = new Date("2026-08-12T12:00:00.000Z");
  const telemetry = new PrivacySafeTelemetry(collector, {
    identityHashKey: Buffer.alloc(32, 9),
    maximumSpanEvents: 2,
    clock: () => now
  });
  const span = telemetry.startSpan("abl.connector.extract", {
    tenantId: "tenant-a",
    component: "connector"
  });
  span.addEvent("abl.connector.stage", { operation: "open" });
  span.addEvent("abl.connector.stage", { operation: "stream" });
  span.addEvent("abl.connector.stage", { operation: "ignored" });
  span.setAttributes({ token: "never-export", outcome: "success" });
  span.setStatus("ok");
  now = new Date(now.getTime() + 125);
  span.end();
  span.end();

  const [record] = collector.snapshot();
  assert.ok(record && record.kind === "span");
  assert.equal(record.durationMilliseconds, 125);
  assert.equal(record.events.length, 2);
  assert.equal(record.attributes.outcome, "success");
  assert.equal(JSON.stringify(record).includes("never-export"), false);
});

test("invalid telemetry names, units and non-finite values fail closed", () => {
  const telemetry = new PrivacySafeTelemetry(new BoundedTelemetryCollector(), {
    identityHashKey: Buffer.alloc(32, 1)
  });
  assert.throws(() => telemetry.event("tenant-controlled-name", "info"));
  assert.throws(() => telemetry.metric("abl.latency", "histogram", Number.NaN, "ms"));
  assert.throws(() => telemetry.metric("abl.latency", "histogram", 1, "customer-id"));
});
