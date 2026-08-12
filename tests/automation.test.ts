import assert from "node:assert/strict";
import { test } from "node:test";

import { PipelineCoordinator } from "../src/automation/pipeline-coordinator.js";
import { InMemoryNotificationDirectory, NotificationDispatchError, dispatchGovernedNotification } from "../src/automation/notifications.js";
import { PipelineStore } from "../src/control/pipelines.js";

const HASH = "a".repeat(64);

test("approved schedules detect immutable deliveries and enqueue exactly-idempotent late pipeline runs", async () => {
  const store = new PipelineStore(":memory:");
  try {
    const coordinator = new PipelineCoordinator(store, { clock: () => new Date("2026-03-02T12:00:00.000Z") });
    const schedule = {
      schemaVersion: 1 as const, tenantId: "tenant-a", scheduleId: "daily-loans", pipelineDefinitionId: "surveillance", pipelineDefinitionVersion: "1.0.0", sourceContractId: "loan-tape", cadence: { type: "daily" as const, hourUtc: 8, minuteUtc: 0 }, deliverySlaMinutes: 60, enabled: true, servicePrincipalId: "pipeline-service", approvedBy: "risk-reviewer", approvedAt: "2026-01-01T00:00:00.000Z"
    };
    const detector = { async detect() { return [{ deliveryId: "delivery-1", immutableVersion: "bucket/key#version-1", contentHash: HASH, observedAt: "2026-03-02T08:00:00.000Z", asOfDate: "2026-02-28", mode: "full" as const, watermarkStart: "2026-01-31", watermarkEnd: "2026-02-28" }]; } };
    const first = await coordinator.detectAndEnqueue(schedule, detector);
    const replay = await coordinator.detectAndEnqueue(schedule, detector);
    assert.equal(first.enqueued[0]?.runId, replay.enqueued[0]?.runId);
    assert.deepEqual(first.lateDeliveryIds, ["delivery-1"]);
    assert.equal(first.watermarkHigh, "2026-02-28");
  } finally { store.close(); }
});

test("notification dispatcher uses only approved opaque destinations/templates and minimized variables", async () => {
  const directory = new InMemoryNotificationDirectory([
    { destinationId: "risk-team", channel: "email", targetRef: "secretref://notifications/risk-team#v3", status: "active", createdBy: "maker", approvedBy: "checker" }
  ], [
    { templateId: "monitor-alert", channel: "email", subject: "{{severity}} portfolio alert", body: "Monitor {{monitor_id}} requires review.", allowedVariables: ["severity", "monitor_id"], status: "active", createdBy: "maker", approvedBy: "checker" }
  ]);
  const sent: string[] = [];
  const receipt = await dispatchGovernedNotification({ destinationId: "risk-team", templateId: "monitor-alert", variables: { severity: "High", monitor_id: "dpd-spike" }, idempotencyKey: "delivery-1" }, {
    directory,
    resolver: { async resolve(_ref, destinationId) { return { destinationId, channel: "email", address: "resolved-only-inside-dispatcher" }; } },
    sender: { async send(input) { sent.push(`${input.subject}|${input.body}`); return { providerReceipt: "provider-123" }; } }
  });
  assert.deepEqual(sent, ["High portfolio alert|Monitor dpd-spike requires review."]);
  assert.match(receipt.providerReceiptHash, /^[0-9a-f]{64}$/u);
  await assert.rejects(
    dispatchGovernedNotification({ destinationId: "risk-team", templateId: "monitor-alert", variables: { severity: "High", monitor_id: "x", callbackUrl: "https://evil.invalid" }, idempotencyKey: "delivery-2" }, {
      directory,
      resolver: { async resolve() { throw new Error("must not resolve"); } },
      sender: { async send() { throw new Error("must not send"); } }
    }),
    (error: unknown) => error instanceof NotificationDispatchError && error.code === "INVALID_INPUT"
  );
});
