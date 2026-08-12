import { createHash } from "node:crypto";

import { PipelineStore, type PipelineDeliveryMode, type PipelineRunV1 } from "../control/pipelines.js";

export type PipelineCadenceV1 =
  | { readonly type: "interval"; readonly minutes: number }
  | { readonly type: "daily"; readonly hourUtc: number; readonly minuteUtc: number }
  | { readonly type: "monthly"; readonly day: number; readonly hourUtc: number; readonly minuteUtc: number };

export interface PipelineScheduleV1 {
  readonly schemaVersion: 1;
  readonly tenantId: string;
  readonly scheduleId: string;
  readonly pipelineDefinitionId: string;
  readonly pipelineDefinitionVersion: string;
  readonly sourceContractId: string;
  readonly cadence: PipelineCadenceV1;
  readonly deliverySlaMinutes: number;
  readonly enabled: boolean;
  readonly servicePrincipalId: string;
  readonly approvedBy: string;
  readonly approvedAt: string;
}

export interface DetectedDeliveryV1 {
  readonly deliveryId: string;
  readonly immutableVersion: string;
  readonly contentHash: string;
  readonly observedAt: string;
  readonly asOfDate: string;
  readonly mode: PipelineDeliveryMode;
  readonly watermarkStart?: string;
  readonly watermarkEnd?: string;
  readonly supersedesRunId?: string;
}

export interface PipelineDeliveryDetector {
  detect(schedule: PipelineScheduleV1, signal?: AbortSignal): Promise<readonly DetectedDeliveryV1[]>;
}

export interface PipelineDetectionResultV1 {
  readonly scheduleId: string;
  readonly detected: number;
  readonly enqueued: readonly PipelineRunV1[];
  readonly lateDeliveryIds: readonly string[];
  readonly watermarkHigh: string | null;
}

export class PipelineCoordinatorError extends Error {
  constructor(readonly code: "INVALID_SCHEDULE" | "INVALID_DELIVERY" | "DETECTOR_FAILED", message: string) {
    super(message);
    this.name = "PipelineCoordinatorError";
  }
}

/** Converts trusted immutable delivery detections into exactly-idempotent pipeline runs. */
export class PipelineCoordinator {
  readonly #pipelines: PipelineStore;
  readonly #clock: () => Date;

  constructor(pipelines: PipelineStore, options: { readonly clock?: () => Date } = {}) {
    this.#pipelines = pipelines;
    this.#clock = options.clock ?? (() => new Date());
  }

  async detectAndEnqueue(
    schedule: PipelineScheduleV1,
    detector: PipelineDeliveryDetector,
    signal?: AbortSignal
  ): Promise<PipelineDetectionResultV1> {
    validateSchedule(schedule);
    if (!schedule.enabled) return Object.freeze({ scheduleId: schedule.scheduleId, detected: 0, enqueued: [], lateDeliveryIds: [], watermarkHigh: null });
    signal?.throwIfAborted();
    let deliveries: readonly DetectedDeliveryV1[];
    try {
      deliveries = await detector.detect(schedule, signal);
    } catch (error) {
      if (signal?.aborted) throw error;
      throw new PipelineCoordinatorError("DETECTOR_FAILED", "Delivery detector failed");
    }
    if (!Array.isArray(deliveries) || deliveries.length > 10_000) invalidDelivery("Delivery batch exceeds the bound");
    const unique = new Set<string>();
    const sorted = [...deliveries].sort((left, right) => left.observedAt.localeCompare(right.observedAt) || left.deliveryId.localeCompare(right.deliveryId));
    const enqueued: PipelineRunV1[] = [];
    const late: string[] = [];
    let watermarkHigh: string | null = null;
    const now = this.#clock();
    if (Number.isNaN(now.getTime())) invalidSchedule("Clock is invalid");
    for (const delivery of sorted) {
      validateDelivery(delivery);
      if (unique.has(delivery.deliveryId)) invalidDelivery("Detector returned a duplicate delivery id");
      unique.add(delivery.deliveryId);
      signal?.throwIfAborted();
      const ageMinutes = Math.floor((now.getTime() - Date.parse(delivery.observedAt)) / 60_000);
      if (ageMinutes > schedule.deliverySlaMinutes) late.push(delivery.deliveryId);
      const deliveryFingerprint = sha256(JSON.stringify({
        contentHash: delivery.contentHash,
        deliveryId: delivery.deliveryId,
        immutableVersion: delivery.immutableVersion,
        mode: delivery.mode,
        sourceContractId: schedule.sourceContractId
      }));
      enqueued.push(this.#pipelines.createRun({
        tenantId: schedule.tenantId,
        pipelineDefinitionId: schedule.pipelineDefinitionId,
        pipelineDefinitionVersion: schedule.pipelineDefinitionVersion,
        sourceContractId: schedule.sourceContractId,
        requestedBy: schedule.servicePrincipalId,
        idempotencyKey: `delivery-${deliveryFingerprint}`,
        deliveryMode: delivery.mode,
        deliveryReference: delivery.immutableVersion,
        ...(delivery.watermarkStart === undefined ? {} : { watermarkStart: delivery.watermarkStart }),
        ...(delivery.watermarkEnd === undefined ? {} : { watermarkEnd: delivery.watermarkEnd }),
        ...(delivery.supersedesRunId === undefined ? {} : { supersedesRunId: delivery.supersedesRunId })
      }));
      if (delivery.watermarkEnd !== undefined && (watermarkHigh === null || delivery.watermarkEnd > watermarkHigh)) watermarkHigh = delivery.watermarkEnd;
    }
    return Object.freeze({
      scheduleId: schedule.scheduleId,
      detected: sorted.length,
      enqueued: Object.freeze(enqueued),
      lateDeliveryIds: Object.freeze(late),
      watermarkHigh
    });
  }
}

function validateSchedule(schedule: PipelineScheduleV1): void {
  if (schedule.schemaVersion !== 1) invalidSchedule("Schedule version is invalid");
  for (const value of [schedule.tenantId, schedule.scheduleId, schedule.pipelineDefinitionId, schedule.pipelineDefinitionVersion, schedule.sourceContractId, schedule.servicePrincipalId, schedule.approvedBy]) identifier(value, "schedule identifier");
  if (schedule.servicePrincipalId === schedule.approvedBy) invalidSchedule("Schedule approver must differ from its service principal");
  iso(schedule.approvedAt, "approvedAt");
  integer(schedule.deliverySlaMinutes, 1, 43_200, "deliverySlaMinutes");
  if (schedule.cadence.type === "interval") integer(schedule.cadence.minutes, 1, 43_200, "cadence minutes");
  else {
    integer(schedule.cadence.hourUtc, 0, 23, "cadence hour");
    integer(schedule.cadence.minuteUtc, 0, 59, "cadence minute");
    if (schedule.cadence.type === "monthly") integer(schedule.cadence.day, 1, 28, "cadence day");
  }
}

function validateDelivery(delivery: DetectedDeliveryV1): void {
  identifier(delivery.deliveryId, "delivery id");
  if (!delivery.immutableVersion || delivery.immutableVersion.length > 1_024 || /[\u0000-\u001f\u007f]/u.test(delivery.immutableVersion)) invalidDelivery("Immutable version is invalid");
  hash(delivery.contentHash);
  iso(delivery.observedAt, "observedAt");
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(delivery.asOfDate)) invalidDelivery("asOfDate is invalid");
  if (!(["full", "delta", "correction", "backfill"] as const).includes(delivery.mode)) invalidDelivery("Delivery mode is invalid");
  const replacement = delivery.mode === "correction" || delivery.mode === "backfill";
  if (replacement !== Boolean(delivery.supersedesRunId)) invalidDelivery("Correction/backfill lineage is invalid");
  if ((delivery.watermarkStart === undefined) !== (delivery.watermarkEnd === undefined)) invalidDelivery("Watermarks must be paired");
  if (delivery.watermarkStart !== undefined && delivery.watermarkEnd !== undefined && delivery.watermarkStart > delivery.watermarkEnd) invalidDelivery("Watermark range is inverted");
}

function identifier(value: string, label: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/u.test(value)) invalidSchedule(`${label} is invalid`);
}

function hash(value: string): void {
  const normalized = value.startsWith("sha256:") ? value.slice(7) : value;
  if (!/^[0-9a-f]{64}$/u.test(normalized)) invalidDelivery("Content hash is invalid");
}

function iso(value: string, label: string): void {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value) || Number.isNaN(Date.parse(value))) invalidSchedule(`${label} is invalid`);
}

function integer(value: number, minimum: number, maximum: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalidSchedule(`${label} is outside its bound`);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function invalidSchedule(message: string): never {
  throw new PipelineCoordinatorError("INVALID_SCHEDULE", message);
}

function invalidDelivery(message: string): never {
  throw new PipelineCoordinatorError("INVALID_DELIVERY", message);
}
