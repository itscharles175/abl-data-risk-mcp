import { createHmac, randomUUID } from "node:crypto";

export type TelemetryAttributeValue = string | number | boolean;
export type TelemetryAttributes = Readonly<Record<string, TelemetryAttributeValue>>;

export interface TelemetryEventRecordV1 {
  readonly recordVersion: 1;
  readonly kind: "event";
  readonly name: string;
  readonly severity: "debug" | "info" | "warn" | "error";
  readonly timestamp: string;
  readonly attributes: TelemetryAttributes;
}

export interface TelemetryMetricRecordV1 {
  readonly recordVersion: 1;
  readonly kind: "metric";
  readonly name: string;
  readonly metricKind: "counter" | "gauge" | "histogram";
  readonly value: number;
  readonly unit: string;
  readonly timestamp: string;
  readonly attributes: TelemetryAttributes;
}

export interface TelemetrySpanRecordV1 {
  readonly recordVersion: 1;
  readonly kind: "span";
  readonly name: string;
  readonly spanId: string;
  readonly startedAt: string;
  readonly endedAt: string;
  readonly durationMilliseconds: number;
  readonly status: "ok" | "error" | "unset";
  readonly attributes: TelemetryAttributes;
  readonly events: readonly {
    readonly name: string;
    readonly timestamp: string;
    readonly attributes: TelemetryAttributes;
  }[];
}

export type PrivacySafeTelemetryRecordV1 =
  | TelemetryEventRecordV1
  | TelemetryMetricRecordV1
  | TelemetrySpanRecordV1;

export interface TelemetryRecordSinkPort {
  accept(record: PrivacySafeTelemetryRecordV1): void;
}

export interface TelemetryBatchExporterPort {
  export(records: readonly PrivacySafeTelemetryRecordV1[]): Promise<void>;
}

export interface PrivacySafeSpanPort {
  setAttributes(attributes: Readonly<Record<string, unknown>>): void;
  addEvent(name: string, attributes?: Readonly<Record<string, unknown>>): void;
  setStatus(status: "ok" | "error", errorCode?: string): void;
  end(): void;
}

export interface PrivacySafeTelemetryPort {
  event(
    name: string,
    severity: TelemetryEventRecordV1["severity"],
    attributes?: Readonly<Record<string, unknown>>
  ): void;
  metric(
    name: string,
    metricKind: TelemetryMetricRecordV1["metricKind"],
    value: number,
    unit: string,
    attributes?: Readonly<Record<string, unknown>>
  ): void;
  startSpan(name: string, attributes?: Readonly<Record<string, unknown>>): PrivacySafeSpanPort;
}

export interface BoundedTelemetryCollectorOptions {
  readonly maximumRecords?: number;
  readonly maximumMetricSeries?: number;
  readonly maximumSpanEvents?: number;
}

/**
 * In-process bounded collector for tests, local operation, and exporter
 * adapters. It intentionally drops oldest records and excess metric series
 * instead of allowing telemetry to become an unbounded memory sink.
 */
export class BoundedTelemetryCollector implements TelemetryRecordSinkPort {
  readonly #maximumRecords: number;
  readonly #maximumMetricSeries: number;
  readonly #maximumSpanEvents: number;
  readonly #records: PrivacySafeTelemetryRecordV1[] = [];
  readonly #metricSeries = new Set<string>();
  #droppedRecords = 0;
  #droppedMetricSeries = 0;

  constructor(options: BoundedTelemetryCollectorOptions = {}) {
    this.#maximumRecords = bounded(options.maximumRecords ?? 10_000, 1, 100_000, "maximumRecords");
    this.#maximumMetricSeries = bounded(
      options.maximumMetricSeries ?? 2_000,
      1,
      20_000,
      "maximumMetricSeries"
    );
    this.#maximumSpanEvents = bounded(options.maximumSpanEvents ?? 32, 0, 256, "maximumSpanEvents");
  }

  accept(record: PrivacySafeTelemetryRecordV1): void {
    let boundedRecord = record;
    if (record.kind === "metric") {
      const series = `${record.name}\u0000${canonicalAttributes(record.attributes)}`;
      if (!this.#metricSeries.has(series) && this.#metricSeries.size >= this.#maximumMetricSeries) {
        this.#droppedMetricSeries += 1;
        return;
      }
      this.#metricSeries.add(series);
    } else if (record.kind === "span" && record.events.length > this.#maximumSpanEvents) {
      boundedRecord = Object.freeze({
        ...record,
        events: Object.freeze(record.events.slice(0, this.#maximumSpanEvents))
      });
      this.#droppedRecords += record.events.length - this.#maximumSpanEvents;
    }
    if (this.#records.length === this.#maximumRecords) {
      this.#records.shift();
      this.#droppedRecords += 1;
    }
    this.#records.push(boundedRecord);
  }

  snapshot(): readonly PrivacySafeTelemetryRecordV1[] {
    return Object.freeze([...this.#records]);
  }

  drain(): readonly PrivacySafeTelemetryRecordV1[] {
    const records = this.snapshot();
    this.#records.length = 0;
    this.#metricSeries.clear();
    return records;
  }

  get droppedRecords(): number {
    return this.#droppedRecords;
  }

  get droppedMetricSeries(): number {
    return this.#droppedMetricSeries;
  }
}

export interface PrivacySafeTelemetryOptions {
  /** Deployment-specific HMAC key; use a secret-manager reference at runtime. */
  readonly identityHashKey: Uint8Array;
  readonly clock?: () => Date;
  readonly maximumAttributes?: number;
  readonly maximumSpanEvents?: number;
}

const SAFE_ATTRIBUTE_NAMES = new Set([
  "artifact.kind",
  "cache.outcome",
  "component",
  "connector.hash",
  "error.code",
  "http.method",
  "http.status_code",
  "job.kind",
  "lease.state",
  "operation",
  "outcome",
  "policy.decision",
  "principal.hash",
  "protocol",
  "queue.name",
  "retry.count",
  "row.count",
  "tenant.hash",
  "worker.pool"
]);

const IDENTITY_INPUTS: Readonly<Record<string, "tenant.hash" | "principal.hash" | "connector.hash">> =
  Object.freeze({
    tenantId: "tenant.hash",
    principalId: "principal.hash",
    requestedBy: "principal.hash",
    subject: "principal.hash",
    connectorId: "connector.hash"
  });

const SAFE_SYMBOLIC_VALUE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const TELEMETRY_NAME = /^abl\.[a-z][a-z0-9_.-]{1,126}$/;
const UNIT = /^(?:1|ms|s|By|{request}|{job}|{event}|{row}|%)$/;

export class PrivacySafeTelemetry implements PrivacySafeTelemetryPort {
  readonly #sink: TelemetryRecordSinkPort;
  readonly #hashKey: Buffer;
  readonly #clock: () => Date;
  readonly #maximumAttributes: number;
  readonly #maximumSpanEvents: number;

  constructor(sink: TelemetryRecordSinkPort, options: PrivacySafeTelemetryOptions) {
    if (!(options.identityHashKey instanceof Uint8Array) || options.identityHashKey.byteLength < 32) {
      throw new Error("identityHashKey must contain at least 32 bytes");
    }
    this.#sink = sink;
    this.#hashKey = Buffer.from(options.identityHashKey);
    this.#clock = options.clock ?? (() => new Date());
    this.#maximumAttributes = bounded(options.maximumAttributes ?? 16, 1, 32, "maximumAttributes");
    this.#maximumSpanEvents = bounded(options.maximumSpanEvents ?? 16, 0, 64, "maximumSpanEvents");
  }

  event(
    name: string,
    severity: TelemetryEventRecordV1["severity"],
    attributes: Readonly<Record<string, unknown>> = {}
  ): void {
    validateTelemetryName(name);
    this.#sink.accept(Object.freeze({
      recordVersion: 1,
      kind: "event",
      name,
      severity,
      timestamp: this.#clock().toISOString(),
      attributes: this.#sanitize(attributes)
    }));
  }

  metric(
    name: string,
    metricKind: TelemetryMetricRecordV1["metricKind"],
    value: number,
    unit: string,
    attributes: Readonly<Record<string, unknown>> = {}
  ): void {
    validateTelemetryName(name);
    if (!Number.isFinite(value)) throw new Error("Telemetry metric value must be finite");
    if (!UNIT.test(unit)) throw new Error("Telemetry metric unit is not allowlisted");
    this.#sink.accept(Object.freeze({
      recordVersion: 1,
      kind: "metric",
      name,
      metricKind,
      value,
      unit,
      timestamp: this.#clock().toISOString(),
      attributes: this.#sanitize(attributes)
    }));
  }

  startSpan(
    name: string,
    attributes: Readonly<Record<string, unknown>> = {}
  ): PrivacySafeSpanPort {
    validateTelemetryName(name);
    return new PrivacySafeSpan(
      name,
      this.#sink,
      this.#clock,
      (values) => this.#sanitize(values),
      this.#maximumSpanEvents,
      attributes
    );
  }

  #sanitize(input: Readonly<Record<string, unknown>>): TelemetryAttributes {
    const output: Record<string, TelemetryAttributeValue> = {};
    for (const key of Object.keys(input).sort()) {
      if (Object.keys(output).length >= this.#maximumAttributes) break;
      const identityTarget = IDENTITY_INPUTS[key];
      const value = input[key];
      if (identityTarget) {
        if (typeof value === "string" && value.length > 0) output[identityTarget] = this.#hashIdentity(value);
        continue;
      }
      if (!SAFE_ATTRIBUTE_NAMES.has(key)) continue;
      if (key.endsWith(".hash") && (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value))) continue;
      const sanitized = sanitizeValue(value);
      if (sanitized !== undefined) output[key] = sanitized;
    }
    return Object.freeze(output);
  }

  #hashIdentity(value: string): string {
    return createHmac("sha256", this.#hashKey).update(value).digest("hex");
  }
}

class PrivacySafeSpan implements PrivacySafeSpanPort {
  readonly #name: string;
  readonly #spanId = randomUUID();
  readonly #sink: TelemetryRecordSinkPort;
  readonly #clock: () => Date;
  readonly #sanitize: (attributes: Readonly<Record<string, unknown>>) => TelemetryAttributes;
  readonly #maximumEvents: number;
  readonly #started: Date;
  readonly #attributes: Record<string, unknown>;
  readonly #events: {
    readonly name: string;
    readonly timestamp: string;
    readonly attributes: TelemetryAttributes;
  }[] = [];
  #status: "ok" | "error" | "unset" = "unset";
  #ended = false;

  constructor(
    name: string,
    sink: TelemetryRecordSinkPort,
    clock: () => Date,
    sanitize: (attributes: Readonly<Record<string, unknown>>) => TelemetryAttributes,
    maximumEvents: number,
    attributes: Readonly<Record<string, unknown>>
  ) {
    this.#name = name;
    this.#sink = sink;
    this.#clock = clock;
    this.#sanitize = sanitize;
    this.#maximumEvents = maximumEvents;
    this.#started = clock();
    this.#attributes = { ...attributes };
  }

  setAttributes(attributes: Readonly<Record<string, unknown>>): void {
    if (this.#ended) return;
    Object.assign(this.#attributes, attributes);
  }

  addEvent(name: string, attributes: Readonly<Record<string, unknown>> = {}): void {
    if (this.#ended || this.#events.length >= this.#maximumEvents) return;
    validateTelemetryName(name);
    this.#events.push(Object.freeze({
      name,
      timestamp: this.#clock().toISOString(),
      attributes: this.#sanitize(attributes)
    }));
  }

  setStatus(status: "ok" | "error", errorCode?: string): void {
    if (this.#ended) return;
    this.#status = status;
    if (errorCode !== undefined) this.#attributes["error.code"] = errorCode;
  }

  end(): void {
    if (this.#ended) return;
    this.#ended = true;
    const ended = this.#clock();
    this.#sink.accept(Object.freeze({
      recordVersion: 1,
      kind: "span",
      name: this.#name,
      spanId: this.#spanId,
      startedAt: this.#started.toISOString(),
      endedAt: ended.toISOString(),
      durationMilliseconds: Math.max(0, ended.getTime() - this.#started.getTime()),
      status: this.#status,
      attributes: this.#sanitize(this.#attributes),
      events: Object.freeze([...this.#events])
    }));
  }
}

function sanitizeValue(value: unknown): TelemetryAttributeValue | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  if (typeof value !== "string") return undefined;
  return SAFE_SYMBOLIC_VALUE.test(value) ? value : "redacted";
}

function validateTelemetryName(name: string): void {
  if (!TELEMETRY_NAME.test(name)) {
    throw new Error("Telemetry names must use the bounded abl.* namespace");
  }
}

function canonicalAttributes(attributes: TelemetryAttributes): string {
  return JSON.stringify(
    Object.fromEntries(Object.entries(attributes).sort(([left], [right]) => left.localeCompare(right)))
  );
}

function bounded(value: number, minimum: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}
