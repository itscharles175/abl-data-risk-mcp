import { createHash } from "node:crypto";

import { Decimal } from "decimal.js";

const ExactDecimal = Decimal.clone({ precision: 50, rounding: Decimal.ROUND_HALF_EVEN });

export type MonitorSeverity = "info" | "warning" | "high" | "critical";

export type DecimalMetricUnit =
  | "basis_points"
  | "count"
  | "currency"
  | "days"
  | "percent"
  | "ratio";

export type DecimalThresholdOperator = "eq" | "gte" | "gt" | "lte" | "lt" | "neq";
export type BooleanThresholdOperator = "eq" | "neq";

export interface MonitoringEvidenceReference {
  readonly kind:
    | "borrowing_base_run"
    | "mapping"
    | "metric_run"
    | "policy"
    | "reconciliation"
    | "source_artifact";
  readonly id: string;
}

export type DataQualityGate =
  | {
      readonly status: "certified";
      readonly gateId: string;
      readonly snapshotId: string;
      readonly certifiedAt: string;
      readonly blockingFindingCount: number;
      readonly evidence: readonly MonitoringEvidenceReference[];
    }
  | {
      readonly status: "failed" | "pending";
      readonly gateId: string;
      readonly snapshotId: string;
      readonly blockingFindingCount: number;
      readonly evidence: readonly MonitoringEvidenceReference[];
    };

interface MonitorDefinitionBase {
  readonly monitorId: string;
  readonly version: string;
  readonly effectiveFrom: string;
  /** Exclusive end date. */
  readonly effectiveTo?: string;
  readonly metricId: string;
  readonly title: string;
  readonly message: string;
  readonly severity: MonitorSeverity;
}

export interface DecimalMonitorDefinition extends MonitorDefinitionBase {
  readonly threshold: {
    readonly type: "decimal";
    readonly operator: DecimalThresholdOperator;
    readonly value: string;
    readonly unit: DecimalMetricUnit;
  };
}

export interface BooleanMonitorDefinition extends MonitorDefinitionBase {
  readonly threshold: {
    readonly type: "boolean";
    readonly operator: BooleanThresholdOperator;
    readonly value: boolean;
    readonly unit: "boolean";
  };
}

export type MonitorDefinition = DecimalMonitorDefinition | BooleanMonitorDefinition;

interface MetricObservationBase {
  readonly observationId: string;
  readonly metricId: string;
  readonly snapshotId: string;
  readonly asOfDate: string;
  readonly evidence: readonly MonitoringEvidenceReference[];
}

export interface DecimalMetricObservation extends MetricObservationBase {
  readonly type: "decimal";
  readonly value: string;
  readonly unit: DecimalMetricUnit;
}

export interface BooleanMetricObservation extends MetricObservationBase {
  readonly type: "boolean";
  readonly value: boolean;
  readonly unit: "boolean";
}

export type MetricObservation = DecimalMetricObservation | BooleanMetricObservation;

export interface MonitoringScope {
  readonly type: "facility" | "portfolio" | "source";
  readonly id: string;
}

export interface EvaluateMonitoringInput {
  readonly asOfDate: string;
  readonly scope: MonitoringScope;
  readonly dataQualityGate: DataQualityGate;
  readonly monitorDefinitions: readonly MonitorDefinition[];
  readonly observations: readonly MetricObservation[];
}

export interface EvaluatedThreshold {
  readonly type: "boolean" | "decimal";
  readonly operator: BooleanThresholdOperator | DecimalThresholdOperator;
  readonly value: string;
  readonly unit: "boolean" | DecimalMetricUnit;
}

export interface MonitorEvaluation {
  readonly monitorId: string;
  readonly monitorVersion: string;
  readonly metricId: string;
  readonly outcome: "clear" | "missing_observation" | "triggered";
  readonly severity: MonitorSeverity;
  readonly dedupeKey: string;
  readonly observedValue: string | null;
  readonly observationId: string | null;
  readonly observationAsOfDate: string | null;
  readonly threshold: EvaluatedThreshold;
}

export interface MonitoringAlertEvidence {
  readonly gateId: string;
  readonly snapshotId: string;
  readonly certifiedAt: string;
  readonly observationId: string;
  readonly observationAsOfDate: string;
  readonly metricId: string;
  readonly observedValue: string;
  readonly threshold: EvaluatedThreshold;
  readonly references: readonly MonitoringEvidenceReference[];
}

export interface MonitoringAlert {
  readonly occurrenceKey: string;
  /** Stable across repeated evaluations of the same monitor version and scope. */
  readonly dedupeKey: string;
  readonly monitorId: string;
  readonly monitorVersion: string;
  readonly scope: MonitoringScope;
  readonly asOfDate: string;
  readonly title: string;
  readonly message: string;
  readonly severity: MonitorSeverity;
  readonly evidence: MonitoringAlertEvidence;
}

export interface MonitoringBlockedResult {
  readonly status: "blocked";
  readonly asOfDate: string;
  readonly scope: MonitoringScope;
  readonly gateId: string;
  readonly snapshotId: string;
  readonly reason:
    | "blocking_findings_present"
    | "data_quality_failed"
    | "data_quality_pending";
  readonly evaluations: readonly [];
  readonly alerts: readonly [];
}

export interface MonitoringEvaluatedResult {
  readonly status: "evaluated";
  readonly asOfDate: string;
  readonly scope: MonitoringScope;
  readonly gateId: string;
  readonly snapshotId: string;
  readonly evaluations: readonly MonitorEvaluation[];
  readonly alerts: readonly MonitoringAlert[];
}

export type MonitoringResult = MonitoringBlockedResult | MonitoringEvaluatedResult;

/**
 * Evaluates effective, typed monitor definitions only after the input snapshot
 * has passed a certified data-quality gate with zero blocking findings.
 */
export function evaluateMonitoring(input: EvaluateMonitoringInput): MonitoringResult {
  assertIsoDate(input.asOfDate, "asOfDate");
  validateScope(input.scope);
  const gate = input.dataQualityGate;
  validateGateIdentity(gate);

  if (gate.status !== "certified") {
    return blocked(
      input,
      gate.status === "pending" ? "data_quality_pending" : "data_quality_failed"
    );
  }
  if (gate.blockingFindingCount > 0) {
    return blocked(input, "blocking_findings_present");
  }
  assertIsoDateTime(gate.certifiedAt, "dataQualityGate.certifiedAt");

  const monitors = selectActiveMonitors(input.monitorDefinitions, input.asOfDate);
  const observations = indexObservations(input.observations);
  const evaluations: MonitorEvaluation[] = [];
  const alerts: MonitoringAlert[] = [];

  for (const monitor of monitors) {
    const threshold = publicThreshold(monitor);
    const dedupeKey = createDedupeKey(monitor, input.scope);
    const observation = observations.get(monitor.metricId);
    if (!observation) {
      evaluations.push({
        monitorId: monitor.monitorId,
        monitorVersion: monitor.version,
        metricId: monitor.metricId,
        outcome: "missing_observation",
        severity: monitor.severity,
        dedupeKey,
        observedValue: null,
        observationId: null,
        observationAsOfDate: null,
        threshold
      });
      continue;
    }

    validateObservationForEvaluation(observation, monitor, input);
    const triggered = evaluateThreshold(monitor, observation);
    const observedValue = observationValue(observation);
    evaluations.push({
      monitorId: monitor.monitorId,
      monitorVersion: monitor.version,
      metricId: monitor.metricId,
      outcome: triggered ? "triggered" : "clear",
      severity: monitor.severity,
      dedupeKey,
      observedValue,
      observationId: observation.observationId,
      observationAsOfDate: observation.asOfDate,
      threshold
    });

    if (!triggered) continue;
    const references = normalizeReferences([
      ...gate.evidence,
      ...observation.evidence
    ]);
    alerts.push({
      occurrenceKey: createOccurrenceKey(dedupeKey, input.asOfDate, observation.observationId),
      dedupeKey,
      monitorId: monitor.monitorId,
      monitorVersion: monitor.version,
      scope: input.scope,
      asOfDate: input.asOfDate,
      title: monitor.title,
      message: monitor.message,
      severity: monitor.severity,
      evidence: {
        gateId: gate.gateId,
        snapshotId: gate.snapshotId,
        certifiedAt: gate.certifiedAt,
        observationId: observation.observationId,
        observationAsOfDate: observation.asOfDate,
        metricId: observation.metricId,
        observedValue,
        threshold,
        references
      }
    });
  }

  return {
    status: "evaluated",
    asOfDate: input.asOfDate,
    scope: input.scope,
    gateId: gate.gateId,
    snapshotId: gate.snapshotId,
    evaluations,
    alerts
  };
}

function blocked(
  input: EvaluateMonitoringInput,
  reason: MonitoringBlockedResult["reason"]
): MonitoringBlockedResult {
  return {
    status: "blocked",
    asOfDate: input.asOfDate,
    scope: input.scope,
    gateId: input.dataQualityGate.gateId,
    snapshotId: input.dataQualityGate.snapshotId,
    reason,
    evaluations: [],
    alerts: []
  };
}

function selectActiveMonitors(
  definitions: readonly MonitorDefinition[],
  asOfDate: string
): readonly MonitorDefinition[] {
  for (const definition of definitions) validateMonitorDefinition(definition);
  const grouped = new Map<string, MonitorDefinition[]>();
  for (const definition of definitions) {
    const versions = grouped.get(definition.monitorId) ?? [];
    versions.push(definition);
    grouped.set(definition.monitorId, versions);
  }

  const active: MonitorDefinition[] = [];
  for (const [monitorId, versions] of grouped) {
    const activeVersions = versions.filter((definition) =>
      isEffective(asOfDate, definition.effectiveFrom, definition.effectiveTo)
    );
    if (activeVersions.length > 1) {
      throw new Error(`Monitor ${monitorId} has ${activeVersions.length} active versions on ${asOfDate}`);
    }
    if (activeVersions[0]) active.push(activeVersions[0]);
  }
  return active.sort((left, right) => compareText(left.monitorId, right.monitorId));
}

function indexObservations(
  observations: readonly MetricObservation[]
): ReadonlyMap<string, MetricObservation> {
  const indexed = new Map<string, MetricObservation>();
  for (const observation of observations) {
    validateObservationIdentity(observation);
    if (indexed.has(observation.metricId)) {
      throw new Error(`Multiple observations supplied for metric ${observation.metricId}`);
    }
    indexed.set(observation.metricId, observation);
  }
  return indexed;
}

function validateObservationForEvaluation(
  observation: MetricObservation,
  monitor: MonitorDefinition,
  input: EvaluateMonitoringInput
): void {
  if (observation.snapshotId !== input.dataQualityGate.snapshotId) {
    throw new Error(
      `Observation ${observation.observationId} belongs to snapshot ${observation.snapshotId}, not certified snapshot ${input.dataQualityGate.snapshotId}`
    );
  }
  if (observation.asOfDate > input.asOfDate) {
    throw new Error(`Observation ${observation.observationId} is future-dated relative to the evaluation`);
  }
  if (observation.type !== monitor.threshold.type) {
    throw new Error(
      `Monitor ${monitor.monitorId} expects ${monitor.threshold.type} but metric ${observation.metricId} is ${observation.type}`
    );
  }
  if (observation.unit !== monitor.threshold.unit) {
    throw new Error(
      `Monitor ${monitor.monitorId} expects unit ${monitor.threshold.unit} but metric ${observation.metricId} uses ${observation.unit}`
    );
  }
}

function evaluateThreshold(monitor: MonitorDefinition, observation: MetricObservation): boolean {
  if (monitor.threshold.type === "boolean") {
    if (observation.type !== "boolean") throw new Error("Boolean monitor received a non-boolean observation");
    return monitor.threshold.operator === "eq"
      ? observation.value === monitor.threshold.value
      : observation.value !== monitor.threshold.value;
  }

  if (observation.type !== "decimal") throw new Error("Decimal monitor received a non-decimal observation");
  const observed = parseDecimal(observation.value, `observation ${observation.observationId} value`);
  const threshold = parseDecimal(monitor.threshold.value, `monitor ${monitor.monitorId} threshold`);
  switch (monitor.threshold.operator) {
    case "eq":
      return observed.eq(threshold);
    case "neq":
      return !observed.eq(threshold);
    case "gt":
      return observed.gt(threshold);
    case "gte":
      return observed.gte(threshold);
    case "lt":
      return observed.lt(threshold);
    case "lte":
      return observed.lte(threshold);
  }
}

function publicThreshold(monitor: MonitorDefinition): EvaluatedThreshold {
  if (monitor.threshold.type === "boolean") {
    return {
      type: "boolean",
      operator: monitor.threshold.operator,
      value: String(monitor.threshold.value),
      unit: "boolean"
    };
  }
  return {
    type: "decimal",
    operator: monitor.threshold.operator,
    value: decimalString(parseDecimal(monitor.threshold.value, `monitor ${monitor.monitorId} threshold`)),
    unit: monitor.threshold.unit
  };
}

function observationValue(observation: MetricObservation): string {
  return observation.type === "boolean"
    ? String(observation.value)
    : decimalString(parseDecimal(observation.value, `observation ${observation.observationId} value`));
}

function createDedupeKey(monitor: MonitorDefinition, scope: MonitoringScope): string {
  const material = [
    "monitor",
    monitor.monitorId,
    monitor.version,
    monitor.metricId,
    scope.type,
    scope.id
  ].join("\u001f");
  return `monitor:${createHash("sha256").update(material).digest("hex")}`;
}

function createOccurrenceKey(dedupeKey: string, asOfDate: string, observationId: string): string {
  return `occurrence:${createHash("sha256")
    .update(dedupeKey)
    .update("\u001f")
    .update(asOfDate)
    .update("\u001f")
    .update(observationId)
    .digest("hex")}`;
}

function normalizeReferences(
  references: readonly MonitoringEvidenceReference[]
): readonly MonitoringEvidenceReference[] {
  const indexed = new Map<string, MonitoringEvidenceReference>();
  for (const reference of references) {
    assertNonEmpty(reference.id, "evidence reference id");
    indexed.set(`${reference.kind}\u001f${reference.id}`, reference);
  }
  return [...indexed.values()].sort(
    (left, right) => compareText(left.kind, right.kind) || compareText(left.id, right.id)
  );
}

function validateMonitorDefinition(definition: MonitorDefinition): void {
  assertNonEmpty(definition.monitorId, "monitorId");
  assertNonEmpty(definition.version, `monitor ${definition.monitorId} version`);
  assertNonEmpty(definition.metricId, `monitor ${definition.monitorId} metricId`);
  assertNonEmpty(definition.title, `monitor ${definition.monitorId} title`);
  assertNonEmpty(definition.message, `monitor ${definition.monitorId} message`);
  assertEffectiveRange(
    definition.effectiveFrom,
    definition.effectiveTo,
    `monitor ${definition.monitorId}`
  );
  if (definition.threshold.type === "decimal") {
    parseDecimal(definition.threshold.value, `monitor ${definition.monitorId} threshold`);
  }
}

function validateObservationIdentity(observation: MetricObservation): void {
  assertNonEmpty(observation.observationId, "observationId");
  assertNonEmpty(observation.metricId, `observation ${observation.observationId} metricId`);
  assertNonEmpty(observation.snapshotId, `observation ${observation.observationId} snapshotId`);
  assertIsoDate(observation.asOfDate, `observation ${observation.observationId} asOfDate`);
  normalizeReferences(observation.evidence);
}

function validateScope(scope: MonitoringScope): void {
  assertNonEmpty(scope.id, "monitoring scope id");
}

function validateGateIdentity(gate: DataQualityGate): void {
  assertNonEmpty(gate.gateId, "data-quality gate id");
  assertNonEmpty(gate.snapshotId, "data-quality gate snapshot id");
  if (!Number.isSafeInteger(gate.blockingFindingCount) || gate.blockingFindingCount < 0) {
    throw new Error("data-quality blockingFindingCount must be a non-negative integer");
  }
  normalizeReferences(gate.evidence);
}

function isEffective(asOfDate: string, effectiveFrom: string, effectiveTo: string | undefined): boolean {
  return asOfDate >= effectiveFrom && (effectiveTo === undefined || asOfDate < effectiveTo);
}

function assertEffectiveRange(effectiveFrom: string, effectiveTo: string | undefined, label: string): void {
  assertIsoDate(effectiveFrom, `${label} effectiveFrom`);
  if (effectiveTo === undefined) return;
  assertIsoDate(effectiveTo, `${label} effectiveTo`);
  if (effectiveTo <= effectiveFrom) throw new Error(`${label} effectiveTo must be after effectiveFrom`);
}

function assertIsoDate(value: string, label: string): void {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) throw new Error(`${label} must be an ISO date (YYYY-MM-DD)`);
  const parsed = new Date(`${value}T00:00:00.000Z`);
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString().slice(0, 10) !== value) {
    throw new Error(`${label} is not a valid calendar date`);
  }
}

function assertIsoDateTime(value: string, label: string): void {
  if (!value.trim() || Number.isNaN(Date.parse(value))) throw new Error(`${label} must be an ISO-compatible datetime`);
}

function assertNonEmpty(value: string, label: string): void {
  if (!value.trim()) throw new Error(`${label} must not be empty`);
}

function parseDecimal(value: string, label: string): Decimal {
  if (typeof value !== "string" || !/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/.test(value.trim())) {
    throw new Error(`${label} must be a plain decimal string`);
  }
  try {
    const parsed = new ExactDecimal(value.trim());
    if (!parsed.isFinite()) throw new Error("non-finite decimal");
    return parsed;
  } catch (error) {
    throw new Error(`${label} is not a valid decimal`, { cause: error });
  }
}

function decimalString(value: Decimal): string {
  return value.isZero() ? "0" : value.toFixed();
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
