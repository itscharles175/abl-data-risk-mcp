import { createHash } from "node:crypto";

import { Decimal } from "decimal.js";

import type { DecimalMetricUnit, MonitorSeverity, MonitoringScope } from "./monitoring.js";

const ExactDecimal = Decimal.clone({ precision: 50, rounding: Decimal.ROUND_HALF_EVEN });

export type MonitorV2Operator = "eq" | "neq" | "gt" | "gte" | "lt" | "lte";
export type MonitorV2MissingPolicy = "alert" | "block" | "clear";

export interface CertifiedMetricPointV1 {
  readonly pointId: string;
  readonly metricId: string;
  readonly snapshotId: string;
  readonly certificationManifestId: string;
  readonly populationHash: string;
  readonly asOfDate: string;
  readonly value: string | boolean | null;
  readonly unit: DecimalMetricUnit | "boolean";
  readonly coverage: string;
}

export type ScalarMonitorConditionV2 =
  | {
      readonly type: "absolute";
      readonly operator: MonitorV2Operator;
      readonly value: string | boolean;
      readonly unit: DecimalMetricUnit | "boolean";
      readonly resetValue?: string | boolean;
    }
  | {
      readonly type: "change";
      readonly mode: "delta" | "percent_change";
      readonly lookbackPeriods: number;
      readonly operator: MonitorV2Operator;
      readonly value: string;
      readonly unit: DecimalMetricUnit | "percent";
      readonly resetValue?: string;
    }
  | {
      readonly type: "rolling";
      readonly aggregation: "average" | "minimum" | "maximum";
      readonly windowPeriods: number;
      readonly minimumObservations: number;
      readonly operator: MonitorV2Operator;
      readonly value: string;
      readonly unit: DecimalMetricUnit;
      readonly resetValue?: string;
    };

export type MonitorConditionV2 =
  | ScalarMonitorConditionV2
  | {
      readonly type: "consecutive";
      readonly requiredPeriods: number;
      readonly condition: ScalarMonitorConditionV2;
    }
  | {
      readonly type: "compound";
      readonly operator: "all" | "any";
      readonly conditions: readonly ScalarMonitorConditionV2[];
    };

export interface MonitorDefinitionV2 {
  readonly schemaVersion: 2;
  readonly monitorId: string;
  readonly version: string;
  readonly effectiveFrom: string;
  readonly effectiveTo?: string;
  readonly metricId: string;
  readonly scopeTypes: readonly MonitoringScope["type"][];
  readonly title: string;
  readonly message: string;
  readonly severity: MonitorSeverity;
  readonly ownerId: string;
  readonly slaHours: number;
  readonly missingPolicy: MonitorV2MissingPolicy;
  readonly staleAfterDays: number;
  readonly cooldownDays: number;
  readonly condition: MonitorConditionV2;
}

export interface MonitorV2State {
  readonly caseOpen: boolean;
  readonly lastTriggeredOn: string | null;
  readonly lastClearedOn: string | null;
}

export interface EvaluateMonitorV2Input {
  readonly asOfDate: string;
  readonly scope: MonitoringScope;
  readonly definition: MonitorDefinitionV2;
  readonly history: readonly CertifiedMetricPointV1[];
  readonly state?: MonitorV2State;
}

export interface MonitorV2Evaluation {
  readonly schemaVersion: 2;
  readonly monitorId: string;
  readonly monitorVersion: string;
  readonly metricId: string;
  readonly scope: MonitoringScope;
  readonly asOfDate: string;
  readonly outcome: "blocked" | "clear" | "cooldown" | "missing" | "reset" | "triggered";
  readonly reason:
    | "condition_clear"
    | "condition_triggered"
    | "cooldown_active"
    | "hysteresis_not_reset"
    | "insufficient_history"
    | "missing_observation"
    | "stale_observation";
  readonly observedValue: string | null;
  readonly comparisonValue: string | null;
  readonly observationIds: readonly string[];
  readonly snapshotIds: readonly string[];
  readonly populationHashes: readonly string[];
  readonly ownerId: string;
  readonly dueAt: string | null;
  readonly dedupeKey: string;
  readonly occurrenceKey: string | null;
  readonly evidenceHash: string;
}

/** Exact, deterministic monitor-v2 evaluator over certified metric history. */
export function evaluateMonitorV2(input: EvaluateMonitorV2Input): MonitorV2Evaluation {
  validateInput(input);
  const definition = input.definition;
  if (!definition.scopeTypes.includes(input.scope.type)) invalid("Monitor does not apply to the requested scope type");
  if (!isEffective(input.asOfDate, definition.effectiveFrom, definition.effectiveTo)) {
    invalid("Monitor is not effective on the evaluation date");
  }
  const history = [...input.history]
    .filter((point) => point.metricId === definition.metricId && point.asOfDate <= input.asOfDate)
    .sort((left, right) => compare(left.asOfDate, right.asOfDate) || compare(left.pointId, right.pointId));
  const dedupeKey = `monitor-v2:${digest({
    monitorId: definition.monitorId,
    scope: input.scope
  })}`;
  const latest = history.at(-1);
  if (!latest) {
    return missingEvaluation(input, dedupeKey, "missing_observation", []);
  }
  const age = daysBetween(latest.asOfDate, input.asOfDate);
  if (age > definition.staleAfterDays) {
    return missingEvaluation(input, dedupeKey, "stale_observation", [latest]);
  }

  const result = evaluateCondition(definition.condition, history);
  if (result.status === "insufficient") {
    return missingEvaluation(input, dedupeKey, "insufficient_history", result.points);
  }
  const state = input.state ?? { caseOpen: false, lastTriggeredOn: null, lastClearedOn: null };
  let outcome: MonitorV2Evaluation["outcome"];
  let reason: MonitorV2Evaluation["reason"];
  if (result.triggered) {
    const cooldownActive =
      state.lastTriggeredOn !== null &&
      daysBetween(state.lastTriggeredOn, input.asOfDate) < definition.cooldownDays;
    outcome = cooldownActive ? "cooldown" : "triggered";
    reason = cooldownActive ? "cooldown_active" : "condition_triggered";
  } else if (state.caseOpen && result.resetSatisfied === false) {
    outcome = "clear";
    reason = "hysteresis_not_reset";
  } else if (state.caseOpen) {
    outcome = "reset";
    reason = "condition_clear";
  } else {
    outcome = "clear";
    reason = "condition_clear";
  }
  const occurrenceKey = outcome === "triggered"
    ? `occurrence-v2:${digest({ asOfDate: input.asOfDate, dedupeKey, evidence: pointEvidence(result.points) })}`
    : null;
  return finalize(input, dedupeKey, outcome, reason, result.observedValue, result.comparisonValue, result.points, occurrenceKey);
}

interface ConditionResult {
  readonly status: "evaluated" | "insufficient";
  readonly triggered: boolean;
  readonly resetSatisfied: boolean | null;
  readonly observedValue: string | null;
  readonly comparisonValue: string | null;
  readonly points: readonly CertifiedMetricPointV1[];
}

function evaluateCondition(
  condition: MonitorConditionV2,
  history: readonly CertifiedMetricPointV1[]
): ConditionResult {
  if (condition.type === "consecutive") {
    if (history.length < condition.requiredPeriods) return insufficient(history);
    const slices = history.slice(-condition.requiredPeriods).map((_, index, selected) => {
      const point = selected[index]!;
      const originalIndex = history.findIndex((candidate) => candidate.pointId === point.pointId);
      return evaluateScalar(condition.condition, history.slice(0, originalIndex + 1));
    });
    if (slices.some((item) => item.status === "insufficient")) return insufficient(history.slice(-condition.requiredPeriods));
    const latest = slices.at(-1)!;
    return {
      ...latest,
      triggered: slices.every((item) => item.triggered),
      points: uniquePoints(slices.flatMap((item) => item.points))
    };
  }
  if (condition.type === "compound") {
    const results = condition.conditions.map((nested) => evaluateScalar(nested, history));
    if (results.some((item) => item.status === "insufficient")) return insufficient(uniquePoints(results.flatMap((item) => item.points)));
    const triggered = condition.operator === "all"
      ? results.every((item) => item.triggered)
      : results.some((item) => item.triggered);
    const resetSatisfied = condition.operator === "all"
      ? results.every((item) => item.resetSatisfied !== false)
      : results.some((item) => item.resetSatisfied !== false);
    return {
      status: "evaluated",
      triggered,
      resetSatisfied,
      observedValue: results.map((item) => item.observedValue ?? "null").join(" | "),
      comparisonValue: results.map((item) => item.comparisonValue ?? "null").join(" | "),
      points: uniquePoints(results.flatMap((item) => item.points))
    };
  }
  return evaluateScalar(condition, history);
}

function evaluateScalar(
  condition: ScalarMonitorConditionV2,
  history: readonly CertifiedMetricPointV1[]
): ConditionResult {
  const latest = history.at(-1);
  if (!latest || latest.value === null) return insufficient(latest ? [latest] : []);
  if (condition.type === "absolute") {
    assertUnit(latest, condition.unit);
    const triggered = compareThreshold(latest.value, condition.operator, condition.value);
    const resetSatisfied = condition.resetValue === undefined
      ? !triggered
      : !compareThreshold(latest.value, condition.operator, condition.resetValue);
    return evaluated(triggered, resetSatisfied, publicValue(latest.value), publicValue(condition.value), [latest]);
  }
  if (condition.type === "change") {
    const prior = history.at(-(condition.lookbackPeriods + 1));
    if (!prior || prior.value === null) return insufficient([...(prior ? [prior] : []), latest]);
    if (typeof latest.value !== "string" || typeof prior.value !== "string") invalid("Change monitor requires decimal observations");
    const current = decimal(latest.value, "current observation");
    const previous = decimal(prior.value, "prior observation");
    let observed: Decimal;
    if (condition.mode === "delta") {
      if (latest.unit !== condition.unit || prior.unit !== latest.unit) invalid("Change monitor unit mismatch");
      observed = current.minus(previous);
    } else {
      if (latest.unit !== prior.unit) invalid("Percent-change monitor unit mismatch");
      if (previous.isZero()) return insufficient([prior, latest]);
      observed = current.minus(previous).div(previous.abs()).times(100);
    }
    const threshold = decimal(condition.value, "change threshold");
    const triggered = compareDecimal(observed, condition.operator, threshold);
    const resetSatisfied = condition.resetValue === undefined
      ? !triggered
      : !compareDecimal(observed, condition.operator, decimal(condition.resetValue, "change reset threshold"));
    return evaluated(triggered, resetSatisfied, exact(observed), exact(threshold), [prior, latest]);
  }
  const points = history.slice(-condition.windowPeriods);
  if (points.length < condition.minimumObservations) return insufficient(points);
  if (points.some((point) => point.value === null || typeof point.value !== "string" || point.unit !== condition.unit)) {
    return insufficient(points);
  }
  const values = points.map((point) => decimal(point.value as string, "rolling observation"));
  let observed: Decimal;
  if (condition.aggregation === "average") {
    observed = values.reduce((sum, value) => sum.plus(value), zero()).div(values.length);
  } else if (condition.aggregation === "minimum") {
    observed = Decimal.min(...values);
  } else {
    observed = Decimal.max(...values);
  }
  const threshold = decimal(condition.value, "rolling threshold");
  const triggered = compareDecimal(observed, condition.operator, threshold);
  const resetSatisfied = condition.resetValue === undefined
    ? !triggered
    : !compareDecimal(observed, condition.operator, decimal(condition.resetValue, "rolling reset threshold"));
  return evaluated(triggered, resetSatisfied, exact(observed), exact(threshold), points);
}

function missingEvaluation(
  input: EvaluateMonitorV2Input,
  dedupeKey: string,
  reason: "insufficient_history" | "missing_observation" | "stale_observation",
  points: readonly CertifiedMetricPointV1[]
): MonitorV2Evaluation {
  const outcome = input.definition.missingPolicy === "block"
    ? "blocked"
    : input.definition.missingPolicy === "alert"
      ? "missing"
      : "clear";
  const occurrenceKey = outcome === "missing"
    ? `occurrence-v2:${digest({ asOfDate: input.asOfDate, dedupeKey, reason })}`
    : null;
  return finalize(input, dedupeKey, outcome, reason, null, null, points, occurrenceKey);
}

function finalize(
  input: EvaluateMonitorV2Input,
  dedupeKey: string,
  outcome: MonitorV2Evaluation["outcome"],
  reason: MonitorV2Evaluation["reason"],
  observedValue: string | null,
  comparisonValue: string | null,
  points: readonly CertifiedMetricPointV1[],
  occurrenceKey: string | null
): MonitorV2Evaluation {
  const evidence = pointEvidence(points);
  const dueAt = outcome === "triggered" || outcome === "missing"
    ? new Date(Date.parse(`${input.asOfDate}T00:00:00.000Z`) + input.definition.slaHours * 3_600_000).toISOString()
    : null;
  return Object.freeze({
    schemaVersion: 2,
    monitorId: input.definition.monitorId,
    monitorVersion: input.definition.version,
    metricId: input.definition.metricId,
    scope: Object.freeze({ ...input.scope }),
    asOfDate: input.asOfDate,
    outcome,
    reason,
    observedValue,
    comparisonValue,
    observationIds: Object.freeze(points.map((point) => point.pointId)),
    snapshotIds: Object.freeze([...new Set(points.map((point) => point.snapshotId))].sort(compare)),
    populationHashes: Object.freeze([...new Set(points.map((point) => point.populationHash))].sort(compare)),
    ownerId: input.definition.ownerId,
    dueAt,
    dedupeKey,
    occurrenceKey,
    evidenceHash: digest({
      asOfDate: input.asOfDate,
      comparisonValue,
      definition: input.definition,
      evidence,
      observedValue,
      outcome,
      reason,
      scope: input.scope
    })
  });
}

function validateInput(input: EvaluateMonitorV2Input): void {
  isoDate(input.asOfDate, "asOfDate");
  identifier(input.scope.id, "scope.id");
  const definition = input.definition;
  if (definition.schemaVersion !== 2) invalid("Monitor schemaVersion must be 2");
  identifier(definition.monitorId, "monitorId");
  identifier(definition.version, "version");
  identifier(definition.metricId, "metricId");
  isoDate(definition.effectiveFrom, "effectiveFrom");
  if (definition.effectiveTo !== undefined) {
    isoDate(definition.effectiveTo, "effectiveTo");
    if (definition.effectiveTo <= definition.effectiveFrom) invalid("effectiveTo must be after effectiveFrom");
  }
  if (!definition.title.trim() || !definition.message.trim()) invalid("Monitor title and message are required");
  identifier(definition.ownerId, "ownerId");
  integer(definition.slaHours, "slaHours", 1, 8_760);
  integer(definition.staleAfterDays, "staleAfterDays", 0, 3_650);
  integer(definition.cooldownDays, "cooldownDays", 0, 3_650);
  if (new Set(definition.scopeTypes).size !== definition.scopeTypes.length || definition.scopeTypes.length < 1) {
    invalid("scopeTypes is invalid");
  }
  validateCondition(definition.condition);
  let previousDate = "";
  const pointIds = new Set<string>();
  for (const point of input.history) {
    identifier(point.pointId, "pointId");
    identifier(point.metricId, "point.metricId");
    identifier(point.snapshotId, "point.snapshotId");
    identifier(point.certificationManifestId, "point.certificationManifestId");
    hash(point.populationHash, "point.populationHash");
    isoDate(point.asOfDate, "point.asOfDate");
    decimal(point.coverage, "point.coverage");
    if (pointIds.has(point.pointId)) invalid("Metric point ids must be unique");
    pointIds.add(point.pointId);
    if (point.asOfDate < previousDate) invalid("Metric history must be ordered by asOfDate");
    previousDate = point.asOfDate;
  }
}

function validateCondition(condition: MonitorConditionV2): void {
  if (condition.type === "consecutive") {
    integer(condition.requiredPeriods, "requiredPeriods", 1, 365);
    validateScalarCondition(condition.condition);
    return;
  }
  if (condition.type === "compound") {
    if (condition.conditions.length < 2 || condition.conditions.length > 10) invalid("Compound condition count is invalid");
    condition.conditions.forEach(validateScalarCondition);
    return;
  }
  validateScalarCondition(condition);
}

function validateScalarCondition(condition: ScalarMonitorConditionV2): void {
  if (condition.type === "absolute") {
    if (condition.unit === "boolean") {
      if (typeof condition.value !== "boolean" || (condition.resetValue !== undefined && typeof condition.resetValue !== "boolean")) {
        invalid("Boolean threshold values must be boolean");
      }
    } else {
      if (typeof condition.value !== "string") invalid("Decimal threshold value must be a string");
      decimal(condition.value, "absolute threshold");
      if (condition.resetValue !== undefined) {
        if (typeof condition.resetValue !== "string") invalid("Decimal reset threshold must be a string");
        decimal(condition.resetValue, "absolute reset threshold");
      }
    }
    return;
  }
  if (condition.type === "change") {
    integer(condition.lookbackPeriods, "lookbackPeriods", 1, 365);
    decimal(condition.value, "change threshold");
    if (condition.resetValue !== undefined) decimal(condition.resetValue, "change reset threshold");
    return;
  }
  integer(condition.windowPeriods, "windowPeriods", 1, 365);
  integer(condition.minimumObservations, "minimumObservations", 1, condition.windowPeriods);
  decimal(condition.value, "rolling threshold");
  if (condition.resetValue !== undefined) decimal(condition.resetValue, "rolling reset threshold");
}

function compareThreshold(
  observed: string | boolean,
  operator: MonitorV2Operator,
  threshold: string | boolean
): boolean {
  if (typeof observed !== typeof threshold) invalid("Threshold and observation types differ");
  if (typeof observed === "boolean") {
    if (operator !== "eq" && operator !== "neq") invalid("Boolean threshold supports eq or neq only");
    return operator === "eq" ? observed === threshold : observed !== threshold;
  }
  return compareDecimal(decimal(observed, "observed value"), operator, decimal(threshold as string, "threshold"));
}

function compareDecimal(observed: Decimal, operator: MonitorV2Operator, threshold: Decimal): boolean {
  if (operator === "eq") return observed.eq(threshold);
  if (operator === "neq") return !observed.eq(threshold);
  if (operator === "gt") return observed.gt(threshold);
  if (operator === "gte") return observed.gte(threshold);
  if (operator === "lt") return observed.lt(threshold);
  return observed.lte(threshold);
}

function evaluated(
  triggered: boolean,
  resetSatisfied: boolean,
  observedValue: string,
  comparisonValue: string,
  points: readonly CertifiedMetricPointV1[]
): ConditionResult {
  return { status: "evaluated", triggered, resetSatisfied, observedValue, comparisonValue, points };
}

function insufficient(points: readonly CertifiedMetricPointV1[]): ConditionResult {
  return {
    status: "insufficient",
    triggered: false,
    resetSatisfied: null,
    observedValue: null,
    comparisonValue: null,
    points
  };
}

function pointEvidence(points: readonly CertifiedMetricPointV1[]): unknown {
  return points.map((point) => ({
    certificationManifestId: point.certificationManifestId,
    coverage: exact(decimal(point.coverage, "coverage")),
    pointId: point.pointId,
    populationHash: point.populationHash,
    snapshotId: point.snapshotId
  }));
}

function uniquePoints(points: readonly CertifiedMetricPointV1[]): readonly CertifiedMetricPointV1[] {
  const byId = new Map(points.map((point) => [point.pointId, point]));
  return [...byId.values()].sort((left, right) => compare(left.asOfDate, right.asOfDate) || compare(left.pointId, right.pointId));
}

function assertUnit(point: CertifiedMetricPointV1, unit: CertifiedMetricPointV1["unit"]): void {
  if (point.unit !== unit) invalid("Monitor and observation units differ");
}

function publicValue(value: string | boolean): string {
  return typeof value === "boolean" ? String(value) : exact(decimal(value, "value"));
}

function decimal(value: string, label: string): Decimal {
  if (!/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/.test(value)) invalid(`${label} must be an exact decimal string`);
  const parsed = new ExactDecimal(value);
  if (!parsed.isFinite()) invalid(`${label} must be finite`);
  return parsed;
}

function zero(): Decimal {
  return new ExactDecimal(0);
}

function exact(value: Decimal): string {
  return value.isZero() ? "0" : value.toFixed();
}

function daysBetween(earlier: string, later: string): number {
  return Math.floor((Date.parse(`${later}T00:00:00.000Z`) - Date.parse(`${earlier}T00:00:00.000Z`)) / 86_400_000);
}

function isEffective(asOfDate: string, from: string, to?: string): boolean {
  return asOfDate >= from && (to === undefined || asOfDate < to);
}

function isoDate(value: string, label: string): void {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) invalid(`${label} must be an ISO date`);
  const parsed = new Date(`${value}T00:00:00.000Z`);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== value) invalid(`${label} is invalid`);
}

function identifier(value: string, label: string): void {
  if (!value || value.length > 256 || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(value)) invalid(`${label} is invalid`);
}

function integer(value: number, label: string, minimum: number, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalid(`${label} is invalid`);
}

function hash(value: string, label: string): void {
  if (!/^[a-f0-9]{64}$/.test(value)) invalid(`${label} must be a lowercase SHA-256 hash`);
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function digest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(canonicalize(value))).digest("hex");
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, nested]) => nested !== undefined)
        .sort(([left], [right]) => compare(left, right))
        .map(([key, nested]) => [key, canonicalize(nested)])
    );
  }
  return value;
}

function invalid(message: string): never {
  throw new Error(message);
}
