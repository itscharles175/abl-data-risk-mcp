import { createHash } from "node:crypto";

import { Decimal } from "decimal.js";

import type {
  BinDefinitionV1,
  CanonicalSurveillanceRecord,
  CohortDefinitionV1,
  DefinitionApprovalV1,
  EntityResolutionDefinitionV1,
  FilterExpressionV1,
  FilterScalarV1,
  MetricDefinitionV1,
  NumericBinV1
} from "./contracts.js";

const IDENTIFIER = /^[a-zA-Z][a-zA-Z0-9_.:-]{0,127}$/;
const FIELD = /^[a-z][a-z0-9_]{0,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const CANONICAL_DECIMAL = /^-?(?:0|[1-9]\d*)(?:\.\d+)?$/;
const ExactDecimal = Decimal.clone({
  precision: 256,
  rounding: Decimal.ROUND_HALF_EVEN,
  toExpNeg: -1_000,
  toExpPos: 1_000
});

export interface ValidatedNumericBinV1 {
  readonly label: string;
  readonly lower: Decimal | null;
  readonly upper: Decimal | null;
  readonly includeLower: boolean;
  readonly includeUpper: boolean;
}

export function stableFingerprint(value: unknown): string {
  return createHash("sha256").update(stableJson(value)).digest("hex");
}

export function stableJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function validateMetricDefinitionV1(definition: MetricDefinitionV1): void {
  exactKeys(definition, "metric definition", [
    "schemaVersion", "definitionType", "definitionId", "version", "name", "family",
    "grain", "unit", "temporalSemantics", "numerator", "denominator", "window",
    "population", "nullPolicy", "coverage", "privacy", "maximumCells", "configuration",
    "approval"
  ]);
  if (definition.schemaVersion !== "1" || definition.definitionType !== "metric_definition") {
    throw new Error("Metric definition must use metric_definition schema version 1");
  }
  validateDefinitionIdentity(definition.definitionId, definition.version, definition.name);
  validateApproval(definition.approval);
  oneOf(definition.family, "metric family", [
    "roll_cure", "default_ever", "loss_recovery", "paydown_prepayment", "rating_migration",
    "balance_utilization", "maturity_wall", "concentration", "period_comparison"
  ]);
  oneOf(definition.grain, "metric grain", ["loan", "entity", "portfolio"]);
  oneOf(definition.unit, "metric unit", ["count", "currency", "ratio", "days"]);
  oneOf(definition.temporalSemantics, "temporalSemantics", [
    "point_in_time", "period_flow", "cumulative", "transition"
  ]);
  validateMeasure(definition.numerator, "numerator");
  if (definition.denominator !== null) validateMeasure(definition.denominator, "denominator");
  exactKeys(definition.window, "metric window", ["kind", "maximumPeriods"]);
  oneOf(definition.window.kind, "metric window kind", ["snapshot", "adjacent_periods", "ever_to_date", "event_lag"]);
  exactKeys(definition.coverage, "metric coverage", ["minimumRatio", "minimumObservedRecords"]);
  exactKeys(definition.privacy, "metric privacy", ["minimumCellCount", "complementarySuppression"]);
  oneOf(definition.nullPolicy, "nullPolicy", ["exclude", "zero", "unavailable"]);
  if (definition.family !== definition.configuration.kind) {
    throw new Error("Metric family must match configuration kind");
  }
  validateFieldIfPresent(definition.numerator.field, "numerator field");
  validateFieldIfPresent(definition.denominator?.field, "denominator field");
  if (definition.numerator.predicate) validateFilterExpressionV1(definition.numerator.predicate);
  if (definition.denominator?.predicate) validateFilterExpressionV1(definition.denominator.predicate);
  if (definition.population) validateFilterExpressionV1(definition.population);
  boundedInteger(definition.window.maximumPeriods, "window.maximumPeriods", 1, 120);
  boundedInteger(definition.coverage.minimumObservedRecords, "coverage.minimumObservedRecords", 1, 1_000_000);
  const minimumRatio = decimal(definition.coverage.minimumRatio, "coverage.minimumRatio");
  if (minimumRatio.isNegative() || minimumRatio.greaterThan(1)) {
    throw new Error("coverage.minimumRatio must be between 0 and 1");
  }
  boundedInteger(definition.privacy.minimumCellCount, "privacy.minimumCellCount", 1, 100_000);
  if (definition.privacy.complementarySuppression !== true) {
    throw new Error("Complementary suppression is mandatory");
  }
  boundedInteger(definition.maximumCells, "maximumCells", 1, 100_000);
  validateConfiguration(definition);
}

export function validateCohortDefinitionV1(definition: CohortDefinitionV1): void {
  exactKeys(definition, "cohort definition", [
    "schemaVersion", "definitionType", "definitionId", "version", "name", "dateField",
    "grain", "population", "maximumCohorts", "approval"
  ]);
  if (definition.schemaVersion !== "1" || definition.definitionType !== "cohort_definition") {
    throw new Error("Cohort definition must use cohort_definition schema version 1");
  }
  validateDefinitionIdentity(definition.definitionId, definition.version, definition.name);
  field(definition.dateField, "cohort dateField");
  oneOf(definition.grain, "cohort grain", ["month", "quarter", "year"]);
  boundedInteger(definition.maximumCohorts, "maximumCohorts", 1, 10_000);
  if (definition.population) validateFilterExpressionV1(definition.population);
  validateApproval(definition.approval);
}

export function validateBinDefinitionV1(definition: BinDefinitionV1): readonly ValidatedNumericBinV1[] {
  exactKeys(definition, "bin definition", [
    "schemaVersion", "definitionType", "definitionId", "version", "name", "field", "bins",
    "unknownLabel", "otherLabel", "approval"
  ]);
  if (definition.schemaVersion !== "1" || definition.definitionType !== "bin_definition") {
    throw new Error("Bin definition must use bin_definition schema version 1");
  }
  validateDefinitionIdentity(definition.definitionId, definition.version, definition.name);
  field(definition.field, "bin field");
  label(definition.unknownLabel, "unknownLabel");
  label(definition.otherLabel, "otherLabel");
  if (definition.unknownLabel === definition.otherLabel) {
    throw new Error("unknownLabel and otherLabel must differ");
  }
  if (definition.bins.length < 1 || definition.bins.length > 100) {
    throw new Error("A bin definition must contain between 1 and 100 bins");
  }
  const seen = new Set([definition.unknownLabel, definition.otherLabel]);
  const parsed: ValidatedNumericBinV1[] = [];
  let previousUpper: Decimal | null | undefined;
  let previousIncludeUpper = false;
  for (const [index, bin] of definition.bins.entries()) {
    exactKeys(bin, `bin ${index + 1}`, ["label", "lower", "upper", "includeLower", "includeUpper"]);
    label(bin.label, `bin ${index + 1} label`);
    if (seen.has(bin.label)) throw new Error(`Duplicate or reserved bin label: ${bin.label}`);
    seen.add(bin.label);
    const next = parseBin(bin);
    if (next.lower === null && next.upper === null) {
      throw new Error(`Bin ${bin.label} must define a lower or upper bound`);
    }
    if (next.lower && next.upper && next.lower.greaterThanOrEqualTo(next.upper)) {
      throw new Error(`Bin ${bin.label} has an invalid range`);
    }
    if (index > 0 && previousUpper === null) {
      throw new Error(`Bin ${bin.label} follows an upper-unbounded bin`);
    }
    if (index > 0 && next.lower === null) {
      throw new Error(`Bin ${bin.label} overlaps prior bins`);
    }
    if (
      previousUpper !== undefined &&
      previousUpper !== null &&
      next.lower !== null &&
      (next.lower.lessThan(previousUpper) ||
        (next.lower.equals(previousUpper) && previousIncludeUpper && next.includeLower))
    ) {
      throw new Error(`Bin ${bin.label} overlaps the previous bin`);
    }
    parsed.push(next);
    previousUpper = next.upper;
    previousIncludeUpper = next.includeUpper;
  }
  validateApproval(definition.approval);
  return parsed;
}

export function validateEntityResolutionDefinitionV1(
  definition: EntityResolutionDefinitionV1,
  expectedTenantId?: string
): void {
  exactKeys(definition, "entity-resolution definition", [
    "schemaVersion", "definitionType", "definitionId", "version", "tenantId", "sourceField",
    "mappings", "approval"
  ]);
  if (definition.schemaVersion !== "1" || definition.definitionType !== "entity_resolution_definition") {
    throw new Error("Entity-resolution definition must use schema version 1");
  }
  validateDefinitionIdentity(definition.definitionId, definition.version, definition.definitionId);
  identifier(definition.tenantId, "entity-resolution tenantId");
  oneOf(definition.sourceField, "entity-resolution sourceField", ["borrower_id", "account_debtor_id"]);
  if (expectedTenantId !== undefined && definition.tenantId !== expectedTenantId) {
    throw new Error("Entity-resolution definition belongs to a different tenant");
  }
  if (definition.mappings.length < 1 || definition.mappings.length > 1_000_000) {
    throw new Error("Entity-resolution mappings must contain between 1 and 1000000 entries");
  }
  const sourceKeys = new Set<string>();
  for (const [index, mapping] of definition.mappings.entries()) {
    exactKeys(mapping, `entity-resolution mapping ${index + 1}`, [
      "sourceSystem", "sourceEntityId", "canonicalEntityId"
    ]);
    identifier(mapping.sourceSystem, `mapping ${index + 1} sourceSystem`);
    identifier(mapping.sourceEntityId, `mapping ${index + 1} sourceEntityId`);
    identifier(mapping.canonicalEntityId, `mapping ${index + 1} canonicalEntityId`);
    const key = stableJson([mapping.sourceSystem, mapping.sourceEntityId]);
    if (sourceKeys.has(key)) throw new Error("Entity-resolution source keys must be unique");
    sourceKeys.add(key);
  }
  validateApproval(definition.approval);
}

export function validateFilterExpressionV1(expression: FilterExpressionV1): void {
  let nodes = 0;
  const visit = (node: FilterExpressionV1, depth: number): void => {
    nodes += 1;
    if (nodes > 50) throw new Error("Population filter exceeds 50 nodes");
    if (depth > 4) throw new Error("Population filter exceeds maximum depth 4");
    if ("clauses" in node) {
      exactKeys(node, "compound filter", ["op", "clauses"]);
      oneOf(node.op, "compound filter op", ["and", "or"]);
      if (node.clauses.length < 1 || node.clauses.length > 10) {
        throw new Error(`${node.op} filters require between 1 and 10 clauses`);
      }
      for (const clause of node.clauses) visit(clause, depth + 1);
      return;
    }
    field(node.field, "filter field");
    if ("values" in node) {
      exactKeys(node, "in filter", ["op", "field", "values"]);
      if (node.op !== "in") throw new Error("Values are only valid for an in filter");
      if (node.values.length < 1 || node.values.length > 50) {
        throw new Error("in filters require between 1 and 50 values");
      }
      for (const value of node.values) validateScalar(value, "filter value");
      return;
    }
    if (node.op === "is_null") {
      exactKeys(node, "is_null filter", ["op", "field", "value"]);
      if (typeof node.value !== "boolean") throw new Error("is_null filter value must be boolean");
      return;
    }
    exactKeys(node, "comparison filter", ["op", "field", "value"]);
    oneOf(node.op, "comparison filter op", ["eq", "neq", "gt", "gte", "lt", "lte"]);
    validateScalar(node.value, "filter value");
    if (["gt", "gte", "lt", "lte"].includes(node.op)) decimal(node.value as string, "filter comparison value");
  };
  visit(expression, 1);
}

export function matchesFilter(record: CanonicalSurveillanceRecord, expression: FilterExpressionV1): boolean {
  if ("clauses" in expression) {
    return expression.op === "and"
      ? expression.clauses.every((clause) => matchesFilter(record, clause))
      : expression.clauses.some((clause) => matchesFilter(record, clause));
  }
  const raw = record[expression.field];
  if (expression.op === "is_null") {
    const absent = raw === null || raw === undefined || raw === "";
    return expression.value ? absent : !absent;
  }
  if (expression.op === "in") return expression.values.some((value) => scalarEquals(raw, value));
  if (expression.op === "eq") return scalarEquals(raw, expression.value);
  if (expression.op === "neq") return !scalarEquals(raw, expression.value);
  if (typeof raw !== "string" || !CANONICAL_DECIMAL.test(raw)) return false;
  const left = decimal(raw, `record field ${expression.field}`);
  const right = decimal(expression.value as string, "filter comparison value");
  if (expression.op === "gt") return left.greaterThan(right);
  if (expression.op === "gte") return left.greaterThanOrEqualTo(right);
  if (expression.op === "lt") return left.lessThan(right);
  return left.lessThanOrEqualTo(right);
}

export function cohortForRecord(
  record: CanonicalSurveillanceRecord,
  definition: CohortDefinitionV1
): string | null {
  validateCohortDefinitionV1(definition);
  if (definition.population && !matchesFilter(record, definition.population)) return null;
  const raw = record[definition.dateField];
  if (typeof raw !== "string") return null;
  parseIsoDate(raw, definition.dateField);
  const [year, month] = raw.split("-").map(Number) as [number, number, number];
  if (definition.grain === "year") return `${year.toString().padStart(4, "0")}-01-01`;
  const outputMonth = definition.grain === "quarter" ? Math.floor((month - 1) / 3) * 3 + 1 : month;
  return `${year.toString().padStart(4, "0")}-${outputMonth.toString().padStart(2, "0")}-01`;
}

export function classifyBin(
  raw: unknown,
  definition: BinDefinitionV1,
  parsedBins: readonly ValidatedNumericBinV1[] = validateBinDefinitionV1(definition)
): string {
  if (raw === null || raw === undefined || raw === "") return definition.unknownLabel;
  if (typeof raw !== "string" || !CANONICAL_DECIMAL.test(raw)) return definition.unknownLabel;
  const value = decimal(raw, definition.field);
  for (const bin of parsedBins) {
    const lowerMatches =
      bin.lower === null || (bin.includeLower ? value.greaterThanOrEqualTo(bin.lower) : value.greaterThan(bin.lower));
    const upperMatches =
      bin.upper === null || (bin.includeUpper ? value.lessThanOrEqualTo(bin.upper) : value.lessThan(bin.upper));
    if (lowerMatches && upperMatches) return bin.label;
  }
  return definition.otherLabel;
}

export function validateHash(value: string, labelText: string): void {
  if (!SHA256.test(value)) throw new Error(`${labelText} must be a lowercase SHA-256 hash`);
}

export function validateIsoDate(value: string, labelText: string): void {
  parseIsoDate(value, labelText);
}

function validateConfiguration(definition: MetricDefinitionV1): void {
  const config = definition.configuration;
  switch (config.kind) {
    case "roll_cure":
      exactKeys(config, "roll/cure configuration", [
        "kind", "delinquencyField", "balanceField", "binDefinitionId"
      ]);
      field(config.delinquencyField, "delinquencyField");
      field(config.balanceField, "balanceField");
      identifier(config.binDefinitionId, "binDefinitionId");
      return;
    case "default_ever": {
      exactKeys(config, "default/ever configuration", [
        "kind", "defaultFlagField", "daysPastDueField", "balanceField", "everDpdThresholds",
        "incidenceBasis"
      ]);
      field(config.defaultFlagField, "defaultFlagField");
      field(config.daysPastDueField, "daysPastDueField");
      field(config.balanceField, "balanceField");
      oneOf(config.incidenceBasis, "incidenceBasis", ["count", "balance"]);
      if (config.everDpdThresholds.length < 1 || config.everDpdThresholds.length > 10) {
        throw new Error("everDpdThresholds must contain between 1 and 10 thresholds");
      }
      let previous = -1;
      for (const threshold of config.everDpdThresholds) {
        boundedInteger(threshold, "ever DPD threshold", 1, 100_000);
        if (threshold <= previous) throw new Error("everDpdThresholds must be strictly increasing");
        previous = threshold;
      }
      return;
    }
    case "loss_recovery":
      exactKeys(config, "loss/recovery configuration", [
        "kind", "grossLossField", "recoveryField", "denominatorField", "defaultDateField",
        "flowSemantics"
      ]);
      field(config.grossLossField, "grossLossField");
      field(config.recoveryField, "recoveryField");
      field(config.denominatorField, "denominatorField");
      field(config.defaultDateField, "defaultDateField");
      oneOf(config.flowSemantics, "flowSemantics", ["period", "cumulative"]);
      return;
    case "paydown_prepayment":
      exactKeys(config, "paydown/prepayment configuration", [
        "kind", "balanceField", "scheduledPrincipalField"
      ]);
      field(config.balanceField, "balanceField");
      validateFieldIfPresent(config.scheduledPrincipalField, "scheduledPrincipalField");
      return;
    case "rating_migration":
      exactKeys(config, "rating-migration configuration", ["kind", "ratingField", "balanceField"]);
      field(config.ratingField, "ratingField");
      field(config.balanceField, "balanceField");
      return;
    case "balance_utilization":
      exactKeys(config, "balance/utilization configuration", [
        "kind", "balanceField", "originalBalanceField", "commitmentField", "cohortDefinitionId"
      ]);
      field(config.balanceField, "balanceField");
      field(config.originalBalanceField, "originalBalanceField");
      field(config.commitmentField, "commitmentField");
      validateFieldIfPresent(config.cohortDefinitionId, "cohortDefinitionId", identifier);
      return;
    case "maturity_wall": {
      exactKeys(config, "maturity-wall configuration", [
        "kind", "maturityDateField", "balanceField", "windows", "includeMatured"
      ]);
      field(config.maturityDateField, "maturityDateField");
      field(config.balanceField, "balanceField");
      if (config.windows.length < 1 || config.windows.length > 50) {
        throw new Error("Maturity wall requires between 1 and 50 windows");
      }
      let previous = -1;
      const labels = new Set<string>();
      for (const window of config.windows) {
        exactKeys(window, "maturity window", ["label", "endingMonth"]);
        label(window.label, "maturity window label");
        if (labels.has(window.label)) throw new Error(`Duplicate maturity window label: ${window.label}`);
        labels.add(window.label);
        boundedInteger(window.endingMonth, "maturity endingMonth", 0, 1_200);
        if (window.endingMonth <= previous) throw new Error("Maturity windows must be strictly increasing");
        previous = window.endingMonth;
      }
      return;
    }
    case "concentration":
      exactKeys(config, "concentration configuration", [
        "kind", "dimensionField", "balanceField", "topN", "binDefinitionId",
        "entityResolutionDefinitionId"
      ]);
      field(config.dimensionField, "dimensionField");
      field(config.balanceField, "balanceField");
      boundedInteger(config.topN, "topN", 1, 50);
      validateFieldIfPresent(config.binDefinitionId, "binDefinitionId", identifier);
      validateFieldIfPresent(config.entityResolutionDefinitionId, "entityResolutionDefinitionId", identifier);
      return;
    case "period_comparison":
      exactKeys(config, "period-comparison configuration", ["kind", "balanceField", "dimensionField"]);
      field(config.balanceField, "balanceField");
      validateFieldIfPresent(config.dimensionField, "dimensionField");
      return;
    default:
      throw new Error("Unknown metric configuration kind");
  }
}

function validateDefinitionIdentity(definitionId: string, version: number, name: string): void {
  identifier(definitionId, "definitionId");
  boundedInteger(version, "definition version", 1, 1_000_000);
  label(name, "definition name");
}

function validateApproval(approval: DefinitionApprovalV1): void {
  exactKeys(approval, "definition approval", ["status", "proposedBy", "approvedBy", "approvedAt"]);
  if (approval.status !== "approved") throw new Error("Definition must be approved");
  identifier(approval.proposedBy, "proposedBy");
  identifier(approval.approvedBy, "approvedBy");
  if (approval.proposedBy === approval.approvedBy) {
    throw new Error("Definition approver must differ from proposer");
  }
  parseIsoTimestamp(approval.approvedAt, "approvedAt");
}

function validateMeasure(
  measure: MetricDefinitionV1["numerator"],
  labelText: string
): void {
  exactKeys(measure, labelText, ["label", "aggregation", "field", "predicate"]);
  label(measure.label, `${labelText} label`);
  oneOf(measure.aggregation, `${labelText} aggregation`, ["count", "sum", "weighted_average"]);
  if (measure.aggregation !== "count" && measure.field === undefined) {
    throw new Error(`${labelText} field is required for ${measure.aggregation}`);
  }
  validateFieldIfPresent(measure.field, `${labelText} field`);
  if (measure.predicate) validateFilterExpressionV1(measure.predicate);
}

function parseBin(bin: NumericBinV1): ValidatedNumericBinV1 {
  return {
    label: bin.label,
    lower: bin.lower === undefined ? null : decimal(bin.lower, `bin ${bin.label} lower`),
    upper: bin.upper === undefined ? null : decimal(bin.upper, `bin ${bin.label} upper`),
    includeLower: bin.includeLower !== false,
    includeUpper: bin.includeUpper === true
  };
}

function validateScalar(value: FilterScalarV1, labelText: string): void {
  if (typeof value === "boolean") return;
  if (typeof value !== "string" || value.length > 512 || value.trim() !== value) {
    throw new Error(`${labelText} must be a boolean or trimmed string of at most 512 characters`);
  }
}

function scalarEquals(raw: unknown, expected: FilterScalarV1): boolean {
  return typeof raw === typeof expected && raw === expected;
}

function validateFieldIfPresent(
  value: string | undefined,
  labelText: string,
  validator: (value: string, labelText: string) => void = field
): void {
  if (value !== undefined) validator(value, labelText);
}

function identifier(value: string, labelText: string): void {
  if (!IDENTIFIER.test(value)) throw new Error(`${labelText} is not a valid identifier`);
}

function field(value: string, labelText: string): void {
  if (!FIELD.test(value)) throw new Error(`${labelText} is not a valid canonical field name`);
}

function label(value: string, labelText: string): void {
  if (value.length < 1 || value.length > 128 || value.trim() !== value) {
    throw new Error(`${labelText} must be trimmed and contain between 1 and 128 characters`);
  }
}

function boundedInteger(value: number, labelText: string, minimum: number, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${labelText} must be an integer between ${minimum} and ${maximum}`);
  }
}

function decimal(value: string, labelText: string): Decimal {
  if (!CANONICAL_DECIMAL.test(value) || value.length > 256) {
    throw new Error(`${labelText} must be an exact canonical decimal string`);
  }
  const parsed = new ExactDecimal(value);
  if (!parsed.isFinite()) throw new Error(`${labelText} must be finite`);
  return parsed;
}

function parseIsoDate(value: string, labelText: string): void {
  const match = ISO_DATE.exec(value);
  if (!match) throw new Error(`${labelText} must be a valid YYYY-MM-DD date`);
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    throw new Error(`${labelText} must be a valid YYYY-MM-DD date`);
  }
}

function parseIsoTimestamp(value: string, labelText: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) {
    throw new Error(`${labelText} must be an ISO-8601 UTC timestamp`);
  }
  if (!Number.isFinite(Date.parse(value))) throw new Error(`${labelText} must be a valid timestamp`);
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, item]) => item !== undefined)
        .sort(([left], [right]) => compareText(left, right))
        .map(([key, item]) => [key, canonicalize(item)])
    );
  }
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new Error("Cannot fingerprint a non-finite number");
  }
  return value;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function exactKeys(value: object, labelText: string, allowed: readonly string[]): void {
  const allowedKeys = new Set(allowed);
  const extra = Object.keys(value).filter((key) => !allowedKeys.has(key)).sort(compareText);
  if (extra.length > 0) throw new Error(`${labelText} contains unsupported fields: ${extra.join(", ")}`);
}

function oneOf(value: string, labelText: string, allowed: readonly string[]): void {
  if (!allowed.includes(value)) throw new Error(`${labelText} must be one of: ${allowed.join(", ")}`);
}
