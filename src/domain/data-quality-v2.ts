import { Decimal } from "decimal.js";

import { canonicalHash } from "../contracts/canonical.js";

const ExactDecimal = Decimal.clone({ precision: 50, rounding: Decimal.ROUND_HALF_EVEN });

export type ProfileLogicalTypeV2 = "null" | "boolean" | "integer" | "decimal" | "date" | "datetime" | "text";
export type DataQualitySeverityV2 = "info" | "warning" | "error" | "critical";

export interface SourceFieldProfileV2 {
  readonly field: string;
  readonly observedTypes: readonly ProfileLogicalTypeV2[];
  readonly rowCount: number;
  readonly nullCount: number;
  readonly nullShare: string;
  readonly distinctCount: number;
  readonly uniquenessShare: string;
  readonly minimum: string | null;
  readonly maximum: string | null;
  readonly topValues: readonly { readonly value: string; readonly count: number; readonly share: string }[];
  readonly inferredUnit: "currency" | "percentage" | "days" | "date" | "identifier" | "unknown";
  readonly temporalKind: "stock" | "flow" | "event" | "lifetime_to_date" | "unknown";
  readonly profileHash: string;
}

export interface SourceProfileV2 {
  readonly schemaVersion: 2;
  readonly rowCount: number;
  readonly populationHash: string;
  readonly schemaHash: string;
  readonly fields: readonly SourceFieldProfileV2[];
  readonly profileHash: string;
}

export interface SourceProfileDriftV2 {
  readonly field: string;
  readonly kind: "added" | "removed" | "type" | "null_share" | "category";
  readonly material: boolean;
  readonly previous: string | null;
  readonly current: string | null;
}

export type DataQualityRuleV2 =
  | { readonly ruleId: string; readonly type: "required"; readonly field: string; readonly severity: DataQualitySeverityV2; readonly blocking: boolean }
  | { readonly ruleId: string; readonly type: "unique"; readonly field: string; readonly severity: DataQualitySeverityV2; readonly blocking: boolean }
  | { readonly ruleId: string; readonly type: "allowed_values"; readonly field: string; readonly values: readonly string[]; readonly severity: DataQualitySeverityV2; readonly blocking: boolean }
  | { readonly ruleId: string; readonly type: "decimal_range"; readonly field: string; readonly minimum?: string; readonly maximum?: string; readonly severity: DataQualitySeverityV2; readonly blocking: boolean }
  | { readonly ruleId: string; readonly type: "equals_sum"; readonly field: string; readonly addends: readonly string[]; readonly tolerance: string; readonly severity: DataQualitySeverityV2; readonly blocking: boolean };

export interface DataQualityFindingV2 {
  readonly findingId: string;
  readonly ruleId: string;
  readonly severity: DataQualitySeverityV2;
  readonly blocking: boolean;
  readonly passed: boolean;
  readonly affectedRows: number;
  readonly affectedBalance: string;
  readonly affectedShare: string;
  readonly field: string;
  readonly expected: string;
  readonly actual: string;
  readonly populationHash: string;
  readonly materiality: "immaterial" | "material";
  readonly remediationRef: string | null;
  readonly findingHash: string;
}

export interface DataQualityResultV2 {
  readonly schemaVersion: 2;
  readonly populationHash: string;
  readonly rowCount: number;
  readonly balance: string;
  readonly findings: readonly DataQualityFindingV2[];
  readonly publicationDecision: "publish" | "block";
  readonly resultHash: string;
}

export interface SegmentedControlTotalV2 {
  readonly dimensions: Readonly<Record<string, string>>;
  readonly rowCount: number;
  readonly balance: string;
  readonly currency: string;
}

export interface SegmentedReconciliationResultV2 {
  readonly schemaVersion: 2;
  readonly dimensions: readonly string[];
  readonly checks: readonly {
    readonly key: string;
    readonly expectedRows: number;
    readonly actualRows: number;
    readonly expectedBalance: string;
    readonly actualBalance: string;
    readonly difference: string;
    readonly currency: string;
    readonly passed: boolean;
    readonly populationHash: string;
  }[];
  readonly passed: boolean;
  readonly resultHash: string;
}

export function profileSourceV2(
  records: readonly Readonly<Record<string, null | boolean | string>>[],
  options: { readonly maximumRows?: number; readonly maximumFields?: number; readonly topValues?: number } = {}
): SourceProfileV2 {
  const maximumRows = bound(options.maximumRows ?? 1_000_000, 1, 1_000_000, "maximumRows");
  const maximumFields = bound(options.maximumFields ?? 2_000, 1, 2_000, "maximumFields");
  const topLimit = bound(options.topValues ?? 20, 1, 100, "topValues");
  if (!Array.isArray(records) || records.length > maximumRows) invalid("Source profile row bound exceeded");
  const fields = [...new Set(records.flatMap((record) => Object.keys(record)))].sort();
  if (fields.length > maximumFields) invalid("Source profile field bound exceeded");
  const populationHash = canonicalHash(records as never);
  const profiles = fields.map((field): SourceFieldProfileV2 => {
    const values = records.map((record) => record[field] ?? null);
    const nullCount = values.filter((value) => value === null).length;
    const nonNull = values.filter((value): value is string | boolean => value !== null);
    const counts = new Map<string, number>();
    for (const value of nonNull) {
      const key = typeof value === "boolean" ? String(value) : value;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    const observedTypes = [...new Set(values.map(classify))].sort();
    const ordered = [...nonNull].map(String).sort(compareProfileValue);
    const body = {
      field,
      observedTypes,
      rowCount: records.length,
      nullCount,
      nullShare: ratio(nullCount, records.length),
      distinctCount: counts.size,
      uniquenessShare: ratio(counts.size, nonNull.length),
      minimum: ordered[0] ?? null,
      maximum: ordered.at(-1) ?? null,
      topValues: [...counts.entries()]
        .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
        .slice(0, topLimit)
        .map(([value, count]) => ({ value, count, share: ratio(count, nonNull.length) })),
      inferredUnit: inferUnit(field),
      temporalKind: inferTemporal(field)
    } as const;
    return Object.freeze({ ...body, profileHash: canonicalHash(body as never) });
  });
  const schemaShape = profiles.map((profile) => ({ field: profile.field, observedTypes: profile.observedTypes }));
  const body = {
    schemaVersion: 2 as const,
    rowCount: records.length,
    populationHash,
    schemaHash: canonicalHash(schemaShape as never),
    fields: Object.freeze(profiles)
  };
  return Object.freeze({ ...body, profileHash: canonicalHash(body as never) });
}

export function compareSourceProfilesV2(
  previous: SourceProfileV2,
  current: SourceProfileV2,
  options: { readonly nullShareThreshold?: string; readonly categoryShareThreshold?: string } = {}
): readonly SourceProfileDriftV2[] {
  const nullThreshold = exact(options.nullShareThreshold ?? "0.05");
  const categoryThreshold = exact(options.categoryShareThreshold ?? "0.1");
  const prior = new Map(previous.fields.map((field) => [field.field, field]));
  const next = new Map(current.fields.map((field) => [field.field, field]));
  const result: SourceProfileDriftV2[] = [];
  for (const field of [...new Set([...prior.keys(), ...next.keys()])].sort()) {
    const left = prior.get(field);
    const right = next.get(field);
    if (!left) { result.push({ field, kind: "added", material: true, previous: null, current: right!.profileHash }); continue; }
    if (!right) { result.push({ field, kind: "removed", material: true, previous: left.profileHash, current: null }); continue; }
    if (left.observedTypes.join("|") !== right.observedTypes.join("|")) {
      result.push({ field, kind: "type", material: true, previous: left.observedTypes.join("|"), current: right.observedTypes.join("|") });
    }
    const nullDelta = exact(right.nullShare).minus(exact(left.nullShare)).abs();
    if (!nullDelta.isZero()) result.push({ field, kind: "null_share", material: nullDelta.greaterThanOrEqualTo(nullThreshold), previous: left.nullShare, current: right.nullShare });
    const leftTop = new Map(left.topValues.map((value) => [value.value, value.share]));
    const rightTop = new Map(right.topValues.map((value) => [value.value, value.share]));
    const maxCategoryDelta = [...new Set([...leftTop.keys(), ...rightTop.keys()])].reduce(
      (maximum, key) => Decimal.max(maximum, exact(rightTop.get(key) ?? "0").minus(exact(leftTop.get(key) ?? "0")).abs()),
      exact("0")
    );
    if (!maxCategoryDelta.isZero()) result.push({ field, kind: "category", material: maxCategoryDelta.greaterThanOrEqualTo(categoryThreshold), previous: left.profileHash, current: right.profileHash });
  }
  return Object.freeze(result);
}

export function runDataQualityV2(input: {
  readonly records: readonly Readonly<Record<string, null | boolean | string>>[];
  readonly rules: readonly DataQualityRuleV2[];
  readonly balanceField: string;
  readonly materialBalance: string;
  readonly remediationRefs?: Readonly<Record<string, string>>;
}): DataQualityResultV2 {
  if (!Array.isArray(input.records) || input.records.length > 1_000_000) invalid("Data-quality row bound exceeded");
  if (!Array.isArray(input.rules) || input.rules.length > 1_000) invalid("Data-quality rule bound exceeded");
  const populationHash = canonicalHash(input.records as never);
  const balances = input.records.map((record) => money(record[input.balanceField] ?? null));
  const totalBalance = balances.reduce((sum, value) => sum.plus(value), exact("0"));
  const materialBalance = exact(input.materialBalance);
  const findings = input.rules.map((rule, ruleIndex) => {
    validateRule(rule);
    const affected: number[] = [];
    if (rule.type === "unique") {
      const seen = new Map<string, number[]>();
      input.records.forEach((record, index) => {
        const value = record[rule.field] ?? null;
        if (value !== null) {
          const key = String(value);
          const list = seen.get(key) ?? [];
          list.push(index);
          seen.set(key, list);
        }
      });
      for (const indexes of seen.values()) if (indexes.length > 1) affected.push(...indexes);
    } else {
      input.records.forEach((record, index) => {
        const value = record[rule.field] ?? null;
        if (violates(rule, value, record)) affected.push(index);
      });
    }
    const uniqueAffected = [...new Set(affected)].sort((left, right) => left - right);
    const affectedBalance = uniqueAffected.reduce((sum, index) => sum.plus(balances[index]!), exact("0"));
    const expected = expectedText(rule);
    const body = {
      findingId: `${rule.ruleId}-${String(ruleIndex + 1).padStart(4, "0")}`,
      ruleId: rule.ruleId,
      severity: rule.severity,
      blocking: rule.blocking,
      passed: uniqueAffected.length === 0,
      affectedRows: uniqueAffected.length,
      affectedBalance: decimalText(affectedBalance),
      affectedShare: totalBalance.isZero() ? "0" : decimalText(affectedBalance.div(totalBalance.abs())),
      field: rule.field,
      expected,
      actual: uniqueAffected.length === 0 ? "conforming" : `${uniqueAffected.length} rows`,
      populationHash,
      materiality: affectedBalance.abs().greaterThanOrEqualTo(materialBalance) ? "material" as const : "immaterial" as const,
      remediationRef: input.remediationRefs?.[rule.ruleId] ?? null
    };
    return Object.freeze({ ...body, findingHash: canonicalHash(body as never) });
  });
  const body = {
    schemaVersion: 2 as const,
    populationHash,
    rowCount: input.records.length,
    balance: decimalText(totalBalance),
    findings: Object.freeze(findings),
    publicationDecision: findings.some((finding) => finding.blocking && !finding.passed) ? "block" as const : "publish" as const
  };
  return Object.freeze({ ...body, resultHash: canonicalHash(body as never) });
}

export function reconcileSegmentsV2(input: {
  readonly records: readonly Readonly<Record<string, null | boolean | string>>[];
  readonly dimensions: readonly string[];
  readonly balanceField: string;
  readonly currencyField: string;
  readonly expected: readonly SegmentedControlTotalV2[];
  readonly balanceTolerance: string;
}): SegmentedReconciliationResultV2 {
  if (input.dimensions.length < 1 || input.dimensions.length > 5 || new Set(input.dimensions).size !== input.dimensions.length) invalid("Reconciliation dimensions are invalid");
  const tolerance = exact(input.balanceTolerance);
  if (tolerance.isNegative()) invalid("Reconciliation tolerance cannot be negative");
  const populationHash = canonicalHash(input.records as never);
  const actual = new Map<string, { rows: number; balance: Decimal; currency: string }>();
  for (const record of input.records) {
    const dimensions = Object.fromEntries(input.dimensions.map((field) => [field, scalarText(record[field] ?? null)]));
    const currency = scalarText(record[input.currencyField] ?? null);
    if (!/^[A-Z]{3}$/u.test(currency)) invalid("Record currency is invalid");
    const key = segmentKey(dimensions, currency);
    const group = actual.get(key) ?? { rows: 0, balance: exact("0"), currency };
    group.rows += 1;
    group.balance = group.balance.plus(money(record[input.balanceField] ?? null));
    actual.set(key, group);
  }
  const expected = new Map<string, SegmentedControlTotalV2>();
  for (const total of input.expected) {
    if (Object.keys(total.dimensions).sort().join("|") !== [...input.dimensions].sort().join("|")) invalid("Expected segment dimensions do not match definition");
    const key = segmentKey(total.dimensions, total.currency);
    if (expected.has(key)) invalid("Duplicate expected segment");
    expected.set(key, total);
  }
  const checks = [...new Set([...expected.keys(), ...actual.keys()])].sort().map((key) => {
    const declared = expected.get(key);
    const observed = actual.get(key);
    const expectedBalance = exact(declared?.balance ?? "0");
    const actualBalance = observed?.balance ?? exact("0");
    const difference = actualBalance.minus(expectedBalance);
    return Object.freeze({
      key,
      expectedRows: declared?.rowCount ?? 0,
      actualRows: observed?.rows ?? 0,
      expectedBalance: decimalText(expectedBalance),
      actualBalance: decimalText(actualBalance),
      difference: decimalText(difference),
      currency: declared?.currency ?? observed?.currency ?? "",
      passed: (declared?.rowCount ?? 0) === (observed?.rows ?? 0) && difference.abs().lessThanOrEqualTo(tolerance),
      populationHash
    });
  });
  const body = {
    schemaVersion: 2 as const,
    dimensions: Object.freeze([...input.dimensions]),
    checks: Object.freeze(checks),
    passed: checks.every((check) => check.passed)
  };
  return Object.freeze({ ...body, resultHash: canonicalHash(body as never) });
}

function violates(rule: DataQualityRuleV2, value: null | boolean | string, record: Readonly<Record<string, null | boolean | string>>): boolean {
  if (rule.type === "required") return value === null || value === "";
  if (rule.type === "allowed_values") return value !== null && !rule.values.includes(String(value));
  if (rule.type === "decimal_range") {
    if (value === null || typeof value !== "string") return value !== null;
    let parsed: Decimal;
    try { parsed = exact(value); } catch { return true; }
    return (rule.minimum !== undefined && parsed.lessThan(exact(rule.minimum))) || (rule.maximum !== undefined && parsed.greaterThan(exact(rule.maximum)));
  }
  if (rule.type === "equals_sum") {
    if (value === null || typeof value !== "string") return true;
    try {
      const expected = rule.addends.reduce((sum, field) => sum.plus(money(record[field] ?? null)), exact("0"));
      return exact(value).minus(expected).abs().greaterThan(exact(rule.tolerance));
    } catch { return true; }
  }
  return false;
}

function validateRule(rule: DataQualityRuleV2): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/u.test(rule.ruleId)) invalid("Rule id is invalid");
  if (!rule.field || rule.field.length > 256) invalid("Rule field is invalid");
  if (!(["info", "warning", "error", "critical"] as const).includes(rule.severity)) invalid("Rule severity is invalid");
  if (rule.type === "allowed_values" && (rule.values.length < 1 || rule.values.length > 10_000)) invalid("Allowed-value rule is invalid");
  if (rule.type === "decimal_range") {
    if (rule.minimum === undefined && rule.maximum === undefined) invalid("Decimal range needs a bound");
    if (rule.minimum !== undefined) exact(rule.minimum);
    if (rule.maximum !== undefined) exact(rule.maximum);
  }
  if (rule.type === "equals_sum") {
    if (rule.addends.length < 1 || rule.addends.length > 32) invalid("Arithmetic rule addends are invalid");
    exact(rule.tolerance);
  }
}

function expectedText(rule: DataQualityRuleV2): string {
  if (rule.type === "required") return "non-null";
  if (rule.type === "unique") return "unique";
  if (rule.type === "allowed_values") return `one of ${rule.values.length} governed values`;
  if (rule.type === "decimal_range") return `${rule.minimum ?? "-infinity"}..${rule.maximum ?? "infinity"}`;
  return `equals sum(${rule.addends.join(",")}) within ${rule.tolerance}`;
}

function classify(value: null | boolean | string): ProfileLogicalTypeV2 {
  if (value === null) return "null";
  if (typeof value === "boolean") return "boolean";
  if (/^-?(?:0|[1-9]\d*)$/u.test(value)) return "integer";
  if (/^-?(?:0|[1-9]\d*)\.\d+$/u.test(value)) return "decimal";
  if (/^\d{4}-\d{2}-\d{2}$/u.test(value)) return "date";
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value)) return "datetime";
  return "text";
}

function inferUnit(field: string): SourceFieldProfileV2["inferredUnit"] {
  const normalized = field.toLowerCase();
  if (/(?:balance|amount|price|value|cost|reserve|commitment)/u.test(normalized)) return "currency";
  if (/(?:rate|percent|pct|ltv)/u.test(normalized)) return "percentage";
  if (/(?:days|dpd|age)/u.test(normalized)) return "days";
  if (/(?:date|_at$)/u.test(normalized)) return "date";
  if (/(?:^id$|_id$|number$|_no$)/u.test(normalized)) return "identifier";
  return "unknown";
}

function inferTemporal(field: string): SourceFieldProfileV2["temporalKind"] {
  const normalized = field.toLowerCase();
  if (/(?:cumulative|lifetime|_ltd)/u.test(normalized)) return "lifetime_to_date";
  if (/(?:payment|charge|recovery|advance|flow)/u.test(normalized)) return "flow";
  if (/(?:event|default_date|modification_date)/u.test(normalized)) return "event";
  if (/(?:balance|status|rating|utilization)/u.test(normalized)) return "stock";
  return "unknown";
}

function compareProfileValue(left: string, right: string): number {
  const leftNumeric = /^-?(?:0|[1-9]\d*)(?:\.\d+)?$/u.test(left);
  const rightNumeric = /^-?(?:0|[1-9]\d*)(?:\.\d+)?$/u.test(right);
  if (leftNumeric && rightNumeric) return exact(left).comparedTo(exact(right));
  return left.localeCompare(right);
}

function ratio(numerator: number, denominator: number): string {
  return denominator === 0 ? "0" : decimalText(exact(String(numerator)).div(String(denominator)));
}

function money(value: null | boolean | string): Decimal {
  if (value === null) return exact("0");
  if (typeof value !== "string") invalid("Balance value must be an exact decimal string");
  return exact(value);
}

function scalarText(value: null | boolean | string): string {
  if (value === null) return "[NULL]";
  return String(value);
}

function segmentKey(dimensions: Readonly<Record<string, string>>, currency: string): string {
  return canonicalHash({ dimensions, currency } as never);
}

function exact(value: string): Decimal {
  if (!/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/u.test(value)) invalid("Value must be an exact decimal string");
  try { return new ExactDecimal(value); } catch { invalid("Value must be an exact decimal string"); }
}

function decimalText(value: Decimal): string {
  const text = value.toFixed();
  const normalized = text.includes(".") ? text.replace(/\.?0+$/u, "") : text;
  return normalized === "-0" || normalized === "" ? "0" : normalized;
}

function bound(value: number, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalid(`${label} is outside its bound`);
  return value;
}

function invalid(message: string): never {
  throw new Error(message);
}
