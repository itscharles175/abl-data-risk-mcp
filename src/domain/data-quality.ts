import { createHash } from "node:crypto";

import { Decimal } from "decimal.js";

export type DataQualitySeverity = "critical" | "error" | "warning";
export type PublicationDecision = "publish" | "block";
export type AsOfMode = "exact" | "through";

export interface DateOrderRule {
  readonly earlierField: string;
  readonly laterField: string;
  readonly allowEqual?: boolean;
}

export interface StatusConsistencyRule {
  readonly statusField: string;
  readonly daysPastDueField: string;
  readonly currentStatuses: readonly string[];
  readonly delinquentStatuses: readonly string[];
  readonly delinquentThresholdDays: number;
}

export interface DataQualityProfile {
  readonly id: string;
  readonly version: string;
  readonly entity: "loan_snapshot" | "loan_history" | "receivable_snapshot" | "collateral_snapshot";
  readonly keyFields: readonly string[];
  readonly requiredFields: readonly string[];
  readonly balanceField: string;
  readonly asOfField: string;
  readonly expectedAsOfDate: string;
  /**
   * `exact` certifies a point-in-time snapshot. `through` certifies a
   * longitudinal population whose rows may precede, but never follow, the
   * declared cutoff. Loan-history profiles default to `through`; all other
   * entities default to `exact`.
   */
  readonly asOfMode?: AsOfMode;
  readonly currencyField?: string;
  readonly expectedCurrency?: string;
  readonly exactDecimalFields?: readonly string[];
  readonly nonNegativeFields?: readonly string[];
  readonly dateFields?: readonly string[];
  readonly dateOrderRules?: readonly DateOrderRule[];
  readonly allowedValues?: Readonly<Record<string, readonly string[]>>;
  readonly maximumNullRates?: Readonly<Record<string, number>>;
  readonly statusConsistency?: StatusConsistencyRule;
  readonly maximumSnapshotAgeDays?: number;
}

export interface DataQualityFinding {
  readonly code: string;
  readonly severity: DataQualitySeverity;
  readonly field?: string;
  readonly affectedRows: number;
  readonly affectedBalance: string;
  readonly message: string;
}

export interface DataQualityResult {
  readonly profileId: string;
  readonly profileVersion: string;
  readonly entity: DataQualityProfile["entity"];
  readonly expectedAsOfDate: string;
  readonly asOfMode: AsOfMode;
  readonly evaluatedAt: string;
  readonly recordCount: number;
  readonly totalBalance: string;
  readonly currency: string | null;
  readonly findings: readonly DataQualityFinding[];
  readonly summary: {
    readonly critical: number;
    readonly error: number;
    readonly warning: number;
  };
  readonly publicationDecision: PublicationDecision;
  readonly fingerprint: string;
}

export interface ControlTotals {
  readonly rowCount: number;
  readonly balance: string;
  readonly currency?: string;
}

export interface ReconciliationTolerance {
  readonly rowCount: number;
  readonly balance: string;
}

export interface ReconciliationResult {
  readonly passed: boolean;
  readonly declared: ControlTotals;
  readonly actual: ControlTotals;
  readonly difference: {
    readonly rowCount: number;
    readonly balance: string;
  };
  readonly tolerance: ReconciliationTolerance;
  readonly reasonCodes: readonly string[];
  readonly fingerprint: string;
}

type CanonicalRecord = Readonly<Record<string, unknown>>;

interface MutableFinding {
  readonly code: string;
  readonly severity: DataQualitySeverity;
  readonly field?: string;
  affectedRows: number;
  affectedBalance: Decimal;
  readonly message: string;
}

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Evaluates canonical records without returning raw identifiers or values. The
 * result is deterministic for the same ordered or unordered record set.
 */
export function runDataQuality(
  records: readonly CanonicalRecord[],
  profile: DataQualityProfile,
  evaluatedAt: string = new Date().toISOString()
): DataQualityResult {
  validateProfile(profile);
  const findings = new Map<string, MutableFinding>();
  const requiredFields = new Set(profile.requiredFields);
  const exactDecimalFields = new Set([profile.balanceField, ...(profile.exactDecimalFields ?? [])]);
  const nonNegativeFields = new Set([profile.balanceField, ...(profile.nonNegativeFields ?? [])]);
  const dateFields = new Set([profile.asOfField, ...(profile.dateFields ?? [])]);
  const keys = new Map<string, number>();
  const currencies = new Set<string>();
  const evaluatedAtNormalized = normalizeTimestamp(evaluatedAt, "evaluatedAt");
  const asOfMode = effectiveAsOfMode(profile);
  const expectedAsOfDate = parseIsoDate(profile.expectedAsOfDate)!;
  let hasCutoffRecord = false;
  let totalBalance = new Decimal(0);

  if (records.length === 0) {
    addFinding(findings, {
      code: "empty_snapshot",
      severity: "critical",
      affectedRows: 0,
      affectedBalance: new Decimal(0),
      message: "The snapshot contains no records"
    });
  }

  for (const record of records) {
    const balance = parseDecimal(record[profile.balanceField]);
    const rowBalance = balance ?? new Decimal(0);
    if (balance) totalBalance = totalBalance.plus(balance);

    for (const field of requiredFields) {
      if (!hasValue(record[field])) {
        addRowFinding(
          findings,
          "required_value_missing",
          "critical",
          field,
          rowBalance,
          `Required field ${field} contains null or blank values`
        );
      }
    }

    const keyParts = profile.keyFields.map((field) => normalizeKeyPart(record[field]));
    if (keyParts.some((part) => part === null)) {
      addRowFinding(
        findings,
        "grain_key_missing",
        "critical",
        profile.keyFields.join(","),
        rowBalance,
        "One or more declared grain-key fields are missing"
      );
    } else {
      const key = JSON.stringify(keyParts);
      keys.set(key, (keys.get(key) ?? 0) + 1);
    }

    for (const field of exactDecimalFields) {
      const value = record[field];
      if (!hasValue(value)) continue;
      if (typeof value !== "string" || parseDecimal(value) === null) {
        addRowFinding(
          findings,
          "exact_decimal_invalid",
          "critical",
          field,
          rowBalance,
          `Exact decimal field ${field} must be a finite decimal string`
        );
      }
    }

    for (const field of nonNegativeFields) {
      const value = record[field];
      if (!hasValue(value)) continue;
      const decimal = parseDecimal(value);
      if (!decimal) {
        addRowFinding(
          findings,
          "numeric_value_invalid",
          "critical",
          field,
          rowBalance,
          `Numeric field ${field} contains values that cannot be parsed`
        );
      } else if (decimal.isNegative()) {
        addRowFinding(
          findings,
          "negative_value",
          "error",
          field,
          rowBalance,
          `Non-negative field ${field} contains negative values`
        );
      }
    }

    for (const field of dateFields) {
      const value = record[field];
      if (!hasValue(value)) continue;
      if (parseIsoDate(value) === null) {
        addRowFinding(
          findings,
          "date_value_invalid",
          "critical",
          field,
          rowBalance,
          `Date field ${field} must use a valid YYYY-MM-DD value`
        );
      }
    }

    const rowAsOfDate = parseIsoDate(record[profile.asOfField]);
    if (rowAsOfDate?.getTime() === expectedAsOfDate.getTime()) hasCutoffRecord = true;
    if (asOfMode === "exact") {
      if (record[profile.asOfField] !== profile.expectedAsOfDate) {
        addRowFinding(
          findings,
          "as_of_date_mismatch",
          "critical",
          profile.asOfField,
          rowBalance,
          `Snapshot rows must match the declared as-of date ${profile.expectedAsOfDate}`
        );
      }
    } else if (rowAsOfDate && rowAsOfDate > expectedAsOfDate) {
      addRowFinding(
        findings,
        "as_of_date_after_cutoff",
        "critical",
        profile.asOfField,
        rowBalance,
        `Historical rows cannot follow the declared cutoff date ${profile.expectedAsOfDate}`
      );
    }

    for (const rule of profile.dateOrderRules ?? []) {
      const earlier = parseIsoDate(record[rule.earlierField]);
      const later = parseIsoDate(record[rule.laterField]);
      if (!earlier || !later) continue;
      const invalid = rule.allowEqual === false ? earlier >= later : earlier > later;
      if (invalid) {
        addRowFinding(
          findings,
          "date_order_invalid",
          "error",
          `${rule.earlierField},${rule.laterField}`,
          rowBalance,
          `${rule.earlierField} must ${rule.allowEqual === false ? "precede" : "not follow"} ${rule.laterField}`
        );
      }
    }

    for (const [field, allowed] of Object.entries(profile.allowedValues ?? {})) {
      const value = record[field];
      if (!hasValue(value)) continue;
      const normalized = String(value).trim().toLowerCase();
      if (!allowed.some((candidate) => candidate.trim().toLowerCase() === normalized)) {
        addRowFinding(
          findings,
          "code_value_unknown",
          "warning",
          field,
          rowBalance,
          `Field ${field} contains values outside the governed code set`
        );
      }
    }

    if (profile.currencyField && hasValue(record[profile.currencyField])) {
      currencies.add(String(record[profile.currencyField]).trim().toUpperCase());
    }

    evaluateStatusConsistency(record, profile.statusConsistency, rowBalance, findings);
  }

  if (asOfMode === "through" && records.length > 0 && !hasCutoffRecord) {
    addFinding(findings, {
      code: "as_of_cutoff_missing",
      severity: "critical",
      field: profile.asOfField,
      affectedRows: records.length,
      affectedBalance: totalBalance,
      message: `Historical data must include at least one row at the declared cutoff date ${profile.expectedAsOfDate}`
    });
  }

  for (const count of keys.values()) {
    if (count <= 1) continue;
    addFinding(findings, {
      code: "duplicate_grain_key",
      severity: "critical",
      affectedRows: count,
      affectedBalance: new Decimal(0),
      message: "The declared snapshot grain is not unique"
    });
  }

  for (const [field, maximumRate] of Object.entries(profile.maximumNullRates ?? {})) {
    const nullCount = records.reduce((count, record) => count + (hasValue(record[field]) ? 0 : 1), 0);
    const rate = records.length === 0 ? 1 : nullCount / records.length;
    if (rate > maximumRate) {
      addFinding(findings, {
        code: "null_rate_exceeded",
        severity: "error",
        field,
        affectedRows: nullCount,
        affectedBalance: new Decimal(0),
        message: `Field ${field} exceeds its maximum allowed null rate`
      });
    }
  }

  if (currencies.size > 1) {
    addFinding(findings, {
      code: "mixed_currency_population",
      severity: "critical",
      ...(profile.currencyField ? { field: profile.currencyField } : {}),
      affectedRows: records.length,
      affectedBalance: totalBalance,
      message: "The snapshot contains multiple currencies without an approved FX basis"
    });
  }
  if (profile.expectedCurrency && (currencies.size !== 1 || !currencies.has(profile.expectedCurrency.toUpperCase()))) {
    addFinding(findings, {
      code: "currency_mismatch",
      severity: "critical",
      ...(profile.currencyField ? { field: profile.currencyField } : {}),
      affectedRows: records.length,
      affectedBalance: totalBalance,
      message: `The snapshot currency does not match ${profile.expectedCurrency.toUpperCase()}`
    });
  }

  const evaluatedDate = new Date(evaluatedAtNormalized);
  const expectedDate = parseIsoDate(profile.expectedAsOfDate);
  if (profile.maximumSnapshotAgeDays !== undefined && expectedDate && !Number.isNaN(evaluatedDate.getTime())) {
    const ageDays = Math.floor((startOfUtcDay(evaluatedDate).getTime() - expectedDate.getTime()) / 86_400_000);
    if (ageDays > profile.maximumSnapshotAgeDays) {
      addFinding(findings, {
        code: "snapshot_stale",
        severity: "critical",
        field: profile.asOfField,
        affectedRows: records.length,
        affectedBalance: totalBalance,
        message: `The snapshot is older than the permitted ${profile.maximumSnapshotAgeDays} days`
      });
    }
  }

  const orderedFindings = [...findings.values()]
    .map<DataQualityFinding>((finding) => ({
      code: finding.code,
      severity: finding.severity,
      ...(finding.field ? { field: finding.field } : {}),
      affectedRows: finding.affectedRows,
      affectedBalance: decimalString(finding.affectedBalance),
      message: finding.message
    }))
    .sort(compareFindings);
  const summary = {
    critical: orderedFindings.filter((finding) => finding.severity === "critical").length,
    error: orderedFindings.filter((finding) => finding.severity === "error").length,
    warning: orderedFindings.filter((finding) => finding.severity === "warning").length
  };
  const fingerprint = hashCanonical({
    profileId: profile.id,
    profileVersion: profile.version,
    asOfMode,
    expectedAsOfDate: profile.expectedAsOfDate,
    evaluatedAt: evaluatedAtNormalized,
    records: [...records].map(canonicalize).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))),
    findings: orderedFindings
  });

  return {
    profileId: profile.id,
    profileVersion: profile.version,
    entity: profile.entity,
    expectedAsOfDate: profile.expectedAsOfDate,
    asOfMode,
    evaluatedAt: evaluatedAtNormalized,
    recordCount: records.length,
    totalBalance: decimalString(totalBalance),
    currency: currencies.size === 1 ? [...currencies][0] ?? null : null,
    findings: orderedFindings,
    summary,
    publicationDecision: summary.critical > 0 || summary.error > 0 ? "block" : "publish",
    fingerprint
  };
}

export function reconcileControlTotals(
  declared: ControlTotals,
  actual: ControlTotals,
  tolerance: ReconciliationTolerance = { rowCount: 0, balance: "0" }
): ReconciliationResult {
  if (!Number.isSafeInteger(declared.rowCount) || declared.rowCount < 0) {
    throw new Error("Declared row count must be a non-negative safe integer");
  }
  if (!Number.isSafeInteger(actual.rowCount) || actual.rowCount < 0) {
    throw new Error("Actual row count must be a non-negative safe integer");
  }
  if (!Number.isSafeInteger(tolerance.rowCount) || tolerance.rowCount < 0) {
    throw new Error("Row-count tolerance must be a non-negative safe integer");
  }
  const declaredBalance = requiredDecimal(declared.balance, "Declared balance");
  const actualBalance = requiredDecimal(actual.balance, "Actual balance");
  const balanceTolerance = requiredDecimal(tolerance.balance, "Balance tolerance");
  if (balanceTolerance.isNegative()) throw new Error("Balance tolerance cannot be negative");

  const rowDifference = actual.rowCount - declared.rowCount;
  const balanceDifference = actualBalance.minus(declaredBalance);
  const reasonCodes: string[] = [];
  if (Math.abs(rowDifference) > tolerance.rowCount) reasonCodes.push("row_count_out_of_tolerance");
  if (balanceDifference.abs().greaterThan(balanceTolerance)) reasonCodes.push("balance_out_of_tolerance");
  const declaredCurrency = declared.currency?.trim().toUpperCase();
  const actualCurrency = actual.currency?.trim().toUpperCase();
  if (declaredCurrency !== actualCurrency) reasonCodes.push("currency_mismatch");

  const normalizedDeclared = {
    rowCount: declared.rowCount,
    balance: decimalString(declaredBalance),
    ...(declaredCurrency ? { currency: declaredCurrency } : {})
  };
  const normalizedActual = {
    rowCount: actual.rowCount,
    balance: decimalString(actualBalance),
    ...(actualCurrency ? { currency: actualCurrency } : {})
  };
  const normalizedTolerance = {
    rowCount: tolerance.rowCount,
    balance: decimalString(balanceTolerance)
  };

  return {
    passed: reasonCodes.length === 0,
    declared: normalizedDeclared,
    actual: normalizedActual,
    difference: { rowCount: rowDifference, balance: decimalString(balanceDifference) },
    tolerance: normalizedTolerance,
    reasonCodes,
    fingerprint: hashCanonical({
      declared: normalizedDeclared,
      actual: normalizedActual,
      tolerance: normalizedTolerance,
      reasonCodes
    })
  };
}

function validateProfile(profile: DataQualityProfile): void {
  if (!profile.id.trim() || !profile.version.trim()) throw new Error("Quality profile id and version are required");
  if (!["loan_snapshot", "loan_history", "receivable_snapshot", "collateral_snapshot"].includes(profile.entity)) {
    throw new Error("Quality profile entity is unsupported");
  }
  if (profile.asOfMode !== undefined && profile.asOfMode !== "exact" && profile.asOfMode !== "through") {
    throw new Error("As-of mode must be exact or through");
  }
  if (profile.keyFields.length === 0) throw new Error("At least one grain-key field is required");
  if (!ISO_DATE.test(profile.expectedAsOfDate) || parseIsoDate(profile.expectedAsOfDate) === null) {
    throw new Error("Expected as-of date must be a valid YYYY-MM-DD value");
  }
  for (const [field, rate] of Object.entries(profile.maximumNullRates ?? {})) {
    if (!field || !Number.isFinite(rate) || rate < 0 || rate > 1) {
      throw new Error("Maximum null rates must be finite values from zero through one");
    }
  }
  if (profile.statusConsistency && profile.statusConsistency.delinquentThresholdDays < 0) {
    throw new Error("Delinquency threshold cannot be negative");
  }
  if (profile.expectedCurrency && !profile.currencyField) {
    throw new Error("A currency field is required when expectedCurrency is configured");
  }
}

function effectiveAsOfMode(profile: DataQualityProfile): AsOfMode {
  return profile.asOfMode ?? (profile.entity === "loan_history" ? "through" : "exact");
}

function evaluateStatusConsistency(
  record: CanonicalRecord,
  rule: StatusConsistencyRule | undefined,
  balance: Decimal,
  findings: Map<string, MutableFinding>
): void {
  if (!rule) return;
  const statusValue = record[rule.statusField];
  const dpdValue = record[rule.daysPastDueField];
  if (!hasValue(statusValue) || !hasValue(dpdValue)) return;
  const dpd = parseDecimal(dpdValue);
  if (!dpd) return;
  const status = String(statusValue).trim().toLowerCase();
  const current = rule.currentStatuses.some((candidate) => candidate.trim().toLowerCase() === status);
  const delinquent = rule.delinquentStatuses.some((candidate) => candidate.trim().toLowerCase() === status);
  if ((current && dpd.greaterThanOrEqualTo(rule.delinquentThresholdDays)) ||
      (delinquent && dpd.lessThan(rule.delinquentThresholdDays))) {
    addRowFinding(
      findings,
      "status_delinquency_inconsistent",
      "error",
      `${rule.statusField},${rule.daysPastDueField}`,
      balance,
      "Loan status and days-past-due classification are inconsistent"
    );
  }
}

function addRowFinding(
  findings: Map<string, MutableFinding>,
  code: string,
  severity: DataQualitySeverity,
  field: string,
  balance: Decimal,
  message: string
): void {
  addFinding(findings, { code, severity, field, affectedRows: 1, affectedBalance: balance, message });
}

function addFinding(findings: Map<string, MutableFinding>, finding: MutableFinding): void {
  const key = `${finding.code}\u0000${finding.field ?? ""}`;
  const existing = findings.get(key);
  if (existing) {
    existing.affectedRows += finding.affectedRows;
    existing.affectedBalance = existing.affectedBalance.plus(finding.affectedBalance);
    return;
  }
  findings.set(key, { ...finding });
}

function compareFindings(left: DataQualityFinding, right: DataQualityFinding): number {
  const severityOrder: Record<DataQualitySeverity, number> = { critical: 0, error: 1, warning: 2 };
  return (
    severityOrder[left.severity] - severityOrder[right.severity] ||
    left.code.localeCompare(right.code) ||
    (left.field ?? "").localeCompare(right.field ?? "")
  );
}

function hasValue(value: unknown): boolean {
  return value !== null && value !== undefined && (typeof value !== "string" || value.trim().length > 0);
}

function normalizeKeyPart(value: unknown): string | null {
  if (!hasValue(value)) return null;
  if (typeof value === "object") return JSON.stringify(canonicalize(value));
  return String(value);
}

function parseDecimal(value: unknown): Decimal | null {
  if (typeof value !== "string" && typeof value !== "number" && typeof value !== "bigint") return null;
  if (typeof value === "string" && value.trim() === "") return null;
  try {
    const decimal = new Decimal(String(value));
    return decimal.isFinite() ? decimal : null;
  } catch {
    return null;
  }
}

function requiredDecimal(value: string, label: string): Decimal {
  const decimal = parseDecimal(value);
  if (!decimal) throw new Error(`${label} must be a finite decimal string`);
  return decimal;
}

function decimalString(value: Decimal): string {
  return value.isZero() ? "0" : value.toFixed().replace(/(\.\d*?)0+$/, "$1").replace(/\.$/, "");
}

function parseIsoDate(value: unknown): Date | null {
  if (typeof value !== "string" || !ISO_DATE.test(value)) return null;
  const [year, month, day] = value.split("-").map(Number);
  const date = new Date(Date.UTC(year!, month! - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month! - 1 && date.getUTCDate() === day
    ? date
    : null;
}

function startOfUtcDay(value: Date): Date {
  return new Date(Date.UTC(value.getUTCFullYear(), value.getUTCMonth(), value.getUTCDate()));
}

function normalizeTimestamp(value: string, label: string): string {
  const milliseconds = Date.parse(value);
  if (Number.isNaN(milliseconds)) throw new Error(`${label} must be a valid ISO timestamp`);
  return new Date(milliseconds).toISOString();
}

function hashCanonical(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(canonicalize(value))).digest("hex");
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalize(nested)])
    );
  }
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Date) return value.toISOString();
  return value;
}
