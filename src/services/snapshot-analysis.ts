import { createHash } from "node:crypto";

import { Decimal } from "decimal.js";

import { getCanonicalField, type LogicalType } from "../domain/dictionary.js";

/**
 * Canonical records are decrypted by the artifact boundary and passed to this
 * module in memory. Numeric canonical values must remain decimal strings so no
 * IEEE-754 conversion can occur before aggregation.
 */
export type CanonicalSnapshotRecord = Readonly<Record<string, unknown>>;

export interface ImmutableSnapshotLineage {
  readonly snapshotHash: string;
  readonly mappingHash: string;
  readonly dictionaryHash: string;
  readonly recipeHash: string;
}

export interface SnapshotAnalysisLineage extends ImmutableSnapshotLineage {
  readonly sourceIsImmutableSnapshot: true;
  /** Hash of the complete result, excluding this field itself. */
  readonly analysisHash: string;
}

export interface SnapshotBucketSpec {
  readonly label: string;
  /** Canonical decimal string. Lower bounds are inclusive by default. */
  readonly lower?: string;
  /** Canonical decimal string. Upper bounds are exclusive by default. */
  readonly upper?: string;
  readonly includeLower?: boolean;
  readonly includeUpper?: boolean;
}

export interface SnapshotStratificationInput {
  readonly records: readonly CanonicalSnapshotRecord[];
  readonly lineage: ImmutableSnapshotLineage;
  readonly asOfDate: string;
  readonly dimension: string;
  readonly balanceField?: string;
  readonly buckets?: readonly SnapshotBucketSpec[];
  readonly weightedAverageFields?: readonly string[];
  readonly minimumCohortSize: number;
  readonly maxRecords: number;
  readonly maxGroups: number;
}

export interface SnapshotStratificationRow {
  readonly bucket: string;
  readonly loanCount: number | null;
  readonly balance: string | null;
  readonly balanceShare: string | null;
  readonly weightedAverages: Readonly<Record<string, string | null>>;
  readonly suppressed: boolean;
}

export interface SnapshotStratificationResult {
  readonly analysisType: "snapshot_stratification";
  readonly asOfDate: string;
  readonly dimension: string;
  readonly balanceField: string;
  readonly rows: readonly SnapshotStratificationRow[];
  readonly totals: {
    readonly loanCount: number;
    readonly balance: string;
  };
  readonly reconciliation: {
    readonly passed: true;
    readonly bucketBalanceDifference: "0";
  };
  readonly lineage: SnapshotAnalysisLineage;
  readonly warnings: readonly string[];
}

export interface SnapshotVintageInput {
  readonly records: readonly CanonicalSnapshotRecord[];
  readonly lineage: ImmutableSnapshotLineage;
  readonly cohortGrain: "month" | "quarter" | "year";
  /** Inclusive reporting cutoff. When omitted, the latest record date is used. */
  readonly asOfDate?: string;
  readonly maxMonthsOnBook: number;
  readonly delinquencyThresholdDays: number;
  readonly minimumCohortSize: number;
  readonly maxRecords: number;
  readonly maxPoints: number;
}

export interface SnapshotVintagePoint {
  readonly cohort: string;
  readonly monthsOnBook: number;
  readonly seasoned: boolean;
  readonly available: boolean;
  readonly originalCohortLoanCount: number | null;
  readonly observedLoanCount: number | null;
  readonly originalCohortBalance: string | null;
  readonly currentBalance: string | null;
  readonly remainingBalanceFactor: string | null;
  readonly cumulativeNetLoss: string | null;
  readonly cumulativeNetLossRate: string | null;
  readonly delinquentBalance: string | null;
  readonly delinquentBalanceRate: string | null;
  readonly suppressed: boolean;
}

export interface SnapshotVintageResult {
  readonly analysisType: "snapshot_vintage";
  readonly cohortGrain: SnapshotVintageInput["cohortGrain"];
  readonly analysisAsOfDate: string | null;
  readonly points: readonly SnapshotVintagePoint[];
  readonly metricAvailability: {
    readonly cumulativeNetLoss: boolean;
    readonly delinquency: boolean;
  };
  readonly lineage: SnapshotAnalysisLineage;
  readonly warnings: readonly string[];
}

interface MutableStratificationGroup {
  readonly bucket: string;
  count: number;
  balance: Decimal;
  readonly weighted: Map<string, { numerator: Decimal; denominator: Decimal }>;
}

interface ParsedBucket {
  readonly label: string;
  readonly lower: Decimal | null;
  readonly upper: Decimal | null;
  readonly includeLower: boolean;
  readonly includeUpper: boolean;
}

interface PreparedVintageRecord {
  readonly loanId: string;
  readonly cohort: string;
  readonly originationDate: string;
  readonly reportingDate: string;
  readonly monthsOnBook: number;
  readonly originalBalance: Decimal;
  readonly currentBalance: Decimal;
  readonly chargeOff: Decimal | null;
  readonly recovery: Decimal | null;
  readonly daysPastDue: number | null;
  readonly sourceIndex: number;
}

interface LoanDenominator {
  readonly cohort: string;
  readonly originationDate: string;
  readonly originalBalance: Decimal;
  readonly sourceIndex: number;
}

interface VintageAggregate {
  observedLoanCount: number;
  currentBalance: Decimal;
  cumulativeNetLoss: Decimal;
  delinquentBalance: Decimal;
}

interface CohortDenominator {
  loanCount: number;
  originalBalance: Decimal;
}

const UNKNOWN_BUCKET = "Unknown/Unmapped";
const OTHER_BUCKET = "Other";
const SHA256 = /^[a-f0-9]{64}$/;
const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const CANONICAL_DECIMAL = /^-?(?:0|[1-9]\d*)(?:\.\d+)?$/;
const CANONICAL_INTEGER = /^-?(?:0|[1-9]\d*)$/;
const NUMERIC_TYPES = new Set(["integer", "decimal", "currency", "percentage"]);
const MAX_DECIMAL_DIGITS = 100;
const RATIO_SIGNIFICANT_DIGITS = 40;
const ExactDecimal = Decimal.clone({
  precision: 256,
  rounding: Decimal.ROUND_HALF_EVEN,
  toExpNeg: -1_000,
  toExpPos: 1_000
});

/**
 * Runs an in-memory stratification over an immutable canonical snapshot. This
 * function is deliberately pure with respect to the supplied records.
 */
export function runSnapshotStratification(
  input: SnapshotStratificationInput
): SnapshotStratificationResult {
  validateLineage(input.lineage);
  validateRecordLimit(input.records, input.maxRecords);
  validatePositiveInteger(input.maxGroups, "maxGroups", 10_000);
  validatePositiveInteger(input.minimumCohortSize, "minimumCohortSize", input.maxRecords);
  if (input.records.length < input.minimumCohortSize) {
    throw new Error("Stratification population is smaller than minimumCohortSize");
  }
  parseIsoDate(input.asOfDate, "asOfDate");

  const balanceField = input.balanceField ?? "outstanding_balance";
  const balanceDefinition = getCanonicalField(balanceField);
  if (!balanceDefinition || balanceDefinition.logicalType !== "currency") {
    throw new Error(`Balance field ${balanceField} must be a canonical currency field`);
  }

  const dimensionDefinition = getCanonicalField(input.dimension);
  if (!dimensionDefinition) throw new Error(`Unknown canonical dimension: ${input.dimension}`);
  if (dimensionDefinition.sensitivity === "restricted" || dimensionDefinition.logicalType === "identifier") {
    throw new Error(`Canonical dimension ${input.dimension} cannot expose identifier values`);
  }

  const numericDimension = NUMERIC_TYPES.has(dimensionDefinition.logicalType);
  if (numericDimension && (!input.buckets || input.buckets.length === 0)) {
    throw new Error(`Numeric dimension ${input.dimension} requires explicit, non-overlapping buckets`);
  }
  if (!numericDimension && input.buckets !== undefined) {
    throw new Error(`Buckets are only valid for canonical numeric dimensions`);
  }
  const buckets = input.buckets ? validateBuckets(input.buckets) : undefined;

  const weightedFields = validateWeightedFields(input.weightedAverageFields ?? []);
  const groups = new Map<string, MutableStratificationGroup>();

  for (const [recordIndex, record] of input.records.entries()) {
    const recordAsOfDate = requiredString(record.as_of_date, "as_of_date", recordIndex);
    parseIsoDate(recordAsOfDate, `Record ${recordIndex} as_of_date`);
    if (recordAsOfDate !== input.asOfDate) {
      throw new Error(`Record ${recordIndex} does not match the immutable snapshot as-of date`);
    }

    const balance = requiredDecimal(record[balanceField], balanceField, recordIndex);
    const bucket = numericDimension
      ? classifyNumericBucket(record[input.dimension], buckets!, input.dimension, recordIndex)
      : categoricalBucket(
          record[input.dimension],
          dimensionDefinition.logicalType,
          input.dimension,
          recordIndex
        );
    let group = groups.get(bucket);
    if (!group) {
      group = {
        bucket,
        count: 0,
        balance: zero(),
        weighted: new Map(
          weightedFields.map((field) => [field, { numerator: zero(), denominator: zero() }])
        )
      };
      groups.set(bucket, group);
      if (groups.size > input.maxGroups) {
        throw new Error(
          `Stratification produced more than ${input.maxGroups} groups; use explicit buckets or a lower-cardinality dimension`
        );
      }
    }

    group.count += 1;
    group.balance = group.balance.plus(balance);
    for (const field of weightedFields) {
      const rawValue = record[field];
      if (rawValue === null || rawValue === undefined || rawValue === "") continue;
      const value = requiredDecimal(rawValue, field, recordIndex);
      const aggregate = group.weighted.get(field)!;
      aggregate.numerator = aggregate.numerator.plus(value.times(balance));
      aggregate.denominator = aggregate.denominator.plus(balance);
    }
  }

  const rawRows = [...groups.values()].sort((left, right) =>
    compareBuckets(left.bucket, right.bucket, buckets)
  );
  const totalBalance = rawRows.reduce((sum, row) => sum.plus(row.balance), zero());
  const totalCount = rawRows.reduce((sum, row) => sum + row.count, 0);
  const suppressedIndexes = complementarySuppression(
    rawRows.map((row) => ({ key: row.bucket, count: row.count })),
    input.minimumCohortSize
  );

  const rows: SnapshotStratificationRow[] = rawRows.map((row, index) => {
    const suppressed = suppressedIndexes.has(index);
    return {
      bucket: row.bucket,
      loanCount: suppressed ? null : row.count,
      balance: suppressed ? null : decimalString(row.balance),
      balanceShare: suppressed ? null : ratio(row.balance, totalBalance),
      weightedAverages: Object.fromEntries(
        weightedFields.map((field) => {
          const aggregate = row.weighted.get(field)!;
          return [field, suppressed ? null : ratio(aggregate.numerator, aggregate.denominator)];
        })
      ),
      suppressed
    };
  });

  const warnings = [
    `Cells with fewer than ${input.minimumCohortSize} records are suppressed; when exactly one cell is small, a deterministic complementary cell is also suppressed.`,
    "Totals remain available for reconciliation, but restricted and identifier-valued dimensions are never emitted."
  ] as const;
  const resultWithoutHash = {
    analysisType: "snapshot_stratification" as const,
    asOfDate: input.asOfDate,
    dimension: input.dimension,
    balanceField,
    rows,
    totals: { loanCount: totalCount, balance: decimalString(totalBalance) },
    reconciliation: { passed: true as const, bucketBalanceDifference: "0" as const },
    lineage: { ...input.lineage, sourceIsImmutableSnapshot: true as const },
    warnings
  };

  return {
    ...resultWithoutHash,
    lineage: {
      ...resultWithoutHash.lineage,
      analysisHash: fingerprint(resultWithoutHash)
    }
  };
}

/**
 * Builds fixed-denominator cohort curves from repeated immutable canonical
 * snapshots. Missing observations and not-yet-seasoned points are materialized
 * as null rather than being converted to zero.
 */
export function runSnapshotVintageAnalysis(input: SnapshotVintageInput): SnapshotVintageResult {
  validateLineage(input.lineage);
  validateRecordLimit(input.records, input.maxRecords);
  validateNonNegativeInteger(input.maxMonthsOnBook, "maxMonthsOnBook", 600);
  validateNonNegativeInteger(input.delinquencyThresholdDays, "delinquencyThresholdDays", 100_000);
  validatePositiveInteger(input.minimumCohortSize, "minimumCohortSize", input.maxRecords);
  validatePositiveInteger(input.maxPoints, "maxPoints", 1_000_000);
  if (input.asOfDate !== undefined) parseIsoDate(input.asOfDate, "asOfDate");

  const parsedRecords = input.records.map((record, index) => prepareVintageRecord(record, index, input.cohortGrain));
  const analysisAsOfDate = input.asOfDate ?? latestDate(parsedRecords.map((record) => record.reportingDate));
  const withinCutoff = parsedRecords.filter(
    (record) => analysisAsOfDate !== null && record.reportingDate <= analysisAsOfDate
  );
  const inRange = withinCutoff.filter((record) => {
    if (record.monthsOnBook < 0) {
      throw new Error(`Record ${record.sourceIndex} has an as-of date before origination`);
    }
    return record.monthsOnBook <= input.maxMonthsOnBook;
  });

  const lossAvailable =
    inRange.length > 0 && inRange.every((record) => record.chargeOff !== null && record.recovery !== null);
  const delinquencyAvailable = inRange.length > 0 && inRange.every((record) => record.daysPastDue !== null);
  const loanDenominators = new Map<string, LoanDenominator>();
  const observations = new Map<string, Map<number, PreparedVintageRecord>>();

  for (const record of inRange) {
    const existingLoan = loanDenominators.get(record.loanId);
    if (existingLoan) {
      if (
        existingLoan.cohort !== record.cohort ||
        existingLoan.originationDate !== record.originationDate ||
        !existingLoan.originalBalance.equals(record.originalBalance)
      ) {
        throw new Error(
          `Record ${record.sourceIndex} conflicts with fixed cohort metadata from record ${existingLoan.sourceIndex}`
        );
      }
    } else {
      loanDenominators.set(record.loanId, {
        cohort: record.cohort,
        originationDate: record.originationDate,
        originalBalance: record.originalBalance,
        sourceIndex: record.sourceIndex
      });
    }

    let loanObservations = observations.get(record.loanId);
    if (!loanObservations) {
      loanObservations = new Map();
      observations.set(record.loanId, loanObservations);
    }
    const existingObservation = loanObservations.get(record.monthsOnBook);
    if (!existingObservation || existingObservation.reportingDate < record.reportingDate) {
      loanObservations.set(record.monthsOnBook, record);
    } else if (
      existingObservation.reportingDate === record.reportingDate &&
      !sameObservation(existingObservation, record)
    ) {
      throw new Error(
        `Record ${record.sourceIndex} conflicts with another observation for the same loan, date, and months-on-book`
      );
    }
  }

  const cohortDenominators = new Map<string, CohortDenominator>();
  for (const denominator of loanDenominators.values()) {
    const cohort = cohortDenominators.get(denominator.cohort) ?? {
      loanCount: 0,
      originalBalance: zero()
    };
    cohort.loanCount += 1;
    cohort.originalBalance = cohort.originalBalance.plus(denominator.originalBalance);
    cohortDenominators.set(denominator.cohort, cohort);
  }

  const aggregates = new Map<string, Map<number, VintageAggregate>>();
  for (const loanObservations of observations.values()) {
    for (const observation of loanObservations.values()) {
      let cohortPoints = aggregates.get(observation.cohort);
      if (!cohortPoints) {
        cohortPoints = new Map();
        aggregates.set(observation.cohort, cohortPoints);
      }
      const aggregate = cohortPoints.get(observation.monthsOnBook) ?? {
        observedLoanCount: 0,
        currentBalance: zero(),
        cumulativeNetLoss: zero(),
        delinquentBalance: zero()
      };
      aggregate.observedLoanCount += 1;
      aggregate.currentBalance = aggregate.currentBalance.plus(observation.currentBalance);
      if (lossAvailable) {
        aggregate.cumulativeNetLoss = aggregate.cumulativeNetLoss.plus(
          observation.chargeOff!.minus(observation.recovery!)
        );
      }
      if (delinquencyAvailable && observation.daysPastDue! >= input.delinquencyThresholdDays) {
        aggregate.delinquentBalance = aggregate.delinquentBalance.plus(observation.currentBalance);
      }
      cohortPoints.set(observation.monthsOnBook, aggregate);
    }
  }

  const cohorts = [...cohortDenominators.keys()].sort(compareText);
  const requestedPointCount = cohorts.length * (input.maxMonthsOnBook + 1);
  if (!Number.isSafeInteger(requestedPointCount) || requestedPointCount > input.maxPoints) {
    throw new Error(
      `Vintage analysis would produce ${requestedPointCount} points, exceeding maxPoints ${input.maxPoints}`
    );
  }

  const suppressedCohortIndexes = complementarySuppression(
    cohorts.map((cohort) => {
      const denominator = cohortDenominators.get(cohort)!;
      return { key: cohort, count: denominator.loanCount };
    }),
    input.minimumCohortSize
  );
  const suppressedCohorts = new Set(
    [...suppressedCohortIndexes].map((index) => cohorts[index]).filter((cohort): cohort is string => cohort !== undefined)
  );

  const points: SnapshotVintagePoint[] = [];
  for (const cohort of cohorts) {
    const denominator = cohortDenominators.get(cohort)!;
    const suppressed = suppressedCohorts.has(cohort);
    for (let monthsOnBook = 0; monthsOnBook <= input.maxMonthsOnBook; monthsOnBook += 1) {
      const seasoned =
        analysisAsOfDate !== null && monthsBetween(cohort, analysisAsOfDate) >= monthsOnBook;
      const aggregate = aggregates.get(cohort)?.get(monthsOnBook);
      const available = seasoned && aggregate !== undefined;
      const currentBalance = available ? aggregate.currentBalance : null;
      const cumulativeNetLoss = available && lossAvailable ? aggregate.cumulativeNetLoss : null;
      const delinquentBalance = available && delinquencyAvailable ? aggregate.delinquentBalance : null;
      points.push({
        cohort,
        monthsOnBook,
        seasoned,
        available,
        originalCohortLoanCount: suppressed ? null : denominator.loanCount,
        observedLoanCount: suppressed || !available ? null : aggregate.observedLoanCount,
        originalCohortBalance: suppressed ? null : decimalString(denominator.originalBalance),
        currentBalance: suppressed ? null : nullableDecimalString(currentBalance),
        remainingBalanceFactor: suppressed ? null : ratio(currentBalance, denominator.originalBalance),
        cumulativeNetLoss: suppressed ? null : nullableDecimalString(cumulativeNetLoss),
        cumulativeNetLossRate: suppressed ? null : ratio(cumulativeNetLoss, denominator.originalBalance),
        delinquentBalance: suppressed ? null : nullableDecimalString(delinquentBalance),
        delinquentBalanceRate: suppressed ? null : ratio(delinquentBalance, currentBalance),
        suppressed
      });
    }
  }

  const warnings = [
    "Cohort denominators are fixed from unique loan ids; origination date and original balance must remain invariant across snapshots.",
    "Unseasoned or missing cohort/month observations are null, never zero.",
    `Cohorts with fewer than ${input.minimumCohortSize} loans are suppressed; when exactly one cohort is small, a deterministic complementary cohort is also suppressed.`
  ] as const;
  const resultWithoutHash = {
    analysisType: "snapshot_vintage" as const,
    cohortGrain: input.cohortGrain,
    analysisAsOfDate,
    points,
    metricAvailability: {
      cumulativeNetLoss: lossAvailable,
      delinquency: delinquencyAvailable
    },
    lineage: { ...input.lineage, sourceIsImmutableSnapshot: true as const },
    warnings
  };

  return {
    ...resultWithoutHash,
    lineage: {
      ...resultWithoutHash.lineage,
      analysisHash: fingerprint(resultWithoutHash)
    }
  };
}

function validateLineage(lineage: ImmutableSnapshotLineage): void {
  if (lineage === null || typeof lineage !== "object" || Array.isArray(lineage)) {
    throw new Error("Lineage must be an object containing four SHA-256 hashes");
  }
  const requiredKeys = ["snapshotHash", "mappingHash", "dictionaryHash", "recipeHash"] as const;
  const actualKeys = Object.keys(lineage).sort(compareText);
  const expectedKeys = [...requiredKeys].sort(compareText);
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new Error("Lineage must contain exactly snapshot, mapping, dictionary, and recipe hashes");
  }
  for (const name of requiredKeys) {
    const value = lineage[name];
    if (!SHA256.test(value)) throw new Error(`${name} must be a lowercase SHA-256 hash`);
  }
}

function validateRecordLimit(records: readonly CanonicalSnapshotRecord[], maxRecords: number): void {
  validatePositiveInteger(maxRecords, "maxRecords", 1_000_000);
  if (records.length > maxRecords) {
    throw new Error(`Snapshot contains ${records.length} records, exceeding maxRecords ${maxRecords}`);
  }
}

function validatePositiveInteger(value: number, label: string, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${label} must be an integer between 1 and ${maximum}`);
  }
}

function validateNonNegativeInteger(value: number, label: string, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new Error(`${label} must be an integer between 0 and ${maximum}`);
  }
}

function validateWeightedFields(fields: readonly string[]): readonly string[] {
  if (fields.length > 5) throw new Error("At most five weighted-average fields are allowed per stratification");
  const unique = new Set<string>();
  for (const field of fields) {
    if (unique.has(field)) throw new Error(`Duplicate weighted-average field: ${field}`);
    unique.add(field);
    const definition = getCanonicalField(field);
    if (!definition || !NUMERIC_TYPES.has(definition.logicalType)) {
      throw new Error(`Weighted-average field ${field} must be a canonical numeric field`);
    }
    if (definition.sensitivity === "restricted" || definition.logicalType === "identifier") {
      throw new Error(`Weighted-average field ${field} cannot expose identifier values`);
    }
  }
  return [...unique].sort(compareText);
}

function validateBuckets(buckets: readonly SnapshotBucketSpec[]): readonly ParsedBucket[] {
  if (buckets.length < 1 || buckets.length > 100) throw new Error("Provide between 1 and 100 buckets");
  const labels = new Set<string>();
  const parsedBuckets: ParsedBucket[] = [];
  let previousUpper: Decimal | undefined;
  let previousIncludeUpper = false;

  for (const [index, bucket] of buckets.entries()) {
    if (bucket.label.length > 128 || bucket.label.trim() !== bucket.label || bucket.label.length === 0) {
      throw new Error(`Bucket ${index + 1} must have a non-empty, trimmed label of at most 128 characters`);
    }
    if (bucket.label === UNKNOWN_BUCKET || bucket.label === OTHER_BUCKET) {
      throw new Error(`Bucket label ${bucket.label} is reserved`);
    }
    if (labels.has(bucket.label)) throw new Error(`Duplicate bucket label: ${bucket.label}`);
    labels.add(bucket.label);
    if (bucket.lower === undefined && bucket.upper === undefined) {
      throw new Error(`Bucket ${bucket.label} must define a lower or upper bound`);
    }

    const lower = bucket.lower === undefined ? undefined : decimalFromString(bucket.lower, `Bucket ${bucket.label} lower`);
    const upper = bucket.upper === undefined ? undefined : decimalFromString(bucket.upper, `Bucket ${bucket.label} upper`);
    if (lower && upper && lower.greaterThanOrEqualTo(upper)) {
      throw new Error(`Bucket ${bucket.label} has an invalid range`);
    }
    if (index > 0 && previousUpper === undefined) {
      throw new Error(`Bucket ${bucket.label} follows an upper-unbounded bucket`);
    }
    if (index > 0 && lower === undefined) {
      throw new Error(`Bucket ${bucket.label} overlaps earlier buckets because it has no lower bound`);
    }
    if (
      previousUpper !== undefined &&
      lower !== undefined &&
      (lower.lessThan(previousUpper) ||
        (lower.equals(previousUpper) && previousIncludeUpper && bucket.includeLower !== false))
    ) {
      throw new Error(`Bucket ${bucket.label} overlaps the previous bucket at its boundary`);
    }
    previousUpper = upper;
    previousIncludeUpper = bucket.includeUpper === true;
    parsedBuckets.push({
      label: bucket.label,
      lower: lower ?? null,
      upper: upper ?? null,
      includeLower: bucket.includeLower !== false,
      includeUpper: bucket.includeUpper === true
    });
  }
  return parsedBuckets;
}

function classifyNumericBucket(
  rawValue: unknown,
  buckets: readonly ParsedBucket[],
  field: string,
  recordIndex: number
): string {
  if (rawValue === null || rawValue === undefined || rawValue === "") return UNKNOWN_BUCKET;
  const value = requiredDecimal(rawValue, field, recordIndex);
  for (const bucket of buckets) {
    const lowerMatches =
      bucket.lower === null ||
      (bucket.includeLower ? value.greaterThanOrEqualTo(bucket.lower) : value.greaterThan(bucket.lower));
    const upperMatches =
      bucket.upper === null ||
      (bucket.includeUpper ? value.lessThanOrEqualTo(bucket.upper) : value.lessThan(bucket.upper));
    if (lowerMatches && upperMatches) return bucket.label;
  }
  return OTHER_BUCKET;
}

function categoricalBucket(
  rawValue: unknown,
  logicalType: LogicalType,
  field: string,
  recordIndex: number
): string {
  if (rawValue === null || rawValue === undefined) return UNKNOWN_BUCKET;
  if (logicalType === "boolean") {
    if (typeof rawValue !== "boolean") {
      throw new Error(`Record ${recordIndex} field ${field} must be a canonical boolean`);
    }
    return String(rawValue);
  }
  if (typeof rawValue !== "string") {
    throw new Error(`Record ${recordIndex} field ${field} must be a canonical string or null`);
  }
  const value = rawValue.trim();
  if (value === "") return UNKNOWN_BUCKET;
  if (value.length > 256) throw new Error(`Record ${recordIndex} field ${field} exceeds 256 characters`);
  if (logicalType === "date") parseIsoDate(value, `Record ${recordIndex} field ${field}`);
  if (logicalType === "datetime") parseIsoDatetime(value, `Record ${recordIndex} field ${field}`);
  if (value === UNKNOWN_BUCKET || value === OTHER_BUCKET) {
    throw new Error(`Record ${recordIndex} field ${field} collides with a reserved aggregate label`);
  }
  return value;
}

function compareBuckets(
  left: string,
  right: string,
  buckets: readonly ParsedBucket[] | undefined
): number {
  if (!buckets) return compareText(left, right);
  const order = new Map(buckets.map((bucket, index) => [bucket.label, index]));
  order.set(UNKNOWN_BUCKET, buckets.length);
  order.set(OTHER_BUCKET, buckets.length + 1);
  const leftOrder = order.get(left) ?? buckets.length + 2;
  const rightOrder = order.get(right) ?? buckets.length + 2;
  return leftOrder - rightOrder || compareText(left, right);
}

function complementarySuppression(
  groups: readonly { readonly key: string; readonly count: number }[],
  minimumCohortSize: number
): Set<number> {
  const suppressed = new Set<number>();
  for (const [index, group] of groups.entries()) {
    if (group.count < minimumCohortSize) suppressed.add(index);
  }
  if (suppressed.size !== 1 || groups.length < 2) return suppressed;

  const complement = groups
    .map((group, index) => ({ ...group, index }))
    .filter(({ index }) => !suppressed.has(index))
    .sort((left, right) => left.count - right.count || compareText(left.key, right.key))[0];
  if (complement) suppressed.add(complement.index);
  return suppressed;
}

function prepareVintageRecord(
  record: CanonicalSnapshotRecord,
  index: number,
  grain: SnapshotVintageInput["cohortGrain"]
): PreparedVintageRecord {
  const loanId = requiredString(record.loan_id, "loan_id", index);
  if (loanId.trim() !== loanId || loanId.length > 512) {
    throw new Error(`Record ${index} loan_id must be trimmed and no longer than 512 characters`);
  }
  const originationDate = requiredString(record.origination_date, "origination_date", index);
  const reportingDate = requiredString(record.as_of_date, "as_of_date", index);
  parseIsoDate(originationDate, `Record ${index} origination_date`);
  parseIsoDate(reportingDate, `Record ${index} as_of_date`);
  return {
    loanId,
    cohort: cohortFor(originationDate, grain),
    originationDate,
    reportingDate,
    monthsOnBook: monthsBetween(originationDate, reportingDate),
    originalBalance: requiredDecimal(record.original_balance, "original_balance", index),
    currentBalance: requiredDecimal(record.outstanding_balance, "outstanding_balance", index),
    chargeOff: optionalDecimal(record.charge_off_amount, "charge_off_amount", index),
    recovery: optionalDecimal(record.recovery_amount, "recovery_amount", index),
    daysPastDue: optionalInteger(record.days_past_due, "days_past_due", index),
    sourceIndex: index
  };
}

function sameObservation(left: PreparedVintageRecord, right: PreparedVintageRecord): boolean {
  return (
    left.currentBalance.equals(right.currentBalance) &&
    nullableDecimalEquals(left.chargeOff, right.chargeOff) &&
    nullableDecimalEquals(left.recovery, right.recovery) &&
    left.daysPastDue === right.daysPastDue
  );
}

function nullableDecimalEquals(left: Decimal | null, right: Decimal | null): boolean {
  if (left === null || right === null) return left === right;
  return left.equals(right);
}

function cohortFor(date: string, grain: SnapshotVintageInput["cohortGrain"]): string {
  const [year, month] = date.split("-").map(Number) as [number, number, number];
  if (grain === "year") return `${year.toString().padStart(4, "0")}-01-01`;
  const cohortMonth = grain === "quarter" ? Math.floor((month - 1) / 3) * 3 + 1 : month;
  return `${year.toString().padStart(4, "0")}-${cohortMonth.toString().padStart(2, "0")}-01`;
}

function monthsBetween(earlier: string, later: string): number {
  const [earlierYear, earlierMonth] = earlier.split("-").map(Number) as [number, number, number];
  const [laterYear, laterMonth] = later.split("-").map(Number) as [number, number, number];
  return (laterYear - earlierYear) * 12 + laterMonth - earlierMonth;
}

function latestDate(dates: readonly string[]): string | null {
  return dates.reduce<string | null>((latest, date) => (latest === null || date > latest ? date : latest), null);
}

function parseIsoDate(value: string, label: string): void {
  const match = ISO_DATE.exec(value);
  if (!match) throw new Error(`${label} must be a valid YYYY-MM-DD date`);
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    throw new Error(`${label} must be a valid YYYY-MM-DD date`);
  }
}

function parseIsoDatetime(value: string, label: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) {
    throw new Error(`${label} must be a valid ISO 8601 datetime with an explicit offset`);
  }
  parseIsoDate(value.slice(0, 10), label);
  if (!Number.isFinite(Date.parse(value))) {
    throw new Error(`${label} must be a valid ISO 8601 datetime with an explicit offset`);
  }
}

function requiredString(value: unknown, field: string, recordIndex: number): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Record ${recordIndex} field ${field} must be a non-empty string`);
  }
  return value;
}

function requiredDecimal(value: unknown, field: string, recordIndex: number): Decimal {
  if (typeof value !== "string") {
    throw new Error(`Record ${recordIndex} field ${field} must be an exact canonical decimal string`);
  }
  return decimalFromString(value, `Record ${recordIndex} field ${field}`);
}

function optionalDecimal(value: unknown, field: string, recordIndex: number): Decimal | null {
  if (value === null || value === undefined || value === "") return null;
  return requiredDecimal(value, field, recordIndex);
}

function optionalInteger(value: unknown, field: string, recordIndex: number): number | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value !== "string" || !CANONICAL_INTEGER.test(value)) {
    throw new Error(`Record ${recordIndex} field ${field} must be an exact canonical integer string`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`Record ${recordIndex} field ${field} exceeds the safe integer range`);
  }
  return parsed;
}

function decimalFromString(value: string, label: string): Decimal {
  if (!CANONICAL_DECIMAL.test(value)) throw new Error(`${label} must be a canonical decimal string`);
  const digits = value.replace(/[-.]/g, "").replace(/^0+/, "").length || 1;
  if (digits > MAX_DECIMAL_DIGITS) {
    throw new Error(`${label} exceeds ${MAX_DECIMAL_DIGITS} significant digits`);
  }
  const decimal = new ExactDecimal(value);
  if (!decimal.isFinite()) throw new Error(`${label} must be finite`);
  return decimal;
}

function zero(): Decimal {
  return new ExactDecimal(0);
}

function decimalString(value: Decimal): string {
  return value.toFixed();
}

function nullableDecimalString(value: Decimal | null): string | null {
  return value === null ? null : decimalString(value);
}

function ratio(numerator: Decimal | null, denominator: Decimal | null): string | null {
  if (numerator === null || denominator === null || denominator.isZero()) return null;
  return numerator
    .dividedBy(denominator)
    .toSignificantDigits(RATIO_SIGNIFICANT_DIGITS, Decimal.ROUND_HALF_EVEN)
    .toFixed();
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function fingerprint(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Cannot hash a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Readonly<Record<string, unknown>>)
      .filter(([, entryValue]) => entryValue !== undefined)
      .sort(([left], [right]) => compareText(left, right));
    return `{${entries
      .map(([key, entryValue]) => `${JSON.stringify(key)}:${canonicalJson(entryValue)}`)
      .join(",")}}`;
  }
  throw new Error(`Cannot hash unsupported value type ${typeof value}`);
}
