import { createHash } from "node:crypto";

import { Decimal } from "decimal.js";

import { getCanonicalField } from "../domain/dictionary.js";
import type { FieldMapping } from "../domain/mapping.js";
import type { SqlAdapter, TableRef } from "../infrastructure/sql/types.js";

export interface BucketSpec {
  readonly label: string;
  readonly lower?: number;
  readonly upper?: number;
  readonly includeLower?: boolean;
  readonly includeUpper?: boolean;
}

export interface StratificationInput {
  readonly table: TableRef;
  readonly mappings: readonly FieldMapping[];
  readonly asOfDate: string;
  readonly dimension: string;
  readonly balanceField?: string;
  readonly buckets?: readonly BucketSpec[];
  readonly weightedAverageFields?: readonly string[];
  readonly minimumCohortSize: number;
  readonly maxGroups: number;
}

export interface StratificationRow {
  readonly bucket: string;
  readonly loanCount: number | null;
  readonly balance: string | null;
  readonly balanceShare: string | null;
  readonly weightedAverages: Readonly<Record<string, string | null>>;
  readonly suppressed: boolean;
}

export interface StratificationResult {
  readonly analysisType: "stratification";
  readonly sourceId: string;
  readonly table: TableRef;
  readonly dimension: string;
  readonly balanceField: string;
  readonly rows: readonly StratificationRow[];
  readonly totals: {
    readonly loanCount: number;
    readonly balance: string;
  };
  readonly reconciliation: {
    readonly passed: true;
    readonly bucketBalanceDifference: "0";
  };
  readonly lineage: {
    readonly mappingFingerprint: string;
    readonly queryFingerprint: string;
    readonly sourceIsImmutableSnapshot: false;
  };
  readonly warnings: readonly string[];
}

export interface VintageInput {
  readonly table: TableRef;
  readonly mappings: readonly FieldMapping[];
  readonly cohortGrain: "month" | "quarter" | "year";
  readonly asOfDate?: string;
  readonly maxMonthsOnBook: number;
  readonly delinquencyThresholdDays: number;
  readonly minimumCohortSize: number;
  readonly maxPoints: number;
}

export interface VintagePoint {
  readonly cohort: string;
  readonly monthsOnBook: number;
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

export interface VintageResult {
  readonly analysisType: "vintage";
  readonly sourceId: string;
  readonly table: TableRef;
  readonly cohortGrain: VintageInput["cohortGrain"];
  readonly points: readonly VintagePoint[];
  readonly metricAvailability: {
    readonly cumulativeNetLoss: boolean;
    readonly delinquency: boolean;
  };
  readonly lineage: {
    readonly mappingFingerprint: string;
    readonly queryFingerprint: string;
    readonly sourceIsImmutableSnapshot: false;
  };
  readonly warnings: readonly string[];
}

interface ResolvedMapping {
  readonly canonicalField: string;
  readonly sourceColumn: string;
}

export async function runStratification(
  adapter: SqlAdapter,
  input: StratificationInput
): Promise<StratificationResult> {
  const table = await adapter.resolveTable(input.table);
  const columns = await adapter.describeTable(table);
  const dimension = resolveMappedColumn(input.dimension, input.mappings, columns);
  const asOfDate = resolveMappedColumn("as_of_date", input.mappings, columns);
  const balanceField = input.balanceField ?? "outstanding_balance";
  const balance = resolveMappedColumn(balanceField, input.mappings, columns);
  const balanceDefinition = getCanonicalField(balanceField);
  if (!balanceDefinition || balanceDefinition.logicalType !== "currency") {
    throw new Error(`Balance field ${balanceField} must be a canonical currency field`);
  }
  const weightedFields = [...new Set(input.weightedAverageFields ?? [])];
  if (weightedFields.length > 5) throw new Error("At most five weighted-average fields are allowed per stratification");

  const weighted = weightedFields.map((field) => {
    const definition = getCanonicalField(field);
    if (!definition || !["integer", "decimal", "currency", "percentage"].includes(definition.logicalType)) {
      throw new Error(`Weighted-average field ${field} must be a canonical numeric field`);
    }
    if (definition.sensitivity === "restricted") {
      throw new Error(`Weighted-average field ${field} is restricted from aggregate output`);
    }
    return {
      canonicalField: field,
      sourceColumn: resolveMappedColumn(field, input.mappings, columns).sourceColumn
    };
  });

  const dimensionDefinition = getCanonicalField(input.dimension);
  if (!dimensionDefinition) throw new Error(`Unknown canonical dimension: ${input.dimension}`);
  if (dimensionDefinition.sensitivity === "restricted") {
    throw new Error(`Canonical dimension ${input.dimension} is restricted from aggregate output`);
  }
  const numericDimension = ["integer", "decimal", "currency", "percentage"].includes(
    dimensionDefinition.logicalType
  );
  if (numericDimension && (!input.buckets || input.buckets.length === 0)) {
    throw new Error(`Numeric dimension ${input.dimension} requires explicit, non-overlapping buckets`);
  }
  if (input.buckets) validateBuckets(input.buckets);

  const values: unknown[] = [];
  const bind = (value: unknown): string => {
    values.push(value);
    return adapter.placeholder(values.length);
  };
  const q = (identifier: string): string => adapter.quoteIdentifier(identifier);
  const qualifiedTable = `${q(table.schema)}.${q(table.table)}`;
  const dimensionExpression = q(dimension.sourceColumn);
  const bucketExpression = input.buckets?.length
    ? compileBucketExpression(dimensionExpression, input.buckets, bind)
    : `COALESCE(NULLIF(TRIM(CAST(${dimensionExpression} AS TEXT)), ''), 'Unknown/Unmapped')`;

  const weightedExpressions = weighted
    .map(({ canonicalField, sourceColumn }) => {
      const value = q(sourceColumn);
      const weight = q(balance.sourceColumn);
      const alias = q(`wa_${canonicalField}`);
      return `(1.0 * SUM(CASE WHEN ${value} IS NOT NULL AND ${weight} IS NOT NULL THEN ${value} * ${weight} ELSE 0 END))
              / NULLIF(SUM(CASE WHEN ${value} IS NOT NULL THEN ${weight} ELSE 0 END), 0) AS ${alias}`;
    })
    .join(",\n       ");

  const selectWeighted = weightedExpressions ? `,\n       ${weightedExpressions}` : "";
  const snapshotDate = bind(input.asOfDate);
  const limit = bind(input.maxGroups + 1);
  const query = {
    text: `SELECT ${bucketExpression} AS bucket,
       COUNT(*) AS loan_count,
       SUM(COALESCE(${q(balance.sourceColumn)}, 0)) AS balance${selectWeighted}
  FROM ${qualifiedTable}
 WHERE ${q(asOfDate.sourceColumn)} = ${snapshotDate}
 GROUP BY 1
 ORDER BY balance DESC, bucket ASC
 LIMIT ${limit}`,
    values
  } as const;

  const result = await adapter.executeAggregate(query, input.maxGroups + 1);
  if (result.truncated || result.rows.length > input.maxGroups) {
    throw new Error(
      `Stratification produced more than ${input.maxGroups} groups; use explicit buckets or a lower-cardinality dimension`
    );
  }

  const rawRows = result.rows.map((row) => ({
    bucket: String(row.bucket ?? "Unknown/Unmapped"),
    loanCount: toInteger(row.loan_count, "loan_count"),
    balance: toDecimal(row.balance, "balance"),
    weightedAverages: Object.fromEntries(
      weighted.map(({ canonicalField }) => [
        canonicalField,
        nullableDecimalString(row[`wa_${canonicalField}`], `wa_${canonicalField}`)
      ])
    )
  }));

  if (input.buckets) {
    const bucketOrder = new Map(input.buckets.map((bucket, index) => [bucket.label, index]));
    rawRows.sort((left, right) => {
      const leftOrder = left.bucket === "Unknown/Unmapped" ? input.buckets!.length : bucketOrder.get(left.bucket);
      const rightOrder = right.bucket === "Unknown/Unmapped" ? input.buckets!.length : bucketOrder.get(right.bucket);
      return (leftOrder ?? input.buckets!.length + 1) - (rightOrder ?? input.buckets!.length + 1);
    });
  }

  const totalBalance = rawRows.reduce((sum, row) => sum.plus(row.balance), new Decimal(0));
  const totalCount = rawRows.reduce((sum, row) => sum + row.loanCount, 0);
  const suppressedIndexes = new Set(
    rawRows.flatMap((row, index) => (row.loanCount < input.minimumCohortSize ? [index] : []))
  );
  if (suppressedIndexes.size === 1 && rawRows.length > 1) {
    const complement = rawRows
      .map((row, index) => ({ row, index }))
      .filter(({ index }) => !suppressedIndexes.has(index))
      .sort((left, right) => left.row.loanCount - right.row.loanCount)[0];
    if (complement) suppressedIndexes.add(complement.index);
  }

  const rows: StratificationRow[] = rawRows.map((row, index) => {
    const suppressed = suppressedIndexes.has(index);
    return {
      bucket: row.bucket,
      loanCount: suppressed ? null : row.loanCount,
      balance: suppressed ? null : decimalString(row.balance),
      balanceShare: suppressed || totalBalance.isZero() ? null : decimalString(row.balance.div(totalBalance)),
      weightedAverages: suppressed
        ? Object.fromEntries(Object.keys(row.weightedAverages).map((field) => [field, null]))
        : row.weightedAverages,
      suppressed
    };
  });

  return {
    analysisType: "stratification",
    sourceId: adapter.sourceId,
    table,
    dimension: input.dimension,
    balanceField,
    rows,
    totals: { loanCount: totalCount, balance: decimalString(totalBalance) },
    reconciliation: { passed: true, bucketBalanceDifference: "0" },
    lineage: {
      mappingFingerprint: mappingFingerprint(input.mappings),
      queryFingerprint: queryFingerprint(query.text, query.values),
      sourceIsImmutableSnapshot: false
    },
    warnings: [
      "The configured source is queried live. Register an immutable snapshot before treating this result as audit-reproducible.",
      `Cells with fewer than ${input.minimumCohortSize} loans, plus complementary cells when needed, have counts and values suppressed.`
    ]
  };
}

export async function runVintageAnalysis(adapter: SqlAdapter, input: VintageInput): Promise<VintageResult> {
  const table = await adapter.resolveTable(input.table);
  const columns = await adapter.describeTable(table);
  const loanId = resolveMappedColumn("loan_id", input.mappings, columns);
  const originationDate = resolveMappedColumn("origination_date", input.mappings, columns);
  const reportingDate = resolveMappedColumn("as_of_date", input.mappings, columns);
  const originalBalance = resolveMappedColumn("original_balance", input.mappings, columns);
  const currentBalance = resolveMappedColumn("outstanding_balance", input.mappings, columns);
  const chargeOff = maybeResolveMappedColumn("charge_off_amount", input.mappings, columns);
  const recovery = maybeResolveMappedColumn("recovery_amount", input.mappings, columns);
  const daysPastDue = maybeResolveMappedColumn("days_past_due", input.mappings, columns);

  const q = (identifier: string): string => adapter.quoteIdentifier(identifier);
  const qualifiedTable = `${q(table.schema)}.${q(table.table)}`;
  const values: unknown[] = [];
  const bind = (value: unknown): string => {
    values.push(value);
    return adapter.placeholder(values.length);
  };

  const cohort = cohortExpression(adapter.dialect, q(originationDate.sourceColumn), input.cohortGrain);
  const mob = monthsOnBookExpression(
    adapter.dialect,
    q(originationDate.sourceColumn),
    q(reportingDate.sourceColumn)
  );
  const lossAvailable = Boolean(chargeOff && recovery);
  const lossExpression =
    chargeOff && recovery ? `(${q(chargeOff.sourceColumn)} - ${q(recovery.sourceColumn)})` : "NULL";
  const cutoffPredicate = input.asOfDate
    ? `AND ${q(reportingDate.sourceColumn)} <= ${bind(input.asOfDate)}`
    : "";
  const delinquentBalanceExpression = daysPastDue
    ? `SUM(CASE WHEN days_past_due >= ${bind(input.delinquencyThresholdDays)} THEN current_balance ELSE 0 END)`
    : "NULL";
  const maxMonths = bind(input.maxMonthsOnBook);
  const limit = bind(input.maxPoints + 1);

  const query = {
    text: `WITH raw_snapshots AS (
    SELECT CAST(${q(loanId.sourceColumn)} AS TEXT) AS loan_id,
           ${cohort} AS cohort,
           ${mob} AS mob,
           ${q(reportingDate.sourceColumn)} AS reporting_date,
           ${q(originalBalance.sourceColumn)} AS original_balance,
           ${q(currentBalance.sourceColumn)} AS current_balance,
           ${lossExpression} AS cumulative_net_loss,
           ${daysPastDue ? q(daysPastDue.sourceColumn) : "NULL"} AS days_past_due
      FROM ${qualifiedTable}
     WHERE ${q(loanId.sourceColumn)} IS NOT NULL
       AND ${q(originationDate.sourceColumn)} IS NOT NULL
       AND ${q(reportingDate.sourceColumn)} IS NOT NULL
       ${cutoffPredicate}
), ranked_snapshots AS (
    SELECT *, ROW_NUMBER() OVER (PARTITION BY loan_id, mob ORDER BY reporting_date DESC) AS snapshot_rank
      FROM raw_snapshots
     WHERE mob BETWEEN 0 AND ${maxMonths}
), snapshots AS (
    SELECT * FROM ranked_snapshots WHERE snapshot_rank = 1
), loan_denominators AS (
    SELECT cohort, loan_id, MAX(original_balance) AS original_balance
      FROM snapshots
     GROUP BY cohort, loan_id
), cohort_denominators AS (
    SELECT cohort,
           COUNT(*) AS original_cohort_loan_count,
           SUM(original_balance) AS original_cohort_balance
      FROM loan_denominators
     GROUP BY cohort
), points AS (
    SELECT cohort,
           mob,
           COUNT(DISTINCT loan_id) AS observed_loan_count,
           SUM(current_balance) AS current_balance,
           SUM(cumulative_net_loss) AS cumulative_net_loss,
           ${delinquentBalanceExpression} AS delinquent_balance
      FROM snapshots
     GROUP BY cohort, mob
)
SELECT points.cohort,
       points.mob,
       cohort_denominators.original_cohort_loan_count,
       points.observed_loan_count,
       cohort_denominators.original_cohort_balance,
       points.current_balance,
       points.cumulative_net_loss,
       points.delinquent_balance
  FROM points
  JOIN cohort_denominators ON cohort_denominators.cohort = points.cohort
 ORDER BY points.cohort, points.mob
 LIMIT ${limit}`,
    values
  } as const;

  const result = await adapter.executeAggregate(query, input.maxPoints + 1);
  if (result.truncated || result.rows.length > input.maxPoints) {
    throw new Error(
      `Vintage analysis produced more than ${input.maxPoints} points; narrow the cutoff, cohort grain, or months-on-book range`
    );
  }

  const points: VintagePoint[] = result.rows.map((row) => {
    const originalCount = toInteger(row.original_cohort_loan_count, "original_cohort_loan_count");
    const observedCount = toInteger(row.observed_loan_count, "observed_loan_count");
    const original = nullableDecimal(row.original_cohort_balance, "original_cohort_balance");
    const current = nullableDecimal(row.current_balance, "current_balance");
    const cumulativeLoss = nullableDecimal(row.cumulative_net_loss, "cumulative_net_loss");
    const delinquent = nullableDecimal(row.delinquent_balance, "delinquent_balance");
    const suppressed = originalCount < input.minimumCohortSize;

    return {
      cohort: String(row.cohort),
      monthsOnBook: toInteger(row.mob, "mob"),
      originalCohortLoanCount: suppressed ? null : originalCount,
      observedLoanCount: suppressed ? null : observedCount,
      originalCohortBalance: suppressed ? null : nullableDecimalStringFromDecimal(original),
      currentBalance: suppressed ? null : nullableDecimalStringFromDecimal(current),
      remainingBalanceFactor: suppressed ? null : ratio(current, original),
      cumulativeNetLoss: suppressed ? null : nullableDecimalStringFromDecimal(cumulativeLoss),
      cumulativeNetLossRate: suppressed ? null : ratio(cumulativeLoss, original),
      delinquentBalance: suppressed ? null : nullableDecimalStringFromDecimal(delinquent),
      delinquentBalanceRate: suppressed ? null : ratio(delinquent, current),
      suppressed
    };
  });

  return {
    analysisType: "vintage",
    sourceId: adapter.sourceId,
    table,
    cohortGrain: input.cohortGrain,
    points,
    metricAvailability: { cumulativeNetLoss: lossAvailable, delinquency: Boolean(daysPastDue) },
    lineage: {
      mappingFingerprint: mappingFingerprint(input.mappings),
      queryFingerprint: queryFingerprint(query.text, query.values),
      sourceIsImmutableSnapshot: false
    },
    warnings: [
      "True vintage analysis requires repeated snapshots or event history; a single current tape only describes the current age distribution.",
      "Cohort membership uses origination date and the denominator uses each loan's maximum observed original balance.",
      "Unseasoned cohort/month combinations are omitted and should be rendered as null, never zero.",
      "The configured source is queried live. Register an immutable snapshot before treating this result as audit-reproducible.",
      `Cohorts with fewer than ${input.minimumCohortSize} loans have counts and values suppressed.`
    ]
  };
}

function resolveMappedColumn(
  canonicalField: string,
  mappings: readonly FieldMapping[],
  columns: readonly { name: string; restricted: boolean }[]
): ResolvedMapping {
  const mapping = mappings.find((candidate) => candidate.canonicalField === canonicalField);
  if (!mapping) throw new Error(`Canonical field is not mapped: ${canonicalField}`);
  const column = columns.find((candidate) => candidate.name === mapping.sourceColumn);
  if (!column) throw new Error(`Mapped source column does not exist: ${mapping.sourceColumn}`);
  if (column.restricted) throw new Error(`Mapped source column is restricted by policy: ${mapping.sourceColumn}`);
  return mapping;
}

function maybeResolveMappedColumn(
  canonicalField: string,
  mappings: readonly FieldMapping[],
  columns: readonly { name: string; restricted: boolean }[]
): ResolvedMapping | undefined {
  if (!mappings.some((mapping) => mapping.canonicalField === canonicalField)) return undefined;
  return resolveMappedColumn(canonicalField, mappings, columns);
}

function validateBuckets(buckets: readonly BucketSpec[]): void {
  if (buckets.length === 0 || buckets.length > 100) throw new Error("Provide between 1 and 100 buckets");
  const labels = new Set<string>();
  let previousUpper: number | undefined;
  let previousIncludeUpper = false;

  for (const [index, bucket] of buckets.entries()) {
    if (!bucket.label.trim()) throw new Error(`Bucket ${index + 1} has an empty label`);
    if (labels.has(bucket.label)) throw new Error(`Duplicate bucket label: ${bucket.label}`);
    labels.add(bucket.label);
    if (bucket.lower === undefined && bucket.upper === undefined) {
      throw new Error(`Bucket ${bucket.label} must define a lower or upper bound`);
    }
    if (bucket.lower !== undefined && bucket.upper !== undefined && bucket.lower >= bucket.upper) {
      throw new Error(`Bucket ${bucket.label} has an invalid range`);
    }
    if (index > 0 && previousUpper === undefined) {
      throw new Error(`Bucket ${bucket.label} follows an upper-unbounded bucket`);
    }
    if (index > 0 && bucket.lower === undefined) {
      throw new Error(`Bucket ${bucket.label} overlaps earlier buckets because it has no lower bound`);
    }
    if (
      previousUpper !== undefined &&
      bucket.lower !== undefined &&
      (bucket.lower < previousUpper ||
        (bucket.lower === previousUpper && previousIncludeUpper && bucket.includeLower !== false))
    ) {
      throw new Error(`Bucket ${bucket.label} overlaps the previous bucket at its boundary`);
    }
    previousUpper = bucket.upper;
    previousIncludeUpper = bucket.includeUpper === true;
  }
}

function compileBucketExpression(
  expression: string,
  buckets: readonly BucketSpec[],
  bind: (value: unknown) => string
): string {
  const branches = buckets.map((bucket) => {
    const conditions: string[] = [];
    if (bucket.lower !== undefined) {
      conditions.push(`${expression} ${bucket.includeLower === false ? ">" : ">="} ${bind(bucket.lower)}`);
    }
    if (bucket.upper !== undefined) {
      conditions.push(`${expression} ${bucket.includeUpper === true ? "<=" : "<"} ${bind(bucket.upper)}`);
    }
    return `WHEN ${conditions.join(" AND ")} THEN ${bind(bucket.label)}`;
  });

  return `CASE WHEN ${expression} IS NULL THEN 'Unknown/Unmapped' ${branches.join(" ")} ELSE 'Other' END`;
}

function cohortExpression(dialect: SqlAdapter["dialect"], expression: string, grain: VintageInput["cohortGrain"]): string {
  if (dialect === "postgres") {
    return `TO_CHAR(DATE_TRUNC('${grain}', CAST(${expression} AS DATE)), 'YYYY-MM-DD')`;
  }
  if (grain === "month") return `STRFTIME('%Y-%m-01', DATE(${expression}))`;
  if (grain === "year") return `STRFTIME('%Y-01-01', DATE(${expression}))`;
  return `PRINTF('%04d-%02d-01', CAST(STRFTIME('%Y', DATE(${expression})) AS INTEGER), (((CAST(STRFTIME('%m', DATE(${expression})) AS INTEGER) - 1) / 3) * 3) + 1)`;
}

function monthsOnBookExpression(
  dialect: SqlAdapter["dialect"],
  originationExpression: string,
  reportingExpression: string
): string {
  if (dialect === "postgres") {
    return `((EXTRACT(YEAR FROM CAST(${reportingExpression} AS DATE)) - EXTRACT(YEAR FROM CAST(${originationExpression} AS DATE))) * 12
          + (EXTRACT(MONTH FROM CAST(${reportingExpression} AS DATE)) - EXTRACT(MONTH FROM CAST(${originationExpression} AS DATE))))::INTEGER`;
  }
  return `((CAST(STRFTIME('%Y', DATE(${reportingExpression})) AS INTEGER) - CAST(STRFTIME('%Y', DATE(${originationExpression})) AS INTEGER)) * 12
          + (CAST(STRFTIME('%m', DATE(${reportingExpression})) AS INTEGER) - CAST(STRFTIME('%m', DATE(${originationExpression})) AS INTEGER)))`;
}

function toInteger(value: unknown, label: string): number {
  const number = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(number)) throw new Error(`Database returned a non-integer ${label}`);
  return number;
}

function toDecimal(value: unknown, label: string): Decimal {
  const converted = nullableDecimal(value, label);
  if (!converted) throw new Error(`Database returned null for ${label}`);
  return converted;
}

function nullableDecimal(value: unknown, label: string): Decimal | null {
  if (value === null || value === undefined) return null;
  try {
    return new Decimal(String(value));
  } catch (error) {
    throw new Error(`Database returned a non-decimal ${label}`, { cause: error });
  }
}

function nullableDecimalString(value: unknown, label: string): string | null {
  return nullableDecimalStringFromDecimal(nullableDecimal(value, label));
}

function nullableDecimalStringFromDecimal(value: Decimal | null): string | null {
  return value ? decimalString(value) : null;
}

function decimalString(value: Decimal): string {
  return value.toSignificantDigits(20).toFixed();
}

function ratio(numerator: Decimal | null, denominator: Decimal | null): string | null {
  if (!numerator || !denominator || denominator.isZero()) return null;
  return decimalString(numerator.div(denominator));
}

function mappingFingerprint(mappings: readonly FieldMapping[]): string {
  const stable = [...mappings].sort((left, right) =>
    `${left.canonicalField}:${left.sourceColumn}`.localeCompare(`${right.canonicalField}:${right.sourceColumn}`)
  );
  return createHash("sha256").update(JSON.stringify(stable)).digest("hex");
}

function queryFingerprint(text: string, values: readonly unknown[]): string {
  return createHash("sha256").update(text).update("\n").update(JSON.stringify(values)).digest("hex");
}
