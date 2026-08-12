import { canonicalHash } from "../contracts/canonical.js";
import { CANONICAL_DICTIONARY_HASH } from "../domain/dictionary-fingerprint.js";
import { getCanonicalField } from "../domain/dictionary.js";
import type { FieldMapping } from "../domain/mapping.js";
import type { ColumnInfo, SqlAdapter, TableRef } from "../infrastructure/sql/types.js";
import {
  runSnapshotStratification,
  runSnapshotVintageAnalysis,
  type SnapshotBucketSpec,
  type SnapshotStratificationResult,
  type SnapshotVintageResult
} from "./snapshot-analysis.js";

export interface LocalStratificationPreviewV2Input {
  readonly table: TableRef;
  readonly mappings: readonly FieldMapping[];
  readonly asOfDate: string;
  readonly dimension: string;
  readonly balanceField?: string;
  readonly buckets?: readonly SnapshotBucketSpec[];
  readonly weightedAverageFields?: readonly string[];
  readonly minimumCohortSize: number;
  readonly maxGroups: number;
}

export interface LocalVintagePreviewV2Input {
  readonly table: TableRef;
  readonly mappings: readonly FieldMapping[];
  readonly cohortGrain: "month" | "quarter" | "year";
  readonly asOfDate?: string;
  readonly maxMonthsOnBook: number;
  readonly delinquencyThresholdDays: number;
  readonly minimumCohortSize: number;
  readonly maxPoints: number;
}

/**
 * Bounded local preview that extracts an allowlisted canonical projection and
 * executes the exact same deterministic engine used by governed jobs.
 */
export async function runLocalStratificationPreviewV2(
  adapter: SqlAdapter,
  input: LocalStratificationPreviewV2Input
): Promise<SnapshotStratificationResult> {
  const balanceField = input.balanceField ?? "outstanding_balance";
  const fields = unique([
    "as_of_date",
    input.dimension,
    balanceField,
    ...(input.weightedAverageFields ?? [])
  ]);
  const extracted = await extractCanonicalProjection(adapter, input.table, input.mappings, fields, {
    field: "as_of_date",
    operator: "eq",
    value: input.asOfDate
  });
  return runSnapshotStratification({
    records: extracted.records,
    lineage: lineage(extracted.records, input.mappings, {
      analysis: "snapshot_stratification",
      asOfDate: input.asOfDate,
      balanceField,
      buckets: input.buckets ?? null,
      dimension: input.dimension,
      weightedAverageFields: input.weightedAverageFields ?? []
    }),
    asOfDate: input.asOfDate,
    dimension: input.dimension,
    balanceField,
    ...(input.buckets === undefined ? {} : { buckets: input.buckets }),
    ...(input.weightedAverageFields === undefined
      ? {}
      : { weightedAverageFields: input.weightedAverageFields }),
    minimumCohortSize: input.minimumCohortSize,
    maxRecords: adapter.maxResultRows,
    maxGroups: input.maxGroups
  });
}

/** Local longitudinal preview with governed-engine parity and explicit preview lineage. */
export async function runLocalVintagePreviewV2(
  adapter: SqlAdapter,
  input: LocalVintagePreviewV2Input
): Promise<SnapshotVintageResult> {
  const required = [
    "loan_id",
    "origination_date",
    "as_of_date",
    "original_balance",
    "outstanding_balance"
  ];
  const optional = ["charge_off_amount", "recovery_amount", "days_past_due"]
    .filter((field) => input.mappings.some((mapping) => mapping.canonicalField === field));
  const extracted = await extractCanonicalProjection(
    adapter,
    input.table,
    input.mappings,
    [...required, ...optional],
    input.asOfDate === undefined
      ? undefined
      : { field: "as_of_date", operator: "lte", value: input.asOfDate }
  );
  return runSnapshotVintageAnalysis({
    records: extracted.records,
    lineage: lineage(extracted.records, input.mappings, {
      analysis: "snapshot_vintage",
      asOfDate: input.asOfDate ?? null,
      cohortGrain: input.cohortGrain,
      delinquencyThresholdDays: input.delinquencyThresholdDays,
      maxMonthsOnBook: input.maxMonthsOnBook
    }),
    cohortGrain: input.cohortGrain,
    ...(input.asOfDate === undefined ? {} : { asOfDate: input.asOfDate }),
    maxMonthsOnBook: input.maxMonthsOnBook,
    delinquencyThresholdDays: input.delinquencyThresholdDays,
    minimumCohortSize: input.minimumCohortSize,
    maxRecords: adapter.maxResultRows,
    maxPoints: input.maxPoints
  });
}

async function extractCanonicalProjection(
  adapter: SqlAdapter,
  requestedTable: TableRef,
  mappings: readonly FieldMapping[],
  fields: readonly string[],
  predicate?: { readonly field: string; readonly operator: "eq" | "lte"; readonly value: string }
): Promise<{ readonly records: readonly Readonly<Record<string, unknown>>[] }> {
  const table = await adapter.resolveTable(requestedTable);
  const columns = await adapter.describeTable(table);
  const selected = fields.map((field) => resolveMapping(field, mappings, columns));
  const predicateMapping = predicate
    ? resolveMapping(predicate.field, mappings, columns)
    : undefined;
  const q = (identifier: string): string => adapter.quoteIdentifier(identifier);
  const select = selected
    .map(({ canonicalField, sourceColumn }) =>
      `CAST(${q(sourceColumn)} AS TEXT) AS ${q(canonicalField)}`
    )
    .join(", ");
  const values: unknown[] = [];
  const where = predicateMapping && predicate
    ? ` WHERE ${q(predicateMapping.sourceColumn)} ${predicate.operator === "eq" ? "=" : "<="} ${bind(adapter, values, predicate.value)}`
    : "";
  const order = selected.map(({ canonicalField }) => q(canonicalField)).join(", ");
  const limit = bind(adapter, values, adapter.maxResultRows + 1);
  const result = await adapter.executeAggregate({
    text: `SELECT ${select} FROM ${q(table.schema)}.${q(table.table)}${where} ORDER BY ${order} LIMIT ${limit}`,
    values
  }, adapter.maxResultRows);
  if (result.truncated || result.rows.length > adapter.maxResultRows) {
    throw new Error(`Local preview exceeds the configured ${adapter.maxResultRows}-record bound`);
  }
  return { records: Object.freeze(result.rows.map((row) => Object.freeze({ ...row }))) };
}

function resolveMapping(
  canonicalField: string,
  mappings: readonly FieldMapping[],
  columns: readonly ColumnInfo[]
): { readonly canonicalField: string; readonly sourceColumn: string } {
  if (!getCanonicalField(canonicalField)) throw new Error(`Unknown canonical field: ${canonicalField}`);
  const matches = mappings.filter((mapping) => mapping.canonicalField === canonicalField);
  if (matches.length !== 1) throw new Error(`Canonical field ${canonicalField} must have exactly one mapping`);
  const source = columns.find((column) => column.name === matches[0]!.sourceColumn);
  if (!source || source.restricted) throw new Error(`Mapped source for ${canonicalField} is unavailable`);
  return { canonicalField, sourceColumn: source.name };
}

function lineage(
  records: readonly Readonly<Record<string, unknown>>[],
  mappings: readonly FieldMapping[],
  recipe: Readonly<Record<string, unknown>>
) {
  return {
    snapshotHash: rawHash(records),
    mappingHash: rawHash([...mappings].sort((left, right) =>
      left.canonicalField.localeCompare(right.canonicalField) || left.sourceColumn.localeCompare(right.sourceColumn)
    )),
    dictionaryHash: CANONICAL_DICTIONARY_HASH,
    recipeHash: rawHash(recipe)
  };
}

function bind(adapter: SqlAdapter, values: unknown[], value: unknown): string {
  values.push(value);
  return adapter.placeholder(values.length);
}

function rawHash(value: unknown): string {
  return canonicalHash(value).slice("sha256:".length);
}

function unique(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)]);
}
