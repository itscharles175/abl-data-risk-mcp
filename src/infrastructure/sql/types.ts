import type { SourceConfig } from "../../config.js";

export type SqlDialect = SourceConfig["dialect"];

export interface TableRef {
  readonly schema: string;
  readonly table: string;
}

export interface ColumnInfo {
  readonly name: string;
  readonly dataType: string;
  readonly nullable: boolean;
  readonly ordinalPosition: number;
  readonly restricted: boolean;
}

export interface AggregateQuery {
  readonly text: string;
  readonly values: readonly unknown[];
}

export interface AggregateResult {
  readonly rows: readonly Record<string, unknown>[];
  readonly truncated: boolean;
}

export interface SqlAdapter {
  readonly dialect: SqlDialect;
  readonly sourceId: string;
  readonly maxResultRows: number;

  listTables(): Promise<readonly TableRef[]>;
  describeTable(table: TableRef): Promise<readonly ColumnInfo[]>;
  resolveTable(table: TableRef): Promise<TableRef>;
  quoteIdentifier(identifier: string): string;
  placeholder(position: number): string;
  executeAggregate(query: AggregateQuery, maxRows?: number): Promise<AggregateResult>;
  close(): Promise<void>;
}

export function tableKey(table: TableRef): string {
  return `${table.schema}.${table.table}`;
}

export function isRestrictedColumn(name: string, explicitlyRestricted: readonly string[]): boolean {
  const normalized = name.trim().toLowerCase();
  if (explicitlyRestricted.some((column) => column.trim().toLowerCase() === normalized)) return true;

  return /(^|_)(ssn|social_security|tax_id|tin|ein|email|phone|mobile|dob|birth_date|routing|account_number|bank_account|full_name|first_name|last_name|street_address|address_line)(_|$)/i.test(
    normalized
  );
}

export function normalizeDatabaseValue(value: unknown): unknown {
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Date) return value.toISOString();
  if (Buffer.isBuffer(value)) return "[binary value withheld]";
  return value;
}

export function normalizeDatabaseRow(row: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(row).map(([key, value]) => [key, normalizeDatabaseValue(value)]));
}
