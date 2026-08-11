import pg from "pg";

import type { PostgresSourceConfig } from "../../config.js";
import {
  type AggregateQuery,
  type AggregateResult,
  type ColumnInfo,
  isRestrictedColumn,
  normalizeDatabaseRow,
  type SqlAdapter,
  type TableRef,
  tableKey
} from "./types.js";

const { Pool } = pg;

export class PostgresAdapter implements SqlAdapter {
  readonly dialect = "postgres" as const;
  readonly sourceId: string;
  readonly maxResultRows: number;

  readonly #config: PostgresSourceConfig;
  readonly #pool: pg.Pool;

  constructor(config: PostgresSourceConfig) {
    const connectionString = process.env[config.connectionEnv];
    if (!connectionString) {
      throw new Error(`Source ${config.id} requires environment variable ${config.connectionEnv}`);
    }

    this.sourceId = config.id;
    this.maxResultRows = config.maxResultRows;
    this.#config = config;
    this.#pool = new Pool({
      connectionString,
      application_name: "abl-mcp",
      max: 4,
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 5_000
    });
  }

  async listTables(): Promise<readonly TableRef[]> {
    const result = await this.#pool.query<{ table_schema: string; table_name: string }>(
      `SELECT table_schema, table_name
         FROM information_schema.tables
        WHERE table_type IN ('BASE TABLE', 'VIEW')
          AND table_schema = ANY($1::text[])
        ORDER BY table_schema, table_name`,
      [this.#config.allowedSchemas]
    );

    const allowed = new Set(this.#config.allowedTables);
    return result.rows
      .map((row) => ({ schema: row.table_schema, table: row.table_name }))
      .filter((table) => allowed.has(tableKey(table)));
  }

  async describeTable(table: TableRef): Promise<readonly ColumnInfo[]> {
    const resolved = await this.resolveTable(table);
    const result = await this.#pool.query<{
      column_name: string;
      data_type: string;
      is_nullable: "YES" | "NO";
      ordinal_position: number;
    }>(
      `SELECT column_name, data_type, is_nullable, ordinal_position
         FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2
        ORDER BY ordinal_position`,
      [resolved.schema, resolved.table]
    );

    return result.rows.map((row) => ({
      name: row.column_name,
      dataType: row.data_type,
      nullable: row.is_nullable === "YES",
      ordinalPosition: row.ordinal_position,
      restricted: isRestrictedColumn(row.column_name, this.#config.restrictedColumns)
    }));
  }

  async resolveTable(table: TableRef): Promise<TableRef> {
    const match = (await this.listTables()).find(
      (candidate) => candidate.schema === table.schema && candidate.table === table.table
    );
    if (!match) throw new Error(`Table is not in the configured allowlist for source ${this.sourceId}`);
    return match;
  }

  quoteIdentifier(identifier: string): string {
    return `"${identifier.replaceAll('"', '""')}"`;
  }

  placeholder(position: number): string {
    return `$${position}`;
  }

  async executeAggregate(query: AggregateQuery, requestedMaxRows?: number): Promise<AggregateResult> {
    const maxRows = Math.min(requestedMaxRows ?? this.maxResultRows, this.maxResultRows);
    const client = await this.#pool.connect();

    try {
      await client.query("BEGIN READ ONLY");
      await client.query(`SET LOCAL statement_timeout = ${this.#config.statementTimeoutMs}`);
      await client.query("SET LOCAL lock_timeout = 1000");
      const result = await client.query<Record<string, unknown>>(query.text, [...query.values]);
      const truncated = result.rows.length > maxRows;
      const rows = result.rows.slice(0, maxRows).map(normalizeDatabaseRow);
      return { rows, truncated };
    } finally {
      try {
        await client.query("ROLLBACK");
      } finally {
        client.release(true);
      }
    }
  }

  async close(): Promise<void> {
    await this.#pool.end();
  }
}
