import { DatabaseSync, type SQLInputValue } from "node:sqlite";

import type { SqliteSourceConfig } from "../../config.js";
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

interface SqliteTableRow {
  readonly name: string;
}

interface SqliteColumnRow {
  readonly cid: number;
  readonly name: string;
  readonly type: string;
  readonly notnull: number;
}

export class SqliteAdapter implements SqlAdapter {
  readonly dialect = "sqlite" as const;
  readonly sourceId: string;
  readonly maxResultRows: number;

  readonly #config: SqliteSourceConfig;
  readonly #database: DatabaseSync;

  constructor(config: SqliteSourceConfig) {
    this.sourceId = config.id;
    this.maxResultRows = config.maxResultRows;
    this.#config = config;
    this.#database = new DatabaseSync(config.path, {
      readOnly: true,
      enableForeignKeyConstraints: true,
      allowExtension: false
    });
  }

  async listTables(): Promise<readonly TableRef[]> {
    const rows = this.#database
      .prepare(
        `SELECT name
           FROM sqlite_master
          WHERE type IN ('table', 'view')
            AND name NOT LIKE 'sqlite_%'
          ORDER BY name`
      )
      .all() as unknown as SqliteTableRow[];

    const allowed = new Set(this.#config.allowedTables);
    return rows
      .map((row) => ({ schema: "main", table: row.name }))
      .filter((table) => this.#config.allowedSchemas.includes("main") && allowed.has(tableKey(table)));
  }

  async describeTable(table: TableRef): Promise<readonly ColumnInfo[]> {
    const resolved = await this.resolveTable(table);
    const rows = this.#database
      .prepare(`PRAGMA main.table_info(${this.quoteIdentifier(resolved.table)})`)
      .all() as unknown as SqliteColumnRow[];

    return rows.map((row) => ({
      name: row.name,
      dataType: row.type || "unknown",
      nullable: row.notnull === 0,
      ordinalPosition: row.cid + 1,
      restricted: isRestrictedColumn(row.name, this.#config.restrictedColumns)
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

  placeholder(_position: number): string {
    return "?";
  }

  async executeAggregate(query: AggregateQuery, requestedMaxRows?: number): Promise<AggregateResult> {
    const maxRows = Math.min(requestedMaxRows ?? this.maxResultRows, this.maxResultRows);
    const parameters = query.values as readonly SQLInputValue[];
    const rows = this.#database.prepare(query.text).all(...parameters) as unknown as Record<string, unknown>[];
    return {
      rows: rows.slice(0, maxRows).map(normalizeDatabaseRow),
      truncated: rows.length > maxRows
    };
  }

  async close(): Promise<void> {
    this.#database.close();
  }
}
