import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import type { AppConfig } from "../../src/config.js";
import type { FieldMapping } from "../../src/domain/mapping.js";

export interface SqliteFixture {
  readonly directory: string;
  readonly databasePath: string;
  readonly configPath: string;
  readonly config: AppConfig;
  readonly mappings: readonly FieldMapping[];
  cleanup(): void;
}

export function createSqliteFixture(): SqliteFixture {
  const directory = mkdtempSync(join(tmpdir(), "abl-mcp-test-"));
  const databasePath = join(directory, "loan-tape.sqlite");
  const configPath = join(directory, "config.json");
  const database = new DatabaseSync(databasePath);

  database.exec(`
    CREATE TABLE loan_tape (
      as_of_dt DATE NOT NULL,
      facility_no TEXT NOT NULL,
      loan_no TEXT NOT NULL,
      borrower_no TEXT NOT NULL,
      loan_status TEXT NOT NULL,
      default_flag BOOLEAN NOT NULL,
      orig_date DATE NOT NULL,
      original_principal NUMERIC NOT NULL,
      current_balance NUMERIC NOT NULL,
      days_past_due INTEGER NOT NULL,
      chargeoff NUMERIC NOT NULL,
      recovery NUMERIC NOT NULL,
      risk_grade TEXT,
      coupon_rate NUMERIC
    );
  `);

  const insert = database.prepare(`
    INSERT INTO loan_tape (
      as_of_dt, facility_no, loan_no, borrower_no, loan_status, default_flag,
      orig_date, original_principal, current_balance, days_past_due,
      chargeoff, recovery, risk_grade, coupon_rate
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const rows = [
    ["2025-01-31", "F1", "L1", "B1", "current", 0, "2024-01-15", 100, 90, 0, 0, 0, "A", 5.0],
    ["2025-02-28", "F1", "L1", "B1", "current", 0, "2024-01-15", 100, 85, 0, 0, 0, "A", 5.0],
    ["2025-03-31", "F1", "L1", "B1", "current", 0, "2024-01-15", 100, 80, 0, 0, 0, "A", 5.0],
    ["2025-01-31", "F1", "L2", "B2", "current", 0, "2024-01-20", 200, 170, 10, 0, 0, "B", 7.0],
    ["2025-02-28", "F1", "L2", "B2", "delinquent", 0, "2024-01-20", 200, 160, 35, 0, 0, "B", 7.0],
    ["2025-03-31", "F1", "L2", "B2", "delinquent", 0, "2024-01-20", 200, 150, 65, 0, 0, "B", 7.0],
    ["2025-01-31", "F2", "L3", "B3", "current", 0, "2024-04-01", 250, 220, 0, 0, 0, "A", 6.0],
    ["2025-02-28", "F2", "L3", "B3", "current", 0, "2024-04-01", 250, 200, 0, 0, 0, "A", 6.0],
    ["2025-03-31", "F2", "L3", "B3", "default", 1, "2024-04-01", 250, 180, 40, 10, 2, "A", 6.0]
  ] as const;

  for (const row of rows) insert.run(...row);
  database.close();

  const config: AppConfig = {
    sources: [
      {
        id: "fixture",
        dialect: "sqlite",
        path: databasePath,
        allowedSchemas: ["main"],
        allowedTables: ["main.loan_tape"],
        restrictedColumns: [],
        statementTimeoutMs: 5_000,
        maxResultRows: 1_000
      }
    ],
    analysis: { maxGroups: 50, maxVintagePoints: 500, minimumCohortSize: 1 }
  };
  writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");

  const mappings: readonly FieldMapping[] = [
    { sourceColumn: "as_of_dt", canonicalField: "as_of_date" },
    { sourceColumn: "facility_no", canonicalField: "facility_id" },
    { sourceColumn: "loan_no", canonicalField: "loan_id" },
    { sourceColumn: "borrower_no", canonicalField: "borrower_id" },
    { sourceColumn: "loan_status", canonicalField: "loan_status" },
    { sourceColumn: "default_flag", canonicalField: "default_flag" },
    { sourceColumn: "orig_date", canonicalField: "origination_date" },
    { sourceColumn: "original_principal", canonicalField: "original_balance" },
    { sourceColumn: "current_balance", canonicalField: "outstanding_balance" },
    { sourceColumn: "days_past_due", canonicalField: "days_past_due" },
    { sourceColumn: "chargeoff", canonicalField: "charge_off_amount" },
    { sourceColumn: "recovery", canonicalField: "recovery_amount" },
    { sourceColumn: "risk_grade", canonicalField: "risk_rating" },
    { sourceColumn: "coupon_rate", canonicalField: "interest_rate" }
  ];

  return {
    directory,
    databasePath,
    configPath,
    config,
    mappings,
    cleanup: () => rmSync(directory, { recursive: true, force: true })
  };
}
