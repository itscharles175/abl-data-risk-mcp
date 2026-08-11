import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";

import { validateFieldMappings } from "../src/domain/mapping.js";
import { SourceRegistry } from "../src/infrastructure/sql/registry.js";
import { runStratification, runVintageAnalysis } from "../src/services/analysis.js";
import { createSqliteFixture, type SqliteFixture } from "./helpers/sqlite-fixture.js";

let fixture: SqliteFixture;
let registry: SourceRegistry;

beforeEach(() => {
  fixture = createSqliteFixture();
  registry = new SourceRegistry(fixture.config);
});

afterEach(async () => {
  await registry.close();
  fixture.cleanup();
});

test("SQLite adapter exposes only the allowlisted table and metadata", async () => {
  const adapter = registry.get("fixture");
  assert.deepEqual(await adapter.listTables(), [{ schema: "main", table: "loan_tape" }]);
  const columns = await adapter.describeTable({ schema: "main", table: "loan_tape" });
  assert.equal(columns.length, 14);
  assert.equal(columns.find((column) => column.name === "current_balance")?.dataType, "NUMERIC");
});

test("mapping is ready for both stratification and vintage", async () => {
  const adapter = registry.get("fixture");
  const columns = (await adapter.describeTable({ schema: "main", table: "loan_tape" })).map((column) => ({
    name: column.name,
    type: column.dataType,
    nullable: column.nullable
  }));
  assert.equal(validateFieldMappings(columns, fixture.mappings, "stratification").ready, true);
  assert.equal(validateFieldMappings(columns, fixture.mappings, "vintage").ready, true);
});

test("stratification reconciles an explicit snapshot and computes weighted averages", async () => {
  const result = await runStratification(registry.get("fixture"), {
    table: { schema: "main", table: "loan_tape" },
    mappings: fixture.mappings,
    asOfDate: "2025-03-31",
    dimension: "risk_rating",
    balanceField: "outstanding_balance",
    weightedAverageFields: ["interest_rate"],
    minimumCohortSize: 1,
    maxGroups: 20
  });

  assert.deepEqual(result.totals, { loanCount: 3, balance: "410" });
  assert.equal(result.reconciliation.passed, true);
  assert.deepEqual(
    result.rows.map((row) => [row.bucket, row.loanCount, row.balance]),
    [
      ["A", 2, "260"],
      ["B", 1, "150"]
    ]
  );
  assert.equal(result.rows[0]?.weightedAverages.interest_rate, "5.6923076923076925");
});

test("numeric stratification preserves declared bucket order and rejects boundary overlap", async () => {
  const baseInput = {
    table: { schema: "main", table: "loan_tape" },
    mappings: fixture.mappings,
    asOfDate: "2025-03-31",
    dimension: "interest_rate",
    balanceField: "outstanding_balance",
    minimumCohortSize: 1,
    maxGroups: 20
  } as const;

  const result = await runStratification(registry.get("fixture"), {
    ...baseInput,
    buckets: [
      { label: "Low", upper: 5.5 },
      { label: "Middle", lower: 5.5, upper: 6.5 },
      { label: "High", lower: 6.5 }
    ]
  });

  assert.deepEqual(
    result.rows.map((row) => [row.bucket, row.loanCount, row.balance]),
    [
      ["Low", 1, "80"],
      ["Middle", 1, "180"],
      ["High", 1, "150"]
    ]
  );

  await assert.rejects(
    runStratification(registry.get("fixture"), {
      ...baseInput,
      buckets: [
        { label: "Up to six", upper: 6, includeUpper: true },
        { label: "Six and above", lower: 6 }
      ]
    }),
    /overlaps the previous bucket at its boundary/
  );
});

test("stratification complementarily suppresses a second cell for a single small cohort", async () => {
  const result = await runStratification(registry.get("fixture"), {
    table: { schema: "main", table: "loan_tape" },
    mappings: fixture.mappings,
    asOfDate: "2025-03-31",
    dimension: "risk_rating",
    balanceField: "outstanding_balance",
    weightedAverageFields: ["interest_rate"],
    minimumCohortSize: 2,
    maxGroups: 20
  });

  assert.deepEqual(result.totals, { loanCount: 3, balance: "410" });
  assert.deepEqual(
    result.rows.map((row) => ({
      bucket: row.bucket,
      loanCount: row.loanCount,
      balance: row.balance,
      balanceShare: row.balanceShare,
      weightedAverage: row.weightedAverages.interest_rate,
      suppressed: row.suppressed
    })),
    [
      {
        bucket: "A",
        loanCount: null,
        balance: null,
        balanceShare: null,
        weightedAverage: null,
        suppressed: true
      },
      {
        bucket: "B",
        loanCount: null,
        balance: null,
        balanceShare: null,
        weightedAverage: null,
        suppressed: true
      }
    ]
  );
  assert.ok(result.warnings.some((warning) => warning.includes("plus complementary cells")));
});

test("stratification rejects identifier-like dimensions and nonnumeric weighted averages", async () => {
  const baseInput = {
    table: { schema: "main", table: "loan_tape" },
    mappings: fixture.mappings,
    asOfDate: "2025-03-31",
    balanceField: "outstanding_balance",
    minimumCohortSize: 1,
    maxGroups: 20
  } as const;

  await assert.rejects(
    runStratification(registry.get("fixture"), { ...baseInput, dimension: "borrower_id" }),
    /restricted from aggregate output/
  );
  await assert.rejects(
    runStratification(registry.get("fixture"), {
      ...baseInput,
      dimension: "risk_rating",
      weightedAverageFields: ["loan_status"]
    }),
    /must be a canonical numeric field/
  );
});

test("vintage analysis fixes cohort denominators and returns sparse seasoned points", async () => {
  const result = await runVintageAnalysis(registry.get("fixture"), {
    table: { schema: "main", table: "loan_tape" },
    mappings: fixture.mappings,
    cohortGrain: "month",
    maxMonthsOnBook: 24,
    delinquencyThresholdDays: 30,
    minimumCohortSize: 1,
    maxPoints: 100
  });

  assert.equal(result.metricAvailability.cumulativeNetLoss, true);
  assert.equal(result.metricAvailability.delinquency, true);
  assert.equal(result.points.length, 6);
  const aprilAtElevenMonths = result.points.find(
    (point) => point.cohort === "2024-04-01" && point.monthsOnBook === 11
  );
  assert.equal(aprilAtElevenMonths?.originalCohortBalance, "250");
  assert.equal(aprilAtElevenMonths?.currentBalance, "180");
  assert.equal(aprilAtElevenMonths?.cumulativeNetLoss, "8");
  assert.equal(aprilAtElevenMonths?.cumulativeNetLossRate, "0.032");
  assert.equal(aprilAtElevenMonths?.delinquentBalanceRate, "1");
});

test("vintage analysis returns null delinquency metrics when DPD is not mapped", async () => {
  const result = await runVintageAnalysis(registry.get("fixture"), {
    table: { schema: "main", table: "loan_tape" },
    mappings: fixture.mappings.filter((mapping) => mapping.canonicalField !== "days_past_due"),
    cohortGrain: "quarter",
    maxMonthsOnBook: 24,
    delinquencyThresholdDays: 30,
    minimumCohortSize: 1,
    maxPoints: 100
  });

  assert.equal(result.metricAvailability.delinquency, false);
  assert.ok(result.points.length > 0);
  assert.ok(result.points.every((point) => point.delinquentBalance === null));
  assert.ok(result.points.every((point) => point.delinquentBalanceRate === null));
});
