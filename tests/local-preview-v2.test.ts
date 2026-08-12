import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { SourceRegistry } from "../src/infrastructure/sql/registry.js";
import {
  runLocalStratificationPreviewV2,
  runLocalVintagePreviewV2
} from "../src/services/local-preview-v2.js";
import {
  runSnapshotStratification,
  runSnapshotVintageAnalysis
} from "../src/services/snapshot-analysis.js";
import { createSqliteFixture, type SqliteFixture } from "./helpers/sqlite-fixture.js";

let fixture: SqliteFixture;
let registry: SourceRegistry;

before(() => {
  fixture = createSqliteFixture();
  registry = new SourceRegistry(fixture.config);
});

after(async () => {
  await registry.close();
  fixture.cleanup();
});

test("local v2 stratification is the governed deterministic engine, not SQL aggregate math", async () => {
  const preview = await runLocalStratificationPreviewV2(registry.get("fixture"), {
    table: { schema: "main", table: "loan_tape" },
    mappings: fixture.mappings,
    asOfDate: "2025-03-31",
    dimension: "risk_rating",
    weightedAverageFields: ["interest_rate"],
    minimumCohortSize: 1,
    maxGroups: 50
  });
  const governed = runSnapshotStratification({
    records: [
      { as_of_date: "2025-03-31", risk_rating: "A", outstanding_balance: "80", interest_rate: "5" },
      { as_of_date: "2025-03-31", risk_rating: "B", outstanding_balance: "150", interest_rate: "7" },
      { as_of_date: "2025-03-31", risk_rating: "A", outstanding_balance: "180", interest_rate: "6" }
    ],
    lineage: {
      snapshotHash: preview.lineage.snapshotHash,
      mappingHash: preview.lineage.mappingHash,
      dictionaryHash: preview.lineage.dictionaryHash,
      recipeHash: preview.lineage.recipeHash
    },
    asOfDate: "2025-03-31",
    dimension: "risk_rating",
    weightedAverageFields: ["interest_rate"],
    minimumCohortSize: 1,
    maxRecords: 1_000,
    maxGroups: 50
  });
  assert.equal(preview.lineage.analysisHash, governed.lineage.analysisHash);
  assert.deepEqual(preview.totals, { loanCount: 3, balance: "410" });
});

test("local v2 vintage preserves exact fixed denominators through the governed engine", async () => {
  const preview = await runLocalVintagePreviewV2(registry.get("fixture"), {
    table: { schema: "main", table: "loan_tape" },
    mappings: fixture.mappings,
    cohortGrain: "quarter",
    asOfDate: "2025-03-31",
    maxMonthsOnBook: 120,
    delinquencyThresholdDays: 30,
    minimumCohortSize: 1,
    maxPoints: 500
  });
  const replay = runSnapshotVintageAnalysis({
    records: [
      { loan_id: "L1", origination_date: "2024-01-15", as_of_date: "2025-01-31", original_balance: "100", outstanding_balance: "90", days_past_due: "0", charge_off_amount: "0", recovery_amount: "0" },
      { loan_id: "L1", origination_date: "2024-01-15", as_of_date: "2025-02-28", original_balance: "100", outstanding_balance: "85", days_past_due: "0", charge_off_amount: "0", recovery_amount: "0" },
      { loan_id: "L1", origination_date: "2024-01-15", as_of_date: "2025-03-31", original_balance: "100", outstanding_balance: "80", days_past_due: "0", charge_off_amount: "0", recovery_amount: "0" },
      { loan_id: "L2", origination_date: "2024-01-20", as_of_date: "2025-01-31", original_balance: "200", outstanding_balance: "170", days_past_due: "10", charge_off_amount: "0", recovery_amount: "0" },
      { loan_id: "L2", origination_date: "2024-01-20", as_of_date: "2025-02-28", original_balance: "200", outstanding_balance: "160", days_past_due: "35", charge_off_amount: "0", recovery_amount: "0" },
      { loan_id: "L2", origination_date: "2024-01-20", as_of_date: "2025-03-31", original_balance: "200", outstanding_balance: "150", days_past_due: "65", charge_off_amount: "0", recovery_amount: "0" },
      { loan_id: "L3", origination_date: "2024-04-01", as_of_date: "2025-01-31", original_balance: "250", outstanding_balance: "220", days_past_due: "0", charge_off_amount: "0", recovery_amount: "0" },
      { loan_id: "L3", origination_date: "2024-04-01", as_of_date: "2025-02-28", original_balance: "250", outstanding_balance: "200", days_past_due: "0", charge_off_amount: "0", recovery_amount: "0" },
      { loan_id: "L3", origination_date: "2024-04-01", as_of_date: "2025-03-31", original_balance: "250", outstanding_balance: "180", days_past_due: "40", charge_off_amount: "10", recovery_amount: "2" }
    ],
    lineage: {
      snapshotHash: preview.lineage.snapshotHash,
      mappingHash: preview.lineage.mappingHash,
      dictionaryHash: preview.lineage.dictionaryHash,
      recipeHash: preview.lineage.recipeHash
    },
    cohortGrain: "quarter",
    asOfDate: "2025-03-31",
    maxMonthsOnBook: 120,
    delinquencyThresholdDays: 30,
    minimumCohortSize: 1,
    maxRecords: 1_000,
    maxPoints: 500
  });
  assert.equal(preview.lineage.analysisHash, replay.lineage.analysisHash);
  assert.ok(preview.points.length > 0);
});
