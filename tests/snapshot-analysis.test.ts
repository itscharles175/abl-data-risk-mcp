import assert from "node:assert/strict";
import { test } from "node:test";

import {
  runSnapshotStratification,
  runSnapshotVintageAnalysis,
  type CanonicalSnapshotRecord,
  type ImmutableSnapshotLineage,
  type SnapshotStratificationInput,
  type SnapshotVintageInput
} from "../src/services/snapshot-analysis.js";

const LINEAGE: ImmutableSnapshotLineage = {
  snapshotHash: "1".repeat(64),
  mappingHash: "2".repeat(64),
  dictionaryHash: "3".repeat(64),
  recipeHash: "4".repeat(64)
};

const STRAT_RECORDS: readonly CanonicalSnapshotRecord[] = [
  Object.freeze({
    as_of_date: "2025-03-31",
    loan_id: "SECRET-A1",
    borrower_id: "SECRET-BORROWER-1",
    risk_rating: "A",
    outstanding_balance: "0.1",
    interest_rate: "5.1"
  }),
  Object.freeze({
    as_of_date: "2025-03-31",
    loan_id: "SECRET-A2",
    borrower_id: "SECRET-BORROWER-2",
    risk_rating: "A",
    outstanding_balance: "0.2",
    interest_rate: "5.2"
  }),
  Object.freeze({
    as_of_date: "2025-03-31",
    loan_id: "SECRET-B1",
    borrower_id: "SECRET-BORROWER-3",
    risk_rating: "B",
    outstanding_balance: "0.3",
    interest_rate: "6"
  }),
  Object.freeze({
    as_of_date: "2025-03-31",
    loan_id: "SECRET-C1",
    borrower_id: "SECRET-BORROWER-4",
    risk_rating: "C",
    outstanding_balance: "1.1",
    interest_rate: "7"
  }),
  Object.freeze({
    as_of_date: "2025-03-31",
    loan_id: "SECRET-C2",
    borrower_id: "SECRET-BORROWER-5",
    risk_rating: "C",
    outstanding_balance: "2.2",
    interest_rate: "7.5"
  }),
  Object.freeze({
    as_of_date: "2025-03-31",
    loan_id: "SECRET-C3",
    borrower_id: "SECRET-BORROWER-6",
    risk_rating: "C",
    outstanding_balance: "3.3",
    interest_rate: "8"
  })
];

function stratInput(
  overrides: Partial<SnapshotStratificationInput> = {}
): SnapshotStratificationInput {
  return {
    records: STRAT_RECORDS,
    lineage: LINEAGE,
    asOfDate: "2025-03-31",
    dimension: "risk_rating",
    balanceField: "outstanding_balance",
    weightedAverageFields: ["interest_rate"],
    minimumCohortSize: 2,
    maxRecords: 100,
    maxGroups: 20,
    ...overrides
  };
}

test("snapshot stratification is exact, complementarily suppressed, immutable, and deterministic", () => {
  const before = JSON.stringify(STRAT_RECORDS);
  const result = runSnapshotStratification(stratInput());
  const reordered = runSnapshotStratification(
    stratInput({ records: [...STRAT_RECORDS].reverse() })
  );

  assert.equal(JSON.stringify(STRAT_RECORDS), before);
  assert.deepEqual(result.totals, { loanCount: 6, balance: "7.2" });
  assert.deepEqual(
    result.rows.map((row) => ({
      bucket: row.bucket,
      count: row.loanCount,
      balance: row.balance,
      weightedAverage: row.weightedAverages.interest_rate,
      suppressed: row.suppressed
    })),
    [
      { bucket: "A", count: null, balance: null, weightedAverage: null, suppressed: true },
      { bucket: "B", count: null, balance: null, weightedAverage: null, suppressed: true },
      { bucket: "C", count: 3, balance: "6.6", weightedAverage: "7.666666666666666666666666666666666666667", suppressed: false }
    ]
  );
  assert.equal(result.lineage.sourceIsImmutableSnapshot, true);
  assert.equal(
    result.lineage.analysisHash,
    "7c3b18e075c72ea434182c5a136d22d37961b87b007a690362d851a04c40aa2c"
  );
  assert.equal(reordered.lineage.analysisHash, result.lineage.analysisHash);
  assert.deepEqual(reordered, result);
  assert.equal(JSON.stringify(result).includes("SECRET-"), false);
});

test("snapshot stratification preserves explicit decimal bucket order", () => {
  const records = [
    { as_of_date: "2025-03-31", interest_rate: "7", outstanding_balance: "1" },
    { as_of_date: "2025-03-31", interest_rate: null, outstanding_balance: "2" },
    { as_of_date: "2025-03-31", interest_rate: "4.5", outstanding_balance: "3" },
    { as_of_date: "2025-03-31", interest_rate: "5.5", outstanding_balance: "4" },
    { as_of_date: "2025-03-31", interest_rate: "6.5", outstanding_balance: "5" }
  ] as const;
  const result = runSnapshotStratification(
    stratInput({
      records,
      dimension: "interest_rate",
      weightedAverageFields: [],
      minimumCohortSize: 1,
      buckets: [
        { label: "Low", upper: "5.5" },
        { label: "Middle", lower: "5.5", upper: "6.5" },
        { label: "High", lower: "6.5" }
      ]
    })
  );

  assert.deepEqual(
    result.rows.map((row) => [row.bucket, row.loanCount, row.balance]),
    [
      ["Low", 1, "3"],
      ["Middle", 1, "4"],
      ["High", 2, "6"],
      ["Unknown/Unmapped", 1, "2"]
    ]
  );
});

test("complementary suppression never selects a cell from sensitive balance ordering", () => {
  const records = [
    { as_of_date: "2025-03-31", risk_rating: "A", outstanding_balance: "1000" },
    { as_of_date: "2025-03-31", risk_rating: "A", outstanding_balance: "1000" },
    { as_of_date: "2025-03-31", risk_rating: "B", outstanding_balance: "1" },
    { as_of_date: "2025-03-31", risk_rating: "C", outstanding_balance: "1" },
    { as_of_date: "2025-03-31", risk_rating: "C", outstanding_balance: "1" }
  ] as const;
  const result = runSnapshotStratification(
    stratInput({ records, weightedAverageFields: [], minimumCohortSize: 2 })
  );
  assert.deepEqual(
    result.rows.map((row) => [row.bucket, row.suppressed]),
    [
      ["A", true],
      ["B", true],
      ["C", false]
    ]
  );
});

test("snapshot stratification fails closed when exact totals would reveal a sub-minimum population", () => {
  assert.throws(
    () =>
      runSnapshotStratification(
        stratInput({
          records: [
            { as_of_date: "2025-03-31", risk_rating: "A", outstanding_balance: "100" }
          ],
          weightedAverageFields: [],
          minimumCohortSize: 2
        })
      ),
    /Stratification population is smaller than minimumCohortSize/
  );
});

test("snapshot stratification rejects overlapping, unsorted, and inexact buckets", () => {
  assert.throws(
    () =>
      runSnapshotStratification(
        stratInput({
          dimension: "interest_rate",
          buckets: [
            { label: "First", upper: "6", includeUpper: true },
            { label: "Second", lower: "6" }
          ]
        })
      ),
    /overlaps the previous bucket at its boundary/
  );
  assert.throws(
    () =>
      runSnapshotStratification(
        stratInput({
          dimension: "interest_rate",
          buckets: [
            { label: "High", lower: "10" },
            { label: "Low", lower: "0", upper: "10" }
          ]
        })
      ),
    /follows an upper-unbounded bucket/
  );
  assert.throws(
    () =>
      runSnapshotStratification(
        stratInput({
          dimension: "interest_rate",
          buckets: [{ label: "Scientific", upper: "1e2" }]
        })
      ),
    /canonical decimal string/
  );
});

test("snapshot stratification enforces privacy and execution bounds", () => {
  assert.throws(
    () => runSnapshotStratification(stratInput({ dimension: "borrower_id" })),
    /cannot expose identifier values/
  );
  assert.throws(
    () => runSnapshotStratification(stratInput({ dimension: "collateral_record_id" })),
    /cannot expose identifier values/
  );
  assert.throws(
    () => runSnapshotStratification(stratInput({ maxRecords: 5 })),
    /exceeding maxRecords/
  );
  assert.throws(
    () => runSnapshotStratification(stratInput({ maxGroups: 2, minimumCohortSize: 1 })),
    /more than 2 groups/
  );
  assert.throws(
    () =>
      runSnapshotStratification(
        stratInput({
          records: [{ as_of_date: "2025-03-31", risk_rating: "A", outstanding_balance: 0.1 }],
          minimumCohortSize: 1
        })
      ),
    /exact canonical decimal string/
  );
  assert.throws(
    () =>
      runSnapshotStratification(
        stratInput({
          records: [
            { as_of_date: "2025-03-31", default_flag: "false", outstanding_balance: "1" }
          ],
          dimension: "default_flag",
          weightedAverageFields: [],
          minimumCohortSize: 1
        })
      ),
    /must be a canonical boolean/
  );
  assert.throws(
    () =>
      runSnapshotStratification(
        stratInput({
          records: [
            { as_of_date: "2025-03-31", maturity_date: "2025-02-30", outstanding_balance: "1" }
          ],
          dimension: "maturity_date",
          weightedAverageFields: [],
          minimumCohortSize: 1
        })
      ),
    /valid YYYY-MM-DD date/
  );
  assert.throws(
    () =>
      runSnapshotStratification(
        stratInput({ lineage: { ...LINEAGE, snapshotHash: "A".repeat(64) } })
      ),
    /lowercase SHA-256 hash/
  );
});

test("snapshot analysis lineage rejects missing, extra, and substituted hash names", () => {
  const validHash = "5".repeat(64);
  const malformed = {
    snapshotHash: validHash,
    mappingHash: validHash,
    dictionaryHash: validHash,
    inventedHash: validHash
  } as unknown as ImmutableSnapshotLineage;
  assert.throws(
    () => runSnapshotStratification(stratInput({ lineage: malformed })),
    /exactly snapshot, mapping, dictionary, and recipe hashes/
  );
  assert.throws(
    () =>
      runSnapshotStratification(
        stratInput({ lineage: { ...LINEAGE, extraHash: validHash } as ImmutableSnapshotLineage })
      ),
    /exactly snapshot, mapping, dictionary, and recipe hashes/
  );
});

const VINTAGE_RECORDS: readonly CanonicalSnapshotRecord[] = [
  {
    loan_id: "SUPER-SECRET-LOAN-1",
    origination_date: "2024-01-15",
    as_of_date: "2024-01-31",
    original_balance: "100",
    outstanding_balance: "100",
    charge_off_amount: "0",
    recovery_amount: "0",
    days_past_due: "0"
  },
  {
    loan_id: "SUPER-SECRET-LOAN-1",
    origination_date: "2024-01-15",
    as_of_date: "2024-02-01",
    original_balance: "100",
    outstanding_balance: "95",
    charge_off_amount: "5",
    recovery_amount: "0",
    days_past_due: "10"
  },
  {
    loan_id: "SUPER-SECRET-LOAN-1",
    origination_date: "2024-01-15",
    as_of_date: "2024-02-29",
    original_balance: "100",
    outstanding_balance: "90",
    charge_off_amount: "10",
    recovery_amount: "2",
    days_past_due: "30"
  },
  {
    loan_id: "SUPER-SECRET-LOAN-2",
    origination_date: "2024-01-20",
    as_of_date: "2024-01-31",
    original_balance: "50",
    outstanding_balance: "50",
    charge_off_amount: "0",
    recovery_amount: "0",
    days_past_due: "0"
  },
  {
    loan_id: "SUPER-SECRET-LOAN-2",
    origination_date: "2024-01-20",
    as_of_date: "2024-03-31",
    original_balance: "50",
    outstanding_balance: "40",
    charge_off_amount: "0",
    recovery_amount: "0",
    days_past_due: "0"
  },
  {
    loan_id: "SUPER-SECRET-LOAN-3",
    origination_date: "2024-02-10",
    as_of_date: "2024-02-29",
    original_balance: "200",
    outstanding_balance: "200",
    charge_off_amount: "0",
    recovery_amount: "0",
    days_past_due: "0"
  }
];

function vintageInput(overrides: Partial<SnapshotVintageInput> = {}): SnapshotVintageInput {
  return {
    records: VINTAGE_RECORDS,
    lineage: LINEAGE,
    cohortGrain: "month",
    asOfDate: "2024-03-31",
    maxMonthsOnBook: 3,
    delinquencyThresholdDays: 30,
    minimumCohortSize: 1,
    maxRecords: 100,
    maxPoints: 100,
    ...overrides
  };
}

test("snapshot vintage fixes denominators, selects latest monthly observations, and nulls missing points", () => {
  const result = runSnapshotVintageAnalysis(vintageInput());
  const reordered = runSnapshotVintageAnalysis(
    vintageInput({ records: [...VINTAGE_RECORDS].reverse() })
  );

  assert.equal(result.analysisAsOfDate, "2024-03-31");
  assert.deepEqual(result.metricAvailability, { cumulativeNetLoss: true, delinquency: true });
  assert.equal(result.points.length, 8);
  const januaryMobOne = result.points.find(
    (point) => point.cohort === "2024-01-01" && point.monthsOnBook === 1
  );
  assert.deepEqual(januaryMobOne, {
    cohort: "2024-01-01",
    monthsOnBook: 1,
    seasoned: true,
    available: true,
    originalCohortLoanCount: 2,
    observedLoanCount: 1,
    originalCohortBalance: "150",
    currentBalance: "90",
    remainingBalanceFactor: "0.6",
    cumulativeNetLoss: "8",
    cumulativeNetLossRate: "0.05333333333333333333333333333333333333333",
    delinquentBalance: "90",
    delinquentBalanceRate: "1",
    suppressed: false
  });
  const januaryMobThree = result.points.find(
    (point) => point.cohort === "2024-01-01" && point.monthsOnBook === 3
  );
  assert.equal(januaryMobThree?.seasoned, false);
  assert.equal(januaryMobThree?.available, false);
  assert.equal(januaryMobThree?.currentBalance, null);
  const februaryMobOne = result.points.find(
    (point) => point.cohort === "2024-02-01" && point.monthsOnBook === 1
  );
  assert.equal(februaryMobOne?.seasoned, true);
  assert.equal(februaryMobOne?.available, false);
  assert.equal(februaryMobOne?.observedLoanCount, null);
  assert.equal(februaryMobOne?.originalCohortBalance, "200");
  assert.equal(JSON.stringify(result).includes("SUPER-SECRET"), false);
  assert.equal(
    result.lineage.analysisHash,
    "81d471d8544925e315b3e7843fc34667ac51533cc4724e58656c5fae8d30c605"
  );
  assert.equal(reordered.lineage.analysisHash, result.lineage.analysisHash);
  assert.deepEqual(reordered, result);
});

test("snapshot vintage applies complementary suppression to the only small cohort", () => {
  const result = runSnapshotVintageAnalysis(vintageInput({ minimumCohortSize: 2 }));
  assert.ok(result.points.length > 0);
  assert.ok(result.points.every((point) => point.suppressed));
  assert.ok(result.points.every((point) => point.originalCohortLoanCount === null));
  assert.ok(result.points.every((point) => point.currentBalance === null));
});

test("snapshot vintage nulls globally unavailable optional metrics", () => {
  const records = VINTAGE_RECORDS.map((record, index) =>
    index === 0 ? { ...record, recovery_amount: null, days_past_due: null } : record
  );
  const result = runSnapshotVintageAnalysis(vintageInput({ records }));

  assert.deepEqual(result.metricAvailability, { cumulativeNetLoss: false, delinquency: false });
  assert.ok(result.points.every((point) => point.cumulativeNetLoss === null));
  assert.ok(result.points.every((point) => point.cumulativeNetLossRate === null));
  assert.ok(result.points.every((point) => point.delinquentBalance === null));
  assert.ok(result.points.every((point) => point.delinquentBalanceRate === null));
});

test("snapshot vintage rejects unstable denominators and conflicting duplicate observations without leaking ids", () => {
  const unstable = [
    ...VINTAGE_RECORDS,
    { ...VINTAGE_RECORDS[0]!, as_of_date: "2024-03-31", original_balance: "101" }
  ];
  assert.throws(
    () => runSnapshotVintageAnalysis(vintageInput({ records: unstable })),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.match(error.message, /conflicts with fixed cohort metadata/);
      assert.equal(error.message.includes("SUPER-SECRET"), false);
      return true;
    }
  );

  const conflicting = [
    ...VINTAGE_RECORDS,
    { ...VINTAGE_RECORDS[2]!, outstanding_balance: "89" }
  ];
  assert.throws(
    () => runSnapshotVintageAnalysis(vintageInput({ records: conflicting })),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.match(error.message, /conflicts with another observation/);
      assert.equal(error.message.includes("SUPER-SECRET"), false);
      return true;
    }
  );
});

test("snapshot vintage enforces point, record, date, and exact numeric bounds", () => {
  assert.throws(
    () => runSnapshotVintageAnalysis(vintageInput({ maxPoints: 7 })),
    /exceeding maxPoints 7/
  );
  assert.throws(
    () => runSnapshotVintageAnalysis(vintageInput({ maxRecords: 5 })),
    /exceeding maxRecords 5/
  );
  assert.throws(
    () =>
      runSnapshotVintageAnalysis(
        vintageInput({ records: [{ ...VINTAGE_RECORDS[0]!, as_of_date: "2024-02-30" }] })
      ),
    /valid YYYY-MM-DD date/
  );
  assert.throws(
    () =>
      runSnapshotVintageAnalysis(
        vintageInput({ records: [{ ...VINTAGE_RECORDS[0]!, outstanding_balance: 100 }] })
      ),
    /exact canonical decimal string/
  );
});
