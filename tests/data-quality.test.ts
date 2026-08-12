import assert from "node:assert/strict";
import test from "node:test";

import {
  reconcileControlTotals,
  runDataQuality,
  type DataQualityProfile
} from "../src/domain/data-quality.js";

const profile: DataQualityProfile = {
  id: "loan-tape-certification",
  version: "1.0.0",
  entity: "loan_snapshot",
  keyFields: ["loan_id", "as_of_date"],
  requiredFields: ["loan_id", "as_of_date", "outstanding_balance", "currency_code"],
  balanceField: "outstanding_balance",
  asOfField: "as_of_date",
  expectedAsOfDate: "2026-07-31",
  currencyField: "currency_code",
  expectedCurrency: "USD",
  exactDecimalFields: ["original_balance"],
  nonNegativeFields: ["original_balance", "days_past_due"],
  dateFields: ["origination_date", "maturity_date"],
  dateOrderRules: [
    { earlierField: "origination_date", laterField: "as_of_date" },
    { earlierField: "origination_date", laterField: "maturity_date", allowEqual: false }
  ],
  allowedValues: { loan_status: ["current", "delinquent", "default"] },
  maximumNullRates: { risk_rating: 0.5 },
  statusConsistency: {
    statusField: "loan_status",
    daysPastDueField: "days_past_due",
    currentStatuses: ["current"],
    delinquentStatuses: ["delinquent"],
    delinquentThresholdDays: 30
  },
  maximumSnapshotAgeDays: 45
};

test("a certified loan snapshot publishes with deterministic exact totals", () => {
  const records = [
    {
      loan_id: "L1",
      as_of_date: "2026-07-31",
      outstanding_balance: "100.10",
      original_balance: "120",
      currency_code: "usd",
      origination_date: "2025-01-01",
      maturity_date: "2028-01-01",
      loan_status: "current",
      days_past_due: "0",
      risk_rating: "A"
    },
    {
      loan_id: "L2",
      as_of_date: "2026-07-31",
      outstanding_balance: "200.20",
      original_balance: "250",
      currency_code: "USD",
      origination_date: "2024-06-15",
      maturity_date: "2027-06-15",
      loan_status: "delinquent",
      days_past_due: "45",
      risk_rating: null
    }
  ];

  const first = runDataQuality(records, profile, "2026-08-11T12:00:00Z");
  const reordered = runDataQuality([...records].reverse(), profile, "2026-08-11T12:00:00Z");

  assert.equal(first.publicationDecision, "publish");
  assert.equal(first.totalBalance, "300.3");
  assert.equal(first.currency, "USD");
  assert.deepEqual(first.findings, []);
  assert.equal(first.fingerprint, reordered.fingerprint);
});

test("critical grain, decimal, currency, freshness and chronology issues block publication", () => {
  const records = [
    {
      loan_id: "L1",
      as_of_date: "2026-07-30",
      outstanding_balance: 100.1,
      original_balance: "-1",
      currency_code: "USD",
      origination_date: "2028-01-01",
      maturity_date: "2027-01-01",
      loan_status: "current",
      days_past_due: "45",
      risk_rating: null
    },
    {
      loan_id: "L1",
      as_of_date: "2026-07-30",
      outstanding_balance: "25",
      original_balance: "50",
      currency_code: "EUR",
      origination_date: "not-a-date",
      maturity_date: "2029-01-01",
      loan_status: "unexpected",
      days_past_due: "0",
      risk_rating: null
    }
  ];

  const result = runDataQuality(records, profile, "2026-10-01T00:00:00Z");
  const codes = new Set(result.findings.map((finding) => finding.code));

  assert.equal(result.publicationDecision, "block");
  assert.ok(codes.has("duplicate_grain_key"));
  assert.ok(codes.has("exact_decimal_invalid"));
  assert.ok(codes.has("as_of_date_mismatch"));
  assert.ok(codes.has("mixed_currency_population"));
  assert.ok(codes.has("snapshot_stale"));
  assert.ok(codes.has("date_order_invalid"));
  assert.ok(codes.has("status_delinquency_inconsistent"));
  assert.ok(codes.has("code_value_unknown"));
  assert.ok(result.findings.every((finding) => !finding.message.includes("L1")));
});

test("a longitudinal loan history publishes through its certified cutoff", () => {
  const historyProfile: DataQualityProfile = {
    ...profile,
    id: "loan-history-certification",
    entity: "loan_history"
  };
  const records = [
    {
      loan_id: "L1",
      as_of_date: "2026-06-30",
      outstanding_balance: "120",
      original_balance: "150",
      currency_code: "USD",
      origination_date: "2025-01-01",
      maturity_date: "2028-01-01",
      loan_status: "current",
      days_past_due: "0",
      risk_rating: "A"
    },
    {
      loan_id: "L1",
      as_of_date: "2026-07-31",
      outstanding_balance: "100",
      original_balance: "150",
      currency_code: "USD",
      origination_date: "2025-01-01",
      maturity_date: "2028-01-01",
      loan_status: "current",
      days_past_due: "0",
      risk_rating: "A"
    }
  ];

  const result = runDataQuality(records, historyProfile, "2026-08-11T12:00:00Z");

  assert.equal(result.asOfMode, "through");
  assert.equal(result.publicationDecision, "publish");
  assert.equal(result.totalBalance, "220");
  assert.deepEqual(result.findings, []);
});

test("a longitudinal history blocks future rows and a missing cutoff", () => {
  const historyProfile: DataQualityProfile = {
    ...profile,
    id: "loan-history-certification",
    entity: "loan_history",
    asOfMode: "through"
  };
  const base = {
    loan_id: "L1",
    outstanding_balance: "100",
    original_balance: "150",
    currency_code: "USD",
    origination_date: "2025-01-01",
    maturity_date: "2028-01-01",
    loan_status: "current",
    days_past_due: "0",
    risk_rating: "A"
  };

  const future = runDataQuality(
    [{ ...base, as_of_date: "2026-08-01" }],
    historyProfile,
    "2026-08-11T12:00:00Z"
  );
  const historicalOnly = runDataQuality(
    [{ ...base, as_of_date: "2026-06-30" }],
    historyProfile,
    "2026-08-11T12:00:00Z"
  );

  assert.equal(future.publicationDecision, "block");
  assert.ok(future.findings.some((finding) => finding.code === "as_of_date_after_cutoff"));
  assert.ok(future.findings.some((finding) => finding.code === "as_of_cutoff_missing"));
  assert.equal(historicalOnly.publicationDecision, "block");
  assert.ok(historicalOnly.findings.some((finding) => finding.code === "as_of_cutoff_missing"));
  assert.ok(!historicalOnly.findings.some((finding) => finding.code === "as_of_date_mismatch"));
});

test("control-total reconciliation is exact, reason-coded and tolerance aware", () => {
  const exact = reconcileControlTotals(
    { rowCount: 2, balance: "300.30", currency: "usd" },
    { rowCount: 2, balance: "300.3", currency: "USD" }
  );
  assert.equal(exact.passed, true);
  assert.deepEqual(exact.reasonCodes, []);

  const broken = reconcileControlTotals(
    { rowCount: 100, balance: "1000", currency: "USD" },
    { rowCount: 98, balance: "999.98", currency: "EUR" },
    { rowCount: 1, balance: "0.01" }
  );
  assert.equal(broken.passed, false);
  assert.deepEqual(broken.reasonCodes, [
    "row_count_out_of_tolerance",
    "balance_out_of_tolerance",
    "currency_mismatch"
  ]);
  assert.deepEqual(broken.difference, { rowCount: -2, balance: "-0.02" });
});
