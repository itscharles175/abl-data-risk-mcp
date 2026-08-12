import assert from "node:assert/strict";
import { test } from "node:test";

import {
  calculateArBorrowingBase,
  type ArBorrowingBasePolicyVersion,
  type ArReceivable
} from "../src/domain/borrowing-base.js";

const fullPolicy: ArBorrowingBasePolicyVersion = {
  policyId: "facility-1-ar",
  version: "3",
  effectiveFrom: "2025-01-01",
  effectiveTo: "2026-01-01",
  currencyCode: "USD",
  eligibilityRules: [
    {
      ruleId: "past-due",
      version: "2",
      effectiveFrom: "2025-01-01",
      priority: 10,
      reasonCode: "PAST_DUE_90",
      description: "Exclude receivables at least 90 days past due",
      condition: { kind: "days_past_due_at_least", days: 90 }
    },
    {
      ruleId: "disputed",
      version: "1",
      effectiveFrom: "2025-01-01",
      priority: 20,
      reasonCode: "DISPUTED",
      description: "Exclude disputed receivables",
      condition: { kind: "flag_present", flag: "disputed" }
    }
  ],
  crossAging: {
    ruleId: "cross-age-20",
    reasonCode: "CROSS_AGED",
    daysPastDueAtLeast: 90,
    triggerRatio: "0.20"
  },
  concentration: {
    ruleId: "debtor-cap-50",
    reasonCode: "CONCENTRATION_EXCESS",
    maxDebtorShare: "0.50",
    allocation: "invoice_id"
  },
  advanceRate: "0.80",
  componentSublimit: "500",
  reserves: [
    {
      reserveId: "dilution",
      reasonCode: "DILUTION_RESERVE",
      description: "Approved dilution reserve",
      amount: "50"
    }
  ],
  commitmentAmount: "425"
};

const receivables: readonly ArReceivable[] = [
  { receivableId: "A-current", debtorId: "D1", outstandingAmount: "300", daysPastDue: 0, flags: [] },
  { receivableId: "A-old", debtorId: "D1", outstandingAmount: "100", daysPastDue: 100, flags: [] },
  { receivableId: "B-current", debtorId: "D2", outstandingAmount: "500", daysPastDue: 0, flags: [] },
  { receivableId: "C-current", debtorId: "D3", outstandingAmount: "300", daysPastDue: 0, flags: [] },
  {
    receivableId: "C-disputed",
    debtorId: "D3",
    outstandingAmount: "100",
    daysPastDue: 0,
    flags: ["disputed"]
  }
];

test("AR borrowing base applies the complete policy waterfall and preserves explanations", () => {
  const result = calculateArBorrowingBase({
    asOfDate: "2025-06-30",
    policyVersions: [fullPolicy],
    receivables,
    usage: [
      { usageId: "revolver", kind: "revolver", amount: "400" },
      { usageId: "lc", kind: "letters_of_credit", amount: "50" }
    ]
  });

  assert.deepEqual(result.totals, {
    grossReceivables: "1300",
    recordRuleIneligible: "200",
    crossAgedIneligible: "300",
    concentrationExcess: "100",
    eligibleReceivables: "700",
    advanceRate: "0.8",
    advancedReceivables: "560",
    componentSublimit: "500",
    componentContribution: "500",
    totalReserves: "50",
    appliedReserves: "50",
    unappliedReserves: "0",
    borrowingBaseBeforeCommitment: "450",
    commitmentAmount: "425",
    borrowingCapacity: "425",
    totalUsage: "450",
    excessAvailability: "-25",
    overadvance: "25"
  });

  assert.deepEqual(
    result.waterfall.map((step) => [step.stage, step.adjustmentAmount, step.afterAmount]),
    [
      ["gross_ar", "1300", "1300"],
      ["eligibility_rule", "-100", "1200"],
      ["eligibility_rule", "-100", "1100"],
      ["cross_aging", "-300", "800"],
      ["concentration", "-100", "700"],
      ["advance_rate", "-140", "560"],
      ["component_sublimit", "-60", "500"],
      ["reserves", "-50", "450"],
      ["commitment", "-25", "425"],
      ["usage", "-450", "-25"]
    ]
  );

  const byId = new Map(result.receivables.map((receivable) => [receivable.receivableId, receivable]));
  assert.equal(byId.get("A-old")?.recordRuleIneligibleAmount, "100");
  assert.equal(byId.get("A-current")?.crossAgedIneligibleAmount, "300");
  assert.equal(byId.get("B-current")?.concentrationExcessAmount, "100");
  assert.equal(byId.get("B-current")?.eligibleAmount, "400");
  assert.equal(byId.get("C-current")?.eligibleAmount, "300");
  assert.equal(byId.get("C-disputed")?.reasons[0]?.reasonCode, "DISPUTED");
  assert.deepEqual(
    result.activeEligibilityRules.map((rule) => `${rule.ruleId}:${rule.version}`),
    ["past-due:2", "disputed:1"]
  );
});

test("effective-dated eligibility versions use an exclusive end boundary", () => {
  const policy: ArBorrowingBasePolicyVersion = {
    policyId: "effective-rules",
    version: "1",
    effectiveFrom: "2024-01-01",
    effectiveTo: "2026-01-01",
    currencyCode: "USD",
    eligibilityRules: [
      {
        ruleId: "past-due",
        version: "old-60",
        effectiveFrom: "2024-01-01",
        effectiveTo: "2025-01-01",
        priority: 1,
        reasonCode: "PAST_DUE_60",
        description: "Old 60-day rule",
        condition: { kind: "days_past_due_at_least", days: 60 }
      },
      {
        ruleId: "past-due",
        version: "new-90",
        effectiveFrom: "2025-01-01",
        effectiveTo: "2026-01-01",
        priority: 1,
        reasonCode: "PAST_DUE_90",
        description: "New 90-day rule",
        condition: { kind: "days_past_due_at_least", days: 90 }
      }
    ],
    advanceRate: "1",
    reserves: [],
    commitmentAmount: "1000"
  };
  const tape: readonly ArReceivable[] = [
    { receivableId: "invoice", debtorId: "debtor", outstandingAmount: "100", daysPastDue: 75, flags: [] }
  ];

  const beforeBoundary = calculateArBorrowingBase({
    asOfDate: "2024-12-31",
    policyVersions: [policy],
    receivables: tape,
    usage: []
  });
  const atBoundary = calculateArBorrowingBase({
    asOfDate: "2025-01-01",
    policyVersions: [policy],
    receivables: tape,
    usage: []
  });

  assert.equal(beforeBoundary.activeEligibilityRules[0]?.version, "old-60");
  assert.equal(beforeBoundary.totals.recordRuleIneligible, "100");
  assert.equal(atBoundary.activeEligibilityRules[0]?.version, "new-90");
  assert.equal(atBoundary.totals.recordRuleIneligible, "0");
  assert.equal(atBoundary.totals.eligibleReceivables, "100");
});

test("all decimal calculations use string inputs without binary floating-point drift", () => {
  const policy: ArBorrowingBasePolicyVersion = {
    policyId: "decimal-test",
    version: "1",
    effectiveFrom: "2025-01-01",
    currencyCode: "USD",
    eligibilityRules: [],
    advanceRate: "0.1",
    reserves: [],
    commitmentAmount: "1"
  };
  const result = calculateArBorrowingBase({
    asOfDate: "2025-01-01",
    policyVersions: [policy],
    receivables: [
      { receivableId: "fraction", debtorId: "debtor", outstandingAmount: "0.3", daysPastDue: 0, flags: [] }
    ],
    usage: [{ usageId: "draw", kind: "revolver", amount: "0.01" }]
  });

  assert.equal(result.totals.advancedReceivables, "0.03");
  assert.equal(result.totals.excessAvailability, "0.02");
  assert.equal(result.totals.overadvance, "0");
});

test("overlapping active versions of one eligibility rule are rejected", () => {
  const overlapping: ArBorrowingBasePolicyVersion = {
    ...fullPolicy,
    eligibilityRules: [
      ...fullPolicy.eligibilityRules,
      {
        ruleId: "past-due",
        version: "overlap",
        effectiveFrom: "2025-06-01",
        effectiveTo: "2025-12-01",
        priority: 10,
        reasonCode: "PAST_DUE_OTHER",
        description: "Conflicting rule",
        condition: { kind: "days_past_due_at_least", days: 120 }
      }
    ]
  };

  assert.throws(
    () =>
      calculateArBorrowingBase({
        asOfDate: "2025-06-30",
        policyVersions: [overlapping],
        receivables,
        usage: []
      }),
    /has 2 active versions/
  );
});
