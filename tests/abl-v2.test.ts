import assert from "node:assert/strict";
import { test } from "node:test";

import type {
  ApprovalEvidenceV1,
  BorrowingBasePolicyV2,
  CalculateBorrowingBaseV2Input,
  CertifiedCollateralPopulationV2,
  GovernedAdjustmentV2
} from "../src/domain/abl-v2/contracts.js";
import {
  calculateBorrowingBaseV2,
  reconcileCashV1,
  runBorrowingBaseScenario
} from "../src/domain/abl-v2/engine.js";

const H = "a".repeat(64);
const C = "b".repeat(64);
const APPROVAL: ApprovalEvidenceV1 = {
  status: "approved",
  proposedBy: "maker-1",
  approvedBy: "checker-1",
  approvedAt: "2026-08-01T12:00:00.000Z",
  authorityRef: "approval-1",
  rationale: "Approved under the facility delegation matrix"
};

const POLICY: BorrowingBasePolicyV2 = {
  schemaVersion: "2",
  policyId: "bb-policy",
  version: "7",
  policyHash: H,
  tenantId: "tenant-a",
  facilityId: "facility-a",
  currencyCode: "USD",
  effectiveFrom: "2026-01-01",
  commitmentAmount: "500",
  components: [
    {
      componentId: "ar",
      collateralClass: "accounts_receivable",
      valueBasis: "eligible_amount",
      advanceRate: "0.85",
      concentration: {
        ruleId: "ar-concentration",
        tiers: [
          { tierId: "small", upToGroupAmount: "150", maximumShare: "0.5" },
          { tierId: "large", maximumShare: "0.4" }
        ]
      }
    },
    {
      componentId: "inventory",
      collateralClass: "inventory",
      valueBasis: "nolv",
      advanceRate: "0.5",
      componentSublimit: "140"
    },
    {
      componentId: "equipment",
      collateralClass: "equipment",
      valueBasis: "appraised_value",
      advanceRate: "0.4"
    },
    {
      componentId: "cash",
      collateralClass: "cash",
      valueBasis: "cleared_balance",
      advanceRate: "1"
    }
  ],
  reserves: [
    { reserveId: "fixed", label: "Fixed reserve", formula: { kind: "fixed_amount", amount: "10" } },
    {
      reserveId: "facility-rate",
      label: "Contribution reserve",
      formula: { kind: "percentage", basis: "facility_contribution", rate: "0.02" }
    },
    {
      reserveId: "ar-excess",
      label: "AR excess reserve",
      componentId: "ar",
      formula: {
        kind: "amount_above",
        basis: "component_eligible",
        threshold: "200",
        rate: "0.1"
      }
    }
  ],
  triggers: [
    {
      triggerId: "low-availability",
      condition: "excess_availability_below",
      threshold: "50",
      action: "availability_block",
      blockAmount: "20"
    },
    {
      triggerId: "dominion",
      condition: "utilization_above",
      threshold: "0.75",
      action: "cash_dominion"
    }
  ],
  ticklerWarningDays: 30,
  approval: APPROVAL
};

function certification(populationId: string) {
  return {
    schemaVersion: "1" as const,
    tenantId: "tenant-a",
    populationId,
    snapshotId: "snapshot-2026-06",
    asOfDate: "2026-06-30",
    status: "certified" as const,
    populationHash: H,
    certificationHash: C
  };
}

const POPULATIONS: readonly CertifiedCollateralPopulationV2[] = [
  {
    certification: certification("a1"),
    collateralClass: "accounts_receivable",
    records: [
      { recordId: "ar-1", collateralClass: "accounts_receivable", grossValue: "110", eligible: true, eligibleAmount: "100", concentrationGroup: "group-a" },
      { recordId: "ar-2", collateralClass: "accounts_receivable", grossValue: "110", eligible: true, eligibleAmount: "100", concentrationGroup: "group-a" },
      { recordId: "ar-3", collateralClass: "accounts_receivable", grossValue: "110", eligible: true, eligibleAmount: "100", concentrationGroup: "group-b" }
    ]
  },
  {
    certification: certification("b1"),
    collateralClass: "inventory",
    records: [{ recordId: "inv-1", collateralClass: "inventory", grossValue: "500", eligible: true, nolv: "300" }]
  },
  {
    certification: certification("c1"),
    collateralClass: "equipment",
    records: [{ recordId: "eq-1", collateralClass: "equipment", grossValue: "250", eligible: true, appraisedValue: "200" }]
  },
  {
    certification: certification("d1"),
    collateralClass: "cash",
    records: [{ recordId: "cash-1", collateralClass: "cash", grossValue: "50", eligible: true, clearedBalance: "50" }]
  }
];

const ADJUSTMENTS: readonly GovernedAdjustmentV2[] = [
  { adjustmentId: "adj-ar-rate", kind: "advance_rate_override", componentId: "ar", value: "0.9", effectiveFrom: "2026-06-01", approval: APPROVAL },
  { adjustmentId: "adj-inv-waiver", kind: "component_sublimit_waiver", componentId: "inventory", effectiveFrom: "2026-06-01", approval: APPROVAL },
  { adjustmentId: "adj-reserve", kind: "reserve_override", reserveId: "fixed", value: "5", effectiveFrom: "2026-06-01", approval: APPROVAL },
  { adjustmentId: "adj-block", kind: "availability_block", value: "5", effectiveFrom: "2026-06-01", approval: APPROVAL }
];

function input(): CalculateBorrowingBaseV2Input {
  return {
    tenantId: "tenant-a",
    facilityId: "facility-a",
    asOfDate: "2026-06-30",
    policy: POLICY,
    populations: POPULATIONS,
    usage: [{ usageId: "revolver", kind: "revolver", amount: "400" }],
    borrowerSubmitted: {
      certificateId: "submitted-1",
      submittedAt: "2026-07-01T12:00:00.000Z",
      componentContributions: { ar: "180", inventory: "140", equipment: "80", cash: "50" },
      totalReserves: "20",
      availabilityBlocks: "20",
      borrowingCapacity: "410",
      totalUsage: "400",
      excessAvailability: "10"
    },
    adjustments: ADJUSTMENTS,
    covenants: [
      { covenantId: "fccr", label: "Fixed charge coverage", comparator: "gte", threshold: "1.1", actualValue: "1.2" },
      { covenantId: "leverage", label: "Leverage", comparator: "lte", threshold: "4", actualValue: "4.25" }
    ],
    ticklers: [
      { ticklerId: "appraisal", kind: "appraisal", dueDate: "2026-07-15" },
      { ticklerId: "ucc", kind: "ucc", dueDate: "2026-06-01", waiver: APPROVAL },
      { ticklerId: "insurance", kind: "insurance", dueDate: "2026-06-01" }
    ]
  };
}

test("multi-component ABL reperforms certified collateral and approved maker/checker adjustments", () => {
  const result = calculateBorrowingBaseV2(input());
  const system = result.states.systemReperformed;
  const approved = result.states.approvedAdjusted;

  assert.deepEqual(
    system.components.map(({ componentId, contribution }) => [componentId, contribution]),
    [["ar", "187"], ["cash", "50"], ["equipment", "80"], ["inventory", "140"]]
  );
  assert.equal(system.totalComponentContribution, "457");
  assert.equal(system.totalReserves, "21.14");
  assert.equal(system.availabilityBlocks, "20");
  assert.equal(system.borrowingCapacity, "415.86");
  assert.equal(system.excessAvailability, "15.86");
  assert.equal(approved.totalComponentContribution, "478");
  assert.equal(approved.totalReserves, "16.56");
  assert.equal(approved.availabilityBlocks, "5");
  assert.equal(approved.borrowingCapacity, "456.44");
  assert.equal(approved.excessAvailability, "56.44");
  assert.equal(result.cashDominionActive, true);
  assert.equal(result.triggers.find(({ triggerId }) => triggerId === "low-availability")?.activated, false);
  assert.deepEqual(result.covenants.map(({ status, headroom }) => [status, headroom]), [["pass", "0.1"], ["breach", "-0.25"]]);
  assert.deepEqual(result.ticklers.map(({ status }) => status), ["due_soon", "overdue", "waived"]);
  assert.equal(result.appliedAdjustments.length, 4);
  assert.equal(result.variances.find(({ metric, leftState }) => metric === "borrowing_capacity" && leftState === "system_reperformed")?.variance, "40.58");
  assert.equal(Object.isFrozen(result), true);
});

test("ABL calculation is order-stable and refuses uncertified or cross-tenant populations", () => {
  const original = calculateBorrowingBaseV2(input());
  const reorderedBase = input();
  const reordered: CalculateBorrowingBaseV2Input = {
    ...reorderedBase,
    populations: [...reorderedBase.populations].reverse(),
    usage: [...reorderedBase.usage].reverse(),
    adjustments: [...(reorderedBase.adjustments ?? [])].reverse()
  };
  assert.equal(calculateBorrowingBaseV2(reordered).lineage.analysisHash, original.lineage.analysisHash);

  const badBase = input();
  const bad: CalculateBorrowingBaseV2Input = {
    ...badBase,
    populations: [{
      ...badBase.populations[0]!,
      certification: { ...badBase.populations[0]!.certification, tenantId: "tenant-b" }
    }, ...badBase.populations.slice(1)]
  };
  assert.throws(() => calculateBorrowingBaseV2(bad), /different tenant/);
});

test("maker/checker evidence and conflicting override/waiver families are enforced", () => {
  const samePrincipal: CalculateBorrowingBaseV2Input = {
    ...input(),
    adjustments: [{
      adjustmentId: "bad",
      kind: "availability_block",
      value: "1",
      effectiveFrom: "2026-01-01",
      approval: { ...APPROVAL, approvedBy: APPROVAL.proposedBy }
    }]
  };
  assert.throws(() => calculateBorrowingBaseV2(samePrincipal), /Maker and checker/);

  const conflict: CalculateBorrowingBaseV2Input = {
    ...input(),
    adjustments: [
      { adjustmentId: "override", kind: "reserve_override", reserveId: "fixed", value: "5", effectiveFrom: "2026-01-01", approval: APPROVAL },
      { adjustmentId: "waiver", kind: "reserve_waiver", reserveId: "fixed", effectiveFrom: "2026-01-01", approval: APPROVAL }
    ]
  };
  assert.throws(() => calculateBorrowingBaseV2(conflict), /Multiple active adjustments/);
});

test("counterfactual scenarios bind the certified baseline and never mutate it", () => {
  const baseInput = input();
  const baseline = calculateBorrowingBaseV2(baseInput);
  const before = JSON.stringify(baseInput);
  const scenario = runBorrowingBaseScenario(baseInput, baseline, {
    schemaVersion: "1",
    scenarioId: "downside",
    tenantId: "tenant-a",
    baseAnalysisHash: baseline.lineage.analysisHash,
    createdBy: "analyst-1",
    createdAt: "2026-07-02T12:00:00.000Z",
    componentAssumptions: [{ componentId: "ar", eligibleValueMultiplier: "0.5", advanceRateMultiplier: "0.9" }],
    reserveDelta: "5"
  });
  assert.equal(JSON.stringify(baseInput), before);
  assert.equal(scenario.baseAnalysisHash, baseline.lineage.analysisHash);
  assert.notEqual(scenario.result.lineage.analysisHash, baseline.lineage.analysisHash);
  assert.equal(Object.isFrozen(scenario), true);
  assert.throws(
    () => runBorrowingBaseScenario(baseInput, baseline, { ...scenarioInput(baseline), baseAnalysisHash: "f".repeat(64) }),
    /baseline hash/
  );
});

function scenarioInput(baseline: ReturnType<typeof calculateBorrowingBaseV2>) {
  return {
    schemaVersion: "1" as const,
    scenarioId: "other",
    tenantId: "tenant-a",
    baseAnalysisHash: baseline.lineage.analysisHash,
    createdBy: "analyst-1",
    createdAt: "2026-07-02T12:00:00.000Z",
    componentAssumptions: [],
    reserveDelta: "0"
  };
}

test("lockbox, cash application, and paydown reconciliation is exact and order-stable", () => {
  const cashInput = {
    tenantId: "tenant-a",
    facilityId: "facility-a",
    asOfDate: "2026-06-30",
    certification: certification("cash-recon"),
    openingLoanBalance: "500",
    reportedEndingLoanBalance: "400",
    transactions: [
      { transactionId: "receipt", kind: "lockbox_receipt" as const, effectiveDate: "2026-06-30", amount: "100", referenceId: "ref-1" },
      { transactionId: "application", kind: "cash_application" as const, effectiveDate: "2026-06-30", amount: "100", referenceId: "ref-2" },
      { transactionId: "paydown", kind: "loan_paydown" as const, effectiveDate: "2026-06-30", amount: "100", referenceId: "ref-3" }
    ]
  };
  const result = reconcileCashV1(cashInput);
  assert.equal(result.passed, true);
  assert.equal(result.expectedEndingLoanBalance, "400");
  assert.equal(result.lineage.reconciliationHash, reconcileCashV1({ ...cashInput, transactions: [...cashInput.transactions].reverse() }).lineage.reconciliationHash);
  const broken = reconcileCashV1({ ...cashInput, reportedEndingLoanBalance: "410", transactions: cashInput.transactions.slice(0, 2) });
  assert.equal(broken.passed, false);
  assert.deepEqual(broken.breaks.map(({ code }) => code), ["cash_application_paydown_mismatch", "ending_balance_mismatch"]);
});
