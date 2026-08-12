import assert from "node:assert/strict";
import { test } from "node:test";

import type {
  BinDefinitionV1,
  CanonicalSurveillanceRecord,
  CertifiedSurveillanceSnapshotV1,
  CohortDefinitionV1,
  DefinitionApprovalV1,
  EntityResolutionDefinitionV1,
  MetricConfigurationV1,
  MetricDefinitionV1,
  PortfolioSurveillanceInputV1
} from "../src/domain/surveillance/contracts.js";
import { runPortfolioSurveillance } from "../src/services/surveillance/engine.js";

const APPROVAL: DefinitionApprovalV1 = {
  status: "approved",
  proposedBy: "steward-1",
  approvedBy: "reviewer-1",
  approvedAt: "2026-08-12T12:00:00.000Z"
};

const DPD_BINS: BinDefinitionV1 = {
  schemaVersion: "1",
  definitionType: "bin_definition",
  definitionId: "dpd-bands",
  version: 1,
  name: "DPD bands",
  field: "days_past_due",
  bins: [
    { label: "Current", lower: "0", upper: "30" },
    { label: "30-59", lower: "30", upper: "60" },
    { label: "60+", lower: "60" }
  ],
  unknownLabel: "Unknown",
  otherLabel: "Outside",
  approval: APPROVAL
};

const ENTITY_RESOLUTION: EntityResolutionDefinitionV1 = {
  schemaVersion: "1",
  definitionType: "entity_resolution_definition",
  definitionId: "borrower-resolution",
  version: 1,
  tenantId: "tenant-a",
  sourceField: "borrower_id",
  mappings: [
    { sourceSystem: "core", sourceEntityId: "raw-e1", canonicalEntityId: "entity-1" },
    { sourceSystem: "core", sourceEntityId: "raw-e1-alias", canonicalEntityId: "entity-1" },
    { sourceSystem: "core", sourceEntityId: "raw-e2", canonicalEntityId: "entity-2" },
    { sourceSystem: "core", sourceEntityId: "raw-e3", canonicalEntityId: "entity-3" }
  ],
  approval: APPROVAL
};

const ORIGINATION_COHORT: CohortDefinitionV1 = {
  schemaVersion: "1",
  definitionType: "cohort_definition",
  definitionId: "origination-year",
  version: 1,
  name: "Origination year",
  dateField: "origination_date",
  grain: "year",
  maximumCohorts: 10,
  approval: APPROVAL
};

function record(
  date: string,
  loan: string,
  values: Partial<CanonicalSurveillanceRecord>
): CanonicalSurveillanceRecord {
  return {
    as_of_date: date,
    source_system: "core",
    facility_id: loan === "L4" ? "F2" : "F1",
    loan_id: loan,
    loan_status: "active",
    origination_date: "2023-01-15",
    outstanding_balance: "0",
    original_balance: "0",
    commitment_amount: "0",
    days_past_due: "0",
    default_flag: false,
    charge_off_amount: "0",
    recovery_amount: "0",
    default_date: null,
    scheduled_principal_amount: "0",
    risk_rating: "A",
    maturity_date: "2026-01-31",
    borrower_id: "raw-e1",
    industry_code: "technology",
    ...values
  };
}

const JAN = [
  record("2024-01-31", "L1", { outstanding_balance: "100", original_balance: "100", commitment_amount: "120", borrower_id: "raw-e1", risk_rating: "A", days_past_due: "0", maturity_date: "2024-03-15" }),
  record("2024-01-31", "L2", { outstanding_balance: "200", original_balance: "200", commitment_amount: "250", borrower_id: "raw-e2", risk_rating: "B", days_past_due: "35", maturity_date: "2024-12-31", industry_code: "retail" }),
  record("2024-01-31", "L3", { outstanding_balance: "300", original_balance: "300", commitment_amount: "350", borrower_id: "raw-e3", risk_rating: "C", days_past_due: "65", default_flag: true, default_date: "2023-12-31", maturity_date: "2026-01-31" }),
  record("2024-01-31", "L4", { outstanding_balance: "400", original_balance: "400", commitment_amount: "500", borrower_id: "raw-e1-alias", risk_rating: "A", days_past_due: "0", maturity_date: "2023-12-31" })
] as const;

const FEB = [
  record("2024-02-29", "L1", { outstanding_balance: "90", original_balance: "100", commitment_amount: "120", borrower_id: "raw-e1", risk_rating: "B", days_past_due: "35", charge_off_amount: "5", scheduled_principal_amount: "5", maturity_date: "2024-03-15" }),
  record("2024-02-29", "L2", { outstanding_balance: "180", original_balance: "200", commitment_amount: "250", borrower_id: "raw-e2", risk_rating: "C", days_past_due: "65", default_flag: true, default_date: "2023-12-31", charge_off_amount: "10", recovery_amount: "2", scheduled_principal_amount: "10", maturity_date: "2024-12-31", industry_code: "retail" }),
  record("2024-02-29", "L3", { outstanding_balance: "280", original_balance: "300", commitment_amount: "350", borrower_id: "raw-e3", risk_rating: "C", days_past_due: "30", default_flag: true, default_date: "2023-12-31", scheduled_principal_amount: "20", maturity_date: "2026-01-31" }),
  record("2024-02-29", "L4", { outstanding_balance: "420", original_balance: "400", commitment_amount: "500", borrower_id: "raw-e1-alias", risk_rating: "A", days_past_due: "0", scheduled_principal_amount: "0", maturity_date: "2023-12-31" })
] as const;

const MAR = [
  record("2024-03-31", "L1", { outstanding_balance: "80", original_balance: "100", commitment_amount: "120", borrower_id: "raw-e1", risk_rating: "A", days_past_due: "0", scheduled_principal_amount: "10", maturity_date: "2024-03-15" }),
  record("2024-03-31", "L2", { outstanding_balance: "0", original_balance: "200", commitment_amount: "250", borrower_id: "raw-e2", risk_rating: "D", days_past_due: "90", default_flag: true, default_date: "2023-12-31", recovery_amount: "5", scheduled_principal_amount: "0", maturity_date: "2024-12-31", industry_code: "retail" }),
  record("2024-03-31", "L3", { outstanding_balance: "250", original_balance: "300", commitment_amount: "350", borrower_id: "raw-e3", risk_rating: "B", days_past_due: "0", default_flag: true, default_date: "2023-12-31", recovery_amount: "3", scheduled_principal_amount: "10", maturity_date: "2026-01-31" }),
  record("2024-03-31", "L4", { outstanding_balance: "400", original_balance: "400", commitment_amount: "500", borrower_id: "raw-e1-alias", risk_rating: "B", days_past_due: "10", scheduled_principal_amount: "10", maturity_date: "2023-12-31" }),
  record("2024-03-31", "L5", { outstanding_balance: "50", original_balance: "50", commitment_amount: "75", borrower_id: "raw-e2", risk_rating: "A", days_past_due: "0", scheduled_principal_amount: "0", maturity_date: "2025-01-31", industry_code: "retail" })
] as const;

function snapshot(
  id: string,
  date: string,
  hashCharacter: string,
  records: readonly CanonicalSurveillanceRecord[]
): CertifiedSurveillanceSnapshotV1 {
  return {
    schemaVersion: "1",
    snapshotId: id,
    tenantId: "tenant-a",
    asOfDate: date,
    snapshotHash: hashCharacter.repeat(64),
    certification: {
      status: "certified",
      certificationId: `cert-${id}`,
      certificationHash: ({ a: "1", b: "2", c: "3" } as const)[hashCharacter as "a" | "b" | "c"].repeat(64),
      certifiedAt: "2026-08-12T12:00:00.000Z"
    },
    records
  };
}

function metric(id: string, configuration: MetricConfigurationV1): MetricDefinitionV1 {
  return {
    schemaVersion: "1",
    definitionType: "metric_definition",
    definitionId: id,
    version: 1,
    name: id,
    family: configuration.kind,
    grain: configuration.kind === "concentration" ? "entity" : "loan",
    unit: "ratio",
    temporalSemantics: ["roll_cure", "rating_migration"].includes(configuration.kind) ? "transition" : "point_in_time",
    numerator: { label: "Numerator", aggregation: "sum", field: "outstanding_balance" },
    denominator: { label: "Denominator", aggregation: "sum", field: "outstanding_balance" },
    window: { kind: "adjacent_periods", maximumPeriods: 3 },
    population: null,
    nullPolicy: "unavailable",
    coverage: { minimumRatio: "1", minimumObservedRecords: 1 },
    privacy: { minimumCellCount: 1, complementarySuppression: true },
    maximumCells: 10_000,
    configuration,
    approval: APPROVAL
  };
}

const METRICS: readonly MetricDefinitionV1[] = [
  metric("roll-cure", { kind: "roll_cure", delinquencyField: "days_past_due", balanceField: "outstanding_balance", binDefinitionId: "dpd-bands" }),
  metric("default-ever", { kind: "default_ever", defaultFlagField: "default_flag", daysPastDueField: "days_past_due", balanceField: "outstanding_balance", everDpdThresholds: [30, 60, 90], incidenceBasis: "count" }),
  metric("loss-recovery", { kind: "loss_recovery", grossLossField: "charge_off_amount", recoveryField: "recovery_amount", denominatorField: "original_balance", defaultDateField: "default_date", flowSemantics: "period" }),
  metric("paydown", { kind: "paydown_prepayment", balanceField: "outstanding_balance", scheduledPrincipalField: "scheduled_principal_amount" }),
  metric("rating", { kind: "rating_migration", ratingField: "risk_rating", balanceField: "outstanding_balance" }),
  metric("balance", { kind: "balance_utilization", balanceField: "outstanding_balance", originalBalanceField: "original_balance", commitmentField: "commitment_amount" }),
  metric("maturity", { kind: "maturity_wall", maturityDateField: "maturity_date", balanceField: "outstanding_balance", windows: [{ label: "0-3 months", endingMonth: 3 }, { label: "4-12 months", endingMonth: 12 }], includeMatured: true }),
  metric("concentration", { kind: "concentration", dimensionField: "borrower_id", balanceField: "outstanding_balance", topN: 10, entityResolutionDefinitionId: "borrower-resolution" }),
  metric("comparison", { kind: "period_comparison", balanceField: "outstanding_balance" })
] as const;

function input(overrides: Partial<PortfolioSurveillanceInputV1> = {}): PortfolioSurveillanceInputV1 {
  return {
    tenantId: "tenant-a",
    snapshots: [
      snapshot("snapshot-jan", "2024-01-31", "a", JAN),
      snapshot("snapshot-feb", "2024-02-29", "b", FEB),
      snapshot("snapshot-mar", "2024-03-31", "c", MAR)
    ],
    metricDefinitions: METRICS,
    binDefinitions: [DPD_BINS],
    entityResolutionDefinitions: [ENTITY_RESOLUTION],
    methodology: {
      methodologyId: "surveillance-methodology",
      methodologyVersion: 1,
      methodologyHash: "d".repeat(64)
    },
    bounds: { maxSnapshots: 12, maxRecords: 1_000, maxMetrics: 100, maxCells: 100_000 },
    ...overrides
  };
}

test("surveillance engine computes the complete deterministic longitudinal analytical pack", () => {
  const before = JSON.stringify(input());
  const result = runPortfolioSurveillance(input());
  assert.equal(JSON.stringify(input()), before);
  assert.equal(result.metrics.length, 9);
  assert.deepEqual(result.asOfDates, ["2024-01-31", "2024-02-29", "2024-03-31"]);

  const defaultMetric = result.metrics.find(({ family }) => family === "default_ever")!;
  const febDefault = defaultMetric.cells.find(
    ({ metric, dimensions }) => metric === "default_incidence" && dimensions.currentAsOfDate === "2024-02-29"
  )!;
  assert.equal(febDefault.value, "0.3333333333333333333333333333333333333333");
  const janEver30 = defaultMetric.cells.find(
    ({ metric, dimensions }) => metric === "ever_dpd_incidence" && dimensions.asOfDate === "2024-01-31" && dimensions.thresholdDays === "30"
  )!;
  assert.equal(janEver30.value, "0.5");

  const paydownMetric = result.metrics.find(({ family }) => family === "paydown_prepayment")!;
  const febPaydown = paydownMetric.cells.find(
    ({ metric, dimensions }) => metric === "paydown_rate" && dimensions.currentAsOfDate === "2024-02-29"
  )!;
  const febPrepayment = paydownMetric.cells.find(
    ({ metric, dimensions }) => metric === "prepayment_rate" && dimensions.currentAsOfDate === "2024-02-29"
  )!;
  assert.equal(febPaydown.value, "0.05");
  assert.equal(febPrepayment.value, "0.015");

  const losses = result.metrics.find(({ family }) => family === "loss_recovery")!;
  const febGrossLoss = losses.cells.find(
    ({ metric, dimensions }) => metric === "gross_loss_rate" && dimensions.asOfDate === "2024-02-29"
  )!;
  const febNetLoss = losses.cells.find(
    ({ metric, dimensions }) => metric === "net_loss_rate" && dimensions.asOfDate === "2024-02-29"
  )!;
  const febRecoveryLag = losses.cells.find(
    ({ metric, dimensions }) => metric === "recovery_lag_days" && dimensions.asOfDate === "2024-02-29"
  )!;
  assert.deepEqual(
    [febGrossLoss.numerator, febGrossLoss.denominator, febGrossLoss.value],
    ["15", "1000", "0.015"]
  );
  assert.equal(febNetLoss.value, "0.013");
  assert.equal(febRecoveryLag.value, "60");

  const balances = result.metrics.find(({ family }) => family === "balance_utilization")!;
  const marchUtilization = balances.cells.find(
    ({ metric, dimensions }) => metric === "utilization" && dimensions.asOfDate === "2024-03-31"
  )!;
  assert.deepEqual(
    [marchUtilization.numerator, marchUtilization.denominator],
    ["780", "1295"]
  );

  const maturity = result.metrics.find(({ family }) => family === "maturity_wall")!;
  const janMatured = maturity.cells.find(
    ({ metric, dimensions }) => metric === "maturity_balance_share" && dimensions.asOfDate === "2024-01-31" && dimensions.maturityWindow === "Matured"
  )!;
  assert.deepEqual([janMatured.numerator, janMatured.denominator, janMatured.value], ["400", "1000", "0.4"]);

  const comparison = result.metrics.find(({ family }) => family === "period_comparison")!;
  const febChange = comparison.cells.find(
    ({ metric, dimensions }) => metric === "portfolio_change_amount" && dimensions.currentAsOfDate === "2024-02-29"
  )!;
  const febDrivers = comparison.cells.filter(
    ({ metric, dimensions }) => metric === "period_driver_amount" && dimensions.currentAsOfDate === "2024-02-29"
  );
  assert.equal(febChange.value, "-30");
  assert.equal(
    febDrivers.reduce((total, cell) => total + Number(cell.value), 0),
    Number(febChange.value)
  );

  const concentration = result.metrics.find(({ family }) => family === "concentration")!;
  const janShares = concentration.cells.filter(
    ({ metric, dimensions }) => metric === "concentration_share" && dimensions.asOfDate === "2024-01-31"
  );
  assert.equal(
    janShares.map(({ value }) => value).filter((value): value is string => value !== null).sort((left, right) => Number(right) - Number(left))[0],
    "0.5"
  );
  assert.ok(janShares.every(({ dimensions }) => !JSON.stringify(dimensions).includes("raw-e")));
  const janHhi = concentration.cells.find(
    ({ metric, dimensions }) => metric === "concentration_hhi" && dimensions.asOfDate === "2024-01-31"
  )!;
  assert.equal(janHhi.value, "0.38");

  assert.ok(result.metrics.every(({ cells }) => cells.every(({ lineage }) => lineage.methodologyHash === "d".repeat(64))));
  assert.ok(result.metrics.every(({ cells }) => cells.every(({ lineage }) => lineage.methodologyId === "surveillance-methodology" && lineage.methodologyVersion === 1)));
  assert.ok(result.metrics.every(({ cells }) => cells.every(({ lineage }) => /^[a-f0-9]{64}$/.test(lineage.populationHash))));
  assert.equal(result.metrics.find(({ family }) => family === "roll_cure")!.lineage.supportingDefinitionHashes.length, 1);
  assert.equal(result.metrics.find(({ family }) => family === "concentration")!.lineage.supportingDefinitionHashes.length, 1);
  assert.equal(JSON.stringify(result).includes("raw-e"), false);
  assert.equal(JSON.stringify(result).includes('"loan_id"'), false);
});

test("record, snapshot, and metric ordering do not affect any result or lineage hash", () => {
  const baseline = runPortfolioSurveillance(input());
  const reorderedSnapshots = [...input().snapshots]
    .reverse()
    .map((item) => ({ ...item, records: [...item.records].reverse() }));
  const reordered = runPortfolioSurveillance(
    input({
      snapshots: reorderedSnapshots,
      metricDefinitions: [...METRICS].reverse(),
      entityResolutionDefinitions: [
        { ...ENTITY_RESOLUTION, mappings: [...ENTITY_RESOLUTION.mappings].reverse() }
      ]
    })
  );
  assert.deepEqual(reordered, baseline);
  assert.equal(reordered.lineage.analysisHash, baseline.lineage.analysisHash);
});

test("roll/cure and rating matrices carry explicit denominators, coverage, and movement", () => {
  const result = runPortfolioSurveillance(input());
  const roll = result.metrics.find(({ family }) => family === "roll_cure")!;
  const currentToThirty = roll.cells.find(
    ({ dimensions }) => dimensions.previousAsOfDate === "2024-01-31" && dimensions.fromBand === "Current" && dimensions.toBand === "30-59"
  )!;
  assert.equal(currentToThirty.numerator, "100");
  assert.equal(currentToThirty.denominator, "500");
  assert.equal(currentToThirty.value, "0.2");
  assert.equal(currentToThirty.dimensions.movement, "roll");
  assert.deepEqual(currentToThirty.coverage, { observedCount: "2", eligibleCount: "2", ratio: "1" });

  const rating = result.metrics.find(({ family }) => family === "rating_migration")!;
  const aToB = rating.cells.find(
    ({ dimensions }) => dimensions.previousAsOfDate === "2024-01-31" && dimensions.fromRating === "A" && dimensions.toRating === "B"
  )!;
  assert.equal(aToB.value, "0.2");
});

test("missing entity approval and scheduled principal fail closed with explicit availability reasons", () => {
  const concentrationOnly = METRICS.filter(({ family }) => family === "concentration");
  const noResolution = runPortfolioSurveillance(
    input({ metricDefinitions: concentrationOnly, entityResolutionDefinitions: [] })
  );
  assert.equal(noResolution.metrics[0]!.cells[0]!.availabilityReason, "entity_resolution_unapproved");
  assert.equal(noResolution.metrics[0]!.cells[0]!.value, null);

  const paydown = metric("paydown-no-schedule", {
    kind: "paydown_prepayment",
    balanceField: "outstanding_balance"
  });
  const noSchedule = runPortfolioSurveillance(input({ metricDefinitions: [paydown] }));
  const prepayments = noSchedule.metrics[0]!.cells.filter(({ metric }) => metric === "prepayment_rate");
  assert.ok(prepayments.every(({ availabilityReason, value }) => availabilityReason === "missing_required_field" && value === null));
});

test("approved cohort definitions drive remaining-balance and utilization trajectories", () => {
  const cohortMetric = metric("cohort-balance", {
    kind: "balance_utilization",
    balanceField: "outstanding_balance",
    originalBalanceField: "original_balance",
    commitmentField: "commitment_amount",
    cohortDefinitionId: "origination-year"
  });
  const records = [
    { ...JAN[0]!, origination_date: "2022-05-01" },
    { ...JAN[1]!, origination_date: "2022-06-01" },
    { ...JAN[2]!, origination_date: "2023-01-01" },
    { ...JAN[3]!, origination_date: "2023-03-01" }
  ];
  const result = runPortfolioSurveillance(
    input({
      snapshots: [snapshot("snapshot-cohort", "2024-01-31", "a", records)],
      metricDefinitions: [cohortMetric],
      cohortDefinitions: [ORIGINATION_COHORT]
    })
  );
  const balances = result.metrics[0]!.cells.filter(({ metric }) => metric === "outstanding_balance");
  assert.deepEqual(
    balances.map(({ dimensions, value }) => [dimensions.cohort, value]),
    [["2022-01-01", "300"], ["2023-01-01", "700"]]
  );
  assert.equal(result.metrics[0]!.lineage.supportingDefinitionHashes.length, 1);
  assert.throws(
    () => runPortfolioSurveillance(input({ metricDefinitions: [cohortMetric], cohortDefinitions: [] })),
    /Missing approved cohort definition/
  );
});

test("minimum-cell privacy performs deterministic complementary suppression", () => {
  const concentration = {
    ...METRICS.find(({ family }) => family === "concentration")!,
    privacy: { minimumCellCount: 2, complementarySuppression: true as const }
  };
  const tinySnapshot = snapshot("snapshot-tiny", "2024-01-31", "a", [
    JAN[0]!,
    JAN[1]!,
    { ...JAN[2]!, borrower_id: "raw-e1" },
    JAN[3]!
  ]);
  const result = runPortfolioSurveillance(
    input({ snapshots: [tinySnapshot], metricDefinitions: [concentration] })
  );
  const shares = result.metrics[0]!.cells.filter(({ metric }) => metric === "concentration_share");
  assert.ok(shares.some(({ suppressed }) => suppressed));
  assert.ok(shares.filter(({ suppressed }) => suppressed).every(({ value, coverage }) => value === null && coverage.ratio === null));
});

test("execution bounds and certification tenant boundaries are enforced before analysis", () => {
  assert.throws(
    () => runPortfolioSurveillance(input({ bounds: { maxSnapshots: 2, maxRecords: 1_000, maxMetrics: 100, maxCells: 100_000 } })),
    /between 1 and 2 snapshots/
  );
  assert.throws(
    () =>
      runPortfolioSurveillance(
        input({ snapshots: [{ ...input().snapshots[0]!, tenantId: "tenant-b" }] })
      ),
    /different tenant/
  );
  assert.throws(
    () =>
      runPortfolioSurveillance(
        input({ snapshots: [{ ...input().snapshots[0]!, snapshotHash: "NOT-A-HASH" }] })
      ),
    /lowercase SHA-256/
  );
  const unresolvedOne = metric("unresolved-one", {
    kind: "concentration",
    dimensionField: "borrower_id",
    balanceField: "outstanding_balance",
    topN: 5,
    entityResolutionDefinitionId: "missing-resolution"
  });
  const unresolvedTwo = { ...unresolvedOne, definitionId: "unresolved-two", name: "unresolved-two" };
  assert.throws(
    () =>
      runPortfolioSurveillance(
        input({
          metricDefinitions: [unresolvedOne, unresolvedTwo],
          entityResolutionDefinitions: [],
          bounds: { maxSnapshots: 12, maxRecords: 1_000, maxMetrics: 100, maxCells: 1 }
        })
      ),
    /pack produced 2 cells/
  );
});
