import assert from "node:assert/strict";
import { test } from "node:test";

import {
  classifyBin,
  cohortForRecord,
  matchesFilter,
  stableFingerprint,
  validateBinDefinitionV1,
  validateCohortDefinitionV1,
  validateEntityResolutionDefinitionV1,
  validateFilterExpressionV1,
  validateMetricDefinitionV1
} from "../src/domain/surveillance/definitions.js";
import type {
  BinDefinitionV1,
  CohortDefinitionV1,
  DefinitionApprovalV1,
  EntityResolutionDefinitionV1,
  MetricDefinitionV1
} from "../src/domain/surveillance/contracts.js";

const APPROVAL: DefinitionApprovalV1 = {
  status: "approved",
  proposedBy: "steward-1",
  approvedBy: "reviewer-1",
  approvedAt: "2026-08-12T12:00:00.000Z"
};

const BIN_DEFINITION: BinDefinitionV1 = {
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

const COHORT_DEFINITION: CohortDefinitionV1 = {
  schemaVersion: "1",
  definitionType: "cohort_definition",
  definitionId: "origination-quarter",
  version: 1,
  name: "Origination quarter",
  dateField: "origination_date",
  grain: "quarter",
  population: { op: "eq", field: "loan_status", value: "active" },
  maximumCohorts: 100,
  approval: APPROVAL
};

function metricDefinition(overrides: Partial<MetricDefinitionV1> = {}): MetricDefinitionV1 {
  return {
    schemaVersion: "1",
    definitionType: "metric_definition",
    definitionId: "roll-rate",
    version: 1,
    name: "Roll rate",
    family: "roll_cure",
    grain: "loan",
    unit: "ratio",
    temporalSemantics: "transition",
    numerator: { label: "Transitioning exposure", aggregation: "sum", field: "outstanding_balance" },
    denominator: { label: "Opening exposure", aggregation: "sum", field: "outstanding_balance" },
    window: { kind: "adjacent_periods", maximumPeriods: 12 },
    population: { op: "neq", field: "loan_status", value: "cancelled" },
    nullPolicy: "unavailable",
    coverage: { minimumRatio: "0.95", minimumObservedRecords: 1 },
    privacy: { minimumCellCount: 3, complementarySuppression: true },
    maximumCells: 10_000,
    configuration: {
      kind: "roll_cure",
      delinquencyField: "days_past_due",
      balanceField: "outstanding_balance",
      binDefinitionId: "dpd-bands"
    },
    approval: APPROVAL,
    ...overrides
  };
}

test("definition contracts validate maker/checker approval, bounds, and matching family", () => {
  assert.doesNotThrow(() => validateMetricDefinitionV1(metricDefinition()));
  assert.throws(
    () =>
      validateMetricDefinitionV1(
        metricDefinition({ approval: { ...APPROVAL, approvedBy: APPROVAL.proposedBy } })
      ),
    /approver must differ/
  );
  assert.throws(
    () =>
      validateMetricDefinitionV1(
        metricDefinition({ family: "concentration" })
      ),
    /family must match/
  );
  assert.throws(
    () =>
      validateMetricDefinitionV1(
        metricDefinition({ coverage: { minimumRatio: "1.01", minimumObservedRecords: 1 } })
      ),
    /between 0 and 1/
  );
  assert.throws(
    () =>
      validateMetricDefinitionV1({
        ...metricDefinition(),
        modelGeneratedSql: "select *"
      } as unknown as MetricDefinitionV1),
    /unsupported fields: modelGeneratedSql/
  );
});

test("bounded filter AST executes exact comparisons and rejects excessive depth", () => {
  const filter = {
    op: "and",
    clauses: [
      { op: "in", field: "risk_rating", values: ["A", "B"] },
      { op: "gte", field: "outstanding_balance", value: "100.00" }
    ]
  } as const;
  validateFilterExpressionV1(filter);
  assert.equal(matchesFilter({ risk_rating: "A", outstanding_balance: "100.00" }, filter), true);
  assert.equal(matchesFilter({ risk_rating: "C", outstanding_balance: "100.00" }, filter), false);
  assert.throws(
    () =>
      validateFilterExpressionV1({
        op: "and",
        clauses: [{ op: "and", clauses: [{ op: "and", clauses: [{ op: "and", clauses: [{ op: "and", clauses: [{ op: "eq", field: "loan_status", value: "active" }] }] }] }] }]
      }),
    /maximum depth/
  );
});

test("bin and cohort definitions are deterministic and preserve unavailable cohorts", () => {
  const parsed = validateBinDefinitionV1(BIN_DEFINITION);
  assert.equal(classifyBin("29.999", BIN_DEFINITION, parsed), "Current");
  assert.equal(classifyBin("30", BIN_DEFINITION, parsed), "30-59");
  assert.equal(classifyBin(null, BIN_DEFINITION, parsed), "Unknown");
  assert.doesNotThrow(() => validateCohortDefinitionV1(COHORT_DEFINITION));
  assert.equal(
    cohortForRecord(
      { origination_date: "2025-05-17", loan_status: "active" },
      COHORT_DEFINITION
    ),
    "2025-04-01"
  );
  assert.equal(
    cohortForRecord(
      { origination_date: "2025-05-17", loan_status: "closed" },
      COHORT_DEFINITION
    ),
    null
  );
  assert.throws(
    () =>
      validateBinDefinitionV1({
        ...BIN_DEFINITION,
        bins: [
          { label: "One", upper: "30", includeUpper: true },
          { label: "Two", lower: "30" }
        ]
      }),
    /overlaps/
  );
});

test("entity resolution is tenant-bound, source-key unique, and order-independent when normalized", () => {
  const definition: EntityResolutionDefinitionV1 = {
    schemaVersion: "1",
    definitionType: "entity_resolution_definition",
    definitionId: "borrower-resolution",
    version: 1,
    tenantId: "tenant-a",
    sourceField: "borrower_id",
    mappings: [
      { sourceSystem: "core", sourceEntityId: "raw-a", canonicalEntityId: "entity-1" },
      { sourceSystem: "core", sourceEntityId: "raw-b", canonicalEntityId: "entity-2" }
    ],
    approval: APPROVAL
  };
  assert.doesNotThrow(() => validateEntityResolutionDefinitionV1(definition, "tenant-a"));
  assert.throws(
    () => validateEntityResolutionDefinitionV1(definition, "tenant-b"),
    /different tenant/
  );
  assert.equal(
    stableFingerprint({ a: "1", b: { c: true } }),
    stableFingerprint({ b: { c: true }, a: "1" })
  );
});
