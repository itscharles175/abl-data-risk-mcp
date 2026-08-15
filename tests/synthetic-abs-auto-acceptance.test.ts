import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { Decimal } from "decimal.js";

type MappingRow = readonly [
  syntheticSourceField: string,
  semanticRole: string,
  syntheticTarget: string | null,
  matchClass: string,
  confidence: string,
  approvalStatus: string
];

interface SyntheticFixture {
  readonly schemaVersion: string;
  readonly fixtureId: string;
  readonly generator: {
    readonly name: string;
    readonly version: string;
    readonly seed: string;
  };
  readonly boundary: string;
  readonly scope: Record<string, boolean>;
  readonly mappingLedgerColumns: readonly string[];
  readonly mappingLedger: readonly MappingRow[];
  readonly semanticControls: {
    readonly sourceIdentity: {
      readonly syntheticIdPattern: string;
      readonly canonicalIdentityRule: string;
      readonly mappingAuthority: string;
    };
    readonly datePrecision: {
      readonly reportingPeriodEnd: string;
      readonly originationDate: string;
      readonly maturityDate: string;
      readonly inventedSourceDayPermitted: boolean;
    };
    readonly creditScoreZero: {
      readonly rawZeroCountAllReportedRows: number;
      readonly rawZeroCountActiveRows: number;
      readonly derivedTreatment: string;
      readonly includeInScoreStatistics: boolean;
      readonly policyStatus: string;
    };
    readonly daysPastDue: {
      readonly rawZeroMeaning: string;
      readonly rawValuePreserved: boolean;
      readonly primaryMarketThresholds: readonly number[];
      readonly alternateBucketLowerBounds: readonly number[];
    };
    readonly rawValueStates: {
      readonly reportedDash: string;
      readonly blank: string;
      readonly null: string;
      readonly zero: string;
      readonly statesRemainDistinct: boolean;
      readonly normalizationLayer: string;
    };
  };
  readonly syntheticPoolControls: {
    readonly reportedRecordCount: number;
    readonly activePositiveBalanceCount: number;
    readonly terminatedZeroBalanceCount: number;
    readonly beginningBalanceUsd: string;
    readonly endingBalanceUsd: string;
    readonly originalPoolBalanceUsd: string;
    readonly weightedAverageCreditScore: string;
    readonly scoredActiveCount: number;
    readonly scoredBalanceUsd: string;
  };
  readonly syntheticDpdControls: ReadonlyArray<{
    readonly threshold: string;
    readonly count: number;
    readonly balanceUsd: string;
  }>;
  readonly designedVisibleExceptions: ReadonlyArray<{
    readonly exceptionId: string;
    readonly computed: string;
    readonly reported: string;
    readonly difference: string;
    readonly tolerance: string;
    readonly status: string;
    readonly balanceComputedUsd?: string;
    readonly balanceReportedUsd?: string;
  }>;
  readonly unavailableWithoutSupplementalEvidence: readonly string[];
  readonly syntheticVintageScenario: {
    readonly scenarioId: string;
    readonly periodStart: string;
    readonly periodCount: number;
    readonly cohortCount: number;
    readonly initial: {
      readonly reportedCount: number;
      readonly activeCount: number;
      readonly currentBalanceUsd: string;
      readonly cumulativeGrossLossPct: string;
      readonly dpd30Pct: string;
      readonly poolFactor: string;
    };
    readonly monthlyDelta: {
      readonly reportedCount: number;
      readonly activeCount: number;
      readonly currentBalanceUsd: string;
      readonly cumulativeGrossLossPct: string;
      readonly dpd30Pct: string;
      readonly poolFactor: string;
    };
  };
}

interface SyntheticManifest {
  readonly schemaVersion: string;
  readonly generator: SyntheticFixture["generator"];
  readonly files: ReadonlyArray<{
    readonly path: string;
    readonly sha256: string;
  }>;
}

interface SyntheticVintagePoint {
  readonly reportDate: string;
  readonly mob: number;
  readonly cohortCount: number;
  readonly reportedCount: number;
  readonly activeCount: number;
  readonly currentBalanceUsd: string;
  readonly cumulativeGrossLossPct: string;
  readonly dpd30Pct: string;
  readonly poolFactor: string;
}

const FIXTURE_URL = new URL("./fixtures/synthetic-abs-auto-v1/fixture.json", import.meta.url);
const MANIFEST_URL = new URL("./fixtures/synthetic-abs-auto-v1/manifest.json", import.meta.url);
const FIXTURE_BYTES = readFileSync(FIXTURE_URL);
const FIXTURE = JSON.parse(FIXTURE_BYTES.toString("utf8")) as SyntheticFixture;
const MANIFEST = JSON.parse(readFileSync(MANIFEST_URL, "utf8")) as SyntheticManifest;
const HighPrecisionDecimal = Decimal.clone({ precision: 50 });

const EXPECTED_BOUNDARY = "This fixture is original synthetic test data created for Aegis Ledger. It contains no copied, sampled, transformed, perturbed, or statistically fitted borrower records, report values, dictionary prose, identifiers, hashes, or source-system metadata. Similarity is limited to public ABS-EE concepts and deliberately constructed control behaviors. It is not private case-study data, production data, certification evidence, or an authority for any real facility.";

function counts(values: readonly string[]): Record<string, number> {
  return values.reduce<Record<string, number>>((result, value) => {
    result[value] = (result[value] ?? 0) + 1;
    return result;
  }, {});
}

function nextMonthEnd(value: string): string {
  const [year, month] = value.split("-").map(Number);
  assert.ok(year !== undefined && month !== undefined);
  return new Date(Date.UTC(year, month + 1, 0)).toISOString().slice(0, 10);
}

function buildSyntheticVintage(fixture: SyntheticFixture): readonly SyntheticVintagePoint[] {
  const scenario = fixture.syntheticVintageScenario;
  const points: SyntheticVintagePoint[] = [];
  let reportDate = scenario.periodStart;
  for (let index = 0; index < scenario.periodCount; index += 1) {
    const offset = new HighPrecisionDecimal(index);
    points.push({
      reportDate,
      mob: index + 1,
      cohortCount: scenario.cohortCount,
      reportedCount: scenario.initial.reportedCount + scenario.monthlyDelta.reportedCount * index,
      activeCount: scenario.initial.activeCount + scenario.monthlyDelta.activeCount * index,
      currentBalanceUsd: new HighPrecisionDecimal(scenario.initial.currentBalanceUsd)
        .plus(new HighPrecisionDecimal(scenario.monthlyDelta.currentBalanceUsd).times(offset))
        .toFixed(2),
      cumulativeGrossLossPct: new HighPrecisionDecimal(scenario.initial.cumulativeGrossLossPct)
        .plus(new HighPrecisionDecimal(scenario.monthlyDelta.cumulativeGrossLossPct).times(offset))
        .toFixed(2),
      dpd30Pct: new HighPrecisionDecimal(scenario.initial.dpd30Pct)
        .plus(new HighPrecisionDecimal(scenario.monthlyDelta.dpd30Pct).times(offset))
        .toFixed(2),
      poolFactor: new HighPrecisionDecimal(scenario.initial.poolFactor)
        .plus(new HighPrecisionDecimal(scenario.monthlyDelta.poolFactor).times(offset))
        .toFixed(3)
    });
    reportDate = nextMonthEnd(reportDate);
  }
  return points;
}

test("synthetic ABS auto fixture is explicitly non-authoritative and self-contained", () => {
  assert.equal(FIXTURE.schemaVersion, "synthetic_abs_auto_v1");
  assert.equal(FIXTURE.fixtureId, "SYN-ABS-AUTO-001");
  assert.equal(FIXTURE.boundary, EXPECTED_BOUNDARY);
  assert.deepEqual(FIXTURE.scope, {
    singleFacility: true,
    aggregateOnly: true,
    containsBorrowerRecords: false,
    containsSourceIdentifiers: false,
    importsSpreadsheetFormulas: false,
    authorizesRealFacilityCertification: false
  });
  assert.equal(FIXTURE.mappingLedger.every(([sourceField]) => /^source_field_[0-9]{2}$/u.test(sourceField)), true);
  assert.equal(JSON.stringify(FIXTURE).includes("/Users/"), false);
  assert.equal(JSON.stringify(FIXTURE).includes("https://"), false);
});

test("synthetic mapping ledger exercises all 25 governed mapping states without self-approval", () => {
  assert.deepEqual(FIXTURE.mappingLedgerColumns, [
    "syntheticSourceField",
    "semanticRole",
    "syntheticTarget",
    "matchClass",
    "confidence",
    "approvalStatus"
  ]);
  assert.equal(FIXTURE.mappingLedger.length, 25);
  assert.equal(new Set(FIXTURE.mappingLedger.map(([sourceField]) => sourceField)).size, 25);
  assert.deepEqual(counts(FIXTURE.mappingLedger.map((row) => row[3])), {
    no_match: 2,
    semantic: 9,
    partial_transformed: 4,
    exact: 8,
    proposed_new_field: 1,
    ambiguous: 1
  });
  assert.deepEqual(counts(FIXTURE.mappingLedger.map((row) => row[4])), { high: 21, medium: 4 });
  assert.deepEqual(counts(FIXTURE.mappingLedger.map((row) => row[5])), {
    blocked_pending_definition: 7,
    proposed_needs_owner_review: 10,
    proposed_auto_approve: 8
  });
  assert.equal(FIXTURE.mappingLedger.some((row) => row[5] === "approved"), false);
});

test("synthetic semantic controls preserve identity, precision, sentinel, DPD, and raw value-state distinctions", () => {
  assert.equal(FIXTURE.semanticControls.sourceIdentity.syntheticIdPattern, "SYN-ASSET-[0-9]{6}");
  assert.equal(FIXTURE.semanticControls.sourceIdentity.canonicalIdentityRule, "preserve_verbatim_no_numeric_semantics");
  assert.equal(FIXTURE.semanticControls.sourceIdentity.mappingAuthority, "blocked_pending_definition");
  assert.deepEqual(FIXTURE.semanticControls.datePrecision, {
    reportingPeriodEnd: "day",
    originationDate: "month",
    maturityDate: "month",
    inventedSourceDayPermitted: false
  });
  assert.deepEqual(FIXTURE.semanticControls.creditScoreZero, {
    rawZeroCountAllReportedRows: 140,
    rawZeroCountActiveRows: 110,
    derivedTreatment: "unavailable",
    includeInScoreStatistics: false,
    policyStatus: "blocked_pending_definition"
  });
  assert.deepEqual(FIXTURE.semanticControls.daysPastDue, {
    rawZeroMeaning: "current",
    rawValuePreserved: true,
    primaryMarketThresholds: [30, 60, 90, 120],
    alternateBucketLowerBounds: [31, 61, 91, 121]
  });
  assert.deepEqual(new Set(Object.values(FIXTURE.semanticControls.rawValueStates).filter((value) => typeof value === "string")), new Set([
    "reported_dash",
    "blank",
    "null",
    "zero",
    "derived_only"
  ]));
  assert.equal(FIXTURE.semanticControls.rawValueStates.statesRemainDistinct, true);
});

test("synthetic pool controls recompute balance, score-coverage, DPD, and designed visible exceptions", () => {
  const controls = FIXTURE.syntheticPoolControls;
  assert.equal(controls.activePositiveBalanceCount + controls.terminatedZeroBalanceCount, controls.reportedRecordCount);
  assert.equal(new HighPrecisionDecimal(controls.endingBalanceUsd).dividedBy(controls.originalPoolBalanceUsd).toFixed(2), "0.46");
  assert.equal(new HighPrecisionDecimal(controls.scoredBalanceUsd).dividedBy(controls.endingBalanceUsd).times(100).toFixed(2), "90.00");
  assert.equal(new HighPrecisionDecimal(controls.scoredActiveCount).dividedBy(controls.activePositiveBalanceCount).times(100).toFixed(6), "88.043478");
  assert.equal(controls.weightedAverageCreditScore, "620.000000");

  for (let index = 1; index < FIXTURE.syntheticDpdControls.length; index += 1) {
    const prior = FIXTURE.syntheticDpdControls[index - 1];
    const current = FIXTURE.syntheticDpdControls[index];
    assert.ok(prior && current);
    assert.ok(current.count <= prior.count);
    assert.ok(new HighPrecisionDecimal(current.balanceUsd).lessThanOrEqualTo(prior.balanceUsd));
  }
  assert.equal(new HighPrecisionDecimal(FIXTURE.syntheticDpdControls[1]?.balanceUsd ?? "0").dividedBy(controls.endingBalanceUsd).times(100).toFixed(6), "8.695652");

  assert.deepEqual(FIXTURE.designedVisibleExceptions.map(({ difference, tolerance, status }) => ({ difference, tolerance, status })), [
    { difference: "-6", tolerance: "0", status: "visible_exception" },
    { difference: "-2", tolerance: "0", status: "visible_exception" }
  ]);
  assert.equal(FIXTURE.designedVisibleExceptions[1]?.balanceComputedUsd, FIXTURE.designedVisibleExceptions[1]?.balanceReportedUsd);
  assert.deepEqual(FIXTURE.unavailableWithoutSupplementalEvidence, [
    "repurchases",
    "liquidations",
    "waterfall_allocations",
    "reserve_movements",
    "tranche_balances",
    "undisclosed_adjustments"
  ]);
});

test("synthetic vintage scenario deterministically generates 27 consecutive post-cutoff periods", () => {
  const points = buildSyntheticVintage(FIXTURE);
  assert.equal(points.length, 27);
  assert.equal(points[0]?.reportDate, "2031-01-31");
  assert.deepEqual(points.at(-1), {
    reportDate: "2033-03-31",
    mob: 27,
    cohortCount: 400,
    reportedCount: 480,
    activeCount: 130,
    currentBalanceUsd: "1300000.00",
    cumulativeGrossLossPct: "5.40",
    dpd30Pct: "4.70",
    poolFactor: "0.325"
  });
  for (let index = 1; index < points.length; index += 1) {
    const prior = points[index - 1];
    const current = points[index];
    assert.ok(prior && current);
    assert.equal(current.reportDate, nextMonthEnd(prior.reportDate));
    assert.equal(current.mob, prior.mob + 1);
    assert.ok(current.reportedCount < prior.reportedCount);
    assert.ok(current.activeCount < prior.activeCount);
  }
});

test("synthetic manifest pins only the checked-in generated fixture", () => {
  assert.equal(MANIFEST.schemaVersion, "synthetic_fixture_manifest_v1");
  assert.deepEqual(MANIFEST.generator, FIXTURE.generator);
  assert.deepEqual(MANIFEST.files, [{
    path: "fixture.json",
    sha256: createHash("sha256").update(FIXTURE_BYTES).digest("hex")
  }]);
});
