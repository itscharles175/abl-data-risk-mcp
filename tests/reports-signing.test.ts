import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";

import type {
  AggregateReportCellV1,
  ReportPackDraftV1,
  SignedReportPackV1
} from "../src/services/reports/contracts.js";
import {
  createReportPackV1,
  createReportSigningKeyV1,
  createReportVerificationKeyV1,
  signReportPackV1,
  verifySignedReportPackV1
} from "../src/services/reports/report-pack.js";

const H = "a".repeat(64);
const C = "b".repeat(64);
const CELL = "c".repeat(64);
const METRIC = "d".repeat(64);
const METHOD = "e".repeat(64);
const DEFINITION = "f".repeat(64);
const POLICY = "1".repeat(64);
const ARTIFACT = "2".repeat(64);

function lineage() {
  return {
    cellPopulationHash: CELL,
    sourcePopulationHashes: [H],
    certificationHashes: [C],
    metricDefinitionHash: METRIC,
    methodologyHash: METHOD
  };
}

function cell(value: string): AggregateReportCellV1 {
  return {
    value,
    unit: "currency",
    coverage: "1",
    suppressed: false,
    lineage: lineage()
  };
}

function draft(): ReportPackDraftV1 {
  return {
    schemaVersion: "1",
    reportId: "portfolio-june",
    tenantId: "tenant-a",
    portfolioId: "portfolio-a",
    title: "June Portfolio Surveillance",
    reportDefinitionHash: DEFINITION,
    methodologyBundleHash: METHOD,
    reportingPeriod: {
      from: "2026-06-30",
      to: "2026-06-30",
      knowledgeCutoff: "2026-07-01T12:00:00.000Z"
    },
    createdBy: "analyst-1",
    createdAt: "2026-07-01T12:00:00.000Z",
    certifiedPopulations: [{
      schemaVersion: "1",
      tenantId: "tenant-a",
      populationId: "population-june",
      snapshotId: "snapshot-june",
      asOfDate: "2026-06-30",
      status: "certified",
      populationHash: H,
      certificationHash: C
    }],
    tables: [{
      tableId: "risk-strat",
      title: "Risk grade stratification",
      dimensionColumns: ["risk_grade"],
      measureColumns: ["loan_count", "outstanding_balance"],
      rows: [
        {
          dimensions: { risk_grade: "A" },
          measures: {
            loan_count: { ...cell("5"), unit: "count" },
            outstanding_balance: cell("100")
          },
          rowPopulationHash: "3".repeat(64)
        },
        {
          dimensions: { risk_grade: "B" },
          measures: {
            loan_count: {
              value: null,
              unit: "count",
              coverage: "1",
              suppressed: true,
              suppressionReason: "minimum_cohort",
              lineage: lineage()
            },
            outstanding_balance: cell("25")
          },
          rowPopulationHash: "4".repeat(64)
        }
      ]
    }],
    charts: [{
      chartId: "risk-chart",
      title: "Balance by risk grade",
      chartType: "bar",
      tableId: "risk-strat",
      xDimension: "risk_grade",
      series: ["outstanding_balance"]
    }],
    warnings: [{
      warningId: "coverage-warning",
      severity: "warning",
      code: "PARTIAL_HISTORY",
      message: "Historical comparison covers only the certified reporting window.",
      relatedHashes: [H]
    }],
    explanations: [{
      explanationId: "risk-explanation",
      subjectId: "risk-strat",
      text: "Balances use the approved month-end population and governed risk-grade definition.",
      methodologyHash: METHOD,
      populationHashes: [H]
    }],
    suppression: {
      policyHash: POLICY,
      minimumCohortSize: 5,
      suppressedCellCount: 1
    },
    comparisons: [{
      comparisonId: "balance-change",
      label: "Outstanding balance change",
      metricId: "outstanding-balance",
      unit: "currency",
      leftPeriod: "2026-05-31",
      rightPeriod: "2026-06-30",
      leftValue: "100",
      rightValue: "125",
      delta: "25",
      lineage: lineage()
    }],
    manifestLinks: [{
      artifactId: "manifest-june",
      contentHash: ARTIFACT,
      mediaType: "application/json",
      relationship: "data_manifest"
    }]
  };
}

test("ReportPackV1 canonicalizes aggregate content and preserves certified cell lineage", () => {
  const source = draft();
  const report = createReportPackV1(source);
  const reordered: ReportPackDraftV1 = {
    ...source,
    tables: source.tables.map((table) => ({ ...table, rows: [...table.rows].reverse() }))
  };
  assert.equal(createReportPackV1(reordered).reportHash, report.reportHash);
  assert.match(report.reportHash, /^[a-f0-9]{64}$/);
  assert.equal(report.tables[0]!.rows[0]!.dimensions.risk_grade, "A");
  assert.equal(Object.isFrozen(report.tables[0]!.rows[0]!.measures), true);

  (source.tables[0]!.rows[0]!.dimensions as Record<string, string>).risk_grade = "Changed";
  assert.equal(report.tables[0]!.rows[0]!.dimensions.risk_grade, "A");
});

test("Ed25519 report signatures bind full canonical content and signer expectations", () => {
  const report = createReportPackV1(draft());
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const signer = createReportSigningKeyV1({ keyId: "report-key-1", privateKey, publicKey });
  const verifier = createReportVerificationKeyV1({ keyId: "report-key-1", publicKey });
  const signed = signReportPackV1(report, signer, "2026-07-01T13:00:00.000Z");

  assert.equal(
    verifySignedReportPackV1(signed, verifier, {
      tenantId: "tenant-a",
      reportId: "portfolio-june",
      reportHash: report.reportHash,
      maximumSignedAt: "2026-07-01T13:00:00.000Z"
    }),
    report
  );
  assert.equal(Object.isFrozen(signed), true);

  const tampered: SignedReportPackV1 = {
    ...signed,
    report: { ...signed.report, title: "Tampered title" }
  };
  assert.throws(() => verifySignedReportPackV1(tampered, verifier), /Report hash/);
  const invalidSignature: SignedReportPackV1 = {
    ...signed,
    signature: `${signed.signature[0] === "A" ? "B" : "A"}${signed.signature.slice(1)}`
  };
  assert.throws(() => verifySignedReportPackV1(invalidSignature, verifier), /signature verification failed/);
});

test("verification rejects the wrong Ed25519 key even when the key id is reused", () => {
  const report = createReportPackV1(draft());
  const first = generateKeyPairSync("ed25519");
  const second = generateKeyPairSync("ed25519");
  const signed = signReportPackV1(
    report,
    createReportSigningKeyV1({ keyId: "rotating-key", ...first }),
    "2026-07-01T13:00:00.000Z"
  );
  const wrongVerifier = createReportVerificationKeyV1({ keyId: "rotating-key", publicKey: second.publicKey });
  assert.throws(() => verifySignedReportPackV1(signed, wrongVerifier), /key identity/);
});

test("report creation enforces structural suppression and forbids record-level dimensions", () => {
  const exposed = draft();
  const exposedCell = exposed.tables[0]!.rows[1]!.measures.loan_count!;
  const invalidSuppression: ReportPackDraftV1 = {
    ...exposed,
    tables: [{
      ...exposed.tables[0]!,
      rows: [exposed.tables[0]!.rows[0]!, {
        ...exposed.tables[0]!.rows[1]!,
        measures: { ...exposed.tables[0]!.rows[1]!.measures, loan_count: { ...exposedCell, value: "1" } }
      }]
    }]
  };
  assert.throws(() => createReportPackV1(invalidSuppression), /Suppressed cells must hide value/);

  const detail = draft();
  const invalidDetail: ReportPackDraftV1 = {
    ...detail,
    tables: [{
      ...detail.tables[0]!,
      dimensionColumns: ["borrower_id"],
      rows: detail.tables[0]!.rows.map((row) => ({ ...row, dimensions: { borrower_id: "masked-borrower" } }))
    }],
    charts: [{ ...detail.charts[0]!, xDimension: "borrower_id" }]
  };
  assert.throws(() => createReportPackV1(invalidDetail), /Record-level dimension/);
});

test("report comparisons reconcile exactly and every source population is certified for the tenant", () => {
  const comparison = draft();
  assert.throws(
    () => createReportPackV1({
      ...comparison,
      comparisons: [{ ...comparison.comparisons[0]!, delta: "24.999999999999999999" }]
    }),
    /delta does not reconcile/
  );
  const crossTenant = draft();
  assert.throws(
    () => createReportPackV1({
      ...crossTenant,
      certifiedPopulations: [{ ...crossTenant.certifiedPopulations[0]!, tenantId: "tenant-b" }]
    }),
    /different tenant/
  );
});
