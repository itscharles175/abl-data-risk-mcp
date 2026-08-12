import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import { ArtifactStore } from "../src/control/artifacts.js";
import { ControlStore } from "../src/control/store.js";
import type { DataQualityProfile } from "../src/domain/data-quality.js";
import { SnapshotIngestionService } from "../src/services/ingestion.js";
import { runSnapshotVintageAnalysis } from "../src/services/snapshot-analysis.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "abl-ingestion-"));
  directories.push(directory);
  const control = new ControlStore(join(directory, "control.sqlite"));
  const artifactRoot = join(directory, "artifacts");
  const artifacts = new ArtifactStore(artifactRoot, {
    activeKeyId: "test-key",
    keys: { "test-key": Buffer.alloc(32, 9) }
  });
  return { directory, artifactRoot, artifacts, control, ingestion: new SnapshotIngestionService(control, artifacts) };
}

const qualityProfile: DataQualityProfile = {
  id: "loan-certification",
  version: "1.0.0",
  entity: "loan_snapshot",
  keyFields: ["loan_id", "as_of_date"],
  requiredFields: ["loan_id", "as_of_date", "outstanding_balance", "currency_code"],
  balanceField: "outstanding_balance",
  asOfField: "as_of_date",
  expectedAsOfDate: "2026-07-31",
  currencyField: "currency_code",
  expectedCurrency: "USD",
  exactDecimalFields: ["outstanding_balance"]
};

test("delivery through approved mapping accepts a maximum-length certification idempotency key", () => {
  const { control, ingestion } = fixture();
  const delivery = ingestion.registerDeliveredSnapshot({
    tenantId: "tenant-a",
    snapshotId: "snapshot-2026-07",
    sourceId: "servicer-file",
    asOfDate: "2026-07-31",
    records: [
      { loan_no: "L1", as_of_dt: "2026-07-31", current_balance: "100.10", currency: "USD" },
      { loan_no: "L2", as_of_dt: "2026-07-31", current_balance: "200.20", currency: "USD" }
    ],
    deliveredBy: "connector-a",
    idempotencyKey: "delivery-1"
  });
  const mapping = control.proposeMappingVersion({
    tenantId: "tenant-a",
    mappingVersionId: "mapping-1",
    mappingKey: "servicer-loan-tape",
    snapshotId: delivery.snapshot.snapshotId,
    dictionaryVersion: "1.0.0",
    mappings: [
      { sourceColumn: "loan_no", canonicalField: "loan_id" },
      { sourceColumn: "as_of_dt", canonicalField: "as_of_date" },
      { sourceColumn: "current_balance", canonicalField: "outstanding_balance" },
      { sourceColumn: "currency", canonicalField: "currency_code" }
    ],
    proposedBy: "maker-a",
    idempotencyKey: "mapping-propose-1"
  });
  control.transitionMappingVersion({
    tenantId: "tenant-a",
    mappingVersionId: mapping.mappingVersionId,
    toStatus: "validated",
    actor: "checker-a",
    idempotencyKey: "mapping-validate-1"
  });
  control.transitionMappingVersion({
    tenantId: "tenant-a",
    mappingVersionId: mapping.mappingVersionId,
    toStatus: "approved",
    actor: "checker-a",
    idempotencyKey: "mapping-approve-1"
  });
  control.transitionMappingVersion({
    tenantId: "tenant-a",
    mappingVersionId: mapping.mappingVersionId,
    toStatus: "active",
    actor: "checker-a",
    idempotencyKey: "mapping-activate-1"
  });

  const certification = ingestion.certifyMappedSnapshot({
    tenantId: "tenant-a",
    snapshotId: delivery.snapshot.snapshotId,
    mappingVersionId: mapping.mappingVersionId,
    dataQualityRunId: "dq-1",
    reconciliationId: "recon-1",
    certificationManifestId: "certification-1",
    dataQualityProfile: qualityProfile,
    declaredControlTotals: { rowCount: 2, balance: "300.30", currency: "USD" },
    evaluatedAt: "2026-08-11T12:00:00Z",
    codeVersion: "test-1",
    executedBy: "pipeline-a",
    idempotencyKey: "c".repeat(128)
  });

  assert.equal(certification.certified, true);
  assert.equal(certification.dataQuality.totalBalance, "300.3");
  assert.equal(certification.reconciliation.passed, true);
  assert.equal(certification.durableDataQualityRun.passed, true);
  assert.equal(certification.manifest.analysisType, "snapshot_certification");
  assert.match(certification.normalizedArtifact.uri, /^abl-artifact:\/\/[a-f0-9]{64}$/);
  control.close();
});

test("material DQ and control-total breaks fail certification", () => {
  const { control, ingestion } = fixture();
  const delivery = ingestion.registerDeliveredSnapshot({
    tenantId: "tenant-a",
    snapshotId: "snapshot-bad",
    sourceId: "servicer-file",
    asOfDate: "2026-07-31",
    records: [
      { loan_no: "L1", as_of_dt: "2026-07-31", current_balance: "100", currency: "USD" },
      { loan_no: "L1", as_of_dt: "2026-07-31", current_balance: "25", currency: "USD" }
    ],
    deliveredBy: "connector-a",
    idempotencyKey: "delivery-bad"
  });
  control.proposeMappingVersion({
    tenantId: "tenant-a",
    mappingVersionId: "mapping-bad",
    mappingKey: "bad-tape",
    snapshotId: delivery.snapshot.snapshotId,
    dictionaryVersion: "1.0.0",
    mappings: [
      { sourceColumn: "loan_no", canonicalField: "loan_id" },
      { sourceColumn: "as_of_dt", canonicalField: "as_of_date" },
      { sourceColumn: "current_balance", canonicalField: "outstanding_balance" },
      { sourceColumn: "currency", canonicalField: "currency_code" }
    ],
    proposedBy: "maker-a",
    idempotencyKey: "propose-bad"
  });
  for (const [toStatus, idempotencyKey] of [
    ["validated", "validate-bad"],
    ["approved", "approve-bad"],
    ["active", "activate-bad"]
  ] as const) {
    control.transitionMappingVersion({
      tenantId: "tenant-a",
      mappingVersionId: "mapping-bad",
      toStatus,
      actor: "checker-a",
      idempotencyKey
    });
  }
  const certification = ingestion.certifyMappedSnapshot({
    tenantId: "tenant-a",
    snapshotId: "snapshot-bad",
    mappingVersionId: "mapping-bad",
    dataQualityRunId: "dq-bad",
    reconciliationId: "recon-bad",
    certificationManifestId: "certification-bad",
    dataQualityProfile: qualityProfile,
    declaredControlTotals: { rowCount: 2, balance: "200", currency: "USD" },
    evaluatedAt: "2026-08-11T12:00:00Z",
    codeVersion: "test-1",
    executedBy: "pipeline-a",
    idempotencyKey: "certify-bad"
  });
  assert.equal(certification.certified, false);
  assert.ok(certification.blockerCodes.includes("duplicate_grain_key"));
  assert.ok(certification.blockerCodes.includes("balance_out_of_tolerance"));
  assert.equal(certification.durableDataQualityRun.passed, false);
  assert.equal(certification.reconciliation.passed, false);
  assert.equal(certification.manifest.analysisType, "snapshot_certification_failed");
  control.close();
});

test("a rejected declared hash leaves no encrypted artifact or snapshot manifest behind", () => {
  const { artifactRoot, control, ingestion } = fixture();
  assert.throws(
    () =>
      ingestion.registerDeliveredSnapshot({
        tenantId: "tenant-a",
        snapshotId: "snapshot-rejected",
        sourceId: "servicer-file",
        asOfDate: "2026-07-31",
        records: [{ loan_no: "PRIVATE-LOAN", current_balance: "100" }],
        deliveredBy: "trusted-connector",
        idempotencyKey: "delivery-rejected",
        expectedCanonicalContentHash: "0".repeat(64)
      }),
    /content hash did not match/
  );
  assert.deepEqual(findFiles(artifactRoot), []);
  assert.equal(control.getDatasetSnapshot("tenant-a", "snapshot-rejected"), undefined);
  control.close();
});

test("safe native integers become exact canonical strings through certification and vintage", () => {
  const { artifacts, control, ingestion } = fixture();
  const delivery = ingestion.registerDeliveredSnapshot({
    tenantId: "tenant-a",
    snapshotId: "snapshot-native-integers",
    sourceId: "trusted-sql",
    asOfDate: "2026-07-31",
    records: [
      {
        loan_no: 101,
        origination_dt: "2026-07-01",
        as_of_dt: "2026-07-31",
        original_balance: 100,
        current_balance: 80,
        charge_off: 0,
        recovery: 0,
        dpd: 30,
        currency: "USD"
      }
    ],
    deliveredBy: "trusted-sql-connector",
    idempotencyKey: "delivery-native-integers"
  });
  const mapping = activateMapping(control, delivery.snapshot.snapshotId, "mapping-native-integers", [
    { sourceColumn: "loan_no", canonicalField: "loan_id" },
    { sourceColumn: "origination_dt", canonicalField: "origination_date" },
    { sourceColumn: "as_of_dt", canonicalField: "as_of_date" },
    { sourceColumn: "original_balance", canonicalField: "original_balance" },
    { sourceColumn: "current_balance", canonicalField: "outstanding_balance" },
    { sourceColumn: "charge_off", canonicalField: "charge_off_amount" },
    { sourceColumn: "recovery", canonicalField: "recovery_amount" },
    { sourceColumn: "dpd", canonicalField: "days_past_due" },
    { sourceColumn: "currency", canonicalField: "currency_code" }
  ]);
  const profile: DataQualityProfile = {
    ...qualityProfile,
    entity: "loan_history",
    asOfMode: "through",
    requiredFields: [
      "loan_id",
      "as_of_date",
      "origination_date",
      "original_balance",
      "outstanding_balance",
      "currency_code"
    ],
    exactDecimalFields: [
      "original_balance",
      "outstanding_balance",
      "charge_off_amount",
      "recovery_amount"
    ]
  };
  const certification = ingestion.certifyMappedSnapshot({
    tenantId: "tenant-a",
    snapshotId: delivery.snapshot.snapshotId,
    mappingVersionId: mapping.mappingVersionId,
    dataQualityRunId: "dq-native-integers",
    reconciliationId: "recon-native-integers",
    certificationManifestId: "cert-native-integers",
    dataQualityProfile: profile,
    declaredControlTotals: { rowCount: 1, balance: "80", currency: "USD" },
    evaluatedAt: "2026-08-11T12:00:00Z",
    codeVersion: "test-1",
    executedBy: "trusted-pipeline",
    idempotencyKey: "certify-native-integers"
  });
  assert.equal(certification.certified, true);
  const payload = artifacts.getJson("tenant-a", certification.normalizedArtifact.artifactId).value as {
    readonly records: readonly Readonly<Record<string, unknown>>[];
  };
  assert.deepEqual(payload.records[0], {
    as_of_date: "2026-07-31",
    charge_off_amount: "0",
    currency_code: "USD",
    days_past_due: "30",
    loan_id: "101",
    origination_date: "2026-07-01",
    original_balance: "100",
    outstanding_balance: "80",
    recovery_amount: "0"
  });
  const vintage = runSnapshotVintageAnalysis({
    records: payload.records,
    lineage: {
      snapshotHash: delivery.snapshot.contentHash,
      mappingHash: mapping.mappingHash.replace(/^sha256:/, ""),
      dictionaryHash: "a".repeat(64),
      recipeHash: "b".repeat(64)
    },
    cohortGrain: "month",
    asOfDate: "2026-07-31",
    maxMonthsOnBook: 0,
    delinquencyThresholdDays: 30,
    minimumCohortSize: 1,
    maxRecords: 10,
    maxPoints: 10
  });
  assert.equal(vintage.points[0]?.currentBalance, "80");
  assert.equal(vintage.points[0]?.delinquentBalance, "80");
  control.close();
});

test("lossy native numeric values fail before normalized analysis artifacts are written", () => {
  const { control, ingestion } = fixture();
  const delivery = ingestion.registerDeliveredSnapshot({
    tenantId: "tenant-a",
    snapshotId: "snapshot-lossy-number",
    sourceId: "trusted-sql",
    asOfDate: "2026-07-31",
    records: [{ loan_no: "L1", as_of_dt: "2026-07-31", current_balance: 0.1, currency: "USD" }],
    deliveredBy: "trusted-sql-connector",
    idempotencyKey: "delivery-lossy-number"
  });
  const mapping = activateMapping(control, delivery.snapshot.snapshotId, "mapping-lossy-number", [
    { sourceColumn: "loan_no", canonicalField: "loan_id" },
    { sourceColumn: "as_of_dt", canonicalField: "as_of_date" },
    { sourceColumn: "current_balance", canonicalField: "outstanding_balance" },
    { sourceColumn: "currency", canonicalField: "currency_code" }
  ]);
  assert.throws(
    () =>
      ingestion.certifyMappedSnapshot({
        tenantId: "tenant-a",
        snapshotId: delivery.snapshot.snapshotId,
        mappingVersionId: mapping.mappingVersionId,
        dataQualityRunId: "dq-lossy-number",
        reconciliationId: "recon-lossy-number",
        certificationManifestId: "cert-lossy-number",
        dataQualityProfile: qualityProfile,
        declaredControlTotals: { rowCount: 1, balance: "0.1", currency: "USD" },
        evaluatedAt: "2026-08-11T12:00:00Z",
        codeVersion: "test-1",
        executedBy: "trusted-pipeline",
        idempotencyKey: "certify-lossy-number"
      }),
    /outstanding_balance is not an exact canonical currency/
  );
  control.close();
});

function activateMapping(
  control: ControlStore,
  snapshotId: string,
  mappingVersionId: string,
  mappings: readonly { readonly sourceColumn: string; readonly canonicalField: string }[]
) {
  const mapping = control.proposeMappingVersion({
    tenantId: "tenant-a",
    mappingVersionId,
    mappingKey: mappingVersionId,
    snapshotId,
    dictionaryVersion: "1.0.0",
    mappings,
    proposedBy: "maker-a",
    idempotencyKey: `${mappingVersionId}-propose`
  });
  for (const [toStatus, suffix] of [
    ["validated", "validate"],
    ["approved", "approve"],
    ["active", "activate"]
  ] as const) {
    control.transitionMappingVersion({
      tenantId: "tenant-a",
      mappingVersionId,
      toStatus,
      actor: "checker-a",
      idempotencyKey: `${mappingVersionId}-${suffix}`
    });
  }
  return mapping;
}

function findFiles(root: string): readonly string[] {
  const files: string[] = [];
  for (const entry of readdirSync(root)) {
    const path = join(root, entry);
    if (statSync(path).isDirectory()) files.push(...findFiles(path));
    else files.push(path);
  }
  return files.sort((left, right) => left.localeCompare(right));
}
