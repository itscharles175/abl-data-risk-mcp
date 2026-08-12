import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import { MonitoringAlertStore } from "../src/control/alerts.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import { DefinitionStore } from "../src/control/definitions.js";
import { ControlStore } from "../src/control/store.js";
import { evaluateMonitoring } from "../src/domain/monitoring.js";
import {
  OperatorControlPlane,
  OperatorControlPlaneError,
  type OperatorPrincipal
} from "../src/operator/control-plane.js";
import { OperatorInputError } from "../src/operator/schemas.js";
import { TenantMembershipStore, TenantMembershipStoreError } from "../src/security/membership-store.js";
import { SnapshotIngestionService } from "../src/services/ingestion.js";
import {
  SqlSnapshotExtractionService,
  TrustedSqliteSnapshotSource,
  type SnapshotRelationPolicy
} from "../src/services/sql-snapshot-extraction.js";
import { createSqliteFixture, type SqliteFixture } from "./helpers/sqlite-fixture.js";

interface Harness {
  readonly directory: string;
  readonly sqlite: SqliteFixture;
  readonly control: ControlStore;
  readonly definitions: DefinitionStore;
  readonly alerts: MonitoringAlertStore;
  readonly memberships: TenantMembershipStore;
  readonly artifacts: ArtifactStore;
  readonly plane: OperatorControlPlane;
  readonly checkerPlane: OperatorControlPlane;
}

const cleanups: Array<() => void> = [];

afterEach(() => {
  for (const cleanup of cleanups.splice(0).reverse()) cleanup();
});

function harness(): Harness {
  const directory = mkdtempSync(join(tmpdir(), "abl-operator-"));
  const sqlite = createSqliteFixture();
  const controlPath = join(directory, "control.sqlite");
  const clock = () => new Date("2026-08-11T12:00:00.000Z");
  const control = new ControlStore(controlPath, { clock });
  const definitions = new DefinitionStore(controlPath, { clock });
  const alerts = new MonitoringAlertStore(controlPath, { clock });
  const memberships = new TenantMembershipStore(join(directory, "security.sqlite"), { clock });
  const artifacts = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "test-key",
    keys: { "test-key": Buffer.alloc(32, 29) }
  });
  const ingestion = new SnapshotIngestionService(control, artifacts);
  const source = new TrustedSqliteSnapshotSource({
    sourceId: "fixture",
    databasePath: sqlite.databasePath,
    assumptions: {
      principalMode: "non_owner",
      accessMode: "read_only",
      configurationSource: "trusted_runtime"
    },
    relations: [sqlPolicy()]
  });
  const sqlExtractor = new SqlSnapshotExtractionService(source, ingestion, {
    maximumRows: 20,
    maximumBytes: 100_000,
    maximumExecutionMs: 5_000,
    maximumColumns: 10
  });
  const dependencies = {
    control,
    definitions,
    artifacts,
    memberships,
    alerts,
    ingestion,
    sqlExtractors: new Map([["fixture", sqlExtractor]])
  };
  const plane = new OperatorControlPlane({
    principal: operatorPrincipal("operator-maker"),
    ...dependencies
  });
  const checkerPlane = new OperatorControlPlane({
    principal: operatorPrincipal("operator-checker"),
    ...dependencies
  });
  cleanups.push(() => {
    memberships.close();
    alerts.close();
    definitions.close();
    control.close();
    sqlite.cleanup();
    rmSync(directory, { recursive: true, force: true });
  });
  return { directory, sqlite, control, definitions, alerts, memberships, artifacts, plane, checkerPlane };
}

function operatorPrincipal(principalId: string): OperatorPrincipal {
  return {
    principalId,
    authenticationMethod: "trusted_service_identity",
    authorizationScope: "global_admin"
  };
}

function sqlPolicy(): SnapshotRelationPolicy {
  return {
    relationId: "loan-tape",
    tenantId: "tenant-a",
    tenantIsolation: "dedicated_relation",
    datasetId: "loan-dataset",
    schema: "main",
    table: "loan_tape",
    relationKind: "table",
    columns: [
      {
        columnId: "as-of-date",
        sourceName: "as_of_dt",
        outputName: "as_of_dt",
        classification: "approved",
        encoding: "native"
      },
      {
        columnId: "loan-id",
        sourceName: "loan_no",
        outputName: "loan_no",
        classification: "approved",
        encoding: "native"
      },
      {
        columnId: "balance",
        sourceName: "current_balance",
        outputName: "current_balance",
        classification: "approved",
        encoding: "exact_text"
      }
    ],
    orderBy: [
      { columnId: "as-of-date", direction: "asc", nulls: "last" },
      { columnId: "loan-id", direction: "asc", nulls: "last" }
    ],
    orderIsUnique: true,
    watermark: {
      columnId: "as-of-date",
      valueKind: "date",
      comparison: "lte",
      required: true
    }
  };
}

const sourceColumns = [
  { name: "as_of_dt", type: "date" },
  { name: "facility_no", type: "varchar" },
  { name: "loan_no", type: "varchar" },
  { name: "borrower_no", type: "varchar" },
  { name: "currency", type: "char(3)" },
  { name: "commitment", type: "decimal(18,2)" },
  { name: "current_balance", type: "decimal(18,2)" }
] as const;

const mappings = [
  { sourceColumn: "as_of_dt", canonicalField: "as_of_date" },
  { sourceColumn: "facility_no", canonicalField: "facility_id" },
  { sourceColumn: "loan_no", canonicalField: "loan_id" },
  { sourceColumn: "borrower_no", canonicalField: "borrower_id" },
  { sourceColumn: "currency", canonicalField: "currency_code" },
  { sourceColumn: "commitment", canonicalField: "commitment_amount" },
  { sourceColumn: "current_balance", canonicalField: "outstanding_balance" }
] as const;

function activateBaseMapping(context: Harness, snapshotId = "snapshot-file"): void {
  context.plane.proposeMapping({
    tenantId: "tenant-a",
    mappingVersionId: "mapping-v1",
    mappingKey: "loan-tape",
    snapshotId,
    sourceColumns,
    mappings,
    profile: "base",
    idempotencyKey: "mapping-propose"
  });
  context.checkerPlane.transitionMapping({
    tenantId: "tenant-a",
    mappingVersionId: "mapping-v1",
    toStatus: "validated",
    sourceColumns,
    profile: "base",
    idempotencyKey: "mapping-validate"
  });
  context.checkerPlane.transitionMapping({
    tenantId: "tenant-a",
    mappingVersionId: "mapping-v1",
    toStatus: "approved",
    idempotencyKey: "mapping-approve"
  });
  context.checkerPlane.transitionMapping({
    tenantId: "tenant-a",
    mappingVersionId: "mapping-v1",
    toStatus: "active",
    idempotencyKey: "mapping-activate"
  });
}

function activateQualityDefinition(context: Harness): void {
  context.plane.proposeDefinition({
    tenantId: "tenant-a",
    definitionId: "loan-quality-v1",
    definitionKey: "loan-quality",
    kind: "data_quality_profile",
    version: "1.0.0",
    effectiveFrom: "2025-01-01",
    document: {
      id: "loan-quality",
      version: "1.0.0",
      entity: "loan_snapshot",
      keyFields: ["loan_id", "as_of_date"],
      requiredFields: [
        "loan_id",
        "as_of_date",
        "outstanding_balance",
        "currency_code"
      ],
      balanceField: "outstanding_balance",
      asOfField: "as_of_date",
      expectedAsOfDate: "2025-02-28",
      currencyField: "currency_code",
      expectedCurrency: "USD",
      exactDecimalFields: ["outstanding_balance", "commitment_amount"]
    },
    idempotencyKey: "dq-propose"
  });
  for (const [toStatus, idempotencyKey] of [
    ["validated", "dq-validate"],
    ["approved", "dq-approve"],
    ["active", "dq-activate"]
  ] as const) {
    context.checkerPlane.transitionDefinition({
      tenantId: "tenant-a",
      definitionId: "loan-quality-v1",
      toStatus,
      idempotencyKey
    });
  }
}

test("operator file ingestion, governed mapping, active DQ definition, and certification form one usable chain", () => {
  const context = harness();
  const tapePath = join(context.directory, "loan-tape.csv");
  writeFileSync(
    tapePath,
    [
      "as_of_dt,facility_no,loan_no,borrower_no,currency,commitment,current_balance",
      "2025-02-28,F1,L1,B1,USD,500.00,100.10",
      "2025-02-28,F1,L2,B2,USD,500.00,200.20"
    ].join("\n")
  );

  const snapshot = context.plane.ingestLoanTape({
    tenantId: "tenant-a",
    snapshotId: "snapshot-file",
    sourceId: "operator-file",
    asOfDate: "2025-02-28",
    filePath: tapePath,
    format: "csv",
    limits: { maximumBytes: 100_000, maximumRecords: 10, maximumColumns: 20 },
    idempotencyKey: "file-ingest"
  });
  assert.equal(snapshot.rowCount, 2);
  assert.equal("records" in snapshot, false);
  assert.equal(
    context.control.getDatasetSnapshot("tenant-a", "snapshot-file")?.createdBy,
    "operator-maker"
  );

  activateBaseMapping(context);
  activateQualityDefinition(context);
  const certification = context.plane.certifySnapshot({
    tenantId: "tenant-a",
    snapshotId: "snapshot-file",
    mappingVersionId: "mapping-v1",
    dataQualityDefinitionKey: "loan-quality",
    dataQualityRunId: "dq-run-v1",
    reconciliationId: "recon-v1",
    certificationManifestId: "cert-v1",
    declaredControlTotals: { rowCount: 2, balance: "300.30", currency: "USD" },
    evaluatedAt: "2026-08-11T12:00:00.000Z",
    codeVersion: "test-1",
    idempotencyKey: "certify-v1"
  });
  assert.equal(certification.certified, true);
  assert.deepEqual(certification.blockerCodes, []);
  assert.equal(certification.dataQualityDefinitionId, "loan-quality-v1");
  assert.equal("records" in certification, false);
});

test("trusted SQL extraction is selected by source id and exposes only snapshot metadata", async () => {
  const context = harness();
  const extracted = await context.plane.extractSqlSnapshot({
    sourceId: "fixture",
    tenantId: "tenant-a",
    datasetId: "loan-dataset",
    snapshotId: "snapshot-sql",
    relationId: "loan-tape",
    columnIds: ["balance", "loan-id", "as-of-date"],
    watermark: { upperBound: "2025-02-28" },
    asOfDate: "2025-02-28",
    idempotencyKey: "sql-extract"
  });
  assert.equal(extracted.rowCount, 6);
  assert.equal(extracted.datasetId, "loan-dataset");
  assert.match(extracted.queryFingerprint, /^sha256:[a-f0-9]{64}$/);
  assert.equal("records" in extracted, false);

  await assert.rejects(
    context.plane.extractSqlSnapshot({
      sourceId: "unknown",
      tenantId: "tenant-a",
      datasetId: "loan-dataset",
      snapshotId: "snapshot-unknown",
      relationId: "loan-tape",
      columnIds: ["loan-id"],
      asOfDate: "2025-02-28",
      idempotencyKey: "sql-unknown"
    }),
    (error: unknown) =>
      error instanceof OperatorControlPlaneError && error.code === "SOURCE_NOT_CONFIGURED"
  );
});

test("operator definition validation accepts governed longitudinal loan-history profiles", () => {
  const context = harness();
  const definition = context.plane.proposeDefinition({
    tenantId: "tenant-a",
    definitionId: "loan-history-quality-v1",
    definitionKey: "loan-history-quality",
    kind: "data_quality_profile",
    version: "1.0.0",
    effectiveFrom: "2025-01-01",
    document: {
      id: "loan-history-quality",
      version: "1.0.0",
      entity: "loan_history",
      asOfMode: "through",
      keyFields: ["loan_id", "as_of_date"],
      requiredFields: ["loan_id", "as_of_date", "outstanding_balance"],
      balanceField: "outstanding_balance",
      asOfField: "as_of_date",
      expectedAsOfDate: "2025-02-28",
      exactDecimalFields: ["outstanding_balance"]
    },
    idempotencyKey: "history-dq-propose"
  });
  assert.equal(definition.kind, "data_quality_profile");
  assert.equal(definition.status, "proposed");
});

test("encrypted borrowing-base and monitoring inputs are snapshot-bound and never returned", () => {
  const context = harness();
  const tapePath = join(context.directory, "minimal.json");
  writeFileSync(
    tapePath,
    JSON.stringify([
      {
        as_of_dt: "2025-02-28",
        facility_no: "F1",
        loan_no: "L1",
        borrower_no: "B1",
        currency: "USD",
        commitment: "500",
        current_balance: "100"
      }
    ])
  );
  context.plane.ingestLoanTape({
    tenantId: "tenant-a",
    snapshotId: "snapshot-file",
    sourceId: "operator-file",
    asOfDate: "2025-02-28",
    filePath: tapePath,
    idempotencyKey: "file-ingest"
  });

  const borrowingPath = join(context.directory, "borrowing.json");
  writeFileSync(
    borrowingPath,
    JSON.stringify({
      snapshotId: "snapshot-file",
      asOfDate: "2025-02-28",
      receivables: [
        {
          receivableId: "PRIVATE-RECEIVABLE",
          debtorId: "PRIVATE-DEBTOR",
          outstandingAmount: "100",
          daysPastDue: 0,
          flags: []
        }
      ],
      usage: []
    })
  );
  const borrowing = context.plane.putInputArtifact({
    tenantId: "tenant-a",
    inputId: "borrowing-input-v1",
    kind: "borrowing_base_input",
    filePath: borrowingPath,
    idempotencyKey: "put-borrowing"
  });
  assert.equal(borrowing.kind, "borrowing_base_input");
  assert.equal(JSON.stringify(borrowing).includes("PRIVATE"), false);
  assert.equal(
    (context.artifacts.getJson("tenant-a", borrowing.artifactId).value as { snapshotId: string }).snapshotId,
    "snapshot-file"
  );

  const monitoringPath = join(context.directory, "monitoring.json");
  writeFileSync(
    monitoringPath,
    JSON.stringify({
      snapshotId: "snapshot-file",
      asOfDate: "2025-02-28",
      scope: { type: "facility", id: "PRIVATE-FACILITY" },
      observations: []
    })
  );
  assert.equal(
    context.plane.putInputArtifact({
      tenantId: "tenant-a",
      inputId: "monitoring-input-v1",
      kind: "monitoring_input",
      filePath: monitoringPath,
      idempotencyKey: "put-monitoring"
    }).kind,
    "monitoring_input"
  );
});

test("membership and mapping maker/checker controls remain enforced through the operator boundary", () => {
  const context = harness();
  const proposed = context.plane.proposeMembership({
    membershipId: "membership-v1",
    issuer: "https://issuer.example.test/",
    subject: "private-subject",
    clientId: "codex-client",
    tenantId: "tenant-a",
    principalId: "analyst-a",
    idempotencyKey: "membership-propose"
  });
  assert.equal(proposed.status, "proposed");
  assert.equal("subject" in proposed, false);
  assert.equal(context.memberships.get("membership-v1")?.proposedBy, "operator-maker");
  assert.throws(
    () =>
      context.plane.approveMembership({
        membershipId: "membership-v1",
        actor: "operator-checker",
        idempotencyKey: "membership-forged-alias"
      }),
    (error: unknown) => error instanceof OperatorInputError
  );
  assert.throws(
    () =>
      context.plane.approveMembership({
        membershipId: "membership-v1",
        idempotencyKey: "membership-self-approve"
      }),
    (error: unknown) =>
      error instanceof TenantMembershipStoreError && error.code === "MAKER_CHECKER_VIOLATION"
  );
  assert.equal(
    context.checkerPlane.approveMembership({
      membershipId: "membership-v1",
      idempotencyKey: "membership-approve"
    }).status,
    "active"
  );
  assert.equal(context.memberships.get("membership-v1")?.approvedBy, "operator-checker");
  assert.equal(
    context.checkerPlane.revokeMembership({
      membershipId: "membership-v1",
      idempotencyKey: "membership-revoke"
    }).status,
    "revoked"
  );

  assert.throws(
    () =>
      context.plane.proposeMapping({
        tenantId: "tenant-a",
        mappingVersionId: "invalid-mapping",
        mappingKey: "invalid",
        snapshotId: "missing-snapshot",
        sourceColumns: [{ name: "loan", type: "varchar" }],
        mappings: [{ sourceColumn: "loan", canonicalField: "loan_id" }],
        profile: "base",
        idempotencyKey: "invalid-mapping"
      }),
    (error: unknown) =>
      error instanceof OperatorControlPlaneError && error.code === "MAPPING_NOT_READY"
  );
});

test("alert case operations and audit inspection expose metadata without evidence or details", () => {
  const context = harness();
  const result = evaluateMonitoring({
    asOfDate: "2025-02-28",
    scope: { type: "facility", id: "facility-1" },
    dataQualityGate: {
      status: "certified",
      gateId: "dq-gate-1",
      snapshotId: "snapshot-file",
      certifiedAt: "2025-03-01T00:00:00.000Z",
      blockingFindingCount: 0,
      evidence: []
    },
    monitorDefinitions: [
      {
        monitorId: "negative-availability",
        version: "1",
        effectiveFrom: "2025-01-01",
        metricId: "availability",
        title: "Private alert title",
        message: "Private evidence message",
        severity: "critical",
        threshold: { type: "decimal", operator: "lt", value: "0", unit: "currency" }
      }
    ],
    observations: [
      {
        observationId: "availability-1",
        metricId: "availability",
        snapshotId: "snapshot-file",
        asOfDate: "2025-02-28",
        type: "decimal",
        value: "-1",
        unit: "currency",
        evidence: []
      }
    ]
  });
  const run = context.alerts.recordRun({
    tenantId: "tenant-a",
    runId: "monitor-run-1",
    result,
    recordedBy: "monitor-worker",
    idempotencyKey: "monitor-run-record"
  });
  const listed = context.plane.listAlerts({ tenantId: "tenant-a", status: "open", limit: 10 });
  assert.equal(listed.length, 1);
  assert.equal("message" in listed[0]!, false);
  assert.equal("evidence" in listed[0]!, false);
  assert.equal(
    context.plane.transitionAlert({
      tenantId: "tenant-a",
      alertId: run.alertIds[0]!,
      action: "acknowledge",
      note: "Private investigation note",
      idempotencyKey: "alert-ack"
    }).status,
    "acknowledged"
  );

  const audit = context.plane.listAudit({
    tenantId: "tenant-a",
    stream: "monitoring",
    afterSequence: 0,
    limit: 20
  });
  assert.ok(audit.length >= 3);
  assert.equal(audit.some((event) => "details" in event), false);
  assert.equal(JSON.stringify(audit).includes("Private"), false);
});
