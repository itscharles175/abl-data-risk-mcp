import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, test } from "node:test";

import {
  CONTROL_STORE_COMPONENT,
  CONTROL_STORE_SCHEMA_VERSION,
  ControlStore,
  ControlStoreError,
  type CreateDatasetSnapshotInput,
  type ProposeMappingVersionInput
} from "../src/control/store.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("snapshots are durable, tenant-scoped, immutable, and exactly idempotent", () => {
  const { databasePath, store } = createStore();
  const input = snapshotInput();

  const created = store.createDatasetSnapshot(input);
  const replayed = store.createDatasetSnapshot(input);
  assert.deepEqual(replayed, created);
  assert.equal(store.listAuditEvents("tenant-a").length, 1, "a replay must not append another event");

  assert.throws(
    () => store.createDatasetSnapshot({ ...input, rowCount: 11 }),
    (error: unknown) => isStoreError(error, "IDEMPOTENCY_CONFLICT")
  );

  const otherTenant = store.createDatasetSnapshot({
    ...input,
    tenantId: "tenant-b",
    createdBy: "maker-b",
    idempotencyKey: "create-snapshot-b"
  });
  assert.equal(otherTenant.snapshotId, created.snapshotId, "ids are scoped, not globally unique");
  assert.equal(store.getDatasetSnapshot("tenant-b", input.snapshotId)?.createdBy, "maker-b");
  assert.equal(store.getDatasetSnapshot("tenant-c", input.snapshotId), undefined);
  store.close();

  const reopened = new ControlStore(databasePath, { clock: fixedClock });
  assert.deepEqual(reopened.getDatasetSnapshot("tenant-a", input.snapshotId), created);
  reopened.close();

  const database = new DatabaseSync(databasePath, { enableForeignKeyConstraints: true });
  const schemaVersion = database
    .prepare(
      "SELECT schema_version FROM component_schema_versions WHERE component_name = ?"
    )
    .get(CONTROL_STORE_COMPONENT) as unknown as {
    readonly schema_version: number;
  };
  assert.equal(schemaVersion.schema_version, CONTROL_STORE_SCHEMA_VERSION);
  assert.throws(
    () =>
      database
        .prepare("UPDATE dataset_snapshots SET row_count = 99 WHERE tenant_id = ? AND snapshot_id = ?")
        .run("tenant-a", input.snapshotId),
    /dataset snapshots are immutable/
  );
  assert.throws(
    () => database.prepare("DELETE FROM audit_events WHERE tenant_id = ?").run("tenant-a"),
    /audit events are append-only/
  );
  database.close();
});

test("failed writes roll back the resource, audit event, and idempotency receipt together", () => {
  const directory = temporaryDirectory();
  const databasePath = join(directory, "rollback.sqlite");
  let clockCalls = 0;
  const store = new ControlStore(databasePath, {
    clock: () => {
      clockCalls += 1;
      return clockCalls === 1 ? new Date("2026-08-11T12:00:00.000Z") : new Date(Number.NaN);
    }
  });
  const input = snapshotInput();

  assert.throws(
    () => store.createDatasetSnapshot(input),
    (error: unknown) => isStoreError(error, "INVALID_ARGUMENT")
  );
  assert.equal(store.getDatasetSnapshot(input.tenantId, input.snapshotId), undefined);
  assert.deepEqual(store.listAuditEvents(input.tenantId), []);
  store.close();

  const database = new DatabaseSync(databasePath);
  const receipt = database
    .prepare(
      "SELECT COUNT(*) AS count FROM idempotency_records WHERE tenant_id = ? AND idempotency_key = ?"
    )
    .get(input.tenantId, input.idempotencyKey) as unknown as { readonly count: number };
  assert.equal(receipt.count, 0);
  database.close();
});

test("mapping lifecycle enforces maker/checker order and atomically supersedes prior active versions", () => {
  const { store } = createStore();
  store.createDatasetSnapshot(snapshotInput());
  const firstInput = mappingInput();
  const first = store.proposeMappingVersion(firstInput);

  assert.equal(first.status, "proposed");
  assert.equal(first.version, 1);
  assert.match(first.mappingHash, /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(store.proposeMappingVersion(firstInput), first);

  assert.throws(
    () =>
      store.transitionMappingVersion({
        tenantId: "tenant-a",
        mappingVersionId: "map-v1",
        toStatus: "approved",
        actor: "checker",
        idempotencyKey: "skip-validation"
      }),
    (error: unknown) => isStoreError(error, "ILLEGAL_TRANSITION")
  );
  assert.throws(
    () =>
      store.transitionMappingVersion({
        tenantId: "tenant-a",
        mappingVersionId: "map-v1",
        toStatus: "validated",
        actor: "maker",
        idempotencyKey: "validate-v1"
      }),
    (error: unknown) => isStoreError(error, "MAKER_CHECKER_VIOLATION")
  );

  // A rolled-back maker/checker violation does not consume the idempotency key.
  store.transitionMappingVersion({
    tenantId: "tenant-a",
    mappingVersionId: "map-v1",
    toStatus: "validated",
    actor: "checker",
    idempotencyKey: "validate-v1",
    evidence: { validationRun: "validation-1" }
  });
  store.transitionMappingVersion({
    tenantId: "tenant-a",
    mappingVersionId: "map-v1",
    toStatus: "approved",
    actor: "checker",
    idempotencyKey: "approve-v1"
  });
  const activeFirst = store.transitionMappingVersion({
    tenantId: "tenant-a",
    mappingVersionId: "map-v1",
    toStatus: "active",
    actor: "deployer",
    idempotencyKey: "activate-v1"
  });
  assert.equal(activeFirst.status, "active");

  const second = store.proposeMappingVersion({
    ...mappingInput(),
    mappingVersionId: "map-v2",
    idempotencyKey: "propose-map-v2",
    mappings: [
      { sourceColumn: "loan_number", canonicalField: "loan_id" },
      { sourceColumn: "balance", canonicalField: "outstanding_balance" }
    ]
  });
  assert.equal(second.version, 2);
  for (const [toStatus, actor, idempotencyKey] of [
    ["validated", "checker", "validate-v2"],
    ["approved", "checker", "approve-v2"],
    ["active", "deployer", "activate-v2"]
  ] as const) {
    store.transitionMappingVersion({
      tenantId: "tenant-a",
      mappingVersionId: "map-v2",
      toStatus,
      actor,
      idempotencyKey
    });
  }

  assert.equal(store.getMappingVersion("tenant-a", "map-v1")?.status, "superseded");
  assert.equal(store.getMappingVersion("tenant-a", "map-v2")?.status, "active");
  assert.equal(store.getMappingVersion("tenant-b", "map-v2"), undefined);
  assert.deepEqual(
    store.listMappingVersions("tenant-a", "loan-tape").map((mapping) => [mapping.version, mapping.status]),
    [
      [1, "superseded"],
      [2, "active"]
    ]
  );
  assert.equal(
    store.listAuditEvents("tenant-a").filter((event) => event.eventType === "mapping_version.superseded")
      .length,
    1
  );
  store.close();
});

test("DQ evidence, reconciliations, manifests, and artifact hashes persist as one governed chain", () => {
  const { databasePath, store } = createStore();
  store.createDatasetSnapshot(snapshotInput());
  activateMapping(store);

  const dqInput = {
    tenantId: "tenant-a",
    runId: "dq-1",
    snapshotId: "snapshot-1",
    rulesetId: "loan-tape-core",
    rulesetHash: digest("ruleset"),
    findings: [
      {
        findingId: "balance-not-null",
        ruleId: "balance-not-null",
        severity: "error" as const,
        passed: true,
        affectedRows: 0,
        message: "All balances are populated"
      },
      {
        findingId: "valid-status",
        ruleId: "valid-status",
        severity: "warning" as const,
        passed: false,
        affectedRows: 2,
        message: "Two statuses require mapping",
        evidence: { values: ["Legacy", "Pending"] }
      }
    ],
    executedBy: "quality-bot",
    idempotencyKey: "record-dq-1"
  };
  const dqRun = store.recordDataQualityRun(dqInput);
  assert.equal(dqRun.passed, false);
  assert.equal(dqRun.failedFindingCount, 1);
  assert.deepEqual(store.recordDataQualityRun(dqInput), dqRun);

  const reconciliation = store.recordReconciliation({
    tenantId: "tenant-a",
    reconciliationId: "recon-1",
    snapshotId: "snapshot-1",
    kind: "stratification-total",
    checks: [
      {
        checkId: "balance",
        expected: "1000.00",
        actual: "1000.00",
        difference: "0.00",
        tolerance: "0.00",
        passed: true
      }
    ],
    details: { denominator: "outstanding_balance" },
    performedBy: "analysis-bot",
    idempotencyKey: "record-recon-1"
  });
  assert.equal(reconciliation.passed, true);

  const manifestInput = {
    tenantId: "tenant-a",
    manifestId: "analysis-1",
    snapshotId: "snapshot-1",
    mappingVersionId: "map-v1",
    analysisType: "stratification",
    parameters: { asOfDate: "2026-06-30", dimension: "risk_rating" },
    queryHash: digest("query"),
    codeVersion: "0.1.0+abc123",
    artifacts: [
      {
        artifactId: "strat-table",
        kind: "table",
        mediaType: "application/json",
        contentHash: digest("artifact"),
        uri: "control://tenant-a/analysis-1/strat-table",
        metadata: { rows: 5 }
      }
    ],
    createdBy: "analysis-bot",
    idempotencyKey: "record-analysis-1"
  } as const;
  const manifest = store.recordAnalysisManifest(manifestInput);
  assert.match(manifest.manifestHash, /^sha256:[a-f0-9]{64}$/);
  assert.equal(manifest.artifacts[0]?.contentHash, digest("artifact"));
  assert.deepEqual(store.recordAnalysisManifest(manifestInput), manifest);

  assert.throws(
    () =>
      store.recordDataQualityRun({
        ...dqInput,
        tenantId: "tenant-b",
        idempotencyKey: "cross-tenant-dq"
      }),
    (error: unknown) => isStoreError(error, "NOT_FOUND")
  );
  assert.equal(store.getDataQualityRun("tenant-b", "dq-1"), undefined);
  store.close();

  const reopened = new ControlStore(databasePath, { clock: fixedClock });
  assert.deepEqual(reopened.getDataQualityRun("tenant-a", "dq-1"), dqRun);
  assert.deepEqual(reopened.getReconciliation("tenant-a", "recon-1"), reconciliation);
  assert.deepEqual(reopened.getAnalysisManifest("tenant-a", "analysis-1"), manifest);
  assert.deepEqual(
    reopened.listAuditEvents("tenant-a", { limit: 100 }).map((event) => event.eventType),
    [
      "dataset_snapshot.created",
      "mapping_version.proposed",
      "mapping_version.validated",
      "mapping_version.approved",
      "mapping_version.active",
      "data_quality_run.recorded",
      "reconciliation.recorded",
      "analysis_manifest.recorded"
    ]
  );
  reopened.close();
});

test("custom audit events paginate by tenant and remain idempotent", () => {
  const { store } = createStore();
  const input = {
    tenantId: "tenant-a",
    eventType: "policy.exception_reviewed",
    entityType: "policy_exception",
    entityId: "exception-1",
    actor: "risk-officer",
    details: { decision: "declined", reasonCode: "insufficient-evidence" },
    idempotencyKey: "audit-exception-1"
  } as const;
  const event = store.appendAuditEvent(input);
  assert.deepEqual(store.appendAuditEvent(input), event);
  assert.deepEqual(store.listAuditEvents("tenant-b"), []);
  assert.deepEqual(store.listAuditEvents("tenant-a", { afterSequence: event.sequence }), []);
  assert.deepEqual(store.listAuditEvents("tenant-a", { limit: 1 }), [event]);
  store.close();
});

function createStore(): { readonly databasePath: string; readonly store: ControlStore } {
  const directory = temporaryDirectory();
  const databasePath = join(directory, "control.sqlite");
  return { databasePath, store: new ControlStore(databasePath, { clock: fixedClock }) };
}

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "abl-control-store-test-"));
  temporaryDirectories.push(directory);
  return directory;
}

function fixedClock(): Date {
  return new Date("2026-08-11T12:00:00.000Z");
}

function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function snapshotInput(): CreateDatasetSnapshotInput {
  return {
    tenantId: "tenant-a",
    snapshotId: "snapshot-1",
    sourceId: "warehouse",
    sourceLocator: "warehouse.public.loan_tape",
    asOfDate: "2026-06-30",
    contentHash: digest("snapshot-content"),
    rowCount: 10,
    schema: {
      columns: [
        { name: "loan_no", type: "varchar" },
        { name: "balance", type: "numeric" }
      ]
    },
    createdBy: "maker",
    idempotencyKey: "create-snapshot-1"
  };
}

function mappingInput(): ProposeMappingVersionInput {
  return {
    tenantId: "tenant-a",
    mappingVersionId: "map-v1",
    mappingKey: "loan-tape",
    snapshotId: "snapshot-1",
    dictionaryVersion: "1.0.0",
    mappings: [
      { sourceColumn: "loan_no", canonicalField: "loan_id" },
      { sourceColumn: "balance", canonicalField: "outstanding_balance" }
    ],
    proposedBy: "maker",
    idempotencyKey: "propose-map-v1"
  };
}

function activateMapping(store: ControlStore): void {
  store.proposeMappingVersion(mappingInput());
  store.transitionMappingVersion({
    tenantId: "tenant-a",
    mappingVersionId: "map-v1",
    toStatus: "validated",
    actor: "checker",
    idempotencyKey: "validate-map-v1"
  });
  store.transitionMappingVersion({
    tenantId: "tenant-a",
    mappingVersionId: "map-v1",
    toStatus: "approved",
    actor: "checker",
    idempotencyKey: "approve-map-v1"
  });
  store.transitionMappingVersion({
    tenantId: "tenant-a",
    mappingVersionId: "map-v1",
    toStatus: "active",
    actor: "deployer",
    idempotencyKey: "activate-map-v1"
  });
}

function isStoreError(error: unknown, code: ControlStoreError["code"]): boolean {
  return error instanceof ControlStoreError && error.code === code;
}
