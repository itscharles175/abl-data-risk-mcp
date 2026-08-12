import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, test } from "node:test";

import {
  ContractValidationError,
  canonicalHash,
  type Sha256Hash
} from "../src/contracts/canonical.js";
import {
  createMetricProjectionV1,
  metricProjectionReferenceV1,
  parseMetricProjectionV1
} from "../src/contracts/metric-projection-v1.js";
import {
  certifyMetricRunV1,
  createMetricRunV1,
  metricRunCellHashV1,
  MetricRunObservationInputV1Schema,
  parseMetricRunV1,
  type MetricDefinitionReferenceV1,
  type MetricRunMethodologyReferenceV1,
  type MetricRunSourceV1,
  type MetricRunV1
} from "../src/contracts/metric-run-v1.js";
import { MonitoringAlertStore } from "../src/control/alerts.js";
import { DefinitionStore } from "../src/control/definitions.js";
import { InputCertificationStore } from "../src/control/input-certifications.js";
import {
  METRIC_RUN_STORE_COMPONENT,
  METRIC_RUN_STORE_SCHEMA_VERSION,
  MetricRunStore,
  MetricRunStoreError,
  type CreateMetricRunInput
} from "../src/control/metric-runs.js";
import { ControlStore } from "../src/control/store.js";
import {
  MetricRunEvidenceError,
  MetricRunEvidenceService,
  type CreateMetricRunCandidateRequestV1,
  type FrozenMetricResultCellV1,
  type MetricRunAuthorityResolver
} from "../src/services/metric-run-evidence.js";

const TENANT_ID = "tenant-a";
const AS_OF_DATE = "2026-08-11";
const SNAPSHOT_CERTIFIED_AT = "2026-08-12T10:00:00.000Z";
const RESULT_RECORDED_AT = "2026-08-12T11:00:00.000Z";
const CREATED_AT = "2026-08-12T12:00:00.000Z";
const APPROVED_AT = "2026-08-12T12:05:00.000Z";
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("metric projection is strict, content-addressed, and approval-neutral", () => {
  const projection = projectionFixture();
  assert.deepEqual(parseMetricProjectionV1(projection), projection);
  assert.deepEqual(
    metricProjectionReferenceV1(projection, projectionGovernanceFixture()),
    projectionReferenceFixture()
  );
  assert.equal(projectionReferenceFixture().version, "1.2.3+build.7");
  assert.throws(
    () =>
      metricProjectionReferenceV1(projection, {
        ...projectionGovernanceFixture(),
        documentHash: canonicalHash("another projection document")
      }),
    (error: unknown) => contractError(error, "HASH_MISMATCH")
  );
  assert.throws(
    () => parseMetricProjectionV1({ ...projection, metricName: "different_metric" }),
    (error: unknown) => contractError(error, "HASH_MISMATCH")
  );
  assert.throws(
    () =>
      createMetricProjectionV1({
        ...projectionInput(),
        scope: { type: "facility", idSource: "dimension", dimension: "as_of_date" }
      }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
});

test("MetricRunV1 binds projected result-cell facts, lineage, lifecycle hashes, and maker/checker", () => {
  const created = createMetricRunV1(contractInput());
  assert.equal(created.status, "created");
  assert.equal(created.observation.scopeHash, canonicalHash(created.observation.scope));
  assert.equal(created.source.sourceType, "point_in_time");
  assert.equal(created.source.cellHash, pointInTimeCellFixture().source.cellHash);
  assert.equal(
    created.derivationHash,
    canonicalHash(without(created, ["createdAt", "createdBy", "runHash", "status", "derivationHash"]))
  );

  const certified = certifyMetricRunV1(created, { approvedBy: "checker", approvedAt: APPROVED_AT });
  assert.equal(certified.status, "certified");
  assert.equal(certified.runHash, created.runHash);
  assert.deepEqual(parseMetricRunV1(certified), certified);
  assert.throws(
    () => certifyMetricRunV1(created, { approvedBy: created.createdBy, approvedAt: APPROVED_AT }),
    (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
  );
});

test("MetricRunV1 rejects observation, result-cell, source, time, and schema tampering", () => {
  const input = contractInput();
  assert.throws(
    () =>
      createMetricRunV1({
        ...input,
        observation: {
          ...input.observation,
          measurement: { type: "decimal", value: "01.00", unit: "currency" }
        }
      }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
  assert.throws(
    () => createMetricRunV1({ ...input, observation: { ...input.observation, denominator: undefined } }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
  assert.throws(
    () =>
      createMetricRunV1({
        ...input,
        observation: { ...input.observation, coverage: { includedCount: 101, eligibleCount: 100 } }
      }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
  assert.throws(
    () =>
      createMetricRunV1({
        ...input,
        source: { ...input.source, cellHash: canonicalHash("substituted cell") }
      }),
    (error: unknown) => contractError(error, "HASH_MISMATCH")
  );
  assert.throws(
    () =>
      createMetricRunV1({
        ...input,
        source: { ...input.source, sourceHash: canonicalHash("substituted source") }
      }),
    (error: unknown) => contractError(error, "HASH_MISMATCH")
  );
  assert.throws(
    () =>
      createMetricRunV1({
        ...input,
        source: pointInTimeSourceFixture({ snapshotAsOfDate: "2026-08-10" })
      }),
    (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
  );
  const futureObservation = observationFixture({ asOfDate: "2026-08-13" });
  const prematurelyCertifiedSource = pointInTimeSourceFixture({
    observation: futureObservation,
    snapshotAsOfDate: "2026-08-13",
    snapshotCertifiedAt: "2026-08-12T10:00:00.000Z",
    resultRecordedAt: "2026-08-13T11:00:00.000Z"
  });
  assert.throws(
    () =>
      createMetricRunV1({
        ...input,
        observation: futureObservation,
        source: prematurelyCertifiedSource,
        createdAt: "2026-08-14T12:00:00.000Z"
      }),
    (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
  );
  assert.throws(
    () => createMetricRunV1({ ...input, createdAt: "2026-08-12T10:30:00.000Z" }),
    (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
  );
  const postdatedDefinitions: readonly PointInTimeCellOptions[] = [
    { projection: { ...projectionReferenceFixture(), approvedAt: "2026-08-12T11:00:00.001Z" } },
    { metricDefinition: { ...metricDefinitionFixture(), approvedAt: "2026-08-12T11:00:00.001Z" } },
    { methodology: { ...methodologyFixture(), approvedAt: "2026-08-12T11:00:00.001Z" } }
  ];
  for (const [index, options] of postdatedDefinitions.entries()) {
    const cell = pointInTimeCellFixture(options);
    assert.throws(
      () =>
        createMetricRunV1({
          contractVersion: 1,
          runId: `postdated-definition-${index}`,
          tenantId: TENANT_ID,
          metricId: cell.metricId,
          projection: cell.projection,
          metricDefinition: cell.metricDefinition,
          methodology: cell.methodology,
          source: cell.source,
          observation: cell.observation,
          createdBy: "maker",
          createdAt: CREATED_AT
        }),
      (error: unknown) => contractError(error, "INVARIANT_VIOLATION"),
      `definition approval ${index} cannot postdate the governed result`
    );
  }
  assert.throws(
    () => createMetricRunV1({ ...input, projection: { ...input.projection, arbitrary: true } } as never),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
});

test("MetricRunV1 rejects result cells that contradict governed projection semantics", () => {
  const wrongDefinition = pointInTimeCellFixture({
    metricDefinition: {
      ...metricDefinitionFixture(),
      definitionId: "metric-definition-wrong"
    }
  });
  const wrongMetric = pointInTimeCellFixture({ metricId: "wrong_metric" });
  const booleanObservation: ObservationInput = {
    asOfDate: AS_OF_DATE,
    scope: { type: "facility", id: "facility-1" },
    measurement: { type: "boolean", value: true, unit: "boolean" },
    coverage: { includedCount: 98, eligibleCount: 100 }
  };
  const wrongMeasurement = pointInTimeCellFixture({ observation: booleanObservation });
  const wrongScopeType = pointInTimeCellFixture({
    observation: observationFixture({ scope: { type: "portfolio", id: "facility-1" } })
  });
  const wrongFixedScopeId = pointInTimeCellFixture({
    observation: observationFixture({ scope: { type: "facility", id: "facility-2" } })
  });

  for (const [index, cell] of [
    wrongDefinition,
    wrongMetric,
    wrongMeasurement,
    wrongScopeType,
    wrongFixedScopeId
  ].entries()) {
    assert.throws(
      () =>
        createMetricRunV1({
          ...contractInput(),
          runId: `projection-semantic-mismatch-${index}`,
          metricId: cell.metricId,
          projection: cell.projection,
          metricDefinition: cell.metricDefinition,
          methodology: cell.methodology,
          source: cell.source,
          observation: cell.observation
        }),
      (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
    );
  }
});

test("ratio observations require reproducible same-unit operands", () => {
  const { numerator: _numerator, denominator: _denominator, ...base } = observationFixture();
  assert.equal(
    MetricRunObservationInputV1Schema.safeParse({
      ...base,
      measurement: { type: "decimal", value: "0.1", unit: "ratio" }
    }).success,
    false
  );
  assert.equal(
    MetricRunObservationInputV1Schema.safeParse({
      ...base,
      measurement: { type: "decimal", value: "0.1", unit: "ratio" },
      numerator: { value: "10", unit: "currency" },
      denominator: { value: "100", unit: "count" }
    }).success,
    false
  );
  assert.equal(
    MetricRunObservationInputV1Schema.safeParse({
      ...base,
      measurement: { type: "decimal", value: "0.1", unit: "ratio" },
      numerator: { value: "10", unit: "currency" },
      denominator: { value: "100", unit: "currency" }
    }).success,
    true
  );
  assert.equal(
    MetricRunObservationInputV1Schema.safeParse({
      ...base,
      measurement: { type: "decimal", value: "0.1", unit: "ratio" },
      numerator: { value: "1", unit: "count" },
      denominator: { value: "0", unit: "count" }
    }).success,
    false
  );
});

test("metric-run coverage cannot exceed the certified population", () => {
  const observation = observationFixture({
    coverage: { includedCount: 100, eligibleCount: 101 }
  });
  const cell = pointInTimeCellFixture({ observation, populationRowCount: 100 });
  assert.throws(
    () =>
      createMetricRunV1({
        ...contractInput(),
        metricId: cell.metricId,
        projection: cell.projection,
        metricDefinition: cell.metricDefinition,
        methodology: cell.methodology,
        source: cell.source,
        observation: cell.observation
      }),
    (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
  );
});

test("certified MetricRunV1 rejects a fully rehashed result recorded after run creation", () => {
  const certified = certifyMetricRunV1(createMetricRunV1(contractInput()), {
    approvedBy: "checker",
    approvedAt: APPROVED_AT
  });
  const { sourceHash: _sourceHash, ...sourceBody } = certified.source;
  const changedSourceBody = {
    ...sourceBody,
    resultRecordedAt: "2026-08-12T12:01:00.000Z"
  };
  const source = { ...changedSourceBody, sourceHash: canonicalHash(changedSourceBody) };
  const derivationBody = {
    contractVersion: certified.contractVersion,
    runId: certified.runId,
    tenantId: certified.tenantId,
    metricId: certified.metricId,
    projection: certified.projection,
    metricDefinition: certified.metricDefinition,
    methodology: certified.methodology,
    source,
    observation: certified.observation
  };
  const body = { ...derivationBody, derivationHash: canonicalHash(derivationBody) };
  const createdBody = {
    ...body,
    status: "created" as const,
    createdBy: certified.createdBy,
    createdAt: certified.createdAt
  };
  const certifiedBody = {
    ...body,
    status: "certified" as const,
    createdBy: certified.createdBy,
    createdAt: certified.createdAt,
    runHash: canonicalHash(createdBody),
    approvedBy: certified.approvedBy,
    approvedAt: certified.approvedAt
  };
  assert.throws(
    () => parseMetricRunV1({ ...certifiedBody, certificationHash: canonicalHash(certifiedBody) }),
    (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
  );
});

test("longitudinal sources bind a certified bundle and enforce observation range and ordering", () => {
  const observation = observationFixture();
  const source = longitudinalSourceFixture({ observation });
  const created = createMetricRunV1({
    ...contractInput(),
    runId: "metric-run-longitudinal",
    source,
    observation
  });
  assert.equal(created.source.sourceType, "longitudinal");
  assert.equal(created.source.longitudinalBundleId, "longitudinal-bundle-1");
  assert.equal(created.source.periodCount, 3);

  assert.throws(
    () =>
      createMetricRunV1({
        ...contractInput(),
        runId: "metric-run-before-range",
        observation: observationFixture({ asOfDate: "2026-05-31" }),
        source
      }),
    (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
  );
  assert.throws(
    () =>
      createMetricRunV1({
        ...contractInput(),
        runId: "metric-run-bad-bundle-time",
        observation,
        source: longitudinalSourceFixture({
          observation,
          bundleCreatedAt: "2026-08-10T10:00:00.000Z"
        })
      }),
    (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
  );
});

test("metric-run store is durable, tenant-scoped, exactly idempotent, and maker/checker", () => {
  const databasePath = temporaryDatabasePath("metric-runs.sqlite");
  const store = new MetricRunStore(databasePath, {
    clock: sequentialClock(CREATED_AT, APPROVED_AT)
  });
  const input = storeInput();
  const created = store.create(input);
  assert.deepEqual(store.create(input), created);
  assert.equal(store.get("tenant-b", created.runId), undefined);
  assert.equal(store.listAuditEvents(TENANT_ID).length, 1);
  assert.throws(
    () => store.create({ ...input, runId: "changed-run", idempotencyKey: input.idempotencyKey }),
    (error: unknown) => storeError(error, "IDEMPOTENCY_CONFLICT")
  );
  assert.throws(
    () => store.create({ ...input, runId: "duplicate-run", idempotencyKey: "duplicate-key" }),
    (error: unknown) => storeError(error, "CONFLICT")
  );
  assert.throws(
    () =>
      store.approve({
        tenantId: TENANT_ID,
        runId: created.runId,
        expectedRunHash: created.runHash,
        approvedBy: created.createdBy,
        idempotencyKey: "maker-approval"
      }),
    (error: unknown) => storeError(error, "MAKER_CHECKER_VIOLATION")
  );
  const approval = {
    tenantId: TENANT_ID,
    runId: created.runId,
    expectedRunHash: created.runHash,
    approvedBy: "checker",
    idempotencyKey: "approve-run"
  } as const;
  const certified = store.approve(approval);
  assert.deepEqual(store.approve(approval), certified);
  assert.equal(store.listAuditEvents(TENANT_ID).length, 2);
  assert.deepEqual(
    store.findCertifiedByObservation({
      tenantId: TENANT_ID,
      metricId: certified.metricId,
      asOfDate: certified.observation.asOfDate,
      scope: certified.observation.scope,
      sourceHash: certified.source.sourceHash
    }),
    certified
  );
  store.close();

  const reopened = new MetricRunStore(databasePath);
  assert.deepEqual(reopened.getCertified(TENANT_ID, created.runId), certified);
  assert.deepEqual(reopened.list(TENANT_ID), [certified]);
  reopened.close();
});

test("metric-run writes reject a regressing store clock without partial certification", () => {
  const store = new MetricRunStore(":memory:", {
    clock: sequentialClock(CREATED_AT, "2026-08-12T11:59:00.000Z")
  });
  const created = store.create(storeInput());
  assert.throws(
    () =>
      store.approve({
        tenantId: TENANT_ID,
        runId: created.runId,
        expectedRunHash: created.runHash,
        approvedBy: "checker",
        idempotencyKey: "regressing-clock-approval"
      }),
    (error: unknown) => storeError(error, "INVALID_INPUT")
  );
  assert.equal(store.getCertified(TENANT_ID, created.runId), undefined);
  assert.equal(store.listAuditEvents(TENANT_ID).length, 1);
  store.close();
});

test("same-date corrections coexist under distinct certified source hashes and require exact lookup", () => {
  const store = new MetricRunStore(":memory:", {
    clock: sequentialClock(CREATED_AT, CREATED_AT, APPROVED_AT, APPROVED_AT)
  });
  const originalInput = storeInput();
  const original = store.create(originalInput);
  const correctedObservation = observationFixture({
    measurement: { type: "decimal", value: "11", unit: "currency" }
  });
  const correctionCell = pointInTimeCellFixture({
    observation: correctedObservation,
    resultArtifactId: "surveillance-result-correction-1",
    resultArtifactHash: canonicalHash("surveillance result correction"),
    resultManifestId: "surveillance-manifest-correction-1",
    resultManifestHash: canonicalHash("surveillance manifest correction"),
    snapshotCertificationManifestId: "snapshot-certification-correction-1",
    snapshotCertificationHash: canonicalHash("snapshot certification correction"),
    inputArtifactId: "normalized-snapshot-correction-1",
    inputArtifactHash: canonicalHash("normalized snapshot correction"),
    populationHash: canonicalHash("corrected population"),
    populationRowCount: 101,
    cellId: "metric-cell-correction-1"
  });
  const correction = store.create(storeInputFromCell(correctionCell, {
    runId: "metric-run-correction-1",
    idempotencyKey: "create-correction"
  }));
  assert.equal(correction.observation.asOfDate, original.observation.asOfDate);
  assert.equal(correction.observation.scopeHash, original.observation.scopeHash);
  assert.notEqual(correction.source.sourceHash, original.source.sourceHash);

  const certifiedOriginal = store.approve({
    tenantId: TENANT_ID,
    runId: original.runId,
    expectedRunHash: original.runHash,
    approvedBy: "checker",
    idempotencyKey: "approve-original"
  });
  const certifiedCorrection = store.approve({
    tenantId: TENANT_ID,
    runId: correction.runId,
    expectedRunHash: correction.runHash,
    approvedBy: "checker",
    idempotencyKey: "approve-correction"
  });
  assert.deepEqual(
    store.findCertifiedByObservation({
      tenantId: TENANT_ID,
      metricId: original.metricId,
      asOfDate: original.observation.asOfDate,
      scope: original.observation.scope,
      sourceHash: original.source.sourceHash
    }),
    certifiedOriginal
  );
  assert.deepEqual(
    store.findCertifiedByObservation({
      tenantId: TENANT_ID,
      metricId: correction.metricId,
      asOfDate: correction.observation.asOfDate,
      scope: correction.observation.scope,
      sourceHash: correction.source.sourceHash
    }),
    certifiedCorrection
  );
  store.close();
});

test("metric-run schema is attested, immutable, and coexists with existing stores", () => {
  const databasePath = temporaryDatabasePath("metric-shared.sqlite");
  new ControlStore(databasePath).close();
  new MonitoringAlertStore(databasePath).close();
  new DefinitionStore(databasePath).close();
  new InputCertificationStore(databasePath).close();
  const store = new MetricRunStore(databasePath, { clock: () => new Date(CREATED_AT) });
  const created = store.create(storeInput());
  store.close();
  new MetricRunStore(databasePath).close();

  const database = new DatabaseSync(databasePath, { enableForeignKeyConstraints: true });
  const version = database
    .prepare("SELECT schema_version FROM component_schema_versions WHERE component_name = ?")
    .get(METRIC_RUN_STORE_COMPONENT) as unknown as { readonly schema_version: number };
  assert.equal(version.schema_version, METRIC_RUN_STORE_SCHEMA_VERSION);
  assert.equal(tableExists(database, "audit_events"), true);
  assert.equal(tableExists(database, "input_certification_audit_events"), true);
  assert.equal(tableExists(database, "metric_run_audit_events"), true);
  assert.throws(
    () =>
      database
        .prepare("UPDATE metric_runs SET metric_id = ? WHERE tenant_id = ? AND run_id = ?")
        .run("tampered", TENANT_ID, created.runId),
    /metric runs are immutable/
  );
  assert.throws(
    () => database.prepare("DELETE FROM metric_run_audit_events WHERE tenant_id = ?").run(TENANT_ID),
    /metric run audit is append-only/
  );
  database.exec("DROP INDEX metric_runs_tenant_created");
  database.close();
  assert.throws(() => new MetricRunStore(databasePath), /failed attestation/);

  const newerPath = temporaryDatabasePath("metric-newer.sqlite");
  new MetricRunStore(newerPath).close();
  const newer = new DatabaseSync(newerPath);
  newer
    .prepare("UPDATE component_schema_versions SET schema_version = ? WHERE component_name = ?")
    .run(METRIC_RUN_STORE_SCHEMA_VERSION + 1, METRIC_RUN_STORE_COMPONENT);
  newer.close();
  assert.throws(
    () => new MetricRunStore(newerPath),
    (error: unknown) => storeError(error, "CONFLICT") && /newer than supported/.test(String(error))
  );
});

test("service creation request contains identifiers only and all quantitative facts come from authority", () => {
  const store = new MetricRunStore(":memory:", {
    clock: sequentialClock(CREATED_AT, APPROVED_AT)
  });
  const authority = new MutableAuthority();
  const service = new MetricRunEvidenceService({ metricRuns: store, authority });
  const request = serviceRequest();
  assert.deepEqual(Object.keys(request).sort(), [
    "cellId",
    "createdBy",
    "idempotencyKey",
    "projectionDefinitionId",
    "runId",
    "surveillanceResultArtifactId",
    "tenantId"
  ]);
  assert.doesNotMatch(JSON.stringify(request), /measurement|numerator|denominator|coverage|populationHash/);

  const created = service.createCandidate(request);
  assert.deepEqual(created.projection, authority.cell.projection);
  assert.deepEqual(created.metricDefinition, authority.cell.metricDefinition);
  assert.deepEqual(created.methodology, authority.cell.methodology);
  assert.deepEqual(created.observation.measurement, authority.cell.observation.measurement);
  assert.deepEqual(created.source, authority.cell.source);

  assert.throws(
    () => service.createCandidate({ ...request, measurement: "999" } as never),
    (error: unknown) => evidenceError(error, "INVALID_REQUEST")
  );
  const certified = service.approveCandidate({
    tenantId: TENANT_ID,
    runId: created.runId,
    expectedRunHash: created.runHash,
    approvedBy: "checker",
    idempotencyKey: "approve-service-run"
  });
  const verified = service.verifyObservation({
    tenantId: TENANT_ID,
    runId: certified.runId,
    metricId: certified.metricId,
    asOfDate: certified.observation.asOfDate,
    scope: certified.observation.scope,
    measurement: certified.observation.measurement
  });
  assert.deepEqual(verified.reference, { kind: "metric_run", id: certified.runId });
  assert.equal(verified.summary.cellHash, certified.source.cellHash);
  assert.equal(verified.summary.sourceHash, certified.source.sourceHash);
  assert.equal(
    service.lookupCertified({
      tenantId: TENANT_ID,
      metricId: certified.metricId,
      asOfDate: certified.observation.asOfDate,
      scope: certified.observation.scope,
      sourceHash: certified.source.sourceHash
    })?.run.runId,
    certified.runId
  );
  store.close();
});

test("service rejects cross-tenant access, mismatched observations, and invalid authority cell hashes", () => {
  const store = new MetricRunStore(":memory:", {
    clock: sequentialClock(CREATED_AT, APPROVED_AT)
  });
  const authority = new MutableAuthority();
  const service = new MetricRunEvidenceService({ metricRuns: store, authority });
  const created = service.createCandidate(serviceRequest());
  const certified = service.approveCandidate({
    tenantId: TENANT_ID,
    runId: created.runId,
    expectedRunHash: created.runHash,
    approvedBy: "checker",
    idempotencyKey: "approve-authority-run"
  });
  assert.throws(
    () =>
      service.verifyObservation({
        tenantId: "tenant-b",
        runId: certified.runId,
        metricId: certified.metricId,
        asOfDate: certified.observation.asOfDate,
        scope: certified.observation.scope,
        measurement: certified.observation.measurement
      }),
    (error: unknown) => evidenceError(error, "NOT_FOUND")
  );
  assert.throws(
    () =>
      service.verifyObservation({
        tenantId: TENANT_ID,
        runId: certified.runId,
        metricId: certified.metricId,
        asOfDate: certified.observation.asOfDate,
        scope: certified.observation.scope,
        measurement: { type: "decimal", value: "999", unit: "currency" }
      }),
    (error: unknown) => evidenceError(error, "OBSERVATION_MISMATCH")
  );

  const invalidAuthority = new MutableAuthority();
  invalidAuthority.cell = {
    ...invalidAuthority.cell,
    source: { ...invalidAuthority.cell.source, cellHash: canonicalHash("forged cell") }
  };
  const invalidService = new MetricRunEvidenceService({ metricRuns: store, authority: invalidAuthority });
  assert.throws(
    () => invalidService.createCandidate({ ...serviceRequest(), runId: "forged-run", idempotencyKey: "forged" }),
    (error: unknown) => contractError(error, "HASH_MISMATCH") || storeError(error, "INVALID_INPUT")
  );

  const crossTenantService = new MetricRunEvidenceService({
    metricRuns: store,
    authority: { resolveFrozenResultCell: () => pointInTimeCellFixture({ tenantId: TENANT_ID }) }
  });
  assert.throws(
    () =>
      crossTenantService.createCandidate({
        ...serviceRequest(),
        tenantId: "tenant-b",
        runId: "cross-tenant-authority-run",
        idempotencyKey: "cross-tenant-authority"
      }),
    (error: unknown) => evidenceError(error, "AUTHORITY_MISMATCH")
  );
  assert.equal(store.get("tenant-b", "cross-tenant-authority-run"), undefined);
  store.close();
});

test("service re-resolves frozen result-cell evidence before approval and every read", () => {
  const store = new MetricRunStore(":memory:", {
    clock: sequentialClock(CREATED_AT, APPROVED_AT)
  });
  const authority = new MutableAuthority();
  const service = new MetricRunEvidenceService({ metricRuns: store, authority });
  const created = service.createCandidate(serviceRequest());
  const original = authority.cell;
  authority.cell = pointInTimeCellFixture({
    metricDefinition: {
      ...original.metricDefinition,
      definitionHash: canonicalHash("replacement metric definition")
    }
  });
  assert.throws(
    () =>
      service.approveCandidate({
        tenantId: TENANT_ID,
        runId: created.runId,
        expectedRunHash: created.runHash,
        approvedBy: "checker",
        idempotencyKey: "approve-after-definition-drift"
      }),
    (error: unknown) => evidenceError(error, "AUTHORITY_MISMATCH")
  );
  assert.equal(store.get(TENANT_ID, created.runId)?.status, "created");

  authority.cell = pointInTimeCellFixture({
    methodology: {
      ...original.methodology,
      definitionId: "methodology-lookalike",
      version: "99.0.0"
    }
  });
  assert.throws(
    () =>
      service.approveCandidate({
        tenantId: TENANT_ID,
        runId: created.runId,
        expectedRunHash: created.runHash,
        approvedBy: "checker",
        idempotencyKey: "approve-after-methodology-identity-drift"
      }),
    (error: unknown) => evidenceError(error, "AUTHORITY_MISMATCH")
  );
  assert.equal(store.get(TENANT_ID, created.runId)?.status, "created");

  authority.cell = original;
  const certified = service.approveCandidate({
    tenantId: TENANT_ID,
    runId: created.runId,
    expectedRunHash: created.runHash,
    approvedBy: "checker",
    idempotencyKey: "approve-after-restoration"
  });
  authority.cell = pointInTimeCellFixture({
    resultArtifactId: original.source.resultArtifactId,
    cellId: original.source.cellId,
    populationHash: canonicalHash("drifted population")
  });
  assert.throws(
    () => service.getCertified(TENANT_ID, certified.runId),
    (error: unknown) => evidenceError(error, "AUTHORITY_MISMATCH")
  );
  store.close();
});

test("candidate and approval retries replay locked receipts after authority supersession", () => {
  const store = new MetricRunStore(":memory:", {
    clock: sequentialClock(CREATED_AT, APPROVED_AT)
  });
  const authority = new MutableAuthority();
  const service = new MetricRunEvidenceService({ metricRuns: store, authority });
  const request = serviceRequest();
  const created = service.createCandidate(request);
  authority.cell = pointInTimeCellFixture({
    projection: {
      ...authority.cell.projection,
      version: "2.0.0",
      definitionHash: canonicalHash("projection v2")
    }
  });
  assert.deepEqual(service.createCandidate(request), created);
  const approval = {
    tenantId: TENANT_ID,
    runId: created.runId,
    expectedRunHash: created.runHash,
    approvedBy: "checker",
    idempotencyKey: "approve-retry"
  } as const;
  authority.cell = pointInTimeCellFixture();
  const certified = service.approveCandidate(approval);
  authority.cell = pointInTimeCellFixture({
    resultArtifactId: authority.cell.source.resultArtifactId,
    cellId: authority.cell.source.cellId,
    populationHash: canonicalHash("new current population")
  });
  assert.deepEqual(service.approveCandidate(approval), certified);
  assert.equal(store.listAuditEvents(TENANT_ID).length, 2);
  store.close();
});

test("verifier rejects a tampered certified record even behind a compromised lookup port", () => {
  const created = createMetricRunV1(contractInput());
  const certified = certifyMetricRunV1(created, { approvedBy: "checker", approvedAt: APPROVED_AT });
  const tampered = {
    ...certified,
    observation: {
      ...certified.observation,
      measurement: { type: "decimal", value: "999", unit: "currency" }
    }
  } as MetricRunV1;
  const authority = new MutableAuthority();
  const service = new MetricRunEvidenceService({
    metricRuns: {
      create: () => {
        throw new Error("not used");
      },
      approve: () => tampered,
      get: () => tampered,
      getCertified: () => tampered,
      findCertifiedByObservation: () => tampered
    },
    authority
  });
  assert.throws(
    () => service.getCertified(TENANT_ID, certified.runId),
    (error: unknown) => error instanceof ContractValidationError
  );
});

test("service rejects tenant, run, lookup-key, create-return, and approval-return substitution", () => {
  const localCreated = createMetricRunV1(contractInput());
  const localCertified = certifyMetricRunV1(localCreated, {
    approvedBy: "checker",
    approvedAt: APPROVED_AT
  });
  const foreignCreated = createMetricRunV1({
    ...contractInput(),
    tenantId: "tenant-b",
    runId: "foreign-run"
  });
  const foreignCertified = certifyMetricRunV1(foreignCreated, {
    approvedBy: "foreign-checker",
    approvedAt: APPROVED_AT
  });
  const wrongRunCreated = createMetricRunV1({ ...contractInput(), runId: "wrong-run" });
  const wrongRunCertified = certifyMetricRunV1(wrongRunCreated, {
    approvedBy: "checker",
    approvedAt: APPROVED_AT
  });
  const authority = new MutableAuthority();

  for (const substituted of [foreignCertified, wrongRunCertified]) {
    const readService = new MetricRunEvidenceService({
      metricRuns: {
        create: () => localCreated,
        approve: () => localCertified,
        get: () => substituted,
        getCertified: () => substituted,
        findCertifiedByObservation: () => substituted
      },
      authority
    });
    assert.throws(
      () => readService.getCertified(TENANT_ID, localCertified.runId),
      (error: unknown) => evidenceError(error, "AUTHORITY_MISMATCH")
    );
    assert.throws(
      () =>
        readService.verifyObservation({
          tenantId: TENANT_ID,
          runId: localCertified.runId,
          metricId: localCertified.metricId,
          asOfDate: localCertified.observation.asOfDate,
          scope: localCertified.observation.scope,
          measurement: localCertified.observation.measurement
        }),
      (error: unknown) => evidenceError(error, "AUTHORITY_MISMATCH")
    );
  }

  const lookupService = new MetricRunEvidenceService({
    metricRuns: {
      create: () => localCreated,
      approve: () => localCertified,
      get: () => localCertified,
      getCertified: () => localCertified,
      findCertifiedByObservation: () => localCertified
    },
    authority
  });
  assert.throws(
    () =>
      lookupService.lookupCertified({
        tenantId: TENANT_ID,
        metricId: "another_metric",
        asOfDate: localCertified.observation.asOfDate,
        scope: localCertified.observation.scope,
        sourceHash: localCertified.source.sourceHash
      }),
    (error: unknown) => evidenceError(error, "AUTHORITY_MISMATCH")
  );

  const createReturnService = new MetricRunEvidenceService({
    metricRuns: {
      create: () => foreignCreated,
      approve: () => foreignCertified,
      get: () => undefined,
      getCertified: () => undefined,
      findCertifiedByObservation: () => undefined
    },
    authority
  });
  assert.throws(
    () => createReturnService.createCandidate(serviceRequest()),
    (error: unknown) => evidenceError(error, "AUTHORITY_MISMATCH")
  );

  const approveReturnService = new MetricRunEvidenceService({
    metricRuns: {
      create: () => localCreated,
      approve: () => foreignCertified,
      get: () => localCreated,
      getCertified: () => undefined,
      findCertifiedByObservation: () => undefined
    },
    authority
  });
  assert.throws(
    () =>
      approveReturnService.approveCandidate({
        tenantId: TENANT_ID,
        runId: localCreated.runId,
        expectedRunHash: localCreated.runHash,
        approvedBy: "checker",
        idempotencyKey: "compromised-approval-return"
      }),
    (error: unknown) => evidenceError(error, "AUTHORITY_MISMATCH")
  );
});

function projectionInput() {
  return {
    contractVersion: 1 as const,
    definitionType: "metric_projection" as const,
    definitionId: "projection-excess-availability",
    version: "1.2.3+build.7",
    metricDefinitionId: "metric-definition-excess-availability",
    metricName: "excess_availability",
    exactDimensionSelectors: { status: "active" },
    observationDateDimension: "as_of_date",
    scope: { type: "facility" as const, idSource: "fixed" as const, fixedId: "facility-1" },
    measurement: { source: "value" as const, type: "decimal" as const, unit: "currency" as const },
    requireAvailable: true as const,
    requireUnsuppressed: true as const,
    approval: {
      status: "pending_durable_approval" as const,
      authority: "governed_definition_v2_lifecycle" as const
    }
  };
}

function projectionFixture() {
  return createMetricProjectionV1(projectionInput());
}

function projectionReferenceFixture() {
  return metricProjectionReferenceV1(projectionFixture(), projectionGovernanceFixture());
}

function projectionGovernanceFixture() {
  return {
    definitionVersionId: "projection-excess-availability-v1",
    documentHash: canonicalHash(projectionFixture()),
    versionHash: canonicalHash("projection governed version 1"),
    approvalEventHash: canonicalHash("projection approval event 1"),
    approvedAt: "2026-08-12T09:00:00.000Z"
  };
}

function metricDefinitionFixture(): MetricDefinitionReferenceV1 {
  return {
    definitionKind: "metric_definition",
    definitionVersionId: "metric-definition-excess-availability-v3",
    definitionId: "metric-definition-excess-availability",
    version: "3.4.5+build.9",
    definitionHash: canonicalHash("metric definition v3"),
    documentHash: canonicalHash("metric governed document v3"),
    versionHash: canonicalHash("metric governed version 3"),
    approvalEventHash: canonicalHash("metric approval event 3"),
    approvedAt: "2026-08-12T09:05:00.000Z"
  };
}

function methodologyFixture(): MetricRunMethodologyReferenceV1 {
  return {
    definitionKind: "methodology_bundle",
    definitionVersionId: "methodology-availability-v2",
    definitionId: "methodology-availability",
    version: "2.1.0+methodology.4",
    definitionHash: canonicalHash("availability methodology v2"),
    documentHash: canonicalHash("methodology governed document 2"),
    versionHash: canonicalHash("methodology governed version 2"),
    approvalEventHash: canonicalHash("methodology approval event 2"),
    approvedAt: "2026-08-12T09:10:00.000Z"
  };
}

type ObservationInput = FrozenMetricResultCellV1["observation"];

function observationFixture(overrides: Partial<ObservationInput> = {}): ObservationInput {
  return {
    asOfDate: AS_OF_DATE,
    scope: { type: "facility", id: "facility-1" },
    measurement: { type: "decimal", value: "10.25", unit: "currency" },
    numerator: { value: "10.25", unit: "currency" },
    denominator: { value: "1000", unit: "currency" },
    coverage: { includedCount: 98, eligibleCount: 100 },
    ...overrides
  };
}

interface PointInTimeCellOptions {
  readonly tenantId?: string;
  readonly projection?: FrozenMetricResultCellV1["projection"];
  readonly metricId?: string;
  readonly metricDefinition?: MetricDefinitionReferenceV1;
  readonly methodology?: MetricRunMethodologyReferenceV1;
  readonly observation?: ObservationInput;
  readonly resultRecordedAt?: string;
  readonly resultArtifactId?: string;
  readonly resultArtifactHash?: Sha256Hash;
  readonly resultManifestId?: string;
  readonly resultManifestHash?: Sha256Hash;
  readonly cellId?: string;
  readonly populationHash?: Sha256Hash;
  readonly populationRowCount?: number;
  readonly snapshotId?: string;
  readonly snapshotAsOfDate?: string;
  readonly snapshotCertificationManifestId?: string;
  readonly snapshotCertificationHash?: Sha256Hash;
  readonly snapshotCertifiedAt?: string;
  readonly inputArtifactId?: string;
  readonly inputArtifactHash?: Sha256Hash;
}

function pointInTimeCellFixture(options: PointInTimeCellOptions = {}): FrozenMetricResultCellV1 {
  const projection = options.projection ?? projectionReferenceFixture();
  const metricId = options.metricId ?? "excess_availability";
  const metricDefinition = options.metricDefinition ?? metricDefinitionFixture();
  const methodology = options.methodology ?? methodologyFixture();
  const observation = options.observation ?? observationFixture();
  const source = pointInTimeSourceFixture({
    ...options,
    projection,
    metricId,
    metricDefinition,
    methodology,
    observation
  });
  return {
    tenantId: options.tenantId ?? TENANT_ID,
    projection,
    metricId,
    metricDefinition,
    methodology,
    source,
    observation
  };
}

function pointInTimeSourceFixture(
  options: PointInTimeCellOptions & {
    readonly projection?: FrozenMetricResultCellV1["projection"];
    readonly metricDefinition?: MetricDefinitionReferenceV1;
    readonly methodology?: MetricRunMethodologyReferenceV1;
    readonly observation?: ObservationInput;
  } = {}
): MetricRunSourceV1 {
  const projection = options.projection ?? projectionReferenceFixture();
  const metricId = options.metricId ?? "excess_availability";
  const metricDefinition = options.metricDefinition ?? metricDefinitionFixture();
  const methodology = options.methodology ?? methodologyFixture();
  const observation = options.observation ?? observationFixture();
  const common = {
    certificationStatus: "certified" as const,
    resultRecordedAt: options.resultRecordedAt ?? RESULT_RECORDED_AT,
    resultArtifactId: options.resultArtifactId ?? "surveillance-result-1",
    resultArtifactHash: options.resultArtifactHash ?? canonicalHash("surveillance result 1"),
    resultManifestId: options.resultManifestId ?? "surveillance-manifest-1",
    resultManifestHash: options.resultManifestHash ?? canonicalHash("surveillance manifest 1"),
    cellId: options.cellId ?? "metric-cell-1",
    populationHash: options.populationHash ?? canonicalHash("certified population 1"),
    populationRowCount: options.populationRowCount ?? 100
  };
  const cellHash = metricRunCellHashV1({
    metricId,
    projection,
    metricDefinition,
    methodology,
    resultArtifactId: common.resultArtifactId,
    resultArtifactHash: common.resultArtifactHash,
    resultManifestId: common.resultManifestId,
    resultManifestHash: common.resultManifestHash,
    cellId: common.cellId,
    populationHash: common.populationHash,
    observation
  });
  const body = {
    ...common,
    cellHash,
    sourceType: "point_in_time" as const,
    snapshotId: options.snapshotId ?? "snapshot-2026-08-11",
    snapshotAsOfDate: options.snapshotAsOfDate ?? observation.asOfDate,
    snapshotCertificationManifestId:
      options.snapshotCertificationManifestId ?? "snapshot-certification-1",
    snapshotCertificationHash:
      options.snapshotCertificationHash ?? canonicalHash("snapshot certification 1"),
    snapshotCertifiedAt: options.snapshotCertifiedAt ?? SNAPSHOT_CERTIFIED_AT,
    inputArtifactId: options.inputArtifactId ?? "normalized-snapshot-1",
    inputArtifactHash: options.inputArtifactHash ?? canonicalHash("normalized snapshot 1"),
    inputArtifactKind: "normalized_snapshot"
  };
  return { ...body, sourceHash: canonicalHash(body) };
}

function longitudinalSourceFixture(options: {
  readonly observation?: ObservationInput;
  readonly bundleCreatedAt?: string;
} = {}): MetricRunSourceV1 {
  const projection = projectionReferenceFixture();
  const metricId = "excess_availability";
  const metricDefinition = metricDefinitionFixture();
  const methodology = methodologyFixture();
  const observation = options.observation ?? observationFixture();
  const common = {
    certificationStatus: "certified" as const,
    resultRecordedAt: RESULT_RECORDED_AT,
    resultArtifactId: "surveillance-result-longitudinal-1",
    resultArtifactHash: canonicalHash("surveillance longitudinal result 1"),
    resultManifestId: "surveillance-manifest-longitudinal-1",
    resultManifestHash: canonicalHash("surveillance longitudinal manifest 1"),
    cellId: "metric-cell-longitudinal-1",
    populationHash: canonicalHash("longitudinal certified population 1"),
    populationRowCount: 300
  };
  const cellHash = metricRunCellHashV1({
    metricId,
    projection,
    metricDefinition,
    methodology,
    resultArtifactId: common.resultArtifactId,
    resultArtifactHash: common.resultArtifactHash,
    resultManifestId: common.resultManifestId,
    resultManifestHash: common.resultManifestHash,
    cellId: common.cellId,
    populationHash: common.populationHash,
    observation
  });
  const body = {
    ...common,
    cellHash,
    sourceType: "longitudinal" as const,
    longitudinalBundleId: "longitudinal-bundle-1",
    longitudinalBundleHash: canonicalHash("longitudinal bundle 1"),
    bundleCreatedAt: options.bundleCreatedAt ?? SNAPSHOT_CERTIFIED_AT,
    firstAsOfDate: "2026-06-30",
    lastAsOfDate: AS_OF_DATE,
    periodCount: 3
  };
  return { ...body, sourceHash: canonicalHash(body) };
}

function contractInput() {
  const cell = pointInTimeCellFixture();
  return {
    contractVersion: 1 as const,
    runId: "metric-run-1",
    tenantId: TENANT_ID,
    metricId: cell.metricId,
    projection: cell.projection,
    metricDefinition: cell.metricDefinition,
    methodology: cell.methodology,
    source: cell.source,
    observation: cell.observation,
    createdBy: "maker",
    createdAt: CREATED_AT
  };
}

function storeInput(): CreateMetricRunInput {
  const { createdAt: _createdAt, ...input } = contractInput();
  return { ...input, idempotencyKey: "create-run" };
}

function storeInputFromCell(
  cell: FrozenMetricResultCellV1,
  ids: { readonly runId: string; readonly idempotencyKey: string }
): CreateMetricRunInput {
  return {
    contractVersion: 1,
    tenantId: TENANT_ID,
    runId: ids.runId,
    metricId: cell.metricId,
    projection: cell.projection,
    metricDefinition: cell.metricDefinition,
    methodology: cell.methodology,
    source: cell.source,
    observation: cell.observation,
    createdBy: "maker",
    idempotencyKey: ids.idempotencyKey
  };
}

function serviceRequest(): CreateMetricRunCandidateRequestV1 {
  const cell = pointInTimeCellFixture();
  return {
    tenantId: TENANT_ID,
    runId: "metric-run-1",
    projectionDefinitionId: cell.projection.definitionId,
    surveillanceResultArtifactId: cell.source.resultArtifactId,
    cellId: cell.source.cellId,
    createdBy: "maker",
    idempotencyKey: "create-service-run"
  };
}

class MutableAuthority implements MetricRunAuthorityResolver {
  cell: FrozenMetricResultCellV1 = pointInTimeCellFixture();

  resolveFrozenResultCell(input: {
    readonly tenantId: string;
    readonly projectionDefinitionId: string;
    readonly surveillanceResultArtifactId: string;
    readonly cellId: string;
  }): FrozenMetricResultCellV1 | undefined {
    return input.tenantId === TENANT_ID &&
      input.projectionDefinitionId === this.cell.projection.definitionId &&
      input.surveillanceResultArtifactId === this.cell.source.resultArtifactId &&
      input.cellId === this.cell.source.cellId
      ? this.cell
      : undefined;
  }
}

function temporaryDatabasePath(name: string): string {
  const directory = mkdtempSync(join(tmpdir(), "abl-metric-runs-"));
  temporaryDirectories.push(directory);
  return join(directory, name);
}

function sequentialClock(...timestamps: readonly string[]): () => Date {
  let index = 0;
  return () => {
    const timestamp = timestamps[Math.min(index, timestamps.length - 1)]!;
    index += 1;
    return new Date(timestamp);
  };
}

function without<T extends object>(value: T, keys: readonly string[]): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([key]) => !keys.includes(key)));
}

function contractError(error: unknown, code: ContractValidationError["code"]): boolean {
  return error instanceof ContractValidationError && error.code === code;
}

function storeError(error: unknown, code: MetricRunStoreError["code"]): boolean {
  return error instanceof MetricRunStoreError && error.code === code;
}

function evidenceError(error: unknown, code: MetricRunEvidenceError["code"]): boolean {
  return error instanceof MetricRunEvidenceError && error.code === code;
}

function tableExists(database: DatabaseSync, table: string): boolean {
  return database.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(table) !== undefined;
}
