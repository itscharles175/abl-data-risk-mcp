import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import {
  createAnalysisInputLineageV1,
  createCertifiedInputPopulationV1
} from "../src/contracts/certified-lineage-v1.js";
import {
  createCertifiedOperationInputV1,
  parseCertifiedOperationInputV1,
  type CertifiedOperationInputV1
} from "../src/contracts/certified-operation-input-v1.js";
import { canonicalHash } from "../src/contracts/canonical.js";
import { MonitoringAlertStore } from "../src/control/alerts.js";
import { ArtifactStore, type StoredArtifact } from "../src/control/artifacts.js";
import { DefinitionStore, type DefinitionKind } from "../src/control/definitions.js";
import {
  InputCertificationStore,
  InputCertificationStoreError,
  type InputCertificationProposalV1,
  type InputCertificationRecordV1
} from "../src/control/input-certifications.js";
import { JobStore } from "../src/control/jobs.js";
import { ControlStore, type JsonValue } from "../src/control/store.js";
import type { DataQualityProfile } from "../src/domain/data-quality.js";
import {
  executeGovernedAnalysis,
  GovernedWorkflow,
  GovernedWorkflowError,
  type GovernedAnalysisExecutionPayload
} from "../src/services/governed-workflow.js";
import { SnapshotIngestionService } from "../src/services/ingestion.js";
import { InputCertificationService } from "../src/services/input-certification.js";
import {
  createVerifiedPrincipalContext,
  principalBinding,
  type VerifiedPrincipalContext
} from "../src/security/identity.js";
import { compileAuthorizationPolicy } from "../src/security/policy.js";
import { createHmacKeyRing } from "../src/security/signed-plan.js";
import { SecurityStateStore } from "../src/security/state-store.js";

const TENANT_ID = "tenant-a";
const SNAPSHOT_ID = "snapshot-2026-07";
const CERTIFICATION_MANIFEST_ID = "certification-2026-07";
const AS_OF_DATE = "2026-07-31";
const PURPOSE = "portfolio-risk-review";
const NOW = Math.floor(Date.parse("2026-08-12T12:00:00.000Z") / 1_000);

const temporaryDirectories: string[] = [];
const closeAfterTest: Array<() => void> = [];

afterEach(() => {
  for (const close of closeAfterTest.splice(0).reverse()) close();
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

const qualityProfile: DataQualityProfile = {
  id: "loan-certification",
  version: "1.0.0",
  entity: "loan_snapshot",
  keyFields: ["loan_id", "as_of_date"],
  requiredFields: ["loan_id", "as_of_date", "outstanding_balance", "currency_code"],
  balanceField: "outstanding_balance",
  asOfField: "as_of_date",
  expectedAsOfDate: AS_OF_DATE,
  currencyField: "currency_code",
  expectedCurrency: "USD",
  exactDecimalFields: [
    "outstanding_balance",
    "interest_rate",
    "original_balance",
    "charge_off_amount",
    "recovery_amount"
  ]
};

const canonicalRecords: readonly Readonly<Record<string, unknown>>[] = [
  {
    as_of_date: AS_OF_DATE,
    loan_id: "RESTRICTED-LOAN-1",
    risk_rating: "A",
    outstanding_balance: "100",
    interest_rate: "5",
    origination_date: "2025-01-15",
    original_balance: "120",
    charge_off_amount: "0",
    recovery_amount: "0",
    days_past_due: "0",
    currency_code: "USD"
  }
];

const mappings = Object.keys(canonicalRecords[0]!).map((field) => ({
  sourceColumn: field,
  canonicalField: field
}));

const borrowingBasePayload = {
  snapshotId: SNAPSHOT_ID,
  asOfDate: AS_OF_DATE,
  receivables: [
    {
      receivableId: "RESTRICTED-RECEIVABLE-1",
      debtorId: "RESTRICTED-DEBTOR-1",
      outstandingAmount: "150",
      daysPastDue: 0,
      flags: []
    }
  ],
  usage: [{ usageId: "usage-1", kind: "revolver", amount: "20" }]
} satisfies JsonValue;

const monitoringPayload = {
  snapshotId: SNAPSHOT_ID,
  asOfDate: AS_OF_DATE,
  scope: { type: "facility", id: "facility-1" },
  observations: [
    {
      observationId: "observation-1",
      metricId: "excess_availability",
      snapshotId: SNAPSHOT_ID,
      asOfDate: AS_OF_DATE,
      type: "decimal",
      value: "-1",
      unit: "currency",
      evidence: []
    }
  ]
} satisfies JsonValue;

function principal(): VerifiedPrincipalContext {
  return createVerifiedPrincipalContext({
    issuer: "https://identity.example.test",
    subject: "risk-analyst",
    principalId: "risk-analyst",
    tenantId: TENANT_ID,
    clientId: "codex-client",
    audiences: ["abl-api"],
    resourceIndicators: ["https://mcp.example.test/mcp"],
    scopes: ["analysis:run", "data:read"],
    credentialFingerprint: "a".repeat(64),
    verifiedAtEpochSeconds: NOW - 60,
    expiresAtEpochSeconds: NOW + 3_600,
    authenticationMethods: ["mfa"]
  });
}

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "abl-governed-sidecar-"));
  temporaryDirectories.push(directory);
  const databasePath = join(directory, "control.sqlite");
  let now = new Date(NOW * 1_000);
  const clock = () => now;
  const control = new ControlStore(databasePath, { clock });
  const definitions = new DefinitionStore(join(directory, "definitions.sqlite"), { clock });
  const artifacts = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "artifact-key",
    keys: { "artifact-key": Buffer.alloc(32, 7) }
  });
  const jobs = new JobStore(join(directory, "jobs.sqlite"), { clock });
  const monitoringAlerts = new MonitoringAlertStore(join(directory, "monitoring.sqlite"), { clock });
  const inputCertifications = new InputCertificationStore(databasePath, { clock });
  const securityState = new SecurityStateStore(join(directory, "security.sqlite"), { clock });
  closeAfterTest.push(
    () => control.close(),
    () => definitions.close(),
    () => jobs.close(),
    () => monitoringAlerts.close(),
    () => inputCertifications.close(),
    () => securityState.close()
  );

  certifySnapshot(control, artifacts);
  activateDefinition(definitions, {
    definitionId: "borrowing-base-v1",
    definitionKey: "facility-1-ar",
    kind: "borrowing_base_policy",
    document: {
      policyId: "facility-1-ar",
      version: "1",
      effectiveFrom: "2026-01-01",
      currencyCode: "USD",
      eligibilityRules: [],
      advanceRate: "0.8",
      reserves: [],
      commitmentAmount: "1000"
    }
  });
  activateDefinition(definitions, {
    definitionId: "monitor-v1",
    definitionKey: "negative-availability",
    kind: "monitor_definition",
    document: {
      monitorId: "negative-availability",
      version: "1",
      effectiveFrom: "2026-01-01",
      metricId: "excess_availability",
      title: "Negative availability",
      message: "Availability is below zero",
      severity: "critical",
      threshold: { type: "decimal", operator: "lt", value: "0", unit: "currency" }
    }
  });

  const borrowingBaseCandidate = artifacts.putJson({
    tenantId: TENANT_ID,
    kind: "borrowing_base_input",
    mediaType: "application/json",
    value: borrowingBasePayload
  });
  const primaryManifest = control.getAnalysisManifest(TENANT_ID, CERTIFICATION_MANIFEST_ID);
  const normalizedArtifactId = primaryManifest?.artifacts.find(
    (artifact) => artifact.kind === "normalized_snapshot"
  )?.artifactId;
  assert.ok(normalizedArtifactId);
  const monitoringCandidate = artifacts.putJson({
    tenantId: TENANT_ID,
    kind: "monitoring_input",
    mediaType: "application/json",
    value: {
      ...monitoringPayload,
      observations: monitoringPayload.observations.map((observation) => ({
        ...observation,
        evidence: [{ kind: "source_artifact", id: normalizedArtifactId }]
      }))
    }
  });
  const policy = compileAuthorizationPolicy({
    id: "workflow-policy",
    version: "1",
    defaultObligations: {
      maxResultRows: 1_000,
      maxResultBytes: 2_000_000,
      maxExecutionMs: 10_000,
      minimumCohortSize: 1,
      requireImmutableSnapshot: true,
      allowRawRows: false,
      allowExport: false,
      rowFilterRefs: ["tenant-boundary"],
      fieldMasks: {},
      auditTags: ["governed-analysis"]
    },
    rules: [
      {
        id: "permit-governed-analysis",
        effect: "permit",
        tenantIds: [TENANT_ID],
        tools: ["*"],
        datasets: ["*"],
        fields: ["*"],
        requiredScopes: ["analysis:run", "data:read"]
      }
    ]
  });
  const keyRing = createHmacKeyRing(
    [{ id: "signing-key", secret: new Uint8Array(32).fill(11) }],
    "signing-key"
  );
  const tenantMembershipResolver = {
    async resolveTenantMembership(lookup: {
      readonly issuer: string;
      readonly subject: string;
      readonly clientId: string;
      readonly resourceIndicators: readonly string[];
    }) {
      if (
        lookup.issuer !== "https://identity.example.test" ||
        lookup.clientId !== "codex-client" ||
        lookup.resourceIndicators[0] !== "https://mcp.example.test/mcp"
      ) {
        return null;
      }
      return { tenantId: TENANT_ID, principalId: lookup.subject };
    }
  };

  function workflowFor(store: InputCertificationStore): GovernedWorkflow {
    return new GovernedWorkflow(
      {
        control,
        definitions,
        artifacts,
        jobs,
        monitoringAlerts,
        inputCertifications: store,
        securityState,
        tenantMembershipResolver,
        policy,
        keyRing
      },
      { codeVersion: "test-1", clock, defaultHandleTtlSeconds: 60 }
    );
  }

  const certificationService = new InputCertificationService(
    { control, definitions, artifacts, inputCertifications },
    clock
  );

  return {
    databasePath,
    clock,
    control,
    definitions,
    artifacts,
    jobs,
    monitoringAlerts,
    inputCertifications,
    certificationService,
    borrowingBaseCandidate,
    monitoringCandidate,
    workflow: workflowFor(inputCertifications),
    workflowFor,
    advance(seconds: number) {
      now = new Date(now.getTime() + seconds * 1_000);
    },
    trackInputCertificationStore(store: InputCertificationStore) {
      closeAfterTest.push(() => store.close());
      return store;
    }
  };
}

test("legacy raw borrowing-base and monitoring artifacts are rejected before enqueue", () => {
  const environment = fixture();
  const identity = principal();
  const cases = [
    {
      operation: "ar_borrowing_base" as const,
      definitionIds: ["borrowing-base-v1"],
      inputArtifactId: environment.borrowingBaseCandidate.artifactId
    },
    {
      operation: "monitoring" as const,
      definitionIds: ["monitor-v1"],
      inputArtifactId: environment.monitoringCandidate.artifactId
    }
  ];

  for (const [index, item] of cases.entries()) {
    assert.throws(
      () =>
        environment.workflow.start(identity, {
          ...item,
          certificationManifestId: CERTIFICATION_MANIFEST_ID,
          purpose: PURPOSE,
          idempotencyKey: `legacy-raw-${index}`
        }),
      invalidWorkflowInput
    );
  }

  assert.deepEqual(environment.jobs.list(TENANT_ID, principalBinding(identity)), []);
  assert.deepEqual(environment.monitoringAlerts.listAlerts(TENANT_ID), []);
});

test("different makers and checkers certify borrowing-base and monitoring inputs end to end", async () => {
  const environment = fixture();
  const identity = principal();
  const borrowingBase = certifyOperationInput(environment, "borrowing_base");
  const monitoring = certifyOperationInput(environment, "monitoring");

  for (const certified of [borrowingBase, monitoring]) {
    assert.equal(certified.proposal.proposedBy, "sidecar-maker");
    assert.equal(certified.record.certifiedBy, "sidecar-checker");
    assert.notEqual(certified.record.proposedBy, certified.record.certifiedBy);
    assert.equal(certified.record.status, "certified");
    assert.equal(certified.record.envelopeHash, certified.envelope.envelopeHash);
  }

  const borrowingBaseJob = environment.workflow.start(identity, {
    operation: "ar_borrowing_base",
    certificationManifestId: CERTIFICATION_MANIFEST_ID,
    definitionIds: ["borrowing-base-v1"],
    inputArtifactId: borrowingBase.record.certifiedArtifactId,
    purpose: PURPOSE,
    idempotencyKey: "certified-borrowing-base"
  });
  assert.deepEqual(await environment.workflow.processNext(TENANT_ID, "worker-bb"), {
    operation: "ar_borrowing_base",
    status: "succeeded",
    errorCode: null
  });
  const borrowingBaseResult = await environment.workflow.getJobResult(identity, borrowingBaseJob.jobHandle);
  const borrowingBaseValue = borrowingBaseResult.result as {
    receivables: readonly unknown[];
    totals: { grossReceivables: string; excessAvailability: string };
  };
  assert.deepEqual(borrowingBaseValue.receivables, []);
  assert.equal(borrowingBaseValue.totals.grossReceivables, "150");
  assert.equal(borrowingBaseValue.totals.excessAvailability, "100");
  assert.equal(JSON.stringify(borrowingBaseValue).includes("RESTRICTED-"), false);
  assertCertifiedResultLineage(environment, borrowingBaseResult.artifactId, borrowingBase.record);

  const monitoringJob = environment.workflow.start(identity, {
    operation: "monitoring",
    certificationManifestId: CERTIFICATION_MANIFEST_ID,
    definitionIds: ["monitor-v1"],
    inputArtifactId: monitoring.record.certifiedArtifactId,
    purpose: PURPOSE,
    idempotencyKey: "certified-monitoring"
  });
  assert.deepEqual(await environment.workflow.processNext(TENANT_ID, "worker-monitor"), {
    operation: "monitoring",
    status: "succeeded",
    errorCode: null
  });
  const monitoringResult = await environment.workflow.getJobResult(identity, monitoringJob.jobHandle);
  const monitoringValue = monitoringResult.result as {
    status: string;
    alerts: readonly { severity: string }[];
  };
  assert.equal(monitoringValue.status, "evaluated");
  assert.equal(monitoringValue.alerts.length, 1);
  assert.equal(monitoringValue.alerts[0]?.severity, "critical");
  assert.equal(environment.monitoringAlerts.listAlerts(TENANT_ID).length, 1);
  assertCertifiedResultLineage(environment, monitoringResult.artifactId, monitoring.record);
});

test("a certified sidecar cannot be reused for another governed purpose", () => {
  const environment = fixture();
  const certified = certifyOperationInput(environment, "borrowing_base");

  assert.throws(
    () =>
      environment.workflow.start(principal(), {
        operation: "ar_borrowing_base",
        certificationManifestId: CERTIFICATION_MANIFEST_ID,
        definitionIds: ["borrowing-base-v1"],
        inputArtifactId: certified.record.certifiedArtifactId,
        purpose: "unapproved-ad-hoc-purpose",
        idempotencyKey: "purpose-mismatch"
      }),
    certificationRequiredWorkflow
  );
  assert.equal(environment.jobs.list(TENANT_ID, principalBinding(principal())).length, 0);
});

test("tampered envelopes and self-hashed evidence without an authoritative record are rejected", () => {
  const environment = fixture();
  const certified = certifyOperationInput(environment, "borrowing_base");
  const payload = certified.envelope.payload as Readonly<Record<string, JsonValue>>;
  const tamperedArtifact = environment.artifacts.putJson({
    tenantId: TENANT_ID,
    kind: "certified_borrowing_base_input",
    mediaType: "application/json",
    value: {
      ...certified.envelope,
      payload: { ...payload, receivables: [] }
    }
  });

  const originalSidecar = certified.envelope.lineage.sidecars[0]!;
  const fakeSidecar = createCertifiedInputPopulationV1({
    contractVersion: 1,
    tenantId: originalSidecar.tenantId,
    populationId: "fake-self-certified-input",
    populationKind: "certified_sidecar",
    purpose: originalSidecar.purpose,
    snapshot: originalSidecar.snapshot,
    mappingApplication: originalSidecar.mappingApplication,
    populationHash: originalSidecar.populationHash,
    fieldSetHash: originalSidecar.fieldSetHash,
    rowCount: originalSidecar.rowCount,
    dataQuality: originalSidecar.dataQuality,
    reconciliation: originalSidecar.reconciliation,
    certificationStatus: "certified",
    certifiedBy: "fake-checker",
    certifiedAt: originalSidecar.certifiedAt
  });
  const fakeLineage = createAnalysisInputLineageV1({
    contractVersion: 1,
    tenantId: TENANT_ID,
    analysisKind: "borrowing_base",
    primary: certified.envelope.lineage.primary,
    sidecars: [fakeSidecar],
    definitions: certified.envelope.lineage.definitions,
    derivationHash: canonicalHash("fake-self-certified-derivation"),
    assembledAt: certified.envelope.lineage.assembledAt
  });
  const fakeEnvelope = createCertifiedOperationInputV1({
    contractVersion: 1,
    inputKind: "borrowing_base",
    payload: certified.envelope.payload,
    payloadHash: certified.envelope.payloadHash,
    lineage: fakeLineage
  });
  const fakeArtifact = environment.artifacts.putJson({
    tenantId: TENANT_ID,
    kind: "certified_borrowing_base_input",
    mediaType: "application/json",
    value: fakeEnvelope
  });

  for (const [index, inputArtifactId] of [
    tamperedArtifact.artifactId,
    fakeArtifact.artifactId
  ].entries()) {
    assert.throws(
      () =>
        environment.workflow.start(principal(), {
          operation: "ar_borrowing_base",
          certificationManifestId: CERTIFICATION_MANIFEST_ID,
          definitionIds: ["borrowing-base-v1"],
          inputArtifactId,
          purpose: PURPOSE,
          idempotencyKey: `forged-sidecar-${index}`
        }),
      certificationRequiredWorkflow
    );
  }
  assert.equal(environment.jobs.list(TENANT_ID, principalBinding(principal())).length, 0);
});

test("a queued certified monitor reloads its durable certification before execution", async () => {
  const environment = fixture();
  const certified = certifyOperationInput(environment, "monitoring");
  const identity = principal();
  const started = environment.workflow.start(identity, {
    operation: "monitoring",
    certificationManifestId: CERTIFICATION_MANIFEST_ID,
    definitionIds: ["monitor-v1"],
    inputArtifactId: certified.record.certifiedArtifactId,
    purpose: PURPOSE,
    idempotencyKey: "durable-sidecar-reload"
  });

  const reopenedStore = environment.trackInputCertificationStore(
    new InputCertificationStore(environment.databasePath, { clock: environment.clock })
  );
  assert.deepEqual(reopenedStore.get(TENANT_ID, certified.record.inputId), certified.record);
  const restartedWorkflow = environment.workflowFor(reopenedStore);
  assert.deepEqual(await restartedWorkflow.processNext(TENANT_ID, "restarted-worker"), {
    operation: "monitoring",
    status: "succeeded",
    errorCode: null
  });
  assert.equal((await restartedWorkflow.getJobStatus(identity, started.jobHandle)).status, "succeeded");
  assert.equal(environment.monitoringAlerts.listAlerts(TENANT_ID).length, 1);
});

test("monitor alert evidence names the certified sidecar reconciliation and certification time", async () => {
  const environment = fixture();
  const certified = certifyOperationInput(environment, "monitoring");
  environment.workflow.start(principal(), {
    operation: "monitoring",
    certificationManifestId: CERTIFICATION_MANIFEST_ID,
    definitionIds: ["monitor-v1"],
    inputArtifactId: certified.record.certifiedArtifactId,
    purpose: PURPOSE,
    idempotencyKey: "monitor-alert-sidecar-evidence"
  });
  assert.equal((await environment.workflow.processNext(TENANT_ID, "worker-alert-evidence"))?.status, "succeeded");
  const alert = environment.monitoringAlerts.listAlerts(TENANT_ID)[0];
  assert.ok(alert);
  const occurrence = environment.monitoringAlerts.listOccurrences(TENANT_ID, alert.alertId)[0];
  assert.ok(occurrence);
  assert.equal(occurrence.evidence.certifiedAt, certified.record.certifiedAt);
  assert.ok(
    occurrence.evidence.references.some(
      (reference) =>
        reference.kind === "reconciliation" &&
        reference.id === certified.record.reconciliationId
    )
  );
  assert.equal(
    occurrence.evidence.references.some(
      (reference) =>
        reference.kind === "reconciliation" && reference.id === certified.record.inputId
    ),
    false
  );
});

test("worker-side certification rejection cannot emit a business-risk alert", async () => {
  const environment = fixture();
  const certified = certifyOperationInput(environment, "monitoring");
  const identity = principal();
  environment.workflow.start(identity, {
    operation: "monitoring",
    certificationManifestId: CERTIFICATION_MANIFEST_ID,
    definitionIds: ["monitor-v1"],
    inputArtifactId: certified.record.certifiedArtifactId,
    purpose: PURPOSE,
    idempotencyKey: "missing-evidence-after-enqueue"
  });

  Object.defineProperty(environment.inputCertifications, "get", {
    configurable: true,
    value: () => undefined
  });
  const processed = await environment.workflow.processNext(TENANT_ID, "worker-missing-evidence");
  assert.equal(processed?.operation, "monitoring");
  assert.equal(processed?.status, "failed");
  assert.equal(processed?.errorCode, "CERTIFICATION_REQUIRED");
  assert.deepEqual(environment.monitoringAlerts.listAlerts(TENANT_ID), []);
  const job = environment.jobs.list(TENANT_ID, principalBinding(identity))[0]!;
  assert.equal(environment.control.getAnalysisManifest(TENANT_ID, job.jobId), undefined);
});

test("completed results remain readable from frozen manifests after current input evidence is unavailable", async () => {
  const environment = fixture();
  const certified = certifyOperationInput(environment, "borrowing_base");
  const identity = principal();
  const started = environment.workflow.start(identity, {
    operation: "ar_borrowing_base",
    certificationManifestId: CERTIFICATION_MANIFEST_ID,
    definitionIds: ["borrowing-base-v1"],
    inputArtifactId: certified.record.certifiedArtifactId,
    purpose: PURPOSE,
    idempotencyKey: "archival-result-authority"
  });
  assert.equal(
    (await environment.workflow.processNext(TENANT_ID, "worker-archival-result"))?.status,
    "succeeded"
  );
  const first = await environment.workflow.getJobResult(identity, started.jobHandle);

  Object.defineProperty(environment.inputCertifications, "get", {
    configurable: true,
    value: () => undefined
  });
  const replay = await environment.workflow.getJobResult(identity, started.jobHandle);
  assert.deepEqual(replay, first);
  assertCertifiedResultLineage(environment, replay.artifactId, certified.record);
});

test("a durable sidecar result is adopted before mutable input evidence is reloaded", async () => {
  const environment = fixture();
  const certified = certifyOperationInput(environment, "borrowing_base");
  const identity = principal();
  const started = environment.workflow.start(identity, {
    operation: "ar_borrowing_base",
    certificationManifestId: CERTIFICATION_MANIFEST_ID,
    definitionIds: ["borrowing-base-v1"],
    inputArtifactId: certified.record.certifiedArtifactId,
    purpose: PURPOSE,
    idempotencyKey: "sidecar-manifest-recovery",
    handleTtlSeconds: 600
  });
  const originalComplete = environment.jobs.complete.bind(environment.jobs);
  Object.defineProperty(environment.jobs, "complete", {
    configurable: true,
    value: () => {
      throw new Error("simulated process loss after sidecar manifest persistence");
    }
  });
  await assert.rejects(
    () => environment.workflow.processNext(TENANT_ID, "worker-sidecar-crash"),
    /simulated process loss/
  );
  const crashed = environment.jobs.list(TENANT_ID, principalBinding(identity))[0]!;
  assert.equal(crashed.status, "running");
  const manifest = environment.control.getAnalysisManifest(TENANT_ID, crashed.jobId);
  assert.ok(manifest);
  const artifactId = manifest.artifacts[0]!.artifactId;

  Object.defineProperty(environment.jobs, "complete", {
    configurable: true,
    value: originalComplete
  });
  Object.defineProperty(environment.inputCertifications, "get", {
    configurable: true,
    value: () => undefined
  });
  environment.advance(301);
  assert.deepEqual(
    await environment.workflow.processNext(TENANT_ID, "worker-sidecar-recovery"),
    { operation: "ar_borrowing_base", status: "succeeded", errorCode: null }
  );
  const result = await environment.workflow.getJobResult(identity, started.jobHandle);
  assert.equal(result.artifactId, artifactId);
});

test("the direct worker boundary rejects structurally uncertified sidecar inputs", () => {
  const environment = fixture();
  const primary = environment.certificationService.loadPrimaryChain(
    TENANT_ID,
    CERTIFICATION_MANIFEST_ID
  );
  const certification = {
    ...primary,
    dataQualityFingerprint: canonicalHash("direct-worker-dq"),
    reconciliationFingerprint: canonicalHash("direct-worker-reconciliation")
  };
  const obligations: GovernedAnalysisExecutionPayload["obligations"] = {
    maxResultRows: 1_000,
    maxResultBytes: 2_000_000,
    maxExecutionMs: 10_000,
    minimumCohortSize: 1,
    requireImmutableSnapshot: true,
    allowRawRows: false,
    allowExport: false,
    rowFilterRefs: ["tenant-boundary"],
    fieldMasks: {},
    auditTags: ["governed-analysis"]
  };
  const cases = [
    {
      operation: "ar_borrowing_base" as const,
      definitionId: "borrowing-base-v1",
      candidate: environment.borrowingBaseCandidate,
      value: borrowingBasePayload
    },
    {
      operation: "monitoring" as const,
      definitionId: "monitor-v1",
      candidate: environment.monitoringCandidate,
      value: monitoringPayload
    }
  ];

  for (const item of cases) {
    const definition = environment.definitions.get(TENANT_ID, item.definitionId);
    assert.ok(definition);
    assert.throws(
      () =>
        executeGovernedAnalysis({
          operation: item.operation,
          certification,
          definitions: { definitions: [definition], recipeHash: "b".repeat(64) },
          inputArtifact: {
            reference: {
              artifactId: item.candidate.artifactId,
              contentHash: item.candidate.contentHash,
              kind: item.candidate.kind
            },
            value: item.value
          },
          obligations
        }),
      certificationRequiredWorkflow
    );
  }
  assert.deepEqual(environment.monitoringAlerts.listAlerts(TENANT_ID), []);
});

test("certification retries replay only the checker-scoped idempotency receipt", () => {
  const environment = fixture();
  const certified = certifyOperationInput(environment, "borrowing_base");

  const replay = environment.certificationService.certify({
    tenantId: TENANT_ID,
    inputId: certified.record.inputId,
    certifiedBy: "sidecar-checker",
    idempotencyKey: `certify-${certified.record.inputId}`
  });
  assert.deepEqual(replay, certified.record);

  assert.throws(
    () =>
      environment.certificationService.certify({
        tenantId: TENANT_ID,
        inputId: certified.record.inputId,
        certifiedBy: "sidecar-checker",
        idempotencyKey: "different-certification-attempt"
      }),
    (error: unknown) =>
      error instanceof InputCertificationStoreError && error.code === "ILLEGAL_TRANSITION"
  );
});

test("proposal retries replay locked evidence after the governed definition is retired", () => {
  const environment = fixture();
  const request = {
    tenantId: TENANT_ID,
    inputId: "proposal-replay-after-retirement",
    inputKind: "borrowing_base" as const,
    candidateArtifactId: environment.borrowingBaseCandidate.artifactId,
    primaryCertificationManifestId: CERTIFICATION_MANIFEST_ID,
    definitionIds: ["borrowing-base-v1"],
    purpose: PURPOSE,
    declaredControls: { rowCount: 2, balance: "150", currency: "USD" },
    proposedBy: "sidecar-maker",
    idempotencyKey: "proposal-replay-after-retirement"
  };
  const first = environment.certificationService.propose(request);
  environment.definitions.transition({
    tenantId: TENANT_ID,
    definitionId: "borrowing-base-v1",
    toStatus: "retired",
    actor: "checker-a",
    idempotencyKey: "retire-borrowing-base-after-proposal"
  });
  assert.deepEqual(environment.certificationService.propose(request), first);
  assert.throws(
    () => environment.certificationService.propose({ ...request, purpose: "changed-purpose" }),
    (error: unknown) =>
      error instanceof InputCertificationStoreError && error.code === "IDEMPOTENCY_CONFLICT"
  );
});

test("borrowing-base controls use the governed policy currency and exact decimal equality", () => {
  const environment = fixture();
  activateDefinition(environment.definitions, {
    definitionId: "borrowing-base-eur-v1",
    definitionKey: "facility-1-ar-eur",
    kind: "borrowing_base_policy",
    document: {
      policyId: "facility-1-ar-eur",
      version: "1",
      effectiveFrom: "2026-01-01",
      currencyCode: "EUR",
      eligibilityRules: [],
      advanceRate: "0.8",
      reserves: [],
      commitmentAmount: "1000"
    }
  });
  environment.certificationService.propose({
    tenantId: TENANT_ID,
    inputId: "certified-borrowing-base-eur",
    inputKind: "borrowing_base",
    candidateArtifactId: environment.borrowingBaseCandidate.artifactId,
    primaryCertificationManifestId: CERTIFICATION_MANIFEST_ID,
    definitionIds: ["borrowing-base-eur-v1"],
    purpose: PURPOSE,
    declaredControls: { rowCount: 2, balance: "150.00", currency: "EUR" },
    proposedBy: "sidecar-maker",
    idempotencyKey: "propose-borrowing-base-eur"
  });
  const record = environment.certificationService.certify({
    tenantId: TENANT_ID,
    inputId: "certified-borrowing-base-eur",
    certifiedBy: "sidecar-checker",
    idempotencyKey: "certify-borrowing-base-eur"
  });
  assert.equal(record.status, "certified");
});

test("monitor evidence is restricted to authoritative governed references", () => {
  const environment = fixture();
  const primaryManifest = environment.control.getAnalysisManifest(
    TENANT_ID,
    CERTIFICATION_MANIFEST_ID
  );
  assert.ok(primaryManifest);
  const normalizedArtifactId = primaryManifest.artifacts.find(
    (artifact) => artifact.kind === "normalized_snapshot"
  )?.artifactId;
  assert.ok(normalizedArtifactId);

  for (const [suffix, evidence, shouldPass] of [
    ["authorized", [{ kind: "source_artifact", id: normalizedArtifactId }], true],
    ["forged", [{ kind: "source_artifact", id: "attacker-controlled-artifact" }], false]
  ] as const) {
    const candidate = environment.artifacts.putJson({
      tenantId: TENANT_ID,
      kind: "monitoring_input",
      mediaType: "application/json",
      value: {
        ...monitoringPayload,
        observations: [{ ...monitoringPayload.observations[0]!, evidence }]
      }
    });
    const inputId = `certified-monitor-${suffix}`;
    environment.certificationService.propose({
      tenantId: TENANT_ID,
      inputId,
      inputKind: "monitoring",
      candidateArtifactId: candidate.artifactId,
      primaryCertificationManifestId: CERTIFICATION_MANIFEST_ID,
      definitionIds: ["monitor-v1"],
      purpose: PURPOSE,
      declaredControls: { rowCount: 1 },
      proposedBy: "sidecar-maker",
      idempotencyKey: `propose-${inputId}`
    });
    const certify = () =>
      environment.certificationService.certify({
        tenantId: TENANT_ID,
        inputId,
        certifiedBy: "sidecar-checker",
        idempotencyKey: `certify-${inputId}`
      });
    if (shouldPass) assert.equal(certify().status, "certified");
    else assert.throws(certify, /data-quality certification/);
  }
});

test("monitor certification requires one unique observation for every governed metric", () => {
  const environment = fixture();
  for (const [suffix, observations] of [
    ["missing", []],
    [
      "duplicate",
      [
        monitoringPayload.observations[0]!,
        {
          ...monitoringPayload.observations[0]!,
          observationId: "observation-duplicate"
        }
      ]
    ]
  ] as const) {
    const candidate = environment.artifacts.putJson({
      tenantId: TENANT_ID,
      kind: "monitoring_input",
      mediaType: "application/json",
      value: { ...monitoringPayload, observations }
    });
    const inputId = `monitor-${suffix}-metric-coverage`;
    environment.certificationService.propose({
      tenantId: TENANT_ID,
      inputId,
      inputKind: "monitoring",
      candidateArtifactId: candidate.artifactId,
      primaryCertificationManifestId: CERTIFICATION_MANIFEST_ID,
      definitionIds: ["monitor-v1"],
      purpose: PURPOSE,
      declaredControls: { rowCount: observations.length },
      proposedBy: "sidecar-maker",
      idempotencyKey: `propose-${inputId}`
    });
    assert.throws(
      () =>
        environment.certificationService.certify({
          tenantId: TENANT_ID,
          inputId,
          certifiedBy: "sidecar-checker",
          idempotencyKey: `certify-${inputId}`
        }),
      /data-quality certification/
    );
  }
});

test("operator-side certification refuses a manifest whose certification decision did not pass", () => {
  const environment = fixture();
  const valid = environment.control.getAnalysisManifest(TENANT_ID, CERTIFICATION_MANIFEST_ID);
  assert.ok(valid);
  environment.control.recordAnalysisManifest({
    tenantId: TENANT_ID,
    manifestId: "uncertified-primary-manifest",
    snapshotId: valid.snapshotId,
    mappingVersionId: valid.mappingVersionId,
    analysisType: "snapshot_certification",
    parameters: {
      dataQualityProfileId: qualityProfile.id,
      dataQualityProfileVersion: qualityProfile.version,
      dataQualityRunId: "dq-good",
      reconciliationId: "reconciliation-good",
      evaluatedAt: "2026-08-12T12:00:00.000Z",
      certified: false,
      blockerCodes: ["forced-blocker"]
    },
    queryHash: valid.queryHash,
    codeVersion: valid.codeVersion,
    artifacts: valid.artifacts.map((artifact) => ({
      artifactId: artifact.artifactId,
      kind: artifact.kind,
      mediaType: artifact.mediaType,
      contentHash: artifact.contentHash,
      ...(artifact.uri === undefined ? {} : { uri: artifact.uri }),
      ...(artifact.metadata === undefined ? {} : { metadata: artifact.metadata })
    })),
    createdBy: "pipeline-a",
    idempotencyKey: "record-uncertified-primary"
  });

  assert.throws(
    () =>
      environment.certificationService.loadPrimaryChain(
        TENANT_ID,
        "uncertified-primary-manifest"
      ),
    /did not pass/
  );
});

function certifyOperationInput(
  environment: ReturnType<typeof fixture>,
  inputKind: "borrowing_base" | "monitoring"
): {
  readonly proposal: InputCertificationProposalV1;
  readonly record: InputCertificationRecordV1;
  readonly envelope: CertifiedOperationInputV1;
  readonly artifact: StoredArtifact;
} {
  const borrowingBase = inputKind === "borrowing_base";
  const inputId = borrowingBase ? "certified-borrowing-base-1" : "certified-monitoring-1";
  const candidate = borrowingBase
    ? environment.borrowingBaseCandidate
    : environment.monitoringCandidate;
  const proposal = environment.certificationService.propose({
    tenantId: TENANT_ID,
    inputId,
    inputKind,
    candidateArtifactId: candidate.artifactId,
    primaryCertificationManifestId: CERTIFICATION_MANIFEST_ID,
    definitionIds: [borrowingBase ? "borrowing-base-v1" : "monitor-v1"],
    purpose: PURPOSE,
    declaredControls: borrowingBase
      ? { rowCount: 2, balance: "150", currency: "USD" }
      : { rowCount: 1 },
    proposedBy: "sidecar-maker",
    idempotencyKey: `propose-${inputId}`
  });
  const record = environment.certificationService.certify({
    tenantId: TENANT_ID,
    inputId,
    certifiedBy: "sidecar-checker",
    idempotencyKey: `certify-${inputId}`
  });
  const loaded = environment.artifacts.getJson(TENANT_ID, record.certifiedArtifactId);
  return {
    proposal,
    record,
    envelope: parseCertifiedOperationInputV1(loaded.value),
    artifact: loaded.metadata
  };
}

function assertCertifiedResultLineage(
  environment: ReturnType<typeof fixture>,
  resultArtifactId: string,
  record: InputCertificationRecordV1
): void {
  const persisted = environment.artifacts.getJson(TENANT_ID, resultArtifactId).value as {
    version: number;
    lineage: {
      inputCertification: {
        inputId: string;
        envelopeHash: string;
        sidecarPopulationHash: string;
      } | null;
    };
  };
  assert.equal(persisted.version, 3);
  assert.equal(persisted.lineage.inputCertification?.inputId, record.inputId);
  assert.equal(persisted.lineage.inputCertification?.envelopeHash, record.envelopeHash);
  assert.equal(
    persisted.lineage.inputCertification?.sidecarPopulationHash,
    record.sidecarPopulationHash
  );
}

function certifySnapshot(control: ControlStore, artifacts: ArtifactStore): void {
  const ingestion = new SnapshotIngestionService(control, artifacts);
  ingestion.registerDeliveredSnapshot({
    tenantId: TENANT_ID,
    snapshotId: SNAPSHOT_ID,
    sourceId: "source-good",
    asOfDate: AS_OF_DATE,
    records: canonicalRecords,
    deliveredBy: "connector-a",
    idempotencyKey: "delivery-good"
  });
  control.proposeMappingVersion({
    tenantId: TENANT_ID,
    mappingVersionId: "mapping-2026-07",
    mappingKey: "mapping-good",
    snapshotId: SNAPSHOT_ID,
    dictionaryVersion: "1.0.0",
    mappings,
    proposedBy: "maker-a",
    idempotencyKey: "mapping-propose-good"
  });
  for (const toStatus of ["validated", "approved", "active"] as const) {
    control.transitionMappingVersion({
      tenantId: TENANT_ID,
      mappingVersionId: "mapping-2026-07",
      toStatus,
      actor: "checker-a",
      idempotencyKey: `mapping-${toStatus}-good`
    });
  }
  ingestion.certifyMappedSnapshot({
    tenantId: TENANT_ID,
    snapshotId: SNAPSHOT_ID,
    mappingVersionId: "mapping-2026-07",
    dataQualityRunId: "dq-good",
    reconciliationId: "reconciliation-good",
    certificationManifestId: CERTIFICATION_MANIFEST_ID,
    dataQualityProfile: qualityProfile,
    declaredControlTotals: { rowCount: 1, balance: "100", currency: "USD" },
    evaluatedAt: "2026-08-12T12:00:00.000Z",
    codeVersion: "test-1",
    executedBy: "pipeline-a",
    idempotencyKey: "certify-good"
  });
}

function activateDefinition(
  store: DefinitionStore,
  input: {
    readonly definitionId: string;
    readonly definitionKey: string;
    readonly kind: DefinitionKind;
    readonly document: JsonValue;
  }
): void {
  store.propose({
    tenantId: TENANT_ID,
    definitionId: input.definitionId,
    definitionKey: input.definitionKey,
    kind: input.kind,
    version: "1",
    effectiveFrom: "2026-01-01",
    document: input.document,
    proposedBy: "maker-a",
    idempotencyKey: `definition-propose-${input.definitionId}`
  });
  for (const toStatus of ["validated", "approved", "active"] as const) {
    store.transition({
      tenantId: TENANT_ID,
      definitionId: input.definitionId,
      toStatus,
      actor: "checker-a",
      idempotencyKey: `definition-${toStatus}-${input.definitionId}`
    });
  }
}

function invalidWorkflowInput(error: unknown): boolean {
  return error instanceof GovernedWorkflowError && error.code === "INVALID_INPUT";
}

function certificationRequiredWorkflow(error: unknown): boolean {
  return error instanceof GovernedWorkflowError && error.code === "CERTIFICATION_REQUIRED";
}
