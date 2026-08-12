import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import { ArtifactStore } from "../src/control/artifacts.js";
import { MonitoringAlertStore } from "../src/control/alerts.js";
import { DefinitionStore, type DefinitionKind } from "../src/control/definitions.js";
import { JobStore } from "../src/control/jobs.js";
import { ControlStore, type JsonValue } from "../src/control/store.js";
import type { DataQualityProfile } from "../src/domain/data-quality.js";
import {
  GovernedWorkflow,
  GovernedWorkflowError,
  type GovernedWorkflowOperation
} from "../src/services/governed-workflow.js";
import { SnapshotIngestionService } from "../src/services/ingestion.js";
import { runSnapshotStratification } from "../src/services/snapshot-analysis.js";
import {
  createVerifiedPrincipalContext,
  principalBinding,
  type VerifiedPrincipalContext
} from "../src/security/identity.js";
import { compileAuthorizationPolicy } from "../src/security/policy.js";
import { createHmacKeyRing, SignedArtifactError } from "../src/security/signed-plan.js";
import { SecurityStateStore } from "../src/security/state-store.js";
import { modernMcpSuccessResultByteLength } from "../src/transports/mcp-result-envelope.js";

const NOW = Math.floor(Date.parse("2026-08-11T12:00:00.000Z") / 1_000);
const directories: string[] = [];
const closeAfterTest: Array<() => void> = [];

afterEach(() => {
  for (const close of closeAfterTest.splice(0).reverse()) close();
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

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
    as_of_date: "2026-07-31",
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
  },
  {
    as_of_date: "2026-07-31",
    loan_id: "RESTRICTED-LOAN-2",
    risk_rating: "A",
    outstanding_balance: "200",
    interest_rate: "6",
    origination_date: "2025-01-20",
    original_balance: "220",
    charge_off_amount: "10",
    recovery_amount: "2",
    days_past_due: "45",
    currency_code: "USD"
  },
  {
    as_of_date: "2026-07-31",
    loan_id: "RESTRICTED-LOAN-3",
    risk_rating: "B",
    outstanding_balance: "300",
    interest_rate: "7",
    origination_date: "2025-02-01",
    original_balance: "350",
    charge_off_amount: "0",
    recovery_amount: "0",
    days_past_due: "10",
    currency_code: "USD"
  }
];

const mappings = Object.keys(canonicalRecords[0]!).map((field) => ({
  sourceColumn: field,
  canonicalField: field
}));

function principal(subject = "analyst-subject"): VerifiedPrincipalContext {
  return createVerifiedPrincipalContext({
    issuer: "https://identity.example.test",
    subject,
    principalId: subject,
    tenantId: "tenant-a",
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

function fixture(
  options: {
    readonly maxExecutionMs?: number;
    readonly maxResultRows?: number;
    readonly maxResultBytes?: number;
    readonly actionAuditTags?: boolean;
  } = {}
) {
  const directory = mkdtempSync(join(tmpdir(), "abl-governed-workflow-"));
  directories.push(directory);
  let now = new Date(NOW * 1_000);
  const clock = () => now;
  const control = new ControlStore(join(directory, "control.sqlite"), { clock });
  const definitions = new DefinitionStore(join(directory, "definitions.sqlite"), { clock });
  const artifacts = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "artifact-key",
    keys: { "artifact-key": Buffer.alloc(32, 7) }
  });
  const jobs = new JobStore(join(directory, "jobs.sqlite"), { clock });
  const monitoringAlerts = new MonitoringAlertStore(join(directory, "monitoring.sqlite"), { clock });
  const securityState = new SecurityStateStore(join(directory, "security.sqlite"), { clock });
  let membershipActive = true;
  const tenantMembershipResolver = {
    async resolveTenantMembership(lookup: { readonly issuer: string; readonly subject: string; readonly clientId: string; readonly resourceIndicators: readonly string[] }) {
      if (
        !membershipActive ||
        lookup.issuer !== "https://identity.example.test" ||
        lookup.clientId !== "codex-client" ||
        lookup.resourceIndicators[0] !== "https://mcp.example.test/mcp"
      ) return null;
      return { tenantId: "tenant-a", principalId: lookup.subject };
    }
  };
  closeAfterTest.push(
    () => control.close(),
    () => definitions.close(),
    () => jobs.close(),
    () => monitoringAlerts.close(),
    () => securityState.close()
  );

  const ingestion = new SnapshotIngestionService(control, artifacts);
  certifySnapshot({
    control,
    ingestion,
    snapshotId: "snapshot-2026-07",
    mappingVersionId: "mapping-2026-07",
    certificationManifestId: "certification-2026-07",
    records: canonicalRecords,
    declaredBalance: "600",
    suffix: "good"
  });

  activateDefinition(definitions, {
    definitionId: "stratification-v1",
    definitionKey: "risk-stratification",
    kind: "stratification_recipe",
    document: {
      dimension: "risk_rating",
      balanceField: "outstanding_balance",
      weightedAverageFields: ["interest_rate"],
      minimumCohortSize: 1,
      maxRecords: 100,
      maxGroups: 20
    }
  });
  activateDefinition(definitions, {
    definitionId: "vintage-v1",
    definitionKey: "monthly-vintage",
    kind: "vintage_recipe",
    document: {
      cohortGrain: "month",
      maxMonthsOnBook: 24,
      delinquencyThresholdDays: 30,
      minimumCohortSize: 1,
      maxRecords: 100,
      maxPoints: 100
    }
  });
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

  const policy = compileAuthorizationPolicy({
    id: "workflow-policy",
    version: "1",
    defaultObligations: {
      maxResultRows: options.maxResultRows ?? 1_000,
      maxResultBytes: options.maxResultBytes ?? 2_000_000,
      maxExecutionMs: options.maxExecutionMs ?? 10_000,
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
        tenantIds: ["tenant-a"],
        tools: ["*"],
        datasets: ["*"],
        fields: ["*"],
        requiredScopes: ["analysis:run", "data:read"]
      },
      ...(options.actionAuditTags
        ? ([
            ["permit-job-status", "job.status", "status-access"],
            ["permit-job-result", "job.result", "result-access"],
            ["permit-job-cancel", "job.cancel", "cancel-access"]
          ] as const).map(([id, tool, auditTag]) => ({
            id,
            effect: "permit" as const,
            tenantIds: ["tenant-a"],
            tools: [tool],
            datasets: ["*"],
            fields: ["*"],
            requiredScopes: ["analysis:run", "data:read"],
            obligations: { auditTags: [auditTag] }
          }))
        : [])
    ]
  });
  const keyRing = createHmacKeyRing(
    [{ id: "signing-key", secret: new Uint8Array(32).fill(11) }],
    "signing-key"
  );
  const workflow = new GovernedWorkflow(
    {
      control,
      definitions,
      artifacts,
      jobs,
      monitoringAlerts,
      securityState,
      tenantMembershipResolver,
      policy,
      keyRing
    },
    { codeVersion: "test-1", clock, defaultHandleTtlSeconds: 60 }
  );
  const borrowingBaseArtifact = artifacts.putJson({
    tenantId: "tenant-a",
    kind: "borrowing_base_input",
    mediaType: "application/json",
    value: {
      snapshotId: "snapshot-2026-07",
      asOfDate: "2026-07-31",
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
    }
  });
  const monitoringArtifact = artifacts.putJson({
    tenantId: "tenant-a",
    kind: "monitoring_input",
    mediaType: "application/json",
    value: {
      snapshotId: "snapshot-2026-07",
      asOfDate: "2026-07-31",
      scope: { type: "facility", id: "facility-1" },
      observations: [
        {
          observationId: "observation-1",
          metricId: "excess_availability",
          snapshotId: "snapshot-2026-07",
          asOfDate: "2026-07-31",
          type: "decimal",
          value: "-1",
          unit: "currency",
          evidence: []
        }
      ]
    }
  });

  return {
    control,
    definitions,
    artifacts,
    jobs,
    monitoringAlerts,
    securityState,
    workflow,
    borrowingBaseArtifact,
    monitoringArtifact,
    setMembershipActive(active: boolean) {
      membershipActive = active;
    },
    advance(seconds: number) {
      now = new Date(now.getTime() + seconds * 1_000);
    }
  };
}

test("all governed operations execute through signed, encrypted, immutable durable state", async () => {
  const environment = fixture();
  const identity = principal();
  const cases: readonly {
    operation: GovernedWorkflowOperation;
    definitionIds: readonly string[];
    inputArtifactId?: string;
    verify(result: unknown): void;
  }[] = [
    {
      operation: "snapshot_stratification",
      definitionIds: ["stratification-v1"],
      verify(result) {
        const value = result as {
          totals: { loanCount: number; balance: string };
          rows: readonly { bucket: string; loanCount: number | null }[];
        };
        assert.deepEqual(value.totals, { loanCount: 3, balance: "600" });
        assert.deepEqual(value.rows.map((row) => [row.bucket, row.loanCount]), [["A", 2], ["B", 1]]);
        assert.equal(JSON.stringify(value).includes("RESTRICTED-LOAN"), false);
      }
    },
    {
      operation: "snapshot_vintage",
      definitionIds: ["vintage-v1"],
      verify(result) {
        const value = result as { points: readonly unknown[]; lineage: { analysisHash: string } };
        assert.ok(value.points.length > 0);
        assert.match(value.lineage.analysisHash, /^[a-f0-9]{64}$/);
        assert.equal(JSON.stringify(value).includes("RESTRICTED-LOAN"), false);
      }
    },
    {
      operation: "ar_borrowing_base",
      definitionIds: ["borrowing-base-v1"],
      inputArtifactId: environment.borrowingBaseArtifact.artifactId,
      verify(result) {
        const value = result as {
          receivables: readonly unknown[];
          totals: { grossReceivables: string; excessAvailability: string };
        };
        assert.deepEqual(value.receivables, []);
        assert.equal(value.totals.grossReceivables, "150");
        assert.equal(value.totals.excessAvailability, "100");
        assert.equal(JSON.stringify(value).includes("RESTRICTED-"), false);
      }
    },
    {
      operation: "monitoring",
      definitionIds: ["monitor-v1"],
      inputArtifactId: environment.monitoringArtifact.artifactId,
      verify(result) {
        const value = result as {
          status: string;
          gateId: string;
          alerts: readonly { severity: string }[];
        };
        assert.equal(value.status, "evaluated");
        assert.equal(value.gateId, "certification-2026-07");
        assert.equal(value.alerts.length, 1);
        assert.equal(value.alerts[0]?.severity, "critical");
      }
    }
  ];

  for (const [index, item] of cases.entries()) {
    const started = environment.workflow.start(identity, {
      operation: item.operation,
      certificationManifestId: "certification-2026-07",
      definitionIds: item.definitionIds,
      ...(item.inputArtifactId === undefined ? {} : { inputArtifactId: item.inputArtifactId }),
      idempotencyKey: `operation-${index}`
    });
    assert.equal(started.status, "queued");
    const queued = environment.jobs.list("tenant-a", principalBinding(identity))[0];
    assert.ok(queued);
    assert.equal(queued.maxAttempts, 3);
    assert.equal(JSON.stringify(queued.request).toLowerCase().includes("bearer"), false);

    const processed = await environment.workflow.processNext("tenant-a", "worker-1");
    assert.deepEqual(processed, { operation: item.operation, status: "succeeded", errorCode: null });
    const status = await environment.workflow.getJobStatus(identity, started.jobHandle);
    assert.equal(status.status, "succeeded");
    assert.equal(status.resultAvailable, true);

    const result = await environment.workflow.getJobResult(identity, started.jobHandle);
    assert.equal(result.operation, item.operation);
    assert.match(result.resultHash, /^[a-f0-9]{64}$/);
    item.verify(result.result);
    const persisted = environment.artifacts.getJson("tenant-a", result.artifactId).value as {
      lineage: { mappingHash: string; mappingDigest: string };
    };
    assert.match(persisted.lineage.mappingHash, /^[a-f0-9]{64}$/);
    assert.equal(persisted.lineage.mappingDigest, `sha256:${persisted.lineage.mappingHash}`);
    const manifest = environment.control.getAnalysisManifest("tenant-a", result.manifestId);
    assert.ok(manifest);
    assert.equal(manifest.queryHash, result.resultHash);
    assert.ok(manifest.artifacts.some((artifact) => artifact.artifactId === result.artifactId));
    if (item.operation === "monitoring") {
      const durableRun = environment.monitoringAlerts.getRun("tenant-a", result.manifestId);
      assert.ok(durableRun);
      assert.equal(durableRun.alertIds.length, 1);
      assert.equal(environment.monitoringAlerts.listAlerts("tenant-a").length, 1);
    }
  }

  assert.equal(await environment.workflow.processNext("tenant-a", "worker-1"), null);
  const auditTypes = environment.control.listAuditEvents("tenant-a", { limit: 1_000 }).map((event) => event.eventType);
  assert.ok(auditTypes.filter((eventType) => eventType === "governed_job.started").length >= 4);
});

test("a certified longitudinal history executes a multi-period vintage end to end", async () => {
  const environment = fixture();
  const historyRecords = [
    {
      ...canonicalRecords[0]!,
      as_of_date: "2026-06-30",
      outstanding_balance: "110",
      charge_off_amount: "0",
      recovery_amount: "0"
    },
    {
      ...canonicalRecords[0]!,
      as_of_date: "2026-07-31",
      outstanding_balance: "100",
      charge_off_amount: "5",
      recovery_amount: "1"
    },
    {
      ...canonicalRecords[1]!,
      as_of_date: "2026-06-30",
      outstanding_balance: "210",
      charge_off_amount: "8",
      recovery_amount: "1"
    },
    {
      ...canonicalRecords[1]!,
      as_of_date: "2026-07-31",
      outstanding_balance: "200",
      charge_off_amount: "10",
      recovery_amount: "2"
    }
  ];
  certifySnapshot({
    control: environment.control,
    ingestion: new SnapshotIngestionService(environment.control, environment.artifacts),
    snapshotId: "snapshot-history-2026-07",
    mappingVersionId: "mapping-history-2026-07",
    certificationManifestId: "certification-history-2026-07",
    records: historyRecords,
    declaredBalance: "620",
    suffix: "history",
    dataQualityProfile: {
      ...qualityProfile,
      id: "loan-history-certification",
      entity: "loan_history",
      asOfMode: "through"
    }
  });

  const started = environment.workflow.start(principal(), {
    operation: "snapshot_vintage",
    certificationManifestId: "certification-history-2026-07",
    definitionIds: ["vintage-v1"],
    idempotencyKey: "longitudinal-vintage"
  });
  assert.deepEqual(await environment.workflow.processNext("tenant-a", "worker-history"), {
    operation: "snapshot_vintage",
    status: "succeeded",
    errorCode: null
  });

  const result = (await environment.workflow.getJobResult(principal(), started.jobHandle)).result as {
    analysisAsOfDate: string;
    points: readonly {
      monthsOnBook: number;
      available: boolean;
      observedLoanCount: number | null;
      currentBalance: string | null;
    }[];
  };
  const available = result.points.filter((point) => point.available);
  assert.equal(result.analysisAsOfDate, "2026-07-31");
  assert.ok(new Set(available.map((point) => point.monthsOnBook)).size >= 2);
  assert.ok(available.some((point) => point.currentBalance === "320"));
  assert.ok(available.some((point) => point.currentBalance === "300"));
  assert.ok(available.every((point) => point.observedLoanCount === 2));
  assert.equal(JSON.stringify(result).includes("RESTRICTED-LOAN"), false);
});

test("job and result access remain principal-bound and queued cancellation is terminal", async () => {
  const environment = fixture();
  const owner = principal();
  const started = environment.workflow.start(owner, {
    operation: "snapshot_stratification",
    certificationManifestId: "certification-2026-07",
    definitionIds: ["stratification-v1"],
    idempotencyKey: "principal-bound"
  });

  await assert.rejects(
    () => environment.workflow.getJobStatus(principal("different-subject"), started.jobHandle),
    (error: unknown) => error instanceof SignedArtifactError && error.code === "INVALID_ARTIFACT"
  );
  await assert.rejects(
    () => environment.workflow.getJobResult(owner, started.jobHandle),
    (error: unknown) => error instanceof GovernedWorkflowError && error.code === "RESULT_NOT_READY"
  );
  const cancelled = await environment.workflow.cancelJob(owner, started.jobHandle);
  assert.equal(cancelled.status, "cancelled");
  assert.equal(cancelled.cancellationRequested, true);
  assert.equal(cancelled.maxAttempts, 3);
  assert.equal(await environment.workflow.processNext("tenant-a", "worker-1"), null);
});

test("running-job cancellation remains idempotent after the worker terminalizes it", async () => {
  const environment = fixture();
  const owner = principal();
  const started = environment.workflow.start(owner, {
    operation: "snapshot_stratification",
    certificationManifestId: "certification-2026-07",
    definitionIds: ["stratification-v1"],
    idempotencyKey: "running-cancel-retry"
  });
  const claimed = environment.jobs.claimNext({
    tenantId: "tenant-a",
    workerId: "worker-cancel",
    leaseSeconds: 300
  });
  assert.ok(claimed);
  assert.equal((await environment.workflow.cancelJob(owner, started.jobHandle)).status, "running");
  assert.equal(
    environment.jobs.fail(
      "tenant-a",
      claimed.jobId,
      "worker-cancel",
      claimed.claimToken,
      "CANCELLED",
      false
    ).status,
    "cancelled"
  );
  assert.equal((await environment.workflow.cancelJob(owner, started.jobHandle)).status, "cancelled");
  const cancellationEvents = environment.control
    .listAuditEvents("tenant-a", { limit: 1_000 })
    .filter((event) => event.eventType === "governed_job.cancellation_requested");
  assert.equal(cancellationEvents.length, 1);
  assert.deepEqual(cancellationEvents[0]?.details, { requestReceived: true });
});

test("start retries recover the same durable job while rejecting changed idempotent intent", async () => {
  const environment = fixture();
  const identity = principal();
  const input = {
    operation: "snapshot_stratification" as const,
    certificationManifestId: "certification-2026-07",
    definitionIds: ["stratification-v1"],
    idempotencyKey: "durable-start-retry"
  };
  const first = environment.workflow.start(identity, input);
  const retry = environment.workflow.start(identity, input);
  assert.notEqual(retry.jobHandle, first.jobHandle);
  assert.equal(retry.status, "queued");
  assert.equal(environment.jobs.list("tenant-a", principalBinding(identity)).length, 1);
  assert.equal(
    environment.control
      .listAuditEvents("tenant-a", { limit: 1_000 })
      .filter((event) => event.eventType === "governed_job.started").length,
    1
  );

  assert.equal((await environment.workflow.processNext("tenant-a", "worker-1"))?.status, "succeeded");
  const completedRetry = environment.workflow.start(identity, input);
  assert.equal(completedRetry.status, "succeeded");
  assert.equal((await environment.workflow.getJobResult(identity, completedRetry.jobHandle)).operation, input.operation);
  assert.throws(
    () => environment.workflow.start(identity, { ...input, purpose: "different-purpose" }),
    (error: unknown) => error instanceof GovernedWorkflowError && error.code === "INVALID_INPUT"
  );
});

test("same-second distinct starts persist distinct authorization receipts", () => {
  const environment = fixture();
  const identity = principal();
  const common = {
    operation: "snapshot_stratification" as const,
    certificationManifestId: "certification-2026-07",
    definitionIds: ["stratification-v1"]
  };
  environment.workflow.start(identity, {
    ...common,
    idempotencyKey: "same-second-authorization-a",
    handleTtlSeconds: 120
  });
  environment.workflow.start(identity, {
    ...common,
    idempotencyKey: "same-second-authorization-b",
    handleTtlSeconds: 121
  });
  const authorizationEvents = environment.control
    .listAuditEvents("tenant-a", { limit: 1_000 })
    .filter((event) => event.entityType === "policy_decision" && event.actor === principalBinding(identity));
  assert.equal(authorizationEvents.length, 2);
  assert.notEqual(authorizationEvents[0]?.entityId, authorizationEvents[1]?.entityId);
});

test("different principals may reuse a conventional start idempotency key", () => {
  const environment = fixture();
  const firstPrincipal = principal("first-analyst");
  const secondPrincipal = principal("second-analyst");
  const input = {
    operation: "snapshot_stratification" as const,
    certificationManifestId: "certification-2026-07",
    definitionIds: ["stratification-v1"],
    idempotencyKey: "daily-run"
  };
  environment.workflow.start(firstPrincipal, input);
  environment.workflow.start(secondPrincipal, input);
  assert.equal(environment.jobs.list("tenant-a", principalBinding(firstPrincipal)).length, 1);
  assert.equal(environment.jobs.list("tenant-a", principalBinding(secondPrincipal)).length, 1);
  const startEvents = environment.control
    .listAuditEvents("tenant-a", { limit: 1_000 })
    .filter((event) => event.eventType === "governed_job.started");
  assert.equal(startEvents.length, 2);
  assert.equal(new Set(startEvents.map((event) => event.entityId)).size, 2);
});

test("a still-valid job handle recovers an expired result handle from the immutable manifest", async () => {
  const environment = fixture();
  const identity = principal();
  const started = environment.workflow.start(identity, {
    operation: "snapshot_stratification",
    certificationManifestId: "certification-2026-07",
    definitionIds: ["stratification-v1"],
    idempotencyKey: "durable-result-recovery",
    handleTtlSeconds: 3_600
  });
  assert.equal((await environment.workflow.processNext("tenant-a", "worker-1"))?.status, "succeeded");
  environment.advance(61);
  const result = await environment.workflow.getJobResult(identity, started.jobHandle);
  assert.equal(result.operation, "snapshot_stratification");
  assert.equal(result.manifestId, environment.jobs.list("tenant-a", principalBinding(identity))[0]?.jobId);
});

test("membership revocation blocks queued execution and retained result access", async () => {
  const queuedEnvironment = fixture();
  const identity = principal();
  queuedEnvironment.workflow.start(identity, {
    operation: "snapshot_stratification",
    certificationManifestId: "certification-2026-07",
    definitionIds: ["stratification-v1"],
    idempotencyKey: "revoke-before-claim"
  });
  queuedEnvironment.setMembershipActive(false);
  assert.deepEqual(await queuedEnvironment.workflow.processNext("tenant-a", "worker-revoked"), {
    operation: "snapshot_stratification",
    status: "failed",
    errorCode: "POLICY_DENIED"
  });
  assert.equal(queuedEnvironment.jobs.list("tenant-a", principalBinding(identity))[0]?.status, "failed");

  const completedEnvironment = fixture();
  const completed = completedEnvironment.workflow.start(identity, {
    operation: "snapshot_stratification",
    certificationManifestId: "certification-2026-07",
    definitionIds: ["stratification-v1"],
    idempotencyKey: "revoke-before-read"
  });
  assert.equal((await completedEnvironment.workflow.processNext("tenant-a", "worker-complete"))?.status, "succeeded");
  completedEnvironment.setMembershipActive(false);
  await assert.rejects(
    () => completedEnvironment.workflow.getJobResult(identity, completed.jobHandle),
    (error: unknown) => error instanceof GovernedWorkflowError && error.code === "POLICY_DENIED"
  );
});

test("analysis worker enforces a hard wall-clock deadline before durable side effects", async () => {
  const environment = fixture({ maxExecutionMs: 1 });
  const identity = principal();
  const started = environment.workflow.start(identity, {
    operation: "snapshot_stratification",
    certificationManifestId: "certification-2026-07",
    definitionIds: ["stratification-v1"],
    idempotencyKey: "hard-timeout"
  });
  assert.deepEqual(await environment.workflow.processNext("tenant-a", "worker-timeout"), {
    operation: "snapshot_stratification",
    status: "failed",
    errorCode: "EXECUTION_TIMEOUT"
  });
  const job = environment.jobs.list("tenant-a", principalBinding(identity))[0]!;
  assert.equal(job.status, "failed");
  assert.equal(environment.control.getAnalysisManifest("tenant-a", job.jobId), undefined);
  await assert.rejects(
    () => environment.workflow.getJobResult(identity, started.jobHandle),
    (error: unknown) => error instanceof GovernedWorkflowError && error.code === "RESULT_NOT_READY"
  );
});

test("control-plane deadlines fail before job submission or cancellation commits", async () => {
  const environment = fixture({ maxExecutionMs: 1 });
  const identity = principal();
  const input = {
    operation: "snapshot_stratification" as const,
    certificationManifestId: "certification-2026-07",
    definitionIds: ["stratification-v1"],
    idempotencyKey: "precommit-timeout"
  };

  assert.throws(
    () =>
      environment.workflow.startAuthorized(identity, input, {
        requestStartedAtMonotonicMs: 0
      }),
    (error: unknown) =>
      error instanceof GovernedWorkflowError && error.code === "EXECUTION_TIMEOUT"
  );
  assert.deepEqual(environment.jobs.list("tenant-a", principalBinding(identity)), []);

  const started = environment.workflow.start(identity, {
    ...input,
    idempotencyKey: "cancel-precommit-timeout"
  });
  await assert.rejects(
    () =>
      environment.workflow.cancelJobAuthorized(identity, started.jobHandle, {
        requestStartedAtMonotonicMs: 0
      }),
    (error: unknown) =>
      error instanceof GovernedWorkflowError && error.code === "EXECUTION_TIMEOUT"
  );
  const queued = environment.jobs.list("tenant-a", principalBinding(identity))[0]!;
  assert.equal(queued.status, "queued");
  assert.equal(queued.cancellationRequested, false);
});

test("borrowing-base row limits count the published waterfall rather than stripped receivables", async () => {
  const environment = fixture({ maxResultRows: 1 });
  const identity = principal();
  environment.workflow.start(identity, {
    operation: "ar_borrowing_base",
    certificationManifestId: "certification-2026-07",
    definitionIds: ["borrowing-base-v1"],
    inputArtifactId: environment.borrowingBaseArtifact.artifactId,
    idempotencyKey: "borrowing-base-published-row-limit"
  });

  assert.deepEqual(await environment.workflow.processNext("tenant-a", "worker-row-limit"), {
    operation: "ar_borrowing_base",
    status: "failed",
    errorCode: "RESULT_TOO_LARGE"
  });
  const job = environment.jobs.list("tenant-a", principalBinding(identity))[0]!;
  assert.equal(environment.control.getAnalysisManifest("tenant-a", job.jobId), undefined);
});

test("a result that cannot fit its complete MCP representation is rejected before persistence", async () => {
  const maximumResultBytes = 12_000;
  const environment = fixture({ maxResultBytes: maximumResultBytes });
  const records = Array.from({ length: 20 }, (_, index) => ({
    ...canonicalRecords[0]!,
    loan_id: `LARGE-RESULT-${index}`,
    risk_rating: `${String(index).padStart(2, "0")}-${"X".repeat(240)}`,
    outstanding_balance: "1"
  }));
  certifySnapshot({
    control: environment.control,
    ingestion: new SnapshotIngestionService(environment.control, environment.artifacts),
    snapshotId: "snapshot-large-result",
    mappingVersionId: "mapping-large-result",
    certificationManifestId: "certification-large-result",
    records,
    declaredBalance: "20",
    suffix: "large-result"
  });

  const modeled = runSnapshotStratification({
    records,
    lineage: {
      snapshotHash: "a".repeat(64),
      mappingHash: "b".repeat(64),
      dictionaryHash: "c".repeat(64),
      recipeHash: "d".repeat(64)
    },
    asOfDate: "2026-07-31",
    dimension: "risk_rating",
    balanceField: "outstanding_balance",
    weightedAverageFields: ["interest_rate"],
    minimumCohortSize: 1,
    maxRecords: 100,
    maxGroups: 20
  });
  const modeledView = {
    operation: "snapshot_stratification",
    manifestId: "m".repeat(36),
    artifactId: "a".repeat(64),
    resultHash: "f".repeat(64),
    result: modeled
  };
  assert.ok(Buffer.byteLength(JSON.stringify(modeled), "utf8") < maximumResultBytes);
  assert.ok(
    modernMcpSuccessResultByteLength(
      { result: modeledView },
      { name: "abl-data", version: "0.1.0" }
    ) > maximumResultBytes
  );

  const identity = principal();
  environment.workflow.start(identity, {
    operation: "snapshot_stratification",
    certificationManifestId: "certification-large-result",
    definitionIds: ["stratification-v1"],
    idempotencyKey: "large-result-envelope"
  });
  assert.deepEqual(await environment.workflow.processNext("tenant-a", "worker-large-result"), {
    operation: "snapshot_stratification",
    status: "failed",
    errorCode: "RESULT_TOO_LARGE"
  });
  const job = environment.jobs.list("tenant-a", principalBinding(identity))[0]!;
  assert.equal(environment.control.getAnalysisManifest("tenant-a", job.jobId), undefined);
});

test("an expired lease recovers a verified manifest without recomputing the result", async () => {
  const environment = fixture();
  const identity = principal();
  const started = environment.workflow.start(identity, {
    operation: "snapshot_stratification",
    certificationManifestId: "certification-2026-07",
    definitionIds: ["stratification-v1"],
    idempotencyKey: "crash-recovery",
    handleTtlSeconds: 600
  });
  const originalComplete = environment.jobs.complete.bind(environment.jobs);
  const originalFail = environment.jobs.fail.bind(environment.jobs);
  Object.defineProperty(environment.jobs, "complete", {
    configurable: true,
    value: () => {
      throw new Error("simulated process loss after manifest persistence");
    }
  });
  Object.defineProperty(environment.jobs, "fail", {
    configurable: true,
    value: () => {
      throw new Error("simulated process termination before failure handling");
    }
  });
  await assert.rejects(() => environment.workflow.processNext("tenant-a", "worker-crash"));
  const crashed = environment.jobs.list("tenant-a", principalBinding(identity))[0]!;
  assert.equal(crashed.status, "running");
  const manifestBeforeRetry = environment.control.getAnalysisManifest("tenant-a", crashed.jobId);
  assert.ok(manifestBeforeRetry);
  const artifactId = manifestBeforeRetry.artifacts[0]!.artifactId;

  Object.defineProperty(environment.jobs, "complete", { configurable: true, value: originalComplete });
  Object.defineProperty(environment.jobs, "fail", { configurable: true, value: originalFail });
  environment.advance(301);
  assert.deepEqual(await environment.workflow.processNext("tenant-a", "worker-recovery"), {
    operation: "snapshot_stratification",
    status: "succeeded",
    errorCode: null
  });
  const result = await environment.workflow.getJobResult(identity, started.jobHandle);
  assert.equal(result.artifactId, artifactId);
  assert.equal(environment.jobs.get("tenant-a", crashed.jobId).attemptCount, 2);
});

test("a verified final-attempt manifest remains recoverable after completion crashes", async () => {
  const environment = fixture();
  const identity = principal();
  const started = environment.workflow.start(identity, {
    operation: "snapshot_stratification",
    certificationManifestId: "certification-2026-07",
    definitionIds: ["stratification-v1"],
    idempotencyKey: "final-attempt-crash-recovery",
    handleTtlSeconds: 600
  });
  const queued = environment.jobs.list("tenant-a", principalBinding(identity))[0]!;
  for (const workerId of ["worker-failed-1", "worker-failed-2"]) {
    const claim = environment.jobs.claimNext({ tenantId: "tenant-a", workerId, leaseSeconds: 300 });
    assert.ok(claim);
    environment.jobs.fail(
      "tenant-a",
      queued.jobId,
      workerId,
      claim.claimToken,
      "AUTHORIZATION_UNAVAILABLE",
      true
    );
  }

  const originalComplete = environment.jobs.complete.bind(environment.jobs);
  Object.defineProperty(environment.jobs, "complete", {
    configurable: true,
    value: () => {
      throw new Error("simulated final-attempt process loss after manifest persistence");
    }
  });
  await assert.rejects(() => environment.workflow.processNext("tenant-a", "worker-final-attempt"));
  const crashed = environment.jobs.get("tenant-a", queued.jobId);
  assert.equal(crashed.status, "running");
  assert.equal(crashed.attemptCount, 3);
  assert.ok(environment.control.getAnalysisManifest("tenant-a", queued.jobId));

  Object.defineProperty(environment.jobs, "complete", { configurable: true, value: originalComplete });
  environment.advance(301);
  assert.deepEqual(await environment.workflow.processNext("tenant-a", "worker-final-recovery"), {
    operation: "snapshot_stratification",
    status: "succeeded",
    errorCode: null
  });
  const completed = environment.jobs.get("tenant-a", queued.jobId);
  assert.equal(completed.attemptCount, 3);
  assert.equal((await environment.workflow.getJobResult(identity, started.jobHandle)).manifestId, queued.jobId);
});

test("job access audit persists current analysis and action policy obligations", async () => {
  const environment = fixture({ actionAuditTags: true });
  const identity = principal();
  const started = environment.workflow.start(identity, {
    operation: "snapshot_stratification",
    certificationManifestId: "certification-2026-07",
    definitionIds: ["stratification-v1"],
    idempotencyKey: "action-audit-obligations",
    purpose: "portfolio-review"
  });
  assert.equal((await environment.workflow.processNext("tenant-a", "worker-audit"))?.status, "succeeded");
  await environment.workflow.getJobStatus(identity, started.jobHandle);
  await environment.workflow.getJobResult(identity, started.jobHandle);
  await environment.workflow.cancelJob(identity, started.jobHandle);

  const expectedTags = new Map([
    ["job.status", "status-access"],
    ["job.result", "result-access"],
    ["job.cancel", "cancel-access"]
  ]);
  const events = environment.control
    .listAuditEvents("tenant-a")
    .filter((event) => event.entityType === "job_access");
  assert.equal(events.length, 3);
  for (const event of events) {
    const details = event.details as {
      actionToolName: string;
      purpose: string;
      analysis: { policyId: string; policyVersion: string; matchedRuleIds: string[]; auditTags: string[] };
      action: { policyId: string; policyVersion: string; matchedRuleIds: string[]; auditTags: string[] };
    };
    const expected = expectedTags.get(details.actionToolName);
    assert.ok(expected);
    assert.equal(details.purpose, "portfolio-review");
    assert.equal(details.analysis.policyId, "workflow-policy");
    assert.equal(details.analysis.policyVersion, "1");
    assert.ok(details.analysis.matchedRuleIds.includes("permit-governed-analysis"));
    assert.ok(details.analysis.auditTags.includes("governed-analysis"));
    assert.equal(details.action.policyId, "workflow-policy");
    assert.equal(details.action.policyVersion, "1");
    assert.ok(details.action.matchedRuleIds.includes(`permit-${details.actionToolName.replace(".", "-")}`));
    assert.ok(details.action.auditTags.includes(expected));
  }
});

test("failed certification and caller-supplied monitoring gate claims are blocked before enqueue", () => {
  const environment = fixture();
  const identity = principal();
  certifySnapshot({
    control: environment.control,
    ingestion: new SnapshotIngestionService(environment.control, environment.artifacts),
    snapshotId: "snapshot-bad",
    mappingVersionId: "mapping-bad",
    certificationManifestId: "certification-bad",
    records: [canonicalRecords[0]!, canonicalRecords[0]!],
    declaredBalance: "999",
    suffix: "bad"
  });

  assert.throws(
    () =>
      environment.workflow.start(identity, {
        operation: "snapshot_stratification",
        certificationManifestId: "certification-bad",
        definitionIds: ["stratification-v1"],
        idempotencyKey: "bad-certification"
      }),
    (error: unknown) => error instanceof GovernedWorkflowError && error.code === "CERTIFICATION_REQUIRED"
  );

  const callerGateArtifact = environment.artifacts.putJson({
    tenantId: "tenant-a",
    kind: "monitoring_input",
    mediaType: "application/json",
    value: {
      snapshotId: "snapshot-2026-07",
      asOfDate: "2026-07-31",
      scope: { type: "facility", id: "facility-1" },
      observations: [],
      dataQualityGate: {
        status: "certified",
        gateId: "caller-claim",
        snapshotId: "snapshot-2026-07",
        certifiedAt: "2026-08-11T12:00:00Z",
        blockingFindingCount: 0,
        evidence: []
      }
    }
  });
  assert.throws(
    () =>
      environment.workflow.start(identity, {
        operation: "monitoring",
        certificationManifestId: "certification-2026-07",
        definitionIds: ["monitor-v1"],
        inputArtifactId: callerGateArtifact.artifactId,
        idempotencyKey: "caller-gate"
      }),
    (error: unknown) => error instanceof GovernedWorkflowError && error.code === "INVALID_INPUT"
  );

  activateDefinition(environment.definitions, {
    definitionId: "invalid-stratification-v1",
    definitionKey: "invalid-stratification",
    kind: "stratification_recipe",
    document: {
      dimension: "risk_rating",
      maxRecords: 100,
      maxGroups: 20,
      callerControlledSql: "select *"
    }
  });
  assert.throws(
    () =>
      environment.workflow.start(identity, {
        operation: "snapshot_stratification",
        certificationManifestId: "certification-2026-07",
        definitionIds: ["invalid-stratification-v1"],
        idempotencyKey: "invalid-definition"
      }),
    (error: unknown) => error instanceof GovernedWorkflowError && error.code === "INVALID_INPUT"
  );
  assert.equal(environment.jobs.list("tenant-a", principalBinding(identity)).length, 0);
});

test("a consumed execution envelope cannot be replayed as another durable job", async () => {
  const environment = fixture();
  const identity = principal();
  const started = environment.workflow.start(identity, {
    operation: "snapshot_stratification",
    certificationManifestId: "certification-2026-07",
    definitionIds: ["stratification-v1"],
    idempotencyKey: "original-plan"
  });
  assert.equal((await environment.workflow.processNext("tenant-a", "worker-1"))?.status, "succeeded");
  assert.equal((await environment.workflow.getJobStatus(identity, started.jobHandle)).status, "succeeded");

  const original = environment.jobs.list("tenant-a", principalBinding(identity))[0];
  assert.ok(original);
  const replay = environment.jobs.submit({
    tenantId: "tenant-a",
    requestedBy: original.requestedBy,
    idempotencyKey: "replayed-envelope",
    toolName: original.toolName,
    ...(original.datasetId === null ? {} : { datasetId: original.datasetId }),
    request: original.request,
    maxAttempts: 1
  });
  const replayed = await environment.workflow.processNext("tenant-a", "worker-2");
  assert.deepEqual(replayed, {
    operation: "snapshot_stratification",
    status: "failed",
    errorCode: "AUDIT_REQUIRED"
  });
  assert.equal(environment.jobs.get("tenant-a", replay.jobId).attemptCount, 1);
  assert.equal(environment.jobs.get("tenant-a", replay.jobId).maxAttempts, 1);
});

function certifySnapshot(input: {
  readonly control: ControlStore;
  readonly ingestion: SnapshotIngestionService;
  readonly snapshotId: string;
  readonly mappingVersionId: string;
  readonly certificationManifestId: string;
  readonly records: readonly Readonly<Record<string, unknown>>[];
  readonly declaredBalance: string;
  readonly suffix: string;
  readonly dataQualityProfile?: DataQualityProfile;
}): void {
  input.ingestion.registerDeliveredSnapshot({
    tenantId: "tenant-a",
    snapshotId: input.snapshotId,
    sourceId: `source-${input.suffix}`,
    asOfDate: "2026-07-31",
    records: input.records,
    deliveredBy: "connector-a",
    idempotencyKey: `delivery-${input.suffix}`
  });
  input.control.proposeMappingVersion({
    tenantId: "tenant-a",
    mappingVersionId: input.mappingVersionId,
    mappingKey: `mapping-${input.suffix}`,
    snapshotId: input.snapshotId,
    dictionaryVersion: "1.0.0",
    mappings,
    proposedBy: "maker-a",
    idempotencyKey: `mapping-propose-${input.suffix}`
  });
  for (const toStatus of ["validated", "approved", "active"] as const) {
    input.control.transitionMappingVersion({
      tenantId: "tenant-a",
      mappingVersionId: input.mappingVersionId,
      toStatus,
      actor: "checker-a",
      idempotencyKey: `mapping-${toStatus}-${input.suffix}`
    });
  }
  input.ingestion.certifyMappedSnapshot({
    tenantId: "tenant-a",
    snapshotId: input.snapshotId,
    mappingVersionId: input.mappingVersionId,
    dataQualityRunId: `dq-${input.suffix}`,
    reconciliationId: `reconciliation-${input.suffix}`,
    certificationManifestId: input.certificationManifestId,
    dataQualityProfile: input.dataQualityProfile ?? qualityProfile,
    declaredControlTotals: {
      rowCount: input.records.length,
      balance: input.declaredBalance,
      currency: "USD"
    },
    evaluatedAt: "2026-08-11T12:00:00Z",
    codeVersion: "test-1",
    executedBy: "pipeline-a",
    idempotencyKey: `certify-${input.suffix}`
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
    tenantId: "tenant-a",
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
      tenantId: "tenant-a",
      definitionId: input.definitionId,
      toStatus,
      actor: "checker-a",
      idempotencyKey: `definition-${toStatus}-${input.definitionId}`
    });
  }
}
