import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import { MonitoringAlertStore } from "../src/control/alerts.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import { DefinitionStore, type DefinitionKind } from "../src/control/definitions.js";
import { InputCertificationStore } from "../src/control/input-certifications.js";
import { JobStore, type SubmitJobInput } from "../src/control/jobs.js";
import { ControlStore, type JsonValue } from "../src/control/store.js";
import type { DataQualityProfile } from "../src/domain/data-quality.js";
import {
  GovernedWorkflow,
  type GovernedWorkflowOperation,
  type StartedGovernedJob
} from "../src/services/governed-workflow.js";
import { SnapshotIngestionService } from "../src/services/ingestion.js";
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

interface CompatibilityCase {
  readonly operation: Extract<
    GovernedWorkflowOperation,
    "snapshot_stratification" | "snapshot_vintage"
  >;
  readonly definitionId: string;
}

const compatibilityCases: readonly CompatibilityCase[] = [
  { operation: "snapshot_stratification", definitionId: "stratification-v1" },
  { operation: "snapshot_vintage", definitionId: "vintage-v1" }
];

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
  const directory = mkdtempSync(join(tmpdir(), "abl-governed-v2-compatibility-"));
  temporaryDirectories.push(directory);
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
  const inputCertifications = new InputCertificationStore(
    join(directory, "input-certifications.sqlite"),
    { clock }
  );
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
  const workflow = new GovernedWorkflow(
    {
      control,
      definitions,
      artifacts,
      jobs,
      monitoringAlerts,
      inputCertifications,
      securityState,
      tenantMembershipResolver: {
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
      },
      policy,
      keyRing: createHmacKeyRing(
        [{ id: "signing-key", secret: new Uint8Array(32).fill(11) }],
        "signing-key"
      )
    },
    { codeVersion: "upgrade-test", clock, defaultHandleTtlSeconds: 600 }
  );

  return {
    control,
    artifacts,
    jobs,
    workflow,
    advance(seconds: number) {
      now = new Date(now.getTime() + seconds * 1_000);
    }
  };
}

for (const compatibilityCase of compatibilityCases) {
  test(`a queued v2 ${compatibilityCase.operation} envelope remains retrievable after upgrade`, async () => {
    const environment = fixture();
    const identity = principal();
    const started = queueLegacyV2Job(environment, identity, compatibilityCase, "retrievable");

    assert.deepEqual(await environment.workflow.processNext(TENANT_ID, "upgraded-worker"), {
      operation: compatibilityCase.operation,
      status: "succeeded",
      errorCode: null
    });
    const result = await environment.workflow.getJobResult(identity, started.jobHandle);
    assert.equal(result.operation, compatibilityCase.operation);
    assert.match(result.resultHash, /^[a-f0-9]{64}$/);
    assert.equal(JSON.stringify(result.result).includes("RESTRICTED-LOAN"), false);
  });

  test(`a queued v2 ${compatibilityCase.operation} envelope recovers its durable result after upgrade`, async () => {
    const environment = fixture();
    const identity = principal();
    const started = queueLegacyV2Job(environment, identity, compatibilityCase, "recoverable");
    const queued = environment.jobs.list(TENANT_ID, principalBinding(identity))[0]!;
    const originalComplete = environment.jobs.complete.bind(environment.jobs);
    Object.defineProperty(environment.jobs, "complete", {
      configurable: true,
      value: () => {
        throw new Error("simulated process loss after v2 job manifest persistence");
      }
    });

    await assert.rejects(
      () => environment.workflow.processNext(TENANT_ID, "pre-upgrade-worker"),
      /simulated process loss/
    );
    const crashed = environment.jobs.get(TENANT_ID, queued.jobId);
    assert.equal(crashed.status, "running");
    const durableManifest = environment.control.getAnalysisManifest(TENANT_ID, crashed.jobId);
    assert.ok(durableManifest);
    const durableArtifactId = durableManifest.artifacts[0]!.artifactId;

    Object.defineProperty(environment.jobs, "complete", {
      configurable: true,
      value: originalComplete
    });
    environment.advance(301);
    assert.deepEqual(await environment.workflow.processNext(TENANT_ID, "upgraded-recovery-worker"), {
      operation: compatibilityCase.operation,
      status: "succeeded",
      errorCode: null
    });
    const result = await environment.workflow.getJobResult(identity, started.jobHandle);
    assert.equal(result.operation, compatibilityCase.operation);
    assert.equal(result.artifactId, durableArtifactId);
    assert.equal(environment.jobs.get(TENANT_ID, queued.jobId).attemptCount, 2);
  });
}

function queueLegacyV2Job(
  environment: ReturnType<typeof fixture>,
  identity: VerifiedPrincipalContext,
  compatibilityCase: CompatibilityCase,
  suffix: string
): StartedGovernedJob {
  const originalSubmit = environment.jobs.submit.bind(environment.jobs);
  Object.defineProperty(environment.jobs, "submit", {
    configurable: true,
    value: (input: SubmitJobInput) =>
      originalSubmit({
        ...input,
        request: { ...input.request, version: 2 }
      })
  });
  try {
    const started = environment.workflow.start(identity, {
      operation: compatibilityCase.operation,
      certificationManifestId: CERTIFICATION_MANIFEST_ID,
      definitionIds: [compatibilityCase.definitionId],
      idempotencyKey: `legacy-v2-${compatibilityCase.operation}-${suffix}`,
      handleTtlSeconds: 600
    });
    const queued = environment.jobs.list(TENANT_ID, principalBinding(identity))[0]!;
    assert.equal(queued.request.version, 2);
    assert.equal(queued.status, "queued");
    return started;
  } finally {
    Object.defineProperty(environment.jobs, "submit", {
      configurable: true,
      value: originalSubmit
    });
  }
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
