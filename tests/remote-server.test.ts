import assert from "node:assert/strict";
import test from "node:test";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createMcpHandler, type AuthInfo } from "@modelcontextprotocol/server";

import { ControlStore } from "../src/control/store.js";
import { DefinitionStore } from "../src/control/definitions.js";
import { MonitoringAlertStore } from "../src/control/alerts.js";
import { evaluateMonitoring } from "../src/domain/monitoring.js";
import { buildRemoteServer, type GovernedWorkflowApi } from "../src/remote-server.js";
import { createVerifiedPrincipalContext } from "../src/security/identity.js";
import { compileAuthorizationPolicy } from "../src/security/policy.js";
import { createHmacKeyRing, issuePrincipalBoundHandle } from "../src/security/signed-plan.js";

const principal = createVerifiedPrincipalContext({
  issuer: "https://issuer.example.com/",
  subject: "user-1",
  principalId: "analyst-1",
  tenantId: "tenant-a",
  clientId: "codex",
  audiences: ["abl-api"],
  resourceIndicators: ["https://mcp.example.test/mcp"],
  scopes: ["abl:all"],
  credentialFingerprint: "a".repeat(64),
  verifiedAtEpochSeconds: 1_786_440_000,
  expiresAtEpochSeconds: 4_000_000_000
});

const policy = compileAuthorizationPolicy({
  id: "test-policy",
  version: "1",
  defaultObligations: {
    maxResultRows: 500,
    maxResultBytes: 1_000_000,
    maxExecutionMs: 30_000,
    minimumCohortSize: 1,
    requireImmutableSnapshot: true,
    allowRawRows: false,
    allowExport: false,
    rowFilterRefs: [],
    fieldMasks: {},
    auditTags: ["test"]
  },
  rules: [
    {
      id: "permit-test",
      effect: "permit",
      tenantIds: ["tenant-a"],
      tools: ["*"],
      datasets: ["*"],
      fields: ["*"],
      requiredScopes: ["abl:all"]
    },
    {
      id: "bound-mutating-receipts",
      effect: "permit",
      tenantIds: ["tenant-a"],
      tools: ["mapping.propose", "alert.transition"],
      datasets: ["*"],
      fields: ["*"],
      requiredScopes: ["abl:all"],
      obligations: { maxResultBytes: 1_024 }
    }
  ]
});

const workflow: GovernedWorkflowApi = {
  startAuthorized: async (_principal, input) => ({
    value: { jobHandle: "job-handle-value-for-test", status: "queued", operation: input.operation },
    obligations: [policy.defaultObligations]
  }),
  getJobStatusAuthorized: async () => ({
    value: { status: "queued" },
    obligations: [policy.defaultObligations]
  }),
  getJobResultAuthorized: async () => ({
    value: { totals: { balance: "10" } },
    obligations: [policy.defaultObligations]
  }),
  cancelJobAuthorized: async () => ({
    value: { status: "cancelled" },
    obligations: [policy.defaultObligations]
  })
};

test("remote server catalog is tenant scoped and mapping proposals never self-activate", async () => {
  const control = new ControlStore(":memory:", { clock: () => new Date("2026-08-11T12:00:00Z") });
  const definitions = new DefinitionStore(":memory:", { clock: () => new Date("2026-08-11T12:00:00Z") });
  const monitoringAlerts = new MonitoringAlertStore(":memory:", { clock: () => new Date("2026-08-11T12:00:00Z") });
  const monitoringResult = evaluateMonitoring({
    asOfDate: "2026-07-31",
    scope: { type: "facility", id: "facility-a" },
    dataQualityGate: {
      status: "certified",
      gateId: "gate-a",
      snapshotId: "snapshot-a",
      certifiedAt: "2026-08-11T11:00:00Z",
      blockingFindingCount: 0,
      evidence: [{ kind: "reconciliation", id: "reconciliation-a" }]
    },
    monitorDefinitions: [
      {
        monitorId: "negative-availability",
        version: "1",
        effectiveFrom: "2026-01-01",
        metricId: "availability",
        title: "Negative availability",
        message: "Availability is below zero",
        severity: "critical",
        threshold: { type: "decimal", operator: "lt", value: "0", unit: "currency" }
      }
    ],
    observations: [
      {
        observationId: "availability-july",
        metricId: "availability",
        snapshotId: "snapshot-a",
        asOfDate: "2026-07-31",
        type: "decimal",
        value: "-25",
        unit: "currency",
        evidence: [{ kind: "metric_run", id: "analysis-a" }]
      }
    ]
  });
  monitoringAlerts.recordRun({
    tenantId: "tenant-a",
    runId: "monitoring-run-a",
    result: monitoringResult,
    recordedBy: "worker-a",
    idempotencyKey: "monitoring-run-a"
  });
  control.createDatasetSnapshot({
    tenantId: "tenant-a",
    snapshotId: "snapshot-a",
    sourceId: "source-a",
    sourceLocator: `abl-artifact://${"1".repeat(64)}`,
    asOfDate: "2026-07-31",
    contentHash: "2".repeat(64),
    rowCount: 1,
    schema: {
      fields: [
        { name: "loan_no", nullable: false, types: ["string"] },
        { name: "facility_no", nullable: false, types: ["string"] },
        { name: "borrower_no", nullable: false, types: ["string"] },
        { name: "as_of_dt", nullable: false, types: ["string"] },
        { name: "balance", nullable: false, types: ["string"] },
        { name: "currency", nullable: false, types: ["string"] },
        { name: "commitment", nullable: false, types: ["string"] }
      ]
    },
    createdBy: "connector-a",
    idempotencyKey: "snapshot-a"
  });
  control.createDatasetSnapshot({
    tenantId: "tenant-b",
    snapshotId: "snapshot-b",
    sourceId: "source-b",
    sourceLocator: `abl-artifact://${"3".repeat(64)}`,
    asOfDate: "2026-07-31",
    contentHash: "4".repeat(64),
    rowCount: 1,
    schema: { fields: [{ name: "secret", nullable: false, types: ["string"] }] },
    createdBy: "connector-b",
    idempotencyKey: "snapshot-b"
  });

  const authInfo: AuthInfo = {
    token: principal.credentialFingerprint,
    clientId: "codex",
    scopes: [...principal.scopes],
    expiresAt: principal.expiresAtEpochSeconds,
    extra: { verifiedPrincipal: principal }
  };
  const handler = createMcpHandler((context) =>
    buildRemoteServer({ control, definitions, monitoringAlerts, policy, workflow }, context)
  );
  const client = new Client(
    { name: "remote-server-test", version: "1" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } }
  );
  const transport = new StreamableHTTPClientTransport(new URL("https://mcp.test/mcp"), {
    fetch: (url, init) => handler.fetch(new Request(url, init), { authInfo })
  });
  await client.connect(transport);
  try {
    const resources = await client.listResources();
    assert.deepEqual(resources.resources, []);
    await assert.rejects(
      client.readResource({ uri: "abl://dictionary/canonical/1.0.0" })
    );

    const listed = await client.callTool({ name: "abl_list_snapshots", arguments: {} });
    const snapshots = (listed.structuredContent as { snapshots: Array<{ snapshotId: string }> }).snapshots;
    assert.deepEqual(snapshots.map((snapshot) => snapshot.snapshotId), ["snapshot-a"]);

    const proposed = await client.callTool({
      name: "abl_propose_mapping",
      arguments: {
        snapshot_id: "snapshot-a",
        mapping_key: "source-a-loans",
        profile: "base",
        idempotency_key: "proposal-a",
        mappings: [
          { sourceColumn: "loan_no", canonicalField: "loan_id" },
          { sourceColumn: "facility_no", canonicalField: "facility_id" },
          { sourceColumn: "borrower_no", canonicalField: "borrower_id" },
          { sourceColumn: "as_of_dt", canonicalField: "as_of_date" },
          { sourceColumn: "balance", canonicalField: "outstanding_balance" },
          { sourceColumn: "currency", canonicalField: "currency_code" },
          { sourceColumn: "commitment", canonicalField: "commitment_amount" }
        ]
      }
    });
    assert.equal(proposed.isError, undefined, JSON.stringify(proposed));
    assert.equal((proposed.structuredContent as { mapping: { status: string } }).mapping.status, "proposed");
    assert.ok(Buffer.byteLength(JSON.stringify(proposed), "utf8") <= 1_024);
    assert.equal(control.listMappingVersions("tenant-b").length, 0);

    const listedAlerts = await client.callTool({ name: "abl_list_alerts", arguments: { status: "open" } });
    const alert = (listedAlerts.structuredContent as { alerts: Array<{ alertId: string; status: string }> }).alerts[0]!;
    assert.equal(alert.status, "open");
    const acknowledged = await client.callTool({
      name: "abl_transition_alert",
      arguments: {
        action: "acknowledge",
        alert_id: alert.alertId,
        note: "Risk review started.",
        idempotency_key: "acknowledge-alert-a"
      }
    });
    assert.equal((acknowledged.structuredContent as { alert: { status: string } }).alert.status, "acknowledged");
    assert.ok(Buffer.byteLength(JSON.stringify(acknowledged), "utf8") <= 1_024);
    const audit = control.listAuditEvents("tenant-a");
    assert.equal(audit.some((event) => event.eventType === "authorization.permitted"), true);
    assert.equal(JSON.stringify(audit).includes(principal.credentialFingerprint), false);
  } finally {
    await client.close();
    await handler.close();
    monitoringAlerts.close();
    definitions.close();
    control.close();
  }
});

test("remote catalog authorizes concrete records before pagination and advertises no governed resources", async () => {
  const control = new ControlStore(":memory:", { clock: () => new Date("2026-08-11T12:00:00Z") });
  const definitions = new DefinitionStore(":memory:", { clock: () => new Date("2026-08-11T12:00:00Z") });
  const monitoringAlerts = new MonitoringAlertStore(":memory:", { clock: () => new Date("2026-08-11T12:00:00Z") });

  for (const [index, snapshotId] of ["snapshot-a", "snapshot-b", "snapshot-c"].entries()) {
    control.createDatasetSnapshot({
      tenantId: "tenant-a",
      snapshotId,
      sourceId: `source-${index}`,
      sourceLocator: `abl-artifact://${String(index + 1).repeat(64)}`,
      asOfDate: "2026-07-31",
      contentHash: String(index + 4).repeat(64),
      rowCount: 1,
      schema: { fields: [{ name: "risk_rating", nullable: false, types: ["string"] }] },
      createdBy: "connector-a",
      idempotencyKey: snapshotId
    });
  }

  for (const [definitionId, dimension] of [
    ["definition-risk", "risk_rating"],
    ["definition-industry", "industry_code"]
  ] as const) {
    definitions.propose({
      tenantId: "tenant-a",
      definitionId,
      definitionKey: definitionId,
      kind: "stratification_recipe",
      version: "1",
      effectiveFrom: "2026-01-01",
      document: {
        dimension,
        balanceField: "outstanding_balance",
        maxRecords: 1_000,
        maxGroups: 100
      },
      proposedBy: "maker-a",
      idempotencyKey: definitionId
    });
  }

  const selectivePolicy = compileAuthorizationPolicy({
    id: "selective-test-policy",
    version: "1",
    defaultObligations: {
      maxResultRows: 100,
      maxResultBytes: 1_000_000,
      maxExecutionMs: 30_000,
      minimumCohortSize: 1,
      requireImmutableSnapshot: true,
      allowRawRows: false,
      allowExport: false,
      rowFilterRefs: ["tenant-boundary"],
      fieldMasks: {},
      auditTags: ["selective-test"]
    },
    rules: [
      {
        id: "list-selected-snapshots",
        effect: "permit",
        tenantIds: ["tenant-a"],
        tools: ["snapshot.list"],
        datasets: ["snapshot-a", "snapshot-c"],
        fields: ["snapshot_metadata", "source_schema"],
        requiredScopes: ["abl:all"],
        obligations: { maxResultRows: 1 }
      },
      {
        id: "read-selected-snapshot-with-tight-byte-cap",
        effect: "permit",
        tenantIds: ["tenant-a"],
        tools: ["snapshot.read"],
        datasets: ["snapshot-a"],
        fields: ["snapshot_metadata", "source_schema"],
        requiredScopes: ["abl:all"],
        obligations: { maxResultBytes: 64 }
      },
      {
        id: "definitions-by-field",
        effect: "permit",
        tenantIds: ["tenant-a"],
        tools: ["definition.list", "definition.read"],
        datasets: ["*"],
        fields: ["as_of_date", "outstanding_balance", "risk_rating"],
        requiredScopes: ["abl:all"]
      }
    ]
  });
  const authInfo: AuthInfo = {
    token: principal.credentialFingerprint,
    clientId: "codex",
    scopes: [...principal.scopes],
    expiresAt: principal.expiresAtEpochSeconds,
    extra: { verifiedPrincipal: principal }
  };
  const handler = createMcpHandler((context) =>
    buildRemoteServer(
      { control, definitions, monitoringAlerts, policy: selectivePolicy, workflow },
      context
    )
  );
  const client = new Client(
    { name: "remote-server-authorization-test", version: "1" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } }
  );
  const transport = new StreamableHTTPClientTransport(new URL("https://mcp.test/mcp"), {
    fetch: (url, init) => handler.fetch(new Request(url, init), { authInfo })
  });
  await client.connect(transport);
  try {
    const resources = await client.listResources();
    assert.deepEqual(resources.resources, []);
    await assert.rejects(
      client.readResource({ uri: `abl://dictionary/canonical/1.0.0` })
    );

    const firstPage = await client.callTool({ name: "abl_list_snapshots", arguments: { limit: 100 } });
    assert.deepEqual(
      (firstPage.structuredContent as { snapshots: Array<{ snapshotId: string }> }).snapshots.map(
        (snapshot) => snapshot.snapshotId
      ),
      ["snapshot-a"]
    );
    assert.equal(
      (firstPage.structuredContent as { nextAfterSnapshotId: string | null }).nextAfterSnapshotId,
      "snapshot-a"
    );
    assert.match((firstPage.content[0] as { text: string }).text, /^UNTRUSTED_DATA_JSON:/);

    const secondPage = await client.callTool({
      name: "abl_list_snapshots",
      arguments: { after_snapshot_id: "snapshot-a", limit: 100 }
    });
    assert.deepEqual(
      (secondPage.structuredContent as { snapshots: Array<{ snapshotId: string }> }).snapshots.map(
        (snapshot) => snapshot.snapshotId
      ),
      ["snapshot-c"]
    );

    const hiddenCursor = await client.callTool({
      name: "abl_list_snapshots",
      arguments: { after_snapshot_id: "snapshot-b" }
    });
    const unknownCursor = await client.callTool({
      name: "abl_list_snapshots",
      arguments: { after_snapshot_id: "snapshot-unknown" }
    });
    assert.equal(hiddenCursor.isError, true);
    assert.equal(
      (hiddenCursor.content[0] as { text: string }).text,
      (unknownCursor.content[0] as { text: string }).text
    );

    const listedDefinitions = await client.callTool({ name: "abl_list_definitions", arguments: {} });
    assert.deepEqual(
      (listedDefinitions.structuredContent as { definitions: Array<{ definitionId: string }> }).definitions.map(
        (definition) => definition.definitionId
      ),
      ["definition-risk"]
    );
    const hiddenDefinition = await client.callTool({
      name: "abl_get_definition",
      arguments: { definition_id: "definition-industry" }
    });
    assert.equal(hiddenDefinition.isError, true);
    assert.match((hiddenDefinition.content[0] as { text: string }).text, /"error":"FORBIDDEN"/);

    const byteBounded = await client.callTool({
      name: "abl_get_snapshot",
      arguments: { snapshot_id: "snapshot-a" }
    });
    assert.equal(byteBounded.isError, true);
    assert.match((byteBounded.content[0] as { text: string }).text, /"error":"RESULT_LIMIT_EXCEEDED"/);

    const status = await client.callTool({
      name: "abl_get_job_status",
      arguments: { job_handle: "job-handle-value-for-test" }
    });
    assert.equal((status.structuredContent as { job: { status: string } }).job.status, "queued");
    assert.equal(
      JSON.stringify(control.listAuditEvents("tenant-a")).includes('"datasetId":"jobs"'),
      false
    );
  } finally {
    await client.close();
    await handler.close();
    monitoringAlerts.close();
    definitions.close();
    control.close();
  }
});

test("remote governed job read routes enforce current policy bytes on the complete compatibility response", async () => {
  const control = new ControlStore(":memory:");
  const definitions = new DefinitionStore(":memory:");
  const monitoringAlerts = new MonitoringAlertStore(":memory:");
  const tightObligations = Object.freeze({
    ...policy.defaultObligations,
    maxResultBytes: 150
  });
  const tightWorkflow: GovernedWorkflowApi = {
    startAuthorized: async (_verifiedPrincipal, input) => ({
      value: { jobHandle: "job-handle-value-for-test", status: "queued", operation: input.operation },
      obligations: [tightObligations]
    }),
    getJobStatusAuthorized: async () => ({
      value: { status: "queued" },
      obligations: [tightObligations]
    }),
    getJobResultAuthorized: async () => ({
      value: { totals: { balance: "10" } },
      obligations: [tightObligations]
    }),
    cancelJobAuthorized: async () => ({
      value: { status: "cancelled" },
      obligations: [tightObligations]
    })
  };
  const authInfo: AuthInfo = {
    token: principal.credentialFingerprint,
    clientId: "codex",
    scopes: [...principal.scopes],
    expiresAt: principal.expiresAtEpochSeconds,
    extra: { verifiedPrincipal: principal }
  };
  const handler = createMcpHandler((context) =>
    buildRemoteServer({ control, definitions, monitoringAlerts, policy, workflow: tightWorkflow }, context)
  );
  const client = new Client(
    { name: "remote-job-response-bound-test", version: "1" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } }
  );
  const transport = new StreamableHTTPClientTransport(new URL("https://mcp.test/mcp"), {
    fetch: (url, init) => handler.fetch(new Request(url, init), { authInfo })
  });
  await client.connect(transport);
  try {
    const statusJson = JSON.stringify({ job: { status: "queued" } });
    const handlerStatusResult = {
      content: [{ type: "text", text: `UNTRUSTED_DATA_JSON:${statusJson}` }],
      structuredContent: JSON.parse(statusJson)
    };
    // The handler shape fits. The modern SDK projection adds resultType and
    // serverInfo; the end-to-end result must therefore still fail closed.
    assert.ok(Buffer.byteLength(JSON.stringify(handlerStatusResult), "utf8") <= tightObligations.maxResultBytes);

    const calls = [
      { name: "abl_get_job_status", arguments: { job_handle: "job-handle-value-for-test" } },
      { name: "abl_get_job_result", arguments: { job_handle: "job-handle-value-for-test" } }
    ] as const;

    for (const call of calls) {
      const result = await client.callTool(call);
      assert.equal(result.isError, true, call.name);
      const text = (result.content[0] as { text: string }).text;
      assert.match(text, /"error":"RESULT_LIMIT_EXCEEDED"/, call.name);
      assert.equal(text.includes("job-handle-value-for-test"), false, call.name);
      assert.equal(text.includes('"balance":"10"'), false, call.name);
      assert.ok(Buffer.byteLength(JSON.stringify(result), "utf8") <= 512, call.name);
    }
  } finally {
    await client.close();
    await handler.close();
    monitoringAlerts.close();
    definitions.close();
    control.close();
  }
});

test("the production result-byte floor preserves mutating job acknowledgements", async () => {
  const control = new ControlStore(":memory:");
  const definitions = new DefinitionStore(":memory:");
  const monitoringAlerts = new MonitoringAlertStore(":memory:");
  const floorObligations = Object.freeze({
    ...policy.defaultObligations,
    maxResultBytes: 1_024,
    maxExecutionMs: 1
  });
  const maximumRuntimeKeyId = "k".repeat(128);
  const issued = issuePrincipalBoundHandle(
    createHmacKeyRing(
      [{ id: maximumRuntimeKeyId, secret: new Uint8Array(32).fill(7) }],
      maximumRuntimeKeyId
    ),
    {
      kind: "job",
      principal,
      handleId: `h${"a".repeat(32)}`,
      ttlSeconds: 604_800,
      nowEpochSeconds: 3_999_000_000
    }
  );
  const status = {
    operation: "snapshot_stratification" as const,
    status: "running" as const,
    attemptCount: 3,
    maxAttempts: 3,
    cancellationRequested: true,
    createdAt: "2026-08-11T12:00:00.000Z",
    updatedAt: "2026-08-11T12:00:00.000Z",
    errorCode: "AUTHORIZATION_UNAVAILABLE",
    resultAvailable: false
  };
  let startMutations = 0;
  let cancelMutations = 0;
  const floorWorkflow: GovernedWorkflowApi = {
    startAuthorized: async (_verifiedPrincipal, input) => {
      startMutations += 1;
      await new Promise((resolve) => setTimeout(resolve, 5));
      return {
        value: { jobHandle: issued.handle, status: "queued", operation: input.operation },
        obligations: [floorObligations]
      };
    },
    getJobStatusAuthorized: async () => ({ value: status, obligations: [floorObligations] }),
    getJobResultAuthorized: async () => ({ value: { totals: {} }, obligations: [floorObligations] }),
    cancelJobAuthorized: async () => {
      cancelMutations += 1;
      await new Promise((resolve) => setTimeout(resolve, 5));
      return { value: status, obligations: [floorObligations] };
    }
  };
  const authInfo: AuthInfo = {
    token: principal.credentialFingerprint,
    clientId: "codex",
    scopes: [...principal.scopes],
    expiresAt: principal.expiresAtEpochSeconds,
    extra: { verifiedPrincipal: principal }
  };
  const handler = createMcpHandler((context) =>
    buildRemoteServer({ control, definitions, monitoringAlerts, policy, workflow: floorWorkflow }, context)
  );
  const client = new Client(
    { name: "remote-write-ack-floor-test", version: "1" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } }
  );
  const transport = new StreamableHTTPClientTransport(new URL("https://mcp.test/mcp"), {
    fetch: (url, init) => handler.fetch(new Request(url, init), { authInfo })
  });
  await client.connect(transport);
  try {
    const started = await client.callTool({
      name: "abl_start_job",
      arguments: {
        operation: "snapshot_stratification",
        certification_manifest_id: "certification-a",
        definition_ids: ["definition-a"],
        idempotency_key: "start-at-result-floor"
      }
    });
    assert.equal(started.isError, undefined, JSON.stringify(started));
    assert.equal(
      (started.structuredContent as { job: { jobHandle: string } }).job.jobHandle,
      issued.handle
    );
    assert.ok(Buffer.byteLength(JSON.stringify(started), "utf8") > 512);
    assert.ok(Buffer.byteLength(JSON.stringify(started), "utf8") <= floorObligations.maxResultBytes);

    const cancelled = await client.callTool({
      name: "abl_cancel_job",
      arguments: { job_handle: issued.handle }
    });
    assert.equal(cancelled.isError, undefined, JSON.stringify(cancelled));
    assert.equal((cancelled.structuredContent as { job: { cancellationRequested: boolean } }).job.cancellationRequested, true);
    assert.ok(Buffer.byteLength(JSON.stringify(cancelled), "utf8") <= floorObligations.maxResultBytes);
    assert.equal(startMutations, 1);
    assert.equal(cancelMutations, 1);
  } finally {
    await client.close();
    await handler.close();
    monitoringAlerts.close();
    definitions.close();
    control.close();
  }
});

test("remote server fails closed when the verified runtime brand is absent", () => {
  const control = new ControlStore(":memory:");
  const definitions = new DefinitionStore(":memory:");
  const monitoringAlerts = new MonitoringAlertStore(":memory:");
  assert.throws(
    () =>
      buildRemoteServer(
        { control, definitions, monitoringAlerts, policy, workflow },
        {
          era: "modern",
          authInfo: {
            token: "fake",
            clientId: "fake",
            scopes: ["abl:all"],
            extra: { verifiedPrincipal: { tenantId: "tenant-a" } }
          }
        }
      ),
    /runtime-issued verified principal context/
  );
  definitions.close();
  monitoringAlerts.close();
  control.close();
});
