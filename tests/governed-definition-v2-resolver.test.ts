import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import {
  canonicalHash,
  createMappingSpecV2,
  createSourceContractV1,
  type CanonicalJsonValue
} from "../src/contracts/index.js";
import {
  GovernedDefinitionV2Store,
  type GovernedDefinitionAuditEventV2,
  type GovernedDefinitionViewV2
} from "../src/control/governed-definitions-v2.js";
import { validateBorrowingBasePolicyV2 } from "../src/domain/abl-v2/engine.js";
import {
  GovernedDefinitionV2Resolver,
  GovernedDefinitionV2ResolverError,
  type GovernedDefinitionV2AuthorityPort
} from "../src/services/governed-definition-v2-resolver.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("resolver derives engine approval only from the durable lifecycle", () => {
  const store = fixture();
  const resolver = new GovernedDefinitionV2Resolver(store);
  const proposed = store.propose(metricProposal("metric-v1", "1.0.0", "2026-01-01", 12));
  store.propose({
    ...metricProposal("tenant-b-metric-v1", "1.0.0", "2026-01-01", 12),
    tenantId: "tenant-b",
    idempotencyKey: "tenant-b-propose"
  });

  assert.throws(
    () => resolver.resolveFrozen({ tenantId: "tenant-a", definitionVersionId: "metric-v1" }),
    (error: unknown) => resolverError(error, "UNAPPROVED")
  );
  const validated = transition(store, proposed, "validated", "real-checker", "v1-validated");
  assert.throws(
    () => resolver.resolveFrozen({ tenantId: "tenant-a", definitionVersionId: "metric-v1" }),
    (error: unknown) => resolverError(error, "UNAPPROVED")
  );
  const approved = transition(store, validated, "approved", "real-checker", "v1-approved");
  assert.throws(
    () => resolver.resolveFrozen({ tenantId: "tenant-a", definitionVersionId: "metric-v1" }),
    (error: unknown) => resolverError(error, "UNAPPROVED")
  );
  const active = transition(store, approved, "active", "real-checker", "v1-active");
  const frozen = resolver.resolveFrozen({ tenantId: "tenant-a", definitionVersionId: "metric-v1" });

  assert.deepEqual((frozen.executionDocument as { approval: unknown }).approval, {
    status: "approved",
    proposedBy: "real-maker",
    approvedBy: "real-checker",
    approvedAt: approved.approvalEvidence?.approvedAt
  });
  assert.equal(JSON.stringify(frozen.executionDocument).includes("forged-checker"), false);
  assert.equal(frozen.reference.approvalEventHash, approved.approvalEvidence?.approvalEventHash);
  assert.equal(frozen.reference.versionHash, approved.version.versionHash);
  assert.equal(frozen.reference.documentHash, approved.version.documentHash);
  assert.equal(Object.isFrozen(frozen), true);
  assert.equal(Object.isFrozen(frozen.executionDocument), true);
  assert.equal(Object.isFrozen((frozen.executionDocument as { numerator: object }).numerator), true);

  const effective = resolver.resolveEffective({
    tenantId: "tenant-a",
    kind: "metric_definition",
    definitionKey: "roll-rate",
    asOfDate: "2026-06-30"
  });
  assert.equal(effective.reference.definitionVersionId, "metric-v1");
  store.close();
});

test("frozen resolution replays superseded and retired versions while effective resolution follows dates", () => {
  const store = fixture();
  const resolver = new GovernedDefinitionV2Resolver(store);
  const first = activate(
    store,
    store.propose(metricProposal("metric-v1", "1.0.0", "2026-01-01", 12)),
    "checker-a",
    "v1"
  );
  const second = store.propose({
    ...metricProposal("metric-v2", "2.0.0", "2026-07-01", 18),
    predecessorDefinitionVersionId: "metric-v1",
    rollbackTargetDefinitionVersionId: "metric-v1"
  });
  activate(store, second, "checker-b", "v2");

  assert.equal(store.get("tenant-a", "metric-v1")?.status, "superseded");
  assert.equal(
    resolver.resolveEffective({
      tenantId: "tenant-a",
      kind: "metric_definition",
      definitionKey: "roll-rate",
      asOfDate: "2026-06-30"
    }).reference.definitionVersionId,
    "metric-v1"
  );
  assert.equal(
    resolver.resolveEffective({
      tenantId: "tenant-a",
      kind: "metric_definition",
      definitionKey: "roll-rate",
      asOfDate: "2026-07-01"
    }).reference.definitionVersionId,
    "metric-v2"
  );
  assert.equal(
    resolver.resolveFrozen({ tenantId: "tenant-a", definitionVersionId: "metric-v1" }).reference
      .versionHash,
    first.version.versionHash
  );

  const superseded = store.get("tenant-a", "metric-v1")!;
  store.transition({
    tenantId: "tenant-a",
    definitionVersionId: "metric-v1",
    toStatus: "retired",
    expectedRevision: superseded.lifecycleRevision,
    actor: "checker-a",
    idempotencyKey: "v1-retire"
  });
  const retired = resolver.resolveFrozen({ tenantId: "tenant-a", definitionVersionId: "metric-v1" });
  assert.equal(retired.reference.versionHash, first.version.versionHash);
  assert.throws(
    () => resolver.resolveFrozen({ tenantId: "tenant-b", definitionVersionId: "metric-v1" }),
    (error: unknown) => resolverError(error, "NOT_FOUND")
  );
  store.close();
});

test("source-contract and mapping projections replace forged identity and recompute inner hashes", () => {
  const store = fixture();
  const resolver = new GovernedDefinitionV2Resolver(store);
  const source = createSourceContractV1(sourceContractInput());
  const sourceVersion = activate(
    store,
    store.propose({
      tenantId: "tenant-a",
      definitionVersionId: "source-v1",
      definitionKey: "loan-tape",
      kind: "source_contract",
      semanticVersion: "1.0.0",
      effectiveFrom: "2026-01-01",
      document: source,
      proposedBy: "real-maker",
      idempotencyKey: "source-propose"
    }),
    "real-checker",
    "source"
  );
  const sourceResult = resolver.resolveFrozen({
    tenantId: "tenant-a",
    definitionVersionId: "source-v1"
  });
  const sourceDocument = sourceResult.executionDocument as Record<string, CanonicalJsonValue>;
  assert.equal(sourceDocument.status, "approved");
  assert.equal(sourceDocument.createdBy, "real-maker");
  assert.equal(sourceDocument.createdAt, sourceVersion.version.proposedAt);
  assert.equal(sourceDocument.approvedBy, "real-checker");
  assert.equal(sourceDocument.approvedAt, sourceVersion.approvalEvidence?.approvedAt);
  assertCanonicalInnerHash(sourceDocument, "sourceContractHash");
  assert.notEqual(sourceDocument.sourceContractHash, source.sourceContractHash);

  const mapping = createMappingSpecV2(mappingSpecInput(source));
  const mappingVersion = activate(
    store,
    store.propose({
      tenantId: "tenant-a",
      definitionVersionId: "mapping-v1",
      definitionKey: "loan-tape",
      kind: "mapping_spec",
      semanticVersion: "1.0.0",
      effectiveFrom: "2026-01-01",
      document: mapping,
      proposedBy: "real-maker",
      idempotencyKey: "mapping-propose"
    }),
    "real-checker",
    "mapping"
  );
  const mappingDocument = resolver.resolveFrozen({
    tenantId: "tenant-a",
    definitionVersionId: "mapping-v1"
  }).executionDocument as Record<string, CanonicalJsonValue>;
  assert.equal(mappingDocument.status, "approved");
  assert.equal(mappingDocument.createdBy, "real-maker");
  assert.equal(mappingDocument.createdAt, mappingVersion.version.proposedAt);
  assert.equal(mappingDocument.approvedBy, "real-checker");
  assertCanonicalInnerHash(mappingDocument, "mappingSpecHash");
  assert.notEqual(mappingDocument.mappingSpecHash, mapping.mappingSpecHash);
  store.close();
});

test("borrowing-base projection preserves the server policy hash and binds approval authority", () => {
  const store = fixture();
  const resolver = new GovernedDefinitionV2Resolver(store);
  const approved = activate(
    store,
    store.propose({
      tenantId: "tenant-a",
      definitionVersionId: "bb-v1",
      definitionKey: "bb-policy",
      kind: "borrowing_base_policy_v2",
      semanticVersion: "1.0.0",
      effectiveFrom: "2026-01-01",
      document: borrowingBasePolicy(),
      proposedBy: "real-maker",
      idempotencyKey: "bb-propose"
    }),
    "real-checker",
    "bb"
  );
  const result = resolver.resolveFrozen({ tenantId: "tenant-a", definitionVersionId: "bb-v1" });
  const stored = approved.version.document as { policyHash: string };
  const execution = result.executionDocument as unknown as Parameters<
    typeof validateBorrowingBasePolicyV2
  >[0];

  validateBorrowingBasePolicyV2(execution);
  assert.equal(execution.policyHash, stored.policyHash);
  assert.equal(execution.approval.proposedBy, "real-maker");
  assert.equal(execution.approval.approvedBy, "real-checker");
  assert.equal(execution.approval.authorityRef, approved.approvalEvidence?.approvalEventHash);
  assert.equal(execution.approval.rationale.includes("governed definition v2 lifecycle"), true);
  store.close();
});

test("non-engine lifecycle documents remain approval-neutral with authority carried separately", () => {
  const store = fixture();
  const resolver = new GovernedDefinitionV2Resolver(store);
  const approved = activate(
    store,
    store.propose({
      tenantId: "tenant-a",
      definitionVersionId: "methodology-v1",
      definitionKey: "portfolio-methodology",
      kind: "methodology_bundle",
      semanticVersion: "1.0.0",
      effectiveFrom: "2026-01-01",
      document: {
        contractVersion: 1,
        bundleKind: "methodology",
        bundleId: "portfolio-methodology",
        version: "1.0.0",
        name: "Portfolio methodology",
        description: "Deterministic portfolio surveillance methodology.",
        calculationEngine: {
          engineId: "surveillance-engine",
          engineVersion: "1.0.0",
          runtimeBundleHash: `sha256:${"e".repeat(64)}`
        },
        requiredDefinitionKinds: ["metric_definition"],
        deterministicParameters: { maximumPeriods: 120 },
        approval: {
          status: "pending_durable_approval",
          authority: "governed_definition_v2_lifecycle"
        }
      },
      proposedBy: "real-maker",
      idempotencyKey: "methodology-propose"
    }),
    "real-checker",
    "methodology"
  );
  const result = resolver.resolveFrozen({
    tenantId: "tenant-a",
    definitionVersionId: "methodology-v1"
  });

  assert.deepEqual((result.executionDocument as { approval: unknown }).approval, {
    status: "pending_durable_approval",
    authority: "governed_definition_v2_lifecycle"
  });
  assert.equal(result.approvalEvidence.approvedBy, "real-checker");
  assert.equal(result.approvalEvidence.approvalEventHash, approved.approvalEvidence?.approvalEventHash);
  store.close();
});

test("resolver rejects hash drift and tampered authority responses", () => {
  const store = fixture();
  const active = activate(
    store,
    store.propose(metricProposal("metric-v1", "1.0.0", "2026-01-01", 12)),
    "real-checker",
    "tamper"
  );
  const driftedView = {
    ...active,
    version: { ...active.version, documentHash: `sha256:${"0".repeat(64)}` }
  } as GovernedDefinitionViewV2;
  const driftedAuthority: GovernedDefinitionV2AuthorityPort = {
    get: () => driftedView,
    selectEffective: () => driftedView,
    listAuditEvents: (tenantId, afterSequence, limit) =>
      store.listAuditEvents(tenantId, afterSequence, limit)
  };
  assert.throws(
    () =>
      new GovernedDefinitionV2Resolver(driftedAuthority).resolveFrozen({
        tenantId: "tenant-a",
        definitionVersionId: "metric-v1"
      }),
    (error: unknown) => resolverError(error, "INTEGRITY_FAILURE")
  );

  const forgedApproval = {
    ...active,
    approvalEvidence: { ...active.approvalEvidence!, approvedBy: "forged-checker" }
  };
  const forgedAuthority: GovernedDefinitionV2AuthorityPort = {
    get: () => forgedApproval,
    selectEffective: () => forgedApproval,
    listAuditEvents: (tenantId, afterSequence, limit) =>
      store.listAuditEvents(tenantId, afterSequence, limit)
  };
  assert.throws(
    () =>
      new GovernedDefinitionV2Resolver(forgedAuthority).resolveFrozen({
        tenantId: "tenant-a",
        definitionVersionId: "metric-v1"
      }),
    (error: unknown) => resolverError(error, "INTEGRITY_FAILURE")
  );

  const events = store.listAuditEvents("tenant-a");
  const proposalEvidenceEvents = rehashAuditEvents(events, (event, index) =>
    index === 0 ? { ...event, evidence: { versionHash: `sha256:${"f".repeat(64)}` } } : event
  );
  const proposalEvidenceAuthority: GovernedDefinitionV2AuthorityPort = {
    get: () => active,
    selectEffective: () => active,
    listAuditEvents: (_tenantId, afterSequence = 0, limit = 100) =>
      proposalEvidenceEvents.filter((event) => event.sequence > afterSequence).slice(0, limit)
  };
  assert.throws(
    () =>
      new GovernedDefinitionV2Resolver(proposalEvidenceAuthority).resolveFrozen({
        tenantId: "tenant-a",
        definitionVersionId: "metric-v1"
      }),
    (error: unknown) => resolverError(error, "INTEGRITY_FAILURE")
  );

  const makerActivationEvents = rehashAuditEvents(events, (event) =>
    event.toStatus === "active" ? { ...event, actor: "real-maker" } : event
  );
  const makerActivationView = { ...active, lastTransitionBy: "real-maker" };
  const makerActivationAuthority: GovernedDefinitionV2AuthorityPort = {
    get: () => makerActivationView,
    selectEffective: () => makerActivationView,
    listAuditEvents: (_tenantId, afterSequence = 0, limit = 100) =>
      makerActivationEvents.filter((event) => event.sequence > afterSequence).slice(0, limit)
  };
  assert.throws(
    () =>
      new GovernedDefinitionV2Resolver(makerActivationAuthority).resolveEffective({
        tenantId: "tenant-a",
        kind: "metric_definition",
        definitionKey: "roll-rate",
        asOfDate: "2026-08-12"
      }),
    (error: unknown) => resolverError(error, "INTEGRITY_FAILURE")
  );
  store.close();
});

function rehashAuditEvents(
  events: readonly GovernedDefinitionAuditEventV2[],
  mutate: (event: GovernedDefinitionAuditEventV2, index: number) => GovernedDefinitionAuditEventV2
): readonly GovernedDefinitionAuditEventV2[] {
  let previousEventHash: GovernedDefinitionAuditEventV2["previousEventHash"] = null;
  return events.map((original, index) => {
    const changed = mutate(original, index);
    const {
      sequence,
      eventHash: _eventHash,
      previousEventHash: _previousEventHash,
      ...body
    } = changed;
    const hashedBody = { ...body, previousEventHash };
    const event = {
      sequence,
      ...hashedBody,
      eventHash: canonicalHash(hashedBody)
    } satisfies GovernedDefinitionAuditEventV2;
    previousEventHash = event.eventHash;
    return event;
  });
}

function fixture(): GovernedDefinitionV2Store {
  const directory = mkdtempSync(join(tmpdir(), "abl-definition-resolver-"));
  directories.push(directory);
  let tick = 0;
  return new GovernedDefinitionV2Store(join(directory, "control.sqlite"), {
    clock: () => new Date(Date.UTC(2026, 7, 12, 12, tick++, 0, 0))
  });
}

function metricProposal(
  definitionVersionId: string,
  semanticVersion: string,
  effectiveFrom: string,
  maximumCells: number
) {
  return {
    tenantId: "tenant-a",
    definitionVersionId,
    definitionKey: "roll-rate",
    kind: "metric_definition" as const,
    semanticVersion,
    effectiveFrom,
    document: {
      schemaVersion: "1",
      definitionType: "metric_definition",
      definitionId: "roll-rate",
      version: Number(semanticVersion.split(".")[0]),
      name: "Roll rate",
      family: "roll_cure",
      grain: "loan",
      unit: "ratio",
      temporalSemantics: "transition",
      numerator: { label: "Transitioning", aggregation: "sum", field: "outstanding_balance" },
      denominator: { label: "Opening", aggregation: "sum", field: "outstanding_balance" },
      window: { kind: "adjacent_periods", maximumPeriods: 12 },
      population: null,
      nullPolicy: "unavailable",
      coverage: { minimumRatio: "0.95", minimumObservedRecords: 1 },
      privacy: { minimumCellCount: 3, complementarySuppression: true },
      maximumCells,
      configuration: {
        kind: "roll_cure",
        delinquencyField: "days_past_due",
        balanceField: "outstanding_balance",
        binDefinitionId: "dpd-bands"
      },
      approval: {
        status: "approved",
        proposedBy: "forged-maker",
        approvedBy: "forged-checker",
        approvedAt: "2099-01-01T00:00:00.000Z"
      }
    },
    proposedBy: "real-maker",
    idempotencyKey: `propose-${definitionVersionId}`
  };
}

function approve(
  store: GovernedDefinitionV2Store,
  start: GovernedDefinitionViewV2,
  actor: string,
  suffix: string
): GovernedDefinitionViewV2 {
  const validated = transition(store, start, "validated", actor, `${suffix}-validated`);
  return transition(store, validated, "approved", actor, `${suffix}-approved`);
}

function activate(
  store: GovernedDefinitionV2Store,
  start: GovernedDefinitionViewV2,
  actor: string,
  suffix: string
): GovernedDefinitionViewV2 {
  const approved = approve(store, start, actor, suffix);
  return transition(store, approved, "active", actor, `${suffix}-active`);
}

function transition(
  store: GovernedDefinitionV2Store,
  current: GovernedDefinitionViewV2,
  toStatus: "validated" | "approved" | "active",
  actor: string,
  idempotencyKey: string
): GovernedDefinitionViewV2 {
  return store.transition({
    tenantId: current.version.tenantId,
    definitionVersionId: current.version.definitionVersionId,
    toStatus,
    expectedRevision: current.lifecycleRevision,
    actor,
    idempotencyKey
  });
}

function resolverError(error: unknown, code: GovernedDefinitionV2ResolverError["code"]): boolean {
  return error instanceof GovernedDefinitionV2ResolverError && error.code === code;
}

function assertCanonicalInnerHash(
  document: Record<string, CanonicalJsonValue>,
  hashField: "sourceContractHash" | "mappingSpecHash"
): void {
  const { [hashField]: actual, ...body } = document;
  assert.equal(actual, canonicalHash(body));
}

function sourceContractInput() {
  return {
    contractVersion: 1 as const,
    tenantId: "tenant-a",
    sourceContractId: "loan-tape-postgres-v1",
    sourceKey: "loan-tape",
    revision: 1,
    status: "active" as const,
    delivery: {
      mode: "managed_upload" as const,
      format: "parquet" as const,
      logicalName: "loan-tape.parquet"
    },
    schemaPolicy: {
      columns: [{ sourceName: "loan_id", ordinal: 0, nativeType: "string", nullable: false, required: true }],
      allowUnknownColumns: false,
      requireStableOrdinals: true
    },
    parserPolicy: {
      format: "parquet" as const,
      parserId: "parquet-v1",
      parserVersion: "1.0.0",
      optionsHash: `sha256:${"a".repeat(64)}` as const,
      exactDecimalMode: "string" as const,
      timezone: "UTC" as const,
      rejectSchemaMerging: true
    },
    extractionPolicy: {
      mode: "full" as const,
      readOnly: true as const,
      maximumRows: 1_000,
      maximumColumns: 100,
      maximumBytes: 1_000_000,
      timeoutMs: 1_000,
      cursorRows: 100
    },
    sections: [{ sectionId: "loans", required: true, selector: "loans", keyFields: ["loan_id"] }],
    effectiveFrom: "2026-01-01",
    createdBy: "forged-maker",
    createdAt: "2026-08-12T00:00:00.000Z",
    approvedBy: "forged-checker",
    approvedAt: "2026-08-12T01:00:00.000Z"
  };
}

function mappingSpecInput(source: ReturnType<typeof createSourceContractV1>) {
  return {
    contractVersion: 2 as const,
    tenantId: "tenant-a",
    mappingSpecId: "loan-tape-mapping-v1",
    mappingKey: "loan-tape",
    revision: 1,
    status: "active" as const,
    sourceContract: {
      sourceContractId: source.sourceContractId,
      revision: source.revision,
      sourceContractHash: source.sourceContractHash
    },
    dictionaryBundle: {
      contractVersion: 1 as const,
      bundleKind: "dictionary" as const,
      bundleId: "dictionary-core",
      version: "1.0.0",
      contentHash: `sha256:${"b".repeat(64)}` as const,
      artifactId: "dictionary-artifact",
      mediaType: "application/json",
      createdAt: "2026-08-12T00:00:00.000Z",
      dictionaryVersion: "1.0.0",
      dictionaryHash: `sha256:${"c".repeat(64)}` as const,
      fieldPolicyVersion: "1.0.0",
      fieldPolicyHash: `sha256:${"d".repeat(64)}` as const
    },
    rules: [
      {
        ruleId: "loan-id",
        canonicalField: "loan_id",
        expression: { op: "source" as const, column: "loan_id" },
        onError: "fail_application" as const
      }
    ],
    requiredCanonicalFields: ["loan_id"],
    createdBy: "forged-maker",
    createdAt: "2026-08-12T00:00:00.000Z",
    approvedBy: "forged-checker",
    approvedAt: "2026-08-12T01:00:00.000Z"
  };
}

function borrowingBasePolicy() {
  return {
    schemaVersion: "2",
    policyId: "bb-policy",
    version: "1",
    policyHash: "a".repeat(64),
    tenantId: "tenant-a",
    facilityId: "facility-a",
    currencyCode: "USD",
    effectiveFrom: "2026-01-01",
    commitmentAmount: "1000",
    components: [
      {
        componentId: "ar",
        collateralClass: "accounts_receivable",
        valueBasis: "eligible_amount",
        advanceRate: "0.85"
      }
    ],
    reserves: [],
    triggers: [],
    ticklerWarningDays: 30,
    approval: {
      status: "approved",
      proposedBy: "forged-maker",
      approvedBy: "forged-checker",
      approvedAt: "2099-01-01T00:00:00.000Z",
      authorityRef: "forged-authority",
      rationale: "Caller supplied and therefore not authoritative"
    }
  };
}
