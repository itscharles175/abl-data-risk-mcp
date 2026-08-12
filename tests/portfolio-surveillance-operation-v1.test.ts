import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ContractValidationError,
  canonicalHash,
  type CanonicalJsonValue,
  type Sha256Hash
} from "../src/contracts/canonical.js";
import type { LongitudinalCertificationBundleV1 } from "../src/contracts/longitudinal-certification-bundle-v1.js";
import type {
  MetricConfigurationV1,
  MetricDefinitionV1
} from "../src/domain/surveillance/contracts.js";
import { stableFingerprint } from "../src/domain/surveillance/definitions.js";
import type { ResolvedGovernedDefinitionV2 } from "../src/services/governed-definition-v2-resolver.js";
import {
  PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR,
  PORTFOLIO_SURVEILLANCE_V1_INTEGRATION_PORTS,
  PORTFOLIO_SURVEILLANCE_V1_SCHEMA_METADATA,
  PortfolioSurveillanceOperationError,
  accountPortfolioSurveillanceOperationResultV1,
  assertAggregateOnlyPortfolioSurveillanceResultV1,
  assertPortfolioSurveillanceMetricCompatibilityV1,
  createCertifiedSnapshotMaterialV1,
  createPortfolioSurveillanceOperationModuleV1,
  executePortfolioSurveillanceOperationV1,
  parsePortfolioSurveillanceExecutionPlanV1,
  parsePortfolioSurveillanceOperationRequestV1,
  portfolioSurveillanceMethodologyHashV1,
  preparePortfolioSurveillanceExecutionPlanV1,
  type CertifiedSnapshotMaterialV1,
  type PortfolioSurveillanceOperationAuthorityV1,
  type PortfolioSurveillanceOperationRequestV1,
  type PortfolioSurveillanceOperationResultV1,
  type PortfolioSurveillanceSnapshotLoadRequestV1
} from "../src/services/operations/portfolio-surveillance-v1.js";

const PURPOSE = "governed-portfolio-surveillance";
const TENANT = "tenant-a";
const FIELDS = [
  "as_of_date",
  "commitment_amount",
  "facility_id",
  "loan_id",
  "original_balance",
  "outstanding_balance",
  "source_system"
] as const;

const METHODOLOGY_DOCUMENT = {
  contractVersion: 1,
  bundleKind: "methodology",
  bundleId: "portfolio-surveillance",
  version: "1.0.0",
  name: "Portfolio surveillance",
  description: "Deterministic certified portfolio surveillance.",
  calculationEngine: {
    engineId: "portfolio-surveillance-engine",
    engineVersion: "1.0.0",
    runtimeBundleHash: hash("surveillance-runtime")
  },
  requiredDefinitionKinds: ["metric_definition"],
  deterministicParameters: { maximumPeriods: 120 },
  approval: {
    status: "pending_durable_approval",
    authority: "governed_definition_v2_lifecycle"
  }
} as const;

const METRIC_DOCUMENT: MetricDefinitionV1 = {
  schemaVersion: "1",
  definitionType: "metric_definition",
  definitionId: "balance-utilization",
  version: 1,
  name: "Balance and utilization",
  family: "balance_utilization",
  grain: "loan",
  unit: "ratio",
  temporalSemantics: "point_in_time",
  numerator: {
    label: "Outstanding balance",
    aggregation: "sum",
    field: "outstanding_balance"
  },
  denominator: {
    label: "Commitment",
    aggregation: "sum",
    field: "commitment_amount"
  },
  window: { kind: "ever_to_date", maximumPeriods: 120 },
  population: null,
  nullPolicy: "unavailable",
  coverage: { minimumRatio: "1", minimumObservedRecords: 1 },
  privacy: { minimumCellCount: 1, complementarySuppression: true },
  maximumCells: 1_000,
  configuration: {
    kind: "balance_utilization",
    balanceField: "outstanding_balance",
    originalBalanceField: "original_balance",
    commitmentField: "commitment_amount"
  },
  approval: {
    status: "approved",
    proposedBy: "data-steward",
    approvedBy: "risk-reviewer",
    approvedAt: "2026-08-01T12:00:00.000Z"
  }
};

const METHODOLOGY = resolvedDefinition(
  "methodology-v1",
  "methodology_bundle",
  "portfolio-surveillance",
  METHODOLOGY_DOCUMENT
);
const METRIC = resolvedDefinition(
  "metric-balance-v1",
  "metric_definition",
  "balance-utilization",
  METRIC_DOCUMENT
);

test("portfolio surveillance descriptor and request are strict, self-describing, and ids-only", () => {
  assert.equal(PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR.operationId, "portfolio_surveillance_v1");
  assert.equal(PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR.requestMode, "ids_only");
  assert.equal(PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR.disclosurePolicy.mode, "aggregate_only");
  assert.equal(
    PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR.requestSchemaHash,
    PORTFOLIO_SURVEILLANCE_V1_SCHEMA_METADATA.request.schemaHash
  );
  assert.equal(
    PORTFOLIO_SURVEILLANCE_V1_INTEGRATION_PORTS.workerProcess.payload,
    "PortfolioSurveillanceWorkerPayloadV1"
  );

  assert.throws(() =>
    parsePortfolioSurveillanceOperationRequestV1({
      contractVersion: 1,
      operation: "portfolio_surveillance_v1",
      sources: [{ kind: "certification_manifest", certificationManifestId: "cert-jan" }],
      definitionVersionIds: ["methodology-v1", "metric-balance-v1"],
      snapshots: [{ raw: true }]
    })
  );
  assert.throws(() =>
    parsePortfolioSurveillanceOperationRequestV1({
      contractVersion: 1,
      operation: "portfolio_surveillance_v1",
      sources: [],
      definitionVersionIds: ["methodology-v1", "metric-balance-v1"]
    })
  );
});

test("parent planning yields a clone-safe least-privilege payload and pure deterministic aggregate execution", async () => {
  const jan = material("cert-jan", "snapshot-jan", "2026-01-31", "100", "200");
  const feb = material("cert-feb", "snapshot-feb", "2026-02-28", "120", "200");
  const authority = new FixtureAuthority([jan, feb]);
  const request = directRequest();
  const plan = await preparePortfolioSurveillanceExecutionPlanV1(
    request,
    { tenantId: TENANT, purpose: PURPOSE },
    authority
  );
  const cloned = structuredClone(plan);
  const reparsed = parsePortfolioSurveillanceExecutionPlanV1(cloned);

  assert.equal(reparsed.planHash, plan.planHash);
  assert.deepEqual(reparsed.requestedFields, FIELDS);
  assert.equal("sensitive_note" in reparsed.engineInput.snapshots[0]!.records[0]!, false);
  assert.equal(reparsed.sourceLineage[0]!.populationHash, jan.populationHash);
  assert.equal(
    reparsed.sourceLineage[0]!.projectedPopulationHash,
    canonicalHash(reparsed.engineInput.snapshots[0]!.records)
  );

  const result = executePortfolioSurveillanceOperationV1(reparsed);
  const repeated = executePortfolioSurveillanceOperationV1(structuredClone(reparsed));
  assert.equal(result.resultHash, repeated.resultHash);
  assert.equal(result.aggregate.metrics.length, 1);
  assert.equal(result.aggregate.asOfDates.length, 2);
  assertAggregateOnlyPortfolioSurveillanceResultV1(structuredClone(result), reparsed);

  const accounting = accountPortfolioSurveillanceOperationResultV1(result, reparsed);
  assert.equal(accounting.metricCount, 1);
  assert.equal(accounting.aggregateRows, result.aggregate.metrics[0]!.cells.length);
  assert.ok(accounting.bytes > 0);
  assert.ok(accounting.populationHashes.length > 0);

  const module = createPortfolioSurveillanceOperationModuleV1(authority);
  const viaModule = await module.prepare(
    module.parseRequest(request),
    { tenantId: TENANT, purpose: PURPOSE }
  );
  const moduleResult = module.execute(viaModule);
  assert.equal(moduleResult.resultHash, result.resultHash);
  assert.equal(module.accountResult(moduleResult, viaModule).metricCount, 1);
});

test("one longitudinal bundle expands its terminal period selections without accepting later replacements", async () => {
  const jan = material("cert-jan", "snapshot-jan", "2026-01-31", "100", "200");
  const feb = material("cert-feb", "snapshot-feb", "2026-02-28", "120", "200");
  const bundle = longitudinalBundle([jan, feb]);
  const authority = new FixtureAuthority([jan, feb], [bundle]);
  const request: PortfolioSurveillanceOperationRequestV1 = {
    contractVersion: 1,
    operation: "portfolio_surveillance_v1",
    sources: [{ kind: "longitudinal_bundle", longitudinalBundleId: bundle.bundleId }],
    definitionVersionIds: ["methodology-v1", "metric-balance-v1"]
  };
  const plan = await preparePortfolioSurveillanceExecutionPlanV1(
    request,
    { tenantId: TENANT, purpose: PURPOSE },
    authority
  );

  assert.equal(plan.sourceLineage.length, 2);
  assert.deepEqual(
    authority.snapshotRequests.map((item) => item.sourceKind),
    ["longitudinal_bundle", "longitudinal_bundle"]
  );
  assert.deepEqual(
    plan.sourceLineage.map(({ certificationManifestId }) => certificationManifestId),
    ["cert-jan", "cert-feb"]
  );
  assert.equal(plan.sourceLineage.every(({ longitudinalBundleHash }) => longitudinalBundleHash === bundle.bundleHash), true);
});

test("source, definition, plan, and aggregate disclosure evidence fail closed", async () => {
  const jan = material("cert-jan", "snapshot-jan", "2026-01-31", "100", "200");
  const feb = material("cert-feb", "snapshot-feb", "2026-02-28", "120", "200");
  const authority = new FixtureAuthority([jan, feb]);

  const badPopulation = structuredClone(jan) as Mutable<CertifiedSnapshotMaterialV1>;
  badPopulation.populationHash = hash("not-the-records");
  rehashMaterial(badPopulation);
  assert.throws(
    () => createCertifiedSnapshotMaterialV1(withoutMaterialHash(badPopulation)),
    (error: unknown) =>
      error instanceof ContractValidationError &&
      error.issues.some((issue) => issue.includes("populationHash"))
  );

  const badAuthorization = material(
    "cert-bad",
    "snapshot-bad",
    "2026-03-31",
    "130",
    "200",
    FIELDS.filter((field) => field !== "commitment_amount")
  );
  const unauthorized = new FixtureAuthority([jan, badAuthorization]);
  await assert.rejects(
    preparePortfolioSurveillanceExecutionPlanV1(
      {
        ...directRequest(),
        sources: [
          { kind: "certification_manifest", certificationManifestId: "cert-jan" },
          { kind: "certification_manifest", certificationManifestId: "cert-bad" }
        ]
      },
      { tenantId: TENANT, purpose: PURPOSE },
      unauthorized
    ),
    (error: unknown) => operationError(error, "DISCLOSURE_POLICY_VIOLATION")
  );

  const plan = await preparePortfolioSurveillanceExecutionPlanV1(
    directRequest(),
    { tenantId: TENANT, purpose: PURPOSE },
    authority
  );
  const result = executePortfolioSurveillanceOperationV1(plan);
  const smuggled = {
    ...structuredClone(result),
    rawRows: [{ loan_id: "L1" }]
  } as unknown as PortfolioSurveillanceOperationResultV1;
  const { resultHash: _oldHash, ...smuggledBody } = smuggled as unknown as Record<string, unknown>;
  (smuggled as Mutable<PortfolioSurveillanceOperationResultV1>).resultHash = canonicalHash(
    smuggledBody
  );
  assert.throws(
    () => assertAggregateOnlyPortfolioSurveillanceResultV1(smuggled, plan),
    (error: unknown) => operationError(error, "DISCLOSURE_POLICY_VIOLATION")
  );

  const dimensionSmuggled = structuredClone(result) as Mutable<typeof result>;
  const dimensionCell = dimensionSmuggled.aggregate.metrics[0]!.cells[0]!;
  dimensionCell.dimensions.raw_record = "loan-1";
  dimensionCell.cellId = stableFingerprint({
    schemaVersion: "1",
    definitionId: METRIC_DOCUMENT.definitionId,
    definitionVersion: METRIC_DOCUMENT.version,
    metric: dimensionCell.metric,
    dimensions: dimensionCell.dimensions
  });
  rehashOperationResult(dimensionSmuggled);
  assert.throws(
    () => assertAggregateOnlyPortfolioSurveillanceResultV1(dimensionSmuggled, plan),
    (error: unknown) => operationError(error, "DISCLOSURE_POLICY_VIOLATION")
  );

  const warningSmuggled = structuredClone(result) as Mutable<typeof result>;
  warningSmuggled.aggregate.metrics[0]!.warnings[0] = "raw borrower note";
  rehashOperationResult(warningSmuggled);
  assert.throws(
    () => assertAggregateOnlyPortfolioSurveillanceResultV1(warningSmuggled, plan),
    (error: unknown) => operationError(error, "DISCLOSURE_POLICY_VIOLATION")
  );

  const numericSmuggled = structuredClone(result) as Mutable<typeof result>;
  numericSmuggled.aggregate.metrics[0]!.cells[0]!.value = "760049";
  rehashOperationResult(numericSmuggled);
  assert.throws(
    () => assertAggregateOnlyPortfolioSurveillanceResultV1(numericSmuggled, plan),
    (error: unknown) => operationError(error, "DISCLOSURE_POLICY_VIOLATION")
  );

  const tampered = structuredClone(plan) as Mutable<typeof plan>;
  (tampered.engineInput.snapshots[0]!.records[0]! as Record<string, CanonicalJsonValue>)[
    "sensitive_note"
  ] = "leak";
  const { planHash: _planHash, ...tamperedBody } = tampered;
  tampered.planHash = canonicalHash(tamperedBody);
  assert.throws(
    () => parsePortfolioSurveillanceExecutionPlanV1(tampered),
    (error: unknown) => operationError(error, "PLAN_INTEGRITY_FAILURE")
  );
});

test("longitudinal row budgets are preflighted before any normalized artifact is loaded", async () => {
  const first = material("cert-huge-1", "snapshot-huge-1", "2026-01-31", "1", "1");
  const second = material("cert-huge-2", "snapshot-huge-2", "2026-02-28", "1", "1");
  const bundle = longitudinalBundle([first, second], 3_000_000);
  const authority = new FixtureAuthority([], [bundle]);

  await assert.rejects(
    preparePortfolioSurveillanceExecutionPlanV1(
      {
        contractVersion: 1,
        operation: "portfolio_surveillance_v1",
        sources: [{ kind: "longitudinal_bundle", longitudinalBundleId: bundle.bundleId }],
        definitionVersionIds: ["methodology-v1", "metric-balance-v1"]
      },
      { tenantId: TENANT, purpose: PURPOSE },
      authority
    ),
    (error: unknown) => operationError(error, "INVALID_REQUEST")
  );
  assert.equal(authority.snapshotRequests.length, 0);
});

test("frozen metric declarations must match the hard-coded family execution semantics", async () => {
  const jan = material("cert-jan", "snapshot-jan", "2026-01-31", "100", "200");
  const feb = material("cert-feb", "snapshot-feb", "2026-02-28", "120", "200");
  const authority = new FixtureAuthority([jan, feb]);
  const incompatible = {
    ...METRIC_DOCUMENT,
    temporalSemantics: "transition" as const,
    numerator: {
      ...METRIC_DOCUMENT.numerator,
      field: "unused_amount"
    }
  };
  authority.definitions.set(
    METRIC.reference.definitionVersionId,
    resolvedDefinition(
      METRIC.reference.definitionVersionId,
      "metric_definition",
      METRIC.reference.definitionKey,
      incompatible
    )
  );

  await assert.rejects(
    preparePortfolioSurveillanceExecutionPlanV1(
      directRequest(),
      { tenantId: TENANT, purpose: PURPOSE },
      authority
    ),
    (error: unknown) => operationError(error, "DEFINITION_EVIDENCE_MISMATCH")
  );
  assert.equal(authority.snapshotRequests.length, 0);
});

test("every metric family binds its declared grain, aggregation, and measure fields", () => {
  const compatible = [
    compatibilityMetric({
      kind: "roll_cure",
      delinquencyField: "days_past_due",
      balanceField: "outstanding_balance",
      binDefinitionId: "dpd-bands"
    }),
    compatibilityMetric({
      kind: "default_ever",
      defaultFlagField: "default_flag",
      daysPastDueField: "days_past_due",
      balanceField: "outstanding_balance",
      everDpdThresholds: [30, 60, 90],
      incidenceBasis: "count"
    }),
    compatibilityMetric({
      kind: "loss_recovery",
      grossLossField: "charge_off_amount",
      recoveryField: "recovery_amount",
      denominatorField: "original_balance",
      defaultDateField: "default_date",
      flowSemantics: "period"
    }),
    compatibilityMetric({
      kind: "paydown_prepayment",
      balanceField: "outstanding_balance",
      scheduledPrincipalField: "scheduled_principal_amount"
    }),
    compatibilityMetric({
      kind: "rating_migration",
      ratingField: "risk_rating",
      balanceField: "outstanding_balance"
    }),
    compatibilityMetric({
      kind: "balance_utilization",
      balanceField: "outstanding_balance",
      originalBalanceField: "original_balance",
      commitmentField: "commitment_amount"
    }),
    compatibilityMetric({
      kind: "maturity_wall",
      maturityDateField: "maturity_date",
      balanceField: "outstanding_balance",
      windows: [{ label: "0-12 months", endingMonth: 12 }],
      includeMatured: true
    }),
    compatibilityMetric({
      kind: "concentration",
      dimensionField: "industry_code",
      balanceField: "outstanding_balance",
      topN: 10
    }),
    compatibilityMetric({
      kind: "period_comparison",
      balanceField: "outstanding_balance"
    })
  ];
  for (const definition of compatible) {
    assert.doesNotThrow(() => assertPortfolioSurveillanceMetricCompatibilityV1(definition));
  }

  const balance = compatible.find(({ family }) => family === "balance_utilization")!;
  const weightedBalance: MetricDefinitionV1 = {
    ...balance,
    numerator: { ...balance.numerator, aggregation: "weighted_average" },
    denominator: { ...balance.denominator!, aggregation: "weighted_average" }
  };
  assert.throws(
    () => assertPortfolioSurveillanceMetricCompatibilityV1(weightedBalance),
    (error: unknown) => operationError(error, "DEFINITION_EVIDENCE_MISMATCH")
  );

  const roll = compatible.find(({ family }) => family === "roll_cure")!;
  const countRoll: MetricDefinitionV1 = {
    ...roll,
    numerator: { label: "Transitions", aggregation: "count" },
    denominator: { label: "Opening population", aggregation: "count" }
  };
  assert.throws(
    () => assertPortfolioSurveillanceMetricCompatibilityV1(countRoll),
    (error: unknown) => operationError(error, "DEFINITION_EVIDENCE_MISMATCH")
  );

  const portfolioGrain: MetricDefinitionV1 = { ...roll, grain: "portfolio" };
  assert.throws(
    () => assertPortfolioSurveillanceMetricCompatibilityV1(portfolioGrain),
    (error: unknown) => operationError(error, "DEFINITION_EVIDENCE_MISMATCH")
  );
});

test("raw aggregate dimensions fail closed unless dictionary policy permits unmasked categories", async () => {
  const jan = material("cert-jan", "snapshot-jan", "2026-01-31", "100", "200");
  const feb = material("cert-feb", "snapshot-feb", "2026-02-28", "120", "200");
  const authority = new FixtureAuthority([jan, feb]);
  const deniedDimension = {
    ...METRIC_DOCUMENT,
    definitionId: "unsafe-comparison",
    name: "Unsafe comparison",
    family: "period_comparison" as const,
    temporalSemantics: "transition" as const,
    numerator: {
      label: "Change",
      aggregation: "sum" as const,
      field: "outstanding_balance"
    },
    denominator: {
      label: "Opening balance",
      aggregation: "sum" as const,
      field: "outstanding_balance"
    },
    window: { kind: "adjacent_periods" as const, maximumPeriods: 120 },
    configuration: {
      kind: "period_comparison" as const,
      balanceField: "outstanding_balance",
      dimensionField: "loan_id"
    }
  };
  authority.definitions.set(
    "metric-unsafe-v1",
    resolvedDefinition(
      "metric-unsafe-v1",
      "metric_definition",
      "unsafe-comparison",
      deniedDimension
    )
  );

  await assert.rejects(
    preparePortfolioSurveillanceExecutionPlanV1(
      {
        ...directRequest(),
        definitionVersionIds: ["methodology-v1", "metric-unsafe-v1"]
      },
      { tenantId: TENANT, purpose: PURPOSE },
      authority
    ),
    (error: unknown) => operationError(error, "DISCLOSURE_POLICY_VIOLATION")
  );
  assert.equal(authority.snapshotRequests.length, 0);
});

function compatibilityMetric(configuration: MetricConfigurationV1): MetricDefinitionV1 {
  let temporalSemantics: MetricDefinitionV1["temporalSemantics"];
  let windowKind: MetricDefinitionV1["window"]["kind"];
  let grain: MetricDefinitionV1["grain"] = "loan";
  let aggregation: MetricDefinitionV1["numerator"]["aggregation"] = "sum";
  let numeratorField: string | undefined;
  let denominatorField: string | undefined;
  switch (configuration.kind) {
    case "roll_cure":
      temporalSemantics = "transition";
      windowKind = "adjacent_periods";
      numeratorField = configuration.balanceField;
      denominatorField = configuration.balanceField;
      break;
    case "default_ever":
      temporalSemantics = "cumulative";
      windowKind = "ever_to_date";
      if (configuration.incidenceBasis === "count") {
        aggregation = "count";
      } else {
        numeratorField = configuration.balanceField;
        denominatorField = configuration.balanceField;
      }
      break;
    case "loss_recovery":
      temporalSemantics = configuration.flowSemantics === "period" ? "period_flow" : "cumulative";
      windowKind = "event_lag";
      numeratorField = configuration.grossLossField;
      denominatorField = configuration.denominatorField;
      break;
    case "paydown_prepayment":
      temporalSemantics = "transition";
      windowKind = "adjacent_periods";
      numeratorField = configuration.balanceField;
      denominatorField = configuration.balanceField;
      break;
    case "rating_migration":
      temporalSemantics = "transition";
      windowKind = "adjacent_periods";
      numeratorField = configuration.balanceField;
      denominatorField = configuration.balanceField;
      break;
    case "balance_utilization":
      temporalSemantics = "point_in_time";
      windowKind = "snapshot";
      numeratorField = configuration.balanceField;
      denominatorField = configuration.commitmentField;
      break;
    case "maturity_wall":
      temporalSemantics = "point_in_time";
      windowKind = "snapshot";
      numeratorField = configuration.balanceField;
      denominatorField = configuration.balanceField;
      break;
    case "concentration":
      temporalSemantics = "point_in_time";
      windowKind = "snapshot";
      grain = "entity";
      numeratorField = configuration.balanceField;
      denominatorField = configuration.balanceField;
      break;
    case "period_comparison":
      temporalSemantics = "transition";
      windowKind = "adjacent_periods";
      numeratorField = configuration.balanceField;
      denominatorField = configuration.balanceField;
      break;
  }
  const numerator: MetricDefinitionV1["numerator"] =
    numeratorField === undefined
      ? { label: "Numerator", aggregation }
      : { label: "Numerator", aggregation, field: numeratorField };
  const denominator: NonNullable<MetricDefinitionV1["denominator"]> =
    denominatorField === undefined
      ? { label: "Denominator", aggregation }
      : { label: "Denominator", aggregation, field: denominatorField };
  return {
    schemaVersion: "1",
    definitionType: "metric_definition",
    definitionId: `compat-${configuration.kind}`,
    version: 1,
    name: `Compatible ${configuration.kind}`,
    family: configuration.kind,
    grain,
    unit: "ratio",
    temporalSemantics,
    numerator,
    denominator,
    window: { kind: windowKind, maximumPeriods: 12 },
    population: null,
    nullPolicy: "unavailable",
    coverage: { minimumRatio: "1", minimumObservedRecords: 1 },
    privacy: { minimumCellCount: 1, complementarySuppression: true },
    maximumCells: 10_000,
    configuration,
    approval: METRIC_DOCUMENT.approval
  };
}

function rehashOperationResult(
  value: Mutable<PortfolioSurveillanceOperationResultV1>
): void {
  for (const metric of value.aggregate.metrics) {
    const { analysisHash: _metricHash, ...metricLineage } = metric.lineage;
    metric.lineage.analysisHash = stableFingerprint({
      schemaVersion: metric.schemaVersion,
      metricDefinitionId: metric.metricDefinitionId,
      metricDefinitionVersion: metric.metricDefinitionVersion,
      family: metric.family,
      cells: metric.cells,
      warnings: metric.warnings,
      lineage: metricLineage
    });
  }
  const { analysisHash: _aggregateHash, ...aggregateLineage } = value.aggregate.lineage;
  value.aggregate.lineage.analysisHash = stableFingerprint({
    schemaVersion: value.aggregate.schemaVersion,
    tenantId: value.aggregate.tenantId,
    asOfDates: value.aggregate.asOfDates,
    metrics: value.aggregate.metrics,
    lineage: aggregateLineage
  });
  const { resultHash: _resultHash, ...body } = value;
  value.resultHash = canonicalHash(body);
}

function directRequest(): PortfolioSurveillanceOperationRequestV1 {
  return {
    contractVersion: 1,
    operation: "portfolio_surveillance_v1",
    sources: [
      { kind: "certification_manifest", certificationManifestId: "cert-feb" },
      { kind: "certification_manifest", certificationManifestId: "cert-jan" }
    ],
    definitionVersionIds: ["metric-balance-v1", "methodology-v1"]
  };
}

function material(
  certificationManifestId: string,
  snapshotId: string,
  asOfDate: string,
  outstanding: string,
  commitment: string,
  authorizedFields: readonly string[] = FIELDS
): CertifiedSnapshotMaterialV1 {
  const records = [
    {
      as_of_date: asOfDate,
      source_system: "core",
      facility_id: "facility-a",
      loan_id: "loan-1",
      outstanding_balance: outstanding,
      original_balance: "150",
      commitment_amount: commitment,
      sensitive_note: "must-not-enter-worker"
    }
  ];
  return createCertifiedSnapshotMaterialV1({
    contractVersion: 1,
    tenantId: TENANT,
    datasetId: "loan-tape",
    source: sourceIdentity(),
    scope: { scopeType: "portfolio", scopeId: "portfolio-a" },
    authorizedPurpose: PURPOSE,
    authorizedFields: [...authorizedFields].sort(),
    authorizedAggregateDimensionFields: [],
    certificationManifestId,
    certificationManifestHash: hash(`manifest:${certificationManifestId}`),
    populationHash: canonicalHash(records),
    normalizedArtifact: {
      artifactId: `artifact-${snapshotId}`,
      contentHash: hash(`artifact-content:${snapshotId}`)
    },
    rowCount: records.length,
    snapshot: {
      schemaVersion: "1",
      snapshotId,
      tenantId: TENANT,
      asOfDate,
      snapshotHash: hash(`snapshot:${snapshotId}`),
      certification: {
        status: "certified",
        certificationId: certificationManifestId,
        certificationHash: hash(`manifest:${certificationManifestId}`),
        certifiedAt: "2026-08-10T12:00:00.000Z"
      },
      records
    }
  });
}

function longitudinalBundle(
  materials: readonly CertifiedSnapshotMaterialV1[],
  certifiedRowCount?: number
): LongitudinalCertificationBundleV1 {
  const methodologyHash = portfolioSurveillanceMethodologyHashV1(METHODOLOGY_DOCUMENT);
  const periods = materials.map((material, index) => {
    const rowCount = certifiedRowCount ?? material.rowCount;
    const populationHash = certifiedRowCount === undefined ? material.populationHash : hash(`huge-pop:${index}`);
    const revision = {
      revisionSequence: 1,
      tenantId: TENANT,
      datasetId: material.datasetId,
      source: material.source,
      scope: material.scope,
      certification: {
        certificationManifestId: material.certificationManifestId,
        certificationManifestHash: material.certificationManifestHash,
        certifiedAt: material.snapshot.certification.certifiedAt
      },
      snapshot: {
        snapshotId: material.snapshot.snapshotId,
        asOfDate: material.snapshot.asOfDate,
        snapshotHash: material.snapshot.snapshotHash
      },
      delivery: {
        deliveryId: `delivery-${material.snapshot.snapshotId}`,
        deliveryMode: "postgresql_pull" as const,
        deliveredContentHash: hash(`delivery:${material.snapshot.snapshotId}`)
      },
      correction: { kind: "original" as const },
      dictionary: {
        dictionaryBundleId: "canonical-dictionary",
        version: "1.0.0",
        dictionaryHash: hash("dictionary")
      },
      mapping: {
        mappingApplicationId: `mapping-${material.snapshot.snapshotId}`,
        mappingApplicationHash: hash(`mapping:${material.snapshot.snapshotId}`),
        mappingSpecId: "loan-mapping",
        mappingSpecHash: hash("mapping-spec"),
        runtime: {
          runtimeBundleId: "mapping-runtime",
          runtimeVersion: "1.0.0",
          runtimeBundleHash: hash("mapping-runtime"),
          compilerHash: hash("mapping-compiler")
        }
      },
      normalizedArtifact: material.normalizedArtifact,
      rowCount,
      populationHash
    };
    return {
      sequence: index + 1,
      asOfDate: material.snapshot.asOfDate,
      revisions: [revision],
      analyticsSelection: {
        revisionSequence: 1,
        certificationManifestId: revision.certification.certificationManifestId,
        certificationManifestHash: revision.certification.certificationManifestHash,
        snapshotId: revision.snapshot.snapshotId,
        snapshotHash: revision.snapshot.snapshotHash,
        normalizedArtifactContentHash: revision.normalizedArtifact.contentHash,
        populationHash: revision.populationHash
      }
    };
  });
  const body = {
    contractVersion: 1 as const,
    bundleId: "portfolio-history",
    tenantId: TENANT,
    datasetId: "loan-tape",
    source: sourceIdentity(),
    scope: { scopeType: "portfolio" as const, scopeId: "portfolio-a" },
    purpose: PURPOSE,
    methodology: {
      methodologyId: "portfolio-surveillance",
      definitionVersionId: METHODOLOGY.reference.definitionVersionId,
      version: METHODOLOGY.reference.semanticVersion,
      versionHash: METHODOLOGY.reference.versionHash,
      documentHash: METHODOLOGY.reference.documentHash,
      methodologyHash,
      approvalEventHash: METHODOLOGY.reference.approvalEventHash,
      approvedAt: METHODOLOGY.approvalEvidence.approvedAt
    },
    periodCount: periods.length,
    certificationCount: periods.length,
    firstAsOfDate: periods[0]!.asOfDate,
    lastAsOfDate: periods.at(-1)!.asOfDate,
    periods,
    createdBy: "risk-reviewer",
    createdAt: "2026-08-12T12:00:00.000Z"
  };
  return { ...body, bundleHash: canonicalHash(body) };
}

class FixtureAuthority implements PortfolioSurveillanceOperationAuthorityV1 {
  readonly materials = new Map<string, CertifiedSnapshotMaterialV1>();
  readonly bundles = new Map<string, LongitudinalCertificationBundleV1>();
  readonly definitions = new Map<string, ResolvedGovernedDefinitionV2>([
    [METHODOLOGY.reference.definitionVersionId, METHODOLOGY],
    [METRIC.reference.definitionVersionId, METRIC]
  ]);
  readonly snapshotRequests: PortfolioSurveillanceSnapshotLoadRequestV1[] = [];

  constructor(
    materials: readonly CertifiedSnapshotMaterialV1[],
    bundles: readonly LongitudinalCertificationBundleV1[] = []
  ) {
    for (const value of materials) this.materials.set(value.certificationManifestId, value);
    for (const value of bundles) this.bundles.set(value.bundleId, value);
  }

  loadLongitudinalBundle(tenantId: string, longitudinalBundleId: string): unknown | undefined {
    return tenantId === TENANT ? this.bundles.get(longitudinalBundleId) : undefined;
  }

  loadCertifiedSnapshot(input: PortfolioSurveillanceSnapshotLoadRequestV1): unknown | undefined {
    this.snapshotRequests.push(structuredClone(input));
    const value = this.materials.get(input.certificationManifestId);
    if (value === undefined || input.tenantId !== TENANT) return undefined;
    if (input.sourceKind === "longitudinal_bundle") {
      if (
        value.certificationManifestHash !== input.certificationManifestHash ||
        value.populationHash !== input.populationHash ||
        value.snapshot.snapshotId !== input.snapshotId ||
        value.snapshot.snapshotHash !== input.snapshotHash ||
        value.normalizedArtifact.artifactId !== input.normalizedArtifactId ||
        value.normalizedArtifact.contentHash !== input.normalizedArtifactContentHash
      ) {
        return undefined;
      }
    }
    return value;
  }

  resolveFrozenDefinition(
    tenantId: string,
    definitionVersionId: string
  ): ResolvedGovernedDefinitionV2 | undefined {
    return tenantId === TENANT ? this.definitions.get(definitionVersionId) : undefined;
  }
}

function resolvedDefinition(
  definitionVersionId: string,
  kind: "methodology_bundle" | "metric_definition",
  definitionKey: string,
  executionDocument: CanonicalJsonValue
): ResolvedGovernedDefinitionV2 {
  const approvalEventHash = hash(`approval:${definitionVersionId}`);
  return {
    reference: {
      definitionVersionId,
      definitionKey,
      kind,
      semanticVersion: "1.0.0",
      versionHash: hash(`version:${definitionVersionId}`),
      documentHash: canonicalHash(executionDocument),
      approvalEventHash
    },
    approvalEvidence: {
      status: "approved",
      proposedBy: "data-steward",
      approvedBy: "risk-reviewer",
      approvedAt: "2026-08-01T12:00:00.000Z",
      approvalEventHash
    },
    executionDocument
  };
}

function sourceIdentity() {
  return {
    sourceContractId: "loan-source-v1",
    sourceKey: "loan-source",
    revision: 1,
    sourceContractHash: hash("source-contract")
  };
}

function hash(value: string): Sha256Hash {
  return canonicalHash(value);
}

function withoutMaterialHash(
  value: CertifiedSnapshotMaterialV1
): Omit<CertifiedSnapshotMaterialV1, "materialHash"> {
  const { materialHash: _materialHash, ...body } = value;
  return body;
}

function rehashMaterial(value: Mutable<CertifiedSnapshotMaterialV1>): void {
  const { materialHash: _materialHash, ...body } = value;
  value.materialHash = canonicalHash(body);
}

function operationError(
  error: unknown,
  code: PortfolioSurveillanceOperationError["code"]
): boolean {
  return error instanceof PortfolioSurveillanceOperationError && error.code === code;
}

type Mutable<T> = { -readonly [Key in keyof T]: Mutable<T[Key]> };
