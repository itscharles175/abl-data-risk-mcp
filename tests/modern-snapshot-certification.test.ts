import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import {
  canonicalHash,
  createDatasetSnapshotV2,
  createGovernedDatasetScopeBindingV1,
  createHistoricalRuntimeBundleV1,
  createMappingSpecV2,
  createSnapshotCertificationAttemptV1,
  createSourceContractV1,
  InMemoryHistoricalRuntimeResolver,
  type DatasetSnapshotV2,
  type DictionaryBundleReferenceV1,
  type GovernedDatasetScopeBindingV1,
  type ImmutableBundleReferenceV1,
  type Sha256Hash,
  type SnapshotCertificationAttemptV1,
  type SourceContractV1
} from "../src/contracts/index.js";
import {
  createGovernedSourceDeliveryRecordV1,
  type GovernedSourceDeliveryRecordV1,
  type GovernedSourceDeliveryResolutionV1
} from "../src/contracts/source-delivery-authority-v1.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import { InMemoryImmutableRepository } from "../src/repositories/in-memory.js";
import {
  SqliteSurveillanceEvidenceRepositories
} from "../src/repositories/sqlite-surveillance.js";
import { SqliteCertificationArtifactStagingStoreV1 } from "../src/repositories/certification-artifact-staging-v1.js";
import type {
  SnapshotCertificationAttemptStoreV1,
  StartSnapshotCertificationAttemptV1
} from "../src/repositories/snapshot-certification-attempts-v1.js";
import {
  ModernSnapshotCertificationError,
  ModernSnapshotCertificationService,
  type CapturedSourcePopulationV2,
  type CertifySnapshotV2Request,
  type ModernCertificationDefinitionResolutionV1
} from "../src/services/modern-snapshot-certification.js";
import {
  modernSnapshotExtractionReceiptIdV1,
  parseModernSnapshotExtractionReceiptV1,
  type ModernSnapshotExtractionReceiptV1
} from "../src/services/modern-snapshot-capture.js";

const directories: string[] = [];
const hash = (value: unknown): Sha256Hash => canonicalHash(value);

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("modern certification reloads governed inputs, persists encrypted normalized evidence, and replays by ids", async () => {
  const fixture = await createFixture();
  try {
    const first = await fixture.service.certify(fixture.request, fixture.actor);
    assert.equal(first.replayed, false);
    assert.equal(first.evidence.certification.evidenceFormat, "modern_snapshot_v2");
    assert.equal(first.evidence.mappingSpec.mappingSpecId, "mapping-spec-1");
    assert.equal(first.evidence.mappingApplication.runtimeBundle.runtimeBundleId, "runtime-1");
    assert.equal(first.evidence.population.dataQuality.publicationDecision, "publish");
    assert.equal(first.evidence.population.reconciliation.passed, true);
    assert.equal(first.evidence.population.rowCount, 2);

    const loaded = fixture.artifacts.getJson(
      fixture.actor.tenantId,
      first.evidence.normalizedArtifact.artifactId
    );
    assert.equal(loaded.metadata.keyId, "test-key");
    assert.equal(first.evidence.normalizedArtifact.uri, loaded.metadata.uri);

    const replay = await fixture.service.certify(fixture.request, fixture.actor);
    assert.equal(replay.replayed, true);
    assert.equal(replay.evidence.evidenceHash, first.evidence.evidenceHash);
    assert.equal(fixture.sourceLoads, 2);
    assert.equal(fixture.definitionLoads, 1);
  } finally {
    fixture.close();
  }
});

test("exact certified replay does not consult mutable live-delivery authority", async () => {
  const fixture = await createFixture();
  try {
    const first = await fixture.service.certify(fixture.request, fixture.actor);
    assert.equal(fixture.deliveryLoads, 1);
    fixture.makeDeliveryUnavailable();

    const replay = await fixture.service.certify(fixture.request, fixture.actor);
    assert.equal(replay.replayed, true);
    assert.equal(replay.evidence.evidenceHash, first.evidence.evidenceHash);
    assert.equal(fixture.deliveryLoads, 1);
  } finally {
    fixture.close();
  }
});

test("a failed evidence write reuses its immutable certification attempt and normalized artifact", async () => {
  const fixture = await createFixture({ evidencePutFailsOnce: true });
  try {
    await assert.rejects(
      () => fixture.service.certify(fixture.request, fixture.actor),
      /simulated evidence persistence failure/
    );
    assert.equal(fixture.artifactWrites, 1);
    fixture.setNow("2026-08-02T11:00:00.000Z");

    const retry = await fixture.service.certify(fixture.request, fixture.actor);
    assert.equal(retry.replayed, false);
    assert.equal(retry.evidence.certification.certifiedAt, "2026-08-02T10:00:00.000Z");
    assert.equal(retry.evidence.normalizedArtifact.createdAt, "2026-08-02T10:00:00.000Z");
    assert.equal(fixture.artifactWrites, 2);
    assert.deepEqual(fixture.artifactIds, [
      retry.evidence.normalizedArtifact.artifactId,
      retry.evidence.normalizedArtifact.artifactId
    ]);

    const replay = await fixture.service.certify(fixture.request, fixture.actor);
    assert.equal(replay.replayed, true);
    assert.equal(replay.evidence.evidenceHash, retry.evidence.evidenceHash);
  } finally {
    fixture.close();
  }
});

test("optional artifact staging preserves failure lineage, commits the exact evidence, and verifies replay", async () => {
  const fixture = await createFixture({ evidencePutFailsOnce: true, artifactStaging: true });
  try {
    await assert.rejects(
      () => fixture.service.certify(fixture.request, fixture.actor),
      /simulated evidence persistence failure/
    );
    const failed = await fixture.staging?.get({
      tenantId: fixture.actor.tenantId,
      certificationManifestId: fixture.certificationManifestId
    });
    assert.equal(failed?.state, "evidence_commit_failed");
    assert.equal(failed?.events.length, 2);
    assert.equal(failed?.events[1]?.eventType, "certification_evidence_failed");
    assert.notEqual(failed?.latestFailureHash, undefined);

    fixture.setNow("2026-08-02T11:00:00.000Z");
    const retried = await fixture.service.certify(fixture.request, fixture.actor);
    assert.equal(retried.replayed, false);
    const committed = await fixture.staging?.get({
      tenantId: fixture.actor.tenantId,
      certificationManifestId: fixture.certificationManifestId
    });
    assert.equal(committed?.state, "evidence_committed");
    assert.equal(committed?.certificationEvidenceHash, retried.evidence.evidenceHash);
    assert.equal(committed?.events.length, 3);
    assert.equal(committed?.stage.preparedAt, "2026-08-02T10:00:00.000Z");

    const replay = await fixture.service.certify(fixture.request, fixture.actor);
    assert.equal(replay.replayed, true);
    const replayedStage = await fixture.staging?.get({
      tenantId: fixture.actor.tenantId,
      certificationManifestId: fixture.certificationManifestId
    });
    assert.equal(replayedStage?.events.length, 3);
    assert.equal(replayedStage?.certificationEvidenceHash, replay.evidence.evidenceHash);
  } finally {
    fixture.close();
  }
});

test("certification rejects caller-supplied quantitative fields and cross-actor manifest reuse", async () => {
  const fixture = await createFixture();
  try {
    await assert.rejects(
      fixture.service.certify(
        {
          ...fixture.request,
          mappingApplicationId: "caller-mapping",
          normalizedPopulationId: "caller-population",
          certificationManifestId: "caller-manifest",
          idempotencyKey: "caller-key",
          populationHash: hash("caller-value")
        } as never,
        fixture.actor
      ),
      certificationCode("INVALID_REQUEST")
    );
    await assert.rejects(
      fixture.service.certify(fixture.request, {
        tenantId: fixture.actor.tenantId,
        actorId: "forged-operator"
      } as never),
      certificationCode("OPERATOR_REQUIRED")
    );

    await fixture.service.certify(fixture.request, fixture.actor);
    await assert.rejects(
      fixture.service.certify(fixture.request, { ...fixture.actor, actorId: "other-checker" }),
      certificationCode("INTEGRITY_FAILURE")
    );
  } finally {
    fixture.close();
  }
});

test("certification fails before mapping when declared supplemental evidence is absent", async () => {
  const fixture = await createFixture({ waterfallPresent: false });
  try {
    await assert.rejects(
      fixture.service.certify(fixture.request, fixture.actor),
      certificationCode("MISSING_REQUIRED_EVIDENCE")
    );
    assert.equal(fixture.sourceLoads, 0);
    assert.equal(
      await fixture.repositories.certifiedSnapshotEvidence.get(
        fixture.actor.tenantId,
        certificationManifestId(fixture.actor.tenantId, fixture.request.snapshotId)
      ),
      undefined
    );
    assert.equal(fixture.artifactWrites, 0);
  } finally {
    fixture.close();
  }
});

test("certification writes no evidence when deterministic DQ or reconciliation controls fail", async () => {
  const dqFixture = await createFixture({ duplicateLoanId: true });
  try {
    await assert.rejects(
      dqFixture.service.certify(dqFixture.request, dqFixture.actor),
      certificationCode("DATA_QUALITY_FAILED")
    );
    assert.equal(
      await dqFixture.repositories.certifiedSnapshotEvidence.get(
        dqFixture.actor.tenantId,
        certificationManifestId(dqFixture.actor.tenantId, dqFixture.request.snapshotId)
      ),
      undefined
    );
    assert.equal(dqFixture.artifactWrites, 0);
  } finally {
    dqFixture.close();
  }

  const reconciliationFixture = await createFixture({ expectedBalance: "301" });
  try {
    await assert.rejects(
      reconciliationFixture.service.certify(
        reconciliationFixture.request,
        reconciliationFixture.actor
      ),
      certificationCode("RECONCILIATION_FAILED")
    );
    assert.equal(
      await reconciliationFixture.repositories.certifiedSnapshotEvidence.get(
        reconciliationFixture.actor.tenantId,
        certificationManifestId(
          reconciliationFixture.actor.tenantId,
          reconciliationFixture.request.snapshotId
        )
      ),
      undefined
    );
    assert.equal(reconciliationFixture.artifactWrites, 0);
  } finally {
    reconciliationFixture.close();
  }
});

test("certification exact-verifies every supplemental section population", async () => {
  const fixture = await createFixture({ tamperWaterfallPopulation: true });
  try {
    await assert.rejects(
      fixture.service.certify(fixture.request, fixture.actor),
      certificationCode("INTEGRITY_FAILURE")
    );
    assert.equal(fixture.artifactWrites, 0);
  } finally {
    fixture.close();
  }
});

test("certification rejects mismatched runtime/dictionary lineage", async () => {
  const fixture = await createFixture({ mismatchedRuntimeDictionary: true });
  try {
    await assert.rejects(
      fixture.service.certify(fixture.request, fixture.actor),
      certificationCode("INTEGRITY_FAILURE")
    );
  } finally {
    fixture.close();
  }
});

test("certification rejects runtime activation after its immutable attempt time", async () => {
  const fixture = await createFixture({ runtimeActivatedAfterAttempt: true });
  try {
    await assert.rejects(
      fixture.service.certify(fixture.request, fixture.actor),
      certificationCode("INTEGRITY_FAILURE")
    );
    assert.equal(fixture.artifactWrites, 0);
  } finally {
    fixture.close();
  }
});

test("certification fails closed when its deterministic extraction receipt is absent or tampered", async () => {
  const absent = await createFixture({ receiptAbsent: true });
  try {
    await assert.rejects(
      absent.service.certify(absent.request, absent.actor),
      certificationCode("MISSING_REQUIRED_EVIDENCE")
    );
    assert.equal(absent.definitionLoads, 0);
    assert.equal(absent.artifactWrites, 0);
  } finally {
    absent.close();
  }

  const tampered = await createFixture({ tamperReceipt: true });
  try {
    await assert.rejects(
      tampered.service.certify(tampered.request, tampered.actor),
      certificationCode("INTEGRITY_FAILURE")
    );
    assert.equal(tampered.definitionLoads, 0);
    assert.equal(tampered.artifactWrites, 0);
  } finally {
    tampered.close();
  }
});

test("certification rejects delivery tamper and valid cross-facility substitution", async () => {
  const tampered = await createFixture({ tamperDelivery: true });
  try {
    await assert.rejects(
      tampered.service.certify(tampered.request, tampered.actor),
      certificationCode("INTEGRITY_FAILURE")
    );
    assert.equal(tampered.definitionLoads, 0);
  } finally {
    tampered.close();
  }

  const substituted = await createFixture({ substituteFacility: true });
  try {
    await assert.rejects(
      substituted.service.certify(substituted.request, substituted.actor),
      certificationCode("INTEGRITY_FAILURE")
    );
    assert.equal(substituted.definitionLoads, 0);
  } finally {
    substituted.close();
  }
});

test("certification rejects compromised source and scope documents from the delivery port", async () => {
  const sourceTamper = await createFixture({ tamperSourceDocument: true });
  try {
    await assert.rejects(
      sourceTamper.service.certify(sourceTamper.request, sourceTamper.actor),
      certificationCode("INTEGRITY_FAILURE")
    );
    assert.equal(sourceTamper.definitionLoads, 0);
  } finally {
    sourceTamper.close();
  }

  const forgedBinding = await createFixture({ forgeBindingDocument: true });
  try {
    await assert.rejects(
      forgedBinding.service.certify(forgedBinding.request, forgedBinding.actor),
      certificationCode("INTEGRITY_FAILURE")
    );
    assert.equal(forgedBinding.definitionLoads, 0);
  } finally {
    forgedBinding.close();
  }
});

test("certification treats effectiveTo as the exclusive end of every definition window", async () => {
  const fixture = await createFixture({ effectiveTo: "2026-07-31" });
  try {
    await assert.rejects(
      fixture.service.certify(fixture.request, fixture.actor),
      certificationCode("INACTIVE_DEFINITION")
    );
    assert.equal(fixture.definitionLoads, 1);
    assert.equal(fixture.sourceLoads, 0);
    assert.equal(fixture.artifactWrites, 0);
  } finally {
    fixture.close();
  }
});

interface FixtureOptions {
  readonly waterfallPresent?: boolean;
  readonly duplicateLoanId?: boolean;
  readonly expectedBalance?: string;
  readonly mismatchedRuntimeDictionary?: boolean;
  readonly tamperWaterfallPopulation?: boolean;
  readonly receiptAbsent?: boolean;
  readonly tamperReceipt?: boolean;
  readonly tamperDelivery?: boolean;
  readonly substituteFacility?: boolean;
  readonly tamperSourceDocument?: boolean;
  readonly forgeBindingDocument?: boolean;
  readonly effectiveTo?: string;
  readonly evidencePutFailsOnce?: boolean;
  readonly artifactStaging?: boolean;
  readonly runtimeActivatedAfterAttempt?: boolean;
}

async function createFixture(options: FixtureOptions = {}) {
  const directory = temporaryDirectory();
  const databasePath = join(directory, "evidence.sqlite");
  const repositories = new SqliteSurveillanceEvidenceRepositories(databasePath);
  const artifacts = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "test-key",
    keys: { "test-key": Buffer.alloc(32, 23) }
  });
  const records = [
    { loan_no: "loan-1", balance: "100", portfolio: "portfolio-1", currency: "USD" },
    {
      loan_no: options.duplicateLoanId ? "loan-1" : "loan-2",
      balance: "200",
      portfolio: "portfolio-1",
      currency: "USD"
    }
  ] as const;
  const waterfallRecords = [
    { report_line: "reserve", balance: "25", currency: "USD" }
  ] as const;
  const capture = captureEvidenceFixture(
    options.waterfallPresent ?? true,
    records,
    waterfallRecords
  );
  const { snapshot } = capture;
  await repositories.datasetSnapshots.put(snapshot, {
    tenantId: snapshot.tenantId,
    actorId: "capture-worker",
    idempotencyKey: "capture-snapshot-1"
  });

  const dictionaryContent = { fields: ["loan_id", "current_balance", "portfolio_id", "currency"] };
  const dictionary = dictionaryReference("dictionary-1", dictionaryContent);
  const alternateDictionary = dictionaryReference("dictionary-2", { fields: ["other"] });
  const compilerContent = { compiler: "closed-ast-v2" };
  const compiler = bundleReference("mapping_compiler", "mapping-compiler-1", compilerContent);
  const runtimeDictionary = options.mismatchedRuntimeDictionary ? alternateDictionary : dictionary;
  const runtime = createHistoricalRuntimeBundleV1({
    contractVersion: 1,
    runtimeBundleId: "runtime-1",
    runtimeVersion: "2.0.0",
    dictionary: runtimeDictionary,
    mappingCompiler: compiler as ImmutableBundleReferenceV1 & { readonly bundleKind: "mapping_compiler" },
    methodologies: [],
    assembledAt: "2026-07-01T00:00:00.000Z"
  });
  const resolvedBundles = [
    { reference: runtimeDictionary, content: options.mismatchedRuntimeDictionary ? { fields: ["other"] } : dictionaryContent },
    { reference: compiler, content: compilerContent }
  ];
  const runtimeResolver = new InMemoryHistoricalRuntimeResolver([runtime], resolvedBundles);
  const certificationRuntime = options.runtimeActivatedAfterAttempt
    ? {
        forCertification: ({ tenantId, certifiedAt }: { readonly tenantId: string; readonly certifiedAt: string }) => ({
          resolveActivatedRuntime: (reference: { readonly runtimeBundleId: string; readonly runtimeBundleHash: string }) => ({
            runtime: reference.runtimeBundleId === runtime.runtimeBundleId &&
              reference.runtimeBundleHash === runtime.runtimeBundleHash
              ? runtime
              : (() => { throw new Error("unexpected runtime reference"); })(),
            activation: {
              tenantId,
              runtimeBundleId: runtime.runtimeBundleId,
              runtimeBundleHash: runtime.runtimeBundleHash,
              activatedAt: `${certifiedAt.slice(0, -5)}01.000Z`
            }
          }),
          resolveRuntimeBundle: runtimeResolver.resolveRuntimeBundle.bind(runtimeResolver),
          resolveDictionary: runtimeResolver.resolveDictionary.bind(runtimeResolver),
          resolveBundle: runtimeResolver.resolveBundle.bind(runtimeResolver)
        })
      }
    : undefined;
  const mappingSpec = createMappingSpecV2({
    contractVersion: 2,
    tenantId: snapshot.tenantId,
    mappingSpecId: "mapping-spec-1",
    mappingKey: "loan-tape",
    revision: 1,
    status: "active",
    sourceContract: snapshot.sourceContract,
    dictionaryBundle: dictionary,
    rules: [
      {
        ruleId: "loan-id",
        canonicalField: "loan_id",
        expression: { op: "source", column: "loan_no" },
        onError: "fail_application"
      },
      {
        ruleId: "balance",
        canonicalField: "current_balance",
        expression: { op: "source", column: "balance" },
        onError: "fail_application"
      },
      {
        ruleId: "portfolio",
        canonicalField: "portfolio_id",
        expression: { op: "source", column: "portfolio" },
        onError: "fail_application"
      },
      {
        ruleId: "currency",
        canonicalField: "currency",
        expression: { op: "source", column: "currency" },
        onError: "fail_application"
      }
    ],
    requiredCanonicalFields: ["loan_id", "current_balance", "portfolio_id", "currency"],
    createdBy: "mapping-maker",
    createdAt: "2026-06-01T00:00:00.000Z",
    approvedBy: "mapping-checker",
    approvedAt: "2026-06-02T00:00:00.000Z"
  });
  const definitions: ModernCertificationDefinitionResolutionV1 = {
    mappingSpec,
    mappingWindow: effectiveWindow(options.effectiveTo),
    runtime: {
      runtimeBundleId: runtime.runtimeBundleId,
      runtimeBundleHash: runtime.runtimeBundleHash,
      window: effectiveWindow(options.effectiveTo)
    },
    dataQuality: {
      definitionId: "dq-definition-1",
      rulesetId: "dq-ruleset-1",
      mappingSectionId: "loans",
      requiredSectionIds: ["loans"],
      rules: [
        {
          ruleId: "loan-id-required",
          type: "required",
          field: "loan_id",
          severity: "critical",
          blocking: true
        },
        {
          ruleId: "loan-id-unique",
          type: "unique",
          field: "loan_id",
          severity: "critical",
          blocking: true
        }
      ],
      balanceField: "current_balance",
      materialBalance: "1",
      window: effectiveWindow(options.effectiveTo)
    },
    reconciliation: {
      definitionId: "reconciliation-definition-1",
      reconciliationId: "reconciliation-run-1",
      requiredSectionIds: ["loans", "waterfall"],
      controls: [{
        controlId: "loan-pool-tie-out",
        sectionId: "loans",
        recordSource: "normalized",
        dimensions: ["portfolio_id"],
        balanceField: "current_balance",
        currencyField: "currency",
        expected: [
          {
            dimensions: { portfolio_id: "portfolio-1" },
            rowCount: 2,
            balance: options.expectedBalance ?? "300",
            currency: "USD"
          }
        ],
        balanceTolerance: "0"
      }, {
        controlId: "waterfall-tie-out",
        sectionId: "waterfall",
        recordSource: "source",
        dimensions: ["report_line"],
        balanceField: "balance",
        currencyField: "currency",
        expected: [
          {
            dimensions: { report_line: "reserve" },
            rowCount: 1,
            balance: "25",
            currency: "USD"
          }
        ],
        balanceTolerance: "0"
      }],
      window: effectiveWindow(options.effectiveTo)
    }
  };
  const source: CapturedSourcePopulationV2 = sourcePopulation(snapshot, "loans", records);
  const waterfallSource = options.waterfallPresent === false
    ? undefined
    : sourcePopulation(
        snapshot,
        "waterfall",
        options.tamperWaterfallPopulation
          ? [{ report_line: "reserve", balance: "999", currency: "USD" }]
          : waterfallRecords
      );
  let sourceLoads = 0;
  let definitionLoads = 0;
  let artifactWrites = 0;
  const artifactIds: string[] = [];
  let deliveryLoads = 0;
  let deliveryAvailable = true;
  let evidencePutFailuresRemaining = options.evidencePutFailsOnce ? 1 : 0;
  let now = "2026-08-02T10:00:00.000Z";
  const attempts = new InMemorySnapshotCertificationAttemptStore();
  const staging = options.artifactStaging
    ? new SqliteCertificationArtifactStagingStoreV1(join(directory, "artifact-staging.sqlite"))
    : undefined;
  const receipts = new InMemoryImmutableRepository<ModernSnapshotExtractionReceiptV1>(
    "modern-certification-receipts",
    (record) => record.receiptId
  );
  if (!options.receiptAbsent) {
    const receipt = options.tamperReceipt
      ? { ...capture.receipt, facilityId: "facility-substituted" }
      : capture.receipt;
    await receipts.put(receipt, {
      tenantId: snapshot.tenantId,
      actorId: "capture-worker",
      idempotencyKey: "capture-receipt-1"
    });
  }
  const substitutedBinding = scopeBindingFixture(capture.sourceContract, "facility-substituted", "binding-substituted");
  const substitutedDelivery = sourceDeliveryFixture(capture.sourceContract, substitutedBinding);
  const { bindingHash: _bindingHash, ...bindingBody } = capture.scopeBinding;
  const forgedBinding = createGovernedDatasetScopeBindingV1({
    ...bindingBody,
    effectiveFrom: "2026-02-01"
  });
  const compromisedSource = options.tamperSourceDocument
    ? {
        ...capture.sourceContract,
        schemaPolicy: {
          ...capture.sourceContract.schemaPolicy,
          allowUnknownColumns: !capture.sourceContract.schemaPolicy.allowUnknownColumns
        }
      }
    : capture.sourceContract;
  const deliveryResolution: GovernedSourceDeliveryResolutionV1 = options.substituteFacility
    ? {
        delivery: substitutedDelivery,
        sourceContract: capture.sourceContract,
        scopeBinding: substitutedBinding
      }
    : {
        delivery: options.tamperDelivery
          ? { ...capture.delivery, facilityId: "facility-substituted" }
          : capture.delivery,
        sourceContract: compromisedSource,
        scopeBinding: options.forgeBindingDocument ? forgedBinding : capture.scopeBinding
      } as GovernedSourceDeliveryResolutionV1;
  const service = new ModernSnapshotCertificationService({
    snapshots: repositories.datasetSnapshots,
    receipts,
    sourceDeliveries: {
      async resolveGovernedDeliveryForCapture() {
        deliveryLoads += 1;
        if (!deliveryAvailable) throw new Error("live delivery authority must not be consulted");
        return deliveryResolution;
      }
    },
    certifiedEvidence: {
      get(tenantId, recordId) {
        return repositories.certifiedSnapshotEvidence.get(tenantId, recordId);
      },
      async put(record, context) {
        if (evidencePutFailuresRemaining > 0) {
          evidencePutFailuresRemaining -= 1;
          throw new Error("simulated evidence persistence failure");
        }
        return repositories.certifiedSnapshotEvidence.put(record, context);
      }
    },
    attempts,
    artifactStaging: staging,
    sourceEvidence: {
      async loadSection(input) {
        sourceLoads += 1;
        return input.sectionId === "loans"
          ? source
          : input.sectionId === "waterfall"
          ? waterfallSource
          : undefined;
      }
    },
    definitions: {
      async resolveForBoundSnapshot(input) {
        definitionLoads += 1;
        assert.equal(input.evidence.extractionReceipt.receiptHash, capture.receipt.receiptHash);
        assert.equal(input.evidence.deliveryHash, capture.delivery.deliveryHash);
        assert.equal(input.evidence.scopeBinding.bindingHash, capture.scopeBinding.bindingHash);
        return definitions;
      }
    },
    runtime: runtimeResolver,
    ...(certificationRuntime === undefined ? {} : { certificationRuntime }),
    dimensions: { async resolveForMapping() { return []; } },
    artifacts: {
      putJson(input) {
        artifactWrites += 1;
        const stored = artifacts.putJson(input);
        artifactIds.push(stored.artifactId);
        return stored;
      },
      getJson(tenantId, artifactId) {
        return artifacts.getJson(tenantId, artifactId);
      }
    },
    now: () => now
  });
  const request: CertifySnapshotV2Request = {
    snapshotId: snapshot.snapshotId
  };
  const actor = {
    tenantId: snapshot.tenantId,
    actorId: "certification-checker",
    authority: "platform_operator",
    identitySource: "server_derived"
  } as const;
  return {
    service,
    request,
    actor,
    repositories,
    artifacts,
    get sourceLoads() { return sourceLoads; },
    get definitionLoads() { return definitionLoads; },
    get artifactWrites() { return artifactWrites; },
    get artifactIds() { return [...artifactIds]; },
    get deliveryLoads() { return deliveryLoads; },
    staging,
    certificationManifestId: certificationManifestId(snapshot.tenantId, snapshot.snapshotId),
    makeDeliveryUnavailable() { deliveryAvailable = false; },
    setNow(value: string) { now = value; },
    close: () => {
      staging?.close();
      repositories.close();
    }
  };
}

class InMemorySnapshotCertificationAttemptStore implements SnapshotCertificationAttemptStoreV1 {
  readonly #attempts = new Map<string, SnapshotCertificationAttemptV1>();

  async startOrReplay(input: StartSnapshotCertificationAttemptV1) {
    const key = `${input.tenantId}:${input.certificationManifestId}`;
    const existing = this.#attempts.get(key);
    if (existing) {
      if (
        existing.snapshotId !== input.snapshotId ||
        existing.snapshotHash !== input.snapshotHash ||
        existing.actorId !== input.actorId ||
        existing.requestHash !== input.requestHash
      ) {
        throw new Error("attempt identity conflict");
      }
      return Object.freeze({ attempt: existing, replayed: true });
    }
    const attempt = createSnapshotCertificationAttemptV1({ contractVersion: 1, ...input });
    this.#attempts.set(key, attempt);
    return Object.freeze({ attempt, replayed: false });
  }
}

function certificationManifestId(tenantId: string, snapshotId: string) {
  const kind = "certification";
  return `${kind}-${canonicalHash({
    contractVersion: 1,
    tenantId,
    snapshotId,
    kind
  }).slice("sha256:".length, "sha256:".length + 32)}`;
}

function captureEvidenceFixture(
  waterfallPresent: boolean,
  loanRecords: readonly Readonly<Record<string, string>>[],
  waterfallRecords: readonly Readonly<Record<string, string>>[]
) {
  const sourceContract = sourceContractFixture();
  const scopeBinding = scopeBindingFixture(sourceContract);
  const delivery = sourceDeliveryFixture(sourceContract, scopeBinding);
  const waterfall = waterfallPresent
    ? {
        sectionId: "waterfall",
        required: false,
        present: true,
        rowCount: 1,
        contentHash: hash("waterfall-content"),
        schemaHash: hash("waterfall-schema"),
        controlPopulationHash: hash(waterfallRecords)
      }
    : { sectionId: "waterfall", required: false, present: false, rowCount: 0 };
  const sections = [
    {
      sectionId: "loans",
      required: true,
      present: true,
      rowCount: 2,
      contentHash: hash("loans-content"),
      schemaHash: hash("loans-schema"),
      controlPopulationHash: hash(loanRecords)
    },
    waterfall
  ] as const;
  const receiptBody = {
    contractVersion: 1 as const,
    tenantId: sourceContract.tenantId,
    receiptId: modernSnapshotExtractionReceiptIdV1("snapshot-1"),
    snapshotId: "snapshot-1",
    deliveryId: delivery.deliveryId,
    datasetId: scopeBinding.datasetId,
    facilityId: scopeBinding.scope.scopeId,
    sourceContract: scopeBinding.sourceContract,
    scopeBinding: {
      bindingId: scopeBinding.bindingId,
      revision: scopeBinding.revision,
      bindingHash: scopeBinding.bindingHash
    },
    sourceDelivery: {
      deliveryId: delivery.deliveryId,
      deliveryRevision: delivery.deliveryRevision,
      deliveryHash: delivery.deliveryHash,
      locatorHash: canonicalHash(delivery.locator),
      sourceVersionHash: delivery.locator.mode === "object_storage"
        ? delivery.locator.immutableVersionHash
        : delivery.locator.sourceVersionHash
    },
    delivery: sourceContract.delivery,
    sourceLocator: `governed-delivery:${delivery.deliveryId}@${delivery.deliveryHash}`,
    immutableSourceVersion: delivery.locator.mode === "object_storage"
      ? delivery.locator.immutableVersionHash
      : undefined,
    asOfDate: "2026-07-31",
    knowledge: {
      sourceObservedAt: "2026-08-01T09:00:00.000Z",
      extractedAt: "2026-08-01T09:01:00.000Z",
      receivedAt: "2026-08-01T09:02:00.000Z",
      persistedAt: "2026-08-01T09:03:00.000Z"
    },
    watermark: { mode: "none" as const },
    hashes: {
      contentHash: delivery.locator.mode === "object_storage"
        ? delivery.locator.contentHash
        : hash("source-bytes"),
      schemaHash: hash("source-schema"),
      profileHash: hash("source-profile"),
      catalogHash: hash("source-catalog"),
      parserHash: hash("parquet-parser")
    },
    rowCount: 2 + waterfall.rowCount,
    columnCount: 5,
    byteCount: delivery.locator.mode === "object_storage" ? delivery.locator.byteCount : 1_024,
    elapsedMs: 100,
    sections,
    correction: { kind: "original" as const },
    capturedBy: "capture-worker"
  };
  const receipt = parseModernSnapshotExtractionReceiptV1({
    ...receiptBody,
    receiptHash: canonicalHash(receiptBody)
  });
  const snapshot = createDatasetSnapshotV2({
    contractVersion: 2,
    tenantId: sourceContract.tenantId,
    snapshotId: "snapshot-1",
    sourceContract: scopeBinding.sourceContract,
    delivery: receipt.delivery,
    sourceLocator: receipt.sourceLocator,
    immutableSourceVersion: receipt.immutableSourceVersion,
    asOfDate: receipt.asOfDate,
    knowledge: receipt.knowledge,
    watermark: receipt.watermark,
    hashes: {
      contentHash: receipt.hashes.contentHash,
      schemaHash: receipt.hashes.schemaHash,
      catalogHash: receipt.hashes.catalogHash,
      parserHash: receipt.hashes.parserHash,
      extractionHash: receipt.receiptHash
    },
    rowCount: receipt.rowCount,
    byteCount: receipt.byteCount,
    sections: receipt.sections,
    correction: receipt.correction,
    createdBy: receipt.capturedBy
  });
  return { sourceContract, scopeBinding, delivery, receipt, snapshot };
}

function sourceContractFixture(): SourceContractV1 {
  return createSourceContractV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    sourceContractId: "source-contract-1",
    sourceKey: "loan-tape",
    revision: 1,
    status: "active",
    delivery: {
      mode: "object_storage",
      format: "parquet",
      connectorId: "object-source",
      credentialRef: "kms/object-source",
      bucket: "governed-bucket",
      keyPattern: "facility-*/*.parquet",
      immutableVersionRequired: true
    },
    schemaPolicy: {
      columns: [
        { sourceName: "loan_no", ordinal: 0, nativeType: "text", nullable: false, required: true },
        { sourceName: "balance", ordinal: 1, nativeType: "decimal", nullable: false, required: true },
        { sourceName: "portfolio", ordinal: 2, nativeType: "text", nullable: false, required: true },
        { sourceName: "currency", ordinal: 3, nativeType: "text", nullable: false, required: true },
        { sourceName: "report_line", ordinal: 4, nativeType: "text", nullable: true, required: false }
      ],
      allowUnknownColumns: false,
      requireStableOrdinals: true
    },
    parserPolicy: {
      format: "parquet",
      parserId: "parquet-safe-v1",
      parserVersion: "1.0.0",
      optionsHash: hash("parser-options"),
      exactDecimalMode: "string",
      timezone: "UTC",
      rejectSchemaMerging: true
    },
    extractionPolicy: {
      mode: "full",
      readOnly: true,
      maximumRows: 1_000,
      maximumColumns: 25,
      maximumBytes: 1_000_000,
      timeoutMs: 5_000,
      cursorRows: 100
    },
    sections: [
      { sectionId: "loans", required: true, selector: "loans", keyFields: ["loan_no"] },
      { sectionId: "waterfall", required: false, selector: "waterfall", keyFields: ["report_line"] }
    ],
    effectiveFrom: "2026-01-01",
    createdBy: "source-maker",
    createdAt: "2026-01-01T00:00:00.000Z",
    approvedBy: "source-checker",
    approvedAt: "2026-01-02T00:00:00.000Z"
  });
}

function scopeBindingFixture(
  sourceContract: SourceContractV1,
  facilityId = "facility-a",
  bindingId = "binding-a"
): GovernedDatasetScopeBindingV1 {
  return createGovernedDatasetScopeBindingV1({
    contractVersion: 1,
    tenantId: sourceContract.tenantId,
    bindingId,
    revision: 1,
    datasetId: "loan-dataset",
    sourceContract: {
      sourceContractId: sourceContract.sourceContractId,
      revision: sourceContract.revision,
      sourceContractHash: sourceContract.sourceContractHash
    },
    scope: { scopeType: "facility", scopeId: facilityId },
    effectiveFrom: "2026-01-01"
  });
}

function sourceDeliveryFixture(
  sourceContract: SourceContractV1,
  scopeBinding: GovernedDatasetScopeBindingV1
): GovernedSourceDeliveryRecordV1 {
  assert.equal(sourceContract.delivery.mode, "object_storage");
  const objectKey = `${scopeBinding.scope.scopeId}/portfolio.parquet`;
  const immutableVersionId = "version-1";
  return createGovernedSourceDeliveryRecordV1({
    contractVersion: 1,
    tenantId: sourceContract.tenantId,
    deliveryId: `delivery-${scopeBinding.scope.scopeId}`,
    deliveryRevision: 1,
    datasetId: scopeBinding.datasetId,
    facilityId: scopeBinding.scope.scopeId,
    sourceContract: scopeBinding.sourceContract,
    scopeBinding: {
      bindingId: scopeBinding.bindingId,
      revision: scopeBinding.revision,
      bindingHash: scopeBinding.bindingHash
    },
    locator: {
      mode: "object_storage",
      format: sourceContract.delivery.format,
      connectorId: sourceContract.delivery.connectorId,
      bucket: sourceContract.delivery.bucket,
      objectKey,
      immutableVersionId,
      immutableVersionHash: canonicalHash({
        connectorId: sourceContract.delivery.connectorId,
        bucket: sourceContract.delivery.bucket,
        objectKey,
        immutableVersionId
      }),
      contentHash: hash("source-bytes"),
      byteCount: 1_024
    },
    sourceObservedAt: "2026-08-01T09:00:00.000Z",
    receivedAt: "2026-08-01T09:00:30.000Z",
    status: "usable",
    recordedBy: "delivery-checker",
    identitySource: "server_derived",
    recordedAt: "2026-08-01T09:00:45.000Z",
    previousDeliveryHash: null
  });
}

function effectiveWindow(effectiveTo?: string) {
  return effectiveTo === undefined
    ? { effectiveFrom: "2026-01-01" }
    : { effectiveFrom: "2026-01-01", effectiveTo };
}

function sourcePopulation(
  snapshot: DatasetSnapshotV2,
  sectionId: string,
  records: readonly Readonly<Record<string, string>>[]
): CapturedSourcePopulationV2 {
  const section = snapshot.sections.find((candidate) => candidate.sectionId === sectionId);
  assert.ok(section?.contentHash);
  assert.ok(section.schemaHash);
  assert.ok(section.controlPopulationHash);
  return {
    tenantId: snapshot.tenantId,
    snapshotId: snapshot.snapshotId,
    snapshotHash: snapshot.snapshotHash,
    sourceContract: snapshot.sourceContract,
    sectionId,
    extractionHash: snapshot.hashes.extractionHash,
    sectionContentHash: section.contentHash,
    sectionSchemaHash: section.schemaHash,
    controlPopulationHash: section.controlPopulationHash,
    records
  };
}

function dictionaryReference(
  bundleId: string,
  content: unknown
): DictionaryBundleReferenceV1 {
  return {
    contractVersion: 1,
    bundleKind: "dictionary",
    bundleId,
    version: "1.0.0",
    contentHash: hash(content),
    artifactId: `${bundleId}-artifact`,
    mediaType: "application/json",
    createdAt: "2026-06-01T00:00:00.000Z",
    dictionaryVersion: "1.0.0",
    dictionaryHash: hash({ bundleId, kind: "dictionary" }),
    fieldPolicyVersion: "1.0.0",
    fieldPolicyHash: hash({ bundleId, kind: "field-policy" })
  };
}

function bundleReference(
  bundleKind: "mapping_compiler",
  bundleId: string,
  content: unknown
): ImmutableBundleReferenceV1 {
  return {
    contractVersion: 1,
    bundleKind,
    bundleId,
    version: "1.0.0",
    contentHash: hash(content),
    artifactId: `${bundleId}-artifact`,
    mediaType: "application/json",
    createdAt: "2026-06-01T00:00:00.000Z"
  };
}

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "modern-certification-"));
  directories.push(directory);
  return directory;
}

function certificationCode(code: ModernSnapshotCertificationError["code"]) {
  return (error: unknown) =>
    error instanceof ModernSnapshotCertificationError && error.code === code;
}
