import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  ContractValidationError,
  canonicalHash,
  canonicalJson,
  type CanonicalJsonValue,
  type Sha256Hash
} from "../src/contracts/canonical.js";
import type { MetricDefinitionV1 } from "../src/domain/surveillance/contracts.js";
import type { ResolvedGovernedDefinitionV2 } from "../src/services/governed-definition-v2-resolver.js";
import { ArtifactStore, artifactJsonContentHash } from "../src/control/artifacts.js";
import {
  assertGovernedResultArtifactV4MatchesEnvelope,
  assertGovernedResultManifestV4Creator,
  assertGovernedResultManifestV4MatchesResult,
  createGovernedExecutionEnvelopeV4,
  finalizeGovernedResultArtifactV4,
  finalizeGovernedResultManifestV4,
  createPortfolioSurveillanceAuthorizationPreflightV4,
  parseGovernedExecutionEnvelopeV4,
  parseGovernedResultArtifactV4Structure,
  parseGovernedResultManifestV4Structure,
  parsePortfolioSurveillanceAuthorizationPreflightV4,
  portfolioSurveillanceDescriptorBindingV4,
  type GovernedExecutionEnvelopeV4,
  type GovernedExecutionEnvelopeV4Input,
  type GovernedExecutionAuthorizationV4,
  type GovernedResultArtifactV4,
  type GovernedResultManifestV4,
  type PortfolioSurveillanceAuthorizationPreflightV4
} from "../src/services/governed-operation-v4.js";
import {
  bindPortfolioSurveillanceGovernanceV1,
  createCertifiedSnapshotMaterialV1,
  executePortfolioSurveillanceOperationV1,
  parsePortfolioSurveillanceExecutionPlanV1,
  preparePortfolioSurveillanceExecutionPlanV1,
  type CertifiedSnapshotMaterialV1,
  type PortfolioSurveillanceExecutionPlanV1,
  type PortfolioSurveillanceOperationAuthorityV1,
  type PortfolioSurveillanceSnapshotLoadRequestV1
} from "../src/services/operations/portfolio-surveillance-v1.js";

const TENANT = "tenant-a";
const PURPOSE = "governed-portfolio-surveillance";
const REQUESTED_FIELDS = [
  "as_of_date",
  "commitment_amount",
  "facility_id",
  "loan_id",
  "original_balance",
  "outstanding_balance",
  "source_system"
] as const;

const SOURCE_ACCESS_POLICIES = [{
  definitionVersionId: "source-policy-v1",
  definitionKey: "portfolio-risk-read",
  semanticVersion: "1.0.0",
  versionHash: hash("source-policy-version"),
  documentHash: hash("source-policy-document"),
  approvalEventHash: hash("source-policy-approval"),
  executionDocumentHash: hash("source-policy-execution"),
  policyId: "portfolio-risk-read",
  revision: 1,
  policyHash: hash("source-policy"),
  effectiveFrom: "2026-01-01",
  effectiveTo: null
}] as const;

const DATASET_SCOPE_BINDINGS = [{
  definitionVersionId: "dataset-binding-v1",
  definitionKey: "loan-tape-binding",
  semanticVersion: "1.0.0",
  versionHash: hash("dataset-binding-version"),
  documentHash: hash("dataset-binding-document"),
  approvalEventHash: hash("dataset-binding-approval"),
  executionDocumentHash: hash("dataset-binding-execution"),
  bindingId: "loan-tape-binding",
  revision: 1,
  bindingHash: hash("dataset-binding"),
  effectiveFrom: "2026-01-01",
  effectiveTo: null
}] as const;

let PLAN: PortfolioSurveillanceExecutionPlanV1;

function testWithPlan(name: string, body: () => void | Promise<void>): void {
  test(name, async () => {
    PLAN ??= await planFixture();
    await body();
  });
}

testWithPlan("v4 preflight and envelope round-trip with exact authority, descriptor, tenant, and plan bindings", () => {
  const preflight = preflightFixture();
  const envelope = envelopeFixture(preflight);

  assert.deepEqual(parsePortfolioSurveillanceAuthorizationPreflightV4(preflight), preflight);
  assert.deepEqual(parseGovernedExecutionEnvelopeV4(envelope), envelope);
  assert.equal(envelope.identity.tenantId, envelope.tenantId);
  assert.equal(envelope.requestHash, preflight.requestHash);
  assert.equal(envelope.sourceSelectionHash, preflight.sourceSelectionHash);
  assert.equal(envelope.definitionSetHash, preflight.definitionSetHash);
  assert.equal(envelope.parameterFingerprint, bare(envelope.planHash));
  assert.deepEqual(envelope.descriptor, portfolioSurveillanceDescriptorBindingV4());
});

testWithPlan("legacy standalone plans remain parseable but v4 requires exact governance references", () => {
  const legacy = mutable(PLAN);
  delete legacy.governanceBindings;
  rehash(legacy, "planHash");
  const parsedLegacy = parsePortfolioSurveillanceExecutionPlanV1(legacy);
  assert.equal(parsedLegacy.governanceBindings, undefined);

  const preflight = preflightFixture();
  const legacyEnvelope = createGovernedExecutionEnvelopeV4({
    ...envelopeInput(preflight),
    planArtifact: {
      ...envelopeInput(preflight).planArtifact,
      contentHash: artifactJsonContentHash(parsedLegacy),
      byteLength: Buffer.byteLength(canonicalJson(parsedLegacy), "utf8")
    },
    planHash: parsedLegacy.planHash,
    parameterFingerprint: bare(parsedLegacy.planHash)
  });
  assert.throws(
    () => finalizeGovernedResultArtifactV4(
      resultSeed(executePortfolioSurveillanceOperationV1(parsedLegacy)),
      legacyEnvelope,
      parsedLegacy,
      executionAuthorizationFixture(legacyEnvelope)
    ),
    ContractValidationError
  );

  const substituted = mutable(PLAN);
  const governance = nested(substituted, "governanceBindings");
  const policies = governance.sourceAccessPolicies as Array<Record<string, unknown>>;
  policies[0]!.policyHash = canonicalHash("substituted-source-policy");
  governance.sourceAccessPolicySetHash = canonicalHash(policies);
  rehash(substituted, "planHash");
  const parsedSubstituted = parsePortfolioSurveillanceExecutionPlanV1(substituted);
  const substitutedEnvelope = createGovernedExecutionEnvelopeV4({
    ...envelopeInput(preflight),
    planArtifact: {
      ...envelopeInput(preflight).planArtifact,
      contentHash: artifactJsonContentHash(parsedSubstituted),
      byteLength: Buffer.byteLength(canonicalJson(parsedSubstituted), "utf8")
    },
    planHash: parsedSubstituted.planHash,
    parameterFingerprint: bare(parsedSubstituted.planHash)
  });
  assert.throws(
    () => finalizeGovernedResultArtifactV4(
      resultSeed(executePortfolioSurveillanceOperationV1(parsedSubstituted)),
      substitutedEnvelope,
      parsedSubstituted,
      executionAuthorizationFixture(substitutedEnvelope)
    ),
    ContractValidationError
  );
});

testWithPlan("preflight rejects schema drift, noncanonical time, unsorted fields, and requested-field hash drift", () => {
  const base = preflightInput();
  assert.throws(
    () =>
      createPortfolioSurveillanceAuthorizationPreflightV4({
        ...base,
        purpose: "free form portfolio review"
      }),
    ContractValidationError
  );
  assert.throws(
    () =>
      createPortfolioSurveillanceAuthorizationPreflightV4({
        ...base,
        planningCutoff: "2026-08-12T12:00:00Z"
      }),
    ContractValidationError
  );
  assert.throws(
    () =>
      createPortfolioSurveillanceAuthorizationPreflightV4({
        ...base,
        requestedFields: ["loan_id", "as_of_date"]
      }),
    ContractValidationError
  );
  assert.throws(
    () =>
      createPortfolioSurveillanceAuthorizationPreflightV4({
        ...base,
        requestedFieldsHash: canonicalHash(["another_field"])
      }),
    ContractValidationError
  );
  assert.throws(
    () =>
      createPortfolioSurveillanceAuthorizationPreflightV4({
        ...base,
        descriptor: {
          ...base.descriptor,
          resultSchemaHash: canonicalHash("unregistered-result-schema")
        }
      }),
    ContractValidationError
  );
});

testWithPlan("envelope rejects cross-tenant, cutoff, set-order, duplicate, and explicit-undefined ambiguity", () => {
  const preflight = preflightFixture();
  const base = envelopeInput(preflight);

  assert.throws(
    () =>
      createGovernedExecutionEnvelopeV4({
        ...base,
        tenantId: "tenant-b"
      }),
    ContractValidationError
  );
  assert.throws(
    () =>
      createGovernedExecutionEnvelopeV4({
        ...base,
        purpose: "another-purpose"
      }),
    ContractValidationError
  );
  assert.throws(
    () =>
      createGovernedExecutionEnvelopeV4({
        ...base,
        datasetId: "another-dataset"
      }),
    ContractValidationError
  );
  assert.throws(
    () =>
      createGovernedExecutionEnvelopeV4({
        ...base,
        planArtifact: {
          ...base.planArtifact,
          byteLength: 10_000_001
        }
      }),
    ContractValidationError
  );
  assert.throws(
    () =>
      createGovernedExecutionEnvelopeV4({
        ...base,
        planArtifact: {
          ...base.planArtifact,
          kind: "normalized_snapshot"
        }
      }),
    ContractValidationError
  );
  const cutoffSeconds = Math.floor(Date.parse(base.planningCutoff) / 1_000);
  assert.throws(
    () =>
      createGovernedExecutionEnvelopeV4({
        ...base,
        identity: {
          ...base.identity,
          verifiedAtEpochSeconds: cutoffSeconds + 60,
          expiresAtEpochSeconds: cutoffSeconds + 3_600
        }
      }),
    ContractValidationError
  );
  assert.throws(
    () =>
      createGovernedExecutionEnvelopeV4({
        ...base,
        planningCutoff: "2026-08-12T12:00:01.000Z"
      }),
    ContractValidationError
  );
  assert.throws(
    () =>
      createGovernedExecutionEnvelopeV4({
        ...base,
        requestedFields: ["loan_id", "as_of_date"]
      }),
    ContractValidationError
  );
  assert.throws(
    () =>
      createGovernedExecutionEnvelopeV4({
        ...base,
        auditTags: ["governed-analysis", "governed-analysis"]
      }),
    ContractValidationError
  );
  assert.throws(
    () =>
      createGovernedExecutionEnvelopeV4({
        ...base,
        identity: {
          ...base.identity,
          audiences: ["abl-api", "abl-api"]
        }
      }),
    ContractValidationError
  );
  assert.throws(
    () =>
      createGovernedExecutionEnvelopeV4({
        ...base,
        identity: {
          ...base.identity,
          scopes: ["data:read", "analysis:run"]
        }
      }),
    ContractValidationError
  );
  assert.throws(
    () =>
      createGovernedExecutionEnvelopeV4({
        ...base,
        identity: {
          ...base.identity,
          authenticationMethods: ["mfa", "mfa"]
        }
      }),
    ContractValidationError
  );
  assert.throws(
    () =>
      createGovernedExecutionEnvelopeV4({
        ...base,
        identity: {
          ...base.identity,
          verifiedAtEpochSeconds: 1_800_000_000,
          expiresAtEpochSeconds: 1_700_000_000
        }
      }),
    ContractValidationError
  );

  const explicitUndefined = {
    ...base,
    identity: { ...base.identity, clientId: undefined }
  } as unknown as GovernedExecutionEnvelopeV4Input;
  assert.throws(
    () => createGovernedExecutionEnvelopeV4(explicitUndefined),
    ContractValidationError
  );
});

testWithPlan("envelope parser catches authority-binding tampering even after an attacker rehashes the outer body", () => {
  const envelope = mutable(envelopeFixture());
  envelope.tenantId = "tenant-b";
  rehash(envelope, "envelopeHash");
  assert.throws(() => parseGovernedExecutionEnvelopeV4(envelope), ContractValidationError);

  const planTamper = mutable(envelopeFixture());
  planTamper.parameterFingerprint = bare(canonicalHash("another-plan"));
  rehash(planTamper, "envelopeHash");
  assert.throws(() => parseGovernedExecutionEnvelopeV4(planTamper), ContractValidationError);

  const accessTamper = mutable(envelopeFixture());
  accessTamper.sourceAccessPolicySetHash = canonicalHash("another-access-policy-set");
  rehash(accessTamper, "envelopeHash");
  assert.throws(() => parseGovernedExecutionEnvelopeV4(accessTamper), ContractValidationError);
});

testWithPlan("v4 result verifies canonical result, accounting, requested fields, and frozen lineage", () => {
  const envelope = envelopeFixture();
  const result = resultFixture(envelope);

  assert.deepEqual(parseGovernedResultArtifactV4Structure(result), result);
  assert.doesNotThrow(() =>
    assertGovernedResultArtifactV4MatchesEnvelope(
      result,
      envelope,
      PLAN,
      executionAuthorizationFixture(envelope)
    )
  );
  assert.equal(result.resultHash, canonicalHash(result.result));
  assert.equal(result.accountingHash, canonicalHash(result.accounting));
  assert.equal(result.lineageHash, canonicalHash(result.lineage));
});

testWithPlan("result rejects result/accounting hashes, duplicate disclosure sets, and rehashed lineage substitution", () => {
  const envelope = envelopeFixture();
  const result = resultFixture(envelope);

  const resultHashTamper = mutable(result);
  resultHashTamper.resultHash = canonicalHash("another-result");
  assert.throws(() => parseGovernedResultArtifactV4Structure(resultHashTamper), ContractValidationError);

  const accountingHashTamper = mutable(result);
  accountingHashTamper.accountingHash = canonicalHash("another-accounting");
  assert.throws(() => parseGovernedResultArtifactV4Structure(accountingHashTamper), ContractValidationError);

  const duplicatePopulation = mutable(result);
  const duplicateAccounting = nested(duplicatePopulation, "accounting");
  const populationHashes = duplicateAccounting.populationHashes as unknown[];
  populationHashes.push(populationHashes[0]);
  duplicatePopulation.accountingHash = canonicalHash(duplicateAccounting);
  assert.throws(() => parseGovernedResultArtifactV4Structure(duplicatePopulation), ContractValidationError);

  const duplicateDisclosure = mutable(result);
  const disclosureAccounting = nested(duplicateDisclosure, "accounting");
  disclosureAccounting.disclosureClasses = [
    "aggregate_metric_cell",
    "aggregate_metric_cell"
  ];
  duplicateDisclosure.accountingHash = canonicalHash(disclosureAccounting);
  assert.throws(() => parseGovernedResultArtifactV4Structure(duplicateDisclosure), ContractValidationError);

  const substituted = mutable(result);
  const lineage = nested(substituted, "lineage");
  lineage.planHash = canonicalHash("substituted-plan");
  substituted.lineageHash = canonicalHash(lineage);
  assert.throws(() => parseGovernedResultArtifactV4Structure(substituted), ContractValidationError);
});

testWithPlan("plan-bound finalization rejects raw-row, forged accounting, and authorization substitution", () => {
  const envelope = envelopeFixture();
  const authorization = executionAuthorizationFixture(envelope);
  const operationResult = mutable(executePortfolioSurveillanceOperationV1(PLAN));
  operationResult.contractVersion = 999;
  operationResult.rawRecords = [{ loan_id: "raw-loan" }];
  rehash(operationResult, "resultHash");
  assert.throws(
    () =>
      finalizeGovernedResultArtifactV4(
        resultSeed(operationResult),
        envelope,
        PLAN,
        authorization
      ),
    ContractValidationError
  );

  const falseAccessPreflight = createPortfolioSurveillanceAuthorizationPreflightV4({
    ...preflightInput(),
    sourceAccessPolicySetHash: canonicalHash("forged-access-policy-set")
  });
  const falseAccessEnvelope = createGovernedExecutionEnvelopeV4(
    envelopeInput(falseAccessPreflight)
  );
  assert.throws(
    () =>
      finalizeGovernedResultArtifactV4(
        resultSeed(executePortfolioSurveillanceOperationV1(PLAN)),
        falseAccessEnvelope,
        PLAN,
        executionAuthorizationFixture(falseAccessEnvelope)
      ),
    ContractValidationError
  );

  const result = resultFixture(envelope);
  const forged = mutable(result);
  const accounting = nested(forged, "accounting");
  accounting.warningCount = Number(accounting.warningCount) + 1;
  accounting.disclosedItemCount = Number(accounting.disclosedItemCount) + 1;
  forged.accountingHash = canonicalHash(accounting);
  assert.throws(
    () => assertGovernedResultArtifactV4MatchesEnvelope(forged, envelope, PLAN, authorization),
    ContractValidationError
  );

  const wrongDecision = mutable(result);
  nested(wrongDecision, "authorization").decisionId = bare(canonicalHash("wrong-decision"));
  assert.throws(
    () =>
      assertGovernedResultArtifactV4MatchesEnvelope(
        wrongDecision,
        envelope,
        PLAN,
        authorization
      ),
    ContractValidationError
  );
});

testWithPlan("frozen policy obligations and trusted execution timing fail closed", () => {
  const envelope = envelopeFixture();
  const rejectAuthorization = (
    authorization: GovernedExecutionAuthorizationV4,
    envelopeValue: GovernedExecutionEnvelopeV4 = envelope
  ) =>
    assert.throws(
      () =>
        finalizeGovernedResultArtifactV4(
          resultSeed(executePortfolioSurveillanceOperationV1(PLAN)),
          envelopeValue,
          PLAN,
          authorization
        ),
      ContractValidationError
    );

  for (const obligations of [
    obligationsFixture({ allowRawRows: true }),
    obligationsFixture({ allowExport: true }),
    obligationsFixture({ maxResultRows: 1 }),
    obligationsFixture({ maxResultBytes: 1 }),
    obligationsFixture({ rowFilterRefs: ["unapplied-filter"] }),
    obligationsFixture({ fieldMasks: { loan_id: "redact" } }),
    obligationsFixture({ auditTags: ["substituted-tag"] })
  ]) {
    rejectAuthorization(executionAuthorizationFixture(envelope, { obligations }));
  }

  rejectAuthorization(
    executionAuthorizationFixture(envelope, {
      completedAt: "2026-08-12T12:05:01.000Z"
    })
  );
  rejectAuthorization(
    executionAuthorizationFixture(envelope, {
      startedAt: "2026-08-12T12:00:04.000Z",
      completedAt: "2026-08-12T12:00:03.000Z"
    })
  );
  rejectAuthorization(
    executionAuthorizationFixture(envelope, {
      obligations: obligationsFixture({ maxExecutionMs: 1_000 }),
      completedAt: "2026-08-12T12:00:04.000Z"
    })
  );

  const expirySeconds = Math.floor(Date.parse("2026-08-12T12:00:02.000Z") / 1_000);
  const shortIdentityEnvelope = createGovernedExecutionEnvelopeV4({
    ...envelopeInput(preflightFixture()),
    identity: {
      ...envelopeInput(preflightFixture()).identity,
      expiresAtEpochSeconds: expirySeconds
    }
  });
  rejectAuthorization(executionAuthorizationFixture(shortIdentityEnvelope), shortIdentityEnvelope);
});

testWithPlan("v4 manifest self-binds accounting and plan lineage and exactly binds jobId to manifestId", () => {
  const envelope = envelopeFixture();
  const result = resultFixture(envelope);
  const manifest = manifestFixture(result);

  assert.deepEqual(parseGovernedResultManifestV4Structure(manifest), manifest);
  assert.doesNotThrow(() => assertGovernedResultManifestV4MatchesResult(manifest, result));
  assert.doesNotThrow(() => assertGovernedResultManifestV4Creator(manifest, "risk-analyst"));
  assert.throws(
    () => assertGovernedResultManifestV4Creator(manifest, "another-principal"),
    ContractValidationError
  );
  assert.equal(manifest.jobId, manifest.manifestId);
  assert.equal(manifest.accountingHash, result.accountingHash);
  assert.deepEqual(manifest.lineage.planArtifact, envelope.planArtifact);
  assert.equal(manifest.lineage.planHash, envelope.planHash);
});

testWithPlan("stored result binding uses exact ArtifactStore bytes for dynamic object keys", () => {
  const root = mkdtempSync(join(tmpdir(), "abl-v4-result-artifact-"));
  try {
    const result = mutable(resultFixture());
    const authorization = nested(result, "authorization");
    const obligations = nested(authorization, "obligations");
    obligations.fieldMasks = { a: "redact", A: "redact" };
    const parsedResult = parseGovernedResultArtifactV4Structure(result);
    const artifacts = new ArtifactStore(root, {
      activeKeyId: "test-key",
      keys: { "test-key": Buffer.alloc(32, 7) }
    });
    const stored = artifacts.putJson({
      tenantId: TENANT,
      kind: "governed_analysis_result_v4",
      mediaType: "application/json",
      value: parsedResult
    });
    assert.equal(stored.contentHash, artifactJsonContentHash(parsedResult));
    assert.notEqual(stored.contentHash, bare(canonicalHash(parsedResult)));

    const manifest = finalizeGovernedResultManifestV4(
      manifestInput(),
      parsedResult,
      {
        artifactId: stored.artifactId,
        kind: "governed_analysis_result_v4",
        mediaType: "application/json",
        contentHash: stored.contentHash,
        byteLength: stored.byteLength
      }
    );
    const recovered = artifacts.getJson(TENANT, stored.artifactId);
    assert.deepEqual(recovered.value, parsedResult);
    assert.doesNotThrow(() =>
      assertGovernedResultManifestV4MatchesResult(manifest, recovered.value)
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

testWithPlan("manifest rejects identifier, accounting, and plan-artifact tampering; cross-check rejects rehashed substitution", () => {
  const result = resultFixture();
  const manifest = manifestFixture(result);

  assert.throws(
    () =>
      finalizeGovernedResultManifestV4(
        { ...manifestInput(), createdAt: "2026-08-12T12:00:02.000Z" },
        result,
        storedResultArtifactFixture(result)
      ),
    ContractValidationError
  );
  assert.throws(
    () =>
      finalizeGovernedResultManifestV4(
        { ...manifestInput(), createdAt: "2026-08-12T12:01:00Z" },
        result,
        storedResultArtifactFixture(result)
      ),
    ContractValidationError
  );
  assert.throws(
    () =>
      finalizeGovernedResultManifestV4(
        manifestInput(),
        result,
        { ...storedResultArtifactFixture(result), byteLength: 10_000_001 }
      ),
    ContractValidationError
  );
  assert.throws(
    () =>
      finalizeGovernedResultManifestV4(
        manifestInput(),
        result,
        {
          ...storedResultArtifactFixture(result),
          mediaType: "application/octet-stream"
        }
      ),
    ContractValidationError
  );

  const extraArtifact = {
    ...manifest,
    resultArtifacts: [manifest.resultArtifact]
  };
  assert.throws(() => parseGovernedResultManifestV4Structure(extraArtifact), ContractValidationError);

  const accountingTamper = mutable(manifest);
  accountingTamper.accountingHash = canonicalHash("another-accounting");
  assert.throws(() => parseGovernedResultManifestV4Structure(accountingTamper), ContractValidationError);

  const planReferenceTamper = mutable(manifest);
  const lineage = nested(planReferenceTamper, "lineage");
  const planArtifact = nested(lineage, "planArtifact");
  planArtifact.contentHash = bare(canonicalHash("another-plan-artifact"));
  assert.throws(() => parseGovernedResultManifestV4Structure(planReferenceTamper), ContractValidationError);

  planReferenceTamper.lineageHash = canonicalHash(lineage);
  rehash(planReferenceTamper, "manifestHash");
  assert.doesNotThrow(() => parseGovernedResultManifestV4Structure(planReferenceTamper));
  assert.throws(
    () => assertGovernedResultManifestV4MatchesResult(planReferenceTamper, result),
    ContractValidationError
  );

  assert.throws(
    () =>
      finalizeGovernedResultManifestV4(
        manifestInput(),
        result,
        {
          ...storedResultArtifactFixture(result),
          contentHash: bare(canonicalHash("different-result-bytes"))
        }
      ),
    ContractValidationError
  );
  assert.throws(
    () =>
      finalizeGovernedResultManifestV4(
        manifestInput(),
        result,
        {
          ...storedResultArtifactFixture(result),
          byteLength: storedResultArtifactFixture(result).byteLength + 1
        }
      ),
    ContractValidationError
  );
});

function preflightFixture(): PortfolioSurveillanceAuthorizationPreflightV4 {
  return createPortfolioSurveillanceAuthorizationPreflightV4(preflightInput());
}

function preflightInput() {
  const firstSource = PLAN.sourceLineage[0]!;
  const sourceIdentityHash = canonicalHash(
    PLAN.sourceLineage.map(({ datasetId, source, scope }) => ({ datasetId, source, scope }))
  );
  return {
    contractVersion: 1 as const,
    operation: "portfolio_surveillance_v1" as const,
    tenantId: TENANT,
    purpose: PURPOSE,
    descriptor: portfolioSurveillanceDescriptorBindingV4(),
    requestHash: PLAN.requestHash,
    datasetId: firstSource.datasetId,
    scopeHash: canonicalHash(firstSource.scope),
    sourceIdentityHash,
    sourceSelectionHash: canonicalHash({
      planningCutoff: "2026-08-12T12:00:00.000Z",
      terminalCertificationIds: ["cert-feb", "cert-jan"]
    }),
    sourceAccessPolicySetHash: canonicalHash(SOURCE_ACCESS_POLICIES),
    datasetScopeBindingSetHash: canonicalHash(DATASET_SCOPE_BINDINGS),
    definitionSetHash: PLAN.definitionSetHash,
    requestedFields: PLAN.requestedFields,
    requestedFieldsHash: PLAN.requestedFieldsHash,
    planningCutoff: "2026-08-12T12:00:00.000Z",
    maximumPlannedCells: 1_000,
    minimumMetricCellCount: 1
  };
}

function envelopeFixture(
  preflight = preflightFixture()
): GovernedExecutionEnvelopeV4 {
  return createGovernedExecutionEnvelopeV4(envelopeInput(preflight));
}

function envelopeInput(
  preflight: PortfolioSurveillanceAuthorizationPreflightV4
): GovernedExecutionEnvelopeV4Input {
  const planHash = PLAN.planHash;
  const canonicalPlan = canonicalJson(PLAN);
  return {
    version: 4,
    operation: "portfolio_surveillance_v1",
    tenantId: TENANT,
    purpose: PURPOSE,
    identity: {
      issuer: "https://identity.example.test",
      subject: "risk-analyst",
      principalId: "risk-analyst",
      tenantId: TENANT,
      clientId: "codex-client",
      audiences: ["abl-api"],
      resourceIndicators: ["https://mcp.example.test/mcp"],
      scopes: ["analysis:run", "data:read"],
      credentialFingerprint: bare(canonicalHash("credential")),
      verifiedAtEpochSeconds: 1_700_000_000,
      notBeforeEpochSeconds: 1_699_999_000,
      expiresAtEpochSeconds: 1_800_000_000,
      authenticationMethods: ["mfa"]
    },
    descriptor: preflight.descriptor,
    preflight,
    planArtifact: {
      artifactId: bare(canonicalHash("plan-artifact-id")),
      kind: "governed_portfolio_surveillance_plan_v4" as const,
      mediaType: "application/json" as const,
      contentHash: artifactJsonContentHash(PLAN),
      byteLength: Buffer.byteLength(canonicalPlan, "utf8")
    },
    requestHash: preflight.requestHash,
    planHash,
    sourceSelectionHash: preflight.sourceSelectionHash,
    sourceIdentityHash: preflight.sourceIdentityHash,
    sourceAccessPolicySetHash: preflight.sourceAccessPolicySetHash,
    datasetScopeBindingSetHash: preflight.datasetScopeBindingSetHash,
    sourceSetHash: PLAN.sourceSetHash,
    definitionSetHash: preflight.definitionSetHash,
    requestedFields: preflight.requestedFields,
    requestedFieldsHash: preflight.requestedFieldsHash,
    datasetId: preflight.datasetId,
    scopeHash: preflight.scopeHash,
    planningCutoff: preflight.planningCutoff,
    planTtlSeconds: 300,
    startAuthorization: {
      decisionId: bare(canonicalHash("start-authorization-decision")),
      policyFingerprint: bare(canonicalHash("start-policy")),
      tenantId: TENANT,
      principalId: "risk-analyst",
      requestedFields: preflight.requestedFields,
      purpose: PURPOSE,
      obligations: obligationsFixture()
    },
    parameterFingerprint: bare(planHash),
    idempotencyFingerprint: bare(canonicalHash("idempotency-key")),
    startFingerprint: bare(canonicalHash("start"))
  };
}

function resultFixture(
  envelope = envelopeFixture()
): GovernedResultArtifactV4 {
  const operationResult = executePortfolioSurveillanceOperationV1(PLAN);
  const executionAuthorization = executionAuthorizationFixture(envelope);
  return finalizeGovernedResultArtifactV4({
    version: 4,
    jobId: "job-v4",
    manifestId: "job-v4",
    operation: "portfolio_surveillance_v1",
    tenantId: envelope.tenantId,
    purpose: envelope.purpose,
    result: operationResult
  }, envelope, PLAN, executionAuthorization);
}

function resultSeed(result: unknown) {
  return {
    version: 4 as const,
    jobId: "job-v4",
    manifestId: "job-v4",
    operation: "portfolio_surveillance_v1" as const,
    tenantId: TENANT,
    purpose: PURPOSE,
    result: result as CanonicalJsonValue
  };
}

function manifestFixture(
  result = resultFixture()
): GovernedResultManifestV4 {
  return finalizeGovernedResultManifestV4(
    manifestInput(),
    result,
    storedResultArtifactFixture(result)
  );
}

function manifestInput() {
  return {
    version: 4 as const,
    createdAt: "2026-08-12T12:01:00.000Z",
    codeVersion: "test-v4",
    planId: bare(canonicalHash("signed-plan"))
  };
}

function storedResultArtifactFixture(result: GovernedResultArtifactV4) {
  return {
    artifactId: bare(canonicalHash("result-artifact-id")),
    kind: "governed_analysis_result_v4" as const,
    mediaType: "application/json" as const,
    contentHash: artifactJsonContentHash(result),
    byteLength: Buffer.byteLength(canonicalJson(result), "utf8")
  };
}

function obligationsFixture(overrides: Partial<GovernedExecutionAuthorizationV4["obligations"]> = {}) {
  return {
    maxResultRows: 1_000,
    maxResultBytes: 2_000_000,
    maxExecutionMs: 10_000,
    minimumCohortSize: 1,
    requireImmutableSnapshot: true,
    allowRawRows: false,
    allowExport: false,
    rowFilterRefs: [],
    fieldMasks: {},
    auditTags: ["governed-analysis"],
    ...overrides
  };
}

function executionAuthorizationFixture(
  envelope: GovernedExecutionEnvelopeV4,
  overrides: Partial<GovernedExecutionAuthorizationV4> = {}
): GovernedExecutionAuthorizationV4 {
  return {
    decisionId: bare(canonicalHash("execution-authorization-decision")),
    policyFingerprint: bare(canonicalHash("execution-policy")),
    tenantId: envelope.tenantId,
    principalId: envelope.identity.principalId,
    requestedFields: envelope.requestedFields,
    purpose: envelope.purpose,
    obligations: obligationsFixture(),
    authorizedAt: "2026-08-12T12:00:01.000Z",
    startedAt: "2026-08-12T12:00:02.000Z",
    completedAt: "2026-08-12T12:00:03.000Z",
    ...overrides
  };
}

function mutable(value: unknown): Record<string, unknown> {
  return structuredClone(value) as Record<string, unknown>;
}

function nested(value: Record<string, unknown>, key: string): Record<string, unknown> {
  const candidate = value[key];
  assert.ok(candidate && typeof candidate === "object" && !Array.isArray(candidate));
  return candidate as Record<string, unknown>;
}

function rehash(value: Record<string, unknown>, hashKey: string): void {
  const body = { ...value };
  delete body[hashKey];
  value[hashKey] = canonicalHash(body);
}

function bare(hash: string): string {
  return hash.slice("sha256:".length);
}

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
  numerator: { label: "Outstanding balance", aggregation: "sum", field: "outstanding_balance" },
  denominator: { label: "Commitment", aggregation: "sum", field: "commitment_amount" },
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

async function planFixture(): Promise<PortfolioSurveillanceExecutionPlanV1> {
  const authority = new FixtureAuthority([
    certifiedMaterial("cert-jan", "snapshot-jan", "2026-01-31", "100"),
    certifiedMaterial("cert-feb", "snapshot-feb", "2026-02-28", "120")
  ]);
  const legacy = await preparePortfolioSurveillanceExecutionPlanV1(
    {
      contractVersion: 1,
      operation: "portfolio_surveillance_v1",
      sources: [
        { kind: "certification_manifest", certificationManifestId: "cert-feb" },
        { kind: "certification_manifest", certificationManifestId: "cert-jan" }
      ],
      definitionVersionIds: ["metric-balance-v1", "methodology-v1"]
    },
    { tenantId: TENANT, purpose: PURPOSE },
    authority
  );
  const firstSource = legacy.sourceLineage[0]!;
  const sourceIdentityHash = canonicalHash(
    legacy.sourceLineage.map(({ datasetId, source, scope }) => ({ datasetId, source, scope }))
  );
  const sourceSelectionHash = canonicalHash({
    planningCutoff: "2026-08-12T12:00:00.000Z",
    terminalCertificationIds: ["cert-feb", "cert-jan"]
  });
  const preflight = createPortfolioSurveillanceAuthorizationPreflightV4({
    contractVersion: 1,
    operation: "portfolio_surveillance_v1",
    tenantId: TENANT,
    purpose: PURPOSE,
    descriptor: portfolioSurveillanceDescriptorBindingV4(),
    requestHash: legacy.requestHash,
    datasetId: firstSource.datasetId,
    scopeHash: canonicalHash(firstSource.scope),
    sourceIdentityHash,
    sourceSelectionHash,
    sourceAccessPolicySetHash: canonicalHash(SOURCE_ACCESS_POLICIES),
    datasetScopeBindingSetHash: canonicalHash(DATASET_SCOPE_BINDINGS),
    definitionSetHash: legacy.definitionSetHash,
    requestedFields: legacy.requestedFields,
    requestedFieldsHash: legacy.requestedFieldsHash,
    planningCutoff: "2026-08-12T12:00:00.000Z",
    maximumPlannedCells: 1_000,
    minimumMetricCellCount: 1
  });
  return bindPortfolioSurveillanceGovernanceV1(legacy, {
    metadataHash: canonicalHash("complete-metadata-preflight"),
    preflightHash: preflight.preflightHash,
    sourceSelectionHash,
    sourceIdentityHash,
    sourceAccessPolicies: [...SOURCE_ACCESS_POLICIES],
    sourceAccessPolicySetHash: canonicalHash(SOURCE_ACCESS_POLICIES),
    datasetScopeBindings: [...DATASET_SCOPE_BINDINGS],
    datasetScopeBindingSetHash: canonicalHash(DATASET_SCOPE_BINDINGS)
  });
}

function certifiedMaterial(
  certificationManifestId: string,
  snapshotId: string,
  asOfDate: string,
  outstanding: string
): CertifiedSnapshotMaterialV1 {
  const records = [{
    as_of_date: asOfDate,
    source_system: "core",
    facility_id: "facility-a",
    loan_id: "loan-1",
    outstanding_balance: outstanding,
    original_balance: "150",
    commitment_amount: "200"
  }];
  return createCertifiedSnapshotMaterialV1({
    contractVersion: 1,
    tenantId: TENANT,
    datasetId: "loan-tape",
    source: {
      sourceContractId: "loan-source-v1",
      sourceKey: "loan-source",
      revision: 1,
      sourceContractHash: hash("source-contract")
    },
    scope: { scopeType: "portfolio", scopeId: "portfolio-a" },
    authorizedPurpose: PURPOSE,
    authorizedFields: [...REQUESTED_FIELDS],
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

class FixtureAuthority implements PortfolioSurveillanceOperationAuthorityV1 {
  private readonly materials = new Map<string, CertifiedSnapshotMaterialV1>();
  private readonly definitions = new Map<string, ResolvedGovernedDefinitionV2>([
    [METHODOLOGY.reference.definitionVersionId, METHODOLOGY],
    [METRIC.reference.definitionVersionId, METRIC]
  ]);

  constructor(materials: readonly CertifiedSnapshotMaterialV1[]) {
    for (const material of materials) this.materials.set(material.certificationManifestId, material);
  }

  loadLongitudinalBundle(): undefined {
    return undefined;
  }

  loadCertifiedSnapshot(input: PortfolioSurveillanceSnapshotLoadRequestV1): unknown | undefined {
    return input.tenantId === TENANT ? this.materials.get(input.certificationManifestId) : undefined;
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

function hash(value: string): Sha256Hash {
  return canonicalHash(value);
}
