import assert from "node:assert/strict";
import test from "node:test";

import { canonicalHash, createFxRateDefinitionV1 } from "../src/contracts/index.js";
import { SqliteFxRateEvidenceStoreV1 } from "../src/control/fx-rate-evidence-store-v1.js";
import {
  GovernedFxRateCaptureError,
  GovernedFxRateCaptureServiceV1
} from "../src/services/governed-fx-rate-capture-v1.js";

const SOURCE_CONTRACT = Object.freeze({
  sourceContractId: "approved-fx-source",
  revision: 1,
  sourceContractHash: canonicalHash({ sourceContract: "approved-fx-source", revision: 1 })
});
const SNAPSHOT_HASH = canonicalHash({ snapshot: "fx-2026-08-13" });

test("trusted FX capture binds active lifecycle definition and certified source material", async () => {
  const store = new SqliteFxRateEvidenceStoreV1(":memory:");
  let calls = 0;
  const service = serviceFor(store, () => {
    calls += 1;
    return {
      rateEvidenceId: "usd-eur-2026-08-13",
      sourceSnapshotId: "fx-snapshot-2026-08-13",
      effectiveAt: "2026-08-13T00:00:00.000Z",
      observedAt: "2026-08-13T01:00:00.000Z",
      receivedAt: "2026-08-13T01:01:00.000Z",
      sourceRate: "1.200000"
    };
  });
  const request = {
    fxDefinitionId: "usd-eur-closing",
    effectiveAt: "2026-08-13T00:00:00.000Z",
    idempotencyKey: "capture-1"
  };
  const first = await service.capture(request, actor());
  assert.equal(first.replayed, false);
  assert.equal(first.evidence.definition.activation.definitionVersionId, "usd-eur-closing-v1");
  assert.equal(first.evidence.sourceSnapshot.snapshotHash, SNAPSHOT_HASH);

  const replay = await service.capture(request, actor());
  assert.equal(replay.replayed, true);
  assert.equal(replay.evidence.rateEvidenceHash, first.evidence.rateEvidenceHash);
  assert.equal(calls, 2);
  store.close();
});

test("capture fails closed on source-contract and effective-time substitution", async () => {
  const store = new SqliteFxRateEvidenceStoreV1(":memory:");
  const service = serviceFor(store, () => ({
    rateEvidenceId: "bad-rate",
    sourceSnapshotId: "fx-snapshot-2026-08-13",
    effectiveAt: "2026-08-14T00:00:00.000Z",
    observedAt: "2026-08-14T01:00:00.000Z",
    receivedAt: "2026-08-14T01:01:00.000Z",
    sourceRate: "1.200000"
  }));
  await assert.rejects(
    service.capture({
      fxDefinitionId: "usd-eur-closing",
      effectiveAt: "2026-08-13T00:00:00.000Z",
      idempotencyKey: "capture-bad"
    }, actor()),
    (error: unknown) => error instanceof GovernedFxRateCaptureError && error.code === "AUTHORITY_MISMATCH"
  );
  assert.equal(store.get("tenant-a", "bad-rate"), undefined);
  store.close();
});

function serviceFor(
  evidence: SqliteFxRateEvidenceStoreV1,
  material: () => {
    readonly rateEvidenceId: string;
    readonly sourceSnapshotId: string;
    readonly effectiveAt: string;
    readonly observedAt: string;
    readonly receivedAt: string;
    readonly sourceRate: string;
  }
): GovernedFxRateCaptureServiceV1 {
  const definition = activeDefinition();
  return new GovernedFxRateCaptureServiceV1({
    definitions: {
      resolveEffective: () => ({
        reference: {
          definitionVersionId: "usd-eur-closing-v1",
          definitionKey: "usd-eur-closing",
          kind: "fx_rate_definition",
          semanticVersion: "1.0.0",
          versionHash: definition.activation!.definitionVersionHash,
          documentHash: canonicalHash({ neutral: "fx-definition" }),
          approvalEventHash: canonicalHash({ approval: "usd-eur-closing" })
        },
        approvalEvidence: {
          status: "approved",
          proposedBy: "fx-maker",
          approvedBy: "fx-checker",
          approvedAt: "2025-12-02T00:00:00.000Z",
          approvalEventHash: canonicalHash({ approval: "usd-eur-closing" })
        },
        executionDocument: definition
      })
    },
    material: { loadRateMaterial: async () => material() },
    snapshots: {
      resolveCertifiedSourceSnapshot: async () => ({
        tenantId: "tenant-a",
        snapshotId: "fx-snapshot-2026-08-13",
        snapshotHash: SNAPSHOT_HASH,
        sourceContract: SOURCE_CONTRACT,
        certifiedAt: "2026-08-13T00:30:00.000Z"
      })
    },
    evidence,
    clock: () => new Date("2026-08-13T02:00:00.000Z")
  });
}

function actor() {
  return {
    tenantId: "tenant-a",
    actorId: "fx-operator",
    authority: "platform_operator" as const,
    identitySource: "server_derived" as const
  };
}

function activeDefinition() {
  const activationBody = {
    authority: "governed_definition_v2_lifecycle" as const,
    tenantId: "tenant-a",
    fxDefinitionId: "usd-eur-closing",
    version: "1.0.0",
    definitionVersionId: "usd-eur-closing-v1",
    definitionVersionHash: canonicalHash({ version: "usd-eur-closing-v1" }),
    activationEventId: "usd-eur-closing-active",
    tenantSequence: 5,
    previousEventHash: canonicalHash({ event: "approved" }),
    activationEventHash: canonicalHash({ event: "active" }),
    activatedBy: "fx-activator",
    activatedAt: "2025-12-03T00:00:00.000Z"
  };
  return createFxRateDefinitionV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    fxDefinitionId: "usd-eur-closing",
    version: "1.0.0",
    status: "active",
    sourceContract: SOURCE_CONTRACT,
    provider: "approved-fx-provider",
    pair: { baseCurrency: "USD", quoteCurrency: "EUR" },
    rateType: "closing",
    sourceConvention: "base_to_quote",
    ratePrecision: 6,
    baseAmountPrecision: 2,
    quoteAmountPrecision: 2,
    effectiveFrom: "2026-01-01",
    createdBy: "fx-maker",
    createdAt: "2025-12-01T00:00:00.000Z",
    approvedBy: "fx-checker",
    approvedAt: "2025-12-02T00:00:00.000Z",
    activation: { ...activationBody, referenceHash: canonicalHash(activationBody) }
  });
}
