import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import {
  canonicalHash,
  createFxRateDefinitionV1,
  createFxRateEvidenceV1,
  type FxRateDefinitionV1
} from "../src/contracts/index.js";
import {
  FxRateEvidenceStoreError,
  SqliteFxRateEvidenceStoreV1,
  type FxRateEvidenceWriteContextV1
} from "../src/control/fx-rate-evidence-store-v1.js";

const SOURCE_CONTRACT = {
  sourceContractId: "approved-fx-provider-daily",
  revision: 1,
  sourceContractHash: canonicalHash({ source: "approved-fx-provider-daily", revision: 1 })
} as const;

test("FX evidence storage is immutable, actor-idempotent, and reopen-safe", () => {
  const fixture = databaseFixture("replay");
  try {
    const store = new SqliteFxRateEvidenceStoreV1(fixture.path);
    const evidence = rate("tenant-a", "usd-eur-rate-1", {
      effectiveAt: "2026-08-13T16:00:00.000Z",
      receivedAt: "2026-08-13T16:00:02.000Z",
      sourceRate: "1.100000"
    });
    const context = writeContext("rate-1", "2026-08-13T16:00:03.000Z");

    const first = store.record(evidence, context);
    assert.equal(first.replayed, false);
    const replay = store.record(evidence, context);
    assert.equal(replay.replayed, true);
    assert.deepEqual(replay.evidence, evidence);

    assert.throws(
      () => store.record(rate("tenant-a", "usd-eur-rate-2", {
        effectiveAt: "2026-08-13T16:00:00.000Z",
        receivedAt: "2026-08-13T16:00:02.000Z",
        sourceRate: "1.200000"
      }), context),
      (error: unknown) => storeError(error, "IDEMPOTENCY_CONFLICT")
    );
    assert.throws(
      () => store.record(evidence, { ...context, idempotencyKey: "rate-1-new-key" }),
      (error: unknown) => storeError(error, "CONFLICT")
    );
    store.close();

    const reopened = new SqliteFxRateEvidenceStoreV1(fixture.path);
    assert.deepEqual(reopened.get("tenant-a", evidence.rateEvidenceId), evidence);
    assert.equal(reopened.record(evidence, context).replayed, true);
    reopened.close();
  } finally {
    fixture.cleanup();
  }
});

test("effective FX selection freezes its knowledge cutoff and prefers corrected evidence deterministically", () => {
  const fixture = databaseFixture("selection");
  try {
    const store = new SqliteFxRateEvidenceStoreV1(fixture.path);
    const original = rate("tenant-a", "usd-eur-original", {
      effectiveAt: "2026-08-13T16:00:00.000Z",
      receivedAt: "2026-08-13T16:01:00.000Z",
      sourceRate: "1.100000"
    });
    const correction = rate("tenant-a", "usd-eur-correction", {
      effectiveAt: "2026-08-13T16:00:00.000Z",
      receivedAt: "2026-08-13T18:00:00.000Z",
      sourceRate: "1.200000"
    });
    const newerEffectiveRate = rate("tenant-a", "usd-eur-later", {
      effectiveAt: "2026-08-13T17:00:00.000Z",
      receivedAt: "2026-08-13T17:01:00.000Z",
      sourceRate: "1.300000"
    });
    for (const [index, evidence] of [original, correction, newerEffectiveRate].entries()) {
      store.record(evidence, writeContext(`selection-${index}`, "2026-08-13T18:01:00.000Z"));
    }

    assert.equal(
      store.selectEffective(selection("2026-08-13T16:30:00.000Z", "2026-08-13T16:30:00.000Z"))
        .rateEvidenceId,
      original.rateEvidenceId
    );
    assert.equal(
      store.selectEffective(selection("2026-08-13T16:30:00.000Z", "2026-08-13T18:30:00.000Z"))
        .rateEvidenceId,
      correction.rateEvidenceId
    );
    assert.equal(
      store.selectEffective(selection("2026-08-13T18:30:00.000Z", "2026-08-13T18:30:00.000Z"))
        .rateEvidenceId,
      newerEffectiveRate.rateEvidenceId
    );
    assert.throws(
      () => store.selectEffective({
        ...selection("2026-08-13T18:30:00.000Z", "2026-08-13T18:30:00.000Z"),
        definitionHash: canonicalHash({ successor: "usd-eur-closing-v2" })
      }),
      (error: unknown) => storeError(error, "NOT_FOUND")
    );
    store.close();
  } finally {
    fixture.cleanup();
  }
});

test("tenant scope prevents cross-tenant FX evidence reads and selection", () => {
  const fixture = databaseFixture("tenant-scope");
  try {
    const store = new SqliteFxRateEvidenceStoreV1(fixture.path);
    const tenantA = rate("tenant-a", "shared-rate-id", {
      effectiveAt: "2026-08-13T16:00:00.000Z",
      receivedAt: "2026-08-13T16:01:00.000Z",
      sourceRate: "1.100000"
    });
    const tenantB = rate("tenant-b", "shared-rate-id", {
      effectiveAt: "2026-08-13T16:00:00.000Z",
      receivedAt: "2026-08-13T16:01:00.000Z",
      sourceRate: "1.200000"
    });
    store.record(tenantA, writeContext("tenant-a-rate", "2026-08-13T16:02:00.000Z", "tenant-a"));
    store.record(tenantB, writeContext("tenant-b-rate", "2026-08-13T16:02:00.000Z", "tenant-b"));

    assert.equal(store.get("tenant-b", tenantA.rateEvidenceId)?.rateEvidenceHash, tenantB.rateEvidenceHash);
    assert.equal(
      store.selectEffective({
        ...selection("2026-08-13T16:30:00.000Z", "2026-08-13T16:30:00.000Z"),
        tenantId: "tenant-b",
        definitionHash: definition("tenant-b").definitionHash
      })
        .rateEvidenceHash,
      tenantB.rateEvidenceHash
    );
    assert.equal(store.get("tenant-a", "missing-rate"), undefined);
    store.close();
  } finally {
    fixture.cleanup();
  }
});

test("FX evidence store rejects direct mutation and fails closed after a schema-preserving tamper", () => {
  const fixture = databaseFixture("tamper");
  try {
    const store = new SqliteFxRateEvidenceStoreV1(fixture.path);
    const evidence = rate("tenant-a", "tamper-rate", {
      effectiveAt: "2026-08-13T16:00:00.000Z",
      receivedAt: "2026-08-13T16:01:00.000Z",
      sourceRate: "1.100000"
    });
    store.record(evidence, writeContext("tamper-rate", "2026-08-13T16:02:00.000Z"));
    store.close();

    const attacker = new DatabaseSync(fixture.path, { enableForeignKeyConstraints: true });
    assert.throws(
      () => attacker.exec("UPDATE fx_rate_evidence_v1 SET received_at = '2026-08-13T19:00:00.000Z'"),
      /FX rate evidence is immutable/u
    );
    attacker.exec(`
      DROP TRIGGER fx_rate_evidence_v1_no_update;
      UPDATE fx_rate_evidence_v1 SET received_at = '2026-08-13T19:00:00.000Z';
      CREATE TRIGGER fx_rate_evidence_v1_no_update
      BEFORE UPDATE ON fx_rate_evidence_v1
      BEGIN SELECT RAISE(ABORT, 'FX rate evidence is immutable'); END;
    `);
    attacker.close();

    assert.throws(
      () => new SqliteFxRateEvidenceStoreV1(fixture.path),
      (error: unknown) => storeError(error, "INTEGRITY_FAILURE")
    );
  } finally {
    fixture.cleanup();
  }
});

function databaseFixture(label: string) {
  const directory = mkdtempSync(join(tmpdir(), `abl-fx-rate-evidence-${label}-`));
  return {
    path: join(directory, "fx-rate-evidence.sqlite"),
    cleanup: () => rmSync(directory, { recursive: true, force: true })
  };
}

function writeContext(
  idempotencyKey: string,
  recordedAt: string,
  tenantId = "tenant-a"
): FxRateEvidenceWriteContextV1 {
  return { tenantId, actorId: "fx-capture-worker", idempotencyKey, recordedAt };
}

function selection(asOf: string, knowledgeCutoff: string) {
  const definitionHash = definition("tenant-a").definitionHash;
  return {
    tenantId: "tenant-a",
    fxDefinitionId: "usd-eur-closing",
    definitionHash,
    baseCurrency: "USD",
    quoteCurrency: "EUR",
    rateType: "closing" as const,
    asOf,
    knowledgeCutoff
  };
}

function rate(
  tenantId: string,
  rateEvidenceId: string,
  input: Readonly<{ effectiveAt: string; receivedAt: string; sourceRate: string }>
) {
  return createFxRateEvidenceV1({
    definition: definition(tenantId),
    tenantId,
    rateEvidenceId,
    sourceSnapshot: {
      snapshotId: `${tenantId}-fx-snapshot`,
      snapshotHash: canonicalHash({ tenantId, snapshot: "approved-fx-delivery" }),
      sourceContract: SOURCE_CONTRACT
    },
    effectiveAt: input.effectiveAt,
    observedAt: input.effectiveAt,
    receivedAt: input.receivedAt,
    sourceRate: input.sourceRate,
    capturedBy: "fx-capture-worker"
  });
}

function definition(tenantId: string): FxRateDefinitionV1 {
  const fxDefinitionId = "usd-eur-closing";
  const activationBody = {
    authority: "governed_definition_v2_lifecycle" as const,
    tenantId,
    fxDefinitionId,
    version: "1.0.0",
    definitionVersionId: `${tenantId}-usd-eur-definition-v1`,
    definitionVersionHash: canonicalHash({ tenantId, fxDefinitionId, version: "1.0.0" }),
    activationEventId: `${tenantId}-usd-eur-activation-v1`,
    tenantSequence: 1,
    previousEventHash: canonicalHash({ tenantId, previous: "fx-definition" }),
    activationEventHash: canonicalHash({ tenantId, event: "activated" }),
    activatedBy: "fx-activation-checker",
    activatedAt: "2026-01-02T00:00:00.000Z"
  };
  return createFxRateDefinitionV1({
    contractVersion: 1,
    tenantId,
    fxDefinitionId,
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
    createdBy: "fx-definition-maker",
    createdAt: "2026-01-01T00:00:00.000Z",
    approvedBy: "fx-definition-checker",
    approvedAt: "2026-01-01T12:00:00.000Z",
    activation: { ...activationBody, referenceHash: canonicalHash(activationBody) }
  });
}

function storeError(error: unknown, code: FxRateEvidenceStoreError["code"]): boolean {
  assert.ok(error instanceof FxRateEvidenceStoreError);
  assert.equal(error.code, code);
  return true;
}
