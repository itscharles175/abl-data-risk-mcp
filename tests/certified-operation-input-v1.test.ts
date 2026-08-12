import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createAnalysisInputLineageV1,
  createBlockedInputPopulationV1,
  createCertifiedInputPopulationV1,
  type AnalysisInputLineageV1,
  type CertifiedInputPopulationV1,
  type InputPopulationV1
} from "../src/contracts/certified-lineage-v1.js";
import {
  createCertifiedOperationInputV1,
  parseCertifiedOperationInputV1
} from "../src/contracts/certified-operation-input-v1.js";
import {
  ContractValidationError,
  canonicalHash,
  type CanonicalJsonValue,
  type Sha256Hash
} from "../src/contracts/canonical.js";

const PAYLOAD = Object.freeze({
  availability: "920.25",
  eligibleReceivables: "1000.25",
  facilityId: "facility-1",
  reserve: "80.00",
  rowCount: 3
} satisfies CanonicalJsonValue);

test("certified operation envelopes canonically bind the payload and certified lineage", () => {
  const payloadHash = canonicalHash(PAYLOAD);
  const lineage = lineageFixture("borrowing_base", [populationFixture("certified_sidecar", payloadHash)]);

  const envelope = createCertifiedOperationInputV1({
    contractVersion: 1,
    inputKind: "borrowing_base",
    payload: PAYLOAD,
    payloadHash,
    lineage
  });

  assert.match(envelope.envelopeHash, /^sha256:[a-f0-9]{64}$/);
  assert.equal(envelope.payloadHash, lineage.sidecars[0]?.populationHash);
  assert.deepEqual(parseCertifiedOperationInputV1(JSON.parse(JSON.stringify(envelope))), envelope);
  assert.equal(Object.isFrozen(envelope), true);
});

test("operation envelope parsing rejects payload and envelope tampering", () => {
  const payloadHash = canonicalHash(PAYLOAD);
  const lineage = lineageFixture("borrowing_base", [populationFixture("certified_sidecar", payloadHash)]);
  const envelope = createCertifiedOperationInputV1({
    contractVersion: 1,
    inputKind: "borrowing_base",
    payload: PAYLOAD,
    payloadHash,
    lineage
  });

  assert.throws(
    () => parseCertifiedOperationInputV1({ ...envelope, payload: { ...PAYLOAD, reserve: "81.00" } }),
    (error: unknown) => contractError(error, "HASH_MISMATCH")
  );
  assert.throws(
    () => parseCertifiedOperationInputV1({ ...envelope, purpose: "unexpected" }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
  assert.throws(
    () => parseCertifiedOperationInputV1({ ...envelope, envelopeHash: canonicalHash("wrong") }),
    (error: unknown) => contractError(error, "HASH_MISMATCH")
  );
});

test("operation envelopes require the exact analysis kind and exactly one certified sidecar", () => {
  const payloadHash = canonicalHash(PAYLOAD);
  const certifiedSidecar = populationFixture("certified_sidecar", payloadHash);

  assert.throws(
    () =>
      createCertifiedOperationInputV1({
        contractVersion: 1,
        inputKind: "borrowing_base",
        payload: PAYLOAD,
        payloadHash,
        lineage: lineageFixture("monitoring", [certifiedSidecar])
      }),
    (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
  );
  for (const sidecars of [[], [certifiedSidecar, populationFixture("certified_sidecar", payloadHash, "sidecar-2")]]) {
    assert.throws(
      () =>
        createCertifiedOperationInputV1({
          contractVersion: 1,
          inputKind: "borrowing_base",
          payload: PAYLOAD,
          payloadHash,
          lineage: lineageFixture("borrowing_base", sidecars)
        }),
      (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
    );
  }
});

test("operation envelopes reject blocked or population-mismatched sidecars", () => {
  const payloadHash = canonicalHash(PAYLOAD);
  const blocked = blockedPopulationFixture(payloadHash);
  assert.throws(
    () =>
      createCertifiedOperationInputV1({
        contractVersion: 1,
        inputKind: "borrowing_base",
        payload: PAYLOAD,
        payloadHash,
        lineage: lineageFixture("borrowing_base", [blocked])
      }),
    (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
  );

  const mismatched = populationFixture("certified_sidecar", canonicalHash("another population"));
  assert.throws(
    () =>
      createCertifiedOperationInputV1({
        contractVersion: 1,
        inputKind: "borrowing_base",
        payload: PAYLOAD,
        payloadHash,
        lineage: lineageFixture("borrowing_base", [mismatched])
      }),
    (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
  );
});

function lineageFixture(
  analysisKind: "borrowing_base" | "monitoring",
  sidecars: readonly InputPopulationV1[]
): AnalysisInputLineageV1 {
  return createAnalysisInputLineageV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    analysisKind,
    primary: populationFixture("canonical_snapshot", canonicalHash("primary population"), "snapshot-population"),
    sidecars,
    definitions: [
      {
        definitionId: `${analysisKind}-methodology`,
        version: "1",
        definitionHash: canonicalHash(`${analysisKind}-methodology-v1`)
      }
    ],
    derivationHash: canonicalHash(`${analysisKind}-derivation`),
    assembledAt: "2026-08-12T12:00:00.000Z"
  });
}

function populationFixture(
  populationKind: "canonical_snapshot" | "certified_sidecar",
  populationHash: Sha256Hash,
  populationId = "sidecar-1"
): CertifiedInputPopulationV1 {
  return createCertifiedInputPopulationV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    populationId,
    populationKind,
    purpose: populationKind === "canonical_snapshot" ? "certified loan tape" : "certified operation input",
    snapshot: {
      snapshotId: "snapshot-1",
      snapshotHash: canonicalHash("snapshot manifest"),
      contentHash: canonicalHash("snapshot contents")
    },
    mappingApplication: {
      mappingApplicationId: "mapping-application-1",
      mappingApplicationHash: canonicalHash("mapping application"),
      mappingSpecId: "mapping-spec-1",
      mappingSpecHash: canonicalHash("mapping specification")
    },
    populationHash,
    fieldSetHash: canonicalHash(`${populationId}-fields`),
    rowCount: 3,
    dataQuality: {
      runId: `${populationId}-dq`,
      rulesetId: "dq-ruleset-1",
      rulesetHash: canonicalHash("dq ruleset"),
      resultHash: canonicalHash(`${populationId}-dq-result`),
      publicationDecision: "publish",
      blockerCodes: []
    },
    reconciliation: {
      reconciliationId: `${populationId}-reconciliation`,
      definitionHash: canonicalHash("reconciliation definition"),
      resultHash: canonicalHash(`${populationId}-reconciliation-result`),
      passed: true,
      populationHash
    },
    certificationStatus: "certified",
    certifiedBy: "checker",
    certifiedAt: "2026-08-12T11:00:00.000Z"
  });
}

function blockedPopulationFixture(populationHash: Sha256Hash): InputPopulationV1 {
  const certified = populationFixture("certified_sidecar", populationHash);
  return createBlockedInputPopulationV1({
    contractVersion: 1,
    tenantId: certified.tenantId,
    populationId: certified.populationId,
    populationKind: "certified_sidecar",
    purpose: certified.purpose,
    snapshot: certified.snapshot,
    mappingApplication: certified.mappingApplication,
    populationHash: certified.populationHash,
    fieldSetHash: certified.fieldSetHash,
    rowCount: certified.rowCount,
    dataQuality: { ...certified.dataQuality, publicationDecision: "block", blockerCodes: ["DQ_BLOCK"] },
    reconciliation: certified.reconciliation,
    certificationStatus: "blocked",
    blockedAt: "2026-08-12T11:00:00.000Z"
  });
}

function contractError(error: unknown, code: ContractValidationError["code"]): boolean {
  return error instanceof ContractValidationError && error.code === code;
}
