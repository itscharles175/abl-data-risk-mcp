import assert from "node:assert/strict";
import test from "node:test";

import {
  ContractValidationError,
  canonicalHash
} from "../src/contracts/canonical.js";
import {
  createFxConversionLineageV1,
  createFxRateDefinitionV1,
  createFxRateEvidenceV1,
  parseFxConversionLineageV1,
  parseFxRateDefinitionV1,
  parseFxRateEvidenceV1
} from "../src/contracts/fx-evidence-v1.js";

const SOURCE_CONTRACT = {
  sourceContractId: "fx-provider-daily",
  revision: 3,
  sourceContractHash: canonicalHash({ contract: "fx-provider-daily", revision: 3 })
} as const;

test("FX evidence freezes maker-checker definition, source snapshot, rate, and half-even conversion", () => {
  const definition = activeDefinition();
  const rate = createFxRateEvidenceV1({
    definition,
    tenantId: "tenant-a",
    rateEvidenceId: "usd-eur-2026-08-13",
    sourceSnapshot: {
      snapshotId: "fx-snapshot-2026-08-13",
      snapshotHash: canonicalHash({ snapshot: "fx-snapshot-2026-08-13" }),
      sourceContract: SOURCE_CONTRACT
    },
    effectiveAt: "2026-08-13T16:00:00.000Z",
    observedAt: "2026-08-13T16:00:01.000Z",
    receivedAt: "2026-08-13T16:00:02.000Z",
    sourceRate: "1.234567",
    capturedBy: "fx-capture-service"
  });
  assert.equal(rate.normalizedBaseToQuoteRate, "1.234567");
  assert.equal(parseFxRateEvidenceV1(rate).rateEvidenceHash, rate.rateEvidenceHash);

  const conversion = createFxConversionLineageV1({
    definition,
    rateEvidence: rate,
    tenantId: "tenant-a",
    conversionId: "conversion-1",
    purpose: "portfolio-surveillance",
    sourceAmount: "10.005",
    sourceCurrency: "USD",
    targetCurrency: "EUR",
    performedAt: "2026-08-13T16:01:00.000Z",
    performedBy: "surveillance-worker"
  });
  assert.equal(conversion.convertedAmount, "12.35");
  assert.equal(conversion.direction, "base_to_quote");
  assert.equal(parseFxConversionLineageV1(conversion).conversionHash, conversion.conversionHash);
});

test("inverse source convention and reverse conversion remain deterministic", () => {
  const definition = createFxRateDefinitionV1({
    ...withoutHash(activeDefinition()),
    fxDefinitionId: "eur-usd-inverse",
    sourceConvention: "quote_to_base",
    ratePrecision: 8,
    activation: activationReference("eur-usd-inverse", "1.0.0")
  });
  const rate = createFxRateEvidenceV1({
    definition,
    tenantId: "tenant-a",
    rateEvidenceId: "inverse-rate",
    sourceSnapshot: {
      snapshotId: "fx-snapshot-inverse",
      snapshotHash: canonicalHash({ snapshot: "inverse" }),
      sourceContract: SOURCE_CONTRACT
    },
    effectiveAt: "2026-08-13T16:00:00.000Z",
    observedAt: "2026-08-13T16:00:00.000Z",
    receivedAt: "2026-08-13T16:00:00.000Z",
    sourceRate: "0.8",
    capturedBy: "fx-capture-service"
  });
  assert.equal(rate.normalizedBaseToQuoteRate, "1.25000000");
  const conversion = createFxConversionLineageV1({
    definition,
    rateEvidence: rate,
    tenantId: "tenant-a",
    conversionId: "reverse-conversion",
    purpose: "reporting",
    sourceAmount: "12.50",
    sourceCurrency: "EUR",
    targetCurrency: "USD",
    performedAt: "2026-08-13T17:00:00.000Z",
    performedBy: "report-worker"
  });
  assert.equal(conversion.convertedAmount, "10.00");
  assert.equal(conversion.direction, "quote_to_base");
});

test("FX contracts reject self-approval, inactive rates, cross-tenant evidence, and unfrozen pairs", () => {
  assert.throws(
    () => createFxRateDefinitionV1({
      ...withoutHash(activeDefinition()),
      createdBy: "same-actor",
      approvedBy: "same-actor"
    }),
    ContractValidationError
  );
  const {
    approvedBy: _approvedBy,
    approvedAt: _approvedAt,
    activation: _activation,
    ...proposalBody
  } = withoutHash(activeDefinition());
  const proposed = createFxRateDefinitionV1({
    ...proposalBody,
    status: "proposed",
  });
  assert.throws(
    () => createFxRateEvidenceV1({
      definition: proposed,
      tenantId: "tenant-a",
      rateEvidenceId: "inactive",
      sourceSnapshot: {
        snapshotId: "snapshot",
        snapshotHash: canonicalHash({ snapshot: 1 }),
        sourceContract: SOURCE_CONTRACT
      },
      effectiveAt: "2026-08-13T16:00:00.000Z",
      observedAt: "2026-08-13T16:00:00.000Z",
      receivedAt: "2026-08-13T16:00:00.000Z",
      sourceRate: "1.2",
      capturedBy: "capture"
    }),
    /active definition/u
  );

  const definition = activeDefinition();
  const rate = validRate(definition);
  assert.throws(
    () => createFxConversionLineageV1({
      definition,
      rateEvidence: rate,
      tenantId: "tenant-b",
      conversionId: "cross-tenant",
      purpose: "reporting",
      sourceAmount: "1",
      sourceCurrency: "USD",
      targetCurrency: "EUR",
      performedAt: "2026-08-13T18:00:00.000Z",
      performedBy: "worker"
    }),
    /tenant/u
  );
  assert.throws(
    () => createFxConversionLineageV1({
      definition,
      rateEvidence: rate,
      tenantId: "tenant-a",
      conversionId: "wrong-pair",
      purpose: "reporting",
      sourceAmount: "1",
      sourceCurrency: "USD",
      targetCurrency: "CAD",
      performedAt: "2026-08-13T18:00:00.000Z",
      performedBy: "worker"
    }),
    /currencies/u
  );
});

test("FX parsers reject rehashed precision and rate lineage tampering", () => {
  const definition = activeDefinition();
  const rate = validRate(definition);
  const { rateEvidenceHash: _rateHash, ...rateBody } = rate;
  assert.throws(
    () => parseFxRateEvidenceV1({
      ...rateBody,
      normalizedBaseToQuoteRate: "9.999999",
      rateEvidenceHash: canonicalHash({ ...rateBody, normalizedBaseToQuoteRate: "9.999999" })
    }),
    /normalized rate/iu
  );

  const conversion = createFxConversionLineageV1({
    definition,
    rateEvidence: rate,
    tenantId: "tenant-a",
    conversionId: "tamper-conversion",
    purpose: "reporting",
    sourceAmount: "100",
    sourceCurrency: "USD",
    targetCurrency: "EUR",
    performedAt: "2026-08-13T18:00:00.000Z",
    performedBy: "worker"
  });
  const { conversionHash: _conversionHash, ...conversionBody } = conversion;
  assert.throws(
    () => parseFxConversionLineageV1({
      ...conversionBody,
      convertedAmount: "999.00",
      conversionHash: canonicalHash({ ...conversionBody, convertedAmount: "999.00" })
    }),
    /converted amount/iu
  );
  assert.throws(
    () => parseFxConversionLineageV1({
      ...conversionBody,
      targetPrecision: 3,
      convertedAmount: "120.000",
      conversionHash: canonicalHash({
        ...conversionBody,
        targetPrecision: 3,
        convertedAmount: "120.000"
      })
    }),
    ContractValidationError
  );
  const forgedRate = {
    ...conversionBody.rateEvidence,
    sourceRate: "9",
    rateEvidenceHash: canonicalHash({
      ...withoutRateHash(conversionBody.rateEvidence),
      sourceRate: "9"
    })
  };
  assert.throws(
    () => parseFxConversionLineageV1({
      ...conversionBody,
      rateEvidence: forgedRate,
      conversionHash: canonicalHash({ ...conversionBody, rateEvidence: forgedRate })
    }),
    /normalized rate/iu
  );
  assert.equal(parseFxRateDefinitionV1(definition).definitionHash, definition.definitionHash);
});

test("FX evidence rejects tenant-substituted and rehashed activation lineage", () => {
  const definition = activeDefinition();
  const rate = validRate(definition);
  const { rateEvidenceHash: _rateHash, ...rateBody } = rate;

  const substitutedTenant = {
    ...rateBody,
    tenantId: "tenant-b"
  };
  assert.throws(
    () => parseFxRateEvidenceV1({
      ...substitutedTenant,
      rateEvidenceHash: canonicalHash(substitutedTenant)
    }),
    (error: unknown) => hasContractIssue(error, "definition.tenantId")
  );

  const retenantDefinition = {
    ...rateBody.definition,
    tenantId: "tenant-b"
  };
  const retenantRateBody = {
    ...rateBody,
    tenantId: "tenant-b",
    definition: retenantDefinition
  };
  assert.throws(
    () => parseFxRateEvidenceV1({
      ...retenantRateBody,
      rateEvidenceHash: canonicalHash(retenantRateBody)
    }),
    (error: unknown) => hasContractIssue(error, "definition.activation.tenantId")
  );

  const substitutedActivationBody = {
    ...withoutActivationReferenceHash(rateBody.definition.activation),
    tenantId: "tenant-b"
  };
  const substitutedActivation = {
    ...substitutedActivationBody,
    referenceHash: canonicalHash(substitutedActivationBody)
  };
  const substitutedDefinition = {
    ...rateBody.definition,
    activation: substitutedActivation
  };
  const substitutedActivationRate = {
    ...rateBody,
    definition: substitutedDefinition
  };
  assert.throws(
    () => parseFxRateEvidenceV1({
      ...substitutedActivationRate,
      rateEvidenceHash: canonicalHash(substitutedActivationRate)
    }),
    (error: unknown) => hasContractIssue(error, "definition.activation.tenantId")
  );

  const { definitionHash: _definitionHash, ...definitionBody } = definition;
  const substitutedDefinitionBody = {
    ...definitionBody,
    tenantId: "tenant-b"
  };
  assert.throws(
    () => parseFxRateDefinitionV1({
      ...substitutedDefinitionBody,
      definitionHash: canonicalHash(substitutedDefinitionBody)
    }),
    (error: unknown) => hasContractIssue(error, "activation.tenantId")
  );

  const tamperedActivation = {
    ...rateBody.definition.activation,
    tenantSequence: rateBody.definition.activation.tenantSequence + 1
  };
  const tamperedDefinition = {
    ...rateBody.definition,
    activation: tamperedActivation
  };
  const tamperedRateBody = {
    ...rateBody,
    definition: tamperedDefinition
  };
  assert.throws(
    () => parseFxRateEvidenceV1({
      ...tamperedRateBody,
      rateEvidenceHash: canonicalHash(tamperedRateBody)
    }),
    (error: unknown) => hasContractIssue(error, "referenceHash")
  );
});

test("FX exact-decimal bounds preserve maximum-width identity and reject overflow", () => {
  const definition = createFxRateDefinitionV1({
    ...withoutHash(activeDefinition()),
    fxDefinitionId: "usd-eur-exact-bound",
    activation: activationReference("usd-eur-exact-bound", "1.0.0")
  });
  const rate = createFxRateEvidenceV1({
    definition,
    tenantId: "tenant-a",
    rateEvidenceId: "exact-bound-rate",
    sourceSnapshot: {
      snapshotId: "fx-snapshot-exact-bound",
      snapshotHash: canonicalHash({ snapshot: "exact-bound" }),
      sourceContract: SOURCE_CONTRACT
    },
    effectiveAt: "2026-08-13T16:00:00.000Z",
    observedAt: "2026-08-13T16:00:00.000Z",
    receivedAt: "2026-08-13T16:00:00.000Z",
    sourceRate: "1.000000",
    capturedBy: "fx-capture-service"
  });
  const maximumWidthAmount = "9".repeat(256);
  const conversion = createFxConversionLineageV1({
    definition,
    rateEvidence: rate,
    tenantId: "tenant-a",
    conversionId: "exact-bound-conversion",
    purpose: "precision-regression",
    sourceAmount: maximumWidthAmount,
    sourceCurrency: "USD",
    targetCurrency: "EUR",
    performedAt: "2026-08-13T17:00:00.000Z",
    performedBy: "surveillance-worker"
  });
  assert.equal(conversion.convertedAmount, `${maximumWidthAmount}.00`);
  assert.equal(parseFxConversionLineageV1(conversion).convertedAmount, `${maximumWidthAmount}.00`);

  assert.throws(
    () => createFxConversionLineageV1({
      definition,
      rateEvidence: rate,
      tenantId: "tenant-a",
      conversionId: "exact-bound-overflow",
      purpose: "precision-regression",
      sourceAmount: "9".repeat(257),
      sourceCurrency: "USD",
      targetCurrency: "EUR",
      performedAt: "2026-08-13T17:00:00.000Z",
      performedBy: "surveillance-worker"
    }),
    (error: unknown) => hasContractIssue(error, "at most 256")
  );
});

function activeDefinition() {
  const activation = activationReference("usd-eur-closing", "1.0.0");
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
    activation
  });
}

function activationReference(fxDefinitionId: string, version: string) {
  const body = {
    authority: "governed_definition_v2_lifecycle" as const,
    tenantId: "tenant-a",
    fxDefinitionId,
    version,
    definitionVersionId: `${fxDefinitionId}-definition-version`,
    definitionVersionHash: canonicalHash({ fxDefinitionId, version, document: "fx-definition" }),
    activationEventId: `${fxDefinitionId}-activation`,
    tenantSequence: 7,
    previousEventHash: canonicalHash({ event: "previous-fx-definition-event" }),
    activationEventHash: canonicalHash({ fxDefinitionId, version, event: "activated" }),
    activatedBy: "fx-activation-checker",
    activatedAt: "2025-12-03T00:00:00.000Z"
  };
  return { ...body, referenceHash: canonicalHash(body) };
}

function validRate(definition: ReturnType<typeof activeDefinition>) {
  return createFxRateEvidenceV1({
    definition,
    tenantId: "tenant-a",
    rateEvidenceId: "valid-rate",
    sourceSnapshot: {
      snapshotId: "fx-snapshot",
      snapshotHash: canonicalHash({ snapshot: "valid" }),
      sourceContract: SOURCE_CONTRACT
    },
    effectiveAt: "2026-08-13T16:00:00.000Z",
    observedAt: "2026-08-13T16:00:00.000Z",
    receivedAt: "2026-08-13T16:00:01.000Z",
    sourceRate: "1.2",
    capturedBy: "fx-capture-service"
  });
}

function withoutHash(value: ReturnType<typeof activeDefinition>) {
  const { definitionHash: _definitionHash, ...body } = value;
  return body;
}

function withoutRateHash(value: ReturnType<typeof validRate>) {
  const { rateEvidenceHash: _rateEvidenceHash, ...body } = value;
  return body;
}

function withoutActivationReferenceHash(
  value: ReturnType<typeof activationReference>
) {
  const { referenceHash: _referenceHash, ...body } = value;
  return body;
}

function hasContractIssue(error: unknown, fragment: string): boolean {
  return error instanceof ContractValidationError &&
    error.issues.some((issue) => issue.includes(fragment));
}
