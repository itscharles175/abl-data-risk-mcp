import assert from "node:assert/strict";
import test from "node:test";

import {
  ContractValidationError,
  InMemoryHistoricalRuntimeResolver,
  assertCanonicalHash,
  assertCertifiedAnalysisInputs,
  assertMappingApplicationBindings,
  assertResolvedBundle,
  canonicalHash,
  canonicalJson,
  createAnalysisInputLineageV1,
  createBlockedInputPopulationV1,
  createCertifiedInputPopulationV1,
  createDatasetSnapshotV2,
  createHistoricalRuntimeBundleV1,
  createMappingApplicationV1,
  createMappingSpecV2,
  createSourceContractV1,
  legacyFieldMappingsToRules,
  mappingRulesToLegacyFieldMappings,
  parseDatasetSnapshotV2,
  parseMappingSpecV2,
  parseSourceContractV1,
  type DictionaryBundleReferenceV1,
  type HistoricalRuntimeBundleV1,
  type MappingSpecV2,
  type SourceContractV1
} from "../src/contracts/index.js";

const HASH_A = `sha256:${"a".repeat(64)}` as const;
const HASH_B = `sha256:${"b".repeat(64)}` as const;
const HASH_C = `sha256:${"c".repeat(64)}` as const;
const HASH_D = `sha256:${"d".repeat(64)}` as const;
const HASH_E = `sha256:${"e".repeat(64)}` as const;
const HASH_F = `sha256:${"f".repeat(64)}` as const;
const CREATED_AT = "2026-08-12T12:00:00.000Z";

test("canonical hashes are property-order independent and reject lossy numeric values", () => {
  const left = { b: [true, "2.50"], a: { z: null, n: 2 } };
  const right = { a: { n: 2, z: null }, b: [true, "2.50"] };
  assert.equal(canonicalJson(left), canonicalJson(right));
  assert.equal(canonicalHash(left), canonicalHash(right));
  assert.match(canonicalHash(left), /^sha256:[a-f0-9]{64}$/);
  assert.throws(
    () => canonicalJson({ amount: 0.1 }),
    (error: unknown) => contractError(error, "NON_CANONICAL_VALUE")
  );
  assert.throws(
    () => assertCanonicalHash(left, HASH_A),
    (error: unknown) => contractError(error, "HASH_MISMATCH")
  );
});

test("SourceContractV1 is strict, content-addressed, and never stores a connection credential", () => {
  const source = sourceContract();
  assert.equal(source.contractVersion, 1);
  assert.equal(source.delivery.mode, "postgresql_pull");
  assert.equal(parseSourceContractV1(JSON.parse(JSON.stringify(source))).sourceContractHash, source.sourceContractHash);
  assert.ok(Object.isFrozen(source));
  assert.ok(Object.isFrozen(source.schemaPolicy.columns));

  assert.throws(
    () => sourceContract({ credentialRef: "postgres://user:secret@example.test/db" }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
  assert.throws(
    () => parseSourceContractV1({ ...source, sourceKey: "changed" }),
    (error: unknown) => contractError(error, "HASH_MISMATCH")
  );
  assert.throws(
    () => parseSourceContractV1({ ...source, futureField: true }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
});

test("MappingSpecV2 is reusable across snapshots while applications bind each historical period", () => {
  const source = sourceContract();
  const runtime = runtimeBundle();
  const spec = mappingSpec(source, runtime.dictionary);
  const applications = ["2026-06-30", "2026-07-31", "2026-08-31"].map((asOfDate, index) =>
    createMappingApplicationV1({
      contractVersion: 1,
      tenantId: "tenant-a",
      mappingApplicationId: `map-app-${index + 1}`,
      snapshot: {
        snapshotId: `snapshot-${asOfDate}`,
        snapshotHash: hashOf(`snapshot:${asOfDate}`),
        contentHash: hashOf(`content:${asOfDate}`)
      },
      mappingSpec: {
        mappingSpecId: spec.mappingSpecId,
        revision: spec.revision,
        mappingSpecHash: spec.mappingSpecHash
      },
      dictionaryBundle: runtime.dictionary,
      runtimeBundle: {
        runtimeBundleId: runtime.runtimeBundleId,
        runtimeBundleHash: runtime.runtimeBundleHash,
        runtimeVersion: runtime.runtimeVersion
      },
      inputPopulationHash: hashOf(`input:${asOfDate}`),
      outputPopulationHash: hashOf(`output:${asOfDate}`),
      inputRowCount: 100,
      outputRowCount: 99,
      rejectedRowCount: 1,
      appliedBy: "worker-1",
      appliedAt: CREATED_AT
    })
  );

  for (const application of applications) assertMappingApplicationBindings(application, spec);
  assert.equal(new Set(applications.map((application) => application.mappingSpec.mappingSpecHash)).size, 1);
  assert.equal(new Set(applications.map((application) => application.snapshot.snapshotId)).size, 3);

  assert.throws(
    () => createMappingApplicationV1({ ...withoutApplicationHash(applications[0]!), outputRowCount: 98 }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
});

test("MappingSpecV2 supports a bounded declarative AST and an explicit v1 bridge", () => {
  const source = sourceContract();
  const runtime = runtimeBundle();
  const legacy = [
    { sourceColumn: "loan_number", canonicalField: "loan_id" },
    { sourceColumn: "balance", canonicalField: "outstanding_balance" }
  ] as const;
  assert.deepEqual(mappingRulesToLegacyFieldMappings(legacyFieldMappingsToRules(legacy)), legacy);

  const transformed = mappingSpec(source, runtime.dictionary);
  assert.equal(transformed.rules[1]?.expression.op, "scale_decimal");
  assert.throws(
    () => mappingRulesToLegacyFieldMappings(transformed.rules),
    (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
  );

  const tampered = JSON.parse(JSON.stringify(transformed)) as Record<string, unknown>;
  tampered.requiredCanonicalFields = ["loan_id", "not_mapped"];
  delete tampered.mappingSpecHash;
  assert.throws(
    () => createMappingSpecV2(tampered as never),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
  assert.throws(
    () => parseMappingSpecV2({ ...transformed, revision: 2 }),
    (error: unknown) => contractError(error, "HASH_MISMATCH")
  );
});

test("historical runtime resolver preserves and verifies immutable historical content", async () => {
  const runtime = runtimeBundle();
  const dictionaryContent = { dictionaryVersion: "1.0.0", fields: [{ id: "loan_id" }] };
  const reference: DictionaryBundleReferenceV1 = {
    ...runtime.dictionary,
    contentHash: canonicalHash(dictionaryContent)
  };
  assert.doesNotThrow(() => assertResolvedBundle(reference, { reference, content: dictionaryContent }));
  const rewrittenRuntime = createHistoricalRuntimeBundleV1({
    ...withoutRuntimeHash(runtime),
    dictionary: reference
  });
  const resolver = new InMemoryHistoricalRuntimeResolver(
    [rewrittenRuntime],
    [{ reference, content: dictionaryContent }]
  );
  assert.deepEqual((await resolver.resolveDictionary(reference)).content, dictionaryContent);
  assert.equal(
    (await resolver.resolveRuntimeBundle({
      runtimeBundleId: rewrittenRuntime.runtimeBundleId,
      runtimeBundleHash: rewrittenRuntime.runtimeBundleHash
    })).runtimeBundleHash,
    rewrittenRuntime.runtimeBundleHash
  );
  assert.throws(
    () => assertResolvedBundle(reference, { reference, content: { fields: [] } }),
    (error: unknown) => contractError(error, "HASH_MISMATCH")
  );
});

test("DatasetSnapshotV2 validates knowledge time, sections, watermarks, and correction lineage", () => {
  const snapshot = datasetSnapshot();
  assert.equal(parseDatasetSnapshotV2(JSON.parse(JSON.stringify(snapshot))).snapshotHash, snapshot.snapshotHash);
  assert.equal(snapshot.hashes.catalogHash, HASH_B);
  assert.equal(snapshot.hashes.parserHash, HASH_C);
  assert.equal(snapshot.hashes.extractionHash, HASH_D);

  assert.throws(
    () =>
      datasetSnapshot({
        knowledge: {
          sourceObservedAt: "2026-08-12T12:01:00.000Z",
          extractedAt: "2026-08-12T12:00:00.000Z",
          receivedAt: "2026-08-12T12:02:00.000Z",
          persistedAt: "2026-08-12T12:03:00.000Z"
        }
      }),
    (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
  );
  assert.throws(
    () => datasetSnapshot({ sections: [{ sectionId: "loans", required: true, present: false, rowCount: 10 }] }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
});

test("monitoring and borrowing-base lineage rejects every uncertified primary or sidecar population", () => {
  const primary = certifiedPopulation("primary", "canonical_snapshot");
  const sidecar = certifiedPopulation("cash", "certified_sidecar");
  const lineage = createAnalysisInputLineageV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    analysisKind: "borrowing_base",
    primary,
    sidecars: [sidecar],
    definitions: [{ definitionId: "bbc-policy", version: "2.0.0", definitionHash: HASH_A }],
    derivationHash: HASH_B,
    assembledAt: CREATED_AT
  });
  assert.doesNotThrow(() => assertCertifiedAnalysisInputs(lineage));

  const blocked = createBlockedInputPopulationV1({
    ...withoutCertificationHash(sidecar),
    certificationStatus: "blocked",
    dataQuality: {
      ...sidecar.dataQuality,
      publicationDecision: "block",
      blockerCodes: ["missing_control"]
    },
    reconciliation: { ...sidecar.reconciliation, passed: false },
    blockedAt: CREATED_AT
  });
  const blockedLineage = createAnalysisInputLineageV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    analysisKind: "monitoring",
    primary,
    sidecars: [blocked],
    definitions: [{ definitionId: "monitor", version: "1.0.0", definitionHash: HASH_A }],
    derivationHash: HASH_B,
    assembledAt: CREATED_AT
  });
  assert.throws(
    () => assertCertifiedAnalysisInputs(blockedLineage),
    (error: unknown) => contractError(error, "INVARIANT_VIOLATION")
  );
});

function sourceContract(
  overrides: { readonly credentialRef?: string } = {}
): SourceContractV1 {
  return createSourceContractV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    sourceContractId: "loan-tape-postgres",
    sourceKey: "loan-tape",
    revision: 1,
    status: "active",
    delivery: {
      mode: "postgresql_pull",
      connectorId: "connector-1",
      credentialRef: overrides.credentialRef ?? "secret/postgres/loan-tape",
      catalog: "risk",
      schema: "abl",
      relation: "loan_tape"
    },
    schemaPolicy: {
      columns: [
        { sourceName: "loan_number", ordinal: 0, nativeType: "text", nullable: false, required: true },
        { sourceName: "balance_cents", ordinal: 1, nativeType: "bigint", nullable: false, required: true }
      ],
      allowUnknownColumns: false,
      requireStableOrdinals: true
    },
    parserPolicy: {
      format: "sql_rows",
      parserId: "postgres-text-v1",
      parserVersion: "1.0.0",
      optionsHash: HASH_A,
      exactDecimalMode: "string",
      timezone: "UTC"
    },
    extractionPolicy: {
      mode: "watermark",
      watermarkField: "updated_at",
      readOnly: true,
      maximumRows: 1_000_000,
      maximumColumns: 200,
      maximumBytes: 1_000_000_000,
      timeoutMs: 60_000,
      cursorRows: 5_000
    },
    sections: [
      {
        sectionId: "loans",
        required: true,
        selector: "loan_tape",
        keyFields: ["loan_number"],
        balanceField: "balance_cents",
        currencyField: "currency"
      }
    ],
    effectiveFrom: "2026-01-01",
    createdBy: "steward-1",
    createdAt: CREATED_AT,
    approvedBy: "reviewer-1",
    approvedAt: CREATED_AT
  });
}

function runtimeBundle(): HistoricalRuntimeBundleV1 {
  return createHistoricalRuntimeBundleV1({
    contractVersion: 1,
    runtimeBundleId: "runtime-2026-08",
    runtimeVersion: "1.0.0",
    dictionary: {
      contractVersion: 1,
      bundleKind: "dictionary",
      bundleId: "dictionary-core",
      version: "1.0.0",
      contentHash: HASH_A,
      artifactId: "artifact-dictionary",
      mediaType: "application/json",
      createdAt: CREATED_AT,
      dictionaryVersion: "1.0.0",
      dictionaryHash: HASH_B,
      fieldPolicyVersion: "1.0.0",
      fieldPolicyHash: HASH_C
    },
    mappingCompiler: {
      contractVersion: 1,
      bundleKind: "mapping_compiler",
      bundleId: "mapping-compiler",
      version: "2.0.0",
      contentHash: HASH_D,
      artifactId: "artifact-compiler",
      mediaType: "application/json",
      createdAt: CREATED_AT
    },
    methodologies: [
      {
        contractVersion: 1,
        bundleKind: "methodology",
        bundleId: "stratification",
        version: "2.0.0",
        contentHash: HASH_E,
        artifactId: "artifact-methodology",
        mediaType: "application/json",
        createdAt: CREATED_AT
      }
    ],
    assembledAt: CREATED_AT
  });
}

function mappingSpec(
  source: SourceContractV1,
  dictionary: DictionaryBundleReferenceV1
): MappingSpecV2 {
  return createMappingSpecV2({
    contractVersion: 2,
    tenantId: "tenant-a",
    mappingSpecId: "loan-tape-map",
    mappingKey: "loan-tape",
    revision: 1,
    status: "active",
    sourceContract: {
      sourceContractId: source.sourceContractId,
      revision: source.revision,
      sourceContractHash: source.sourceContractHash
    },
    dictionaryBundle: dictionary,
    rules: [
      {
        ruleId: "loan-id",
        canonicalField: "loan_id",
        expression: { op: "source", column: "loan_number" },
        onError: "fail_application"
      },
      {
        ruleId: "balance",
        canonicalField: "outstanding_balance",
        expression: {
          op: "scale_decimal",
          input: { op: "source", column: "balance_cents" },
          factor: "0.01",
          decimalPlaces: 2,
          rounding: "reject"
        },
        onError: "reject_row"
      }
    ],
    requiredCanonicalFields: ["loan_id", "outstanding_balance"],
    createdBy: "steward-1",
    createdAt: CREATED_AT,
    approvedBy: "reviewer-1",
    approvedAt: CREATED_AT
  });
}

function datasetSnapshot(overrides: Record<string, unknown> = {}) {
  const source = sourceContract();
  return createDatasetSnapshotV2({
    contractVersion: 2,
    tenantId: "tenant-a",
    snapshotId: "snapshot-2026-08-31",
    sourceContract: {
      sourceContractId: source.sourceContractId,
      revision: source.revision,
      sourceContractHash: source.sourceContractHash
    },
    delivery: source.delivery,
    sourceLocator: "postgresql:abl.loan_tape",
    asOfDate: "2026-08-31",
    knowledge: {
      sourceObservedAt: "2026-08-12T12:00:00.000Z",
      extractedAt: "2026-08-12T12:01:00.000Z",
      receivedAt: "2026-08-12T12:02:00.000Z",
      persistedAt: "2026-08-12T12:03:00.000Z"
    },
    watermark: {
      mode: "bounded",
      field: "updated_at",
      lowerExclusive: "2026-07-31T00:00:00.000Z",
      upperInclusive: "2026-08-31T23:59:59.999Z",
      valueType: "datetime"
    },
    hashes: {
      contentHash: HASH_A,
      schemaHash: HASH_A,
      catalogHash: HASH_B,
      parserHash: HASH_C,
      extractionHash: HASH_D
    },
    rowCount: 10,
    byteCount: 1_000,
    sections: [
      {
        sectionId: "loans",
        required: true,
        present: true,
        rowCount: 10,
        contentHash: HASH_E,
        schemaHash: HASH_F,
        balance: "125000.00",
        currency: "USD",
        controlPopulationHash: HASH_B
      }
    ],
    correction: { kind: "original" },
    createdBy: "connector-1",
    ...overrides
  });
}

function certifiedPopulation(
  populationId: string,
  populationKind: "canonical_snapshot" | "certified_sidecar"
) {
  const populationHash = hashOf(`population:${populationId}`);
  return createCertifiedInputPopulationV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    populationId,
    populationKind,
    purpose: populationId === "primary" ? "governed canonical source" : "cash control sidecar",
    snapshot: { snapshotId: "snapshot-1", snapshotHash: HASH_A, contentHash: HASH_B },
    mappingApplication: {
      mappingApplicationId: "application-1",
      mappingApplicationHash: HASH_C,
      mappingSpecId: "mapping-1",
      mappingSpecHash: HASH_D
    },
    populationHash,
    fieldSetHash: HASH_E,
    rowCount: 10,
    dataQuality: {
      runId: `dq-${populationId}`,
      rulesetId: "dq-core",
      rulesetHash: HASH_A,
      resultHash: HASH_B,
      publicationDecision: "publish",
      blockerCodes: []
    },
    reconciliation: {
      reconciliationId: `recon-${populationId}`,
      definitionHash: HASH_C,
      resultHash: HASH_D,
      passed: true,
      populationHash
    },
    certificationStatus: "certified",
    certifiedBy: "reviewer-1",
    certifiedAt: CREATED_AT
  });
}

function withoutApplicationHash(application: ReturnType<typeof createMappingApplicationV1>) {
  const { mappingApplicationHash: _hash, ...body } = application;
  return body;
}

function withoutCertificationHash(population: ReturnType<typeof certifiedPopulation>) {
  const {
    certificationHash: _hash,
    certifiedBy: _certifiedBy,
    certifiedAt: _certifiedAt,
    ...body
  } = population;
  return body;
}

function withoutRuntimeHash(runtime: HistoricalRuntimeBundleV1) {
  const { runtimeBundleHash: _hash, ...body } = runtime;
  return body;
}

function hashOf(value: string): `sha256:${string}` {
  return canonicalHash(value);
}

function contractError(error: unknown, code: ContractValidationError["code"]): boolean {
  return error instanceof ContractValidationError && error.code === code;
}
