import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalHash,
  createGovernedDatasetScopeBindingV1,
  createSourceContractV1,
  parseDatasetSnapshotV2,
  type GovernedDatasetScopeBindingV1,
  type SourceContractV1
} from "../src/contracts/index.js";
import { InMemoryImmutableRepository } from "../src/repositories/in-memory.js";
import {
  createGovernedSnapshotCommitLineageV1,
  type GovernedDatasetSnapshotCommitRepositoryV1
} from "../src/repositories/governed-snapshot-commit.js";
import type {
  RepositoryPutResult,
  RepositoryWriteContext
} from "../src/repositories/ports.js";
import { RepositoryError } from "../src/repositories/ports.js";
import {
  ModernSnapshotCaptureError,
  ModernSnapshotCaptureServiceV1,
  type ModernSnapshotExtractionReceiptV1,
  type TrustedModernSnapshotExtractionV1
} from "../src/services/modern-snapshot-capture.js";

const FIRST_CAPTURED_AT = "2026-08-13T12:03:00.000Z";

test("modern capture accepts IDs only and persists content-addressed PostgreSQL evidence", async () => {
  const source = sourceContract("postgresql");
  const binding = scopeBinding(source);
  let authorityInput: Record<string, unknown> | undefined;
  const fixture = captureFixture(source, binding, (input) => {
    authorityInput = input as unknown as Record<string, unknown>;
    return extractionEvidence(source, binding);
  });

  const result = await fixture.service.capture(operator(), request());

  assert.deepEqual(Object.keys(authorityInput ?? {}).sort(), [
    "actorId",
    "datasetId",
    "deliveryId",
    "facilityId",
    "limits",
    "scopeBinding",
    "snapshotId",
    "sourceContract",
    "sourceDelivery",
    "tenantId"
  ]);
  assert.equal(result.snapshot.tenantId, "tenant-a");
  assert.equal(result.snapshot.sourceContract.sourceContractHash, source.sourceContractHash);
  assert.equal(result.snapshot.hashes.extractionHash, result.receipt.receiptHash);
  assert.equal(result.receipt.hashes.profileHash, hash("profile"));
  assert.equal(result.receipt.facilityId, "facility-auto-1");
  assert.equal(result.snapshot.createdBy, "operator-1");
  assert.equal(result.receiptReplayed, false);
  assert.equal(result.snapshotReplayed, false);
  assert.equal(
    (await fixture.receipts.get("tenant-a", `${snapshotId()}:extraction`))?.receiptHash,
    result.receipt.receiptHash
  );
  assert.equal(
    parseDatasetSnapshotV2(
      await fixture.snapshots.get("tenant-a", snapshotId())
    ).snapshotHash,
    result.snapshot.snapshotHash
  );
});

test("capture replays before source access and repairs a receipt-only crash window", async () => {
  const source = sourceContract("postgresql");
  const binding = scopeBinding(source);
  const receipts = receiptRepository();
  const firstSnapshots = snapshotRepository();
  let extractionCalls = 0;
  const first = captureFixture(
    source,
    binding,
    async () => {
      extractionCalls += 1;
      return extractionEvidence(source, binding);
    },
    { receipts, snapshots: firstSnapshots }
  );
  const captured = await first.service.capture(operator(), request());
  const replayed = await first.service.capture(operator(), request());
  assert.equal(replayed.receiptReplayed, true);
  assert.equal(replayed.snapshotReplayed, true);
  assert.equal(replayed.snapshot.snapshotHash, captured.snapshot.snapshotHash);
  assert.equal(extractionCalls, 1);

  const recoveredSnapshots = snapshotRepository();
  const recovery = captureFixture(
    source,
    binding,
    async () => {
      throw new Error("source must not be read during durable recovery");
    },
    {
      receipts,
      snapshots: recoveredSnapshots,
      sourceResolved: () => {
        throw new Error("current source authority must not gate frozen recovery");
      }
    }
  );
  const recovered = await recovery.service.capture(operator(), request());
  assert.equal(recovered.receiptReplayed, true);
  assert.equal(recovered.snapshotReplayed, false);
  assert.equal(recovered.snapshot.snapshotHash, captured.snapshot.snapshotHash);

  await assert.rejects(
    recovery.service.capture({ ...operator(), actorId: "operator-2" }, request()),
    captureError("EVIDENCE_INVALID")
  );
});

test("modern capture binds immutable XLSX and Parquet object versions and parser evidence", async () => {
  for (const kind of ["object_xlsx", "object_parquet"] as const) {
    const source = sourceContract(kind);
    const binding = scopeBinding(source);
    const extension = kind === "object_xlsx" ? "xlsx" : "parquet";
    const extraction = extractionEvidence(source, binding, {
      hashes: evidenceHashes(source, "original")
    });
    const fixture = captureFixture(source, binding, async () => extraction);

    const result = await fixture.service.capture(operator(), request());

    assert.equal(result.snapshot.delivery.mode, "object_storage");
    assert.equal(result.snapshot.delivery.format, extension);
    assert.equal(result.snapshot.immutableSourceVersion, result.receipt.sourceDelivery.sourceVersionHash);
    assert.equal(result.receipt.deliveryId, "delivery-2026-08");
    assert.equal(result.receipt.hashes.parserHash, parserHash(source));
  }
});

test("capture rejects request smuggling before consulting any authority", async () => {
  const source = sourceContract("postgresql");
  const binding = scopeBinding(source);
  let sourceCalls = 0;
  const fixture = captureFixture(source, binding, async () => extractionEvidence(source, binding), {
    sourceResolved: () => {
      sourceCalls += 1;
      return source;
    }
  });

  await assert.rejects(
    fixture.service.capture(operator(), {
      ...request(),
      sql: "select * from loans",
      rawRows: [{ loan_id: "1" }],
      actorId: "attacker",
      snapshotId: "caller-chosen-snapshot",
      sourceHash: hash("forged")
    } as never),
    captureError("INVALID_REQUEST")
  );
  assert.equal(sourceCalls, 0);
});

test("capture fails closed on authority substitution, missing sections, and extraction bounds", async () => {
  const source = sourceContract("postgresql");
  const binding = scopeBinding(source);

  for (const [expectedCode, override] of [
    ["EXTRACTION_SUBSTITUTION", { datasetId: "dataset-other" }],
    [
      "REQUIRED_SECTION_MISSING",
      {
        rowCount: 0,
        sections: [{ sectionId: "loans", required: true, present: false, rowCount: 0 }]
      }
    ],
    [
      "EXTRACTION_LIMIT_EXCEEDED",
      {
        rowCount: 11,
        sections: [section("loans", 11)]
      }
    ]
  ] as const) {
    const fixture = captureFixture(source, binding, async () =>
      extractionEvidence(source, binding, override as Partial<TrustedModernSnapshotExtractionV1>)
    );
    await assert.rejects(
      fixture.service.capture(operator(), request()),
      captureError(expectedCode)
    );
    assert.equal((await fixture.snapshots.list("tenant-a")).items.length, 0);
    assert.equal((await fixture.receipts.list("tenant-a")).items.length, 0);
  }
});

test("capture rejects future periods and source approval after extraction", async () => {
  const source = sourceContract("postgresql");
  const binding = scopeBinding(source);
  const future = captureFixture(source, binding, async () =>
    extractionEvidence(source, binding, { asOfDate: "2026-08-14" })
  );
  await assert.rejects(future.service.capture(operator(), request()), captureError("EVIDENCE_INVALID"));

  const lateApproval = createSourceContractV1({
    ...withoutSourceHash(source),
    approvedAt: "2026-08-13T12:01:30.000Z"
  });
  const lateBinding = scopeBinding(lateApproval);
  const fixture = captureFixture(lateApproval, lateBinding, async () =>
    extractionEvidence(lateApproval, lateBinding)
  );
  await assert.rejects(fixture.service.capture(operator(), request()), captureError("EVIDENCE_INVALID"));
});

test("capture enforces single-chain correction lineage before persistence", async () => {
  const source = sourceContract("postgresql");
  const binding = scopeBinding(source);
  const receipts = receiptRepository();
  const snapshots = snapshotRepository();
  const originalFixture = captureFixture(
    source,
    binding,
    async () => extractionEvidence(source, binding),
    { receipts, snapshots }
  );
  const original = await originalFixture.service.capture(operator(), request());

  const correctionEvidence = extractionEvidence(source, binding, {
    snapshotId: snapshotId("delivery-2026-08-c1"),
    deliveryId: "delivery-2026-08-c1",
    knowledge: {
      sourceObservedAt: "2026-08-13T12:04:00.000Z",
      extractedAt: "2026-08-13T12:05:00.000Z",
      receivedAt: "2026-08-13T12:06:00.000Z"
    },
    hashes: evidenceHashes(source, "correction-1"),
    correction: {
      kind: "correction",
      correctsSnapshotId: original.snapshot.snapshotId,
      correctsSnapshotHash: original.snapshot.snapshotHash,
      correctionSequence: 1,
      reasonCode: "servicer_restated",
      reason: "Servicer replaced the delivery.",
      detectedAt: "2026-08-13T12:10:00.000Z"
    }
  });
  const correctionFixture = captureFixture(source, binding, async () => correctionEvidence, {
    receipts,
    snapshots,
    now: "2026-08-13T13:00:00.000Z"
  });
  const corrected = await correctionFixture.service.capture(operator(), {
    sourceContractId: source.sourceContractId,
    deliveryId: "delivery-2026-08-c1"
  });
  assert.equal(corrected.snapshot.correction.kind, "correction");

  const branchFixture = captureFixture(
    source,
    binding,
    async () => ({
      ...correctionEvidence,
      snapshotId: snapshotId("delivery-2026-08-branch"),
      deliveryId: "delivery-2026-08-branch"
    }),
    { receipts, snapshots, now: "2026-08-13T13:01:00.000Z" }
  );
  await assert.rejects(
    branchFixture.service.capture(operator(), {
      sourceContractId: source.sourceContractId,
      deliveryId: "delivery-2026-08-branch"
    }),
    captureError("CORRECTION_LINEAGE_INVALID")
  );
  assert.equal((await snapshots.list("tenant-a")).items.length, 2);
  // Bronze extraction evidence remains append-only even when the governed
  // snapshot CAS rejects a second child for the predecessor.
  assert.equal((await receipts.list("tenant-a")).items.length, 3);
});

function captureFixture(
  source: SourceContractV1,
  binding: GovernedDatasetScopeBindingV1,
  extract: (input: Record<string, unknown>) =>
    | TrustedModernSnapshotExtractionV1
    | Promise<TrustedModernSnapshotExtractionV1>,
  overrides: {
    readonly receipts?: InMemoryImmutableRepository<ModernSnapshotExtractionReceiptV1>;
    readonly snapshots?: GovernedDatasetSnapshotCommitRepositoryV1;
    readonly now?: string;
    readonly sourceResolved?: () => SourceContractV1 | undefined;
  } = {}
) {
  const receipts = overrides.receipts ?? receiptRepository();
  const snapshots = overrides.snapshots ?? snapshotRepository();
  const service = new ModernSnapshotCaptureServiceV1({
    sourceDeliveries: {
      resolveGovernedDeliveryForCapture: async (input) => {
        const resolved = overrides.sourceResolved?.() ?? source;
        return resolved === undefined
          ? undefined
          : governedDeliveryResolution(resolved, binding, input.deliveryId);
      }
    },
    extraction: {
      extract: async (input) => extract(input as unknown as Record<string, unknown>)
    },
    receipts,
    snapshots,
    now: () => overrides.now ?? FIRST_CAPTURED_AT
  });
  return { service, receipts, snapshots };
}

function receiptRepository() {
  return new InMemoryImmutableRepository<ModernSnapshotExtractionReceiptV1>(
    "modern-extraction-receipts",
    (record) => record.receiptId
  );
}

function snapshotRepository() {
  const repository = new InMemoryImmutableRepository<ReturnType<typeof parseDatasetSnapshotV2>>(
    "modern-dataset-snapshots",
    (record) => record.snapshotId,
    (record) => {
      parseDatasetSnapshotV2(record);
    }
  );
  return new TestGovernedSnapshotRepository(repository);
}

class TestGovernedSnapshotRepository implements GovernedDatasetSnapshotCommitRepositoryV1 {
  readonly #repository: InMemoryImmutableRepository<ReturnType<typeof parseDatasetSnapshotV2>>;
  readonly #lineages = new Map<string, ReturnType<typeof createGovernedSnapshotCommitLineageV1>>();

  constructor(repository: InMemoryImmutableRepository<ReturnType<typeof parseDatasetSnapshotV2>>) {
    this.#repository = repository;
  }

  async commitGovernedCapture(
    snapshot: ReturnType<typeof parseDatasetSnapshotV2>,
    lineage: ReturnType<typeof createGovernedSnapshotCommitLineageV1>,
    context: RepositoryWriteContext
  ): Promise<RepositoryPutResult<ReturnType<typeof parseDatasetSnapshotV2>>> {
    const prior = this.#lineages.get(`${snapshot.tenantId}\u0000${snapshot.snapshotId}`);
    if (prior !== undefined) assert.deepEqual(prior, lineage);
    const population = canonicalHash({
      sourceContractHash: lineage.sourceContract.sourceContractHash,
      bindingHash: lineage.scopeBinding.bindingHash,
      datasetId: lineage.datasetId,
      facilityId: lineage.facilityId
    });
    for (const [key, existingLineage] of this.#lineages) {
      if (!key.startsWith(`${snapshot.tenantId}\u0000`)) continue;
      const existingPopulation = canonicalHash({
        sourceContractHash: existingLineage.sourceContract.sourceContractHash,
        bindingHash: existingLineage.scopeBinding.bindingHash,
        datasetId: existingLineage.datasetId,
        facilityId: existingLineage.facilityId
      });
      const existingSnapshot = await this.#repository.get(
        snapshot.tenantId,
        existingLineage.snapshotId
      );
      if (
        snapshot.correction.kind === "original" &&
        existingSnapshot?.correction.kind === "original" &&
        existingSnapshot.asOfDate === snapshot.asOfDate &&
        existingPopulation === population
      ) {
        throw new RepositoryError("ALREADY_EXISTS", "Governed original already exists");
      }
      if (
        snapshot.correction.kind === "correction" &&
        existingSnapshot?.correction.kind === "correction" &&
        existingSnapshot.correction.correctsSnapshotId === snapshot.correction.correctsSnapshotId
      ) {
        throw new RepositoryError("CONCURRENCY_CONFLICT", "Correction predecessor already replaced");
      }
    }
    if (snapshot.correction.kind === "correction") {
      const predecessor = this.#lineages.get(
        `${snapshot.tenantId}\u0000${snapshot.correction.correctsSnapshotId}`
      );
      if (!predecessor) throw new RepositoryError("NOT_FOUND", "Correction predecessor missing");
      const predecessorPopulation = canonicalHash({
        sourceContractHash: predecessor.sourceContract.sourceContractHash,
        bindingHash: predecessor.scopeBinding.bindingHash,
        datasetId: predecessor.datasetId,
        facilityId: predecessor.facilityId
      });
      if (predecessorPopulation !== population) {
        throw new RepositoryError("INTEGRITY_FAILURE", "Correction crossed governed population");
      }
    }
    const result = await this.#repository.put(snapshot, context);
    this.#lineages.set(`${snapshot.tenantId}\u0000${snapshot.snapshotId}`, lineage);
    return result;
  }

  put(...args: Parameters<typeof this.#repository.put>) {
    return this.#repository.put(...args);
  }

  get(...args: Parameters<typeof this.#repository.get>) {
    return this.#repository.get(...args);
  }

  list(...args: Parameters<typeof this.#repository.list>) {
    return this.#repository.list(...args);
  }
}

function governedDeliveryResolution(
  source: SourceContractV1,
  binding: GovernedDatasetScopeBindingV1,
  deliveryId = "delivery-2026-08"
) {
  const objectLocator = source.delivery.mode === "object_storage"
    ? {
        mode: "object_storage" as const,
        format: source.delivery.format,
        connectorId: source.delivery.connectorId,
        bucket: source.delivery.bucket,
        objectKey: `synthetic-auto/2026-08.${source.delivery.format}`,
        immutableVersionId: "version-v17",
        immutableVersionHash: hash("version-v17"),
        contentHash: hash("content:original"),
        byteCount: 512
      }
    : undefined;
  const locator = objectLocator ?? {
    mode: "postgresql_pull" as const,
    connectorId: source.delivery.connectorId,
    catalog: source.delivery.catalog,
    schema: source.delivery.schema,
    relation: source.delivery.relation,
    relationIdentityHash: canonicalHash({
      connectorId: source.delivery.connectorId,
      catalog: source.delivery.catalog ?? null,
      schema: source.delivery.schema,
      relation: source.delivery.relation
    }),
    sourceVersionHash: hash("source-version")
  };
  const isCorrection = deliveryId !== "delivery-2026-08";
  const body = {
    contractVersion: 1 as const,
    tenantId: source.tenantId,
    deliveryId,
    deliveryRevision: 1,
    datasetId: binding.datasetId,
    facilityId: binding.scope.scopeId,
    sourceContract: {
      sourceContractId: source.sourceContractId,
      revision: source.revision,
      sourceContractHash: source.sourceContractHash
    },
    scopeBinding: {
      bindingId: binding.bindingId,
      revision: binding.revision,
      bindingHash: binding.bindingHash
    },
    locator,
    sourceObservedAt: isCorrection
      ? "2026-08-13T12:04:00.000Z"
      : "2026-08-13T12:00:00.000Z",
    receivedAt: isCorrection
      ? "2026-08-13T12:04:30.000Z"
      : "2026-08-13T12:00:30.000Z",
    status: "usable" as const,
    recordedBy: "operator-1",
    identitySource: "server_derived" as const,
    recordedAt: isCorrection
      ? "2026-08-13T12:04:30.000Z"
      : "2026-08-13T12:00:30.000Z",
    previousDeliveryHash: null
  };
  return {
    delivery: { ...body, deliveryHash: canonicalHash(body) },
    sourceContract: source,
    scopeBinding: binding
  };
}

function operator() {
  return {
    tenantId: "tenant-a",
    actorId: "operator-1",
    authority: "platform_operator" as const,
    identitySource: "server_derived" as const
  };
}

function request() {
  return {
    sourceContractId: "loan-tape-source",
    deliveryId: "delivery-2026-08"
  };
}

function snapshotId(deliveryId = "delivery-2026-08") {
  return `snapshot-${canonicalHash({
    contractVersion: 1,
    tenantId: "tenant-a",
    sourceContractId: "loan-tape-source",
    deliveryId
  }).slice("sha256:".length, "sha256:".length + 32)}`;
}

function sourceContract(kind: "postgresql" | "object_xlsx" | "object_parquet"): SourceContractV1 {
  const delivery = kind === "postgresql"
    ? {
        mode: "postgresql_pull" as const,
        connectorId: "postgres-primary",
        credentialRef: "kms/postgres/readonly",
        catalog: "risk",
        schema: "servicing",
        relation: "loan_tape"
      }
    : {
        mode: "object_storage" as const,
        format: kind === "object_xlsx" ? "xlsx" as const : "parquet" as const,
        connectorId: "object-primary",
        credentialRef: "kms/object/readonly",
        bucket: "loan-tapes",
        keyPattern: kind === "object_xlsx" ? "synthetic-auto/*.xlsx" : "synthetic-auto/*.parquet",
        immutableVersionRequired: true as const
      };
  const parserPolicy = kind === "postgresql"
    ? {
        format: "sql_rows" as const,
        parserId: "postgres-exact-v1",
        parserVersion: "1.0.0",
        optionsHash: hash("parser-options"),
        exactDecimalMode: "string" as const,
        timezone: "UTC" as const
      }
    : kind === "object_xlsx"
    ? {
        format: "xlsx" as const,
        parserId: "xlsx-safe-v1",
        parserVersion: "1.0.0",
        optionsHash: hash("parser-options"),
        rejectMacros: true as const,
        rejectExternalLinks: true as const,
        rejectFormulaCells: true as const,
        dateSystem: "reject_mixed" as const,
        exactDecimalMode: "string" as const
      }
    : {
        format: "parquet" as const,
        parserId: "parquet-safe-v1",
        parserVersion: "1.0.0",
        optionsHash: hash("parser-options"),
        exactDecimalMode: "string" as const,
        timezone: "UTC" as const,
        rejectSchemaMerging: true
      };
  return createSourceContractV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    sourceContractId: "loan-tape-source",
    sourceKey: "loan-tape",
    revision: 1,
    status: "active",
    delivery,
    schemaPolicy: {
      columns: [
        { sourceName: "assetNumber", ordinal: 0, nativeType: "text", nullable: false, required: true },
        { sourceName: "actualEndBalance", ordinal: 1, nativeType: "decimal", nullable: false, required: true }
      ],
      allowUnknownColumns: false,
      requireStableOrdinals: true
    },
    parserPolicy,
    extractionPolicy: {
      mode: "full",
      readOnly: true,
      maximumRows: 10,
      maximumColumns: 25,
      maximumBytes: 100_000,
      timeoutMs: 5_000,
      cursorRows: 5
    },
    sections: [{
      sectionId: "loans",
      required: true,
      selector: "Loan Tape",
      keyFields: ["assetNumber"],
      minimumRows: 1,
      maximumRows: 10
    }],
    effectiveFrom: "2026-01-01",
    createdBy: "steward-1",
    createdAt: "2026-01-02T00:00:00.000Z",
    approvedBy: "reviewer-1",
    approvedAt: "2026-01-03T00:00:00.000Z"
  });
}

function scopeBinding(source: SourceContractV1): GovernedDatasetScopeBindingV1 {
  return createGovernedDatasetScopeBindingV1({
    contractVersion: 1,
    tenantId: source.tenantId,
    bindingId: "loan-tape-facility-binding",
    revision: 1,
    datasetId: "dataset-loans",
    sourceContract: {
      sourceContractId: source.sourceContractId,
      revision: source.revision,
      sourceContractHash: source.sourceContractHash
    },
    scope: { scopeType: "facility", scopeId: "facility-auto-1" },
    effectiveFrom: "2026-01-01"
  });
}

function extractionEvidence(
  source: SourceContractV1,
  binding: GovernedDatasetScopeBindingV1,
  overrides: Partial<TrustedModernSnapshotExtractionV1> = {}
): TrustedModernSnapshotExtractionV1 {
  return {
    tenantId: source.tenantId,
    datasetId: binding.datasetId,
    facilityId: binding.scope.scopeId,
    snapshotId: snapshotId(),
    deliveryId: "delivery-2026-08",
    asOfDate: "2026-07-31",
    knowledge: {
      sourceObservedAt: "2026-08-13T12:00:00.000Z",
      extractedAt: "2026-08-13T12:01:00.000Z",
      receivedAt: "2026-08-13T12:02:00.000Z"
    },
    watermark: { mode: "none" },
    hashes: evidenceHashes(source, "original"),
    rowCount: 2,
    columnCount: 2,
    byteCount: 512,
    elapsedMs: 250,
    sections: [section("loans", 2)],
    correction: { kind: "original" },
    ...overrides
  };
}

function evidenceHashes(source: SourceContractV1, suffix: string) {
  return {
    contentHash: hash(`content:${suffix}`),
    schemaHash: hash(`schema:${suffix}`),
    profileHash: hash(`profile${suffix === "original" ? "" : `:${suffix}`}`),
    catalogHash: hash(`catalog:${suffix}`),
    parserHash: parserHash(source)
  };
}

function parserHash(source: SourceContractV1) {
  return canonicalHash({
    parserId: source.parserPolicy.parserId,
    parserVersion: source.parserPolicy.parserVersion,
    optionsHash: source.parserPolicy.optionsHash
  });
}

function section(sectionId: string, rowCount: number) {
  return {
    sectionId,
    required: true,
    present: true,
    rowCount,
    contentHash: hash(`section:${sectionId}:${rowCount}`),
    schemaHash: hash(`section-schema:${sectionId}`),
    controlPopulationHash: hash(`section-population:${sectionId}:${rowCount}`)
  };
}

function hash(value: string) {
  return canonicalHash(value);
}

function withoutSourceHash(source: SourceContractV1) {
  const { sourceContractHash: _sourceContractHash, ...body } = source;
  return body;
}

function captureError(code: ModernSnapshotCaptureError["code"]) {
  return (error: unknown) => error instanceof ModernSnapshotCaptureError && error.code === code;
}
