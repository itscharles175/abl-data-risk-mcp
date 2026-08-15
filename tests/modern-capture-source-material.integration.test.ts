import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalHash } from "../src/contracts/canonical.js";
import { parseDatasetSnapshotV2 } from "../src/contracts/dataset-snapshot-v2.js";
import { createGovernedDatasetScopeBindingV1 } from "../src/contracts/dataset-scope-binding-v1.js";
import { createSourceContractV1 } from "../src/contracts/source-contract-v1.js";
import { createGovernedSourceDeliveryRecordV1 } from "../src/contracts/source-delivery-authority-v1.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import { InMemoryImmutableRepository } from "../src/repositories/in-memory.js";
import type { GovernedDatasetSnapshotCommitRepositoryV1 } from "../src/repositories/governed-snapshot-commit.js";
import { SqliteCapturedSourceMaterialStoreV1 } from "../src/repositories/captured-source-material-v1.js";
import {
  ModernSnapshotCaptureError,
  ModernSnapshotCaptureServiceV1,
  type ModernSnapshotExtractionReceiptV1,
  type TrustedModernSnapshotExtractionV1
} from "../src/services/modern-snapshot-capture.js";
import {
  ArtifactBackedModernSnapshotSourceEvidenceAuthorityV1,
  CapturedSourceMaterialPublisherV1
} from "../src/services/artifact-backed-modern-source-evidence-v1.js";

const RECORDS = [
  { asset_number: "A-1", ending_balance: "100.00" },
  { asset_number: "A-2", ending_balance: "50.00" }
] as const;
const TRANCHE_RECORDS = [{ tranche_id: "A", ending_balance: "150.00" }] as const;

test("composed capture persists hash-bound source sections that certification can reload", async () => {
  const fixture = createFixture();
  try {
    const captured = await fixture.service.capture(operator(), request());
    const loaded = await fixture.authority.loadSection({
      tenantId: "tenant-a",
      snapshotId: captured.snapshot.snapshotId,
      sectionId: "loans"
    });

    assert.deepEqual(loaded?.records, RECORDS);
    assert.equal(loaded?.snapshotHash, captured.snapshot.snapshotHash);
    assert.equal(loaded?.extractionHash, captured.receipt.receiptHash);
    assert.equal(loaded?.sourceContract.sourceContractHash, captured.snapshot.sourceContract.sourceContractHash);
    assert.equal(loaded?.controlPopulationHash, canonicalHash(RECORDS));
    assert.equal(
      await fixture.authority.loadSection({
        tenantId: "tenant-b",
        snapshotId: captured.snapshot.snapshotId,
        sectionId: "loans"
      }),
      undefined
    );
  } finally {
    fixture.close();
  }
});

test("composed capture rejects missing or control-mismatched source-section records before durable capture", async () => {
  for (const sourceSections of [
    undefined,
    [{ sectionId: "loans", records: [{ asset_number: "A-1", ending_balance: "999.00" }] }]
  ] as const) {
    const fixture = createFixture({ sourceSections });
    try {
      await assert.rejects(
        fixture.service.capture(operator(), request()),
        (error: unknown) => error instanceof ModernSnapshotCaptureError && error.code === "EVIDENCE_INVALID"
      );
      assert.equal((await fixture.receipts.list("tenant-a")).items.length, 0);
      assert.equal((await fixture.snapshots.list("tenant-a")).items.length, 0);
      assert.equal(
        await fixture.authority.loadSection({
          tenantId: "tenant-a",
          snapshotId: snapshotId(),
          sectionId: "loans"
        }),
        undefined
      );
    } finally {
      fixture.close();
    }
  }
});

test("capture retry adopts the materialized capture identity after a pre-receipt crash", async () => {
  const fixture = createFixture({ failAfterMaterialOnce: true });
  try {
    await assert.rejects(
      fixture.service.capture(operator(), request()),
      (error: unknown) => error instanceof ModernSnapshotCaptureError && error.code === "EVIDENCE_INVALID"
    );
    assert.equal((await fixture.receipts.list("tenant-a")).items.length, 0);
    assert.equal((await fixture.snapshots.list("tenant-a")).items.length, 0);

    fixture.setNow("2026-08-13T12:04:00.000Z");
    const retried = await fixture.service.capture(operator(), request());
    assert.equal(retried.receipt.knowledge.persistedAt, "2026-08-13T12:03:00.000Z");
    assert.equal(retried.snapshot.hashes.extractionHash, retried.receipt.receiptHash);
    assert.deepEqual(
      (await fixture.authority.loadSection({
        tenantId: "tenant-a",
        snapshotId: retried.snapshot.snapshotId,
        sectionId: "loans"
      }))?.records,
      RECORDS
    );
  } finally {
    fixture.close();
  }
});

test("multi-section capture retry completes an interrupted immutable material set", async () => {
  const fixture = createFixture({ multiSection: true, failAfterMaterialPublishCount: 1 });
  try {
    await assert.rejects(
      fixture.service.capture(operator(), request()),
      (error: unknown) => error instanceof ModernSnapshotCaptureError && error.code === "EVIDENCE_INVALID"
    );
    assert.equal((await fixture.receipts.list("tenant-a")).items.length, 0);
    assert.equal((await fixture.snapshots.list("tenant-a")).items.length, 0);

    fixture.setNow("2026-08-13T12:05:00.000Z");
    const retried = await fixture.service.capture(operator(), request());
    assert.equal(retried.receipt.knowledge.persistedAt, "2026-08-13T12:03:00.000Z");
    assert.deepEqual(
      (await fixture.authority.loadSection({
        tenantId: "tenant-a",
        snapshotId: retried.snapshot.snapshotId,
        sectionId: "loans"
      }))?.records,
      RECORDS
    );
    assert.deepEqual(
      (await fixture.authority.loadSection({
        tenantId: "tenant-a",
        snapshotId: retried.snapshot.snapshotId,
        sectionId: "tranches"
      }))?.records,
      TRANCHE_RECORDS
    );
  } finally {
    fixture.close();
  }
});

function createFixture(overrides: {
  readonly sourceSections?: TrustedModernSnapshotExtractionV1["sourceSections"];
  readonly failAfterMaterialOnce?: boolean;
  readonly failAfterMaterialPublishCount?: number;
  readonly multiSection?: boolean;
} = {}) {
  const directory = mkdtempSync(join(tmpdir(), "abl-modern-capture-material-"));
  const source = createSourceContractV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    sourceContractId: "loan-tape-source",
    sourceKey: "loan-tape",
    revision: 1,
    status: "active",
    delivery: {
      mode: "postgresql_pull",
      connectorId: "postgres-primary",
      credentialRef: "kms/postgres/readonly",
      catalog: "risk",
      schema: "servicing",
      relation: "loan_tape"
    },
    schemaPolicy: {
      columns: [
        { sourceName: "assetNumber", ordinal: 0, nativeType: "text", nullable: false, required: true },
        { sourceName: "actualEndBalance", ordinal: 1, nativeType: "decimal", nullable: false, required: true }
      ],
      allowUnknownColumns: false,
      requireStableOrdinals: true
    },
    parserPolicy: {
      format: "sql_rows",
      parserId: "postgres-exact-v1",
      parserVersion: "1.0.0",
      optionsHash: hash("parser-options"),
      exactDecimalMode: "string",
      timezone: "UTC"
    },
    extractionPolicy: {
      mode: "full",
      readOnly: true,
      maximumRows: 10,
      maximumColumns: 25,
      maximumBytes: 100_000,
      timeoutMs: 5_000,
      cursorRows: 5
    },
    sections: [
      {
        sectionId: "loans",
        required: true,
        selector: "Loan Tape",
        keyFields: ["assetNumber"],
        minimumRows: 1,
        maximumRows: 10
      },
      ...(overrides.multiSection
        ? [{
            sectionId: "tranches",
            required: true,
            selector: "Tranches",
            keyFields: ["trancheId"],
            minimumRows: 1,
            maximumRows: 10
          }]
        : [])
    ],
    effectiveFrom: "2026-01-01",
    createdBy: "steward-1",
    createdAt: "2026-01-02T00:00:00.000Z",
    approvedBy: "reviewer-1",
    approvedAt: "2026-01-03T00:00:00.000Z"
  });
  const binding = createGovernedDatasetScopeBindingV1({
    contractVersion: 1,
    tenantId: "tenant-a",
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
  const delivery = createGovernedSourceDeliveryRecordV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    deliveryId: "delivery-2026-08",
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
    locator: {
      mode: "postgresql_pull",
      connectorId: "postgres-primary",
      catalog: "risk",
      schema: "servicing",
      relation: "loan_tape",
      relationIdentityHash: canonicalHash({ catalog: "risk", schema: "servicing", relation: "loan_tape" }),
      sourceVersionHash: hash("source-version")
    },
    sourceObservedAt: "2026-08-13T12:00:00.000Z",
    receivedAt: "2026-08-13T12:00:30.000Z",
    status: "usable",
    recordedBy: "operator-1",
    identitySource: "server_derived",
    recordedAt: "2026-08-13T12:00:30.000Z",
    previousDeliveryHash: null
  });
  const receipts = new InMemoryImmutableRepository<ModernSnapshotExtractionReceiptV1>(
    "modern-capture-material-receipts",
    (record) => record.receiptId
  );
  const snapshots = snapshotRepository();
  const artifacts = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "key-2026",
    keys: { "key-2026": Buffer.alloc(32, 43) }
  });
  const material = new SqliteCapturedSourceMaterialStoreV1(join(directory, "material.sqlite"));
  const publisher = new CapturedSourceMaterialPublisherV1({
    artifacts,
    material,
    maximumSectionBytes: 1_000_000
  });
  const authority = new ArtifactBackedModernSnapshotSourceEvidenceAuthorityV1({ artifacts, material });
  let remainingSuccessfulPublishes = overrides.failAfterMaterialPublishCount ??
    (overrides.failAfterMaterialOnce === true ? 1 : undefined);
  let now = "2026-08-13T12:03:00.000Z";
  const sourceMaterial = {
    async publish(input: Parameters<CapturedSourceMaterialPublisherV1["publish"]>[0]) {
      const published = await publisher.publish(input);
      if (remainingSuccessfulPublishes !== undefined) {
        remainingSuccessfulPublishes -= 1;
      }
      if (remainingSuccessfulPublishes === 0) {
        remainingSuccessfulPublishes = undefined;
        throw new Error("simulated pre-receipt crash");
      }
      return published;
    },
    resolveReplayIdentity: publisher.resolveReplayIdentity.bind(publisher)
  };
  const sourceSections = Object.prototype.hasOwnProperty.call(overrides, "sourceSections")
    ? overrides.sourceSections
    : [
        { sectionId: "loans", records: RECORDS },
        ...(overrides.multiSection ? [{ sectionId: "tranches", records: TRANCHE_RECORDS }] : [])
      ];
  const service = new ModernSnapshotCaptureServiceV1({
    sourceDeliveries: {
      resolveGovernedDeliveryForCapture: async () => ({ delivery, sourceContract: source, scopeBinding: binding })
    },
    extraction: {
      extract: async (input) => extraction(input, sourceSections, overrides.multiSection === true)
    },
    receipts,
    snapshots,
    sourceMaterial,
    now: () => now
  });
  return {
    service,
    receipts,
    snapshots,
    authority,
    setNow: (value: string) => { now = value; },
    close: () => {
      material.close();
      rmSync(directory, { recursive: true, force: true });
    }
  };
}

function extraction(
  input: {
    readonly tenantId: string;
    readonly datasetId: string;
    readonly facilityId: string;
    readonly snapshotId: string;
    readonly deliveryId: string;
    readonly sourceContract: { readonly parserPolicy: { readonly parserId: string; readonly parserVersion: string; readonly optionsHash: string } };
  },
  sourceSections: TrustedModernSnapshotExtractionV1["sourceSections"],
  multiSection: boolean
): TrustedModernSnapshotExtractionV1 {
  const sections = [
    {
      sectionId: "loans",
      required: true,
      present: true,
      rowCount: RECORDS.length,
      contentHash: hash("section-content"),
      schemaHash: hash("section-schema"),
      controlPopulationHash: canonicalHash(RECORDS)
    },
    ...(multiSection
      ? [{
          sectionId: "tranches",
          required: true,
          present: true,
          rowCount: TRANCHE_RECORDS.length,
          contentHash: hash("tranche-section-content"),
          schemaHash: hash("tranche-section-schema"),
          controlPopulationHash: canonicalHash(TRANCHE_RECORDS)
        }]
      : [])
  ];
  return {
    tenantId: input.tenantId,
    datasetId: input.datasetId,
    facilityId: input.facilityId,
    snapshotId: input.snapshotId,
    deliveryId: input.deliveryId,
    asOfDate: "2026-07-31",
    knowledge: {
      sourceObservedAt: "2026-08-13T12:00:00.000Z",
      extractedAt: "2026-08-13T12:01:00.000Z",
      receivedAt: "2026-08-13T12:02:00.000Z"
    },
    watermark: { mode: "none" },
    hashes: {
      contentHash: hash("content"),
      schemaHash: hash("schema"),
      profileHash: hash("profile"),
      catalogHash: hash("catalog"),
      parserHash: canonicalHash({
        parserId: input.sourceContract.parserPolicy.parserId,
        parserVersion: input.sourceContract.parserPolicy.parserVersion,
        optionsHash: input.sourceContract.parserPolicy.optionsHash
      })
    },
    rowCount: sections.reduce((total, section) => total + section.rowCount, 0),
    columnCount: 2,
    byteCount: 512,
    elapsedMs: 100,
    sections,
    correction: { kind: "original" },
    ...(sourceSections === undefined ? {} : { sourceSections })
  };
}

function snapshotRepository(): GovernedDatasetSnapshotCommitRepositoryV1 {
  const records = new InMemoryImmutableRepository<ReturnType<typeof parseDatasetSnapshotV2>>(
    "modern-capture-material-snapshots",
    (record) => record.snapshotId,
    parseDatasetSnapshotV2
  );
  return {
    put: (record, context) => records.put(record, context),
    get: (tenantId, recordId) => records.get(tenantId, recordId),
    list: (tenantId, page) => records.list(tenantId, page),
    commitGovernedCapture: (record, _lineage, context) => records.put(record, context)
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
  return { sourceContractId: "loan-tape-source", deliveryId: "delivery-2026-08" };
}

function snapshotId() {
  return `snapshot-${canonicalHash({
    contractVersion: 1,
    tenantId: "tenant-a",
    sourceContractId: "loan-tape-source",
    deliveryId: "delivery-2026-08"
  }).slice("sha256:".length, "sha256:".length + 32)}`;
}

function hash(value: string) {
  return canonicalHash(value);
}
