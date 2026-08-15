import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalHash } from "../src/contracts/canonical.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import { SqliteCapturedSourceMaterialStoreV1 } from "../src/repositories/captured-source-material-v1.js";
import {
  ArtifactBackedModernSnapshotSourceEvidenceAuthorityV1,
  CapturedSourceMaterialError,
  CapturedSourceMaterialPublisherV1
} from "../src/services/artifact-backed-modern-source-evidence-v1.js";

const SYNTHETIC_AUTO_SECTION_BYTES = 30_000_000;

test("captured source material round-trips a bounded 25 MB+ synthetic auto section", async () => {
  const fixture = capacityFixture(SYNTHETIC_AUTO_SECTION_BYTES);
  try {
    const artifact = sectionArtifact("snapshot-large", 820, 32_000);
    const published = await fixture.publisher.publish(artifact);

    assert.ok(published.metadata.byteLength > 25_000_000);
    assert.ok(published.metadata.byteLength <= SYNTHETIC_AUTO_SECTION_BYTES);

    const loaded = await fixture.authority.loadSection({
      tenantId: "tenant-a",
      snapshotId: artifact.snapshotId,
      sectionId: artifact.sectionId
    });
    assert.equal(loaded?.records.length, 820);
    assert.equal(loaded?.records[0]?.payload.length, 32_000);
    assert.equal(loaded?.records.at(-1)?.asset_number, "A-000819");
    assert.equal(loaded?.controlPopulationHash, canonicalHash(artifact.records));
  } finally {
    fixture.close();
  }
});

test("captured source material rejects a section above its configured bound before metadata commit", async () => {
  const fixture = capacityFixture(1_000_000, 5_000_000);
  try {
    const artifact = sectionArtifact("snapshot-over-limit", 40, 32_000);
    await assert.rejects(
      fixture.publisher.publish(artifact),
      (error: unknown) =>
        error instanceof CapturedSourceMaterialError &&
        error.code === "INVALID_ARGUMENT" &&
        error.message === "Captured source artifact exceeds the configured section byte limit"
    );
    assert.equal(
      await fixture.material.get({
        tenantId: "tenant-a",
        snapshotId: artifact.snapshotId,
        sectionId: artifact.sectionId
      }),
      undefined
    );
  } finally {
    fixture.close();
  }
});

test("captured source material rejects missing, unsafe, or effectively unbounded ceilings", () => {
  const directory = mkdtempSync(join(tmpdir(), "abl-source-capacity-config-"));
  const artifacts = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "key-a",
    keys: { "key-a": Buffer.alloc(32, 31) }
  });
  const material = new SqliteCapturedSourceMaterialStoreV1(join(directory, "material.sqlite"));
  try {
    for (const maximumSectionBytes of [undefined, 1_023, 100_000_001, Number.POSITIVE_INFINITY]) {
      assert.throws(
        () => new CapturedSourceMaterialPublisherV1({
          artifacts,
          material,
          maximumSectionBytes: maximumSectionBytes as number
        }),
        (error: unknown) =>
          error instanceof CapturedSourceMaterialError && error.code === "INVALID_ARGUMENT"
      );
    }
  } finally {
    material.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

function capacityFixture(maximumSectionBytes: number, maximumArtifactBytes = maximumSectionBytes) {
  const directory = mkdtempSync(join(tmpdir(), "abl-source-capacity-"));
  const artifacts = new ArtifactStore(
    join(directory, "artifacts"),
    { activeKeyId: "key-a", keys: { "key-a": Buffer.alloc(32, 29) } },
    { maximumArtifactBytes }
  );
  const material = new SqliteCapturedSourceMaterialStoreV1(join(directory, "material.sqlite"));
  return {
    material,
    publisher: new CapturedSourceMaterialPublisherV1({
      artifacts,
      material,
      maximumSectionBytes
    }),
    authority: new ArtifactBackedModernSnapshotSourceEvidenceAuthorityV1({ artifacts, material }),
    close: () => {
      material.close();
      rmSync(directory, { recursive: true, force: true });
    }
  };
}

function sectionArtifact(snapshotId: string, rowCount: number, payloadBytes: number) {
  const payload = "x".repeat(payloadBytes);
  const records = Array.from({ length: rowCount }, (_, index) => ({
    asset_number: `A-${index.toString().padStart(6, "0")}`,
    payload
  }));
  return {
    contractVersion: 1 as const,
    kind: "captured_source_section" as const,
    tenantId: "tenant-a",
    snapshotId,
    snapshotHash: canonicalHash({ snapshotId }),
    extractionReceiptHash: canonicalHash({ snapshotId, receipt: true }),
    sourceContract: {
      sourceContractId: "synthetic-auto-loan-tape",
      revision: 1,
      sourceContractHash: canonicalHash({ contract: "synthetic-auto-loan-tape", revision: 1 })
    },
    sectionId: "loans",
    sectionContentHash: canonicalHash({ snapshotId, content: true }),
    sectionSchemaHash: canonicalHash({ fields: ["asset_number", "payload"] }),
    controlPopulationHash: canonicalHash(records),
    rowCount: records.length,
    records,
    capturedAt: "2026-08-15T12:00:00.000Z"
  };
}
