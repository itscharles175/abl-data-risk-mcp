import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import { canonicalHash } from "../src/contracts/canonical.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import {
  CapturedSourceMaterialStoreError,
  SqliteCapturedSourceMaterialStoreV1
} from "../src/repositories/captured-source-material-v1.js";
import {
  ArtifactBackedModernSnapshotSourceEvidenceAuthorityV1,
  CapturedSourceMaterialPublisherV1
} from "../src/services/artifact-backed-modern-source-evidence-v1.js";

test("captured source material is encrypted, immutable, and reloads as certification evidence", async () => {
  const fixture = createFixture();
  try {
    const published = await fixture.publisher.publish(sectionArtifact());
    assert.equal(published.replayed, false);
    assert.equal(published.metadata.snapshotHash, sectionArtifact().snapshotHash);
    const replay = await fixture.publisher.publish(sectionArtifact());
    assert.equal(replay.replayed, true);
    assert.equal(replay.metadata.artifactId, published.metadata.artifactId);

    const section = await fixture.authority.loadSection({
      tenantId: "tenant-a",
      snapshotId: "snapshot-2026-08",
      sectionId: "loans"
    });
    assert.deepEqual(section?.records, sectionArtifact().records);
    assert.equal(section?.controlPopulationHash, canonicalHash(sectionArtifact().records));
    assert.equal(
      await fixture.authority.loadSection({ tenantId: "tenant-b", snapshotId: "snapshot-2026-08", sectionId: "loans" }),
      undefined
    );
    fixture.close();
  } finally {
    fixture.cleanup();
  }
});

test("captured source material fails closed after a schema-preserving metadata substitution", async () => {
  const fixture = createFixture();
  try {
    const published = await fixture.publisher.publish(sectionArtifact());
    fixture.store.close();
    const attacker = new DatabaseSync(fixture.databasePath);
    attacker.exec("DROP TRIGGER captured_source_section_material_v1_no_update");
    attacker.prepare(
      "UPDATE captured_source_section_material_v1 SET artifact_id = ? WHERE tenant_id = ?"
    ).run(canonicalHash("forged-artifact").slice("sha256:".length), "tenant-a");
    attacker.close();
    assert.throws(
      () => new SqliteCapturedSourceMaterialStoreV1(fixture.databasePath),
      (error: unknown) => storeError(error, "INTEGRITY_FAILURE")
    );
  } finally {
    fixture.cleanup();
  }
});

test("captured source material replays the exact bound artifact across encryption-key rotation", async () => {
  const directory = mkdtempSync(join(tmpdir(), "abl-captured-source-material-rotation-"));
  const databasePath = join(directory, "material.sqlite");
  const artifactRoot = join(directory, "artifacts");
  const keys = {
    "key-1": Buffer.alloc(32, 21),
    "key-2": Buffer.alloc(32, 22)
  };
  const store = new SqliteCapturedSourceMaterialStoreV1(databasePath);
  try {
    const firstArtifacts = new ArtifactStore(artifactRoot, { activeKeyId: "key-1", keys });
    const first = await new CapturedSourceMaterialPublisherV1({
      artifacts: firstArtifacts,
      material: store,
      maximumSectionBytes: 1_000_000
    }).publish(sectionArtifact());

    const rotatedArtifacts = new ArtifactStore(artifactRoot, { activeKeyId: "key-2", keys });
    const replay = await new CapturedSourceMaterialPublisherV1({
      artifacts: rotatedArtifacts,
      material: store,
      maximumSectionBytes: 1_000_000
    }).publish(sectionArtifact());

    assert.equal(replay.replayed, true);
    assert.equal(replay.metadata.artifactId, first.metadata.artifactId);
    assert.equal(replay.metadata.keyId, "key-1");
  } finally {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

function createFixture() {
  const directory = mkdtempSync(join(tmpdir(), "abl-captured-source-material-"));
  const databasePath = join(directory, "material.sqlite");
  const artifacts = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "key-2026",
    keys: { "key-2026": Buffer.alloc(32, 19) }
  });
  const store = new SqliteCapturedSourceMaterialStoreV1(databasePath);
  const publisher = new CapturedSourceMaterialPublisherV1({
    artifacts,
    material: store,
    maximumSectionBytes: 1_000_000
  });
  const authority = new ArtifactBackedModernSnapshotSourceEvidenceAuthorityV1({ artifacts, material: store });
  return {
    databasePath,
    artifacts,
    store,
    publisher,
    authority,
    close: () => store.close(),
    cleanup: () => rmSync(directory, { recursive: true, force: true })
  };
}

function sectionArtifact() {
  const records = [
    { asset_number: "A-1", balance: "100.00", days_past_due: "0" },
    { asset_number: "A-2", balance: "50.00", days_past_due: "30" }
  ];
  return {
    contractVersion: 1 as const,
    kind: "captured_source_section" as const,
    tenantId: "tenant-a",
    snapshotId: "snapshot-2026-08",
    snapshotHash: canonicalHash({ snapshot: "2026-08" }),
    extractionReceiptHash: canonicalHash({ receipt: "capture-2026-08" }),
    sourceContract: {
      sourceContractId: "synthetic-auto-loan-tape",
      revision: 1,
      sourceContractHash: canonicalHash({ contract: "synthetic-auto-loan-tape", revision: 1 })
    },
    sectionId: "loans",
    sectionContentHash: canonicalHash({ section: "loans", bytes: "exact" }),
    sectionSchemaHash: canonicalHash({ section: "loans", schema: ["asset_number", "balance", "days_past_due"] }),
    controlPopulationHash: canonicalHash(records),
    rowCount: records.length,
    records,
    capturedAt: "2026-08-13T01:00:00.000Z"
  };
}

function storeError(error: unknown, code: CapturedSourceMaterialStoreError["code"]): boolean {
  assert.ok(error instanceof CapturedSourceMaterialStoreError);
  assert.equal(error.code, code);
  return true;
}
