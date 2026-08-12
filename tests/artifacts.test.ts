import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import {
  artifactJsonContentHash,
  ArtifactStore,
  ArtifactStoreError
} from "../src/control/artifacts.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "abl-artifacts-"));
  directories.push(directory);
  const key = Buffer.alloc(32, 7);
  const store = new ArtifactStore(directory, { activeKeyId: "key-2026-08", keys: { "key-2026-08": key } });
  return { directory, key, store };
}

test("JSON artifacts are canonical, encrypted, immutable and tenant scoped", () => {
  const { directory, store } = fixture();
  const first = store.putJson({
    tenantId: "tenant-a",
    kind: "stratification",
    mediaType: "application/json",
    value: { rows: [{ balance: "10", bucket: "A" }], totals: { balance: "10" } }
  });
  const replay = store.putJson({
    tenantId: "tenant-a",
    kind: "stratification",
    mediaType: "application/json",
    value: { totals: { balance: "10" }, rows: [{ bucket: "A", balance: "10" }] }
  });
  assert.equal(first.artifactId, replay.artifactId);
  assert.equal(
    artifactJsonContentHash({ totals: { balance: "10" }, rows: [{ bucket: "A", balance: "10" }] }),
    first.contentHash
  );
  assert.deepEqual(store.getJson("tenant-a", first.artifactId).value, {
    rows: [{ balance: "10", bucket: "A" }],
    totals: { balance: "10" }
  });
  assert.throws(
    () => store.getJson("tenant-b", first.artifactId),
    (error: unknown) => error instanceof ArtifactStoreError && error.code === "ARTIFACT_NOT_FOUND"
  );

  const files = findFiles(directory);
  assert.equal(files.length, 1);
  assert.equal(readFileSync(files[0]!, "utf8").includes('"balance":"10"'), false);
});

test("tampering fails authenticated decryption", () => {
  const { directory, store } = fixture();
  const artifact = store.putJson({
    tenantId: "tenant-a",
    kind: "borrowing_base",
    mediaType: "application/json",
    value: { availability: "125.50" }
  });
  const file = findFiles(directory)[0]!;
  const envelope = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
  const ciphertext = String(envelope.ciphertext);
  envelope.ciphertext = `${ciphertext.slice(0, -4)}AAAA`;
  writeFileSync(file, `${JSON.stringify(envelope)}\n`, "utf8");
  assert.throws(
    () => store.getJson("tenant-a", artifact.artifactId),
    (error: unknown) => error instanceof ArtifactStoreError && error.code === "INTEGRITY_FAILURE"
  );
});

test("old encryption keys remain readable after key rotation", () => {
  const directory = mkdtempSync(join(tmpdir(), "abl-artifacts-rotation-"));
  directories.push(directory);
  const oldKey = Buffer.alloc(32, 1);
  const newKey = Buffer.alloc(32, 2);
  const oldStore = new ArtifactStore(directory, { activeKeyId: "old", keys: { old: oldKey } });
  const artifact = oldStore.putJson({
    tenantId: "tenant-a",
    kind: "monitor",
    mediaType: "application/json",
    value: { status: "clear" }
  });
  const rotatedStore = new ArtifactStore(directory, {
    activeKeyId: "new",
    keys: { old: oldKey, new: newKey }
  });
  assert.deepEqual(rotatedStore.getJson("tenant-a", artifact.artifactId).value, { status: "clear" });
});

function findFiles(root: string): string[] {
  const paths: string[] = [];
  for (const entry of readdirSync(root)) {
    const path = join(root, entry);
    if (statSync(path).isDirectory()) paths.push(...findFiles(path));
    else paths.push(path);
  }
  return paths;
}
