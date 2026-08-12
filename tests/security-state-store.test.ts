import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import { SecurityStateStore, SecurityStateStoreError } from "../src/security/state-store.js";
import type { PrincipalBoundHandleRecord, ReplayRecord } from "../src/security/signed-plan.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "abl-security-state-"));
  directories.push(directory);
  const path = join(directory, "state.sqlite");
  let now = new Date("2026-08-11T12:00:00Z");
  return {
    path,
    clock: () => now,
    advance(seconds: number) {
      now = new Date(now.getTime() + seconds * 1_000);
    }
  };
}

test("replay consumption is atomic across store instances", () => {
  const { path, clock } = fixture();
  const first = new SecurityStateStore(path, { clock });
  const second = new SecurityStateStore(path, { clock });
  const replay: ReplayRecord = {
    replayKey: "1".repeat(64),
    planId: "2".repeat(64),
    nonce: "nonce-1",
    tenantId: "tenant-a",
    principalBinding: "3".repeat(64),
    expiresAtEpochSeconds: Math.floor(clock().getTime() / 1_000) + 60
  };
  assert.equal(first.consumeOnce(replay), true);
  assert.equal(second.consumeOnce(replay), false);
  first.close();
  second.close();
});

test("opaque handles remain bound to exactly one principal-scoped resource", () => {
  const { path, clock } = fixture();
  const store = new SecurityStateStore(path, { clock });
  const issuedAt = Math.floor(clock().getTime() / 1_000);
  const handle: PrincipalBoundHandleRecord = {
    handleId: "opaque-handle-id",
    kind: "job",
    tenantId: "tenant-a",
    principalBinding: "a".repeat(64),
    issuedAtEpochSeconds: issuedAt,
    expiresAtEpochSeconds: issuedAt + 300
  };
  assert.equal(store.bindHandle(handle, "job-123").resourceId, "job-123");
  assert.equal(store.bindHandle(handle, "job-123").resourceId, "job-123");
  assert.equal(store.resolveHandle(handle).resourceId, "job-123");
  assert.throws(
    () => store.bindHandle(handle, "job-456"),
    (error: unknown) => error instanceof SecurityStateStoreError && error.code === "HANDLE_CONFLICT"
  );
  assert.throws(
    () => store.resolveHandle({ ...handle, tenantId: "tenant-b" }),
    (error: unknown) => error instanceof SecurityStateStoreError && error.code === "HANDLE_NOT_FOUND"
  );
  store.close();
});

test("expired security state is rejected and can be pruned", () => {
  const { path, clock, advance } = fixture();
  const store = new SecurityStateStore(path, { clock });
  const issuedAt = Math.floor(clock().getTime() / 1_000);
  const handle: PrincipalBoundHandleRecord = {
    handleId: "opaque-handle-id",
    kind: "result",
    tenantId: "tenant-a",
    principalBinding: "a".repeat(64),
    issuedAtEpochSeconds: issuedAt,
    expiresAtEpochSeconds: issuedAt + 5
  };
  store.bindHandle(handle, "artifact-123");
  advance(6);
  assert.throws(
    () => store.resolveHandle(handle),
    (error: unknown) => error instanceof SecurityStateStoreError && error.code === "HANDLE_EXPIRED"
  );
  assert.deepEqual(store.pruneExpired(), { replayRecords: 0, handleBindings: 1 });
  store.close();
});
