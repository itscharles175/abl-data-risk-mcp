import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, test } from "node:test";

import { canonicalHash } from "../src/contracts/canonical.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import {
  HistoricalRuntimeAuthorityError,
  SqliteHistoricalRuntimeAuthorityV1,
  type TrustedRuntimeAuthorityActorV1
} from "../src/control/historical-runtime-authority-v1.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("artifact-backed runtime authority replays only exact activated tenant evidence", async () => {
  const fixture = authorityFixture();
  const registered = registerEvidence(fixture.authority);
  const resolver = fixture.authority.forTenant("tenant-a", {
    usedAt: () => "2026-08-13T13:00:00.000Z"
  });

  await assert.rejects(
    resolver.resolveRuntimeBundle({
      runtimeBundleId: registered.runtime.runtimeBundleId,
      runtimeBundleHash: registered.runtime.runtimeBundleHash
    }),
    (error: unknown) => authorityError(error, "INACTIVE")
  );
  assert.throws(
    () => fixture.authority.activateRuntime(MAKER, {
      runtimeBundleId: registered.runtime.runtimeBundleId,
      runtimeBundleHash: registered.runtime.runtimeBundleHash,
      idempotencyKey: "runtime-activate-maker"
    }),
    (error: unknown) => authorityError(error, "MAKER_CHECKER_VIOLATION")
  );
  const activation = fixture.authority.activateRuntime(CHECKER, {
    runtimeBundleId: registered.runtime.runtimeBundleId,
    runtimeBundleHash: registered.runtime.runtimeBundleHash,
    idempotencyKey: "runtime-activate"
  });
  const replay = fixture.authority.activateRuntime(CHECKER, {
    runtimeBundleId: registered.runtime.runtimeBundleId,
    runtimeBundleHash: registered.runtime.runtimeBundleHash,
    idempotencyKey: "runtime-activate"
  });
  assert.equal(activation.replayed, false);
  assert.equal(replay.replayed, true);
  assert.deepEqual(replay.value, activation.value);
  assert.notEqual(activation.value.registeredBy, activation.value.activatedBy);

  const resolvedRuntime = await resolver.resolveRuntimeBundle({
    runtimeBundleId: registered.runtime.runtimeBundleId,
    runtimeBundleHash: registered.runtime.runtimeBundleHash
  });
  assert.deepEqual(resolvedRuntime, registered.runtime);
  assert.deepEqual(
    await resolver.resolveDictionary(registered.dictionary),
    {
      reference: registered.dictionary,
      content: {
        dictionary: { fields: ["loan_id", "balance"] },
        fieldPolicy: { nulls: "preserve" }
      }
    }
  );
  assert.deepEqual(
    await resolver.resolveBundle(registered.compiler),
    { reference: registered.compiler, content: { compiler: "mapping-v2", revision: 1 } }
  );
  await assert.rejects(
    fixture.authority.forTenant("tenant-b").resolveRuntimeBundle({
      runtimeBundleId: registered.runtime.runtimeBundleId,
      runtimeBundleHash: registered.runtime.runtimeBundleHash
    }),
    (error: unknown) => authorityError(error, "NOT_FOUND")
  );
  await assert.rejects(
    fixture.authority.forTenant("tenant-a", {
      usedAt: () => "2026-08-13T11:59:59.999Z"
    }).resolveRuntimeBundle({
      runtimeBundleId: registered.runtime.runtimeBundleId,
      runtimeBundleHash: registered.runtime.runtimeBundleHash
    }),
    (error: unknown) => authorityError(error, "INACTIVE")
  );

  fixture.authority.close();
  const reopened = new SqliteHistoricalRuntimeAuthorityV1(
    fixture.databasePath,
    fixture.artifacts,
    { clock: () => new Date("2026-08-13T14:00:00.000Z") }
  );
  assert.deepEqual(
    await reopened.forTenant("tenant-a").resolveRuntimeBundle({
      runtimeBundleId: registered.runtime.runtimeBundleId,
      runtimeBundleHash: registered.runtime.runtimeBundleHash
    }),
    registered.runtime
  );
  reopened.close();
});

test("runtime authority rejects idempotency drift and detects persisted audit tampering on reopen", () => {
  const fixture = authorityFixture();
  const registered = registerEvidence(fixture.authority);
  assert.throws(
    () => fixture.authority.activateRuntime(CHECKER, {
      runtimeBundleId: registered.runtime.runtimeBundleId,
      runtimeBundleHash: canonicalHash("substituted"),
      idempotencyKey: "runtime-activate"
    }),
    (error: unknown) => authorityError(error, "NOT_FOUND")
  );
  fixture.authority.activateRuntime(CHECKER, {
    runtimeBundleId: registered.runtime.runtimeBundleId,
    runtimeBundleHash: registered.runtime.runtimeBundleHash,
    idempotencyKey: "runtime-activate"
  });
  assert.throws(
    () => fixture.authority.activateRuntime(CHECKER, {
      runtimeBundleId: "runtime-substituted",
      runtimeBundleHash: registered.runtime.runtimeBundleHash,
      idempotencyKey: "runtime-activate"
    }),
    (error: unknown) => authorityError(error, "IDEMPOTENCY_CONFLICT")
  );
  fixture.authority.close();

  const database = new DatabaseSync(fixture.databasePath);
  database.exec("DROP TRIGGER historical_runtime_audit_v1_no_update");
  database.prepare(
    "UPDATE historical_runtime_audit_v1 SET event_hash = ? WHERE tenant_id = ? AND tenant_sequence = 1"
  ).run(`sha256:${"0".repeat(64)}`, "tenant-a");
  database.close();

  assert.throws(
    () => new SqliteHistoricalRuntimeAuthorityV1(fixture.databasePath, fixture.artifacts),
    (error: unknown) => authorityError(error, "INTEGRITY_FAILURE")
  );
});

test("runtime authority derives dictionary semantic hashes and rejects receipt-scope tampering", () => {
  const fixture = authorityFixture();
  assert.throws(
    () => fixture.authority.registerBundle(MAKER, {
      bundleKind: "dictionary",
      bundleId: "forged-dictionary",
      version: "1.0.0",
      mediaType: "application/json",
      createdAt: "2026-08-13T09:00:00.000Z",
      dictionaryVersion: "1.0.0",
      dictionaryHash: canonicalHash("forged"),
      fieldPolicyVersion: "1.0.0",
      fieldPolicyHash: canonicalHash({ nulls: "preserve" }),
      content: {
        dictionary: { fields: ["loan_id"] },
        fieldPolicy: { nulls: "preserve" }
      },
      idempotencyKey: "forged-dictionary"
    }),
    (error: unknown) => authorityError(error, "INVALID_INPUT")
  );
  registerEvidence(fixture.authority);
  fixture.authority.close();
  const database = new DatabaseSync(fixture.databasePath);
  database.exec("DROP TRIGGER historical_runtime_idempotency_v1_no_update");
  database.prepare(
    "UPDATE historical_runtime_idempotency_v1 SET actor_id = 'substituted-actor' WHERE operation = 'register_runtime'"
  ).run();
  database.close();
  assert.throws(
    () => new SqliteHistoricalRuntimeAuthorityV1(fixture.databasePath, fixture.artifacts),
    (error: unknown) => authorityError(error, "INTEGRITY_FAILURE")
  );
});

function registerEvidence(authority: SqliteHistoricalRuntimeAuthorityV1) {
  const dictionaryContent = {
    dictionary: { fields: ["loan_id", "balance"] },
    fieldPolicy: { nulls: "preserve" }
  };
  const dictionary = authority.registerBundle(MAKER, {
    bundleKind: "dictionary",
    bundleId: "dictionary-core",
    version: "1.0.0",
    mediaType: "application/json",
    createdAt: "2026-08-13T09:00:00.000Z",
    dictionaryVersion: "1.0.0",
    dictionaryHash: canonicalHash(dictionaryContent.dictionary),
    fieldPolicyVersion: "1.0.0",
    fieldPolicyHash: canonicalHash(dictionaryContent.fieldPolicy),
    content: dictionaryContent,
    idempotencyKey: "dictionary-register"
  }).value;
  assert.equal(dictionary.bundleKind, "dictionary");
  if (dictionary.bundleKind !== "dictionary") throw new Error("expected dictionary reference");
  const compiler = authority.registerBundle(MAKER, {
    bundleKind: "mapping_compiler",
    bundleId: "mapping-v2",
    version: "1.0.0",
    mediaType: "application/json",
    createdAt: "2026-08-13T09:10:00.000Z",
    content: { compiler: "mapping-v2", revision: 1 },
    idempotencyKey: "compiler-register"
  }).value;
  if (compiler.bundleKind !== "mapping_compiler") throw new Error("expected compiler reference");
  const methodology = authority.registerBundle(MAKER, {
    bundleKind: "methodology",
    bundleId: "certification-methodology",
    version: "1.0.0",
    mediaType: "application/json",
    createdAt: "2026-08-13T09:20:00.000Z",
    content: { name: "Synthetic auto certification", sections: ["loan_tape"] },
    idempotencyKey: "methodology-register"
  }).value;
  if (methodology.bundleKind !== "methodology") throw new Error("expected methodology reference");
  const runtime = authority.registerRuntime(MAKER, {
    runtimeBundleId: "runtime-synthetic-auto-v1",
    runtimeVersion: "1.0.0",
    dictionary,
    mappingCompiler: compiler,
    methodologies: [methodology],
    assembledAt: "2026-08-13T10:00:00.000Z",
    idempotencyKey: "runtime-register"
  }).value;
  return { dictionary, compiler, methodology, runtime };
}

function authorityFixture() {
  const directory = mkdtempSync(join(tmpdir(), "historical-runtime-authority-"));
  directories.push(directory);
  const databasePath = join(directory, "authority.sqlite");
  const artifacts = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "test-key",
    keys: { "test-key": Buffer.alloc(32, 7) }
  });
  let event = 0;
  const authority = new SqliteHistoricalRuntimeAuthorityV1(databasePath, artifacts, {
    clock: () => new Date("2026-08-13T12:00:00.000Z"),
    eventId: () => `event-${++event}`
  });
  return { authority, artifacts, databasePath };
}

const MAKER: TrustedRuntimeAuthorityActorV1 = {
  tenantId: "tenant-a",
  actorId: "runtime-maker",
  authority: "platform_operator",
  identitySource: "server_derived"
};

const CHECKER: TrustedRuntimeAuthorityActorV1 = {
  tenantId: "tenant-a",
  actorId: "runtime-checker",
  authority: "platform_operator",
  identitySource: "server_derived"
};

function authorityError(error: unknown, code: HistoricalRuntimeAuthorityError["code"]): boolean {
  return error instanceof HistoricalRuntimeAuthorityError && error.code === code;
}
